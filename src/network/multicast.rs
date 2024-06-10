use bincode;

use crate::log_service::LogService;
use crate::security::MeetingToken;

use super::{Announce, AnnounceHeader, Error};
use crate::peer_connection_service::{PeerConnectionMessage, PeerConnectionService};

use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;

//maximum message size
const MULTICAST_MTU: usize = 4096;

#[derive(Serialize, Deserialize)]
pub enum MulticastMessage {
    ProbeLocalIp([u8; 32]),
    Annouce(Announce),
    InitiateConnection(AnnounceHeader, MeetingToken),
}

//#[allow(clippy::unnecessary_unwrap)]
pub async fn start_multicast_discovery(
    multicast_adress: SocketAddr,
    multicast_ipv4_interface: Ipv4Addr,
    peer_service: PeerConnectionService,
    log: LogService,
) -> Result<Sender<MulticastMessage>, Error> {
    let socket_sender = new_sender(&multicast_ipv4_interface)?;
    let socket_listener = new_listener(multicast_adress, &multicast_ipv4_interface)?;
    let (sender, mut receiv) = mpsc::channel::<MulticastMessage>(1);

    let logs = log.clone();
    tokio::spawn(async move {
        let mut buffer: Vec<u8> = Vec::new();
        while let Some(msg) = receiv.recv().await {
            buffer.clear();
            let b = bincode::serialize_into(&mut buffer, &msg);
            match b {
                Ok(_) => {
                    let error = socket_sender.send_to(&buffer, multicast_adress).await;
                    if let Err(e) = error {
                        logs.error("multicast send".to_string(), crate::Error::from(e));
                    }
                }
                Err(e) => logs.error("multicast send".to_string(), crate::Error::from(e)),
            }
        }
    });

    tokio::spawn(async move {
        let mut buffer: [u8; MULTICAST_MTU] = [0; MULTICAST_MTU];
        loop {
            let rec = receive(&socket_listener, &mut buffer).await;

            match rec {
                Ok((msg, adress)) => {
                    let _ = peer_service
                        .sender
                        .send(PeerConnectionMessage::MulticastMessage(msg, adress))
                        .await;
                }
                Err(e) => {
                    log.error("multicast receiv".to_string(), crate::Error::from(e));
                }
            }
        }
    });

    Ok(sender)
}

async fn receive(
    socket_listener: &UdpSocket,
    buffer: &mut [u8; MULTICAST_MTU],
) -> Result<(MulticastMessage, SocketAddr), Error> {
    let (len, remote_addr) = socket_listener
        .recv_from(buffer)
        .await
        .map_err(Error::from)?;

    let message: MulticastMessage = bincode::deserialize(&buffer[0..len])?;

    Ok((message, remote_addr))
}

fn new_listener(
    multicast_adress: SocketAddr,
    multicast_ipv4_interface: &Ipv4Addr,
) -> io::Result<UdpSocket> {
    let ip_addr = multicast_adress.ip();
    let socket = new_socket()?;

    match ip_addr {
        IpAddr::V4(ref v4) => {
            // join to the multicast address, with all interfaces
            socket.join_multicast_v4(v4, multicast_ipv4_interface)?;
        }
        IpAddr::V6(ref _v6) => {} //don't know how to make it work well windows
    };
    bind_multicast(&socket, &multicast_adress, multicast_ipv4_interface)?;
    let socket: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(socket).expect("could not convert to tokio socket"))
}

fn new_sender(multicast_ipv4_interface: &Ipv4Addr) -> io::Result<UdpSocket> {
    let socket = new_socket()?;
    socket.set_multicast_if_v4(multicast_ipv4_interface)?;
    socket.bind(&SockAddr::from(SocketAddr::new(
        multicast_ipv4_interface.clone().into(),
        0,
    )))?;
    let socket: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(socket).expect("could not convert to tokio socket"))
}

// this will be common for all our sockets
fn new_socket() -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    // socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    socket
        .set_nonblocking(true)
        .expect("could not set socket to non blocking");
    Ok(socket)
}

/// On Windows, unlike all Unix variants, it is improper to bind to the multicast address
///
/// see https://msdn.microsoft.com/en-us/library/windows/desktop/ms737550(v=vs.85).aspx
#[cfg(windows)]
fn bind_multicast(
    socket: &Socket,
    addr: &SocketAddr,
    multicast_ipv4_interface: &Ipv4Addr,
) -> io::Result<()> {
    let addr = SocketAddr::new(multicast_ipv4_interface.clone().into(), addr.port());
    socket.set_reuse_address(true)?;
    socket.bind(&socket2::SockAddr::from(addr))
}

/// On unixes we bind to the multicast address
#[cfg(unix)]
fn bind_multicast(socket: &Socket, addr: &SocketAddr, _: &Ipv4Addr) -> io::Result<()> {
    socket.set_reuse_address(true)?;
    socket.bind(&socket2::SockAddr::from(*addr))
}

#[cfg(test)]
mod test {

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn multicast_test() {
        let multicast_adress = SocketAddr::new(Ipv4Addr::new(224, 0, 0, 224).into(), 22401);
        let multicast_ipv4: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
        let socket_sender = new_sender(&multicast_ipv4).unwrap();
        let socket_listener = new_listener(multicast_adress, &multicast_ipv4).unwrap();
        let socket_listener2 = new_listener(multicast_adress, &multicast_ipv4).unwrap();

        let first = tokio::spawn(async move {
            let mut buffer: [u8; 4096] = [0; 4096];
            let (len, remote_addr) = socket_listener
                .recv_from(&mut buffer)
                .await
                .map_err(Error::from)
                .unwrap();

            (
                String::from_utf8(buffer[0..len].to_vec()).unwrap(),
                remote_addr,
            )
        });

        let second = tokio::spawn(async move {
            let mut buffer: [u8; 4096] = [0; 4096];
            let (len, remote_addr) = socket_listener2
                .recv_from(&mut buffer)
                .await
                .map_err(Error::from)
                .unwrap();

            (
                String::from_utf8(buffer[0..len].to_vec()).unwrap(),
                remote_addr,
            )
        });

        let message = "Hello World".to_string();
        let _ = socket_sender
            .send_to(message.as_bytes(), multicast_adress)
            .await
            .unwrap();

        let (msg, _) = first.await.unwrap();
        assert_eq!(msg, message);
        let (msg, _) = second.await.unwrap();
        assert_eq!(msg, message);
    }
}
