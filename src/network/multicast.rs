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
    peer_service: PeerConnectionService,
    log: LogService,
) -> Result<Sender<MulticastMessage>, Error> {
    let socket_sender = new_sender()?;
    let socket_listener = new_listener(multicast_adress)?;
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

fn new_listener(multicast_adress: SocketAddr) -> io::Result<UdpSocket> {
    let ip_addr = multicast_adress.ip();
    let socket = new_socket()?;

    match ip_addr {
        IpAddr::V4(ref v4) => {
            // join to the multicast address, with all interfaces
            socket.join_multicast_v4(v4, &Ipv4Addr::new(0, 0, 0, 0))?;
        }
        IpAddr::V6(ref _v6) => {} //don't know how to make it work well windows
    };
    bind_multicast(&socket, &multicast_adress)?;
    let socket: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(socket).expect("could not convert to tokio socket"))
}

fn new_sender() -> io::Result<UdpSocket> {
    let socket = new_socket()?;
    socket.set_multicast_if_v4(&Ipv4Addr::new(0, 0, 0, 0))?;
    socket.bind(&SockAddr::from(SocketAddr::new(
        Ipv4Addr::new(0, 0, 0, 0).into(),
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
fn bind_multicast(socket: &Socket, addr: &SocketAddr) -> io::Result<()> {
    let addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), addr.port());
    socket.bind(&socket2::SockAddr::from(addr))
}

/// On unixes we bind to the multicast address, which causes multicast packets to be filtered
#[cfg(unix)]
fn bind_multicast(socket: &Socket, addr: &SocketAddr) -> io::Result<()> {
    socket.set_reuse_address(true)?;
    socket.bind(&socket2::SockAddr::from(*addr))
}

#[cfg(test)]
mod test {

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn multicast_test() {
        let multicast_adress = SocketAddr::new(Ipv4Addr::new(224, 0, 0, 224).into(), 22401);

        let socket_sender = new_sender().unwrap();
        let socket_listener = new_listener(multicast_adress).unwrap();
        let socket_listener2 = new_listener(multicast_adress).unwrap();

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

    /*    #[tokio::test(flavor = "multi_thread")]
    async fn multicast_discovery_test() -> Result<(), Box<dyn std::error::Error>> {
        let multicast_adress = SocketAddr::new(Ipv4Addr::new(224, 0, 0, 224).into(), 22401);
        let announce_frequency = 10;

        let (sender, mut receiver): (
            Sender<Result<Message, Error>>,
            Receiver<Result<Message, Error>>,
        ) = mpsc::channel(1);

        let sender = start_multicast_discovery(
            multicast_adress,
            Duration::from_millis(announce_frequency),
            sender,
        )
        .await
        .unwrap();

        let ann = Announce {
            port: 8,
            certificate: vec![1, 2, 3, 4],
            signature: vec![1, 2, 3],
            tokens: vec![vec![4, 3, 2, 1]],
        };

        let _ = sender.send(ann.clone()).await;
        let received = receiver.recv().await.unwrap()?;

        let mut _ipr = &multicast_adress.ip();
        match &received {
            Message::MulticastCandidates { ip, announce } => {
                assert_eq!(announce.as_ref(), &ann);
                _ipr = ip;
            }
        }

        //sleep enought time for one announce
        thread::sleep(Duration::from_millis(announce_frequency));
        let msg = receiver.recv().await.unwrap()?;
        match &msg {
            Message::MulticastCandidates { ip, announce } => {
                assert_eq!(announce.as_ref(), &ann);
                assert_eq!(ip, _ipr);
            }
        }
        assert_eq!(received, msg);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ipv4_multicast_tokio_test() -> Result<(), Box<dyn std::error::Error>> {
        let multicast_adress = SocketAddr::new(Ipv4Addr::new(224, 0, 0, 224).into(), 22402);

        let listener = new_listener(multicast_adress).expect("failed to create listener");

        let client_message = "Hello from client";
        let server_response = "Hello from server";

        tokio::spawn(async move {
            let mut buf = [0u8; 64];

            let (len, remote_addr) = listener
                .recv_from(&mut buf)
                .await
                .expect("Server encoutered an error while receiving");

            let data = &buf[..len];
            let response = String::from_utf8_lossy(data);
            assert_eq!(client_message, response);

            listener
                .send_to(server_response.as_bytes(), &remote_addr)
                .await
                .expect("failed to respond");
        });

        let sender = new_sender().expect("could not create sender!");

        sender
            .send_to(client_message.as_bytes(), &multicast_adress)
            .await
            .expect("could not send_to!");

        let mut buf = [0u8; 64];

        let (len, _addr) = sender
            .recv_from(&mut buf)
            .await
            .expect("client issue while receiving");
        let data = &buf[..len];
        let response = String::from_utf8_lossy(data);

        assert_eq!(server_response, response);

        Ok(())
    }*/
}
