use bincode;

use futures::lock::Mutex;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::error::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::time::{sleep, Duration};

//maximum message size
const MULTICAST_MTU: usize = 1330;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Message {
    TestMessage,
    TestMessage2,
}

pub async fn star_multicast_discovery(
    multicast_adress: SocketAddr,
    announce_frequency: Duration,
) -> Result<(Sender<Message>, Receiver<Result<Message, Error>>), Error> {
    let socket_sender = new_sender();
    if socket_sender.is_err() {
        return Err(socket_sender.expect_err("").into());
    }
    let socket_sender = socket_sender.unwrap();

    let socket_listener = new_listener(multicast_adress);
    if socket_listener.is_err() {
        return Err(socket_listener.expect_err("").into());
    }
    let socket_listener = socket_listener.unwrap();

    let (sender, mut internal_reciever): (Sender<Message>, Receiver<Message>) = mpsc::channel(2);

    let (internal_sender, reciever): (
        Sender<Result<Message, Error>>,
        Receiver<Result<Message, Error>>,
    ) = mpsc::channel(1);

    let error_channel = internal_sender.clone();

    tokio::spawn(async move {
        let mut buf: Vec<u8> = Vec::with_capacity(MULTICAST_MTU);
        let msg_option = internal_reciever.recv().await;
        let mut msg;
        if msg_option.is_none() {
            return;
        } else {
            msg = msg_option.unwrap();
        }
        loop {
            buf.clear();
            match bincode::serialize_into(&mut buf, &msg) {
                Ok(_) => {
                    if buf.len() > MULTICAST_MTU {
                        let _ = error_channel
                            .send(Err(Error::MsgSerialisationToLong(buf.len(), MULTICAST_MTU)))
                            .await;
                        buf.clear();
                        buf.shrink_to(MULTICAST_MTU)
                    } else {
                        match socket_sender.send_to(&buf[..], &multicast_adress).await {
                            Err(e) => {
                                let _ = error_channel.send(Err(e.into())).await;
                            }
                            _ => (),
                        };
                    }
                }
                Err(e) => {
                    let _ = error_channel.send(Err(e.into())).await;
                }
            };

            tokio::select! {
                option = internal_reciever.recv() => {
                    if option.is_none() {
                        return;
                    } else {
                        msg = option.unwrap();
                    }
                }
                _ = sleep(announce_frequency) => {
                }
            };
        }
    });

    tokio::spawn(async move {
        let mut buf = [0u8; MULTICAST_MTU];
        loop {
            let ms = socket_listener.recv_from(&mut buf).await;
            match ms {
                Ok((len, _remote_addr)) => {
                    if len > buf.len() {
                        let _ = internal_sender
                            .send(Err(Error::MsgDeserialisationToLong(len, MULTICAST_MTU)))
                            .await;
                        continue;
                    };
                    let msg: Result<Message, Box<bincode::ErrorKind>> =
                        bincode::deserialize(&buf[0..len]);
                    let _ = match msg {
                        Ok(message) => internal_sender.send(Ok(message)).await,
                        Err(e) => internal_sender.send(Err(e.into())).await,
                    };
                }
                Err(e) => {
                    let _ = internal_sender.send(Err(e.into())).await;
                }
            }
        }
    });

    Ok((sender, reciever))
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
    socket.bind(&socket2::SockAddr::from(*addr))
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{error::Error, thread};

    #[tokio::test(flavor = "multi_thread")]
    async fn multicast_discovery_test() -> Result<(), Box<dyn Error>> {
        let multicast_adress = SocketAddr::new(Ipv4Addr::new(224, 0, 0, 224).into(), 22401);
        let announce_frequency = 1;
        let (sender, mut receiver) =
            star_multicast_discovery(multicast_adress, Duration::from_millis(announce_frequency))
                .await
                .unwrap();
        let _ = sender.send(Message::TestMessage).await;
        let message = receiver.recv().await.unwrap()?;
        assert_eq!(message, Message::TestMessage);
        let _ = sender.send(Message::TestMessage2).await;
        let message = receiver.recv().await.unwrap()?;
        assert_eq!(message, Message::TestMessage2);

        //sleep enought time for one announce
        thread::sleep(Duration::from_millis(announce_frequency));
        let message = receiver.recv().await.unwrap()?;
        assert_eq!(message, Message::TestMessage2);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ipv4_multicast_tokio_test() -> Result<(), Box<dyn Error>> {
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
    }
}