use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

fn listener(multicast_adress: SocketAddr) -> io::Result<UdpSocket> {
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

fn sender() -> io::Result<UdpSocket> {
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
    use std::error::Error;
    #[tokio::test(flavor = "multi_thread")]
    async fn test_ipv4_multicast_tokio() -> Result<(), Box<dyn Error>> {
        let multicast_ip: IpAddr = Ipv4Addr::new(224, 0, 0, 224).into();
        let multicast_adress = SocketAddr::new(multicast_ip, 1234);
        let listener = listener(multicast_adress).expect("failed to create listener");
        let server_response = "ServerResponse";
        tokio::spawn(async move {
            let mut buf = [0u8; 64]; // receive buffer

            // we're assuming failures were timeouts, the client_done loop will stop us
            match listener.recv_from(&mut buf).await {
                Ok((len, remote_addr)) => {
                    let data = &buf[..len];

                    println!(
                        "server: got data: {} from: {}",
                        String::from_utf8_lossy(data),
                        remote_addr
                    );
                    // we send the response that was set at the method beginning
                    listener
                        .send_to(server_response.as_bytes(), &remote_addr)
                        .await
                        .expect("failed to respond");

                    println!("server: sent response to: {}", remote_addr);
                }
                Err(err) => {
                    println!("server: got an error: {}", err);
                }
            }
        });

        let message = b"Hello from client!";
        // create the sending socket
        let socket = sender().expect("could not create sender!");
        //let socket = join_multicast_2(*IPV4, 4566).expect("failed to create listener");
        socket
            .send_to(message, &multicast_adress)
            .await
            .expect("could not send_to!");

        let mut buf = [0u8; 64]; // receive buffer

        match socket.recv_from(&mut buf).await {
            Ok((len, _addr)) => {
                let data = &buf[..len];
                let response = String::from_utf8_lossy(data);

                println!("client: got data: {}", response);

                // verify it's what we expected
                assert_eq!(server_response, response);
            }
            Err(err) => {
                println!("client: had a problem: {}", err);
                assert!(false);
            }
        }
        Ok(())
    }
}
