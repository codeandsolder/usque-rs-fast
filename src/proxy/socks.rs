use super::net::VirtualNet;
use anyhow::Result;
use fast_socks5::{
    ReplyError, Socks5Command, new_udp_header, parse_udp_request,
    server::{Socks5ServerProtocol, states::CommandRead},
    util::target_addr::TargetAddr,
};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream, UdpSocket},
};

#[derive(Clone, Debug)]
pub struct SocksConfig {
    pub bind: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Serve SOCKS5/SOCKS5h TCP CONNECT requests on the configured listener.
///
/// # Errors
/// Returns an error when the listener cannot be bound or accepted, or when the
/// underlying userspace WARP network stops.
pub async fn serve(config: SocksConfig, net: Arc<VirtualNet>) -> Result<()> {
    let listener = TcpListener::bind(config.bind).await?;
    log::info!("SOCKS5/SOCKS5h proxy listening on {}", config.bind);

    let closed = net.wait_closed();
    tokio::pin!(closed);

    loop {
        let (stream, peer) = tokio::select! {
            result = listener.accept() => result?,
            () = &mut closed => anyhow::bail!("userspace WARP network stopped"),
        };
        let net = net.clone();
        let username = config.username.clone();
        let password = config.password.clone();

        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, peer, net, username, password).await {
                log::debug!("SOCKS connection from {peer} failed: {error:#}");
            }
        });
    }
}

async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    net: Arc<VirtualNet>,
    username: Option<String>,
    password: Option<String>,
) -> Result<()> {
    let relay_ip = stream.local_addr()?.ip();
    let protocol = match (username, password) {
        (Some(username), Some(password)) => {
            Socks5ServerProtocol::accept_password_auth(stream, move |user, pass| {
                user == username && pass == password
            })
            .await?
            .0
        }
        (None, None) => Socks5ServerProtocol::accept_no_auth(stream).await?,
        _ => anyhow::bail!("SOCKS username and password must be configured together"),
    };

    let (protocol, command, target) = protocol.read_command().await?;
    match command {
        Socks5Command::TCPConnect => serve_tcp_connect(protocol, target, net).await,
        Socks5Command::UDPAssociate => {
            serve_udp_associate(protocol, target, peer, relay_ip, net).await
        }
        Socks5Command::TCPBind => {
            protocol
                .reply_error(&ReplyError::CommandNotSupported)
                .await?;
            Ok(())
        }
    }
}

async fn serve_tcp_connect(
    protocol: Socks5ServerProtocol<TcpStream, CommandRead>,
    target: TargetAddr,
    net: Arc<VirtualNet>,
) -> Result<()> {
    let dial = match &target {
        TargetAddr::Ip(address) => net.dial_tcp(*address).await,
        TargetAddr::Domain(domain, port) => net.dial_host(domain, *port).await,
    };

    let mut remote = match dial {
        Ok(stream) => stream,
        Err(error) => {
            let reply = map_connect_error(&error);
            protocol.reply_error(&reply).await?;
            return Err(error.into());
        }
    };

    let bind = SocketAddr::from(([0, 0, 0, 0], 0));
    let mut client = protocol.reply_success(bind).await?;
    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

async fn serve_udp_associate(
    protocol: Socks5ServerProtocol<TcpStream, CommandRead>,
    requested_client: TargetAddr,
    control_peer: SocketAddr,
    relay_ip: std::net::IpAddr,
    net: Arc<VirtualNet>,
) -> Result<()> {
    let relay = UdpSocket::bind(SocketAddr::new(relay_ip, 0)).await?;
    let relay_addr = relay.local_addr()?;
    let mut control = protocol.reply_success(relay_addr).await?;
    let virtual_udp = net.bind_udp()?;
    log::debug!(
        "SOCKS UDP association for {control_peer}: relay={relay_addr}, WARP-side port={}",
        virtual_udp.local_port()
    );

    let requested_port = target_port_if_specified(&requested_client);
    let mut client_endpoint = requested_port.map(|port| SocketAddr::new(control_peer.ip(), port));
    let mut client_buffer = vec![0_u8; usize::from(u16::MAX)];
    let mut remote_buffer = vec![0_u8; usize::from(u16::MAX)];
    let mut control_byte = [0_u8; 1];
    let closed = net.wait_closed();
    tokio::pin!(closed);

    loop {
        tokio::select! {
            read = control.read(&mut control_byte) => {
                match read? {
                    0 => return Ok(()),
                    _ => anyhow::bail!(
                        "unexpected data on SOCKS UDP control connection from {control_peer}"
                    ),
                }
            }
            incoming = relay.recv_from(&mut client_buffer) => {
                let (size, source) = incoming?;
                if source.ip() != control_peer.ip() {
                    log::debug!(
                        "dropping SOCKS UDP datagram from {source}; control peer is {control_peer}"
                    );
                    continue;
                }
                if let Some(expected) = client_endpoint {
                    if source != expected {
                        log::debug!(
                            "dropping SOCKS UDP datagram from unexpected endpoint {source}; expected {expected}"
                        );
                        continue;
                    }
                } else {
                    client_endpoint = Some(source);
                }

                let (fragment, target, payload) = match parse_udp_request(&client_buffer[..size]).await {
                    Ok(request) => request,
                    Err(error) => {
                        log::debug!("dropping malformed SOCKS UDP datagram: {error}");
                        continue;
                    }
                };
                if fragment != 0 {
                    log::debug!("dropping fragmented SOCKS UDP datagram (FRAG={fragment})");
                    continue;
                }

                match resolve_udp_target(&net, target).await {
                    Ok(remote) => {
                        if let Err(error) = virtual_udp.send_to(payload, remote).await {
                            log::debug!("SOCKS UDP send to {remote} failed: {error}");
                        }
                    }
                    Err(error) => log::debug!("SOCKS UDP target resolution failed: {error}"),
                }
            }
            incoming = virtual_udp.recv_from(&mut remote_buffer) => {
                let (size, remote) = incoming?;
                let Some(client) = client_endpoint else {
                    continue;
                };
                let mut datagram = new_udp_header(remote)?;
                datagram.extend_from_slice(&remote_buffer[..size]);
                relay.send_to(&datagram, client).await?;
            }
            () = &mut closed => anyhow::bail!("userspace WARP network stopped"),
        }
    }
}

fn target_port_if_specified(target: &TargetAddr) -> Option<u16> {
    let port = match target {
        TargetAddr::Ip(address) => address.port(),
        TargetAddr::Domain(_, port) => *port,
    };
    (port != 0).then_some(port)
}

async fn resolve_udp_target(net: &Arc<VirtualNet>, target: TargetAddr) -> io::Result<SocketAddr> {
    match target {
        TargetAddr::Ip(address) => Ok(address),
        TargetAddr::Domain(domain, port) => {
            let address = net
                .resolve_all(&domain)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("no addresses for UDP target {domain}"),
                    )
                })?;
            Ok(SocketAddr::new(address, port))
        }
    }
}

fn map_connect_error(error: &io::Error) -> ReplyError {
    match error.kind() {
        io::ErrorKind::TimedOut => ReplyError::ConnectionTimeout,
        io::ErrorKind::ConnectionRefused => ReplyError::ConnectionRefused,
        io::ErrorKind::AddrNotAvailable | io::ErrorKind::NotFound => ReplyError::HostUnreachable,
        io::ErrorKind::NetworkUnreachable => ReplyError::NetworkUnreachable,
        _ => ReplyError::GeneralFailure,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_associate_uses_requested_port_when_nonzero() {
        assert_eq!(
            target_port_if_specified(&TargetAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 53000)))),
            Some(53000)
        );
        assert_eq!(
            target_port_if_specified(&TargetAddr::Ip(SocketAddr::from(([0, 0, 0, 0], 0)))),
            None
        );
    }

    #[test]
    fn maps_common_connect_errors_to_socks_replies() {
        assert!(matches!(
            map_connect_error(&io::Error::new(io::ErrorKind::TimedOut, "timeout")),
            ReplyError::ConnectionTimeout
        ));
        assert!(matches!(
            map_connect_error(&io::Error::new(io::ErrorKind::ConnectionRefused, "refused")),
            ReplyError::ConnectionRefused
        ));
        assert!(matches!(
            map_connect_error(&io::Error::new(io::ErrorKind::NotFound, "dns")),
            ReplyError::HostUnreachable
        ));
    }
}
