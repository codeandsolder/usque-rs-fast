use crate::l4::L4Client;
use anyhow::Result;
use fast_socks5::{
    ReplyError, Socks5Command,
    server::{Socks5ServerProtocol, states::CommandRead},
    util::target_addr::TargetAddr,
};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Debug)]
pub struct SocksConfig {
    pub bind: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
    pub allow_passwordless_loopback: bool,
}

/// Serve TCP-only SOCKS5/SOCKS5h CONNECT requests over direct L4 MASQUE.
///
/// UDP ASSOCIATE is deliberately rejected: enabling it would require the old
/// packet/TCP-IP stack and defeat the direct-L4 feature boundary.
///
/// # Errors
/// Returns an error when the listener cannot be bound or accepted.
pub async fn serve(config: SocksConfig, l4: Arc<L4Client>) -> Result<()> {
    let listener = TcpListener::bind(config.bind).await?;
    log::info!(
        "direct-L4 SOCKS5/SOCKS5h proxy listening on {}",
        config.bind
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let l4 = l4.clone();
        let username = config.username.clone();
        let password = config.password.clone();
        let allow_passwordless_loopback = config.allow_passwordless_loopback;
        tokio::spawn(async move {
            if let Err(error) = serve_connection(
                stream,
                peer,
                l4,
                username,
                password,
                allow_passwordless_loopback,
            )
            .await
            {
                log::debug!("SOCKS connection from {peer} failed: {error:#}");
            }
        });
    }
}

async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    l4: Arc<L4Client>,
    username: Option<String>,
    password: Option<String>,
    allow_passwordless_loopback: bool,
) -> Result<()> {
    let protocol = if allow_passwordless_loopback && peer.ip().is_loopback() {
        Socks5ServerProtocol::accept_no_auth(stream).await?
    } else {
        match (username, password) {
            (Some(username), Some(password)) => {
                Socks5ServerProtocol::accept_password_auth(stream, move |user, pass| {
                    user == username && pass == password
                })
                .await?
                .0
            }
            (None, None) => Socks5ServerProtocol::accept_no_auth(stream).await?,
            _ => anyhow::bail!("SOCKS username and password must be configured together"),
        }
    };

    let (protocol, command, target) = protocol.read_command().await?;
    match command {
        Socks5Command::TCPConnect => serve_tcp_connect(protocol, target, l4).await,
        Socks5Command::UDPAssociate | Socks5Command::TCPBind => {
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
    l4: Arc<L4Client>,
) -> Result<()> {
    let dial = match &target {
        TargetAddr::Ip(address) => l4.dial_addr(*address).await,
        TargetAddr::Domain(domain, port) => l4.dial_host(domain, *port).await,
    };

    let mut remote = match dial {
        Ok(stream) => stream,
        Err(error) => {
            protocol.reply_error(&map_connect_error(&error)).await?;
            return Err(error.into());
        }
    };

    let bind = SocketAddr::from(([0, 0, 0, 0], 0));
    let mut client = protocol.reply_success(bind).await?;
    tokio::io::copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
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
    fn loopback_detection_covers_ipv4_and_ipv6_only() -> Result<()> {
        assert!("127.0.0.1:1234".parse::<SocketAddr>()?.ip().is_loopback());
        assert!("[::1]:1234".parse::<SocketAddr>()?.ip().is_loopback());
        assert!(!"192.0.2.1:1234".parse::<SocketAddr>()?.ip().is_loopback());
        assert!(
            !"[2001:db8::1]:1234"
                .parse::<SocketAddr>()?
                .ip()
                .is_loopback()
        );
        Ok(())
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
