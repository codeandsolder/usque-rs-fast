use super::net::VirtualNet;
use anyhow::Result;
use fast_socks5::{
    server::Socks5ServerProtocol,
    util::target_addr::TargetAddr,
    ReplyError, Socks5Command,
};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Debug)]
pub struct SocksConfig {
    pub bind: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
}

pub async fn serve(config: SocksConfig, net: Arc<VirtualNet>) -> Result<()> {
    let listener = TcpListener::bind(config.bind).await?;
    log::info!("SOCKS5/SOCKS5h proxy listening on {}", config.bind);

    loop {
        let (stream, peer) = listener.accept().await?;
        let net = net.clone();
        let username = config.username.clone();
        let password = config.password.clone();

        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, net, username, password).await {
                log::debug!("SOCKS connection from {peer} failed: {error:#}");
            }
        });
    }
}

async fn serve_connection(
    stream: TcpStream,
    net: Arc<VirtualNet>,
    username: Option<String>,
    password: Option<String>,
) -> Result<()> {
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

    if command != Socks5Command::TCPConnect {
        protocol
            .reply_error(&ReplyError::CommandNotSupported)
            .await?;
        return Ok(());
    }

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
