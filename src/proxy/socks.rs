use crate::l4::L4Client;
use anyhow::Result;
use fast_socks5::{
    ReplyError, Socks5Command,
    server::{
        Socks5ServerProtocol, StandardAuthentication, StandardAuthenticationStarted,
        states::{Authenticated, CommandRead},
    },
    util::target_addr::TargetAddr,
};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};

#[derive(Clone, Debug)]
pub struct SocksConfig {
    pub bind: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
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
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, l4, username, password).await {
                log::debug!("SOCKS connection from {peer} failed: {error:#}");
            }
        });
    }
}

async fn serve_connection(
    stream: TcpStream,
    l4: Arc<L4Client>,
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
        (None, None) => accept_open_auth(stream).await?,
        _ => anyhow::bail!("SOCKS username and password must be configured together"),
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

async fn accept_open_auth<T>(stream: T) -> Result<Socks5ServerProtocol<T, Authenticated>>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let auth = Socks5ServerProtocol::start(stream)
        .negotiate_auth(StandardAuthentication::allow_no_auth(true))
        .await?;

    Ok(match auth {
        StandardAuthenticationStarted::NoAuthentication(auth) => {
            Socks5ServerProtocol::finish_auth(auth)
        }
        StandardAuthenticationStarted::PasswordAuthentication(auth) => {
            let (_username, _password, auth) = auth.read_username_password().await?;
            Socks5ServerProtocol::finish_auth(auth.accept().await?)
        }
    })
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    #[tokio::test]
    async fn open_listener_accepts_no_auth() -> Result<()> {
        let (server, mut client) = tokio::io::duplex(64);
        let task = tokio::spawn(async move { accept_open_auth(server).await });

        client.write_all(&[5, 1, 0]).await?;
        let mut reply = [0; 2];
        client.read_exact(&mut reply).await?;
        assert_eq!(reply, [5, 0]);

        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn open_listener_accepts_arbitrary_password_auth() -> Result<()> {
        let (server, mut client) = tokio::io::duplex(64);
        let task = tokio::spawn(async move { accept_open_auth(server).await });

        client.write_all(&[5, 1, 2]).await?;
        let mut method = [0; 2];
        client.read_exact(&mut method).await?;
        assert_eq!(method, [5, 2]);

        client.write_all(&[1, 1, b'u', 1, b'p']).await?;
        let mut auth = [0; 2];
        client.read_exact(&mut auth).await?;
        assert_eq!(auth, [1, 0]);

        task.await??;
        Ok(())
    }
}
