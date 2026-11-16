use crate::{l4::L4Client, proxy::safe_no_auth_bind};
use anyhow::Result;
use fast_socks5::{
    ReplyError, Socks5Command,
    server::{
        Socks5ServerProtocol,
        states::{Authenticated, CommandRead},
    },
    util::target_addr::TargetAddr,
};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc, oneshot, watch},
    task::JoinHandle,
};

// Includes plaintext authentication credentials; do not derive Debug.
#[derive(Clone)]
pub struct SocksConfig {
    pub bind: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Maximum number of concurrently accepted connections.
    pub max_connections: usize,
    /// Deadline for completing authentication and parsing the initial request.
    pub handshake_timeout: Duration,
}

impl SocksConfig {
    fn validate(&self, bind: SocketAddr) -> Result<()> {
        anyhow::ensure!(
            (1..=Semaphore::MAX_PERMITS).contains(&self.max_connections),
            "SOCKS connection limit must be between 1 and {}",
            Semaphore::MAX_PERMITS
        );
        anyhow::ensure!(
            !self.handshake_timeout.is_zero(),
            "SOCKS handshake timeout must be nonzero"
        );
        match (&self.username, &self.password) {
            (None, None) => validate_open_bind(bind),
            (Some(username), Some(password)) => {
                anyhow::ensure!(
                    (1..=255).contains(&username.len()) && (1..=255).contains(&password.len()),
                    "SOCKS RFC 1929 credentials must contain 1–255 bytes each"
                );
                Ok(())
            }
            _ => anyhow::bail!("SOCKS username and password must be configured together"),
        }
    }
}

// Immutable credentials are shared by accepted tasks. A connection only
// clones the Arc, not both plaintext strings.
struct Credentials {
    username: String,
    password: String,
}

fn validate_open_bind(bind: SocketAddr) -> Result<()> {
    anyhow::ensure!(
        safe_no_auth_bind(bind.ip()),
        "unauthenticated SOCKS listener cannot bind to {bind}"
    );
    Ok(())
}

enum ServerCommand {
    Rebind {
        listener: TcpListener,
        local_addr: SocketAddr,
        reply: oneshot::Sender<()>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

/// Running direct-L4 SOCKS server backed by one shared MASQUE session.
///
/// The listener address can be changed without reconnecting the [`L4Client`].
/// Existing accepted SOCKS connections are unaffected; only future accepts use
/// the replacement listener.
pub struct SocksServer {
    commands: mpsc::Sender<ServerCommand>,
    local_addr: watch::Receiver<SocketAddr>,
    requires_auth: bool,
    task: Option<JoinHandle<Result<()>>>,
}

impl SocksServer {
    /// Bind and start a SOCKS server over an existing L4 MASQUE client.
    ///
    /// # Errors
    /// Returns an error if policy/limits are invalid, or the listener cannot be bound or inspected.
    pub async fn bind(config: SocksConfig, l4: Arc<L4Client>) -> Result<Self> {
        config.validate(config.bind)?;
        let requires_auth = config.username.is_some();
        let listener = TcpListener::bind(config.bind).await?;
        let local_addr = listener.local_addr()?;
        let (command_tx, command_rx) = mpsc::channel(4);
        let (address_tx, address_rx) = watch::channel(local_addr);
        let task = tokio::spawn(run_server(listener, config, l4, command_rx, address_tx));
        Ok(Self {
            commands: command_tx,
            local_addr: address_rx,
            requires_auth,
            task: Some(task),
        })
    }

    /// Return the address currently used for new SOCKS connections.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        *self.local_addr.borrow()
    }

    /// Return whether the listener task is still running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.task.as_ref().is_some_and(|task| !task.is_finished())
    }

    /// Move future SOCKS accepts to a new local IP/port while preserving the
    /// existing shared MASQUE session and already accepted connections.
    ///
    /// The replacement socket is bound before the old listener is dropped, so
    /// a failed bind leaves the current listener untouched.
    ///
    /// # Errors
    /// Returns an error if the replacement violates the no-auth bind policy,
    /// cannot be bound or inspected, or cannot be delivered to the running task.
    pub async fn rebind(&self, bind: SocketAddr) -> Result<SocketAddr> {
        if !self.requires_auth {
            validate_open_bind(bind)?;
        }
        if bind == self.local_addr() {
            return Ok(bind);
        }
        let listener = TcpListener::bind(bind).await?;
        let local_addr = listener.local_addr()?;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(ServerCommand::Rebind {
                listener,
                local_addr,
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("SOCKS server task stopped"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("SOCKS server stopped before rebind completed"))?;
        Ok(local_addr)
    }

    /// Stop accepting new SOCKS connections and wait for the server task.
    ///
    /// Already accepted connection tasks are independent and may finish
    /// naturally after this method returns.
    ///
    /// # Errors
    /// Returns an error if the server task stopped unexpectedly or failed.
    pub async fn shutdown(mut self) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(ServerCommand::Shutdown { reply: reply_tx })
            .await
            .map_err(|_| anyhow::anyhow!("SOCKS server task stopped"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("SOCKS server stopped before shutdown completed"))?;
        self.join_task().await
    }

    /// Wait until the server task exits.
    ///
    /// # Errors
    /// Returns an error if the task is cancelled, panics, or the listener
    /// accept loop fails.
    pub async fn wait(mut self) -> Result<()> {
        self.join_task().await
    }

    async fn join_task(&mut self) -> Result<()> {
        let task = self
            .task
            .take()
            .ok_or_else(|| anyhow::anyhow!("SOCKS server task already joined"))?;
        task.await
            .map_err(|error| anyhow::anyhow!("SOCKS server task failed: {error}"))?
    }
}

impl Drop for SocksServer {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn run_server(
    mut listener: TcpListener,
    config: SocksConfig,
    l4: Arc<L4Client>,
    mut commands: mpsc::Receiver<ServerCommand>,
    local_addr: watch::Sender<SocketAddr>,
) -> Result<()> {
    log::info!(
        "direct-L4 SOCKS5/SOCKS5h proxy listening on {}",
        listener.local_addr()?
    );
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let handshake_timeout = config.handshake_timeout;
    let credentials = match (config.username, config.password) {
        (Some(username), Some(password)) => Some(Arc::new(Credentials { username, password })),
        (None, None) => None,
        _ => anyhow::bail!("SOCKS username and password must be configured together"),
    };
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    log::debug!("SOCKS connection rejected at concurrency limit");
                    continue;
                };
                let l4 = l4.clone();
                let credentials = credentials.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve_connection(stream, l4, credentials, handshake_timeout).await {
                        log::debug!("SOCKS connection from {peer} failed: {error:#}");
                    }
                });
            }
            command = commands.recv() => {
                match command {
                    Some(ServerCommand::Rebind { listener: replacement, local_addr: replacement_addr, reply }) => {
                        listener = replacement;
                        local_addr.send_replace(replacement_addr);
                        log::info!("direct-L4 SOCKS5/SOCKS5h proxy rebound to {replacement_addr}");
                        let _ignored = reply.send(());
                    }
                    Some(ServerCommand::Shutdown { reply }) => {
                        let _ignored = reply.send(());
                        return Ok(());
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

/// Serve TCP-only SOCKS5/SOCKS5h CONNECT requests over direct L4 MASQUE.
///
/// UDP ASSOCIATE is deliberately rejected: enabling it would require the old
/// packet/TCP-IP stack and defeat the direct-L4 feature boundary.
///
/// # Errors
/// Returns an error when the listener cannot be bound or accepted.
pub async fn serve(config: SocksConfig, l4: Arc<L4Client>) -> Result<()> {
    SocksServer::bind(config, l4).await?.wait().await
}

async fn serve_connection(
    stream: TcpStream,
    l4: Arc<L4Client>,
    credentials: Option<Arc<Credentials>>,
    handshake_timeout: Duration,
) -> Result<()> {
    let (protocol, command, target) =
        read_handshake(stream, credentials.as_deref(), handshake_timeout).await?;
    // Established relays no longer need the credential allocation, even if
    // they outlive the listener during a graceful shutdown.
    drop(credentials);
    match command {
        Socks5Command::TcpConnect => serve_tcp_connect(protocol, target, l4).await,
        Socks5Command::UdpAssociate | Socks5Command::TcpBind => {
            protocol
                .reply_error(&ReplyError::CommandNotSupported)
                .await?;
            Ok(())
        }
    }
}

async fn read_handshake<T>(
    stream: T,
    credentials: Option<&Credentials>,
    handshake_timeout: Duration,
) -> Result<(
    Socks5ServerProtocol<T, CommandRead>,
    Socks5Command,
    TargetAddr,
)>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    tokio::time::timeout(handshake_timeout, async move {
        let protocol = if let Some(credentials) = credentials {
            Socks5ServerProtocol::accept_password_auth(stream, |user, pass| {
                user == credentials.username.as_bytes() && pass == credentials.password.as_bytes()
            })
            .await?
        } else {
            accept_open_auth(stream).await?
        };
        Ok::<_, anyhow::Error>(protocol.read_command().await?)
    })
    .await
    .map_err(|_| anyhow::anyhow!("SOCKS5 handshake timed out"))?
}

async fn accept_open_auth<T>(stream: T) -> Result<Socks5ServerProtocol<T, Authenticated>>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    Ok(Socks5ServerProtocol::accept_no_auth(stream).await?)
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
    // RFC 1928 has no generic connect-timeout status: TTL expired (0x06)
    // describes an IP hop limit, not an application-level timeout.
    // TimedOut intentionally follows the generic failure fallback.
    match error.kind() {
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
            ReplyError::GeneralFailure
        ));
        assert_eq!(
            map_connect_error(&io::Error::new(io::ErrorKind::TimedOut, "timeout")).as_u8(),
            0x01,
        );
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
    async fn open_listener_does_not_accept_password_auth() -> Result<()> {
        let (server, mut client) = tokio::io::duplex(64);
        let task = tokio::spawn(async move { accept_open_auth(server).await });

        client.write_all(&[5, 1, 2]).await?;
        let mut method = [0; 2];
        client.read_exact(&mut method).await?;
        assert_eq!(method, [5, 0xff]);
        assert!(task.await?.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn open_listener_prefers_no_auth_even_if_password_is_offered() -> Result<()> {
        let (server, mut client) = tokio::io::duplex(64);
        let task = tokio::spawn(async move { accept_open_auth(server).await });

        client.write_all(&[5, 2, 2, 0]).await?;
        let mut method = [0; 2];
        client.read_exact(&mut method).await?;
        assert_eq!(method, [5, 0]);
        task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn incomplete_socks_handshake_expires() -> Result<()> {
        let (server, _client) = tokio::io::duplex(64);
        let result = read_handshake(server, None, Duration::from_millis(5)).await;
        assert!(matches!(result, Err(ref error) if error.to_string().contains("timed out")));
        Ok(())
    }

    #[tokio::test]
    async fn handshake_timeout_covers_command_after_method_selection() -> Result<()> {
        let (server, mut client) = tokio::io::duplex(64);
        let task =
            tokio::spawn(
                async move { read_handshake(server, None, Duration::from_millis(20)).await },
            );

        client.write_all(&[5, 1, 0]).await?;
        let mut method = [0; 2];
        client.read_exact(&mut method).await?;
        assert_eq!(method, [5, 0]);
        // Keep the socket open without sending a command; the *same* deadline
        // must cover both method negotiation and request framing.
        let result = task.await?;
        assert!(matches!(result, Err(ref error) if error.to_string().contains("timed out")));
        Ok(())
    }

    #[tokio::test]
    async fn password_authentication_is_verified_before_command_parsing() -> Result<()> {
        for authorized in [true, false] {
            let (server, mut client) = tokio::io::duplex(128);
            let task = tokio::spawn(async move {
                let credentials = Credentials {
                    username: "alice".to_owned(),
                    password: "correct".to_owned(),
                };
                read_handshake(server, Some(&credentials), Duration::from_secs(1)).await
            });
            client.write_all(&[5, 1, 2]).await?;
            let mut reply = [0; 2];
            client.read_exact(&mut reply).await?;
            assert_eq!(reply, [5, 2]);

            client.write_all(&[1, 5]).await?;
            client.write_all(b"alice").await?;
            let password = if authorized {
                b"correct".as_slice()
            } else {
                b"wrong".as_slice()
            };
            client.write_all(&[u8::try_from(password.len())?]).await?;
            client.write_all(password).await?;
            client.read_exact(&mut reply).await?;
            assert_eq!(reply, [1, u8::from(!authorized)]);

            if authorized {
                client.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80]).await?;
                let (_protocol, command, target) = task.await??;
                assert_eq!(command, Socks5Command::TcpConnect);
                assert_eq!(
                    target,
                    TargetAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 80)))
                );
            } else {
                assert!(task.await?.is_err());
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_sessions_share_one_credentials_allocation() -> Result<()> {
        let credentials = Arc::new(Credentials {
            username: "alice".to_owned(),
            password: "correct".to_owned(),
        });
        let (mut client_a, server_a) = tokio::io::duplex(128);
        let (mut client_b, server_b) = tokio::io::duplex(128);
        let credentials_a = Arc::clone(&credentials);
        let credentials_b = Arc::clone(&credentials);
        assert!(Arc::ptr_eq(&credentials_a, &credentials_b));

        let task_a = tokio::spawn(async move {
            read_handshake(server_a, Some(&credentials_a), Duration::from_secs(1)).await
        });
        let task_b = tokio::spawn(async move {
            read_handshake(server_b, Some(&credentials_b), Duration::from_secs(1)).await
        });

        for client in [&mut client_a, &mut client_b] {
            client.write_all(&[5, 1, 2]).await?;
            let mut reply = [0; 2];
            client.read_exact(&mut reply).await?;
            assert_eq!(reply, [5, 2]);
            client.write_all(&[1, 5]).await?;
            client.write_all(b"alice").await?;
            client.write_all(&[7]).await?;
            client.write_all(b"correct").await?;
            client.read_exact(&mut reply).await?;
            assert_eq!(reply, [1, 0]);
            client.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80]).await?;
        }
        let (_protocol, command_a, target_a) = task_a.await??;
        let (_protocol, command_b, target_b) = task_b.await??;
        assert_eq!(command_a, Socks5Command::TcpConnect);
        assert_eq!(command_b, Socks5Command::TcpConnect);
        let expected = TargetAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 80)));
        assert_eq!(target_a, expected);
        assert_eq!(target_b, expected);
        Ok(())
    }

    #[test]
    fn listener_configuration_enforces_open_bind_and_valid_limits() {
        let config = SocksConfig {
            bind: SocketAddr::from(([127, 0, 0, 1], 1080)),
            username: None,
            password: None,
            max_connections: 10,
            handshake_timeout: Duration::from_secs(10),
        };
        assert!(config.validate(config.bind).is_ok());
        assert!(
            config
                .validate(SocketAddr::from(([0, 0, 0, 0], 1080)))
                .is_err()
        );
        assert!(
            config
                .validate(SocketAddr::from(([8, 8, 8, 8], 1080)))
                .is_err()
        );
        let mut config = config;
        config.max_connections = 0;
        assert!(config.validate(config.bind).is_err());
        config.max_connections = 10;
        config.handshake_timeout = Duration::ZERO;
        assert!(config.validate(config.bind).is_err());
        config.handshake_timeout = Duration::from_secs(10);
        config.username = Some("u".to_owned());
        config.password = Some("p".to_owned());
        assert!(
            config
                .validate(SocketAddr::from(([0, 0, 0, 0], 1080)))
                .is_ok()
        );
        config.username = Some(String::new());
        assert!(config.validate(config.bind).is_err());
        config.username = Some("u".repeat(256));
        assert!(config.validate(config.bind).is_err());
    }
}
