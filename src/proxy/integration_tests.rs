//! Local, deterministic wire-protocol integration tests.
//!
//! Each test connects over a real TCP (or TLS) listener to the production
//! proxy handler. The outer MASQUE transport alone is replaced by a loopback
//! L4 command driver, keeping CI independent of remote networks and secrets.

use crate::l4::L4Client;
use anyhow::{Result, ensure};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

#[cfg(any(feature = "http-proxy", feature = "https-proxy"))]
use super::http::HttpConfig;
#[cfg(feature = "https-proxy")]
use super::http::HttpsConfig;
#[cfg(any(feature = "http-proxy", feature = "https-proxy"))]
use tokio::io::AsyncRead;

const DEADLINE: Duration = Duration::from_secs(5);
const LOOPBACK: &str = "127.0.0.1:0";

fn test_l4() -> Result<Arc<L4Client>> {
    Ok(L4Client::loopback_test_client(&[(
        "origin.test",
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    )])?)
}

async fn echo_origin() -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind(LOOPBACK).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut peer, _) = timeout(DEADLINE, listener.accept()).await??;
        let (mut reader, mut writer) = peer.split();
        timeout(DEADLINE, tokio::io::copy(&mut reader, &mut writer)).await??;
        Ok(())
    });
    Ok((addr, task))
}

#[cfg(any(feature = "http-proxy", feature = "https-proxy"))]
async fn read_headers<T: AsyncRead + Unpin>(stream: &mut T) -> Result<String> {
    timeout(DEADLINE, async {
        let mut header = Vec::with_capacity(256);
        while !header.ends_with(b"\r\n\r\n") {
            ensure!(header.len() < 8192, "HTTP header exceeds test limit");
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await?;
            header.push(byte[0]);
        }
        Ok::<_, anyhow::Error>(String::from_utf8(header)?)
    })
    .await?
}

#[cfg(feature = "socks5-proxy")]
fn socks_config(username: Option<&str>, password: Option<&str>) -> super::socks::SocksConfig {
    super::socks::SocksConfig {
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        username: username.map(str::to_owned),
        password: password.map(str::to_owned),
        max_connections: 2,
        handshake_timeout: Duration::from_millis(250),
    }
}

#[cfg(feature = "socks5-proxy")]
async fn socks_auth(client: &mut TcpStream, credentials: Option<(&str, &str)>) -> Result<bool> {
    let method = if credentials.is_some() { 2 } else { 0 };
    // An actual fragmented SOCKS5 greeting, not an in-memory protocol mock.
    for byte in [5, 1, method] {
        client.write_all(&[byte]).await?;
        tokio::task::yield_now().await;
    }
    let mut reply = [0_u8; 2];
    timeout(DEADLINE, client.read_exact(&mut reply)).await??;
    ensure!(reply == [5, method], "SOCKS5 method reply {reply:?}");

    if let Some((username, password)) = credentials {
        let user_len = u8::try_from(username.len())?;
        let pass_len = u8::try_from(password.len())?;
        client.write_all(&[1, user_len]).await?;
        client.write_all(username.as_bytes()).await?;
        client.write_all(&[pass_len]).await?;
        client.write_all(password.as_bytes()).await?;
        timeout(DEADLINE, client.read_exact(&mut reply)).await??;
        return Ok(reply == [1, 0]);
    }
    Ok(true)
}

#[cfg(feature = "socks5-proxy")]
async fn socks_request(client: &mut TcpStream, command: u8, host: &str, port: u16) -> Result<u8> {
    let len = u8::try_from(host.len())?;
    let mut frame = vec![5, command, 0, 3, len];
    frame.extend_from_slice(host.as_bytes());
    frame.extend_from_slice(&port.to_be_bytes());
    client.write_all(&frame).await?;
    let mut response = [0_u8; 10];
    timeout(DEADLINE, client.read_exact(&mut response)).await??;
    ensure!(
        response[0] == 5 && response[2..4] == [0, 1],
        "bad SOCKS response"
    );
    Ok(response[1])
}

#[cfg(feature = "socks5-proxy")]
#[tokio::test]
async fn socks5h_no_auth_relay_through_real_socket() -> Result<()> {
    let (origin, origin_task) = echo_origin().await?;
    let server = super::socks::SocksServer::bind(socks_config(None, None), test_l4()?).await?;
    let mut client = TcpStream::connect(server.local_addr()).await?;
    ensure!(
        socks_auth(&mut client, None).await?,
        "no-auth negotiation rejected"
    );
    ensure!(socks_request(&mut client, 1, "origin.test", origin.port()).await? == 0);
    client.write_all(b"echo-through-l4").await?;
    let mut received = [0_u8; 15];
    timeout(DEADLINE, client.read_exact(&mut received)).await??;
    ensure!(&received == b"echo-through-l4");
    server.shutdown().await?;
    drop(client);
    timeout(DEADLINE, origin_task).await???;
    Ok(())
}

#[cfg(feature = "socks5-proxy")]
#[tokio::test]
async fn socks5_authenticated_rebind_and_unsupported_commands() -> Result<()> {
    let (origin, origin_task) = echo_origin().await?;
    let server =
        super::socks::SocksServer::bind(socks_config(Some("alice"), Some("secret")), test_l4()?)
            .await?;

    let mut rejected = TcpStream::connect(server.local_addr()).await?;
    ensure!(!socks_auth(&mut rejected, Some(("alice", "wrong"))).await?);
    drop(rejected);

    let mut unsupported = TcpStream::connect(server.local_addr()).await?;
    ensure!(socks_auth(&mut unsupported, Some(("alice", "secret"))).await?);
    ensure!(socks_request(&mut unsupported, 3, "origin.test", origin.port()).await? == 7);
    drop(unsupported);

    let previous = server.local_addr();
    let new_addr = server.rebind("127.0.0.1:0".parse()?).await?;
    ensure!(
        new_addr != previous,
        "rebind must select a new listener address"
    );
    let mut client = TcpStream::connect(new_addr).await?;
    ensure!(socks_auth(&mut client, Some(("alice", "secret"))).await?);
    ensure!(socks_request(&mut client, 1, "origin.test", origin.port()).await? == 0);
    server.shutdown().await?;
    // Shutdown stops accepting but does not interrupt an established relay.
    client.write_all(b"still-alive").await?;
    let mut echoed = [0_u8; 11];
    timeout(DEADLINE, client.read_exact(&mut echoed)).await??;
    ensure!(&echoed == b"still-alive");
    drop(client);
    timeout(DEADLINE, origin_task).await???;
    Ok(())
}

#[cfg(feature = "socks5-proxy")]
#[tokio::test]
async fn socks5_handshake_deadline_and_connection_cap() -> Result<()> {
    let mut config = socks_config(None, None);
    config.max_connections = 1;
    config.handshake_timeout = Duration::from_millis(80);
    let server = super::socks::SocksServer::bind(config, test_l4()?).await?;

    let mut stuck = TcpStream::connect(server.local_addr()).await?;
    stuck.write_all(&[5]).await?;
    let mut rejected = TcpStream::connect(server.local_addr()).await?;
    let mut byte = [0_u8; 1];
    ensure!(timeout(DEADLINE, rejected.read(&mut byte)).await?? == 0);

    // The held slot is eventually released by the total-handshake deadline.
    ensure!(timeout(DEADLINE, stuck.read(&mut byte)).await?? == 0);
    let mut recovered = TcpStream::connect(server.local_addr()).await?;
    ensure!(socks_auth(&mut recovered, None).await?);
    server.shutdown().await?;
    Ok(())
}

#[cfg(any(feature = "http-proxy", feature = "https-proxy"))]
fn http_config(username: Option<&str>, password: Option<&str>) -> Result<HttpConfig> {
    Ok(HttpConfig {
        bind: LOOPBACK.parse()?,
        username: username.map(str::to_owned),
        password: password.map(str::to_owned),
        max_connections: 2,
        header_timeout: Duration::from_millis(200),
    })
}

#[cfg(feature = "http-proxy")]
async fn http_server(config: HttpConfig) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind(LOOPBACK).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(super::http::serve_plain_on(listener, config, test_l4()?));
    Ok((addr, task))
}

#[cfg(feature = "http-proxy")]
#[tokio::test]
async fn http_forward_real_socket_strips_hop_by_hop_headers() -> Result<()> {
    let listener = TcpListener::bind(LOOPBACK).await?;
    let origin = listener.local_addr()?;
    let origin_task = tokio::spawn(async move {
        let (mut upstream, _) = timeout(DEADLINE, listener.accept()).await??;
        let request = read_headers(&mut upstream).await?;
        ensure!(
            request.starts_with("GET /resource HTTP/1.1\r\n"),
            "{request:?}"
        );
        ensure!(
            request.contains(&format!("host: 127.0.0.1:{}\r\n", origin.port()))
                || request.contains(&format!("Host: 127.0.0.1:{}\r\n", origin.port()))
        );
        ensure!(
            !request
                .to_ascii_lowercase()
                .contains("proxy-authorization:")
        );
        ensure!(!request.to_ascii_lowercase().contains("x-hop-only:"));
        upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
            .await?;
        Ok::<_, anyhow::Error>(())
    });
    let (addr, task) = http_server(http_config(Some("alice"), Some("secret"))?).await?;
    let mut client = TcpStream::connect(addr).await?;
    let request = format!(
        "GET http://127.0.0.1:{}/resource HTTP/1.1\r\nHost: wrong.invalid\r\nProxy-Authorization: bAsIc   YWxpY2U6c2VjcmV0\r\nConnection: x-hop-only, close\r\nx-hop-only: secret\r\n\r\n",
        origin.port()
    );
    client.write_all(request.as_bytes()).await?;
    let headers = read_headers(&mut client).await?;
    ensure!(headers.starts_with("HTTP/1.1 200"), "{headers}");
    let mut body = [0_u8; 5];
    timeout(DEADLINE, client.read_exact(&mut body)).await??;
    ensure!(&body == b"hello", "unexpected forwarded HTTP body");
    timeout(DEADLINE, origin_task).await???;
    task.abort();
    Ok(())
}

#[cfg(feature = "http-proxy")]
#[tokio::test]
async fn http_auth_rejection_and_header_deadline_over_tcp() -> Result<()> {
    let (addr, task) = http_server(http_config(Some("alice"), Some("secret"))?).await?;
    let mut wrong = TcpStream::connect(addr).await?;
    wrong.write_all(b"GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: Bearer invalid\r\n\r\n").await?;
    let response = read_headers(&mut wrong).await?;
    ensure!(response.starts_with("HTTP/1.1 407"), "{response}");
    ensure!(
        response
            .to_ascii_lowercase()
            .contains("proxy-authenticate: basic")
    );

    let mut stalled = TcpStream::connect(addr).await?;
    stalled.write_all(b"GET / HTTP/1.1\r\nHost: ").await?;
    let response = read_headers(&mut stalled).await?;
    ensure!(response.starts_with("HTTP/1.1 408"), "{response}");
    task.abort();
    Ok(())
}

#[cfg(feature = "http-proxy")]
#[tokio::test]
async fn http_connect_upgrade_relays_after_successful_response() -> Result<()> {
    let (origin, origin_task) = echo_origin().await?;
    let (addr, task) = http_server(http_config(None, None)?).await?;
    let mut client = TcpStream::connect(addr).await?;
    let req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        origin.port(),
        origin.port()
    );
    client.write_all(req.as_bytes()).await?;
    let response = read_headers(&mut client).await?;
    ensure!(response.starts_with("HTTP/1.1 200"), "{response}");
    client.write_all(b"CONNECT-echo").await?;
    let mut echoed = [0_u8; 12];
    timeout(DEADLINE, client.read_exact(&mut echoed)).await??;
    ensure!(&echoed == b"CONNECT-echo");
    drop(client);
    timeout(DEADLINE, origin_task).await???;
    task.abort();
    Ok(())
}

#[cfg(feature = "https-proxy")]
#[tokio::test]
async fn https_proxy_tls_connect_and_relay_over_real_socket() -> Result<()> {
    use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
    let (origin, origin_task) = echo_origin().await?;
    let folder = tempfile::tempdir()?;
    let certificate = folder.path().join("certificate.pem");
    let private_key = folder.path().join("private-key.pem");
    std::fs::write(
        &certificate,
        include_bytes!("../../tests/fixtures/loopback.cert.pem"),
    )?;
    std::fs::write(
        &private_key,
        include_bytes!("../../tests/fixtures/loopback.key.pem"),
    )?;
    let listener = TcpListener::bind(LOOPBACK).await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(super::http::serve_tls_on(
        listener,
        http_config(None, None)?,
        HttpsConfig {
            certificate,
            private_key,
        },
        test_l4()?,
    ));
    let mut builder = SslConnector::builder(SslMethod::tls())?;
    // The certificate is a test-only self-signed fixture. Test the actual TLS
    // framing/handshake, not a public PKI trust chain.
    builder.set_verify(SslVerifyMode::NONE);
    let config = builder.build().configure()?;
    let socket = TcpStream::connect(addr).await?;
    let mut client =
        timeout(DEADLINE, tokio_boring::connect(config, "localhost", socket)).await??;
    let req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: localhost\r\n\r\n",
        origin.port()
    );
    client.write_all(req.as_bytes()).await?;
    let response = read_headers(&mut client).await?;
    ensure!(response.starts_with("HTTP/1.1 200"), "{response}");
    client.write_all(b"tls-echo").await?;
    let mut echoed = [0_u8; 8];
    timeout(DEADLINE, client.read_exact(&mut echoed)).await??;
    ensure!(&echoed == b"tls-echo");
    drop(client);
    timeout(DEADLINE, origin_task).await???;
    server.abort();
    Ok(())
}
