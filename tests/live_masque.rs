//! Real, opt-in MASQUE acceptance test against an operator-controlled HTTP observer.
//!
//! Intentionally ignored by default: CI's offline socket suite remains entirely
//! deterministic. Set USQUE_LIVE_CONFIG, USQUE_LIVE_SOURCE_IP and
//! USQUE_LIVE_OBSERVER_ADDR, then run:
//! cargo +1.100.0 test --locked --no-default-features --features socks5-proxy,http-proxy
//!   --test live_masque -- --ignored --exact real_masque_socks_and_http_egress

#![cfg(any(feature = "socks5-proxy", feature = "http-proxy"))]

use anyhow::{Context, Result, ensure};
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
#[cfg(feature = "http-proxy")]
use tokio::net::TcpListener;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
#[cfg(feature = "http-proxy")]
use usque_rs::proxy::http::{self, HttpConfig};
#[cfg(feature = "socks5-proxy")]
use usque_rs::proxy::socks::{SocksConfig, SocksServer};
use usque_rs::{
    config::Config,
    l4::{L4Client, L4Config},
};

const DEADLINE: Duration = Duration::from_secs(40);

async fn http_reply<T: AsyncRead + Unpin>(stream: &mut T) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    timeout(DEADLINE, stream.read_to_end(&mut result))
        .await
        .context("timed out awaiting real WARP observer response")??;
    ensure!(
        result.starts_with(b"HTTP/1.1 200") || result.starts_with(b"HTTP/1.0 200"),
        "observer did not return HTTP 200: {:?}",
        String::from_utf8_lossy(&result[..result.len().min(100)])
    );
    Ok(result)
}

#[tokio::test]
#[ignore = "requires a real enrolled WARP identity, routable source IP and operator-controlled observer"]
async fn real_masque_socks_and_http_egress() -> Result<()> {
    let config_path = env::var_os("USQUE_LIVE_CONFIG").context("set USQUE_LIVE_CONFIG")?;
    let source_ip = env::var("USQUE_LIVE_SOURCE_IP")
        .context("set USQUE_LIVE_SOURCE_IP")?
        .parse()?;
    let observer: SocketAddr = env::var("USQUE_LIVE_OBSERVER_ADDR")
        .context("set USQUE_LIVE_OBSERVER_ADDR")?
        .parse()
        .context("observer must be a literal SocketAddr")?;
    ensure!(observer.port() != 0, "observer must have a nonzero port");
    let config = Config::load(config_path)?;
    let l4 = timeout(
        DEADLINE,
        L4Client::connect(
            config,
            &L4Config {
                use_ipv6_endpoint: source_ip.is_ipv6(),
                source_ip: Some(source_ip),
                ..L4Config::default()
            },
        ),
    )
    .await
    .context("timed out connecting real WARP MASQUE session")??;

    #[cfg(feature = "socks5-proxy")]
    {
        let server = SocksServer::bind(
            SocksConfig {
                bind: "127.0.0.1:0".parse()?,
                username: None,
                password: None,
                max_connections: 4,
                handshake_timeout: Duration::from_secs(10),
            },
            Arc::clone(&l4),
        )
        .await?;
        let mut client = TcpStream::connect(server.local_addr()).await?;
        client.write_all(&[5, 1, 0]).await?;
        let mut greeting = [0_u8; 2];
        timeout(DEADLINE, client.read_exact(&mut greeting)).await??;
        ensure!(greeting == [5, 0], "SOCKS5 no-auth greeting refused");
        let mut command = vec![5, 1, 0];
        match observer.ip() {
            std::net::IpAddr::V4(ip) => {
                command.push(1);
                command.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                command.push(4);
                command.extend_from_slice(&ip.octets());
            }
        }
        command.extend_from_slice(&observer.port().to_be_bytes());
        client.write_all(&command).await?;
        let mut response = [0_u8; 10];
        timeout(DEADLINE, client.read_exact(&mut response)).await??;
        ensure!(
            response[..2] == [5, 0],
            "SOCKS5 CONNECT failed: {response:?}"
        );
        client
            .write_all(b"GET /ip HTTP/1.1\r\nHost: observer\r\nConnection: close\r\n\r\n")
            .await?;
        let reply = http_reply(&mut client).await?;
        ensure!(reply.len() > 30, "empty observer response over SOCKS5");
        server.shutdown().await?;
    }

    #[cfg(feature = "http-proxy")]
    {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local = listener.local_addr()?;
        let task = tokio::spawn(http::serve_plain_on(
            listener,
            HttpConfig {
                bind: local,
                username: None,
                password: None,
                max_connections: 4,
                header_timeout: Duration::from_secs(10),
            },
            Arc::clone(&l4),
        ));
        let mut client = TcpStream::connect(local).await?;
        let request = format!(
            "GET http://{observer}/ip HTTP/1.1\r\nHost: observer\r\nConnection: close\r\n\r\n"
        );
        client.write_all(request.as_bytes()).await?;
        let reply = http_reply(&mut client).await?;
        ensure!(
            reply.len() > 30,
            "empty observer response over HTTP forward proxy"
        );
        task.abort();
    }

    Ok(())
}
