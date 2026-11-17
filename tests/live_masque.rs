//! Real, opt-in MASQUE acceptance test against an operator-controlled HTTP observer.
//!
//! This test is ignored by default to keep routine CI deterministic and offline.
//! Refer to the README live acceptance section for its configuration and command.

#![cfg(any(feature = "socks5-proxy", feature = "http-proxy"))]

use anyhow::{Context, Result, ensure};
use std::{
    env,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
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
const DIRECT_PROBE_DEADLINE: Duration = Duration::from_secs(3);

/// Read the owned observer's complete Content-Length framed response.
/// This avoids waiting for connection EOF on HTTP/1.1 proxy keep-alive.
async fn observer_reply<T: AsyncRead + Unpin>(stream: &mut T) -> Result<IpAddr> {
    timeout(DEADLINE, async {
        let mut raw_headers = Vec::with_capacity(256);
        while !raw_headers.ends_with(b"\r\n\r\n") {
            ensure!(raw_headers.len() < 8192, "observer headers too large");
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await?;
            raw_headers.push(byte[0]);
        }
        let headers = String::from_utf8(raw_headers)?;
        ensure!(
            headers.starts_with("HTTP/1.1 200") || headers.starts_with("HTTP/1.0 200"),
            "unexpected observer response: {headers:?}"
        );
        let length = headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .context("owned observer must send a Content-Length header")?
            .1
            .trim()
            .parse::<usize>()?;
        ensure!(
            (7..=256).contains(&length),
            "unexpected observer body length"
        );
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await?;
        let exit_ip: IpAddr = String::from_utf8(body)?.trim().parse()?;
        ensure!(
            !exit_ip.is_loopback() && !exit_ip.is_unspecified(),
            "invalid observed WARP exit"
        );
        Ok::<_, anyhow::Error>(exit_ip)
    })
    .await
    .context("real WARP observer did not finish its response")?
}

#[tokio::test]
#[ignore = "requires a real enrolled WARP identity, routable source IP and operator-controlled observer"]
async fn real_masque_socks_and_http_egress() -> Result<()> {
    let config_path = env::var_os("USQUE_LIVE_CONFIG").context("set USQUE_LIVE_CONFIG")?;
    let source_ip: IpAddr = env::var("USQUE_LIVE_SOURCE_IP")
        .context("set USQUE_LIVE_SOURCE_IP")?
        .parse()?;
    let observer: SocketAddr = env::var("USQUE_LIVE_OBSERVER_ADDR")
        .context("set USQUE_LIVE_OBSERVER_ADDR")?
        .parse()
        .context("observer must be a literal SocketAddr")?;
    ensure!(observer.port() != 0, "observer must have a nonzero port");
    // The owned observer may deliberately allow WARP egress but reject
    // unproxied hosts. An optional direct probe helps distinguish sources
    // without mistakenly failing the WARP acceptance when it is restricted.
    let direct_ip = match timeout(DIRECT_PROBE_DEADLINE, async {
        let mut direct = TcpStream::connect(observer).await?;
        direct
            .write_all(b"GET /ip HTTP/1.1\r\nHost: observer\r\nConnection: close\r\n\r\n")
            .await?;
        observer_reply(&mut direct).await
    })
    .await
    {
        Ok(Ok(ip)) => {
            eprintln!("direct observer baseline exit: {ip}");
            Some(ip)
        }
        Ok(Err(error)) => {
            eprintln!("direct observer probe unavailable: {error:#}");
            None
        }
        Err(_) => {
            eprintln!("direct observer probe timed out (continuing via WARP)");
            None
        }
    };

    let config = Config::load(config_path)?;
    eprintln!("starting real MASQUE session for {source_ip}");
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
    eprintln!("real MASQUE transport session established");

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
        eprintln!("SOCKS5 CONNECT accepted over real MASQUE transport");
        client
            .write_all(b"GET /ip HTTP/1.1\r\nHost: observer\r\nConnection: close\r\n\r\n")
            .await?;
        let exit_ip = observer_reply(&mut client)
            .await
            .context("SOCKS5 observer response over real MASQUE stalled")?;
        eprintln!("real MASQUE SOCKS5 observer exit: {exit_ip}");
        if let Some(baseline_ip) = direct_ip {
            ensure!(
                exit_ip != baseline_ip,
                "SOCKS5 request did not exit through WARP"
            );
        }
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
        eprintln!("HTTP forward request sent over real MASQUE transport");
        let exit_ip = observer_reply(&mut client)
            .await
            .context("HTTP proxy observer response over real MASQUE stalled")?;
        eprintln!("real MASQUE HTTP observer exit: {exit_ip}");
        if let Some(baseline_ip) = direct_ip {
            ensure!(
                exit_ip != baseline_ip,
                "HTTP request did not exit through WARP"
            );
        }
        task.abort();
    }

    Ok(())
}
