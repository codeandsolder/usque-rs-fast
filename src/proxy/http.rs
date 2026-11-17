use crate::{l4::L4Client, proxy::safe_no_auth_bind};
use anyhow::Result;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{HOST, HeaderMap, HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
    server::conn::http1 as server_http1,
    service::service_fn,
};
use hyper::{Uri, client::conn::http1 as client_http1, header::CONNECTION};
use hyper_util::rt::{TokioIo, TokioTimer};
#[cfg(feature = "https-proxy")]
use std::path::PathBuf;
use std::{error::Error, net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
};

type BoxError = Box<dyn Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

// Credentials must never appear in automatically formatted Debug output.
#[derive(Clone)]
pub struct HttpConfig {
    pub bind: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Maximum simultaneous accepted connections, including upgraded CONNECT tunnels.
    pub max_connections: usize,
    /// Deadline for parsing each HTTP request header and for the TLS handshake.
    pub header_timeout: Duration,
}

impl HttpConfig {
    fn validate(&self, bind: SocketAddr) -> Result<()> {
        anyhow::ensure!(
            (1..=Semaphore::MAX_PERMITS).contains(&self.max_connections),
            "HTTP connection limit must be between 1 and {}",
            Semaphore::MAX_PERMITS
        );
        anyhow::ensure!(
            !self.header_timeout.is_zero(),
            "HTTP header timeout must be nonzero"
        );
        match (&self.username, &self.password) {
            (None, None) => {
                anyhow::ensure!(
                    safe_no_auth_bind(bind.ip()),
                    "unauthenticated HTTP(S) listener cannot bind to {bind}"
                );
            }
            (Some(username), Some(password)) => {
                anyhow::ensure!(
                    !username.is_empty() && !password.is_empty(),
                    "HTTP Basic username and password must be nonempty"
                );
                anyhow::ensure!(
                    !username.contains(':'),
                    "HTTP Basic username cannot contain ':'"
                );
                anyhow::ensure!(
                    !username.chars().any(char::is_control)
                        && !password.chars().any(char::is_control),
                    "HTTP Basic credentials cannot contain control characters"
                );
            }
            _ => anyhow::bail!("HTTP proxy username and password must be configured together"),
        }
        Ok(())
    }
}

#[cfg(feature = "https-proxy")]
#[derive(Clone, Debug)]
pub struct HttpsConfig {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

#[cfg(feature = "http-proxy")]
/// Serve a plaintext HTTP proxy listener.
///
/// # Errors
/// Returns an error when authentication configuration is incomplete or the listener
/// cannot be bound or accepted.
pub async fn serve_plain(config: HttpConfig, l4: Arc<L4Client>) -> Result<()> {
    config.validate(config.bind)?;
    let listener = TcpListener::bind(config.bind).await?;
    serve_plain_on(listener, config, l4).await
}

#[cfg(feature = "http-proxy")]
/// Serve a plaintext HTTP proxy on an already-bound listener.
///
/// This lets embedding applications reserve/validate the socket before the
/// accept loop starts instead of racing an asynchronously spawned bind.
///
/// # Errors
/// Returns an error when authentication configuration is incomplete or the
/// listener cannot be inspected or accepted.
pub async fn serve_plain_on(
    listener: TcpListener,
    config: HttpConfig,
    l4: Arc<L4Client>,
) -> Result<()> {
    let local_addr = listener.local_addr()?;
    config.validate(local_addr)?;
    let expected_auth = expected_basic_token(&config)?;
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let header_timeout = config.header_timeout;
    log::info!("HTTP proxy listening on {local_addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            log::debug!("HTTP proxy rejected a connection at the concurrency limit");
            continue;
        };
        let l4 = Arc::clone(&l4);
        let expected_auth = expected_auth.clone();
        tokio::spawn(async move {
            serve_connection(stream, peer, l4, expected_auth, header_timeout, permit).await;
        });
    }
}

#[cfg(feature = "https-proxy")]
/// Serve an HTTPS proxy: HTTP proxy semantics inside a TLS listener.
///
/// # Errors
/// Returns an error when TLS material cannot be loaded, authentication configuration
/// is incomplete, or the listener cannot be bound or accepted.
pub async fn serve_tls(config: HttpConfig, tls: HttpsConfig, l4: Arc<L4Client>) -> Result<()> {
    config.validate(config.bind)?;
    let listener = TcpListener::bind(config.bind).await?;
    serve_tls_on(listener, config, tls, l4).await
}

#[cfg(feature = "https-proxy")]
/// Serve an HTTPS proxy on an already-bound listener.
///
/// # Errors
/// Returns an error when TLS/authentication configuration is invalid or the
/// listener cannot be inspected or accepted.
pub async fn serve_tls_on(
    listener: TcpListener,
    config: HttpConfig,
    tls: HttpsConfig,
    l4: Arc<L4Client>,
) -> Result<()> {
    use boring::ssl::{AlpnError, SslAcceptor, SslFiletype, SslMethod, select_next_proto};

    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;
    builder.set_certificate_chain_file(&tls.certificate)?;
    builder.set_private_key_file(&tls.private_key, SslFiletype::PEM)?;
    builder.check_private_key()?;
    builder.set_alpn_select_callback(|_, client| {
        select_next_proto(b"\x08http/1.1", client).ok_or(AlpnError::NOACK)
    });
    let acceptor = Arc::new(builder.build());
    let local_addr = listener.local_addr()?;
    config.validate(local_addr)?;
    let expected_auth = expected_basic_token(&config)?;
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let header_timeout = config.header_timeout;
    log::info!("HTTPS proxy listening on {local_addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            log::debug!("HTTPS proxy rejected a connection at the concurrency limit");
            continue;
        };
        let acceptor = Arc::clone(&acceptor);
        let l4 = Arc::clone(&l4);
        let expected_auth = expected_auth.clone();
        tokio::spawn(async move {
            match tokio::time::timeout(header_timeout, tokio_boring::accept(&acceptor, stream))
                .await
            {
                Ok(Ok(stream)) => {
                    serve_connection(stream, peer, l4, expected_auth, header_timeout, permit).await;
                }
                Ok(Err(error)) => {
                    log::debug!("HTTPS proxy TLS handshake from {peer} failed: {error}");
                }
                Err(_) => {
                    log::debug!("HTTPS proxy TLS handshake from {peer} timed out");
                }
            }
        });
    }
}

fn expected_basic_token(config: &HttpConfig) -> Result<Option<Arc<str>>> {
    match (&config.username, &config.password) {
        (Some(username), Some(password)) => Ok(Some(Arc::from(
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}")),
        ))),
        (None, None) => Ok(None),
        _ => anyhow::bail!("HTTP proxy username and password must be configured together"),
    }
}

/// RFC 9110: auth-scheme is ASCII case-insensitive, separated from
/// the case-sensitive token68 by one or more SP characters.
fn matches_basic_proxy_auth(headers: &HeaderMap, expected_token: &str) -> bool {
    let mut values = headers.get_all(PROXY_AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(value) = value.to_str() else {
        return false;
    };
    // Ignore HTTP optional whitespace around the entire field value.
    let value = value.trim_matches([' ', '\t']);
    let Some((scheme, token)) = value.split_once(' ') else {
        return false;
    };
    scheme.eq_ignore_ascii_case("Basic") && token.trim_start_matches(' ') == expected_token
}

async fn serve_connection<I>(
    stream: I,
    peer: SocketAddr,
    l4: Arc<L4Client>,
    expected_auth: Option<Arc<str>>,
    header_timeout: Duration,
    permit: OwnedSemaphorePermit,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Hyper drops its connection driver after an HTTP CONNECT upgrade, but the
    // upgrade task continues relaying. Share the permit with that relay so it
    // remains counted until both halves have finished.
    let permit = Arc::new(permit);
    let service = service_fn(move |request| {
        let l4 = Arc::clone(&l4);
        let expected_auth = expected_auth.clone();
        let permit = Arc::clone(&permit);
        async move { Ok::<_, !>(handle(request, l4, expected_auth.as_deref(), permit).await) }
    });

    let mut builder = server_http1::Builder::new();
    builder
        .preserve_header_case(true)
        .title_case_headers(false)
        .timer(TokioTimer::new())
        .header_read_timeout(header_timeout);

    if let Err(error) = builder
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
    {
        log::debug!("HTTP proxy connection from {peer} failed: {error}");
    }
}

async fn handle(
    request: Request<Incoming>,
    l4: Arc<L4Client>,
    expected_auth: Option<&str>,
    permit: Arc<OwnedSemaphorePermit>,
) -> Response<ProxyBody> {
    if let Some(expected) = expected_auth {
        if !matches_basic_proxy_auth(request.headers(), expected) {
            let mut response =
                response_with_status(StatusCode::PROXY_AUTHENTICATION_REQUIRED, empty_body());
            response.headers_mut().insert(
                PROXY_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"usque-rs\""),
            );
            return response;
        }
    }

    if request.method() == Method::CONNECT {
        return handle_connect(request, l4, permit).await;
    }

    handle_forward(request, l4).await
}

async fn handle_forward(mut request: Request<Incoming>, l4: Arc<L4Client>) -> Response<ProxyBody> {
    let (host, port) = match request_target(&request, 80) {
        Ok(target) => target,
        Err(message) => return text_response(StatusCode::BAD_REQUEST, message),
    };

    if request
        .uri()
        .scheme_str()
        .is_some_and(|scheme| !scheme.eq_ignore_ascii_case("http"))
    {
        return text_response(
            StatusCode::BAD_REQUEST,
            "HTTPS proxy requests must use CONNECT",
        );
    }

    let remote = match l4.dial_host(&host, port).await {
        Ok(remote) => remote,
        Err(error) => {
            log::debug!("HTTP proxy dial to {host}:{port} failed: {error}");
            return text_response(StatusCode::BAD_GATEWAY, "upstream connection failed");
        }
    };

    let mut client_builder = client_http1::Builder::new();
    client_builder.preserve_header_case(true);
    let (mut sender, connection) = match client_builder
        .handshake::<_, Incoming>(TokioIo::new(remote))
        .await
    {
        Ok(parts) => parts,
        Err(error) => {
            log::debug!("HTTP upstream handshake failed: {error}");
            return text_response(StatusCode::BAD_GATEWAY, "upstream handshake failed");
        }
    };
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            log::debug!("HTTP upstream connection failed: {error}");
        }
    });

    if let Err(error) = rewrite_for_origin(&mut request) {
        return text_response(StatusCode::BAD_REQUEST, error);
    }
    strip_hop_by_hop(request.headers_mut());

    let response = match sender.send_request(request).await {
        Ok(response) => response,
        Err(error) => {
            log::debug!("HTTP upstream request failed: {error}");
            return text_response(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };

    let (mut parts, body) = response.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    Response::from_parts(
        parts,
        body.map_err(|error| -> BoxError { Box::new(error) })
            .boxed_unsync(),
    )
}

async fn handle_connect(
    request: Request<Incoming>,
    l4: Arc<L4Client>,
    permit: Arc<OwnedSemaphorePermit>,
) -> Response<ProxyBody> {
    let (host, port) = match request_target(&request, 443) {
        Ok(target) => target,
        Err(message) => return text_response(StatusCode::BAD_REQUEST, message),
    };

    let mut remote = match l4.dial_host(&host, port).await {
        Ok(remote) => remote,
        Err(error) => {
            log::debug!("HTTP CONNECT dial to {host}:{port} failed: {error}");
            return text_response(StatusCode::BAD_GATEWAY, "CONNECT upstream failed");
        }
    };

    let upgraded = hyper::upgrade::on(request);
    tokio::spawn(async move {
        let _permit = permit;
        match upgraded.await {
            Ok(stream) => {
                let mut client = TokioIo::new(stream);
                if let Err(error) = tokio::io::copy_bidirectional(&mut client, &mut remote).await {
                    log::debug!("HTTP CONNECT relay failed: {error}");
                }
            }
            Err(error) => log::debug!("HTTP CONNECT upgrade failed: {error}"),
        }
    });

    response_with_status(StatusCode::OK, empty_body())
}

fn request_target(
    request: &Request<Incoming>,
    default_port: u16,
) -> Result<(String, u16), &'static str> {
    if let Some(authority) = request.uri().authority() {
        return parse_authority(authority.as_str(), default_port);
    }

    let host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or("proxy request is missing a valid Host header")?;
    parse_authority(host, default_port)
}

fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16), &'static str> {
    if let Ok(address) = authority.parse::<SocketAddr>() {
        return Ok((address.ip().to_string(), address.port()));
    }

    if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or("invalid bracketed IPv6 authority")?;
        let host = &stripped[..end];
        let rest = &stripped[end + 1..];
        let port = if rest.is_empty() {
            default_port
        } else {
            rest.strip_prefix(':')
                .ok_or("invalid IPv6 authority")?
                .parse()
                .map_err(|_| "invalid proxy target port")?
        };
        return Ok((host.to_string(), port));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            let port = port.parse().map_err(|_| "invalid proxy target port")?;
            if host.is_empty() {
                return Err("empty proxy target host");
            }
            Ok((host.to_string(), port))
        }
        _ if !authority.is_empty() => Ok((authority.to_string(), default_port)),
        _ => Err("empty proxy target authority"),
    }
}

fn rewrite_for_origin<B>(request: &mut Request<B>) -> Result<(), &'static str> {
    let authority = request.uri().authority().cloned();
    let path_and_query = request
        .uri()
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);
    let origin_uri: Uri = path_and_query
        .parse()
        .map_err(|_| "invalid origin-form request URI")?;
    *request.uri_mut() = origin_uri;

    if let Some(authority) = authority {
        let host = HeaderValue::from_str(authority.as_str())
            .map_err(|_| "invalid proxy request authority")?;
        request.headers_mut().insert(HOST, host);
    }
    Ok(())
}

fn strip_hop_by_hop(headers: &mut hyper::HeaderMap) {
    let connection_tokens = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();

    for token in connection_tokens {
        headers.remove(token.as_str());
    }

    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn response_with_status(status: StatusCode, body: ProxyBody) -> Response<ProxyBody> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

fn text_response(status: StatusCode, message: &'static str) -> Response<ProxyBody> {
    response_with_status(
        status,
        Full::new(Bytes::from_static(message.as_bytes()))
            .map_err(|never| match never {})
            .boxed_unsync(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_form_request_rewrites_host_for_origin() -> Result<()> {
        let mut request = Request::builder()
            .uri("http://example.com:8080/path?q=1")
            .header(HOST, "wrong.example")
            .body(())?;

        rewrite_for_origin(&mut request).map_err(anyhow::Error::msg)?;

        assert_eq!(request.uri(), "/path?q=1");
        assert_eq!(
            request.headers().get(HOST),
            Some(&HeaderValue::from_static("example.com:8080"))
        );
        Ok(())
    }

    #[test]
    fn origin_form_request_keeps_existing_host() -> Result<()> {
        let mut request = Request::builder()
            .uri("/path")
            .header(HOST, "example.com")
            .body(())?;

        rewrite_for_origin(&mut request).map_err(anyhow::Error::msg)?;

        assert_eq!(request.uri(), "/path");
        assert_eq!(
            request.headers().get(HOST),
            Some(&HeaderValue::from_static("example.com"))
        );
        Ok(())
    }

    #[cfg(feature = "http-proxy")]
    #[test]
    fn strips_connection_named_hop_by_hop_headers() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            CONNECTION,
            HeaderValue::from_static("x-private, keep-alive"),
        );
        headers.append(CONNECTION, HeaderValue::from_static("x-private-later"));
        headers.insert("x-private", HeaderValue::from_static("secret"));
        headers.insert("x-private-later", HeaderValue::from_static("secret-too"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("x-end-to-end", HeaderValue::from_static("keep"));

        strip_hop_by_hop(&mut headers);

        assert!(!headers.contains_key(CONNECTION));
        assert!(!headers.contains_key("x-private"));
        assert!(!headers.contains_key("x-private-later"));
        assert!(!headers.contains_key("keep-alive"));
        assert_eq!(
            headers.get("x-end-to-end"),
            Some(&HeaderValue::from_static("keep"))
        );
    }

    #[test]
    fn open_http_listener_rejects_public_addresses_and_invalid_limits() -> Result<()> {
        let mut config = HttpConfig {
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            username: None,
            password: None,
            max_connections: 8,
            header_timeout: Duration::from_secs(5),
        };
        for address in [
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            SocketAddr::from(([192, 168, 1, 2], 8080)),
            SocketAddr::from(([100, 64, 0, 1], 8080)),
            "[fd00::1]:8080".parse()?,
        ] {
            assert!(config.validate(address).is_ok(), "{address}");
        }
        for address in [
            SocketAddr::from(([0, 0, 0, 0], 8080)),
            SocketAddr::from(([8, 8, 8, 8], 8080)),
            SocketAddr::from(([192, 0, 2, 2], 8080)),
            "[::]:8080".parse()?,
            "[2001:db8::1]:8080".parse()?,
        ] {
            assert!(config.validate(address).is_err(), "{address}");
        }
        config.max_connections = 0;
        assert!(config.validate(config.bind).is_err());
        config.max_connections = 8;
        config.header_timeout = Duration::ZERO;
        assert!(config.validate(config.bind).is_err());
        config.header_timeout = Duration::from_secs(5);
        config.username = Some("user".to_owned());
        assert!(config.validate(config.bind).is_err());
        config.password = Some("password".to_owned());
        assert!(
            config
                .validate(SocketAddr::from(([0, 0, 0, 0], 8080)))
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn basic_proxy_authorization_token_is_shared_without_string_copy() -> Result<()> {
        let config = HttpConfig {
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            username: Some("alice".to_owned()),
            password: Some("secret".to_owned()),
            max_connections: 4,
            header_timeout: Duration::from_secs(10),
        };
        let token =
            expected_basic_token(&config)?.ok_or_else(|| anyhow::anyhow!("missing token"))?;
        let per_connection = Arc::clone(&token);
        let per_request = Arc::clone(&per_connection);
        assert!(Arc::ptr_eq(&token, &per_request));
        assert_eq!(token.as_ref(), "YWxpY2U6c2VjcmV0");
        Ok(())
    }

    #[test]
    fn http_basic_scheme_is_case_insensitive_and_allows_multiple_spaces() {
        let expected = "YWxpY2U6c2VjcmV0";
        for value in [
            "Basic YWxpY2U6c2VjcmV0",
            "basic YWxpY2U6c2VjcmV0",
            "BASIC YWxpY2U6c2VjcmV0",
            "bAsIc    YWxpY2U6c2VjcmV0",
            "  basic YWxpY2U6c2VjcmV0   ",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(PROXY_AUTHORIZATION, HeaderValue::from_static(value));
            assert!(matches_basic_proxy_auth(&headers, expected), "{value:?}");
        }
    }

    #[test]
    fn http_basic_auth_rejects_wrong_tokens_schemes_and_duplicate_fields() {
        let expected = "YWxpY2U6c2VjcmV0";
        let mut headers = HeaderMap::new();
        assert!(!matches_basic_proxy_auth(&headers, expected));
        for value in [
            "Bearer YWxpY2U6c2VjcmV0",
            "Basic",
            "Basic ",
            "Basic  ",
            "Basic\tYWxpY2U6c2VjcmV0",
            "Basic YWxpY2U6c2VjcmV0 extra",
            "Basic YWxpY2U6c2VjcmV0, Basic YWxpY2U6c2VjcmV0",
            "Basic YWxpY2U6c2VjcmV1",
            "Basic YWxpY2U6c2Vjcmv0",
            "Basics YWxpY2U6c2VjcmV0",
            "BasicY WxpY2U6c2VjcmV0",
        ] {
            headers.insert(PROXY_AUTHORIZATION, HeaderValue::from_static(value));
            assert!(!matches_basic_proxy_auth(&headers, expected), "{value:?}");
        }
        headers.insert(
            PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic YWxpY2U6c2VjcmV0"),
        );
        headers.append(
            PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic YWxpY2U6c2VjcmV0"),
        );
        assert!(!matches_basic_proxy_auth(&headers, expected));
    }

    #[test]
    fn configured_basic_credentials_reject_nonrepresentable_usernames() {
        let mut config = HttpConfig {
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            username: Some("alice".to_owned()),
            password: Some("secret".to_owned()),
            max_connections: 8,
            header_timeout: Duration::from_secs(5),
        };
        assert!(config.validate(config.bind).is_ok());
        for username in ["", "alice:admin", "alice\radmin", "alice\tadmin"] {
            config.username = Some(username.to_owned());
            assert!(config.validate(config.bind).is_err(), "{username:?}");
        }
        config.username = Some("alice".to_owned());
        for password in ["", "secret\nnext", "secret\u{007f}"] {
            config.password = Some(password.to_owned());
            assert!(config.validate(config.bind).is_err(), "{password:?}");
        }
        config.password = Some("a:valid:password".to_owned());
        assert!(config.validate(config.bind).is_ok());
    }

    #[tokio::test]
    async fn connection_permit_survives_upgraded_tunnel_until_relay_finishes() -> Result<()> {
        let permits = Arc::new(Semaphore::new(1));
        let permit = Arc::new(Arc::clone(&permits).try_acquire_owned()?);
        let (client, mut proxy_client) = tokio::io::duplex(64);
        let (upstream, mut proxy_upstream) = tokio::io::duplex(64);
        let relay_permit = Arc::clone(&permit);
        let relay = tokio::spawn(async move {
            let _permit = relay_permit;
            tokio::io::copy_bidirectional(&mut proxy_client, &mut proxy_upstream).await
        });
        // The Hyper connection driver may already have returned after upgrade.
        drop(permit);
        assert!(Arc::clone(&permits).try_acquire_owned().is_err());

        drop(client);
        drop(upstream);
        relay.await??;
        assert!(Arc::clone(&permits).try_acquire_owned().is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn partial_http_headers_expire_under_tokio_timer() -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let (mut client, server) = tokio::io::duplex(256);
        let service = service_fn(|_| async { Ok::<_, !>(Response::new(Empty::<Bytes>::new())) });
        let task = tokio::spawn(async move {
            let mut builder = server_http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_millis(20));
            builder
                .serve_connection(TokioIo::new(server), service)
                .await
        });
        client.write_all(b"GET / HTTP/1.1\r\nHost: ").await?;
        // The client deliberately keeps the stream open with incomplete headers.
        let result = tokio::time::timeout(Duration::from_secs(1), task).await??;
        assert!(result.is_err(), "Hyper must reject the incomplete header");
        Ok(())
    }

    #[test]
    fn parses_domain_and_ipv6_authorities() -> Result<()> {
        assert_eq!(
            parse_authority("example.com:8443", 443).map_err(anyhow::Error::msg)?,
            ("example.com".to_string(), 8443)
        );
        assert_eq!(
            parse_authority("example.com", 443).map_err(anyhow::Error::msg)?,
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_authority("[2001:db8::1]:8080", 443).map_err(anyhow::Error::msg)?,
            ("2001:db8::1".to_string(), 8080)
        );
        Ok(())
    }
}
