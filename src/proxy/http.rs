use crate::l4::L4Client;
use anyhow::Result;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{HOST, HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
    server::conn::http1 as server_http1,
    service::service_fn,
};
#[cfg(feature = "http-proxy")]
use hyper::{Uri, client::conn::http1 as client_http1, header::CONNECTION};
use hyper_util::rt::TokioIo;
use std::{convert::Infallible, error::Error, net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;

type BoxError = Box<dyn Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

#[derive(Clone, Debug)]
pub struct HttpConfig {
    pub bind: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// Serve whichever HTTP proxy modes were compiled and enabled by the caller.
///
/// # Errors
/// Returns an error when authentication configuration is incomplete or the listener
/// cannot be bound or accepted.
pub async fn serve(
    config: HttpConfig,
    l4: Arc<L4Client>,
    allow_forward_http: bool,
    allow_connect: bool,
) -> Result<()> {
    let expected_auth = match (&config.username, &config.password) {
        (Some(username), Some(password)) => Some(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
        )),
        (None, None) => None,
        _ => anyhow::bail!("HTTP proxy username and password must be configured together"),
    };

    let listener = TcpListener::bind(config.bind).await?;
    log::info!("HTTP proxy listening on {}", config.bind);

    loop {
        let (stream, peer) = listener.accept().await?;
        let l4 = l4.clone();
        let expected_auth = expected_auth.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let l4 = l4.clone();
                let expected_auth = expected_auth.clone();
                async move {
                    Ok::<_, Infallible>(
                        handle(
                            request,
                            l4,
                            expected_auth.as_deref(),
                            allow_forward_http,
                            allow_connect,
                        )
                        .await,
                    )
                }
            });

            if let Err(error) = server_http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(false)
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await
            {
                log::debug!("HTTP proxy connection from {peer} failed: {error}");
            }
        });
    }
}

async fn handle(
    request: Request<Incoming>,
    l4: Arc<L4Client>,
    expected_auth: Option<&str>,
    allow_forward_http: bool,
    allow_connect: bool,
) -> Response<ProxyBody> {
    if let Some(expected) = expected_auth {
        let provided = request
            .headers()
            .get(PROXY_AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        if provided != Some(expected) {
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
        #[cfg(feature = "https-proxy")]
        if allow_connect {
            return handle_connect(request, l4).await;
        }
        let _ = allow_connect;
        return text_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "CONNECT proxy support is not compiled/enabled",
        );
    }

    #[cfg(feature = "http-proxy")]
    {
        if allow_forward_http {
            return handle_forward(request, l4).await;
        }
    }
    let _ = (request, l4, allow_forward_http);
    text_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "plain HTTP proxy support is not compiled/enabled",
    )
}

#[cfg(feature = "http-proxy")]
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

    let (mut sender, connection) =
        match client_http1::handshake::<_, Incoming>(TokioIo::new(remote)).await {
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

#[cfg(feature = "https-proxy")]
async fn handle_connect(request: Request<Incoming>, l4: Arc<L4Client>) -> Response<ProxyBody> {
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

#[cfg(any(feature = "http-proxy", feature = "https-proxy"))]
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

#[cfg(feature = "http-proxy")]
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

#[cfg(feature = "http-proxy")]
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

    #[cfg(feature = "http-proxy")]
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

    #[cfg(feature = "http-proxy")]
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
