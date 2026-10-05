#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod config;
#[cfg(feature = "tun")]
pub mod icmp;
#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
pub mod l4;
#[cfg(feature = "tun")]
pub mod packet;
#[cfg(any(
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
pub mod proxy;
pub mod register;
pub mod tls;
#[cfg(feature = "tun")]
pub mod tun_device;
#[cfg(feature = "tun")]
pub mod tunnel;
#[cfg(any(
    feature = "tun",
    feature = "http-proxy",
    feature = "https-proxy",
    feature = "socks5-proxy"
))]
mod udp_socket;
