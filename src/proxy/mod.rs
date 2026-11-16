#[cfg(any(feature = "http-proxy", feature = "https-proxy"))]
pub mod http;
#[cfg(feature = "socks5-proxy")]
pub mod socks;

use std::net::IpAddr;

/// Whether an address is permitted for an explicitly unauthenticated proxy listener.
#[must_use]
pub fn safe_no_auth_bind(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            a == 127
                || a == 10
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 198 && (b == 18 || b == 19))
        }
        IpAddr::V6(ip) => {
            let octets = ip.octets();
            ip.is_loopback()
                || (octets[0] & 0xfe) == 0xfc
                || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80)
        }
    }
}
