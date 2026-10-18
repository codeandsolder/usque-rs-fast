# usque-rs

High-performance, unofficial Rust client for Cloudflare WARP's MASQUE transports.

This repository (`codeandsolder/usque-rs-fast`) is a maintained fork of
[`Diniboy1123/usque-rs`](https://github.com/Diniboy1123/usque-rs), which is itself a Rust
rewrite of [`Diniboy1123/usque`](https://github.com/Diniboy1123/usque). The package and
binary are still named `usque-rs`.

The project now has two deliberately separate data paths:

- **Native TUN**: Linux TUN packets are carried with MASQUE CONNECT-IP.
- **Direct L4 proxies**: SOCKS5/SOCKS5h and HTTP(S) proxy connections map TCP streams
  directly onto Cloudflare's L4 HTTP/3 CONNECT service. Proxy-only builds do **not**
  carry a TUN device or userspace IP/TCP stack.

The emphasis of this fork is correctness first, then low CPU/memory overhead on small
routers and high-throughput hosts. Performance-sensitive changes are measured
end-to-end rather than accepted from microbenchmarks alone.

## Current capabilities

| Capability | Cargo feature | Runtime command | Notes |
| --- | --- | --- | --- |
| SOCKS5 / SOCKS5h proxy | `socks5-proxy` | `proxy` | **Default build**. TCP CONNECT only. |
| Plain HTTP proxy | `http-proxy` | `proxy` | HTTP forwarding and CONNECT. |
| TLS-wrapped HTTP proxy | `https-proxy` | `proxy` | HTTPS proxy transport; HTTP forwarding and CONNECT. |
| Native Linux TUN | `tun` | `nativetun` | CONNECT-IP, Linux only. |
| WARP registration / MASQUE enrollment | `register` | automatic | Included by every runtime feature. |

All selected proxy listeners in one process share a single outer QUIC/HTTP/3 session and
the same WARP egress identity.

### Important limitations

- This is an **unofficial** client. Cloudflare can change the service or protocol details.
- Native TUN is Linux-only.
- Direct L4 proxying is TCP-only. SOCKS5 `UDP ASSOCIATE` and `BIND` are not supported.
- There is no HTTP/2 fallback; the MASQUE paths here use QUIC/HTTP/3.
- `nativetun` configures the TUN device and its addresses, but **does not install or
  replace your routes**.
- The supported/default TUN MTU is `1280`. Other values are accepted with a warning;
  automatic PMTU growth is currently disabled.
- Published release artifacts currently use the default Cargo feature set, so they are
  SOCKS5/SOCKS5h builds. Build from source for TUN, HTTP, HTTPS, or combined binaries.

## Quick start

### SOCKS5/SOCKS5h

The default build contains only the SOCKS5 frontend plus the registration and direct-L4
transport it needs:

```sh
cargo build --release

./target/release/usque-rs proxy \
  --socks5-no-auth 127.0.0.1:1080
```

The first connection automatically creates and enrolls a WARP identity in
`./registrations/`. There is no separate `login` step in the current fork.

Test an IP-resolving SOCKS5 request:

```sh
curl --socks5 127.0.0.1:1080 https://example.com/
```

Or let the proxy resolve the hostname through DNS tunneled over WARP:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

For an authenticated listener:

```sh
./target/release/usque-rs proxy \
  --socks5 0.0.0.0:1080 \
  --username alice \
  --password 'correct horse battery staple'
```

`--socks5` always requires credentials. Use `--auth-file PATH` instead of
`--username`/`--password` if you do not want the password in argv. The file format is:

```text
username:password
```

### Native TUN

Build only the native TUN path:

```sh
cargo build --release --no-default-features --features tun
```

Creating/configuring a TUN device requires the usual Linux network privileges. For
example:

```sh
sudo ./target/release/usque-rs nativetun
```

`usque-rs` creates the interface, sets the selected WARP IPv4/IPv6 addresses and MTU,
and maintains the MASQUE tunnel. Routing policy remains yours.

Useful TUN options include:

```text
--interface-name NAME   choose the TUN interface name
--no-tunnel-ipv4       do not assign/use the WARP IPv4 address
--no-tunnel-ipv6       do not assign/use the WARP IPv6 address
--no-iproute2          skip TUN address setup; manage addresses yourself
--mtu N                TUN MTU (1280 is the supported/default value)
--ipv6                 use the IPv6 outer WARP/MASQUE endpoint
--source-ip IP         bind registration and outer MASQUE traffic to this source
```

The inherited [`SETUP_NOTES.md`](SETUP_NOTES.md) is useful as an OpenWrt routing
example, but it predates automatic registration. In particular, the old `login` step is
obsolete.

## Building

Rust **1.99 or newer** is required.

The project builds BoringSSL through Rust dependencies, so a source build also needs the
usual native build tools. CI installs the following on Ubuntu:

```sh
sudo apt-get install \
  cmake ninja-build golang-go perl pkg-config clang libclang-dev nasm
```

### Cargo feature combinations

```sh
# Default: SOCKS5/SOCKS5h only
cargo build --release

# Registration/enrollment library support only
cargo build --release --no-default-features --features register

# Native TUN only
cargo build --release --no-default-features --features tun

# Plain HTTP proxy only
cargo build --release --no-default-features --features http-proxy

# TLS-wrapped HTTP proxy only
cargo build --release --no-default-features --features https-proxy

# Explicit SOCKS5/SOCKS5h only
cargo build --release --no-default-features --features socks5-proxy

# All runtime frontends in one binary
cargo build --release --all-features
```

The feature split is real rather than cosmetic:

- proxy-only builds do not compile `tun-rs` or CONNECT-IP packet handling;
- TUN-only builds do not compile the proxy frontends;
- SOCKS5-only builds do not compile the HTTP proxy frontend;
- every runtime frontend pulls in `register`, because a fresh installation can enroll
  itself without a separate provisioning executable.

The binary uses a current-thread Tokio runtime. Runtime concurrency comes from
non-blocking I/O and the underlying protocol engines rather than a permanently
multi-threaded async executor.

## Registration and identity lifecycle

Registration is automatic and is intentionally tied to the selected outer source.

On startup, `usque-rs`:

1. derives a registration-store key;
2. takes a per-key cross-process lock;
3. reuses a valid cached MASQUE identity if one exists;
4. otherwise registers a WARP device through the selected source address;
5. enrolls a P-256 MASQUE key through that same source;
6. saves the resulting identity atomically; and
7. connects the requested TUN or direct-L4 transport.

The default registration store is:

```text
./registrations/
```

By default the cache key is transport-independent:

- no `--source-ip` -> `default-route`;
- IPv4 source -> a key derived from that IPv4 address;
- IPv6 source -> a key derived from that IPv6 address.

That means native CONNECT-IP and direct-L4 proxying reuse the same enrolled identity
when they use the same source.

### Stable identity across source rotation

`--registration-key NAME` decouples cache identity from the current source address:

```sh
usque-rs \
  --registration-key pool-g0-s3 \
  proxy \
  --ipv6 \
  --source-ip 2001:db8::1234 \
  --socks5-no-auth 127.0.0.1:1080
```

The initial cache miss still registers and enrolls through the selected `--source-ip`,
but later runs using the same registration key can move to another source address
without creating a new WARP identity.

Use `--reregister` to replace the selected cached identity deliberately.

Other global registration controls are available for the registration API metadata:

```text
--registration-store PATH
--registration-key NAME
--reregister
--registration-locale LOCALE
--registration-model MODEL
--registration-name NAME
--registration-jwt JWT
```

On Unix, the registration directory is tightened to mode `0700` and registration/lock
files to `0600`. Identity files contain private key and account material; treat the
directory accordingly.

## Source-address binding

`--source-ip` is stronger than merely binding the final UDP socket.

For a fresh identity, both registration/enrollment HTTP connections and the outer
MASQUE connection are bound to that source address. The source family must match the
selected outer endpoint family:

```sh
# IPv6 registration + IPv6 outer MASQUE transport
usque-rs proxy \
  --ipv6 \
  --source-ip 2001:db8::1234 \
  --socks5-no-auth 127.0.0.1:1080
```

Without `--source-ip`, normal host routing selects the source.

`--ipv6` selects the IPv6 **outer WARP endpoint**. It is independent of the target
address family carried inside the tunnel/proxy.

## Proxy architecture

Proxy mode uses Cloudflare's direct L4 service rather than constructing IP packets and
feeding them through CONNECT-IP.

Conceptually:

```text
SOCKS5 / HTTP / HTTPS listener
            |
            v
         L4Client
            |
            +-- TCP connection A -> HTTP/3 CONNECT stream A
            +-- TCP connection B -> HTTP/3 CONNECT stream B
            +-- DNS-over-TCP      -> HTTP/3 CONNECT stream(s)
            |
            v
      one shared QUIC/H3 session
            |
            v
            WARP
```

A single `proxy` process can expose several listeners while keeping one outer session:

```sh
usque-rs proxy \
  --socks5 127.0.0.1:1080 \
  --socks5-no-auth '[::1]:1081' \
  --http 127.0.0.1:8000 \
  --https 127.0.0.1:8443 \
  --tls-cert proxy-chain.pem \
  --tls-key proxy-key.pem \
  --username alice \
  --password secret
```

`--socks5` and `--socks5-no-auth` may be repeated. `--http` and `--https` each accept one
listener address.

The shared session has a 30-second keepalive by default (`--keepalive-period`) and uses
port 443 by default (`--connect-port`). Startup fails if the initial outer transport
cannot be established. The driver reconnects the outer session when needed after a
failure.

### SOCKS5 and SOCKS5h

The protocol distinction is chosen by the client:

- SOCKS5 with an IP target sends that IP directly.
- SOCKS5h sends a hostname to the proxy, and `usque-rs` resolves it through WARP.

Hostname resolution uses a small in-tree DNS-over-TCP codec over direct-L4 streams. It
does **not** fall back to the host resolver for SOCKS5h names.

By default queries race A and AAAA lookups against:

```text
1.1.1.1
8.8.8.8
```

Repeat `--dns-server IP` to provide a different resolver set. Positive results are
cached with their DNS TTL in a bounded cache.

Hostnames are expected in ASCII DNS form. Normal clients send internationalized names
as IDNA/punycode; raw non-ASCII names are rejected.

### Passwordless SOCKS listeners

`--socks5-no-auth` is deliberately limited to non-public namespaces. It accepts:

- IPv4 loopback;
- RFC1918 private IPv4;
- CGNAT/Tailscale `100.64.0.0/10`;
- IPv4 link-local;
- benchmark/lab `198.18.0.0/15`;
- IPv6 loopback;
- IPv6 ULA; and
- IPv6 link-local.

Wildcard, globally routable, multicast, and documentation-only addresses are rejected.

For compatibility, an open listener accepts either RFC1928 no-auth negotiation or an
RFC1929 username/password exchange; if credentials are presented to this explicitly
open listener, they are accepted and ignored.

### HTTP and HTTPS proxy listeners

Plain HTTP proxy:

```sh
usque-rs proxy --http 127.0.0.1:8000
curl --proxy http://127.0.0.1:8000 http://example.com/
```

TLS-wrapped HTTP proxy:

```sh
usque-rs proxy \
  --https 127.0.0.1:8443 \
  --tls-cert proxy-chain.pem \
  --tls-key proxy-key.pem

curl --proxy https://127.0.0.1:8443 \
  --proxy-cacert proxy-chain.pem \
  https://example.com/
```

`--https` means **TLS on the client-to-proxy connection**. It does not MITM target TLS.

Both HTTP listener types support:

- ordinary forward-proxy requests for `http://` targets; and
- `CONNECT` tunnels for HTTPS or arbitrary TCP destinations.

A non-CONNECT request whose target scheme is not HTTP is rejected; HTTPS destinations
should use CONNECT, as normal proxy clients do.

SOCKS5 and HTTP CONNECT relay application bytes unchanged, so the target sees the
client's TLS/application handshake rather than one generated by the proxy. Ordinary
HTTP forwarding necessarily parses and rewrites the proxy-form request and strips
hop-by-hop headers.

If `--username`/`--password` or `--auth-file` is supplied, HTTP(S) listeners require
matching HTTP Basic proxy authentication.

**Unlike `--socks5-no-auth`, HTTP/HTTPS listeners do not currently restrict the bind
address when authentication is absent. Do not expose an unauthenticated HTTP proxy on
an untrusted interface.**

## Native TUN architecture

The native path remains a CONNECT-IP dataplane:

```text
Linux network stack
       |
       v
   tun-rs TUN
       |
       v
packet validation / batching / GSO-GRO handling
       |
       v
 MASQUE CONNECT-IP over QUIC/H3
       |
       v
       WARP
```

The maintained dataplane includes Linux TUN offload support, receive/transmit batching,
UDP GSO handling where available, packet validation, ICMP handling, incremental checksum
updates, and the quiche/tun hot-path changes that survived correctness review and
end-to-end benchmarking.

The TUN is configured with the WARP `/32` IPv4 and `/128` IPv6 addresses unless disabled
with `--no-tunnel-ipv4`, `--no-tunnel-ipv6`, or address setup is skipped entirely with
`--no-iproute2`.

Routing is intentionally out of scope. This makes policy routing, split tunneling, and
"IPv6 through WARP while leaving IPv4 alone" configurations explicit rather than hidden
inside the client.

## Security-relevant behavior

A few implementation choices are worth knowing:

- the WARP endpoint public key from registration is pinned and checked during MASQUE
  setup;
- registration responses are size-bounded;
- registration API operations have explicit timeouts;
- registration files are written atomically and synced before replacement;
- a registration-store lock prevents concurrent processes from racing to create the
  same identity;
- authenticated SOCKS listeners reject missing credentials;
- explicit passwordless SOCKS listeners cannot bind globally routable addresses;
- proxy CONNECT paths do not terminate or inspect target TLS.

This is still an unofficial research/engineering client, not a security boundary you
should assume has received an external audit.

## Performance

The native TUN path is measured with a two-tier end-to-end CONNECT-IP harness rather
than process CPU alone.

The primary metric is **raw target-visible host CPU seconds per steady inner-L3 Gbit**,
with:

- a low-end MT7621/OpenWrt-class target;
- a high-end EPYC-class target;
- calibrated 8-second steady windows;
- one-second bins;
- quality/saturation gates; and
- pinned-stack A/B comparisons across usque, quiche, and tun-rs.

See [`docs/BENCHMARKING.md`](docs/BENCHMARKING.md) for the methodology, calibration,
profiler workflow, and representative results.

Before revisiting native-TUN optimization ideas, also check
[`docs/REJECTED_OPTIMIZATIONS.md`](docs/REJECTED_OPTIMIZATIONS.md). It records rejected,
neutral, superseded, or context-dependent experiments so the same dead ends do not need
to be rediscovered.

The direct-L4 proxy path was adopted after matched tests showed lower CPU/Gbit than
routing proxy TCP through a userspace packet stack and CONNECT-IP. The intended
optimization boundary is therefore now:

- **TUN traffic** -> optimize CONNECT-IP/TUN;
- **proxy TCP traffic** -> optimize direct L4/H3 stream bridging.

A separate field datapoint from the original project remains useful for scale: the
native client saturated a 150 Mbit/s downstream / 30 Mbit/s upstream residential link on
a Cudy WR3000P v1 (MediaTek dual-core Cortex-A53). Treat that as an observation, not a
controlled benchmark result.

## Maintained dependency forks

This fork currently pins maintained revisions of:

- [`codeandsolder/quiche-fast`](https://github.com/codeandsolder/quiche-fast) for
  `quiche`, `octets`, and `datagram-socket`;
- [`codeandsolder/tun-rs-fast`](https://github.com/codeandsolder/tun-rs-fast); and
- [`codeandsolder/fast-socks5-fast`](https://github.com/codeandsolder/fast-socks5-fast).

Those pins are intentional. They carry correctness, portability, and/or measured
performance work that has not necessarily all landed in the corresponding upstream
projects yet. Do not assume replacing them with the latest crates.io/git head is a
behavior-preserving change.

## Releases

Tag builds publish Linux musl archives plus SHA-256 checksum files.

Current release targets are:

| Artifact family | Intended target |
| --- | --- |
| `usque-rs-x86_64-linux-musl` | portable x86-64 baseline |
| `usque-rs-x86_64-v2-linux-musl` | x86-64-v2 |
| `usque-rs-x86_64-v3-linux-musl` | x86-64-v3 |
| `usque-rs-x86_64-znver1-linux-musl` | AMD Zen / EPYC tuned |
| `usque-rs-x86_64-znver2-linux-musl` | AMD Zen 2 / EPYC tuned |
| `usque-rs-aarch64-linux-musl` | 64-bit ARM |
| `usque-rs-armv7-linux-musleabihf` | ARMv7 hard-float |
| `usque-rs-arm-linux-musleabi` | generic 32-bit ARM EABI |
| `usque-rs-armv5te-linux-musleabi` | ARMv5TE |
| `usque-rs-mipsel-linux-musl` | little-endian MIPS/OpenWrt-class routers |

The MIPS target uses nightly Rust with `build-std` because stable Rust no longer ships
the required standard library target. The normal project toolchain remains Rust 1.99.

x86 CPU tuning is explicit in the release workflow. Ordinary local builds are not
silently compiled for the build machine.

Again: release archives currently build the default feature set. If you need `tun`,
`http-proxy`, `https-proxy`, or a custom feature combination, build from source.

## Development and CI

The repository treats warnings and many common Rust foot-guns as hard failures. CI
checks formatting, strict Clippy, tests, the default build, the empty feature set, each
independently selectable feature, and the combined proxy feature set.

Useful local checks are:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features

cargo check --all-targets
cargo check --all-targets --no-default-features
cargo check --all-targets --no-default-features --features register
cargo check --all-targets --no-default-features --features tun
cargo check --all-targets --no-default-features --features http-proxy
cargo check --all-targets --no-default-features --features https-proxy
cargo check --all-targets --no-default-features --features socks5-proxy
cargo check --all-targets --no-default-features \
  --features http-proxy,https-proxy,socks5-proxy
```

The crate denies unsafe code in the main lint configuration and applies strict
correctness/style/performance/pedantic/nursery Clippy policy.

## Project lineage and scope

The original `usque-rs` was intentionally tiny: a fast native Rust TUN client for WARP
MASQUE. This fork grew because the same transport machinery was useful for more than a
TUN device and because there was substantial performance/correctness work to do around
the dataplane and its dependencies.

The important architectural constraint is that proxy support did **not** turn the
native client into a permanent userspace TCP/IP stack. Direct-L4 proxies and CONNECT-IP
TUN remain separate frontends over related WARP/MASQUE machinery, and Cargo features
let deployments compile only the path they actually need.

Higher-level exit-pool orchestration, multi-exit inventory, watchdogs, and routed `/128`
management intentionally live outside this repository. `usque-rs` is the transport
client; orchestration belongs in callers such as `warpproxy`.

## PQC

PQC is not currently a project goal. The client follows the WARP/MASQUE protocol path
implemented here and does not add its own post-quantum handshake layer.

## Disclaimer

Please do not use this tool for abuse. Apart from harming other people and services,
abuse makes unofficial protocol clients much more likely to be blocked for everyone.

The client mimics some properties of official WARP clients where needed for
compatibility and stability, but it is **not** intended to be indistinguishable from
them. Cloudflare can identify, rate-limit, change, or reject this client.

This software is provided as-is, without warranty. It manipulates networking state and
depends on an external service whose behavior is outside this project's control.

Security reports are welcome. Please disclose vulnerabilities privately first so there
is a reasonable opportunity to fix them before public discussion.

**This project is not affiliated with, endorsed by, or reviewed by Cloudflare, Inc.**
Cloudflare WARP, WARP+, 1.1.1.1, Cloudflare Access, Cloudflare Gateway, and Cloudflare
One are trademarks or registered trademarks of Cloudflare, Inc.
