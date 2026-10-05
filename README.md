# usque-rs

A tiny Rust rewrite of my previous [usque](https://github.com/Diniboy1123/usque) project. The goal is simple: a decently fast, native tunnel using Cloudflare WARP and its MASQUE-based protocol.

The Rust client has four independently selectable application features: native Linux TUN, HTTP forward proxy, HTTPS CONNECT proxy, and SOCKS5/SOCKS5h proxy. Proxy modes use the direct L4 WARP endpoint: one shared QUIC/HTTP/3 connection is reused and each proxied TCP connection is an HTTP/3 CONNECT stream, so proxy builds do not carry a userspace IP/TCP stack.

Just like the Go based usque project, `nativetun` won't try to choose or replace your routes; you still control routing policy. The TUN IP addresses and MTU are configured for you.

Read [SETUP_NOTES.md](SETUP_NOTES.md) for my use-case.

## Cargo features

The default build enables all four runtime capabilities plus the registration command. The runtime capabilities can also be compiled independently, without registration-only HTTP/TLS dependencies:

```sh
# Native TUN only
cargo build --release --no-default-features --features tun

# Plain HTTP forward proxy only
cargo build --release --no-default-features --features http-proxy

# HTTPS CONNECT proxy only
cargo build --release --no-default-features --features https-proxy

# TCP-only SOCKS5/SOCKS5h proxy only
cargo build --release --no-default-features --features socks5-proxy

# Registration/enrollment utility only
cargo build --release --no-default-features --features register
```

Proxy-only builds do not compile `tun-rs`, rtnetlink, CONNECT-IP packet handling, or a userspace TCP/IP stack. A TUN-only build does not compile the proxy frontends, Hyper, or reqwest; a SOCKS5-only build likewise avoids Hyper and reqwest. Saved-config parsing remains available to every runtime build. The `register` feature is separate and is included in the default feature set for backwards compatibility.

## Proxy modes

All proxy listeners bind to loopback by default. Binding to a non-loopback address is explicit; if you do that, configure `--username` and `--password` together unless you deliberately want an unauthenticated proxy.

Start a SOCKS5 proxy:

```sh
usque-rs -c config.json socks
```

The distinction between SOCKS5 and SOCKS5h is made by the client. SOCKS5h hostnames are resolved with DNS-over-TCP through the same WARP L4 transport, so hostname resolution does not fall back to the host resolver. Repeat `--dns-server IP` to select resolvers; the default pair is `1.1.1.1` and `8.8.8.8`. Positive answers are cached with their DNS TTL in a bounded cache.

```sh
# Client-side DNS; the proxy receives an IP address.
curl --socks5 127.0.0.1:1080 https://example.com/

# Proxy-side tunneled DNS.
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

Direct L4 is TCP-only. SOCKS5 UDP ASSOCIATE is deliberately reported as unsupported rather than pulling CONNECT-IP and a userspace packet stack back into a SOCKS-only build.

Start the plaintext HTTP forward proxy:

```sh
usque-rs -c config.json http-proxy
curl --proxy http://127.0.0.1:8000 http://example.com/
```

Start the HTTPS CONNECT proxy:

```sh
usque-rs -c config.json https-proxy
curl --proxy http://127.0.0.1:8000 https://example.com/
```

When both `http-proxy` and `https-proxy` are compiled (including the default build), the `http-proxy` command also accepts CONNECT for backwards compatibility. `https-proxy` remains CONNECT-only.

Optional proxy authentication uses the same flags in all proxy modes:

```sh
usque-rs -c config.json socks --username alice --password secret
usque-rs -c config.json http-proxy --username alice --password secret
usque-rs -c config.json https-proxy --username alice --password secret
```

For authenticated curl tests, add `--proxy-user alice:secret`. Supplying only one of `--username` or `--password` is rejected. `--source-ip` pins the shared outer MASQUE UDP socket to a specific host address.

## Why the rewrite?

I wrote the Go version as a PoC research client back when I was mostly focused on proxies. Since then, I’ve moved countries and my local ISP doesn't provide native IPv6. I wanted to use WARP to fill that gap, but there isn't an official client for my platform yet.

Since my router is a literal **hot potato**, I wanted to get this working with zero copies. This project is basically just speedy glue that takes packets from the kernel, translates them to CONNECT-IP, and vice-versa.

## How it differs from the Go version

**usque (Go):**
- Reconnects if it loses the connection.
- Uses a hardcoded initial packet size.

**usque-rs (Rust):**
- Reconnects on-demand.
- Uses a conservative 1280-byte TUN MTU by default with a 1350-byte QUIC UDP payload ceiling; automatic PMTU growth is not currently enabled.

## Is it PQC ready?

**No.** It's not a priority right now. Lattice-based math usually eats more RAM and comes with much larger key sizes—two things I really don't want running on a resource-constrained router.

## Performance

Performance is measured with a two-tier end-to-end CONNECT-IP harness rather than process CPU alone. The primary metric is raw host-wide CPU seconds per steady inner-L3 Gbit, with separate low-end MT7621 and high-end EPYC targets, calibrated 8-second steady windows, quality/saturation gates, and pinned-stack A/B comparisons across usque, quiche, and tun-rs.

See [Performance benchmarking](docs/BENCHMARKING.md) for the complete methodology, calibration, profiler workflow, and representative results. Before proposing another native-TUN optimization, also search [Rejected, neutral, and superseded performance experiments](docs/REJECTED_OPTIMIZATIONS.md); it records the dead ends, policy variants, aliases, and conditions that would actually justify revisiting them.

As a separate field datapoint, the project has also saturated a 150 Mbit/s downstream / 30 Mbit/s upstream residential link on a `Cudy WR3000P v1` (MediaTek dual-core Cortex-A53). That observation is not used as controlled benchmark evidence.

## Release binaries

Building from source requires Rust 1.88 or newer.

x86-64 releases are built at three ISA levels:

- `usque-rs-x86_64-linux-musl`: portable baseline build.
- `usque-rs-x86_64-v2-linux-musl`: requires x86-64-v2.
- `usque-rs-x86_64-v3-linux-musl`: requires x86-64-v3.

Use the highest ISA level supported by the deployment CPU. CPU tuning is explicit in the release workflow; ordinary local builds are not silently compiled for the build machine.

## Disclaimer

Please do NOT use this tool for abuse. At the end of the day you hurt Cloudflare, which is probably unfair as you get this stuff even for free, secondly you will most likely get this tool sanctioned and ruin the fun for everyone.

The tool mimics certain properties of the official clients, those are mostly done for stability and compatibility reasons. I never intended to make this tool indistinguishable from the official clients. That means if they want to detect this tool, they can. I am not responsible for any consequences that may arise from using this tool. That is absolutely your own responsibility. I am not responsible for any damage that may occur to your system or your network. This tool is provided as is without any guarantees. Use at your own risk.

While the tool was made with security considerations in mind, I am not a security expert nor an IT professional. I am just a hobbyist and this is just a hobby project. Again, use at your own risk. However security reports are welcome. Feel free to open an issue with your contact details and I will get back to you, so you can share your findings **IN PRIVATE**. Once there was enough time to fix the issue, I will credit you in the release notes and the findings can be made public. I appreciate any help in making this tool more secure.

**This tool is not affiliated with Cloudflare in any way. The tool was neither endorsed nor reviewed by Cloudflare. It is an independent research project. Cloudflare Warp, Warp+, 1.1.1.1™, Cloudflare Access™, Cloudflare Gateway™ and Cloudflare One™ [are all registered trademarks/wordmarks](https://www.cloudflare.com/trademark/) of Cloudflare, Inc. If you are a Cloudflare employee and you think this project is in any way harmful, please open an issue and I will do my best to contact you and resolve the issue.**
