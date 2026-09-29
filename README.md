# usque-rs

A tiny Rust rewrite of my previous [usque](https://github.com/Diniboy1123/usque) project. The goal is simple: a decently fast, native tunnel using Cloudflare WARP and its MASQUE-based protocol.

The Rust client supports both the Linux `nativetun` mode and userspace TCP proxy modes. The proxy path runs a dual-stack smoltcp network stack directly over the existing MASQUE CONNECT-IP session, so it does not require a host TUN device.

Just like the Go based usque project, `nativetun` won't try to choose or replace your routes; you still control routing policy. The TUN IP addresses and MTU are configured for you.

Read [SETUP_NOTES.md](SETUP_NOTES.md) for my use-case.

## Proxy modes

Both proxy listeners bind to loopback by default. Binding to a non-loopback address is explicit; if you do that, configure `--username` and `--password` together unless you deliberately want an unauthenticated proxy.

Start a SOCKS5 proxy:

```sh
usque-rs -c config.json socks
```

The distinction between SOCKS5 and SOCKS5h is made by the client, not by a separate server mode:

```sh
# curl resolves the hostname locally and sends an IP address to the proxy.
curl --socks5 127.0.0.1:1080 https://example.com/

# curl sends the hostname to usque-rs; DNS resolution happens inside the WARP-side userspace stack.
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

SOCKS5 UDP ASSOCIATE is also supported. UDP destinations may be literal IPv4/IPv6 addresses or domain names; domain targets are resolved through the tunneled WARP-side resolver. SOCKS UDP fragmentation (`FRAG != 0`) is not supported, but ordinary large UDP datagrams are carried using IP fragmentation/reassembly inside the userspace stack when needed.

Start the streaming HTTP/1.1 proxy:

```sh
usque-rs -c config.json http-proxy
```

It supports ordinary HTTP forwarding and HTTPS tunnelling with `CONNECT`:

```sh
curl --proxy http://127.0.0.1:8000 http://example.com/
curl --proxy http://127.0.0.1:8000 https://example.com/
```

Optional proxy authentication uses the same flags in both modes:

```sh
usque-rs -c config.json socks --username alice --password secret
usque-rs -c config.json http-proxy --username alice --password secret
```

For authenticated curl tests, add `--proxy-user alice:secret`. Supplying only one of `--username` or `--password` is rejected.

The proxy transport accepts the same WARP-side family controls as the native tunnel (`--ipv6`, `--no-tunnel-ipv4`, `--no-tunnel-ipv6`, `--connect-port`, `--sni-address`, `--keepalive-period`, and `--mtu`). Hostname targets use tunneled DNS and dual-stack connections use staggered IPv6/IPv4 connection attempts rather than waiting through a dead address family serially.

After building the binary, `tests/proxy_smoke.sh` runs authenticated SOCKS5, SOCKS5h, HTTP-forwarding, and HTTPS-CONNECT checks against a real WARP config. Set `USQUE_BIN` if the binary is outside `target/debug/usque-rs`, and pass a config path readable by the account running the test.

`--source-ip` pins the outer MASQUE UDP socket to a specific host address. Normal single-proxy use does not need it; remote pool mode uses it to preserve one routed source `/128` per WARP identity.

## Proxy pools

Pool operation is split into two explicit modes. Both reuse the same SOCKS5 userspace dataplane and keep one child process per WARP identity so one failed identity does not take the whole pool down.

`pool-offline` means **no central control plane**; it still needs Internet access to register and use WARP. It maintains the requested number of identities and exposes them only on localhost:

```sh
usque-rs pool-offline --dir ./usque-pool --count 4 --base-port 20000
```

The listeners are `127.0.0.1:20000`, `127.0.0.1:20001`, and so on. Re-running the command reuses identity configs under the pool directory instead of registering fresh identities. `inventory.json` records the local listeners. Add `--username` and `--password` if local clients should authenticate.

`pool-remote` ports the routed-`/128` lifecycle from `warpproxy`. It expects one or more routed IPv6 `/64` prefixes, adds per-slot `/128` addresses to the selected interface, pins both the listener and outer MASQUE socket to that `/128`, keeps only distinct observed WARP IPv4 egresses, and reports healthy proxies to the existing warp-orchestrator heartbeat/register API:

```sh
sudo usque-rs pool-remote \
  --prefix 2001:db8:1234:5678::/64 \
  --slots-per-prefix 10 \
  --auth-file /etc/warp-pool/auth \
  --psk-file /etc/warp-pool/psk \
  --orchestrator-url https://orchestrator.example
```

Remote mode requires root or equivalent `CAP_NET_ADMIN` permission to add the routed `/128` addresses. The auth file remains the legacy `username:password` format. By default `pool-remote` also reads the legacy `/etc/warp-pool/config.json`; existing `prefixes`, `orchestrator_url`, and optional `psk` values are accepted so an existing fleet does not need to be reconfigured. Explicit CLI values take priority; `ORCHESTRATOR_URL` remains an environment override, and `PREFIXES_CSV` is used when neither CLI nor the legacy config supplies prefixes.

The useful legacy layout is retained (`identities/group-N/slot-N/config.json`, `addresses/group-N.json`, and `state.json`), but Python self-update is intentionally not part of the Rust agent; binary deployment/versioning owns upgrades.


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

Still needs to be measured properly, but it is able to max out my 150 Mbit/s residential downstream and 30 Mbit/s upstream network on a `Cudy WR3000P v1` with some Mediatek 1.3 GHz Dual-Core Cortex-A53 CPU with a load avg of 0.4 during the speedtest. That is good enough for my goals. And memory usage was optimized for as less copies as possible.

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
