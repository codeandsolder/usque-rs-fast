# Proxy-origin DNS selection trace

SOCKS5h, HTTP CONNECT with a hostname, and direct-L4 hostname consumers
resolve through the shared `L4Client`. Ordinary SOCKS5 with a numeric target
does not exercise the proxy's DNS resolver. A SOCKS reply's `BND.ADDR` is a
bind-address field, **not** the target destination and must not be used to infer
which server was reached.

## Opt-in events

With a binary containing this implementation, enable only this logger target
**for the one selected proxy worker**:

```text
RUST_LOG=usque_rs::l4::route=debug
```

The existing `env_logger` initialization respects this environment setting.
There is no new listener, control port, mutation of WARP registrations, global
tracing overhead, or default change in logging. Production must not be
reconfigured just to perform a test; activating the setting on a managed
worker requires a separately approved deployment and operator-controlled
restart/rollout.

Each completed hostname-origin dial produces **one** debug event:

```text
event=origin_dial host="example.test" port=443 selected_ip=2001:db8::123 selected_peer=[2001:db8::123]:443 source=queried resolver=Some(1.1.1.1) record_type=Some(Aaaa) ttl_secs=Some(60) connected=true error_kind=None
```

This is illustrative, not a measured event. Fields are tied to the same
L4 request, so concurrent DNS races cannot misattribute the selected peer:

- `host`, `port`: requested host/SOCKS domain target, before remote DNS.
- `selected_ip`, `selected_peer`: the concrete address and port passed to
  the H3 CONNECT dialer, **not** the local SOCKS socket or public WARP exit IP.
- `source`: `queried` means the first successful proxy-side DNS-over-TCP
  response in the A/AAAA and upstream-server race; `cache` means the proxy's
  TTL-bounded host cache supplied the exact IP; `literal` means the caller
  supplied a numeric IP as a host string.
- `resolver`, `record_type`, `ttl_secs`: populated for a fresh winning DNS
  response; unavailable (not invented) for cache or literal results.
- `connected`, `error_kind`: whether H3 CONNECT accepted the selected peer,
  **not** whether origin TLS or an HTTP request succeeded.

If proxy-side DNS cannot choose an IP, `event=resolution_failed` logs the
requested host/port and error kind without falsely reporting a selected peer.
Literal-IP SOCKS5 `TargetAddr::Ip` skips `dial_host` and therefore does not emit
a hostname-resolution event.

This trace records requested domain names. Keep debugging scoped to a single
worker and a short bounded experiment; avoid collecting unrelated browsing
traffic. The log is opt-in and has no effect on SOCKS reply semantics.

## Controlled verification

Use `curl --socks5-hostname 127.0.0.1:PORT https://HOST/` to force domain
ATYP in SOCKS5. Match the emitted `origin_dial` record (host, selected IP,
source, success) to the observed HTTP response and to the same session's
owned-collector egress check. For strict family tests, remember `curl -6`
also constrains the **socket used to reach the proxy**: use an IPv6-reachable
proxy listener, e.g. `[::1]:PORT`. Remote DNS via SOCKS5h itself is not
strict IPv4/IPv6 unless the proxy resolver exposes that separate policy.

The selected IP is a real L4 dial target but not a complete DNS CNAME chain.
Do not represent this event as source-linked per-RR DNS provenance or as
proof that the WARP source IP is identical for all destinations.

Detailed research and rollout handoff:
https://app.notion.com/p/413f74be90208188a824e8c3554a8280
