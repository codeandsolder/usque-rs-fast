# OpenWrt: use WARP as the IPv6 upstream

This is the configuration I use when the ISP provides working IPv4 but no useful native IPv6: the router keeps its normal IPv4 WAN, creates a WARP TUN interface, gives LAN clients IPv6 from the router's local prefix, NAT66s that traffic to WARP's `/128`, and sends only the IPv6 default route through WARP.

This is an **example OpenWrt deployment**, not a generic networking recipe. OpenWrt releases and LuCI labels move around; the UCI commands below describe the state that matters.

## Before you start

A few things changed since the original version of this guide:

- There is **no `login` command anymore**. Registration and MASQUE enrollment happen automatically when `nativetun` first starts.
- Registrations are persisted in `--registration-store` and reused on later starts.
- The published release archives currently use the default Cargo feature set, which is SOCKS5/SOCKS5h only. For this guide you need a binary built with the `tun` feature.
- This setup deliberately uses the normal IPv4 WAN as the **outer** transport to Cloudflare. Do not add `--ipv6` to `nativetun` unless you actually have a working IPv6 underlay and know how you want to avoid routing the outer MASQUE connection back into the tunnel.

The router needs enough flash/RAM for the binary, a working system clock, ordinary IPv4 Internet access, and the TUN kernel module.

Install the OpenWrt prerequisites:

```sh
opkg update
opkg install kmod-tun ca-bundle
```

Verify that TUN support is present:

```sh
lsmod | grep '^tun '
ls -l /dev/net/tun
```

## 1. Build a TUN-enabled binary

On a matching Linux target:

```sh
cargo build --release --no-default-features --features tun
```

For an OpenWrt router, cross-compile for the router's actual architecture using your usual OpenWrt SDK/toolchain or `cross`. The repository's release workflow is a useful reference for the supported musl targets, including x86-64, AArch64, ARM, and little-endian MIPS.

Before copying the binary, confirm that it actually contains the TUN frontend:

```sh
./usque-rs nativetun --help
```

If `nativetun` is not present, you built the default proxy-only feature set rather than `--features tun`.

## 2. Install the binary

Create a persistent working directory on the router:

```sh
ssh root@192.168.1.1 'mkdir -p /root/usque'
```

Copy the TUN-enabled binary and make it executable:

```sh
scp ./usque-rs root@192.168.1.1:/root/usque/usque-rs
ssh root@192.168.1.1 'chmod 0755 /root/usque/usque-rs'
```

The examples below use an explicit registration store at `/root/usque/registrations`, so service startup does not depend on its current working directory.

## 3. Do one interactive smoke test

On the router:

```sh
cd /root/usque

./usque-rs \
  --registration-store /root/usque/registrations \
  nativetun \
  --no-tunnel-ipv4
```

On the first run, `usque-rs` automatically:

1. registers a WARP device over the router's normal IPv4 Internet connection;
2. enrolls the MASQUE key;
3. saves the identity under `/root/usque/registrations`; and
4. creates the TUN interface and assigns the WARP IPv6 address.

`--no-tunnel-ipv4` is intentional for this setup: IPv4 stays on the ISP WAN, while only WARP IPv6 is assigned to the tunnel.

In another shell, check the interface:

```sh
ip -6 addr show dev tun0
```

You should see the WARP `/128`. If you selected a custom interface name with `--interface-name`, use that name instead.

Stop the foreground test with `Ctrl-C` once registration and TUN creation are confirmed. The registration remains on disk and will be reused by the service.

## 4. Run usque-rs under procd

Create `/etc/init.d/usque-rs`:

```sh
cat >/etc/init.d/usque-rs <<'EOF'
#!/bin/sh /etc/rc.common

USE_PROCD=1
START=95
STOP=05

APP="/root/usque/usque-rs"
STORE="/root/usque/registrations"

start_service() {
    procd_open_instance

    procd_set_param command \
        "$APP" \
        --registration-store "$STORE" \
        nativetun \
        --no-tunnel-ipv4

    procd_set_param stdout 1
    procd_set_param stderr 1

    # OpenWrt's normal procd policy: if it repeatedly dies shortly after
    # startup, stop restart-looping; otherwise keep a long-running service up.
    procd_set_param respawn 3600 5 5

    procd_close_instance
}
EOF

chmod +x /etc/init.d/usque-rs
/etc/init.d/usque-rs enable
/etc/init.d/usque-rs start
```

Check it:

```sh
/etc/init.d/usque-rs status
logread -e usque-rs
ip -6 addr show dev tun0
```

The service runs in the foreground from procd's point of view; do not add `&`, daemonize it, or wrap it in another supervisor.

## 5. Tell netifd about `tun0`

Create an unmanaged logical OpenWrt interface backed by the TUN device:

```sh
uci -q delete network.warp
uci set network.warp='interface'
uci set network.warp.proto='none'
uci set network.warp.device='tun0'
uci commit network
service network reload
```

In LuCI this is the equivalent of adding an unmanaged interface named `WARP` whose device is `tun0`.

If you changed the usque interface name, use the same device here.

## 6. Give WARP its own firewall zone and enable NAT66

The old version of this guide put WARP into the existing `wan` zone. A dedicated zone is cleaner: it makes the IPv6-only policy explicit and avoids changing masquerading behavior for the physical WAN.

Create the zone and allow LAN forwarding into it:

```sh
uci -q delete firewall.warp
uci set firewall.warp='zone'
uci set firewall.warp.name='warp'
uci add_list firewall.warp.network='warp'
uci set firewall.warp.input='REJECT'
uci set firewall.warp.output='ACCEPT'
uci set firewall.warp.forward='REJECT'
uci set firewall.warp.masq6='1'

uci -q delete firewall.lan_warp
uci set firewall.lan_warp='forwarding'
uci set firewall.lan_warp.src='lan'
uci set firewall.lan_warp.dest='warp'

uci commit firewall
service firewall restart
```

Why NAT66? WARP gives this client a single routed IPv6 `/128`, not a delegated LAN prefix. LAN clients therefore use the router's own IPv6 prefix (normally its ULA), and firewall4 masquerades those client addresses to the WARP address on egress.

This is the same `masq6` mechanism documented by OpenWrt for IPv6 masquerading:

- <https://openwrt.org/docs/guide-user/network/ipv6/ipv6.nat6>
- <https://openwrt.org/docs/guide-user/firewall/firewall_configuration>

Because `warp` is an unmanaged TUN interface rather than a DHCPv6 WAN, the `wan6.sourcefilter=0` workaround from the generic OpenWrt NAT66 guide is not normally relevant here.

## 7. Advertise IPv6 on the LAN

If the ISP gives you no public IPv6 prefix, OpenWrt can still advertise its local/ULA prefix to LAN clients and tell them to use the router as the IPv6 default gateway.

For the normal `lan` section:

```sh
uci set dhcp.lan.ra='server'
uci set dhcp.lan.dhcpv6='server'
uci set dhcp.lan.ndp='disabled'

# Advertise a default route even though the router itself has no native
# globally-routable IPv6 prefix from the ISP.
uci set dhcp.lan.ra_default='1'

uci commit dhcp
service odhcpd restart
```

`ra_default=1` is the important part for this use case: it allows the router to advertise itself as the default IPv6 router despite having no native public prefix.

OpenWrt documents the option here:

- <https://openwrt.org/docs/guide-user/base-system/dhcp>
- <https://openwrt.org/docs/guide-user/network/ipv6/ipv6_extras>

You can leave SLAAC and the normal OpenWrt ULA generation at their defaults unless your LAN already has a deliberate IPv6 addressing plan.

## 8. Route the IPv6 default through WARP

Add an IPv6 default route tied to the logical `warp` interface:

```sh
uci -q delete network.warp_default
uci set network.warp_default='route6'
uci set network.warp_default.interface='warp'
uci set network.warp_default.target='::/0'
uci set network.warp_default.metric='10'

uci commit network
service network reload
```

The exact metric is not important when this is the only IPv6 upstream. A lower metric simply wins if you later add another IPv6 route.

At this point the intended split is:

```text
LAN IPv4  -> normal ISP WAN
LAN IPv6  -> router -> tun0 -> WARP -> Internet
```

## 9. Verify the whole path

On the router:

```sh
/etc/init.d/usque-rs status
ip -6 addr show dev tun0
ip -6 route show table all
ip -6 route get 2606:4700:4700::1111
nft list ruleset | grep -i -E 'warp|masquerade'
```

The route lookup for a public IPv6 destination should resolve through `tun0`/`warp`, not the physical WAN.

Then test from a LAN client:

```sh
curl -6 https://cloudflare.com/cdn-cgi/trace
```

or simply open any IPv6-only test site. IPv4 should still follow the ISP path.

Useful router-side diagnostics if it does not work:

```sh
logread -e usque-rs
logread -e odhcpd
uci show network
uci show firewall
uci show dhcp
ip -6 address show
ip -6 route show table all
ip -6 rule show
nft list ruleset
```

## Notes and variations

### Use a different TUN name

Pass, for example:

```sh
nativetun --no-tunnel-ipv4 --interface-name warp0
```

and replace `tun0` with `warp0` in the OpenWrt configuration.

### Manage TUN addresses yourself

`--no-iproute2` is a legacy-named option that tells `usque-rs` to skip its normal TUN address setup. The current implementation configures addresses through `tun-rs`; it does not literally require the `iproute2` userspace package.

For the setup in this document, **do not use `--no-iproute2`**.

### Bind the outer connection to a specific WAN source

If the router has several IPv4 uplinks, `--source-ip A.B.C.D` binds both first-time registration/enrollment and the outer MASQUE UDP socket to that source address.

Registrations are keyed by source by default. `--registration-key NAME` can instead keep one registered identity stable across deliberate source-address changes.

See the main [README](README.md) for the full registration model.

### Re-register deliberately

Normal restarts reuse the existing identity. If you actually want to replace it, stop the service and run once with the global `--reregister` option:

```sh
/etc/init.d/usque-rs stop

/root/usque/usque-rs \
  --registration-store /root/usque/registrations \
  --reregister \
  nativetun \
  --no-tunnel-ipv4
```

Once the replacement identity has been created and the TUN comes up, stop the foreground process and start the service again:

```sh
/etc/init.d/usque-rs start
```

Do not routinely delete or regenerate registrations on boot.

### Why not use the WARP IPv6 `/128` directly on the LAN?

Because it is a host address assigned to the WARP client, not a delegated prefix. There is no subnet to hand out to LAN devices. NAT66 from the LAN ULA is therefore the practical setup for this particular use case.

### procd behavior

The service definition follows OpenWrt's normal procd model: the child stays in the foreground, stdout/stderr go to syslog, and procd handles restarts.

OpenWrt's procd documentation is here:

- <https://openwrt.org/docs/guide-developer/procd-init-scripts>
