#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import socket
import struct
from dataclasses import dataclass


SOCKS_VERSION = 5
AUTH_METHOD_USERPASS = 2
CMD_UDP_ASSOCIATE = 3
ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4


@dataclass(frozen=True)
class SocksAddress:
    host: str
    port: int


def recv_exact(stream: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise RuntimeError(f"SOCKS control connection closed with {remaining} bytes pending")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_socks_address(stream: socket.socket, atyp: int) -> SocksAddress:
    if atyp == ATYP_IPV4:
        host = socket.inet_ntop(socket.AF_INET, recv_exact(stream, 4))
    elif atyp == ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, recv_exact(stream, 16))
    elif atyp == ATYP_DOMAIN:
        length = recv_exact(stream, 1)[0]
        host = recv_exact(stream, length).decode("ascii")
    else:
        raise RuntimeError(f"unsupported SOCKS address type {atyp}")
    port = struct.unpack("!H", recv_exact(stream, 2))[0]
    return SocksAddress(host, port)


def encode_socks_address(host: str, port: int) -> bytes:
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            raise ValueError("SOCKS domain name exceeds 255 bytes")
        return bytes([ATYP_DOMAIN, len(encoded)]) + encoded + struct.pack("!H", port)

    if isinstance(parsed, ipaddress.IPv4Address):
        return bytes([ATYP_IPV4]) + parsed.packed + struct.pack("!H", port)
    return bytes([ATYP_IPV6]) + parsed.packed + struct.pack("!H", port)


def parse_udp_payload(datagram: bytes) -> tuple[SocksAddress, bytes]:
    if len(datagram) < 4 or datagram[:2] != b"\x00\x00":
        raise RuntimeError("invalid SOCKS UDP reserved bytes")
    if datagram[2] != 0:
        raise RuntimeError(f"unexpected SOCKS UDP fragment {datagram[2]}")

    atyp = datagram[3]
    offset = 4
    if atyp == ATYP_IPV4:
        if len(datagram) < offset + 4 + 2:
            raise RuntimeError("truncated SOCKS UDP IPv4 header")
        host = socket.inet_ntop(socket.AF_INET, datagram[offset : offset + 4])
        offset += 4
    elif atyp == ATYP_IPV6:
        if len(datagram) < offset + 16 + 2:
            raise RuntimeError("truncated SOCKS UDP IPv6 header")
        host = socket.inet_ntop(socket.AF_INET6, datagram[offset : offset + 16])
        offset += 16
    elif atyp == ATYP_DOMAIN:
        if len(datagram) < offset + 1:
            raise RuntimeError("truncated SOCKS UDP domain length")
        length = datagram[offset]
        offset += 1
        if len(datagram) < offset + length + 2:
            raise RuntimeError("truncated SOCKS UDP domain header")
        host = datagram[offset : offset + length].decode("ascii")
        offset += length
    else:
        raise RuntimeError(f"unsupported SOCKS UDP address type {atyp}")

    port = struct.unpack("!H", datagram[offset : offset + 2])[0]
    offset += 2
    return SocksAddress(host, port), datagram[offset:]


def dns_query(name: str, transaction_id: int) -> bytes:
    labels = name.rstrip(".").split(".")
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    return (
        struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        + qname
        + struct.pack("!HH", 1, 1)
    )


def authenticate(stream: socket.socket, username: str, password: str) -> None:
    stream.sendall(bytes([SOCKS_VERSION, 1, AUTH_METHOD_USERPASS]))
    version, method = recv_exact(stream, 2)
    if (version, method) != (SOCKS_VERSION, AUTH_METHOD_USERPASS):
        raise RuntimeError(f"SOCKS method negotiation failed: version={version}, method={method}")

    user = username.encode()
    secret = password.encode()
    if not (1 <= len(user) <= 255 and 1 <= len(secret) <= 255):
        raise ValueError("username/password must be 1..255 bytes")
    stream.sendall(bytes([1, len(user)]) + user + bytes([len(secret)]) + secret)
    auth_version, status = recv_exact(stream, 2)
    if (auth_version, status) != (1, 0):
        raise RuntimeError(f"SOCKS username/password authentication failed: status={status}")


def udp_associate(stream: socket.socket) -> SocksAddress:
    request = bytes([SOCKS_VERSION, CMD_UDP_ASSOCIATE, 0, ATYP_IPV4]) + b"\x00" * 4 + b"\x00\x00"
    stream.sendall(request)
    version, reply, reserved, atyp = recv_exact(stream, 4)
    if version != SOCKS_VERSION or reserved != 0 or reply != 0:
        raise RuntimeError(
            f"UDP ASSOCIATE failed: version={version}, reply={reply}, reserved={reserved}"
        )
    return read_socks_address(stream, atyp)


def main() -> None:
    parser = argparse.ArgumentParser(description="End-to-end SOCKS5 UDP ASSOCIATE smoke test")
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=19082)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--dns-server", default="one.one.one.one")
    parser.add_argument("--query-name", default="example.com")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    proxy = (args.proxy_host, args.proxy_port)
    transaction_id = 0xC0DE

    with socket.create_connection(proxy, timeout=args.timeout) as control:
        control.settimeout(args.timeout)
        authenticate(control, args.username, args.password)
        relay = udp_associate(control)

        relay_host = relay.host
        if ipaddress.ip_address(relay_host).is_unspecified:
            relay_host = args.proxy_host

        family = socket.AF_INET6 if ":" in relay_host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.settimeout(args.timeout)
            bind_host = "::1" if family == socket.AF_INET6 else "127.0.0.1"
            udp.bind((bind_host, 0))

            query = dns_query(args.query_name, transaction_id)
            frame = (
                b"\x00\x00\x00"
                + encode_socks_address(args.dns_server, 53)
                + query
            )
            udp.sendto(frame, (relay_host, relay.port))
            response, _ = udp.recvfrom(65535)

    remote, payload = parse_udp_payload(response)
    if len(payload) < 12:
        raise RuntimeError("truncated DNS response")
    response_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", payload[:12])
    if response_id != transaction_id:
        raise RuntimeError(
            f"DNS transaction ID mismatch: got 0x{response_id:04x}, expected 0x{transaction_id:04x}"
        )
    if flags & 0x8000 == 0:
        raise RuntimeError("received DNS payload is not a response")
    if flags & 0x000F != 0:
        raise RuntimeError(f"DNS response has RCODE={flags & 0x000F}")
    if qdcount != 1 or ancount == 0:
        raise RuntimeError(f"unexpected DNS counts: qd={qdcount}, an={ancount}")

    print(
        "SOCKS5 UDP ASSOCIATE smoke passed: "
        f"relay={relay_host}:{relay.port}, remote={remote.host}:{remote.port}, answers={ancount}"
    )


if __name__ == "__main__":
    main()
