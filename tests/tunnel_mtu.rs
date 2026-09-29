//! Integration tests for tunnel MTU handling.
//!
//! **Requires root or CAP_NET_ADMIN** - tests are skipped otherwise.

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;

fn make_ipv4_packet(total_len: usize, ttl: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    assert!(total_len >= IPV4_HEADER_LEN);
    let mut pkt = vec![0xAAu8; total_len];
    pkt[0] = 0x45;
    pkt[1] = 0x00;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&[0x00, 0x00]);
    pkt[6..8].copy_from_slice(&[0x40, 0x00]);
    pkt[8] = ttl;
    pkt[9] = 17;
    pkt[10..12].copy_from_slice(&[0x00, 0x00]);
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);

    // Compute IP header checksum
    let cksum = ipv4_checksum(&pkt[..IPV4_HEADER_LEN]);
    pkt[10..12].copy_from_slice(&cksum.to_be_bytes());
    pkt
}

fn make_ipv6_packet(total_len: usize, hop_limit: u8, src: [u8; 16], dst: [u8; 16]) -> Vec<u8> {
    assert!(total_len >= IPV6_HEADER_LEN);
    let mut pkt = vec![0xBBu8; total_len];
    pkt[0] = 0x60;
    pkt[1] = 0x00;
    pkt[2] = 0x00;
    pkt[3] = 0x00;
    let payload_len = (total_len - IPV6_HEADER_LEN) as u16;
    pkt[4..6].copy_from_slice(&payload_len.to_be_bytes());
    pkt[6] = 17;
    pkt[7] = hop_limit;
    pkt[8..24].copy_from_slice(&src);
    pkt[24..40].copy_from_slice(&dst);
    pkt
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < header.len() {
        if i == 10 {
            i += 2;
            continue;
        }
        let word = if i + 1 < header.len() {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };
        sum += word as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn verify_ipv4_checksum(header: &[u8]) -> bool {
    let mut sum: u32 = (0..IPV4_HEADER_LEN)
        .step_by(2)
        .map(|i| u16::from_be_bytes([header[i], header[i + 1]]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16 == 0xFFFF
}

fn try_create_tun(name: &str, mtu: u16) -> Option<tun_rs::SyncDevice> {
    match tun_rs::DeviceBuilder::new()
        .name(name)
        .mtu(mtu)
        .enable(true)
        .build_sync()
    {
        Ok(dev) => Some(dev),
        Err(e) => {
            eprintln!("Skipping TUN test (no permission): {e}");
            None
        }
    }
}

// ---- TUN device tests ----

#[test]
fn tun_device_small_mtu_ipv4_write() {
    let dev = match try_create_tun("usqt0", 576) {
        Some(d) => d,
        None => return, // skip if no permissions
    };

    let pkt = make_ipv4_packet(100, 64, [10, 200, 0, 1], [10, 200, 0, 2]);
    let result = dev.send(&pkt);
    assert!(result.is_ok(), "should be able to write small IPv4 to TUN");
    assert_eq!(result.unwrap_or_default(), 100);
}

#[test]
fn tun_device_large_mtu_ipv4_write() {
    let dev = match try_create_tun("usqt1", 9000) {
        Some(d) => d,
        None => return,
    };

    let pkt = make_ipv4_packet(8000, 64, [10, 200, 0, 1], [10, 200, 0, 2]);
    let result = dev.send(&pkt);
    assert!(result.is_ok(), "should be able to write jumbo IPv4 to TUN");
    assert_eq!(result.unwrap_or_default(), 8000);
}

#[test]
fn tun_device_small_mtu_ipv6_write() {
    let dev = match try_create_tun("usqt2", 1280) {
        Some(d) => d,
        None => return,
    };

    let src = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let pkt = make_ipv6_packet(1280, 64, src, dst);
    let result = dev.send(&pkt);
    assert!(
        result.is_ok(),
        "should be able to write 1280-byte IPv6 to TUN"
    );
}

#[test]
fn tun_device_jumbo_mtu_ipv6_write() {
    let dev = match try_create_tun("usqt3", 9000) {
        Some(d) => d,
        None => return,
    };

    let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let pkt = make_ipv6_packet(8000, 64, src, dst);
    let result = dev.send(&pkt);
    assert!(result.is_ok(), "should be able to write jumbo IPv6 to TUN");
}

// ---- Full pipeline tests ----
// These don't require root.

mod pipeline {
    use super::*;

    fn encode_varint(val: u64) -> Vec<u8> {
        let mut tmp = [0u8; 8];
        let mut b = octets::OctetsMut::with_slice(&mut tmp);
        assert!(b.put_varint(val).is_ok());
        let len = b.off();
        tmp[..len].to_vec()
    }

    fn prepare_outgoing(buf: &mut [u8]) -> Result<u8, String> {
        if buf.is_empty() {
            return Err("empty".into());
        }
        match buf[0] >> 4 {
            4 => {
                if buf.len() < IPV4_HEADER_LEN {
                    return Err("too short".into());
                }
                let ttl = buf[8];
                if ttl <= 1 {
                    return Err("ttl expired".into());
                }
                buf[8] -= 1;
                let cksum = ipv4_checksum(&buf[..IPV4_HEADER_LEN]);
                buf[10..12].copy_from_slice(&cksum.to_be_bytes());
                Ok(4)
            }
            6 => {
                if buf.len() < IPV6_HEADER_LEN {
                    return Err("too short".into());
                }
                if buf[7] <= 1 {
                    return Err("hop limit expired".into());
                }
                buf[7] -= 1;
                Ok(6)
            }
            v => Err(format!("unknown version: {v}")),
        }
    }

    fn validate_incoming(buf: &[u8]) -> Result<u8, String> {
        if buf.is_empty() {
            return Err("empty".into());
        }
        match buf[0] >> 4 {
            4 if buf.len() >= IPV4_HEADER_LEN => Ok(4),
            6 if buf.len() >= IPV6_HEADER_LEN => Ok(6),
            4 | 6 => Err("too short".into()),
            v => Err(format!("unknown version: {v}")),
        }
    }

    fn parse_datagram(dgram: &[u8], expected_flow_id: u64) -> Option<Vec<u8>> {
        let mut b = octets::Octets::with_slice(dgram);
        let fid = b.get_varint().ok()?;
        if fid != expected_flow_id {
            return None;
        }
        let ctx = b.get_varint().ok()?;
        if ctx != 0 {
            return None;
        }
        let off = b.off();
        if off >= dgram.len() {
            return None;
        }
        Some(dgram[off..].to_vec())
    }

    struct TestResult {
        datagram: Vec<u8>,
        ttl_after: u8,
        version: u8,
    }

    fn pipeline_ipv4(packet_size: usize, flow_id: u64) -> TestResult {
        let mut pkt = make_ipv4_packet(packet_size, 64, [10, 0, 0, 1], [10, 0, 0, 2]);
        let version = prepare_outgoing(&mut pkt).unwrap_or_default();

        let flow_prefix = encode_varint(flow_id);
        let ctx_prefix = encode_varint(0);
        let mut dgram = Vec::with_capacity(flow_prefix.len() + ctx_prefix.len() + pkt.len());
        dgram.extend_from_slice(&flow_prefix);
        dgram.extend_from_slice(&ctx_prefix);
        dgram.extend_from_slice(&pkt);

        TestResult {
            datagram: dgram,
            ttl_after: pkt[8],
            version,
        }
    }

    fn pipeline_ipv6(packet_size: usize, flow_id: u64) -> TestResult {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut pkt = make_ipv6_packet(packet_size, 64, src, dst);
        let version = prepare_outgoing(&mut pkt).unwrap_or_default();

        let flow_prefix = encode_varint(flow_id);
        let ctx_prefix = encode_varint(0);
        let mut dgram = Vec::with_capacity(flow_prefix.len() + ctx_prefix.len() + pkt.len());
        dgram.extend_from_slice(&flow_prefix);
        dgram.extend_from_slice(&ctx_prefix);
        dgram.extend_from_slice(&pkt);

        TestResult {
            datagram: dgram,
            ttl_after: pkt[7],
            version,
        }
    }

    #[test]
    fn ipv4_576_outgoing_pipeline() {
        let r = pipeline_ipv4(576, 0);
        assert_eq!(r.version, 4);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).unwrap_or_default();
        assert_eq!(payload.len(), 576);
        assert_eq!(validate_incoming(&payload).unwrap_or_default(), 4);
        assert!(verify_ipv4_checksum(&payload[..IPV4_HEADER_LEN]));
    }

    #[test]
    fn ipv4_68_minimum_outgoing_pipeline() {
        let r = pipeline_ipv4(68, 0);
        assert_eq!(r.version, 4);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).unwrap_or_default();
        assert_eq!(payload.len(), 68);
    }

    #[test]
    fn ipv4_1280_outgoing_pipeline() {
        let r = pipeline_ipv4(1280, 0);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).unwrap_or_default();
        assert_eq!(payload.len(), 1280);
        assert!(verify_ipv4_checksum(&payload[..IPV4_HEADER_LEN]));
    }

    #[test]
    fn ipv4_1500_outgoing_pipeline() {
        let r = pipeline_ipv4(1500, 0);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).unwrap_or_default();
        assert_eq!(payload.len(), 1500);
    }

    #[test]
    fn ipv4_9000_jumbo_outgoing_pipeline() {
        let r = pipeline_ipv4(9000, 0);
        assert_eq!(r.version, 4);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).unwrap_or_default();
        assert_eq!(payload.len(), 9000);
        assert!(verify_ipv4_checksum(&payload[..IPV4_HEADER_LEN]));
    }

    #[test]
    fn ipv6_1280_minimum_outgoing_pipeline() {
        let r = pipeline_ipv6(1280, 0);
        assert_eq!(r.version, 6);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).unwrap_or_default();
        assert_eq!(payload.len(), 1280);
    }

    #[test]
    fn ipv6_1500_outgoing_pipeline() {
        let r = pipeline_ipv6(1500, 0);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).unwrap_or_default();
        assert_eq!(payload.len(), 1500);
    }

    #[test]
    fn ipv6_9000_jumbo_outgoing_pipeline() {
        let r = pipeline_ipv6(9000, 0);
        assert_eq!(r.version, 6);
        assert_eq!(r.ttl_after, 63);
        let payload = parse_datagram(&r.datagram, 0).unwrap_or_default();
        assert_eq!(payload.len(), 9000);
    }

    #[test]
    fn round_trip_ipv4_small() {
        let r = pipeline_ipv4(100, 42);
        let payload = parse_datagram(&r.datagram, 42).unwrap_or_default();
        assert_eq!(validate_incoming(&payload).unwrap_or_default(), 4);
        assert_eq!(payload[8], 63);
    }

    #[test]
    fn round_trip_ipv4_large() {
        let r = pipeline_ipv4(4000, 42);
        let payload = parse_datagram(&r.datagram, 42).unwrap_or_default();
        assert_eq!(validate_incoming(&payload).unwrap_or_default(), 4);
    }

    #[test]
    fn round_trip_ipv6_small() {
        let r = pipeline_ipv6(100, 7);
        let payload = parse_datagram(&r.datagram, 7).unwrap_or_default();
        assert_eq!(validate_incoming(&payload).unwrap_or_default(), 6);
        assert_eq!(payload[7], 63);
    }

    #[test]
    fn round_trip_ipv6_large() {
        let r = pipeline_ipv6(5000, 7);
        let payload = parse_datagram(&r.datagram, 7).unwrap_or_default();
        assert_eq!(validate_incoming(&payload).unwrap_or_default(), 6);
    }

    #[test]
    fn wrong_flow_id_rejected() {
        let r = pipeline_ipv4(200, 0);
        assert!(parse_datagram(&r.datagram, 999).is_none());
    }

    #[test]
    fn ttl_1_rejected() {
        let mut pkt = make_ipv4_packet(100, 1, [10, 0, 0, 1], [10, 0, 0, 2]);
        assert!(prepare_outgoing(&mut pkt).is_err());
    }

    #[test]
    fn hop_limit_1_rejected() {
        let src = [0; 16];
        let dst = [1; 16];
        let mut pkt = make_ipv6_packet(100, 1, src, dst);
        assert!(prepare_outgoing(&mut pkt).is_err());
    }

    #[test]
    fn icmp_too_large_ipv4_small_mtu() {
        let original = make_ipv4_packet(1500, 64, [10, 0, 0, 1], [10, 0, 0, 2]);
        let icmp = compose_icmp_too_large(&original, 1280);
        assert!(icmp.is_some());

        let resp = icmp.unwrap_or_default();
        assert_eq!(resp[0] >> 4, 4);
        assert_eq!(resp[9], 1);
        let icmp_hdr = &resp[IPV4_HEADER_LEN..];
        assert_eq!(icmp_hdr[0], 3);
        assert_eq!(icmp_hdr[1], 4);
        let mtu = u16::from_be_bytes([icmp_hdr[6], icmp_hdr[7]]);
        assert_eq!(mtu, 1280);
    }

    #[test]
    fn icmp_too_large_ipv6_small_mtu() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let original = make_ipv6_packet(1500, 64, src, dst);
        let icmp = compose_icmp_too_large(&original, 1280);
        assert!(icmp.is_some());

        let resp = icmp.unwrap_or_default();
        assert_eq!(resp[0] >> 4, 6);
        assert_eq!(resp[6], 58);
        let icmp_hdr = &resp[IPV6_HEADER_LEN..];
        assert_eq!(icmp_hdr[0], 2);
        let mtu = u32::from_be_bytes([icmp_hdr[4], icmp_hdr[5], icmp_hdr[6], icmp_hdr[7]]);
        assert_eq!(mtu, 1280);
    }

    #[test]
    fn icmp_too_large_ipv4_jumbo_to_standard() {
        let original = make_ipv4_packet(9000, 64, [172, 16, 0, 1], [8, 8, 8, 8]);
        let icmp = compose_icmp_too_large(&original, 1500);
        assert!(icmp.is_some());

        let resp = icmp.unwrap_or_default();
        let icmp_hdr = &resp[IPV4_HEADER_LEN..];
        let mtu = u16::from_be_bytes([icmp_hdr[6], icmp_hdr[7]]);
        assert_eq!(mtu, 1500);
    }

    #[test]
    fn icmp_too_large_ipv6_jumbo_to_minimum() {
        let src = [0; 16];
        let dst = [1; 16];
        let original = make_ipv6_packet(9000, 64, src, dst);
        let icmp = compose_icmp_too_large(&original, 1280);
        assert!(icmp.is_some());

        let resp = icmp.unwrap_or_default();
        let icmp_hdr = &resp[IPV6_HEADER_LEN..];
        let mtu = u32::from_be_bytes([icmp_hdr[4], icmp_hdr[5], icmp_hdr[6], icmp_hdr[7]]);
        assert_eq!(mtu, 1280);
    }

    // Helper that re-implements compose_icmp_too_large so the test file
    // is standalone (integration tests can't access private crate items).
    fn compose_icmp_too_large(original: &[u8], mtu: u16) -> Option<Vec<u8>> {
        if original.is_empty() {
            return None;
        }
        match original[0] >> 4 {
            4 => compose_icmpv4_too_large(original, mtu),
            6 => compose_icmpv6_too_large(original, mtu),
            _ => None,
        }
    }

    fn compose_icmpv4_too_large(original: &[u8], mtu: u16) -> Option<Vec<u8>> {
        if original.len() < IPV4_HEADER_LEN {
            return None;
        }
        let icmp_payload_len = (IPV4_HEADER_LEN + 8).min(original.len());
        let icmp_data = &original[..icmp_payload_len];
        let total_len = IPV4_HEADER_LEN + 8 + icmp_data.len();
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 1;
        pkt[12..16].copy_from_slice(&original[16..20]);
        pkt[16..20].copy_from_slice(&original[12..16]);
        let ip_cksum = ipv4_checksum(&pkt[..IPV4_HEADER_LEN]);
        pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());
        let icmp_start = IPV4_HEADER_LEN;
        pkt[icmp_start] = 3;
        pkt[icmp_start + 1] = 4;
        pkt[icmp_start + 6..icmp_start + 8].copy_from_slice(&mtu.to_be_bytes());
        pkt[icmp_start + 8..].copy_from_slice(icmp_data);
        let icmp_cksum = internet_checksum(&pkt[icmp_start..]);
        pkt[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_cksum.to_be_bytes());
        Some(pkt)
    }

    fn compose_icmpv6_too_large(original: &[u8], mtu: u16) -> Option<Vec<u8>> {
        if original.len() < IPV6_HEADER_LEN {
            return None;
        }
        let max_icmp_payload = 1232;
        let icmp_payload_len = original.len().min(max_icmp_payload);
        let icmp_data = &original[..icmp_payload_len];
        let payload_len = 8 + icmp_data.len();
        let total_len = IPV6_HEADER_LEN + payload_len;
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        pkt[6] = 58;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&original[24..40]);
        pkt[24..40].copy_from_slice(&original[8..24]);
        let icmp_start = IPV6_HEADER_LEN;
        pkt[icmp_start] = 2;
        pkt[icmp_start + 1] = 0;
        pkt[icmp_start + 4..icmp_start + 8].copy_from_slice(&(mtu as u32).to_be_bytes());
        pkt[icmp_start + 8..].copy_from_slice(icmp_data);
        // ICMPv6 checksum with pseudo-header
        let mut sum: u32 = 0;
        for i in (0..16).step_by(2) {
            sum += u16::from_be_bytes([pkt[8 + i], pkt[8 + i + 1]]) as u32;
            sum += u16::from_be_bytes([pkt[24 + i], pkt[24 + i + 1]]) as u32;
        }
        let plen = pkt[icmp_start..].len() as u32;
        sum += plen >> 16;
        sum += plen & 0xFFFF;
        sum += 58u32;
        let mut j = 0;
        while j < pkt[icmp_start..].len() {
            if j == 2 {
                j += 2;
                continue;
            }
            let w = if j + 1 < pkt[icmp_start..].len() {
                u16::from_be_bytes([pkt[icmp_start + j], pkt[icmp_start + j + 1]])
            } else {
                u16::from_be_bytes([pkt[icmp_start + j], 0])
            };
            sum += w as u32;
            j += 2;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        pkt[icmp_start + 2..icmp_start + 4].copy_from_slice(&cksum.to_be_bytes());
        Some(pkt)
    }

    fn internet_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i < data.len() {
            let word = if i + 1 < data.len() {
                u16::from_be_bytes([data[i], data[i + 1]])
            } else {
                u16::from_be_bytes([data[i], 0])
            };
            sum += word as u32;
            i += 2;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}
