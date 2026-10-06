use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

const HEADER_LEN: usize = 12;
const CLASS_IN: u16 = 1;
const FLAG_QR: u16 = 0x8000;
const FLAG_RD: u16 = 0x0100;
const FLAG_TC: u16 = 0x0200;
const OPCODE_MASK: u16 = 0x7800;
const RCODE_MASK: u16 = 0x000f;
const RCODE_NXDOMAIN: u16 = 3;
const MAX_RECORDS: usize = 1024;
const MAX_POINTER_JUMPS: usize = 128;
const MAX_NAME_WIRE_LEN: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordType {
    A,
    Aaaa,
}

impl RecordType {
    const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }

    const fn address_len(self) -> usize {
        match self {
            Self::A => 4,
            Self::Aaaa => 16,
        }
    }
}

#[derive(Clone, Copy)]
struct CachedAddress {
    address: IpAddr,
    expires_at: Instant,
}

pub struct Cache {
    entries: Mutex<HashMap<String, CachedAddress>>,
    max_entries: usize,
}

impl Cache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    pub fn get(&self, host: &str) -> io::Result<Option<IpAddr>> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| io::Error::other("DNS cache lock poisoned"))?;
        let now = Instant::now();
        let address = match entries.get(host).copied() {
            Some(entry) if entry.expires_at > now => Some(entry.address),
            Some(_) => {
                entries.remove(host);
                None
            }
            None => None,
        };
        drop(entries);
        Ok(address)
    }

    pub fn insert(&self, host: &str, address: IpAddr, ttl: Duration) -> io::Result<()> {
        if ttl.is_zero() {
            return Ok(());
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| io::Error::other("DNS cache lock poisoned"))?;
        let now = Instant::now();
        if entries.len() >= self.max_entries && !entries.contains_key(host) {
            entries.retain(|_, entry| entry.expires_at > now);
            if entries.len() >= self.max_entries {
                entries.clear();
            }
        }
        let expires_at = now.checked_add(ttl).unwrap_or(now);
        entries.insert(
            host.to_owned(),
            CachedAddress {
                address,
                expires_at,
            },
        );
        drop(entries);
        Ok(())
    }
}

pub fn canonical_ascii_name(host: &str) -> io::Result<String> {
    if !host.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "non-ASCII hostname; supply an IDNA/punycode hostname",
        ));
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS hostname is empty",
        ));
    }
    validate_name(host)?;
    Ok(host.to_ascii_lowercase())
}

fn validate_name(host: &str) -> io::Result<()> {
    let mut wire_len = 1_usize;
    for label in host.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS hostname contains an empty label",
            ));
        }
        if bytes.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS label exceeds 63 bytes",
            ));
        }
        if bytes
            .iter()
            .any(|byte| byte.is_ascii_control() || *byte == b' ')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS hostname contains whitespace or control bytes",
            ));
        }
        wire_len = wire_len
            .checked_add(bytes.len() + 1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "DNS hostname too long"))?;
    }
    if wire_len > MAX_NAME_WIRE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS hostname exceeds 255 wire bytes",
        ));
    }
    Ok(())
}

pub fn build_query(host: &str, record_type: RecordType, id: u16) -> io::Result<Vec<u8>> {
    validate_name(host)?;
    let mut packet = Vec::with_capacity(HEADER_LEN + host.len() + 6);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&FLAG_RD.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    for label in host.split('.') {
        let len = u8::try_from(label.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS label too long"))?;
        packet.push(len);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&record_type.code().to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(packet)
}

pub fn parse_response(
    packet: &[u8],
    expected_id: u16,
    expected_name: &str,
    expected_type: RecordType,
) -> io::Result<Option<(IpAddr, Duration)>> {
    if packet.len() < HEADER_LEN {
        return Err(invalid_data("DNS response is shorter than its header"));
    }
    let id = read_u16(packet, 0)?;
    let flags = read_u16(packet, 2)?;
    let question_count = usize::from(read_u16(packet, 4)?);
    let answer_count = usize::from(read_u16(packet, 6)?);
    if id != expected_id || flags & FLAG_QR == 0 {
        return Err(invalid_data("DNS response does not match the request"));
    }
    if flags & OPCODE_MASK != 0 {
        return Err(invalid_data("DNS response uses an unsupported opcode"));
    }
    if flags & FLAG_TC != 0 {
        return Err(invalid_data(
            "DNS-over-TCP response is unexpectedly truncated",
        ));
    }
    if question_count != 1 {
        return Err(invalid_data(
            "DNS response has an unexpected question count",
        ));
    }
    if answer_count > MAX_RECORDS {
        return Err(invalid_data("DNS response has too many answers"));
    }

    let (question_name, mut offset) = decode_name_ascii(packet, HEADER_LEN)?;
    if !question_name.eq_ignore_ascii_case(expected_name) {
        return Err(invalid_data(
            "DNS response echoed a different question name",
        ));
    }
    let question_type = read_u16(packet, offset)?;
    let question_class = read_u16(packet, checked_add(offset, 2)?)?;
    offset = checked_add(offset, 4)?;
    if question_type != expected_type.code() || question_class != CLASS_IN {
        return Err(invalid_data("DNS response echoed a different question"));
    }
    match flags & RCODE_MASK {
        0 => {}
        RCODE_NXDOMAIN => return Ok(None),
        code => {
            return Err(io::Error::other(format!(
                "DNS server returned RCODE {code}"
            )));
        }
    }

    for _ in 0..answer_count {
        offset = skip_name(packet, offset)?;
        let rr_type = read_u16(packet, offset)?;
        let rr_class = read_u16(packet, checked_add(offset, 2)?)?;
        let ttl = read_u32(packet, checked_add(offset, 4)?)?;
        let rd_len = usize::from(read_u16(packet, checked_add(offset, 8)?)?);
        offset = checked_add(offset, 10)?;
        let end = checked_add(offset, rd_len)?;
        let rdata = packet
            .get(offset..end)
            .ok_or_else(|| invalid_data("DNS resource record exceeds packet length"))?;
        if rr_class == CLASS_IN
            && rr_type == expected_type.code()
            && rd_len == expected_type.address_len()
        {
            let address = match expected_type {
                RecordType::A => IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
                RecordType::Aaaa => {
                    let mut bytes = [0_u8; 16];
                    bytes.copy_from_slice(rdata);
                    IpAddr::V6(Ipv6Addr::from(bytes))
                }
            };
            return Ok(Some((address, Duration::from_secs(u64::from(ttl)))));
        }
        offset = end;
    }
    Ok(None)
}

fn decode_name_ascii(packet: &[u8], start: usize) -> io::Result<(String, usize)> {
    let mut cursor = start;
    let mut consumed_end = None;
    let mut expanded_len = 1_usize;
    let mut jumps = 0_usize;
    let mut labels = Vec::new();

    loop {
        let byte = *packet
            .get(cursor)
            .ok_or_else(|| invalid_data("DNS name exceeds packet length"))?;
        match byte & 0xc0 {
            0xc0 => {
                let second = *packet
                    .get(checked_add(cursor, 1)?)
                    .ok_or_else(|| invalid_data("truncated DNS compression pointer"))?;
                let pointer = usize::from((u16::from(byte & 0x3f) << 8) | u16::from(second));
                if pointer >= packet.len() {
                    return Err(invalid_data("DNS compression pointer is out of bounds"));
                }
                if consumed_end.is_none() {
                    consumed_end = Some(checked_add(cursor, 2)?);
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(invalid_data("DNS compression pointer loop"));
                }
                cursor = pointer;
            }
            0x00 => {
                if byte == 0 {
                    let name = labels.join(".");
                    return Ok((name, consumed_end.unwrap_or(checked_add(cursor, 1)?)));
                }
                let label_len = usize::from(byte);
                expanded_len = expanded_len
                    .checked_add(label_len + 1)
                    .ok_or_else(|| invalid_data("DNS name length overflow"))?;
                if expanded_len > MAX_NAME_WIRE_LEN {
                    return Err(invalid_data("expanded DNS name exceeds 255 bytes"));
                }
                cursor = checked_add(cursor, 1)?;
                let end = checked_add(cursor, label_len)?;
                let label = packet
                    .get(cursor..end)
                    .ok_or_else(|| invalid_data("DNS label exceeds packet length"))?;
                if !label.is_ascii() {
                    return Err(invalid_data("DNS question name contains non-ASCII bytes"));
                }
                labels.push(
                    std::str::from_utf8(label)
                        .map_err(|_| invalid_data("DNS question name is not valid ASCII"))?
                        .to_owned(),
                );
                cursor = end;
            }
            _ => return Err(invalid_data("unsupported DNS label encoding")),
        }
    }
}

fn skip_name(packet: &[u8], start: usize) -> io::Result<usize> {
    let mut cursor = start;
    let mut consumed_end = None;
    let mut expanded_len = 1_usize;
    let mut jumps = 0_usize;
    loop {
        let byte = *packet
            .get(cursor)
            .ok_or_else(|| invalid_data("DNS name exceeds packet length"))?;
        match byte & 0xc0 {
            0xc0 => {
                let second = *packet
                    .get(checked_add(cursor, 1)?)
                    .ok_or_else(|| invalid_data("truncated DNS compression pointer"))?;
                let pointer = usize::from((u16::from(byte & 0x3f) << 8) | u16::from(second));
                if pointer >= packet.len() {
                    return Err(invalid_data("DNS compression pointer is out of bounds"));
                }
                if consumed_end.is_none() {
                    consumed_end = Some(checked_add(cursor, 2)?);
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(invalid_data("DNS compression pointer loop"));
                }
                cursor = pointer;
            }
            0x00 => {
                if byte == 0 {
                    return Ok(consumed_end.unwrap_or(checked_add(cursor, 1)?));
                }
                let label_len = usize::from(byte);
                expanded_len = expanded_len
                    .checked_add(label_len + 1)
                    .ok_or_else(|| invalid_data("DNS name length overflow"))?;
                if expanded_len > MAX_NAME_WIRE_LEN {
                    return Err(invalid_data("expanded DNS name exceeds 255 bytes"));
                }
                cursor = checked_add(cursor, 1)?;
                let end = checked_add(cursor, label_len)?;
                packet
                    .get(cursor..end)
                    .ok_or_else(|| invalid_data("DNS label exceeds packet length"))?;
                cursor = end;
            }
            _ => return Err(invalid_data("unsupported DNS label encoding")),
        }
    }
}

fn read_u16(packet: &[u8], offset: usize) -> io::Result<u16> {
    let end = checked_add(offset, 2)?;
    let bytes = packet
        .get(offset..end)
        .ok_or_else(|| invalid_data("truncated DNS u16 field"))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> io::Result<u32> {
    let end = checked_add(offset, 4)?;
    let bytes = packet
        .get(offset..end)
        .ok_or_else(|| invalid_data("truncated DNS u32 field"))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn checked_add(value: usize, add: usize) -> io::Result<usize> {
    value
        .checked_add(add)
        .ok_or_else(|| invalid_data("DNS packet offset overflow"))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_for(query: &[u8], answer_type: RecordType, rdata: &[u8], ttl: u32) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2..4].copy_from_slice(&(FLAG_QR | FLAG_RD | 0x0080).to_be_bytes());
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&answer_type.code().to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&u16::try_from(rdata.len()).unwrap_or(0).to_be_bytes());
        response.extend_from_slice(rdata);
        response
    }

    #[test]
    fn canonicalizes_ascii_names() -> io::Result<()> {
        assert_eq!(canonical_ascii_name("Example.COM.")?, "example.com");
        assert!(canonical_ascii_name("münchen.example").is_err());
        assert!(canonical_ascii_name("bad..example").is_err());
        Ok(())
    }

    #[test]
    fn builds_standard_a_query() -> io::Result<()> {
        let query = build_query("example.com", RecordType::A, 0x1234)?;
        assert_eq!(
            &query[..12],
            &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(&query[12..], b"\x07example\x03com\x00\x00\x01\x00\x01");
        Ok(())
    }

    #[test]
    fn parses_compressed_answers() -> io::Result<()> {
        let query = build_query("example.com", RecordType::A, 0x1234)?;
        let response = response_for(&query, RecordType::A, &[203, 0, 113, 7], 300);
        assert_eq!(
            parse_response(&response, 0x1234, "example.com", RecordType::A)?,
            Some((
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                Duration::from_secs(300)
            ))
        );
        let query = build_query("example.com", RecordType::Aaaa, 7)?;
        let address = Ipv6Addr::LOCALHOST.octets();
        let response = response_for(&query, RecordType::Aaaa, &address, 60);
        assert_eq!(
            parse_response(&response, 7, "example.com", RecordType::Aaaa)?,
            Some((IpAddr::V6(Ipv6Addr::LOCALHOST), Duration::from_secs(60)))
        );
        Ok(())
    }

    #[test]
    fn rejects_every_truncated_prefix() -> io::Result<()> {
        let query = build_query("example.com", RecordType::A, 0x4321)?;
        let response = response_for(&query, RecordType::A, &[203, 0, 113, 9], 60);
        for end in 0..response.len() {
            assert!(
                parse_response(&response[..end], 0x4321, "example.com", RecordType::A).is_err()
            );
        }
        Ok(())
    }

    #[test]
    fn nxdomain_still_validates_the_echoed_question() -> io::Result<()> {
        let query = build_query("example.com", RecordType::A, 0x9999)?;
        let mut response = query;
        response[2..4]
            .copy_from_slice(&(FLAG_QR | FLAG_RD | 0x0080 | RCODE_NXDOMAIN).to_be_bytes());
        assert_eq!(
            parse_response(&response, 0x9999, "example.com", RecordType::A)?,
            None
        );
        assert!(parse_response(&response, 0x9999, "other.example", RecordType::A).is_err());
        Ok(())
    }

    #[test]
    fn rejects_pointer_loops_and_mismatched_ids() -> io::Result<()> {
        let query = build_query("example.com", RecordType::A, 1)?;
        let mut looped = query.clone();
        looped[2..4].copy_from_slice(&(FLAG_QR | FLAG_RD).to_be_bytes());
        looped[12] = 0xc0;
        looped[13] = 0x0c;
        assert!(parse_response(&looped, 1, "example.com", RecordType::A).is_err());
        let response = response_for(&query, RecordType::A, &[127, 0, 0, 1], 1);
        assert!(parse_response(&response, 2, "example.com", RecordType::A).is_err());
        assert!(parse_response(&response, 1, "other.example", RecordType::A).is_err());
        Ok(())
    }
}
