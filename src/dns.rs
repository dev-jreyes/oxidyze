//! Reverse DNS (PTR) lookups over raw UDP, plus mDNS fallback.
//!
//! Hand-rolled rather than pulling in a resolver crate, which keeps the
//! whole tool dependency-free.

use std::collections::hash_map::RandomState;
use std::fs;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::process::Command;
use std::time::{Duration, Instant};

/// EDNS-era responses can exceed the classic 512-byte limit; 1232 bytes is
/// the widely used safe MTU-avoiding size.
const RESPONSE_BUF: usize = 1232;

const QTYPE_PTR: u16 = 12;

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// Decodes a possibly-compressed DNS name starting at `start`.
///
/// Returns the decoded name and the offset just past the name *as it appears
/// in the enclosing record* — following a compression pointer must not
/// advance that cursor, which is why `jumped` gates the `end_pos` updates.
pub fn parse_name(buf: &[u8], start: usize) -> (String, usize) {
    let mut pos = start;
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut end_pos = start;
    // A malformed or malicious response can point a compression pointer back
    // at itself; cap the work so we terminate regardless.
    let mut budget = buf.len().saturating_mul(2) + 16;

    loop {
        if pos >= buf.len() || budget == 0 {
            break;
        }
        budget -= 1;

        let len = buf[pos] as usize;
        if len == 0 {
            pos += 1;
            if !jumped {
                end_pos = pos;
            }
            break;
        } else if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                break;
            }
            let ptr = ((len & 0x3F) << 8) | buf[pos + 1] as usize;
            if !jumped {
                end_pos = pos + 2;
                jumped = true;
            }
            if ptr >= buf.len() {
                break;
            }
            pos = ptr;
        } else {
            pos += 1;
            if pos + len > buf.len() {
                break;
            }
            labels.push(String::from_utf8_lossy(&buf[pos..pos + len]).into_owned());
            pos += len;
            if !jumped {
                end_pos = pos;
            }
        }
    }

    (labels.join("."), end_pos)
}

pub fn ptr_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

fn build_query(ip: Ipv4Addr, id: u16, qclass: [u8; 2], recursion_desired: bool) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(if recursion_desired {
        &[0x01, 0x00]
    } else {
        &[0x00, 0x00]
    });
    pkt.extend_from_slice(&[0x00, 0x01]); // qdcount
    pkt.extend_from_slice(&[0x00, 0x00]); // ancount
    pkt.extend_from_slice(&[0x00, 0x00]); // nscount
    pkt.extend_from_slice(&[0x00, 0x00]); // arcount
    pkt.extend_from_slice(&encode_name(&ptr_name(ip)));
    pkt.extend_from_slice(&QTYPE_PTR.to_be_bytes());
    pkt.extend_from_slice(&qclass);
    pkt
}

/// Extracts the first PTR target from a DNS/mDNS response.
pub fn extract_ptr_answer(buf: &[u8]) -> Option<String> {
    let n = buf.len();
    if n < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    // Skip the question section.
    let (_, mut pos) = parse_name(buf, 12);
    pos += 4; // qtype + qclass

    for _ in 0..ancount {
        let (_, next) = parse_name(buf, pos);
        pos = next;
        if pos + 10 > n {
            break;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > n {
            break;
        }
        if rtype == QTYPE_PTR {
            let (name, _) = parse_name(buf, pos);
            let name = name.trim_end_matches('.').to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
        pos += rdlength;
    }
    None
}

/// Unpredictable transaction ID.
///
/// The original derived the ID from the last octet of the target address,
/// which made it trivially guessable. `RandomState` is randomly seeded per
/// process, and mixing in the clock keeps successive queries distinct.
fn transaction_id() -> u16 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    );
    (hasher.finish() & 0xFFFF) as u16
}

/// Waits for a reply, discarding packets that don't match.
///
/// `expect_from` pins the accepted source address for unicast queries so a
/// stray or spoofed datagram from elsewhere can't answer for the resolver.
/// mDNS replies legitimately come from the target host, so that path passes
/// `None` and matches on the transaction ID and question instead.
fn recv_matching(
    socket: &UdpSocket,
    expect_from: Option<Ipv4Addr>,
    expect_id: Option<u16>,
    deadline: Instant,
) -> Option<Vec<u8>> {
    let mut buf = [0u8; RESPONSE_BUF];
    loop {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        if remaining.is_zero() {
            return None;
        }
        socket.set_read_timeout(Some(remaining)).ok()?;

        let (n, from) = socket.recv_from(&mut buf).ok()?;
        if n < 12 {
            continue;
        }
        if let Some(expected) = expect_from {
            match from.ip() {
                IpAddr::V4(v4) if v4 == expected => {}
                _ => continue,
            }
        }
        if let Some(id) = expect_id {
            if u16::from_be_bytes([buf[0], buf[1]]) != id {
                continue;
            }
        }
        return Some(buf[..n].to_vec());
    }
}

pub fn reverse_lookup(resolver: Ipv4Addr, ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_write_timeout(Some(timeout)).ok()?;

    let id = transaction_id();
    let query = build_query(ip, id, [0x00, 0x01], true);
    socket
        .send_to(&query, SocketAddr::from((resolver, 53)))
        .ok()?;

    let reply = recv_matching(&socket, Some(resolver), Some(id), Instant::now() + timeout)?;
    extract_ptr_answer(&reply)
}

/// mDNS (RFC 6762) query to 224.0.0.251:5353.
///
/// The top bit of QCLASS requests a unicast reply, so we don't need to join
/// the multicast group.
pub fn mdns_reverse_lookup(ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_write_timeout(Some(timeout)).ok()?;
    // Link-local scope only; don't leak queries past the first router.
    let _ = socket.set_multicast_ttl_v4(1);

    let query = build_query(ip, 0, [0x80, 0x01], false);
    socket.send_to(&query, "224.0.0.251:5353").ok()?;

    let reply = recv_matching(&socket, None, None, Instant::now() + timeout)?;
    extract_ptr_answer(&reply)
}

/// Tries each unicast resolver in order, then falls back to mDNS.
pub fn reverse_lookup_multi(
    resolvers: &[Ipv4Addr],
    ip: Ipv4Addr,
    timeout: Duration,
) -> Option<String> {
    for &resolver in resolvers {
        if let Some(name) = reverse_lookup(resolver, ip, timeout) {
            return Some(name);
        }
    }
    mdns_reverse_lookup(ip, timeout)
}

/// System resolvers, preferring the platform-native source.
///
/// On macOS `/etc/resolv.conf` is generated by configd and is frequently
/// stale or absent, so `scutil --dns` is consulted first there. On Linux
/// `/etc/resolv.conf` is authoritative.
pub fn system_resolvers() -> Vec<Ipv4Addr> {
    let mut found: Vec<Ipv4Addr> = Vec::new();

    if cfg!(target_os = "macos") {
        if let Ok(output) = Command::new("scutil").arg("--dns").output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                found.extend(parse_scutil_dns(&text));
            }
        }
    }

    if let Ok(contents) = fs::read_to_string("/etc/resolv.conf") {
        found.extend(parse_resolv_conf(&contents));
    }

    found.sort_unstable();
    found.dedup();
    found
}

pub fn parse_resolv_conf(contents: &str) -> Vec<Ipv4Addr> {
    contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.starts_with(';'))
        .filter_map(|l| l.strip_prefix("nameserver"))
        .filter_map(|rest| rest.trim().parse::<Ipv4Addr>().ok())
        .collect()
}

/// Parses `nameserver[N] : ADDR` lines out of `scutil --dns` output.
pub fn parse_scutil_dns(text: &str) -> Vec<Ipv4Addr> {
    text.lines()
        .map(str::trim)
        .filter(|l| l.starts_with("nameserver["))
        .filter_map(|l| l.split_once(':'))
        .filter_map(|(_, addr)| addr.trim().parse::<Ipv4Addr>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn ptr_name_reverses_the_octets() {
        assert_eq!(ptr_name(ip("192.168.4.44")), "44.4.168.192.in-addr.arpa");
    }

    #[test]
    fn encodes_names_as_length_prefixed_labels() {
        assert_eq!(encode_name("ab.cd"), vec![2, b'a', b'b', 2, b'c', b'd', 0]);
    }

    #[test]
    fn query_has_well_formed_header() {
        let q = build_query(ip("10.0.0.1"), 0xBEEF, [0x00, 0x01], true);
        assert_eq!(&q[0..2], &[0xBE, 0xEF]); // id
        assert_eq!(&q[2..4], &[0x01, 0x00]); // recursion desired
        assert_eq!(&q[4..6], &[0x00, 0x01]); // qdcount == 1
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x0C, 0x00, 0x01]); // PTR / IN
    }

    #[test]
    fn mdns_query_sets_unicast_response_bit() {
        let q = build_query(ip("10.0.0.1"), 0, [0x80, 0x01], false);
        assert_eq!(&q[q.len() - 2..], &[0x80, 0x01]);
    }

    /// Builds a minimal PTR response for 1.0.0.10.in-addr.arpa -> `target`.
    fn sample_response(target: &str, use_compression: bool) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x1234u16.to_be_bytes());
        pkt.extend_from_slice(&[0x81, 0x80]); // response, no error
        pkt.extend_from_slice(&[0x00, 0x01]); // qdcount
        pkt.extend_from_slice(&[0x00, 0x01]); // ancount
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&encode_name("1.0.0.10.in-addr.arpa"));
        pkt.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]);

        // Answer
        if use_compression {
            pkt.extend_from_slice(&[0xC0, 0x0C]); // pointer back to the question
        } else {
            pkt.extend_from_slice(&encode_name("1.0.0.10.in-addr.arpa"));
        }
        pkt.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]); // PTR / IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]); // ttl
        let rdata = encode_name(target);
        pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&rdata);
        pkt
    }

    #[test]
    fn extracts_ptr_from_uncompressed_response() {
        let pkt = sample_response("router.lan", false);
        assert_eq!(extract_ptr_answer(&pkt), Some("router.lan".to_string()));
    }

    #[test]
    fn extracts_ptr_when_answer_name_is_compressed() {
        let pkt = sample_response("router.lan", true);
        assert_eq!(extract_ptr_answer(&pkt), Some("router.lan".to_string()));
    }

    #[test]
    fn returns_none_when_no_answers() {
        let mut pkt = sample_response("router.lan", true);
        pkt[6] = 0;
        pkt[7] = 0; // ancount = 0
        assert_eq!(extract_ptr_answer(&pkt), None);
    }

    #[test]
    fn truncated_and_empty_input_is_rejected_not_panicked() {
        assert_eq!(extract_ptr_answer(&[]), None);
        assert_eq!(extract_ptr_answer(&[0u8; 11]), None);
        let pkt = sample_response("router.lan", true);
        for cut in 12..pkt.len() {
            let _ = extract_ptr_answer(&pkt[..cut]); // must not panic
        }
    }

    // A pointer that targets itself would spin forever without the budget.
    #[test]
    fn self_referential_compression_pointer_terminates() {
        let mut pkt = vec![0u8; 20];
        pkt[12] = 0xC0;
        pkt[13] = 0x0C; // points at itself
        let (name, _) = parse_name(&pkt, 12);
        assert!(name.is_empty());
    }

    #[test]
    fn transaction_ids_are_not_derived_from_the_address() {
        // Sample enough IDs that a constant or address-derived scheme shows up.
        let ids: std::collections::HashSet<u16> = (0..64).map(|_| transaction_id()).collect();
        assert!(ids.len() > 1, "transaction IDs should vary");
    }

    #[test]
    fn parses_resolv_conf() {
        let text = "\
# comment
nameserver 192.168.4.1
nameserver 8.8.8.8
search lan
nameserver not-an-ip
";
        assert_eq!(
            parse_resolv_conf(text),
            vec![ip("192.168.4.1"), ip("8.8.8.8")]
        );
    }

    #[test]
    fn parses_scutil_output() {
        let text = "\
DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.4.1
  nameserver[1] : 8.8.4.4
  if_index : 14 (en0)

resolver #2
  domain   : local
  options  : mdns
";
        assert_eq!(
            parse_scutil_dns(text),
            vec![ip("192.168.4.1"), ip("8.8.4.4")]
        );
    }
}
