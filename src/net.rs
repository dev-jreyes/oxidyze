//! IPv4 / CIDR helpers.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs, UdpSocket};

/// Above this many addresses, a scan needs an explicit opt-in. A /16 is
/// 65_534 hosts, which is already a long scan; anything larger is almost
/// always a typo'd prefix.
pub const MAX_AUTO_HOSTS: u64 = 65_536;

/// A parsed CIDR block, normalized to its network address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub network: Ipv4Addr,
    pub prefix: u8,
}

impl Cidr {
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Result<Self, String> {
        if prefix > 32 {
            return Err(format!("prefix /{prefix} is out of range (0-32)"));
        }
        let mask = prefix_mask(prefix);
        Ok(Cidr {
            network: Ipv4Addr::from(u32::from(addr) & mask),
            prefix,
        })
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        let (addr_part, prefix_part) = s
            .split_once('/')
            .ok_or_else(|| format!("'{s}' is not a CIDR block (expected e.g. 192.168.1.0/24)"))?;

        let addr: Ipv4Addr = addr_part
            .parse()
            .map_err(|_| format!("'{addr_part}' is not a valid IPv4 address"))?;

        let prefix: u8 = prefix_part
            .parse()
            .map_err(|_| format!("'{prefix_part}' is not a valid prefix length"))?;

        Cidr::new(addr, prefix)
    }

    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network) | !prefix_mask(self.prefix))
    }

    /// Number of scannable host addresses in the block.
    ///
    /// A /32 is a single host and a /31 is a two-address point-to-point link
    /// (RFC 3021) where both addresses are usable. Everything else excludes
    /// the network and broadcast addresses.
    pub fn host_count(&self) -> u64 {
        match self.prefix {
            32 => 1,
            31 => 2,
            p => (1u64 << (32 - p as u32)) - 2,
        }
    }

    /// Iterator over the scannable host addresses.
    ///
    /// Yields lazily rather than building a `Vec`: a /8 would be a 67 MB
    /// allocation and a /0 would be roughly 17 GB.
    pub fn hosts(&self) -> impl Iterator<Item = Ipv4Addr> {
        let net = u32::from(self.network);
        let bcast = u32::from(self.broadcast());
        let (start, end) = match self.prefix {
            32 | 31 => (net, bcast),
            _ => (net + 1, bcast - 1),
        };
        (start..=end).map(Ipv4Addr::from)
    }
}

#[inline]
fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix as u32)
    }
}

/// Resolves a host string that may be a literal IP or a DNS name.
pub fn resolve_host(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    // `ToSocketAddrs` needs a port, so supply a dummy one and discard it.
    (host, 0)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(|addr| addr.ip())
}

/// Best-effort local IPv4 address.
///
/// `connect` on a UDP socket sends no packets: it only asks the OS which
/// local address it would route from, which is exactly what we want.
pub fn local_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

pub fn is_private_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 169 && o[1] == 254)
}

/// Guesses the LAN gateway for an address, assuming a /24 and `.1`.
pub fn guess_gateway(local: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from((u32::from(local) & 0xFFFF_FF00) | 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_and_normalizes_to_network_address() {
        // A host address with a /24 should normalize down to the network.
        let c = Cidr::parse("192.168.1.77/24").unwrap();
        assert_eq!(c.network, ip("192.168.1.0"));
        assert_eq!(c.broadcast(), ip("192.168.1.255"));
    }

    #[test]
    fn slash_24_has_254_hosts_from_1_to_254() {
        let c = Cidr::parse("192.168.1.0/24").unwrap();
        let hosts: Vec<_> = c.hosts().collect();
        assert_eq!(c.host_count(), 254);
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], ip("192.168.1.1"));
        assert_eq!(hosts[253], ip("192.168.1.254"));
    }

    #[test]
    fn slash_30_excludes_network_and_broadcast() {
        let c = Cidr::parse("10.0.0.0/30").unwrap();
        let hosts: Vec<_> = c.hosts().collect();
        assert_eq!(hosts, vec![ip("10.0.0.1"), ip("10.0.0.2")]);
        assert_eq!(c.host_count(), 2);
    }

    // Regression: the original returned zero hosts for a /31 because it
    // computed network+1 ..= broadcast-1, which collapses to an empty range.
    #[test]
    fn slash_31_yields_both_addresses_rfc3021() {
        let c = Cidr::parse("10.0.0.0/31").unwrap();
        let hosts: Vec<_> = c.hosts().collect();
        assert_eq!(hosts, vec![ip("10.0.0.0"), ip("10.0.0.1")]);
        assert_eq!(c.host_count(), 2);
    }

    #[test]
    fn slash_32_yields_exactly_the_address() {
        let c = Cidr::parse("10.0.0.5/32").unwrap();
        let hosts: Vec<_> = c.hosts().collect();
        assert_eq!(hosts, vec![ip("10.0.0.5")]);
        assert_eq!(c.host_count(), 1);
    }

    // Regression: host_count must not overflow or allocate for huge blocks.
    #[test]
    fn large_blocks_report_size_without_allocating() {
        assert_eq!(Cidr::parse("10.0.0.0/8").unwrap().host_count(), 16_777_214);
        assert_eq!(
            Cidr::parse("0.0.0.0/0").unwrap().host_count(),
            4_294_967_294
        );
        // Both are far over the opt-in threshold, so the CLI will refuse them.
        assert!(Cidr::parse("10.0.0.0/8").unwrap().host_count() > MAX_AUTO_HOSTS);
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(Cidr::parse("192.168.1.0").is_err());
        assert!(Cidr::parse("notanip/24").is_err());
        assert!(Cidr::parse("192.168.1.0/33").is_err());
        assert!(Cidr::parse("192.168.1.0/abc").is_err());
    }

    #[test]
    fn boundary_blocks_do_not_overflow() {
        let c = Cidr::parse("255.255.255.255/32").unwrap();
        assert_eq!(c.hosts().collect::<Vec<_>>(), vec![ip("255.255.255.255")]);
        let c = Cidr::parse("255.255.255.254/31").unwrap();
        assert_eq!(c.host_count(), 2);
    }

    #[test]
    fn private_range_classification() {
        assert!(is_private_v4(ip("10.1.2.3")));
        assert!(is_private_v4(ip("172.16.0.1")));
        assert!(is_private_v4(ip("172.31.255.254")));
        assert!(is_private_v4(ip("192.168.4.44")));
        assert!(is_private_v4(ip("169.254.1.1")));
        assert!(!is_private_v4(ip("172.15.0.1")));
        assert!(!is_private_v4(ip("172.32.0.1")));
        assert!(!is_private_v4(ip("8.8.8.8")));
    }

    #[test]
    fn gateway_guess_is_dot_one_of_the_24() {
        assert_eq!(guess_gateway(ip("192.168.4.44")), ip("192.168.4.1"));
    }
}
