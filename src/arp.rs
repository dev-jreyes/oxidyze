//! MAC address lookup via the local ARP cache.
//!
//! ARP does not cross routers, so this only resolves devices on the same L2
//! segment. The cache is populated as a side effect of the TCP probes, which
//! is why callers read it *after* scanning.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;

/// Reads and parses the local ARP/neighbor table. Best-effort: an empty map
/// means neither source was usable.
///
/// Tries `arp -a` first (works everywhere, but on Linux it comes from
/// net-tools, which a lot of modern minimal distros don't install by
/// default). If that yields nothing, falls back to `ip neighbor`
/// (iproute2), which ships on essentially every Linux system since it's
/// needed for basic networking.
pub fn table() -> HashMap<Ipv4Addr, String> {
    let via_arp = run(&["arp", "-a"], parse_arp_output);
    if !via_arp.is_empty() {
        return via_arp;
    }
    run(&["ip", "neighbor"], parse_ip_neighbor_output)
}

fn run(argv: &[&str], parser: fn(&str) -> HashMap<Ipv4Addr, String>) -> HashMap<Ipv4Addr, String> {
    match Command::new(argv[0]).args(&argv[1..]).output() {
        Ok(o) if o.status.success() => parser(&String::from_utf8_lossy(&o.stdout)),
        _ => HashMap::new(),
    }
}

/// Parses the `... (IP) at MAC ...` shape shared by macOS, Linux and BSD.
pub fn parse_arp_output(text: &str) -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();

    for line in text.lines() {
        let ip = line
            .split_once('(')
            .and_then(|(_, rest)| rest.split_once(')'))
            .and_then(|(addr, _)| addr.parse::<Ipv4Addr>().ok());

        let mac = line
            .split_once(" at ")
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .filter(|tok| tok.contains(':') && *tok != "(incomplete)")
            .map(normalize_mac);

        if let (Some(ip), Some(mac)) = (ip, mac) {
            map.insert(ip, mac);
        }
    }

    map
}

/// Parses `ip neighbor show` lines: `<ip> dev <iface> [lladdr <mac>]
/// [router] <STATE>`. Entries with no `lladdr` (e.g. `FAILED`,
/// `INCOMPLETE`) have nothing to report and are skipped. IPv6 rows are
/// naturally dropped too, since their address token won't parse as
/// `Ipv4Addr`.
pub fn parse_ip_neighbor_output(text: &str) -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();

    for line in text.lines() {
        let Some(ip) = line
            .split_whitespace()
            .next()
            .and_then(|tok| tok.parse::<Ipv4Addr>().ok())
        else {
            continue;
        };

        let mac = line
            .split_whitespace()
            .skip_while(|tok| *tok != "lladdr")
            .nth(1)
            .filter(|tok| tok.contains(':'))
            .map(normalize_mac);

        if let Some(mac) = mac {
            map.insert(ip, mac);
        }
    }

    map
}

/// macOS prints ARP MACs without leading zeros (`0:1c:42:...`); pad each
/// octet so the column lines up and the values are comparable.
fn normalize_mac(raw: &str) -> String {
    raw.split(':')
        .map(|octet| {
            if octet.len() == 1 {
                format!("0{octet}")
            } else {
                octet.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(":")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_macos_style_output() {
        let text = "\
? (192.168.4.1) at 0:1c:42:aa:bb:cc on en0 ifscope [ethernet]
? (192.168.4.44) at 3c:22:fb:11:22:33 on en0 ifscope [ethernet]
? (192.168.4.99) at (incomplete) on en0 ifscope [ethernet]
";
        let map = parse_arp_output(text);
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get(&ip("192.168.4.1")),
            Some(&"00:1c:42:aa:bb:cc".to_string())
        );
        assert_eq!(
            map.get(&ip("192.168.4.44")),
            Some(&"3c:22:fb:11:22:33".to_string())
        );
        assert!(!map.contains_key(&ip("192.168.4.99")));
    }

    #[test]
    fn parses_linux_style_output() {
        let text = "gateway (10.0.0.1) at aa:bb:cc:dd:ee:ff [ether] on eth0\n";
        let map = parse_arp_output(text);
        assert_eq!(
            map.get(&ip("10.0.0.1")),
            Some(&"aa:bb:cc:dd:ee:ff".to_string())
        );
    }

    #[test]
    fn ignores_junk_lines() {
        let map = parse_arp_output("total garbage\n\n(notanip) at xx\n");
        assert!(map.is_empty());
    }

    #[test]
    fn pads_short_octets() {
        assert_eq!(normalize_mac("0:1:2:3:4:5"), "00:01:02:03:04:05");
        assert_eq!(normalize_mac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn parses_ip_neighbor_output() {
        let text = "\
192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE
192.168.1.44 dev wlan0 lladdr 11:22:33:44:55:66 REACHABLE
";
        let map = parse_ip_neighbor_output(text);
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get(&ip("192.168.1.1")),
            Some(&"aa:bb:cc:dd:ee:ff".to_string())
        );
        assert_eq!(
            map.get(&ip("192.168.1.44")),
            Some(&"11:22:33:44:55:66".to_string())
        );
    }

    // Regression guard: FAILED/INCOMPLETE entries have no lladdr token at
    // all, not a placeholder -- naive "skip a fixed offset" parsing would
    // grab STATE ("FAILED") as if it were the MAC.
    #[test]
    fn ip_neighbor_entries_without_lladdr_are_skipped() {
        let map = parse_ip_neighbor_output("192.168.1.99 dev eth0  FAILED\n");
        assert!(!map.contains_key(&ip("192.168.1.99")));
    }

    #[test]
    fn ip_neighbor_ipv6_rows_are_dropped() {
        let map =
            parse_ip_neighbor_output("fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff router STALE\n");
        assert!(map.is_empty());
    }
}
