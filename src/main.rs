//! oxidyze - a multi-threaded TCP connect scanner with no dependencies.
//!
//! Host discovery uses TCP connect probes rather than ICMP echo, because raw
//! ICMP sockets require root. A host counts as up if any probe connects or is
//! actively refused; a timeout means nothing answered at all.
//!
//! Only scan hosts and networks you own or have written authorization to test.

mod arp;
mod banner;
mod cli;
mod dns;
mod net;
mod scan;
mod table;

use std::net::{IpAddr, Ipv4Addr};
use std::process::ExitCode;
use std::time::Duration;

use cli::{Config, NetworkSpec, Parsed, Target};
use net::Cidr;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let program = argv
        .first()
        .map(|p| {
            std::path::Path::new(p)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_else(|| p.clone())
        })
        .unwrap_or_else(|| "oxidyze".to_string());

    match cli::parse(&argv[1..]) {
        Ok(Parsed::Help) => {
            println!("{}", cli::usage(&program));
            ExitCode::SUCCESS
        }
        Ok(Parsed::Version) => {
            println!("oxidyze {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Parsed::Run(config)) => match run(*config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => fail(&message),
        },
        Err(message) => {
            eprintln!("error: {message}");
            eprintln!();
            eprintln!("{}", cli::usage(&program));
            ExitCode::from(2)
        }
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::FAILURE
}

fn run(config: Config) -> Result<(), String> {
    match &config.target {
        Target::Host(host) => run_single_host(host, &config),
        Target::Discover(spec) => run_discover(spec, &config),
        Target::Lan(spec) => run_lan(spec, &config),
    }
}

/// Turns `auto` into the local interface's /24, and refuses networks that
/// are almost certainly a typo'd prefix.
fn resolve_network(spec: &NetworkSpec, allow_large: bool) -> Result<Cidr, String> {
    let cidr = match spec {
        NetworkSpec::Explicit(cidr) => *cidr,
        NetworkSpec::Auto => {
            let local = net::local_ipv4().ok_or(
                "could not auto-detect a local IPv4 address; pass a network like 192.168.1.0/24",
            )?;
            Cidr::new(local, 24)?
        }
    };

    let hosts = cidr.host_count();
    if hosts > net::MAX_AUTO_HOSTS && !allow_large {
        return Err(format!(
            "{}/{} covers {} addresses, which would take a very long time.\n       \
             Use a smaller prefix, or pass --allow-large if you really mean it.",
            cidr.network, cidr.prefix, hosts
        ));
    }
    Ok(cidr)
}

/// Resolvers to try, best-first.
///
/// Public resolvers hold no PTR records for RFC1918 space, so for private
/// targets the LAN gateway is tried first: it usually knows DHCP hostnames.
fn resolvers_for(target: Ipv4Addr) -> Vec<Ipv4Addr> {
    let mut resolvers = Vec::new();
    if net::is_private_v4(target) {
        if let Some(local) = net::local_ipv4() {
            resolvers.push(net::guess_gateway(local));
        }
    }
    resolvers.extend(dns::system_resolvers());
    resolvers.dedup();
    resolvers
}

fn resolvers_for_network(cidr: &Cidr) -> Vec<Ipv4Addr> {
    let mut resolvers = vec![net::guess_gateway(cidr.network)];
    resolvers.extend(dns::system_resolvers());
    resolvers.dedup();
    resolvers
}

/// Resolves hostnames for many addresses on a worker pool.
fn resolve_hostnames(
    ips: &[Ipv4Addr],
    resolvers: Vec<Ipv4Addr>,
    threads: usize,
    timeout: Duration,
) -> std::collections::HashMap<Ipv4Addr, String> {
    let found = scan::parallel_filter_map(ips.to_vec(), threads, move |ip| {
        dns::reverse_lookup_multi(&resolvers, ip, timeout).map(|name| (ip, name))
    });
    found.into_iter().collect()
}

fn dash(value: Option<String>) -> String {
    value.unwrap_or_else(|| "-".to_string())
}

fn run_single_host(host: &str, config: &Config) -> Result<(), String> {
    let ip = net::resolve_host(host).ok_or_else(|| format!("could not resolve host '{host}'"))?;

    println!(
        "Scanning {} ({}) - {} port(s), {} threads, {}ms timeout\n",
        host,
        ip,
        config.ports.len(),
        scan::effective_threads(config.threads, config.ports.len()),
        config.timeout.as_millis(),
    );

    // Port scan first: the TCP connects are what populate the ARP cache, so
    // the MAC lookup below has something to find.
    let open_ports = scan::scan_ports(ip, config.ports.clone(), config.threads, config.timeout);

    let (hostname, mac) = match ip {
        IpAddr::V4(v4) => (
            dns::reverse_lookup_multi(&resolvers_for(v4), v4, config.timeout),
            arp::table().get(&v4).cloned(),
        ),
        IpAddr::V6(_) => (None, None),
    };

    table::print(
        &["IP", "HOSTNAME", "MAC ADDRESS"],
        &[vec![ip.to_string(), dash(hostname), dash(mac)]],
    );
    println!();

    if open_ports.is_empty() {
        println!("No open ports found.");
    } else if config.banners {
        let timeout = config.timeout;
        let mut labeled =
            scan::parallel_filter_map(open_ports.clone(), config.threads, move |port| {
                Some((port, banner::label(ip, port, timeout)))
            });
        labeled.sort_unstable_by_key(|(port, _)| *port);

        println!("Open ports:\n");
        let rows: Vec<Vec<String>> = labeled
            .into_iter()
            .map(|(port, service)| vec![format!("{port}/tcp"), "open".to_string(), service])
            .collect();
        table::print(&["PORT", "STATE", "SERVICE"], &rows);
    } else {
        println!("Open ports:");
        for port in &open_ports {
            println!("  {port}/tcp open");
        }
    }
    Ok(())
}

fn run_discover(spec: &NetworkSpec, config: &Config) -> Result<(), String> {
    let cidr = resolve_network(spec, config.allow_large)?;
    let alive = discover(&cidr, config);

    if alive.is_empty() {
        println!("No live hosts found.");
        return Ok(());
    }

    let names = resolve_hostnames(
        &alive,
        resolvers_for_network(&cidr),
        config.threads,
        config.timeout,
    );
    let arp = arp::table();

    println!("Live hosts ({}):\n", alive.len());
    let rows: Vec<Vec<String>> = alive
        .iter()
        .map(|ip| {
            vec![
                ip.to_string(),
                dash(names.get(ip).cloned()),
                dash(arp.get(ip).cloned()),
            ]
        })
        .collect();
    table::print(&["IP", "HOSTNAME", "MAC ADDRESS"], &rows);
    Ok(())
}

fn run_lan(spec: &NetworkSpec, config: &Config) -> Result<(), String> {
    let cidr = resolve_network(spec, config.allow_large)?;
    let alive = discover(&cidr, config);

    if alive.is_empty() {
        println!("No live hosts found.");
        return Ok(());
    }

    let names = resolve_hostnames(
        &alive,
        resolvers_for_network(&cidr),
        config.threads,
        config.timeout,
    );

    println!(
        "Found {} live host(s). Scanning {} port(s) on each...\n",
        alive.len(),
        config.ports.len()
    );

    // One shared pool across every (host, port) pair rather than a fresh
    // pool per host.
    let open = scan::scan_ports_multi(&alive, &config.ports, config.threads, config.timeout);

    // ARP entries only appear once we've actually talked to a host, so read
    // the table after the scans above rather than before them.
    let arp = arp::table();

    let banners: std::collections::HashMap<(Ipv4Addr, u16), String> = if config.banners {
        let work: Vec<(Ipv4Addr, u16)> = alive
            .iter()
            .flat_map(|ip| {
                open.get(ip)
                    .into_iter()
                    .flat_map(move |ports| ports.iter().map(move |port| (*ip, *port)))
            })
            .collect();
        let timeout = config.timeout;
        scan::parallel_filter_map(work, config.threads, move |(ip, port)| {
            Some(((ip, port), banner::label(IpAddr::V4(ip), port, timeout)))
        })
        .into_iter()
        .collect()
    } else {
        std::collections::HashMap::new()
    };

    let rows: Vec<Vec<String>> = alive
        .iter()
        .map(|ip| {
            let ports = open.get(ip).map(|p| p.as_slice()).unwrap_or(&[]);
            let ports_str = if ports.is_empty() {
                "-".to_string()
            } else {
                ports
                    .iter()
                    .map(|p| {
                        if config.banners {
                            let service = banners
                                .get(&(*ip, *p))
                                .cloned()
                                .unwrap_or_else(|| "-".to_string());
                            format!("{p}/{service}")
                        } else {
                            p.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            vec![
                ip.to_string(),
                dash(names.get(ip).cloned()),
                dash(arp.get(ip).cloned()),
                ports_str,
            ]
        })
        .collect();

    table::print(&["IP", "HOSTNAME", "MAC ADDRESS", "OPEN PORTS"], &rows);
    Ok(())
}

fn discover(cidr: &Cidr, config: &Config) -> Vec<Ipv4Addr> {
    println!(
        "Discovering live hosts on {}/{} ({} addresses)...",
        cidr.network,
        cidr.prefix,
        cidr.host_count()
    );
    scan::discover_hosts(
        cidr.hosts(),
        &scan::default_probe_ports(),
        config.threads,
        config.timeout,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_networks_are_refused_without_the_opt_in() {
        let spec = NetworkSpec::Explicit(Cidr::parse("10.0.0.0/8").unwrap());
        let err = resolve_network(&spec, false).unwrap_err();
        assert!(err.contains("--allow-large"), "unexpected message: {err}");
        assert!(resolve_network(&spec, true).is_ok());
    }

    #[test]
    fn normal_networks_pass_through() {
        let spec = NetworkSpec::Explicit(Cidr::parse("192.168.1.0/24").unwrap());
        let cidr = resolve_network(&spec, false).unwrap();
        assert_eq!(cidr.prefix, 24);
    }

    #[test]
    fn missing_values_render_as_a_dash() {
        assert_eq!(dash(None), "-");
        assert_eq!(dash(Some("router.lan".into())), "router.lan");
    }
}
