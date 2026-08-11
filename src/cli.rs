//! Command line parsing.
//!
//! Hand-rolled to keep the tool dependency-free. The important property is
//! that a malformed value is a hard error: the original used
//! `.parse().ok().unwrap_or(default)`, so `--threads abc` silently ran with
//! the default instead of telling you the flag was ignored.

use std::time::Duration;

use crate::net::Cidr;

pub const DEFAULT_PORTS: &str = "1-1024";
pub const DEFAULT_THREADS: usize = 256;
pub const DEFAULT_TIMEOUT_MS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A single host, given as a literal IP or a DNS name.
    Host(String),
    /// Discover live hosts only.
    Discover(NetworkSpec),
    /// Discover live hosts, then port-scan each one.
    Lan(NetworkSpec),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkSpec {
    /// Derive the block from the local interface address.
    Auto,
    Explicit(Cidr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub target: Target,
    pub ports: Vec<u16>,
    pub threads: usize,
    pub timeout: Duration,
    pub allow_large: bool,
    pub banners: bool,
}

#[derive(Debug)]
pub enum Parsed {
    Run(Box<Config>),
    Help,
    Version,
}

pub fn parse<I, S>(args: I) -> Result<Parsed, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|a| a.as_ref().to_string()).collect();

    let mut target: Option<Target> = None;
    let mut ports_spec: Option<String> = None;
    let mut threads: Option<usize> = None;
    let mut timeout_ms: Option<u64> = None;
    let mut allow_large = false;
    let mut banners = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();

        match arg {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-V" | "--version" => return Ok(Parsed::Version),

            "-d" | "--discover" | "-l" | "--lan" => {
                let spec = take_optional_positional(&args, &mut i);
                let network = parse_network_spec(spec.as_deref())?;
                let mode = if arg == "-d" || arg == "--discover" {
                    Target::Discover(network)
                } else {
                    Target::Lan(network)
                };
                set_target(&mut target, mode)?;
            }

            "-p" | "--ports" => {
                ports_spec = Some(take_value(&args, &mut i, arg)?);
            }
            "-t" | "--threads" => {
                let raw = take_value(&args, &mut i, arg)?;
                let n: usize = raw
                    .parse()
                    .map_err(|_| format!("--threads expects a whole number, got '{raw}'"))?;
                if n == 0 {
                    return Err("--threads must be at least 1".to_string());
                }
                threads = Some(n);
            }
            "--timeout" => {
                let raw = take_value(&args, &mut i, arg)?;
                let ms: u64 = raw
                    .parse()
                    .map_err(|_| format!("--timeout expects milliseconds, got '{raw}'"))?;
                if ms == 0 {
                    return Err("--timeout must be at least 1ms".to_string());
                }
                timeout_ms = Some(ms);
            }
            "--allow-large" => allow_large = true,
            "-b" | "--banners" => banners = true,

            other if other.starts_with('-') && other != "-" => {
                return Err(format!("unknown option '{other}' (try --help)"));
            }

            host => {
                set_target(&mut target, Target::Host(host.to_string()))?;
            }
        }

        i += 1;
    }

    let target = target.ok_or_else(|| "no target given (try --help)".to_string())?;
    let ports = parse_ports(ports_spec.as_deref().unwrap_or(DEFAULT_PORTS))?;

    Ok(Parsed::Run(Box::new(Config {
        target,
        ports,
        threads: threads.unwrap_or(DEFAULT_THREADS),
        timeout: Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
        allow_large,
        banners,
    })))
}

fn set_target(slot: &mut Option<Target>, value: Target) -> Result<(), String> {
    if slot.is_some() {
        return Err(
            "more than one target given; pass a single host or one of --lan/--discover".to_string(),
        );
    }
    *slot = Some(value);
    Ok(())
}

/// Consumes the next argument as a flag's value.
fn take_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    let next = args
        .get(*i + 1)
        .ok_or_else(|| format!("{flag} expects a value"))?;
    if next.starts_with('-') && next.len() > 1 {
        return Err(format!("{flag} expects a value, but found '{next}'"));
    }
    *i += 1;
    Ok(next.clone())
}

/// Consumes the next argument only if it looks like a positional value.
fn take_optional_positional(args: &[String], i: &mut usize) -> Option<String> {
    match args.get(*i + 1) {
        Some(next) if !next.starts_with('-') => {
            *i += 1;
            Some(next.clone())
        }
        _ => None,
    }
}

fn parse_network_spec(spec: Option<&str>) -> Result<NetworkSpec, String> {
    match spec {
        None | Some("auto") => Ok(NetworkSpec::Auto),
        Some(s) => Cidr::parse(s).map(NetworkSpec::Explicit),
    }
}

/// Parses a port specification: `80`, `1-1024`, `22,80,443`, `1-100,8080`,
/// or `all`.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    if spec.trim().eq_ignore_ascii_case("all") {
        return Ok((1..=u16::MAX).collect());
    }

    let mut ports: Vec<u16> = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(format!("empty entry in port list '{spec}'"));
        }

        match part.split_once('-') {
            Some((start, end)) => {
                let start: u16 = parse_port(start.trim())?;
                let end: u16 = parse_port(end.trim())?;
                if start > end {
                    return Err(format!("port range '{part}' runs backwards"));
                }
                ports.extend(start..=end);
            }
            None => ports.push(parse_port(part)?),
        }
    }

    ports.sort_unstable();
    ports.dedup();

    if ports.is_empty() {
        return Err("no ports selected".to_string());
    }
    Ok(ports)
}

fn parse_port(s: &str) -> Result<u16, String> {
    let n: u32 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a valid port number"))?;
    if n == 0 {
        return Err("port 0 is not scannable".to_string());
    }
    u16::try_from(n).map_err(|_| format!("port {n} is above the maximum of 65535"))
}

pub fn usage(program: &str) -> String {
    format!(
        "\
{program} {version} - a personal network recon / pentesting toolkit

Currently: multi-threaded TCP port scanning, live-host discovery, hostname
resolution (DNS PTR + mDNS), MAC address lookup, and optional service banner
grabbing. More capabilities are on the way.

USAGE:
  {program} <host> [options]              scan one host
  {program} --discover [cidr|auto] [opts] list live hosts on a network
  {program} --lan [cidr|auto] [options]   list live hosts, then scan each

OPTIONS:
  -p, --ports <spec>    ports to scan: 1-1024, 22,80,443, or all [default: {ports}]
  -b, --banners         grab a service banner from each open port (adds a
                         round trip per open port; off by default)
  -t, --threads <n>     worker threads, capped at {max_threads} [default: {threads}]
      --timeout <ms>    per-connection timeout [default: {timeout}]
      --allow-large     permit networks larger than {max_hosts} addresses
  -h, --help            show this help
  -V, --version         show the version

EXAMPLES:
  {program} 127.0.0.1 --ports 1-1024
  {program} scanme.example.com -p 22,80,443 --banners
  {program} --discover auto
  {program} --lan 192.168.1.0/24 --ports 1-1024 --threads 400 --banners

Only scan hosts and networks you own or have written authorization to test.",
        version = env!("CARGO_PKG_VERSION"),
        program = program,
        ports = DEFAULT_PORTS,
        threads = DEFAULT_THREADS,
        max_threads = crate::scan::MAX_THREADS,
        timeout = DEFAULT_TIMEOUT_MS,
        max_hosts = crate::net::MAX_AUTO_HOSTS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(args: &[&str]) -> Config {
        match parse(args).unwrap() {
            Parsed::Run(c) => *c,
            _ => panic!("expected a run config"),
        }
    }

    #[test]
    fn single_host_with_defaults() {
        let c = cfg(&["127.0.0.1"]);
        assert_eq!(c.target, Target::Host("127.0.0.1".to_string()));
        assert_eq!(c.ports.len(), 1024);
        assert_eq!(c.threads, DEFAULT_THREADS);
        assert_eq!(c.timeout, Duration::from_millis(DEFAULT_TIMEOUT_MS));
    }

    // Regression: `scanner host 1 1024 abc 200` silently used 100 threads.
    #[test]
    fn non_numeric_thread_count_is_an_error() {
        let err = parse(["127.0.0.1", "--threads", "abc"]).unwrap_err();
        assert!(err.contains("--threads"), "unexpected message: {err}");
    }

    #[test]
    fn non_numeric_timeout_is_an_error() {
        assert!(parse(["127.0.0.1", "--timeout", "soon"]).is_err());
    }

    #[test]
    fn zero_values_are_rejected() {
        assert!(parse(["127.0.0.1", "--threads", "0"]).is_err());
        assert!(parse(["127.0.0.1", "--timeout", "0"]).is_err());
    }

    #[test]
    fn missing_flag_value_is_an_error() {
        assert!(parse(["127.0.0.1", "--threads"]).is_err());
        assert!(parse(["127.0.0.1", "--ports"]).is_err());
    }

    #[test]
    fn flag_followed_by_another_flag_is_an_error() {
        assert!(parse(["127.0.0.1", "--ports", "--threads", "4"]).is_err());
    }

    // Regression: `scanner --lann` was treated as a hostname and produced
    // "Could not resolve host: --lann".
    #[test]
    fn misspelled_flag_is_reported_as_an_unknown_option() {
        let err = parse(["--lann"]).unwrap_err();
        assert!(err.contains("unknown option"), "unexpected message: {err}");
    }

    #[test]
    fn no_target_is_an_error() {
        assert!(parse(Vec::<String>::new()).is_err());
        assert!(parse(["--threads", "8"]).is_err());
    }

    #[test]
    fn two_targets_are_rejected() {
        assert!(parse(["10.0.0.1", "10.0.0.2"]).is_err());
        assert!(parse(["10.0.0.1", "--lan", "auto"]).is_err());
    }

    #[test]
    fn discover_defaults_to_auto_network() {
        assert_eq!(
            cfg(&["--discover"]).target,
            Target::Discover(NetworkSpec::Auto)
        );
        assert_eq!(
            cfg(&["--discover", "auto"]).target,
            Target::Discover(NetworkSpec::Auto)
        );
    }

    #[test]
    fn lan_accepts_an_explicit_cidr() {
        let c = cfg(&["--lan", "192.168.1.0/24"]);
        match c.target {
            Target::Lan(NetworkSpec::Explicit(cidr)) => {
                assert_eq!(
                    cidr.network,
                    "192.168.1.0".parse::<std::net::Ipv4Addr>().unwrap()
                );
                assert_eq!(cidr.prefix, 24);
            }
            other => panic!("unexpected target: {other:?}"),
        }
    }

    #[test]
    fn bad_cidr_is_an_error() {
        assert!(parse(["--lan", "192.168.1.0/33"]).is_err());
        assert!(parse(["--lan", "banana/24"]).is_err());
    }

    #[test]
    fn discover_flag_does_not_swallow_the_next_option() {
        let c = cfg(&["--discover", "--threads", "8"]);
        assert_eq!(c.target, Target::Discover(NetworkSpec::Auto));
        assert_eq!(c.threads, 8);
    }

    #[test]
    fn options_may_precede_the_target() {
        let c = cfg(&["--threads", "8", "127.0.0.1"]);
        assert_eq!(c.threads, 8);
        assert_eq!(c.target, Target::Host("127.0.0.1".to_string()));
    }

    #[test]
    fn port_specs() {
        assert_eq!(parse_ports("80").unwrap(), vec![80]);
        assert_eq!(parse_ports("22,80,443").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("1-5").unwrap(), vec![1, 2, 3, 4, 5]);
        assert_eq!(parse_ports("80, 22 , 80").unwrap(), vec![22, 80]);
        assert_eq!(parse_ports("1-3,2-4").unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(parse_ports("all").unwrap().len(), 65535);
    }

    #[test]
    fn bad_port_specs_are_errors() {
        assert!(parse_ports("").is_err());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("70000").is_err());
        assert!(parse_ports("100-1").is_err());
        assert!(parse_ports("22,,80").is_err());
        assert!(parse_ports("http").is_err());
    }

    #[test]
    fn banners_flag_defaults_off_and_is_settable() {
        assert!(!cfg(&["127.0.0.1"]).banners);
        assert!(cfg(&["127.0.0.1", "--banners"]).banners);
        assert!(cfg(&["127.0.0.1", "-b"]).banners);
    }

    #[test]
    fn help_and_version_short_circuit() {
        assert!(matches!(parse(["--help"]).unwrap(), Parsed::Help));
        assert!(matches!(parse(["-h"]).unwrap(), Parsed::Help));
        assert!(matches!(parse(["-V"]).unwrap(), Parsed::Version));
    }
}
