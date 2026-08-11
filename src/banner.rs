//! Service banner grabbing for already-confirmed-open ports.
//!
//! Two families of TCP service exist here: ones that speak first (SSH, FTP,
//! SMTP, most databases) and ones that wait for a request (HTTP and
//! friends). Rather than hardcode a port list to decide which is which, we
//! just try a passive read, and if nothing arrives before the timeout we
//! send a minimal HTTP probe and read again. Non-HTTP services that ignore
//! the garbage bytes simply time out a second time and we fall back to a
//! guessed name from the well-known port table.
//!
//! This only ever runs against ports the connect scan already proved open,
//! so a `--banners` run costs at most two connection timeouts per open port
//! rather than per port scanned.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

/// Banners get sanitized and clipped to this many characters so a chatty
/// service (or a full HTML error page) can't blow out the results table.
const MAX_BANNER_LEN: usize = 72;

/// Best-effort label for an open port: a live banner if we can get one,
/// otherwise a guessed service name, otherwise "-".
pub fn label(ip: IpAddr, port: u16, timeout: Duration) -> String {
    if let Some(banner) = grab(ip, port, timeout) {
        banner
    } else if let Some(name) = guess_service(port) {
        format!("{name}?")
    } else {
        "-".to_string()
    }
}

fn grab(ip: IpAddr, port: u16, timeout: Duration) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;

    if let Some(text) = read_available(&mut stream) {
        return finalize(&text);
    }

    // Nothing arrived unsolicited, so this is probably a service that waits
    // for a request (HTTP and its relatives). A malformed request is enough
    // to provoke a response worth reading; anything that doesn't understand
    // it just stays silent and we fall through to the guess table.
    let probe = format!("HEAD / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\n\r\n");
    stream.write_all(probe.as_bytes()).ok()?;
    let text = read_available(&mut stream)?;
    finalize(&text)
}

fn read_available(stream: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

fn finalize(text: &str) -> Option<String> {
    let summary = summarize_http(text).unwrap_or_else(|| text.to_string());
    let cleaned = sanitize(&summary);
    if cleaned.is_empty() {
        None
    } else {
        Some(truncate(&cleaned, MAX_BANNER_LEN))
    }
}

/// Reduces an HTTP response to "status line; Server: x" instead of dumping
/// the raw headers and body. Returns `None` for anything that doesn't start
/// with a status line, so non-HTTP banners fall through unchanged.
fn summarize_http(raw: &str) -> Option<String> {
    let status = raw.split("\r\n").next()?;
    if !status.starts_with("HTTP/") {
        return None;
    }
    let server = raw
        .split("\r\n")
        .find(|line| line.len() > 7 && line[..7].eq_ignore_ascii_case("server:"))
        .map(|line| line[7..].trim());

    match server {
        Some(s) if !s.is_empty() => Some(format!("{status}; Server: {s}")),
        _ => Some(status.to_string()),
    }
}

/// Collapses control characters and runs of whitespace so a raw banner
/// prints as one clean line instead of wrapping the results table.
fn sanitize(raw: &str) -> String {
    let mut out = String::new();
    let mut last_was_space = false;
    for ch in raw.chars() {
        let mapped = if ch.is_control() { ' ' } else { ch };
        if mapped == ' ' {
            if !last_was_space {
                out.push(' ');
            }
            last_was_space = true;
        } else {
            out.push(mapped);
            last_was_space = false;
        }
    }
    out.trim().to_string()
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// A short, deliberately non-exhaustive well-known-port table: enough to
/// label the ports a home or small-office scan actually turns up, not a
/// full IANA registry.
pub fn guess_service(port: u16) -> Option<&'static str> {
    const KNOWN: &[(u16, &str)] = &[
        (21, "ftp"),
        (22, "ssh"),
        (23, "telnet"),
        (25, "smtp"),
        (53, "domain"),
        (80, "http"),
        (110, "pop3"),
        (111, "rpcbind"),
        (135, "msrpc"),
        (139, "netbios-ssn"),
        (143, "imap"),
        (389, "ldap"),
        (443, "https"),
        (445, "microsoft-ds"),
        (465, "smtps"),
        (587, "submission"),
        (636, "ldaps"),
        (853, "dns-over-tls"),
        (993, "imaps"),
        (995, "pop3s"),
        (1433, "ms-sql-s"),
        (1521, "oracle"),
        (2049, "nfs"),
        (3000, "http-dev"),
        (3306, "mysql"),
        (3389, "rdp"),
        (5000, "http-dev"),
        (5432, "postgresql"),
        (5900, "vnc"),
        (6379, "redis"),
        (8000, "http-alt"),
        (8080, "http-proxy"),
        (8443, "https-alt"),
        (8888, "http-alt"),
        (9200, "elasticsearch"),
        (11211, "memcached"),
        (27017, "mongodb"),
    ];
    KNOWN
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, name)| *name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn sanitize_collapses_control_chars_and_whitespace() {
        assert_eq!(sanitize("SSH-2.0-OpenSSH_9.6\r\n"), "SSH-2.0-OpenSSH_9.6");
        assert_eq!(sanitize("a\tb\r\n\nc"), "a b c");
    }

    #[test]
    fn truncate_adds_ellipsis_only_when_it_actually_cuts_something() {
        assert_eq!(truncate("short", 10), "short");
        let long = "a".repeat(20);
        let out = truncate(&long, 10);
        assert_eq!(out.chars().count(), 10);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn summarize_http_extracts_status_and_server() {
        let raw = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            summarize_http(raw),
            Some("HTTP/1.1 200 OK; Server: nginx/1.24.0".to_string())
        );
    }

    #[test]
    fn summarize_http_returns_none_for_non_http_text() {
        assert_eq!(summarize_http("SSH-2.0-OpenSSH_9.6\r\n"), None);
    }

    #[test]
    fn guess_service_covers_common_ports_and_nothing_else() {
        assert_eq!(guess_service(22), Some("ssh"));
        assert_eq!(guess_service(65533), None);
    }

    #[test]
    fn label_uses_the_banner_when_the_service_speaks_first() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.write_all(b"SSH-2.0-OpenSSH_9.6\r\n");
            }
        });

        let out = label(
            "127.0.0.1".parse().unwrap(),
            port,
            Duration::from_millis(500),
        );
        assert_eq!(out, "SSH-2.0-OpenSSH_9.6");
    }

    #[test]
    fn label_probes_services_that_wait_for_a_request_first() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf); // wait for our HEAD request
                let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nServer: TestServer/1.0\r\n\r\n");
            }
        });

        let out = label(
            "127.0.0.1".parse().unwrap(),
            port,
            Duration::from_millis(500),
        );
        assert_eq!(out, "HTTP/1.1 200 OK; Server: TestServer/1.0");
    }

    // Regression guard: a silent port with no known-service match must not
    // print an empty string or panic -- it should fall back to "-".
    #[test]
    fn label_falls_back_to_a_dash_for_silent_unknown_ports() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // Never accept: the connect still succeeds via the kernel backlog,
        // but nothing will ever be written back.
        assert!(guess_service(port).is_none(), "test needs an unlisted port");

        let out = label(
            "127.0.0.1".parse().unwrap(),
            port,
            Duration::from_millis(150),
        );
        assert_eq!(out, "-");
        drop(listener);
    }
}
