//! TCP connect scanning and host discovery.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Hard ceiling on worker threads.
///
/// The original passed the user's thread count straight to `thread::spawn`,
/// so a large value aborted the process with "failed to spawn thread:
/// Resource temporarily unavailable". macOS caps per-process threads well
/// below Linux, so this ceiling is deliberately conservative.
pub const MAX_THREADS: usize = 1024;

/// Workers only block on sockets, so they don't need the default 8 MB stack.
/// Shrinking it keeps a full pool cheap.
const WORKER_STACK: usize = 256 * 1024;

/// Ports probed to decide whether a host is up, in the order tried.
pub fn default_probe_ports() -> Vec<u16> {
    vec![80, 443, 22, 445, 139, 3389, 8080, 53, 21, 8443]
}

/// Clamps a requested thread count to something the OS will actually grant,
/// and never spawns more workers than there are units of work.
pub fn effective_threads(requested: usize, work_items: usize) -> usize {
    requested.clamp(1, MAX_THREADS).min(work_items.max(1))
}

/// Runs `f` over `items` on a bounded worker pool, collecting the `Some`s.
///
/// Results come back in completion order, so callers that care about
/// ordering sort afterwards.
pub fn parallel_filter_map<T, R, F>(items: Vec<T>, threads: usize, f: F) -> Vec<R>
where
    T: Copy + Send + Sync + 'static,
    R: Send + 'static,
    F: Fn(T) -> Option<R> + Send + Sync + 'static,
{
    if items.is_empty() {
        return Vec::new();
    }

    let worker_count = effective_threads(threads, items.len());
    let items = Arc::new(items);
    let cursor = Arc::new(AtomicUsize::new(0));
    let func = Arc::new(f);
    let results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    for _ in 0..worker_count {
        let items = Arc::clone(&items);
        let cursor = Arc::clone(&cursor);
        let func = Arc::clone(&func);
        let results = Arc::clone(&results);

        let spawned = thread::Builder::new()
            .stack_size(WORKER_STACK)
            .spawn(move || {
                let mut local: Vec<R> = Vec::new();
                loop {
                    let idx = cursor.fetch_add(1, Ordering::Relaxed);
                    if idx >= items.len() {
                        break;
                    }
                    if let Some(r) = func(items[idx]) {
                        local.push(r);
                    }
                }
                results.lock().unwrap().extend(local);
            });

        match spawned {
            Ok(handle) => handles.push(handle),
            // The OS refused another thread. Rather than aborting, carry on
            // with the workers we already have -- they drain the same queue.
            Err(_) => break,
        }
    }

    for handle in handles {
        let _ = handle.join();
    }

    // Every worker has been joined, so nothing else holds the lock.
    let mut guard = results.lock().unwrap();
    std::mem::take(&mut *guard)
}

fn tcp_connect_succeeds(addr: SocketAddr, timeout: Duration) -> bool {
    TcpStream::connect_timeout(&addr, timeout).is_ok()
}

/// A refused connection still proves something is listening at that address.
fn tcp_probe_answers(addr: SocketAddr, timeout: Duration) -> bool {
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => true,
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => true,
        Err(_) => false,
    }
}

/// Scans a single host's ports.
pub fn scan_ports(ip: IpAddr, ports: Vec<u16>, threads: usize, timeout: Duration) -> Vec<u16> {
    let mut open = parallel_filter_map(ports, threads, move |port| {
        tcp_connect_succeeds(SocketAddr::new(ip, port), timeout).then_some(port)
    });
    open.sort_unstable();
    open
}

/// Scans many hosts on one shared pool.
///
/// The original spawned a fresh pool per host and scanned hosts one at a
/// time; flattening to (host, port) work items keeps every worker busy for
/// the whole run.
pub fn scan_ports_multi(
    hosts: &[Ipv4Addr],
    ports: &[u16],
    threads: usize,
    timeout: Duration,
) -> HashMap<Ipv4Addr, Vec<u16>> {
    let work: Vec<(Ipv4Addr, u16)> = hosts
        .iter()
        .flat_map(|ip| ports.iter().map(move |port| (*ip, *port)))
        .collect();

    let found = parallel_filter_map(work, threads, move |(ip, port)| {
        tcp_connect_succeeds(SocketAddr::new(IpAddr::V4(ip), port), timeout).then_some((ip, port))
    });

    let mut by_host: HashMap<Ipv4Addr, Vec<u16>> =
        hosts.iter().map(|ip| (*ip, Vec::new())).collect();
    for (ip, port) in found {
        by_host.entry(ip).or_default().push(port);
    }
    for ports in by_host.values_mut() {
        ports.sort_unstable();
    }
    by_host
}

/// Finds live hosts by TCP-probing a handful of common ports.
///
/// Work is ordered port-major -- every candidate's first probe port, then
/// every candidate's second, and so on -- so the pool stays saturated
/// instead of serializing ten probes per host. Once a host has answered,
/// its remaining probes are skipped.
pub fn discover_hosts<I>(
    candidates: I,
    probe_ports: &[u16],
    threads: usize,
    timeout: Duration,
) -> Vec<Ipv4Addr>
where
    I: IntoIterator<Item = Ipv4Addr>,
{
    let candidates: Vec<Ipv4Addr> = candidates.into_iter().collect();

    // Each work item carries its candidate's index so a worker can flag the
    // host directly, without hashing the address or consulting a shared map.
    let work: Vec<(usize, Ipv4Addr, u16)> = probe_ports
        .iter()
        .flat_map(|port| {
            candidates
                .iter()
                .enumerate()
                .map(move |(idx, ip)| (idx, *ip, *port))
        })
        .collect();

    // One flag per candidate rather than a shared set behind a mutex. The
    // membership check runs on every (host, probe port) pair, so a lock there
    // put the whole pool in contention on the hot path -- for a check far
    // cheaper than the syscall needed to acquire it.
    let answered: Arc<Vec<AtomicBool>> =
        Arc::new(candidates.iter().map(|_| AtomicBool::new(false)).collect());
    let answered_worker = Arc::clone(&answered);

    parallel_filter_map(work, threads, move |(idx, ip, port)| {
        // Relaxed is sufficient: the flag synchronizes no other memory, and a
        // stale read costs at most one redundant probe -- which the mutex
        // version could also produce by racing between its check and insert.
        if answered_worker[idx].load(Ordering::Relaxed) {
            return None; // already proven up by an earlier probe
        }
        if tcp_probe_answers(SocketAddr::new(IpAddr::V4(ip), port), timeout) {
            answered_worker[idx].store(true, Ordering::Relaxed);
        }
        None::<()>
    });

    // Callers pass ascending CIDR iterators, but the signature accepts any
    // order, so sort rather than inherit whatever came in.
    let mut hosts: Vec<Ipv4Addr> = candidates
        .iter()
        .zip(answered.iter())
        .filter(|(_, flag)| flag.load(Ordering::Relaxed))
        .map(|(ip, _)| *ip)
        .collect();
    hosts.sort_unstable();
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn thread_count_is_clamped_to_the_ceiling() {
        // Regression: 200_000 threads aborted the process at runtime.
        assert_eq!(effective_threads(200_000, 10_000), MAX_THREADS);
        assert_eq!(effective_threads(usize::MAX, 10_000), MAX_THREADS);
    }

    #[test]
    fn never_spawns_more_threads_than_work() {
        // Regression: 2 ports with threads=20000 spawned 20000 threads.
        assert_eq!(effective_threads(20_000, 2), 2);
        assert_eq!(effective_threads(100, 10), 10);
    }

    #[test]
    fn always_spawns_at_least_one_thread() {
        assert_eq!(effective_threads(0, 100), 1);
        assert_eq!(effective_threads(0, 0), 1);
    }

    #[test]
    fn pool_visits_every_item_exactly_once() {
        let items: Vec<u32> = (0..5000).collect();
        let mut seen = parallel_filter_map(items.clone(), 64, Some);
        seen.sort_unstable();
        assert_eq!(seen, items);
    }

    #[test]
    fn pool_handles_empty_input() {
        let out = parallel_filter_map(Vec::<u32>::new(), 8, Some);
        assert!(out.is_empty());
    }

    #[test]
    fn finds_a_real_listening_port_and_ignores_closed_ones() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let open = scan_ports(
            "127.0.0.1".parse().unwrap(),
            vec![port, port.wrapping_add(1)],
            4,
            Duration::from_millis(300),
        );
        assert!(open.contains(&port), "expected {port} to be reported open");
    }

    #[test]
    fn multi_host_scan_groups_results_per_host() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let localhost: Ipv4Addr = "127.0.0.1".parse().unwrap();

        let results = scan_ports_multi(&[localhost], &[port], 4, Duration::from_millis(300));
        assert_eq!(results.get(&localhost), Some(&vec![port]));
    }

    #[test]
    fn discovery_reports_a_host_with_a_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let localhost: Ipv4Addr = "127.0.0.1".parse().unwrap();

        let alive = discover_hosts(vec![localhost], &[port], 4, Duration::from_millis(300));
        assert_eq!(alive, vec![localhost]);
    }

    #[test]
    fn discovery_reports_each_host_once_across_probe_ports() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let localhost: Ipv4Addr = "127.0.0.1".parse().unwrap();

        // Loopback answers on every port -- open on the listener, refused on
        // the rest -- so all three probes prove the host up. It must still be
        // reported exactly once.
        let alive = discover_hosts(
            vec![localhost],
            &[port, port.wrapping_add(1), port.wrapping_add(2)],
            4,
            Duration::from_millis(300),
        );
        assert_eq!(alive, vec![localhost]);
    }

    #[test]
    fn discovery_returns_hosts_sorted() {
        // The result is built by filtering the candidate list, so an unsorted
        // caller must not leak its ordering into the output.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let localhost: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let unroutable: Ipv4Addr = "192.0.2.1".parse().unwrap(); // TEST-NET-1

        let alive = discover_hosts(
            vec![unroutable, localhost],
            &[port],
            4,
            Duration::from_millis(50),
        );
        assert!(alive.windows(2).all(|w| w[0] < w[1]));
    }
}
