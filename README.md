# oxidyze

[![CI](https://github.com/dev-jreyes/oxidyze/actions/workflows/ci.yml/badge.svg)](https://github.com/dev-jreyes/oxidyze/actions/workflows/ci.yml)

A multi-threaded TCP connect scanner and LAN recon tool, written in Rust with
zero external dependencies — no async runtime, no crates, just `std`.

Point it at a host and it scans ports. Point it at a CIDR block and it finds
the live hosts, resolves their names over PTR and mDNS, pulls their MAC
addresses from the ARP cache, and optionally grabs service banners.

> **Scope:** only scan hosts and networks you own or have written
> authorization to test.

## Build

```sh
cargo build --release
./target/release/oxidyze --help
```

`cargo run -- <args>` works too, but note that a plain `cargo run` is a debug
build and will be noticeably slower than `--release`.

## Usage

```sh
oxidyze <host> [options]                 # scan one host
oxidyze --discover [cidr|auto] [options] # list live hosts on a network
oxidyze --lan [cidr|auto] [options]      # list live hosts, then scan each
```

Options:

| Flag | Meaning | Default |
| --- | --- | --- |
| `-p`, `--ports <spec>` | `1-1024`, `22,80,443`, `1-100,8080`, or `all` | `1-1024` |
| `-b`, `--banners` | grab a service banner from each open port | off |
| `-t`, `--threads <n>` | worker threads, capped at 1024 | `256` |
| `--timeout <ms>` | per-connection timeout | `300` |
| `--allow-large` | permit networks over 65536 addresses | off |

Examples:

```sh
oxidyze 127.0.0.1 --ports 1-1024
oxidyze myhost.lan -p 22,80,443 --timeout 500
oxidyze --discover auto
oxidyze --lan 192.168.4.0/24 --ports 1-1024 --threads 400
oxidyze myhost.lan -p 1-1024 --banners   # e.g. "80/tcp open  HTTP/1.1 200 OK; Server: nginx"
```

## How it works

Host discovery uses TCP connect probes on ten common ports rather than ICMP
echo, because raw ICMP sockets require root. A host counts as up if any probe
connects **or** is actively refused — a refusal still proves something is
there. Only a timeout means nothing answered.

Hostnames come from raw PTR queries against, in order: the guessed LAN gateway
(for RFC1918 targets, since public resolvers hold no PTR records for private
space), then the system resolvers, then mDNS for devices that advertise
themselves via Bonjour instead of registering with the router.

MAC addresses come from the local ARP cache, which the OS populates as a side
effect of the TCP probes — which is why the code reads `arp -a` *after*
scanning, not before. ARP doesn't cross routers, so this only works for
devices on the same L2 segment. On Linux, if `arp -a` isn't available (it
comes from net-tools, which many minimal distros skip), MAC lookup falls
back to `ip neighbor` (iproute2), which ships on essentially every Linux
system.

With `--banners`, each already-open port gets a follow-up connection: first a
passive read (catches services that speak first, like SSH/FTP/SMTP), and if
nothing arrives, a minimal HTTP probe (catches services that wait for a
request). Anything that answers with an HTTP response gets reduced to its
status line and `Server:` header; anything else is sanitized and shown as-is.
A port that stays silent either way falls back to a guessed name from a
small well-known-port table, marked with a trailing `?` to distinguish a
guess from a confirmed banner. This doesn't decode TLS, so HTTPS-only ports
(443, 8443, ...) will usually just show the guess.

## Layout

| File | Contents |
| --- | --- |
| `src/main.rs` | mode dispatch and output |
| `src/cli.rs` | argument and port-spec parsing |
| `src/net.rs` | CIDR math, address helpers |
| `src/scan.rs` | worker pool, port scanning, host discovery |
| `src/dns.rs` | PTR / mDNS lookups, resolver discovery |
| `src/arp.rs` | ARP cache parsing |
| `src/banner.rs` | service banner grabbing, well-known-port guesses |
| `src/table.rs` | text table rendering |

## Tests

```sh
cargo test
cargo clippy --all-targets
cargo fmt --check
```

75 tests, no network access required beyond loopback. The socket-touching
tests bind an ephemeral port on `127.0.0.1` and scan for it.

## Notable fixes and hardening

oxidyze began as a single-file prototype. Rewriting it as a proper Cargo
project surfaced a number of real bugs — worth listing because most of them
are easy to reproduce in any scanner written the obvious way.

Bugs fixed:

- **`print_table` panicked** on any row with more cells than headers
  (`index out of bounds`). Ragged rows are now tolerated.
- **Large `--threads` aborted the process** with `failed to spawn thread:
  Resource temporarily unavailable`. Thread count is now clamped to 1024 and
  to the number of work items, spawn failure degrades gracefully, and workers
  use 256 KB stacks instead of the default 8 MB.
- **`/31` returned zero hosts.** `network+1 ..= broadcast-1` collapses to an
  empty range; RFC 3021 makes both addresses usable.
- **Bad numeric arguments were silently ignored.** `--threads abc` now exits
  with an error instead of quietly using the default. Unknown flags are
  reported as unknown flags rather than treated as hostnames.
- **Whole CIDR ranges were materialized into a `Vec`.** A `/8` allocated
  67 MB and a `/0` would have tried for ~17 GB. Hosts are now yielded lazily,
  and anything over 65536 addresses requires `--allow-large`.

Hardening:

- DNS transaction IDs are random rather than derived from the target's last
  octet, and replies are only accepted from the resolver that was queried.
- Response buffer raised from 512 to 1232 bytes; compression-pointer loops
  are bounded so a malformed response can't hang the parser.
- macOS reads resolvers from `scutil --dns` first, since `/etc/resolv.conf`
  there is generated by configd and is often stale or missing.
- mDNS queries are pinned to multicast TTL 1.

Performance:

- Discovery probes are ordered port-major across a single shared pool, so all
  workers stay busy instead of serializing ten probes per host; a host's
  remaining probes are skipped once it has answered.
- `--lan` scans every (host, port) pair on one pool rather than spawning a
  fresh pool per host.
- The work queue is an atomic index instead of a mutex-guarded iterator, and
  discovery tracks which hosts have answered with one atomic flag per
  candidate — nothing on the hot path takes a lock.

## Ideas for later

- JSON output mode, for piping into other tools.
- Basic OS fingerprinting from TTL / TCP window size.
- UDP port scanning (currently TCP-only).

## License

MIT — see [LICENSE](LICENSE).
