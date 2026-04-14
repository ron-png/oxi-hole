use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// DNS root server addresses (IPv4).
const ROOT_SERVERS: &[Ipv4Addr] = &[
    Ipv4Addr::new(198, 41, 0, 4),     // a.root-servers.net
    Ipv4Addr::new(199, 9, 14, 201),   // b.root-servers.net
    Ipv4Addr::new(192, 33, 4, 12),    // c.root-servers.net
    Ipv4Addr::new(199, 7, 91, 13),    // d.root-servers.net
    Ipv4Addr::new(192, 203, 230, 10), // e.root-servers.net
    Ipv4Addr::new(192, 5, 5, 241),    // f.root-servers.net
    Ipv4Addr::new(192, 112, 36, 4),   // g.root-servers.net
    Ipv4Addr::new(198, 97, 190, 53),  // h.root-servers.net
    Ipv4Addr::new(192, 36, 148, 17),  // i.root-servers.net
    Ipv4Addr::new(192, 58, 128, 30),  // j.root-servers.net
    Ipv4Addr::new(193, 0, 14, 129),   // k.root-servers.net
    Ipv4Addr::new(199, 7, 83, 42),    // l.root-servers.net
    Ipv4Addr::new(202, 12, 27, 33),   // m.root-servers.net
];

/// DNS root server addresses (IPv6).
const ROOT_SERVERS_V6: &[Ipv6Addr] = &[
    Ipv6Addr::new(0x2001, 0x0503, 0xba3e, 0, 0, 0, 0x0002, 0x0030), // a.root-servers.net
    Ipv6Addr::new(0x2001, 0x0500, 0x0200, 0, 0, 0, 0, 0x000b),      // b.root-servers.net
    Ipv6Addr::new(0x2001, 0x0500, 0x0002, 0, 0, 0, 0, 0x000c),      // c.root-servers.net
    Ipv6Addr::new(0x2001, 0x0500, 0x002d, 0, 0, 0, 0, 0x000d),      // d.root-servers.net
    Ipv6Addr::new(0x2001, 0x0500, 0x00a8, 0, 0, 0, 0, 0x000e),      // e.root-servers.net
    Ipv6Addr::new(0x2001, 0x0500, 0x002f, 0, 0, 0, 0, 0x000f),      // f.root-servers.net
    Ipv6Addr::new(0x2001, 0x0500, 0x0012, 0, 0, 0, 0, 0x0d0d),      // g.root-servers.net
    Ipv6Addr::new(0x2001, 0x0500, 0x0001, 0, 0, 0, 0, 0x0053),      // h.root-servers.net
    Ipv6Addr::new(0x2001, 0x07fe, 0, 0, 0, 0, 0, 0x0053),           // i.root-servers.net
    Ipv6Addr::new(0x2001, 0x0503, 0x0c27, 0, 0, 0, 0x0002, 0x0030), // j.root-servers.net
    Ipv6Addr::new(0x2001, 0x07fd, 0, 0, 0, 0, 0, 0x0001),           // k.root-servers.net
    Ipv6Addr::new(0x2001, 0x0500, 0x009f, 0, 0, 0, 0, 0x0042),      // l.root-servers.net
    Ipv6Addr::new(0x2001, 0x0dc3, 0, 0, 0, 0, 0, 0x0035),           // m.root-servers.net
];

const MAX_REFERRAL_DEPTH: usize = 10;

/// Parsed upstream server specification.
#[derive(Debug, Clone)]
pub enum UpstreamSpec {
    /// Plain UDP DNS (e.g., "8.8.8.8", "9.9.9.10:53", "udp://149.112.112.10:53")
    Udp(SocketAddr),
    /// DNS-over-TLS (e.g., "tls://9.9.9.10:853" or "tls://dns.adguard-dns.com")
    Tls {
        addrs: Vec<SocketAddr>,
        hostname: String,
    },
    /// DNS-over-HTTPS (e.g., "https://dns10.quad9.net/dns-query")
    /// Addresses are pre-resolved at parse time to avoid infinite loops
    /// when oxi-dns is itself the system DNS resolver.
    Https {
        url: String,
        hostname: String,
        resolved_addrs: Vec<SocketAddr>,
    },
    /// DNS-over-QUIC (e.g., "quic://9.9.9.10:853" or "quic://dns.adguard-dns.com")
    Quic {
        addrs: Vec<SocketAddr>,
        hostname: String,
    },
}

impl UpstreamSpec {
    /// Parse an upstream spec. Uses the system resolver for hostnames.
    /// Suitable for startup; for runtime additions use `UpstreamForwarder::add_upstream`.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        if let Some(rest) = s.strip_prefix("tls://") {
            let (hostname, port, maybe_addr) = parse_host_port(rest, 853);
            let addrs = match maybe_addr {
                Some(a) => vec![a],
                None => resolve_all_blocking(&hostname, port)?,
            };
            Ok(Self::Tls { addrs, hostname })
        } else if s.starts_with("https://") {
            let (hostname, port) = parse_url_host(s)?;
            let resolved_addrs = if let Ok(ip) = hostname.parse::<IpAddr>() {
                vec![SocketAddr::new(ip, port)]
            } else {
                resolve_all_blocking(&hostname, port)?
            };
            Ok(Self::Https {
                url: s.to_string(),
                hostname,
                resolved_addrs,
            })
        } else if let Some(rest) = s.strip_prefix("quic://") {
            let (hostname, port, maybe_addr) = parse_host_port(rest, 853);
            let addrs = match maybe_addr {
                Some(a) => vec![a],
                None => resolve_all_blocking(&hostname, port)?,
            };
            Ok(Self::Quic { addrs, hostname })
        } else if s.starts_with("sdns://") {
            anyhow::bail!(
                "DNSCrypt (sdns://) is not supported. Use tls://, https://, or quic:// instead."
            )
        } else {
            let rest = s.strip_prefix("udp://").unwrap_or(s);
            let addr = parse_udp_addr(rest)?;
            Ok(Self::Udp(addr))
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Udp(addr) => format!("udp://{}", addr),
            Self::Tls { hostname, addrs } => format!("tls://{}:{}", hostname, addrs[0].port()),
            Self::Https { url, .. } => url.clone(),
            Self::Quic { hostname, addrs } => format!("quic://{}:{}", hostname, addrs[0].port()),
        }
    }
}

/// Parse host:port or bare host with a default port. Returns (hostname, addr) if the
/// host is an IP, or (hostname, None) if it needs DNS resolution.
fn parse_host_port(s: &str, default_port: u16) -> (String, u16, Option<SocketAddr>) {
    // Try as SocketAddr first (e.g., "1.1.1.1:853")
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return (addr.ip().to_string(), addr.port(), Some(addr));
    }
    // Try as bare IP
    if let Ok(ip) = s.parse::<IpAddr>() {
        let addr = SocketAddr::new(ip, default_port);
        return (ip.to_string(), default_port, Some(addr));
    }
    // Try as host:port (e.g., "dns.google:853")
    if let Some((host, port_str)) = s.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), port, None);
        }
    }
    // Just a hostname, use default port
    (s.to_string(), default_port, None)
}

/// Parse a plain UDP address: "8.8.8.8" or "8.8.8.8:53"
fn parse_udp_addr(s: &str) -> anyhow::Result<SocketAddr> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    anyhow::bail!(
        "Invalid address '{}'. Expected an IP like 8.8.8.8 or 8.8.8.8:53",
        s
    )
}

/// Extract the hostname and port from an HTTPS URL.
fn parse_url_host(url: &str) -> anyhow::Result<(String, u16)> {
    let without_scheme = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow::anyhow!("Not an HTTPS URL"))?;
    let host_part = without_scheme.split('/').next().unwrap_or(without_scheme);
    if let Some((h, p)) = host_part.rsplit_once(':') {
        Ok((h.to_string(), p.parse::<u16>().unwrap_or(443)))
    } else {
        Ok((host_part.to_string(), 443))
    }
}

/// Blocking hostname resolution, returning all addresses.
/// Tries the system resolver first. If that fails (e.g. oxi-dns is the system DNS
/// and is restarting), falls back to iterative resolution from root servers.
fn resolve_all_blocking(host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
    use std::net::ToSocketAddrs;

    // Fast path: system resolver
    let addrs: Vec<SocketAddr> = format!("{}:{}", host, port)
        .to_socket_addrs()
        .map(|iter| iter.collect())
        .unwrap_or_default();
    if !addrs.is_empty() {
        return Ok(addrs);
    }

    // Fallback: resolve via root servers
    warn!(
        "System DNS failed to resolve '{}', falling back to root server resolution",
        host
    );
    let handle = tokio::runtime::Handle::current();
    tokio::task::block_in_place(|| handle.block_on(resolve_via_root_servers(host, port)))
}

/// Send a single UDP DNS query and parse the response.
/// Standalone — no UpstreamForwarder needed.
async fn udp_query(
    packet: &[u8],
    server: SocketAddr,
    timeout: Duration,
) -> anyhow::Result<hickory_proto::op::Message> {
    use hickory_proto::serialize::binary::BinDecodable;

    let bind_addr = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
    socket.send_to(packet, server).await?;

    let mut buf = vec![0u8; 4096];
    let (len, src) = tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await??;
    // RFC 5452 §9.2: validate response source address matches the server we queried
    if src.ip() != server.ip() || src.port() != server.port() {
        anyhow::bail!(
            "DNS response from unexpected source {} (expected {})",
            src,
            server
        );
    }
    // Some authoritative servers return malformed EDNS OPT records in the
    // additional section (e.g. ns1/ns2.dnsleaktest.com -> 23.239.16.110).
    // hickory-proto's strict parser rejects the whole packet, which would
    // make us SERVFAIL. Retry once with ARCOUNT zeroed so the additional
    // section is skipped — answer/authority parse fine.
    let msg = match hickory_proto::op::Message::from_bytes(&buf[..len]) {
        Ok(m) => m,
        Err(_) if len >= 12 => {
            let mut patched = buf[..len].to_vec();
            patched[10] = 0;
            patched[11] = 0;
            hickory_proto::op::Message::from_bytes(&patched)?
        }
        Err(e) => return Err(e.into()),
    };
    // RFC 1035 §4.1.1: validate response transaction ID matches the query
    if packet.len() >= 2 && msg.header().id() != u16::from_be_bytes([packet[0], packet[1]]) {
        anyhow::bail!("DNS response ID mismatch from {}", server);
    }
    Ok(msg)
}

/// Resolve a hostname to IP addresses by walking the DNS hierarchy from root servers.
/// Standalone function — no UpstreamForwarder needed. Used as fallback when the
/// system resolver is unavailable (e.g. oxi-dns is the system DNS and is restarting).
///
/// Delegates to `iterative_walk` with a temporary NsCache, then extracts A/AAAA
/// records from the result. Also queries AAAA separately to collect both address families.
async fn resolve_via_root_servers(host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
    use hickory_proto::rr::{Name, RData, RecordType};

    let fqdn = if host.ends_with('.') {
        host.to_string()
    } else {
        format!("{}.", host)
    };
    let name = Name::from_ascii(&fqdn)?;
    let timeout = Duration::from_secs(5);
    let tmp_cache: NsCache = DashMap::new();

    let mut addrs = Vec::new();

    // Resolve A records
    match iterative_walk(name.clone(), RecordType::A, timeout, &tmp_cache).await {
        Ok(WalkOutcome::Answers(records)) => {
            for r in &records {
                if let RData::A(ip) = r.data() {
                    addrs.push(SocketAddr::new(IpAddr::V4(ip.0), port));
                }
            }
        }
        Ok(_) => {} // NxDomain or NoData — no A records
        Err(e) => {
            warn!("Root fallback A lookup for {}: {}", host, e);
        }
    }

    // Resolve AAAA records (reuses ns_cache from the A walk)
    match iterative_walk(name, RecordType::AAAA, timeout, &tmp_cache).await {
        Ok(WalkOutcome::Answers(records)) => {
            for r in &records {
                if let RData::AAAA(ip) = r.data() {
                    addrs.push(SocketAddr::new(IpAddr::V6(ip.0), port));
                }
            }
        }
        Ok(_) => {}
        Err(e) => {
            warn!("Root fallback AAAA lookup for {}: {}", host, e);
        }
    }

    if addrs.is_empty() {
        anyhow::bail!("Root fallback: no A/AAAA records found for {}", host);
    }

    Ok(addrs)
}

/// Outcome of a single-name iterative walk.
enum WalkOutcome {
    Answers(Vec<hickory_proto::rr::Record>),
    NxDomain,
    NoData,
}

/// Look up the deepest cached NS referral that is an ancestor of `qname`.
/// E.g. for `foo.bar.example.com.` this tries `foo.bar.example.com.`,
/// `bar.example.com.`, `example.com.`, `com.` in order and returns the first
/// non-expired hit.
fn lookup_ns_cache(
    ns_cache: &NsCache,
    qname: &hickory_proto::rr::Name,
) -> Option<(String, Vec<SocketAddr>)> {
    let ascii = qname.to_ascii();
    let trimmed = ascii.trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    let labels: Vec<&str> = trimmed.split('.').collect();
    for start in 0..labels.len() {
        let key = format!("{}.", labels[start..].join(".")).to_ascii_lowercase();
        if let Some(entry) = ns_cache.get(&key) {
            if !entry.is_expired() {
                return Some((key, entry.servers.clone()));
            }
        }
    }
    None
}

/// Fully iterative DNS resolution starting from root servers (or from a
/// cached intermediate delegation when available).
///
/// Self-contained — no hickory-recursor, no upstream leakage. This is the
/// only iterative path when `use_root_servers` is enabled, so we never leak
/// queries to the configured upstreams.
///
/// Supports: arbitrary RR types, CNAME chasing, NXDOMAIN / NOERROR-empty,
/// glueless NS referrals (resolved via `resolve_via_root_servers`), and a
/// per-zone NS+glue referral cache.
///
/// Not supported: DNSSEC validation, DNAME, EDNS0 negotiation. DNSSEC is
/// planned as a follow-up.
async fn iterative_resolve_from_roots(
    original_packet: &[u8],
    timeout: Duration,
    ns_cache: &NsCache,
) -> anyhow::Result<Vec<u8>> {
    use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_proto::serialize::binary::BinDecodable;

    let original = Message::from_bytes(original_packet)?;
    let question = original
        .queries()
        .first()
        .ok_or_else(|| anyhow::anyhow!("No question in DNS query"))?;
    let qname = question.name().clone();
    let qtype = question.query_type();
    let qclass = question.query_class();
    let original_id = original.header().id();

    let outcome = iterative_walk(qname.clone(), qtype, timeout, ns_cache).await?;

    let mut response = Message::new();
    response.set_id(original_id);
    response.set_message_type(MessageType::Response);
    response.set_op_code(original.op_code());
    response.set_recursion_desired(original.recursion_desired());
    response.set_recursion_available(true);
    let mut echo = Query::new();
    echo.set_name(qname);
    echo.set_query_type(qtype);
    echo.set_query_class(qclass);
    response.add_query(echo);

    match outcome {
        WalkOutcome::Answers(records) => {
            response.set_response_code(ResponseCode::NoError);
            for r in records {
                response.add_answer(r);
            }
        }
        WalkOutcome::NxDomain => {
            response.set_response_code(ResponseCode::NXDomain);
        }
        WalkOutcome::NoData => {
            // NOERROR with no answers.
            response.set_response_code(ResponseCode::NoError);
        }
    }

    Ok(response.to_vec()?)
}

/// Walk the DNS hierarchy to resolve a single (qname, qtype) pair, starting
/// from the deepest cached delegation point if one is known, otherwise from
/// the root servers. CNAME chasing is handled by restarting the walk with
/// the target name (which may itself benefit from a cached delegation).
async fn iterative_walk(
    mut qname: hickory_proto::rr::Name,
    qtype: hickory_proto::rr::RecordType,
    timeout: Duration,
    ns_cache: &NsCache,
) -> anyhow::Result<WalkOutcome> {
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::{RData, Record, RecordType};

    const MAX_CNAME: usize = 8;

    let mut accumulated: Vec<Record> = Vec::new();
    let mut cname_hops = 0usize;

    'restart: loop {
        let (mut current_servers, _seed_zone) = match lookup_ns_cache(ns_cache, &qname) {
            Some((zone, servers)) => (servers, Some(zone)),
            None => (
                ROOT_SERVERS
                    .iter()
                    .map(|ip| SocketAddr::new(IpAddr::V4(*ip), 53))
                    .chain(
                        ROOT_SERVERS_V6
                            .iter()
                            .map(|ip| SocketAddr::new(IpAddr::V6(*ip), 53)),
                    )
                    .collect::<Vec<_>>(),
                None,
            ),
        };

        for _depth in 0..MAX_REFERRAL_DEPTH {
            let query_packet = build_query(rand::random::<u16>(), &qname, qtype, false)?;

            let mut resp = None;
            for server in &current_servers {
                match udp_query(&query_packet, *server, timeout).await {
                    Ok(msg) => {
                        resp = Some(msg);
                        break;
                    }
                    Err(e) => {
                        warn!("Self-coded walker: {} failed: {}", server, e);
                    }
                }
            }
            let resp = resp.ok_or_else(|| {
                anyhow::anyhow!("Self-coded walker: all servers failed for {}", qname)
            })?;

            match resp.response_code() {
                ResponseCode::NoError => {}
                ResponseCode::NXDomain => {
                    return Ok(if accumulated.is_empty() {
                        WalkOutcome::NxDomain
                    } else {
                        WalkOutcome::Answers(accumulated)
                    });
                }
                other => {
                    anyhow::bail!("Self-coded walker: response code {:?} for {}", other, qname)
                }
            }

            // Direct answers matching the requested type — done. Authoritative
            // servers commonly return a CNAME chain plus the final RRset of
            // the requested type in a single response; include any CNAMEs
            // from the same answer section so the client sees a record
            // whose owner name matches the original question.
            let direct: Vec<Record> = resp
                .answers()
                .iter()
                .filter(|r| r.record_type() == qtype)
                .cloned()
                .collect();
            if !direct.is_empty() {
                if qtype != RecordType::CNAME {
                    let inline_cnames: Vec<Record> = resp
                        .answers()
                        .iter()
                        .filter(|r| r.record_type() == RecordType::CNAME)
                        .cloned()
                        .collect();
                    accumulated.extend(inline_cnames);
                }
                accumulated.extend(direct);
                return Ok(WalkOutcome::Answers(accumulated));
            }

            // CNAME in the answer section — follow it unless we're explicitly
            // asking for CNAME records.
            if qtype != RecordType::CNAME {
                let cname_records: Vec<Record> = resp
                    .answers()
                    .iter()
                    .filter(|r| r.record_type() == RecordType::CNAME)
                    .cloned()
                    .collect();
                if let Some(target) = cname_records.iter().find_map(|r| match r.data() {
                    RData::CNAME(c) => Some(c.0.clone()),
                    _ => None,
                }) {
                    accumulated.extend(cname_records);
                    cname_hops += 1;
                    if cname_hops > MAX_CNAME {
                        anyhow::bail!("Self-coded walker: CNAME chain too long");
                    }
                    qname = target;
                    continue 'restart;
                }
            }

            // No answers — look for a referral in the authority section.
            let ns_names: Vec<String> = resp
                .name_servers()
                .iter()
                .filter_map(|r| match r.data() {
                    RData::NS(ns) => Some(ns.0.to_ascii()),
                    _ => None,
                })
                .collect();

            if ns_names.is_empty() {
                // NOERROR, no answers, no referral → NoData.
                return Ok(if accumulated.is_empty() {
                    WalkOutcome::NoData
                } else {
                    WalkOutcome::Answers(accumulated)
                });
            }

            // Extract glue records for the referred NSes.
            let mut next_servers: Vec<SocketAddr> = Vec::new();
            for record in resp.additionals() {
                let rec_name = record.name().to_ascii();
                if ns_names.iter().any(|n| n.eq_ignore_ascii_case(&rec_name)) {
                    match record.data() {
                        RData::A(ip) => {
                            next_servers.push(SocketAddr::new(IpAddr::V4(ip.0), 53));
                        }
                        RData::AAAA(ip) => {
                            next_servers.push(SocketAddr::new(IpAddr::V6(ip.0), 53));
                        }
                        _ => {}
                    }
                }
            }

            // Glueless referral: resolve NS hostnames using the same walker
            // and shared ns_cache (avoids a separate bootstrap resolver).
            if next_servers.is_empty() {
                for ns_name in &ns_names {
                    let ns_fqdn = if ns_name.ends_with('.') {
                        ns_name.clone()
                    } else {
                        format!("{}.", ns_name)
                    };
                    if let Ok(ns_name_parsed) = hickory_proto::rr::Name::from_ascii(&ns_fqdn) {
                        // Resolve A records for the NS hostname
                        if let Ok(WalkOutcome::Answers(records)) = Box::pin(iterative_walk(
                            ns_name_parsed.clone(),
                            RecordType::A,
                            timeout,
                            ns_cache,
                        ))
                        .await
                        {
                            for r in &records {
                                if let RData::A(ip) = r.data() {
                                    next_servers.push(SocketAddr::new(IpAddr::V4(ip.0), 53));
                                }
                            }
                        }
                        // Also try AAAA
                        if next_servers.is_empty() {
                            if let Ok(WalkOutcome::Answers(records)) = Box::pin(iterative_walk(
                                ns_name_parsed,
                                RecordType::AAAA,
                                timeout,
                                ns_cache,
                            ))
                            .await
                            {
                                for r in &records {
                                    if let RData::AAAA(ip) = r.data() {
                                        next_servers.push(SocketAddr::new(IpAddr::V6(ip.0), 53));
                                    }
                                }
                            }
                        }
                        if !next_servers.is_empty() {
                            break;
                        }
                    }
                }
            }

            if next_servers.is_empty() {
                anyhow::bail!("Self-coded walker: no usable NS for {} referral", qname);
            }

            // Populate the per-zone NS cache so the next query under this
            // zone can skip straight here instead of walking from the roots.
            // Key = the owner name of the NS RRset (the delegated zone),
            // TTL = the minimum NS RRset TTL clamped to sane bounds.
            if let Some((zone_key, ttl)) = resp
                .name_servers()
                .iter()
                .filter(|r| matches!(r.data(), RData::NS(_)))
                .fold(None::<(String, u32)>, |acc, r| {
                    let key = r.name().to_ascii().to_ascii_lowercase();
                    let key = if key.ends_with('.') {
                        key
                    } else {
                        format!("{}.", key)
                    };
                    let ttl = r.ttl();
                    Some(match acc {
                        Some((k, t)) if k == key => (k, t.min(ttl)),
                        Some(prev) => prev,
                        None => (key, ttl),
                    })
                })
            {
                if zone_key != "." {
                    let ttl = ttl.clamp(CACHE_TTL_FLOOR, CACHE_TTL_CEILING);
                    ns_cache.insert(
                        zone_key,
                        NsCacheEntry {
                            servers: next_servers.clone(),
                            expires_at: Instant::now() + Duration::from_secs(ttl as u64),
                        },
                    );
                }
            }

            current_servers = next_servers;
        }

        anyhow::bail!(
            "Self-coded walker: max referral depth exceeded for {}",
            qname
        );
    }
}

/// A cached DNS response with expiration.
struct CacheEntry {
    response_bytes: Vec<u8>,
    expires_at: Instant,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

const CACHE_TTL_FLOOR: u32 = 5;
const CACHE_TTL_CEILING: u32 = 86400;

/// Extract the appropriate cache TTL from a DNS response.
/// For negative responses (NXDOMAIN/NODATA), uses the SOA minimum TTL
/// RFC 2308 §7: only cache NOERROR and NXDOMAIN responses.
/// SERVFAIL, REFUSED, and other transient errors must not be cached.
fn is_cacheable_response(msg: &hickory_proto::op::Message) -> bool {
    use hickory_proto::op::ResponseCode;
    matches!(
        msg.response_code(),
        ResponseCode::NoError | ResponseCode::NXDomain
    )
}

/// from the authority section per RFC 2308 §5.
/// For positive responses, uses the minimum TTL across all records.
/// Result is clamped to [CACHE_TTL_FLOOR, CACHE_TTL_CEILING].
fn extract_min_ttl(msg: &hickory_proto::op::Message) -> u32 {
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::RData;

    let is_negative = msg.response_code() == ResponseCode::NXDomain
        || (msg.response_code() == ResponseCode::NoError && msg.answers().is_empty());

    if is_negative {
        // RFC 2308: use SOA minimum TTL from authority section
        let soa_ttl = msg.name_servers().iter().find_map(|r| match r.data() {
            RData::SOA(soa) => Some(r.ttl().min(soa.minimum())),
            _ => None,
        });
        return soa_ttl
            .unwrap_or(CACHE_TTL_FLOOR)
            .clamp(CACHE_TTL_FLOOR, CACHE_TTL_CEILING);
    }

    let all_records = msg
        .answers()
        .iter()
        .chain(msg.name_servers().iter())
        .chain(msg.additionals().iter());

    let min_ttl = all_records
        .map(|r| r.ttl())
        .min()
        .unwrap_or(CACHE_TTL_FLOOR);

    min_ttl.clamp(CACHE_TTL_FLOOR, CACHE_TTL_CEILING)
}

/// Rewrite all TTL values in a cached DNS response to reflect remaining cache time.
fn rewrite_response_ttls(response_bytes: &[u8], remaining: Duration) -> anyhow::Result<Vec<u8>> {
    use hickory_proto::op::Message;
    use hickory_proto::serialize::binary::BinDecodable;

    let msg = Message::from_bytes(response_bytes)?;
    let ttl = remaining.as_secs().max(1) as u32;

    let mut new_msg = Message::new();
    new_msg.set_header(*msg.header());
    for q in msg.queries() {
        new_msg.add_query(q.clone());
    }
    for mut r in msg.answers().to_vec() {
        r.set_ttl(ttl);
        new_msg.add_answer(r);
    }
    for mut r in msg.name_servers().to_vec() {
        r.set_ttl(ttl);
        new_msg.add_name_server(r);
    }
    for mut r in msg.additionals().to_vec() {
        r.set_ttl(ttl);
        new_msg.add_additional(r);
    }

    Ok(new_msg.to_vec()?)
}

/// Build a normalized cache key from domain and query type.
fn make_cache_key(domain: &str, query_type: u16) -> (String, u16) {
    let normalized = domain
        .to_ascii_lowercase()
        .trim_end_matches('.')
        .to_string();
    (normalized, query_type)
}

fn response_matches_name_and_type(
    response: &hickory_proto::op::Message,
    expected_name: &hickory_proto::rr::Name,
    expected_type: hickory_proto::rr::RecordType,
) -> bool {
    response.queries().first().is_some_and(|query| {
        make_cache_key(&query.name().to_ascii(), query.query_type().into())
            == make_cache_key(&expected_name.to_ascii(), expected_type.into())
    })
}

fn response_matches_query(
    response: &hickory_proto::op::Message,
    query: &hickory_proto::op::Query,
) -> bool {
    response_matches_name_and_type(response, query.name(), query.query_type())
}

fn response_bytes_match_name_and_type(
    response_bytes: &[u8],
    expected_name: &hickory_proto::rr::Name,
    expected_type: hickory_proto::rr::RecordType,
) -> bool {
    use hickory_proto::serialize::binary::BinDecodable;

    hickory_proto::op::Message::from_bytes(response_bytes)
        .map(|response| response_matches_name_and_type(&response, expected_name, expected_type))
        .unwrap_or(false)
}

/// A pooled DoQ connection for reuse per RFC 9250 §5.5.1.
struct DoqPoolEntry {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

/// Cached NS+glue referral for a zone, used by the iterative walker to skip
/// the root → TLD → ... part of the walk on subsequent queries under the
/// same delegation point.
#[derive(Clone)]
struct NsCacheEntry {
    servers: Vec<SocketAddr>,
    expires_at: Instant,
}

impl NsCacheEntry {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// Per-zone NS cache. Key = lowercase FQDN with trailing dot (e.g.
/// `"dnsleaktest.com."`), value = the addresses of the authoritative servers
/// for that zone, plus an expiry derived from the NS RRset TTL.
type NsCache = DashMap<String, NsCacheEntry>;

/// Handles forwarding DNS queries to upstream servers with multi-protocol support.
#[derive(Clone)]
pub struct UpstreamForwarder {
    upstreams: Arc<std::sync::RwLock<Vec<UpstreamSpec>>>,
    timeout: Duration,
    tls_client_config: Arc<rustls::ClientConfig>,
    quic_client_config: quinn::ClientConfig,
    use_root_servers: Arc<AtomicBool>,
    cache: Arc<DashMap<(String, u16), CacheEntry>>,
    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,
    cache_enabled: Arc<AtomicBool>,
    /// DoQ connection pool keyed by (addr, hostname) per RFC 9250 §5.5.1.
    #[allow(clippy::type_complexity)]
    doq_pool: Arc<DashMap<(SocketAddr, String), Arc<Mutex<DoqPoolEntry>>>>,
    /// Per-zone NS+glue cache used by the in-tree iterative walker.
    ns_cache: Arc<NsCache>,
}

impl UpstreamForwarder {
    pub fn new(
        upstream_strs: &[String],
        timeout_ms: u64,
        tls_client_config: Arc<rustls::ClientConfig>,
        quic_client_config: quinn::ClientConfig,
    ) -> anyhow::Result<Self> {
        let mut upstreams = Vec::new();
        for s in upstream_strs {
            match UpstreamSpec::parse(s) {
                Ok(spec) => {
                    tracing::info!("Upstream: {}", spec.label());
                    upstreams.push(spec);
                }
                Err(e) => {
                    warn!("Skipping invalid upstream '{}': {}", s, e);
                }
            }
        }
        if upstreams.is_empty() {
            anyhow::bail!("No valid upstream DNS servers configured");
        }
        Ok(Self {
            upstreams: Arc::new(std::sync::RwLock::new(upstreams)),
            timeout: Duration::from_millis(timeout_ms),
            tls_client_config,
            quic_client_config,
            use_root_servers: Arc::new(AtomicBool::new(false)),
            cache: Arc::new(DashMap::new()),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            cache_enabled: Arc::new(AtomicBool::new(true)),
            doq_pool: Arc::new(DashMap::new()),
            ns_cache: Arc::new(DashMap::new()),
        })
    }

    pub fn set_use_root_servers(&self, enabled: bool) {
        let was_enabled = self.use_root_servers.swap(enabled, Ordering::Relaxed);
        if was_enabled != enabled {
            self.cache_flush();
        }
    }

    /// Get cache stats: (size, hits, misses).
    pub fn cache_stats(&self) -> (usize, u64, u64) {
        (
            self.cache.len(),
            self.cache_hits.load(Ordering::Relaxed),
            self.cache_misses.load(Ordering::Relaxed),
        )
    }

    /// Flush the cache, reset counters, and close pooled DoQ connections.
    pub fn cache_flush(&self) {
        self.cache.clear();
        self.ns_cache.clear();
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.doq_pool.clear();
    }

    /// Set whether caching is enabled.
    pub fn set_cache_enabled(&self, enabled: bool) {
        let prev = self.cache_enabled.swap(enabled, Ordering::Relaxed);
        if prev != enabled && !enabled {
            // Disabling caching: drop the per-zone NS cache too so we don't
            // serve referrals from a stale snapshot.
            self.ns_cache.clear();
        }
    }

    /// Remove expired entries from the cache and stale DoQ connections. Returns number removed.
    pub fn evict_expired(&self) -> usize {
        let before = self.cache.len();
        self.cache.retain(|_, entry| !entry.is_expired());
        self.ns_cache.retain(|_, entry| !entry.is_expired());

        // Enforce max cache sizes — drop entries closest to expiry first.
        let limits = crate::resources::limits();
        let cache_max = limits.dns_cache_entries;
        if self.cache.len() > cache_max {
            let mut entries: Vec<((String, u16), Instant)> = self
                .cache
                .iter()
                .map(|e| (e.key().clone(), e.value().expires_at))
                .collect();
            entries.sort_by_key(|(_, exp)| *exp);
            let to_remove = self.cache.len() - cache_max;
            for (key, _) in entries.into_iter().take(to_remove) {
                self.cache.remove(&key);
            }
            tracing::info!(
                "Cache size limit enforced: evicted {} entries (max {})",
                to_remove,
                cache_max
            );
        }

        let ns_max = limits.ns_cache_entries;
        if self.ns_cache.len() > ns_max {
            let mut entries: Vec<(String, Instant)> = self
                .ns_cache
                .iter()
                .map(|e| (e.key().clone(), e.value().expires_at))
                .collect();
            entries.sort_by_key(|(_, exp)| *exp);
            let to_remove = self.ns_cache.len() - ns_max;
            for (key, _) in entries.into_iter().take(to_remove) {
                self.ns_cache.remove(&key);
            }
            tracing::info!(
                "NS cache size limit enforced: evicted {} entries (max {})",
                to_remove,
                ns_max
            );
        }

        // Clean up closed DoQ connections
        self.doq_pool.retain(|_, entry| {
            // Try to check without blocking; if locked, assume it's in use
            match entry.try_lock() {
                Ok(guard) => guard.connection.close_reason().is_none(),
                Err(_) => true,
            }
        });

        before - self.cache.len()
    }

    pub fn get_upstream_labels(&self) -> Vec<String> {
        self.upstreams
            .read()
            .unwrap()
            .iter()
            .map(|u| u.label())
            .collect()
    }

    /// Add an upstream server. Resolves hostnames using existing configured upstreams
    /// (not the system resolver) to avoid deadlocks when oxi-dns is the system DNS.
    pub async fn add_upstream(&self, s: &str) -> anyhow::Result<()> {
        let spec = if let Some(rest) = s.strip_prefix("tls://") {
            let (hostname, port, maybe_addr) = parse_host_port(rest, 853);
            let addrs = match maybe_addr {
                Some(a) => vec![a],
                None => self.resolve_hostname_via_upstreams(&hostname, port).await?,
            };
            UpstreamSpec::Tls { addrs, hostname }
        } else if s.starts_with("https://") {
            let (hostname, port) = parse_url_host(s)?;
            let resolved_addrs = if let Ok(ip) = hostname.parse::<IpAddr>() {
                vec![SocketAddr::new(ip, port)]
            } else {
                self.resolve_hostname_via_upstreams(&hostname, port).await?
            };
            UpstreamSpec::Https {
                url: s.to_string(),
                hostname,
                resolved_addrs,
            }
        } else if let Some(rest) = s.strip_prefix("quic://") {
            let (hostname, port, maybe_addr) = parse_host_port(rest, 853);
            let addrs = match maybe_addr {
                Some(a) => vec![a],
                None => self.resolve_hostname_via_upstreams(&hostname, port).await?,
            };
            UpstreamSpec::Quic { addrs, hostname }
        } else if s.starts_with("sdns://") {
            anyhow::bail!(
                "DNSCrypt (sdns://) is not supported. Use tls://, https://, or quic:// instead."
            )
        } else {
            let rest = s.strip_prefix("udp://").unwrap_or(s);
            let addr = parse_udp_addr(rest)?;
            UpstreamSpec::Udp(addr)
        };

        tracing::info!("Adding upstream: {}", spec.label());
        self.upstreams.write().unwrap().push(spec);
        Ok(())
    }

    /// Resolve a hostname to all available IP addresses by querying existing upstreams.
    async fn resolve_hostname_via_upstreams(
        &self,
        hostname: &str,
        port: u16,
    ) -> anyhow::Result<Vec<SocketAddr>> {
        use hickory_proto::rr::{Name, RData, RecordType};
        use hickory_proto::serialize::binary::BinDecodable;

        let fqdn = if hostname.ends_with('.') {
            hostname.to_string()
        } else {
            format!("{}.", hostname)
        };
        let name = Name::from_ascii(&fqdn)?;
        let packet = build_query(rand::random::<u16>(), &name, RecordType::A, true)?;

        let (response_bytes, _) = self.forward(&packet).await?;
        let response = hickory_proto::op::Message::from_bytes(&response_bytes)?;

        let addrs: Vec<SocketAddr> = response
            .answers()
            .iter()
            .filter_map(|r| match r.data() {
                RData::A(ip) => Some(SocketAddr::new(IpAddr::V4(ip.0), port)),
                _ => None,
            })
            .collect();

        if addrs.is_empty() {
            anyhow::bail!("Could not resolve hostname '{}'", hostname);
        }

        Ok(addrs)
    }

    pub fn remove_upstream(&self, s: &str) -> bool {
        let mut upstreams = self.upstreams.write().unwrap();
        let before = upstreams.len();
        upstreams.retain(|u| u.label() != s);
        let removed = upstreams.len() < before;
        if removed {
            tracing::info!("Removed upstream: {}", s);
        }
        removed
    }

    /// Forward a DNS query to upstream servers.
    /// When multiple upstreams are configured, queries all in parallel and
    /// returns the fastest successful response.
    pub async fn forward(&self, packet: &[u8]) -> anyhow::Result<(Vec<u8>, String)> {
        use hickory_proto::serialize::binary::BinDecodable;

        // Try cache lookup first
        if self.cache_enabled.load(Ordering::Relaxed) {
            if let Ok(msg) = hickory_proto::op::Message::from_bytes(packet) {
                if let Some(q) = msg.queries().first() {
                    let key = make_cache_key(&q.name().to_ascii(), q.query_type().into());
                    if let Some(entry) = self.cache.get(&key) {
                        if !entry.is_expired() {
                            if response_bytes_match_name_and_type(
                                &entry.response_bytes,
                                q.name(),
                                q.query_type(),
                            ) {
                                let remaining = entry.expires_at.duration_since(Instant::now());
                                if let Ok(rewritten) =
                                    rewrite_response_ttls(&entry.response_bytes, remaining)
                                {
                                    // Rewrite the message ID to match the request
                                    let mut rewritten = rewritten;
                                    if rewritten.len() >= 2 {
                                        let id_bytes = msg.header().id().to_be_bytes();
                                        rewritten[0] = id_bytes[0];
                                        rewritten[1] = id_bytes[1];
                                    }
                                    self.cache_hits.fetch_add(1, Ordering::Relaxed);
                                    return Ok((rewritten, "cache".to_string()));
                                }
                            } else {
                                drop(entry);
                                self.cache.remove(&key);
                            }
                        } else {
                            drop(entry);
                            self.cache.remove(&key);
                        }
                    }
                    self.cache_misses.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        // Cache miss — forward to upstream or iterative
        let result = if self.use_root_servers.load(Ordering::Relaxed) {
            self.forward_iterative(packet).await?
        } else {
            let upstreams = self.upstreams.read().unwrap().clone();
            if upstreams.len() == 1 {
                let upstream = &upstreams[0];
                let response = self.forward_single(packet, upstream).await?;
                (response, upstream.label())
            } else {
                // Query all upstreams in parallel, return the fastest success
                let (tx, mut rx) = tokio::sync::mpsc::channel(upstreams.len());
                for upstream in &upstreams {
                    let tx = tx.clone();
                    let forwarder = self.clone();
                    let packet = packet.to_vec();
                    let label = upstream.label();
                    let upstream = upstream.clone();
                    tokio::spawn(async move {
                        let result = forwarder.forward_single(&packet, &upstream).await;
                        let _ = tx.send((result, label)).await;
                    });
                }
                drop(tx);
                let mut last_err = None;
                while let Some((result, label)) = rx.recv().await {
                    match result {
                        Ok(response) => {
                            // Store in cache before returning (RFC 2308 §7: only NOERROR/NXDOMAIN)
                            if self.cache_enabled.load(Ordering::Relaxed) {
                                if let Ok(resp_msg) =
                                    hickory_proto::op::Message::from_bytes(&response)
                                {
                                    if is_cacheable_response(&resp_msg) {
                                        if let Ok(orig) =
                                            hickory_proto::op::Message::from_bytes(packet)
                                        {
                                            if let Some(q) = orig.queries().first() {
                                                if response_matches_query(&resp_msg, q) {
                                                    let key = make_cache_key(
                                                        &q.name().to_ascii(),
                                                        q.query_type().into(),
                                                    );
                                                    let ttl = extract_min_ttl(&resp_msg);
                                                    self.cache.insert(
                                                        key,
                                                        CacheEntry {
                                                            response_bytes: response.clone(),
                                                            expires_at: Instant::now()
                                                                + Duration::from_secs(ttl as u64),
                                                        },
                                                    );
                                                } else {
                                                    warn!(
                                                        "Skipping cache insert for mismatched upstream response to {} {:?}",
                                                        q.name().to_ascii(),
                                                        q.query_type()
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            return Ok((response, label));
                        }
                        Err(e) => {
                            warn!("Upstream {} failed: {}", label, e);
                            last_err = Some(e);
                        }
                    }
                }
                return Err(
                    last_err.unwrap_or_else(|| anyhow::anyhow!("All upstream DNS servers failed"))
                );
            }
        };

        // Store result in cache (RFC 2308 §7: only NOERROR/NXDOMAIN)
        let (ref response_bytes, ref _label) = result;
        if self.cache_enabled.load(Ordering::Relaxed) {
            if let Ok(resp_msg) = hickory_proto::op::Message::from_bytes(response_bytes) {
                if is_cacheable_response(&resp_msg) {
                    if let Ok(orig) = hickory_proto::op::Message::from_bytes(packet) {
                        if let Some(q) = orig.queries().first() {
                            if response_matches_query(&resp_msg, q) {
                                let key =
                                    make_cache_key(&q.name().to_ascii(), q.query_type().into());
                                let ttl = extract_min_ttl(&resp_msg);
                                self.cache.insert(
                                    key,
                                    CacheEntry {
                                        response_bytes: response_bytes.clone(),
                                        expires_at: Instant::now()
                                            + Duration::from_secs(ttl as u64),
                                    },
                                );
                            } else {
                                warn!(
                                    "Skipping cache insert for mismatched upstream response to {} {:?}",
                                    q.name().to_ascii(),
                                    q.query_type()
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    /// Forward a DNS query to a single upstream server.
    async fn forward_single(
        &self,
        packet: &[u8],
        upstream: &UpstreamSpec,
    ) -> anyhow::Result<Vec<u8>> {
        match upstream {
            UpstreamSpec::Udp(addr) => {
                use hickory_proto::serialize::binary::BinDecodable;
                let response = self.forward_udp(packet, *addr).await?;
                // Check TC bit and retry over TCP per RFC 7766
                if let Ok(msg) = hickory_proto::op::Message::from_bytes(&response) {
                    if msg.header().truncated() {
                        debug!("Truncated UDP response from {}, retrying via TCP", addr);
                        if let Ok(tcp_response) = self.forward_tcp(packet, *addr).await {
                            return Ok(tcp_response);
                        }
                    }
                }
                Ok(response)
            }
            UpstreamSpec::Tls { addrs, hostname } => {
                self.forward_dot(packet, addrs, hostname).await
            }
            UpstreamSpec::Https {
                url,
                hostname,
                resolved_addrs,
            } => {
                self.forward_doh(packet, url, hostname, resolved_addrs)
                    .await
            }
            UpstreamSpec::Quic { addrs, hostname } => {
                self.forward_doq(packet, addrs, hostname).await
            }
        }
    }

    // ==================== Iterative resolution (root servers) ====================

    /// Iterative resolution starting from root servers using the in-tree
    /// walker. No upstreams are contacted — queries are answered by walking
    /// the DNS hierarchy ourselves, with a per-zone NS+glue cache to skip the
    /// upper levels of the walk on repeat queries under the same delegation.
    async fn forward_iterative(&self, packet: &[u8]) -> anyhow::Result<(Vec<u8>, String)> {
        use hickory_proto::op::Message;
        use hickory_proto::serialize::binary::BinDecodable;

        let qname = Message::from_bytes(packet)?
            .queries()
            .first()
            .map(|q| q.name().clone())
            .ok_or_else(|| anyhow::anyhow!("No question in DNS query"))?;

        let bytes = iterative_resolve_from_roots(packet, self.timeout, &self.ns_cache).await?;
        Ok((bytes, format!("root-walker({})", qname)))
    }

    // ==================== Transport methods ====================

    /// Plain UDP forwarding.
    async fn forward_udp(&self, packet: &[u8], addr: SocketAddr) -> anyhow::Result<Vec<u8>> {
        let bind_addr = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.send_to(packet, addr).await?;

        // RFC 6891 §6.2.5: buffer must accommodate max EDNS0 UDP payload (e.g. DNSSEC responses)
        let mut buf = vec![0u8; 65535];
        let (len, src) = tokio::time::timeout(self.timeout, socket.recv_from(&mut buf)).await??;
        // RFC 5452 §9.2: validate response source address matches the server we queried
        if src.ip() != addr.ip() || src.port() != addr.port() {
            anyhow::bail!(
                "DNS response from unexpected source {} (expected {})",
                src,
                addr
            );
        }
        // RFC 1035 §4.1.1: validate response transaction ID matches the query
        if packet.len() >= 2 && buf.len() >= 2 {
            let sent_id = u16::from_be_bytes([packet[0], packet[1]]);
            let recv_id = u16::from_be_bytes([buf[0], buf[1]]);
            if sent_id != recv_id {
                anyhow::bail!("DNS response ID mismatch from {}", addr);
            }
        }
        Ok(buf[..len].to_vec())
    }

    /// Plain TCP forwarding (for TC=1 retry). Uses 2-byte length prefix per RFC 1035 4.2.2.
    async fn forward_tcp(&self, packet: &[u8], addr: SocketAddr) -> anyhow::Result<Vec<u8>> {
        let tcp =
            tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(addr)).await??;

        let mut stream = tcp;
        let len = (packet.len() as u16).to_be_bytes();
        tokio::time::timeout(self.timeout, async {
            stream.write_all(&len).await?;
            stream.write_all(packet).await?;
            stream.flush().await?;

            let mut resp_len_buf = [0u8; 2];
            stream.read_exact(&mut resp_len_buf).await?;
            let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

            let mut resp_buf = vec![0u8; resp_len];
            stream.read_exact(&mut resp_buf).await?;
            Ok::<Vec<u8>, anyhow::Error>(resp_buf)
        })
        .await?
    }

    /// DNS-over-TLS forwarding. Races all resolved addresses in parallel,
    /// returns the fastest successful response.
    async fn forward_dot(
        &self,
        packet: &[u8],
        addrs: &[SocketAddr],
        hostname: &str,
    ) -> anyhow::Result<Vec<u8>> {
        if addrs.len() == 1 {
            return self.forward_dot_single(packet, addrs[0], hostname).await;
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel(addrs.len());
        for addr in addrs {
            let tx = tx.clone();
            let forwarder = self.clone();
            let packet = packet.to_vec();
            let hostname = hostname.to_string();
            let addr = *addr;
            tokio::spawn(async move {
                let result = forwarder.forward_dot_single(&packet, addr, &hostname).await;
                let _ = tx.send((result, addr)).await;
            });
        }
        drop(tx);

        let mut last_err = None;
        while let Some((result, addr)) = rx.recv().await {
            match result {
                Ok(response) => return Ok(response),
                Err(e) => {
                    warn!("DoT {} failed: {}", addr, e);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("DoT: all addresses failed")))
    }

    async fn forward_dot_single(
        &self,
        packet: &[u8],
        addr: SocketAddr,
        hostname: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let connector = tokio_rustls::TlsConnector::from(self.tls_client_config.clone());
        let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())?;

        let tcp =
            tokio::time::timeout(self.timeout, tokio::net::TcpStream::connect(addr)).await??;
        let mut tls =
            tokio::time::timeout(self.timeout, connector.connect(server_name, tcp)).await??;

        let len_bytes = (packet.len() as u16).to_be_bytes();
        tls.write_all(&len_bytes).await?;
        tls.write_all(packet).await?;
        tls.flush().await?;

        let mut resp_len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, tls.read_exact(&mut resp_len_buf)).await??;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        tokio::time::timeout(self.timeout, tls.read_exact(&mut resp_buf)).await??;

        Ok(resp_buf)
    }

    /// DNS-over-HTTPS forwarding (RFC 8484). Races all resolved addresses in parallel,
    /// returns the fastest successful response.
    async fn forward_doh(
        &self,
        packet: &[u8],
        url: &str,
        hostname: &str,
        resolved_addrs: &[SocketAddr],
    ) -> anyhow::Result<Vec<u8>> {
        if resolved_addrs.len() == 1 {
            return self
                .forward_doh_single(packet, url, hostname, resolved_addrs[0])
                .await;
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel(resolved_addrs.len());
        for addr in resolved_addrs {
            let tx = tx.clone();
            let timeout = self.timeout;
            let packet = packet.to_vec();
            let url = url.to_string();
            let hostname = hostname.to_string();
            let addr = *addr;
            tokio::spawn(async move {
                let result =
                    Self::forward_doh_to_addr(&packet, &url, &hostname, addr, timeout).await;
                let _ = tx.send((result, addr)).await;
            });
        }
        drop(tx);

        let mut last_err = None;
        while let Some((result, addr)) = rx.recv().await {
            match result {
                Ok(response) => return Ok(response),
                Err(e) => {
                    warn!("DoH {} failed: {}", addr, e);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("DoH: all addresses failed")))
    }

    async fn forward_doh_single(
        &self,
        packet: &[u8],
        url: &str,
        hostname: &str,
        addr: SocketAddr,
    ) -> anyhow::Result<Vec<u8>> {
        Self::forward_doh_to_addr(packet, url, hostname, addr, self.timeout).await
    }

    async fn forward_doh_to_addr(
        packet: &[u8],
        url: &str,
        hostname: &str,
        addr: SocketAddr,
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .resolve(hostname, addr)
            .build()?;

        let response = client
            .post(url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(packet.to_vec())
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("DoH upstream returned status {}", response.status());
        }

        // RFC 8484 §4.1: validate response Content-Type
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !content_type.starts_with("application/dns-message") {
            anyhow::bail!(
                "DoH: unexpected Content-Type from upstream: {}",
                content_type
            );
        }

        let body = response.bytes().await?;
        Ok(body.to_vec())
    }

    /// DNS-over-QUIC forwarding (RFC 9250). Races all resolved addresses in parallel,
    /// returns the fastest successful response.
    async fn forward_doq(
        &self,
        packet: &[u8],
        addrs: &[SocketAddr],
        hostname: &str,
    ) -> anyhow::Result<Vec<u8>> {
        if addrs.len() == 1 {
            return self.forward_doq_single(packet, addrs[0], hostname).await;
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel(addrs.len());
        for addr in addrs {
            let tx = tx.clone();
            let forwarder = self.clone();
            let packet = packet.to_vec();
            let hostname = hostname.to_string();
            let addr = *addr;
            tokio::spawn(async move {
                let result = forwarder.forward_doq_single(&packet, addr, &hostname).await;
                let _ = tx.send((result, addr)).await;
            });
        }
        drop(tx);

        let mut last_err = None;
        while let Some((result, addr)) = rx.recv().await {
            match result {
                Ok(response) => return Ok(response),
                Err(e) => {
                    warn!("DoQ {} failed: {}", addr, e);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("DoQ: all addresses failed")))
    }

    /// Send a single DoQ query on a QUIC connection, returning the response bytes.
    async fn doq_query_on_connection(
        &self,
        packet: &[u8],
        connection: &quinn::Connection,
    ) -> anyhow::Result<Vec<u8>> {
        let (mut send, mut recv) =
            tokio::time::timeout(self.timeout, connection.open_bi()).await??;

        // DoQ: no length prefix per RFC 9250 §4.2
        // RFC 9250 §4.2.1: DNS Message ID MUST be set to 0 over QUIC
        let mut doq_packet = packet.to_vec();
        if doq_packet.len() >= 2 {
            doq_packet[0] = 0;
            doq_packet[1] = 0;
        }
        send.write_all(&doq_packet).await?;
        send.finish()?;

        let resp_buf = tokio::time::timeout(self.timeout, recv.read_to_end(65535)).await??;

        // Restore original message ID in the response for the caller
        let mut response = resp_buf;
        if response.len() >= 2 && packet.len() >= 2 {
            response[0] = packet[0];
            response[1] = packet[1];
        }

        Ok(response)
    }

    /// Create a new QUIC endpoint and connection for DoQ.
    async fn doq_connect(&self, addr: SocketAddr, hostname: &str) -> anyhow::Result<DoqPoolEntry> {
        let bind_addr: std::net::SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse()?
        } else {
            "[::]:0".parse()?
        };
        let mut endpoint = quinn::Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(self.quic_client_config.clone());

        let connection =
            tokio::time::timeout(self.timeout, endpoint.connect(addr, hostname)?).await??;

        Ok(DoqPoolEntry {
            endpoint,
            connection,
        })
    }

    async fn forward_doq_single(
        &self,
        packet: &[u8],
        addr: SocketAddr,
        hostname: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let pool_key = (addr, hostname.to_string());

        // Try reusing a pooled connection (RFC 9250 §5.5.1)
        if let Some(entry) = self.doq_pool.get(&pool_key) {
            let guard = entry.lock().await;
            if guard.connection.close_reason().is_none() {
                match self
                    .doq_query_on_connection(packet, &guard.connection)
                    .await
                {
                    Ok(response) => return Ok(response),
                    Err(e) => {
                        debug!(
                            "DoQ pooled connection to {}:{} failed: {}, reconnecting",
                            addr, hostname, e
                        );
                        drop(guard);
                        self.doq_pool.remove(&pool_key);
                    }
                }
            } else {
                drop(guard);
                self.doq_pool.remove(&pool_key);
            }
        }

        // Create a new connection and pool it
        let entry = self.doq_connect(addr, hostname).await?;
        let result = self
            .doq_query_on_connection(packet, &entry.connection)
            .await;

        match result {
            Ok(response) => {
                self.doq_pool.insert(pool_key, Arc::new(Mutex::new(entry)));
                Ok(response)
            }
            Err(e) => {
                // Connection failed immediately — close and don't pool
                entry.connection.close(0u32.into(), b"");
                entry.endpoint.wait_idle().await;
                Err(e)
            }
        }
    }
}

/// Build a DNS query packet with the given parameters.
fn build_query(
    id: u16,
    name: &hickory_proto::rr::Name,
    qtype: hickory_proto::rr::RecordType,
    recursion_desired: bool,
) -> anyhow::Result<Vec<u8>> {
    use hickory_proto::op::{Header, Message, MessageType, OpCode, Query};

    let mut msg = Message::new();
    let mut header = Header::new();
    header.set_id(id);
    header.set_message_type(MessageType::Query);
    header.set_op_code(OpCode::Query);
    header.set_recursion_desired(recursion_desired);
    msg.set_header(header);

    let mut query = Query::new();
    query.set_name(name.clone());
    query.set_query_type(qtype);
    msg.add_query(query);

    Ok(msg.to_vec()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;

    #[test]
    fn cache_entry_is_not_expired_before_ttl() {
        let entry = CacheEntry {
            response_bytes: vec![0u8; 10],
            expires_at: Instant::now() + Duration::from_secs(60),
        };
        assert!(!entry.is_expired());
    }

    #[test]
    fn extract_min_ttl_from_single_answer() {
        use hickory_proto::op::{Header, Message, MessageType, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record};

        let mut msg = Message::new();
        let mut header = Header::new();
        header.set_id(1);
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);
        msg.set_header(header);

        let name = Name::from_ascii("example.com.").unwrap();
        let rdata = RData::A("1.2.3.4".parse().unwrap());
        let record = Record::from_rdata(name, 120, rdata);
        msg.add_answer(record);

        assert_eq!(extract_min_ttl(&msg), 120);
    }

    #[test]
    fn extract_min_ttl_picks_smallest_across_sections() {
        use hickory_proto::op::{Header, Message, MessageType, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record};

        let mut msg = Message::new();
        let mut header = Header::new();
        header.set_id(1);
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);
        msg.set_header(header);

        let name = Name::from_ascii("example.com.").unwrap();
        let a_record = Record::from_rdata(name.clone(), 300, RData::A("1.2.3.4".parse().unwrap()));
        msg.add_answer(a_record);

        let ns_record = Record::from_rdata(name.clone(), 60, RData::A("5.6.7.8".parse().unwrap()));
        msg.add_name_server(ns_record);

        assert_eq!(extract_min_ttl(&msg), 60);
    }

    #[test]
    fn extract_min_ttl_clamps_to_floor() {
        use hickory_proto::op::{Header, Message, MessageType, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record};

        let mut msg = Message::new();
        let mut header = Header::new();
        header.set_id(1);
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);
        msg.set_header(header);

        let name = Name::from_ascii("example.com.").unwrap();
        let record = Record::from_rdata(name, 2, RData::A("1.2.3.4".parse().unwrap()));
        msg.add_answer(record);

        assert_eq!(extract_min_ttl(&msg), CACHE_TTL_FLOOR);
    }

    #[test]
    fn extract_min_ttl_clamps_to_ceiling() {
        use hickory_proto::op::{Header, Message, MessageType, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record};

        let mut msg = Message::new();
        let mut header = Header::new();
        header.set_id(1);
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);
        msg.set_header(header);

        let name = Name::from_ascii("example.com.").unwrap();
        let record = Record::from_rdata(name, 100_000, RData::A("1.2.3.4".parse().unwrap()));
        msg.add_answer(record);

        assert_eq!(extract_min_ttl(&msg), 86400);
    }

    #[test]
    fn extract_min_ttl_empty_response_returns_floor() {
        use hickory_proto::op::{Header, Message, MessageType, ResponseCode};

        let mut msg = Message::new();
        let mut header = Header::new();
        header.set_id(1);
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);
        msg.set_header(header);

        assert_eq!(extract_min_ttl(&msg), CACHE_TTL_FLOOR);
    }

    #[test]
    fn rewrite_ttls_reduces_values() {
        use hickory_proto::op::{Header, Message, MessageType, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record};
        use hickory_proto::serialize::binary::BinDecodable;

        let mut msg = Message::new();
        let mut header = Header::new();
        header.set_id(0xABCD);
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);
        msg.set_header(header);

        let name = Name::from_ascii("example.com.").unwrap();
        let record = Record::from_rdata(name, 300, RData::A("1.2.3.4".parse().unwrap()));
        msg.add_answer(record);

        let bytes = msg.to_vec().unwrap();
        let remaining = Duration::from_secs(120);
        let rewritten = rewrite_response_ttls(&bytes, remaining).unwrap();

        let parsed = Message::from_bytes(&rewritten).unwrap();
        assert_eq!(parsed.answers()[0].ttl(), 120);
        assert_eq!(parsed.header().id(), 0xABCD);
    }

    #[test]
    fn rewrite_ttls_floors_at_one() {
        use hickory_proto::op::{Header, Message, MessageType, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record};
        use hickory_proto::serialize::binary::BinDecodable;

        let mut msg = Message::new();
        let mut header = Header::new();
        header.set_id(1);
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);
        msg.set_header(header);

        let name = Name::from_ascii("example.com.").unwrap();
        let record = Record::from_rdata(name, 300, RData::A("1.2.3.4".parse().unwrap()));
        msg.add_answer(record);

        let bytes = msg.to_vec().unwrap();
        let remaining = Duration::from_secs(0);
        let rewritten = rewrite_response_ttls(&bytes, remaining).unwrap();

        let parsed = Message::from_bytes(&rewritten).unwrap();
        assert_eq!(parsed.answers()[0].ttl(), 1);
    }

    #[test]
    fn cache_key_is_case_insensitive() {
        let key1 = make_cache_key("Example.COM.", 1);
        let key2 = make_cache_key("example.com.", 1);
        assert_eq!(key1, key2);
    }

    #[test]
    fn cache_key_strips_trailing_dot() {
        let key1 = make_cache_key("example.com.", 1);
        let key2 = make_cache_key("example.com", 1);
        assert_eq!(key1, key2);
    }

    #[test]
    fn truncated_flag_detected() {
        use hickory_proto::op::{Header, Message, MessageType, ResponseCode};

        let mut msg = Message::new();
        let mut header = Header::new();
        header.set_id(1);
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);
        header.set_truncated(true);
        msg.set_header(header);

        assert!(msg.header().truncated());
    }

    #[test]
    fn cache_roundtrip_store_and_lookup() {
        use hickory_proto::op::{Header, Message, MessageType, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record};
        use hickory_proto::serialize::binary::BinDecodable;

        let cache: DashMap<(String, u16), CacheEntry> = DashMap::new();

        // Build a response
        let mut msg = Message::new();
        let mut header = Header::new();
        header.set_id(1);
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);
        msg.set_header(header);
        let name = Name::from_ascii("test.example.com.").unwrap();
        let record = Record::from_rdata(name, 300, RData::A("93.184.216.34".parse().unwrap()));
        msg.add_answer(record);
        let response_bytes = msg.to_vec().unwrap();

        // Store
        let key = make_cache_key("test.example.com.", 1); // RecordType::A = 1
        let ttl = extract_min_ttl(&msg);
        cache.insert(
            key.clone(),
            CacheEntry {
                response_bytes: response_bytes.clone(),
                expires_at: Instant::now() + Duration::from_secs(ttl as u64),
            },
        );

        // Lookup
        let entry = cache.get(&key).unwrap();
        assert!(!entry.is_expired());
        assert_eq!(entry.response_bytes, response_bytes);

        // Rewrite TTLs
        let remaining = entry.expires_at.duration_since(Instant::now());
        let rewritten = rewrite_response_ttls(&entry.response_bytes, remaining).unwrap();
        let parsed = Message::from_bytes(&rewritten).unwrap();
        assert!(!parsed.answers().is_empty());
        assert!(parsed.answers()[0].ttl() <= 300);
        assert!(parsed.answers()[0].ttl() > 0);
    }

    #[test]
    fn response_match_accepts_equivalent_question_name() {
        use hickory_proto::op::{Header, Message, MessageType, ResponseCode};
        use hickory_proto::rr::{Name, RecordType};

        let expected = Name::from_ascii("Example.COM.").unwrap();

        let mut response = Message::new();
        let mut header = Header::new();
        header.set_id(1);
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);
        response.set_header(header);

        let mut query = Query::new();
        query.set_name(Name::from_ascii("example.com.").unwrap());
        query.set_query_type(RecordType::A);
        response.add_query(query);

        assert!(response_matches_name_and_type(
            &response,
            &expected,
            RecordType::A
        ));
    }

    #[test]
    fn response_match_rejects_mismatched_question_name() {
        use hickory_proto::op::{Header, Message, MessageType, ResponseCode};
        use hickory_proto::rr::{Name, RecordType};

        let expected = Name::from_ascii("www.example.com.").unwrap();

        let mut response = Message::new();
        let mut header = Header::new();
        header.set_id(1);
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);
        response.set_header(header);

        let mut query = Query::new();
        query.set_name(Name::from_ascii("com.").unwrap());
        query.set_query_type(RecordType::NS);
        response.add_query(query);

        assert!(!response_matches_name_and_type(
            &response,
            &expected,
            RecordType::A
        ));
    }

    #[test]
    fn response_bytes_match_rejects_minimized_query_response() {
        use hickory_proto::op::{Header, Message, MessageType, ResponseCode};
        use hickory_proto::rr::{Name, RecordType};

        let expected = Name::from_ascii("www.example.com.").unwrap();

        let mut response = Message::new();
        let mut header = Header::new();
        header.set_id(1);
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);
        response.set_header(header);

        let mut query = Query::new();
        query.set_name(Name::from_ascii("example.com.").unwrap());
        query.set_query_type(RecordType::NS);
        response.add_query(query);

        let response_bytes = response.to_vec().unwrap();
        assert!(!response_bytes_match_name_and_type(
            &response_bytes,
            &expected,
            RecordType::A,
        ));
    }
}
