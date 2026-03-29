use dashmap::DashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
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
    /// when oxi-hole is itself the system DNS resolver.
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
/// Tries the system resolver first. If that fails (e.g. oxi-hole is the system DNS
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
    let (len, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await??;
    let msg = hickory_proto::op::Message::from_bytes(&buf[..len])?;
    Ok(msg)
}

/// Resolve a hostname to IP addresses by walking the DNS hierarchy from root servers.
/// Standalone function — no UpstreamForwarder needed. Used as fallback when the
/// system resolver is unavailable (e.g. oxi-hole is the system DNS and is restarting).
async fn resolve_via_root_servers(host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::{Name, RData, RecordType};

    let fqdn = if host.ends_with('.') {
        host.to_string()
    } else {
        format!("{}.", host)
    };
    let name = Name::from_ascii(&fqdn)?;
    let timeout = Duration::from_secs(5);

    let mut current_servers: Vec<SocketAddr> = ROOT_SERVERS
        .iter()
        .map(|ip| SocketAddr::new(IpAddr::V4(*ip), 53))
        .chain(
            ROOT_SERVERS_V6
                .iter()
                .map(|ip| SocketAddr::new(IpAddr::V6(*ip), 53)),
        )
        .collect();

    for _depth in 0..MAX_REFERRAL_DEPTH {
        let query_packet = build_query(random_query_id(), &name, RecordType::A, false)?;

        // Try each server until one responds
        let mut resp = None;
        for server in &current_servers {
            match udp_query(&query_packet, *server, timeout).await {
                Ok(msg) => {
                    resp = Some(msg);
                    break;
                }
                Err(e) => {
                    warn!("Root fallback: {} failed: {}", server, e);
                }
            }
        }
        let resp = resp.ok_or_else(|| {
            anyhow::anyhow!("Root fallback: all servers failed resolving {}", host)
        })?;

        // Got A records — done
        let addrs: Vec<SocketAddr> = resp
            .answers()
            .iter()
            .filter_map(|r| match r.data() {
                RData::A(ip) => Some(SocketAddr::new(IpAddr::V4(ip.0), port)),
                _ => None,
            })
            .collect();
        // Also try AAAA if we got A records (or even if we didn't, to collect both)
        let mut all_addrs = addrs;
        {
            let aaaa_packet = build_query(random_query_id(), &name, RecordType::AAAA, false)?;
            for server in &current_servers {
                if let Ok(aaaa_resp) = udp_query(&aaaa_packet, *server, timeout).await {
                    for r in aaaa_resp.answers() {
                        if let RData::AAAA(ip) = r.data() {
                            all_addrs.push(SocketAddr::new(IpAddr::V6(ip.0), port));
                        }
                    }
                    break;
                }
            }
        }
        if !all_addrs.is_empty() {
            return Ok(all_addrs);
        }

        // NXDOMAIN or non-NOERROR — give up
        if resp.response_code() != ResponseCode::NoError {
            anyhow::bail!(
                "Root fallback: {} returned {:?}",
                host,
                resp.response_code()
            );
        }

        // Follow referral: extract NS names, then glue A records
        let ns_names: Vec<String> = resp
            .name_servers()
            .iter()
            .filter_map(|r| match r.data() {
                RData::NS(ns) => Some(ns.0.to_ascii()),
                _ => None,
            })
            .collect();

        if ns_names.is_empty() {
            anyhow::bail!("Root fallback: no referral for {}", host);
        }

        let mut next_servers = Vec::new();
        for record in resp.additionals() {
            let rec_name = record.name().to_ascii();
            if ns_names.iter().any(|n| n == &rec_name) {
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

        if next_servers.is_empty() {
            anyhow::bail!("Root fallback: no glue records for {} referral", host);
        }

        current_servers = next_servers;
    }

    anyhow::bail!("Root fallback: max referral depth exceeded for {}", host)
}

/// A cached DNS response with expiration.
struct CacheEntry {
    response_bytes: Vec<u8>,
    expires_at: Instant,
    inserted_at: Instant,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

const CACHE_TTL_FLOOR: u32 = 30;
const CACHE_TTL_CEILING: u32 = 86400;

/// Extract the minimum TTL from all records in a DNS response,
/// clamped to [CACHE_TTL_FLOOR, CACHE_TTL_CEILING].
fn extract_min_ttl(msg: &hickory_proto::op::Message) -> u32 {
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
fn rewrite_response_ttls(
    response_bytes: &[u8],
    remaining: Duration,
) -> anyhow::Result<Vec<u8>> {
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
    let normalized = domain.to_ascii_lowercase().trim_end_matches('.').to_string();
    (normalized, query_type)
}

/// Extract IP addresses from glue records (A and AAAA) in the additional section.
fn extract_glue_records(
    response: &hickory_proto::op::Message,
    ns_names: &[String],
) -> Vec<SocketAddr> {
    use hickory_proto::rr::RData;

    let mut servers = Vec::new();
    for record in response.additionals() {
        let name = record.name().to_ascii();
        if !ns_names.iter().any(|ns| ns == &name) {
            continue;
        }
        match record.data() {
            RData::A(ip) => {
                servers.push(SocketAddr::new(IpAddr::V4(ip.0), 53));
            }
            RData::AAAA(ip) => {
                servers.push(SocketAddr::new(IpAddr::V6(ip.0), 53));
            }
            _ => {}
        }
    }
    servers
}

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
        })
    }

    pub fn set_use_root_servers(&self, enabled: bool) {
        self.use_root_servers.store(enabled, Ordering::Relaxed);
    }

    /// Get cache stats: (size, hits, misses).
    pub fn cache_stats(&self) -> (usize, u64, u64) {
        (
            self.cache.len(),
            self.cache_hits.load(Ordering::Relaxed),
            self.cache_misses.load(Ordering::Relaxed),
        )
    }

    /// Flush the cache and reset counters.
    pub fn cache_flush(&self) {
        self.cache.clear();
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
    }

    /// Set whether caching is enabled.
    pub fn set_cache_enabled(&self, enabled: bool) {
        self.cache_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Remove expired entries from the cache. Returns number removed.
    pub fn evict_expired(&self) -> usize {
        let before = self.cache.len();
        self.cache.retain(|_, entry| !entry.is_expired());
        before - self.cache.len()
    }

    #[allow(dead_code)]
    pub fn is_using_root_servers(&self) -> bool {
        self.use_root_servers.load(Ordering::Relaxed)
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
    /// (not the system resolver) to avoid deadlocks when oxi-hole is the system DNS.
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
        let packet = build_query(random_query_id(), &name, RecordType::A, true)?;

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
                            // Store in cache before returning
                            if self.cache_enabled.load(Ordering::Relaxed) {
                                if let Ok(resp_msg) =
                                    hickory_proto::op::Message::from_bytes(&response)
                                {
                                    if let Ok(orig) =
                                        hickory_proto::op::Message::from_bytes(&packet)
                                    {
                                        if let Some(q) = orig.queries().first() {
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
                                                    inserted_at: Instant::now(),
                                                },
                                            );
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
                return Err(last_err
                    .unwrap_or_else(|| anyhow::anyhow!("All upstream DNS servers failed")));
            }
        };

        // Store result in cache
        let (ref response_bytes, ref _label) = result;
        if self.cache_enabled.load(Ordering::Relaxed) {
            if let Ok(resp_msg) = hickory_proto::op::Message::from_bytes(response_bytes) {
                if let Ok(orig) = hickory_proto::op::Message::from_bytes(packet) {
                    if let Some(q) = orig.queries().first() {
                        let key =
                            make_cache_key(&q.name().to_ascii(), q.query_type().into());
                        let ttl = extract_min_ttl(&resp_msg);
                        self.cache.insert(
                            key,
                            CacheEntry {
                                response_bytes: response_bytes.clone(),
                                expires_at: Instant::now() + Duration::from_secs(ttl as u64),
                                inserted_at: Instant::now(),
                            },
                        );
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
            UpstreamSpec::Udp(addr) => self.forward_udp(packet, *addr).await,
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

    /// Iterative resolution starting from root servers with QNAME minimization (RFC 7816).
    ///
    /// Instead of forwarding the client's packet to a third-party resolver, we walk
    /// the DNS hierarchy ourselves: root → TLD → authoritative, sending fresh queries
    /// with RD=0 at each level. QNAME minimization reveals only the minimal number of
    /// labels needed at each step for maximum privacy.
    async fn forward_iterative(&self, packet: &[u8]) -> anyhow::Result<(Vec<u8>, String)> {
        use hickory_proto::op::{Message, ResponseCode};
        use hickory_proto::rr::{Name, RData, RecordType};
        use hickory_proto::serialize::binary::BinDecodable;

        // Parse the original client query
        let original = Message::from_bytes(packet)?;
        let question = original
            .queries()
            .first()
            .ok_or_else(|| anyhow::anyhow!("No question in DNS query"))?;
        let target_name = question.name().clone();
        let target_type = question.query_type();
        let original_id = original.header().id();

        // Collect labels for QNAME minimization.
        // For "www.example.com." → ["www", "example", "com"]
        let labels: Vec<String> = target_name
            .iter()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .collect();

        let mut current_servers: Vec<SocketAddr> = ROOT_SERVERS
            .iter()
            .map(|ip| SocketAddr::new(IpAddr::V4(*ip), 53))
            .collect();
        let mut last_label = "root".to_string();
        let mut known_zone_depth: usize = 0;

        // Check referral cache: find the deepest cached zone to start from
        if self.cache_enabled.load(Ordering::Relaxed) {
            for start in 0..labels.len() {
                let zone = format!("{}.", labels[start..].join(".")).to_lowercase();
                let key = (zone.clone(), hickory_proto::rr::RecordType::NS.into());
                if let Some(entry) = self.cache.get(&key) {
                    if !entry.is_expired() {
                        if let Ok(cached_resp) =
                            hickory_proto::op::Message::from_bytes(&entry.response_bytes)
                        {
                            let ns_names: Vec<String> = cached_resp
                                .name_servers()
                                .iter()
                                .filter_map(|r| match r.data() {
                                    RData::NS(ns) => Some(ns.0.to_ascii()),
                                    _ => None,
                                })
                                .collect();
                            let cached_servers =
                                extract_glue_records(&cached_resp, &ns_names);
                            if !cached_servers.is_empty() {
                                debug!(
                                    "Iterative: starting from cached referral for {}",
                                    zone
                                );
                                current_servers = cached_servers;
                                known_zone_depth = labels.len() - start;
                                break;
                            }
                        }
                    }
                }
            }
        }

        for _depth in 0..MAX_REFERRAL_DEPTH {
            // QNAME minimization: reveal one more label than the known zone
            let qmin_depth = (known_zone_depth + 1).min(labels.len());
            let at_full_name = qmin_depth >= labels.len();

            let query_packet = if at_full_name {
                // At authoritative level — send the full original query with RD=0
                build_query(original_id, &target_name, target_type, false)?
            } else {
                // Minimized: build name from the rightmost qmin_depth labels
                let start = labels.len() - qmin_depth;
                let name_str = format!("{}.", labels[start..].join("."));
                let name = Name::from_ascii(&name_str)?;
                build_query(random_query_id(), &name, RecordType::A, false)?
            };

            debug!(
                "Iterative depth {}: querying {} servers (zone depth {})",
                _depth,
                current_servers.len(),
                known_zone_depth
            );

            let (resp_bytes, resp) =
                match self.query_any_server(&query_packet, &current_servers).await {
                    Some(r) => r,
                    None => {
                        anyhow::bail!("Iterative resolution: all servers failed at {}", last_label);
                    }
                };

            // Extract NS names from authority section
            let ns_names: Vec<String> = resp
                .name_servers()
                .iter()
                .filter_map(|r| match r.data() {
                    RData::NS(ns) => Some(ns.0.to_ascii()),
                    _ => None,
                })
                .collect();

            // Referral: NS records present, no answers, NOERROR
            if !ns_names.is_empty()
                && resp.answers().is_empty()
                && resp.response_code() == ResponseCode::NoError
            {
                let next_servers = self.resolve_referral_servers(&resp, &ns_names).await;
                if next_servers.is_empty() {
                    warn!(
                        "Iterative: could not resolve any NS for referral at {}",
                        last_label
                    );
                    return self
                        .iterative_fallback_full_query(
                            original_id,
                            &target_name,
                            target_type,
                            &current_servers,
                            &resp_bytes,
                            &last_label,
                        )
                        .await;
                }

                // Update zone depth from the NS record owner name
                if let Some(ns_record) = resp.name_servers().first() {
                    known_zone_depth = ns_record.name().num_labels() as usize;
                } else {
                    known_zone_depth = qmin_depth;
                }

                last_label = ns_names
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                current_servers = next_servers;

                // Cache the referral response so future queries for this zone skip earlier levels
                if self.cache_enabled.load(Ordering::Relaxed) {
                    if let Some(ns_record) = resp.name_servers().first() {
                        let zone = ns_record.name().to_ascii().to_lowercase();
                        let ttl = extract_min_ttl(&resp);
                        self.cache.insert(
                            (zone, hickory_proto::rr::RecordType::NS.into()),
                            CacheEntry {
                                response_bytes: resp_bytes.clone(),
                                expires_at: Instant::now() + Duration::from_secs(ttl as u64),
                                inserted_at: Instant::now(),
                            },
                        );
                    }
                }

                continue;
            }

            // Got answers
            if !resp.answers().is_empty() {
                if at_full_name {
                    return Ok((resp_bytes, format!("iterative({})", last_label)));
                }
                // Answer for minimized query — send full query to same servers
                return self
                    .iterative_fallback_full_query(
                        original_id,
                        &target_name,
                        target_type,
                        &current_servers,
                        &resp_bytes,
                        &last_label,
                    )
                    .await;
            }

            // NXDOMAIN — domain doesn't exist
            if resp.response_code() == ResponseCode::NXDomain {
                if at_full_name {
                    return Ok((resp_bytes, format!("iterative({})", last_label)));
                }
                // Minimized query got NXDOMAIN — send full query to confirm
                return self
                    .iterative_fallback_full_query(
                        original_id,
                        &target_name,
                        target_type,
                        &current_servers,
                        &resp_bytes,
                        &last_label,
                    )
                    .await;
            }

            // SERVFAIL, REFUSED, or empty NOERROR
            if at_full_name {
                return Ok((resp_bytes, format!("iterative({})", last_label)));
            }
            // Ambiguous response for minimized query — try full query
            return self
                .iterative_fallback_full_query(
                    original_id,
                    &target_name,
                    target_type,
                    &current_servers,
                    &resp_bytes,
                    &last_label,
                )
                .await;
        }

        anyhow::bail!("Iterative resolution: max referral depth exceeded")
    }

    /// When a minimized query gets a non-referral response, send the full original
    /// query to the same servers to get a proper response for the client.
    async fn iterative_fallback_full_query(
        &self,
        original_id: u16,
        target_name: &hickory_proto::rr::Name,
        target_type: hickory_proto::rr::RecordType,
        servers: &[SocketAddr],
        fallback_bytes: &[u8],
        last_label: &str,
    ) -> anyhow::Result<(Vec<u8>, String)> {
        let full_packet = build_query(original_id, target_name, target_type, false)?;
        if let Some((bytes, _)) = self.query_any_server(&full_packet, servers).await {
            return Ok((bytes, format!("iterative({})", last_label)));
        }
        Ok((
            fallback_bytes.to_vec(),
            format!("iterative({})", last_label),
        ))
    }

    /// Resolve servers from a referral response: first try glue records from the
    /// additional section, then fall back to iterative resolution of NS hostnames.
    async fn resolve_referral_servers(
        &self,
        response: &hickory_proto::op::Message,
        ns_names: &[String],
    ) -> Vec<SocketAddr> {
        let servers = extract_glue_records(response, ns_names);
        if !servers.is_empty() {
            return servers;
        }

        // No glue — resolve NS names iteratively (no third-party resolvers)
        let mut servers = Vec::new();
        for ns_name in ns_names {
            if let Ok(addrs) = self.resolve_ns_iterative(ns_name).await {
                servers.extend(addrs);
            }
            if !servers.is_empty() {
                break;
            }
        }
        servers
    }

    /// Resolve an NS hostname to IP addresses using iterative resolution from root.
    /// Uses a simplified walk (no QNAME minimization) to avoid deep recursion.
    async fn resolve_ns_iterative(&self, ns_name: &str) -> anyhow::Result<Vec<SocketAddr>> {
        use hickory_proto::op::ResponseCode;
        use hickory_proto::rr::{Name, RData, RecordType};

        let fqdn = if ns_name.ends_with('.') {
            ns_name.to_string()
        } else {
            format!("{}.", ns_name)
        };
        let name = Name::from_ascii(&fqdn)?;

        let mut current_servers: Vec<SocketAddr> = ROOT_SERVERS
            .iter()
            .map(|ip| SocketAddr::new(IpAddr::V4(*ip), 53))
            .collect();

        for _depth in 0..MAX_REFERRAL_DEPTH {
            let query_packet = build_query(random_query_id(), &name, RecordType::A, false)?;

            let (_resp_bytes, resp) =
                match self.query_any_server(&query_packet, &current_servers).await {
                    Some(r) => r,
                    None => {
                        anyhow::bail!("NS resolution: all servers failed for {}", ns_name)
                    }
                };

            // Got A records — done
            if !resp.answers().is_empty() {
                let addrs: Vec<SocketAddr> = resp
                    .answers()
                    .iter()
                    .filter_map(|r| match r.data() {
                        RData::A(ip) => Some(SocketAddr::new(IpAddr::V4(ip.0), 53)),
                        _ => None,
                    })
                    .collect();
                if !addrs.is_empty() {
                    // Cache the NS address resolution
                    if self.cache_enabled.load(Ordering::Relaxed) {
                        let ttl = extract_min_ttl(&resp);
                        let key = make_cache_key(&fqdn, hickory_proto::rr::RecordType::A.into());
                        self.cache.insert(
                            key,
                            CacheEntry {
                                response_bytes: _resp_bytes.clone(),
                                expires_at: Instant::now() + Duration::from_secs(ttl as u64),
                                inserted_at: Instant::now(),
                            },
                        );
                    }
                    return Ok(addrs);
                }
            }

            // Non-NOERROR is a dead end
            if resp.response_code() != ResponseCode::NoError {
                anyhow::bail!(
                    "NS resolution: {} returned {:?}",
                    ns_name,
                    resp.response_code()
                );
            }

            // Follow referral
            let ns_names: Vec<String> = resp
                .name_servers()
                .iter()
                .filter_map(|r| match r.data() {
                    RData::NS(ns) => Some(ns.0.to_ascii()),
                    _ => None,
                })
                .collect();

            if ns_names.is_empty() {
                anyhow::bail!("NS resolution: no referral for {}", ns_name);
            }

            // Extract glue A and AAAA records
            let next_servers = extract_glue_records(&resp, &ns_names);

            if next_servers.is_empty() {
                // No glue for sub-resolution — give up to avoid infinite recursion
                anyhow::bail!("NS resolution: no glue records for {} referral", ns_name);
            }

            current_servers = next_servers;
        }

        anyhow::bail!("NS resolution: max depth exceeded for {}", ns_name)
    }

    /// Try querying each server in the list until one gives a parseable response.
    async fn query_any_server(
        &self,
        packet: &[u8],
        servers: &[SocketAddr],
    ) -> Option<(Vec<u8>, hickory_proto::op::Message)> {
        use hickory_proto::serialize::binary::BinDecodable;

        // Pick up to 3 random servers to query in parallel
        let selected: Vec<SocketAddr> = {
            use rand::seq::SliceRandom;
            let mut rng = rand::rng();
            let mut v: Vec<SocketAddr> = servers.to_vec();
            v.shuffle(&mut rng);
            v.truncate(3);
            v
        };

        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<(Vec<u8>, hickory_proto::op::Message)>(selected.len());

        for server in &selected {
            let tx = tx.clone();
            let forwarder = self.clone();
            let packet = packet.to_vec();
            let server = *server;

            tokio::spawn(async move {
                match forwarder.forward_udp(&packet, server).await {
                    Ok(bytes) => {
                        match hickory_proto::op::Message::from_bytes(&bytes) {
                            Ok(msg) => {
                                // TC bit — retry over TCP
                                if msg.header().truncated() {
                                    debug!("Truncated response from {}, retrying via TCP", server);
                                    if let Ok(tcp_bytes) =
                                        forwarder.forward_tcp(&packet, server).await
                                    {
                                        if let Ok(tcp_msg) =
                                            hickory_proto::op::Message::from_bytes(&tcp_bytes)
                                        {
                                            let _ = tx.send((tcp_bytes, tcp_msg)).await;
                                            return;
                                        }
                                    }
                                    // TCP failed — still send truncated UDP response
                                    let _ = tx.send((bytes, msg)).await;
                                } else {
                                    let _ = tx.send((bytes, msg)).await;
                                }
                            }
                            Err(e) => {
                                warn!("Iterative: bad response from {}: {}", server, e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Iterative: {} failed: {}", server, e);
                    }
                }
            });
        }
        drop(tx);

        // Return the first successful response
        rx.recv().await
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

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(self.timeout, socket.recv_from(&mut buf)).await??;
        Ok(buf[..len].to_vec())
    }

    /// Plain TCP forwarding (for TC=1 retry). Uses 2-byte length prefix per RFC 1035 4.2.2.
    async fn forward_tcp(&self, packet: &[u8], addr: SocketAddr) -> anyhow::Result<Vec<u8>> {
        let tcp = tokio::time::timeout(
            self.timeout,
            tokio::net::TcpStream::connect(addr),
        )
        .await??;

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

    async fn forward_doq_single(
        &self,
        packet: &[u8],
        addr: SocketAddr,
        hostname: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let bind_addr: std::net::SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse()?
        } else {
            "[::]:0".parse()?
        };
        let mut endpoint = quinn::Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(self.quic_client_config.clone());

        let connection =
            tokio::time::timeout(self.timeout, endpoint.connect(addr, hostname)?).await??;

        let (mut send, mut recv) =
            tokio::time::timeout(self.timeout, connection.open_bi()).await??;

        // DoQ: 2-byte length prefix + DNS message
        let len_bytes = (packet.len() as u16).to_be_bytes();
        send.write_all(&len_bytes).await?;
        send.write_all(packet).await?;
        send.finish()?;

        let mut resp_len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, recv.read_exact(&mut resp_len_buf)).await??;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        tokio::time::timeout(self.timeout, recv.read_exact(&mut resp_buf)).await??;

        connection.close(0u32.into(), b"done");
        endpoint.wait_idle().await;

        Ok(resp_buf)
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

/// Generate a pseudo-random query ID.
fn random_query_id() -> u16 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(1234)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Integration test: resolve a well-known hostname via root servers.
    /// This verifies the full iterative resolution path works without
    /// any system DNS dependency.
    #[tokio::test]
    async fn test_resolve_via_root_servers() {
        // dns.google is a stable hostname that should always resolve
        let addrs = resolve_via_root_servers("dns.google", 853).await.unwrap();
        assert!(!addrs.is_empty(), "Should resolve to at least one address");
        // All returned addresses should have the requested port
        for addr in &addrs {
            assert_eq!(addr.port(), 853);
        }
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn cache_entry_is_expired_after_ttl() {
        let entry = CacheEntry {
            response_bytes: vec![0u8; 10],
            expires_at: Instant::now() - Duration::from_secs(1),
            inserted_at: Instant::now() - Duration::from_secs(61),
        };
        assert!(entry.is_expired());
    }

    #[test]
    fn cache_entry_is_not_expired_before_ttl() {
        let entry = CacheEntry {
            response_bytes: vec![0u8; 10],
            expires_at: Instant::now() + Duration::from_secs(60),
            inserted_at: Instant::now(),
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
        let record = Record::from_rdata(name, 5, RData::A("1.2.3.4".parse().unwrap()));
        msg.add_answer(record);

        assert_eq!(extract_min_ttl(&msg), 30);
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

        assert_eq!(extract_min_ttl(&msg), 30);
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
    fn glue_extraction_includes_aaaa() {
        use hickory_proto::op::{Header, Message, MessageType, ResponseCode};
        use hickory_proto::rr::{Name, RData, Record};
        use hickory_proto::rr::rdata;

        let mut msg = Message::new();
        let mut header = Header::new();
        header.set_id(1);
        header.set_message_type(MessageType::Response);
        header.set_response_code(ResponseCode::NoError);
        msg.set_header(header);

        // Add NS record in authority
        let ns_name = Name::from_ascii("example.com.").unwrap();
        let ns_target = Name::from_ascii("ns1.example.com.").unwrap();
        let ns_rdata = RData::NS(rdata::NS(ns_target.clone()));
        let ns_record = Record::from_rdata(ns_name, 300, ns_rdata);
        msg.add_name_server(ns_record);

        // Add AAAA glue in additional (no A glue)
        let aaaa_rdata = RData::AAAA("2001:db8::1".parse().unwrap());
        let aaaa_record = Record::from_rdata(ns_target, 300, aaaa_rdata);
        msg.add_additional(aaaa_record);

        let ns_names = vec!["ns1.example.com.".to_string()];
        let servers = extract_glue_records(&msg, &ns_names);
        assert!(!servers.is_empty(), "Should extract AAAA glue records");
        assert!(servers[0].is_ipv6());
    }
}
