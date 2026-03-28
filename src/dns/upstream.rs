use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::warn;

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

const MAX_REFERRAL_DEPTH: usize = 10;

/// Parsed upstream server specification.
#[derive(Debug, Clone)]
pub enum UpstreamSpec {
    /// Plain UDP DNS (e.g., "9.9.9.10:53" or "udp://149.112.112.10:53")
    Udp(SocketAddr),
    /// DNS-over-TLS (e.g., "tls://9.9.9.10:853" or "tls://149.112.112.10:853")
    Tls { addr: SocketAddr, hostname: String },
    /// DNS-over-HTTPS (e.g., "https://dns10.quad9.net/dns-query")
    Https { url: String },
    /// DNS-over-QUIC (e.g., "quic://9.9.9.10:853" or "quic://149.112.112.10:853")
    Quic { addr: SocketAddr, hostname: String },
}

impl UpstreamSpec {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        if let Some(rest) = s.strip_prefix("tls://") {
            let (hostname, addr) = parse_host_port(rest, 853)?;
            Ok(Self::Tls { addr, hostname })
        } else if s.starts_with("https://") {
            Ok(Self::Https { url: s.to_string() })
        } else if let Some(rest) = s.strip_prefix("quic://") {
            let (hostname, addr) = parse_host_port(rest, 853)?;
            Ok(Self::Quic { addr, hostname })
        } else if let Some(rest) = s.strip_prefix("udp://") {
            let addr: SocketAddr = rest.parse()?;
            Ok(Self::Udp(addr))
        } else {
            // Default: plain UDP
            let addr: SocketAddr = s.parse()?;
            Ok(Self::Udp(addr))
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Udp(addr) => format!("udp://{}", addr),
            Self::Tls { hostname, addr } => format!("tls://{}:{}", hostname, addr.port()),
            Self::Https { url } => url.clone(),
            Self::Quic { hostname, addr } => format!("quic://{}:{}", hostname, addr.port()),
        }
    }
}

fn parse_host_port(s: &str, default_port: u16) -> anyhow::Result<(String, SocketAddr)> {
    // Try as SocketAddr first (e.g., "1.1.1.1:853")
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr));
    }

    // Try as host:port (e.g., "dns.google:853")
    if let Some((host, port_str)) = s.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            let addr = resolve_hostname(host, port)?;
            return Ok((host.to_string(), addr));
        }
    }

    // Just a hostname, use default port
    let addr = resolve_hostname(s, default_port)?;
    Ok((s.to_string(), addr))
}

fn resolve_hostname(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    let addr = format!("{}:{}", host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("Could not resolve {}", host))?;
    Ok(addr)
}

/// Handles forwarding DNS queries to upstream servers with multi-protocol support.
#[derive(Clone)]
pub struct UpstreamForwarder {
    upstreams: Arc<std::sync::RwLock<Vec<UpstreamSpec>>>,
    timeout: Duration,
    tls_client_config: Arc<rustls::ClientConfig>,
    quic_client_config: quinn::ClientConfig,
    use_root_servers: Arc<AtomicBool>,
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
        })
    }

    pub fn set_use_root_servers(&self, enabled: bool) {
        self.use_root_servers.store(enabled, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub fn is_using_root_servers(&self) -> bool {
        self.use_root_servers.load(Ordering::Relaxed)
    }

    pub fn get_upstream_labels(&self) -> Vec<String> {
        self.upstreams.read().unwrap().iter().map(|u| u.label()).collect()
    }

    pub fn add_upstream(&self, s: &str) -> anyhow::Result<()> {
        let spec = UpstreamSpec::parse(s)?;
        tracing::info!("Adding upstream: {}", spec.label());
        self.upstreams.write().unwrap().push(spec);
        Ok(())
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
        if self.use_root_servers.load(Ordering::Relaxed) {
            return self.forward_iterative(packet).await;
        }

        let upstreams = self.upstreams.read().unwrap().clone();

        if upstreams.len() == 1 {
            let upstream = &upstreams[0];
            let response = self.forward_single(packet, upstream).await?;
            return Ok((response, upstream.label()));
        }

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
                Ok(response) => return Ok((response, label)),
                Err(e) => {
                    warn!("Upstream {} failed: {}", label, e);
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("All upstream DNS servers failed")))
    }

    /// Forward a DNS query to a single upstream server.
    async fn forward_single(
        &self,
        packet: &[u8],
        upstream: &UpstreamSpec,
    ) -> anyhow::Result<Vec<u8>> {
        match upstream {
            UpstreamSpec::Udp(addr) => self.forward_udp(packet, *addr).await,
            UpstreamSpec::Tls { addr, hostname } => self.forward_dot(packet, *addr, hostname).await,
            UpstreamSpec::Https { url } => self.forward_doh(packet, url).await,
            UpstreamSpec::Quic { addr, hostname } => {
                self.forward_doq(packet, *addr, hostname).await
            }
        }
    }

    /// Iterative resolution starting from root servers.
    async fn forward_iterative(&self, packet: &[u8]) -> anyhow::Result<(Vec<u8>, String)> {
        use hickory_proto::op::{Message, ResponseCode};
        use hickory_proto::rr::{RData, RecordType};
        use hickory_proto::serialize::binary::BinDecodable;

        let mut current_servers: Vec<SocketAddr> = ROOT_SERVERS
            .iter()
            .map(|ip| SocketAddr::new(IpAddr::V4(*ip), 53))
            .collect();

        let mut last_label = "root".to_string();

        for depth in 0..MAX_REFERRAL_DEPTH {
            let server = current_servers[depth % current_servers.len()];

            let response_bytes = match self.forward_udp(packet, server).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!("Iterative: {} failed: {}", server, e);
                    continue;
                }
            };

            let response = Message::from_bytes(&response_bytes)?;

            // Got answers, NXDOMAIN, or no further referrals — return as-is
            if !response.answers().is_empty()
                || response.response_code() != ResponseCode::NoError
                || response.name_servers().is_empty()
            {
                return Ok((response_bytes, format!("iterative({})", last_label)));
            }

            // Extract NS names from authority section
            let ns_names: Vec<String> = response
                .name_servers()
                .iter()
                .filter_map(|r| match r.data() {
                    RData::NS(ns) => Some(ns.0.to_ascii()),
                    _ => None,
                })
                .collect();

            if ns_names.is_empty() {
                return Ok((response_bytes, format!("iterative({})", last_label)));
            }

            // Extract glue A records from additional section
            let mut next_servers = Vec::new();
            for record in response.additionals() {
                if record.record_type() == RecordType::A {
                    if let RData::A(ip) = record.data() {
                        let name = record.name().to_ascii();
                        if ns_names.iter().any(|ns| ns == &name) {
                            next_servers.push(SocketAddr::new(IpAddr::V4(ip.0), 53));
                        }
                    }
                }
            }

            if next_servers.is_empty() {
                // No glue records — return the referral response
                return Ok((response_bytes, format!("iterative({})", last_label)));
            }

            last_label = ns_names
                .first()
                .cloned()
                .unwrap_or_else(|| server.to_string());
            current_servers = next_servers;
        }

        anyhow::bail!("Iterative resolution: max referral depth exceeded")
    }

    /// Plain UDP forwarding.
    async fn forward_udp(&self, packet: &[u8], addr: SocketAddr) -> anyhow::Result<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(packet, addr).await?;

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(self.timeout, socket.recv_from(&mut buf)).await??;
        Ok(buf[..len].to_vec())
    }

    /// DNS-over-TLS forwarding.
    async fn forward_dot(
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

        // DNS over TCP/TLS: 2-byte big-endian length prefix
        let len_bytes = (packet.len() as u16).to_be_bytes();
        tls.write_all(&len_bytes).await?;
        tls.write_all(packet).await?;
        tls.flush().await?;

        // Read response length
        let mut resp_len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, tls.read_exact(&mut resp_len_buf)).await??;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

        // Read response
        let mut resp_buf = vec![0u8; resp_len];
        tokio::time::timeout(self.timeout, tls.read_exact(&mut resp_buf)).await??;

        Ok(resp_buf)
    }

    /// DNS-over-HTTPS forwarding (RFC 8484).
    async fn forward_doh(&self, packet: &[u8], url: &str) -> anyhow::Result<Vec<u8>> {
        // Use reqwest for HTTPS POST with application/dns-message
        let client = reqwest::Client::builder().timeout(self.timeout).build()?;

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

    /// DNS-over-QUIC forwarding (RFC 9250).
    async fn forward_doq(
        &self,
        packet: &[u8],
        addr: SocketAddr,
        hostname: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(self.quic_client_config.clone());

        let connection =
            tokio::time::timeout(self.timeout, endpoint.connect(addr, hostname)?).await??;

        // Open a bidirectional stream for this query
        let (mut send, mut recv) =
            tokio::time::timeout(self.timeout, connection.open_bi()).await??;

        // DoQ: 2-byte length prefix + DNS message
        let len_bytes = (packet.len() as u16).to_be_bytes();
        send.write_all(&len_bytes).await?;
        send.write_all(packet).await?;
        send.finish()?;

        // Read response: 2-byte length + message
        let mut resp_len_buf = [0u8; 2];
        tokio::time::timeout(self.timeout, recv.read_exact(&mut resp_len_buf)).await??;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        tokio::time::timeout(self.timeout, recv.read_exact(&mut resp_buf)).await??;

        // Clean up
        connection.close(0u32.into(), b"done");
        endpoint.wait_idle().await;

        Ok(resp_buf)
    }
}
