use crate::blocklist::BlocklistManager;
use crate::config::BlockingMode;
use crate::dns::handler;
use crate::dns::upstream::UpstreamForwarder;
use crate::features::FeatureManager;
use crate::query_log::QueryLog;
use crate::stats::Stats;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, warn};

/// Minimum valid DNS message size (header only, RFC 1035 §4.1.1).
const MIN_DNS_MESSAGE_LEN: usize = 12;

/// Extract the EDNS0 UDP payload size from an OPT record in the request.
/// Returns the client-advertised buffer size, or 512 if no OPT is present (RFC 1035 default).
fn get_edns_udp_size(packet: &[u8]) -> usize {
    use hickory_proto::op::Message;
    use hickory_proto::serialize::binary::BinDecodable;

    if let Ok(msg) = Message::from_bytes(packet) {
        if let Some(opt) = msg.extensions() {
            // OPT record's CLASS field encodes the UDP payload size (RFC 6891 §6.1.2)
            let client_size = opt.max_payload() as usize;
            // Clamp to a reasonable range: at least 512, at most 4096
            // (RFC 6891 §6.2.5 recommends 1232 for avoiding fragmentation)
            return client_size.clamp(512, 4096);
        }
    }
    512 // RFC 1035 default when no EDNS0
}

/// Truncate a DNS response to fit within the UDP size limit.
/// Sets the TC bit and removes records until it fits.
/// Preserves OPT records in the additional section (RFC 6891 §7).
fn truncate_udp_response(response: &[u8], max_size: usize) -> anyhow::Result<Vec<u8>> {
    use hickory_proto::op::Message;
    use hickory_proto::serialize::binary::BinDecodable;

    let msg = Message::from_bytes(response)?;
    let mut truncated = Message::new();
    let mut header = *msg.header();
    header.set_truncated(true);
    truncated.set_header(header);

    for q in msg.queries() {
        truncated.add_query(q.clone());
    }

    // Preserve OPT record from additional section (RFC 6891 §7)
    for ad in msg.additionals() {
        if ad.record_type() == hickory_proto::rr::RecordType::OPT {
            truncated.add_additional(ad.clone());
        }
    }

    // Include as many answers as will fit
    for answer in msg.answers() {
        truncated.add_answer(answer.clone());
        if let Ok(bytes) = truncated.to_vec() {
            if bytes.len() > max_size {
                // This answer pushed us over — remove it and return truncated
                let answers: Vec<_> = truncated.answers().to_vec();
                let count = answers.len().saturating_sub(1);
                let mut final_msg = Message::new();
                final_msg.set_header(header);
                for q in msg.queries() {
                    final_msg.add_query(q.clone());
                }
                for a in answers.into_iter().take(count) {
                    final_msg.add_answer(a);
                }
                // Re-add OPT record
                for ad in msg.additionals() {
                    if ad.record_type() == hickory_proto::rr::RecordType::OPT {
                        final_msg.add_additional(ad.clone());
                    }
                }
                return Ok(final_msg.to_vec()?);
            }
        }
    }

    // All answers fit — don't set TC bit (RFC 1035 §4.2.1)
    header.set_truncated(false);
    truncated.set_header(header);

    Ok(truncated.to_vec()?)
}

fn bind_udp_reuse_port(addr: &str) -> anyhow::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock_addr: std::net::SocketAddr = addr.parse()?;
    let domain = if sock_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&sock_addr.into())?;
    Ok(socket.into())
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    addr: String,
    blocklist: BlocklistManager,
    stats: Stats,
    upstream: UpstreamForwarder,
    features: FeatureManager,
    blocking_mode: Arc<RwLock<BlockingMode>>,
    ready_tx: Option<tokio::sync::oneshot::Sender<()>>,
    query_log: QueryLog,
    anonymize_ip: Arc<AtomicBool>,
    ipv6_enabled: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let std_socket = bind_udp_reuse_port(&addr)?;
    let socket = Arc::new(UdpSocket::from_std(std_socket)?);
    if let Some(tx) = ready_tx {
        let _ = tx.send(());
    }
    let mut buf = vec![0u8; 4096];
    let max_inflight = crate::resources::limits().udp_max_inflight;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_inflight));

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                error!("UDP recv error: {}", e);
                continue;
            }
        };

        // RFC 1035 §4.1.1: a valid DNS message needs at least a 12-byte header
        if len < MIN_DNS_MESSAGE_LEN {
            debug!(
                "Dropping sub-header-size UDP packet ({} bytes) from {}",
                len, src
            );
            continue;
        }

        // Backpressure: drop under flood rather than spawning unbounded tasks
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(
                    "UDP task limit reached ({}), dropping packet from {}",
                    max_inflight, src
                );
                continue;
            }
        };

        let packet = buf[..len].to_vec();
        let sock = socket.clone();
        let bl = blocklist.clone();
        let st = stats.clone();
        let up = upstream.clone();
        let ft = features.clone();
        let bm = blocking_mode.clone();
        let ql = query_log.clone();
        let anon = anonymize_ip.clone();
        let ipv6 = ipv6_enabled.clone();

        tokio::spawn(async move {
            let _permit = permit; // hold permit for task lifetime
            let client_ip = src.ip().to_string();
            match handler::process_dns_query_bounded(
                &packet, &client_ip, &bl, &up, &st, &ft, &bm, &ql, &anon, &ipv6,
            )
            .await
            {
                Ok(response) => {
                    // RFC 6891: use EDNS0 UDP payload size if present, else 512 (RFC 1035)
                    let max_udp_size = get_edns_udp_size(&packet);
                    let response = if response.len() > max_udp_size {
                        truncate_udp_response(&response, max_udp_size).unwrap_or(response)
                    } else {
                        response
                    };
                    if let Err(e) = sock.send_to(&response, src).await {
                        debug!("Failed to send UDP response to {}: {}", src, e);
                    }
                }
                Err(e) => {
                    debug!("Error handling UDP query from {}: {}", src, e);
                    use hickory_proto::op::ResponseCode;
                    let rcode = match &e {
                        handler::DnsError::ParseError(_) => ResponseCode::FormErr,
                        handler::DnsError::ServerError(_) => ResponseCode::ServFail,
                    };
                    let bytes = handler::build_error_response(&packet, rcode);
                    let _ = sock.send_to(&bytes, src).await;
                }
            }
        });
    }
}
