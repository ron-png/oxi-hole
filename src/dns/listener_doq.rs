use crate::blocklist::BlocklistManager;
use crate::config::BlockingMode;
use crate::dns::handler;
use crate::dns::upstream::UpstreamForwarder;
use crate::features::FeatureManager;
use crate::query_log::QueryLog;
use crate::stats::Stats;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// RFC 9250 §8.4 DoQ error codes.
const DOQ_NO_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x0);
const DOQ_INTERNAL_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x1);
const DOQ_PROTOCOL_ERROR: quinn::VarInt = quinn::VarInt::from_u32(0x2);

/// How long a single DoQ stream may take to finish delivering its query.
/// The connection-level idle timeout (30s in TransportConfig) covers the
/// whole connection, but a slow-dribble client could hold an open stream
/// indefinitely while still pinging keepalive traffic on the connection.
const DOQ_STREAM_READ_TIMEOUT_SECS: u64 = 5;
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
    quic_config: quinn::ServerConfig,
    query_log: QueryLog,
    anonymize_ip: Arc<AtomicBool>,
    ipv6_enabled: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let std_socket = bind_udp_reuse_port(&addr)?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(quic_config),
        std_socket,
        quinn::default_runtime().unwrap(),
    )?;
    info!("DoQ listener ready on {}", addr);

    while let Some(incoming) = endpoint.accept().await {
        let bl = blocklist.clone();
        let st = stats.clone();
        let up = upstream.clone();
        let ft = features.clone();
        let bm = blocking_mode.clone();
        let ql = query_log.clone();
        let anon = anonymize_ip.clone();
        let ipv6_enabled = ipv6_enabled.clone();

        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    let peer = connection.remote_address();
                    let client_ip = peer.ip().to_string();

                    loop {
                        match connection.accept_bi().await {
                            Ok((send, recv)) => {
                                let bl = bl.clone();
                                let st = st.clone();
                                let up = up.clone();
                                let ft = ft.clone();
                                let bm = bm.clone();
                                let cip = client_ip.clone();
                                let ql = ql.clone();
                                let anon = anon.clone();
                                let ipv6 = ipv6_enabled.clone();

                                let conn = connection.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = handle_doq_stream(
                                        conn, send, recv, &cip, &bl, &st, &up, &ft, &bm, &ql,
                                        &anon, &ipv6,
                                    )
                                    .await
                                    {
                                        debug!("DoQ stream error from {}: {}", cip, e);
                                    }
                                });
                            }
                            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
                            Err(e) => {
                                debug!("DoQ connection error: {}", e);
                                break;
                            }
                        }
                    }

                    // Graceful close with DOQ_NO_ERROR (RFC 9250 §8.4)
                    connection.close(DOQ_NO_ERROR, b"");
                }
                Err(e) => {
                    error!("DoQ incoming connection error: {}", e);
                }
            }
        });
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_doq_stream(
    connection: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    client_ip: &str,
    blocklist: &BlocklistManager,
    stats: &Stats,
    upstream: &UpstreamForwarder,
    features: &FeatureManager,
    blocking_mode: &Arc<RwLock<BlockingMode>>,
    query_log: &QueryLog,
    anonymize_ip: &Arc<AtomicBool>,
    ipv6_enabled: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    // DoQ: no length prefix per RFC 9250 §4.2 — read until stream FIN,
    // but cap the read time so a slow-dribble client can't hold a stream
    // (and therefore a spawned task slot) indefinitely.
    let msg_buf = match tokio::time::timeout(
        std::time::Duration::from_secs(DOQ_STREAM_READ_TIMEOUT_SECS),
        recv.read_to_end(65535),
    )
    .await
    {
        Ok(Ok(buf)) => buf,
        Ok(Err(_)) => {
            // RFC 9250 §4.3.3: protocol violations close the connection, not just the stream
            connection.close(DOQ_PROTOCOL_ERROR, b"failed to read stream");
            anyhow::bail!("Failed to read DoQ stream");
        }
        Err(_) => {
            // Slow client — reset just the stream, not the whole connection.
            let _ = send.reset(DOQ_PROTOCOL_ERROR);
            anyhow::bail!(
                "DoQ stream read from {} timed out after {}s",
                client_ip,
                DOQ_STREAM_READ_TIMEOUT_SECS
            );
        }
    };

    if msg_buf.is_empty() {
        connection.close(DOQ_PROTOCOL_ERROR, b"empty message");
        anyhow::bail!("Empty DoQ message");
    }

    // Some clients (e.g. kdig) send a 2-byte TCP-style length prefix even
    // though RFC 9250 §4.2 says QUIC streams don't need one.  Detect and
    // strip it so the DNS parser sees a clean message.  We remember whether
    // the client used one so we can mirror it in the response.
    let mut msg_buf = msg_buf;
    let mut client_used_length_prefix = false;
    if msg_buf.len() >= 14 {
        let maybe_len = u16::from_be_bytes([msg_buf[0], msg_buf[1]]) as usize;
        if maybe_len == msg_buf.len() - 2 {
            debug!(
                "DoQ: stripping 2-byte TCP-style length prefix from {}",
                client_ip
            );
            msg_buf = msg_buf[2..].to_vec();
            client_used_length_prefix = true;
        }
    }

    // RFC 9250 §4.2.1: DNS Message ID MUST be 0 over QUIC.
    // Many clients still send non-zero IDs.  Save the original so we can
    // echo it back (clients like kdig need it to match the response to
    // their query), then zero it for internal processing.
    let original_msg_id = if msg_buf.len() >= 2 {
        [msg_buf[0], msg_buf[1]]
    } else {
        [0, 0]
    };
    if msg_buf.len() >= 2 && (msg_buf[0] != 0 || msg_buf[1] != 0) {
        debug!("DoQ: zeroing non-zero DNS Message ID from {}", client_ip);
        msg_buf[0] = 0;
        msg_buf[1] = 0;
    }

    let response = match handler::process_dns_query_bounded(
        &msg_buf,
        client_ip,
        blocklist,
        upstream,
        stats,
        features,
        blocking_mode,
        query_log,
        anonymize_ip,
        ipv6_enabled,
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => {
            let code = match &e {
                handler::DnsError::ParseError(_) => DOQ_PROTOCOL_ERROR,
                handler::DnsError::ServerError(_) => DOQ_INTERNAL_ERROR,
            };
            send.reset(code)?;
            anyhow::bail!("{}", e);
        }
    };

    // Restore the original message ID so the client can correlate the
    // response to its query.  RFC 9250 says both MUST be 0, but clients
    // that send non-zero IDs expect the same ID back.
    let mut response = response;
    if response.len() >= 2 {
        response[0] = original_msg_id[0];
        response[1] = original_msg_id[1];
    }

    // If the client sent a TCP-style length prefix, include one in the
    // response so the client can parse it the same way it framed the query.
    if client_used_length_prefix {
        let len = (response.len() as u16).to_be_bytes();
        send.write_all(&len).await?;
    }
    send.write_all(&response).await?;
    send.finish()?;

    Ok(())
}
