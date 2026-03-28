use crate::blocklist::BlocklistManager;
use crate::dns::upstream::UpstreamForwarder;
use crate::features::{FeatureManager, SafeSearchTarget};
use crate::stats::{QueryLogEntry, Stats};
use chrono::Utc;
use hickory_proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use std::net::Ipv4Addr;
use std::time::Instant;
use tracing::debug;

/// Process a DNS query: check safe search, check blocklist, forward if allowed.
pub async fn process_dns_query(
    packet: &[u8],
    client_ip: &str,
    blocklist: &BlocklistManager,
    upstream: &UpstreamForwarder,
    stats: &Stats,
    features: &FeatureManager,
) -> anyhow::Result<Vec<u8>> {
    let start = Instant::now();
    let request = Message::from_bytes(packet)?;

    let question = match request.queries().first() {
        Some(q) => q,
        None => anyhow::bail!("No question in DNS query"),
    };

    let domain = question.name().to_string();
    let query_type = question.query_type();
    let domain_trimmed = domain.trim_end_matches('.');

    debug!(
        "Query from {}: {} {:?}",
        client_ip, domain_trimmed, query_type
    );

    // Check safe search rewriting (A and AAAA queries)
    if query_type == RecordType::A || query_type == RecordType::AAAA {
        if let Some(target) = features.get_safe_search_target(domain_trimmed).await {
            let response = match (&target, query_type) {
                (SafeSearchTarget::A(ip), RecordType::A) => {
                    debug!("Safe search rewrite: {} -> {}", domain_trimmed, ip);
                    Some(build_safe_search_response(&request, &domain, *ip))
                }
                (SafeSearchTarget::A(_), RecordType::AAAA) => {
                    // A-only rule has no IPv6 equivalent — return empty answer
                    debug!("Safe search: no AAAA for {}", domain_trimmed);
                    Some(build_empty_response(&request))
                }
                (SafeSearchTarget::Cname(cname), _) => {
                    debug!(
                        "Safe search CNAME rewrite: {} -> {} ({:?})",
                        domain_trimmed, cname, query_type
                    );
                    build_cname_rewrite_response(&request, &domain, cname, query_type, upstream)
                        .await
                }
                _ => None,
            };

            if let Some(response) = response {
                let response_bytes = response.to_vec()?;

                stats.record_query(QueryLogEntry {
                    timestamp: Utc::now(),
                    domain: domain_trimmed.to_string(),
                    query_type: format!("{:?}", query_type),
                    client_ip: client_ip.to_string(),
                    blocked: false,
                    response_time_ms: start.elapsed().as_millis() as u64,
                    upstream: Some("safe-search".to_string()),
                });

                return Ok(response_bytes);
            }
        }
    }

    // Check blocklist
    if blocklist.is_blocked(domain_trimmed).await {
        let response = build_blocked_response(&request, &domain, query_type);
        let response_bytes = response.to_vec()?;

        stats.record_query(QueryLogEntry {
            timestamp: Utc::now(),
            domain: domain_trimmed.to_string(),
            query_type: format!("{:?}", query_type),
            client_ip: client_ip.to_string(),
            blocked: true,
            response_time_ms: start.elapsed().as_millis() as u64,
            upstream: None,
        });

        debug!("Blocked: {} {:?}", domain_trimmed, query_type);
        return Ok(response_bytes);
    }

    // Forward to upstream
    let (response_bytes, upstream_used) = upstream.forward(packet).await?;

    stats.record_query(QueryLogEntry {
        timestamp: Utc::now(),
        domain: domain_trimmed.to_string(),
        query_type: format!("{:?}", query_type),
        client_ip: client_ip.to_string(),
        blocked: false,
        response_time_ms: start.elapsed().as_millis() as u64,
        upstream: Some(upstream_used),
    });

    Ok(response_bytes)
}

/// Build a safe search response that returns a specific IP.
fn build_safe_search_response(request: &Message, domain: &str, ip: Ipv4Addr) -> Message {
    let mut response = Message::new();
    let mut header = Header::new();
    header.set_id(request.header().id());
    header.set_message_type(MessageType::Response);
    header.set_op_code(OpCode::Query);
    header.set_authoritative(true);
    header.set_recursion_desired(request.header().recursion_desired());
    header.set_recursion_available(true);
    header.set_response_code(ResponseCode::NoError);
    response.set_header(header);

    for query in request.queries() {
        response.add_query(query.clone());
    }

    let name = Name::from_ascii(domain).unwrap_or_default();
    let rdata = RData::A(ip.into());
    let record = Record::from_rdata(name, 3600, rdata);
    response.add_answer(record);

    response
}

/// Build a response that blocks the domain by returning 0.0.0.0 / :: sinkhole.
fn build_blocked_response(request: &Message, domain: &str, query_type: RecordType) -> Message {
    let mut response = Message::new();
    let mut header = Header::new();
    header.set_id(request.header().id());
    header.set_message_type(MessageType::Response);
    header.set_op_code(OpCode::Query);
    header.set_authoritative(true);
    header.set_recursion_desired(request.header().recursion_desired());
    header.set_recursion_available(true);
    header.set_response_code(ResponseCode::NoError);
    response.set_header(header);

    for query in request.queries() {
        response.add_query(query.clone());
    }

    let name = Name::from_ascii(domain).unwrap_or_default();
    match query_type {
        RecordType::A => {
            let rdata = RData::A("0.0.0.0".parse().unwrap());
            let record = Record::from_rdata(name, 300, rdata);
            response.add_answer(record);
        }
        RecordType::AAAA => {
            let rdata = RData::AAAA("::".parse().unwrap());
            let record = Record::from_rdata(name, 300, rdata);
            response.add_answer(record);
        }
        _ => {}
    }

    response
}

/// Build a CNAME rewrite response: returns CNAME record + resolved address records.
/// This is needed for safe search enforcement (e.g. YouTube restricted mode)
/// where the client must see the CNAME in the response.
/// Resolves the CNAME target for the requested query_type (A or AAAA).
async fn build_cname_rewrite_response(
    request: &Message,
    domain: &str,
    cname: &str,
    query_type: RecordType,
    upstream: &UpstreamForwarder,
) -> Option<Message> {
    use hickory_proto::op::Query;

    // Resolve the CNAME target via upstream
    let cname_fqdn = format!("{}.", cname);
    let target_name = Name::from_ascii(cname_fqdn).ok()?;

    let mut resolve_req = Message::new();
    let mut hdr = Header::new();
    hdr.set_id(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u16)
            .unwrap_or(1234),
    );
    hdr.set_message_type(MessageType::Query);
    hdr.set_op_code(OpCode::Query);
    hdr.set_recursion_desired(true);
    resolve_req.set_header(hdr);

    let mut query = Query::new();
    query.set_name(target_name.clone());
    query.set_query_type(query_type);
    resolve_req.add_query(query);

    let packet = resolve_req.to_vec().ok()?;
    let (response_bytes, _) = upstream.forward(&packet).await.ok()?;
    let upstream_resp = Message::from_bytes(&response_bytes).ok()?;

    // Build our response with CNAME + address records
    let mut response = Message::new();
    let mut header = Header::new();
    header.set_id(request.header().id());
    header.set_message_type(MessageType::Response);
    header.set_op_code(OpCode::Query);
    header.set_authoritative(true);
    header.set_recursion_desired(request.header().recursion_desired());
    header.set_recursion_available(true);
    header.set_response_code(ResponseCode::NoError);
    response.set_header(header);

    for q in request.queries() {
        response.add_query(q.clone());
    }

    // Add CNAME record: domain -> cname target
    let orig_name = Name::from_ascii(domain).unwrap_or_default();
    let cname_rdata = RData::CNAME(hickory_proto::rr::rdata::CNAME(target_name));
    let cname_record = Record::from_rdata(orig_name, 3600, cname_rdata);
    response.add_answer(cname_record);

    // Add address records from upstream resolution of the CNAME target
    // Override TTL to match our CNAME TTL so the rewrite stays cached together
    for answer in upstream_resp.answers() {
        match (answer.data(), query_type) {
            (RData::A(_), RecordType::A) | (RData::AAAA(_), RecordType::AAAA) => {
                let mut record = answer.clone();
                record.set_ttl(3600);
                response.add_answer(record);
            }
            _ => {}
        }
    }

    Some(response)
}

/// Build an empty (NOERROR, no answers) response.
fn build_empty_response(request: &Message) -> Message {
    let mut response = Message::new();
    let mut header = Header::new();
    header.set_id(request.header().id());
    header.set_message_type(MessageType::Response);
    header.set_op_code(OpCode::Query);
    header.set_authoritative(true);
    header.set_recursion_desired(request.header().recursion_desired());
    header.set_recursion_available(true);
    header.set_response_code(ResponseCode::NoError);
    response.set_header(header);
    for query in request.queries() {
        response.add_query(query.clone());
    }
    response
}
