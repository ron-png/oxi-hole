use crate::blocklist::{BlockResult, BlocklistManager};
use crate::config::BlockingMode;
use crate::dns::upstream::UpstreamForwarder;
use crate::features::{url_to_feature_id, FeatureManager, SafeSearchTarget};
use crate::query_log::{anonymize_ip, LogEntry, QueryLog};
use crate::stats::{QueryLogEntry, Stats};
use chrono::Utc;
use hickory_proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::debug;

/// Typed error for DNS query processing, allowing callers to distinguish
/// parse failures (FORMERR) from upstream/internal failures (SERVFAIL).
#[derive(Debug)]
pub enum DnsError {
    /// The query could not be parsed — respond with FORMERR (RFC 1035 §4.1.1)
    ParseError(anyhow::Error),
    /// The query was valid but processing failed — respond with SERVFAIL
    ServerError(anyhow::Error),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::ParseError(e) => write!(f, "parse error: {}", e),
            DnsError::ServerError(e) => write!(f, "server error: {}", e),
        }
    }
}

impl From<anyhow::Error> for DnsError {
    fn from(e: anyhow::Error) -> Self {
        DnsError::ServerError(e)
    }
}

impl From<hickory_proto::ProtoError> for DnsError {
    fn from(e: hickory_proto::ProtoError) -> Self {
        DnsError::ServerError(e.into())
    }
}

/// Process a DNS query: check safe search, check blocklist, forward if allowed.
#[allow(clippy::too_many_arguments)]
pub async fn process_dns_query(
    packet: &[u8],
    client_ip: &str,
    blocklist: &BlocklistManager,
    upstream: &UpstreamForwarder,
    stats: &Stats,
    features: &FeatureManager,
    blocking_mode: &Arc<RwLock<BlockingMode>>,
    query_log: &QueryLog,
    anonymize_ip_flag: &Arc<AtomicBool>,
    ipv6_enabled: &Arc<AtomicBool>,
) -> Result<Vec<u8>, DnsError> {
    let start = Instant::now();
    let request = Message::from_bytes(packet).map_err(|e| DnsError::ParseError(e.into()))?;

    // RFC 1035 §4.1.1: reject non-QUERY opcodes with NOTIMPL (RCODE=4)
    if request.header().op_code() != OpCode::Query {
        let mut response = Message::new();
        let mut header = Header::new();
        header.set_id(request.header().id());
        header.set_message_type(MessageType::Response);
        header.set_op_code(request.header().op_code());
        header.set_recursion_desired(request.header().recursion_desired());
        header.set_recursion_available(true);
        header.set_response_code(ResponseCode::NotImp);
        response.set_header(header);
        for query in request.queries() {
            response.add_query(query.clone());
        }
        echo_edns_opt(&request, &mut response);
        return Ok(response.to_vec()?);
    }

    let question = match request.queries().first() {
        Some(q) => q,
        None => {
            return Err(DnsError::ParseError(anyhow::anyhow!(
                "No question in DNS query"
            )))
        }
    };

    let domain = question.name().to_string();
    let query_type = question.query_type();
    let domain_trimmed = domain.trim_end_matches('.');

    debug!(
        "Query from {}: {} {:?}",
        client_ip, domain_trimmed, query_type
    );

    let client_ip_stored = if anonymize_ip_flag.load(Ordering::Relaxed) {
        anonymize_ip(client_ip)
    } else {
        client_ip.to_string()
    };

    // If IPv6 is disabled, return empty response for AAAA queries
    if query_type == RecordType::AAAA && !ipv6_enabled.load(Ordering::Relaxed) {
        let response = build_empty_response(&request);
        let response_bytes = response.to_vec()?;
        let elapsed = start.elapsed().as_millis() as u64;

        stats.record_query(QueryLogEntry {
            timestamp: Utc::now(),
            domain: domain_trimmed.to_string(),
            query_type: format!("{:?}", query_type),
            client_ip: client_ip_stored.clone(),
            blocked: false,
            response_time_ms: elapsed,
            upstream: None,
        });

        query_log.insert(LogEntry {
            id: 0,
            timestamp: Utc::now(),
            domain: domain_trimmed.to_string(),
            query_type: format!("{:?}", query_type),
            client_ip: client_ip_stored.clone(),
            status: "filtered_ipv6".to_string(),
            block_source: None,
            block_feature: None,
            response_time_ms: elapsed,
            upstream: None,
        });

        return Ok(response_bytes);
    }

    // Check safe search rewriting (A and AAAA queries)
    if query_type == RecordType::A || query_type == RecordType::AAAA {
        if let Some((target, feature_id)) = features.get_safe_search_target(domain_trimmed).await {
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
                let elapsed = start.elapsed().as_millis() as u64;

                stats.record_query(QueryLogEntry {
                    timestamp: Utc::now(),
                    domain: domain_trimmed.to_string(),
                    query_type: format!("{:?}", query_type),
                    client_ip: client_ip_stored.clone(),
                    blocked: false,
                    response_time_ms: elapsed,
                    upstream: Some("safe-search".to_string()),
                });

                query_log.insert(LogEntry {
                    id: 0,
                    timestamp: Utc::now(),
                    domain: domain_trimmed.to_string(),
                    query_type: format!("{:?}", query_type),
                    client_ip: client_ip_stored,
                    status: "rewritten".to_string(),
                    block_source: None,
                    block_feature: Some(feature_id.to_string()),
                    response_time_ms: elapsed,
                    upstream: Some("safe-search".to_string()),
                });

                return Ok(response_bytes);
            }
        }
    }

    // Check blocklist
    let block_result = blocklist.check_domain(domain_trimmed).await;
    if !matches!(block_result, BlockResult::Allowed) {
        let mode = blocking_mode.read().await;
        let response = build_blocked_response(&request, &domain, query_type, &mode);
        let response_bytes = response.to_vec()?;
        let elapsed = start.elapsed().as_millis() as u64;

        let (block_source, block_feature) = match &block_result {
            BlockResult::Blocked { source_url } => {
                let feature = url_to_feature_id(source_url).map(String::from);
                (Some(source_url.clone()), feature)
            }
            BlockResult::BlockedCustom => (Some("custom".to_string()), None),
            BlockResult::Allowed => unreachable!(),
        };

        stats.record_query(QueryLogEntry {
            timestamp: Utc::now(),
            domain: domain_trimmed.to_string(),
            query_type: format!("{:?}", query_type),
            client_ip: client_ip_stored.clone(),
            blocked: true,
            response_time_ms: elapsed,
            upstream: None,
        });

        query_log.insert(LogEntry {
            id: 0,
            timestamp: Utc::now(),
            domain: domain_trimmed.to_string(),
            query_type: format!("{:?}", query_type),
            client_ip: client_ip_stored,
            status: "blocked".to_string(),
            block_source,
            block_feature,
            response_time_ms: elapsed,
            upstream: None,
        });

        debug!("Blocked: {} {:?}", domain_trimmed, query_type);
        return Ok(response_bytes);
    }

    // Forward to upstream
    let (response_bytes, upstream_used) = upstream.forward(packet).await?;

    // Filter AAAA records from upstream response if IPv6 is disabled
    let response_bytes = if !ipv6_enabled.load(Ordering::Relaxed) {
        filter_aaaa_records(&response_bytes).unwrap_or(response_bytes)
    } else {
        response_bytes
    };

    let elapsed = start.elapsed().as_millis() as u64;

    stats.record_query(QueryLogEntry {
        timestamp: Utc::now(),
        domain: domain_trimmed.to_string(),
        query_type: format!("{:?}", query_type),
        client_ip: client_ip_stored.clone(),
        blocked: false,
        response_time_ms: elapsed,
        upstream: Some(upstream_used.clone()),
    });

    query_log.insert(LogEntry {
        id: 0,
        timestamp: Utc::now(),
        domain: domain_trimmed.to_string(),
        query_type: format!("{:?}", query_type),
        client_ip: client_ip_stored,
        status: "allowed".to_string(),
        block_source: None,
        block_feature: None,
        response_time_ms: elapsed,
        upstream: Some(upstream_used),
    });

    Ok(response_bytes)
}

/// Build an RFC-compliant error response from raw packet bytes.
/// Sets RA, echoes question section and EDNS OPT when the query is parseable.
pub fn build_error_response(packet: &[u8], rcode: ResponseCode) -> Vec<u8> {
    let mut resp = Message::new();
    let mut header = Header::new();
    if packet.len() >= 2 {
        header.set_id(u16::from_be_bytes([packet[0], packet[1]]));
    }
    header.set_message_type(MessageType::Response);
    header.set_response_code(rcode);
    header.set_recursion_available(true);
    resp.set_header(header);

    if let Ok(req) = Message::from_bytes(packet) {
        // RFC 1035 §4.1.1: OPCODE must be copied from query to response
        header.set_op_code(req.header().op_code());
        header.set_recursion_desired(req.header().recursion_desired());
        resp.set_header(header);
        for query in req.queries() {
            resp.add_query(query.clone());
        }
        echo_edns_opt(&req, &mut resp);
    }

    resp.to_vec().unwrap_or_default()
}

/// If the request contains an EDNS0 OPT record, add one to the response (RFC 6891 §7).
/// This signals to the client that the server supports EDNS.
fn echo_edns_opt(request: &Message, response: &mut Message) {
    if request.extensions().is_some() {
        let mut server_opt = hickory_proto::op::Edns::new();
        server_opt.set_max_payload(1232); // RFC 6891 §6.2.5
        server_opt.set_version(0);
        response.set_edns(server_opt);
    }
}

/// Build a safe search response that returns a specific IP.
fn build_safe_search_response(request: &Message, domain: &str, ip: Ipv4Addr) -> Message {
    let mut response = Message::new();
    let mut header = Header::new();
    header.set_id(request.header().id());
    header.set_message_type(MessageType::Response);
    header.set_op_code(request.header().op_code());
    header.set_authoritative(false); // RFC 1035 §6: not authoritative for rewritten domains
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
    echo_edns_opt(request, &mut response);

    response
}

/// Build a response that blocks the domain according to the configured blocking mode.
fn build_blocked_response(
    request: &Message,
    domain: &str,
    query_type: RecordType,
    mode: &BlockingMode,
) -> Message {
    let mut response = Message::new();
    let mut header = Header::new();
    header.set_id(request.header().id());
    header.set_message_type(MessageType::Response);
    header.set_op_code(request.header().op_code());
    header.set_authoritative(true);
    header.set_recursion_desired(request.header().recursion_desired());
    header.set_recursion_available(true);

    match mode {
        BlockingMode::Refused => {
            header.set_response_code(ResponseCode::Refused);
            response.set_header(header);
            for query in request.queries() {
                response.add_query(query.clone());
            }
            echo_edns_opt(request, &mut response);
            return response;
        }
        BlockingMode::NxDomain => {
            header.set_response_code(ResponseCode::NXDomain);
            response.set_header(header);
            for query in request.queries() {
                response.add_query(query.clone());
            }
            echo_edns_opt(request, &mut response);
            return response;
        }
        _ => {
            header.set_response_code(ResponseCode::NoError);
        }
    }

    response.set_header(header);
    for query in request.queries() {
        response.add_query(query.clone());
    }

    let name = Name::from_ascii(domain).unwrap_or_default();

    match mode {
        BlockingMode::Default | BlockingMode::NullIp => match query_type {
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
        },
        BlockingMode::CustomIp { ipv4, ipv6 } => match query_type {
            RecordType::A => {
                let rdata = RData::A((*ipv4).into());
                let record = Record::from_rdata(name, 300, rdata);
                response.add_answer(record);
            }
            RecordType::AAAA => {
                let rdata = RData::AAAA((*ipv6).into());
                let record = Record::from_rdata(name, 300, rdata);
                response.add_answer(record);
            }
            _ => {}
        },
        BlockingMode::Refused | BlockingMode::NxDomain => unreachable!(),
    }

    echo_edns_opt(request, &mut response);
    response
}

/// Build a CNAME rewrite response: returns CNAME chain + resolved address records.
async fn build_cname_rewrite_response(
    request: &Message,
    domain: &str,
    cname: &str,
    query_type: RecordType,
    upstream: &UpstreamForwarder,
) -> Option<Message> {
    use hickory_proto::op::Query;

    const MAX_CNAME_HOPS: usize = 10;

    let orig_name = Name::from_ascii(domain).ok()?;
    let cname_fqdn = format!("{}.", cname);
    let mut current_target = Name::from_ascii(cname_fqdn).ok()?;

    let mut response = Message::new();
    let mut header = Header::new();
    header.set_id(request.header().id());
    header.set_message_type(MessageType::Response);
    header.set_op_code(request.header().op_code());
    header.set_authoritative(false);
    header.set_recursion_desired(request.header().recursion_desired());
    header.set_recursion_available(true);
    header.set_response_code(ResponseCode::NoError);
    response.set_header(header);

    for q in request.queries() {
        response.add_query(q.clone());
    }

    let cname_rdata = RData::CNAME(hickory_proto::rr::rdata::CNAME(current_target.clone()));
    let cname_record = Record::from_rdata(orig_name, 3600, cname_rdata);
    response.add_answer(cname_record);

    let mut cname_chain: Vec<Record<RData>> = Vec::new();
    let mut address_records: Vec<Record<RData>> = Vec::new();
    let mut seen_targets: std::collections::HashSet<String> = std::collections::HashSet::new();
    seen_targets.insert(current_target.to_ascii().to_lowercase());

    for _ in 0..MAX_CNAME_HOPS {
        let mut resolve_req = Message::new();
        let mut hdr = Header::new();
        hdr.set_id(rand::random::<u16>());
        hdr.set_message_type(MessageType::Query);
        hdr.set_op_code(OpCode::Query);
        hdr.set_recursion_desired(true);
        resolve_req.set_header(hdr);

        let mut query = Query::new();
        query.set_name(current_target.clone());
        query.set_query_type(query_type);
        resolve_req.add_query(query);

        let packet = resolve_req.to_vec().ok()?;
        let (response_bytes, _) = upstream.forward(&packet).await.ok()?;
        let upstream_resp = Message::from_bytes(&response_bytes).ok()?;

        let mut found_cname = false;

        for answer in upstream_resp.answers() {
            match answer.data() {
                RData::CNAME(cname_rdata) => {
                    let target = cname_rdata.0.clone();
                    let target_str = target.to_ascii().to_lowercase();
                    if !seen_targets.contains(&target_str) {
                        seen_targets.insert(target_str);
                        let mut record = answer.clone();
                        record.set_ttl(3600);
                        cname_chain.push(record);
                        current_target = target.clone();
                        found_cname = true;
                    }
                }
                RData::A(_) if query_type == RecordType::A => {
                    let mut record = answer.clone();
                    record.set_ttl(3600);
                    address_records.push(record);
                }
                RData::AAAA(_) if query_type == RecordType::AAAA => {
                    let mut record = answer.clone();
                    record.set_ttl(3600);
                    address_records.push(record);
                }
                _ => {}
            }
        }

        if !address_records.is_empty() || !found_cname {
            break;
        }
    }

    for record in cname_chain {
        response.add_answer(record);
    }

    for record in address_records {
        response.add_answer(record);
    }

    echo_edns_opt(request, &mut response);
    Some(response)
}

/// Build an empty (NOERROR, no answers) response.
/// Used for IPv6-disabled AAAA filtering and safe-search with no AAAA equivalent.
fn build_empty_response(request: &Message) -> Message {
    let mut response = Message::new();
    let mut header = Header::new();
    header.set_id(request.header().id());
    header.set_message_type(MessageType::Response);
    header.set_op_code(request.header().op_code());
    // RFC 1035 §4.1.1: AA=false — we are not authoritative for filtered domains
    header.set_authoritative(false);
    header.set_recursion_desired(request.header().recursion_desired());
    header.set_recursion_available(true);
    header.set_response_code(ResponseCode::NoError);
    response.set_header(header);
    for query in request.queries() {
        response.add_query(query.clone());
    }
    echo_edns_opt(request, &mut response);
    response
}

/// Remove AAAA records from a DNS response.
fn filter_aaaa_records(response_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let response = Message::from_bytes(response_bytes)?;
    let mut new_response = Message::new();
    new_response.set_header(*response.header());
    for q in response.queries() {
        new_response.add_query(q.clone());
    }
    for a in response.answers() {
        if a.record_type() != RecordType::AAAA {
            new_response.add_answer(a.clone());
        }
    }
    for ns in response.name_servers() {
        new_response.add_name_server(ns.clone());
    }
    for ad in response.additionals() {
        if ad.record_type() != RecordType::AAAA {
            new_response.add_additional(ad.clone());
        }
    }
    Ok(new_response.to_vec()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Build a minimal DNS request for testing.
    fn make_request(domain: &str, query_type: RecordType) -> Message {
        let mut msg = Message::new();
        let mut header = Header::new();
        header.set_id(0x1234);
        header.set_message_type(MessageType::Query);
        header.set_op_code(OpCode::Query);
        header.set_recursion_desired(true);
        msg.set_header(header);

        let mut query = Query::new();
        query.set_name(Name::from_ascii(domain).unwrap());
        query.set_query_type(query_type);
        msg.add_query(query);
        msg
    }

    // ── Default mode ──────────────────────────────────────────────

    #[test]
    fn default_mode_a_query_returns_noerror_with_zero_ip() {
        let req = make_request("blocked.example.", RecordType::A);
        let resp = build_blocked_response(
            &req,
            "blocked.example.",
            RecordType::A,
            &BlockingMode::Default,
        );

        assert_eq!(resp.header().response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        match resp.answers()[0].data() {
            RData::A(ip) => assert_eq!(
                std::net::Ipv4Addr::from(*ip),
                "0.0.0.0".parse::<Ipv4Addr>().unwrap()
            ),
            other => panic!("expected A record, got {:?}", other),
        }
        assert_eq!(resp.answers()[0].ttl(), 300);
    }

    #[test]
    fn default_mode_aaaa_query_returns_noerror_with_zero_ipv6() {
        let req = make_request("blocked.example.", RecordType::AAAA);
        let resp = build_blocked_response(
            &req,
            "blocked.example.",
            RecordType::AAAA,
            &BlockingMode::Default,
        );

        assert_eq!(resp.header().response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        match resp.answers()[0].data() {
            RData::AAAA(ip) => assert_eq!(
                std::net::Ipv6Addr::from(*ip),
                "::".parse::<Ipv6Addr>().unwrap()
            ),
            other => panic!("expected AAAA record, got {:?}", other),
        }
        assert_eq!(resp.answers()[0].ttl(), 300);
    }

    #[test]
    fn default_mode_mx_query_returns_noerror_no_answers() {
        let req = make_request("blocked.example.", RecordType::MX);
        let resp = build_blocked_response(
            &req,
            "blocked.example.",
            RecordType::MX,
            &BlockingMode::Default,
        );

        assert_eq!(resp.header().response_code(), ResponseCode::NoError);
        assert!(resp.answers().is_empty());
    }

    // ── Refused mode ──────────────────────────────────────────────

    #[test]
    fn refused_mode_a_query_returns_refused_no_answers() {
        let req = make_request("blocked.example.", RecordType::A);
        let resp = build_blocked_response(
            &req,
            "blocked.example.",
            RecordType::A,
            &BlockingMode::Refused,
        );

        assert_eq!(resp.header().response_code(), ResponseCode::Refused);
        assert!(resp.answers().is_empty());
    }

    #[test]
    fn refused_mode_aaaa_query_returns_refused_no_answers() {
        let req = make_request("blocked.example.", RecordType::AAAA);
        let resp = build_blocked_response(
            &req,
            "blocked.example.",
            RecordType::AAAA,
            &BlockingMode::Refused,
        );

        assert_eq!(resp.header().response_code(), ResponseCode::Refused);
        assert!(resp.answers().is_empty());
    }

    // ── NxDomain mode ─────────────────────────────────────────────

    #[test]
    fn nxdomain_mode_a_query_returns_nxdomain_no_answers() {
        let req = make_request("blocked.example.", RecordType::A);
        let resp = build_blocked_response(
            &req,
            "blocked.example.",
            RecordType::A,
            &BlockingMode::NxDomain,
        );

        assert_eq!(resp.header().response_code(), ResponseCode::NXDomain);
        assert!(resp.answers().is_empty());
    }

    #[test]
    fn nxdomain_mode_aaaa_query_returns_nxdomain_no_answers() {
        let req = make_request("blocked.example.", RecordType::AAAA);
        let resp = build_blocked_response(
            &req,
            "blocked.example.",
            RecordType::AAAA,
            &BlockingMode::NxDomain,
        );

        assert_eq!(resp.header().response_code(), ResponseCode::NXDomain);
        assert!(resp.answers().is_empty());
    }

    // ── NullIp mode ───────────────────────────────────────────────

    #[test]
    fn null_ip_mode_a_query_returns_noerror_with_zero_ip() {
        let req = make_request("blocked.example.", RecordType::A);
        let resp = build_blocked_response(
            &req,
            "blocked.example.",
            RecordType::A,
            &BlockingMode::NullIp,
        );

        assert_eq!(resp.header().response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        match resp.answers()[0].data() {
            RData::A(ip) => assert_eq!(
                std::net::Ipv4Addr::from(*ip),
                "0.0.0.0".parse::<Ipv4Addr>().unwrap()
            ),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[test]
    fn null_ip_mode_aaaa_query_returns_noerror_with_zero_ipv6() {
        let req = make_request("blocked.example.", RecordType::AAAA);
        let resp = build_blocked_response(
            &req,
            "blocked.example.",
            RecordType::AAAA,
            &BlockingMode::NullIp,
        );

        assert_eq!(resp.header().response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        match resp.answers()[0].data() {
            RData::AAAA(ip) => assert_eq!(
                std::net::Ipv6Addr::from(*ip),
                "::".parse::<Ipv6Addr>().unwrap()
            ),
            other => panic!("expected AAAA record, got {:?}", other),
        }
    }

    // ── CustomIp mode ─────────────────────────────────────────────

    #[test]
    fn custom_ip_mode_a_query_returns_noerror_with_custom_ipv4() {
        let mode = BlockingMode::CustomIp {
            ipv4: "192.168.1.1".parse().unwrap(),
            ipv6: "fd00::1".parse().unwrap(),
        };
        let req = make_request("blocked.example.", RecordType::A);
        let resp = build_blocked_response(&req, "blocked.example.", RecordType::A, &mode);

        assert_eq!(resp.header().response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        match resp.answers()[0].data() {
            RData::A(ip) => assert_eq!(
                std::net::Ipv4Addr::from(*ip),
                "192.168.1.1".parse::<Ipv4Addr>().unwrap()
            ),
            other => panic!("expected A record, got {:?}", other),
        }
        assert_eq!(resp.answers()[0].ttl(), 300);
    }

    #[test]
    fn custom_ip_mode_aaaa_query_returns_noerror_with_custom_ipv6() {
        let mode = BlockingMode::CustomIp {
            ipv4: "192.168.1.1".parse().unwrap(),
            ipv6: "fd00::1".parse().unwrap(),
        };
        let req = make_request("blocked.example.", RecordType::AAAA);
        let resp = build_blocked_response(&req, "blocked.example.", RecordType::AAAA, &mode);

        assert_eq!(resp.header().response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        match resp.answers()[0].data() {
            RData::AAAA(ip) => assert_eq!(
                std::net::Ipv6Addr::from(*ip),
                "fd00::1".parse::<Ipv6Addr>().unwrap()
            ),
            other => panic!("expected AAAA record, got {:?}", other),
        }
        assert_eq!(resp.answers()[0].ttl(), 300);
    }

    #[test]
    fn custom_ip_mode_mx_query_returns_noerror_no_answers() {
        let mode = BlockingMode::CustomIp {
            ipv4: "192.168.1.1".parse().unwrap(),
            ipv6: "fd00::1".parse().unwrap(),
        };
        let req = make_request("blocked.example.", RecordType::MX);
        let resp = build_blocked_response(&req, "blocked.example.", RecordType::MX, &mode);

        assert_eq!(resp.header().response_code(), ResponseCode::NoError);
        assert!(resp.answers().is_empty());
    }

    // ── Common header properties ──────────────────────────────────

    #[test]
    fn all_modes_echo_query_section() {
        let modes: Vec<BlockingMode> = vec![
            BlockingMode::Default,
            BlockingMode::Refused,
            BlockingMode::NxDomain,
            BlockingMode::NullIp,
            BlockingMode::CustomIp {
                ipv4: "10.0.0.1".parse().unwrap(),
                ipv6: "::1".parse().unwrap(),
            },
        ];

        for mode in &modes {
            let req = make_request("test.example.", RecordType::A);
            let resp = build_blocked_response(&req, "test.example.", RecordType::A, mode);

            assert_eq!(
                resp.header().id(),
                0x1234,
                "mode={} should echo request ID",
                mode
            );
            assert_eq!(
                resp.header().message_type(),
                MessageType::Response,
                "mode={}",
                mode
            );
            assert!(
                resp.header().authoritative(),
                "mode={} should be authoritative",
                mode
            );
            assert!(
                resp.header().recursion_available(),
                "mode={} should set RA",
                mode
            );
            assert_eq!(resp.queries().len(), 1, "mode={} should echo query", mode);
        }
    }
}
