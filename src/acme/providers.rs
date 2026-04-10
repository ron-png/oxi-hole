use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{info, warn};

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

// ── Cloudflare API response shapes ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CfError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct CfResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct ZoneResult {
    id: String,
}

#[derive(Debug, Deserialize)]
struct DnsRecordResult {
    id: String,
}

// ── CloudflareProvider ───────────────────────────────────────────────────────

pub struct CloudflareProvider {
    client: reqwest::Client,
    token: String,
}

impl CloudflareProvider {
    pub fn new(token: &str) -> Self {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to build reqwest client");

        Self {
            client,
            token: token.to_owned(),
        }
    }

    /// Walk domain labels to find the Cloudflare zone ID.
    ///
    /// For `sub.example.com`, tries `sub.example.com`, then `example.com`,
    /// then `com` until a zone is found.
    pub async fn find_zone_id(&self, domain: &str) -> Result<String> {
        let labels: Vec<&str> = domain.split('.').collect();
        let label_count = labels.len();

        for start in 0..label_count.saturating_sub(1) {
            let candidate = labels[start..].join(".");
            let url = format!("{}/zones?name={}", CF_API_BASE, candidate);

            let resp = self
                .client
                .get(&url)
                .bearer_auth(&self.token)
                .send()
                .await?;

            let body: CfResponse<Vec<ZoneResult>> = resp.json().await?;

            if body.success {
                if let Some(zones) = body.result {
                    if let Some(zone) = zones.into_iter().next() {
                        info!("Found Cloudflare zone '{}' (id={})", candidate, zone.id);
                        return Ok(zone.id);
                    }
                }
            }
        }

        Err(anyhow!("No Cloudflare zone found for domain '{}'", domain))
    }

    /// Create an `_acme-challenge.{domain}` TXT record and return its record ID.
    pub async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        let zone_id = self.find_zone_id(domain).await?;
        let record_name = format!("_acme-challenge.{}", domain);

        let url = format!("{}/zones/{}/dns_records", CF_API_BASE, zone_id);
        let body = serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": value,
            "ttl": 120
        });

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        let cf_resp: CfResponse<DnsRecordResult> = resp.json().await?;

        if !cf_resp.success {
            let msgs: Vec<String> = cf_resp.errors.iter().map(|e| e.message.clone()).collect();
            return Err(anyhow!(
                "Cloudflare create TXT record failed: {}",
                msgs.join("; ")
            ));
        }

        let record = cf_resp
            .result
            .ok_or_else(|| anyhow!("Cloudflare returned no result for TXT record creation"))?;

        info!(
            "Created TXT record '{}' (id={}) for domain '{}'",
            record_name, record.id, domain
        );

        Ok(record.id)
    }

    /// Delete a DNS record by its record ID.
    pub async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        let zone_id = self.find_zone_id(domain).await?;
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            CF_API_BASE, zone_id, record_id
        );

        let resp = self
            .client
            .delete(&url)
            .bearer_auth(&self.token)
            .send()
            .await?;

        // Cloudflare returns 200 with a `result: { id }` on success.
        // Accept any 2xx response as success.
        if resp.status().is_success() {
            info!(
                "Deleted TXT record id='{}' for domain '{}'",
                record_id, domain
            );
            Ok(())
        } else {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            Err(anyhow!(
                "Cloudflare delete TXT record failed (HTTP {}): {}",
                status,
                text
            ))
        }
    }
}

// ── DNS TXT polling ──────────────────────────────────────────────────────────

const DNS_RESOLVERS: &[Ipv4Addr] = &[Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];
const DNS_TIMEOUT: Duration = Duration::from_secs(3);

/// Check whether `_acme-challenge.{domain}` contains `expected_value` by
/// querying public resolvers directly over UDP.
///
/// Returns `true` if the value is found in any response from any resolver.
pub async fn poll_dns_txt_record(domain: &str, expected_value: &str) -> bool {
    let record_name = format!("_acme-challenge.{}.", domain);

    for resolver_ip in DNS_RESOLVERS {
        let resolver: SocketAddr = SocketAddr::new((*resolver_ip).into(), 53);

        match query_txt_via_udp(&record_name, resolver, expected_value).await {
            Ok(true) => {
                info!(
                    "DNS TXT record for '{}' confirmed via resolver {}",
                    record_name, resolver_ip
                );
                return true;
            }
            Ok(false) => {
                warn!(
                    "DNS TXT record for '{}' not yet visible at resolver {}",
                    record_name, resolver_ip
                );
            }
            Err(e) => {
                warn!(
                    "DNS query error for '{}' via {}: {}",
                    record_name, resolver_ip, e
                );
            }
        }
    }

    false
}

/// Send a TXT DNS query to `resolver` and check if `expected_value` appears
/// in any TXT record in the answer section.
async fn query_txt_via_udp(fqdn: &str, resolver: SocketAddr, expected_value: &str) -> Result<bool> {
    use hickory_proto::op::{Header, Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;

    let name = Name::from_ascii(fqdn)?;

    // Build query packet.
    let mut msg = Message::new();
    let mut header = Header::new();
    let id: u16 = rand::random();
    header.set_id(id);
    header.set_message_type(MessageType::Query);
    header.set_op_code(OpCode::Query);
    header.set_recursion_desired(true);
    msg.set_header(header);

    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(RecordType::TXT);
    msg.add_query(query);

    let packet = msg.to_vec()?;

    // Bind an ephemeral UDP socket.
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(resolver).await?;

    // Send and receive with timeout.
    let recv_result = timeout(DNS_TIMEOUT, async {
        sock.send(&packet).await?;
        let mut buf = vec![0u8; 4096];
        let len = sock.recv(&mut buf).await?;
        buf.truncate(len);
        Ok::<Vec<u8>, std::io::Error>(buf)
    })
    .await;

    let response_bytes = match recv_result {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => return Err(anyhow!("UDP I/O error: {}", e)),
        Err(_) => {
            return Err(anyhow!(
                "DNS query timed out after {}s",
                DNS_TIMEOUT.as_secs()
            ))
        }
    };

    // Parse and inspect TXT answers.
    let response = Message::from_bytes(&response_bytes)?;

    for record in response.answers() {
        if let Some(RData::TXT(txt)) = record.data() {
            for part in txt.iter() {
                if let Ok(s) = std::str::from_utf8(part) {
                    if s == expected_value {
                        return Ok(true);
                    }
                }
            }
        }
    }

    Ok(false)
}
