use anyhow::Context;
use std::path::Path;

use crate::config::TlsConfig;

/// Parsed certificate data ready for use.
#[derive(Debug, Clone)]
pub struct ParsedCertificate {
    /// DER-encoded certificate chain
    pub certs: Vec<Vec<u8>>,
    /// DER-encoded private key
    pub key: Vec<u8>,
    /// Subject common name or DN
    pub subject: String,
    /// Issuer common name or DN
    pub issuer: String,
    /// Expiration date as string
    pub not_after: String,
    /// Whether the certificate is self-signed
    pub self_signed: bool,
}

/// Errors from certificate parsing.
#[derive(Debug)]
pub enum ParseError {
    /// A password is required to decrypt the certificate or key.
    PasswordRequired { cert_type: String },
    /// Any other error.
    Other(anyhow::Error),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::PasswordRequired { cert_type } => {
                write!(f, "Password required for {}", cert_type)
            }
            ParseError::Other(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<anyhow::Error> for ParseError {
    fn from(e: anyhow::Error) -> Self {
        ParseError::Other(e)
    }
}

/// Parse PEM certificate data from one or two byte slices.
///
/// - `cert_data`: PEM data that must contain at least one certificate.
///   May also contain the private key (combined file) and full chain.
/// - `key_data`: Optional separate PEM data for the private key.
/// - `password`: Optional password for encrypted private keys.
pub fn parse_pem(
    cert_data: &[u8],
    key_data: Option<&[u8]>,
    password: Option<&str>,
) -> Result<ParsedCertificate, ParseError> {
    let mut certs: Vec<Vec<u8>> = Vec::new();
    let mut key_der: Option<Vec<u8>> = None;

    // Parse certs and possibly keys from cert_data
    parse_pem_items(cert_data, password, &mut certs, &mut key_der)?;

    // Parse keys from key_data if provided
    if let Some(kd) = key_data {
        parse_pem_items(kd, password, &mut Vec::new(), &mut key_der)?;
    }

    if certs.is_empty() {
        return Err(ParseError::Other(anyhow::anyhow!(
            "No certificates found in PEM data"
        )));
    }

    let key = key_der
        .ok_or_else(|| ParseError::Other(anyhow::anyhow!("No private key found in PEM data")))?;

    let (subject, issuer, not_after, self_signed) = extract_cert_info(&certs[0])?;

    Ok(ParsedCertificate {
        certs,
        key,
        subject,
        issuer,
        not_after,
        self_signed,
    })
}

/// Parse PEM items from a byte slice, collecting certs and key.
fn parse_pem_items(
    data: &[u8],
    password: Option<&str>,
    certs: &mut Vec<Vec<u8>>,
    key_der: &mut Option<Vec<u8>>,
) -> Result<(), ParseError> {
    // Check for encrypted private key marker before rustls_pemfile parsing
    let data_str = std::str::from_utf8(data).unwrap_or("");
    if data_str.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        let pw = password.ok_or_else(|| ParseError::PasswordRequired {
            cert_type: "encrypted PEM private key".to_string(),
        })?;

        // Decrypt the encrypted key using pkcs8
        let (_, doc) = pkcs8::SecretDocument::from_pem(data_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse encrypted PEM: {}", e))?;
        let enc_key: pkcs8::EncryptedPrivateKeyInfo<'_> =
            pkcs8::EncryptedPrivateKeyInfo::try_from(doc.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to parse encrypted key info: {}", e))?;
        let decrypted = enc_key
            .decrypt(pw)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt private key: {}", e))?;
        *key_der = Some(decrypted.as_bytes().to_vec());
    }

    // Parse PEM items using rustls_pemfile
    let mut cursor = std::io::Cursor::new(data);
    loop {
        match rustls_pemfile::read_one(&mut cursor) {
            Ok(Some(item)) => match item {
                rustls_pemfile::Item::X509Certificate(cert) => {
                    certs.push(cert.to_vec());
                }
                rustls_pemfile::Item::Pkcs1Key(key) => {
                    if key_der.is_none() {
                        *key_der = Some(key.secret_pkcs1_der().to_vec());
                    }
                }
                rustls_pemfile::Item::Pkcs8Key(key) => {
                    if key_der.is_none() {
                        *key_der = Some(key.secret_pkcs8_der().to_vec());
                    }
                }
                rustls_pemfile::Item::Sec1Key(key) => {
                    if key_der.is_none() {
                        *key_der = Some(key.secret_sec1_der().to_vec());
                    }
                }
                _ => {}
            },
            Ok(None) => break,
            Err(_) => break,
        }
    }

    Ok(())
}

/// Parse a PKCS12 bundle.
///
/// - `data`: Raw PKCS12 bytes.
/// - `password`: Password for the bundle. If `None` and the bundle is encrypted,
///   returns `ParseError::PasswordRequired`.
pub fn parse_pkcs12(data: &[u8], password: Option<&str>) -> Result<ParsedCertificate, ParseError> {
    let pfx =
        p12::PFX::parse(data).map_err(|e| anyhow::anyhow!("Failed to parse PKCS12: {:?}", e))?;

    let pw = password.unwrap_or("");

    let certs = pfx
        .cert_x509_bags(pw)
        .map_err(|e| anyhow::anyhow!("Failed to extract certs from PKCS12: {:?}", e))?;

    let keys = pfx
        .key_bags(pw)
        .map_err(|e| anyhow::anyhow!("Failed to extract keys from PKCS12: {:?}", e))?;

    if certs.is_empty() {
        // If we got no certs, might be password-protected
        if password.is_none() {
            return Err(ParseError::PasswordRequired {
                cert_type: "PKCS12 bundle".to_string(),
            });
        }
        return Err(ParseError::Other(anyhow::anyhow!(
            "No certificates found in PKCS12 bundle"
        )));
    }

    if keys.is_empty() {
        if password.is_none() {
            return Err(ParseError::PasswordRequired {
                cert_type: "PKCS12 bundle".to_string(),
            });
        }
        return Err(ParseError::Other(anyhow::anyhow!(
            "No private key found in PKCS12 bundle"
        )));
    }

    let (subject, issuer, not_after, self_signed) = extract_cert_info(&certs[0])?;

    Ok(ParsedCertificate {
        certs,
        key: keys[0].clone(),
        subject,
        issuer,
        not_after,
        self_signed,
    })
}

/// Extract subject, issuer, not_after, and self_signed from a DER-encoded certificate.
fn extract_cert_info(der: &[u8]) -> Result<(String, String, String, bool), ParseError> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| anyhow::anyhow!("Failed to parse X.509 certificate: {}", e))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let not_after = cert
        .validity()
        .not_after
        .to_rfc2822()
        .unwrap_or_else(|_| cert.validity().not_after.to_string());
    let self_signed = cert.subject() == cert.issuer();

    Ok((subject, issuer, not_after, self_signed))
}

/// Write parsed certificate data to PEM files with proper permissions.
///
/// - cert file gets mode 644
/// - key file gets mode 600
pub fn write_cert_files(
    parsed: &ParsedCertificate,
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    // Write certificate chain
    let mut cert_pem = String::new();
    for cert_der in &parsed.certs {
        cert_pem.push_str(&pem_encode("CERTIFICATE", cert_der));
        cert_pem.push('\n');
    }
    fs::write(cert_path, cert_pem.as_bytes())
        .with_context(|| format!("Failed to write cert file: {:?}", cert_path))?;
    fs::set_permissions(cert_path, fs::Permissions::from_mode(0o644))
        .with_context(|| format!("Failed to set permissions on {:?}", cert_path))?;

    // Write private key
    let key_pem = pem_encode("PRIVATE KEY", &parsed.key);
    fs::write(key_path, key_pem.as_bytes())
        .with_context(|| format!("Failed to write key file: {:?}", key_path))?;
    fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to set permissions on {:?}", key_path))?;

    Ok(())
}

/// Read current certificate info from TLS config paths.
pub fn get_current_cert_info(tls_config: &TlsConfig) -> anyhow::Result<Option<ParsedCertificate>> {
    let cert_path = match &tls_config.cert_path {
        Some(p) => p,
        None => return Ok(None),
    };
    let key_path = match &tls_config.key_path {
        Some(p) => p,
        None => return Ok(None),
    };

    let cert_data =
        std::fs::read(cert_path).with_context(|| format!("Failed to read cert: {}", cert_path))?;
    let key_data =
        std::fs::read(key_path).with_context(|| format!("Failed to read key: {}", key_path))?;

    let parsed = parse_pem(&cert_data, Some(&key_data), None)
        .map_err(|e| anyhow::anyhow!("Failed to parse current cert: {}", e))?;

    Ok(Some(parsed))
}

/// Encode DER bytes as PEM with the given label.
fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a self-signed test certificate using rcgen.
    fn generate_test_cert() -> (Vec<u8>, Vec<u8>, rcgen::CertifiedKey) {
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        (
            cert_pem.into_bytes(),
            key_pem.into_bytes(),
            rcgen::CertifiedKey { cert, key_pair },
        )
    }

    #[test]
    fn parse_separate_pem_files() {
        let (cert_pem, key_pem, _) = generate_test_cert();
        let parsed = parse_pem(&cert_pem, Some(&key_pem), None).unwrap();
        assert_eq!(parsed.certs.len(), 1);
        assert!(!parsed.key.is_empty());
        assert!(parsed.self_signed);
    }

    #[test]
    fn parse_combined_pem() {
        let (cert_pem, key_pem, _) = generate_test_cert();
        let mut combined = Vec::new();
        combined.extend_from_slice(&cert_pem);
        combined.extend_from_slice(&key_pem);

        let parsed = parse_pem(&combined, None, None).unwrap();
        assert_eq!(parsed.certs.len(), 1);
        assert!(!parsed.key.is_empty());
    }

    #[test]
    fn parse_no_key_fails() {
        let (cert_pem, _, _) = generate_test_cert();
        let result = parse_pem(&cert_pem, None, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            ParseError::Other(e) => assert!(e.to_string().contains("No private key")),
            _ => panic!("Expected Other error"),
        }
    }

    #[test]
    fn parse_no_cert_fails() {
        let (_, key_pem, _) = generate_test_cert();
        let result = parse_pem(&key_pem, None, None);
        assert!(result.is_err());
        match result.unwrap_err() {
            ParseError::Other(e) => assert!(e.to_string().contains("No certificates")),
            _ => panic!("Expected Other error"),
        }
    }

    #[test]
    fn extract_cert_info_works() {
        let (cert_pem, _, _) = generate_test_cert();

        // Parse the PEM to get DER
        let mut cursor = std::io::Cursor::new(&cert_pem);
        let item = rustls_pemfile::read_one(&mut cursor).unwrap().unwrap();
        let der = match item {
            rustls_pemfile::Item::X509Certificate(c) => c.to_vec(),
            _ => panic!("Expected X509Certificate"),
        };

        let (subject, issuer, not_after, self_signed) = extract_cert_info(&der).unwrap();
        assert!(!subject.is_empty());
        assert!(!issuer.is_empty());
        assert!(!not_after.is_empty());
        assert!(self_signed);
        // For a self-signed cert, subject == issuer
        assert_eq!(subject, issuer);
    }

    #[test]
    fn base64_roundtrip() {
        use base64::Engine;
        let original = b"Hello, certificate world!";
        let encoded = base64::engine::general_purpose::STANDARD.encode(original);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        assert_eq!(original.as_slice(), decoded.as_slice());
    }

    #[test]
    fn pem_encode_format() {
        let der = vec![0x01, 0x02, 0x03, 0x04];
        let pem = pem_encode("CERTIFICATE", &der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        // Should contain base64 content between markers
        let lines: Vec<&str> = pem.lines().collect();
        assert!(lines.len() >= 3);
        assert_eq!(lines[0], "-----BEGIN CERTIFICATE-----");
        assert_eq!(lines[lines.len() - 1], "-----END CERTIFICATE-----");
    }
}
