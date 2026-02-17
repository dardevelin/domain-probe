use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Utc};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;
use x509_parser::time::ASN1Time;

#[derive(Debug)]
pub(crate) struct TlsProbe {
    pub protocol_version: String,
    pub cipher_suite: String,
    pub certificate_chain: Vec<CertInfo>,
    pub elapsed_ms: u64,
}

#[derive(Debug)]
pub(crate) struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub san: Vec<String>,
    pub is_leaf: bool,
}

pub(crate) async fn probe_tls(host: &str, timeout_secs: u64) -> Result<TlsProbe> {
    let started = Instant::now();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = rustls::crypto::ring::default_provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .context("failed to set TLS protocol versions")?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| anyhow!("invalid DNS name: {host}"))?;

    let addr = format!("{host}:443");
    let tcp = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs.clamp(1, 8)),
        TcpStream::connect(&addr),
    )
    .await
    .context("TCP connection timed out")?
    .with_context(|| format!("TCP connection to {addr} failed"))?;

    let tls = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs.max(1)),
        connector.connect(server_name, tcp),
    )
    .await
    .context("TLS handshake timed out")?
    .context("TLS handshake failed")?;

    let (_, conn) = tls.get_ref();

    let protocol_version = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_0) => "TLS 1.0",
        Some(rustls::ProtocolVersion::TLSv1_1) => "TLS 1.1",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2",
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3",
        _ => "unknown",
    }
    .to_string();

    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()))
        .unwrap_or_else(|| "unknown".to_string());

    let certs_slice = conn.peer_certificates();
    let mut certificate_chain = Vec::with_capacity(certs_slice.map(|c| c.len()).unwrap_or(0));
    if let Some(certs) = certs_slice {
        for (idx, cert_der) in certs.iter().enumerate() {
            let is_leaf = idx == 0;
            match X509Certificate::from_der(cert_der.as_ref()) {
                Ok((_, cert)) => {
                    let subject = cert
                        .subject()
                        .iter_common_name()
                        .next()
                        .and_then(|cn| cn.as_str().ok())
                        .unwrap_or("")
                        .to_string();

                    let issuer = cert
                        .issuer()
                        .iter_common_name()
                        .next()
                        .and_then(|cn| cn.as_str().ok())
                        .unwrap_or("")
                        .to_string();

                    let not_before = asn1_to_datetime(cert.validity().not_before);
                    let not_after = asn1_to_datetime(cert.validity().not_after);

                    let mut san = Vec::new();
                    if let Ok(Some(ext)) = cert.subject_alternative_name() {
                        for name in &ext.value.general_names {
                            match name {
                                GeneralName::DNSName(dns) => san.push(dns.to_string()),
                                GeneralName::IPAddress(bytes) => {
                                    let formatted = match bytes.len() {
                                        4 => {
                                            if let Ok(octets) = <[u8; 4]>::try_from(*bytes) {
                                                IpAddr::from(octets).to_string()
                                            } else {
                                                format!("IP:{:02x?}", bytes)
                                            }
                                        }
                                        16 => {
                                            if let Ok(octets) = <[u8; 16]>::try_from(*bytes) {
                                                IpAddr::from(octets).to_string()
                                            } else {
                                                format!("IP:{:02x?}", bytes)
                                            }
                                        }
                                        _ => format!("IP:{:02x?}", bytes),
                                    };
                                    san.push(formatted);
                                }
                                _ => {}
                            }
                        }
                    }

                    certificate_chain.push(CertInfo {
                        subject,
                        issuer,
                        not_before,
                        not_after,
                        san,
                        is_leaf,
                    });
                }
                Err(_) => {
                    certificate_chain.push(CertInfo {
                        subject: "(parse error)".to_string(),
                        issuer: "(parse error)".to_string(),
                        not_before: None,
                        not_after: None,
                        san: Vec::new(),
                        is_leaf,
                    });
                }
            }
        }
    }

    Ok(TlsProbe {
        protocol_version,
        cipher_suite,
        certificate_chain,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

fn asn1_to_datetime(t: ASN1Time) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(t.timestamp(), 0)
}
