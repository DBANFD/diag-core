use crate::types::{Certificate, Failure};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use std::{sync::Arc, time::Duration};
pub type Stream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;
pub fn config() -> anyhow::Result<(Arc<ClientConfig>, Vec<String>)> {
    let loaded = rustls_native_certs::load_native_certs();
    let mut warnings = Vec::new();
    if !loaded.errors.is_empty() {
        warnings.push(format!(
            "Native trust store reported {} loading errors; some roots may be missing.",
            loaded.errors.len()
        ));
    }
    let mut roots = RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(loaded.certs);
    if rejected > 0 {
        warnings.push(format!("{rejected} root certificates could not be parsed."));
    }
    anyhow::ensure!(
        accepted > 0,
        "No usable native trust roots; cannot perform verified TLS"
    );
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    // Every probe must perform a fresh full handshake.
    cfg.resumption = rustls::client::Resumption::disabled();
    Ok((Arc::new(cfg), warnings))
}
pub async fn handshake(
    stream: tokio::net::TcpStream,
    host: &str,
    cfg: Arc<ClientConfig>,
    limit: Duration,
) -> Result<Stream, Failure> {
    let name =
        ServerName::try_from(host.to_owned()).map_err(|e| Failure::new("TLS_INVALID_NAME", e))?;
    match tokio::time::timeout(
        limit,
        tokio_rustls::TlsConnector::from(cfg).connect(name, stream),
    )
    .await
    {
        Err(_) => Err(Failure::new(
            "TLS_TIMEOUT",
            "TLS handshake exceeded deadline",
        )),
        Ok(Err(e)) => {
            let cert_error = e
                .get_ref()
                .and_then(|x| x.downcast_ref::<rustls::Error>())
                .is_some_and(|x| matches!(x, rustls::Error::InvalidCertificate(_)));
            Err(Failure::new(
                if cert_error {
                    "TLS_CERTIFICATE_INVALID"
                } else {
                    "TLS_HANDSHAKE_FAILED"
                },
                e,
            ))
        }
        Ok(Ok(s)) => Ok(s),
    }
}
pub fn certificates(s: &Stream) -> Vec<Certificate> {
    s.get_ref()
        .1
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .map(
            |der| match x509_parser::parse_x509_certificate(der.as_ref()) {
                Ok((_, c)) => Certificate {
                    subject: c.subject().to_string(),
                    issuer: c.issuer().to_string(),
                    expires: c.validity().not_after.to_string(),
                },
                Err(_) => Certificate {
                    subject: "[parse failed]".into(),
                    issuer: "[parse failed]".into(),
                    expires: "[parse failed]".into(),
                },
            },
        )
        .collect()
}
