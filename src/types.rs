//! Evidence record types shared by the diagnostics tools.
use serde::Serialize;
use std::net::IpAddr;
#[derive(Debug, Clone, Serialize)]
pub struct Failure {
    pub code: String,
    pub message: String,
}
impl Failure {
    pub fn new(code: &str, message: impl ToString) -> Self {
        Self {
            code: code.into(),
            message: message.to_string(),
        }
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct DnsResult {
    pub hostname: String,
    pub iteration: u16,
    pub timestamp: String,
    pub source: String,
    pub duration_ms: f64,
    pub addresses: Vec<IpAddr>,
    pub error: Option<Failure>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub expires: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Attempt {
    pub http_method: Option<String>,
    pub http_path: Option<String>,
    pub assessment: String,
    pub diagnostic_note: String,
    pub hostname: String,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub iteration: u16,
    pub timestamp: String,
    pub route: String,
    pub tcp_ms: Option<f64>,
    pub tls_ms: Option<f64>,
    pub http_ms: Option<f64>,
    pub total_ms: f64,
    pub tls_version: Option<String>,
    pub cipher: Option<String>,
    pub certificates: Vec<Certificate>,
    pub http_status: Option<u16>,
    pub success: bool,
    pub error: Option<Failure>,
    /// Time for the proxy CONNECT exchange when the attempt was tunnelled.
    pub proxy_connect_ms: Option<f64>,
    /// Sanitized Location of a 3xx response (query and fragment removed). Never followed.
    pub redirect_location: Option<String>,
}
impl Attempt {
    pub fn new(host: String, ip: Option<IpAddr>, port: u16, iteration: u16) -> Self {
        Self {
            http_method: None,
            http_path: None,
            assessment: "not_assessed".into(),
            diagnostic_note: String::new(),
            hostname: host,
            ip,
            port,
            iteration,
            timestamp: chrono::Utc::now().to_rfc3339(),
            route: "direct".into(),
            tcp_ms: None,
            tls_ms: None,
            http_ms: None,
            total_ms: 0.,
            tls_version: None,
            cipher: None,
            certificates: Vec::new(),
            http_status: None,
            success: false,
            error: None,
            proxy_connect_ms: None,
            redirect_location: None,
        }
    }
}
