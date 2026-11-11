//! Transport probes shared by url-diag and defender-diag.
//!
//! The crate holds only the evidence-gathering layer: DNS resolution, TCP connect,
//! verified TLS handshake, one HTTP/1.1 request, HTTP CONNECT proxy tunnelling and
//! latency statistics. Catalogs, command lines, reports and the dashboards stay in
//! the tools. Callers pass their own User-Agent so each tool identifies itself.
#![forbid(unsafe_code)]
pub mod dns;
pub mod http;
pub mod proxy;
pub mod statistics;
pub mod tcp;
pub mod tls;
pub mod types;
