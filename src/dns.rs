use crate::types::{DnsResult, Failure};
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};
pub async fn resolve(
    host: &str,
    iteration: u16,
    limit: Duration,
    pinned: Option<IpAddr>,
) -> DnsResult {
    let start = Instant::now();
    let mut r = DnsResult {
        hostname: host.into(),
        iteration,
        timestamp: chrono::Utc::now().to_rfc3339(),
        source: if pinned.is_some() {
            "override (DNS skipped)"
        } else {
            "operating system"
        }
        .into(),
        duration_ms: 0.,
        addresses: Vec::new(),
        error: None,
    };
    if let Some(ip) = pinned {
        r.addresses.push(ip);
    } else {
        match tokio::time::timeout(limit, tokio::net::lookup_host((host, 0))).await {
            Err(_) => r.error = Some(Failure::new("DNS_TIMEOUT", "OS resolver exceeded deadline")),
            Ok(Err(e)) => r.error = Some(Failure::new("DNS_LOOKUP_FAILED", e)),
            Ok(Ok(addrs)) => {
                r.addresses = addrs.map(|a| a.ip()).collect();
                r.addresses.sort();
                r.addresses.dedup();
                if r.addresses.is_empty() {
                    r.error = Some(Failure::new(
                        "DNS_NO_ADDRESSES",
                        "OS resolver returned no addresses",
                    ));
                }
            }
        }
    }
    r.duration_ms = start.elapsed().as_secs_f64() * 1000.;
    r
}
