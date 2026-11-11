//! One HTTP/1.1 request over an established TLS stream. Headers only, never a body.
use crate::{tls::Stream, types::Failure};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Response headers larger than this are refused.
pub const MAX_HEADER_BYTES: usize = 32768;

/// What to send. `user_agent` is the full product token, e.g. `url-diag/0.3.0`.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub user_agent: &'a str,
}

/// Host header value. The default HTTPS port is omitted, as browsers and agents do,
/// so front ends that route on the exact Host value see what a real client sends.
pub fn host_header(host: &str, port: u16) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    }
}

/// Sends the request and returns the status plus a sanitized Location header
/// (3xx only; query and fragment removed). Redirects are never followed.
pub async fn request(
    s: &mut Stream,
    host: &str,
    port: u16,
    limit: Duration,
    plan: Request<'_>,
) -> Result<(u16, Option<String>), Failure> {
    let work = async {
        let request = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: close\r\n\r\n",
            plan.method,
            plan.path,
            host_header(host, port),
            plan.user_agent
        );
        s.write_all(request.as_bytes())
            .await
            .map_err(|e| Failure::new("HTTP_IO", e))?;
        s.flush().await.map_err(|e| Failure::new("HTTP_IO", e))?;
        // Chunked reads; memory stays bounded even for hostile or malformed servers.
        let mut buf: Vec<u8> = Vec::with_capacity(2048);
        let mut chunk = [0u8; 2048];
        let mut scanned = 0usize;
        loop {
            let n = s
                .read(&mut chunk)
                .await
                .map_err(|e| Failure::new("HTTP_IO", e))?;
            if n == 0 {
                return Err(Failure::new(
                    "HTTP_IO",
                    "connection closed before response headers were complete",
                ));
            }
            buf.extend_from_slice(&chunk[..n]);
            // Resume the terminator search three bytes back so a split CRLFCRLF is found.
            while let Some(end) = find_terminator(&buf, scanned) {
                let head = &buf[..end];
                let status = parse_status(head)?;
                if (100..200).contains(&status) && status != 101 {
                    // Interim response: drop it and keep reading the final one.
                    buf.drain(..end);
                    scanned = 0;
                    continue;
                }
                let location = (300..400)
                    .contains(&status)
                    .then(|| location(head))
                    .flatten();
                return Ok((status, location));
            }
            scanned = buf.len().saturating_sub(3);
            if buf.len() >= MAX_HEADER_BYTES {
                return Err(Failure::new(
                    "HTTP_HEADERS_TOO_LARGE",
                    "headers exceed 32 KiB",
                ));
            }
        }
    };
    tokio::time::timeout(limit, work)
        .await
        .map_err(|_| Failure::new("HTTP_TIMEOUT", "response headers exceeded deadline"))?
}

/// Index just past the first CRLFCRLF at or after `from`.
fn find_terminator(buf: &[u8], from: usize) -> Option<usize> {
    buf.get(from..)?
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| from + i + 4)
}

pub fn parse_status(buf: &[u8]) -> Result<u16, Failure> {
    let line = buf.split(|b| *b == b'\n').next().unwrap_or_default();
    let text = std::str::from_utf8(line)
        .map_err(|_| Failure::new("HTTP_INVALID_RESPONSE", "invalid status encoding"))?;
    let parts: Vec<_> = text.split_whitespace().collect();
    if parts.len() < 2
        || !matches!(parts[0], "HTTP/1.0" | "HTTP/1.1")
        || parts[1].len() != 3
        || !parts[1].bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Failure::new(
            "HTTP_INVALID_RESPONSE",
            "invalid HTTP/1.x status line",
        ));
    }
    let status = parts[1]
        .parse::<u16>()
        .map_err(|_| Failure::new("HTTP_INVALID_RESPONSE", "invalid status"))?;
    if !(100..=599).contains(&status) {
        return Err(Failure::new(
            "HTTP_INVALID_RESPONSE",
            "status outside 100..599",
        ));
    }
    Ok(status)
}

/// Extracts Location, dropping any query string or fragment because redirects can
/// carry tokens. Control characters are removed and the value is capped at 512 bytes.
pub fn location(headers: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(headers);
    let raw = text.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("location")
            .then(|| value.trim().to_string())
    })?;
    let cut = raw.find(['?', '#']).unwrap_or(raw.len());
    let clean: String = raw[..cut]
        .chars()
        .filter(|c| !c.is_control())
        .take(512)
        .collect();
    (!clean.is_empty()).then_some(clean)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn application_errors_are_transport_responses() {
        assert_eq!(
            parse_status(b"HTTP/1.1 403 Forbidden\r\n\r\n").unwrap(),
            403
        );
        assert_eq!(
            parse_status(b"HTTP/1.1 404 Not Found\r\n\r\n").unwrap(),
            404
        );
        assert!(parse_status(b"garbage 200").is_err());
    }
    #[test]
    fn host_header_omits_only_the_default_port() {
        assert_eq!(host_header("example.com", 443), "example.com");
        assert_eq!(host_header("example.com", 8443), "example.com:8443");
        assert_eq!(host_header("2001:db8::1", 443), "[2001:db8::1]");
        assert_eq!(host_header("2001:db8::1", 8443), "[2001:db8::1]:8443");
    }
    #[test]
    fn terminator_search_handles_split_and_offset() {
        assert_eq!(find_terminator(b"HTTP/1.1 200 OK\r\n\r\nrest", 0), Some(19));
        assert_eq!(find_terminator(b"abc\r\n\r", 0), None);
        assert_eq!(find_terminator(b"abc\r\n\r\n", 3), Some(7));
        assert_eq!(find_terminator(b"ab", 10), None);
    }
    #[test]
    fn strips_tokens_and_controls() {
        assert_eq!(
            location(
                b"HTTP/1.1 302 Found\r\nLocation: https://login.example/auth?code=secret#x\r\n\r\n"
            )
            .as_deref(),
            Some("https://login.example/auth")
        );
        assert_eq!(
            location(b"HTTP/1.1 301 Moved\r\nlocation:/new\r\n\r\n").as_deref(),
            Some("/new")
        );
        assert_eq!(location(b"HTTP/1.1 302 Found\r\nServer: x\r\n\r\n"), None);
        assert_eq!(
            location(b"HTTP/1.1 302 Found\r\nLocation: ?only=query\r\n\r\n"),
            None
        );
    }
}
