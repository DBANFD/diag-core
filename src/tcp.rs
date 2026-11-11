use crate::types::Failure;
use std::{io, net::SocketAddr, time::Duration};
pub fn classify(e: &io::Error) -> &'static str {
    match e.kind() {
        io::ErrorKind::TimedOut => "TCP_TIMEOUT",
        io::ErrorKind::ConnectionRefused => "TCP_REFUSED",
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => "TCP_UNREACHABLE",
        io::ErrorKind::PermissionDenied => "TCP_PERMISSION_DENIED",
        io::ErrorKind::ConnectionReset => "TCP_RESET",
        _ => "TCP_OTHER",
    }
}
pub async fn connect(addr: SocketAddr, limit: Duration) -> Result<tokio::net::TcpStream, Failure> {
    match tokio::time::timeout(limit, tokio::net::TcpStream::connect(addr)).await {
        Err(_) => Err(Failure::new("TCP_TIMEOUT", "connect exceeded deadline")),
        Ok(Err(e)) => Err(Failure::new(classify(&e), e)),
        Ok(Ok(s)) => Ok(s),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classification() {
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::ConnectionRefused)),
            "TCP_REFUSED"
        );
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::NetworkUnreachable)),
            "TCP_UNREACHABLE"
        );
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::TimedOut)),
            "TCP_TIMEOUT"
        );
    }
}
