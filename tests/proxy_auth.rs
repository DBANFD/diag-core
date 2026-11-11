use diag_core::proxy::{self, Credentials, Endpoint};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// CONNECT proxy that accepts only `Basic dXNlcjpwYXNz` (user:pass) and records the request.
async fn auth_proxy() -> (std::net::SocketAddr, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(client.read_u8().await.unwrap());
        }
        let request = String::from_utf8(request).unwrap();
        let reply = if request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n") {
            "HTTP/1.1 200 Connection established\r\n\r\n"
        } else {
            "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\nProxy-Authenticate: Basic realm=\"corp\"\r\nContent-Length: 0\r\n\r\n"
        };
        client.write_all(reply.as_bytes()).await.unwrap();
        request
    });
    (address, task)
}

fn endpoint(address: std::net::SocketAddr, credentials: Option<(&str, &str)>) -> Endpoint {
    let mut endpoint = Endpoint::parse(&address.to_string()).unwrap();
    endpoint.credentials = credentials.map(|(user, password)| Credentials {
        user: user.into(),
        password: password.into(),
    });
    endpoint
}

#[tokio::test]
async fn basic_credentials_open_the_tunnel() {
    let (address, task) = auth_proxy().await;
    let endpoint = endpoint(address, Some(("user", "pass")));
    proxy::tunnel(
        &endpoint,
        "example.invalid",
        443,
        Duration::from_secs(3),
        "test/1",
    )
    .await
    .unwrap();
    let request = task.await.unwrap();
    assert!(request.contains("User-Agent: test/1\r\n"), "{request}");
}

#[tokio::test]
async fn missing_and_wrong_credentials_are_distinct_failures() {
    for (credentials, code) in [
        (None, "PROXY_AUTH_REQUIRED"),
        (Some(("user", "wrong")), "PROXY_AUTH_FAILED"),
    ] {
        let (address, task) = auth_proxy().await;
        let endpoint = endpoint(address, credentials);
        let err = proxy::tunnel(
            &endpoint,
            "example.invalid",
            443,
            Duration::from_secs(3),
            "test/1",
        )
        .await
        .unwrap_err();
        assert_eq!(err.code, code);
        // Scheme names are reported; the secret and the realm are not.
        assert!(err.message.contains("Basic, Negotiate"), "{}", err.message);
        assert!(!err.message.contains("wrong") && !err.message.contains("corp"));
        let request = task.await.unwrap();
        assert_eq!(
            request.contains("Proxy-Authorization:"),
            credentials.is_some()
        );
    }
}
