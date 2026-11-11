# diag-core

Shared transport probes for [url-diag](https://github.com/DBANFD/url-diag) and [defender-diag](https://github.com/DBANFD/defender-diag).

Both tools test connectivity the same way: resolve a name with the operating system resolver, connect over TCP, complete a verified TLS handshake against the native trust store, optionally send one HTTP/1.1 request, and optionally do all of that through an HTTP CONNECT proxy. That code used to be copied between the two repositories. It now lives here so a fix lands once.

## Modules

| Module | Purpose |
| --- | --- |
| `types` | Evidence records: `Attempt`, `DnsResult`, `Certificate`, `Failure` |
| `dns` | OS resolver lookup with a deadline, or a pinned address |
| `tcp` | TCP connect with a deadline and stable failure codes |
| `tls` | Verified TLS handshake (rustls, native roots, no resumption), certificate chain summary |
| `http` | One HTTP/1.1 request, headers only, sanitized `Location` capture |
| `proxy` | Proxy selection (explicit, environment, WinHTTP), bypass rules, CONNECT tunnel, Basic authentication |
| `statistics` | Success rate and latency summaries per host |

Catalogs, command lines, reports and dashboards stay in the tools.

## Use

The tools pin an exact commit:

```toml
diag-core = { git = "https://github.com/DBANFD/diag-core", rev = "<commit>" }
```

Callers pass their own User-Agent product token to `http::request` and `proxy::tunnel`, and the wording for what is being diagnosed to `proxy::describe`.

## Proxy authentication

Basic only. Credentials are read from the environment, either `DIAG_PROXY_USER` and `DIAG_PROXY_PASSWORD`, or the userinfo part of `HTTPS_PROXY` / `ALL_PROXY`. They are refused on the command line, and are never serialized, displayed or logged. Basic credentials reach the proxy without encryption, as with any HTTP proxy. Negotiate, Kerberos and NTLM are not supported.

## Build and test

```
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Licensed under the [MIT License](LICENSE).
