//! Explicit HTTP CONNECT proxy routing. Direct remains the default.
//!
//! Supported sources: a literal `http://host:port` URL, the HTTPS_PROXY/ALL_PROXY
//! environment variables (with NO_PROXY), or the Windows WinHTTP configuration
//! (`netsh winhttp show proxy`). PAC/WPAD scripts are not supported.
//!
//! Proxy authentication: Basic only. Credentials come from the environment, either
//! `DIAG_PROXY_USER` and `DIAG_PROXY_PASSWORD` or the userinfo part of
//! HTTPS_PROXY/ALL_PROXY. They are never accepted on the command line and never
//! written to reports, journals or logs. Basic credentials travel to the proxy
//! without encryption, as with any HTTP proxy. Negotiate, Kerberos and NTLM are not
//! supported; a 407 is reported as PROXY_AUTH_REQUIRED or PROXY_AUTH_FAILED.
use crate::types::Failure;
use base64::Engine as _;
use serde::Serialize;
use std::{fmt, str::FromStr, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ProxyChoice {
    #[default]
    Direct,
    Env,
    System,
    Url(Endpoint),
}
impl FromStr for ProxyChoice {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "direct" | "none" => Ok(Self::Direct),
            "env" => Ok(Self::Env),
            "system" | "winhttp" => Ok(Self::System),
            _ => Endpoint::parse(s).map(Self::Url),
        }
    }
}
impl fmt::Display for ProxyChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Env => write!(f, "env"),
            Self::System => write!(f, "system"),
            Self::Url(e) => write!(f, "{e}"),
        }
    }
}
pub fn parse_choice(s: &str) -> Result<ProxyChoice, String> {
    s.parse()
}

/// Basic proxy credentials. Debug output is redacted and the type is not serializable.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub user: String,
    pub password: String,
}
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials([redacted])")
    }
}
impl Credentials {
    /// Value for the Proxy-Authorization header.
    fn basic(&self) -> String {
        let raw = format!("{}:{}", self.user, self.password);
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        )
    }
    /// `DIAG_PROXY_USER` with `DIAG_PROXY_PASSWORD` (the password may be empty).
    pub fn from_env() -> Option<Self> {
        let user = std::env::var("DIAG_PROXY_USER")
            .ok()
            .filter(|v| !v.is_empty())?;
        Some(Self {
            user,
            password: std::env::var("DIAG_PROXY_PASSWORD").unwrap_or_default(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    /// Never serialized or displayed.
    #[serde(skip)]
    pub credentials: Option<Credentials>,
}
impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "http://[{}]:{}", self.host, self.port)
        } else {
            write!(f, "http://{}:{}", self.host, self.port)
        }
    }
}
impl Endpoint {
    /// Accepts `http://host:port`, `host:port` or `[v6]:port`. Credentials, paths,
    /// queries and HTTPS-to-proxy are rejected so nothing secret reaches reports.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let s = raw.trim();
        let rest = match s.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => rest,
            Some((scheme, _)) => {
                return Err(format!(
                    "unsupported proxy scheme '{scheme}': only http:// CONNECT proxies are supported"
                ));
            }
            None => s,
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.contains('@') {
            return Err("proxy credentials are not supported; remove user:password@".into());
        }
        if rest.contains(['/', '?', '#']) || rest.chars().any(|c| c.is_control() || c == ' ') {
            return Err("proxy must be host:port without a path".into());
        }
        let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
            let (host, port) = v6.split_once("]:").ok_or("expected [ipv6]:port")?;
            (host.to_string(), port)
        } else {
            let (host, port) = rest
                .rsplit_once(':')
                .ok_or("proxy needs an explicit port, e.g. http://proxy.example:8080")?;
            (host.to_string(), port)
        };
        let port: u16 = port.parse().map_err(|_| "invalid proxy port".to_string())?;
        if host.is_empty() || port == 0 {
            return Err("proxy host and port are required".into());
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
            credentials: None,
        })
    }
    /// Like [`Endpoint::parse`], but accepts `http://user:password@host:port` as found
    /// in proxy environment variables. Userinfo is percent-decoded.
    pub fn parse_with_userinfo(raw: &str) -> Result<Self, String> {
        let s = raw.trim();
        let (scheme, rest) = match s.split_once("://") {
            Some((scheme, rest)) => (Some(scheme), rest),
            None => (None, s),
        };
        let Some((userinfo, hostport)) = rest.rsplit_once('@') else {
            return Self::parse(s);
        };
        let mut endpoint = Self::parse(&match scheme {
            Some(scheme) => format!("{scheme}://{hostport}"),
            None => hostport.to_string(),
        })?;
        let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
        let user = percent_decode(user).ok_or("invalid percent-encoding in proxy user")?;
        let password =
            percent_decode(password).ok_or("invalid percent-encoding in proxy password")?;
        if user.is_empty() {
            return Err("proxy user name is empty".into());
        }
        endpoint.credentials = Some(Credentials { user, password });
        Ok(endpoint)
    }
}
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Resolved routing for one run: which proxy (if any) applies, plus bypass rules.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub source: String,
    pub endpoint: Option<Endpoint>,
    pub bypass: Vec<String>,
    pub bypass_local: bool,
}
impl Plan {
    pub fn route(&self, host: &str) -> Option<&Endpoint> {
        let endpoint = self.endpoint.as_ref()?;
        let host = host.to_ascii_lowercase();
        if self.bypass_local && !host.contains('.') {
            return None;
        }
        let bypassed = self.bypass.iter().any(|rule| {
            let rule = rule.trim().trim_start_matches("*.").trim_start_matches('.');
            rule == "*"
                || (!rule.is_empty() && (host == rule || host.ends_with(&format!(".{rule}"))))
        });
        (!bypassed).then_some(endpoint)
    }
}

/// Resolves the route and attaches Basic credentials from the environment when a
/// proxy is used and the proxy URL did not already carry them.
pub fn plan(choice: &ProxyChoice) -> Result<Plan, String> {
    let mut plan = resolve(choice)?;
    if let Some(endpoint) = &mut plan.endpoint
        && endpoint.credentials.is_none()
    {
        endpoint.credentials = Credentials::from_env();
    }
    Ok(plan)
}
fn resolve(choice: &ProxyChoice) -> Result<Plan, String> {
    match choice {
        ProxyChoice::Direct => Ok(Plan {
            source: "direct".into(),
            ..Default::default()
        }),
        ProxyChoice::Url(e) => Ok(Plan {
            source: "explicit".into(),
            endpoint: Some(e.clone()),
            ..Default::default()
        }),
        ProxyChoice::Env => {
            let get = |names: &[&str]| {
                names
                    .iter()
                    .find_map(|n| std::env::var(n).ok().filter(|v| !v.trim().is_empty()))
            };
            let endpoint = get(&["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"])
                .map(|v| {
                    Endpoint::parse_with_userinfo(&v)
                        .map_err(|e| format!("HTTPS_PROXY/ALL_PROXY: {e}"))
                })
                .transpose()?;
            let bypass = get(&["NO_PROXY", "no_proxy"])
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            Ok(Plan {
                source: "environment".into(),
                endpoint,
                bypass,
                bypass_local: false,
            })
        }
        ProxyChoice::System => system(),
    }
}

#[cfg(windows)]
fn system() -> Result<Plan, String> {
    let out = std::process::Command::new("netsh")
        .args(["winhttp", "show", "proxy"])
        .output()
        .map_err(|e| format!("could not read WinHTTP proxy: {e}"))?;
    Ok(parse_winhttp(&String::from_utf8_lossy(&out.stdout)))
}
#[cfg(not(windows))]
fn system() -> Result<Plan, String> {
    Err("--proxy system reads Windows WinHTTP settings; use --proxy env or an explicit http://host:port on this platform".into())
}

/// Parses `netsh winhttp show proxy` output. Per-scheme lists use the https= entry.
pub fn parse_winhttp(text: &str) -> Plan {
    let mut plan = Plan {
        source: "winhttp".into(),
        ..Default::default()
    };
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if key.starts_with("proxy server") {
            let pick = value
                .split(';')
                .map(str::trim)
                .find(|v| v.to_ascii_lowercase().starts_with("https="))
                .or_else(|| value.split(';').map(str::trim).find(|v| !v.contains('=')))
                .map(|v| v.split_once('=').map_or(v, |(_, x)| x));
            plan.endpoint = pick.and_then(|v| Endpoint::parse(v).ok());
        } else if key.starts_with("bypass list") {
            for item in value
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty() && *s != "(none)")
            {
                if item.eq_ignore_ascii_case("<local>") {
                    plan.bypass_local = true;
                } else {
                    plan.bypass.push(item.to_string());
                }
            }
        }
    }
    plan
}

#[derive(Serialize)]
pub struct ProxyInfo {
    pub environment_variables_present: Vec<String>,
    /// direct, explicit, environment or winhttp.
    pub source: String,
    /// host:port only; credentials are never exported.
    pub proxy: Option<String>,
    /// "none" or "basic". States only whether credentials were supplied.
    pub authentication: String,
    pub bypass_rules: usize,
    pub note: String,
}
/// Proxy facts for a direct run. `subject` names what is being diagnosed, for
/// example "the tested application's" or "the Defender sensor's".
pub fn detect(subject: &str) -> ProxyInfo {
    describe(
        &Plan {
            source: "direct".into(),
            ..Default::default()
        },
        subject,
    )
}
pub fn describe(plan: &Plan, subject: &str) -> ProxyInfo {
    // Intentionally export variable names only, never values or NO_PROXY contents.
    let names = [
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
        "no_proxy",
    ];
    let authenticated = plan
        .endpoint
        .as_ref()
        .is_some_and(|e| e.credentials.is_some());
    let note = match &plan.endpoint {
        None => format!(
            "All probes are DIRECT. This is not necessarily {subject} effective proxy configuration. Use --proxy env, --proxy system (WinHTTP) or --proxy http://host:port to test through a proxy."
        ),
        Some(e) => format!(
            "Probes use HTTP CONNECT through {e} ({}) unless a bypass rule matches. The proxy resolves target names, so per-IP results are not available for proxied hosts. PAC/WPAD is not supported. Proxy authentication: {}.",
            plan.source,
            if authenticated {
                "Basic credentials from the environment are sent"
            } else {
                "none supplied (Basic is supported through DIAG_PROXY_USER and DIAG_PROXY_PASSWORD)"
            }
        ),
    };
    ProxyInfo {
        environment_variables_present: names
            .iter()
            .filter(|n| std::env::var_os(n).is_some())
            .map(|n| n.to_string())
            .collect(),
        source: plan.source.clone(),
        proxy: plan.endpoint.as_ref().map(|e| e.to_string()),
        authentication: if authenticated { "basic" } else { "none" }.into(),
        bypass_rules: plan.bypass.len() + usize::from(plan.bypass_local),
        note,
    }
}

/// Connect to the proxy and open a CONNECT tunnel. Returns the tunnel and the
/// time spent on the proxy TCP connect and the CONNECT exchange. `user_agent` is the
/// calling tool's product token.
pub async fn tunnel(
    proxy: &Endpoint,
    host: &str,
    port: u16,
    limit: Duration,
    user_agent: &str,
) -> Result<(tokio::net::TcpStream, f64, f64), Failure> {
    let start = std::time::Instant::now();
    let connect = tokio::net::TcpStream::connect((proxy.host.as_str(), proxy.port));
    let mut stream = match tokio::time::timeout(limit, connect).await {
        Err(_) => {
            return Err(Failure::new(
                "PROXY_TCP_TIMEOUT",
                format!("connect to proxy {proxy} exceeded deadline"),
            ));
        }
        Ok(Err(e)) => {
            return Err(Failure::new(
                &format!("PROXY_{}", crate::tcp::classify(&e)),
                format!("proxy {proxy}: {e}"),
            ));
        }
        Ok(Ok(s)) => s,
    };
    let tcp_ms = start.elapsed().as_secs_f64() * 1000.;
    let start = std::time::Instant::now();
    let exchange = async {
        let authorization = proxy
            .credentials
            .as_ref()
            .map(|c| format!("Proxy-Authorization: {}\r\n", c.basic()))
            .unwrap_or_default();
        let request = format!(
            "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: {user_agent}\r\n{authorization}Proxy-Connection: keep-alive\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| Failure::new("PROXY_IO", e))?;
        // Read byte by byte so no tunnel bytes are consumed past the header block.
        let mut buf = Vec::new();
        loop {
            let b = stream
                .read_u8()
                .await
                .map_err(|e| Failure::new("PROXY_IO", e))?;
            buf.push(b);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if buf.len() >= 16384 {
                return Err(Failure::new(
                    "PROXY_INVALID_RESPONSE",
                    "CONNECT response headers exceed 16 KiB",
                ));
            }
        }
        let status = crate::http::parse_status(&buf)
            .map_err(|f| Failure::new("PROXY_INVALID_RESPONSE", f.message))?;
        match status {
            200..=299 => Ok(()),
            407 => {
                let offered = offered_schemes(&buf);
                Err(if proxy.credentials.is_some() {
                    Failure::new(
                        "PROXY_AUTH_FAILED",
                        format!(
                            "proxy rejected the supplied Basic credentials (407). Schemes offered by the proxy: {offered}. Only Basic is supported."
                        ),
                    )
                } else {
                    Failure::new(
                        "PROXY_AUTH_REQUIRED",
                        format!(
                            "proxy requires authentication (407). Schemes offered by the proxy: {offered}. Basic is supported: set DIAG_PROXY_USER and DIAG_PROXY_PASSWORD."
                        ),
                    )
                })
            }
            s => Err(Failure::new(
                "PROXY_CONNECT_REJECTED",
                format!("proxy answered CONNECT with HTTP {s}"),
            )),
        }
    };
    match tokio::time::timeout(limit, exchange).await {
        Err(_) => Err(Failure::new(
            "PROXY_TIMEOUT",
            "CONNECT response exceeded deadline",
        )),
        Ok(Err(e)) => Err(e),
        Ok(Ok(())) => Ok((stream, tcp_ms, start.elapsed().as_secs_f64() * 1000.)),
    }
}

/// Scheme names from Proxy-Authenticate headers (never the challenge parameters).
fn offered_schemes(headers: &[u8]) -> String {
    let text = String::from_utf8_lossy(headers);
    let mut schemes: Vec<String> = text
        .lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("proxy-authenticate")
                .then(|| value.split_whitespace().next().unwrap_or("").to_string())
        })
        .filter(|s| !s.is_empty() && s.len() <= 32 && s.chars().all(|c| c.is_ascii_graphic()))
        .collect();
    schemes.sort();
    schemes.dedup();
    if schemes.is_empty() {
        "not stated".into()
    } else {
        schemes.join(", ")
    }
}

static SESSION: std::sync::OnceLock<ProxyChoice> = std::sync::OnceLock::new();
/// Dashboard-wide route chosen at launch with `ui --proxy`.
pub fn set_session(choice: ProxyChoice) {
    let _ = SESSION.set(choice);
}
pub fn session() -> ProxyChoice {
    SESSION.get().cloned().unwrap_or_default()
}
/// Short header label: DIRECT, or PROXY with its source.
pub fn session_label() -> String {
    match session() {
        ProxyChoice::Direct => "DIRECT".into(),
        other => format!("PROXY {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_choices_and_rejects_secrets() {
        assert_eq!(
            "direct".parse::<ProxyChoice>().unwrap(),
            ProxyChoice::Direct
        );
        assert_eq!("ENV".parse::<ProxyChoice>().unwrap(), ProxyChoice::Env);
        assert_eq!(
            "winhttp".parse::<ProxyChoice>().unwrap(),
            ProxyChoice::System
        );
        let e = Endpoint::parse("http://Proxy.Example:8080/").unwrap();
        assert_eq!((e.host.as_str(), e.port), ("proxy.example", 8080));
        assert_eq!(
            Endpoint::parse("[2001:db8::1]:3128").unwrap().to_string(),
            "http://[2001:db8::1]:3128"
        );
        for bad in [
            "http://user:pw@proxy:8080",
            "https://proxy:443",
            "proxy",
            "proxy:0",
            "http://proxy:8080/path",
            "socks5://p:1080",
            "proxy:80\r\nX: y",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn bypass_rules() {
        let plan = Plan {
            source: "environment".into(),
            endpoint: Some(Endpoint::parse("proxy:8080").unwrap()),
            bypass: vec!["corp.example".into(), "*.internal".into(), ".lan".into()],
            bypass_local: true,
        };
        assert!(plan.route("login.microsoftonline.com").is_some());
        assert!(plan.route("corp.example").is_none());
        assert!(plan.route("a.corp.example").is_none());
        assert!(plan.route("notcorp.example").is_some());
        assert!(plan.route("db.internal").is_none());
        assert!(plan.route("host.lan").is_none());
        assert!(plan.route("intranet").is_none());
        let all = Plan {
            bypass: vec!["*".into()],
            ..plan.clone()
        };
        assert!(all.route("anything.example").is_none());
        assert!(Plan::default().route("x.example").is_none());
    }
    #[test]
    fn winhttp_output() {
        let direct = parse_winhttp(
            "Current WinHTTP proxy settings:\n\n    Direct access (no proxy server).\n",
        );
        assert!(direct.endpoint.is_none());
        let p = parse_winhttp(
            "Current WinHTTP proxy settings:\n\n    Proxy Server(s) :  http=web:80;https=secure.example:8443\n    Bypass List     :  *.corp.example;<local>\n",
        );
        assert_eq!(
            p.endpoint.unwrap().to_string(),
            "http://secure.example:8443"
        );
        assert_eq!(p.bypass, vec!["*.corp.example"]);
        assert!(p.bypass_local);
        let single = parse_winhttp(
            "    Proxy Server(s) :  proxy.example:3128\n    Bypass List     :  (none)\n",
        );
        assert_eq!(single.endpoint.unwrap().port, 3128);
        assert!(single.bypass.is_empty());
    }
    #[test]
    fn info_never_exports_values() {
        let info = describe(
            &Plan {
                source: "explicit".into(),
                endpoint: Some(Endpoint::parse("proxy.example:8080").unwrap()),
                ..Default::default()
            },
            "the tested application's",
        );
        assert_eq!(info.proxy.as_deref(), Some("http://proxy.example:8080"));
        assert_eq!(info.authentication, "none");
        assert!(info.note.contains("CONNECT"));
        assert!(
            detect("the Defender sensor's")
                .note
                .contains("the Defender sensor's effective proxy")
        );
    }
    #[test]
    fn credentials_are_parsed_from_environment_urls_and_never_leak() {
        // The command-line parser still refuses credentials.
        assert!(Endpoint::parse("http://user:pw@proxy:8080").is_err());
        let e = Endpoint::parse_with_userinfo("http://svc%40corp:p%3Aw%20d@Proxy.Example:8080/")
            .unwrap();
        assert_eq!((e.host.as_str(), e.port), ("proxy.example", 8080));
        let c = e.credentials.clone().unwrap();
        assert_eq!(
            (c.user.as_str(), c.password.as_str()),
            ("svc@corp", "p:w d")
        );
        assert_eq!(c.basic(), "Basic c3ZjQGNvcnA6cDp3IGQ=");
        assert_eq!(e.to_string(), "http://proxy.example:8080");
        let debug = format!("{e:?}");
        assert!(!debug.contains("svc") && !debug.contains("p:w"), "{debug}");
        let info = describe(
            &Plan {
                source: "environment".into(),
                endpoint: Some(e),
                ..Default::default()
            },
            "the tested application's",
        );
        assert_eq!(info.authentication, "basic");
        assert!(
            !info.note.contains("svc")
                && info.proxy.as_deref() == Some("http://proxy.example:8080")
        );
        assert!(
            Endpoint::parse_with_userinfo("proxy.example:3128")
                .unwrap()
                .credentials
                .is_none()
        );
        for bad in [
            "http://:pw@proxy:8080",
            "http://u%zz:pw@proxy:8080",
            "https://u:p@proxy:443",
        ] {
            assert!(Endpoint::parse_with_userinfo(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn offered_schemes_lists_names_only() {
        assert_eq!(
            offered_schemes(
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Negotiate\r\nproxy-authenticate: Basic realm=\"secret realm\"\r\n\r\n"
            ),
            "Basic, Negotiate"
        );
        assert_eq!(offered_schemes(b"HTTP/1.1 407 x\r\n\r\n"), "not stated");
    }
}
