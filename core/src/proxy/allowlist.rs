//! Pure egress authorization, following `spec/02-core.md` (egress proxy).
//!
//! Call `Allowlist::authorize` before DNS, resolve once in the core, then call
//! `AuthorizedTarget::validate_resolved` with *all* returned addresses. Connect
//! only to that validated address set; resolving the hostname again would reopen
//! DNS rebinding. This module performs no DNS or network I/O.

use super::nat64::{Nat64Prefixes, is_local_use};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Connect,
    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AllowlistError {
    #[error("invalid allowlist pattern")]
    InvalidPattern,
    #[error("invalid destination host")]
    InvalidHost,
    #[error("invalid destination port")]
    InvalidPort,
    #[error("destination is not allowed")]
    Denied,
    #[error("DNS returned no destination addresses")]
    EmptyResolution,
    #[error("non-public address requires an exact host and explicit port")]
    NonPublicAddress,
    #[error("resolved address does not match the authorized IP literal")]
    ResolutionMismatch,
}

#[derive(Debug, Clone)]
enum HostPattern {
    Any,
    Subdomains(String),
    Exact(String),
}

#[derive(Debug, Clone)]
struct Rule {
    host: HostPattern,
    port: u16,
    explicit_port: bool,
}

/// An empty allowlist denies every destination.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    rules: Vec<Rule>,
    nat64: Nat64Prefixes,
}

/// A normalized destination whose hostname/port matched the allowlist.
/// Address validation is still required before opening a connection.
#[derive(Debug, Clone)]
pub struct AuthorizedTarget {
    host: String,
    port: u16,
    exact_with_port: bool,
    literal: Option<IpAddr>,
    nat64: Nat64Prefixes,
}

impl Allowlist {
    /// Parses exact hosts and `*.domain`, optionally suffixed by a decimal port,
    /// plus bare `*`. IP literals require a port; IPv6 also requires brackets.
    /// Without a port only CONNECT to 443 is allowed.
    pub fn new(patterns: &[String]) -> Result<Self, AllowlistError> {
        Self::new_with_nat64(patterns, &Nat64Prefixes::default())
    }

    pub fn new_with_nat64(
        patterns: &[String],
        nat64: &Nat64Prefixes,
    ) -> Result<Self, AllowlistError> {
        let rules = patterns
            .iter()
            .map(|pattern| Rule::parse(pattern, nat64))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            rules,
            nat64: nat64.clone(),
        })
    }

    /// Canonical spelling for lock preparation, preserving the original order.
    /// `Ipv6Addr::Display` uses RFC 5952 (ADR-021).
    pub fn normalized_patterns(&self) -> Vec<String> {
        self.rules
            .iter()
            .map(|rule| {
                let host = match &rule.host {
                    HostPattern::Any => "*".into(),
                    HostPattern::Subdomains(suffix) => format!("*.{suffix}"),
                    HostPattern::Exact(host) if host.contains(':') => format!("[{host}]"),
                    HostPattern::Exact(host) => host.clone(),
                };
                if rule.explicit_port {
                    format!("{host}:{}", rule.port)
                } else {
                    host
                }
            })
            .collect()
    }

    /// Whether every permitted host belongs to the exact trusted-host list.
    /// This uses the same ASCII case folding as the egress proxy. Configured
    /// trusted entries are host names, not patterns or authorities: no port,
    /// root-dot or alternative IP spelling is silently removed from them.
    /// Ports on parsed allow rules do not change a host's trust. A finite exact
    /// list cannot cover `*` or `*.domain`, even if it contains known children.
    pub fn all_hosts_trusted(&self, trusted_domains: &[String]) -> bool {
        self.rules.iter().all(|rule| match &rule.host {
            HostPattern::Exact(host) => trusted_domains
                .iter()
                .any(|trusted| host.eq_ignore_ascii_case(trusted)),
            HostPattern::Any | HostPattern::Subdomains(_) => false,
        })
    }

    /// `host` is the host alone, without URL syntax or a port. IPv6 literals may
    /// be unbracketed or bracketed. Mapped IPv4 and well-known NAT64 destinations
    /// are compared by their embedded IPv4 without changing the connection host.
    pub fn authorize(
        &self,
        host: &str,
        port: u16,
        kind: RequestKind,
    ) -> Result<AuthorizedTarget, AllowlistError> {
        if port == 0 {
            return Err(AllowlistError::InvalidPort);
        }
        // Absolute DNS names accept one root dot in requests; manifest patterns
        // keep their stricter grammar through normalize_host in Rule::parse.
        let host = if !host.contains([':', '[', ']']) {
            host.strip_suffix('.').unwrap_or(host)
        } else {
            host
        };
        let host = normalize_host(host)?;
        let literal = host.parse::<IpAddr>().ok();
        // RFC 6761 reserves the entire .localhost namespace for loopback use.
        let requires_exact =
            literal.is_some() || host == "localhost" || host.ends_with(".localhost");
        let mut matched = false;
        let mut exact_with_port = false;
        for rule in &self.rules {
            if rule.port != port || (kind == RequestKind::Http && !rule.explicit_port) {
                continue;
            }
            let host_matches = match &rule.host {
                HostPattern::Any => true,
                HostPattern::Subdomains(suffix) => host
                    .strip_suffix(suffix)
                    .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.')),
                HostPattern::Exact(expected) => match (expected.parse::<IpAddr>(), literal) {
                    (Ok(expected), Some(actual)) => {
                        self.nat64.canonical_ip(expected) == self.nat64.canonical_ip(actual)
                    }
                    _ => host == *expected,
                },
            };
            if host_matches {
                matched = true;
                exact_with_port |= rule.explicit_port && matches!(rule.host, HostPattern::Exact(_));
            }
        }
        if !matched || (requires_exact && !exact_with_port) {
            return Err(AllowlistError::Denied);
        }
        Ok(AuthorizedTarget {
            host,
            port,
            exact_with_port,
            literal,
            nat64: self.nat64.clone(),
        })
    }
}

impl AuthorizedTarget {
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Rejects the whole DNS result when any address is outside the permission.
    /// An exact hostname with an explicit port can intentionally name a private
    /// service. A wildcard or implicit 443 never authorizes that access.
    pub fn validate_resolved(&self, addresses: &[IpAddr]) -> Result<(), AllowlistError> {
        if addresses.is_empty() {
            return Err(AllowlistError::EmptyResolution);
        }
        for address in addresses {
            if self.literal.is_some_and(|literal| {
                self.nat64.canonical_ip(literal) != self.nat64.canonical_ip(*address)
            }) {
                return Err(AllowlistError::ResolutionMismatch);
            }
            if !self.exact_with_port && !is_public(*address, &self.nat64) {
                return Err(AllowlistError::NonPublicAddress);
            }
        }
        Ok(())
    }
}

impl Rule {
    fn parse(pattern: &str, nat64: &Nat64Prefixes) -> Result<Self, AllowlistError> {
        if let Some(bracketed) = pattern.strip_prefix('[') {
            let (address, port) = bracketed
                .split_once("]:")
                .ok_or(AllowlistError::InvalidPattern)?;
            let address = address
                .parse::<Ipv6Addr>()
                .map_err(|_| AllowlistError::InvalidPattern)?;
            if address.to_ipv4_mapped().is_some() || nat64.is_translation(address) {
                return Err(AllowlistError::InvalidPattern);
            }
            return Ok(Self {
                host: HostPattern::Exact(address.to_string()),
                port: parse_port(port)?,
                explicit_port: true,
            });
        }
        if pattern.contains(['[', ']']) || pattern.matches(':').count() > 1 {
            return Err(AllowlistError::InvalidPattern);
        }
        let (host, port, explicit_port) = match pattern.split_once(':') {
            Some((host, port)) => {
                if host == "*" {
                    return Err(AllowlistError::InvalidPattern);
                }
                (host, parse_port(port)?, true)
            }
            None => (pattern, 443, false),
        };
        let host = if host == "*" {
            HostPattern::Any
        } else if let Some(suffix) = host.strip_prefix("*.") {
            let suffix = normalize_host(suffix).map_err(|_| AllowlistError::InvalidPattern)?;
            if suffix.parse::<IpAddr>().is_ok() {
                return Err(AllowlistError::InvalidPattern);
            }
            HostPattern::Subdomains(suffix)
        } else {
            let host = normalize_host(host).map_err(|_| AllowlistError::InvalidPattern)?;
            if !explicit_port && host.parse::<IpAddr>().is_ok() {
                return Err(AllowlistError::InvalidPattern);
            }
            HostPattern::Exact(host)
        };
        Ok(Self {
            host,
            port,
            explicit_port,
        })
    }
}

fn parse_port(port: &str) -> Result<u16, AllowlistError> {
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AllowlistError::InvalidPattern);
    }
    port.parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(AllowlistError::InvalidPattern)
}

fn normalize_host(host: &str) -> Result<String, AllowlistError> {
    if host.is_empty() || !host.is_ascii() || host.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(AllowlistError::InvalidHost);
    }
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        return inner
            .parse::<Ipv6Addr>()
            .map(|address| address.to_string())
            .map_err(|_| AllowlistError::InvalidHost);
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(address.to_string());
    }
    if host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(AllowlistError::InvalidHost);
    }
    // Reject legacy numeric forms (127.1, integer/octal/hex IPv4) instead of
    // allowing resolver-specific interpretation to differ from this parser.
    let last = host.rsplit('.').next().ok_or(AllowlistError::InvalidHost)?;
    if last.bytes().all(|byte| byte.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .or_else(|| last.strip_prefix("0X"))
            .is_some_and(|digits| {
                !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
    {
        return Err(AllowlistError::InvalidHost);
    }
    Ok(host.to_ascii_lowercase())
}

fn is_public(address: IpAddr, nat64: &Nat64Prefixes) -> bool {
    if let IpAddr::V6(address) = address
        && is_local_use(address)
    {
        return false;
    }
    match nat64.canonical_ip(address) {
        IpAddr::V4(address) => public_v4(address),
        IpAddr::V6(address) => public_v6(address),
    }
}

fn public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, d] = address.octets();
    // IANA special-purpose registry, checked 2026-10-17:
    // https://www.iana.org/assignments/iana-ipv4-special-registry
    // Multicast is not a public unicast TCP destination either.
    !(a == 0
        || a == 10
        || (a == 100 && (64..=127).contains(&b))
        || a == 127
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0 && d != 9 && d != 10)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn public_v6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    // IANA special-purpose registry, checked 2026-10-17:
    // https://www.iana.org/assignments/iana-ipv6-special-registry
    if !(0x2000..=0x3fff).contains(&segments[0]) {
        return false;
    }
    if segments[0] == 0x2001 && segments[1] < 0x200 {
        return (segments[1] == 1 && segments[2..7] == [0; 5] && (1..=3).contains(&segments[7]))
            || segments[1] == 3
            || (segments[1] == 4 && segments[2] == 0x112)
            || (0x20..=0x3f).contains(&segments[1]);
    }
    !(segments[0] == 0x2002
        || (segments[0] == 0x2001 && segments[1] == 0xdb8)
        || (segments[0] == 0x3fff && segments[1] < 0x1000))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(patterns: &[&str]) -> Allowlist {
        Allowlist::new(
            &patterns
                .iter()
                .map(|pattern| (*pattern).into())
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn ip(address: &str) -> IpAddr {
        address.parse().unwrap()
    }

    #[test]
    fn trust_coverage_uses_exact_hosts_and_ignores_allowed_ports() {
        let trusted = [
            "TRUSTED.EXAMPLE".into(),
            "127.0.0.1".into(),
            "2001:db8::1".into(),
        ];
        assert!(allow(&[]).all_hosts_trusted(&[]));
        assert!(
            allow(&[
                "Trusted.Example",
                "trusted.example:8443",
                "127.0.0.1:80",
                "[2001:db8::1]:443"
            ])
            .all_hosts_trusted(&trusted)
        );
        assert!(!allow(&["trusted.example", "untrusted.example"]).all_hosts_trusted(&trusted));
        assert!(!allow(&["trusted.example.evil"]).all_hosts_trusted(&trusted));
        assert!(!allow(&["sub.trusted.example"]).all_hosts_trusted(&trusted));
    }

    #[test]
    fn finite_exact_trust_never_covers_wildcard_network_authority() {
        let trusted = [
            "example.com".into(),
            "a.example.com".into(),
            "b.example.com".into(),
            "*.example.com".into(),
            "*".into(),
        ];
        assert!(!allow(&["*"]).all_hosts_trusted(&trusted));
        assert!(!allow(&["*.example.com"]).all_hosts_trusted(&trusted));
        assert!(!allow(&["*.example.com:8443"]).all_hosts_trusted(&trusted));
        assert!(allow(&["a.example.com", "b.example.com:8443"]).all_hosts_trusted(&trusted));
    }

    #[test]
    fn trust_entries_preserve_the_existing_egress_host_comparison() {
        for entry in [
            "trusted.example:443",
            "trusted.example.",
            " trusted.example",
            "*.example",
        ] {
            assert!(!allow(&["trusted.example"]).all_hosts_trusted(&[entry.into()]));
        }
        assert!(!allow(&["[2001:db8::1]:443"]).all_hosts_trusted(&["[2001:db8::1]".into()]));
        assert!(!allow(&["[2001:db8::1]:443"]).all_hosts_trusted(&["2001:db8:0:0:0:0:0:1".into()]));
    }

    #[test]
    fn exact_domains_and_default_port_are_strict() {
        let list = allow(&["Example.COM"]);
        let approved = list
            .authorize("EXAMPLE.com", 443, RequestKind::Connect)
            .unwrap();
        assert_eq!(approved.host(), "example.com");
        assert_eq!(approved.port(), 443);
        approved.validate_resolved(&[ip("93.184.215.14")]).unwrap();
        for host in ["www.example.com", "example.com.evil.test", "notexample.com"] {
            assert_eq!(
                list.authorize(host, 443, RequestKind::Connect).unwrap_err(),
                AllowlistError::Denied
            );
        }
        assert!(
            list.authorize("example.com", 8443, RequestKind::Connect)
                .is_err()
        );
        assert!(
            list.authorize("example.com", 443, RequestKind::Http)
                .is_err()
        );
        assert!(
            Allowlist::default()
                .authorize("example.com", 443, RequestKind::Connect)
                .is_err()
        );
    }

    #[test]
    fn wildcard_requires_a_label_boundary_and_excludes_apex() {
        let list = allow(&["*.example.com"]);
        for host in ["a.example.com", "a.b.example.com"] {
            list.authorize(host, 443, RequestKind::Connect).unwrap();
        }
        for host in ["example.com", "notexample.com", "a.example.com.evil.test"] {
            assert!(
                list.authorize(host, 443, RequestKind::Connect).is_err(),
                "{host}"
            );
        }
    }

    #[test]
    fn destination_root_dot_is_normalized_without_relaxing_patterns() {
        let exact = allow(&["example.com"]);
        assert_eq!(
            exact
                .authorize("EXAMPLE.com.", 443, RequestKind::Connect)
                .unwrap()
                .host(),
            "example.com"
        );
        assert_eq!(
            allow(&["*.example.com"])
                .authorize("a.example.com.", 443, RequestKind::Connect)
                .unwrap()
                .host(),
            "a.example.com"
        );
        for host in ["example.com..", "[::1].", "::1."] {
            assert_eq!(
                exact
                    .authorize(host, 443, RequestKind::Connect)
                    .unwrap_err(),
                AllowlistError::InvalidHost
            );
        }
        for pattern in ["example.com.", "*.example.com.", "example.com.:443"] {
            assert_eq!(
                Allowlist::new(&[pattern.into()]).unwrap_err(),
                AllowlistError::InvalidPattern
            );
        }
        assert_eq!(
            allow(&["*"])
                .authorize("127.0.0.1.", 443, RequestKind::Connect)
                .unwrap_err(),
            AllowlistError::Denied
        );
        let loopback = allow(&["127.0.0.1:443"])
            .authorize("127.0.0.1.", 443, RequestKind::Connect)
            .unwrap();
        assert_eq!(loopback.host(), "127.0.0.1");
        loopback.validate_resolved(&[ip("127.0.0.1")]).unwrap();
    }

    #[test]
    fn plain_http_requires_an_explicit_matching_port() {
        let list = allow(&[
            "example.com",
            "other.example:80",
            "*.test:8080",
            "*.example:8443",
        ]);
        assert!(
            list.authorize("example.com", 80, RequestKind::Http)
                .is_err()
        );
        assert!(
            list.authorize("example.com", 443, RequestKind::Http)
                .is_err()
        );
        list.authorize("other.example", 80, RequestKind::Http)
            .unwrap();
        list.authorize("service.test", 8080, RequestKind::Http)
            .unwrap();
        list.authorize("service.example", 8443, RequestKind::Http)
            .unwrap();
        assert!(
            list.authorize("other.example", 81, RequestKind::Http)
                .is_err()
        );
    }

    #[test]
    fn ip_literals_and_localhost_require_exact_host_and_port() {
        for patterns in [&["*"][..], &["*.localhost"], &["*.localhost:443"]] {
            let list = allow(patterns);
            for host in [
                "127.0.0.1",
                "8.8.8.8",
                "localhost",
                "app.localhost",
                "::1",
                "[::ffff:127.0.0.1]",
            ] {
                assert!(
                    list.authorize(host, 443, RequestKind::Connect).is_err(),
                    "{patterns:?}: {host}"
                );
            }
        }
        for host in ["127.0.0.1", "8.8.8.8", "localhost"] {
            if host == "localhost" {
                assert!(
                    allow(&[host])
                        .authorize(host, 443, RequestKind::Connect)
                        .is_err()
                );
            } else {
                assert!(Allowlist::new(&[host.into()]).is_err());
            }
            let list = allow(&[&format!("{host}:443")]);
            list.authorize(host, 443, RequestKind::Connect).unwrap();
        }
        let target = allow(&["127.0.0.1:11434"])
            .authorize("127.0.0.1", 11434, RequestKind::Http)
            .unwrap();
        target
            .validate_resolved(&[ip("127.0.0.1"), ip("::ffff:127.0.0.1")])
            .unwrap();
        assert_eq!(
            target.validate_resolved(&[ip("8.8.8.8")]),
            Err(AllowlistError::ResolutionMismatch)
        );
    }

    #[test]
    fn ipv6_patterns_require_brackets_and_port_and_use_rfc5952() {
        let list = allow(&[
            "[2001:0DB8:0000:0000:0000:0000:0000:0010]:08080",
            "[::1]:11434",
        ]);
        assert_eq!(
            list.normalized_patterns(),
            ["[2001:db8::10]:8080", "[::1]:11434"]
        );
        let target = list
            .authorize("[2001:db8::10]", 8080, RequestKind::Http)
            .unwrap();
        assert_eq!(target.host(), "2001:db8::10");
        target.validate_resolved(&[ip("2001:db8::10")]).unwrap();
        assert!(
            list.authorize("2001:db8::11", 8080, RequestKind::Http)
                .is_err()
        );
        assert!(
            list.authorize("2001:db8::10", 443, RequestKind::Connect)
                .is_err()
        );
        list.authorize("0:0:0:0:0:0:0:1", 11434, RequestKind::Http)
            .unwrap()
            .validate_resolved(&[ip("::1")])
            .unwrap();
    }

    #[test]
    fn mapped_and_well_known_nat64_destinations_use_embedded_ipv4() {
        let list = allow(&["10.1.2.3:443", "8.8.8.8:443"]);
        for host in ["::ffff:10.1.2.3", "[64:ff9b::a01:203]"] {
            let target = list.authorize(host, 443, RequestKind::Connect).unwrap();
            assert!(
                target.host().contains(':'),
                "connection address must stay IPv6"
            );
            target
                .validate_resolved(&[
                    ip("10.1.2.3"),
                    ip("::ffff:10.1.2.3"),
                    ip("64:ff9b::a01:203"),
                ])
                .unwrap();
            assert_eq!(
                target.validate_resolved(&[ip("10.1.2.4")]),
                Err(AllowlistError::ResolutionMismatch)
            );
        }
        list.authorize("64:ff9b::808:808", 443, RequestKind::Connect)
            .unwrap();
        assert!(Allowlist::new(&["[64:ff9b::808:808]:443".into()]).is_err());
        let dns_target = allow(&["*"])
            .authorize("public.example", 443, RequestKind::Connect)
            .unwrap();
        assert_eq!(
            dns_target.validate_resolved(&[ip("64:ff9b::a01:203")]),
            Err(AllowlistError::NonPublicAddress)
        );
        dns_target
            .validate_resolved(&[ip("64:ff9b::808:808"), ip("::ffff:8.8.8.8")])
            .unwrap();
    }

    #[test]
    fn configured_nat64_rejects_ipv6_rules_and_authorizes_embedded_ipv4_literals() {
        let policy = Nat64Prefixes::new(&["2001:4860:64::/96".into()]).unwrap();
        assert!(
            Allowlist::new_with_nat64(&["[2001:4860:64::a01:203]:443".into()], &policy).is_err()
        );
        let list = Allowlist::new_with_nat64(&["10.1.2.3:443".into()], &policy).unwrap();
        let target = list
            .authorize("2001:4860:64::a01:203", 443, RequestKind::Connect)
            .unwrap();
        assert_eq!(target.host(), "2001:4860:64::a01:203");
        target
            .validate_resolved(&[
                ip("2001:4860:64::a01:203"),
                ip("10.1.2.3"),
                ip("::ffff:10.1.2.3"),
            ])
            .unwrap();
        assert_eq!(
            target.validate_resolved(&[ip("2001:4860:64::a01:204")]),
            Err(AllowlistError::ResolutionMismatch)
        );
    }

    #[test]
    fn configured_nat64_checks_every_dns_address_as_ipv4_and_unknown_prefix_stays_ipv6() {
        let host = "2001:4860:64::a01:203";
        let unconfigured = allow(&["*"])
            .authorize("api.example", 443, RequestKind::Connect)
            .unwrap();
        unconfigured.validate_resolved(&[ip(host)]).unwrap();
        let policy = Nat64Prefixes::new(&["2001:4860:64::/96".into()]).unwrap();
        let wildcard = Allowlist::new_with_nat64(&["*".into()], &policy)
            .unwrap()
            .authorize("api.example", 443, RequestKind::Connect)
            .unwrap();
        assert_eq!(
            wildcard.validate_resolved(&[ip("8.8.8.8"), ip(host)]),
            Err(AllowlistError::NonPublicAddress)
        );
        wildcard
            .validate_resolved(&[ip("2001:4860:64::808:808")])
            .unwrap();
        Allowlist::new_with_nat64(&["api.example:443".into()], &policy)
            .unwrap()
            .authorize("api.example", 443, RequestKind::Connect)
            .unwrap()
            .validate_resolved(&[ip(host)])
            .unwrap();
    }

    #[test]
    fn local_use_nat64_is_non_public_even_with_a_more_specific_configured_prefix() {
        let local = "64:ff9b:1:abcd::808:808";
        let policy = Nat64Prefixes::new(&["64:ff9b:1:abcd::/96".into()]).unwrap();
        let broad = Allowlist::new_with_nat64(&["*".into()], &policy)
            .unwrap()
            .authorize("api.example", 443, RequestKind::Connect)
            .unwrap();
        assert_eq!(
            broad.validate_resolved(&[ip(local)]),
            Err(AllowlistError::NonPublicAddress)
        );
        Allowlist::new_with_nat64(&["8.8.8.8:443".into()], &policy)
            .unwrap()
            .authorize(local, 443, RequestKind::Connect)
            .unwrap()
            .validate_resolved(&[ip(local)])
            .unwrap();
        assert!(Allowlist::new_with_nat64(&[format!("[{local}]:443")], &policy).is_err());
        let unconfigured = allow(&["*"])
            .authorize("api.example", 443, RequestKind::Connect)
            .unwrap();
        assert_eq!(
            unconfigured.validate_resolved(&[ip(local)]),
            Err(AllowlistError::NonPublicAddress)
        );
        allow(&[&format!("[{local}]:443")])
            .authorize(local, 443, RequestKind::Connect)
            .unwrap()
            .validate_resolved(&[ip(local)])
            .unwrap();
    }

    #[test]
    fn every_resolved_address_is_checked_against_rebinding() {
        for pattern in ["*", "*.example", "api.example", "*.example:443"] {
            let target = allow(&[pattern])
                .authorize("api.example", 443, RequestKind::Connect)
                .unwrap();
            target
                .validate_resolved(&[ip("8.8.8.8"), ip("2606:4700:4700::1111")])
                .unwrap();
            assert_eq!(
                target.validate_resolved(&[]),
                Err(AllowlistError::EmptyResolution)
            );
            for private in [
                "127.0.0.1",
                "10.1.2.3",
                "172.16.0.1",
                "172.31.255.255",
                "192.168.1.1",
                "169.254.169.254",
                "100.64.1.1",
                "::1",
                "fc00::1",
                "fdff::1",
                "fe80::1",
                "::ffff:127.0.0.1",
                "::ffff:10.0.0.1",
                "64:ff9b::a00:1",
            ] {
                assert_eq!(
                    target.validate_resolved(&[ip("8.8.8.8"), ip(private)]),
                    Err(AllowlistError::NonPublicAddress),
                    "{pattern}: {private}"
                );
            }
        }
        let explicit = allow(&["api.example:443"])
            .authorize("api.example", 443, RequestKind::Connect)
            .unwrap();
        explicit
            .validate_resolved(&[ip("10.1.2.3"), ip("::1")])
            .unwrap();
    }

    #[test]
    fn adding_a_broad_rule_does_not_hide_an_exact_private_grant() {
        for patterns in [&["*", "local.example:443"][..], &["local.example:443", "*"]] {
            allow(patterns)
                .authorize("local.example", 443, RequestKind::Connect)
                .unwrap()
                .validate_resolved(&[ip("192.168.1.1")])
                .unwrap();
        }
    }

    #[test]
    fn special_addresses_cannot_pass_as_public_unicast() {
        let target = allow(&["*"])
            .authorize("api.example", 443, RequestKind::Connect)
            .unwrap();
        for address in [
            "0.0.0.0",
            "0.1.2.3",
            "100.127.255.255",
            "192.0.0.1",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.2",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.1.2.3",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::8.8.8.8",
            "100::1",
            "64:ff9b:1::1",
            "2001:2::1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "3fff::1",
            "5f00::1",
            "fec0::1",
            "ff0e::1",
        ] {
            assert_eq!(
                target.validate_resolved(&[ip(address)]),
                Err(AllowlistError::NonPublicAddress),
                "{address}"
            );
        }
        for address in [
            "8.8.8.8",
            "100.128.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "192.0.0.9",
            "192.0.0.10",
            "192.169.1.1",
            "198.20.0.1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2001:1::1",
            "2001:1::3",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2001:30::1",
        ] {
            target
                .validate_resolved(&[ip(address)])
                .unwrap_or_else(|error| panic!("{address}: {error}"));
        }
    }

    #[test]
    fn malformed_hosts_patterns_and_ports_are_rejected() {
        for host in [
            "",
            " example.com",
            "example.com ",
            "example.com..",
            ".example.com",
            "a..example.com",
            "a_b.example.com",
            "-a.example",
            "a-.example",
            "https://example.com",
            "user@example.com",
            "example.com:443",
            "example.com/path",
            "example.com?query",
            "example.com#fragment",
            "exämple.com",
            "example.com\n",
            "example.com\0",
            "127.1",
            "2130706433",
            "0177.0.0.1",
            "0x7f000001",
            "127.0.0.256",
            "[::1",
            "::1]",
            "fe80::1%en0",
            "[fe80::1%25en0]",
        ] {
            assert_eq!(
                allow(&["*"])
                    .authorize(host, 443, RequestKind::Connect)
                    .unwrap_err(),
                AllowlistError::InvalidHost,
                "{host:?}"
            );
        }
        for pattern in [
            "",
            "*example.com",
            "foo.*.example",
            "*.127.0.0.1",
            "http://example.com",
            "example.com:",
            "example.com:0",
            "example.com:65536",
            "example.com:000443",
            "example.com:+443",
            "example.com:-1",
            "example.com:4a3",
            "example.com: 443",
            "user@example.com:443",
            "*:443",
            "*:8443",
        ] {
            assert!(Allowlist::new(&[pattern.into()]).is_err(), "{pattern}");
        }
        for pattern in [
            "::1",
            "[::1]",
            "::1:443",
            "[::1]:0",
            "[::1]:65536",
            "[::1]:000443",
            "[::1]:+443",
            "[::1]:443/path",
            "[::1]]:443",
            "[fe80::1%en0]:80",
            "[fe80::1%25en0]:80",
            "[::ffff:127.0.0.1]:80",
            "[0:0:0:0:0:ffff:7f00:1]:80",
            "[2001:db8::/32]:443",
            "[2001:db8::*]:443",
        ] {
            assert_eq!(
                Allowlist::new(&[pattern.into()]).unwrap_err(),
                AllowlistError::InvalidPattern
            );
        }
        assert_eq!(
            allow(&["*"])
                .authorize("example.com", 0, RequestKind::Connect)
                .unwrap_err(),
            AllowlistError::InvalidPort
        );
        assert!(normalize_host(&format!("{}.example", "a".repeat(64))).is_err());
        let label = "a".repeat(63);
        assert!(normalize_host(&[label.as_str(); 5].join(".")).is_err());
    }
}
