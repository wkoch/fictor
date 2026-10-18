//! Opaque provider request preparation (ADR-022).
use crate::config::Provider;
use hyper::{
    Request, Uri,
    header::{HeaderMap, HeaderName, HeaderValue},
};

#[derive(Debug, thiserror::Error)]
pub enum ModelRequestError {
    #[error("configuração de provider inválida")]
    InvalidProvider,
    #[error("caminho do provider inválido")]
    InvalidPath,
    #[error("segredo de provider ausente ou inesperado")]
    MissingSecret,
    #[error("método HTTP não permitido para provider")]
    InvalidMethod,
}

/// Prepare a core-owned request for the configured provider, without interpreting
/// its API or payload. `secret` comes exclusively from the core's SecretStore.
pub fn prepare<B>(
    mut request: Request<B>,
    provider: &Provider,
    path: &str,
    secret: Option<&str>,
) -> Result<Request<B>, ModelRequestError> {
    // RFC 9110 §9.3.8 forbids sensitive fields in TRACE; reflecting a core
    // credential into the response would break I4 even on a trusted provider.
    if request.method() == hyper::Method::TRACE {
        return Err(ModelRequestError::InvalidMethod);
    }
    let base: Uri = provider
        .base_url
        .parse()
        .map_err(|_| ModelRequestError::InvalidProvider)?;
    let scheme = base
        .scheme_str()
        .filter(|scheme| matches!(*scheme, "http" | "https"))
        .ok_or(ModelRequestError::InvalidProvider)?;
    let authority = base
        .authority()
        .filter(|authority| !authority.as_str().contains('@') && !authority.host().is_empty())
        .ok_or(ModelRequestError::InvalidProvider)?;
    let raw = authority.as_str();
    if scheme == "http"
        && !authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| {
                ip == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                    || ip == std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            })
    {
        // ADR-022 admits only these two exact literals. Never downgrade TLS.
        return Err(ModelRequestError::InvalidProvider);
    }
    let suffix = if raw.starts_with('[') {
        let suffix = raw
            .rsplit_once(']')
            .ok_or(ModelRequestError::InvalidProvider)?
            .1;
        if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .ok_or(ModelRequestError::InvalidProvider)?,
            )
        }
    } else {
        raw.split_once(':').map(|(_, port)| port)
    };
    if let Some(port) = suffix
        && (port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().ok().filter(|port| *port != 0).is_none())
    {
        return Err(ModelRequestError::InvalidProvider);
    }
    if base.query().is_some()
        || path.starts_with("//")
        || !path.starts_with('/')
        || path.contains('#')
    {
        return Err(ModelRequestError::InvalidPath);
    }
    let path = format!("{}{path}", base.path().trim_end_matches('/'));
    let destination = Uri::builder()
        .scheme(scheme)
        .authority(authority.clone())
        .path_and_query(path)
        .build()
        .map_err(|_| ModelRequestError::InvalidPath)?;
    let auth_header = provider
        .auth_header
        .as_deref()
        .map(|header| {
            HeaderName::from_bytes(header.as_bytes())
                .map_err(|_| ModelRequestError::InvalidProvider)
        })
        .transpose()?;
    strip_hop(request.headers_mut());
    for header in [
        "authorization",
        "x-api-key",
        "api-key",
        "proxy-authorization",
    ] {
        request.headers_mut().remove(header);
    }
    if let Some(header) = &auth_header {
        request.headers_mut().remove(header);
    }
    for (name, value) in &provider.extra_headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| ModelRequestError::InvalidProvider)?;
        if hop(&name) || name == "host" {
            return Err(ModelRequestError::InvalidProvider);
        }
        let value = HeaderValue::from_str(value).map_err(|_| ModelRequestError::InvalidProvider)?;
        request.headers_mut().insert(name, value);
    }
    match (provider.secret.as_ref(), secret) {
        (Some(_), Some(value)) => {
            let name = auth_header.ok_or(ModelRequestError::InvalidProvider)?;
            if hop(&name) || name == "host" {
                return Err(ModelRequestError::InvalidProvider);
            }
            let mut value = HeaderValue::from_str(&format!(
                "{}{value}",
                provider.auth_prefix.as_deref().unwrap_or("")
            ))
            .map_err(|_| ModelRequestError::InvalidProvider)?;
            value.set_sensitive(true);
            request.headers_mut().insert(name, value);
        }
        (None, None) => {}
        _ => return Err(ModelRequestError::MissingSecret),
    }
    request.headers_mut().insert(
        "host",
        HeaderValue::from_str(authority.as_str())
            .map_err(|_| ModelRequestError::InvalidProvider)?,
    );
    *request.uri_mut() = destination;
    Ok(request)
}

/// Validate the complete provider settings at boot without accessing credentials.
pub fn validate_provider(provider: &Provider) -> Result<(), ModelRequestError> {
    let placeholder = provider.secret.as_ref().map(|_| "configuration-validation");
    prepare(Request::new(()), provider, "/", placeholder).map(|_| ())
}

fn hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}
pub(super) fn strip_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    let names: Vec<_> = headers.keys().filter(|name| hop(name)).cloned().collect();
    for name in names {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn provider() -> Provider {
        Provider {
            base_url: "https://api.example/prefix".into(),
            auth_header: Some("x-custom-token".into()),
            auth_prefix: Some("Bearer ".into()),
            secret: Some("provider_key".into()),
            extra_headers: Default::default(),
        }
    }
    #[test]
    fn strips_credentials_and_hop_headers_without_inspecting_body() {
        let body = std::sync::Arc::new(17);
        let request = Request::builder()
            .uri("http://models.fictor.internal/p/test/v1/messages")
            .header("authorization", "attacker")
            .header("x-api-key", "attacker")
            .header("api-key", "attacker")
            .header("x-custom-token", "attacker")
            .header("proxy-authorization", "attacker")
            .header("connection", "x-nominated, keep-alive")
            .header("x-nominated", "remove")
            .header("keep-alive", "remove")
            .body(body.clone())
            .unwrap();
        let result = prepare(
            request,
            &provider(),
            "/v1/messages?stream=true",
            Some("fake-core-key"),
        )
        .unwrap();
        assert!(std::sync::Arc::ptr_eq(result.body(), &body));
        assert_eq!(
            result.uri(),
            "https://api.example/prefix/v1/messages?stream=true"
        );
        assert_eq!(result.headers()["host"], "api.example");
        assert_eq!(result.headers()["x-custom-token"], "Bearer fake-core-key");
        assert!(result.headers()["x-custom-token"].is_sensitive());
        for name in [
            "authorization",
            "x-api-key",
            "api-key",
            "proxy-authorization",
            "connection",
            "x-nominated",
            "keep-alive",
        ] {
            assert!(!result.headers().contains_key(name));
        }
    }
    #[test]
    fn malformed_configuration_never_echoes_secret_or_changes_destination() {
        for base in [
            "file:///tmp",
            "http://user@evil.test",
            "https://api.example?query",
            "https://api.example:bad",
            "https://api.example:0",
            "https://api.example:65536",
            "https://api.example:",
            "http://api.example",
            "http://192.168.1.2:11434",
        ] {
            let mut provider = provider();
            provider.base_url = base.into();
            let error = prepare(
                Request::new(()),
                &provider,
                "/v1",
                Some("fake-sensitive-key"),
            )
            .unwrap_err();
            assert!(!format!("{error:?}: {error}").contains("fake-sensitive-key"));
        }
        for path in ["//evil.test/v1", "https://evil.test/v1", "/v1#fragment"] {
            assert!(prepare(Request::new(()), &provider(), path, Some("fake-core-key")).is_err());
        }
        assert!(prepare(Request::new(()), &provider(), "/v1", None).is_err());
    }

    #[test]
    fn trace_cannot_reflect_the_core_credential() {
        let request = Request::builder()
            .method(hyper::Method::TRACE)
            .body(())
            .unwrap();
        assert!(matches!(
            prepare(request, &provider(), "/v1", Some("fake-core-key")),
            Err(ModelRequestError::InvalidMethod)
        ));
    }
    #[test]
    fn local_provider_can_have_no_secret_and_keeps_provider_headers() {
        let provider = Provider {
            base_url: "http://127.0.0.1:11434".into(),
            auth_header: None,
            auth_prefix: None,
            secret: None,
            extra_headers: std::collections::BTreeMap::from([(
                "x-provider-version".into(),
                "1".into(),
            )]),
        };
        let result = prepare(
            Request::builder()
                .header("authorization", "attacker")
                .body(())
                .unwrap(),
            &provider,
            "/v1/messages",
            None,
        )
        .unwrap();
        assert_eq!(result.uri(), "http://127.0.0.1:11434/v1/messages");
        assert_eq!(result.headers()["x-provider-version"], "1");
        assert!(!result.headers().contains_key("authorization"));
    }
}
