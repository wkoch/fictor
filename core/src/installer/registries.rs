//! ADR-040: exact installer authorities, using the egress parser without widening
//! an omitted port into an explicit grant for HTTP or non-public addresses.
use crate::proxy::{allowlist::Allowlist, nat64::Nat64Prefixes};
use std::collections::BTreeSet;

#[derive(Debug, thiserror::Error)]
#[error("installer registry policy invalid")]
pub(crate) struct RegistryError;

pub(crate) fn normalize(
    authorities: &[String],
    nat64: &Nat64Prefixes,
) -> Result<Vec<String>, RegistryError> {
    let mut normalized = Vec::new();
    let mut seen = BTreeSet::new();
    for authority in authorities {
        if !authority.is_ascii() || authority.contains('*') {
            return Err(RegistryError);
        }
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (address, port) = bracketed.split_once("]:").ok_or(RegistryError)?;
            (format!("[{address}]"), Some(port))
        } else {
            let (host, port) = match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority.as_str(), None),
            };
            (
                host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase(),
                port,
            )
        };
        if host == "models.fictor.internal"
            || (port.is_none() && (host == "localhost" || host.ends_with(".localhost")))
        {
            return Err(RegistryError);
        }
        let pattern = if let Some(port) = port {
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(RegistryError);
            }
            let port = port
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or(RegistryError)?;
            format!("{host}:{port}")
        } else {
            host
        };
        let allowlist = Allowlist::new_with_nat64(&[pattern], nat64).map_err(|_| RegistryError)?;
        for pattern in allowlist.normalized_patterns() {
            if seen.insert(pattern.clone()) {
                normalized.push(pattern);
            }
        }
    }
    Ok(normalized)
}
