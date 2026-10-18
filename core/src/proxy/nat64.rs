//! Explicit NAT64 policy (ADR-023). DNS discovery only produces doctor suggestions.
//! Extraction follows RFC 6052 §2.2; the reserved u octet and suffix are ignored.
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

const LENGTHS: [u8; 6] = [32, 40, 48, 56, 64, 96];
const WELL_KNOWN: Nat64Prefix = Nat64Prefix {
    network: Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0),
    length: 96,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Nat64Error {
    #[error("malformed IPv6 NAT64 prefix")]
    Malformed,
    #[error("NAT64 prefix length must be 32, 40, 48, 56, 64 or 96")]
    Length,
    #[error("NAT64 prefix has nonzero host bits")]
    HostBits,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nat64Prefix {
    network: Ipv6Addr,
    length: u8,
}
impl Nat64Prefix {
    pub fn parse(value: &str) -> Result<Self, Nat64Error> {
        let (address, length) = value.split_once('/').ok_or(Nat64Error::Malformed)?;
        let network = address
            .parse::<Ipv6Addr>()
            .map_err(|_| Nat64Error::Malformed)?;
        if length.is_empty() || !length.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Nat64Error::Malformed);
        }
        let length = length.parse::<u8>().map_err(|_| Nat64Error::Length)?;
        if !LENGTHS.contains(&length) {
            return Err(Nat64Error::Length);
        }
        let prefix = Self { network, length };
        if u128::from(network) & mask(length) != u128::from(network) {
            return Err(Nat64Error::HostBits);
        }
        Ok(prefix)
    }
    pub fn contains(self, address: Ipv6Addr) -> bool {
        u128::from(address) & mask(self.length) == u128::from(self.network)
    }
    pub fn extract(self, address: Ipv6Addr) -> Option<Ipv4Addr> {
        if !self.contains(address) {
            return None;
        }
        let bytes = address.octets();
        let start = usize::from(self.length / 8);
        let mut ipv4 = [0; 4];
        for (index, octet) in ipv4.iter_mut().enumerate() {
            let position = start + index;
            *octet = bytes[if self.length != 96 && position >= 8 {
                position + 1
            } else {
                position
            }];
        }
        Some(Ipv4Addr::from(ipv4))
    }
}
impl fmt::Display for Nat64Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.length)
    }
}
fn mask(length: u8) -> u128 {
    u128::MAX << (128 - length)
}

/// Configured prefixes are immutable for an active proxy. WK96 always applies.
#[derive(Debug, Clone, Default)]
pub struct Nat64Prefixes {
    configured: Vec<Nat64Prefix>,
}
impl Nat64Prefixes {
    pub fn new(values: &[String]) -> Result<Self, Nat64Error> {
        let mut configured = values
            .iter()
            .map(|value| Nat64Prefix::parse(value))
            .collect::<Result<Vec<_>, _>>()?;
        configured.sort();
        configured.dedup();
        Ok(Self { configured })
    }
    fn prefix_for(&self, address: Ipv6Addr) -> Option<Nat64Prefix> {
        self.configured
            .iter()
            .copied()
            .chain(std::iter::once(WELL_KNOWN))
            .filter(|prefix| prefix.contains(address))
            .max_by_key(|prefix| prefix.length)
    }
    pub fn is_translation(&self, address: Ipv6Addr) -> bool {
        self.prefix_for(address).is_some()
    }
    pub fn canonical_ip(&self, address: IpAddr) -> IpAddr {
        match address {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .or_else(|| {
                    self.prefix_for(address)
                        .and_then(|prefix| prefix.extract(address))
                })
                .map_or(IpAddr::V6(address), IpAddr::V4),
            address => address,
        }
    }
    /// RFC 7050 observations never change this policy or the config file.
    pub fn suggestions(&self, addresses: &[Ipv6Addr]) -> Vec<String> {
        let mut prefixes = std::collections::BTreeSet::new();
        for address in addresses {
            // A known translation layout already explains this answer. Prefix
            // bytes can coincidentally contain RFC7050's marker too; do not
            // suggest a broader fake prefix from those unrelated bytes.
            if self
                .prefix_for(*address)
                .and_then(|prefix| prefix.extract(*address))
                .is_some_and(|ip| matches!(ip.octets(), [192, 0, 0, 170] | [192, 0, 0, 171]))
            {
                continue;
            }
            for length in LENGTHS {
                let prefix = Nat64Prefix {
                    network: Ipv6Addr::from(u128::from(*address) & mask(length)),
                    length,
                };
                if prefix
                    .extract(*address)
                    .is_some_and(|ip| matches!(ip.octets(), [192, 0, 0, 170] | [192, 0, 0, 171]))
                    && prefix != WELL_KNOWN
                    && !self.configured.contains(&prefix)
                {
                    prefixes.insert(prefix.to_string());
                }
            }
        }
        prefixes.into_iter().collect()
    }
}
/// Even a configured subprefix must not make local-use NAT64 publicly reachable.
pub fn is_local_use(address: Ipv6Addr) -> bool {
    address.segments()[..3] == [0x64, 0xff9b, 1]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extracts_all_six_rfc6052_layouts_and_ignores_u_and_suffix() {
        for (prefix, address) in [
            ("2001:db8::/32", "2001:db8:c000:221::"),
            ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
            ("2001:db8:122::/48", "2001:db8:122:c000:2:2100::"),
            ("2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"),
            ("2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100::"),
            ("2001:db8:122:344::/96", "2001:db8:122:344::c000:221"),
        ] {
            let prefix = Nat64Prefix::parse(prefix).unwrap();
            let address = address.parse::<Ipv6Addr>().unwrap();
            assert_eq!(prefix.extract(address), Some(Ipv4Addr::new(192, 0, 2, 33)));
            if prefix.length < 96 {
                let mut bytes = address.octets();
                bytes[8] = 0x7f;
                bytes[15] = 0xff;
                assert_eq!(
                    prefix.extract(Ipv6Addr::from(bytes)),
                    Some(Ipv4Addr::new(192, 0, 2, 33))
                );
            }
        }
    }
    #[test]
    fn rejects_malformed_lengths_host_bits_and_zones() {
        for value in [
            "",
            "2001:db8::",
            "2001:db8::/24",
            "2001:db8::/128",
            "2001:db8::1/96",
            "2001:db8:1::/32",
            "2001:db8::/96/96",
            "127.0.0.1/32",
            "fe80::%lo/64",
            "2001:db8::/+96",
        ] {
            assert!(Nat64Prefix::parse(value).is_err(), "{value}");
        }
    }
    #[test]
    fn longest_configured_prefix_wins_and_well_known_remains_implicit() {
        let address = "2001:db8:1::808:808".parse().unwrap();
        for values in [
            ["2001:db8::/32", "2001:db8:1::/96"],
            ["2001:db8:1::/96", "2001:db8::/32"],
        ] {
            let policy = Nat64Prefixes::new(&values.map(Into::into)).unwrap();
            assert_eq!(
                policy.canonical_ip(IpAddr::V6(address)),
                "8.8.8.8".parse::<IpAddr>().unwrap()
            );
        }
        assert_eq!(
            Nat64Prefixes::default().canonical_ip("64:ff9b::a00:1".parse().unwrap()),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert!(is_local_use("64:ff9b:1:abcd::1".parse().unwrap()));
    }
    #[test]
    fn discovery_recognizes_all_rfc7050_prefix_lengths_without_network_io() {
        for (address, prefix) in [
            ("2001:4860:c000:aa::", "2001:4860::/32"),
            ("2001:4860:1c0:0:aa::", "2001:4860:100::/40"),
            ("2001:4860:122:c000:0:aa00::", "2001:4860:122::/48"),
            ("2001:4860:122:3c0:0:aa::", "2001:4860:122:300::/56"),
            ("2001:4860:122:344:c0:0:aa00:0", "2001:4860:122:344::/64"),
            ("2001:4860:122:344::c000:aa", "2001:4860:122:344::/96"),
        ] {
            assert_eq!(
                Nat64Prefixes::default().suggestions(&[address.parse().unwrap()]),
                vec![prefix],
                "{address}"
            );
        }
    }

    #[test]
    fn discovery_only_suggests_unknown_prefixes_and_never_mutates_policy() {
        let policy =
            Nat64Prefixes::new(&["2001:db8:1::/96".into(), "2001:db8:c000:aa::/96".into()])
                .unwrap();
        let observed = [
            "64:ff9b::c000:aa",
            "2001:db8:1::c000:aa",
            "2001:db8:c000:aa::c000:ab",
            "2001:db8:2::c000:ab",
            "2001:db8:2::c000:aa",
        ]
        .map(|address| address.parse().unwrap());
        assert_eq!(policy.suggestions(&observed), vec!["2001:db8:2::/96"]);
        assert!(!policy.is_translation(observed[3]));
    }
}
