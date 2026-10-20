//! Pure Phase-0 `tool.result` classification from the approved effective
//! manifest. Flags remain the store's monotonic responsibility. The current
//! session's U flag is deliberately not an input: trusted output is not made
//! untrusted merely because its recipient previously received untrusted data.

use crate::{
    installer::{
        manifest::{OutputTrust, Scope, Sensitivity as ToolSensitivity},
        overrides::EffectiveManifest,
    },
    proxy::{
        allowlist::{Allowlist, AllowlistError},
        nat64::Nat64Prefixes,
    },
    store::{Sensitivity, Trust},
};

#[derive(Clone, Copy, Debug)]
pub struct Workspace {
    pub trust: Trust,
    pub untrusted: bool,
}

/// The caller attaches its own verified exposed tool identity as provenance
/// source. Neither the extension nor its MCP annotations choose these fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResultClass {
    pub trust: Trust,
    pub sensitivity: Sensitivity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProvenanceError {
    #[error("the tool is absent from the approved catalog")]
    UnknownTool,
    #[error("global extension provenance requires its Phase-1 watermark")]
    GlobalUnsupported,
    #[error("invalid effective network authority")]
    InvalidNetwork(#[from] AllowlistError),
}

/// `tool_name` is the exact raw name in the approved MCP catalog. Revalidate
/// effective network authority against the pinned NAT64 configuration, and
/// apply network/workspace trust floors after human classification overrides.
pub fn tool_result(
    effective: &EffectiveManifest,
    tool_name: &str,
    workspace: Workspace,
    trusted_domains: &[String],
    nat64: &Nat64Prefixes,
) -> Result<ResultClass, ProvenanceError> {
    let manifest = effective.manifest();
    if manifest.scope == Scope::Global {
        return Err(ProvenanceError::GlobalUnsupported);
    }
    let class = effective
        .tool_class(tool_name)
        .ok_or(ProvenanceError::UnknownTool)?;
    let network = Allowlist::new_with_nat64(&manifest.permissions.net.allow, nat64)?;
    let untrusted_output = match class.output_trust {
        OutputTrust::Untrusted => true,
        OutputTrust::Workspace => workspace.trust == Trust::Untrusted || workspace.untrusted,
        OutputTrust::Trusted => false,
    };
    Ok(ResultClass {
        trust: if untrusted_output || !network.all_hosts_trusted(trusted_domains) {
            Trust::Untrusted
        } else {
            Trust::Trusted
        },
        sensitivity: match class.sensitivity {
            ToolSensitivity::Public => Sensitivity::Public,
            ToolSensitivity::Private => Sensitivity::Private,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        gateway::PinnedCatalog,
        installer::{
            manifest::Manifest,
            overrides::{Overrides, resolve},
        },
    };
    use serde_json::{Value, json};

    fn manifest(network: &[&str], output_trust: &str, sensitivity: &str) -> Manifest {
        Manifest::parse(&json!({
            "schema":1,"id":"reviewed","version":"1.0.0","description":"Reviewed result",
            "scope":"session","runtime":{"kind":"binary","entry":"server"},
            "permissions":{"net":{"allow":network}},
            "tools":{"default":{"effect":"read","output_trust":output_trust,"sensitivity":sensitivity}}
        }).to_string()).unwrap()
    }

    fn effective(original: &Manifest, patch: Value) -> EffectiveManifest {
        let catalog = PinnedCatalog::new(["read", "other"].into_iter().map(|name| {
            json!({"name":name,"description":"Approved tool","inputSchema":{"type":"object"}})
        }).collect()).unwrap();
        resolve(
            original,
            &catalog,
            &Overrides::from_value(patch).unwrap(),
            "user",
            &Nat64Prefixes::default(),
        )
        .unwrap()
    }

    fn workspace() -> Workspace {
        Workspace {
            trust: Trust::Trusted,
            untrusted: false,
        }
    }

    fn result(
        effective: &EffectiveManifest,
        name: &str,
        workspace: Workspace,
        trusted: &[String],
    ) -> ResultClass {
        tool_result(
            effective,
            name,
            workspace,
            trusted,
            &Nat64Prefixes::default(),
        )
        .unwrap()
    }

    #[test]
    fn workspace_outputs_follow_initial_trust_and_shared_workspace_contamination() {
        let effective = effective(&manifest(&[], "workspace", "private"), json!({}));
        assert_eq!(
            result(&effective, "read", workspace(), &[]),
            ResultClass {
                trust: Trust::Trusted,
                sensitivity: Sensitivity::Private
            }
        );
        for workspace in [
            Workspace {
                trust: Trust::Untrusted,
                untrusted: false,
            },
            Workspace {
                trust: Trust::Trusted,
                untrusted: true,
            },
            Workspace {
                trust: Trust::Untrusted,
                untrusted: true,
            },
        ] {
            assert_eq!(
                result(&effective, "read", workspace, &[]),
                ResultClass {
                    trust: Trust::Untrusted,
                    sensitivity: Sensitivity::Private
                }
            );
        }
    }

    #[test]
    fn explicit_trusted_output_does_not_inherit_workspace_or_recipient_history() {
        let contaminated = Workspace {
            trust: Trust::Untrusted,
            untrusted: true,
        };
        let trusted = effective(&manifest(&[], "trusted", "public"), json!({}));
        assert_eq!(
            result(&trusted, "read", contaminated, &[]),
            ResultClass {
                trust: Trust::Trusted,
                sensitivity: Sensitivity::Public
            }
        );
        let untrusted = effective(&manifest(&[], "untrusted", "public"), json!({}));
        assert_eq!(
            result(&untrusted, "read", workspace(), &[]).trust,
            Trust::Untrusted
        );
    }

    #[test]
    fn untrusted_network_floors_every_tool_until_the_approved_authority_is_removed() {
        let original = manifest(
            &["trusted.example", "outside.example:8443"],
            "trusted",
            "public",
        );
        let trusted = ["TRUSTED.EXAMPLE".into()];
        let base = effective(&original, json!({}));
        let classification_override = effective(
            &original,
            json!({"tools":{"read":{"output_trust":"trusted","sensitivity":"private"}}}),
        );
        for name in ["read", "other"] {
            assert_eq!(
                result(&base, name, workspace(), &trusted).trust,
                Trust::Untrusted
            );
            assert_eq!(
                result(&classification_override, name, workspace(), &trusted).trust,
                Trust::Untrusted
            );
        }
        assert_eq!(
            result(&classification_override, "read", workspace(), &trusted).sensitivity,
            Sensitivity::Private
        );
        let narrowed = effective(
            &original,
            json!({"permissions":{"net":{"allow":["trusted.example"]}}}),
        );
        let removed = effective(&original, json!({"permissions":{"net":{"allow":[]}}}));
        for effective in [&narrowed, &removed] {
            assert_eq!(
                result(effective, "read", workspace(), &trusted).trust,
                Trust::Trusted
            );
        }
    }

    #[test]
    fn human_output_override_applies_when_no_network_floor_remains() {
        let original = manifest(&["trusted.example:8443"], "untrusted", "private");
        let trusted = ["trusted.example".into()];
        let approved = effective(
            &original,
            json!({"tools":{"read":{"output_trust":"trusted","sensitivity":"public"}}}),
        );
        assert_eq!(
            result(&approved, "read", workspace(), &trusted),
            ResultClass {
                trust: Trust::Trusted,
                sensitivity: Sensitivity::Public
            }
        );
        assert_eq!(
            result(&approved, "other", workspace(), &trusted),
            ResultClass {
                trust: Trust::Untrusted,
                sensitivity: Sensitivity::Private
            }
        );
    }

    #[test]
    fn wildcard_network_is_not_covered_by_finitely_many_trusted_children_or_apex() {
        let effective = effective(
            &manifest(&["*.example.com:8443"], "trusted", "public"),
            json!({}),
        );
        let trusted = [
            "example.com".into(),
            "a.example.com".into(),
            "b.example.com".into(),
            "*.example.com".into(),
        ];
        assert_eq!(
            result(&effective, "read", workspace(), &trusted).trust,
            Trust::Untrusted
        );
    }

    #[test]
    fn unknown_tools_and_global_instances_cannot_claim_phase_zero_result_classification() {
        let original = manifest(&[], "trusted", "public");
        let approved = effective(&original, json!({}));
        assert_eq!(
            tool_result(
                &approved,
                "reviewed__read",
                workspace(),
                &[],
                &Nat64Prefixes::default()
            ),
            Err(ProvenanceError::UnknownTool)
        );
        let mut global = original;
        global.scope = Scope::Global;
        assert_eq!(
            tool_result(
                &effective(&global, json!({})),
                "read",
                workspace(),
                &[],
                &Nat64Prefixes::default()
            ),
            Err(ProvenanceError::GlobalUnsupported)
        );
    }

    #[test]
    fn changed_nat64_configuration_revalidates_effective_network_authority() {
        let approved = effective(
            &manifest(&["[2001:4860:64::a00:1]:443"], "trusted", "public"),
            json!({}),
        );
        let nat64 = Nat64Prefixes::new(&["2001:4860:64::/96".into()]).unwrap();
        assert_eq!(
            tool_result(
                &approved,
                "read",
                workspace(),
                &["2001:4860:64::a00:1".into()],
                &nat64
            ),
            Err(ProvenanceError::InvalidNetwork(
                AllowlistError::InvalidPattern
            ))
        );
    }
}
