use fictor::{
    gateway::PinnedCatalog,
    installer::{
        manifest::{Effect, Manifest, OutputTrust, Sensitivity},
        overrides::{Overrides, OverridesError, resolve},
    },
    proxy::nat64::Nat64Prefixes,
};
use serde_json::{Value, json};

fn manifest(permissions: Value, tools: Value) -> Manifest {
    Manifest::parse(
        &json!({
            "schema":1,"id":"reviewed","version":"1.0.0","description":"Reviewed",
            "scope":"session","runtime":{"kind":"binary","entry":"server"},
            "permissions":permissions,"tools":tools
        })
        .to_string(),
    )
    .unwrap()
}
fn catalog() -> PinnedCatalog {
    PinnedCatalog::new(
        ["named", "other", "default", "hook_before"]
            .into_iter()
            .map(|name| json!({"name":name,"description":"Original pin","inputSchema":{}}))
            .collect(),
    )
    .unwrap()
}
fn patch(value: Value) -> Overrides {
    Overrides::from_value(value).unwrap()
}
fn effective(original: &Manifest, value: Value) -> fictor::installer::overrides::EffectiveManifest {
    resolve(
        original,
        &catalog(),
        &patch(value),
        "user",
        &Nat64Prefixes::default(),
    )
    .unwrap()
}

#[test]
fn sparse_precedence_preserves_false_and_never_inherits_manifest_default_into_a_nominal() {
    let original = manifest(
        json!({}),
        json!({
            "default":{"effect":"write_local","model_visible":false},
            "named":{"effect":"read"}
        }),
    );
    let unchanged = effective(&original, json!({}));
    assert!(unchanged.tool_class("named").unwrap().model_visible);
    assert_eq!(
        unchanged.tool_class("named").unwrap().sensitivity,
        Sensitivity::Private
    );
    assert!(!unchanged.tool_class("other").unwrap().model_visible);
    let approved = effective(
        &original,
        json!({"tools":{
            "default":{"model_visible":false,"ui_callable":true,"timeout_ms":1000},
            "named":{"sensitivity":"public","ui_callable":false},
            "hook_before":{"model_visible":true}
        }}),
    );
    let named = approved.tool_class("named").unwrap();
    assert_eq!(named.effect, Effect::Read);
    assert_eq!(named.sensitivity, Sensitivity::Public);
    assert_eq!(named.output_trust, OutputTrust::Untrusted);
    assert!(!named.model_visible && !named.ui_callable);
    assert_eq!(named.timeout_ms, 1000);
    assert_eq!(
        approved.tool_class("other").unwrap().effect,
        Effect::WriteLocal
    );
    assert_eq!(
        approved.tool_class("default").unwrap().effect,
        Effect::WriteLocal
    );
    assert!(!approved.tool_class("hook_before").unwrap().model_visible);
    assert_eq!(approved.catalog().hash(), catalog().hash());
    assert_eq!(approved.catalog().tools(), catalog().tools());
}

#[test]
fn patch_roundtrip_is_exact_and_structural_objects_do_not_inject_defaults() {
    let original = manifest(json!({"env":{"FEATURE":"yes"},"spawn":true}), json!({}));
    for value in [
        json!({}),
        json!({"permissions":{"fs":{},"net":{}},"tools":{"named":{},"default":{}}}),
    ] {
        let patch = patch(value.clone());
        assert!(patch.is_noop());
        let serialized = serde_json::to_string(&patch).unwrap();
        let reopened: Overrides = serde_json::from_str(&serialized).unwrap();
        assert_eq!(reopened.as_value(), &value);
        let resolved = resolve(
            &original,
            &catalog(),
            &reopened,
            "auto:dev-profile",
            &Nat64Prefixes::default(),
        )
        .unwrap();
        assert!(resolved.manifest().permissions.spawn);
        assert_eq!(resolved.manifest().permissions.env["FEATURE"], "yes");
    }
    assert_eq!(
        serde_json::to_value(Overrides::default()).unwrap(),
        json!({"permissions":{},"tools":{}})
    );
    let empty_env = patch(json!({"permissions":{"env":{}}}));
    assert!(!empty_env.is_noop());
    assert!(matches!(
        resolve(
            &original,
            &catalog(),
            &empty_env,
            "auto:dev-profile",
            &Nat64Prefixes::default()
        ),
        Err(OverridesError::NotHuman)
    ));
    let resolved = resolve(
        &original,
        &catalog(),
        &empty_env,
        "user",
        &Nat64Prefixes::default(),
    )
    .unwrap();
    assert!(resolved.manifest().permissions.env.is_empty());
    assert!(resolved.manifest().permissions.spawn);
}

#[test]
fn malformed_or_duplicate_overrides_never_become_an_empty_or_partial_patch() {
    for text in [
        "null",
        r#"{"permissions":null}"#,
        r#"{"permissions":{"fs":null}}"#,
        r#"{"permissions":{"env":{"FEATURE":null}}}"#,
        r#"{"tools":{"named":null}}"#,
        r#"{"permissions":{"fs":{"read":["${tmp}","${tmp}"]}}}"#,
        r#"{"tools":{"named":{"model_visible":"false"}}}"#,
        r#"{"tools":{"named":{"timeout_ms":1000.0}}}"#,
        r#"{"permissions":{"spawn":false,"spawn":true}}"#,
        r#"{"permissions":{"env":{"KEY":"first","KEY":"second"}}}"#,
        r#"{"tools":{"named":{},"named":{"effect":"read"}}}"#,
        r#"{"tools":{"named":{"effect":"read","effect":"external"}}}"#,
        r#"{"permissions":{"kernel":[]}}"#,
        r#"{"tools":{"named":{"extra":true}}}"#,
        r#"{"permissions":{"env":{"NODE_OPTIONS":"--eval"}}}"#,
    ] {
        assert!(Overrides::parse(text).is_err(), "{text}");
        assert!(serde_json::from_str::<Overrides>(text).is_err(), "{text}");
    }
    let original = manifest(json!({}), json!({}));
    for value in [
        json!({"tools":{"absent":{}}}),
        json!({"tools":{"reviewed__named":{}}}),
    ] {
        assert!(
            resolve(
                &original,
                &catalog(),
                &patch(value),
                "user",
                &Nat64Prefixes::default()
            )
            .is_err()
        );
    }
}

#[test]
fn permissions_replace_lists_and_maps_and_allow_only_exact_removal_or_write_to_read() {
    let original = manifest(
        json!({
            "fs":{"read":["${ext_root}","${tmp}"],"write":["${ext_data}","${workspace}"]},
            "net":{"allow":["example.test","[2001:4860:4860:0:0:0:0:8888]:443"]},
            "models":["first","second"],"spawn":true,
            "secrets":[{"name":"token","env":"API_TOKEN"}],
            "env":{"KEEP":"same","DROP":"remove"}
        }),
        json!({"default":{"effect":"read","output_trust":"trusted"}}),
    );
    let value = json!({"permissions":{
        "fs":{"read":["${workspace}"],"write":[]},"net":{"allow":[]},"models":[],
        "spawn":false,"secrets":[],"env":{"KEEP":"same"}
    }});
    let resolved = effective(&original, value);
    let permissions = &resolved.manifest().permissions;
    assert_eq!(permissions.fs.read, ["${workspace}"]);
    assert!(permissions.fs.write.is_empty() && permissions.net.allow.is_empty());
    assert!(permissions.models.is_empty() && permissions.secrets.is_empty() && !permissions.spawn);
    assert_eq!(
        serde_json::to_value(&permissions.env).unwrap(),
        json!({"KEEP":"same"})
    );
    assert_eq!(resolved.tool_class("named").unwrap().effect, Effect::Read);
    let ipv6 = effective(
        &original,
        json!({"permissions":{"net":{"allow":["[2001:4860:4860::8888]:443"]}}}),
    );
    assert_eq!(
        ipv6.manifest().permissions.net.allow,
        ["[2001:4860:4860::8888]:443"]
    );
    assert_eq!(ipv6.tool_class("named").unwrap().effect, Effect::External);
    assert!(original.permissions.spawn && original.permissions.env.contains_key("DROP"));
}

#[test]
fn capability_expansion_and_invalid_secret_combinations_fail_before_use() {
    let original = manifest(
        json!({
            "fs":{"read":["${workspace}"],"write":["${ext_data}"]},
            "net":{"allow":["example.test"]},"models":["first"],
            "secrets":[{"name":"token","env":"API_TOKEN"}],"env":{"KEEP":"same"}
        }),
        json!({}),
    );
    for permissions in [
        json!({"fs":{"write":["${workspace}"]}}),
        json!({"fs":{"read":["${workspace}/child"]}}),
        json!({"net":{"allow":["different.test"]}}),
        json!({"models":["second"]}),
        json!({"spawn":true}),
        json!({"env":{"KEEP":"changed"}}),
        json!({"secrets":[{"name":"token","env":"OTHER_TOKEN"}]}),
        json!({"secrets":[{"name":"other","env":"API_TOKEN"}]}),
        json!({"net":{"allow":[]}}),
    ] {
        assert!(
            resolve(
                &original,
                &catalog(),
                &patch(json!({"permissions":permissions})),
                "user",
                &Nat64Prefixes::default()
            )
            .is_err()
        );
    }
    let wildcard = manifest(
        json!({"net":{"allow":["*.example.test"]},"models":["*"]}),
        json!({}),
    );
    for permissions in [
        json!({"net":{"allow":["sub.example.test"]}}),
        json!({"models":["first"]}),
    ] {
        assert!(
            resolve(
                &wildcard,
                &catalog(),
                &patch(json!({"permissions":permissions})),
                "user",
                &Nat64Prefixes::default()
            )
            .is_err()
        );
    }
}

#[test]
fn errors_and_debug_never_include_declared_environment_values() {
    let patch = patch(json!({"permissions":{"env":{"KEY":"private-credential-canary"}}}));
    assert!(!format!("{patch:?}").contains("private-credential-canary"));
    let original = manifest(json!({}), json!({}));
    let error = match resolve(
        &original,
        &catalog(),
        &patch,
        "user",
        &Nat64Prefixes::default(),
    ) {
        Err(error) => error,
        Ok(_) => panic!("undeclared environment value accepted"),
    };
    assert!(!error.to_string().contains("private-credential-canary"));
}
