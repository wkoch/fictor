use fictor::{
    installer::manifest::{
        Effect, Manifest, ManifestError, OutputTrust, Role, RuntimeKind, Scope, Sensitivity,
        valid_environment_name,
    },
    proxy::nat64::Nat64Prefixes,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn base() -> Value {
    json!({"schema":1,"id":"test-extension","version":"1.2.3","description":"A test extension","runtime":{"kind":"deno","entry":"server.ts"}})
}
fn parse(value: Value) -> Result<Manifest, ManifestError> {
    Manifest::parse(&value.to_string())
}
fn error(value: Value) -> ManifestError {
    match parse(value) {
        Ok(_) => panic!("invalid manifest accepted"),
        Err(error) => error,
    }
}

#[test]
fn defaults_are_restrictive_and_mcp_depends_on_runtime() {
    let mut value = base();
    value["tools"] = json!({"read_file":{}});
    let manifest = parse(value).unwrap();
    assert_eq!(manifest.role, Role::Extension);
    assert_eq!(manifest.scope, Scope::Global);
    assert!(manifest.mcp_enabled());
    assert!(manifest.permissions.fs.read.is_empty());
    assert!(manifest.permissions.fs.write.is_empty());
    assert!(manifest.permissions.net.allow.is_empty());
    assert!(!manifest.permissions.spawn);
    let class = &manifest.tools["read_file"];
    assert_eq!(class.effect, Effect::External);
    assert_eq!(class.sensitivity, Sensitivity::Private);
    assert_eq!(class.output_trust, OutputTrust::Untrusted);
    assert!(class.model_visible);
    assert!(!class.ui_callable);
    assert_eq!(class.timeout_ms, 120_000);
    let mut value = base();
    value["runtime"] = json!({"kind":"none"});
    let manifest = parse(value).unwrap();
    assert_eq!(manifest.runtime.kind, RuntimeKind::None);
    assert!(!manifest.mcp_enabled());
    assert!(manifest.validate().is_ok());
}

#[test]
fn semver_accepts_builds_and_rejects_invalid_numeric_and_empty_identifiers() {
    for version in [
        "0.0.0",
        "1.0.0+build.5",
        "1.0.0-0",
        "1.0.0-alpha.1+build.05",
        "1.0.0-0a.0-rc",
    ] {
        let mut value = base();
        value["version"] = version.into();
        let manifest = parse(value).unwrap();
        assert!(manifest.validate().is_ok(), "{version}");
    }
    for version in [
        "01.0.0",
        "1.01.0",
        "1.0.01",
        "1.0.0-01",
        "1.0.0-alpha.01",
        "1.0.0-alpha..x",
        "1.0.0-",
        "1.0.0+",
        "1.0.0+build..5",
        "v1.0.0",
    ] {
        let mut value = base();
        value["version"] = version.into();
        assert_eq!(error(value), ManifestError::Schema, "{version}");
    }
    let mut value = base();
    value["version"] = format!("1.0.0+{}", "a".repeat(59)).into();
    assert_eq!(error(value), ManifestError::Schema);
}

#[test]
fn absent_defaults_roundtrip_without_admitting_forbidden_raw_fields() {
    let mut none = base();
    none["runtime"] = json!({"kind":"none"});
    none["mcp"] = false.into();
    let manifest = parse(none.clone()).unwrap();
    let serialized = serde_json::to_value(&manifest).unwrap();
    for field in ["kernel", "tools", "surfaces", "permissions"] {
        assert!(serialized.get(field).is_none(), "{field}");
        let mut explicit = none.clone();
        explicit[field] = match field {
            "kernel" | "surfaces" => json!([]),
            _ => json!({}),
        };
        assert_eq!(error(explicit), ManifestError::Schema, "{field}");
    }
    let roundtrip: Manifest = serde_json::from_value(serialized).unwrap();
    assert!(roundtrip.validate().is_ok());
    let mut forged = roundtrip.clone();
    forged.permissions.spawn = true;
    assert_eq!(forged.validate(), Err(ManifestError::Schema));
    forged = roundtrip;
    forged.tools.insert("fake".into(), Default::default());
    assert_eq!(forged.validate(), Err(ManifestError::Schema));
}

#[test]
fn process_roles_require_a_real_channel_and_harness_cannot_serve_mcp() {
    let mut harness = base();
    harness["role"] = "harness".into();
    harness["scope"] = "session".into();
    harness["mcp"] = false.into();
    harness["kernel"] = json!(["config"]);
    let manifest = parse(harness.clone()).unwrap();
    let serialized = serde_json::to_value(&manifest).unwrap();
    assert!(serialized.get("tools").is_none());
    assert!(serialized.get("surfaces").is_none());
    assert!(parse(serialized).is_ok());
    for field in ["hooks", "surfaces", "tools"] {
        let mut explicit = harness.clone();
        explicit[field] = if field == "tools" {
            json!({})
        } else {
            json!([])
        };
        assert_eq!(error(explicit), ManifestError::Schema);
    }
    for invalid in [
        json!({"runtime":{"kind":"none"}}),
        json!({"mcp":true}),
        json!({"kernel":[]}),
    ] {
        let mut value = harness.clone();
        for (field, entry) in invalid.as_object().unwrap() {
            value[field] = entry.clone();
        }
        assert_eq!(error(value), ManifestError::Schema);
    }
    let mut forged = manifest;
    forged.mcp = None;
    assert_eq!(forged.validate(), Err(ManifestError::Schema));
    let mut process = base();
    process["scope"] = "session".into();
    process["mcp"] = false.into();
    assert_eq!(error(process.clone()), ManifestError::Schema);
    process["kernel"] = json!(["config"]);
    assert!(parse(process).is_ok());
    let mut none = base();
    none["runtime"] = json!({"kind":"none"});
    none["mcp"] = true.into();
    assert_eq!(error(none), ManifestError::Schema);
}

#[test]
fn toolchains_are_recognized_but_fail_closed_until_mount_support_exists() {
    let mut value = base();
    value["scope"] = "session".into();
    value["permissions"] = json!({"toolchains":false});
    let mut manifest = parse(value.clone()).unwrap();
    assert!(!manifest.permissions.toolchains);
    manifest.permissions.toolchains = true;
    assert_eq!(manifest.validate(), Err(ManifestError::UnsupportedPhase));
    value["permissions"]["toolchains"] = true.into();
    assert_eq!(error(value.clone()), ManifestError::UnsupportedPhase);
    value["scope"] = "global".into();
    assert_eq!(error(value), ManifestError::Schema);
}

#[test]
fn local_runtimes_and_declarative_hooks_validate_without_activation() {
    for kind in ["deno", "node", "python", "binary"] {
        let mut value = base();
        value["runtime"]["kind"] = kind.into();
        value["scope"] = "session".into();
        value["hooks_api"] = 1.into();
        value["hooks"] = json!([{"point":"tool.after"}]);
        value["permissions"] = json!({"fs":{"read":["${workspace}"],"write":["${workspace}/target","${ext_data}"]},"env":{"FEATURE":"enabled"}});
        let manifest = parse(value).unwrap();
        let hook = &manifest.hooks.as_ref().unwrap()[0];
        assert_eq!(hook.priority, 100);
        assert_eq!(hook.timeout_ms, 2000);
        let roundtrip: Manifest =
            serde_json::from_value(serde_json::to_value(&manifest).unwrap()).unwrap();
        assert!(roundtrip.validate().is_ok());
    }
}

#[test]
fn schema_structure_and_future_runtime_tiers_are_enforced() {
    for id in ["bad_id", "Bad", "trailing-", "double--dash"] {
        let mut value = base();
        value["id"] = id.into();
        assert_eq!(error(value), ManifestError::Schema);
    }
    for runtime in [
        json!({"kind":"deno"}),
        json!({"kind":"binary","entry":"/usr/bin/tool"}),
        json!({"kind":"none","entry":"server.ts"}),
    ] {
        let mut value = base();
        value["runtime"] = runtime;
        assert!(parse(value).is_err());
    }
    let mut value = base();
    value["runtime"] = json!({"kind":"remote","url":"https://example.test/mcp"});
    assert_eq!(error(value), ManifestError::UnsupportedPhase);
    for tier in ["container", "vm"] {
        let mut value = base();
        value["isolation"] = tier.into();
        assert_eq!(error(value), ManifestError::UnsupportedPhase);
    }
    let mut value = base();
    value["unknown"] = "fake-secret-not-in-error".into();
    let problem = error(value);
    assert!(!format!("{problem}: {problem:?}").contains("fake-secret-not-in-error"));
}

#[test]
fn harness_and_tools_clients_receive_only_mediated_data() {
    let mut harness = base();
    harness["role"] = "harness".into();
    harness["scope"] = "session".into();
    harness["mcp"] = false.into();
    harness["kernel"] = json!(["tools", "events.read"]);
    harness["permissions"] = json!({"fs":{"read":["${store}","${ext_root}/prompts"],"write":["${ext_data}","${tmp}/state"]},"models":["provider"]});
    assert!(parse(harness.clone()).is_ok());
    for path in [
        "${workspace}",
        "${workspace}/src",
        "/home/user/private",
        "~/private",
    ] {
        for role in ["harness", "extension"] {
            let mut value = harness.clone();
            value["role"] = role.into();
            value["permissions"]["fs"]["read"] = json!([path]);
            assert!(parse(value).is_err(), "{role}: {path}");
        }
    }
    let mut value = harness.clone();
    value["permissions"]["net"] = json!({"allow":["example.test"]});
    assert!(parse(value).is_err());
    let mut value = harness.clone();
    value["hooks"] = json!([]);
    value["hooks_api"] = 1.into();
    assert!(parse(value).is_err());
    let mut value = harness;
    value["scope"] = "global".into();
    assert!(parse(value).is_err());
    for scope in ["tools", "hooks", "sessions"] {
        let mut value = base();
        value["kernel"] = json!([scope]);
        assert!(parse(value).is_err());
    }
    let mut value = base();
    value["kernel"] = json!(["sessions.input"]);
    assert!(parse(value).is_ok());
}

#[test]
fn templates_paths_and_read_only_code_boundaries_are_checked() {
    for path in [
        "${workspace}",
        "${store}",
        "${unknown}",
        "${ext_data}/../private",
        "${tmp}/${workspace}",
        "/tmp/../private",
        "relative",
        "~/../private",
        "${ext_data}/bad\\path",
    ] {
        let mut value = base();
        value["permissions"] = json!({"fs":{"read":[path]}});
        assert!(parse(value).is_err(), "{path}");
    }
    for path in ["${ext_root}", "${ext_root}/server.ts", "${store}/bundle"] {
        let mut value = base();
        value["role"] = "harness".into();
        value["scope"] = "session".into();
        value["mcp"] = false.into();
        value["kernel"] = json!(["config"]);
        value["permissions"] = json!({"fs":{"write":[path]}});
        assert!(parse(value).is_err(), "{path}");
    }
    for entry in [
        "../server.ts",
        "sub/../../server.ts",
        "server\\file.ts",
        "sub/\nfile.ts",
    ] {
        let mut value = base();
        value["runtime"]["entry"] = entry.into();
        assert!(parse(value).is_err());
    }
    let mut value = base();
    value["permissions"] = json!({"fs":{"read":["~/project","/opt/inputs","${ext_root}"]}});
    assert!(parse(value).is_ok());
}

#[test]
fn reserved_environment_and_secret_collisions_are_rejected_at_both_boundaries() {
    for name in [
        "PATH",
        "FICTOR_EXT_ID",
        "LC_ALL",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "DENO_DIR",
        "BASH_FUNC_TEST",
        "HTTP_PROXY",
        "NODE_OPTIONS",
        "SSL_CERT_FILE",
        "GNUPGHOME",
        "DBUS_SESSION_BUS_ADDRESS",
        "http_proxy",
    ] {
        assert!(!valid_environment_name(name));
        let mut value = base();
        value["permissions"] = json!({"env":{name:"fake-env-value"}});
        assert!(parse(value).is_err());
    }
    assert!(valid_environment_name("APPLICATION_FEATURE_2"));
    for bindings in [
        json!([{"name":"first","env":"TOKEN"},{"name":"second","env":"TOKEN"}]),
        json!([{"name":"first","env":"TOKEN"}]),
    ] {
        let mut value = base();
        value["permissions"] =
            json!({"net":{"allow":["example.test"]},"env":{"TOKEN":"static"},"secrets":bindings});
        assert!(parse(value).is_err());
    }
    let mut manifest = parse(base()).unwrap();
    manifest
        .permissions
        .env
        .insert("HOME".into(), "fake".into());
    assert!(manifest.validate().is_err());
}

#[test]
fn injected_secrets_require_explicit_domains_and_exclude_provider_credentials() {
    for allow in [json!([]), json!(["*"]), json!(["*.example.test"])] {
        let mut value = base();
        value["permissions"] =
            json!({"net":{"allow":allow},"secrets":[{"name":"app_token","env":"APP_TOKEN"}]});
        assert!(parse(value).is_err());
    }
    let mut value = base();
    value["permissions"] = json!({"net":{"allow":["api.example.test"]},"secrets":[{"name":"app_token","env":"APP_TOKEN"}]});
    let manifest = parse(value).unwrap();
    assert!(
        manifest
            .validate_provider_secrets(&BTreeSet::from(["provider_key".into()]))
            .is_ok()
    );
    assert!(
        manifest
            .validate_provider_secrets(&BTreeSet::from(["app_token".into()]))
            .is_err()
    );
}

#[test]
fn semantic_network_validation_normalizes_ipv6_and_rejects_nat64_encodings() {
    let mut value = base();
    value["permissions"] =
        json!({"net":{"allow":["[2001:0DB8:0000:0000:0000:0000:0000:0010]:08080"]}});
    assert_eq!(
        parse(value).unwrap().permissions.net.allow,
        ["[2001:db8::10]:8080"]
    );
    for pattern in [
        "127.0.0.1",
        "example.test:0",
        "example.test:65536",
        "*:443",
        "[::ffff:127.0.0.1]:443",
        "[64:ff9b::7f00:1]:443",
        "[fe80::1%en0]:80",
    ] {
        let mut value = base();
        value["permissions"] = json!({"net":{"allow":[pattern]}});
        assert!(parse(value).is_err(), "{pattern}");
    }
    let configured = Nat64Prefixes::new(&["2001:db8:64::/96".into()]).unwrap();
    let mut value = base();
    value["permissions"] = json!({"net":{"allow":["[2001:db8:64::7f00:1]:443"]}});
    assert!(Manifest::parse_with_nat64(&value.to_string(), &configured).is_err());
}

#[test]
fn commands_surfaces_and_kernel_lists_are_unique() {
    let mut value = base();
    value["commands"] = json!([{"name":"run","description":"one","prompt":"prompts/one.md"},{"name":"run","description":"two","prompt":"prompts/two.md"}]);
    assert!(parse(value).is_err());
    let mut value = base();
    value["surfaces"] = json!([{"id":"panel","slot":"left","resource":"ui://test/panel","title":"One"},{"id":"panel","slot":"right","resource":"ui://test/other","title":"Two"}]);
    assert!(parse(value).is_err());
    let mut value = base();
    value["kernel"] = json!(["kv", "kv"]);
    assert!(parse(value).is_err());
    let mut value = base();
    value["hooks"] = json!([{"point":"tool.after"}]);
    assert!(parse(value).is_err());
}

#[test]
fn yaml_duplicates_tags_complex_keys_and_multiple_documents_fail_without_echo() {
    let prefix = "schema: 1\nid: test-extension\nversion: 1.0.0\ndescription: test\nruntime: {kind: deno, entry: server.ts}\n";
    for suffix in [
        "id: other\n",
        "permissions: {env: {TOKEN: fake-sensitive-one, TOKEN: fake-sensitive-two}}\n",
        "permissions: !Injected {env: {TOKEN: fake-sensitive}}\n",
        "tools: {? [complex, key]: {}}\n",
        "---\nschema: 1\n",
    ] {
        let text = format!("{prefix}{suffix}");
        let problem = match Manifest::parse(&text) {
            Ok(_) => panic!("unsafe YAML accepted"),
            Err(error) => error,
        };
        assert!(!format!("{problem}: {problem:?}").contains("fake-sensitive"));
    }
}

#[test]
fn parser_bounds_recursion_and_alias_expansion_before_schema_validation() {
    let nested = format!("value: {}0{}", "[".repeat(64), "]".repeat(64));
    assert!(Manifest::parse(&nested).is_err());
    assert!(Manifest::parse("value: &cycle [*cycle]").is_err());
    let mut aliases = "a: &a [null,null,null,null,null,null,null,null]\n".to_owned();
    let mut previous = 'a';
    for name in 'b'..='l' {
        aliases.push_str(&format!(
            "{name}: &{name} [{}]\n",
            vec![format!("*{previous}"); 8].join(",")
        ));
        previous = name;
    }
    assert!(Manifest::parse(&aliases).is_err());
}

#[test]
fn embedded_schema_rejects_untrusted_schema_directives() {
    for directive in ["$ref", "$schema"] {
        let mut value = base();
        value[directive] = "file:///var/lib/fake-sensitive-reference".into();
        assert_eq!(error(value), ManifestError::Schema);
    }
}
