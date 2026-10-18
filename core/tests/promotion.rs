use fictor::{
    installer::{
        BundleBudget, BundleProfile, inspect,
        lease::InstallerLease,
        manifest::{Manifest, RuntimeKind},
        promotion::{PromotionError, materialize},
    },
    store::{
        HumanDecision, NewProposal, ProposalCheck, ProposalIdentity, ProposalState, ProposalUpdate,
        ResolvedPackage, ReviewBase, Store,
    },
};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    store: Arc<Store>,
    lease: Arc<InstallerLease>,
    id: String,
    source: PathBuf,
    key: String,
}
impl Fixture {
    async fn new(approve: bool) -> Self {
        Self::with_bundle(approve, |_, _| vec![]).await
    }

    async fn with_bundle(
        approve: bool,
        prepare: impl FnOnce(&Path, &mut Manifest) -> Vec<ResolvedPackage>,
    ) -> Self {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        fictor::initialize(&home).await.unwrap();
        let store = Arc::new(Store::open(&home).await.unwrap());
        let lease = Arc::new(InstallerLease::acquire(&home).unwrap());
        let proposal = store
            .begin_attempt(NewProposal {
                source: json!({"kind":"local"}),
                tainted: false,
            })
            .await
            .unwrap();
        let mut manifest = Manifest::parse(
            &json!({
                "schema":1,"id":"sample","version":"1.0.0","description":"Fixture",
                "runtime":{"kind":"binary","entry":"server"},
                "scope":"session","mcp":false,"kernel":["config"]
            })
            .to_string(),
        )
        .unwrap();
        let source = home.join("extensions/quarantine").join(&proposal.id);
        fs::create_dir(&source).unwrap();
        fs::write(source.join("server"), b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(source.join("server"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(source.join("nested")).unwrap();
        fs::write(source.join("nested/data"), b"approved payload").unwrap();
        let packages = prepare(&source, &mut manifest);
        fs::write(
            source.join("fictor.yaml"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let inspected = inspect(
            &source,
            &BundleBudget::start(BundleProfile::PostDependencies),
        )
        .unwrap();
        let key = format!("1.0.0-{}", &inspected.bundle_hash[7..19]);
        let review_base = ReviewBase {
            update_of: None,
            hash: fictor::installer::lock::Lock::default()
                .review_base_hash("sample")
                .unwrap(),
        };
        let catalog = fictor::gateway::PinnedCatalog::new(vec![]).unwrap();
        store
            .transition_proposal(
                proposal.id.clone(),
                ProposalState::Received,
                ProposalState::Checking,
                ProposalUpdate {
                    identity: Some(ProposalIdentity {
                        ext_id: manifest.id.clone(),
                        version: manifest.version.clone(),
                        manifest: serde_json::to_value(&manifest).unwrap(),
                        update_of: None,
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        store
            .transition_proposal(
                proposal.id.clone(),
                ProposalState::Checking,
                ProposalState::Checked,
                ProposalUpdate {
                    hash: Some(inspected.bundle_hash),
                    review_base: Some(review_base.clone()),
                    packages: Some(packages),
                    checks: Some(
                        [
                            "manifest",
                            "dependencies",
                            "bundle",
                            "declarations",
                            "smoke",
                        ]
                        .into_iter()
                        .map(|name| ProposalCheck {
                            name: name.into(),
                            passed: true,
                            blocking: true,
                            detail: (name == "smoke").then(|| {
                                json!({"tools":[],"tools_hash":catalog.hash()}).to_string()
                            }),
                        })
                        .collect(),
                    ),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        if approve {
            let nonce = store.proposal_nonce(proposal.id.clone()).await.unwrap();
            store
                .transition_proposal(
                    proposal.id.clone(),
                    ProposalState::Checked,
                    ProposalState::Approved,
                    ProposalUpdate {
                        decision: Some(HumanDecision::User(nonce)),
                        review_base: Some(review_base),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
        }
        Self {
            _root: root,
            home,
            store,
            lease,
            id: proposal.id,
            source,
            key,
        }
    }
    fn destination(&self) -> PathBuf {
        self.home.join("extensions/store/sample").join(&self.key)
    }
    async fn materialize(
        &self,
    ) -> Result<fictor::installer::promotion::MaterializedBundle, PromotionError> {
        materialize(
            &self.home,
            self.store.clone(),
            self.lease.clone(),
            self.id.clone(),
        )
        .await
    }
}

fn npm_snapshot(source: &Path, manifest: &mut Manifest, unlisted: bool) -> Vec<ResolvedPackage> {
    manifest.runtime.kind = RuntimeKind::Node;
    manifest.runtime.entry = Some("server.mjs".into());
    fs::write(source.join("server.mjs"), "process.exit(0);\n").unwrap();
    fs::write(
        source.join("package.json"),
        json!({"dependencies":{"fixture-pkg":"1.0.0"}}).to_string(),
    )
    .unwrap();
    let locked = json!({"node_modules/fixture-pkg":{"version":"1.0.0"}});
    fs::write(
        source.join("package-lock.json"),
        json!({"lockfileVersion":3,"packages":locked}).to_string(),
    )
    .unwrap();
    fs::create_dir_all(source.join("node_modules/fixture-pkg")).unwrap();
    fs::write(
        source.join("node_modules/.package-lock.json"),
        json!({"lockfileVersion":3,"packages":locked}).to_string(),
    )
    .unwrap();
    fs::write(
        source.join("node_modules/fixture-pkg/package.json"),
        json!({"name":"fixture-pkg","version":"1.0.0"}).to_string(),
    )
    .unwrap();
    fs::write(
        source.join("node_modules/fixture-pkg/index.js"),
        "module.exports = 1;\n",
    )
    .unwrap();
    if unlisted {
        fs::create_dir_all(source.join("node_modules/fixture-pkg/node_modules/extra-pkg")).unwrap();
        fs::write(
            source.join("node_modules/fixture-pkg/node_modules/extra-pkg/package.json"),
            json!({"name":"extra-pkg","version":"9.9.9"}).to_string(),
        )
        .unwrap();
        fs::write(
            source.join("node_modules/fixture-pkg/node_modules/extra-pkg/index.js"),
            "module.exports = 2;\n",
        )
        .unwrap();
    }
    vec![ResolvedPackage {
        ecosystem: "npm".into(),
        name: "fixture-pkg".into(),
        version: "1.0.0".into(),
    }]
}

#[tokio::test]
async fn approved_legacy_inventory_cannot_publish_unlisted_physical_packages() {
    for missing_declarations in [false, true] {
        let fixture = Fixture::with_bundle(true, |source, manifest| {
            let packages = npm_snapshot(source, manifest, true);
            if missing_declarations {
                fs::write(source.join("package.json"), "{}").unwrap();
                vec![]
            } else {
                packages
            }
        })
        .await;
        assert!(matches!(
            fixture.materialize().await,
            Err(PromotionError::Changed)
        ));
        assert!(!fixture.destination().exists());
        assert!(fixture.source.is_dir());
        assert_eq!(
            fixture
                .store
                .proposal(fixture.id.clone())
                .await
                .unwrap()
                .state,
            ProposalState::Approved
        );
    }
}

#[tokio::test]
async fn approved_inventory_must_match_the_current_verified_package_metadata() {
    let fixture = Fixture::with_bundle(true, |source, manifest| {
        let mut packages = npm_snapshot(source, manifest, false);
        packages[0].version = "9.9.9".into();
        packages
    })
    .await;
    assert!(matches!(
        fixture.materialize().await,
        Err(PromotionError::Changed)
    ));
    assert!(!fixture.destination().exists());
    assert!(fixture.source.is_dir());
}

#[tokio::test]
async fn approved_complete_package_inventory_is_materialized_without_resolving_again() {
    let fixture = Fixture::with_bundle(true, |source, manifest| {
        npm_snapshot(source, manifest, false)
    })
    .await;
    let before = fixture.store.proposal(fixture.id.clone()).await.unwrap();
    let materialized = fixture.materialize().await.unwrap();
    assert_eq!(materialized.path, fixture.destination());
    assert!(
        materialized
            .path
            .join("node_modules/fixture-pkg/index.js")
            .is_file()
    );
    let after = fixture.store.proposal(fixture.id.clone()).await.unwrap();
    assert_eq!(after.state, ProposalState::Approved);
    assert_eq!(
        serde_json::to_value(after.packages).unwrap(),
        serde_json::to_value(before.packages).unwrap()
    );
    assert!(
        fictor::installer::lock::Lock::load_required(&fixture.home)
            .unwrap()
            .extensions
            .is_empty()
    );
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Only fixture-owned output: make it removable when the TempDir drops.
        let mut pending = vec![self.home.join("extensions/store")];
        while let Some(path) = pending.pop() {
            if let Ok(metadata) = fs::symlink_metadata(&path)
                && metadata.is_dir()
                && !metadata.file_type().is_symlink()
            {
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o700));
                if let Ok(entries) = fs::read_dir(path) {
                    pending.extend(entries.filter_map(Result::ok).map(|entry| entry.path()));
                }
            }
        }
    }
}

#[tokio::test]
async fn approved_bytes_are_materialized_immutable_without_activation_or_audit_transition() {
    let fixture = Fixture::new(true).await;
    let before = fixture.store.session("sys".into()).await.unwrap().head_id;
    let materialized = fixture.materialize().await.unwrap();
    assert_eq!(materialized.path, fixture.destination());
    assert_eq!(materialized.key, fixture.key);
    for (path, mode) in [
        ("", 0o555),
        ("nested", 0o555),
        ("fictor.yaml", 0o444),
        ("nested/data", 0o444),
        ("server", 0o555),
    ] {
        assert_eq!(
            fs::metadata(materialized.path.join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            mode
        );
    }
    assert_eq!(
        fs::read(materialized.path.join("nested/data")).unwrap(),
        b"approved payload"
    );
    assert_eq!(
        inspect(
            &materialized.path,
            &BundleBudget::start(BundleProfile::PostDependencies)
        )
        .unwrap()
        .bundle_hash,
        materialized.hash
    );
    assert!(fixture.source.is_dir());
    assert!(
        fictor::installer::lock::Lock::load_required(&fixture.home)
            .unwrap()
            .extensions
            .is_empty()
    );
    assert_eq!(
        fixture
            .store
            .proposal(fixture.id.clone())
            .await
            .unwrap()
            .state,
        ProposalState::Approved
    );
    assert_eq!(
        fixture.store.session("sys".into()).await.unwrap().head_id,
        before
    );
    assert_eq!(
        fs::read_dir(fixture.home.join("extensions/quarantine"))
            .unwrap()
            .count(),
        1
    );
    assert_eq!(fixture.materialize().await.unwrap(), materialized);
}

#[tokio::test]
async fn checked_without_human_approval_never_creates_store_bytes() {
    let fixture = Fixture::new(false).await;
    assert!(matches!(
        fixture.materialize().await,
        Err(PromotionError::Unapproved)
    ));
    assert!(!fixture.destination().exists());
    assert!(fixture.source.is_dir());

    let incomplete = Fixture::new(true).await;
    let id = incomplete.id.clone();
    incomplete
        .store
        .write(move |db| {
            db.execute("UPDATE proposals SET checks='[]' WHERE id=?1", [id])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(matches!(
        incomplete.materialize().await,
        Err(PromotionError::Unapproved)
    ));
    assert!(!incomplete.destination().exists());
}

#[tokio::test]
async fn changed_quarantine_is_rejected_without_changing_the_last_lock() {
    let fixture = Fixture::new(true).await;
    let lock = fixture.home.join("extensions/lock.json");
    fs::write(&lock, b"last lock is untouched").unwrap();
    fs::write(
        fixture.source.join("nested/data"),
        b"changed after checking",
    )
    .unwrap();
    assert!(matches!(
        fixture.materialize().await,
        Err(PromotionError::Changed)
    ));
    assert!(!fixture.destination().exists());
    assert_eq!(fs::read(lock).unwrap(), b"last lock is untouched");
    assert!(fixture.source.is_dir());
    assert_eq!(
        fs::read_dir(fixture.home.join("extensions/quarantine"))
            .unwrap()
            .count(),
        1
    );
}

#[tokio::test]
async fn matching_hash_does_not_authorize_a_different_manifest_identity() {
    let fixture = Fixture::new(true).await;
    let manifest =
        Manifest::parse(&fs::read_to_string(fixture.source.join("fictor.yaml")).unwrap()).unwrap();
    let mut value = serde_json::to_value(manifest).unwrap();
    value["description"] = "unreviewed manifest".into();
    fs::write(fixture.source.join("fictor.yaml"), value.to_string()).unwrap();
    let changed_hash = inspect(
        &fixture.source,
        &BundleBudget::start(BundleProfile::PostDependencies),
    )
    .unwrap()
    .bundle_hash;
    let id = fixture.id.clone();
    fixture
        .store
        .write(move |db| {
            db.execute(
                "UPDATE proposals SET hash=?1 WHERE id=?2",
                rusqlite::params![changed_hash, id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(matches!(
        fixture.materialize().await,
        Err(PromotionError::Changed)
    ));
    assert_eq!(
        fs::read_dir(fixture.home.join("extensions/store"))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn an_existing_version_is_never_replaced_even_when_its_contents_are_wrong() {
    let fixture = Fixture::new(true).await;
    fs::create_dir_all(fixture.destination()).unwrap();
    fs::write(
        fixture.destination().join("sentinel"),
        b"retain existing bytes",
    )
    .unwrap();
    assert!(matches!(
        fixture.materialize().await,
        Err(PromotionError::Changed)
    ));
    assert_eq!(
        fs::read(fixture.destination().join("sentinel")).unwrap(),
        b"retain existing bytes"
    );
    assert!(!fixture.destination().join("server").exists());
    assert!(fixture.source.is_dir());
    assert_eq!(
        fs::read_dir(fixture.home.join("extensions/quarantine"))
            .unwrap()
            .count(),
        1
    );
}

#[tokio::test]
async fn existing_mutable_output_and_symlinked_source_or_store_are_refused() {
    let fixture = Fixture::new(true).await;
    fixture.materialize().await.unwrap();
    fs::set_permissions(
        fixture.destination().join("server"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(matches!(
        fixture.materialize().await,
        Err(PromotionError::UnsafePath)
    ));
    assert_eq!(
        fs::metadata(fixture.destination().join("server"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o755
    );

    let source_fixture = Fixture::new(true).await;
    let retained = source_fixture.source.with_extension("retained");
    fs::rename(&source_fixture.source, &retained).unwrap();
    std::os::unix::fs::symlink(&retained, &source_fixture.source).unwrap();
    assert!(source_fixture.materialize().await.is_err());
    assert!(!source_fixture.destination().exists());
    assert!(retained.join("server").is_file());

    let target_fixture = Fixture::new(true).await;
    let outside = target_fixture._root.path().join("outside");
    fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(
        &outside,
        target_fixture.home.join("extensions/store/sample"),
    )
    .unwrap();
    assert!(target_fixture.materialize().await.is_err());
    assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
}
