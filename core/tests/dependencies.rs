use base64::{Engine, engine::general_purpose::STANDARD};
use fictor::{
    config::Config,
    installer::{
        BundleBudget, BundleProfile, bundle,
        dependencies::{self, DependencyError, DependencyKind, DependencyResolver},
        lease::InstallerLease,
        local::LocalChecker,
    },
    proxy::{EgressProxy, nat64::Nat64Prefixes},
    secrets::{BackendKind, Redactor, SecretStore},
    store::{ProposalState, Store},
    supervisor::Supervisor,
};
use serde_json::json;
use sha2::{Digest, Sha256, Sha512};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn requires_toolbx() -> bool {
    let available = Path::new("/run/.toolboxenv").is_file();
    if !available {
        eprintln!(
            "real npm/uv scenario not executed: requires the actual Toolbx development runtime"
        );
    }
    available
}

#[tokio::test]
async fn dependency_execution_is_refused_outside_the_actual_development_toolbx() {
    if Path::new("/run/.toolboxenv").is_file() {
        return;
    }
    let fixture = Fixture::new(vec![]).await;
    for kind in [DependencyKind::Npm, DependencyKind::Python] {
        assert!(matches!(
            fixture
                .resolver
                .resolve(kind, &fixture.candidate, fixture.lease.clone())
                .await,
            Err(DependencyError::Runtime)
        ));
    }
    assert_eq!(fs::read_dir(&fixture.candidate).unwrap().count(), 0);
}

struct Registry {
    address: std::net::SocketAddr,
    calls: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Registry {
    async fn new(path: &str, bytes: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = calls.clone();
        let path = path.to_owned();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut request = Vec::new();
                let mut byte = [0u8];
                while request.len() < 16384 && !request.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        break;
                    }
                    request.push(byte[0]);
                }
                let request = String::from_utf8_lossy(&request);
                let mut first = request
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .split_whitespace();
                let method = first.next().unwrap_or_default();
                let requested = first.next().unwrap_or_default();
                seen.lock().unwrap().push(requested.into());
                let found = requested == path;
                let body = if found { bytes.as_slice() } else { &[] };
                let response = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    if found { "200 OK" } else { "404 Not Found" },
                    body.len()
                );
                if stream.write_all(response.as_bytes()).await.is_ok() && method != "HEAD" {
                    let _ = stream.write_all(body).await;
                }
            }
        });
        Self {
            address,
            calls,
            task,
        }
    }
    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.address, path)
    }
}
impl Drop for Registry {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn archive(kind: &str, files: BTreeMap<&str, String>) -> Vec<u8> {
    // Trusted fixture generation uses only Python's standard library. No package
    // manager or fixture lifecycle/build hook is invoked outside the sandbox.
    let mut child = Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-c",
            r#"
import gzip, io, json, sys, tarfile, zipfile
spec = json.load(sys.stdin)
output = io.BytesIO()
if spec['kind'] == 'tar':
    with tarfile.open(fileobj=output, mode='w:gz') as target:
        for name, value in spec['files'].items():
            data = value.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            target.addfile(info, io.BytesIO(data))
else:
    with zipfile.ZipFile(output, 'w') as target:
        for name, value in spec['files'].items():
            target.writestr(name, value)
sys.stdout.buffer.write(output.getvalue())
"#,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(json!({"kind":kind,"files":files}).to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    output.stdout
}

struct Fixture {
    _root: tempfile::TempDir,
    candidate: PathBuf,
    resolver: DependencyResolver,
    lease: Arc<InstallerLease>,
}

struct CliFixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    real_home: PathBuf,
    source: PathBuf,
}
impl CliFixture {
    async fn new(registries: Vec<String>, runtime: &str) -> Self {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let home = root.path().join("core");
        fictor::initialize(&home).await.unwrap();
        let config_path = home.join("config.toml");
        let mut config: toml::Value =
            toml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        config["installer"]["registries"] =
            toml::Value::Array(registries.into_iter().map(toml::Value::String).collect());
        config["secrets"]["backend"] = toml::Value::String("file".into());
        fs::write(config_path, toml::to_string(&config).unwrap()).unwrap();
        let real_home = root.path().join("user");
        fs::create_dir(&real_home).unwrap();
        let source = root.path().join("source");
        fs::create_dir(&source).unwrap();
        let entry = if runtime == "node" {
            "main.mjs"
        } else {
            "main.py"
        };
        fs::write(source.join("fictor.yaml"), format!("schema: 1\nid: fixture\nversion: 0.1.0\ndescription: Installer regression\nscope: session\nmcp: false\nkernel: [kv]\nruntime:\n  kind: {runtime}\n  entry: {entry}\n")).unwrap();
        fs::write(
            source.join(entry),
            if runtime == "node" {
                "process.exit(0);\n"
            } else {
                "pass\n"
            },
        )
        .unwrap();
        Self {
            _root: root,
            home,
            real_home,
            source,
        }
    }

    async fn check(&self) -> std::process::Output {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_fictor"))
            .args(["ext", "check"])
            .arg(&self.source)
            .env("FICTOR_HOME", &self.home)
            .env("HOME", &self.real_home)
            .output()
            .await
            .unwrap()
    }
}
impl Fixture {
    async fn new(registries: Vec<String>) -> Self {
        let root = tempfile::Builder::new()
            .prefix("fx-dependency-test-")
            .tempdir_in("/tmp")
            .unwrap();
        let home = root.path().join("core");
        fictor::initialize(&home).await.unwrap();
        let mut config = Config::load(&home).unwrap();
        config.installer.registries = registries;
        let real_home = root.path().join("user");
        fs::create_dir(&real_home).unwrap();
        fs::write(real_home.join("private"), "not available to the installer").unwrap();
        let candidate = home
            .join("extensions/quarantine")
            .join(ulid::Ulid::generate().to_string());
        fs::create_dir(&candidate).unwrap();
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700)).unwrap();
        let resolver = DependencyResolver::new(
            Arc::new(config),
            real_home,
            env!("CARGO_BIN_EXE_fictor").into(),
        );
        let lease = Arc::new(InstallerLease::acquire(&home).unwrap());
        Self {
            _root: root,
            candidate,
            resolver,
            lease,
        }
    }
}

fn npm_candidate(path: &Path, url: &str, integrity: &str) {
    fs::write(
        path.join("package.json"),
        json!({"name":"fixture-root","version":"1.0.0","dependencies":{"fixture-pkg":"1.0.0"}})
            .to_string(),
    )
    .unwrap();
    fs::write(path.join("package-lock.json"), json!({
        "name":"fixture-root","version":"1.0.0","lockfileVersion":3,"requires":true,
        "packages": {
            "":{"name":"fixture-root","version":"1.0.0","dependencies":{"fixture-pkg":"1.0.0"}},
            "node_modules/fixture-pkg":{"version":"1.0.0","resolved":url,"integrity":integrity,"hasInstallScript":true,"bin":{"fixture-bin":"bin.js"}}
        }
    }).to_string()).unwrap();
}

#[tokio::test]
async fn npm_installs_from_a_local_registry_without_scripts_or_bin_symlinks() {
    if !requires_toolbx() {
        return;
    }
    let artifact = archive("tar", BTreeMap::from([
        ("package/package.json", json!({"name":"fixture-pkg","version":"1.0.0","bin":{"fixture-bin":"bin.js"},"scripts":{"postinstall":"node -e \"require('fs').writeFileSync('../../INSTALL_SCRIPT_RAN','yes')\""}}).to_string()),
        ("package/bin.js", "process.exit(0);\n".into()),
    ]));
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&artifact)));
    let registry = Registry::new("/fixture.tgz", artifact).await;
    let fixture = Fixture::new(vec![registry.address.to_string()]).await;
    npm_candidate(
        &fixture.candidate,
        &registry.url("/fixture.tgz"),
        &integrity,
    );
    let original_lock = fs::read(fixture.candidate.join("package-lock.json")).unwrap();
    let report = fixture
        .resolver
        .resolve(
            DependencyKind::Npm,
            &fixture.candidate,
            fixture.lease.clone(),
        )
        .await
        .unwrap();
    assert_eq!(report.packages.len(), 1);
    assert_eq!(report.packages[0].ecosystem, "npm");
    assert_eq!(report.packages[0].name, "fixture-pkg");
    assert_eq!(report.packages[0].version, "1.0.0");
    assert!(!fixture.candidate.join("INSTALL_SCRIPT_RAN").exists());
    assert!(
        !fixture
            .candidate
            .join("node_modules/.bin/fixture-bin")
            .exists()
    );
    assert_eq!(
        fs::read(fixture.candidate.join("package-lock.json")).unwrap(),
        original_lock
    );
    assert!(
        registry
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|path| path == "/fixture.tgz")
    );
    let inspected = bundle::inspect(
        &fixture.candidate,
        &BundleBudget::start(BundleProfile::PostDependencies),
    )
    .unwrap();
    assert_eq!(inspected.bundle_hash, report.inspection.bundle_hash);
}

#[tokio::test]
async fn npm_refuses_a_tampered_hash_and_a_registry_outside_the_allowlist() {
    if !requires_toolbx() {
        return;
    }
    let registry = Registry::new("/fixture.tgz", b"tampered".to_vec()).await;
    let fixture = Fixture::new(vec![registry.address.to_string()]).await;
    npm_candidate(
        &fixture.candidate,
        &registry.url("/fixture.tgz"),
        &format!("sha512-{}", STANDARD.encode([0u8; 64])),
    );
    assert!(matches!(
        fixture
            .resolver
            .resolve(
                DependencyKind::Npm,
                &fixture.candidate,
                fixture.lease.clone()
            )
            .await,
        Err(DependencyError::Command)
    ));
    assert!(!fixture.candidate.join("node_modules").exists());
    let denied = Fixture::new(vec![]).await;
    npm_candidate(
        &denied.candidate,
        &registry.url("/denied.tgz"),
        &format!("sha512-{}", STANDARD.encode([0u8; 64])),
    );
    assert!(matches!(
        denied
            .resolver
            .resolve(DependencyKind::Npm, &denied.candidate, denied.lease.clone())
            .await,
        Err(DependencyError::Command)
    ));
    assert!(
        !registry
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|path| path == "/denied.tgz")
    );
}

#[tokio::test]
async fn cli_refuses_npm_packages_missing_from_the_installed_lock() {
    if !requires_toolbx() {
        return;
    }
    for with_metadata in [true, false] {
        let mut files = BTreeMap::from([
            (
                "package/package.json",
                json!({"name":"fixture-pkg","version":"1.0.0"}).to_string(),
            ),
            ("package/index.js", "module.exports = 1;\n".into()),
            (
                "package/node_modules/extra-pkg/index.js",
                "module.exports = 2;\n".into(),
            ),
        ]);
        if with_metadata {
            files.insert(
                "package/node_modules/extra-pkg/package.json",
                json!({"name":"extra-pkg","version":"9.9.9"}).to_string(),
            );
        }
        let artifact = archive("tar", files);
        let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&artifact)));
        let registry = Registry::new("/fixture.tgz", artifact).await;
        let fixture = CliFixture::new(vec![registry.address.to_string()], "node").await;
        npm_candidate(&fixture.source, &registry.url("/fixture.tgz"), &integrity);
        let output = fixture.check().await;
        assert!(!output.status.success(), "unlisted package was accepted");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("invalid package metadata"), "{stderr}");
        let id = stderr
            .split_whitespace()
            .find(|value| value.parse::<ulid::Ulid>().is_ok())
            .unwrap();
        let store = Store::open(&fixture.home).await.unwrap();
        let proposal = store.proposal(id.into()).await.unwrap();
        assert_eq!(proposal.state, ProposalState::Failed);
        assert!(proposal.packages.is_none());
        let checks = proposal.checks.unwrap();
        assert!(
            checks
                .iter()
                .any(|check| check.name == "dependencies" && !check.passed)
        );
        assert!(!checks.iter().any(|check| check.name == "smoke"));
    }
}

#[tokio::test]
async fn npm_inventories_bundled_scoped_packages_without_treating_fixture_metadata_as_packages() {
    if !requires_toolbx() {
        return;
    }
    let artifact = archive("tar", BTreeMap::from([
        ("package/package.json", json!({"name":"fixture-pkg","version":"1.0.0","dependencies":{"@nested/pkg":"2.0.0"},"bundledDependencies":["@nested/pkg"]}).to_string()),
        ("package/index.js", "module.exports = 1;\n".into()),
        ("package/node_modules/@nested/pkg/package.json", json!({"name":"@nested/pkg","version":"2.0.0"}).to_string()),
        ("package/node_modules/@nested/pkg/index.js", "module.exports = 2;\n".into()),
        ("package/tests/fixture/package.json", "deliberately not package metadata".into()),
    ]));
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&artifact)));
    let registry = Registry::new("/fixture.tgz", artifact).await;
    let fixture = Fixture::new(vec![registry.address.to_string()]).await;
    npm_candidate(
        &fixture.candidate,
        &registry.url("/fixture.tgz"),
        &integrity,
    );
    let lock_path = fixture.candidate.join("package-lock.json");
    let mut lock: serde_json::Value =
        serde_json::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
    lock["packages"]["node_modules/fixture-pkg"]["dependencies"] = json!({"@nested/pkg":"2.0.0"});
    lock["packages"]["node_modules/fixture-pkg"]["bundleDependencies"] = json!(["@nested/pkg"]);
    lock["packages"]["node_modules/fixture-pkg/node_modules/@nested/pkg"] =
        json!({"version":"2.0.0","inBundle":true});
    fs::write(lock_path, lock.to_string()).unwrap();
    let report = fixture
        .resolver
        .resolve(
            DependencyKind::Npm,
            &fixture.candidate,
            fixture.lease.clone(),
        )
        .await
        .unwrap();
    assert_eq!(report.packages.len(), 2);
    assert_eq!(report.packages[0].name, "@nested/pkg");
    assert_eq!(report.packages[0].version, "2.0.0");
    assert_eq!(report.packages[1].name, "fixture-pkg");
}

#[tokio::test]
async fn wildcard_installer_registry_is_refused_before_network_access() {
    if !requires_toolbx() {
        return;
    }
    let registry = Registry::new("/fixture.tgz", vec![]).await;
    let fixture = Fixture::new(vec!["*".into()]).await;
    npm_candidate(
        &fixture.candidate,
        &registry.url("/fixture.tgz"),
        "sha512-invalid",
    );
    assert!(matches!(
        fixture
            .resolver
            .resolve(
                DependencyKind::Npm,
                &fixture.candidate,
                fixture.lease.clone()
            )
            .await,
        Err(DependencyError::RegistryPolicy)
    ));
    assert!(registry.calls.lock().unwrap().is_empty());
    assert!(!fixture.candidate.join("node_modules").exists());
}

#[tokio::test]
async fn local_pipeline_persists_installed_packages_and_smokes_the_final_bundle() {
    if !requires_toolbx() {
        return;
    }
    let artifact = archive("tar", BTreeMap::from([
        ("package/package.json", json!({"name":"fixture-pkg","version":"1.0.0","type":"module","exports":"./index.js"}).to_string()),
        ("package/index.js", "export const toolName = 'installed_echo';\n".into()),
    ]));
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&artifact)));
    let registry = Registry::new("/fixture.tgz", artifact).await;
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let home = root.path().join("core");
    let real_home = root.path().join("user");
    fs::create_dir(&real_home).unwrap();
    fs::write(real_home.join("private"), "not mounted").unwrap();
    fictor::initialize(&home).await.unwrap();
    let mut config = Config::load(&home).unwrap();
    config.installer.registries = vec![registry.address.to_string()];
    let config = Arc::new(config);
    let store = Arc::new(Store::open(&home).await.unwrap());
    let secrets =
        Arc::new(SecretStore::open(&home, BackendKind::File, Redactor::default()).unwrap());
    let proxy = Arc::new(
        EgressProxy::bind_unix_with_nat64(
            home.join("run/test-proxy.sock"),
            store.clone(),
            vec![],
            Nat64Prefixes::default(),
        )
        .await
        .unwrap(),
    );
    let supervisor = Arc::new(
        Supervisor::new(
            &home,
            &real_home,
            config.clone(),
            secrets,
            store.clone(),
            proxy,
        )
        .unwrap()
        .with_fictor_exe(env!("CARGO_BIN_EXE_fictor").into())
        .unwrap(),
    );
    let resolver = Arc::new(DependencyResolver::new(
        config,
        real_home,
        env!("CARGO_BIN_EXE_fictor").into(),
    ));
    let checker = LocalChecker::new(
        home.clone(),
        Nat64Prefixes::default(),
        store.clone(),
        supervisor,
        Default::default(),
    )
    .with_dependency_resolver(resolver);
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    npm_candidate(&source, &registry.url("/fixture.tgz"), &integrity);
    fs::write(source.join("fictor.yaml"), "schema: 1\nid: fixture\nversion: 0.1.0\ndescription: Dependency integration\nscope: session\nruntime:\n  kind: node\n  entry: main.mjs\ntools:\n  installed_echo: {}\n").unwrap();
    fs::write(source.join("main.mjs"), r#"import { toolName } from 'fixture-pkg';
import { createInterface } from 'node:readline';
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  if (!Object.hasOwn(request, 'id')) continue;
  const result = request.method === 'initialize' ? {
    protocolVersion: request.params.protocolVersion,
    capabilities: { tools: {}, resources: {} },
    serverInfo: { name: 'installed-fixture', version: '1.0.0' }
  } : request.method === 'tools/list' ? {
    tools: [{ name: toolName, description: 'Installed dependency', inputSchema: { type: 'object' } }]
  } : request.method === 'resources/list' ? { resources: [] } : {};
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }) + '\n');
}
"#).unwrap();
    let report = checker.check_local(&source).await.unwrap();
    assert_eq!(report.proposal.state, ProposalState::Checked);
    assert_eq!(report.catalog.tools()[0]["name"], "installed_echo");
    let proposal = store.proposal(report.proposal.id.clone()).await.unwrap();
    let packages = proposal.packages.unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].name, "fixture-pkg");
    assert_eq!(packages[0].version, "1.0.0");
    let candidate = home.join("extensions/quarantine").join(&proposal.id);
    let inspected = bundle::inspect(
        &candidate,
        &BundleBudget::start(BundleProfile::PostDependencies),
    )
    .unwrap();
    assert_eq!(
        proposal.hash.as_deref(),
        Some(inspected.bundle_hash.as_str())
    );
    assert!(!source.join("node_modules").exists());
    assert!(!home.join("extensions/lock.json").exists());
    drop(checker);
    let config_path = home.join("config.toml");
    let mut persisted: toml::Value =
        toml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    persisted["installer"]["registries"] =
        toml::Value::Array(vec![toml::Value::String(registry.address.to_string())]);
    persisted["secrets"]["backend"] = toml::Value::String("file".into());
    fs::write(&config_path, toml::to_string(&persisted).unwrap()).unwrap();
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_fictor"))
        .args(["ext", "check"])
        .arg(&source)
        .env("FICTOR_HOME", &home)
        .env("HOME", root.path().join("user"))
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cli: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cli["state"], "checked");
    assert_eq!(cli["activated"], false);
    assert_eq!(cli["bundle_hash"], inspected.bundle_hash);
    let cli_id = cli["proposal_id"].as_str().unwrap();
    assert_ne!(cli_id, proposal.id);
    let cli_proposal = store.proposal(cli_id.into()).await.unwrap();
    let cli_packages = cli_proposal.packages.unwrap();
    assert_eq!(cli_packages.len(), 1);
    assert_eq!(cli_packages[0].name, "fixture-pkg");
    assert_eq!(cli_packages[0].version, "1.0.0");
    assert!(!source.join("node_modules").exists());
    assert!(!home.join("extensions/lock.json").exists());
}

fn wheel() -> Vec<u8> {
    wheel_with_metadata("Metadata-Version: 2.1\nName: fixture-pkg\nVersion: 1.0.0\n\n")
}

fn wheel_with_metadata(metadata: &str) -> Vec<u8> {
    let mut files = BTreeMap::from([
        ("fixture_pkg/__init__.py", "VALUE = 'fixture'\n".into()),
        ("fixture_pkg-1.0.0.dist-info/METADATA", metadata.into()),
        ("fixture_pkg-1.0.0.dist-info/WHEEL", "Wheel-Version: 1.0\nGenerator: fictor-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n".into()),
    ]);
    let record = files
        .keys()
        .map(|name| format!("{name},,\n"))
        .collect::<String>();
    files.insert("fixture_pkg-1.0.0.dist-info/RECORD", record);
    archive("zip", files)
}

#[tokio::test]
async fn uv_installs_a_hashed_local_wheel_and_inventories_metadata() {
    if !requires_toolbx() {
        return;
    }
    let artifact = wheel();
    let digest: String = Sha256::digest(&artifact)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let endpoint = "/fixture_pkg-1.0.0-py3-none-any.whl";
    let registry = Registry::new(endpoint, artifact).await;
    let fixture = Fixture::new(vec![registry.address.to_string()]).await;
    fs::write(
        fixture.candidate.join("requirements.lock"),
        format!(
            "fixture-pkg @ {} --hash=sha256:{digest}\n",
            registry.url(endpoint)
        ),
    )
    .unwrap();
    let report = fixture
        .resolver
        .resolve(
            DependencyKind::Python,
            &fixture.candidate,
            fixture.lease.clone(),
        )
        .await
        .unwrap();
    assert_eq!(report.packages.len(), 1);
    assert_eq!(report.packages[0].ecosystem, "pypi");
    assert_eq!(report.packages[0].name, "fixture-pkg");
    assert_eq!(report.packages[0].version, "1.0.0");
    assert!(
        fixture
            .candidate
            .join(".pydeps/fixture_pkg/__init__.py")
            .is_file()
    );
    assert!(
        registry
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|path| path == endpoint)
    );
}

#[tokio::test]
async fn cli_accepts_standard_case_insensitive_python_metadata_headers() {
    if !requires_toolbx() {
        return;
    }
    let artifact = wheel_with_metadata(
        "Metadata-Version: 2.1\r\nname:fixture-pkg\r\nVERSION:\t1.0.0 \t\r\n\r\n",
    );
    let digest: String = Sha256::digest(&artifact)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let endpoint = "/fixture_pkg-1.0.0-py3-none-any.whl";
    let registry = Registry::new(endpoint, artifact).await;
    let fixture = CliFixture::new(vec![registry.address.to_string()], "python").await;
    fs::write(
        fixture.source.join("requirements.lock"),
        format!(
            "fixture-pkg @ {} --hash=sha256:{digest}\n",
            registry.url(endpoint)
        ),
    )
    .unwrap();
    let output = fixture.check().await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cli: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(cli["state"], "checked");
    let store = Store::open(&fixture.home).await.unwrap();
    let proposal = store
        .proposal(cli["proposal_id"].as_str().unwrap().into())
        .await
        .unwrap();
    let packages = proposal.packages.unwrap();
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].ecosystem, "pypi");
    assert_eq!(packages[0].name, "fixture-pkg");
    assert_eq!(packages[0].version, "1.0.0");
}

#[test]
fn python_inventory_unfolds_headers_and_rejects_case_insensitive_identity_duplicates() {
    for (headers, accepted) in [
        (
            "Metadata-Version: 2.1\r\nNAME:\r\n fixture-pkg\r\nVERSION:\t1.0.0\t\r\nDescription: fixture\r\n Name: not-an-identity\r\n\r\nName: body-not-identity\r\n",
            true,
        ),
        (
            "Metadata-Version: 2.1\nName: fixture-pkg\nnAmE: hidden\nVersion: 1.0.0\n\n",
            false,
        ),
        (
            "Metadata-Version: 2.1\nName: fixture-pkg\nVersion: 1.0.0\nvErSiOn: 9.9.9\n\n",
            false,
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let metadata = root
            .path()
            .join(".pydeps/fixture_pkg-1.0.0.dist-info/METADATA");
        fs::create_dir_all(metadata.parent().unwrap()).unwrap();
        fs::write(metadata, headers).unwrap();
        let inspected = bundle::inspect(
            root.path(),
            &BundleBudget::start(BundleProfile::PostDependencies),
        )
        .unwrap();
        let result = dependencies::inventory(DependencyKind::Python, root.path(), &inspected);
        if accepted {
            let packages = result.unwrap();
            assert_eq!(packages.len(), 1);
            assert_eq!(packages[0].name, "fixture-pkg");
            assert_eq!(packages[0].version, "1.0.0");
        } else {
            assert!(matches!(result, Err(DependencyError::Metadata)));
        }
    }
}

#[tokio::test]
async fn uv_refuses_unhashed_requirements_and_source_builds() {
    if !requires_toolbx() {
        return;
    }
    let artifact = archive(
        "tar",
        BTreeMap::from([
            (
                "fixture_pkg-1.0.0/pyproject.toml",
                "[build-system]\nrequires=[]\nbuild-backend='backend'\nbackend-path=['.']\n".into(),
            ),
            (
                "fixture_pkg-1.0.0/backend.py",
                "raise RuntimeError('installer must never import build backends')\n".into(),
            ),
            (
                "fixture_pkg-1.0.0/PKG-INFO",
                "Metadata-Version: 2.1\nName: fixture-pkg\nVersion: 1.0.0\n".into(),
            ),
        ]),
    );
    let digest: String = Sha256::digest(&artifact)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let registry = Registry::new("/fixture_pkg-1.0.0.tar.gz", artifact).await;
    for hashed in [false, true] {
        let fixture = Fixture::new(vec![registry.address.to_string()]).await;
        let hash = if hashed {
            format!(" --hash=sha256:{digest}")
        } else {
            String::new()
        };
        fs::write(
            fixture.candidate.join("requirements.lock"),
            format!(
                "fixture-pkg @ {}{hash}\n",
                registry.url("/fixture_pkg-1.0.0.tar.gz")
            ),
        )
        .unwrap();
        assert!(matches!(
            fixture
                .resolver
                .resolve(
                    DependencyKind::Python,
                    &fixture.candidate,
                    fixture.lease.clone()
                )
                .await,
            Err(DependencyError::Command)
        ));
        assert!(!fixture.candidate.join(".pydeps").exists());
    }
}

#[test]
fn plans_require_lockfiles_and_reject_ambiguous_or_malformed_metadata() {
    use fictor::installer::manifest::RuntimeKind;
    let root = tempfile::tempdir().unwrap();
    assert_eq!(
        dependencies::plan(RuntimeKind::Node, root.path()).unwrap(),
        None
    );
    fs::write(
        root.path().join("package.json"),
        r#"{"dependencies":{"fixture-pkg":"1.0.0"}}"#,
    )
    .unwrap();
    assert!(matches!(
        dependencies::plan(RuntimeKind::Node, root.path()),
        Err(DependencyError::MissingLock)
    ));
    fs::write(root.path().join("package-lock.json"), "{}").unwrap();
    assert_eq!(
        dependencies::plan(RuntimeKind::Node, root.path()).unwrap(),
        Some(DependencyKind::Npm)
    );
    fs::write(root.path().join("npm-shrinkwrap.json"), "{}").unwrap();
    assert!(matches!(
        dependencies::plan(RuntimeKind::Node, root.path()),
        Err(DependencyError::Metadata)
    ));
    assert!(matches!(
        dependencies::plan(RuntimeKind::Python, root.path()),
        Err(DependencyError::MissingLock)
    ));
}
