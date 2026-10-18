//! Bubblewrap's mount namespace is built from a small base plus validated grants.
use std::process::Command;
use std::{ffi::OsString, path::Path};

use super::{SandboxError, ValidatedSandbox, attestation::Attestation, mounts::MountProof};

pub(super) fn arguments(
    sandbox: &ValidatedSandbox,
    command: &[OsString],
    mounts: &super::plan::MountPlan,
    proof: &MountProof,
) -> Result<Vec<OsString>, SandboxError> {
    let normalized = mounts.normalized(proof)?;
    render(sandbox, command, mounts, proof, &normalized)
}

fn render(
    sandbox: &ValidatedSandbox,
    command: &[OsString],
    mounts: &super::plan::MountPlan,
    proof: &MountProof,
    normalized: &[&super::plan::Mount],
) -> Result<Vec<OsString>, SandboxError> {
    let mut attestation = Attestation::default();
    let mut args: Vec<OsString> = [
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--as-pid-1",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/tmp/home",
        "--dir",
        "/fx",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    // The only ordering here is structural: fixed bases provide existing alias
    // nodes; data/grant normalization has already rejected every override.
    for mount in normalized
        .iter()
        .filter(|mount| mount.role == super::plan::Role::Base)
    {
        render_mount(&mut args, &mut attestation, proof, mount)?;
    }
    for alias in &mounts.aliases {
        attestation.alias(&alias.destination, &alias.target)?;
        if alias.create {
            args.extend([
                "--symlink".into(),
                alias.target.as_os_str().into(),
                alias.destination.as_os_str().into(),
            ]);
        }
    }
    for directory in &mounts.directories {
        args.extend(["--dir".into(), directory.as_os_str().into()]);
    }
    for mount in normalized
        .iter()
        .filter(|mount| mount.role != super::plan::Role::Base)
    {
        render_mount(&mut args, &mut attestation, proof, mount)?;
    }
    let context = &sandbox.context;
    let profile = &sandbox.profile;
    for (key, value) in &profile.env {
        if matches!(key.as_str(), "FICTOR_KERNEL_SOCKET" | "FICTOR_KERNEL_URL") {
            continue;
        }
        let value = match key.as_str() {
            "HOME" => OsString::from("/tmp/home"),
            "TMPDIR" => OsString::from("/tmp"),
            "FICTOR_WORKSPACE" => translate_path(value.as_ref(), &context.tmp_dir),
            "PATH" | "PYTHONPATH" => {
                std::env::join_paths(std::env::split_paths(value).map(|path| {
                    std::path::PathBuf::from(translate_path(path.as_os_str(), &context.tmp_dir))
                }))
                .map_err(|_| SandboxError::Invalid("lista de caminhos inválida"))?
            }
            _ => value.into(),
        };
        args.extend(["--setenv".into(), key.into(), value]);
    }
    if profile.kernel_socket.is_some() {
        args.extend(["--setenv", "FICTOR_KERNEL_URL", "tcp://127.0.0.1:3129"].map(OsString::from));
    }
    args.extend(["--setenv", "LANG", "C.UTF-8"].map(OsString::from));
    args.extend([
        "--chdir".into(),
        translate_path(profile.cwd.as_os_str(), &context.tmp_dir),
    ]);
    args.extend(["/fx/fictor", "__sandbox-init", "--mount-proof"].map(OsString::from));
    args.push(attestation.encode()?.into());
    args.push("--".into());
    args.push(context.runtime.as_os_str().into());
    args.extend(runtime_arguments(sandbox, command));
    Ok(args)
}

pub(super) use super::plan::atomic_alias_target;

fn render_mount(
    args: &mut Vec<OsString>,
    attestation: &mut Attestation,
    proof: &MountProof,
    mount: &super::plan::Mount,
) -> Result<(), SandboxError> {
    attestation.bind(&mount.destination, proof.source(&mount.source)?)?;
    let option = if mount.writable {
        "--bind"
    } else if mount.optional {
        "--ro-bind-try"
    } else {
        "--ro-bind"
    };
    args.extend([
        option.into(),
        mount.source.as_os_str().into(),
        mount.destination.as_os_str().into(),
    ]);
    Ok(())
}

fn translate_path(value: &std::ffi::OsStr, temporary: &Path) -> OsString {
    if let Ok(relative) = Path::new(value).strip_prefix(temporary) {
        return if relative.as_os_str().is_empty() {
            "/tmp".into()
        } else {
            Path::new("/tmp").join(relative).into_os_string()
        };
    }
    value.to_os_string()
}

fn translate_argument(value: &std::ffi::OsStr, temporary: &Path) -> OsString {
    if let Some(value) = value.to_str() {
        // Only runtime path flags are rewritten; arbitrary extension arguments
        // may contain opaque data that happens to resemble a host path.
        if let Some((flag, paths)) = value.split_once('=')
            && matches!(flag, "--allow-fs-read" | "--allow-fs-write")
        {
            let mut result = OsString::from(flag);
            result.push("=");
            // Node grants one path per repeated flag; a comma is a literal filename.
            result.push(translate_path(paths.as_ref(), temporary));
            return result;
        }
    }
    translate_path(value, temporary)
}

fn runtime_arguments(sandbox: &ValidatedSandbox, arguments: &[OsString]) -> Vec<OsString> {
    let context = &sandbox.context;
    // The supervisor supplies permissions. Only translate Node's trusted runtime
    // flags before `--`; extension arguments remain opaque, even if flag-shaped.
    let node = context
        .runtime
        .file_name()
        // Fedora's canonical executable is named node-<major>.
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "node" || name.starts_with("node-"))
        && arguments
            .first()
            .is_some_and(|argument| argument == "--permission");
    let mut result = Vec::new();
    let mut permissions = node;
    for argument in arguments {
        if argument == "--" {
            permissions = false;
        }
        result.push(if permissions {
            translate_argument(argument, &context.tmp_dir)
        } else {
            argument.clone()
        });
    }
    result
}

pub(super) fn command(
    sandbox: &ValidatedSandbox,
    child_arguments: &[OsString],
    mounts: &super::plan::MountPlan,
    proof: &MountProof,
) -> Result<Command, SandboxError> {
    // Do not resolve a security boundary from the user's PATH or extension env.
    let executable = ["/usr/bin/bwrap", "/bin/bwrap"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .ok_or(SandboxError::Invalid(
            "bubblewrap indisponível; execute fictor doctor",
        ))?;
    let unshare = "/usr/bin/unshare";
    if !Path::new(unshare).is_file() {
        return Err(SandboxError::Invalid(
            "util-linux unshare indisponível; execute fictor doctor",
        ));
    }
    // bubblewrap makes inherited sources slaves, which can still receive host
    // submounts. Privatize an additional child namespace before its bind setup.
    // No --fork: unshare execs bwrap and preserves the supervised PID/parent.
    // This changes no mounts in the core/host namespace and adds no workload caps.
    let mut command = Command::new(unshare);
    command
        .env_clear()
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--propagation",
            "private",
            "--",
            executable,
        ])
        .args(arguments(sandbox, child_arguments, mounts, proof)?);
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::{
        ProxyEndpoint, SandboxContext, SandboxProfile, Tier, plan::ATOMIC_ALIASES,
    };
    use std::collections::BTreeMap;

    fn test_proof(sandbox: &ValidatedSandbox) -> MountProof {
        use crate::sandbox::mounts::{SnapshotEntry, SourceSnapshot};
        let mut sources: Vec<std::path::PathBuf> = [
            "/usr",
            "/etc/ssl",
            "/etc/pki",
            "/etc/ca-certificates",
            "/etc/alternatives",
            "/etc/localtime",
            "/etc/passwd",
            "/etc/group",
            "/etc/crypto-policies",
            "/etc/nsswitch.conf",
        ]
        .map(Into::into)
        .into();
        sources.extend([
            sandbox.context.bundle_root.clone(),
            sandbox.context.ext_data.clone(),
            sandbox.context.runtime_root.clone(),
            sandbox.context.fictor_exe.clone(),
            sandbox.context.fictor_home.join("extensions/store"),
        ]);
        sources.extend(sandbox.profile.read_paths.iter().cloned());
        sources.extend(sandbox.profile.write_paths.iter().cloned());
        sources.extend(sandbox.context.home_ro_files.iter().cloned());
        let ProxyEndpoint::Unix(proxy) = &sandbox.profile.proxy;
        sources.push(proxy.clone());
        sources.extend(sandbox.profile.kernel_socket.iter().cloned());
        MountProof::for_test(
            sources
                .into_iter()
                .map(|path| {
                    (
                        path,
                        Some(SourceSnapshot {
                            entries: vec![SnapshotEntry {
                                relative: Default::default(),
                                device: (0, 0),
                                inode: 1,
                                filesystem: "tmpfs".into(),
                                filesystem_magic: libc::TMPFS_MAGIC as u64,
                            }],
                            private: true,
                        }),
                    )
                })
                .collect(),
        )
    }

    fn arguments(
        sandbox: &ValidatedSandbox,
        command: &[OsString],
    ) -> Result<Vec<OsString>, SandboxError> {
        let mounts = super::super::plan::MountPlan::declare(&sandbox.profile, &sandbox.context)?;
        // Rendering tests use fictional paths. FD-backed equivalence is tested
        // in mounts/plan integration; this supplies only structural identities.
        let normalized = mounts.normalize_with(
            |outer, inner, relative| Ok(outer.source.join(relative) == inner.source),
            |_| Ok(false),
        )?;
        super::render(sandbox, command, &mounts, &test_proof(sandbox), &normalized)
    }

    #[test]
    fn atomic_aliases_only_accept_the_documented_var_targets() {
        for (alias, target) in ATOMIC_ALIASES {
            assert!(atomic_alias_target(Path::new(alias), Path::new(target)));
            assert!(atomic_alias_target(
                Path::new(alias),
                &Path::new("/").join(target)
            ));
            assert!(!atomic_alias_target(
                Path::new(alias),
                Path::new("var/private")
            ));
        }
        assert!(atomic_alias_target(
            Path::new("/usr/local"),
            Path::new("../var/usrlocal")
        ));
        assert!(!atomic_alias_target(
            Path::new("/work/link"),
            Path::new("/var/home")
        ));
        let args = arguments(&fixture(), &[]).unwrap();
        assert!(has(
            &args,
            &[
                "--ro-bind-try",
                "/etc/crypto-policies",
                "/etc/crypto-policies"
            ]
        ));
        assert!(has(
            &args,
            &["--ro-bind-try", "/etc/nsswitch.conf", "/etc/nsswitch.conf"]
        ));
        assert!(!has(&args, &["--bind", "/var", "/var"]));
        assert!(!has(&args, &["--ro-bind", "/var", "/var"]));
    }

    fn fixture() -> ValidatedSandbox {
        ValidatedSandbox {
            profile: SandboxProfile {
                read_paths: vec!["/work/input".into()],
                write_paths: vec!["/work/output".into()],
                spawn: false,
                kernel_socket: Some("/data/fictor/run/k/test.sock".into()),
                proxy: ProxyEndpoint::Unix("/data/fictor/run/proxy.sock".into()),
                env: BTreeMap::from([
                    ("HOME".into(), "/host/tmp/instance/home".into()),
                    ("TMPDIR".into(), "/host/tmp/instance".into()),
                    ("TOKEN".into(), "opaque/host/tmp/instance/value".into()),
                    (
                        "FICTOR_KERNEL_SOCKET".into(),
                        "/data/fictor/run/k/test.sock".into(),
                    ),
                ]),
                cwd: "/work/output".into(),
                tier: Tier::Os,
            },
            context: SandboxContext {
                fictor_home: "/data/fictor".into(),
                real_home: "/home/user".into(),
                bundle_root: "/data/fictor/extensions/store/test/1-hash".into(),
                ext_data: "/data/fictor/extensions/data/test".into(),
                tmp_dir: "/host/tmp/instance".into(),
                runtime: "/opt/runtime/node".into(),
                runtime_root: "/opt/runtime".into(),
                fictor_exe: "/opt/fictor".into(),
                home_ro_files: vec!["/home/user/AGENTS.md".into()],
                allow_store_read: false,
            },
        }
    }

    fn has(args: &[OsString], expected: &[&str]) -> bool {
        args.windows(expected.len())
            .any(|values| values.iter().zip(expected).all(|(a, b)| a == b))
    }

    #[test]
    fn renders_isolated_namespace_explicit_mounts_and_private_init() {
        let sandbox = fixture();
        let args = arguments(&sandbox, &["run".into()]).unwrap();
        for option in [
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--as-pid-1",
        ] {
            assert!(args.iter().any(|arg| arg == option));
        }
        assert!(has(&args, &["--tmpfs", "/tmp"]));
        assert!(has(&args, &["--ro-bind", "/work/input", "/work/input"]));
        assert!(has(&args, &["--bind", "/work/output", "/work/output"]));
        let home_target = if std::fs::read_link("/home")
            .ok()
            .is_some_and(|target| atomic_alias_target(Path::new("/home"), &target))
        {
            "/var/home/user/AGENTS.md"
        } else {
            "/home/user/AGENTS.md"
        };
        assert!(has(
            &args,
            &["--ro-bind", "/home/user/AGENTS.md", home_target]
        ));
        assert!(has(
            &args,
            &["--bind", "/data/fictor/run/proxy.sock", "/fx/proxy.sock"]
        ));
        assert!(has(
            &args,
            &["--bind", "/data/fictor/run/k/test.sock", "/fx/kernel.sock"]
        ));
        let init = args
            .windows(3)
            .position(|values| values == ["/fx/fictor", "__sandbox-init", "--mount-proof"])
            .unwrap();
        assert!(Attestation::parse(args[init + 3].to_str().unwrap()).is_ok());
        assert_eq!(&args[init + 4..], &["--", "/opt/runtime/node", "run"]);
        assert!(!args.iter().any(|arg| arg == "/home/user"
            || arg == "/data/fictor"
            || arg == "/host/tmp/instance"));
    }

    #[test]
    fn translates_temporary_paths_and_preserves_opaque_environment() {
        let mut sandbox = fixture();
        sandbox.profile.cwd = "/host/tmp/instance/home".into();
        let args = arguments(
            &sandbox,
            &[
                "--permission".into(),
                "--allow-fs-read=/work/input".into(),
                "--allow-fs-read=/host/tmp/instance".into(),
                "--".into(),
                "server.ts".into(),
            ],
        )
        .unwrap();
        assert!(has(&args, &["--setenv", "HOME", "/tmp/home"]));
        assert!(has(&args, &["--setenv", "TMPDIR", "/tmp"]));
        assert!(has(
            &args,
            &["--setenv", "FICTOR_KERNEL_URL", "tcp://127.0.0.1:3129"]
        ));
        assert!(has(
            &args,
            &["--setenv", "TOKEN", "opaque/host/tmp/instance/value"]
        ));
        assert!(has(&args, &["--chdir", "/tmp/home"]));
        assert!(args.iter().any(|arg| arg == "--allow-fs-read=/tmp"));
        assert_eq!(
            translate_path(
                "/host/tmp/instance-other".as_ref(),
                &sandbox.context.tmp_dir
            ),
            OsString::from("/host/tmp/instance-other")
        );
    }

    #[test]
    fn kernel_is_optional_and_legacy_environment_is_never_exported() {
        let mut sandbox = fixture();
        sandbox
            .profile
            .env
            .insert("FICTOR_KERNEL_URL".into(), "unix:///host/stale.sock".into());
        let present = arguments(&sandbox, &[]).unwrap();
        assert!(has(
            &present,
            &["--setenv", "FICTOR_KERNEL_URL", "tcp://127.0.0.1:3129"]
        ));
        assert!(
            !present
                .iter()
                .any(|argument| argument == "FICTOR_KERNEL_SOCKET")
        );
        sandbox.profile.kernel_socket = None;
        let absent = arguments(&sandbox, &[]).unwrap();
        assert!(
            !absent.iter().any(|argument| argument == "FICTOR_KERNEL_URL"
                || argument == "FICTOR_KERNEL_SOCKET"
                || argument == "/fx/kernel.sock")
        );
    }

    #[test]
    fn node_translates_each_permission_path_and_preserves_opaque_arguments() {
        let mut sandbox = fixture();
        sandbox.context.runtime = "/usr/bin/node-24".into();
        let command: Vec<OsString> = [
            "--permission",
            "--allow-fs-read=/host/tmp/instance/a,b",
            "--allow-fs-read=/work/input",
            "--allow-fs-write=/host/tmp/instance",
            "--",
            "server.ts",
            "--allow-fs-read=/host/tmp/instance/opaque",
            "/host/tmp/instance/opaque",
        ]
        .map(Into::into)
        .to_vec();
        let arguments = runtime_arguments(&sandbox, &command);
        assert!(has(
            &arguments,
            &[
                "--permission",
                "--allow-fs-read=/tmp/a,b",
                "--allow-fs-read=/work/input",
                "--allow-fs-write=/tmp",
            ]
        ));
        assert!(has(
            &arguments,
            &[
                "server.ts",
                "--allow-fs-read=/host/tmp/instance/opaque",
                "/host/tmp/instance/opaque"
            ]
        ));
        let absent = runtime_arguments(&sandbox, &["server.mjs".into()]);
        assert_eq!(absent, vec![OsString::from("server.mjs")]);
    }

    #[test]
    fn mounts_store_only_for_harness_and_sets_linux_locale() {
        let mut sandbox = fixture();
        let ordinary = arguments(&sandbox, &[]).unwrap();
        assert!(!has(
            &ordinary,
            &[
                "--ro-bind",
                "/data/fictor/extensions/store",
                "/data/fictor/extensions/store"
            ]
        ));
        sandbox.context.allow_store_read = true;
        let harness = arguments(&sandbox, &[]).unwrap();
        assert!(has(
            &harness,
            &[
                "--ro-bind",
                "/data/fictor/extensions/store",
                "/data/fictor/extensions/store"
            ]
        ));
        assert!(has(&harness, &["--setenv", "LANG", "C.UTF-8"]));
    }

    #[test]
    fn creates_empty_temporary_directories_and_rejects_importing_tmp_files() {
        let mut sandbox = fixture();
        let temporary = tempfile::tempdir().unwrap();
        sandbox.context.tmp_dir = temporary.path().to_path_buf();
        sandbox.profile.cwd = temporary.path().join("work");
        std::fs::create_dir(&sandbox.profile.cwd).unwrap();
        sandbox
            .profile
            .write_paths
            .push(sandbox.profile.cwd.clone());
        let args = arguments(&sandbox, &[]).unwrap();
        assert!(has(&args, &["--dir", "/tmp/work"]));
        assert!(!args.iter().any(|arg| arg == temporary.path().as_os_str()));
        let input = temporary.path().join("input");
        std::fs::write(&input, b"must not be imported").unwrap();
        sandbox.profile.read_paths.push(input);
        assert!(arguments(&sandbox, &[]).is_err());
    }
}
