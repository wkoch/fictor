//! Bubblewrap's mount namespace is built from a small base plus validated grants.
use std::process::Command;
use std::{collections::BTreeSet, ffi::OsString, path::Path};

use super::{ProxyEndpoint, SandboxError, ValidatedSandbox};

pub(super) fn arguments(
    sandbox: &ValidatedSandbox,
    command: &[OsString],
) -> Result<Vec<OsString>, SandboxError> {
    let ProxyEndpoint::Unix(proxy) = &sandbox.profile.proxy;
    let mut args: Vec<OsString> = [
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--as-pid-1",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    mount(&mut args, "--ro-bind", Path::new("/usr"), Path::new("/usr"));
    for (target, link) in [
        ("usr/bin", "/bin"),
        ("usr/sbin", "/sbin"),
        ("usr/lib", "/lib"),
        ("usr/lib64", "/lib64"),
    ] {
        args.extend(["--symlink".into(), target.into(), link.into()]);
    }
    for path in [
        "/etc/ssl",
        "/etc/pki",
        "/etc/ca-certificates",
        "/etc/alternatives",
        "/etc/localtime",
        "/etc/passwd",
        "/etc/group",
        "/etc/crypto-policies",
        "/etc/nsswitch.conf",
    ] {
        mount(&mut args, "--ro-bind-try", Path::new(path), Path::new(path));
    }
    // Reproduce only Fedora Atomic's trusted root aliases. Their /var targets
    // remain empty unless a specific canonical runtime/workspace grant mounts them.
    for (alias, target) in ATOMIC_ALIASES {
        if std::fs::read_link(alias)
            .ok()
            .is_some_and(|link| atomic_alias_target(Path::new(alias), &link))
        {
            args.extend(["--symlink".into(), (*target).into(), (*alias).into()]);
        }
    }
    args.extend(
        [
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
        .map(OsString::from),
    );
    let context = &sandbox.context;
    let profile = &sandbox.profile;
    for path in profile.read_paths.iter().chain(&profile.write_paths) {
        if path.starts_with(&context.tmp_dir) && !path.is_dir() {
            return Err(SandboxError::Invalid(
                "Linux tmp aceita só diretórios; entradas devem estar no bundle ou data",
            ));
        }
    }
    // The instance tmp is fresh tmpfs; reproduce directory structure, never host contents.
    for path in profile
        .read_paths
        .iter()
        .chain(&profile.write_paths)
        .chain(std::iter::once(&profile.cwd))
    {
        if path.starts_with(&context.tmp_dir) && path.is_dir() {
            args.extend([
                "--dir".into(),
                translate_path(path.as_os_str(), &context.tmp_dir),
            ]);
        }
    }
    if !context.runtime_root.starts_with("/usr") {
        mount(
            &mut args,
            "--ro-bind",
            &context.runtime_root,
            &context.runtime_root,
        );
    }
    mount(
        &mut args,
        "--ro-bind",
        &context.bundle_root,
        &context.bundle_root,
    );
    let writes: BTreeSet<_> = profile.write_paths.iter().collect();
    let mut reads: BTreeSet<_> = profile
        .read_paths
        .iter()
        .chain(&context.home_ro_files)
        .collect();
    let store = context.fictor_home.join("extensions/store");
    if context.allow_store_read {
        reads.insert(&store);
    }
    for path in reads {
        if !path.starts_with(&context.tmp_dir)
            && !writes.contains(path)
            && path != &context.ext_data
        {
            mount(&mut args, "--ro-bind", path, path);
        }
    }
    // Writes are mounted last so a narrower read grant cannot hide a write grant.
    mount(&mut args, "--bind", &context.ext_data, &context.ext_data);
    for path in writes {
        if !path.starts_with(&context.tmp_dir) && path != &context.ext_data {
            mount(&mut args, "--bind", path, path);
        }
    }
    mount(
        &mut args,
        "--ro-bind",
        &context.fictor_exe,
        Path::new("/fx/fictor"),
    );
    mount(&mut args, "--bind", proxy, Path::new("/fx/proxy.sock"));
    if let Some(socket) = &profile.kernel_socket {
        mount(&mut args, "--bind", socket, Path::new("/fx/kernel.sock"));
    }
    for (key, value) in &profile.env {
        if matches!(key.as_str(), "FICTOR_KERNEL_SOCKET" | "FICTOR_KERNEL_URL") {
            continue;
        }
        let value = match key.as_str() {
            "HOME" => OsString::from("/tmp/home"),
            "TMPDIR" => OsString::from("/tmp"),
            "DENO_DIR" | "FICTOR_WORKSPACE" => translate_path(value.as_ref(), &context.tmp_dir),
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
    args.extend(["/fx/fictor", "__sandbox-init", "--"].map(OsString::from));
    args.push(context.runtime.as_os_str().into());
    args.extend(runtime_arguments(sandbox, command));
    Ok(args)
}

const ATOMIC_ALIASES: &[(&str, &str)] = &[
    ("/home", "var/home"),
    ("/opt", "var/opt"),
    ("/srv", "var/srv"),
    ("/mnt", "var/mnt"),
    ("/root", "var/roothome"),
];

pub(super) fn atomic_alias_target(alias: &Path, target: &Path) -> bool {
    ATOMIC_ALIASES.iter().any(|(path, relative)| {
        alias == Path::new(path)
            && (target == Path::new(relative) || target == Path::new("/").join(relative))
    }) || (alias == Path::new("/usr/local")
        && matches!(target.to_str(), Some("../var/usrlocal" | "/var/usrlocal")))
}

fn mount(args: &mut Vec<OsString>, option: &str, source: &Path, target: &Path) {
    args.extend([
        option.into(),
        source.as_os_str().into(),
        target.as_os_str().into(),
    ]);
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
            && matches!(
                flag,
                "--allow-read" | "--allow-write" | "--deny-read" | "--deny-write"
            )
        {
            let paths: Vec<_> = paths
                .split(',')
                .map(|path| translate_path(path.as_ref(), temporary))
                .collect();
            let mut result = OsString::from(flag);
            result.push("=");
            for (index, path) in paths.iter().enumerate() {
                if index > 0 {
                    result.push(",");
                }
                result.push(path);
            }
            return result;
        }
    }
    translate_path(value, temporary)
}

fn runtime_arguments(sandbox: &ValidatedSandbox, arguments: &[OsString]) -> Vec<OsString> {
    let context = &sandbox.context;
    let kernel = sandbox.profile.kernel_socket.as_deref();
    // M0.5's supervisor constructs exact runtime-kind-specific permissions. This
    // internal launcher recognizes the standard Deno executable/run shape only.
    let deno = context
        .runtime
        .file_name()
        .is_some_and(|name| name == "deno")
        && arguments.first().is_some_and(|argument| argument == "run");
    let mut result = Vec::new();
    let mut permissions = deno;
    let mut network = Vec::<String>::new();
    let mut unrestricted_network = false;
    for (index, argument) in arguments.iter().enumerate() {
        let value = argument.to_str();
        if value == Some("--") {
            permissions = false;
        }
        if permissions && index > 0 && !value.is_some_and(|value| value.starts_with('-')) {
            permissions = false;
        }
        if permissions && let Some(value) = value {
            if value == "--allow-net" {
                unrestricted_network = true;
            } else if let Some(hosts) = value.strip_prefix("--allow-net=") {
                network.extend(
                    hosts
                        .split(',')
                        .filter(|host| !host.is_empty())
                        .map(str::to_owned),
                );
                continue;
            }
            if let Some((flag, paths)) = value.split_once('=')
                && matches!(flag, "--allow-read" | "--allow-write")
            {
                let paths: Vec<_> = paths
                    .split(',')
                    .filter(|path| {
                        *path != "/fx/kernel.sock"
                            && !kernel.is_some_and(|socket| Path::new(path) == socket)
                    })
                    .collect();
                // An empty Deno allow flag could grant everything; omit it instead.
                if !paths.is_empty() {
                    let flag = format!("{flag}={}", paths.join(","));
                    result.push(translate_argument(flag.as_ref(), &context.tmp_dir));
                }
                continue;
            }
        }
        result.push(translate_argument(argument, &context.tmp_dir));
    }
    if deno && !unrestricted_network {
        if kernel.is_some() && !network.iter().any(|host| host == "127.0.0.1:3129") {
            network.push("127.0.0.1:3129".into());
        }
        if !network.is_empty() {
            // Deno permissions must precede the entrypoint and its opaque arguments.
            result.insert(1, format!("--allow-net={}", network.join(",")).into());
        }
    }
    result
}

pub(super) fn command(
    sandbox: &ValidatedSandbox,
    child_arguments: &[OsString],
) -> Result<Command, SandboxError> {
    // Do not resolve a security boundary from the user's PATH or extension env.
    let executable = ["/usr/bin/bwrap", "/bin/bwrap"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .ok_or(SandboxError::Invalid(
            "bubblewrap indisponível; execute fictor doctor",
        ))?;
    let mut command = Command::new(executable);
    command
        .env_clear()
        .args(arguments(sandbox, child_arguments)?);
    use std::os::unix::process::CommandExt;
    command.process_group(0);
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::{SandboxContext, SandboxProfile, Tier};
    use std::collections::BTreeMap;

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
                    ("DENO_DIR".into(), "/host/tmp/instance/deno".into()),
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
                runtime: "/opt/runtime/deno".into(),
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
        assert!(has(
            &args,
            &["--ro-bind", "/home/user/AGENTS.md", "/home/user/AGENTS.md"]
        ));
        assert!(has(
            &args,
            &["--bind", "/data/fictor/run/proxy.sock", "/fx/proxy.sock"]
        ));
        assert!(has(
            &args,
            &["--bind", "/data/fictor/run/k/test.sock", "/fx/kernel.sock"]
        ));
        assert!(has(
            &args,
            &[
                "/fx/fictor",
                "__sandbox-init",
                "--",
                "/opt/runtime/deno",
                "run"
            ]
        ));
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
                "run".into(),
                "--allow-read=/work/input,/host/tmp/instance,/data/fictor/run/k/test.sock".into(),
                "server.ts".into(),
            ],
        )
        .unwrap();
        assert!(has(&args, &["--setenv", "HOME", "/tmp/home"]));
        assert!(has(&args, &["--setenv", "TMPDIR", "/tmp"]));
        assert!(has(&args, &["--setenv", "DENO_DIR", "/tmp/deno"]));
        assert!(has(
            &args,
            &["--setenv", "FICTOR_KERNEL_URL", "tcp://127.0.0.1:3129"]
        ));
        assert!(has(
            &args,
            &["--setenv", "TOKEN", "opaque/host/tmp/instance/value"]
        ));
        assert!(has(&args, &["--chdir", "/tmp/home"]));
        assert!(
            args.iter()
                .any(|arg| arg == "--allow-read=/work/input,/tmp")
        );
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
    fn deno_uses_kernel_network_permission_without_socket_filesystem_grants() {
        let mut sandbox = fixture();
        let command: Vec<OsString> = [
            "run",
            "--allow-net=127.0.0.1:3128,example.test",
            "--allow-read=/data/fictor/run/k/test.sock",
            "--allow-write=/fx/kernel.sock,/work/output",
            "server.ts",
            "--allow-read=/data/fictor/run/k/test.sock",
        ]
        .map(Into::into)
        .to_vec();
        let arguments = runtime_arguments(&sandbox, &command);
        assert!(has(
            &arguments,
            &[
                "run",
                "--allow-net=127.0.0.1:3128,example.test,127.0.0.1:3129"
            ]
        ));
        assert!(
            arguments
                .iter()
                .any(|argument| argument == "--allow-write=/work/output")
        );
        assert!(has(
            &arguments,
            &["server.ts", "--allow-read=/data/fictor/run/k/test.sock"]
        ));
        assert_eq!(
            arguments
                .iter()
                .filter(|argument| *argument == "--allow-read=/data/fictor/run/k/test.sock")
                .count(),
            1
        );
        assert!(
            !arguments
                .iter()
                .any(|argument| argument == "--allow-read=" || argument == "--allow-write=")
        );
        sandbox.profile.kernel_socket = None;
        let absent = runtime_arguments(&sandbox, &["run".into(), "server.ts".into()]);
        assert_eq!(
            absent,
            vec![OsString::from("run"), OsString::from("server.ts")]
        );
        sandbox.context.runtime = "/opt/runtime/node".into();
        let node = runtime_arguments(&sandbox, &["server.js".into()]);
        assert_eq!(node, vec![OsString::from("server.js")]);
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
