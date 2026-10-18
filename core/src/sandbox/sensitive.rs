//! ADR-020: a snapshot of known credential roots and local service sockets.
//! Discovery only runs `gpgconf --list-dirs`; it never launches an agent.
//! Unknown sockets inside mounted directories remain the documented Linux
//! residual risk until the phase-3 AF_UNIX restriction.

use super::SandboxError;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    io::{self, Read},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const GPG_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_GPG_OUTPUT: usize = 64 * 1024;
const VARIABLES: &[&str] = &[
    "XDG_RUNTIME_DIR",
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
    "GNUPGHOME",
    "DOCKER_HOST",
    "DBUS_SESSION_BUS_ADDRESS",
];
const GPG_FIELDS: &[&str] = &[
    "homedir",
    "socketdir",
    "agent-socket",
    "agent-ssh-socket",
    "agent-extra-socket",
    "agent-browser-socket",
    "dirmngr-socket",
    "keyboxd-socket",
];

#[derive(Clone, Debug)]
pub struct SensitivePaths {
    paths: BTreeSet<PathBuf>,
    warnings: Vec<&'static str>,
}

#[derive(Clone, Copy, Debug)]
enum GpgFailure {
    Missing,
    Failed,
    Timeout,
    InvalidOutput,
}

impl SensitivePaths {
    /// Discover using a snapshot of the trusted core environment. Call at startup
    /// and again from doctor; callers can retain this value for repeated spawns.
    pub fn discover(real_home: &Path) -> Result<Self, SandboxError> {
        let environment = VARIABLES
            .iter()
            .filter_map(|name| std::env::var_os(name).map(|value| ((*name).into(), value)))
            .collect();
        // SAFETY: getuid has no arguments or memory-safety preconditions.
        let uid = unsafe { libc::getuid() };
        Self::collect(
            real_home,
            &environment,
            uid,
            run_gpgconf(Command::new("gpgconf"), GPG_TIMEOUT),
        )
    }

    /// Static messages only: discovery diagnostics never expose environment values.
    pub fn warnings(&self) -> &[&'static str] {
        &self.warnings
    }

    /// Reject equality, a containing grant, or any descendant of a sensitive root.
    /// Existing symlink prefixes are resolved even when the endpoint is absent.
    pub fn check_grant(&self, grant: &Path) -> Result<(), SandboxError> {
        let grant = canonical_prefix(grant)?;
        if self
            .paths
            .iter()
            .any(|sensitive| grant.starts_with(sensitive) || sensitive.starts_with(&grant))
        {
            return Err(SandboxError::Invalid("grant sobrepõe caminho sensível"));
        }
        Ok(())
    }

    /// Writing shell startup/service files or the installed core could persist
    /// code beyond this sandbox. Reads retain their independently checked grant.
    pub(super) fn check_write_grant(
        &self,
        grant: &Path,
        real_home: &Path,
        core_executable: &Path,
    ) -> Result<(), SandboxError> {
        self.check_grant(grant)?;
        let grant = canonical_prefix(grant)?;
        let core_directory = core_executable
            .parent()
            .ok_or(SandboxError::Invalid("executável do core sem diretório"))?;
        let mut protected = vec![canonical_prefix(core_directory)?];
        for relative in [
            ".local/bin",
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
            ".config/autostart",
            ".config/systemd/user",
            ".config/environment.d",
            ".local/share/applications",
        ] {
            protected.push(canonical_prefix(&real_home.join(relative))?);
        }
        if protected
            .iter()
            .any(|path| grant.starts_with(path) || path.starts_with(&grant))
        {
            return Err(SandboxError::Invalid(
                "escrita sobrepõe destino de persistência do host",
            ));
        }
        Ok(())
    }

    fn insert(&mut self, path: &Path) -> Result<(), SandboxError> {
        self.paths.insert(canonical_prefix(path)?);
        Ok(())
    }

    fn collect(
        real_home: &Path,
        environment: &BTreeMap<String, OsString>,
        uid: u32,
        gpg: Result<Vec<u8>, GpgFailure>,
    ) -> Result<Self, SandboxError> {
        let mut result = Self {
            paths: BTreeSet::new(),
            warnings: vec![],
        };
        for suffix in [
            ".ssh",
            ".gnupg",
            ".aws",
            ".kube",
            ".docker",
            ".config/gcloud",
            ".config/gh",
            ".netrc",
            ".git-credentials",
            ".local/share/keyrings",
            ".npmrc",
            ".pypirc",
            ".cargo/credentials",
            ".cargo/credentials.toml",
            ".config/containers/auth.json",
        ] {
            result.insert(&real_home.join(suffix))?;
        }
        let fallback_runtime = PathBuf::from(format!("/run/user/{uid}"));
        let runtime = match environment.get("XDG_RUNTIME_DIR").map(PathBuf::from) {
            Some(path) if path.is_absolute() => path,
            Some(path) if !path.as_os_str().is_empty() => {
                result
                    .warnings
                    .push("XDG_RUNTIME_DIR inválido; usando /run/user/<uid>");
                fallback_runtime
            }
            _ => fallback_runtime,
        };
        for path in [
            runtime.clone(),
            runtime.join("gnupg"),
            runtime.join("docker.sock"),
            runtime.join("podman/podman.sock"),
            PathBuf::from("/run"),
            PathBuf::from("/var/run"),
            PathBuf::from("/tmp/.X11-unix"),
            PathBuf::from("/run/docker.sock"),
            PathBuf::from("/run/podman/podman.sock"),
            PathBuf::from("/run/dbus/system_bus_socket"),
        ] {
            result.insert(&path)?;
        }
        for name in ["SSH_AUTH_SOCK", "GNUPGHOME"] {
            if let Some(value) = environment.get(name).filter(|value| !value.is_empty()) {
                result.insert(Path::new(value))?;
            }
        }
        // Keep protection for legacy environments while using gpgconf for modern GnuPG.
        if let Some(value) = environment.get("GPG_AGENT_INFO") {
            let value = value
                .to_str()
                .ok_or(SandboxError::Invalid("GPG_AGENT_INFO não é UTF-8"))?;
            if let Some(path) = value.split(':').next().filter(|path| !path.is_empty()) {
                result.insert(Path::new(path))?;
            }
        }
        if let Some(value) = environment.get("DOCKER_HOST") {
            let value = value
                .to_str()
                .ok_or(SandboxError::Invalid("DOCKER_HOST não é UTF-8"))?;
            if let Some(path) = value.strip_prefix("unix://") {
                result.insert(
                    &decode_path(path.as_bytes())
                        .ok_or(SandboxError::Invalid("DOCKER_HOST Unix inválido"))?,
                )?;
            }
        }
        if let Some(value) = environment.get("DBUS_SESSION_BUS_ADDRESS") {
            let value = value
                .to_str()
                .ok_or(SandboxError::Invalid("endereço D-Bus não é UTF-8"))?;
            for address in value
                .split(';')
                .filter_map(|address| address.strip_prefix("unix:"))
            {
                for field in address.split(',') {
                    if let Some(path) = field.strip_prefix("path=") {
                        result.insert(
                            &decode_path(path.as_bytes())
                                .ok_or(SandboxError::Invalid("endereço D-Bus Unix inválido"))?,
                        )?;
                    }
                }
            }
        }
        let gpg = gpg.and_then(|output| parse_gpg(&output));
        match gpg {
            Ok(paths) => {
                for path in paths { result.insert(&path)?; }
            }
            Err(failure) => result.warnings.push(match failure {
                GpgFailure::Missing => "gpgconf ausente; caminhos padrão do GnuPG protegidos, descoberta incompleta",
                GpgFailure::Timeout => "gpgconf excedeu 2 s; caminhos padrão do GnuPG protegidos, descoberta incompleta",
                GpgFailure::Failed | GpgFailure::InvalidOutput => "gpgconf falhou; caminhos padrão do GnuPG protegidos, descoberta incompleta",
            }),
        }
        Ok(result)
    }
}

fn parse_gpg(output: &[u8]) -> Result<Vec<PathBuf>, GpgFailure> {
    let mut paths = Vec::new();
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err(GpgFailure::InvalidOutput);
        };
        if GPG_FIELDS
            .iter()
            .any(|name| name.as_bytes() == &line[..colon])
        {
            // The unnamed --list-dirs form uses percent-escaped colon fields.
            // https://gnupg.org/documentation/manuals/gnupg26/gpgconf.1.html
            let value = line[colon + 1..]
                .split(|byte| *byte == b':')
                .next()
                .unwrap_or_default();
            let path = decode_path(value).ok_or(GpgFailure::InvalidOutput)?;
            if !path.is_absolute() {
                return Err(GpgFailure::InvalidOutput);
            }
            paths.push(path);
        }
    }
    if paths.is_empty() {
        return Err(GpgFailure::InvalidOutput);
    }
    Ok(paths)
}

fn decode_path(value: &[u8]) -> Option<PathBuf> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        let byte = if value[index] == b'%' {
            let high = char::from(*value.get(index + 1)?).to_digit(16)?;
            let low = char::from(*value.get(index + 2)?).to_digit(16)?;
            index += 3;
            (high * 16 + low) as u8
        } else {
            let byte = value[index];
            index += 1;
            byte
        };
        if byte == 0 {
            return None;
        }
        decoded.push(byte);
    }
    use std::os::unix::ffi::OsStringExt;
    Some(OsString::from_vec(decoded).into())
}

fn canonical_prefix(path: &Path) -> Result<PathBuf, SandboxError> {
    if !path.is_absolute() {
        return Err(SandboxError::Invalid("caminho sensível deve ser absoluto"));
    }
    // Resolve symlinks before reducing `..`: /alias/../x may have a different
    // parent from its lexical spelling when alias points outside its directory.
    let mut ancestor = path;
    loop {
        if let Ok(canonical) = ancestor.canonicalize() {
            let suffix = path
                .strip_prefix(ancestor)
                .map_err(|_| SandboxError::Invalid("prefixo sensível inválido"))?;
            let mut normalized = PathBuf::new();
            for component in canonical.join(suffix).components() {
                match component {
                    Component::ParentDir => {
                        normalized.pop();
                    }
                    Component::CurDir => {}
                    component => normalized.push(component),
                }
            }
            return Ok(normalized);
        }
        ancestor = ancestor.parent().ok_or(SandboxError::Invalid(
            "caminho sensível sem ancestral acessível",
        ))?;
    }
}

fn run_gpgconf(mut command: Command, timeout: Duration) -> Result<Vec<u8>, GpgFailure> {
    use std::os::{fd::AsRawFd, unix::process::CommandExt};
    command
        .arg("--list-dirs")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let started = Instant::now();
    let mut child = command.spawn().map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            GpgFailure::Missing
        } else {
            GpgFailure::Failed
        }
    })?;
    let outcome = (|| {
        let mut stdout = child.stdout.take().ok_or(GpgFailure::Failed)?;
        // SAFETY: stdout owns a live descriptor; fcntl only changes its read flags.
        let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                < 0
        {
            return Err(GpgFailure::Failed);
        }
        let mut output = Vec::new();
        let mut exited = None;
        let mut eof = false;
        loop {
            let mut buffer = [0; 4096];
            match stdout.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(count) => {
                    if output.len() + count > MAX_GPG_OUTPUT {
                        return Err(GpgFailure::InvalidOutput);
                    }
                    output.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(GpgFailure::Failed),
            }
            if exited.is_none() {
                exited = child.try_wait().map_err(|_| GpgFailure::Failed)?;
            }
            if let Some(status) = exited {
                if !status.success() {
                    return Err(GpgFailure::Failed);
                }
                if eof {
                    return Ok(output);
                }
            }
            if started.elapsed() >= timeout {
                return Err(GpgFailure::Timeout);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if outcome.is_err() {
        // SAFETY: process_group(0) gave this child a separate group with its PID.
        // This also closes inherited pipe writers when a timed-out command spawned children.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let _ = child.kill();
    }
    let _ = child.wait();
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(
        home: &Path,
        environment: BTreeMap<String, OsString>,
        gpg: Result<Vec<u8>, GpgFailure>,
    ) -> SensitivePaths {
        SensitivePaths::collect(home, &environment, 1234, gpg).unwrap()
    }

    #[test]
    fn rejects_write_grants_that_can_persist_code_on_the_host() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let core = root.path().join("bin/fictor");
        let paths = paths(&home, BTreeMap::new(), Err(GpgFailure::Missing));
        for relative in [
            ".local/bin",
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
            ".config/autostart",
            ".config/systemd/user",
            ".config/environment.d",
            ".local/share/applications",
        ] {
            let target = home.join(relative);
            assert!(paths.check_write_grant(&target, &home, &core).is_err());
            assert!(
                paths
                    .check_write_grant(target.parent().unwrap(), &home, &core)
                    .is_err()
            );
            assert!(
                paths
                    .check_write_grant(&target.join("child"), &home, &core)
                    .is_err()
            );
            assert!(paths.check_grant(&target).is_ok());
        }
        assert!(
            paths
                .check_write_grant(core.parent().unwrap(), &home, &core)
                .is_err()
        );
        assert!(
            paths
                .check_write_grant(&home.join("workspace"), &home, &core)
                .is_ok()
        );
    }

    #[test]
    fn protects_default_credentials_and_runtime_roots_before_creation() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let paths = paths(&home, BTreeMap::new(), Err(GpgFailure::Missing));
        for suffix in [
            ".ssh",
            ".gnupg",
            ".aws",
            ".kube",
            ".docker",
            ".config/gcloud",
            ".config/gh",
            ".netrc",
            ".git-credentials",
            ".local/share/keyrings",
            ".npmrc",
            ".pypirc",
            ".cargo/credentials",
            ".cargo/credentials.toml",
            ".config/containers/auth.json",
        ] {
            let sensitive = home.join(suffix);
            for grant in [
                sensitive.clone(),
                sensitive.join("child"),
                sensitive.parent().unwrap().into(),
            ] {
                assert!(paths.check_grant(&grant).is_err(), "{grant:?}");
            }
        }
        for grant in [
            "/run",
            "/var/run",
            "/run/user/1234",
            "/run/user/1234/podman/podman.sock",
            "/run/dbus/system_bus_socket",
            "/tmp/.X11-unix/X0",
        ] {
            assert!(paths.check_grant(Path::new(grant)).is_err(), "{grant}");
        }
        assert!(paths.check_grant(&home.join("Projects/workspace")).is_ok());
        assert!(paths.check_grant(&home.join(".ssh-backup")).is_ok());
        assert_eq!(paths.warnings().len(), 1);
    }

    #[test]
    fn discovers_ssh_docker_dbus_gnupg_and_custom_runtime_from_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let environment = BTreeMap::from([
            ("XDG_RUNTIME_DIR".into(), root.path().join("runtime").into_os_string()),
            ("SSH_AUTH_SOCK".into(), root.path().join("ssh/custom.sock").into_os_string()),
            ("GNUPGHOME".into(), root.path().join("gnupg-home").into_os_string()),
            ("GPG_AGENT_INFO".into(), format!("{}/legacy/gpg.sock:123:1", root.path().display()).into()),
            ("DOCKER_HOST".into(), format!("unix://{}/docker%20custom/socket", root.path().display()).into()),
            ("DBUS_SESSION_BUS_ADDRESS".into(), format!("tcp:host=ignored;unix:path={}/dbus%2Ccustom/socket,guid=ignored;unix:abstract=ignored", root.path().display()).into()),
        ]);
        let paths = paths(
            &root.path().join("home"),
            environment,
            Err(GpgFailure::Missing),
        );
        for relative in [
            "runtime",
            "runtime/gnupg",
            "runtime/docker.sock",
            "runtime/podman/podman.sock",
            "ssh/custom.sock",
            "gnupg-home/private",
            "legacy/gpg.sock",
            "docker custom/socket",
            "dbus,custom/socket",
        ] {
            let sensitive = root.path().join(relative);
            assert!(paths.check_grant(&sensitive).is_err(), "{relative}");
            assert!(
                paths.check_grant(sensitive.parent().unwrap()).is_err(),
                "parent {relative}"
            );
        }
        assert!(paths.check_grant(&root.path().join("ordinary")).is_ok());
    }

    #[test]
    fn gpg_output_decodes_all_normative_fields_and_ignores_executable_paths() {
        let root = tempfile::tempdir().unwrap();
        let mut output = format!("bindir:{}/ordinary\n", root.path().display());
        for field in GPG_FIELDS {
            output.push_str(&format!(
                "{field}:{}/{field}%20private/socket\n",
                root.path().display()
            ));
        }
        let paths = paths(
            &root.path().join("home"),
            BTreeMap::new(),
            Ok(output.into_bytes()),
        );
        for field in GPG_FIELDS {
            assert!(
                paths
                    .check_grant(&root.path().join(format!("{field} private/socket")))
                    .is_err()
            );
        }
        assert!(paths.check_grant(&root.path().join("ordinary")).is_ok());
        assert!(paths.warnings().is_empty());
    }

    #[test]
    fn malformed_gpg_output_falls_back_with_a_static_warning() {
        let root = tempfile::tempdir().unwrap();
        for output in [
            b"".as_slice(),
            b"not a record",
            b"homedir:relative",
            b"homedir:/bad%xx",
            b"homedir:/bad%00",
        ] {
            let paths = paths(root.path(), BTreeMap::new(), Ok(output.into()));
            assert!(paths.check_grant(&root.path().join(".gnupg")).is_err());
            assert_eq!(paths.warnings().len(), 1);
            assert!(!paths.warnings()[0].contains("bad"));
        }
    }

    #[test]
    fn resolves_symlink_prefix_even_if_sensitive_socket_does_not_exist_yet() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("actual")).unwrap();
        symlink(root.path().join("actual"), root.path().join("alias")).unwrap();
        let paths = paths(
            &root.path().join("home"),
            BTreeMap::from([(
                "SSH_AUTH_SOCK".into(),
                root.path().join("alias/later/socket").into_os_string(),
            )]),
            Err(GpgFailure::Missing),
        );
        for relative in [
            "actual",
            "actual/later",
            "actual/later/socket",
            "actual/later/socket/child",
            "alias/later/socket",
        ] {
            assert!(
                paths.check_grant(&root.path().join(relative)).is_err(),
                "{relative}"
            );
        }
        std::fs::create_dir(root.path().join("actual/child")).unwrap();
        symlink(
            root.path().join("actual/child"),
            root.path().join("parent-alias"),
        )
        .unwrap();
        let paths = self::paths(
            &root.path().join("home"),
            BTreeMap::from([(
                "SSH_AUTH_SOCK".into(),
                root.path().join("parent-alias/../socket").into_os_string(),
            )]),
            Err(GpgFailure::Missing),
        );
        assert!(
            paths
                .check_grant(&root.path().join("actual/socket"))
                .is_err()
        );
    }

    #[test]
    fn gpg_command_has_only_list_dirs_and_is_bounded_without_environment_mutation() {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "test \"$1\" = --list-dirs && test \"$#\" = 1 && printf 'homedir:/fake/private\\n'",
            "probe",
        ]);
        assert_eq!(
            run_gpgconf(command, GPG_TIMEOUT).unwrap(),
            b"homedir:/fake/private\n"
        );
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 5", "probe"]);
        let started = Instant::now();
        assert!(matches!(
            run_gpgconf(command, Duration::from_millis(100)),
            Err(GpgFailure::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(matches!(
            run_gpgconf(
                Command::new("/nonexistent/fictor-gpgconf-test"),
                GPG_TIMEOUT
            ),
            Err(GpgFailure::Missing)
        ));
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exit 1", "probe"]);
        assert!(matches!(
            run_gpgconf(command, GPG_TIMEOUT),
            Err(GpgFailure::Failed)
        ));
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "head -c 70000 /dev/zero", "probe"]);
        assert!(matches!(
            run_gpgconf(command, GPG_TIMEOUT),
            Err(GpgFailure::InvalidOutput)
        ));
    }
}
