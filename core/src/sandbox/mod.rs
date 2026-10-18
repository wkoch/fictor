//! OS confinement. Inputs are constructed by the trusted supervisor, never an extension.
pub mod admission;
mod attestation;
pub mod init;
pub mod linux;
pub(crate) mod mounts;
mod plan;
mod pre_exec;
pub mod sensitive;

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::File,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub enum ProxyEndpoint {
    Unix(PathBuf),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Os,
}

pub struct SandboxProfile {
    pub read_paths: Vec<PathBuf>,
    pub write_paths: Vec<PathBuf>,
    pub spawn: bool,
    pub kernel_socket: Option<PathBuf>,
    pub proxy: ProxyEndpoint,
    pub env: BTreeMap<String, String>,
    pub cwd: PathBuf,
    pub tier: Tier,
}

/// Trusted launch inputs; role/template resolution belongs to the supervisor (M0.5).
pub struct SandboxContext {
    pub fictor_home: PathBuf,
    pub real_home: PathBuf,
    pub bundle_root: PathBuf,
    pub ext_data: PathBuf,
    pub tmp_dir: PathBuf,
    pub runtime: PathBuf,
    pub runtime_root: PathBuf,
    pub fictor_exe: PathBuf,
    pub home_ro_files: Vec<PathBuf>,
    pub allow_store_read: bool,
}

pub(super) struct ValidatedSandbox {
    pub profile: SandboxProfile,
    pub context: SandboxContext,
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("erro de arquivo do sandbox: {0}")]
    Io(#[from] std::io::Error),
    #[error("perfil de sandbox inválido: {0}")]
    Invalid(&'static str),
    #[error("origem {resource:?}: filesystem {filesystem}, regra {rule}")]
    Origin {
        resource: PathBuf,
        filesystem: String,
        rule: &'static str,
    },
}

pub struct SandboxPlan {
    validated: ValidatedSandbox,
    arguments: Vec<OsString>,
    home: File,
    proof: Mutex<Vec<Arc<mounts::MountProof>>>,
}

impl SandboxPlan {
    pub fn new(
        profile: SandboxProfile,
        context: SandboxContext,
        arguments: Vec<OsString>,
    ) -> Result<Self, SandboxError> {
        let home = mounts::pin_home(&context.fictor_home)?;
        Self::with_home(profile, context, arguments, home)
    }

    pub(crate) fn new_anchored(
        profile: SandboxProfile,
        context: SandboxContext,
        arguments: Vec<OsString>,
        home: &File,
    ) -> Result<Self, SandboxError> {
        Self::with_home(profile, context, arguments, home.try_clone()?)
    }

    fn with_home(
        profile: SandboxProfile,
        context: SandboxContext,
        arguments: Vec<OsString>,
        home: File,
    ) -> Result<Self, SandboxError> {
        let validated = validate(profile, context, &home)?;
        let (_, proof) = check_mounts(&validated.profile, &validated.context, &home, None)?;
        Ok(Self {
            validated,
            arguments,
            home,
            proof: Mutex::new(vec![Arc::new(proof)]),
        })
    }

    /// Legacy raw backend without the durable admission barrier. Production
    /// callers migrate to command_with_admission before ADR-038 is complete.
    /// Keep this plan alive until reap; Command alone is not an inode lease.
    pub fn command(&self) -> Result<Command, SandboxError> {
        self.command_inner(None)
    }

    /// Trusted core admission channel, included in the same validated mount
    /// plan and final proof. The caller retains the listener through accept,
    /// persists armed for its exact peer, then explicitly releases the init.
    pub fn command_with_admission(
        &self,
        admission: &admission::AdmissionListener,
    ) -> Result<Command, SandboxError> {
        admission.verify()?;
        self.command_inner(Some(admission.socket_path()))
    }

    fn command_inner(&self, admission: Option<&Path>) -> Result<Command, SandboxError> {
        let (mounts, proof) = check_mounts(
            &self.validated.profile,
            &self.validated.context,
            &self.home,
            admission,
        )?;
        let proof = Arc::new(proof);
        self.proof
            .lock()
            .map_err(|_| SandboxError::Invalid("prova de montagem indisponível"))?
            .push(proof.clone());
        linux::command(&self.validated, &self.arguments, &mounts, &proof)
    }

    pub fn linux_arguments(&self) -> Result<Vec<OsString>, SandboxError> {
        let (mounts, proof) = check_mounts(
            &self.validated.profile,
            &self.validated.context,
            &self.home,
            None,
        )?;
        let proof = Arc::new(proof);
        self.proof
            .lock()
            .map_err(|_| SandboxError::Invalid("prova de montagem indisponível"))?
            .push(proof.clone());
        linux::arguments(&self.validated, &self.arguments, &mounts, &proof)
    }
}

fn validate(
    mut profile: SandboxProfile,
    mut context: SandboxContext,
    home: &File,
) -> Result<ValidatedSandbox, SandboxError> {
    context.fictor_home = directory(&context.fictor_home)?;
    context.real_home = directory(&context.real_home)?;
    context.bundle_root = directory(&context.bundle_root)?;
    context.ext_data = directory(&context.ext_data)?;
    context.tmp_dir = directory(&context.tmp_dir)?;
    context.runtime = regular_file(&context.runtime)?;
    context.runtime_root = directory(&context.runtime_root)?;
    context.fictor_exe = regular_file(&context.fictor_exe)?;
    if context.fictor_home.parent().is_none() || context.real_home.parent().is_none() {
        return Err(SandboxError::Invalid("raízes privadas não podem ser /"));
    }
    let store = context.fictor_home.join("extensions/store");
    let quarantine = context.fictor_home.join("extensions/quarantine");
    if context.allow_store_read && directory(&store)? != store {
        return Err(SandboxError::Invalid(
            "store deve ser um diretório canônico sem redirecionamento",
        ));
    }
    if !(strictly_below(&context.bundle_root, &store)
        || strictly_below(&context.bundle_root, &quarantine))
        || !strictly_below(
            &context.ext_data,
            &context.fictor_home.join("extensions/data"),
        )
    {
        return Err(SandboxError::Invalid(
            "bundle e dados devem estar nos diretórios próprios",
        ));
    }
    // Bundled native executables share only their own already-authorized bundle.
    // No enclosing quarantine/store/core directory becomes a runtime installation.
    let own_bundle_runtime = context.runtime_root == context.bundle_root
        && strictly_below(&context.runtime, &context.bundle_root);
    if !context.runtime.starts_with(&context.runtime_root)
        || context.runtime_root.parent().is_none()
        || (overlaps(&context.runtime_root, &context.fictor_home) && !own_bundle_runtime)
        || context.runtime_root == context.real_home
        || context.real_home.starts_with(&context.runtime_root)
        || (overlaps(&context.tmp_dir, &context.fictor_home) && !journal_temporary(&context))
        || overlaps(&context.tmp_dir, &context.runtime_root)
        || context.tmp_dir == context.real_home
        || context.real_home.starts_with(&context.tmp_dir)
    {
        return Err(SandboxError::Invalid(
            "diretórios de runtime/tmp expõem ou sobrepõem dados protegidos",
        ));
    }
    // Normative base mounts cannot hide an arbitrarily relocated private core directory.
    for base in ["/usr", "/etc"] {
        if let Ok(base) = Path::new(base).canonicalize()
            && (context.fictor_home.starts_with(&base) || context.real_home.starts_with(&base))
        {
            return Err(SandboxError::Invalid(
                "diretórios privados não podem ficar sob mounts de sistema",
            ));
        }
    }
    context.home_ro_files = context
        .home_ro_files
        .iter()
        .map(|path| regular_file(path))
        .collect::<Result<_, _>>()?;
    let sensitive = sensitive::SensitivePaths::discover(&context.real_home)?;
    for warning in sensitive.warnings() {
        tracing::warn!("{warning}");
    }
    // Implicit mounts are grants too, even when no fs.read/fs.write entry names them.
    for path in [
        &context.bundle_root,
        &context.ext_data,
        &context.tmp_dir,
        &context.runtime_root,
        &context.fictor_exe,
    ]
    .into_iter()
    .chain(context.home_ro_files.iter())
    {
        sensitive.check_grant(path)?;
    }
    for writable in [&context.ext_data, &context.tmp_dir] {
        sensitive.check_write_grant(writable, &context.real_home, &context.fictor_exe)?;
        if overlaps(writable, &context.bundle_root)
            || overlaps(writable, &context.runtime_root)
            || overlaps(writable, &context.fictor_exe)
            || context
                .home_ro_files
                .iter()
                .any(|file| overlaps(writable, file))
        {
            return Err(SandboxError::Invalid(
                "diretórios graváveis sobrepõem código ou arquivos somente leitura",
            ));
        }
    }
    for path in &context.home_ro_files {
        if !strictly_below(path, &context.real_home) || path.starts_with(&context.fictor_home) {
            return Err(SandboxError::Invalid(
                "home_ro_files deve conter apenas arquivos do HOME fora do core",
            ));
        }
    }
    profile.cwd = directory(&profile.cwd)?;
    profile.read_paths = profile
        .read_paths
        .iter()
        .map(|path| canonical_grant(path))
        .collect::<Result<_, _>>()?;
    profile.write_paths = profile
        .write_paths
        .iter()
        .map(|path| canonical_grant(path))
        .collect::<Result<_, _>>()?;
    profile
        .read_paths
        .extend(context.home_ro_files.iter().cloned());
    if let Some(path) = &profile.kernel_socket {
        let canonical = socket(path)?;
        if !strictly_below(&canonical, &context.fictor_home.join("run/k")) {
            return Err(SandboxError::Invalid("socket de kernel fora de run/k"));
        }
        profile.kernel_socket = Some(canonical);
    }
    profile.proxy = match &profile.proxy {
        ProxyEndpoint::Unix(path) => {
            let canonical = socket(path)?;
            if canonical != context.fictor_home.join("run/proxy.sock") {
                return Err(SandboxError::Invalid(
                    "socket de proxy fora de run/proxy.sock",
                ));
            }
            ProxyEndpoint::Unix(canonical)
        }
    };
    for path in &profile.read_paths {
        validate_grant(path, &context, &sensitive, false)?;
    }
    for path in &profile.write_paths {
        validate_grant(path, &context, &sensitive, true)?;
        if overlaps(path, &context.bundle_root)
            || overlaps(path, &context.runtime_root)
            || overlaps(path, &context.fictor_exe)
            || context
                .home_ro_files
                .iter()
                .any(|file| overlaps(path, file))
        {
            return Err(SandboxError::Invalid(
                "escrita sobrepõe código ou arquivos somente leitura",
            ));
        }
    }
    if ![&context.bundle_root, &context.ext_data, &context.tmp_dir]
        .into_iter()
        .chain(profile.read_paths.iter())
        .chain(profile.write_paths.iter())
        .any(|allowed| profile.cwd.starts_with(allowed))
    {
        return Err(SandboxError::Invalid("cwd fora dos caminhos permitidos"));
    }
    if profile
        .env
        .iter()
        .any(|(key, value)| key.is_empty() || key.contains(['=', '\0']) || value.contains('\0'))
    {
        return Err(SandboxError::Invalid(
            "ambiente contém nome ou valor inválido",
        ));
    }
    check_mounts(&profile, &context, home, None)?;
    let tmp_home = context.tmp_dir.join("home");
    crate::home::private_dir(&tmp_home)?;
    let utf8 = |path: &Path| {
        path.to_str()
            .map(str::to_owned)
            .ok_or(SandboxError::Invalid(
                "caminhos de ambiente devem ser UTF-8",
            ))
    };
    profile.env.insert("HOME".into(), utf8(&tmp_home)?);
    profile.env.insert("TMPDIR".into(), utf8(&context.tmp_dir)?);
    profile.env.insert("LANG".into(), "C.UTF-8".into());
    profile.env.insert("NO_PROXY".into(), String::new());
    profile.env.insert("no_proxy".into(), String::new());
    profile.env.insert("NODE_USE_ENV_PROXY".into(), "1".into());
    let path = vec![
        context
            .runtime
            .parent()
            .ok_or(SandboxError::Invalid("runtime sem diretório"))?
            .to_path_buf(),
        "/usr/bin".into(),
        "/bin".into(),
    ];
    profile.env.insert(
        "PATH".into(),
        std::env::join_paths(path)
            .map_err(|_| SandboxError::Invalid("PATH inválido"))?
            .into_string()
            .map_err(|_| SandboxError::Invalid("PATH deve ser UTF-8"))?,
    );
    Ok(ValidatedSandbox { profile, context })
}

fn check_mounts(
    profile: &SandboxProfile,
    context: &SandboxContext,
    home: &File,
    admission: Option<&Path>,
) -> Result<(plan::MountPlan, mounts::MountProof), SandboxError> {
    let mut boundary = mounts::Boundary::new(&context.fictor_home, home)?;
    let mut proof = mounts::MountProof::default();
    boundary.protect_temporary(&context.tmp_dir, &mut proof)?;
    let plan = match admission {
        Some(socket) => plan::MountPlan::declare_with_admission(profile, context, Some(socket))?,
        None => plan::MountPlan::declare(profile, context)?,
    };
    let mut done = std::collections::BTreeSet::new();
    for index in 0..plan.mounts.len() {
        prove_mount(index, &plan, context, &boundary, &mut proof, &mut done)?;
    }
    boundary.finish()?;
    plan.normalized(&proof)?;
    Ok((plan, proof))
}

fn prove_mount(
    index: usize,
    plan: &plan::MountPlan,
    context: &SandboxContext,
    boundary: &mounts::Boundary,
    proof: &mut mounts::MountProof,
    done: &mut std::collections::BTreeSet<usize>,
) -> Result<(), SandboxError> {
    if done.contains(&index) {
        return Ok(());
    }
    let request = &plan.mounts[index];
    let store = context.fictor_home.join("extensions/store");
    let mut exceptions = Vec::new();
    if request.source.starts_with(&context.ext_data) {
        exceptions.push(context.ext_data.as_path());
    }
    if !request.writable && request.source.starts_with(&context.bundle_root) {
        exceptions.push(context.bundle_root.as_path());
    }
    if !request.writable && context.allow_store_read && request.source.starts_with(&store) {
        exceptions.push(store.as_path());
    }
    if request.role == plan::Role::Endpoint {
        exceptions.push(request.source.as_path());
    }
    let result = if let Some(outer) = plan.covering(index) {
        prove_mount(outer, plan, context, boundary, proof, done)?;
        boundary.prove_covered(
            &request.source,
            &exceptions,
            &plan.mounts[outer].source,
            proof,
        )
    } else {
        boundary.prove(&request.source, &exceptions, request.purpose())
    };
    match result {
        Ok(proven) => proof.record(request.source.clone(), Some(proven))?,
        Err(SandboxError::Io(error))
            if request.optional && error.kind() == std::io::ErrorKind::NotFound =>
        {
            proof.record(request.source.clone(), None)?
        }
        Err(error) => return Err(error),
    }
    done.insert(index);
    Ok(())
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn journal_temporary(context: &SandboxContext) -> bool {
    // ADR-038's exact private preparation directory is not an imported mount.
    // Boundary::protect_temporary still seals its physical origin against every
    // ordinary import/alias; no other home descendant gets this exception.
    let Some(instance) = context.tmp_dir.parent() else {
        return false;
    };
    context.tmp_dir.file_name() == Some("tmp".as_ref())
        && instance.parent() == Some(context.fictor_home.join("run/instances").as_path())
        && instance
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.parse::<ulid::Ulid>()
                    .is_ok_and(|id| id.to_string() == name)
            })
}
fn strictly_below(path: &Path, root: &Path) -> bool {
    path != root && path.starts_with(root)
}
fn canonical(path: &Path) -> Result<PathBuf, SandboxError> {
    if !path.is_absolute() {
        return Err(SandboxError::Invalid("caminho deve ser absoluto"));
    }
    mounts::canonicalize(path)
}
fn directory(path: &Path) -> Result<PathBuf, SandboxError> {
    let path = canonical(path)?;
    if !path.is_dir() {
        return Err(SandboxError::Invalid("diretório esperado"));
    }
    Ok(path)
}
fn regular_file(path: &Path) -> Result<PathBuf, SandboxError> {
    let path = canonical(path)?;
    if !path.is_file() {
        return Err(SandboxError::Invalid("arquivo regular esperado"));
    }
    Ok(path)
}
fn socket(path: &Path) -> Result<PathBuf, SandboxError> {
    let path = canonical(path)?;
    use std::os::unix::fs::FileTypeExt;
    if !std::fs::metadata(&path)?.file_type().is_socket() {
        return Err(SandboxError::Invalid("socket Unix esperado"));
    }
    Ok(path)
}
fn canonical_grant(path: &Path) -> Result<PathBuf, SandboxError> {
    let resolved = canonical(path)?;
    // Trusted Linux system aliases are normalized; user-created symlinks
    // must be resolved by the supervisor's template boundary check before reaching this API.
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        if std::fs::symlink_metadata(&prefix)?.file_type().is_symlink()
            && !matches!(
                prefix.to_str(),
                Some("/var" | "/tmp" | "/etc" | "/bin" | "/sbin" | "/lib" | "/lib64")
            )
            && !std::fs::read_link(&prefix)
                .ok()
                .is_some_and(|target| linux::atomic_alias_target(&prefix, &target))
        {
            return Err(SandboxError::Invalid("grant contém symlink não resolvido"));
        }
    }
    let metadata = std::fs::metadata(&resolved)?;
    if !metadata.is_dir() && !metadata.is_file() {
        return Err(SandboxError::Invalid(
            "grant deve ser arquivo ou diretório regular",
        ));
    }
    Ok(resolved)
}
fn validate_grant(
    path: &Path,
    context: &SandboxContext,
    sensitive: &sensitive::SensitivePaths,
    writable: bool,
) -> Result<(), SandboxError> {
    if path.parent().is_none() || path == context.real_home || context.real_home.starts_with(path) {
        return Err(SandboxError::Invalid("grant expõe / ou HOME inteiro"));
    }
    if overlaps(path, &context.fictor_home) {
        let data = path.starts_with(&context.ext_data);
        let bundle = !writable && path.starts_with(&context.bundle_root);
        let store = !writable
            && context.allow_store_read
            && path.starts_with(context.fictor_home.join("extensions/store"));
        if !(data || bundle || store) {
            return Err(SandboxError::Invalid(
                "grant expõe arquivos privados do core",
            ));
        }
    }
    if writable {
        sensitive.check_write_grant(path, &context.real_home, &context.fictor_exe)
    } else {
        sensitive.check_grant(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_grants_follow_installed_atomic_system_aliases() {
        for alias in ["/home", "/opt", "/srv", "/mnt", "/root", "/usr/local"] {
            let path = Path::new(alias);
            if std::fs::read_link(path)
                .ok()
                .is_some_and(|target| linux::atomic_alias_target(path, &target))
                && path.is_dir()
            {
                assert_eq!(canonical_grant(path).unwrap(), path.canonicalize().unwrap());
            }
        }
    }
}
