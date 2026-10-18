//! One core-owned description of mounts, reservations and alias routing.
//! Validation and rendering consume this same description (ADR-044).
use super::{ProxyEndpoint, SandboxContext, SandboxError, SandboxProfile, mounts::MountProof};
use std::{
    collections::BTreeSet,
    path::{Component, Path, PathBuf},
};

pub(super) const BASES: &[&str] = &[
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
];

/// Only the core assigns this purpose. A grant never chooses a base exception.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SourcePurpose {
    SystemBase,
    Bootstrap,
    Ordinary,
    Endpoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    Base,
    Runtime,
    Bundle,
    Store,
    ExtData,
    HomeRead,
    Grant,
    Bootstrap,
    Endpoint,
}

#[derive(Clone, Debug)]
pub(super) struct Mount {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub writable: bool,
    pub optional: bool,
    pub role: Role,
}
impl Mount {
    pub fn purpose(&self) -> SourcePurpose {
        match self.role {
            Role::Base => SourcePurpose::SystemBase,
            Role::Bootstrap => SourcePurpose::Bootstrap,
            Role::Endpoint => SourcePurpose::Endpoint,
            _ => SourcePurpose::Ordinary,
        }
    }
    fn grant(&self) -> bool {
        matches!(self.role, Role::Grant | Role::HomeRead)
    }
}

#[derive(Clone, Debug)]
pub(super) struct Alias {
    pub destination: PathBuf,
    pub target: PathBuf,
    pub create: bool,
}

pub(super) struct MountPlan {
    pub mounts: Vec<Mount>,
    pub aliases: Vec<Alias>,
    pub directories: BTreeSet<PathBuf>,
}

fn invalid() -> SandboxError {
    SandboxError::Invalid(
        "destino de montagem reservado, sobreposto ou sem equivalência comprovada",
    )
}
fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}
fn absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

impl MountPlan {
    pub fn declare(
        profile: &SandboxProfile,
        context: &SandboxContext,
    ) -> Result<Self, SandboxError> {
        Self::declare_with_admission(profile, context, None)
    }

    pub fn declare_with_admission(
        profile: &SandboxProfile,
        context: &SandboxContext,
        admission: Option<&Path>,
    ) -> Result<Self, SandboxError> {
        let mut plan = Self {
            mounts: Vec::new(),
            aliases: aliases()?,
            directories: BTreeSet::new(),
        };
        for base in BASES {
            plan.add(base.into(), base.into(), false, *base != "/usr", Role::Base)?;
        }
        // A system runtime is already supplied by the fixed /usr base. No
        // arbitrary runtime installation gains the base's overlay exception.
        if !context.runtime_root.starts_with("/usr") {
            plan.own(&context.runtime_root, false, Role::Runtime)?;
        }
        if context.allow_store_read {
            plan.own(
                &context.fictor_home.join("extensions/store"),
                false,
                Role::Store,
            )?;
        }
        plan.own(&context.bundle_root, false, Role::Bundle)?;
        // Install the mandatory RW resource before redundant read declarations.
        plan.own(&context.ext_data, true, Role::ExtData)?;
        plan.add(
            context.fictor_exe.clone(),
            "/fx/fictor".into(),
            false,
            false,
            Role::Bootstrap,
        )?;
        let ProxyEndpoint::Unix(proxy) = &profile.proxy;
        plan.add(
            proxy.clone(),
            "/fx/proxy.sock".into(),
            true,
            false,
            Role::Endpoint,
        )?;
        if let Some(socket) = &profile.kernel_socket {
            plan.add(
                socket.clone(),
                "/fx/kernel.sock".into(),
                true,
                false,
                Role::Endpoint,
            )?;
        }
        if let Some(socket) = admission {
            plan.add(
                socket.into(),
                "/fx/admission.sock".into(),
                true,
                false,
                Role::Endpoint,
            )?;
        }
        for (paths, writable) in [
            (&profile.write_paths, true),
            (&profile.read_paths, false),
            (&context.home_ro_files, false),
        ] {
            for path in paths {
                if let Ok(relative) = path.strip_prefix(&context.tmp_dir) {
                    if !path.is_dir() {
                        return Err(SandboxError::Invalid(
                            "Linux tmp aceita só diretórios; entradas devem estar no bundle ou data",
                        ));
                    }
                    let target = Path::new("/tmp").join(relative);
                    if target != Path::new("/tmp") && overlaps(&target, Path::new("/tmp/home")) {
                        return Err(invalid());
                    }
                    if target != Path::new("/tmp") {
                        plan.directories.insert(target);
                    }
                } else {
                    let role = if context.home_ro_files.contains(path) {
                        Role::HomeRead
                    } else {
                        Role::Grant
                    };
                    plan.own(path, writable, role)?;
                }
            }
        }
        if let Ok(relative) = profile.cwd.strip_prefix(&context.tmp_dir) {
            let target = Path::new("/tmp").join(relative);
            if target != Path::new("/tmp") {
                plan.directories.insert(target);
            }
        }
        // Private HOME is allocated by the core and cannot become a template
        // or ordinary grant's data tree. Its own cwd remains valid.
        for directory in &plan.directories {
            if !absolute(directory) {
                return Err(invalid());
            }
        }
        // The host preparation tree is private, even while the legacy helper
        // still lives outside FICTOR_HOME. ${tmp} contributes only directories
        // above; an ordinary ancestor import must not bring its host contents.
        if plan.mounts.iter().any(|mount| {
            mount.purpose() == SourcePurpose::Ordinary && overlaps(&mount.source, &context.tmp_dir)
        }) {
            return Err(invalid());
        }
        plan.check_reservations()?;
        Ok(plan)
    }

    fn own(&mut self, source: &Path, writable: bool, role: Role) -> Result<(), SandboxError> {
        self.add(source.into(), self.effective(source), writable, false, role)
    }
    fn add(
        &mut self,
        source: PathBuf,
        destination: PathBuf,
        writable: bool,
        optional: bool,
        role: Role,
    ) -> Result<(), SandboxError> {
        if !absolute(&source) || !absolute(&destination) {
            return Err(invalid());
        }
        self.mounts.push(Mount {
            source,
            destination,
            writable,
            optional,
            role,
        });
        Ok(())
    }
    fn effective(&self, path: &Path) -> PathBuf {
        // Every target is absolute; apply the longest routing prefix once.
        self.aliases
            .iter()
            .filter_map(|alias| {
                path.strip_prefix(&alias.destination).ok().map(|relative| {
                    (
                        alias.destination.components().count(),
                        alias.target.join(relative),
                    )
                })
            })
            .max_by_key(|(depth, _)| *depth)
            .map_or_else(|| path.into(), |(_, path)| path)
    }

    fn check_reservations(&self) -> Result<(), SandboxError> {
        let home = Path::new("/tmp/home");
        for mount in &self.mounts {
            if mount.role != Role::Base
                && mount.role != Role::Bootstrap
                && mount.role != Role::Endpoint
                && ["/proc", "/dev", "/fx"]
                    .iter()
                    .any(|root| overlaps(&mount.destination, Path::new(root)))
            {
                return Err(invalid());
            }
            if overlaps(&mount.destination, home) {
                return Err(invalid());
            }
            // /tmp is a private container; children may import ordinary data.
            if Path::new("/tmp").starts_with(&mount.destination) {
                return Err(invalid());
            }
            if mount.role != Role::Base
                && mount.role != Role::Bootstrap
                && mount.role != Role::Endpoint
            {
                for alias in &self.aliases {
                    // Routing nodes and their ancestors cannot be replaced;
                    // canonical children of their target remain grantable.
                    if (alias.destination.starts_with(&mount.destination)
                        || alias.target.starts_with(&mount.destination))
                        && !self.mounts.iter().any(|outer| {
                            outer.role == Role::Base
                                && mount.destination.starts_with(&outer.destination)
                                && !mount.writable
                        })
                    {
                        return Err(invalid());
                    }
                }
            }
            for directory in &self.directories {
                if overlaps(directory, &mount.destination) {
                    return Err(invalid());
                }
            }
        }
        for mount in self.mounts.iter().filter(|mount| mount.role != Role::Base) {
            for base in self.mounts.iter().filter(|mount| mount.role == Role::Base) {
                if overlaps(&mount.destination, &base.destination)
                    && (!mount.destination.starts_with(&base.destination) || mount.writable)
                {
                    return Err(invalid());
                }
            }
        }
        for (index, grant) in self
            .mounts
            .iter()
            .enumerate()
            .filter(|(_, mount)| mount.grant())
        {
            for (other_index, own) in self
                .mounts
                .iter()
                .enumerate()
                .filter(|(_, mount)| !mount.grant())
            {
                if index == other_index || !overlaps(&grant.destination, &own.destination) {
                    continue;
                }
                let already_covered = self.mounts.iter().any(|outer| {
                    !outer.grant()
                        && grant.destination.starts_with(&outer.destination)
                        && (!grant.writable || outer.writable)
                });
                if !grant.destination.starts_with(&own.destination) && !already_covered
                    || grant.writable && !own.writable
                {
                    return Err(invalid());
                }
                // Only a same-subtree proof can normalize the remaining case.
            }
        }
        Ok(())
    }

    /// A candidate may inherit an already-authorized source only when its
    /// destination is the same subtree and its permission does not grow.
    pub fn covering(&self, index: usize) -> Option<usize> {
        let mount = &self.mounts[index];
        self.mounts
            .iter()
            .enumerate()
            .filter(|(other_index, outer)| {
                *other_index != index
                    && mount.destination.starts_with(&outer.destination)
                    && (!mount.writable || outer.writable)
                    && (mount.destination != outer.destination || *other_index < index)
            })
            .min_by_key(|(_, outer)| (outer.grant(), outer.destination.components().count()))
            .map(|(index, _)| index)
    }

    pub fn normalized(&self, proof: &MountProof) -> Result<Vec<&Mount>, SandboxError> {
        self.normalize_with(
            |outer, inner, relative| proof.covers(&outer.source, &inner.source, relative),
            |mount| Ok(mount.optional && proof.optional_source(&mount.source)?.is_none()),
        )
    }

    pub(super) fn normalize_with(
        &self,
        mut covers: impl FnMut(&Mount, &Mount, &Path) -> Result<bool, SandboxError>,
        mut absent: impl FnMut(&Mount) -> Result<bool, SandboxError>,
    ) -> Result<Vec<&Mount>, SandboxError> {
        let mut keep = Vec::new();
        for (index, mount) in self.mounts.iter().enumerate() {
            if absent(mount)? {
                continue;
            }
            let mut redundant = false;
            for (other_index, outer) in self.mounts.iter().enumerate() {
                if index == other_index || !overlaps(&mount.destination, &outer.destination) {
                    continue;
                }
                if absent(outer)? {
                    continue;
                }
                // Core declarations may be nested only when the same object
                // and mode are proven, e.g. bundle within authorized store.
                if let Ok(relative) = mount.destination.strip_prefix(&outer.destination)
                    && (!mount.writable || outer.writable)
                    && (mount.destination != outer.destination || other_index < index)
                {
                    if covers(outer, mount, relative)? {
                        redundant = true;
                        break;
                    }
                    return Err(invalid());
                }
                if !outer.destination.starts_with(&mount.destination) {
                    continue;
                }
                if mount.destination == outer.destination && mount.writable == outer.writable {
                    continue;
                }
                // An approved RO ancestor plus RW child is conservatively
                // refused; no mount ordering upgrades a reserved/ordinary tree.
                if !mount.writable && outer.writable {
                    return Err(invalid());
                }
            }
            if !redundant {
                keep.push(mount);
            }
        }
        Ok(keep)
    }
}

pub(super) const ATOMIC_ALIASES: &[(&str, &str)] = &[
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
    }) || alias == Path::new("/usr/local")
        && matches!(target.to_str(), Some("../var/usrlocal" | "/var/usrlocal"))
}
fn aliases() -> Result<Vec<Alias>, SandboxError> {
    let mut aliases: Vec<Alias> = [
        ("/bin", "/usr/bin"),
        ("/sbin", "/usr/sbin"),
        ("/lib", "/usr/lib"),
        ("/lib64", "/usr/lib64"),
    ]
    .into_iter()
    .map(|(destination, target)| Alias {
        destination: destination.into(),
        target: target.into(),
        create: true,
    })
    .collect();
    for (destination, relative) in ATOMIC_ALIASES {
        match std::fs::read_link(destination) {
            Ok(target) if atomic_alias_target(Path::new(destination), &target) => {
                aliases.push(Alias {
                    destination: (*destination).into(),
                    target: Path::new("/").join(relative),
                    create: true,
                })
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidInput
                ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    if let Ok(target) = std::fs::read_link("/usr/local")
        && atomic_alias_target(Path::new("/usr/local"), &target)
    {
        aliases.push(Alias {
            destination: "/usr/local".into(),
            target: "/var/usrlocal".into(),
            create: false,
        });
    }
    Ok(aliases)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::Tier;
    use std::collections::BTreeMap;

    fn fixture() -> (SandboxProfile, SandboxContext) {
        (
            SandboxProfile {
                read_paths: vec![],
                write_paths: vec![],
                spawn: false,
                kernel_socket: None,
                proxy: ProxyEndpoint::Unix("/core/run/proxy.sock".into()),
                env: BTreeMap::new(),
                cwd: "/workspace".into(),
                tier: Tier::Os,
            },
            SandboxContext {
                fictor_home: "/core".into(),
                real_home: "/users/test".into(),
                bundle_root: "/core/extensions/store/tool/key".into(),
                ext_data: "/core/extensions/data/tool".into(),
                tmp_dir: "/instance/tmp".into(),
                runtime: "/usr/bin/node".into(),
                runtime_root: "/usr".into(),
                fictor_exe: "/core-bin/fictor".into(),
                home_ro_files: vec![],
                allow_store_read: false,
            },
        )
    }
    fn normalized(plan: &MountPlan) -> Result<Vec<&Mount>, SandboxError> {
        plan.normalize_with(
            |outer, inner, relative| Ok(outer.source.join(relative) == inner.source),
            |_| Ok(false),
        )
    }
    #[test]
    fn sealed_destinations_and_system_base_modes_are_reserved_by_components() {
        for path in [
            "/",
            "/proc",
            "/proc/fake",
            "/dev",
            "/dev/file",
            "/fx",
            "/fx/fictor",
            "/tmp",
            "/tmp/home",
            "/tmp/home/file",
            "/etc",
        ] {
            for writable in [false, true] {
                let (mut profile, context) = fixture();
                if writable {
                    profile.write_paths.push(path.into());
                } else {
                    profile.read_paths.push(path.into());
                }
                assert!(
                    MountPlan::declare(&profile, &context).is_err(),
                    "{path} writable={writable}"
                );
            }
        }
        for base in BASES {
            for path in [PathBuf::from(base), Path::new(base).join("child")] {
                let (mut profile, context) = fixture();
                profile.write_paths.push(path.clone());
                assert!(
                    MountPlan::declare(&profile, &context).is_err(),
                    "{}",
                    path.display()
                );
            }
        }
        let (mut profile, context) = fixture();
        // Component boundaries do not reserve unrelated lookalike names.
        profile.write_paths.push("/usr-data/work".into());
        assert!(MountPlan::declare(&profile, &context).is_ok());
    }
    #[test]
    fn equivalent_reads_and_own_data_are_coalesced_without_removing_rw() {
        let (mut profile, mut context) = fixture();
        context.allow_store_read = true;
        profile.read_paths.extend([
            "/usr/bin".into(),
            context.bundle_root.clone(),
            context.ext_data.join("child"),
            context.fictor_home.join("extensions/store"),
            context.fictor_home.join("extensions/store/tool"),
        ]);
        profile.write_paths.push(context.ext_data.clone());
        let plan = MountPlan::declare(&profile, &context).unwrap();
        let kept = normalized(&plan).unwrap();
        assert!(kept.iter().all(|mount| !mount.grant()));
        assert_eq!(
            kept.iter()
                .filter(|mount| mount.destination == context.ext_data && mount.writable)
                .count(),
            1
        );
        assert!(kept.iter().any(|mount| mount.role == Role::Store));
        assert!(kept.iter().all(|mount| mount.role != Role::Bundle));
        assert!(
            plan.normalize_with(|_, _, _| Ok(false), |_| Ok(false))
                .is_err()
        );
    }
    #[test]
    fn ancestors_different_objects_and_mode_expansions_are_not_redundant() {
        for path in [
            "/core/extensions/store/tool",
            "/core/extensions",
            "/core/extensions/data",
        ] {
            let (mut profile, context) = fixture();
            profile.read_paths.push(path.into());
            assert!(MountPlan::declare(&profile, &context).is_err(), "{path}");
        }
        let (mut profile, context) = fixture();
        profile.read_paths.push("/workspace".into());
        profile.write_paths.push("/workspace/out".into());
        let plan = MountPlan::declare(&profile, &context).unwrap();
        assert!(normalized(&plan).is_err());
        let (mut profile, context) = fixture();
        profile.read_paths.push(context.ext_data.clone());
        let mut plan = MountPlan::declare(&profile, &context).unwrap();
        plan.mounts.last_mut().unwrap().source = "/different-object".into();
        assert!(normalized(&plan).is_err());
    }
    #[test]
    fn tmp_children_and_template_directories_have_distinct_origins() {
        let (mut profile, mut context) = fixture();
        let temporary = tempfile::tempdir().unwrap();
        context.tmp_dir = temporary.path().into();
        profile.cwd = context.tmp_dir.join("work");
        std::fs::create_dir(&profile.cwd).unwrap();
        profile.write_paths.push(profile.cwd.clone());
        profile.write_paths.push("/tmp/project".into());
        let plan = MountPlan::declare(&profile, &context).unwrap();
        assert!(plan.directories.contains(Path::new("/tmp/work")));
        assert!(
            plan.mounts
                .iter()
                .any(|mount| mount.source == Path::new("/tmp/project"))
        );
        assert!(
            plan.mounts
                .iter()
                .all(|mount| !mount.source.starts_with(&context.tmp_dir))
        );
        profile.read_paths.push("/tmp/work/input".into());
        assert!(MountPlan::declare(&profile, &context).is_err());
        profile.read_paths.clear();
        for relative in ["home", "home/child"] {
            let path = context.tmp_dir.join(relative);
            std::fs::create_dir_all(&path).unwrap();
            profile.read_paths.push(path);
            assert!(
                MountPlan::declare(&profile, &context).is_err(),
                "template {relative}"
            );
            profile.read_paths.clear();
        }
    }
    #[test]
    fn routing_aliases_allow_children_without_replacing_nodes() {
        let (profile, context) = fixture();
        let plan = MountPlan::declare(&profile, &context).unwrap();
        for alias in plan
            .aliases
            .iter()
            .filter(|alias| !alias.target.starts_with("/usr"))
        {
            for path in [&alias.destination, &alias.target] {
                let (mut profile, context) = fixture();
                profile.read_paths.push(path.clone());
                assert!(
                    MountPlan::declare(&profile, &context).is_err(),
                    "{}",
                    path.display()
                );
            }
            let (mut profile, context) = fixture();
            profile.write_paths.push(alias.target.join("fresh-child"));
            assert!(MountPlan::declare(&profile, &context).is_ok());
        }
    }

    #[test]
    fn host_preparation_tree_is_not_imported_through_an_ordinary_ancestor() {
        let (mut profile, context) = fixture();
        profile.read_paths.push("/instance".into());
        assert!(MountPlan::declare(&profile, &context).is_err());
    }
}
