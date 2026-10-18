use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::{env, fs, io, path::Path, path::PathBuf};

pub fn resolve() -> io::Result<PathBuf> {
    resolve_with(
        env::var_os("FICTOR_HOME").map(PathBuf::from),
        env::var_os("HOME").map(PathBuf::from),
        env::var_os("XDG_DATA_HOME").map(PathBuf::from),
    )
}

pub fn resolve_with(
    explicit: Option<PathBuf>,
    user_home: Option<PathBuf>,
    xdg: Option<PathBuf>,
) -> io::Result<PathBuf> {
    if let Some(path) = explicit {
        if path.as_os_str().is_empty() {
            return Err(io::Error::other("FICTOR_HOME não pode ser vazio"));
        }
        return std::path::absolute(path);
    }
    if let Some(xdg) = xdg.as_ref().filter(|p| p.is_absolute()) {
        return Ok(xdg.join("fictor"));
    }
    let user_home = user_home.ok_or_else(|| io::Error::other("HOME não definido"))?;
    if !user_home.is_absolute() {
        return Err(io::Error::other("HOME deve ser absoluto"));
    }
    Ok(user_home.join(".local/share/fictor"))
}

pub fn private_dir(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    builder.mode(0o700);
    builder.create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::other("diretório de dados não pode ser symlink"));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub fn prepare(home: &Path) -> io::Result<()> {
    private_dir(home)?;
    for relative in [
        "blobs",
        "extensions",
        "extensions/store",
        "extensions/quarantine",
        "extensions/data",
        "run",
        "run/k",
        "logs",
        "logs/ext",
    ] {
        private_dir(&home.join(relative))?;
    }
    Ok(())
}
