use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use nix::fcntl::{Flock, FlockArg};

use crate::{AuthError, Result};

const MAX_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) fn absolute_private_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() || path.file_name().is_none() {
        return unavailable();
    }
    let parent = path
        .parent()
        .ok_or(AuthError::ReplayProtectionUnavailable)?;
    let metadata =
        fs::symlink_metadata(parent).map_err(|_| AuthError::ReplayProtectionUnavailable)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return unavailable();
    }
    Ok(path.to_path_buf())
}

pub(crate) fn sibling(path: &Path, suffix: &str) -> Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or(AuthError::ReplayProtectionUnavailable)?;
    Ok(path.with_file_name(format!(".{name}.{suffix}")))
}

pub(crate) fn lock(path: &Path) -> Result<Flock<File>> {
    let file = open(path, true, true)?;
    Flock::lock(file, FlockArg::LockExclusive).map_err(|_| AuthError::ReplayProtectionUnavailable)
}

pub(crate) fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    if !path.exists() {
        return Ok(None);
    }
    let mut file = open(path, false, false)?;
    let before = checked(&file)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AuthError::ReplayProtectionUnavailable)?;
    let after = checked(&file)?;
    if before != after || bytes.len() as u64 != after.2 || bytes.len() as u64 > MAX_BYTES {
        return unavailable();
    }
    Ok(Some(bytes))
}

pub(crate) fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 > MAX_BYTES {
        return unavailable();
    }
    let parent = path
        .parent()
        .ok_or(AuthError::ReplayProtectionUnavailable)?;
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| AuthError::ReplayProtectionUnavailable)?;
    let temporary = parent.join(format!(".auth-state-{}.tmp", hex::encode(random)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|_| AuthError::ReplayProtectionUnavailable)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| AuthError::ReplayProtectionUnavailable)?;
    fs::rename(&temporary, path).map_err(|_| AuthError::ReplayProtectionUnavailable)?;
    File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| AuthError::ReplayProtectionUnavailable)
}

fn open(path: &Path, write: bool, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(write)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|_| AuthError::ReplayProtectionUnavailable)?;
    checked(&file)?;
    Ok(file)
}

fn checked(file: &File) -> Result<(u64, u64, u64)> {
    let metadata = file
        .metadata()
        .map_err(|_| AuthError::ReplayProtectionUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() > MAX_BYTES
    {
        return unavailable();
    }
    Ok((metadata.dev(), metadata.ino(), metadata.len()))
}

fn unavailable<T>() -> Result<T> {
    Err(AuthError::ReplayProtectionUnavailable)
}
