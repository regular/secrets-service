use std::path::{Component, Path, PathBuf};
use std::io;

use crate::error::ServiceError;

/// Joins `base` and `relative`, ensuring that the resolved path is within `base`.
/// The `relative` path denotes a file (its last component is a file).
/// Returns the joined path on success.
pub fn join_within(base: &Path, relative: &Path) -> Result<PathBuf, ServiceError> {
    if relative.is_absolute() {
        return Err(ServiceError::Store(io::Error::new(
            io::ErrorKind::InvalidInput,
            "relative path must not be absolute",
        )));
    }
    
    // Canonicalize the base to resolve symlinks.
    let base_canon = base.canonicalize()?;
    let joined = base_canon.join(relative);
    let normalized = normalize_path(&joined);

    if !normalized.starts_with(&base_canon) {
        return Err(ServiceError::Store(io::Error::new(
            io::ErrorKind::InvalidInput,
            "resolved path is outside the base directory",
        )));
    }
    Ok(normalized)
}

/// Similar to `join_within`, but creates the parent directory structure for the file.
/// Returns the joined file path on success.
pub fn mkdir_within(base: &Path, relative: &Path) -> Result<PathBuf, ServiceError> {
    let full_path = join_within(base, relative)?;
    if let Some(parent) = full_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(full_path)
}

/// -- util

/// Normalizes a path by resolving `.` and `..` without touching the filesystem.
fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => continue,
            Component::ParentDir => { normalized.pop(); },
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}
