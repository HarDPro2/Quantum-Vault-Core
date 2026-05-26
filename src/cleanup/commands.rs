// cleanup/commands.rs — Public API for secure deletion
//
// Demonstrates how Quantum Vault exposes DOD 5220.22-M file wiping
// through a safe public interface with input validation.

use std::path::PathBuf;
use super::{cleanup_on_close, secure_delete_file};

/// Runs the full cleanup routine: Recent Files, Jump Lists,
/// Thumbnail Cache, and temp files.
///
/// This is called automatically when locking the vault to ensure
/// zero forensic footprint on the host OS.
pub fn cleanup_traces() -> Result<bool, String> {
    cleanup_on_close()
        .map_err(|e| format!("cleanup_traces: {}", e))?;
    Ok(true)
}

/// Securely deletes a file using DOD 5220.22-M (3-pass overwrite).
///
/// Overwrites the file content 3 times (0x00, 0xFF, random) with
/// `sync_all()` between passes, then removes the directory entry.
///
/// # Validation Rules
/// The command rejects:
///   - Empty paths
///   - Relative paths (must be absolute)
///   - Directories (use a dedicated function for recursive deletion)
///   - Files that don't exist (explicit verification for user feedback)
///
/// # Security Note
/// On SSDs with wear-levelling and TRIM, the physical block may have been
/// remapped; the logical overwrite does not guarantee purging of the physical
/// block. For serious forensic threats, combine with full-disk encryption.
pub fn secure_delete(path: String) -> Result<bool, String> {
    if path.trim().is_empty() {
        return Err("secure_delete: empty path".into());
    }

    let p = PathBuf::from(&path);
    if !p.is_absolute() {
        return Err("secure_delete: only absolute paths are accepted".into());
    }

    if p.is_dir() {
        return Err("secure_delete: path points to a directory".into());
    }

    if !p.exists() {
        return Err("secure_delete: file not found — cannot verify secure deletion".into());
    }

    secure_delete_file(&p)
        .map_err(|e| format!("secure_delete: {}", e))?;

    Ok(true)
}
