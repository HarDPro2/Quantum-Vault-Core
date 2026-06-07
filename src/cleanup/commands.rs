// cleanup/commands.rs — Public API for secure deletion
//
// Demonstrates how Quantum Vault exposes cryptographic file erasing.

use super::cleanup_on_close;

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
