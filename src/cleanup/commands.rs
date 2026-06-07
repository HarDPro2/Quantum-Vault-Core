// cleanup/commands.rs — Public API for host-artifact cleanup
//
// Thin wrapper exposing `cleanup_on_close` as `cleanup_traces`.

use super::cleanup_on_close;

/// Runs the full cleanup routine: Recent Files, Jump Lists,
/// Thumbnail Cache, and temp files.
///
/// This is called automatically when locking the vault to clear
/// leftover session/temp artifacts from the host OS.
pub fn cleanup_traces() -> Result<bool, String> {
    cleanup_on_close()
        .map_err(|e| format!("cleanup_traces: {}", e))?;
    Ok(true)
}
