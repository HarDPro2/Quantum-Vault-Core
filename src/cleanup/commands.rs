// cleanup/commands.rs — Public API for secure deletion
//
// Demonstrates how Quantum Vault exposes cryptographic file erasing.

use crate::crypto_erase::Vault;
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

/// Realiza el borrado seguro de un archivo de la bóveda mediante el borrado criptográfico (crypto-erase).
///
/// En lugar de sobrescribir el archivo en disco (lo cual es ineficaz y peligroso en SSDs/CoW),
/// destruye la clave de cifrado (DEK) del archivo dentro de la cabecera de la bóveda.
/// Una vez eliminada la DEK de la cabecera persistida, el bloque de datos cifrados queda
/// reducido a ruido aleatorio matemáticamente irrecuperable.
///
/// # Parámetros
/// - `vault`: La instancia abierta de la bóveda.
/// - `file_id`: El identificador único del archivo a borrar.
pub fn secure_delete(vault: &mut Vault, file_id: &str) -> Result<bool, String> {
    if file_id.trim().is_empty() {
        return Err("secure_delete: file_id vacío".into());
    }

    vault.crypto_erase_file(file_id);

    Ok(true)
}
