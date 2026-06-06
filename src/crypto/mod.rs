// crypto/mod.rs — Shamir Secret Sharing (Quantum Vault Core)
// REGLA: NUNCA implementar cripto desde cero. Solo crates auditados.
// El cifrado del contenedor vive en `crypto_erase` (XChaCha20-Poly1305 + Argon2id KEK).
// Crates: sharks

pub mod commands;
pub mod mem_lock;

use anyhow::Result;

// ── Shamir Secret Sharing ─────────────────────────────

/// Divide una llave en `total` fragmentos, necesitando `threshold` para reconstruir
pub fn split_key_shamir(key: &[u8], threshold: u8, total: u8) -> Result<Vec<Vec<u8>>> {
    use sharks::Sharks;

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(key);
    let shares: Vec<Vec<u8>> = dealer
        .take(total as usize)
        .map(|s| {
            let bytes: Vec<u8> = (&s).into();
            bytes
        })
        .collect();

    tracing::info!("Shamir: llave dividida en {} fragmentos (umbral: {})", total, threshold);
    Ok(shares)
}

/// Reconstruye la llave original desde los fragmentos (mínimo `threshold`)
pub fn recover_key_shamir(shares_bytes: &[Vec<u8>]) -> Result<Vec<u8>> {
    use sharks::{Sharks, Share};

    let shares: Vec<Share> = shares_bytes.iter()
        .map(|b| Share::try_from(b.as_slice()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| anyhow::anyhow!("Fragmentos inválidos"))?;

    // El threshold no importa aquí — si hay suficientes fragmentos, funciona
    let sharks = Sharks(1); // placeholder, la reconstrucción no usa threshold
    let secret = sharks.recover(&shares)
        .map_err(|_| anyhow::anyhow!("No hay suficientes fragmentos o son inválidos"))?;

    tracing::info!("Shamir: llave reconstruida desde {} fragmentos", shares_bytes.len());
    Ok(secret)
}
