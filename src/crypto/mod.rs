// crypto/mod.rs — Core criptografico (Plan Maestro Fase 1)
// REGLA: NUNCA implementar AES desde cero. Solo crates auditados.
// Crates: aes-gcm, argon2, rand, zeroize

pub mod commands;
pub mod mem_lock;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::Argon2;
use zeroize::Zeroize;
use anyhow::Result;

/// Parametros Argon2id (OWASP recomendados para alta seguridad)
/// Intencionalmente lento: ~500ms para resistir fuerza bruta
const ARGON2_MEM_COST: u32 = 65536;  // 64 MB
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

/// Deriva una llave AES-256 desde la contrasena del usuario
pub fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<Vec<u8>> {
    let params = argon2::Params::new(ARGON2_MEM_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM, Some(32))
        .map_err(|e| anyhow::anyhow!("Error creando parametros Argon2id: {}", e))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    let mut output_key = vec![0u8; 32]; // 256 bits
    if let Err(e) = argon2.hash_password_into(password.as_bytes(), salt, &mut output_key) {
        // Zeroizar antes de propagar el error — el buffer podría tener bytes parciales
        output_key.zeroize();
        return Err(anyhow::anyhow!("Error derivando llave: {}", e));
    }

    Ok(output_key)
}

/// Cifra datos con AES-256-GCM
/// Devuelve: [nonce (12 bytes) | ciphertext + tag]
pub fn encrypt(key_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    // Cipher construido directamente — sin variable `key` intermedia.
    // Con feature "zeroize" de aes-gcm el key schedule se zeroiza al hacer drop.
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Error cifrando: {}", e))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Descifra datos con AES-256-GCM directamente a memoria
/// El plaintext resultante NUNCA se escribe en disco
pub fn decrypt_to_memory(key_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        anyhow::bail!("Datos cifrados invalidos: demasiado cortos");
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    // Cipher construido directamente — sin variable `key` intermedia.
    // Con feature "zeroize" de aes-gcm el key schedule se zeroiza al hacer drop.
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Contrasena incorrecta o datos corruptos"))?;

    Ok(plaintext)
}

/// Genera salt aleatorio para Argon2id (32 bytes)
pub fn generate_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut salt = vec![0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Limpia datos sensibles de la memoria
pub fn secure_clear(data: &mut Vec<u8>) {
    data.zeroize();
}

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