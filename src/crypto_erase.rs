//! Criptografía de tres niveles para la bóveda de Quantum Vault (KEK -> MK -> DEK).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as AeadKey, XChaCha20Poly1305, XNonce};
use argon2::Argon2;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

pub const KEY_LEN: usize = 32; // claves de 256 bits
pub const NONCE_LEN: usize = 24; // XChaCha20Poly1305: nonce de 192 bits
pub const SALT_LEN: usize = 16;

pub const MK_CONTEXT: &[u8] = b"quantum-vault:master-key:v1";
const INDEX_CONTEXT: &[u8] = b"quantum-vault:index:v1";

/// Constructs the AAD for wrapping/unwrapping the Master Key.
/// Binding salt and KDF params into the AAD ensures that tampering
/// with any of them causes a deterministic AEAD authentication failure,
/// independently of whether the KEK derivation also changes.
pub fn mk_wrap_aad(salt: &[u8; SALT_LEN], m_cost: u32, t_cost: u32, p_cost: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MK_CONTEXT.len() + SALT_LEN + 12);
    aad.extend_from_slice(MK_CONTEXT);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(&m_cost.to_le_bytes());
    aad.extend_from_slice(&t_cost.to_le_bytes());
    aad.extend_from_slice(&p_cost.to_le_bytes());
    aad
}

/// Validates KDF params against sane bounds. Rejects (not clamps) out-of-range
/// values to prevent DoS via absurd m_cost before Argon2 runs.
pub fn validate_kdf_params(m_cost: u32, t_cost: u32, p_cost: u32) -> Result<(), Error> {
    // m_cost in KiB: min 4 MiB (4096 KiB), max 512 MiB (524288 KiB)
    if m_cost < 4096 || m_cost > 524_288 {
        return Err(Error::Kdf);
    }
    if t_cost < 1 || t_cost > 64 {
        return Err(Error::Kdf);
    }
    if p_cost < 1 || p_cost > 16 {
        return Err(Error::Kdf);
    }
    Ok(())
}

#[derive(Debug)]
pub enum Error {
    Kdf,
    Aead,
    BadKeyLen,
    Truncated,
    NoSuchFile,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

/// Material de clave de 256 bits. Se sobrescribe con ceros al destruirse (Drop).
#[derive(Clone)]
pub struct Key(pub Zeroizing<[u8; KEY_LEN]>);

impl Key {
    pub fn random() -> Self {
        let mut k = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut k);
        Key(Zeroizing::new(k))
    }

    pub fn aead(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(AeadKey::from_slice(self.0.as_ref()))
    }
}

/// Una clave cifrada (envuelta) bajo otra clave: nonce + ciphertext autenticado.
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct WrappedKey {
    pub nonce: [u8; NONCE_LEN],
    pub ct: Vec<u8>,
}

/// Entrada de archivo en el índice del contenedor.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultEntry {
    pub id: String,          // UUID v4
    pub name: String,        // nombre original
    pub size: u64,           // tamaño original en bytes
    pub mime_type: String,
    pub encrypted_at: u64,   // timestamp unix
    pub data_offset: u64,    // posición en el contenedor
    pub data_len: u64,       // tamaño cifrado
    pub wrapped_dek: WrappedKey, // DEK cifrada bajo la MK
}

/// Cabecera persistente de la bóveda (se serializa como JSON y se guarda al inicio del contenedor).
///
/// LIMITACIÓN DE SEGURIDAD — Denegación Plausible:
///
/// 1. SIZE TELL: El tamaño total del contenedor crece al agregar archivos.
///    Un adversario puede comparar el tamaño total con lo que explica el
///    índice decoy y deducir que existen datos ocultos.
///
/// 2. INDEX ASYMMETRY: `encrypted_indices[1]` (decoy/relleno) se genera con
///    el tamaño de un índice vacío al crear el contenedor y NUNCA crece.
///    Cuando la bóveda real acumula entradas, `encrypted_indices[0]` crece
///    proporcionalmente, creando un distinguidor estadístico trivial entre
///    ambos slots. Esto es una limitación conocida de esta fase.
///
/// La deniabilidad resistente a forense requiere contenedores de tamaño
/// fijo pre-asignados + volumen oculto + protección contra escritura,
/// lo cual se abordará en una fase posterior.
/// NUNCA publicitar esta funcionalidad como "a prueba de forense".
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Header {
    pub version: u32,
    pub salt: [u8; SALT_LEN],
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub keyslots: Vec<WrappedKey>,       // Siempre de tamaño 2 (0 = real/decoy, 1 = decoy/relleno)
    pub encrypted_indices: Vec<Vec<u8>>, // Siempre de tamaño 2
}

/// Deriva la KEK utilizando parámetros Argon2id explícitos.
pub fn derive_kek(password: &[u8], salt: &[u8], m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Key, Error> {
    let mut out = [0u8; KEY_LEN];
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(KEY_LEN))
        .map_err(|_| Error::Kdf)?;
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );
    argon2.hash_password_into(password, salt, &mut out)
        .map_err(|_| Error::Kdf)?;
    Ok(Key(Zeroizing::new(out)))
}

/// Envuelve `inner` bajo `wrapping`. `aad` liga el wrap a su contexto.
pub fn wrap_key(wrapping: &Key, inner: &Key, aad: &[u8]) -> Result<WrappedKey, Error> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = wrapping
        .aead()
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: inner.0.as_ref(), aad },
        )
        .map_err(|_| Error::Aead)?;
    Ok(WrappedKey { nonce, ct })
}

/// Desenvuelve una clave. Falla si el `aad` no coincide (protección contra swaps).
pub fn unwrap_key(wrapping: &Key, wrapped: &WrappedKey, aad: &[u8]) -> Result<Key, Error> {
    let mut pt = wrapping
        .aead()
        .decrypt(
            XNonce::from_slice(&wrapped.nonce),
            Payload { msg: &wrapped.ct, aad },
        )
        .map_err(|_| Error::Aead)?;
    if pt.len() != KEY_LEN {
        pt.zeroize();
        return Err(Error::BadKeyLen);
    }
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&pt);
    pt.zeroize();
    Ok(Key(Zeroizing::new(k)))
}

/// Cifra el contenido de un archivo con su DEK. El blob = nonce || ciphertext.
pub fn encrypt_file(dek: &Key, plaintext: &[u8], file_id: &str) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = dek
        .aead()
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: plaintext, aad: file_id.as_bytes() },
        )
        .map_err(|_| Error::Aead)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Descifra el contenido de un archivo con su DEK.
pub fn decrypt_file(dek: &Key, blob: &[u8], file_id: &str) -> Result<Vec<u8>, Error> {
    if blob.len() < NONCE_LEN {
        return Err(Error::Truncated);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    dek.aead()
        .decrypt(
            XNonce::from_slice(nonce),
            Payload { msg: ct, aad: file_id.as_bytes() },
        )
        .map_err(|_| Error::Aead)
}

/// Cifra el índice completo bajo la MK.
pub fn encrypt_index(mk: &Key, index_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = mk
        .aead()
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: index_bytes, aad: INDEX_CONTEXT },
        )
        .map_err(|_| Error::Aead)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Descifra el índice completo bajo la MK.
pub fn decrypt_index(mk: &Key, blob: &[u8]) -> Result<Vec<u8>, Error> {
    if blob.len() < NONCE_LEN {
        return Err(Error::Truncated);
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    mk.aead()
        .decrypt(
            XNonce::from_slice(nonce),
            Payload { msg: ct, aad: INDEX_CONTEXT },
        )
        .map_err(|_| Error::Aead)
}

/// Bóveda abierta en memoria.
pub struct Vault {
    pub header: Header,
    pub master_key: Key,       // MK en memoria (Zeroizing)
    pub index: Vec<VaultEntry>, // índice descifrado
    pub active_slot: usize,    // 0 = real, 1 = decoy
}

impl Vault {
    /// Desbloquea una bóveda intentando con los keyslots disponibles.
    /// Valida versión y params KDF antes de derivar la KEK.
    pub fn unlock(header: Header, password: &[u8]) -> Result<Self, Error> {
        // Validar versión del contenedor
        if header.version != 2 {
            return Err(Error::Aead);
        }

        // Validar params KDF antes de correr Argon2 (previene DoS por m_cost absurdo)
        validate_kdf_params(header.m_cost, header.t_cost, header.p_cost)?;

        // Derivar KEK única usando el salt y parámetros Argon2id de la cabecera
        let kek = derive_kek(password, &header.salt, header.m_cost, header.t_cost, header.p_cost)?;

        // AAD binds salt + params al wrap de la MK: manipular cualquiera falla determinísticamente
        let aad = mk_wrap_aad(&header.salt, header.m_cost, header.t_cost, header.p_cost);

        // Intentar desenvolver cada slot en orden
        for (i, slot) in header.keyslots.iter().enumerate() {
            if let Ok(master_key) = unwrap_key(&kek, slot, &aad) {
                // Descifrar el correspondiente índice
                if let Some(enc_idx) = header.encrypted_indices.get(i) {
                    if let Ok(index_bytes) = decrypt_index(&master_key, enc_idx) {
                        if let Ok(index) = serde_json::from_slice(&index_bytes) {
                            return Ok(Self {
                                header,
                                master_key,
                                index,
                                active_slot: i,
                            });
                        }
                    }
                }
            }
        }

        Err(Error::Aead) // Ninguno autenticó
    }

    /// Elimina la entrada del índice y destruye la DEK de un archivo.
    pub fn crypto_erase_file(&mut self, file_id: &str) {
        self.index.retain(|e| e.id != file_id);
        // AUDIT: Para la persistencia atómica de la cabecera, al guardar self.header
        // tras agregar o eliminar un archivo, se debe escribir a un archivo temporal
        // y luego hacer un renombrado atómico (fs::rename) sobre el archivo original.
    }

    /// Rota la Master Key (re-keying): genera nueva MK, re-envuelve todas las DEK,
    /// y actualiza el keyslot activo. El slot inactivo NO se modifica.
    ///
    /// El salt NO se regenera — la KEK se re-deriva con el salt existente.
    /// `wrap_key` usa un nonce nuevo cada vez, así que reusar la misma KEK es seguro.
    /// Esto preserva el decoy sin necesitar su password.
    ///
    /// NOTA: Esto es re-keying, NO forward secrecy. La MK vieja sigue siendo
    /// derivable desde remanentes en SSD + el password. Limita el daño si la MK
    /// en memoria se compromete, pero no purga las DEK borradas de remanentes.
    pub fn rotate_master_key(&mut self, password: &[u8]) -> Result<(), Error> {
        let new_mk = Key::random();

        // Re-envolver todas las DEK con la nueva MK
        for entry in &mut self.index {
            let old_dek = unwrap_key(
                &self.master_key, &entry.wrapped_dek, entry.id.as_bytes()
            )?;
            entry.wrapped_dek = wrap_key(&new_mk, &old_dek, entry.id.as_bytes())?;
        }

        // Derivar KEK con el salt EXISTENTE (no regenerar)
        let kek = derive_kek(
            password, &self.header.salt,
            self.header.m_cost, self.header.t_cost, self.header.p_cost
        )?;

        // AAD con el salt existente
        let aad = mk_wrap_aad(
            &self.header.salt, self.header.m_cost, self.header.t_cost, self.header.p_cost
        );
        let wrapped_mk = wrap_key(&kek, &new_mk, &aad)?;

        // Re-cifrar índice con la nueva MK
        let index_bytes = serde_json::to_vec(&self.index)
            .map_err(|_| Error::Aead)?;
        let encrypted_index = encrypt_index(&new_mk, &index_bytes)?;

        // Actualizar header — solo el slot activo
        self.header.keyslots[self.active_slot] = wrapped_mk;
        self.header.encrypted_indices[self.active_slot] = encrypted_index;

        // Actualizar MK en memoria
        self.master_key = new_mk;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Write, Read, Seek, SeekFrom};

    fn create_test_container(path: &std::path::Path, password: &[u8], decoy_pwd: Option<&[u8]>) -> Header {
        let m_cost = 4096; // Argon2id rápido para tests
        let t_cost = 2;
        let p_cost = 1;

        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        // KEK real — AAD incluye salt + params
        let kek = derive_kek(password, &salt, m_cost, t_cost, p_cost).unwrap();
        let real_mk = Key::random();
        let aad = mk_wrap_aad(&salt, m_cost, t_cost, p_cost);
        let wrapped_mk = wrap_key(&kek, &real_mk, &aad).unwrap();

        // Index real vacío
        let empty_index: Vec<VaultEntry> = Vec::new();
        let index_bytes = serde_json::to_vec(&empty_index).unwrap();
        let encrypted_index = encrypt_index(&real_mk, &index_bytes).unwrap();

        let (keyslots, encrypted_indices) = if let Some(dp) = decoy_pwd {
            let decoy_kek = derive_kek(dp, &salt, m_cost, t_cost, p_cost).unwrap();
            let decoy_mk = Key::random();
            let decoy_wrapped = wrap_key(&decoy_kek, &decoy_mk, &aad).unwrap();
            let decoy_encrypted = encrypt_index(&decoy_mk, &index_bytes).unwrap();
            (vec![wrapped_mk, decoy_wrapped], vec![encrypted_index, decoy_encrypted])
        } else {
            let mut random_nonce = [0u8; NONCE_LEN];
            let mut random_ct = vec![0u8; 48];
            rand::rngs::OsRng.fill_bytes(&mut random_nonce);
            rand::rngs::OsRng.fill_bytes(&mut random_ct);
            let random_slot = WrappedKey { nonce: random_nonce, ct: random_ct };

            let mut random_idx = vec![0u8; encrypted_index.len()];
            rand::rngs::OsRng.fill_bytes(&mut random_idx);

            (vec![wrapped_mk, random_slot], vec![encrypted_index, random_idx])
        };

        let header = Header {
            version: 2,
            salt,
            m_cost,
            t_cost,
            p_cost,
            keyslots,
            encrypted_indices,
        };

        let header_json = serde_json::to_vec(&header).unwrap();
        let len = header_json.len() as u64;

        let mut file = File::create(path).unwrap();
        file.write_all(b"QVAULT02").unwrap();
        file.write_all(&len.to_le_bytes()).unwrap();
        file.write_all(&header_json).unwrap();
        header
    }

    fn read_header_v2(path: &std::path::Path) -> Result<(Header, u64), Error> {
        let mut file = File::open(path).map_err(|_| Error::NoSuchFile)?;
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic).map_err(|_| Error::Truncated)?;
        if &magic != b"QVAULT02" {
            return Err(Error::Aead);
        }
        let mut len_bytes = [0u8; 8];
        file.read_exact(&mut len_bytes).map_err(|_| Error::Truncated)?;
        let len = u64::from_le_bytes(len_bytes);
        let mut json = vec![0u8; len as usize];
        file.read_exact(&mut json).map_err(|_| Error::Truncated)?;
        let h = serde_json::from_slice(&json).map_err(|_| Error::Aead)?;
        Ok((h, 8 + 8 + len))
    }

    #[test]
    fn test_flow_real_decoy_tampering() {
        let temp_dir = std::env::temp_dir();
        let unique_id = rand::random::<u64>();
        let container_path = temp_dir.join(format!("container_{}.qv", unique_id));
        let real_pwd = b"secret123";
        let decoy_pwd = b"decoy456";

        // 1. Crear contenedor con decoy
        let _initial_header = create_test_container(&container_path, real_pwd, Some(decoy_pwd));

        // 2. Unlock con password real
        let (header, _data_start) = read_header_v2(&container_path).unwrap();
        let mut vault = Vault::unlock(header, real_pwd).unwrap();
        assert_eq!(vault.active_slot, 0);

        // 3. Añadir archivo
        let original_data = b"Hello, World!";
        let file_id = "test-file-id-123456";
        let dek = Key::random();
        let encrypted_file = encrypt_file(&dek, original_data, file_id).unwrap();
        let wrapped_dek = wrap_key(&vault.master_key, &dek, file_id.as_bytes()).unwrap();

        let entry = VaultEntry {
            id: file_id.to_string(),
            name: "test.txt".to_string(),
            size: original_data.len() as u64,
            mime_type: "text/plain".to_string(),
            encrypted_at: 123456789,
            data_offset: 0,
            data_len: encrypted_file.len() as u64,
            wrapped_dek,
        };
        vault.index.push(entry);

        // Persistir cambio
        let index_bytes = serde_json::to_vec(&vault.index).unwrap();
        let encrypted_index = encrypt_index(&vault.master_key, &index_bytes).unwrap();
        vault.header.encrypted_indices[0] = encrypted_index;

        let header_json = serde_json::to_vec(&vault.header).unwrap();
        let len = header_json.len() as u64;
        {
            let mut file = File::create(&container_path).unwrap();
            file.write_all(b"QVAULT02").unwrap();
            file.write_all(&len.to_le_bytes()).unwrap();
            file.write_all(&header_json).unwrap();
            file.write_all(&encrypted_file).unwrap();
        }

        // 4. Lock (drop) y volver a abrir (Unlock) con password real
        let (header2, data_start2) = read_header_v2(&container_path).unwrap();
        let vault2 = Vault::unlock(header2, real_pwd).unwrap();
        assert_eq!(vault2.active_slot, 0);
        assert_eq!(vault2.index.len(), 1);

        // Leer y descifrar archivo
        let entry_read = &vault2.index[0];
        let mut file_read = File::open(&container_path).unwrap();
        file_read.seek(SeekFrom::Start(data_start2 + entry_read.data_offset)).unwrap();
        let mut encrypted_buf = vec![0u8; entry_read.data_len as usize];
        file_read.read_exact(&mut encrypted_buf).unwrap();

        let dek_unwrapped = unwrap_key(&vault2.master_key, &entry_read.wrapped_dek, entry_read.id.as_bytes()).unwrap();
        let decrypted_data = decrypt_file(&dek_unwrapped, &encrypted_buf, &entry_read.id).unwrap();
        assert_eq!(decrypted_data, original_data);

        // 5. Borrar archivo del índice
        let mut vault3 = vault2;
        vault3.crypto_erase_file(file_id);
        assert_eq!(vault3.index.len(), 0);

        // 6. Probar unlock con decoy password
        let (header3, _) = read_header_v2(&container_path).unwrap();
        let vault_decoy = Vault::unlock(header3, decoy_pwd).unwrap();
        assert_eq!(vault_decoy.active_slot, 1);
        assert_eq!(vault_decoy.index.len(), 0);

        // 7. Probar password equivocado
        let (header4, _) = read_header_v2(&container_path).unwrap();
        let unlock_err = Vault::unlock(header4, b"wrong_pwd");
        assert!(unlock_err.is_err());

        // 8. Corrupción de keyslot ct → el AEAD rechaza el unwrap
        let (mut header_tampered, _) = read_header_v2(&container_path).unwrap();
        header_tampered.keyslots[0].ct[0] ^= 0xFF;
        let unlock_tampered = Vault::unlock(header_tampered, real_pwd);
        assert!(unlock_tampered.is_err());

        // 9. Corrupción de bloque de datos cifrado → decrypt_file falla por AEAD
        let mut tampered_blob = encrypted_file.clone();
        tampered_blob[NONCE_LEN + 1] ^= 0xFF;
        let decrypt_err = decrypt_file(&dek, &tampered_blob, file_id);
        assert!(decrypt_err.is_err());

        // 10. Manipulación de params KDF → el AEAD rechaza (AAD no coincide)
        let (mut header_params, _) = read_header_v2(&container_path).unwrap();
        header_params.m_cost = 8192; // cambiar params sin cambiar el keyslot ct
        let unlock_params = Vault::unlock(header_params, real_pwd);
        assert!(unlock_params.is_err());

        // 11. Validación de versión → version != 2 rechazado
        let (mut header_ver, _) = read_header_v2(&container_path).unwrap();
        header_ver.version = 99;
        let unlock_ver = Vault::unlock(header_ver, real_pwd);
        assert!(unlock_ver.is_err());

        // 12. Validación de params KDF → m_cost absurdo rechazado antes de Argon2
        let (mut header_dos, _) = read_header_v2(&container_path).unwrap();
        header_dos.m_cost = 999_999_999;
        let unlock_dos = Vault::unlock(header_dos, real_pwd);
        assert!(unlock_dos.is_err());

        // Limpiar
        let _ = std::fs::remove_file(&container_path);
    }

    #[test]
    fn test_mk_rotation() {
        let temp_dir = std::env::temp_dir();
        let unique_id = rand::random::<u64>();
        let container_path = temp_dir.join(format!("rotation_{}.qv", unique_id));
        let real_pwd = b"rotation_test_pwd";
        let decoy_pwd = b"decoy_rotation";

        // 1. Crear contenedor con decoy y un archivo
        let _header = create_test_container(&container_path, real_pwd, Some(decoy_pwd));

        let (header, _) = read_header_v2(&container_path).unwrap();
        let mut vault = Vault::unlock(header, real_pwd).unwrap();
        assert_eq!(vault.active_slot, 0);

        // Añadir un archivo
        let original_data = b"data before rotation";
        let file_id = "rotation-test-file";
        let dek = Key::random();
        let encrypted_file = encrypt_file(&dek, original_data, file_id).unwrap();
        let wrapped_dek = wrap_key(&vault.master_key, &dek, file_id.as_bytes()).unwrap();
        vault.index.push(VaultEntry {
            id: file_id.to_string(),
            name: "rotated.txt".to_string(),
            size: original_data.len() as u64,
            mime_type: "text/plain".to_string(),
            encrypted_at: 12345,
            data_offset: 0,
            data_len: encrypted_file.len() as u64,
            wrapped_dek,
        });

        // Persistir
        let index_bytes = serde_json::to_vec(&vault.index).unwrap();
        let enc_idx = encrypt_index(&vault.master_key, &index_bytes).unwrap();
        vault.header.encrypted_indices[0] = enc_idx;
        let hdr_json = serde_json::to_vec(&vault.header).unwrap();
        let len = hdr_json.len() as u64;
        {
            let mut f = File::create(&container_path).unwrap();
            f.write_all(b"QVAULT02").unwrap();
            f.write_all(&len.to_le_bytes()).unwrap();
            f.write_all(&hdr_json).unwrap();
            f.write_all(&encrypted_file).unwrap();
        }

        // 2. Rotar MK
        vault.rotate_master_key(real_pwd).unwrap();

        // 3. Verificar: la DEK se desenvuelve con la nueva MK
        let entry = &vault.index[0];
        let dek_after = unwrap_key(&vault.master_key, &entry.wrapped_dek, entry.id.as_bytes()).unwrap();
        let decrypted = decrypt_file(&dek_after, &encrypted_file, file_id).unwrap();
        assert_eq!(decrypted, original_data);

        // 4. Persistir header rotado y reabrir
        let enc_idx2 = encrypt_index(&vault.master_key, &serde_json::to_vec(&vault.index).unwrap()).unwrap();
        vault.header.encrypted_indices[0] = enc_idx2;
        let hdr_json2 = serde_json::to_vec(&vault.header).unwrap();
        let len2 = hdr_json2.len() as u64;
        {
            let mut f = File::create(&container_path).unwrap();
            f.write_all(b"QVAULT02").unwrap();
            f.write_all(&len2.to_le_bytes()).unwrap();
            f.write_all(&hdr_json2).unwrap();
            f.write_all(&encrypted_file).unwrap();
        }

        let (header2, _) = read_header_v2(&container_path).unwrap();
        let vault2 = Vault::unlock(header2, real_pwd).unwrap();
        assert_eq!(vault2.active_slot, 0);
        assert_eq!(vault2.index.len(), 1);

        // 5. Decoy sigue funcionando (salt no cambió)
        let (header3, _) = read_header_v2(&container_path).unwrap();
        let vault_decoy = Vault::unlock(header3, decoy_pwd).unwrap();
        assert_eq!(vault_decoy.active_slot, 1);
        assert_eq!(vault_decoy.index.len(), 0);

        // 6. Segunda rotación — sigue funcionando
        let (header4, _) = read_header_v2(&container_path).unwrap();
        let mut vault4 = Vault::unlock(header4, real_pwd).unwrap();
        vault4.rotate_master_key(real_pwd).unwrap();
        let entry4 = &vault4.index[0];
        let dek4 = unwrap_key(&vault4.master_key, &entry4.wrapped_dek, entry4.id.as_bytes()).unwrap();
        let decrypted4 = decrypt_file(&dek4, &encrypted_file, file_id).unwrap();
        assert_eq!(decrypted4, original_data);

        let _ = std::fs::remove_file(&container_path);
    }
}
