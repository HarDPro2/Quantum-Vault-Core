//! # Quantum Vault Core
//!
//! Open-source cryptographic engine powering [Quantum Vault](https://quantum-vault-web.vercel.app).
//!
//! This crate contains the security-critical modules that handle:
//! - **AES-256-GCM** encryption/decryption with authenticated encryption
//! - **Argon2id** key derivation (OWASP high-security parameters)
//! - **Shamir Secret Sharing** for key recovery
//! - **Memory locking** (`VirtualLock`/`mlock`) to prevent key paging
//! - **DOD 5220.22-M** secure file deletion (3-pass overwrite)
//! - **Panic-safe key zeroization** for defense-in-depth
//!
//! ## Design Philosophy
//!
//! 1. **Zero custom crypto.** Every cryptographic primitive comes from
//!    audited [RustCrypto](https://github.com/RustCrypto) crates.
//! 2. **Zero footprint.** Keys never touch swap/pagefile, temp files
//!    are DOD-wiped, and crash dumps can't leak key material.
//! 3. **Honest limitations.** We document what we CAN'T protect against
//!    (SSD wear-levelling, CoW filesystems) instead of making false claims.
//!
//! ## License
//!
//! This crate is licensed under [AGPL-3.0](LICENSE). If you use this code
//! in your application, your entire application must also be AGPL-3.0.

pub mod crypto;
pub mod cleanup;
pub mod errors;
pub mod crypto_erase;
