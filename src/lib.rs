//! # Quantum Vault Core
//!
//! Open-source cryptographic engine powering [Quantum Vault](https://quantum-vault-web.vercel.app).
//!
//! This crate contains the security-critical modules that handle:
//! - **XChaCha20-Poly1305** authenticated encryption for the vault container
//!   (`crypto_erase`) — the cipher the product actually runs
//! - **Argon2id** key derivation (OWASP high-security parameters) for the KEK
//! - **Shamir Secret Sharing** for key recovery
//! - **Memory locking** (`VirtualLock`/`mlock`) to prevent key paging
//! - **Crypto-erase** secure file deletion (key destruction, not overwrite)
//! - **Panic-hook pattern** for key zeroization (reference; production hook in the app)
//!
//! ## Design Philosophy
//!
//! 1. **Zero custom crypto.** Every cryptographic primitive comes from
//!    audited [RustCrypto](https://github.com/RustCrypto) crates.
//! 2. **Zero footprint.** Keys never touch swap/pagefile, temp files
//!    are zeroized, and crash dumps can't leak key material.
//! 3. **Honest limitations.** We document what we CAN'T protect against
//!    (SSD wear-levelling, CoW filesystems) instead of making false claims.
//!
//! ## License
//!
//! This crate is licensed under [AGPL-3.0](LICENSE). If you use this code
//! in your application, your entire application must also be AGPL-3.0.

pub mod crypto;
pub mod errors;
pub mod crypto_erase;
