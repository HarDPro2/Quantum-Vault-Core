<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/XChaCha20--Poly1305-00897B?style=for-the-badge&logo=letsencrypt&logoColor=white" alt="XChaCha20-Poly1305">
  <img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg?style=for-the-badge" alt="AGPL-3.0">
  <img src="https://img.shields.io/badge/Zero%20Custom%20Crypto-✓-brightgreen?style=for-the-badge" alt="No custom crypto">
</p>

<h1 align="center">🔐 Quantum Vault Core</h1>

<p align="center">
  <strong>Open-source cryptographic engine powering <a href="https://quantum-vault-web.vercel.app">Quantum Vault</a></strong><br>
  <em>XChaCha20-Poly1305 · Argon2id · Memory Locking · Crypto-Erase Secure Delete</em>
</p>

---

## Why Open Source This?

Trust is everything for security software. Instead of asking you to trust our marketing claims, we're showing you the code that protects your data.

**This repository contains ~20% of the Quantum Vault codebase** — specifically, all security-critical modules:

| Module | What It Does | Lines |
|--------|-------------|-------|
| `crypto_erase.rs` | XChaCha20-Poly1305 + Argon2id KEK + Vault/key hierarchy | 618 |
| `crypto/mod.rs` | Shamir Secret Sharing | 47 |
| `crypto/mem_lock.rs` | `VirtualLock`/`mlock` — keys never touch swap/pagefile | 99 |
| `crypto/commands.rs` | Zeroize patterns for safe key handling | 74 |
| `errors.rs` | Reference panic-hook pattern (production hook lives in the app) | 139 |

The remaining 80% (UI, vault container format, stealth system, licensing) remains closed-source.

---

## Security Architecture

### 🔑 Encryption: XChaCha20-Poly1305

```
Password → Argon2id → 256-bit Key (KEK) → XChaCha20-Poly1305
```

- **Algorithm:** XChaCha20-Poly1305 (authenticated encryption with associated data)
- **Key derivation:** Argon2id. The memory, iteration and parallelism parameters are
  supplied per vault and validated by the core against safe bounds:
  memory 4–512 MiB, iterations 1–64, parallelism 1–16.
- **Nonce:** 24 bytes from OS cryptographic RNG (`OsRng`)
- **Format:** `[nonce (24B) | ciphertext | Poly1305 tag (16B)]`

### 🧠 Memory Protection

```
Key derived → VirtualLock(key) → Use key → Zeroize(key) → VirtualUnlock(key)
```

- **Windows:** `VirtualLock` prevents the OS from paging key memory to `pagefile.sys`
- **Linux:** `mlock` prevents paging to swap
- **On panic:** Global hook calls `unlock → zeroize → reset` before process death
- **On drop:** `Zeroizing<Vec<u8>>` wrapper guarantees zeroing even on error paths

### 🗑️ Secure Deletion: Crypto-Erase (Key Destruction)

Quantum Vault does not overwrite file bytes — overwriting is ineffective on modern
SSDs and copy-on-write filesystems. Instead it uses **crypto-erase**:

- Every file is encrypted under its own random per-file key (DEK).
- That DEK exists only wrapped under the master key, inside the encrypted index.
- Deleting a file removes its wrapped DEK from the index and atomically rewrites
  the container (temp → fsync → rename).
- With the wrapped DEK gone from the persisted index, the file's ciphertext is left
  under a key that no longer exists → mathematically unrecoverable.

(The file-level delete is orchestrated by the vault/app layer using this key hierarchy.)

**Honest limitations:**
- Traces of the old wrapped key may survive in unallocated SSD cells. They are useless
  without your master password; rotating the master key renders even those undecryptable.
- The container is not compacted: deleted blocks remain as unreadable random noise.

### 🔀 Key Recovery: Shamir Secret Sharing

Split your master key into N shares, requiring K to reconstruct:

```
Master Key → Shamir(threshold=3, total=5) → 5 shares
Any 3 shares → Original Master Key
```

- Threshold: 2–10
- Total shares: threshold–10
- Each share is zeroized after recovery

---

## Dependencies (All Audited)

Every cryptographic dependency comes from the [RustCrypto](https://github.com/RustCrypto) project or well-established Rust crates:

| Crate | Version | Purpose | Project |
|-------|---------|---------|---------|
| `chacha20poly1305` | 0.10 | XChaCha20-Poly1305 authenticated encryption | RustCrypto |
| `argon2` | 0.5 | Argon2id key derivation | RustCrypto |
| `zeroize` | 1.0 | Secure memory zeroing | RustCrypto |
| `sha2` | 0.10 | SHA-256 hashing | RustCrypto |
| `rand` | 0.8 | Cryptographic RNG | Rust |
| `sharks` | 0.5 | Shamir Secret Sharing | — |
| `hex` | 0.4 | Hex encoding | — |

**Zero custom cryptography.** We don't implement any primitives ourselves.

### Release Profile (Security-Hardened)

```toml
[profile.release]
panic = "abort"       # No unwinding → smaller attack surface
codegen-units = 1     # Better optimization
lto = true            # Link-time optimization
strip = true          # Strip debug symbols
opt-level = "z"       # Minimize binary size
```

---

## Building

```bash
# Clone
git clone https://github.com/HarDPro2/Quantum-Vault-Core.git
cd Quantum-Vault-Core

# Build
cargo build --release

# Run tests (if added)
cargo test
```

**Requirements:**
- Rust 1.75+ (2021 edition)
- Windows: Windows SDK (for `VirtualLock`)
- Linux: Standard libc (for `mlock`)

---

## Project Structure

```
quantum-vault-core/
├── Cargo.toml          # Dependencies (crypto-only, no frameworks)
├── LICENSE             # AGPL-3.0
├── README.md           # This file
├── SECURITY.md         # Vulnerability disclosure policy
└── src/
    ├── lib.rs          # Crate root
    ├── errors.rs       # Reference panic-hook pattern (prod hook in app)
    ├── crypto_erase.rs # XChaCha20-Poly1305 + Argon2id KEK + Vault/key hierarchy
    └── crypto/
        ├── mod.rs      # Shamir Secret Sharing
        ├── mem_lock.rs # VirtualLock/mlock memory protection
        └── commands.rs # Zeroize wrapper patterns
```

---

## Full Application

This crate is the cryptographic core of **Quantum Vault**, a hardware-locked encrypted file vault for Windows and Android.

Features in the full app (closed-source):
- 🔒 Hardware-locked containers (useless on another device)
- 👻 Ghost mode (app vanishes from taskbar)
- 🎭 Window disguise (looks like Windows Update, etc.)
- 📺 In-memory media playback (photos/videos never touch disk)
- 🚪 Multiple unlock methods (hotkey, USB key, time-based)
- 🔄 Local WiFi sync between devices
- 💀 Panic button (instant lock + hide)

**Download:** [quantum-vault-web.vercel.app](https://quantum-vault-web.vercel.app)

---

## License

This project is licensed under the **GNU Affero General Public License v3.0** — see the [LICENSE](LICENSE) file.

**What this means:**
- ✅ You CAN read, audit, and learn from this code
- ✅ You CAN use it in your own AGPL-3.0 projects
- ✅ You CAN fork and modify it (under AGPL-3.0)
- ❌ You CANNOT use it in closed-source/proprietary software
- ❌ You CANNOT use it in a paid product without open-sourcing your entire app

---

<p align="center">
  <strong>Built with Rust 🦀 for maximum security and performance</strong><br>
  <a href="https://quantum-vault-web.vercel.app">Website</a> ·
  <a href="https://github.com/HarDPro2/Quantum-Vault-Core/issues">Issues</a> ·
  <a href="SECURITY.md">Security Policy</a>
</p>
