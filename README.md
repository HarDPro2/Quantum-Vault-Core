<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/AES--256--GCM-00897B?style=for-the-badge&logo=letsencrypt&logoColor=white" alt="AES-256-GCM">
  <img src="https://img.shields.io/badge/License-AGPL%20v3-blue.svg?style=for-the-badge" alt="AGPL-3.0">
  <img src="https://img.shields.io/badge/Zero%20Custom%20Crypto-✓-brightgreen?style=for-the-badge" alt="No custom crypto">
</p>

<h1 align="center">🔐 Quantum Vault Core</h1>

<p align="center">
  <strong>Open-source cryptographic engine powering <a href="https://quantum-vault-web.vercel.app">Quantum Vault</a></strong><br>
  <em>AES-256-GCM · Argon2id · Memory Locking · DOD 5220.22-M Secure Delete</em>
</p>

---

## Why Open Source This?

Trust is everything for security software. Instead of asking you to trust our marketing claims, we're showing you the code that protects your data.

**This repository contains ~20% of the Quantum Vault codebase** — specifically, all security-critical modules:

| Module | What It Does | Lines |
|--------|-------------|-------|
| `crypto/mod.rs` | AES-256-GCM encryption + Argon2id key derivation + Shamir SSS | 129 |
| `crypto/mem_lock.rs` | `VirtualLock`/`mlock` — keys never touch swap/pagefile | 100 |
| `crypto/commands.rs` | Zeroize patterns for safe key handling | 95 |
| `cleanup/mod.rs` | DOD 5220.22-M secure delete (3-pass overwrite) | 383 |
| `cleanup/commands.rs` | Safe public API for secure file deletion | 56 |
| `errors.rs` | Panic hook that zeroizes keys before process death | 115 |

The remaining 80% (UI, vault container format, stealth system, licensing) remains closed-source.

---

## Security Architecture

### 🔑 Encryption: AES-256-GCM

```
Password → Argon2id(64MB, 3 iterations, 4 parallelism) → 256-bit Key → AES-256-GCM
```

- **Algorithm:** AES-256-GCM (authenticated encryption with associated data)
- **Key Derivation:** Argon2id with OWASP high-security parameters
  - Memory: 64 MB (resists GPU attacks)
  - Time cost: 3 iterations (~500ms on modern hardware)
  - Parallelism: 4 threads
- **Nonce:** 12 bytes from OS cryptographic RNG (`OsRng`)
- **Format:** `[nonce (12B) | ciphertext | GCM tag (16B)]`

### 🧠 Memory Protection

```
Key derived → VirtualLock(key) → Use key → Zeroize(key) → VirtualUnlock(key)
```

- **Windows:** `VirtualLock` prevents the OS from paging key memory to `pagefile.sys`
- **Linux:** `mlock` prevents paging to swap
- **On panic:** Global hook calls `unlock → zeroize → reset` before process death
- **On drop:** `Zeroizing<Vec<u8>>` wrapper guarantees zeroing even on error paths

### 🗑️ Secure Deletion: DOD 5220.22-M

```
Pass 1: Write 0x00 to entire file → fsync
Pass 2: Write 0xFF to entire file → fsync
Pass 3: Write crypto random bytes → fsync
Final: Delete file entry from directory
```

**Honest limitations (we declare these upfront):**
- ⚠️ SSDs with wear-levelling/TRIM may remap physical blocks
- ⚠️ Copy-on-write filesystems (ReFS, Btrfs, APFS) may write to new blocks
- ⚠️ For serious forensic threats, combine with full-disk encryption

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
| `aes-gcm` | 0.10 | AES-256-GCM authenticated encryption | RustCrypto |
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
    ├── errors.rs       # Panic hook with key zeroization
    ├── crypto/
    │   ├── mod.rs      # AES-256-GCM + Argon2id + Shamir SSS
    │   ├── mem_lock.rs # VirtualLock/mlock memory protection
    │   └── commands.rs # Zeroize wrapper patterns
    └── cleanup/
        ├── mod.rs      # DOD 5220.22-M secure file deletion
        └── commands.rs # Public API with input validation
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
- 💀 Panic button (instant lock + hide + trace cleanup)

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
