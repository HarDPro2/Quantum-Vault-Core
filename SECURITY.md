# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅ Active support  |

## Reporting a Vulnerability

If you discover a security vulnerability in Quantum Vault Core, **please do NOT open a public issue.**

Instead, report it privately:

1. **Email:** quantumvault2026@gmail.com
2. **Subject:** `[SECURITY] Brief description`
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 7 days
- **Fix & Disclosure:** Within 30 days (coordinated disclosure)

## Scope

This policy covers the code in this repository:
- `src/crypto/` — Encryption, key derivation, memory locking
- `src/cleanup/` — Secure file deletion
- `src/errors.rs` — Panic handling with key zeroization

## Out of Scope

- The full Quantum Vault application (closed-source)
- The licensing/payment system
- The web frontend

## Recognition

Security researchers who responsibly disclose vulnerabilities will be:
- Credited in the changelog (with permission)
- Given early access to Quantum Vault Elite tier

Thank you for helping keep Quantum Vault secure. 🔐
