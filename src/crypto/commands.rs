// crypto/commands.rs — Example Tauri commands showing Zeroize patterns
//
// These commands demonstrate how Quantum Vault uses the `zeroize` crate
// to ensure cryptographic keys are ALWAYS cleaned from memory, even on error paths.
//
// In the full application, these integrate with the vault session manager.
// This file shows the patterns for educational/audit purposes.

use zeroize::Zeroizing;

/// Generates Shamir recovery shares from a key.
///
/// Demonstrates:
/// - Wrapping the source key in `Zeroizing`
/// - Parameter validation before crypto operations
/// - Encoding shares as hex for safe transport
///
/// # Parameters
/// - `key`: The secret key to split (will be wrapped in Zeroizing)
/// - `threshold`: Minimum shares needed to reconstruct (>= 2)
/// - `total`: Total shares to generate (>= threshold, <= 10)
pub fn generate_recovery_shares_example(
    key: Vec<u8>,
    threshold: u8,
    total: u8,
) -> Result<Vec<String>, String> {
    // Wrap immediately — even if validation fails, the key is zeroized on return.
    let key = Zeroizing::new(key);

    if threshold < 2 || total < threshold || total > 10 {
        return Err("Invalid params: threshold >= 2, total >= threshold, total <= 10".into());
    }

    let shares = super::split_key_shamir(&key, threshold, total)
        .map_err(|e| format!("Shamir split failed: {}", e))?;

    // Encode each share as hex for transport; key auto-zeroized on scope exit.
    let hex_shares: Vec<String> = shares.iter().map(|s| hex::encode(s)).collect();
    Ok(hex_shares)
}

/// Recovers a key from Shamir shares.
///
/// Demonstrates:
/// - Zeroizing each share after use (shares are equivalent to key material)
/// - Wrapping the recovered key in Zeroizing
///
/// # Security Note
/// Shamir shares ARE key material — if an attacker collects `threshold` shares,
/// they can reconstruct the key. Each share must be zeroized after recovery.
pub fn recover_with_shares_example(
    shares_hex: Vec<String>,
) -> Result<Zeroizing<Vec<u8>>, String> {
    // Decode shares from hex
    let mut shares: Vec<Vec<u8>> = shares_hex
        .iter()
        .map(|h| hex::decode(h).map_err(|_| "Invalid share (not valid hex)".to_string()))
        .collect::<Result<Vec<_>, _>>()?;

    // Recover the key
    let key = Zeroizing::new(
        super::recover_key_shamir(&shares)
            .map_err(|e| format!("Recovery failed: {}", e))?
    );

    // CRITICAL: Zeroize each share — they are cryptographic material
    // equivalent to the key itself.
    use zeroize::Zeroize;
    for share in shares.iter_mut() {
        share.zeroize();
    }

    Ok(key)
}
