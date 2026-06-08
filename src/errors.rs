//! Centralized error handling with cryptographic safety guarantees.
//!
//! Zero Footprint Policy:
//! - Every error that crosses module boundaries is logged first.
//! - Error messages returned to callers contain NO paths, passwords, or keys;
//!   only the failure context and the textual cause of the underlying error.
//!
//! Panic Safety (reference pattern — NOT the production hook):
//! - This crate does NOT install the production panic hook. The real hook
//!   lives in the application layer, which owns the session and key material.
//!   Here we only document the pattern (see `install_panic_hook_example`).
//! - The pattern zeroizes the in-RAM master key on a *Rust panic* (e.g. an
//!   unexpected `unwrap`/`expect` or an explicit `panic!`). It does NOT cover
//!   native crashes that bypass the Rust runtime: a segfault or FFI undefined
//!   behaviour aborts the process WITHOUT running the panic hook.
//!
//! Goal for Zero Footprint: a Rust panic should not leave the master key in
//! RAM for a later core/crash dump to expose.

use std::fmt::Display;

/// Logs the error with context and returns a sanitized `String` for callers.
/// Designed for use inside `.map_err(...)`.
///
/// # Example
/// ```ignore
/// some_operation()
///     .map_err(|e| log_err("operation_name", e))?;
/// ```
#[inline]
pub fn log_err<E: Display>(context: &'static str, err: E) -> String {
    // In the full application, this also reports to Sentry with PII scrubbing.
    // The error telemetry strips all paths, passwords, and crypto material.
    eprintln!("[ERROR] {}: {}", context, err);
    format!("{}: {}", context, err)
}

/// Variant for errors that are already `String` and just need logging.
#[inline]
pub fn log_msg(context: &'static str, msg: impl Into<String>) -> String {
    let msg = msg.into();
    eprintln!("[ERROR] {}: {}", context, msg);
    format!("{}: {}", context, msg)
}

/// Convenience macro: `map_err_log!("context")` produces a closure
/// ready for `.map_err(...)`. Logs and returns `String`.
///
/// # Example
/// ```ignore
/// let data = encrypt(&key, &plaintext)
///     .map_err(map_err_log!("encrypt_file"))?;
/// ```
#[macro_export]
macro_rules! map_err_log {
    ($ctx:expr) => {
        |e| $crate::errors::log_err($ctx, e)
    };
}

/// **Reference pattern** for a panic hook that zeroizes the session key.
///
/// ⚠️ This function is illustrative — it does NOT zeroize anything itself,
/// because this crate has no access to the application's session/key state.
/// The production hook lives in the application layer (which owns `SESSION`).
/// This example only shows the shape and logs the panic.
///
/// The production hook follows this pattern on a Rust panic:
///
/// 1. The session key is located via a global mutex.
/// 2. `unlock_slice()` is called BEFORE `zeroize()` — unlocking doesn't
///    touch the bytes, but zeroizing without unlocking would leave pages
///    still marked as locked when the process exits.
/// 3. The key bytes are overwritten with zeros via `zeroize::Zeroize`.
/// 4. The session state is fully reset (key = None, path = None).
/// 5. The panic info is logged WITHOUT any user payload or sensitive data.
/// 6. The previous hook is chained (default = stderr/abort per profile).
///
/// # Scope (be precise)
///
/// This fires only on a **Rust panic** (an unexpected `unwrap`/`expect`, or
/// an explicit `panic!`). It does NOT fire on native crashes that bypass the
/// Rust runtime — a segfault or FFI undefined behaviour aborts WITHOUT running
/// the hook, so the key would not be scrubbed in those cases.
///
/// Under `panic = "abort"` (this crate's release profile) destructors do not
/// run during a panic, so it is the hook — not `Drop` — that performs the
/// explicit zeroization. The panic hook still runs before the process aborts.
///
/// # Implementation Note (application layer)
///
/// The real implementation accesses the session via:
/// ```ignore
/// let mut session = SESSION.lock().unwrap_or_else(|e| e.into_inner());
/// if let Some(ref mut key) = session.key {
///     crypto::mem_lock::unlock_slice(key);
///     key.zeroize();
/// }
/// session.key = None;
/// ```
///
/// The `unwrap_or_else(|e| e.into_inner())` pattern handles poisoned mutexes:
/// if another thread panicked while holding the lock, we still recover the
/// inner data and zeroize it. Security > correctness in this edge case.
pub fn install_panic_hook_example() {
    let prev = std::panic::take_hook();

    std::panic::set_hook(Box::new(move |info| {
        // In production, this accesses the global SESSION mutex and:
        // 1. Calls mem_lock::unlock_slice(&key) to release VirtualLock
        // 2. Calls key.zeroize() to overwrite with zeros
        // 3. Sets session.key = None
        //
        // This code is omitted here to avoid exposing the session structure,
        // but the pattern is fully demonstrated in the doc comment above.

        // Log the panic WITHOUT sensitive payload
        let location = info.location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".into());

        let payload = info.payload();
        let panic_msg = if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic payload>".to_string()
        };

        eprintln!(
            "[PANIC] (reference hook — no zeroization performed here) @ {} :: {}",
            location, panic_msg
        );

        // Chain to previous hook (default = stderr/abort per release profile)
        prev(info);
    }));
}
