//! Bloqueo de páginas de memoria que contienen secretos.
//!
//! Objetivo: impedir que el kernel pagine la llave maestra al swap
//! (`pagefile.sys` en Windows, `/swap` en Linux). Sin esto, un atacante
//! con acceso al disco podría rescatar la clave después de cerrar la app.
//!
//! API:
//!   - `lock_slice(&[u8]) -> bool` — `true` si el bloqueo tuvo éxito.
//!   - `unlock_slice(&[u8])` — siempre intenta desbloquear (idempotente).
//!
//! Contrato:
//!   - El slice DEBE permanecer en la misma dirección de memoria hasta el
//!     `unlock_slice` correspondiente. En la práctica, esto significa que
//!     el `Vec<u8>` que aloja la clave NO debe reasignarse (`push`/`extend`)
//!     entre lock y unlock — solo `zeroize` in-place.
//!   - En Linux puede fallar si `ulimit -l` está demasiado bajo. Esto se
//!     registra como `warn` pero NO aborta la app: la clave sigue siendo
//!     funcional, solo pierde la garantía de no-paging.

#[cfg(unix)]
mod imp {
    use std::ffi::c_void;

    pub fn lock_slice(slice: &[u8]) -> bool {
        if slice.is_empty() {
            return true;
        }
        // SAFETY: mlock acepta un puntero y un tamaño; el kernel hace la
        // validación. El slice vive más que la llamada.
        let ret = unsafe {
            libc::mlock(slice.as_ptr() as *const c_void, slice.len())
        };
        if ret == 0 {
            tracing::debug!(target: "vault_desktop::mlock", bytes = slice.len(), "mlock OK");
            true
        } else {
            let err = std::io::Error::last_os_error();
            tracing::warn!(target: "vault_desktop::mlock", error = %err, "mlock falló (¿ulimit -l bajo?)");
            false
        }
    }

    pub fn unlock_slice(slice: &[u8]) {
        if slice.is_empty() {
            return;
        }
        // SAFETY: idem mlock. munlock es idempotente y seguro de invocar.
        let ret = unsafe {
            libc::munlock(slice.as_ptr() as *const c_void, slice.len())
        };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            tracing::debug!(target: "vault_desktop::mlock", error = %err, "munlock no aplicable");
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use windows::Win32::System::Memory::{VirtualLock, VirtualUnlock};

    pub fn lock_slice(slice: &[u8]) -> bool {
        if slice.is_empty() {
            return true;
        }
        // SAFETY: VirtualLock recibe un puntero válido y un length > 0.
        // El kernel verifica que la región pertenece al proceso.
        let ok = unsafe {
            VirtualLock(slice.as_ptr() as *const c_void, slice.len()).is_ok()
        };
        if ok {
            tracing::debug!(target: "vault_desktop::mlock", bytes = slice.len(), "VirtualLock OK");
        } else {
            let err = std::io::Error::last_os_error();
            tracing::warn!(target: "vault_desktop::mlock", error = %err, "VirtualLock falló");
        }
        ok
    }

    pub fn unlock_slice(slice: &[u8]) {
        if slice.is_empty() {
            return;
        }
        // SAFETY: idem VirtualLock. VirtualUnlock es seguro de invocar
        // incluso si la región no estaba bloqueada (ERROR_NOT_LOCKED).
        let _ = unsafe {
            VirtualUnlock(slice.as_ptr() as *const c_void, slice.len())
        };
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub fn lock_slice(_slice: &[u8]) -> bool { false }
    pub fn unlock_slice(_slice: &[u8]) {}
}

pub use imp::{lock_slice, unlock_slice};
