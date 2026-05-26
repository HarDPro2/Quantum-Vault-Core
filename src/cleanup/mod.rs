// cleanup/mod.rs — Limpieza quirúrgica de rastros en Windows (Zero Footprint)
// Limpia: Recent Files, Jump Lists, Thumbnail Cache, archivos temporales
pub mod commands;

use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

/// Tamaño del buffer de escritura para borrado seguro (1 MiB).
const SECURE_WIPE_CHUNK: usize = 1024 * 1024;

/// Borra un archivo siguiendo el estándar **DOD 5220.22-M (E)** de 3 pasadas:
///   1. `0x00` en todo el contenido
///   2. `0xFF` en todo el contenido
///   3. Datos aleatorios criptográficos (OsRng)
///
/// Tras cada pasada se llama a `sync_all()` para forzar al SO a vaciar los
/// buffers de disco antes de la siguiente sobreescritura. Al final se elimina
/// la entrada del directorio.
///
/// Limitaciones honestas (declaradas):
///   - En SSDs con wear-levelling y TRIM el bloque físico puede haber sido
///     reasignado; el sobrescrito lógico no garantiza purga del bloque físico.
///   - En sistemas de archivos copy-on-write (ReFS, Btrfs, APFS) la sobre-
///     escritura puede caer en un bloque nuevo. Para amenazas forenses serias
///     hay que combinarlo con cifrado de disco completo.
///   - En enlaces simbólicos sobreescribimos el archivo apuntado, no el link.
pub fn secure_delete_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(()); // Idempotente: borrar lo que no existe es éxito silencioso.
    }

    if path.is_dir() {
        anyhow::bail!("secure_delete_file: la ruta es un directorio, usa secure_delete_dir");
    }

    let meta = std::fs::metadata(path)
        .with_context(|| "secure_delete_file: no se pudo leer metadata")?;
    let size = meta.len();

    // Si está vacío, simplemente borramos.
    if size == 0 {
        return std::fs::remove_file(path)
            .with_context(|| "secure_delete_file: no se pudo eliminar archivo vacío");
    }

    // Abrimos en RW para sobrescribir EN-SITU (sin copiar a otro inodo).
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| "secure_delete_file: no se pudo abrir en RW")?;

    // ── Pasada 1: 0x00 ─────────────────────────────────────────
    wipe_pass(&mut file, size, FillPattern::Zeros)
        .with_context(|| "secure_delete_file: fallo pasada 0x00")?;

    // ── Pasada 2: 0xFF ─────────────────────────────────────────
    wipe_pass(&mut file, size, FillPattern::Ones)
        .with_context(|| "secure_delete_file: fallo pasada 0xFF")?;

    // ── Pasada 3: random criptográfico ─────────────────────────
    wipe_pass(&mut file, size, FillPattern::Random)
        .with_context(|| "secure_delete_file: fallo pasada random")?;

    // Cerrar handle antes de borrar (Windows mantiene lock).
    drop(file);

    // Eliminar la entrada del directorio. En este punto los bytes del archivo
    // han sido sobrescritos 3 veces. La entrada de nombre, aún así, podría
    // dejar rastro en el journal del FS — pero la app usa nombres stealth.
    std::fs::remove_file(path)
        .with_context(|| "secure_delete_file: no se pudo eliminar tras wipe")?;

    tracing::debug!(
        target: "vault_desktop::secure_delete",
        bytes = size,
        "DOD 5220.22-M completado y archivo eliminado"
    );
    Ok(())
}

#[derive(Clone, Copy)]
enum FillPattern {
    Zeros,
    Ones,
    Random,
}

fn wipe_pass(file: &mut std::fs::File, size: u64, pattern: FillPattern) -> Result<()> {
    use rand::RngCore;

    file.seek(SeekFrom::Start(0))?;

    let mut remaining = size;
    let mut buffer = vec![0u8; SECURE_WIPE_CHUNK.min(remaining as usize).max(1)];

    while remaining > 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        let slice = &mut buffer[..chunk];

        match pattern {
            FillPattern::Zeros => slice.fill(0x00),
            FillPattern::Ones => slice.fill(0xFF),
            FillPattern::Random => rand::rngs::OsRng.fill_bytes(slice),
        }

        file.write_all(slice)?;
        remaining -= chunk as u64;
    }

    // Flush a kernel + flush a hardware (fsync). Crítico: sin esto la pasada
    // siguiente podría sobreescribir en el caché del SO sin tocar el plato.
    file.flush()?;
    file.sync_all()?;
    Ok(())
}

/// Borra recursivamente un directorio, aplicando `secure_delete_file` a cada
/// archivo regular. Útil para limpiar `qv_temp/` o `qv_import_*`.
pub fn secure_delete_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    if !dir.is_dir() {
        return secure_delete_file(dir);
    }

    let mut last_err: Option<anyhow::Error> = None;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let res = if path.is_dir() {
                secure_delete_dir(&path)
            } else {
                secure_delete_file(&path)
            };
            if let Err(e) = res {
                tracing::warn!(target: "vault_desktop::secure_delete", error = %e, "fallo en entrada");
                last_err = Some(e);
            }
        }
    }

    // El directorio en sí puede borrarse normalmente — su contenido ya está purgado.
    std::fs::remove_dir_all(dir)
        .with_context(|| "secure_delete_dir: no se pudo eliminar directorio")?;

    if let Some(e) = last_err {
        return Err(e);
    }
    Ok(())
}

/// Limpieza completa al cerrar la bóveda
/// Se ejecuta síncrono para garantizar que termine antes de cerrar la ventana
pub fn cleanup_on_close() -> Result<()> {
    tracing::info!("Iniciando limpieza de rastros...");

    #[cfg(target_os = "windows")]
    {
        if let Err(e) = clear_recent_files() {
            tracing::warn!("Error limpiando Recent Files: {}", e);
        }
        if let Err(e) = clear_jump_lists() {
            tracing::warn!("Error limpiando Jump Lists: {}", e);
        }
        if let Err(e) = clear_thumbnail_cache() {
            tracing::warn!("Error limpiando Thumbnail Cache: {}", e);
        }
        if let Err(e) = clear_temp_files() {
            tracing::warn!("Error limpiando archivos temporales: {}", e);
        }
    }

    tracing::info!("Limpieza completada");
    Ok(())
}

/// Borra archivos recientes que contengan nombres sospechosos
/// Solo limpia archivos .lnk recientes de las últimas 24h para no levantar sospechas
#[cfg(target_os = "windows")]
fn clear_recent_files() -> Result<()> {
    use std::time::{SystemTime, Duration};

    if let Ok(appdata) = std::env::var("APPDATA") {
        let recent = std::path::PathBuf::from(appdata)
            .join("Microsoft").join("Windows").join("Recent");

        if !recent.exists() {
            return Ok(());
        }

        let now = SystemTime::now();
        let threshold = Duration::from_secs(86400); // 24h

        // Nombres de archivos stealth que podrían aparecer en Recent
        let stealth_names = [
            "cache_v2", "telemetry", "report_queue", "sync_engine",
            "cloud_manifest", "inetres", "state_repo", "action_store",
            "font_staging", "shader_cache", "diag_trace", "container_map",
            "thumbcache_srv", "netprofm", "wer_heap", "cache_data",
            "qvault", "qv_import", "qv_temp",
        ];

        if let Ok(entries) = std::fs::read_dir(&recent) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_stem()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_lowercase();

                // Solo borrar si: es .lnk Y (fue creado recientemente O contiene nombre stealth)
                let is_lnk = path.extension().and_then(|e| e.to_str()) == Some("lnk");
                let is_stealth = stealth_names.iter().any(|s| name.contains(s));

                if is_lnk && is_stealth {
                    // Verificar que sea reciente
                    if let Ok(meta) = std::fs::metadata(&path) {
                        if let Ok(modified) = meta.modified() {
                            if let Ok(age) = now.duration_since(modified) {
                                if age < threshold {
                                    let _ = std::fs::remove_file(&path);
                                    tracing::debug!("Recent file eliminado: {:?}", path);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    tracing::info!("Recent Files: limpieza selectiva completada");
    Ok(())
}

/// Limpia las Jump Lists de la app (AutomaticDestinations)
/// Busca archivos .automaticDestinations-ms modificados recientemente
#[cfg(target_os = "windows")]
fn clear_jump_lists() -> Result<()> {
    use std::time::{SystemTime, Duration};

    if let Ok(appdata) = std::env::var("APPDATA") {
        let auto_dest = std::path::PathBuf::from(&appdata)
            .join("Microsoft").join("Windows")
            .join("Recent").join("AutomaticDestinations");

        let custom_dest = std::path::PathBuf::from(&appdata)
            .join("Microsoft").join("Windows")
            .join("Recent").join("CustomDestinations");

        let now = SystemTime::now();
        let threshold = Duration::from_secs(300); // Últimos 5 min solamente

        for dir in [&auto_dest, &custom_dest] {
            if !dir.exists() { continue; }
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Ok(meta) = std::fs::metadata(&path) {
                        if let Ok(modified) = meta.modified() {
                            if let Ok(age) = now.duration_since(modified) {
                                // Solo tocamos archivos modificados en los últimos 5 min
                                // (que son los que nuestra app pudo haber provocado)
                                if age < threshold {
                                    // No borramos, solo truncamos a 0 bytes
                                    // Borrar el archivo puede causar que Explorer lo recree
                                    if let Ok(file) = std::fs::OpenOptions::new()
                                        .write(true).truncate(true).open(&path) {
                                        drop(file);
                                        tracing::debug!("Jump list truncada: {:?}", path);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    tracing::info!("Jump Lists: limpieza completada");
    Ok(())
}

/// Limpia las miniaturas (thumbnails) que Windows genera automáticamente
/// cuando abrimos imágenes/videos con el sistema
#[cfg(target_os = "windows")]
fn clear_thumbnail_cache() -> Result<()> {
    if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
        let explorer = std::path::PathBuf::from(localappdata)
            .join("Microsoft").join("Windows").join("Explorer");

        if !explorer.exists() {
            return Ok(());
        }

        // Los thumbcache_*.db se regeneran automáticamente
        // Podemos vaciarlos de forma segura, Explorer los recreará
        if let Ok(entries) = std::fs::read_dir(&explorer) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");

                if name.starts_with("thumbcache_") && name.ends_with(".db") {
                    // Vaciar el archivo en lugar de borrarlo
                    if let Ok(_file) = std::fs::OpenOptions::new()
                        .write(true).truncate(true).open(&path) {
                        tracing::debug!("Thumbnail cache vaciado: {:?}", path);
                    }
                }

                // iconcache_*.db también puede contener pistas
                if name.starts_with("iconcache_") && name.ends_with(".db") {
                    if let Ok(_file) = std::fs::OpenOptions::new()
                        .write(true).truncate(true).open(&path) {
                        tracing::debug!("Icon cache vaciado: {:?}", path);
                    }
                }
            }
        }
    }

    tracing::info!("Thumbnail Cache: limpieza completada");
    Ok(())
}

/// Limpia archivos temporales creados por open_with_system.
/// Cada archivo se borra con `secure_delete_file` (3 pasadas DOD).
#[cfg(target_os = "windows")]
fn clear_temp_files() -> Result<()> {
    // Buscar en el directorio de cache de la app
    if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
        let cache_base = std::path::PathBuf::from(localappdata)
            .join("com.qvault.app");

        if cache_base.exists() {
            fn clean_dir(dir: &std::path::Path) {
                let Ok(entries) = std::fs::read_dir(dir) else { return };
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = path.file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");

                    if path.is_dir() {
                        if name == "qv_temp" || name.starts_with("qv_import") {
                            if let Err(e) = secure_delete_dir(&path) {
                                tracing::warn!("Fallo wipe temp dir: {}", e);
                            } else {
                                tracing::debug!("Temp dir purgado (DOD): {:?}", path);
                            }
                        }
                    } else if name.starts_with("qv_import_") {
                        if let Err(e) = secure_delete_file(&path) {
                            tracing::warn!("Fallo wipe temp file: {}", e);
                        } else {
                            tracing::debug!("Temp file purgado (DOD): {:?}", path);
                        }
                    }
                }
            }
            clean_dir(&cache_base);

            // También limpiar subdirectorios del cache
            if let Ok(entries) = std::fs::read_dir(&cache_base) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        clean_dir(&entry.path());
                    }
                }
            }
        }
    }

    tracing::info!("Archivos temporales: limpieza completada (DOD 5220.22-M)");
    Ok(())
}