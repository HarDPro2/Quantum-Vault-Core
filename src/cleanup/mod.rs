// cleanup/mod.rs — Limpieza de rastros en Windows
// Limpia: Recent Files, Jump Lists, Thumbnail Cache, archivos temporales
pub mod commands;

use anyhow::Result;

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
                            if let Err(e) = std::fs::remove_dir_all(&path) {
                                tracing::warn!("Fallo al eliminar temp dir: {}", e);
                            } else {
                                tracing::debug!("Temp dir eliminado: {:?}", path);
                            }
                        }
                    } else if name.starts_with("qv_import_") {
                        if let Err(e) = std::fs::remove_file(&path) {
                            tracing::warn!("Fallo al eliminar temp file: {}", e);
                        } else {
                            tracing::debug!("Temp file eliminado: {:?}", path);
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

    tracing::info!("Archivos temporales: limpieza completada");
    Ok(())
}