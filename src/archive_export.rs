// SPDX-License-Identifier: GPL-3.0-or-later

//! Static archive inventory and byte-preserving extraction prototype.
//!
//! Entries are never interpreted or executed. Unsafe paths and symbolic links are reported
//! in the manifest but are not extracted.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::Path;
use std::rc::Rc;

use serde::Serialize;

const MAX_ENTRY: u64 = 32 * 1024 * 1024;
const MAX_TOTAL: u64 = 256 * 1024 * 1024;
const MAX_ARCHIVE: u64 = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;

#[derive(Debug, Serialize)]
pub struct Manifest {
    pub format_version: u32,
    pub archive_kind: &'static str,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Serialize)]
pub struct Entry {
    /// The archive's path spelling, for inspection and round-trip context.
    pub source_path: String,
    /// Relative path below `assets/`; absent when the source path is unsafe.
    pub output_path: Option<String>,
    pub size: u64,
    /// Extension-level classification only. `opaque` resources remain preserved as bytes.
    pub resource: &'static str,
    pub extracted: bool,
    #[serde(skip)]
    bytes: Rc<[u8]>,
}

/// Reads and bounds a local archive before allocating its contents.
pub fn read_archive(path: &Path) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_ARCHIVE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() as u64 > MAX_ARCHIVE {
        return Err("the compressed archive is too large".into());
    }
    Ok(bytes)
}

pub fn inventory(bytes: &[u8]) -> Result<Manifest, String> {
    if bytes.len() as u64 > MAX_ARCHIVE {
        return Err("the compressed archive is too large".into());
    }
    let mut zip =
        zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| format!("not a zip archive: {e}"))?;
    if zip.len() > MAX_ENTRIES {
        return Err("the archive has too many entries".into());
    }
    let mut entries = Vec::new();
    let mut names = HashSet::new();
    let mut paths = Vec::new();
    let mut total = 0u64;
    let mut has_wal_marker = false;
    let mut has_classic_marker = false;

    for i in 0..zip.len() {
        let mut file = zip
            .by_index(i)
            .map_err(|e| format!("cannot read archive entry {i}: {e}"))?;
        let source_path = file.name().to_string();
        if file.is_dir() {
            continue;
        }

        let mut content = Vec::new();
        let size = file
            .by_ref()
            .take(MAX_ENTRY + 1)
            .read_to_end(&mut content)
            .map_err(|e| format!("cannot read archive entry {source_path:?}: {e}"))?
            as u64;
        if size > MAX_ENTRY {
            return Err(format!("archive entry is too large: {source_path:?}"));
        }
        total = total.saturating_add(size);
        if total > MAX_TOTAL {
            return Err("the archive is too large".into());
        }

        let normalized = safe_relative_path(&source_path);
        let is_symlink = file
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000);
        let output_path = if is_symlink { None } else { normalized };
        if let Some(path) = &output_path {
            let marker_path = path.to_ascii_lowercase();
            has_wal_marker |= marker_path == "skin.xml" || marker_path.ends_with("/skin.xml");
            has_classic_marker |= marker_path == "main.bmp" || marker_path.ends_with("/main.bmp");
            // Lowercase keys also catch collisions on case-insensitive filesystems.
            let key = path.to_lowercase();
            if !names.insert(key.clone()) {
                return Err(format!(
                    "duplicate or case-colliding archive output path: {path:?}"
                ));
            }
            paths.push(key);
        }
        entries.push(Entry {
            source_path: source_path.clone(),
            output_path,
            size,
            resource: resource_kind(&source_path),
            extracted: false,
            bytes: content.into(),
        });
    }

    // Reject file/directory conflicts such as entries `Images` and `images/icon.bmp`.
    paths.sort();
    for pair in paths.windows(2) {
        if pair[1].starts_with(&pair[0]) && pair[1].as_bytes().get(pair[0].len()) == Some(&b'/') {
            return Err(format!(
                "archive file path conflicts with a directory: {:?}",
                pair[0]
            ));
        }
    }

    let archive_kind = match (has_wal_marker, has_classic_marker) {
        (true, false) => "wal",
        (false, true) => "wsz",
        (true, true) => "mixed",
        (false, false) => "unknown",
    };
    Ok(Manifest {
        format_version: 1,
        archive_kind,
        entries,
    })
}

/// Writes a `manifest.json` and raw archive entries under `assets/`. The destination must
/// not already exist. On failure, the newly created destination is removed.
pub fn extract(bytes: &[u8], destination: &Path) -> Result<Manifest, String> {
    if destination.exists() {
        return Err(format!(
            "destination already exists: {}",
            destination.display()
        ));
    }
    let mut manifest = inventory(bytes)?;
    std::fs::create_dir(destination).map_err(|e| format!("{}: {e}", destination.display()))?;

    let result = (|| {
        let assets = destination.join("assets");
        std::fs::create_dir(&assets).map_err(|e| format!("{}: {e}", assets.display()))?;
        for entry in &mut manifest.entries {
            let Some(relative) = &entry.output_path else {
                continue;
            };
            let path = assets.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("{}: {e}", parent.display()))?;
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            file.write_all(&entry.bytes)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            entry.extracted = true;
        }
        let semantics = crate::semantics::inspect(
            manifest.archive_kind,
            manifest.entries.iter().filter_map(|entry| {
                entry
                    .output_path
                    .as_deref()
                    .map(|path| (path, entry.bytes.clone()))
            }),
        );
        let semantics_path = destination.join("semantics.json");
        let semantics_json = serde_json::to_vec_pretty(&semantics).map_err(|e| e.to_string())?;
        let mut semantics_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&semantics_path)
            .map_err(|e| format!("{}: {e}", semantics_path.display()))?;
        semantics_file
            .write_all(&semantics_json)
            .map_err(|e| format!("{}: {e}", semantics_path.display()))?;

        let path = destination.join("manifest.json");
        let json = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        file.write_all(&json)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(())
    })();

    if let Err(error) = result {
        return match std::fs::remove_dir_all(destination) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!("{error}; cleanup failed: {cleanup}")),
        };
    }
    Ok(manifest)
}

fn safe_relative_path(name: &str) -> Option<String> {
    let normalized = name.replace('\\', "/");
    if normalized.is_empty()
        || normalized.len() > 4096
        || normalized.starts_with('/')
        || normalized.contains(':')
        || normalized.contains('\0')
    {
        return None;
    }
    let components: Vec<&str> = normalized.split('/').collect();
    if components.iter().any(|part| {
        part.is_empty()
            || *part == "."
            || *part == ".."
            || part.encode_utf16().count() > 255
            || part.ends_with(['.', ' '])
            || part
                .chars()
                .any(|c| matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
            || is_windows_device_name(part)
    }) {
        return None;
    }
    Some(components.join("/"))
}

fn is_windows_device_name(component: &str) -> bool {
    let stem = component
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix)
            .is_some_and(|n| n.len() == 1 && matches!(n.as_bytes()[0], b'1'..=b'9'))
    })
}

fn resource_kind(name: &str) -> &'static str {
    let ext = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "bmp" | "png" | "jpg" | "jpeg" | "gif" | "tga" => "image",
        "wav" | "mp3" | "ogg" | "flac" => "audio",
        "ttf" | "otf" => "font",
        "xml" | "txt" | "ini" | "cfg" | "wsz" | "wal" => "text_or_archive",
        _ => "opaque",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, contents) in entries {
            writer
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(contents).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("walkit-unpack-{name}-{}", std::process::id()))
    }

    #[test]
    fn inventories_and_extracts_wsz_bytes_and_opaque_resources() {
        let bytes = archive(&[
            ("main.bmp", b"bitmap"),
            ("scripts/run.js", b"do not run"),
            ("mystery.bin", b"opaque"),
        ]);
        let dir = scratch("classic");
        let _ = std::fs::remove_dir_all(&dir);
        let manifest = extract(&bytes, &dir).unwrap();
        assert_eq!(manifest.archive_kind, "wsz");
        assert_eq!(
            std::fs::read(dir.join("assets/main.bmp")).unwrap(),
            b"bitmap"
        );
        assert_eq!(
            std::fs::read(dir.join("assets/scripts/run.js")).unwrap(),
            b"do not run"
        );
        let opaque = manifest
            .entries
            .iter()
            .find(|e| e.source_path == "mystery.bin")
            .unwrap();
        assert_eq!(opaque.resource, "opaque");
        assert!(opaque.extracted);
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(json["format_version"], 1);
        assert_eq!(json["entries"][0]["size"], 6);
        let semantics: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("semantics.json")).unwrap()).unwrap();
        assert_eq!(semantics["archive_kind"], "wsz");
        assert_eq!(semantics["classic"]["regions"], serde_json::json!([]));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unpack_wal_writes_static_semantics_and_keeps_scripts_as_assets() {
        let bytes = archive(&[
            (
                "skin.xml",
                br#"<WasabiXML version="1"><skininfo><name>Static</name></skininfo><container id="main"><layout id="normal" w="64" h="32"/></container></WasabiXML>"#,
            ),
            ("scripts/load.maki", b"opaque script bytes"),
        ]);
        let dir = scratch("modern");
        let _ = std::fs::remove_dir_all(&dir);
        extract(&bytes, &dir).unwrap();
        assert_eq!(
            std::fs::read(dir.join("assets/scripts/load.maki")).unwrap(),
            b"opaque script bytes"
        );
        let semantics: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("semantics.json")).unwrap()).unwrap();
        assert_eq!(semantics["modern"]["skin_info"]["name"], "Static");
        assert_eq!(semantics["modern"]["scripts"][0], "scripts/load.maki");
        assert!(semantics["modern"]["windows"].is_null());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn recognizes_wal_and_rejects_existing_destination() {
        let bytes = archive(&[("skin.xml", b"<WasabiXML/>")]);
        assert_eq!(inventory(&bytes).unwrap().archive_kind, "wal");
        let dir = scratch("existing");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("keep.txt"), b"keep").unwrap();
        assert!(extract(&bytes, &dir)
            .unwrap_err()
            .contains("already exists"));
        assert_eq!(std::fs::read(dir.join("keep.txt")).unwrap(), b"keep");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unsafe_paths_are_listed_but_never_extracted() {
        let bytes = archive(&[
            ("../escape.txt", b"outside"),
            ("/absolute.txt", b"outside"),
            ("C:/drive.txt", b"outside"),
            ("safe//empty-segment.txt", b"outside"),
            ("CON.txt", b"device"),
            ("nul\0byte", b"invalid"),
            ("safe/file.txt", b"inside"),
        ]);
        let manifest = inventory(&bytes).unwrap();
        assert!(manifest.entries[..6]
            .iter()
            .all(|entry| entry.output_path.is_none()));
        assert_eq!(
            manifest.entries[6].output_path.as_deref(),
            Some("safe/file.txt")
        );
        let dir = scratch("safe");
        let _ = std::fs::remove_dir_all(&dir);
        let manifest = extract(&bytes, &dir).unwrap();
        assert!(manifest.entries[..6].iter().all(|entry| !entry.extracted));
        assert!(!dir.parent().unwrap().join("escape.txt").exists());
        assert_eq!(
            std::fs::read(dir.join("assets/safe/file.txt")).unwrap(),
            b"inside"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_duplicate_case_colliding_and_file_directory_paths() {
        assert!(inventory(&archive(&[("A/file", b"a"), ("a/FILE", b"b")]))
            .unwrap_err()
            .contains("case-colliding"));
        assert!(
            inventory(&archive(&[("Folder", b"file"), ("folder/child", b"child")]))
                .unwrap_err()
                .contains("conflicts with a directory")
        );
        assert!(inventory(&archive(&[("a\\b", b"a"), ("a/b", b"b")]))
            .unwrap_err()
            .contains("duplicate"));
    }

    #[test]
    fn symbolic_links_are_never_extracted() {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .add_symlink(
                "link",
                "../../outside",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        let manifest = inventory(&writer.finish().unwrap().into_inner()).unwrap();
        assert_eq!(manifest.archive_kind, "unknown");
        assert_eq!(manifest.entries[0].output_path, None);
        assert!(!manifest.entries[0].extracted);
    }

    #[test]
    fn malformed_archives_and_unknown_archives_are_reported_accurately() {
        assert!(inventory(b"not a zip")
            .unwrap_err()
            .contains("not a zip archive"));
        assert_eq!(
            inventory(&archive(&[("readme", b"text")]))
                .unwrap()
                .archive_kind,
            "unknown"
        );
        assert_eq!(
            inventory(&archive(&[
                ("../skin.xml", b"<WasabiXML/>"),
                ("../main.bmp", b"x")
            ]))
            .unwrap()
            .archive_kind,
            "unknown"
        );
    }
}
