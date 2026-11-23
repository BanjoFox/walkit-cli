// SPDX-License-Identifier: GPL-3.0-or-later

//! Static archive inventory and byte-preserving extraction prototype.
//!
//! Entries are never interpreted or executed. Unsafe paths and symbolic links are reported
//! in the manifest but are not extracted.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_ENTRY: u64 = 32 * 1024 * 1024;
const MAX_TOTAL: u64 = 256 * 1024 * 1024;
const MAX_ARCHIVE: u64 = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_VALIDATION_NODES: usize = MAX_ENTRIES * 2;
const MAX_VALIDATION_DEPTH: usize = 2048;
const MAX_VALIDATION_PATH_BYTES: usize = MAX_MANIFEST_BYTES as usize;

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
    /// SHA-256 of the source entry bytes, for comparison with an unpacked asset.
    pub sha256: String,
    /// Extension-level classification only. `opaque` resources remain preserved as bytes.
    pub resource: &'static str,
    pub extracted: bool,
    #[serde(skip)]
    bytes: Rc<[u8]>,
}

#[derive(Debug, Deserialize)]
struct ManifestSnapshot {
    format_version: u32,
    archive_kind: String,
    entries: Vec<EntrySnapshot>,
}

#[derive(Debug, Deserialize)]
struct EntrySnapshot {
    source_path: String,
    output_path: Option<String>,
    size: u64,
    resource: String,
    extracted: bool,
    #[serde(default)]
    sha256: Option<String>,
}

#[derive(Debug, Default)]
pub struct ValidationReport {
    pub unchanged: usize,
    pub modified: Vec<String>,
    pub missing: Vec<String>,
    pub added: Vec<String>,
    pub unsafe_paths: Vec<String>,
    /// V1 entries whose size matches but have no hash to verify their contents.
    pub legacy_unverified: usize,
}

impl ValidationReport {
    pub fn is_clean(&self) -> bool {
        self.modified.is_empty()
            && self.missing.is_empty()
            && self.added.is_empty()
            && self.unsafe_paths.is_empty()
            && self.legacy_unverified == 0
    }
}

#[derive(Debug, Clone, Copy)]
enum ObservedKind {
    File { size: u64 },
    Directory,
    Symlink,
    Other,
    CaseCollision,
}

#[derive(Debug)]
struct ObservedEntry {
    path: PathBuf,
    kind: ObservedKind,
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
            sha256: format!("{:x}", Sha256::digest(&content)),
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
        format_version: 2,
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
        let json = manifest_json(&manifest)?;
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

struct LimitedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > self.limit {
            self.exceeded = true;
            return Err(std::io::Error::other("manifest size limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn manifest_json(manifest: &Manifest) -> Result<Vec<u8>, String> {
    let mut writer = LimitedWriter {
        bytes: Vec::new(),
        limit: MAX_MANIFEST_BYTES as usize,
        exceeded: false,
    };
    if let Err(error) = serde_json::to_writer_pretty(&mut writer, manifest) {
        if writer.exceeded {
            return Err("the manifest is too large to validate".into());
        }
        return Err(error.to_string());
    }
    Ok(writer.bytes)
}

/// Compare an unpacked directory with its manifest without modifying the directory.
/// Version 1 manifests can only detect size changes; version 2 also checks SHA-256.
pub fn validate_directory(directory: &Path) -> Result<ValidationReport, String> {
    let root_metadata =
        fs::symlink_metadata(directory).map_err(|e| format!("{}: {e}", directory.display()))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(format!("not a regular directory: {}", directory.display()));
    }

    let manifest_path = directory.join("manifest.json");
    let manifest_metadata = fs::symlink_metadata(&manifest_path)
        .map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    if manifest_metadata.file_type().is_symlink() || !manifest_metadata.is_file() {
        return Err(format!(
            "manifest is not a regular file: {}",
            manifest_path.display()
        ));
    }
    if manifest_metadata.len() > MAX_MANIFEST_BYTES {
        return Err("manifest.json is too large to validate".into());
    }
    let mut manifest_bytes = Vec::new();
    File::open(&manifest_path)
        .map_err(|e| format!("{}: {e}", manifest_path.display()))?
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut manifest_bytes)
        .map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    if manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("manifest.json is too large to validate".into());
    }
    let manifest: ManifestSnapshot = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("{}: invalid manifest: {e}", manifest_path.display()))?;
    let expected = validate_manifest(&manifest)?;

    let assets = directory.join("assets");
    let assets_metadata =
        fs::symlink_metadata(&assets).map_err(|e| format!("{}: {e}", assets.display()))?;
    if assets_metadata.file_type().is_symlink() || !assets_metadata.is_dir() {
        return Err(format!(
            "assets is not a regular directory: {}",
            assets.display()
        ));
    }

    let mut report = ValidationReport::default();
    let (observed, mut unsafe_paths) = observe_assets(&assets)?;
    report.unsafe_paths.append(&mut unsafe_paths);

    for entry in &manifest.entries {
        let Some(relative) = &entry.output_path else {
            continue;
        };
        let display = format!("assets/{relative}");
        if let Some(ancestor) = unsafe_ancestor(relative, &observed) {
            report
                .unsafe_paths
                .push(format!("assets/{ancestor} (unsafe parent of {relative})"));
            continue;
        }
        match observed.get(relative).map(|entry| &entry.kind) {
            None => report.missing.push(display),
            Some(ObservedKind::Directory) => report.unsafe_paths.push(format!(
                "{display} (expected a regular file, found a directory)"
            )),
            Some(ObservedKind::Symlink) => report
                .unsafe_paths
                .push(format!("{display} (symbolic link)")),
            Some(ObservedKind::Other | ObservedKind::CaseCollision) => report
                .unsafe_paths
                .push(format!("{display} (not a unique regular file)")),
            Some(ObservedKind::File { size }) if *size != entry.size => {
                report.modified.push(display)
            }
            Some(ObservedKind::File { .. }) => match &entry.sha256 {
                Some(expected_hash) => {
                    let path = &observed[relative].path;
                    let Some(actual_hash) = hash_file(path, entry.size)? else {
                        report.modified.push(display);
                        continue;
                    };
                    if &actual_hash == expected_hash {
                        report.unchanged += 1;
                    } else {
                        report.modified.push(display);
                    }
                }
                None => report.legacy_unverified += 1,
            },
        }
    }

    for (relative, entry) in &observed {
        if expected.contains(relative) {
            continue;
        }
        if matches!(entry.kind, ObservedKind::File { .. }) {
            report.added.push(format!("assets/{relative}"));
        }
    }
    report.modified.sort();
    report.missing.sort();
    report.added.sort();
    report.unsafe_paths.sort();
    report.unsafe_paths.dedup();
    Ok(report)
}

fn validate_manifest(manifest: &ManifestSnapshot) -> Result<HashSet<String>, String> {
    if !matches!(manifest.format_version, 1 | 2) {
        return Err(format!(
            "unsupported manifest format_version: {}",
            manifest.format_version
        ));
    }
    if !matches!(
        manifest.archive_kind.as_str(),
        "wsz" | "wal" | "mixed" | "unknown"
    ) {
        return Err("manifest has an unknown archive_kind".into());
    }
    if manifest.entries.len() > MAX_ENTRIES {
        return Err("manifest has too many entries".into());
    }

    let mut expected = HashSet::new();
    let mut folded = HashSet::new();
    let mut output_paths = Vec::new();
    let mut has_wal_marker = false;
    let mut has_classic_marker = false;
    for (index, entry) in manifest.entries.iter().enumerate() {
        if entry.size > MAX_ENTRY {
            return Err(format!(
                "manifest entry {index} exceeds the file size limit"
            ));
        }
        if !matches!(
            entry.resource.as_str(),
            "image" | "audio" | "font" | "text_or_archive" | "opaque"
        ) {
            return Err(format!(
                "manifest entry {index} has an unknown resource kind"
            ));
        }
        if entry.resource != resource_kind(&entry.source_path) {
            return Err(format!(
                "manifest entry {index} resource kind does not match source_path"
            ));
        }
        match &entry.output_path {
            Some(path) => {
                if !entry.extracted {
                    return Err(format!(
                        "manifest entry {index} has an output_path but is not extracted"
                    ));
                }
                if safe_relative_path(path).as_deref() != Some(path.as_str()) {
                    return Err(format!("manifest entry {index} has an unsafe output_path"));
                }
                if safe_relative_path(&entry.source_path).as_deref() != Some(path.as_str()) {
                    return Err(format!(
                        "manifest entry {index} source_path does not normalize to output_path"
                    ));
                }
                if !folded.insert(path.to_lowercase()) {
                    return Err(format!(
                        "manifest contains duplicate or case-colliding output_path: {path:?}"
                    ));
                }
                expected.insert(path.clone());
                output_paths.push(path.to_lowercase());
                has_wal_marker |= path.eq_ignore_ascii_case("skin.xml")
                    || path
                        .rsplit_once('/')
                        .is_some_and(|(_, name)| name.eq_ignore_ascii_case("skin.xml"));
                has_classic_marker |= path.eq_ignore_ascii_case("main.bmp")
                    || path
                        .rsplit_once('/')
                        .is_some_and(|(_, name)| name.eq_ignore_ascii_case("main.bmp"));
            }
            None if entry.extracted => {
                return Err(format!(
                    "manifest entry {index} is extracted without an output_path"
                ));
            }
            None => {}
        }

        if manifest.format_version == 2 {
            let hash = entry
                .sha256
                .as_deref()
                .ok_or_else(|| format!("manifest entry {index} is missing its SHA-256 digest"))?;
            if !is_sha256(hash) {
                return Err(format!(
                    "manifest entry {index} has an invalid SHA-256 digest"
                ));
            }
        } else if entry.sha256.as_deref().is_some_and(|hash| !is_sha256(hash)) {
            return Err(format!(
                "manifest entry {index} has an invalid SHA-256 digest"
            ));
        }
    }

    output_paths.sort();
    for pair in output_paths.windows(2) {
        if pair[1].starts_with(&pair[0]) && pair[1].as_bytes().get(pair[0].len()) == Some(&b'/') {
            return Err(format!(
                "manifest output paths conflict as file and directory: {:?} and {:?}",
                pair[0], pair[1]
            ));
        }
    }

    let expected_archive_kind = match (has_wal_marker, has_classic_marker) {
        (true, false) => "wal",
        (false, true) => "wsz",
        (true, true) => "mixed",
        (false, false) => "unknown",
    };
    if manifest.archive_kind != expected_archive_kind {
        return Err("manifest archive_kind does not match its extracted source paths".into());
    }
    Ok(expected)
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn observe_assets(assets: &Path) -> Result<(HashMap<String, ObservedEntry>, Vec<String>), String> {
    let mut observed = HashMap::<String, ObservedEntry>::new();
    let mut folded = HashMap::<String, String>::new();
    let mut unsafe_paths = Vec::new();
    let mut pending = vec![(assets.to_path_buf(), 0usize)];
    let mut nodes = 0usize;
    let mut path_bytes = 0usize;

    while let Some((directory, depth)) = pending.pop() {
        let contents =
            fs::read_dir(&directory).map_err(|e| format!("{}: {e}", directory.display()))?;
        let mut items = contents
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{}: {e}", directory.display()))?;
        items.sort_by_key(|item| item.file_name());
        for item in items {
            nodes += 1;
            if nodes > MAX_VALIDATION_NODES {
                return Err("assets directory contains too many entries to validate".into());
            }
            let path = item.path();
            let file_type = item
                .file_type()
                .map_err(|e| format!("{}: {e}", path.display()))?;
            let relative = path
                .strip_prefix(assets)
                .map_err(|_| "assets entry escaped its directory".to_string())?;
            if !add_validation_path_bytes(&mut path_bytes, relative.to_string_lossy().len()) {
                return Err("assets directory has too much path data to validate".into());
            }
            let Some(key) = asset_key(relative) else {
                unsafe_paths.push(format!("assets/{relative:?} (unsafe or non-UTF-8 path)"));
                continue;
            };

            let kind = if file_type.is_symlink() {
                unsafe_paths.push(format!("assets/{key} (symbolic link)"));
                ObservedKind::Symlink
            } else if file_type.is_dir() {
                if depth >= MAX_VALIDATION_DEPTH {
                    unsafe_paths.push(format!("assets/{key} (directory nesting limit exceeded)"));
                    ObservedKind::Other
                } else {
                    pending.push((path.clone(), depth + 1));
                    ObservedKind::Directory
                }
            } else if file_type.is_file() {
                let size = item
                    .metadata()
                    .map_err(|e| format!("{}: {e}", path.display()))?
                    .len();
                ObservedKind::File { size }
            } else {
                unsafe_paths.push(format!("assets/{key} (not a regular file or directory)"));
                ObservedKind::Other
            };

            let folded_key = key.to_lowercase();
            if let Some(previous) = folded.get(&folded_key) {
                unsafe_paths.push(format!(
                    "assets/{previous} and assets/{key} (case-colliding paths)"
                ));
                if let Some(previous_entry) = observed.get_mut(previous) {
                    previous_entry.kind = ObservedKind::CaseCollision;
                }
                observed.insert(
                    key,
                    ObservedEntry {
                        path,
                        kind: ObservedKind::CaseCollision,
                    },
                );
            } else {
                folded.insert(folded_key, key.clone());
                observed.insert(key, ObservedEntry { path, kind });
            }
        }
    }
    Ok((observed, unsafe_paths))
}

fn asset_key(relative: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return None;
        };
        parts.push(part.to_str()?);
    }
    let key = parts.join("/");
    (safe_relative_path(&key).as_deref() == Some(key.as_str())).then_some(key)
}

fn add_validation_path_bytes(total: &mut usize, bytes: usize) -> bool {
    *total = total.saturating_add(bytes);
    *total <= MAX_VALIDATION_PATH_BYTES
}

fn unsafe_ancestor(relative: &str, observed: &HashMap<String, ObservedEntry>) -> Option<String> {
    let mut prefix = String::new();
    let parts: Vec<_> = relative.split('/').collect();
    for part in parts.iter().take(parts.len().saturating_sub(1)) {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(part);
        if observed.get(&prefix).is_some_and(|entry| {
            matches!(
                entry.kind,
                ObservedKind::File { .. }
                    | ObservedKind::Symlink
                    | ObservedKind::Other
                    | ObservedKind::CaseCollision
            )
        }) {
            return Some(prefix);
        }
    }
    None
}

fn hash_file(path: &Path, expected_size: u64) -> Result<Option<String>, String> {
    let mut file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(expected_size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() as u64 != expected_size {
        return Ok(None);
    }
    Ok(Some(format!("{:x}", Sha256::digest(bytes))))
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
            (
                "region.txt",
                b"[Normal]\nNumPoints=3\nPointList=0,0,8,0,8,8\n",
            ),
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
        assert_eq!(json["format_version"], 2);
        assert_eq!(json["entries"][0]["size"], 6);
        let semantics: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("semantics.json")).unwrap()).unwrap();
        assert_eq!(semantics["archive_kind"], "wsz");
        assert_eq!(
            semantics["classic"]["regions"],
            serde_json::json!(["normal"])
        );
        assert_eq!(
            semantics["classic"]["region_geometry"][0]["polygons"][0][1]["x"],
            8
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unpack_wal_writes_static_semantics_and_keeps_scripts_as_assets() {
        let bytes = archive(&[
            (
                "skin.xml",
                br#"<WasabiXML version="1"><skininfo><name>Static</name></skininfo><container id="main"><layout id="normal" w="64" h="32"><layer x="4" y="5"/></layout></container></WasabiXML>"#,
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
        assert_eq!(semantics["modern"]["layouts"][0]["width"], "64");
        assert_eq!(
            semantics["modern"]["layouts"][0]["elements"][0]["tag"],
            "layer"
        );
        assert!(semantics["modern"]["windows"].is_null());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn project_skin_fixtures_keep_static_summaries_tied_to_source() {
        let classic = include_bytes!("../tests/skins/walkit-classic.wsz");
        let classic_dir = scratch("fixture-classic");
        let _ = std::fs::remove_dir_all(&classic_dir);
        extract(classic, &classic_dir).unwrap();
        let classic_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(classic_dir.join("semantics.json")).unwrap())
                .unwrap();
        assert_eq!(
            classic_json["classic"]["missing_sheets"],
            serde_json::json!([])
        );
        assert_eq!(classic_json["classic"]["playlist"]["font"], "Arial");
        assert_eq!(
            classic_json["classic"]["visualizer_colors"]
                .as_array()
                .unwrap()
                .len(),
            24
        );
        assert_eq!(
            classic_json["classic"]["region_geometry"],
            serde_json::json!([])
        );

        let modern = include_bytes!("../tests/skins/walkit-modern.wal");
        let modern_dir = scratch("fixture-modern");
        let _ = std::fs::remove_dir_all(&modern_dir);
        extract(modern, &modern_dir).unwrap();
        let modern_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(modern_dir.join("semantics.json")).unwrap())
                .unwrap();
        let semantics = &modern_json["modern"];
        assert_eq!(semantics["xml_documents"].as_array().unwrap().len(), 1);
        assert_eq!(semantics["xml_documents"][0]["source_file"], "skin.xml");
        assert_eq!(
            semantics["xml_documents"][0]["includes"],
            serde_json::json!([])
        );
        assert_eq!(semantics["xml_include_references"], serde_json::json!([]));
        assert_eq!(semantics["layouts"].as_array().unwrap().len(), 2);
        assert_eq!(semantics["duplicate_declarations"], serde_json::json!([]));
        let refs = semantics["file_references"].as_array().unwrap();
        assert_eq!(refs.len(), 20);
        assert!(refs
            .iter()
            .all(|reference| reference["archive_file_present"] == true));
        assert!(semantics["xml_documents"][0]["definitions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|definition| {
                definition["tag"] == "bitmap"
                    && definition["attributes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|attribute| attribute["name"] == "id" && attribute["value"] == "close")
            }));
        assert!(semantics["bitmap_references"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reference| {
                reference["target"] == "close"
                    && reference["attribute"] == "image"
                    && reference["matching_declaration_files"] == serde_json::json!(["skin.xml"])
            }));

        let _ = std::fs::remove_dir_all(classic_dir);
        let _ = std::fs::remove_dir_all(modern_dir);
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

    #[test]
    fn validation_detects_same_size_edits_missing_files_and_additions() {
        let bytes = archive(&[("main.bmp", b"original"), ("notes.txt", b"keep")]);
        let dir = scratch("validate-edits");
        let _ = std::fs::remove_dir_all(&dir);
        extract(&bytes, &dir).unwrap();

        let clean = validate_directory(&dir).unwrap();
        assert!(clean.is_clean());
        assert_eq!(clean.unchanged, 2);

        std::fs::write(dir.join("assets/main.bmp"), b"edited!!").unwrap();
        std::fs::remove_file(dir.join("assets/notes.txt")).unwrap();
        std::fs::write(dir.join("assets/new-image.bmp"), b"new").unwrap();

        let report = validate_directory(&dir).unwrap();
        assert_eq!(report.modified, ["assets/main.bmp"]);
        assert_eq!(report.missing, ["assets/notes.txt"]);
        assert_eq!(report.added, ["assets/new-image.bmp"]);
        assert!(!report.is_clean());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn legacy_v1_validation_does_not_claim_same_size_files_are_unchanged() {
        let dir = scratch("validate-v1");
        let assets = dir.join("assets");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&assets).unwrap();
        std::fs::write(assets.join("main.bmp"), b"edited!").unwrap();
        let manifest = serde_json::json!({
            "format_version": 1,
            "archive_kind": "wsz",
            "entries": [{
                "source_path": "main.bmp",
                "output_path": "main.bmp",
                "size": 7,
                "resource": "image",
                "extracted": true
            }]
        });
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let report = validate_directory(&dir).unwrap();
        assert_eq!(report.legacy_unverified, 1);
        assert_eq!(report.unchanged, 0);
        assert!(!report.is_clean());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn validation_reports_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;

        let bytes = archive(&[("main.bmp", b"bitmap")]);
        let dir = scratch("validate-symlink");
        let _ = std::fs::remove_dir_all(&dir);
        extract(&bytes, &dir).unwrap();
        let asset = dir.join("assets/main.bmp");
        std::fs::remove_file(&asset).unwrap();
        let outside = dir.join("outside.bmp");
        std::fs::write(&outside, b"bitmap").unwrap();
        symlink(&outside, &asset).unwrap();

        let report = validate_directory(&dir).unwrap();
        assert!(report
            .unsafe_paths
            .iter()
            .any(|path| path.contains("assets/main.bmp") && path.contains("symbolic link")));
        assert_eq!(report.unchanged, 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn validation_rejects_traversal_in_the_manifest() {
        let dir = scratch("validate-traversal");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = serde_json::json!({
            "format_version": 2,
            "archive_kind": "wsz",
            "entries": [{
                "source_path": "../outside.bmp",
                "output_path": "../outside.bmp",
                "size": 1,
                "sha256": "2d711642b726b04401627ca9fbac32f5da7e5f7f5b7f7f2d4d9d6b7f3f7f3f7f",
                "resource": "image",
                "extracted": true
            }]
        });
        std::fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let error = validate_directory(&dir).unwrap_err();
        assert!(error.contains("unsafe output_path"), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn validation_rejects_inconsistent_manifest_provenance_and_classification() {
        let dir = scratch("validate-provenance");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest_path = dir.join("manifest.json");

        let cases = [
            (
                serde_json::json!({
                    "format_version": 2,
                    "archive_kind": "wsz",
                    "entries": [{
                        "output_path": "main.bmp",
                        "size": 1,
                        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                        "resource": "image",
                        "extracted": true
                    }]
                }),
                "source_path",
            ),
            (
                serde_json::json!({
                    "format_version": 2,
                    "archive_kind": "wsz",
                    "entries": [{
                        "source_path": "other.bmp",
                        "output_path": "main.bmp",
                        "size": 1,
                        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                        "resource": "image",
                        "extracted": true
                    }]
                }),
                "source_path does not normalize",
            ),
            (
                serde_json::json!({
                    "format_version": 2,
                    "archive_kind": "wsz",
                    "entries": [{
                        "source_path": "main.bmp",
                        "output_path": "main.bmp",
                        "size": 1,
                        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                        "resource": "opaque",
                        "extracted": true
                    }]
                }),
                "resource kind does not match",
            ),
            (
                serde_json::json!({
                    "format_version": 2,
                    "archive_kind": "wsz",
                    "entries": [{
                        "source_path": "main.bmp",
                        "output_path": "main.bmp",
                        "size": 1,
                        "sha256": "000000000000000000000000000000000000000000000000000000000000000A",
                        "resource": "image",
                        "extracted": true
                    }]
                }),
                "invalid SHA-256 digest",
            ),
        ];

        for (manifest, expected_error) in cases {
            std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
            let error = validate_directory(&dir).unwrap_err();
            assert!(
                error.contains(expected_error),
                "expected {expected_error:?}: {error}"
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn validation_rejects_conflicting_manifest_paths_and_archive_kind() {
        let dir = scratch("validate-conflicts");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest_path = dir.join("manifest.json");
        let digest = "0000000000000000000000000000000000000000000000000000000000000000";
        let conflicting_paths = serde_json::json!({
            "format_version": 2,
            "archive_kind": "unknown",
            "entries": [
                {"source_path":"folder", "output_path":"folder", "size":1, "sha256":digest, "resource":"opaque", "extracted":true},
                {"source_path":"folder/file.bin", "output_path":"folder/file.bin", "size":1, "sha256":digest, "resource":"opaque", "extracted":true}
            ]
        });
        std::fs::write(
            &manifest_path,
            serde_json::to_vec(&conflicting_paths).unwrap(),
        )
        .unwrap();
        let error = validate_directory(&dir).unwrap_err();
        assert!(error.contains("conflict as file and directory"), "{error}");

        let wrong_archive_kind = serde_json::json!({
            "format_version": 2,
            "archive_kind": "wal",
            "entries": [{
                "source_path":"main.bmp", "output_path":"main.bmp", "size":1,
                "sha256":digest, "resource":"image", "extracted":true
            }]
        });
        std::fs::write(
            &manifest_path,
            serde_json::to_vec(&wrong_archive_kind).unwrap(),
        )
        .unwrap();
        let error = validate_directory(&dir).unwrap_err();
        assert!(error.contains("archive_kind does not match"), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn validation_orders_added_assets_independently_of_directory_iteration() {
        let bytes = archive(&[("main.bmp", b"bitmap")]);
        let dir = scratch("validate-order");
        let _ = std::fs::remove_dir_all(&dir);
        extract(&bytes, &dir).unwrap();
        std::fs::write(dir.join("assets/z-last.bin"), b"z").unwrap();
        std::fs::write(dir.join("assets/a-first.bin"), b"a").unwrap();

        let report = validate_directory(&dir).unwrap();
        assert_eq!(report.added, ["assets/a-first.bin", "assets/z-last.bin"]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn validation_path_budget_is_bounded() {
        let mut total = MAX_VALIDATION_PATH_BYTES - 1;
        assert!(add_validation_path_bytes(&mut total, 1));
        assert!(!add_validation_path_bytes(&mut total, 1));

        let mut total = usize::MAX;
        assert!(!add_validation_path_bytes(&mut total, 1));
        assert_eq!(total, usize::MAX);
    }
}
