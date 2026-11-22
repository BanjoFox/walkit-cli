// SPDX-License-Identifier: GPL-3.0-or-later

//! Static, editable summaries of skin files. This module only parses files; it never loads a
//! skin runtime or executes scripts.

use serde::Serialize;
use std::rc::Rc;
use walkit::draw::Rgb;
use walkit::files::{MemoryFiles, SkinFiles};

const MAX_XML_DEPTH: usize = 128;
const MAX_XML_NODES: usize = 10_000;

#[derive(Debug, Serialize)]
pub struct StaticSemantics {
    pub format_version: u32,
    pub archive_kind: &'static str,
    /// Selected skin folder inside the archive, empty for a root-level skin.
    pub skin_folder: Option<String>,
    pub classic: Option<ClassicSemantics>,
    pub modern: Option<ModernSemantics>,
    /// Why a format parser was skipped for resource-limited input.
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ClassicSemantics {
    pub missing_sheets: Vec<String>,
    pub extras: Vec<String>,
    pub playlist: Option<PlaylistStyle>,
    pub visualizer_colors: Vec<String>,
    pub regions: Vec<String>,
    pub cursors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PlaylistStyle {
    pub normal: String,
    pub current: String,
    pub normal_background: String,
    pub selected_background: String,
    pub font: String,
}

#[derive(Debug, Serialize)]
pub struct ModernSemantics {
    pub skin_info: SkinMetadata,
    pub format_version: Option<String>,
    pub containers: Vec<ContainerMetadata>,
    /// Declared layouts and their static element trees, with source attributes kept as text.
    pub layouts: Vec<LayoutMetadata>,
    /// Compiled script files are listed as opaque dependencies; they are never run or decoded.
    pub scripts: Vec<String>,
    pub fonts: Vec<String>,
    pub plugins: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct LayoutMetadata {
    /// Entry path below the extracted `assets/` directory.
    pub source_file: String,
    pub container_id: Option<String>,
    pub id: Option<String>,
    pub width: Option<String>,
    pub height: Option<String>,
    pub attributes: Vec<StaticAttribute>,
    pub elements: Vec<StaticElement>,
}

#[derive(Debug, Serialize)]
pub struct StaticAttribute {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct StaticElement {
    pub tag: String,
    pub attributes: Vec<StaticAttribute>,
    pub text: Option<String>,
    pub children: Vec<StaticElement>,
}

#[derive(Debug, Serialize)]
pub struct SkinMetadata {
    pub name: Option<String>,
    pub version: Option<String>,
    pub author: Option<String>,
    pub comment: Option<String>,
    pub email: Option<String>,
    pub homepage: Option<String>,
    pub screenshot: Option<String>,
    pub wacup_screenshot: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ContainerMetadata {
    pub id: String,
    pub name: Option<String>,
    pub default_visible: bool,
}

/// Parse existing walkit static metadata from safe archive entries. The returned data is a
/// provisional inspection model; layout geometry and runtime-derived windows are omitted.
pub fn inspect<'a>(
    archive_kind: &'static str,
    entries: impl IntoIterator<Item = (&'a str, Rc<[u8]>)>,
) -> StaticSemantics {
    if !matches!(archive_kind, "wsz" | "wal") {
        return StaticSemantics {
            format_version: 1,
            archive_kind,
            skin_folder: None,
            classic: None,
            modern: None,
            diagnostics: Vec::new(),
        };
    }
    let mut files = MemoryFiles::new();
    let mut names = Vec::new();
    for (path, bytes) in entries {
        files.insert(path, bytes);
        names.push(path.to_string());
    }
    let folders = crate::skin::skin_folders(&names);
    let skin_folder = folders.first().cloned();
    let files = files.in_folder(skin_folder.as_deref().unwrap_or_default());

    let mut diagnostics = Vec::new();
    let (classic, modern) = match archive_kind {
        "wsz" => {
            let info = walkit::info::classic(&files);
            let playlist = info.playlist.map(|p| PlaylistStyle {
                normal: color(p.normal),
                current: color(p.current),
                normal_background: color(p.normal_bg),
                selected_background: color(p.selected_bg),
                font: p.font,
            });
            (
                Some(ClassicSemantics {
                    missing_sheets: info.missing_sheets,
                    extras: info.extras,
                    playlist,
                    visualizer_colors: info.vis_colors.into_iter().map(color).collect(),
                    regions: info.regions,
                    cursors: info.cursors,
                }),
                None,
            )
        }
        "wal" => {
            let mut xml_nodes = 0;
            let overdeep_xml = files.names().into_iter().find_map(|path| {
                if !path.to_ascii_lowercase().ends_with(".xml") {
                    return None;
                }
                let contents = files.read(&path)?;
                let text = String::from_utf8_lossy(&contents);
                (!xml_is_within_limits(&text, &mut xml_nodes)).then_some(path)
            });
            if let Some(path) = overdeep_xml {
                diagnostics.push(format!(
                    "static XML parsing skipped: {path:?} exceeds the XML depth or {MAX_XML_NODES}-node limit"
                ));
                (None, None)
            } else {
                let info = walkit::info::modern(&files);
                let layouts = layouts(&files, skin_folder.as_deref().unwrap_or_default());
                let i = info.skin_info;
                let skin_info = SkinMetadata {
                    name: i.name,
                    version: i.version,
                    author: i.author,
                    comment: i.comment,
                    email: i.email,
                    homepage: i.homepage,
                    screenshot: i.screenshot,
                    wacup_screenshot: i.wacup_screenshot,
                };
                let containers = info
                    .containers
                    .into_iter()
                    .map(|c| ContainerMetadata {
                        id: c.id,
                        name: c.name,
                        default_visible: c.default_visible,
                    })
                    .collect();
                (
                    None,
                    Some(ModernSemantics {
                        skin_info,
                        format_version: info.format_version,
                        containers,
                        layouts,
                        scripts: info.scripts,
                        fonts: info.fonts,
                        plugins: info.plugins,
                    }),
                )
            }
        }
        _ => (None, None),
    };

    StaticSemantics {
        format_version: 1,
        archive_kind,
        skin_folder,
        classic,
        modern,
        diagnostics,
    }
}

/// Guard the recursive walkit metadata traversal against adversarially nested XML.
fn xml_is_within_limits(text: &str, nodes: &mut usize) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut depth = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        if bytes[i..].starts_with(b"<!--") {
            i = find_after(bytes, i + 4, b"-->").unwrap_or(bytes.len());
            continue;
        }
        if bytes[i..].starts_with(b"<![CDATA[") {
            i = find_after(bytes, i + 9, b"]]>").unwrap_or(bytes.len());
            continue;
        }

        let start = i + 1;
        let mut quote = None;
        let mut end = bytes.len();
        for (offset, byte) in bytes[start..].iter().copied().enumerate() {
            match (quote, byte) {
                (Some(q), b) if q == b => quote = None,
                (None, b'\'' | b'"') => quote = Some(byte),
                (None, b'>') => {
                    end = start + offset;
                    break;
                }
                _ => {}
            }
        }
        let token = trim_ascii(&bytes[start..end]);
        if token.first() == Some(&b'/') {
            depth = depth.saturating_sub(1);
        } else if !token.is_empty() && token.first() != Some(&b'!') && token.first() != Some(&b'?')
        {
            *nodes += 1;
            if *nodes > MAX_XML_NODES {
                return false;
            }
            if !token.ends_with(b"/") {
                depth += 1;
                if depth > MAX_XML_DEPTH {
                    return false;
                }
            }
        }
        i = if end < bytes.len() {
            end + 1
        } else {
            bytes.len()
        };
    }
    true
}

fn find_after(bytes: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    bytes[start..]
        .windows(needle.len())
        .position(|part| part == needle)
        .map(|offset| start + offset + needle.len())
}

fn layouts(files: &MemoryFiles, folder: &str) -> Vec<LayoutMetadata> {
    let mut layouts = Vec::new();
    for path in files.names() {
        if !path.to_ascii_lowercase().ends_with(".xml") {
            continue;
        }
        let Some(bytes) = files.read(&path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        for root in walkit::xml::parse(&text) {
            collect_layouts(&root, &format!("{folder}{path}"), None, &mut layouts);
        }
    }
    layouts
}

fn collect_layouts(
    node: &walkit::xml::XmlNode,
    source_file: &str,
    parent_container: Option<&str>,
    out: &mut Vec<LayoutMetadata>,
) {
    let container = if node.name == "container" {
        node.get("id").or(parent_container)
    } else {
        parent_container
    };
    if node.name == "layout" {
        out.push(LayoutMetadata {
            source_file: source_file.to_string(),
            container_id: container.map(str::to_string),
            id: node.get("id").map(str::to_string),
            width: node.get("w").map(str::to_string),
            height: node.get("h").map(str::to_string),
            attributes: node
                .attrs
                .iter()
                .map(|(name, value)| StaticAttribute {
                    name: name.clone(),
                    value: value.clone(),
                })
                .collect(),
            elements: node
                .children
                .iter()
                .map(|child| static_element(child.as_ref()))
                .collect(),
        });
        return;
    }
    for child in &node.children {
        collect_layouts(child, source_file, container, out);
    }
}

fn static_element(node: &walkit::xml::XmlNode) -> StaticElement {
    StaticElement {
        tag: node.name.clone(),
        attributes: node
            .attrs
            .iter()
            .map(|(name, value)| StaticAttribute {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        text: (!node.text.is_empty()).then(|| node.text.clone()),
        children: node
            .children
            .iter()
            .map(|child| static_element(child.as_ref()))
            .collect(),
    }
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn color(rgb: Rgb) -> String {
    format!("#{:06x}", rgb.0 & 0x00ff_ffff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_semantics_are_parsed_from_the_selected_folder() {
        let entries = [
            ("pack/skin/main.bmp", Rc::from(b"bitmap".as_slice())),
            (
                "pack/skin/pledit.txt",
                Rc::from(&b"[Text]\nNormal=#123456\nFont=Tahoma\n"[..]),
            ),
            (
                "pack/skin/region.txt",
                Rc::from(&b"[Normal]\nPointList=0,0,1,1\n"[..]),
            ),
            ("other/readme.txt", Rc::from(&b"not part of the skin"[..])),
        ];
        let semantics = inspect("wsz", entries);
        assert_eq!(semantics.skin_folder.as_deref(), Some("pack/skin/"));
        let classic = semantics.classic.unwrap();
        let playlist = classic.playlist.unwrap();
        assert_eq!(playlist.normal, "#123456");
        assert_eq!(playlist.font, "Tahoma");
        assert_eq!(classic.regions, ["normal"]);
    }

    #[test]
    fn modern_semantics_read_xml_without_runtime_geometry_or_script_execution() {
        let entries = [
            (
                "skin.xml",
                Rc::from(&br#"<WasabiXML version="1.2"><skininfo><name>Static Test</name><author>Fox</author></skininfo><container id="main" name="Main" default_visible="1"><layout id="normal" w="320" h="200"><layer id="bg" x="12" y="24" w="50" h="40"><image source="main.bmp"/></layer></layout></container></WasabiXML>"#[..]),
            ),
            (
                "scripts/loader.maki",
                Rc::from(&b"script bytes remain opaque"[..]),
            ),
        ];
        let semantics = inspect("wal", entries);
        let modern = semantics.modern.unwrap();
        assert_eq!(modern.skin_info.name.as_deref(), Some("Static Test"));
        assert_eq!(modern.skin_info.author.as_deref(), Some("Fox"));
        assert_eq!(modern.format_version.as_deref(), Some("1.2"));
        assert_eq!(modern.containers[0].id, "main");
        assert_eq!(modern.scripts, ["scripts/loader.maki"]);
        assert_eq!(modern.layouts[0].source_file, "skin.xml");
        assert_eq!(modern.layouts[0].container_id.as_deref(), Some("main"));
        assert_eq!(modern.layouts[0].id.as_deref(), Some("normal"));
        assert_eq!(modern.layouts[0].width.as_deref(), Some("320"));
        assert_eq!(modern.layouts[0].height.as_deref(), Some("200"));
        assert_eq!(modern.layouts[0].elements[0].tag, "layer");
        assert_eq!(modern.layouts[0].elements[0].attributes[1].value, "12");
        assert_eq!(modern.layouts[0].elements[0].children[0].tag, "image");
        assert_eq!(
            modern.layouts[0].elements[0].children[0].attributes[0].value,
            "main.bmp"
        );
    }

    #[test]
    fn deeply_nested_xml_is_reported_without_recursive_semantic_parsing() {
        let xml = format!(
            "{}{}",
            "<x>".repeat(MAX_XML_DEPTH + 1),
            "</x>".repeat(MAX_XML_DEPTH + 1)
        );
        let entries = [("skin.xml", Rc::from(xml.into_bytes()))];
        let semantics = inspect("wal", entries);
        assert!(semantics.modern.is_none());
        assert!(semantics.diagnostics[0].contains("XML depth"));
    }

    #[test]
    fn excessively_large_xml_trees_are_reported_before_walkit_parses_them() {
        let xml = "<x/>".repeat(MAX_XML_NODES + 1);
        let entries = [("skin.xml", Rc::from(xml.into_bytes()))];
        let semantics = inspect("wal", entries);
        assert!(semantics.modern.is_none());
        assert!(semantics.diagnostics[0].contains("node limit"));
    }
}
