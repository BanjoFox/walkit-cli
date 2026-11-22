// SPDX-License-Identifier: GPL-3.0-or-later

//! Static, editable summaries of skin files. This module only parses files; it never loads a
//! skin runtime or executes scripts.

use serde::Serialize;
use std::collections::HashMap;
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
    /// Polygon coordinates from `region.txt`, ordered by section then polygon.
    pub region_geometry: Vec<RegionGeometry>,
    pub cursors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RegionGeometry {
    pub section: String,
    pub polygons: Vec<Vec<RegionPoint>>,
}

#[derive(Debug, Serialize)]
pub struct RegionPoint {
    pub x: i32,
    pub y: i32,
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
    /// Source documents and their directly written declarations; this is not an include graph.
    pub xml_documents: Vec<XmlDocumentMetadata>,
    /// Include declarations and whether their literal target exists at the skin root.
    pub xml_include_references: Vec<XmlIncludeReference>,
    pub duplicate_declarations: Vec<DuplicateDeclaration>,
    pub file_references: Vec<XmlFileReference>,
    /// Literal layout attributes used by walkit's runtime as bitmap names; matching is lexical.
    pub bitmap_references: Vec<BitmapReference>,
    /// Compiled script files are listed as opaque dependencies; they are never run or decoded.
    pub scripts: Vec<String>,
    pub fonts: Vec<String>,
    pub plugins: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct XmlDocumentMetadata {
    pub source_file: String,
    /// Literal include paths as written in this file. Resolution and reachability are not inferred.
    pub includes: Vec<String>,
    /// Direct children of `<elements>` blocks, retaining IDs and attributes as parsed.
    pub definitions: Vec<StaticElement>,
}

#[derive(Debug, Serialize)]
pub struct XmlIncludeReference {
    pub source_file: String,
    pub target: String,
    /// Root-relative lookup only; false does not imply a runtime include failure.
    pub root_entry_present: bool,
}

#[derive(Debug, Serialize)]
pub struct DuplicateDeclaration {
    pub tag: String,
    pub id: String,
    /// Source file for each occurrence, including repeated declarations within one file.
    pub source_files: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct XmlFileReference {
    pub source_file: String,
    pub tag: String,
    pub id: Option<String>,
    pub path: String,
    /// `None` means the runtime generates or substitutes this resource path.
    pub archive_file_present: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct BitmapReference {
    pub source_file: String,
    pub element_tag: String,
    pub element_id: Option<String>,
    pub attribute: String,
    pub target: String,
    /// Exact case-insensitive bitmap declaration IDs found in any scanned XML source file.
    pub matching_declaration_files: Vec<String>,
    /// Whether the target is also a literal archive path (walkit permits this fallback).
    pub archive_file_present: bool,
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
            let region_geometry = files
                .read("region.txt")
                .map(|bytes| walkit::info::decode(&bytes))
                .map(|text| walkit::classic::region::parse(&text))
                .map(|regions| {
                    let mut regions: Vec<_> = regions.into_iter().collect();
                    regions.sort_by(|a, b| a.0.cmp(&b.0));
                    regions
                        .into_iter()
                        .map(|(section, polygons)| RegionGeometry {
                            section,
                            polygons: polygons
                                .into_iter()
                                .map(|points| {
                                    points
                                        .into_iter()
                                        .map(|(x, y)| RegionPoint { x, y })
                                        .collect()
                                })
                                .collect(),
                        })
                        .collect()
                })
                .unwrap_or_default();
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
                    region_geometry,
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
                let xml = inspect_xml_documents(&files, skin_folder.as_deref().unwrap_or_default());
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
                let modern = Some(ModernSemantics {
                    skin_info,
                    format_version: info.format_version,
                    containers,
                    layouts: xml.layouts,
                    xml_documents: xml.documents,
                    xml_include_references: xml.include_references,
                    duplicate_declarations: xml.duplicate_declarations,
                    file_references: xml.file_references,
                    bitmap_references: xml.bitmap_references,
                    scripts: info.scripts,
                    fonts: info.fonts,
                    plugins: info.plugins,
                });
                (None, modern)
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

struct XmlInspection {
    layouts: Vec<LayoutMetadata>,
    documents: Vec<XmlDocumentMetadata>,
    include_references: Vec<XmlIncludeReference>,
    duplicate_declarations: Vec<DuplicateDeclaration>,
    file_references: Vec<XmlFileReference>,
    bitmap_references: Vec<BitmapReference>,
}

fn inspect_xml_documents(files: &MemoryFiles, folder: &str) -> XmlInspection {
    let mut layouts = Vec::new();
    let mut documents = Vec::new();
    let mut declarations: HashMap<(String, String), Vec<String>> = HashMap::new();
    let mut file_references = Vec::new();
    let mut raw_bitmap_references = Vec::new();
    let mut include_references = Vec::new();
    for path in files.names() {
        if !path.to_ascii_lowercase().ends_with(".xml") {
            continue;
        }
        let Some(bytes) = files.read(&path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        let source_file = format!("{folder}{path}");
        let mut includes = Vec::new();
        let mut definitions = Vec::new();
        {
            let mut scan = XmlScan {
                files,
                layouts: &mut layouts,
                includes: &mut includes,
                definitions: &mut definitions,
                declarations: &mut declarations,
                file_references: &mut file_references,
                bitmap_references: &mut raw_bitmap_references,
                include_references: &mut include_references,
            };
            for root in walkit::xml::parse(&text) {
                scan.node(&root, &source_file, None);
            }
        }
        documents.push(XmlDocumentMetadata {
            source_file,
            includes,
            definitions,
        });
    }
    let include_references = include_references
        .into_iter()
        .map(|(source_file, target)| XmlIncludeReference {
            source_file,
            root_entry_present: files.exists(&target),
            target,
        })
        .collect();
    let bitmap_declaration_files: HashMap<_, _> = declarations
        .iter()
        .filter(|((tag, _), _)| tag == "bitmap")
        .map(|((_, id), files)| (id.clone(), files.clone()))
        .collect();
    let mut duplicate_declarations: Vec<_> = declarations
        .into_iter()
        .filter(|(_, source_files)| source_files.len() > 1)
        .map(|((tag, id), mut source_files)| {
            source_files.sort();
            DuplicateDeclaration {
                tag,
                id,
                source_files,
            }
        })
        .collect();
    duplicate_declarations.sort_by(|a, b| (&a.tag, &a.id).cmp(&(&b.tag, &b.id)));
    let bitmap_references = raw_bitmap_references
        .into_iter()
        .map(
            |(source_file, element_tag, element_id, attribute, target)| {
                let matching_declaration_files = bitmap_declaration_files
                    .get(&target.to_ascii_lowercase())
                    .cloned()
                    .unwrap_or_default();
                BitmapReference {
                    source_file,
                    element_tag,
                    element_id,
                    attribute,
                    archive_file_present: files.exists(&target),
                    target,
                    matching_declaration_files,
                }
            },
        )
        .collect();
    XmlInspection {
        layouts,
        documents,
        include_references,
        duplicate_declarations,
        file_references,
        bitmap_references,
    }
}

type RawBitmapReference = (String, String, Option<String>, String, String);
type RawXmlIncludeReference = (String, String);

struct XmlScan<'a> {
    files: &'a MemoryFiles,
    layouts: &'a mut Vec<LayoutMetadata>,
    includes: &'a mut Vec<String>,
    definitions: &'a mut Vec<StaticElement>,
    declarations: &'a mut HashMap<(String, String), Vec<String>>,
    file_references: &'a mut Vec<XmlFileReference>,
    bitmap_references: &'a mut Vec<RawBitmapReference>,
    include_references: &'a mut Vec<RawXmlIncludeReference>,
}

impl XmlScan<'_> {
    fn node(
        &mut self,
        node: &walkit::xml::XmlNode,
        source_file: &str,
        parent_container: Option<&str>,
    ) {
        let container = if node.name == "container" {
            node.get("id").or(parent_container)
        } else {
            parent_container
        };
        if node.name == "include" {
            if let Some(path) = node.get("file") {
                self.includes.push(path.to_string());
                self.include_references
                    .push((source_file.to_string(), path.to_string()));
            }
        }
        if node.name == "elements" {
            self.definitions.extend(
                node.children
                    .iter()
                    .map(|child| static_element(child.as_ref())),
            );
        }
        if let Some(id) = node.get("id") {
            if matches!(
                node.name.as_str(),
                "bitmap" | "bitmapfont" | "color" | "container" | "truetypefont"
            ) {
                self.declarations
                    .entry((node.name.clone(), id.to_ascii_lowercase()))
                    .or_default()
                    .push(source_file.to_string());
            }
        }
        if matches!(node.name.as_str(), "bitmap" | "truetypefont" | "script") {
            if let Some(path) = node.get("file") {
                let runtime_generated = path
                    .rsplit(['/', '\\'])
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case("$solid"));
                self.file_references.push(XmlFileReference {
                    source_file: source_file.to_string(),
                    tag: node.name.clone(),
                    id: node.get("id").map(str::to_string),
                    path: path.to_string(),
                    archive_file_present: (!runtime_generated).then(|| self.files.exists(path)),
                });
            }
        }
        const BITMAP_ATTRIBUTES: [&str; 12] = [
            "image",
            "downimage",
            "hoverimage",
            "activeimage",
            "inactiveimage",
            "thumb",
            "downthumb",
            "barleft",
            "barmiddle",
            "barright",
            "background",
            "images",
        ];
        for (attribute, target) in &node.attrs {
            if BITMAP_ATTRIBUTES.contains(&attribute.as_str()) {
                self.bitmap_references.push((
                    source_file.to_string(),
                    node.name.clone(),
                    node.get("id").map(str::to_string),
                    attribute.clone(),
                    target.clone(),
                ));
            }
        }
        if node.name == "layout" {
            self.layouts.push(LayoutMetadata {
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
        }
        for child in &node.children {
            self.node(child, source_file, container);
        }
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
                Rc::from(&b"[Normal]\nNumPoints=4\nPointList=0,0,10,0,10,10,0,10\n"[..]),
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
        assert_eq!(classic.region_geometry[0].section, "normal");
        assert_eq!(classic.region_geometry[0].polygons[0][2].x, 10);
        assert_eq!(classic.region_geometry[0].polygons[0][2].y, 10);
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
    fn source_documents_expose_raw_includes_definitions_and_file_presence() {
        let entries = [
            (
                "skin.xml",
                Rc::from(&br#"<WasabiXML><include file="parts/ui.xml"/><include file="missing.xml"/><elements><bitmap id="Logo" file="img/logo.png"/></elements><container id="main"><layout id="normal"><button id="close" image="logo"/><button id="bad" image="not-declared"/></layout></container></WasabiXML>"#[..]),
            ),
            (
                "parts/ui.xml",
                Rc::from(&br#"<elements><bitmap id="logo" file="img/alternate.png"/><bitmap id="missing" file="img/missing.png"/><bitmap id="generated" file="$solid" w="1" h="1"/><script id="loader" file="scripts/loader.maki"/></elements>"#[..]),
            ),
            ("img/logo.png", Rc::from(&b"logo"[..])),
            ("img/alternate.png", Rc::from(&b"alternate"[..])),
            ("scripts/loader.maki", Rc::from(&b"opaque script"[..])),
        ];
        let semantics = inspect("wal", entries);
        let modern = semantics.modern.unwrap();
        assert_eq!(modern.xml_documents.len(), 2);
        assert_eq!(modern.xml_documents[0].source_file, "parts/ui.xml");
        assert_eq!(
            modern.xml_documents[1].includes,
            ["parts/ui.xml", "missing.xml"]
        );
        assert_eq!(modern.xml_documents[1].definitions[0].tag, "bitmap");
        assert_eq!(modern.duplicate_declarations.len(), 1);
        assert_eq!(modern.duplicate_declarations[0].tag, "bitmap");
        assert_eq!(modern.duplicate_declarations[0].id, "logo");
        assert_eq!(modern.duplicate_declarations[0].source_files.len(), 2);
        let present = |path: &str| {
            modern
                .file_references
                .iter()
                .find(|reference| reference.path == path)
                .unwrap()
                .archive_file_present
        };
        assert_eq!(present("img/logo.png"), Some(true));
        assert_eq!(present("img/alternate.png"), Some(true));
        assert_eq!(present("img/missing.png"), Some(false));
        assert_eq!(present("$solid"), None);
        assert_eq!(present("scripts/loader.maki"), Some(true));
        assert_eq!(modern.xml_include_references.len(), 2);
        assert!(modern.xml_include_references[0].root_entry_present);
        assert!(!modern.xml_include_references[1].root_entry_present);
        let bitmap_ref = |target: &str| {
            modern
                .bitmap_references
                .iter()
                .find(|reference| reference.target == target)
                .unwrap()
        };
        assert_eq!(
            bitmap_ref("logo").matching_declaration_files,
            ["parts/ui.xml", "skin.xml"]
        );
        assert!(!bitmap_ref("logo").archive_file_present);
        assert!(bitmap_ref("not-declared")
            .matching_declaration_files
            .is_empty());
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
