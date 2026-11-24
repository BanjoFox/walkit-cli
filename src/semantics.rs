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
    /// Direct alias IDs found in source; target chains are not resolved.
    pub matching_alias_declaration_files: Vec<String>,
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
    let normalized_folder = match skin_folder.as_deref() {
        Some(folder) if !folder.is_empty() => {
            format!("{}/", walkit::files::normalize(folder))
        }
        _ => String::new(),
    };
    let files = files.in_folder(&normalized_folder);

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
                scan.node(&root, &source_file, None, false);
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
    let alias_declaration_files: HashMap<_, _> = declarations
        .iter()
        .filter(|((tag, _), _)| tag == "elementalias")
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
                    .get(&target.to_lowercase())
                    .cloned()
                    .unwrap_or_default();
                let matching_alias_declaration_files = alias_declaration_files
                    .get(&target.to_lowercase())
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
                    matching_alias_declaration_files,
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

fn is_bitmap_reference_attribute(tag: &str, attribute: &str) -> bool {
    match tag {
        "button" | "wasabi:button" | "nstatesbutton" | "togglebutton" => matches!(
            attribute,
            "image" | "downimage" | "hoverimage" | "activeimage"
        ),
        "layer" | "animatedlayer" => matches!(attribute, "image" | "inactiveimage"),
        "slider" | "wasabi:hslider" | "wasabi:vslider" => matches!(
            attribute,
            "thumb" | "downthumb" | "barleft" | "barmiddle" | "barright"
        ),
        "status" => matches!(attribute, "stopbitmap" | "playbitmap" | "pausebitmap"),
        "grid" | "progressgrid" => matches!(
            attribute,
            "topleft"
                | "top"
                | "topright"
                | "left"
                | "middle"
                | "right"
                | "bottomleft"
                | "bottom"
                | "bottomright"
        ),
        "images" => attribute == "images",
        "container" | "layout" | "group" | "component" | "windowholder" => {
            attribute == "background"
        }
        _ => false,
    }
}

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
        inside_layout: bool,
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
                "bitmap" | "bitmapfont" | "color" | "container" | "elementalias" | "truetypefont"
            ) {
                self.declarations
                    .entry((node.name.clone(), id.to_lowercase()))
                    .or_default()
                    .push(source_file.to_string());
            }
        }
        if matches!(
            node.name.as_str(),
            "bitmap" | "bitmapfont" | "truetypefont" | "script"
        ) {
            if let Some(path) = node.get("file") {
                let runtime_generated = (node.name == "bitmap"
                    && path
                        .rsplit('/')
                        .next()
                        .is_some_and(|name| name.eq_ignore_ascii_case("$solid")))
                    || ["@HAVE_LIBRARY@", "@HAVE_VIDEO@"]
                        .iter()
                        .any(|token| path.contains(token));
                self.file_references.push(XmlFileReference {
                    source_file: source_file.to_string(),
                    tag: node.name.clone(),
                    id: node.get("id").map(str::to_string),
                    path: path.to_string(),
                    archive_file_present: (!runtime_generated).then(|| self.files.exists(path)),
                });
            }
        }
        for (attribute, target) in &node.attrs {
            if is_bitmap_reference_attribute(&node.name, attribute) {
                self.bitmap_references.push((
                    source_file.to_string(),
                    node.name.clone(),
                    node.get("id").map(str::to_string),
                    attribute.clone(),
                    target.clone(),
                ));
            }
        }
        if node.name == "layout" && !inside_layout {
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
            self.node(
                child,
                source_file,
                container,
                inside_layout || node.name == "layout",
            );
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
    fn semantics_select_mixed_case_nested_skin_folders() {
        let entries = [
            (
                "Glasses/Skin.xml",
                Rc::from(&br#"<WasabiXML version="0.8"><skininfo><name>Glasses</name></skininfo><container id="main"><layout id="normal"><button id="logoButton" image="logo"/></layout></container></WasabiXML>"#[..]),
            ),
            (
                "Glasses/XML/Part.XML",
                Rc::from(&br#"<elements><bitmap id="logo" file="img/Logo.png"/></elements>"#[..]),
            ),
            ("Glasses/img/Logo.png", Rc::from(&b"opaque image bytes"[..])),
        ];

        let semantics = inspect("wal", entries);
        assert_eq!(semantics.skin_folder.as_deref(), Some("Glasses/"));
        let modern = semantics.modern.unwrap();
        assert_eq!(modern.skin_info.name.as_deref(), Some("Glasses"));
        assert_eq!(modern.format_version.as_deref(), Some("0.8"));
        assert_eq!(modern.xml_documents.len(), 2);
        assert!(modern
            .xml_documents
            .iter()
            .any(|document| document.source_file == "Glasses/skin.xml"));
        assert_eq!(modern.layouts.len(), 1);
        assert_eq!(modern.bitmap_references[0].target, "logo");

        let classic_entries = [
            ("ClassicSkin/Main.BMP", Rc::from(&b"bitmap bytes"[..])),
            (
                "ClassicSkin/Pledit.TXT",
                Rc::from(&b"[Text]\nNormal=#123456\nFont=Arial\n"[..]),
            ),
        ];
        let classic = inspect("wsz", classic_entries);
        assert_eq!(classic.skin_folder.as_deref(), Some("ClassicSkin/"));
        assert_eq!(classic.classic.unwrap().playlist.unwrap().normal, "#123456");
    }

    #[test]
    fn nested_container_and_element_trees_keep_their_source_parentage() {
        let entries = [(
            "skin.xml",
            Rc::from(&br#"<WasabiXML><container id="outer"><container id="inner"><layout id="nested" w="80" h="40"><group id="group"><button id="child" image="asset"/></group></layout></container></container></WasabiXML>"#[..]),
        )];
        let semantics = inspect("wal", entries);
        let modern = semantics.modern.unwrap();
        assert_eq!(modern.layouts.len(), 1);
        assert_eq!(modern.layouts[0].container_id.as_deref(), Some("inner"));
        assert_eq!(modern.layouts[0].elements[0].tag, "group");
        assert_eq!(modern.layouts[0].elements[0].children[0].tag, "button");
        assert_eq!(modern.bitmap_references[0].target, "asset");
        assert_eq!(modern.bitmap_references[0].source_file, "skin.xml");
    }

    #[test]
    fn nested_layout_elements_remain_in_the_parent_layout_tree() {
        let entries = [(
            "skin.xml",
            Rc::from(&br#"<WasabiXML><container id="main"><layout id="normal"><group id="group"><layout id="embedded"><button id="child" image="nested-image"/></layout></group></layout></container></WasabiXML>"#[..]),
        )];
        let semantics = inspect("wal", entries);
        let modern = semantics.modern.unwrap();
        assert_eq!(modern.layouts.len(), 1);
        assert_eq!(modern.layouts[0].id.as_deref(), Some("normal"));
        assert_eq!(modern.layouts[0].elements[0].children[0].tag, "layout");
        assert_eq!(modern.bitmap_references.len(), 1);
        assert_eq!(modern.bitmap_references[0].target, "nested-image");
    }

    #[test]
    fn malformed_reference_attributes_preserve_absent_and_empty_distinctions() {
        let entries = [(
            "skin.xml",
            Rc::from(&br#"<WasabiXML><include/><include file=""/><elements><bitmap id="no-file"/><bitmap id="empty-file" file=""/><bitmapfont id="font-no-file"/></elements><container id="main"><layout id="normal"><button id="no-image"/><button id="empty-image" image=""/></layout></container></WasabiXML>"#[..]),
        )];
        let semantics = inspect("wal", entries);
        let modern = semantics.modern.unwrap();
        assert_eq!(modern.xml_include_references.len(), 1);
        assert_eq!(modern.xml_include_references[0].target, "");
        assert!(!modern.xml_include_references[0].root_entry_present);
        assert_eq!(modern.file_references.len(), 1);
        assert_eq!(modern.file_references[0].tag, "bitmap");
        assert_eq!(modern.file_references[0].id.as_deref(), Some("empty-file"));
        assert_eq!(modern.file_references[0].path, "");
        assert_eq!(modern.file_references[0].archive_file_present, Some(false));
        assert_eq!(modern.bitmap_references.len(), 1);
        assert_eq!(
            modern.bitmap_references[0].element_id.as_deref(),
            Some("empty-image")
        );
        assert_eq!(modern.bitmap_references[0].target, "");
        assert!(!modern.bitmap_references[0].archive_file_present);
    }

    #[test]
    fn bitmap_references_use_walkits_tag_specific_attribute_contracts() {
        let entries = [(
            "skin.xml",
            Rc::from(&br#"<WasabiXML><skininfo image="metadata-image" background="metadata-background"/><container id="main" background="window-bg"><layout id="normal" background="layout-bg"><button id="button" image="button-image"/><animatedlayer id="animation" inactiveimage="inactive-image"/><slider id="slider" thumb="thumb-image"/><status id="status" stopbitmap="stop-image"/><grid id="grid" topleft="grid-image"/><images id="images" images="strip-image"/></layout></container></WasabiXML>"#[..]),
        )];
        let semantics = inspect("wal", entries);
        let modern = semantics.modern.unwrap();
        let refs: Vec<_> = modern
            .bitmap_references
            .iter()
            .map(|reference| (reference.element_tag.as_str(), reference.attribute.as_str()))
            .collect();
        for expected in [
            ("container", "background"),
            ("layout", "background"),
            ("button", "image"),
            ("animatedlayer", "inactiveimage"),
            ("slider", "thumb"),
            ("status", "stopbitmap"),
            ("grid", "topleft"),
            ("images", "images"),
        ] {
            assert!(refs.contains(&expected), "missing {expected:?} in {refs:?}");
        }
        assert!(modern
            .bitmap_references
            .iter()
            .all(|reference| !reference.target.starts_with("metadata-")));
    }

    #[test]
    fn declaration_and_reference_ids_use_walkits_unicode_lowercase_convention() {
        let entries = [(
            "skin.xml",
            Rc::from(r#"<WasabiXML><elements><bitmap id="Ä" file="first.bmp"/><bitmap id="ä" file="second.bmp"/></elements><container id="main"><layout id="normal"><button id="button" image="Ä"/></layout></container></WasabiXML>"#.as_bytes()),
        )];
        let semantics = inspect("wal", entries);
        let modern = semantics.modern.unwrap();
        let duplicate = modern
            .duplicate_declarations
            .iter()
            .find(|declaration| declaration.tag == "bitmap")
            .unwrap();
        assert_eq!(duplicate.id, "ä");
        assert_eq!(duplicate.source_files, ["skin.xml", "skin.xml"]);
        assert_eq!(
            modern.bitmap_references[0].matching_declaration_files,
            ["skin.xml", "skin.xml"]
        );
    }

    #[test]
    fn source_documents_expose_raw_includes_definitions_and_file_presence() {
        let entries = [
            (
                "skin.xml",
                Rc::from(&br#"<WasabiXML><include file="parts/ui.xml"/><include file="missing.xml"/><elements><bitmap id="Logo" file="img/logo.png"/><elementalias id="logoAlias" target="logo"/></elements><container id="main"><layout id="normal"><button id="close" image="logo"/><button id="alias" image="logoAlias"/><button id="bad" image="not-declared"/></layout></container></WasabiXML>"#[..]),
            ),
            (
                "parts/ui.xml",
                Rc::from(&br#"<elements><elementalias id="LOGOALIAS" target="img/alternate.png"/><bitmap id="logo" file="img/alternate.png"/><bitmap id="missing" file="img/missing.png"/><bitmap id="generated" file="$solid" w="1" h="1"/><bitmap id="escaped-generated" file="dir\$solid"/><bitmap id="runtime-library" file="@HAVE_LIBRARY@.bmp"/><bitmapfont id="fontgrid" file="fonts/grid.bmp"/><bitmapfont id="fontmissing" file="fonts/missing.bmp"/><bitmapfont id="fontliteral" file="$solid"/><script id="loader" file="scripts/loader.maki"/><script id="runtime-video" file="@HAVE_VIDEO@.maki"/><script id="literal-token" file="@CUSTOM@.maki"/><include file="deep/panel.xml"/></elements>"#[..]),
            ),
            (
                "parts/deep/panel.xml",
                Rc::from(&br#"<elements><color id="panel" value="1,2,3"/></elements>"#[..]),
            ),
            ("img/logo.png", Rc::from(&b"logo"[..])),
            ("img/alternate.png", Rc::from(&b"alternate"[..])),
            ("fonts/grid.bmp", Rc::from(&b"glyph sheet"[..])),
            ("scripts/loader.maki", Rc::from(&b"opaque script"[..])),
        ];
        let semantics = inspect("wal", entries);
        let modern = semantics.modern.unwrap();
        assert_eq!(modern.xml_documents.len(), 3);
        let document = |source_file: &str| {
            modern
                .xml_documents
                .iter()
                .find(|document| document.source_file == source_file)
                .unwrap()
        };
        assert_eq!(
            document("skin.xml").includes,
            ["parts/ui.xml", "missing.xml"]
        );
        assert_eq!(document("parts/ui.xml").includes, ["deep/panel.xml"]);
        assert!(document("parts/ui.xml")
            .definitions
            .iter()
            .any(|definition| definition.tag == "bitmap"));
        assert_eq!(modern.duplicate_declarations.len(), 2);
        assert_eq!(modern.duplicate_declarations[0].tag, "bitmap");
        assert_eq!(modern.duplicate_declarations[0].id, "logo");
        assert_eq!(modern.duplicate_declarations[0].source_files.len(), 2);
        assert_eq!(modern.duplicate_declarations[1].tag, "elementalias");
        assert_eq!(modern.duplicate_declarations[1].id, "logoalias");
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
        assert_eq!(present("dir\\$solid"), Some(false));
        assert_eq!(present("@HAVE_LIBRARY@.bmp"), None);
        assert_eq!(present("@HAVE_VIDEO@.maki"), None);
        assert_eq!(present("@CUSTOM@.maki"), Some(false));
        assert_eq!(present("fonts/grid.bmp"), Some(true));
        assert_eq!(present("fonts/missing.bmp"), Some(false));
        assert_eq!(
            modern
                .file_references
                .iter()
                .find(|reference| reference.tag == "bitmapfont" && reference.path == "$solid")
                .unwrap()
                .archive_file_present,
            Some(false)
        );
        assert_eq!(present("scripts/loader.maki"), Some(true));
        assert_eq!(modern.xml_include_references.len(), 3);
        let root_include = |source_file: &str, target: &str| {
            modern
                .xml_include_references
                .iter()
                .find(|reference| {
                    reference.source_file == source_file && reference.target == target
                })
                .unwrap()
                .root_entry_present
        };
        assert!(root_include("skin.xml", "parts/ui.xml"));
        assert!(!root_include("skin.xml", "missing.xml"));
        // Runtime-relative existence is deliberately outside this root-only observation.
        assert!(!root_include("parts/ui.xml", "deep/panel.xml"));
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
        assert_eq!(
            bitmap_ref("logoAlias").matching_alias_declaration_files,
            ["parts/ui.xml", "skin.xml"]
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
