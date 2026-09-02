//! Architecture discovery from an installed Ghidra processor tree.
//!
//! This is metadata discovery only: it never edits the pinned upstream tree.
//! Each returned language points at the directory whose `.sla` files can be
//! selected by a native consumer.

use lre_model::ArchitectureSpec;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ArchitectureError {
    #[error("architecture tree: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ArchitectureError>;

/// Enumerates processor language definitions below `install/Ghidra/Processors`.
pub fn discover(install: &Path) -> Result<Vec<ArchitectureSpec>> {
    let root = install.join("Ghidra/Processors");
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut specs = Vec::new();
    for processor in std::fs::read_dir(root)? {
        let processor = processor?;
        let processor_path = processor.path();
        if !processor_path.is_dir() {
            continue;
        }
        let language_dir = processor_path.join("data/languages");
        if !language_dir.is_dir() {
            continue;
        }
        let mut sla_count = 0;
        for entry in std::fs::read_dir(&language_dir)? {
            if entry?.path().extension().is_some_and(|ext| ext == "sla") {
                sla_count += 1;
            }
        }
        for ldefs in language_dir_files(&language_dir)? {
            let xml = std::fs::read_to_string(&ldefs)?;
            for language in tags(&xml, "language") {
                let Some(id) = attribute(language, "id") else {
                    continue;
                };
                let processor_name = attribute(language, "processor")
                    .unwrap_or_else(|| processor.file_name().to_string_lossy().into_owned());
                let endian = attribute(language, "endian").unwrap_or_default();
                let bits = attribute(language, "size").and_then(|size| size.parse().ok());
                specs.push(ArchitectureSpec {
                    id,
                    processor: processor_name,
                    endian,
                    bits,
                    language_dir: language_dir.to_string_lossy().into_owned(),
                    sla_count,
                });
            }
        }
    }
    specs.sort_by(|left, right| left.id.cmp(&right.id));
    specs.dedup_by(|left, right| left.id == right.id);
    Ok(specs)
}
/// Finds the installed language directory containing `id`.
pub fn directory_for_id(install: &Path, id: &str) -> Result<Option<PathBuf>> {
    Ok(discover(install)?
        .into_iter()
        .find(|spec| spec.id == id)
        .map(|spec| PathBuf::from(spec.language_dir)))
}


fn language_dir_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = std::fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "ldefs"))
        .collect::<Vec<_>>();
    files.sort();
    Ok(files)
}

fn tags<'a>(xml: &'a str, _name: &str) -> impl Iterator<Item = &'a str> {
    let mut found = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<language ") {
        let tag = &rest[start..];
        let Some(end) = tag.find('>') else {
            break;
        };
        found.push(&tag[..end]);
        rest = &tag[end..];
    }
    found.into_iter()
}

fn attribute(tag: &str, name: &str) -> Option<String> {
    let marker = format!("{name}=\"");
    let start = tag.find(&marker)? + marker.len();
    let end = tag[start..].find('"')?;
    Some(tag[start..start + end].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn discovers_language_metadata_without_mutating_tree() {
        let root = std::env::temp_dir().join(format!(
            "ventris-arch-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let languages = root.join("Ghidra/Processors/ARM/data/languages");
        fs::create_dir_all(&languages).unwrap();
        fs::write(
            languages.join("ARM.ldefs"),
            r#"<language_definitions><language id="ARM:LE:32:v8" processor="ARM" endian="little" size="32"/></language_definitions>"#,
        )
        .unwrap();
        fs::write(languages.join("ARM8_le.sla"), b"sla").unwrap();
        let specs = discover(&root).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].id, "ARM:LE:32:v8");
        assert_eq!(specs[0].bits, Some(32));
        assert_eq!(specs[0].sla_count, 1);
        assert!(languages.join("ARM.ldefs").is_file());
        fs::remove_dir_all(root).unwrap();
    }
}
