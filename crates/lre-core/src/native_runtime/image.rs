//! Temporary sparse images for the pinned LoadImageXml console loader.
use super::{NativeRuntimeError, Result};
use crate::native::NativeImport;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) struct MappedImage {
    path: PathBuf,
}

impl MappedImage {
    pub(super) fn for_elf_or_dol(binary: &Path) -> Result<Option<Self>> {
        let mut file = std::fs::File::open(binary)
            .map_err(|e| NativeRuntimeError(format!("image probe: {e}")))?;
        let mut prefix = [0; 4];
        let size = file.read(&mut prefix)
            .map_err(|e| NativeRuntimeError(format!("image probe: {e}")))?;
        if prefix[..2] == *b"MZ" {
            return Ok(None);
        }
        let mut bytes = prefix[..size].to_vec();
        file.read_to_end(&mut bytes)
            .map_err(|e| NativeRuntimeError(format!("mapped image read: {e}")))?;
        if prefix == *b"\x7fELF" {
            let import = crate::native::import_elf(&bytes)
                .map_err(|e| NativeRuntimeError(format!("ELF image: {e}")))?;
            return Self::new(&import).map(Some);
        }
        // DOL has no magic. Non-DOL raw images remain valid console inputs.
        match crate::native::dol::import(&bytes) {
            Ok(import) => Self::new(&import).map(Some),
            Err(_) => Ok(None),
        }
    }

    pub(super) fn new(import: &NativeImport) -> Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!("ventris-image-{}-{}.xml",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)
            .map_err(|e| NativeRuntimeError(format!("mapped image create: {e}")))?;
        let image = Self { path };
        let mut writer = std::io::BufWriter::new(file);
        let mut write_image = || -> std::io::Result<()> {
            // Full language + compiler id; resolveArchitecture uses loader.getArchType.
            writeln!(writer, "<binaryimage arch=\"{}:default\">", import.language)?;
            for mapping in &import.mappings {
                // BSS is non-executable and has no instruction bytes. Native
                // ProgramImage supplies its zero-fill to memory/worker consumers.
                if mapping.bytes.is_empty() { continue; }
                write!(writer, "<bytechunk space=\"ram\" offset=\"0x{:x}\">", mapping.vaddr)?;
                for byte in &mapping.bytes { write!(writer, "{byte:02x}")?; }
                writeln!(writer, "</bytechunk>")?;
            }
            // Relocated BSS words have no file-backed mapping bytes.
            for relocation in &import.relocations {
                if import.mappings.iter().any(|m| relocation.address >= m.vaddr
                    && relocation.address - m.vaddr < m.bytes.len() as u64) { continue; }
                write!(writer, "<bytechunk space=\"ram\" offset=\"0x{:x}\">", relocation.address)?;
                for byte in &relocation.bytes[..relocation.width] { write!(writer, "{byte:02x}")?; }
                writeln!(writer, "</bytechunk>")?;
            }
            writeln!(writer, "</binaryimage>")?;
            writer.flush()
        };
        write_image().map_err(|e| NativeRuntimeError(format!("mapped image write: {e}")))?;
        Ok(image)
    }

    pub(super) fn command(&self) -> String {
        // No explicit target: a colon-bearing target forces RawBinaryArchitecture
        // in the existing patch, bypassing XML capability selection.
        format!("load file {}\n", self.path.display())
    }
}

impl Drop for MappedImage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
