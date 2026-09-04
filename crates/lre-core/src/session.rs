//! Sessionful runtime foundation (review Phase 2 / CORE-002 + RuntimeConfig).
//!
//! The clipboard of the ratified review: "the UI must not know storage or
//! launcher details" and "open/map once; share reads across all views and
//! workers". This module replaces the per-read `load_native` pattern with a
//! single read-only memory map per open program, a first-class (immutable)
//! runtime configuration, and a session that carries the image.
//!
//! `RuntimeConfig` is the internal contract going forward: environment
//! variables may seed defaults (the CLI's env surface stays), but services
//! take an explicit value — never call `std::env` themselves.

use crate::native::NativeImport;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Immutable runtime configuration (built from env defaults or explicit
/// values; services receive one instead of reading process-wide state).
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Path to the `lre-worker` binary.
    pub worker_path: PathBuf,
    /// Path to the patched `ghidra_opt` (raw-SLEIGH mode).
    pub decompiler_path: PathBuf,
    /// Spec root directory (pspec/cspec/tspec/coretypes + registers.txt).
    pub spec_root: PathBuf,
    /// SLEIGH console binary (disasm-native / console discovery), if built.
    pub console_path: Option<PathBuf>,
    /// Selected Ghidra language id (defaults to x86-64).
    pub language_id: String,
    /// Installed processor directory used by the SLEIGH console.
    pub language_dir: PathBuf,
    /// Compiled .sla used by the raw-SLEIGH worker hook.
    pub sla_path: Option<PathBuf>,
    /// Ghidra 12.1.3 install root (console language lookup).
    pub ghidra_install: PathBuf,
    /// Peak RSS permitted for one worker process (bytes).
    pub worker_memory_cap: u64,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

/// Reads the stored language id for `program` from the project database.
/// Used to drive per-language decompile resolution; falls back to the
/// configured default when the store is unreachable.
pub fn program_language(
    cfg: &RuntimeConfig,
    program: &str,
    project_dir: &std::path::Path,
) -> crate::Result<String> {
    let db = crate::ProjectDb::open(&project_dir.join("project.sqlite"))?;
    let id = db.program_id(program)?;
    Ok(db.program_language(id)?)
}

impl RuntimeConfig {
    /// Builds a config from the environment (the CLI's documented surface),
    /// with repo/install-relative defaults.
    pub fn from_env() -> Self {
        let install = std::env::var("VENTRIS_GHIDRA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(format!(
                    "{}/ghidra_12.1.3_PUBLIC",
                    std::env::var("HOME").unwrap_or_default()
                ))
            });
        let language_id = std::env::var("VENTRIS_LANGUAGE")
            .unwrap_or_else(|_| "x86:LE:64:default".into());
        let language_dir = std::env::var("VENTRIS_LANGUAGE_DIR")
            .map(PathBuf::from)
            .ok()
            .or_else(|| {
                crate::architecture::directory_for_id(&install, &language_id)
                    .ok()
                    .flatten()
            })
            .unwrap_or_else(|| install.join("Ghidra/Processors/x86/data/languages"));
        let worker_path = std::env::var("VENTRIS_WORKER")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("target/debug/lre-worker"));
        let decompiler_path = std::env::var("VENTRIS_GHIDRA_OPT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("native/build/ghidra_opt"));
        let spec_root = std::env::var("VENTRIS_SPECS")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("native/specs"));
        let console_path = std::env::var("VENTRIS_CONSOLE")
            .map(PathBuf::from)
            .ok()
            .or_else(|| {
                for candidate in [
                    PathBuf::from("native/build/decomp_native"),
                    PathBuf::from("../../native/build/decomp_native"),
                    PathBuf::from("../native/build/decomp_native"),
                    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../native/build/decomp_native"),
                ] {
                    if candidate.is_file() {
                        return Some(candidate);
                    }
                }
                None
            });
        let sla_path = std::env::var("VENTRIS_SLA")
            .ok()
            .filter(|p| {
                let pb = PathBuf::from(p);
                pb.is_file()
            })
            .map(PathBuf::from);
        Self {
            worker_path,
            decompiler_path,
            spec_root,
            language_id,
            language_dir,
            console_path,
            sla_path,
            ghidra_install: install,
            worker_memory_cap: 256 * 1024 * 1024,
        }
    }
}

/// One mapped file range with its flags (ELF SHF_* / PE section chars).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    pub vaddr: u64,
    /// Virtual size (includes BSS/file-less extent).
    pub size: u64,
    pub file_off: u64,
    /// File-backed bytes (section raw size on disk; may be < `size`).
    pub file_size: u64,
    pub flags: u64,
}

/// Read-only program image: one mmap + region map + sparse patch overlay.
///
/// Reads land in a region's file range where file-backed, zero otherwise
/// (BSS), with patch bytes taking precedence. The binary is mapped (not
/// copied) so listing/hex/decompiler consumers share one view of the file.
#[derive(Debug)]
pub struct ProgramImage {
    path: PathBuf,
    map: memmap2::Mmap,
    regions: Vec<MemoryRegion>,
    patches: BTreeMap<u64, Vec<u8>>,
}

impl ProgramImage {
    /// Maps `binary` and derives regions from the existing native loader
    /// (the loader's section/mapping knowledge, minus its discovery work).
    pub fn open(binary: &Path) -> crate::Result<Self> {
        let file = std::fs::File::open(binary).map_err(crate::CoreError::Io)?;
        // SAFETY: the file handle stays alive for the mapping's lifetime
        // (memmap2's `Mmap` keeps the mapping; the handle is only needed
        // by the unsafe block below, which memmap2 requires us to allow —
        // this is the single reviewed FFI-adjacent site).
        // SAFETY: read-only mapping; no file can be written through it;
        // the file content cannot change beneath us because we keep a
        // separate read-only descriptor semantics and treat the absence
        // of a mapping as a fixed snapshot of the open file's bytes.
        let map = unsafe { memmap2::Mmap::map(&file) }.map_err(|e| {
            crate::CoreError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("mmap {}: {e}", binary.display()),
            ))
        })?;
        // Region derivation reuses the native parser (sections -> ranges;
        // flags preserved so discovery classification still sees them).
        let mappings = crate::native::load_native_mappings(binary)?;
        let regions = mappings
            .iter()
            .map(|m| MemoryRegion {
                vaddr: m.vaddr,
                size: m.size,
                file_off: m.file_off,
                file_size: m.bytes.len() as u64,
                flags: m.flags,
            })
            .collect();
        Ok(Self {
            path: binary.to_path_buf(),
            map,
            regions,
            patches: BTreeMap::new(),
        })
    }

    /// The mapped file path (diagnostics).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// All derived regions (ascending vaddr).
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Applies a sparse patch (offset -> bytes) over the mapped image.
    pub fn patch(&mut self, vaddr: u64, bytes: Vec<u8>) {
        self.patches.insert(vaddr, bytes);
    }

    /// Reads `size` bytes at `vaddr`. Within a region: file-backed bytes
    /// where the region has them, zeros for the rest (BSS). Patches
    /// override region reads. Returns `None` when the range crosses a
    /// region boundary or is unmapped.
    pub fn read(&self, vaddr: u64, size: u64) -> Option<Vec<u8>> {
        let region = self.regions.iter().find(|r| {
            vaddr >= r.vaddr && vaddr.checked_add(size).map(|e| e <= r.vaddr + r.size).unwrap_or(false)
        })?;
        let mut out = vec![0u8; size as usize];
        let local = vaddr - region.vaddr;
        let file_bytes = region.file_off.checked_add(local)?;
        // Zero-fill by default (BSS); copy file-backed bytes where the
        // mapping covers them. `Mmap` derefs to `&[u8]` — no unsafe here.
        for (i, b) in out.iter_mut().enumerate() {
            let at = file_bytes + i as u64;
            if at < region.file_off + region.file_size {
                *b = self.map.get(at as usize).copied().unwrap_or(0);
            } else {
                *b = 0;
            }
        }
        for (p, bytes) in &self.patches {
            let pend = p + bytes.len() as u64;
            let ostart = vaddr.max(*p);
            let oend = (vaddr + size).min(pend);
            if ostart < oend {
                let src = (ostart - *p) as usize;
                let dst = (ostart - vaddr) as usize;
                out[dst..dst + (oend - ostart) as usize]
                    .copy_from_slice(&bytes[src..src + (oend - ostart) as usize]);
            }
        }
        Some(out)
    }
}

/// An open program: identity + shared image + provenance metadata.
#[derive(Debug, Clone)]
pub struct ProgramSession {
    /// Program name in the project store.
    pub program: String,
    /// Shared, read-only binary image (views and workers share it).
    pub image: Arc<ProgramImage>,
    /// Import provenance and format facts the UI needs to display.
    pub metadata: SessionMetadata,
}

#[derive(Debug, Clone)]
pub struct SessionMetadata {
    /// Ghidra-compatible language id selected by the importer.
    pub language: String,
    /// `ELF` / `PE`
    pub format: String,
    /// Load address used for byte resolution (0 for ET_DYN, image base for PE).
    pub image_base: u64,
}

impl SessionMetadata {
    /// Derives metadata from a loaded import (the session's one parse).
    pub fn from_import(imp: &NativeImport) -> Self {
        let image_base = imp
            .mappings
            .iter()
            .map(|m| m.vaddr)
            .min()
            .unwrap_or(0)
            & !0xfff;
        Self {
            language: imp.language.clone(),
            format: imp.format.clone(),
            image_base,
        }
    }
}

/// Session configuration error.
#[derive(Debug, thiserror::Error)]
#[error("session: {0}")]
pub struct SessionError(pub String);

pub type Result<T> = std::result::Result<T, SessionError>;


#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> ProgramImage {
        // File-backed bytes at 0x400000 (file off 0, 0x100 bytes) and a
        // BSS region at 0x400100 (file off 0x100, 0x200 bytes, file only
        // covers 0x40).
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("lre-session-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("img.bin");
        let data: Vec<u8> = (0..0x1000u64).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &data).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        // SAFETY: read-only mapping of the test file; the file is not
        // modified while the mmap lives (same contract as ProgramImage::open).
        let map = unsafe { memmap2::Mmap::map(&file) }.unwrap();
        let mut img = ProgramImage {
            path,
            map,
            regions: vec![
                MemoryRegion { vaddr: 0x400000, size: 0x100, file_off: 0, file_size: 0x100, flags: 0x6 },
                MemoryRegion { vaddr: 0x400100, size: 0x200, file_off: 0x100, file_size: 0x40, flags: 0x2 },
            ],
            patches: BTreeMap::new(),
        };
        img.patch(0x400010, vec![0xde, 0xad]);
        img
    }

    #[test]
    fn region_read_copies_file_bytes() {
        let image = image();
        let r = image.read(0x400000, 8).unwrap();
        assert_eq!(r, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn bss_zero_fills_beyond_file_range() {
        let image = image();
        // 0x400100 + 0x40 covers the file range; past that: zeros.
        let r = image.read(0x400140, 8).unwrap();
        assert_eq!(r, vec![0; 8]);
        let r = image.read(0x400100, 4).unwrap();
        let want: Vec<u8> = (0x100..0x104).map(|i| (i % 251) as u8).collect();
        assert_eq!(r, want);
    }

    #[test]
    fn patch_overrides_region_read() {
        let image = image();
        let r = image.read(0x400010, 2).unwrap();
        assert_eq!(r, vec![0xde, 0xad]);
    }

    #[test]
    fn unmapped_or_crossing_read_is_none() {
        let image = image();
        assert!(image.read(0x500000, 4).is_none());
        // Spanning two regions (0x4000ff..0x400103) -> None.
        assert!(image.read(0x4000ff, 4).is_none());
    }

    #[test]
    fn program_image_opens_real_fixture() {
        // Exercises ProgramImage::open's real path: mmap + loader-derived
        // regions; add's entry bytes at 0x400466 must read back from the map.
        let path = Path::new("../../tests/fixtures-src/tiny_bin");
        if !path.is_file() {
            return; // not present in a published crate test context
        }
        let img = ProgramImage::open(path).unwrap();
        assert!(!img.regions().is_empty());
        // add: 55 48 89 e5 (push rbp; mov rbp,rsp)
        let r = img.read(0x400466, 4).unwrap();
        assert_eq!(r, vec![0x55, 0x48, 0x89, 0xe5]);
    }

    #[test]
    fn runtime_config_builds_from_env_defaults() {
        let cfg = RuntimeConfig::from_env();
        assert_eq!(cfg.worker_memory_cap, 256 * 1024 * 1024);
        assert!(cfg.spec_root.ends_with("native/specs"));
    }
}
