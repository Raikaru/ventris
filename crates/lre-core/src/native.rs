//! Native (no-JVM) ELF/PE/DOL import: parse headers, derive the memory map,
//! discover functions from symbols and entry-point call walking, and extract
//! direct xrefs. Facts land in the same project.sqlite tables the bridge
//! import fills, with provenance `native-import`.
//!
//! Design notes:
//! - ELF64 import selects a Ghidra language from `e_machine` for the
//!   architectures currently represented in the catalog; PE supports PE32+ (x86-64) and PE32 (i386).
//! - Structural ELF facts (mappings, symbols, entry point) are architecture
//!   independent. Discovery uses the selected SLEIGH language and the generic
//!   worklist; without a console, ELF/PE retain structural facts only.
use lre_db::ProjectDb;
use std::collections::HashSet;
use std::path::Path;
pub(crate) mod dol;
mod discovery;
mod elf_pointers;
mod elf_unwind;
use lre_model::{
    FunctionRow, MemoryRegion, Provenance, ProgramSummary, StringRow, XrefRow,
};
/// Errors from a native import.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("{0}")]
    Bad(String),
    #[error("store: {0}")]
    Store(#[from] lre_db::DbError),
}

pub type Result<T> = std::result::Result<T, ImportError>;

pub fn native_provenance() -> Provenance {
    Provenance {
        producer: "native-import".into(),
        upstream_version: "12.1.3".into(),
    }
}

/// One loaded code/data range in memory (vaddr..vaddr+size).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub vaddr: u64,
    pub size: u64,
    /// File offset of the mapping's first byte (ELF: section offset; PE:
    /// section raw offset — the RVA-to-file translation the worker uses).
    pub file_off: u64,
    /// Section flags: ELF SHF_* (0x4 = executable); PE image characteristics
    /// (0x60000020 = code).
    pub flags: u64,
    /// Raw bytes of the mapping.
    pub bytes: Vec<u8>,
}

/// A discovered function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFunction {
    pub entry: u64,
    pub name: String,
    pub size: u64,
}

/// A discovered xref (direct call or branch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeXref {
    pub from: u64,
    pub to: u64,
    pub kind: String,
    pub provenance: String,
}

impl NativeXref {
    pub fn new(from: u64, to: u64, kind: impl Into<String>) -> Self {
        Self {
            from,
            to,
            kind: kind.into(),
            provenance: "native-import".into(),
        }
    }

    pub fn with_provenance(from: u64, to: u64, kind: impl Into<String>, provenance: impl Into<String>) -> Self {
        Self {
            from,
            to,
            kind: kind.into(),
            provenance: provenance.into(),
        }
    }
}

/// Parsed import result: everything the importer writes to the store.
#[derive(Debug, Default)]
pub struct NativeImport {
    pub mappings: Vec<Mapping>,
    pub functions: Vec<NativeFunction>,
    pub xrefs: Vec<NativeXref>,
    pub externals: Vec<(u64, String)>,
    /// Relocation code targets to be verified as candidate function entries.
    pub reloc_candidates: Vec<u64>,
    /// Untrusted data pointers; never functions until flow confirms them.
    pub pointer_candidates: Vec<u64>,
    /// Loader-declared initializer entry points, also requiring valid flow.
    pub initializer_candidates: Vec<u64>,
    pub format: String,
    /// Ghidra-compatible language id selected from the file machine.
    pub language: String,
    /// Runtime configuration used to reach the SLEIGH console/worker.
    pub cfg: crate::session::RuntimeConfig,
    /// Path to the binary used for console-driven x86 flow.
    pub binary: std::path::PathBuf,
}
fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(ImportError::Bad(msg.into()))
}

fn u16_at(b: &[u8], o: usize) -> Result<u16> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(ImportError::Bad("truncated".into()))
}
fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(ImportError::Bad("truncated".into()))
}
fn u64_at(b: &[u8], o: usize) -> Result<u64> {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .ok_or(ImportError::Bad("truncated".into()))
}
fn u16_be_at(b: &[u8], o: usize) -> Result<u16> {
    b.get(o..o + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or(ImportError::Bad("truncated".into()))
}
fn u32_be_at(b: &[u8], o: usize) -> Result<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(ImportError::Bad("truncated".into()))
}

// ---- ELF32 ----------------------------------------------------------------

/// ELF32 section parse (40-byte Shdr), either endianness.
fn parse_elf32_sections(data: &[u8], be: bool) -> Result<(Vec<ElfSection>, Vec<u8>)> {
    let rd32 = |o: usize| -> Result<u32> {
        if be {
            u32_be_at(data, o)
        } else {
            u32_at(data, o)
        }
    };
    let rd16 = |o: usize| -> Result<u16> {
        if be {
            u16_be_at(data, o)
        } else {
            u16_at(data, o)
        }
    };
    let shentsize = rd16(46)? as usize;
    let shnum = rd16(48)? as usize;
    let shoff = rd32(32)? as usize;
    let shstrndx = rd16(50)? as usize;
    if shoff == 0 || shnum == 0 {
        return err("ELF32 has no section headers");
    }
    let mut sections = Vec::new();
    for i in 0..shnum {
        let hdr = shoff + i * shentsize;
        if hdr + 40 > data.len() {
            break;
        }
        sections.push(ElfSection {
            name: String::new(),
            typ: rd32(hdr + 4)?,
            flags: rd32(hdr + 8)? as u64,
            addr: rd32(hdr + 12)? as u64,
            off: rd32(hdr + 16)? as u64,
            size: rd32(hdr + 20)? as u64,
            link: rd32(hdr + 24)?,
        });
    }
    // shstrtab content for names.
    let mut shstr = Vec::new();
    if let Some(s) = sections.get(shstrndx) {
        shstr = data
            .get(s.off as usize..s.off as usize + s.size as usize)
            .unwrap_or(&[])
            .to_vec();
    }
    for section in &mut sections {
        let name_off = rd32(shoff + 0)?; // placeholder, replaced below
        let _ = name_off;
    }
    // Names: re-walk with stored offsets (Shdr sh_name at +0).
    let mut name_offs = Vec::new();
    for i in 0..sections.len() {
        name_offs.push(rd32(shoff + i * shentsize)? as usize);
    }
    for (section, name_off) in sections.iter_mut().zip(name_offs) {
        section.name = shstr
            .get(name_off..)
            .and_then(|r| r.split(|c| *c == 0).next())
            .map(|r| String::from_utf8_lossy(r).into_owned())
            .unwrap_or_default();
    }
    Ok((sections, shstr))
}

/// ELF32 import (Phase 4 target: GameCube PowerPC BE, PS2 MIPS BE).
/// Symbols come from SHT_SYMTAB (16-byte Elf32_Sym); the x86 GOT-stub scan
/// and RELA processing do not apply and are skipped.
fn import_elf32(data: &[u8], be: bool) -> Result<NativeImport> {
    let rd32 = |o: usize| -> Result<u32> {
        if be {
            u32_be_at(data, o)
        } else {
            u32_at(data, o)
        }
    };
    let rd16 = |o: usize| -> Result<u16> {
        if be {
            u16_be_at(data, o)
        } else {
            u16_at(data, o)
        }
    };
    let language = elf_language(rd16(18)?, be, rd32(36)?)?;
    let entry = rd32(24)? as u64;
    let (sections, _shstr) = parse_elf32_sections(data, be)?;

    let mut mappings = Vec::new();
    for s in sections.iter() {
        if s.flags & 0x2 == 0 || s.size == 0 {
            continue;
        }
        let b = data
            .get(s.off as usize..s.off as usize + s.size as usize)
            .unwrap_or(&[]);
        mappings.push(Mapping {
            vaddr: s.addr,
            size: s.size,
            file_off: s.off,
            flags: s.flags,
            bytes: b.to_vec(),
        });
    }
    if mappings.is_empty() {
        return err("ELF has no allocated sections");
    }

    let mut functions = Vec::new();
    let mut externals = Vec::new();
    // SHT_SYMTAB (2) and SHT_DYNSYM (11): 16-byte Elf32_Sym.
    for s in sections.iter().filter(|s| s.typ == 2 || s.typ == 11) {
        let strtab = sections
            .get(s.link as usize)
            .map(|t| {
                data.get(t.off as usize..t.off as usize + t.size as usize)
                    .unwrap_or(&[])
                    .to_vec()
            })
            .unwrap_or_default();
        let count = s.size as usize / 16;
        for i in 0..count {
            let hdr = s.off as usize + i * 16;
            if hdr + 16 > data.len() {
                break;
            }
            let name_off = rd32(hdr)? as usize;
            let info = data[hdr + 12];
            let shndx = rd16(hdr + 14)?;
            let value = rd32(hdr + 4)? as u64;
            let size = rd32(hdr + 8)? as u64;
            let name = strtab
                .get(name_off..)
                .and_then(|r| r.split(|c| *c == 0).next())
                .map(|r| String::from_utf8_lossy(r).into_owned())
                .unwrap_or_default();
            let typ = info & 0xf;
            if typ == 2 && value != 0 && !name.is_empty() {
                functions.push(NativeFunction {
                    entry: value,
                    name: name.clone(),
                    size: size.max(1),
                });
            }
            if shndx == 0 && !name.is_empty() {
                externals.push((0, name.clone()));
            }
        }
    }
    if entry != 0 && !functions.iter().any(|f| f.entry == entry) {
        functions.push(NativeFunction {
            entry,
            name: "_entry".into(),
            size: 1,
        });
    }
    functions.sort_by_key(|f| f.entry);
    let mut import = NativeImport {

        format: "elf32".into(),
        language,
        mappings,
        functions,
        xrefs: Vec::new(),
        externals,
        ..Default::default()
    };
    elf_pointers::collect(data, &sections, &mut import, 4, be)?;
    elf_unwind::collect(data, &sections, &mut import, 4, be);
    Ok(import)
}

// ---- ELF64 ----------------------------------------------------------------

struct ElfSection {
    name: String,
    typ: u32,
    flags: u64,
    addr: u64,
    off: u64,
    size: u64,
    link: u32,
}

fn parse_elf_sections(data: &[u8]) -> Result<(Vec<ElfSection>, Vec<u8>)> {
    let shentsize = u16_at(data, 58)? as usize;
    let shnum = u16_at(data, 60)? as usize;
    let shoff = u64_at(data, 40)? as usize;
    let shstrndx = u16_at(data, 62)? as usize;
    let mut shstr = Vec::new();
    let mut sections = Vec::new();
    for i in 0..shnum {
        let hdr = shoff + i * shentsize;
        let name_off = u32_at(data, hdr)? as usize;
        sections.push(ElfSection {
            name: String::new(),
            typ: u32_at(data, hdr + 4)?,
            flags: u64_at(data, hdr + 8)?,
            addr: u64_at(data, hdr + 16)?,
            off: u64_at(data, hdr + 24)?,
            size: u64_at(data, hdr + 32)?,
            link: u32_at(data, hdr + 40)?,
        });
        sections.last_mut().unwrap().name = String::new(); // set below
    }
    // fetch shstrtab content
    {
        let hdr = shoff + shstrndx * shentsize;
        let off = u64_at(data, hdr + 24)? as usize;
        let sz = u64_at(data, hdr + 32)? as usize;
        shstr = data.get(off..off + sz).unwrap_or(&[]).to_vec();
    }
    // names assigned from shstrtab after fetching; store raw offsets
    let mut name_offs = Vec::new();
    for i in 0..shnum {
        let hdr = shoff + i * shentsize;
        name_offs.push(u32_at(data, hdr)? as usize);
    }
    for (s, no) in sections.iter_mut().zip(name_offs) {
        s.name = shstr
            .get(no..)
            .and_then(|r| r.split(|c| *c == 0).next())
            .map(|r| String::from_utf8_lossy(r).into_owned())
            .unwrap_or_default();
    }
    Ok((sections, shstr))
}

fn elf_language(machine: u16, big_endian: bool, flags: u32) -> Result<String> {
    // ARM ELF EF_ARM_BE8: big-endian data, little-endian instructions.
    // The pinned ARM.ldefs calls this variant v7LEInstruction.
    const EF_ARM_BE8: u32 = 0x0080_0000;
    match (machine, big_endian) {
        (0x03e, false) => Ok("x86:LE:64:default".into()),
        (0x003, false) => Ok("x86:LE:32:default".into()),
        (0x0b7, false) => Ok("AARCH64:LE:64:v8A".into()),
        (0x028, false) => Ok("ARM:LE:32:v7".into()),
        (0x028, true) if flags & EF_ARM_BE8 != 0 => Ok("ARM:LEBE:32:v7LEInstruction".into()),
        (0x028, true) => Ok("ARM:BE:32:v7".into()),
        (0x008, false) => Ok("MIPS:LE:32:default".into()),
        (0x008, true) => Ok("MIPS:BE:32:default".into()),
        (0x0f3, false) => Ok("RISCV:LE:64:default".into()),
        (0x014, false) => Ok("PowerPC:LE:32:default".into()),
        (0x014, true) => Ok("PowerPC:BE:32:default".into()),
        (0x015, false) => Ok("PowerPC:LE:64:default".into()),
        (0x015, true) => Ok("PowerPC:BE:64:default".into()),
        (other, _) => err(format!("unsupported ELF machine {other:#x}")),
    }
}

/// ELF64 parse. Returns (mappings, functions from symtab + entry, externals).
pub fn import_elf(data: &[u8]) -> Result<NativeImport> {
    if data.get(0..4) != Some(b"\x7fELF") {
        return err("not an ELF");
    }
    // A magic-only (or truncated) file must error, not panic on indexing.
    if data.len() < 6 {
        return err("truncated ELF header");
    }
    if data[4] == 1 {
        // ELF32: GameCube/PS2-class images (PowerPC/MIPS, either endian).
        return import_elf32(data, data[5] == 2);
    }
    if data[4] != 2 || data[5] != 1 {
        return err("ELF64 little-endian expected");
    }
    let language = elf_language(u16_at(data, 18)?, false, u32_at(data, 48)?)?;
    let entry = u64_at(data, 24)?;
    let (sections, _shstr) = parse_elf_sections(data)?;

    // Mappings: SHF_ALLOC sections carrying file bytes (SHT_PROGBITS etc).
    let mut mappings = Vec::new();
    for s in sections.iter() {
        if s.flags & 0x2 == 0 || s.size == 0 {
            continue;
        }
        let b = data
            .get(s.off as usize..s.off as usize + s.size as usize)
            .unwrap_or(&[]);
        mappings.push(Mapping {
            vaddr: s.addr,
            size: s.size,
            file_off: s.off,
            flags: s.flags,
            bytes: b.to_vec(),
        });
    }
    if mappings.is_empty() {
        return err("ELF has no allocated sections");
    }

    // Symbols: the SHT_SYMTAB (type 2) and its sh_link strtab.
    let mut functions = Vec::new();
    let mut externals = Vec::new();
    for s in sections.iter() {
        if s.typ != 2 {
            continue;
        }
        let strtab = sections
            .get(s.link as usize)
            .map(|t| {
                data.get(t.off as usize..t.off as usize + t.size as usize)
                    .unwrap_or(&[])
                    .to_vec()
            })
            .unwrap_or_default();
        let count = s.size as usize / 24;
        for i in 0..count {
            let hdr = s.off as usize + i * 24;
            if hdr + 24 > data.len() {
                break;
            }
            let name_off = u32_at(data, hdr)? as usize;
            let info = data[hdr + 4];
            // ELF64_Sym: st_name(0,4) st_info(4) st_other(5) st_shndx(6,2)
            // st_value(8,8) st_size(16,8)
            let value = u64_at(data, hdr + 8)?;
            let size = u64_at(data, hdr + 16)?;
            let name = strtab
                .get(name_off..)
                .and_then(|r| r.split(|c| *c == 0).next())
                .map(|r| String::from_utf8_lossy(r).into_owned())
                .unwrap_or_default();
            let typ = info & 0xf;
            if typ == 2 && value != 0 && !name.is_empty() {
                functions.push(NativeFunction {
                    entry: value,
                    name: name.clone(),
                    size: size.max(1),
                });
            }
            if value == 0 && typ == 1 && !name.is_empty() {
                externals.push((0, name));
            }
        }
    }
    // SHT_DYNSYM (6): externals (SHN_UNDEF) that the loader binds; their
    // PLT stubs are named via SHT_RELA (4) .rela.plt/dyn entries.
    let mut dynsyms: Vec<String> = Vec::new();
    // SHT_DYNSYM = 11 (SHT_SYMTAB = 2 already handled above).
    for s in sections.iter().filter(|s| s.typ == 11) {
        let strtab = sections
            .get(s.link as usize)
            .map(|t| {
                data.get(t.off as usize..t.off as usize + t.size as usize)
                    .unwrap_or(&[])
                    .to_vec()
            })
            .unwrap_or_default();
        let count = s.size as usize / 24;
        for i in 0..count {
            let hdr = s.off as usize + i * 24;
            if hdr + 24 > data.len() {
                break;
            }
            let name_off = u32_at(data, hdr)? as usize;
            let info = data[hdr + 4];
            let shndx = u16_at(data, hdr + 6)?;
            let name = strtab
                .get(name_off..)
                .and_then(|r| r.split(|c| *c == 0).next())
                .map(|r| String::from_utf8_lossy(r).into_owned())
                .unwrap_or_default();
            if !name.is_empty() {
                if shndx == 0 {
                    externals.push((0, name.clone()));
                }
            }
            // Preserve index zero: relocation symbol indexes are absolute.
            dynsyms.push(name);
            let _ = info;
        }
    }
    // .rela.plt/.rela.dyn (SHT_RELA=4): r_offset -> symbol name. A PLT stub
    // `ff 25 <disp32>` references its GOT slot (stub+6+disp == r_offset), so
    // the exact stub gets the exact name regardless of relocation order.
    let mut relocs: Vec<(u64, String)> = Vec::new();
    for r in sections.iter().filter(|s| s.typ == 4 && s.size > 0) {
        let entry_count = r.size as usize / 24;
        for i in 0..entry_count {
            let hdr = r.off as usize + i * 24;
            if hdr + 24 > data.len() {
                break;
            }
            let got_off = u64_at(data, hdr)?;
            let r_info = u64_at(data, hdr + 8)?;
            let sym_idx = (r_info >> 32) as usize;
            if sym_idx < dynsyms.len() && !dynsyms[sym_idx].is_empty() {
                relocs.push((got_off, dynsyms[sym_idx].clone()));
            }
        }
    }
    let mut seen_got: Vec<(u64, String)> = Vec::new();
    for m in &mappings {
        let mut i = 0usize;
        while i + 6 <= m.bytes.len() {
            if m.bytes[i] == 0xff && m.bytes[i + 1] == 0x25 {
                let disp = i32::from_le_bytes([
                    m.bytes[i + 2], m.bytes[i + 3], m.bytes[i + 4], m.bytes[i + 5],
                ]);
                let got = (m.vaddr + i as u64 + 6).wrapping_add(disp as u64);
                if let Some((_, rname)) = relocs.iter().find(|(o, _)| *o == got) {
                    // .plt.sec on x86-64 is endbr64 (f3 0f 1e fa, 4 bytes) followed
                    // by the indirect jmp. Align the entry to the start of the stub.
                    let mut stub_off = i;
                    let mut stub_size = 6;
                    if i >= 4
                        && (m.bytes[i - 4..i] == [0xf3, 0x0f, 0x1e, 0xfa]
                            || m.bytes[i - 4..i] == [0xf3, 0x0f, 0x1e, 0xfb])
                    {
                        stub_off = i - 4;
                        stub_size = 10;
                    }
                    let addr = m.vaddr + stub_off as u64;
                    if !seen_got.iter().any(|(a, _)| *a == addr) {
                        functions.push(NativeFunction {
                            entry: addr,
                            name: rname.clone(),
                            size: stub_size,
                        });
                        externals.push((got, rname.clone()));
                        seen_got.push((addr, rname.clone()));
                    }
                }
                i += 6;
            } else {
                i += 1;
            }
        }
    }
    for s in &sections {
        if s.flags & 4 == 0 || s.size == 0 || s.addr == 0 || functions.iter().any(|f| f.entry == s.addr) {
            continue;
        }
        let (name, size) = match s.name.as_str() {
            ".init" => ("_init", s.size),
            ".fini" => ("_fini", s.size),
            ".plt" => ("_plt", 1),
            _ => continue,
        };
        functions.push(NativeFunction { entry: s.addr, name: name.into(), size });
    }
    // R_*_RELATIVE relocations: SHT_RELA (typ=4) and SHT_RELR (typ=19).
    // x86-64 R_X86_64_RELATIVE = 8, AArch64 R_AARCH64_RELATIVE = 1027,
    // RISC-V R_RISCV_RELATIVE = 3, PowerPC64 R_PPC64_RELATIVE = 22.
    let machine = u16_at(data, 18).unwrap_or(0);
    let rel_type = match machine {
        0x03e => 8,    // x86-64
        0x0b7 => 1027, // AArch64
        0x0f3 => 3,    // RISC-V
        0x015 => 22,   // PPC64
        _ => 8,
    };
    let mut reloc_candidates = Vec::new();
    let mut xrefs = Vec::new();
    for r in sections.iter().filter(|s| s.typ == 4 && s.size > 0) {
        let entry_count = r.size as usize / 24;
        for i in 0..entry_count {
            let hdr = r.off as usize + i * 24;
            if hdr + 24 > data.len() {
                break;
            }
            let got_off = u64_at(data, hdr)?;
            let r_info = u64_at(data, hdr + 8)?;
            let r_type = (r_info & 0xffffffff) as u32;
            if r_type == rel_type {
                let addend = u64_at(data, hdr + 16)? as i64;
                if addend > 0 {
                    let target = addend as u64;
                    xrefs.push(NativeXref::with_provenance(
                        got_off,
                        target,
                        "DATA",
                        "native-import:elf-reloc",
                    ));
                    let in_code = mappings
                        .iter()
                        .any(|m| m.flags & 0x4 != 0 && target >= m.vaddr && target < m.vaddr + m.size);
                    if in_code {
                        reloc_candidates.push(target);
                    }
                }
            }
        }
    }
    // SHT_RELR (type 19 = 0x13): packed relative relocations (RFC / generic ELF).
    for r in sections.iter().filter(|s| s.typ == 19 && s.size > 0) {
        let count = r.size as usize / 8;
        let mut where_addr: u64 = 0;
        let mut relr_locs = Vec::new();
        for i in 0..count {
            let hdr = r.off as usize + i * 8;
            if hdr + 8 > data.len() {
                break;
            }
            let entry = u64_at(data, hdr)?;
            if (entry & 1) == 0 {
                where_addr = entry;
                relr_locs.push(where_addr);
                where_addr = where_addr.wrapping_add(8);
            } else {
                for bit in 1..64 {
                    if (entry & (1u64 << bit)) != 0 {
                        relr_locs.push(where_addr.wrapping_add((bit - 1) * 8));
                    }
                }
                where_addr = where_addr.wrapping_add(63 * 8);
            }
        }
        for loc in relr_locs {
            for m in &mappings {
                if loc >= m.vaddr && loc + 8 <= m.vaddr + m.size {
                    let file_off = m.file_off + (loc - m.vaddr);
                    if let Ok(target) = u64_at(data, file_off as usize) {
                        xrefs.push(NativeXref::with_provenance(
                            loc,
                            target,
                            "DATA",
                            "native-import:elf-reloc",
                        ));
                        let in_code = mappings.iter().any(|m| {
                            m.flags & 0x4 != 0 && target >= m.vaddr && target < m.vaddr + m.size
                        });
                        if in_code {
                            reloc_candidates.push(target);
                        }
                    }
                    break;
                }
            }
        }
    }
    if entry != 0 && !functions.iter().any(|f| f.entry == entry) {
        functions.push(NativeFunction {
            entry,
            name: "_entry".into(),
            size: 1,
        });
    }
    functions.sort_by_key(|f| f.entry);
    functions.dedup_by_key(|f| f.entry);
    let mut import = NativeImport {
        mappings,
        functions,
        xrefs,
        externals,
        reloc_candidates,
        format: "ELF".into(),
        language,
        ..Default::default()
    };
    elf_pointers::collect(data, &sections, &mut import, 8, false)?;
    elf_unwind::collect(data, &sections, &mut import, 8, false);
    Ok(import)
}

pub fn import_pe(data: &[u8]) -> Result<NativeImport> {
    if data.get(0..2) != Some(b"MZ") {
        return err("not a PE");
    }
    let pe_off = u32_at(data, 0x3c)? as usize;
    if data.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return err("missing PE signature");
    }
    let machine = u16_at(data, pe_off + 4)?;
    let (is_64, language) = match machine {
        0x8664 => (true, "x86:LE:64:default"),
        0x014c => (false, "x86:LE:32:default"),
        other => return err(format!("unsupported PE machine {other:#x} (AMD64 0x8664 or i386 0x14c expected)")),
    };
    let num_sections = u16_at(data, pe_off + 6)? as usize;
    let opt_size = u16_at(data, pe_off + 20)? as usize;
    let opt = pe_off + 24;
    if opt + opt_size > data.len() {
        return err("PE optional header truncated");
    }
    let magic = u16_at(data, opt)?;

    let (entry_rva, image_base, reloc_dir_offset) = match (machine, magic) {
        (0x8664, 0x20b) => {
            if opt_size < 112 {
                return err(format!("PE32+ optional header size {opt_size} too small (>= 112 expected)"));
            }
            let entry_rva = u32_at(data, opt + 16)? as u64;
            let image_base = u64_at(data, opt + 24)?;
            let num_rva_sizes = u32_at(data, opt + 108)? as usize;
            let reloc_offset = if num_rva_sizes > 5 && opt_size >= 160 {
                Some(opt + 152)
            } else {
                None
            };
            (entry_rva, image_base, reloc_offset)
        }
        (0x014c, 0x10b) => {
            if opt_size < 96 {
                return err(format!("PE32 optional header size {opt_size} too small (>= 96 expected)"));
            }
            let entry_rva = u32_at(data, opt + 16)? as u64;
            let image_base = u32_at(data, opt + 28)? as u64;
            let num_rva_sizes = u32_at(data, opt + 92)? as usize;
            let reloc_offset = if num_rva_sizes > 5 && opt_size >= 144 {
                Some(opt + 136)
            } else {
                None
            };
            (entry_rva, image_base, reloc_offset)
        }
        (0x8664, other) => {
            return err(format!("PE AMD64 requires PE32+ optional header magic 0x20b, got {other:#x}"));
        }
        (0x014c, other) => {
            return err(format!("PE i386 requires PE32 optional header magic 0x10b, got {other:#x}"));
        }
        (other, _) => {
            return err(format!("unsupported PE machine {other:#x} (AMD64 0x8664 or i386 0x14c expected)"));
        }
    };
    let sec_table = opt + opt_size;
    if sec_table + num_sections * 40 > data.len() {
        return err("PE section table truncated");
    }
    let mut mappings = Vec::new();
    struct PeSectionInfo {
        vaddr: u64,
        vsize: usize,
        raw_off: usize,
    }
    let mut raw_sections = Vec::new();
    for i in 0..num_sections {
        let o = sec_table + i * 40;
        let vaddr = u32_at(data, o + 12)? as u64;
        let size = u32_at(data, o + 8)? as usize;
        let raw = u32_at(data, o + 20)? as usize;
        let raw_size = u32_at(data, o + 16)? as usize;
        if size == 0 {
            continue;
        }
        raw_sections.push(PeSectionInfo {
            vaddr,
            vsize: size,
            raw_off: raw,
        });
        let mut bytes = data.get(raw..raw + raw_size).unwrap_or(&[]).to_vec();
        bytes.resize(size, 0);
        let sflags = u32_at(data, o + 36)? as u64; // section characteristics
        let exec = sflags & 0x20000000 != 0;
        mappings.push(Mapping {
            vaddr: image_base + vaddr,
            size: size as u64,
            file_off: raw as u64,
            flags: if exec { 0x4 } else { 0 },
            bytes,
        });
    }
    if mappings.is_empty() {
        return err("PE has no sections");
    }
    let mut functions = vec![NativeFunction {
        entry: image_base + entry_rva,
        name: "_entry".into(),
        size: 1,
    }];

    // Parse base relocations from Data Directory 5 (.reloc)
    let (reloc_dir_rva, reloc_dir_size) = if let Some(offset) = reloc_dir_offset {
        let rva = u32_at(data, offset).unwrap_or(0) as u64;
        let size = u32_at(data, offset + 4).unwrap_or(0) as usize;
        (rva, size)
    } else {
        (0, 0)
    };

    let reloc_raw_data: Option<&[u8]> = if reloc_dir_rva > 0 && reloc_dir_size > 0 {
        raw_sections.iter().find_map(|s| {
            if reloc_dir_rva >= s.vaddr && reloc_dir_rva < s.vaddr + s.vsize as u64 {
                let off = s.raw_off + (reloc_dir_rva - s.vaddr) as usize;
                data.get(off..off + reloc_dir_size)
            } else {
                None
            }
        })
    } else {
        None
    };

    let mut reloc_candidates: Vec<u64> = Vec::new();
    let mut xrefs: Vec<NativeXref> = Vec::new();
    if let Some(reloc_bytes) = reloc_raw_data {
        let mut pos = 0usize;
        while pos + 8 <= reloc_bytes.len() {
            let page_rva = match u32_at(reloc_bytes, pos) {
                Ok(v) => v as u64,
                Err(_) => break,
            };
            let block_size = match u32_at(reloc_bytes, pos + 4) {
                Ok(v) => v as usize,
                Err(_) => break,
            };
            if block_size < 8 || pos + block_size > reloc_bytes.len() {
                break;
            }
            let entry_count = (block_size - 8) / 2;
            for i in 0..entry_count {
                let entry = match u16_at(reloc_bytes, pos + 8 + i * 2) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let r_type = entry >> 12;
                let r_offset = (entry & 0x0fff) as u64;
                let target_rva = page_rva + r_offset;
                let loc = image_base + target_rva;

                if let Some(m) = mappings.iter().find(|m| loc >= m.vaddr && loc < m.vaddr + m.size) {
                    let off = (loc - m.vaddr) as usize;
                    match r_type {
                        10 => { // IMAGE_REL_BASED_DIR64
                            if off + 8 <= m.bytes.len() {
                                let ptr = u64::from_le_bytes(m.bytes[off..off + 8].try_into().unwrap());
                                let in_mem = mappings.iter().any(|cm| ptr >= cm.vaddr && ptr < cm.vaddr + cm.size);
                                if in_mem {
                                    xrefs.push(NativeXref::with_provenance(
                                        loc,
                                        ptr,
                                        "DATA",
                                        "native-import:pe-reloc",
                                    ));
                                }
                                let in_code = mappings.iter().any(|cm| {
                                    cm.flags & 0x4 != 0 && ptr >= cm.vaddr && ptr < cm.vaddr + cm.size
                                });
                                if in_code {
                                    reloc_candidates.push(ptr);
                                }
                            }
                        }
                        3 => { // IMAGE_REL_BASED_HIGHLOW
                            if off + 4 <= m.bytes.len() {
                                let ptr = u32::from_le_bytes(m.bytes[off..off + 4].try_into().unwrap()) as u64;
                                let in_mem = mappings.iter().any(|cm| ptr >= cm.vaddr && ptr < cm.vaddr + cm.size);
                                if in_mem {
                                    xrefs.push(NativeXref::with_provenance(
                                        loc,
                                        ptr,
                                        "DATA",
                                        "native-import:pe-reloc",
                                    ));
                                }
                                let in_code = mappings.iter().any(|cm| {
                                    cm.flags & 0x4 != 0 && ptr >= cm.vaddr && ptr < cm.vaddr + cm.size
                                });
                                if in_code {
                                    reloc_candidates.push(ptr);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            pos += block_size;
        }
    }

    functions.sort_by_key(|f| f.entry);
    functions.dedup_by_key(|f| f.entry);
    Ok(NativeImport {
        mappings,
        functions,
        xrefs,
        externals: Vec::new(),
        reloc_candidates,
        format: "PE".into(),
        language: language.into(),
        ..Default::default()
    })
}
/// Returns the executable (code) ranges of the import, for seed filtering.
pub fn code_ranges(imp: &NativeImport) -> Vec<(u64, u64)> {
    imp.mappings
        .iter()
        .filter(|m| m.flags & 0x4 != 0 && m.size > 0)
        .map(|m| (m.vaddr, m.vaddr + m.size))
        .collect()
}

/// Finds a known external name for a function entry, if any (PLT/GOT named
/// stubs; FUN_<hex> otherwise).
pub fn extern_name(imp: &NativeImport, entry: u64) -> Option<String> {
    imp.externals
        .iter()
        .find(|(a, n)| *a == entry && !n.is_empty())
        .map(|(_, n)| n.clone())
}

/// Image base of a PE binary (the optional-header `ImageBase` field:
/// `e_lfanew + 24` (optional header start) `+ 24`), or `None` when `data`
/// is not a PE32+ with a parseable header. Used to default `--base` for
/// the worker: PE addresses are RVA-based, so byte resolution falls back
/// to `vaddr - base` when no section mapping covers a request.
pub fn pe_image_base(data: &[u8]) -> Option<u64> {
    if data.get(0..2) != Some(b"MZ") {
        return None;
    }
    let pe_off = u32_at(data, 0x3c).ok()? as usize;
    if data.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return None;
    }
    let opt = pe_off + 24;
    let magic = u16_at(data, opt).ok()?;
    if magic == 0x10b {
        u32_at(data, opt + 28).ok().map(|b| b as u64)
    } else if magic == 0x20b {
        u64_at(data, opt + 24).ok()
    } else {
        None
    }
}

/// Returns the preferred image base for an ELF image.
/// For ET_EXEC (fixed base), returns 0.
/// For ET_DYN (PIE / shared library), returns the minimum PT_LOAD vaddr
/// or 0x100000 (64-bit) / 0x10000 (32-bit), matching Ghidra's default.
pub fn elf_image_base(data: &[u8]) -> Option<u64> {
    if data.get(0..4) != Some(b"\x7fELF") || data.len() < 18 {
        return None;
    }
    let is_64 = data.get(4).copied() == Some(2);
    let is_be = data.get(5).copied() == Some(2);
    let e_type = if is_be {
        u16_be_at(data, 16).ok()?
    } else {
        u16_at(data, 16).ok()?
    };
    if e_type != 3 {
        // ET_EXEC or other non-DYN: base is already fixed in the headers.
        return Some(0);
    }
    // ET_DYN: find minimum PT_LOAD vaddr from program headers if any non-zero.
    let (phoff, phentsize, phnum) = if is_64 {
        let off = u64_at(data, 32).ok()? as usize;
        let esz = u16_at(data, 54).ok()? as usize;
        let num = u16_at(data, 56).ok()? as usize;
        (off, esz, num)
    } else {
        let off = if is_be { u32_be_at(data, 28).ok()? } else { u32_at(data, 28).ok()? } as usize;
        let esz = if is_be { u16_be_at(data, 42).ok()? } else { u16_at(data, 42).ok()? } as usize;
        let num = if is_be { u16_be_at(data, 44).ok()? } else { u16_at(data, 44).ok()? } as usize;
        (off, esz, num)
    };
    let mut min_vaddr = u64::MAX;
    for i in 0..phnum {
        let hdr = phoff + i * phentsize;
        if hdr + (if is_64 { 56 } else { 32 }) > data.len() {
            break;
        }
        let p_type = if is_be { u32_be_at(data, hdr).ok()? } else { u32_at(data, hdr).ok()? };
        if p_type == 1 {
            // PT_LOAD
            let p_vaddr = if is_64 {
                u64_at(data, hdr + 16).ok()?
            } else if is_be {
                u32_be_at(data, hdr + 8).ok()? as u64
            } else {
                u32_at(data, hdr + 8).ok()? as u64
            };
            if p_vaddr < min_vaddr {
                min_vaddr = p_vaddr;
            }
        }
    }
    if min_vaddr != u64::MAX && min_vaddr != 0 {
        Some(min_vaddr)
    } else if is_64 {
        Some(0x100000)
    } else {
        Some(0x10000)
    }
}

fn parse_native(data: &[u8]) -> Result<NativeImport> {
    if data.starts_with(b"\x7fELF") {
        import_elf(data)
    } else if data.starts_with(b"MZ") {
        import_pe(data)
    } else {
        dol::import(data)
    }
}

/// Loads `<binary>` mappings without running discovery or sweep passes.
pub fn load_native_mappings(binary: &Path) -> Result<Vec<Mapping>> {
    let data = std::fs::read(binary)
        .map_err(|e| ImportError::Bad(format!("{}: {e}", binary.display())))?;
    let imp = parse_native(&data)?;
    Ok(imp.mappings)
}

/// Loads `<binary>` natively and closes its seeds through SLEIGH flow.
pub fn load_native(binary: &Path) -> Result<NativeImport> {
    let data = std::fs::read(binary)
        .map_err(|e| ImportError::Bad(format!("{}: {e}", binary.display())))?;
    let mut imp = parse_native(&data)?;
    imp.binary = binary.canonicalize().unwrap_or_else(|_| binary.to_path_buf());
    imp.cfg = crate::session::RuntimeConfig::from_env();
    imp.cfg.language_id = imp.language.clone();
    if imp.format == "dol" {
        discovery::discover_mapped(&mut imp)?;
    } else {
        elf_pointers::confirm_initializers(&mut imp);
        discovery::discover_seeded(&mut imp);
    }
    Ok(imp)
}


/// Adds FUN_<hex> functions for every xref target inside a code mapping
/// (the direct-call closure; mirrors Ghidra's FUN_ naming).
pub fn close_call_targets(imp: &mut NativeImport) {
    for x in &imp.xrefs {
        if !x.kind.contains("CALL") {
            continue;
        }
        let in_code = imp
            .mappings
            .iter()
            .any(|m| m.flags & 0x4 != 0 && x.to >= m.vaddr && x.to < m.vaddr + m.size);
        if !in_code || imp.functions.iter().any(|f| f.entry == x.to) {
            continue;
        }
        imp.functions.push(NativeFunction {
            entry: x.to,
            name: format!("FUN_{:08x}", x.to),
            size: 1,
        });
    }
    imp.functions.sort_by_key(|f| f.entry);
    imp.functions.dedup_by_key(|f| f.entry);
}

/// Writes a native import into the store, returning the summary.
pub fn store_import(
    db: &ProjectDb,
    program: &str,
    imp: &NativeImport,
) -> Result<ProgramSummary> {
    let mut functions = imp.functions.clone();
    functions.sort_by_key(|f| f.entry);
    // Fill sizes from the next function's entry when unknown.
    for i in 0..functions.len() {
        if functions[i].size <= 1 {
            let end = functions
                .get(i + 1)
                .map(|n| n.entry)
                .unwrap_or(functions[i].entry + 16);
            functions[i].size = end.saturating_sub(functions[i].entry).max(1);
        }
    }
    let pid = db.upsert_program(program, &imp.language, &native_provenance())?;
    let regions = imp
        .mappings
        .iter()
        .enumerate()
        .map(|(index, mapping)| MemoryRegion {
            name: format!("{}:{index}", imp.format.to_ascii_lowercase()),
            start: lre_model::Address::ram(mapping.vaddr),
            size: mapping.size,
            permissions: mapping_permissions(mapping.flags, &imp.format),
            source: "native-import".into(),
        })
        .collect::<Vec<_>>();
    db.replace_memory_regions(pid, &regions)?;
    db.replace_strings(pid, &discover_strings(imp))?;
    let rows: Vec<FunctionRow> = functions
        .iter()
        .map(|f| FunctionRow {
            entry: lre_model::Address::ram(f.entry),
            name: f.name.clone(),
            size: f.size.max(1),
            signature: None,
            calling_convention: None,
        })
        .collect();
    db.replace_functions(pid, &rows)?;
    let xrows: Vec<XrefRow> = imp
        .xrefs
        .iter()
        .map(|x| XrefRow {
            from: lre_model::Address::ram(x.from),
            to: lre_model::Address::ram(x.to),
            kind: x.kind.clone(),
            // Containment resolves at query time from the function table.
            function: None,
            provenance: if x.provenance.is_empty() {
                "native-import".into()
            } else {
                x.provenance.clone()
            },
        })
        .collect();
    db.replace_xrefs(pid, &xrows)?;
    Ok(ProgramSummary {
        program: program.to_string(),
        functions: functions.len() as u64,
        language: imp.language.clone(),
    })
}

fn mapping_permissions(flags: u64, format: &str) -> String {
    let (read, write, execute) = if format.eq_ignore_ascii_case("ELF") {
        (flags & 0x2 != 0, flags & 0x1 != 0, flags & 0x4 != 0)
    } else {
        (
            flags & 0x40000000 != 0,
            flags & 0x80000000 != 0,
            flags & 0x20000000 != 0,
        )
    };
    format!(
        "{}{}{}",
        if read { "r" } else { "-" },
        if write { "w" } else { "-" },
        if execute { "x" } else { "-" }
    )
}

fn discover_strings(imp: &NativeImport) -> Vec<StringRow> {
    let mut rows = Vec::new();
    for mapping in &imp.mappings {
        let mut start = None;
        for index in 0..=mapping.bytes.len() {
            let printable = mapping
                .bytes
                .get(index)
                .is_some_and(|byte| (0x20..=0x7e).contains(byte));
            if printable && start.is_none() {
                start = Some(index);
            }
            if (!printable || index == mapping.bytes.len()) && start.is_some() {
                let begin = start.take().unwrap_or(index);
                if index.saturating_sub(begin) >= 4 {
                    let value = String::from_utf8_lossy(&mapping.bytes[begin..index]).into_owned();
                    rows.push(StringRow {
                        address: lre_model::Address::ram(mapping.vaddr + begin as u64),
                        value,
                        kind: "ASCII".into(),
                    });
                }
            }
        }
    }
    rows
}

/// Context for candidate pre-pass confirmation.
pub struct CandidateFilterContext<'a> {
    pub mappings: &'a [Mapping],
    pub known_extents: &'a [(u64, u64)],
    pub initial_seeds: &'a HashSet<u64>,
}

/// Evaluates whether an unseeded candidate represents a genuine function entry point.
pub fn filter_candidate<F: FnMut(u64) -> crate::native_runtime::FlowResult>(
    cand: u64,
    ctx: &CandidateFilterContext,
    mut flow_fn: F,
) -> bool {
    use crate::native_runtime::FlowKind;

    // 1. Must fall inside executable memory
    let in_code = ctx
        .mappings
        .iter()
        .any(|m| m.flags & 0x4 != 0 && cand >= m.vaddr && cand < m.vaddr + m.size);
    if !in_code {
        return false;
    }

    // 2. Reject if strictly inside the body of an already known function:
    // [f.entry + 1, f.entry + f.size)
    let inside_known = ctx.known_extents.iter().any(|&(entry, size)| {
        size > 1 && cand > entry && cand < entry + size
    });
    if inside_known {
        return false;
    }

    // 3. Flow validity
    let info = flow_fn(cand);
    if info.kind == FlowKind::Bad || info.kind == FlowKind::Unimpl || info.length == 0 {
        return false;
    }

    // Straight-line flow into an established entry does not establish a body.
    // Calls can be distinct one-instruction functions even with adjacent entries.
    info.kind != FlowKind::Fallthrough
        || !info.fallthrough.is_some_and(|fall| ctx.initial_seeds.contains(&fall))
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::discovery::flow_discover_with_provider;
    #[test]
    fn elf_data_pointer_waits_for_flow_and_walks_indirect_call_fallthrough() {
        use crate::native_runtime::{FlowKind, FlowResult};
        let mut bytes = vec![0; 0x300];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        for (offset, value) in [(16, 2_u16), (18, 0x3e), (58, 64), (60, 4), (62, 3)] {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(24, 0x1000_u64), (40, 0x200),
                                (0x248, 6), (0x250, 0x1000), (0x258, 0x100), (0x260, 0x80),
                                (0x288, 3), (0x290, 0x2000), (0x298, 0x180), (0x2a0, 16),
                                (0x2d8, 0x1a0), (0x2e0, 13),
                                (0x180, 0x1020), (0x188, 0x1030)] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(0x240, 1_u32), (0x244, 1), (0x280, 7), (0x284, 1), (0x2c4, 3)] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[0x100..0x180].fill(1);
        bytes[0x1a0..0x1ad].copy_from_slice(b"\0.text\0.data\0");
        let mut imp = import_elf(&bytes).unwrap();
        assert!(!imp.functions.iter().any(|f| f.entry == 0x1020));
        flow_discover_with_provider(&mut imp, |_| Vec::new());
        assert!(!imp.functions.iter().any(|f| f.entry == 0x1020));
        flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&address| {
            let (kind, fallthrough, targets) = match address {
                0x1020 => (FlowKind::CallInd, Some(0x1024), vec![]),
                0x1024 => (FlowKind::Call, Some(0x1028), vec![0x1040]),
                0x1030 => (FlowKind::Bad, None, vec![]),
                _ => (FlowKind::Return, None, vec![]),
            };
            FlowResult { pure_jump: false, address, length: 4, fallthrough, targets, kind }
        }).collect());
        assert!(imp.functions.iter().any(|f| f.entry == 0x1020));
        assert!(imp.functions.iter().any(|f| f.entry == 0x1040),
                "pointer-rooted traversal must continue after an indirect call");
        assert!(!imp.functions.iter().any(|f| f.entry == 0x1030));
        assert!(imp.xrefs.iter().any(|x| x.from == 0x2000 && x.to == 0x1020
                && x.kind == "DATA" && x.provenance == "native-import:elf-pointer"));
    }

    #[test]
    fn distant_branch_does_not_claim_unvisited_gap() {
        use crate::native_runtime::{FlowKind, FlowResult};
        let mut imp = NativeImport {
            mappings: vec![Mapping {
                vaddr: 0x1000, size: 0x2010, file_off: 0, flags: 6,
                bytes: vec![0x90; 0x2010],
            }],
            functions: vec![NativeFunction { entry: 0x1000, name: "entry".into(), size: 1 }],
            reloc_candidates: vec![0x2000, 0x3001],
            ..Default::default()
        };
        flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&address| {
            FlowResult { pure_jump: false, address, length: 4, fallthrough: None,
            targets: if address == 0x1000 { vec![0x3000] } else { vec![] },
            kind: if address == 0x1000 { FlowKind::Branch } else { FlowKind::Return }, }
        }).collect());
        assert!(imp.functions.iter().any(|f| f.entry == 0x2000),
                "a distant branch must not suppress a function in the unvisited gap");
        assert!(!imp.functions.iter().any(|f| f.entry == 0x3001),
                "an instruction-interior pointer must still be rejected");
    }



    #[test]
    fn architecture_selection_rejects_unsupported_machines() {
        assert_eq!(elf_language(0x0b7, false, 0).unwrap(), "AARCH64:LE:64:v8A");
        assert_eq!(elf_language(0x0f3, false, 0).unwrap(), "RISCV:LE:64:default");
        assert!(elf_language(0xffff, false, 0).is_err());
    }

    #[test]
    fn elf_load_populates_functions() {
        // Build a tiny synthetic ELF64 with one symtab entry.
        let mut b = vec![0u8; 0x1000];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        // e_entry
        b[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        // ehdr: e_shoff (0x200), e_shentsize (64), e_shnum (4),
        // e_shstrndx (3)
        b[40..48].copy_from_slice(&0x200u64.to_le_bytes());
        b[58..60].copy_from_slice(&64u16.to_le_bytes());
        b[60..62].copy_from_slice(&4u16.to_le_bytes());
        b[62..64].copy_from_slice(&3u16.to_le_bytes());
        // section 0 null; section 1 .text; section 2 .symtab; section 3 .strtab
        for (o, typ, flags, addr, off, size, link) in [
            (0x200usize, 0u32, 0u64, 0u64, 0u64, 0u64, 0u32),
            (0x240, 1, 0x2, 0x401000, 0x300, 0x10, 0), // .text
            (0x280, 2, 0, 0, 0x400, 24, 3), // .symtab -> .strtab
            (0x2c0, 3, 0, 0, 0x380, 8, 0), // .strtab
        ] {
            b[o..o + 4].copy_from_slice(&0u32.to_le_bytes());
            b[o + 4..o + 8].copy_from_slice(&typ.to_le_bytes());
            b[o + 8..o + 16].copy_from_slice(&flags.to_le_bytes());
            b[o + 16..o + 24].copy_from_slice(&addr.to_le_bytes());
            b[o + 24..o + 32].copy_from_slice(&off.to_le_bytes());
            b[o + 32..o + 40].copy_from_slice(&size.to_le_bytes());
            b[o + 40..o + 44].copy_from_slice(&link.to_le_bytes());
        }
        b[0x380] = 0;
        b[0x381..0x381 + 4].copy_from_slice(b"add\0");
        // symtab entry: st_name=1, info=0x12 (STT_FUNC|STB_GLOBAL),
        // st_size=4, st_value=0x401000
        b[0x400..0x404].copy_from_slice(&1u32.to_le_bytes());
        b[0x404] = 0x12;
        b[0x408..0x410].copy_from_slice(&0x401000u64.to_le_bytes());
        b[0x410..0x418].copy_from_slice(&4u64.to_le_bytes());
        // shstrtab for names: .text\0.symtab\0.strtab\0
        {
            let shstr = b".text\0.symtab\0.strtab\0";
            b[0x800..0x800 + shstr.len()].copy_from_slice(shstr);
        }
        // set section name offsets
        for (o, off) in [(0x240usize, 1usize), (0x280, 7), (0x2c0, 14)] {
            b[o..o + 4].copy_from_slice(&(off as u32).to_le_bytes());
        }
        let imp = import_elf(&b).unwrap();
        let f = imp.functions.iter().find(|f| f.name == "add").unwrap();
        assert_eq!(f.entry, 0x401000);
        assert_eq!(f.size, 4);
        assert_eq!(imp.mappings[0].vaddr, 0x401000);
        assert_eq!(imp.language, "x86:LE:64:default");
    }

    #[test]
    fn pe_exec_requires_execute_characteristic() {
        // Section flags: READ (0x40000000) alone must NOT be executable.
        let mut b = vec![0u8; 0x200];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        b[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes()); // opt size
        b[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+ magic
        b[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes()); // ImageBase at opt + 24
        let sec = 0x80 + 24 + 0xf0;
        b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // vsize
        b[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        b[sec + 20..sec + 24].copy_from_slice(&0x100u32.to_le_bytes()); // raw ptr
        b[sec + 36..sec + 40].copy_from_slice(&0x40000000u32.to_le_bytes()); // READ only
        let imp = import_pe(&b).unwrap();
        assert_eq!(imp.mappings[0].flags & 0x4, 0, "readable data must not be exec");
        // EXECUTE (0x20000000) must be.
        b[sec + 36..sec + 40].copy_from_slice(&0x60000000u32.to_le_bytes());
        let imp = import_pe(&b).unwrap();
        assert_eq!(imp.mappings[0].flags & 0x4, 0x4, "code section must be exec");
    }

    #[test]
    fn truncated_elf_magic_errors_not_panics() {
        assert!(import_elf(b"\x7fELF").is_err());
        assert!(import_elf(b"\x7fELF\x02\x01").is_err());
        assert!(import_elf(b"\x7fELF\x02\x01\x00\x00").is_err());
    }

    #[test]
    fn malformed_inputs_never_panic() {
        // Deterministic PRNG (xorshift64) fuzz smoke: truncated headers,
        // magic-only files, and arbitrary byte soups must return typed
        // errors (or a parse) — never panic or OOM (review QA-002).
        let mut state: u64 = 0x9e3779b97f4a7c15;
        let mut rand = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for len in 1..=64usize {
            for _ in 0..64 {
                let mut bytes = vec![0u8; len];
                for b in bytes.iter_mut() {
                    *b = (rand() & 0xff) as u8;
                }
                let _ = import_elf(&bytes);
                let _ = import_pe(&bytes);
                if len >= 4 {
                    let _ = crate::disasm::decode(&bytes, 0x400000);
                }
                // magic-only truncated variants
                let _ = import_elf(&b"\x7fELF"[..len.min(4)]);
                let _ = import_pe(&b"MZ"[..len.min(2)]);
            }
        }
        // Structured but corrupted: valid ELF header with bogus section
        // table offsets/counts.
        let mut b = vec![0u8; 0x100];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[40..48].copy_from_slice(&(0x100000000u64).to_le_bytes()); // absurd shoff
        b[58..60].copy_from_slice(&0xffffu16.to_le_bytes()); // shentsize
        b[60..62].copy_from_slice(&0xffffu16.to_le_bytes()); // shnum
        let _ = import_elf(&b);
    }

    #[test]
    fn pe_image_base_reads_header_field() {
        // Minimal MZ + PE signature + optional header carrying ImageBase.
        let mut b = vec![0u8; 0x100];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+ magic
        b[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes());
        assert_eq!(pe_image_base(&b), Some(0x140000000));
        assert_eq!(pe_image_base(b"\x7fELF"), None);
    }
    #[test]
    fn regression_candidates_inside_known_bodies_are_rejected() {
        let mut imp = NativeImport {
            mappings: vec![Mapping {
                vaddr: 0x1000,
                size: 0x100,
                file_off: 0,
                flags: 0x4,
                bytes: vec![0x90; 0x100],
            }],
            functions: vec![NativeFunction {
                entry: 0x1000,
                name: "known_outer".into(),
                size: 0x80, // covers 0x1000..0x1080
            }],
            reloc_candidates: vec![0x1040], // strictly inside known_outer
            format: "ELF".into(),
            language: "x86:LE:64:default".into(),
            ..Default::default()
        };
        flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&address| {
            crate::native_runtime::FlowResult { address, length: 1, fallthrough: None,
                targets: vec![], kind: crate::native_runtime::FlowKind::Return, pure_jump: false }
        }).collect());
        assert!(!imp.functions.iter().any(|f| f.entry == 0x1040));
    }

    #[test]
    fn regression_console_absence_does_not_promote_unconfirmed_candidates() {
        let mut imp = NativeImport {
            mappings: vec![Mapping {
                vaddr: 0x1000,
                size: 0x200,
                file_off: 0,
                flags: 0x4,
                bytes: vec![0x90; 0x200],
            }],
            functions: vec![NativeFunction {
                entry: 0x1000,
                name: "root".into(),
                size: 0x10,
            }],
            reloc_candidates: vec![0x1100],
            cfg: crate::session::RuntimeConfig {
                console_path: Some(std::path::PathBuf::from("/nonexistent/decomp_native")),
                ..Default::default()
            },
            format: "ELF".into(),
            language: "x86:LE:64:default".into(),
            ..Default::default()
        };
        discovery::discover_seeded(&mut imp);
        // Unconfirmed candidate 0x1100 must NOT be promoted when console is absent/failing
        assert_eq!(imp.functions.len(), 1);
        assert_eq!(imp.functions[0].entry, 0x1000);
    }

    #[test]
    fn regression_invalid_relocation_target_is_not_promoted() {
        let mut imp = NativeImport {
            mappings: vec![Mapping {
                vaddr: 0x1000,
                size: 0x100,
                file_off: 0,
                flags: 0x4,
                bytes: vec![0x90; 0x100],
            }],
            functions: vec![NativeFunction {
                entry: 0x1000,
                name: "entry".into(),
                size: 0x10,
            }],
            reloc_candidates: vec![0x99999], // out of bounds / non-code
            format: "ELF".into(),
            language: "x86:LE:64:default".into(),
            ..Default::default()
        };
        flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&address| {
            crate::native_runtime::FlowResult { address, length: 1, fallthrough: None,
                targets: vec![], kind: crate::native_runtime::FlowKind::Return, pure_jump: false }
        }).collect());
        assert!(!imp.functions.iter().any(|f| f.entry == 0x99999));
    }
    #[test]
    fn test_filter_candidate_rejects_internal_even_with_valid_flow() {
        use crate::native_runtime::FlowResult;
        let mappings = vec![Mapping {
            vaddr: 0x1000,
            size: 0x100,
            file_off: 0,
            flags: 0x4,
            bytes: vec![0x90; 0x100],
        }];
        let extents = vec![(0x1000, 0x50)]; // 0x1000..0x1050
        let initial_seeds = HashSet::from([0x1000]);
        let ctx = CandidateFilterContext {
            mappings: &mappings,
            known_extents: &extents,
            initial_seeds: &initial_seeds,
        };

        // Candidate 0x1020 is internal to 0x1000..0x1050.
        // Mock flow returns a valid instruction with length 4.
        let result = filter_candidate(0x1020, &ctx, |addr| FlowResult { pure_jump: false, address: addr,
        length: 4,
        fallthrough: Some(addr + 4),
        targets: Vec::new(),
        kind: crate::native_runtime::FlowKind::Fallthrough, });
        assert!(!result, "candidate inside known function must be rejected even with valid flow");
    }

    #[test]
    fn test_filter_candidate_rejects_out_of_code_even_with_valid_flow() {
        use crate::native_runtime::FlowResult;
        let mappings = vec![
            Mapping {
                vaddr: 0x1000,
                size: 0x100,
                file_off: 0,
                flags: 0x4, // executable
                bytes: vec![0x90; 0x100],
            },
            Mapping {
                vaddr: 0x2000,
                size: 0x100,
                file_off: 0x100,
                flags: 0x2, // non-executable data
                bytes: vec![0x00; 0x100],
            },
        ];
        let extents = vec![(0x1000, 0x20)];
        let initial_seeds = HashSet::from([0x1000]);
        let ctx = CandidateFilterContext {
            mappings: &mappings,
            known_extents: &extents,
            initial_seeds: &initial_seeds,
        };

        // Candidate 0x2050 is in data mapping. Flow returns valid instruction.
        let result = filter_candidate(0x2050, &ctx, |addr| FlowResult { pure_jump: false, address: addr,
        length: 4,
        fallthrough: Some(addr + 4),
        targets: Vec::new(),
        kind: crate::native_runtime::FlowKind::Fallthrough, });
        assert!(!result, "candidate outside executable mapping must be rejected even with valid flow");
    }

    #[test]
    fn test_pe_data_to_data_relocation_recorded_in_xrefs() {
        // Build mock PE with .text (code) and .data (data) sections.
        // Relocation in .data points to .data (data-to-data).
        let mut b = vec![0u8; 0x400];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        b[0x86..0x88].copy_from_slice(&3u16.to_le_bytes()); // 3 sections (.text, .data, .reloc)
        b[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes()); // opt size
        b[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
        b[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes()); // ImageBase at opt + 24
        // NumberOfRvaAndSizes at opt + 108: 16 directories
        b[0x98 + 108..0x98 + 112].copy_from_slice(&16u32.to_le_bytes());
        // Directory 5 (.reloc) at opt + 152:
        b[0x98 + 152..0x98 + 156].copy_from_slice(&0x3000u32.to_le_bytes()); // RVA
        b[0x98 + 156..0x98 + 160].copy_from_slice(&16u32.to_le_bytes()); // Size 16
        let sec = 0x80 + 24 + 0xf0;
        // Sec 0: .text (RVA 0x1000, size 0x1000, raw 0x100, raw_sz 0x100, flags 0x60000020 code)
        b[sec..sec + 5].copy_from_slice(b".text");
        b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes());
        b[sec + 20..sec + 24].copy_from_slice(&0x100u32.to_le_bytes());
        b[sec + 36..sec + 40].copy_from_slice(&0x60000020u32.to_le_bytes());

        // Sec 1: .data (RVA 0x2000, size 0x1000, raw 0x200, raw_sz 0x100, flags 0xc0000040 data)
        let sec1 = sec + 40;
        b[sec1..sec1 + 5].copy_from_slice(b".data");
        b[sec1 + 8..sec1 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec1 + 12..sec1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        b[sec1 + 16..sec1 + 20].copy_from_slice(&0x100u32.to_le_bytes());
        b[sec1 + 20..sec1 + 24].copy_from_slice(&0x200u32.to_le_bytes());
        b[sec1 + 36..sec1 + 40].copy_from_slice(&0xc0000040u32.to_le_bytes());
        // Put a pointer at raw 0x200 (RVA 0x2000) pointing to .data at 0x140002080 (data-to-data)
        b[0x200..0x208].copy_from_slice(&0x140002080u64.to_le_bytes());

        // Sec 2: .reloc (RVA 0x3000, size 0x1000, raw 0x300, raw_sz 0x100, flags 0x42000040)
        let sec2 = sec + 80;
        b[sec2..sec2 + 6].copy_from_slice(b".reloc");
        b[sec2 + 8..sec2 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec2 + 12..sec2 + 16].copy_from_slice(&0x3000u32.to_le_bytes());
        b[sec2 + 16..sec2 + 20].copy_from_slice(&16u32.to_le_bytes());
        b[sec2 + 20..sec2 + 24].copy_from_slice(&0x300u32.to_le_bytes());
        b[sec2 + 36..sec2 + 40].copy_from_slice(&0x42000040u32.to_le_bytes());
        // Relocation block at 0x300:
        b[0x300..0x304].copy_from_slice(&0x2000u32.to_le_bytes()); // page RVA 0x2000
        b[0x304..0x308].copy_from_slice(&12u32.to_le_bytes()); // block size 12 (8 header + 2*2 entries)
        let entry0: u16 = (10 << 12) | 0; // DIR64 at off 0
        b[0x308..0x30a].copy_from_slice(&entry0.to_le_bytes());
        b[0x30a..0x30c].copy_from_slice(&0u16.to_le_bytes()); // padding

        let imp = import_pe(&b).unwrap();
        // 1. Data-to-data relocation must be emitted as DATA xref with pe-reloc provenance
        let xref = imp.xrefs.iter().find(|x| x.from == 0x140002000 && x.to == 0x140002080);
        assert!(xref.is_some(), "data-to-data relocation must be present in xrefs");
        assert_eq!(xref.unwrap().kind, "DATA");
        assert_eq!(xref.unwrap().provenance, "native-import:pe-reloc");

        // 2. Data-to-data relocation must NOT be promoted as a function candidate
        assert!(!imp.reloc_candidates.contains(&0x140002080), "data-to-data relocation must not be a function candidate");
    }

    #[test]
    fn test_pe32_fixture_import_and_discovery() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let path = manifest_dir.join("../../tests/fixtures-src/tiny_pe32.exe");
        assert!(path.is_file(), "committed fixture must exist at {}", path.display());
        let imp = load_native(&path).expect("tiny_pe32 must load cleanly");
        assert_eq!(imp.format, "PE");
        assert_eq!(imp.language, "x86:LE:32:default");
        assert_eq!(pe_image_base(&std::fs::read(&path).unwrap()), Some(0x400000));
        assert!(imp.functions.iter().any(|f| f.entry == 0x401400));
        assert!(imp.xrefs.iter().any(|x| x.provenance == "native-import:pe-reloc"));
        if crate::native_runtime::find_console(&imp.cfg).is_ok() {
            assert!(imp.functions.len() >= 10, "console discovery should find >= 10 functions, got {}", imp.functions.len());
        } else {
            assert!(!imp.functions.is_empty(), "entry function must be present");
        }
    }

    #[test]
    fn test_relocation_only_code_function_is_promoted() {
        use crate::native_runtime::{FlowKind, FlowResult};
        // Setup:
        // func_root at 0x1000 has normal instruction-sized flow:
        // 0x1000: push rbp (len 1, fall 0x1001)
        // 0x1001: mov rbp, rsp (len 3, fall 0x1004)
        // 0x1004: ret (len 1, Return) -> proven extent 0x1000..0x1005 (size 5).
        //
        // Relocation candidate 0x1040 is in the gap outside func_root's extent:
        // 0x1040: push rbp (len 1, fall 0x1041)
        // 0x1041: mov rbp, rsp (len 3, fall 0x1044) -> reaches 0x1044 via Fallthrough!
        // 0x1044: call 0x1080 (len 5, Call target 0x1080, fall 0x1049)
        // 0x1049: ret (len 1, Return)
        //
        // Candidate 0x1044 is reached through fallthrough from 0x1040 (internal target!).
        // Candidate 0x1080 is reached through Call (call target!).
        //
        // Assert:
        // 1. Relocation-only code function at 0x1040 IS PROMOTED to imp.functions.
        // 2. Call target 0x1080 REMAINS a separate function in imp.functions.
        // 3. Internal candidate 0x1044 reached through fallthrough is merged/dropped!
        let mut imp = NativeImport {
            mappings: vec![Mapping {
                vaddr: 0x1000,
                size: 0x200,
                file_off: 0,
                flags: 0x4, // executable
                bytes: vec![0x90; 0x200],
            }],
            functions: vec![NativeFunction {
                entry: 0x1000,
                name: "func_root".into(),
                size: 5, // 0x1000..0x1005
            }],
            reloc_candidates: vec![0x1040, 0x1044, 0x1080],
            format: "ELF".into(),
            language: "x86:LE:64:default".into(),
            ..Default::default()
        };

        flow_discover_with_provider(&mut imp, |chunk| {
            chunk.iter().map(|&addr| {
                match addr {
                    0x1000 => FlowResult { pure_jump: false, address: 0x1000,
                    length: 1,
                    fallthrough: Some(0x1001),
                    targets: Vec::new(),
                    kind: FlowKind::Fallthrough, },
                    0x1001 => FlowResult { pure_jump: false, address: 0x1001,
                    length: 3,
                    fallthrough: Some(0x1004),
                    targets: Vec::new(),
                    kind: FlowKind::Fallthrough, },
                    0x1004 => FlowResult { pure_jump: false, address: 0x1004,
                    length: 1,
                    fallthrough: None,
                    targets: Vec::new(),
                    kind: FlowKind::Return, },
                    0x1040 => FlowResult { pure_jump: false, address: 0x1040,
                    length: 1,
                    fallthrough: Some(0x1041),
                    targets: Vec::new(),
                    kind: FlowKind::Fallthrough, },
                    0x1041 => FlowResult { pure_jump: false, address: 0x1041,
                    length: 3,
                    fallthrough: Some(0x1044),
                    targets: Vec::new(),
                    kind: FlowKind::Fallthrough, },
                    0x1044 => FlowResult { pure_jump: false, address: 0x1044,
                    length: 5,
                    fallthrough: Some(0x1049),
                    targets: vec![0x1080],
                    kind: FlowKind::Call, },
                    0x1049 => FlowResult { pure_jump: false, address: 0x1049,
                    length: 1,
                    fallthrough: None,
                    targets: Vec::new(),
                    kind: FlowKind::Return, },
                    0x1080 => FlowResult { pure_jump: false, address: 0x1080,
                    length: 1,
                    fallthrough: None,
                    targets: Vec::new(),
                    kind: FlowKind::Return, },
                    other => FlowResult { pure_jump: false, address: other,
                    length: 1,
                    fallthrough: None,
                    targets: Vec::new(),
                    kind: FlowKind::Return, },
                }
            }).collect()
        });

        // 1. Relocation-only code function at 0x1040 outside func_root's extent IS PROMOTED
        assert!(imp.functions.iter().any(|f| f.entry == 0x1040), "0x1040 must be promoted to a function");

        // 2. Call target 0x1080 remains a separate function
        assert!(imp.functions.iter().any(|f| f.entry == 0x1080), "call target 0x1080 must remain a separate function");

        // 3. Internal candidate 0x1044 reached through fallthrough from 0x1040 is merged/dropped
        assert!(!imp.functions.iter().any(|f| f.entry == 0x1044), "internal candidate 0x1044 reached via fallthrough must be merged/dropped");

        // 4. Function size of 0x1040 covers the full span 0x1040..0x104a (size 0xa)
        let f_1040 = imp.functions.iter().find(|f| f.entry == 0x1040).expect("0x1040 must be present");
        assert_eq!(f_1040.size, 0xa, "0x1040 function size must be 0xa (0x1040..0x104a)");
    }
    #[test]
    fn regression_load_native_pe32_data_to_data_relocation_never_becomes_function() {
        let mut b = vec![0u8; 0x600];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // i386
        b[0x86..0x88].copy_from_slice(&3u16.to_le_bytes()); // 3 sections
        b[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // opt size 224
        let opt = 0x98;
        b[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes()); // PE32 magic
        b[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
        b[opt + 28..opt + 32].copy_from_slice(&0x400000u32.to_le_bytes()); // image base
        // NumberOfRvaAndSizes at opt + 92: 16 directories
        b[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes());
        // Relocation directory at opt + 136: RVA 0x3000, size 16
        b[opt + 136..opt + 140].copy_from_slice(&0x3000u32.to_le_bytes());
        b[opt + 140..opt + 144].copy_from_slice(&16u32.to_le_bytes());

        let sec = opt + 0xe0; // 0x178
        // Sec 0: .text (RVA 0x1000, size 0x1000, raw 0x200, raw_sz 0x100, exec)
        b[sec..sec + 5].copy_from_slice(b".text");
        b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes());
        b[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
        b[sec + 36..sec + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
        b[0x200] = 0xc3; // ret at 0x401000

        // Sec 1: .data (RVA 0x2000, size 0x1000, raw 0x300, raw_sz 0x100, data)
        let sec1 = sec + 40;
        b[sec1..sec1 + 5].copy_from_slice(b".data");
        b[sec1 + 8..sec1 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec1 + 12..sec1 + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        b[sec1 + 16..sec1 + 20].copy_from_slice(&0x100u32.to_le_bytes());
        b[sec1 + 20..sec1 + 24].copy_from_slice(&0x300u32.to_le_bytes());
        b[sec1 + 36..sec1 + 40].copy_from_slice(&0xc0000040u32.to_le_bytes());
        // Put a 32-bit pointer at raw 0x300 (0x402000) pointing to 0x402080 (in .data)
        b[0x300..0x304].copy_from_slice(&0x402080u32.to_le_bytes());

        // Sec 2: .reloc (RVA 0x3000, size 0x1000, raw 0x400, raw_sz 0x100, reloc)
        let sec2 = sec + 80;
        b[sec2..sec2 + 6].copy_from_slice(b".reloc");
        b[sec2 + 8..sec2 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        b[sec2 + 12..sec2 + 16].copy_from_slice(&0x3000u32.to_le_bytes());
        b[sec2 + 16..sec2 + 20].copy_from_slice(&16u32.to_le_bytes());
        b[sec2 + 20..sec2 + 24].copy_from_slice(&0x400u32.to_le_bytes());
        b[sec2 + 36..sec2 + 40].copy_from_slice(&0x42000040u32.to_le_bytes());
        // Relocation block at 0x400: page RVA 0x2000, block size 12
        b[0x400..0x404].copy_from_slice(&0x2000u32.to_le_bytes());
        b[0x404..0x408].copy_from_slice(&12u32.to_le_bytes());
        let entry0: u16 = (3 << 12) | 0; // HIGHLOW at offset 0
        b[0x408..0x40a].copy_from_slice(&entry0.to_le_bytes());

        let tmp_dir = std::env::temp_dir();
        let tmp_path = tmp_dir.join("test_pe32_data_reloc_regression.exe");
        std::fs::write(&tmp_path, &b).expect("write temp pe32");

        let imp = load_native(&tmp_path).expect("load_native must succeed on valid PE32");
        let _ = std::fs::remove_file(&tmp_path);

        assert_eq!(imp.format, "PE");
        assert_eq!(imp.language, "x86:LE:32:default");
        assert!(imp.functions.iter().any(|f| f.entry == 0x401000));

        // Proves data-to-data relocation remains an xref with pe-reloc provenance
        let xref = imp.xrefs.iter().find(|x| x.from == 0x402000 && x.to == 0x402080);
        assert!(xref.is_some(), "data-to-data relocation must be recorded in xrefs");
        assert_eq!(xref.unwrap().kind, "DATA");
        assert_eq!(xref.unwrap().provenance, "native-import:pe-reloc");

        // Proves data-to-data relocation target and source NEVER become functions
        assert!(
            !imp.functions.iter().any(|f| f.entry == 0x402080),
            "data-to-data relocation target must never become a function"
        );
        assert!(
            !imp.functions.iter().any(|f| f.entry == 0x402000),
            "data relocation source must never become a function"
        );
    }

    #[test]
    fn regression_pe_truncated_optional_header_returns_error() {
        let mut b = vec![0u8; 0x100];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        b[0x94..0x96].copy_from_slice(&0x200u16.to_le_bytes()); // opt_size claims 0x200 (past 0x100 len)
        let res = import_pe(&b);
        assert!(res.is_err(), "truncated optional header must return Err");

        // Also test opt_size too small for PE32+ (e.g. 50 < 160)
        let mut b2 = vec![0u8; 0x200];
        b2[0..2].copy_from_slice(b"MZ");
        b2[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b2[0x80..0x84].copy_from_slice(b"PE\0\0");
        b2[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b2[0x94..0x96].copy_from_slice(&50u16.to_le_bytes()); // opt_size 50
        b2[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes()); // magic 0x20b
        let res2 = import_pe(&b2);
        assert!(res2.is_err(), "undersized PE32+ optional header must return Err");

        // Also test opt_size too small for PE32 (e.g. 40 < 96)
        let mut b3 = vec![0u8; 0x200];
        b3[0..2].copy_from_slice(b"MZ");
        b3[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b3[0x80..0x84].copy_from_slice(b"PE\0\0");
        b3[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // i386
        b3[0x94..0x96].copy_from_slice(&40u16.to_le_bytes()); // opt_size 40 < 96
        b3[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes()); // magic 0x10b
        let res3 = import_pe(&b3);
        assert!(res3.is_err(), "undersized PE32 optional header must return Err");
    }
    #[test]
    fn regression_pe_truncated_section_table_returns_error() {
        let mut b = vec![0u8; 0x200];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes()); // i386
        b[0x86..0x88].copy_from_slice(&50u16.to_le_bytes()); // 50 sections * 40 = 2000 bytes (past 0x200 len)
        b[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes()); // opt_size 224
        let opt = 0x98;
        b[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes());
        let res = import_pe(&b);
        assert!(res.is_err(), "truncated section table must return Err");
    }
    #[test]
    fn negative_test_reloc_section_ignored_when_directory_5_absent() {
        let mut b = vec![0u8; 0x600];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let pe_off = 0x80;
        b[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        b[pe_off + 4..pe_off + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        b[pe_off + 6..pe_off + 8].copy_from_slice(&2u16.to_le_bytes()); // 2 sections (.text, .reloc)
        b[pe_off + 20..pe_off + 22].copy_from_slice(&0xf0u16.to_le_bytes()); // opt size 240
        let opt = pe_off + 24; // 0x98
        b[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
        b[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
        // Explicit ImageBase (0x140000000) at opt + 24:
        b[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        // NumberOfRvaAndSizes at opt + 108 = 0 (Directory 5 ABSENT!)
        b[opt + 108..opt + 112].copy_from_slice(&0u32.to_le_bytes());

        let sec = opt + 0xf0; // 0x98 + 0xf0 = 0x188
        // Section table: 2 sections * 40 bytes = 80 bytes (0x188..0x1d8)
        // Sec 0: .text
        b[sec..sec + 5].copy_from_slice(b".text");
        b[sec + 8..sec + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        b[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        b[sec + 16..sec + 20].copy_from_slice(&0x100u32.to_le_bytes()); // SizeOfRawData
        b[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData (after section table ends at 0x1d8)
        b[sec + 36..sec + 40].copy_from_slice(&0x60000020u32.to_le_bytes()); // CODE | EXECUTE | READ

        // Sec 1: .reloc with valid relocation block bytes, but Directory 5 is ABSENT
        let sec1 = sec + 40; // 0x1b0
        b[sec1..sec1 + 6].copy_from_slice(b".reloc");
        b[sec1 + 8..sec1 + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        b[sec1 + 12..sec1 + 16].copy_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress
        b[sec1 + 16..sec1 + 20].copy_from_slice(&0x100u32.to_le_bytes()); // SizeOfRawData
        b[sec1 + 20..sec1 + 24].copy_from_slice(&0x300u32.to_le_bytes()); // PointerToRawData (after .text raw data)
        b[sec1 + 36..sec1 + 40].copy_from_slice(&0x42000040u32.to_le_bytes()); // INITIALIZED_DATA | DISCARDABLE | READ

        // Put mapped executable pointer at relocation location in .text raw data (raw 0x200, RVA 0x1000):
        // Relocated pointer 0x140001050 lands inside executable mapping (ImageBase 0x140000000 + RVA 0x1000..0x2000)
        b[0x200..0x208].copy_from_slice(&0x140001050u64.to_le_bytes());

        // Put valid relocation block in .reloc raw data (raw 0x300):
        b[0x300..0x304].copy_from_slice(&0x1000u32.to_le_bytes()); // Page RVA
        b[0x304..0x308].copy_from_slice(&12u32.to_le_bytes()); // Block Size
        let entry0: u16 = (10 << 12) | 0; // DIR64 at offset 0
        b[0x308..0x30a].copy_from_slice(&entry0.to_le_bytes());

        let imp = import_pe(&b).expect("PE must parse cleanly");
        // Directory 5 is absent, so .reloc section MUST BE IGNORED
        assert!(imp.xrefs.is_empty(), "xrefs must be empty when directory 5 is absent");
        assert!(imp.reloc_candidates.is_empty(), "reloc_candidates must be empty when directory 5 is absent");
    }
}
