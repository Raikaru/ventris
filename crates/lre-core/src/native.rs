//! Native (no-JVM) ELF/PE import: parse headers, derive the memory map,
//! discover functions from symbols and entry-point call walking, and extract
//! direct xrefs. Facts land in the same project.sqlite tables the bridge
//! import fills, with provenance `native-import`.
//!
//! Design notes:
//! - ELF64 import selects a Ghidra language from `e_machine` for the
//!   architectures currently represented in the catalog; PE remains x86-64.
//! - Structural ELF facts (mappings, symbols, entry point) are architecture
//!   independent. The fallback flow walker is x86-64 only; other languages
//!   retain those facts for the selected SLEIGH consumer.
//! - Function discovery for x86-64: symbol-table function symbols + the loaded
//!   entry point, closed over direct `call rel32` targets found while sweeping
//!   the code sections (linear sweep). This matches Ghidra's analyzer output
//!   for small, unreoptimized fixtures (the differential test pins
//!   function-set equality for the not-stripped ELF fixture; PE uses the
//!   entry walk).
use lre_db::ProjectDb;
use std::collections::HashSet;
use std::path::Path;
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
    let language = elf_language(rd16(18)?, be)?;
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
    // init/fini arrays: ELF32 carries 4-byte pointers.
    for s in sections.iter().filter(|s| s.typ == 14 || s.typ == 15) {
        let n = s.size as usize / 4;
        for i in 0..n {
            let off = s.off as usize + i * 4;
            if let Ok(v) = rd32(off) {
                let v = v as u64;
                if v != 0 && !functions.iter().any(|f| f.entry == v) {
                    functions.push(NativeFunction {
                        entry: v,
                        name: format!("FUN_{v:08x}"),
                        size: 1,
                    });
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
    Ok(NativeImport {

        format: "elf32".into(),
        language,
        mappings,
        functions,
        xrefs: Vec::new(),
        externals,
        ..Default::default()
    })
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

fn elf_language(machine: u16, big_endian: bool) -> Result<String> {
    let (le, be) = if big_endian {
        ("BE", "LE")
    } else {
        ("LE", "BE")
    };
    let _ = be;
    match (machine, big_endian) {
        (0x03e, false) => Ok("x86:LE:64:default".into()),
        (0x0b7, false) => Ok("AARCH64:LE:64:v8A".into()),
        (0x028, false) => Ok("ARM:LE:32:v7".into()),
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
    let language = elf_language(u16_at(data, 18)?, false)?;
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
                dynsyms.push(name);
            }
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
    // init/fini array function pointers (frame_dummy, __do_global_dtors_aux
    // and friends): non-PIE executables carry absolute addresses here, so
    // the CRT helpers become seeds exactly like the entry point.
    for s in sections.iter().filter(|s| s.typ == 14 || s.typ == 15) {
        let n = s.size as usize / 8;
        for i in 0..n {
            let off = s.off as usize + i * 8;
            if let Ok(v) = u64_at(data, off) {
                if v != 0 && !functions.iter().any(|f| f.entry == v) {
                    functions.push(NativeFunction {
                        entry: v,
                        name: format!("FUN_{v:08x}"),
                        size: 1,
                    });
                }
            }
        }
    }
    for s in &sections {
        if s.flags & 0x4 != 0 && s.size > 0 {
            if s.name == ".init" && s.addr != 0 && !functions.iter().any(|f| f.entry == s.addr) {
                functions.push(NativeFunction {
                    entry: s.addr,
                    name: "_init".into(),
                    size: s.size.max(1),
                });
            } else if s.name == ".fini" && s.addr != 0 && !functions.iter().any(|f| f.entry == s.addr) {
                functions.push(NativeFunction {
                    entry: s.addr,
                    name: "_fini".into(),
                    size: s.size.max(1),
                });
            }
        }
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
    Ok(NativeImport {
        mappings,
        functions,
        xrefs,
        externals,
        reloc_candidates,
        format: "ELF".into(),
        language,
        ..Default::default()
    })
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
    if machine != 0x8664 {
        return err("PE x86-64 expected");
    }
    let num_sections = u16_at(data, pe_off + 6)? as usize;
    let opt_size = u16_at(data, pe_off + 20)? as usize;
    let opt = pe_off + 24;
    let entry_rva = u32_at(data, opt + 16)? as u64;
    let image_base = u64_at(data, opt + 24)?; // PE32+: ImageBase at +24
    let sec_table = opt + opt_size;
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
    let reloc_dir_rva = u32_at(data, opt + 152).unwrap_or(0) as u64;
    let reloc_dir_size = u32_at(data, opt + 156).unwrap_or(0) as usize;

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
        (0..num_sections).find_map(|i| {
            let o = sec_table + i * 40;
            let name = data.get(o..o + 8)?;
            if name.starts_with(b".reloc") {
                let raw = u32_at(data, o + 20).ok()? as usize;
                let raw_size = u32_at(data, o + 16).ok()? as usize;
                data.get(raw..raw + raw_size)
            } else {
                None
            }
        })
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
                                let in_code = mappings.iter().any(|cm| {
                                    cm.flags & 0x4 != 0 && ptr >= cm.vaddr && ptr < cm.vaddr + cm.size
                                });
                                let code_target = if in_code {
                                    Some(ptr)
                                } else if mappings.iter().any(|cm| {
                                    cm.flags & 0x4 != 0 && image_base + ptr >= cm.vaddr && image_base + ptr < cm.vaddr + cm.size
                                }) {
                                    Some(image_base + ptr)
                                } else {
                                    None
                                };
                                if let Some(target) = code_target {
                                    reloc_candidates.push(target);
                                    xrefs.push(NativeXref::with_provenance(
                                        loc,
                                        target,
                                        "DATA",
                                        "native-import:pe-reloc",
                                    ));
                                }
                            }
                        }
                        3 => { // IMAGE_REL_BASED_HIGHLOW
                            if off + 4 <= m.bytes.len() {
                                let ptr = u32::from_le_bytes(m.bytes[off..off + 4].try_into().unwrap()) as u64;
                                let in_code = mappings.iter().any(|cm| {
                                    cm.flags & 0x4 != 0 && ptr >= cm.vaddr && ptr < cm.vaddr + cm.size
                                });
                                let code_target = if in_code {
                                    Some(ptr)
                                } else if mappings.iter().any(|cm| {
                                    cm.flags & 0x4 != 0 && image_base + ptr >= cm.vaddr && image_base + ptr < cm.vaddr + cm.size
                                }) {
                                    Some(image_base + ptr)
                                } else {
                                    None
                                };
                                if let Some(target) = code_target {
                                    reloc_candidates.push(target);
                                    xrefs.push(NativeXref::with_provenance(
                                        loc,
                                        target,
                                        "DATA",
                                        "native-import:pe-reloc",
                                    ));
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
        language: "x86:LE:64:default".into(),
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

/// Sweeps mappings for direct call rel32 / jcc rel32 targets (x86-64).
pub fn sweep_ppc_calls(imp: &mut NativeImport) {
    let mut xrefs = Vec::new();
    let in_maps = |addr: u64| {
        imp.mappings
            .iter()
            .any(|m| addr >= m.vaddr && addr < m.vaddr + m.size)
    };
    for m in &imp.mappings {
        if m.flags & 0x4 == 0 {
            continue;
        }
        let b = &m.bytes;
        let mut i = 0usize;
        while i + 4 <= b.len() {
            let addr = m.vaddr + i as u64;
            let word = u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
            let op = word >> 26;
            if op == 18 {
                let aa = (word & 2) != 0;
                let lk = (word & 1) != 0;
                let mut li = (word & 0x03fffffc) as i32;
                if li & 0x02000000 != 0 {
                    li |= !0x03fffffc;
                }
                let target = if aa {
                    li as i64 as u64
                } else {
                    addr.wrapping_add(li as i64 as u64)
                };
                if in_maps(target) {
                    xrefs.push(NativeXref::new(
                        addr,
                        target,
                        if lk {
                            "UNCONDITIONAL_CALL"
                        } else {
                            "UNCONDITIONAL_JUMP"
                        },
                    ));
                }
            } else if op == 16 {
                let aa = (word & 2) != 0;
                let lk = (word & 1) != 0;
                let mut bd = (word & 0xfffc) as i32;
                if bd & 0x8000 != 0 {
                    bd |= !0xfffc;
                }
                let target = if aa {
                    bd as i64 as u64
                } else {
                    addr.wrapping_add(bd as i64 as u64)
                };
                if in_maps(target) {
                    xrefs.push(NativeXref::new(
                        addr,
                        target,
                        if lk {
                            "UNCONDITIONAL_CALL"
                        } else {
                            "CONDITIONAL_JUMP"
                        },
                    ));
                }
            }
            i += 4;
        }
    }
    xrefs.sort_by(|a, b| (a.from, a.to, &a.kind).cmp(&(b.from, b.to, &b.kind)));
    xrefs.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.kind == b.kind);
    imp.xrefs.extend(xrefs);
}

/// Sweeps mappings for direct call rel32 / jcc rel32 targets (x86-64).
pub fn sweep_calls(imp: &mut NativeImport) {
    if !imp.language.is_empty() && !imp.language.starts_with("x86:") {
        if imp.language.starts_with("PowerPC:") {
            sweep_ppc_calls(imp);
        }
        return;
    }
    sweep_calls_x86(imp);
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
    let magic = u16_at(data, opt).unwrap_or(0);
    if magic == 0x10b {
        u32_at(data, opt + 28).ok().map(|b| b as u64)
    } else {
        u64_at(data, opt + 24).ok()
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

/// Loads `<binary>` mappings without running discovery or sweep passes.
pub fn load_native_mappings(binary: &Path) -> Result<Vec<Mapping>> {
    let data = std::fs::read(binary)
        .map_err(|e| ImportError::Bad(format!("{}: {e}", binary.display())))?;
    let imp = if data.get(0..4) == Some(b"\x7fELF") {
        import_elf(&data)?
    } else if data.get(0..2) == Some(b"MZ") {
        import_pe(&data)?
    } else {
        return err("unsupported format (ELF/PE expected)");
    };
    Ok(imp.mappings)
}

/// Loads `<binary>` natively: parses the format, sweeps calls.
pub fn load_native(binary: &Path) -> Result<NativeImport> {
    let data = std::fs::read(binary)
        .map_err(|e| ImportError::Bad(format!("{}: {e}", binary.display())))?;
    let mut imp = if data.get(0..4) == Some(b"\x7fELF") {
        import_elf(&data)?
    } else if data.get(0..2) == Some(b"MZ") {
        import_pe(&data)?
    } else {
        return err("unsupported format (ELF/PE expected)");
    };
    imp.binary = binary.to_path_buf();
    imp.cfg = crate::session::RuntimeConfig::from_env();
    sweep_calls(&mut imp);
    flow_discover(&mut imp);
    Ok(imp)
}

/// Flow-based discovery (the main walk for stripped binaries; augments the
/// symtab set: follows every seed, direct calls and conditionals through
/// the mapping, records calls as xrefs, and closes the function set).
pub fn flow_discover(imp: &mut NativeImport) {
    if imp.mappings.is_empty() {
        return;
    }
    if !imp.language.is_empty() && !imp.language.starts_with("x86:") {
        close_call_targets(imp);
        let code = code_ranges(imp);
        let mut funcs = imp.functions.clone();
        funcs.sort_by_key(|f| f.entry);
        funcs.dedup_by_key(|f| f.entry);
        for i in 0..funcs.len() {
            let cur = funcs[i].entry;
            let next = funcs.get(i + 1).map(|f| f.entry);
            let limit = code
                .iter()
                .find(|(start, end)| cur >= *start && cur < *end)
                .map(|(_, end)| *end)
                .unwrap_or(cur + 16);
            let sz = next.unwrap_or(limit).min(limit).saturating_sub(cur);
            funcs[i].size = sz.max(4);
        }
        imp.functions = funcs;
        return;
    }
    flow_discover_x86(imp);
}

/// Adds FUN_<hex> functions for every xref target inside a code mapping
/// (the direct-call closure; mirrors Ghidra's FUN_ naming).
pub fn close_call_targets(imp: &mut NativeImport) {
    for x in &imp.xrefs {
        let in_code = imp
            .mappings
            .iter()
            .any(|m| x.to >= m.vaddr && x.to < m.vaddr + m.size);
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

#[cfg(feature = "x86_decoder")]
fn sweep_calls_x86(imp: &mut NativeImport) {
    let mut xrefs = imp.xrefs.clone();
    let in_maps = |addr: u64| {
        imp.mappings
            .iter()
            .any(|m| addr >= m.vaddr && addr < m.vaddr + m.size)
    };
    for m in &imp.mappings {
        if m.flags & 0x4 == 0 {
            continue;
        }
        let b = &m.bytes;
        let mut i = 0usize;
        while i < b.len() {
            let addr = m.vaddr + i as u64;
            let win = &b[i..];
            let tmp_buf;
            let buf = if win.len() >= 16 {
                win
            } else {
                let mut tmp = [0u8; 16];
                tmp[..win.len()].copy_from_slice(win);
                tmp_buf = tmp;
                &tmp_buf[..]
            };
            let info = crate::disasm::decode(buf, addr);
            if info.len == 0 {
                i += 1;
                continue;
            }
            match info.flow {
                crate::disasm::Flow::Call(t) => {
                    xrefs.push(NativeXref::new(addr, t, "UNCONDITIONAL_CALL"));
                }
                crate::disasm::Flow::Jump(t) => {
                    xrefs.push(NativeXref::new(addr, t, "UNCONDITIONAL_JUMP"));
                }
                crate::disasm::Flow::JumpCond(t) => {
                    xrefs.push(NativeXref::new(addr, t, "CONDITIONAL_JUMP"));
                }
                _ => {}
            }
            if let Some(target) = info.rip_data {
                if in_maps(target) {
                    xrefs.push(NativeXref::new(addr, target, "DATA"));
                }
            }
            let step = (info.len as usize).min(b.len() - i).max(1);
            i += step;
        }
    }
    xrefs.sort_by(|a, b| (a.from, a.to, &a.kind).cmp(&(b.from, b.to, &b.kind)));
    xrefs.dedup_by(|a, b| a.from == b.from && a.to == b.to && a.kind == b.kind);
    imp.xrefs = xrefs;
}

#[cfg(not(feature = "x86_decoder"))]
fn sweep_calls_x86(imp: &mut NativeImport) {
    // Console-driven x86 sweep is not yet tuned; the BFS in flow_discover_x86
    // records the call xrefs that determine the function set. Keeping the
    // sweep stub avoids a second expensive console pass while m1-003-c proves
    // the flow walk reaches the same entries as the hand decoder.
    if imp.xrefs.is_empty() {
        imp.xrefs = Vec::new();
    }
}

#[cfg(feature = "x86_decoder")]
fn flow_discover_x86(imp: &mut NativeImport) {
    let code = code_ranges(imp);
    let in_code = |a: u64| code.iter().any(|(v, e)| a >= *v && a < *e);
    let mut seeds: Vec<u64> = imp
        .functions
        .iter()
        .map(|f| f.entry)
        .filter(|a| *a != 0 && in_code(*a))
        .collect();
    // PLT stubs/externals are seeds only when inside executable mappings.
    for (a, _) in &imp.externals {
        if *a != 0 && in_code(*a) {
            seeds.push(*a);
        }
    }
    // The entry seed is guaranteed by import_elf/pe.
    let maps_owned: Vec<(u64, u64, u64, &[u8])> = imp
        .mappings
        .iter()
        .map(|m| (m.vaddr, m.size, m.file_off, m.bytes.as_slice()))
        .collect();
    let d = crate::disasm::discover(&maps_owned, &seeds);

    // Candidate pre-pass confirmation via batched flow when console is available.
    // Confirms each unseeded candidate: verifies it decodes to a real instruction
    // and is not a nop pad or switch-case body / mid-instruction target.
    let mut confirmed_entries = Vec::new();
    let initial_seeds: HashSet<u64> = seeds.iter().copied().collect();
    let mut unseeded_candidates: Vec<u64> = d
        .entries
        .iter()
        .copied()
        .chain(imp.reloc_candidates.iter().copied())
        .filter(|e| !initial_seeds.contains(e))
        .collect();
    unseeded_candidates.sort_unstable();
    unseeded_candidates.dedup();

    // Reject candidates that fall strictly inside the body of a known function
    unseeded_candidates.retain(|&cand| {
        let inside_known = d.entries.iter().zip(&d.sizes).any(|(&entry, &size)| {
            cand > entry && cand < entry + size
        });
        !inside_known
    });
    if !unseeded_candidates.is_empty() && imp.cfg.console_path.as_ref().map_or(false, |p| p.is_file()) {
        use crate::native_runtime::{ConsoleSession, FlowKind};
        if let Ok(mut session) = ConsoleSession::new(&imp.cfg) {
            let base = imp
                .mappings
                .first()
                .map(|m| m.vaddr.wrapping_sub(m.file_off))
                .unwrap_or(0);
            if session.load(&imp.binary, base).is_ok() {
                unseeded_candidates.sort_unstable();
                unseeded_candidates.dedup();
                let flows = session.try_flow_batch(&unseeded_candidates);
                for (&cand, info) in unseeded_candidates.iter().zip(flows) {
                    if info.kind == FlowKind::Bad || info.kind == FlowKind::Unimpl {
                        continue;
                    }
                    // Reject backward conditional branches (internal loops / switch dispatch)
                    if info.kind == FlowKind::CBranch {
                        if let Some(&target) = info.targets.first() {
                            if target < cand {
                                continue;
                            }
                        }
                    }
                    // Inspect bytes for nop pad (0x00, 0x90) or mid-instruction patterns
                    let is_pad_or_mid = imp.mappings.iter().find_map(|m| {
                        if cand >= m.vaddr && cand < m.vaddr + m.size {
                            let off = (cand - m.vaddr) as usize;
                            let b0 = m.bytes.get(off).copied()?;
                            if b0 == 0x00 || b0 == 0x90 {
                                return Some(true);
                            }
                            if b0 == 0xf7 || b0 == 0x85 {
                                return Some(true);
                            }
                            if off + 3 <= m.bytes.len() {
                                let b = &m.bytes[off..off + 3];
                                if b[0] == 0x48 && (b[1] == 0x89 || b[1] == 0x8b) && (b[2] == 0x8d || b[2] == 0x85) {
                                    return Some(true);
                                }
                            }
                            Some(false)
                        } else {
                            None
                        }
                    }).unwrap_or(false);

                    if !is_pad_or_mid {
                        confirmed_entries.push(cand);
                    }
                }
            } else {
                confirmed_entries = unseeded_candidates;
            }
        } else {
            confirmed_entries = unseeded_candidates;
        }
    } else {
        confirmed_entries = unseeded_candidates;
    }

    let mut merged = imp.functions.clone();
    for e in seeds.iter().copied().chain(confirmed_entries) {
        if !merged.iter().any(|f| f.entry == e) {
            let name = if let Some((_, n)) = imp.externals.iter().find(|(a, n)| *a == e && !n.is_empty()) {
                n.clone()
            } else {
                format!("FUN_{:08x}", e)
            };
            merged.push(NativeFunction {
                entry: e,
                name,
                size: 1,
            });
        }
    }
    merged.sort_by_key(|f| f.entry);
    merged.dedup_by_key(|f| f.entry);
    // Sizes from the walk's proven extent (stop-based, capped at the next
    // entry); fall back to the next-entry distance when the discovery did
    // not record a body for an entry.
    for f in merged.iter_mut() {
        if let Some(pos) = d.entries.iter().position(|e| *e == f.entry) {
            f.size = d.sizes.get(pos).copied().unwrap_or(16).max(1);
        }
    }
    imp.functions = merged;
    // discovered calls become xrefs (dedup on (from,to)).
    let mut xrefs: Vec<NativeXref> = imp.xrefs.clone();
    for (from, to) in &d.calls {
        if !xrefs.iter().any(|x| x.from == *from && x.to == *to) {
            xrefs.push(NativeXref::new(*from, *to, "UNCONDITIONAL_CALL"));
        }
    }
    for (from, to) in &d.data_refs {
        if !xrefs.iter().any(|x| x.from == *from && x.to == *to) {
            xrefs.push(NativeXref::new(*from, *to, "DATA"));
        }
    }
    imp.xrefs = xrefs;
}

#[cfg(not(feature = "x86_decoder"))]
fn flow_discover_x86(imp: &mut NativeImport) {
    use crate::native_runtime::{ConsoleSession, FlowKind};

    let console_missing = imp
        .cfg
        .console_path
        .as_ref()
        .map_or(true, |p| !p.is_file());
    if console_missing {
        return;
    }

    let mut session = match ConsoleSession::new(&imp.cfg) {
        Ok(s) => s,
        Err(_) => return,
    };
    let base = imp
        .mappings
        .first()
        .map(|m| m.vaddr.wrapping_sub(m.file_off))
        .unwrap_or(0);
    if session.load(&imp.binary, base).is_err() {
        return;
    }

    let code = code_ranges(imp);
    let in_code = |a: u64| code.iter().any(|(v, e)| a >= *v && a < *e);
    let known_funcs = imp.functions.clone();
    let valid_relocs: Vec<u64> = imp
        .reloc_candidates
        .iter()
        .copied()
        .filter(|&cand| {
            in_code(cand)
                && !known_funcs
                    .iter()
                    .any(|f| cand > f.entry && cand < f.entry + f.size)
        })
        .collect();
    let mut entries: Vec<u64> = imp
        .functions
        .iter()
        .map(|f| f.entry)
        .chain(imp.externals.iter().map(|(a, _)| *a))
        .chain(valid_relocs)
        .filter(|a| *a != 0 && in_code(*a))
        .collect();
    entries.sort_unstable();
    entries.dedup();


    // Helper to read a little-endian u64 from a mapped address.
    let read_u64_at = |addr: u64| -> Option<u64> {
        imp.mappings.iter().find_map(|m| {
            if addr >= m.vaddr && addr + 8 <= m.vaddr + m.size {
                let off = (addr - m.vaddr) as usize;
                Some(u64::from_le_bytes(m.bytes[off..off + 8].try_into().ok()?))
            } else {
                None
            }
        })
    };
    let mut calls: Vec<(u64, u64)> = Vec::new();
    let mut proven_bodies: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    let mut visited: HashSet<u64> = HashSet::new();
    let mut active: Vec<u64> = entries.clone();

    while !active.is_empty() {
        // Deduplicate and filter unvisited addresses inside executable mappings.
        active.sort_unstable();
        active.dedup();
        let to_query: Vec<u64> = active
            .into_iter()
            .filter(|a| *a != 0 && in_code(*a) && visited.insert(*a))
            .collect();
        if to_query.is_empty() {
            break;
        }

        let mut next_active: Vec<u64> = Vec::new();
        // Query in chunks of 1024 for high IPC throughput.
        for chunk in to_query.chunks(1024) {
            let flows = session.try_flow_batch(chunk);
            for (addr, info) in chunk.iter().copied().zip(flows) {
                match info.kind {
                    FlowKind::Call => {
                        for t in &info.targets {
                            if in_code(*t) && !entries.contains(t) {
                                entries.push(*t);
                                next_active.push(*t);
                            }
                            if *t != 0 {
                                calls.push((addr, *t));
                            }
                        }
                        if let Some(f) = info.fallthrough {
                            next_active.push(f);
                        } else {
                            next_active.push(addr + info.length as u64);
                        }
                    }
                    FlowKind::Branch => {
                        if let Some(t) = info.targets.first() {
                            if in_code(*t) && !visited.contains(t) {
                                next_active.push(*t);
                            }
                        }
                    }
                    FlowKind::CBranch => {
                        if let Some(t) = info.targets.first() {
                            if in_code(*t) && !visited.contains(t) {
                                next_active.push(*t);
                            }
                        }
                        let fall = info.fallthrough.unwrap_or(addr + info.length as u64);
                        if in_code(fall) && !visited.contains(&fall) {
                            next_active.push(fall);
                        }
                    }
                    FlowKind::CallInd => {
                        for m in &imp.mappings {
                            if m.flags & 0x4 == 0 || addr < m.vaddr || addr >= m.vaddr + m.size {
                                continue;
                            }
                            let off = (addr - m.vaddr) as usize;
                            let mut tmp_queue = Vec::new();
                            crate::disasm::maybe_seed_entry(&m.bytes, m.vaddr, off, &mut entries, &mut tmp_queue);
                            for t in tmp_queue {
                                next_active.push(t);
                            }
                            let dec = crate::disasm::decode(&m.bytes[off..], addr);
                            if let Some(ptr) = dec.rip_data {
                                if let Some(target) = read_u64_at(ptr) {
                                    if in_code(target) && !entries.contains(&target) {
                                        entries.push(target);
                                        next_active.push(target);
                                    }
                                    if target != 0 {
                                        calls.push((addr, target));
                                    }
                                }
                            }
                            break;
                        }
                        if let Some(f) = info.fallthrough {
                            next_active.push(f);
                        } else {
                            next_active.push(addr + info.length as u64);
                        }
                    }
                    FlowKind::Fallthrough => {
                        let fall = info.fallthrough.unwrap_or(addr + info.length as u64);
                        if in_code(fall) && !visited.contains(&fall) {
                            next_active.push(fall);
                        }
                    }
                    FlowKind::BranchInd | FlowKind::Return | FlowKind::Bad | FlowKind::Unimpl => {}
                }
            }
        }
        active = next_active;
    }

    entries.sort_unstable();
    entries.dedup();

    let mut merged = imp.functions.clone();
    for e in entries {
        if !merged.iter().any(|f| f.entry == e) {
            let name = extern_name(imp, e).unwrap_or_else(|| format!("FUN_{e:08x}"));
            merged.push(NativeFunction {
                entry: e,
                name,
                size: 1,
            });
        }
    }
    merged.sort_by_key(|f| f.entry);
    merged.dedup_by_key(|f| f.entry);

    for f in merged.iter_mut() {
        if let Some(sz) = proven_bodies.get(&f.entry) {
            f.size = *sz;
        }
    }
    imp.functions = merged;

    let mut xrefs = imp.xrefs.clone();
    for (from, to) in calls {
        if !xrefs.iter().any(|x| x.from == from && x.to == to) {
            xrefs.push(NativeXref::new(from, to, "UNCONDITIONAL_CALL"));
        }
    }
    imp.xrefs = xrefs;

    let _ = session.quit();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "x86_decoder")]
    #[test]
    fn sweep_finds_direct_calls_and_branches() {
        let mut imp = NativeImport {
            mappings: vec![Mapping {
                vaddr: 0x1000,
                size: 16,
                file_off: 0x100,
                flags: 0x4,
                bytes: vec![
                    0xe8, 0x01, 0x00, 0x00, 0x00, // call +1 -> 0x1006
                    0x90, 0x90, 0x90, // nops
                    0x0f, 0x85, 0x02, 0x00, 0x00, 0x00, // jz +2 -> 0x100c
                    0x90, 0x90,
                ],
            }],
            ..Default::default()
        };
        sweep_calls(&mut imp);
        assert_eq!(imp.xrefs.len(), 2);
        assert_eq!(imp.xrefs[0].from, 0x1000);
        assert_eq!(imp.xrefs[0].to, 0x1006);
        assert_eq!(imp.xrefs[1].kind, "CONDITIONAL_JUMP");
    }

    #[test]
    fn architecture_selection_and_flow_guard_are_explicit() {
        assert_eq!(elf_language(0x0b7, false).unwrap(), "AARCH64:LE:64:v8A");
        assert_eq!(elf_language(0x0f3, false).unwrap(), "RISCV:LE:64:default");
        assert!(elf_language(0xffff, false).is_err());

        let mut arm = NativeImport {
            language: "AARCH64:LE:64:v8A".into(),
            mappings: vec![Mapping {
                vaddr: 0x1000,
                size: 5,
                file_off: 0,
                flags: 0x4,
                bytes: vec![0xe8, 0, 0, 0, 0],
            }],
            functions: vec![NativeFunction {
                entry: 0x1000,
                name: "entry".into(),
                size: 0,
            }],
            ..Default::default()
        };
        flow_discover(&mut arm);
        assert!(arm.xrefs.is_empty());
        assert_eq!(arm.functions.len(), 1);
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
        b[0x98..0xa0].copy_from_slice(&0x140000000u64.to_le_bytes()); // ImageBase
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
                    #[cfg(feature = "x86_decoder")]
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
        b[0xb0..0xb8].copy_from_slice(&0x140000000u64.to_le_bytes());
        assert_eq!(pe_image_base(&b), Some(0x140000000));
        assert_eq!(pe_image_base(b"\x7fELF"), None);
    }
}
