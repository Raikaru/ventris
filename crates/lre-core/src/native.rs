//! Native (no-JVM) ELF/PE import: parse headers, derive the memory map,
//! discover functions from symbols and entry-point call walking, and extract
//! direct xrefs. Facts land in the same project.sqlite tables the bridge
//! import fills, with provenance `native-import`.
//!
//! Design notes:
//! - x86-64 only (the pinned SLEIGH language); multi-arch is a later stage.
//! - Function discovery: symbol-table function symbols + the loaded entry
//!   point, closed over direct `call rel32` targets found while sweeping the
//!   code sections (linear sweep). This matches Ghidra's analyzer output for
//!   small, unreoptimized fixtures (the differential test pins function-set
//!   equality for the not-stripped ELF fixture; PE uses the entry walk).

use lre_db::ProjectDb;
use lre_model::{FunctionRow, Provenance, ProgramSummary, XrefRow};
use std::path::Path;

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
}

/// Parsed import result: everything the importer writes to the store.
#[derive(Debug, Default)]
pub struct NativeImport {
    pub mappings: Vec<Mapping>,
    pub functions: Vec<NativeFunction>,
    pub xrefs: Vec<NativeXref>,
    pub externals: Vec<(u64, String)>,
    pub format: String,
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

/// ELF64 parse. Returns (mappings, functions from symtab + entry, externals).
pub fn import_elf(data: &[u8]) -> Result<NativeImport> {
    if data.get(0..4) != Some(b"\x7fELF") {
        return err("not an ELF");
    }
    if data[4] != 2 || data[5] != 1 {
        return err("ELF64 little-endian expected");
    }
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
                    let addr = m.vaddr + i as u64;
                    if !seen_got.iter().any(|(a, _)| *a == addr) {
                        functions.push(NativeFunction {
                            entry: addr,
                            name: rname.clone(),
                            size: 6,
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
        xrefs: Vec::new(),
        externals,
        format: "ELF".into(),
    })
}

/// PE32+ parse: sections + entry point (import table externals kept out of
/// scope; the differential covers the ELF function set).
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
    let entry_rva = u32_at(data, pe_off + 24)?;
    let num_sections = u16_at(data, pe_off + 6)? as usize;
    let opt_size = u16_at(data, pe_off + 20)? as usize;
    let opt = pe_off + 24;
    let image_base = u64_at(data, opt + 24)?; // PE32+: no BaseOfData; ImageBase at +24
    let sec_table = opt + opt_size;
    let mut mappings = Vec::new();
    for i in 0..num_sections {
        let o = sec_table + i * 40;
        let vaddr = u32_at(data, o + 12)? as u64;
        let size = u32_at(data, o + 8)? as usize;
        let raw = u32_at(data, o + 20)? as usize;
        let raw_size = u32_at(data, o + 16)? as usize;
        if size == 0 {
            continue;
        }
        let mut bytes = data.get(raw..raw + raw_size).unwrap_or(&[]).to_vec();
        bytes.resize(size, 0);
        let sflags = u32_at(data, o + 36)? as u64; // section characteristics
        let exec = sflags & 0x60000000 != 0;
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
        entry: image_base + entry_rva as u64,
        name: "_entry".into(),
        size: 1,
    }];
    functions.sort_by_key(|f| f.entry);
    Ok(NativeImport {
        mappings,
        functions,
        xrefs: Vec::new(),
        externals: Vec::new(),
        format: "PE".into(),
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
pub fn sweep_calls(imp: &mut NativeImport) {
    let mut xrefs = Vec::new();
    for m in &imp.mappings {
        let b = &m.bytes;
        let mut i = 0usize;
        while i < b.len() {
            match b[i] {
                0xe8 if i + 5 <= b.len() => {
                    let rel = i32::from_le_bytes([b[i + 1], b[i + 2], b[i + 3], b[i + 4]]);
                    xrefs.push(NativeXref {
                        from: m.vaddr + i as u64,
                        to: (m.vaddr + i as u64).wrapping_add(5).wrapping_add(rel as u64),
                        kind: "UNCONDITIONAL_CALL".into(),
                    });
                    i += 5;
                }
                0x0f if b.get(i + 1) == Some(&0x85) && i + 6 <= b.len() => {
                    let rel = i32::from_le_bytes([b[i + 2], b[i + 3], b[i + 4], b[i + 5]]);
                    xrefs.push(NativeXref {
                        from: m.vaddr + i as u64,
                        to: (m.vaddr + i as u64).wrapping_add(6).wrapping_add(rel as u64),
                        kind: "CONDITIONAL_JUMP".into(),
                    });
                    i += 6;
                }
                0xe9 if i + 5 <= b.len() => {
                    let rel = i32::from_le_bytes([b[i + 1], b[i + 2], b[i + 3], b[i + 4]]);
                    xrefs.push(NativeXref {
                        from: m.vaddr + i as u64,
                        to: (m.vaddr + i as u64).wrapping_add(5).wrapping_add(rel as u64),
                        kind: "UNCONDITIONAL_JUMP".into(),
                    });
                    i += 5;
                }
                _ => i += 1,
            }
        }
    }
    imp.xrefs = xrefs;
}

/// Finds an external's display name for a function entry, if known.
pub fn extern_name(imp: &NativeImport, entry: u64) -> Option<String> {
    imp.externals
        .iter()
        .find(|(a, n)| *a == entry && !n.is_empty())
        .map(|(_, n)| n.clone())
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
    let mut seeds: Vec<u64> = imp.functions.iter().map(|f| f.entry).collect();
    // PLT stubs/externs are seeds too.
    for (a, _) in &imp.externals {
        seeds.push(*a);
    }
    // The entry seed is guaranteed by import_elf/pe.
    let maps_owned: Vec<(u64, u64, u64, &[u8])> = imp
        .mappings
        .iter()
        .map(|m| (m.vaddr, m.size, m.file_off, m.bytes.as_slice()))
        .collect();
    let d = crate::disasm::discover(&maps_owned, &seeds);
    let mut merged = imp.functions.clone();
    for e in &d.entries {
        if !merged.iter().any(|f| f.entry == *e) {
            let name = if let Some((_, n)) = imp.externals.iter().find(|(a, n)| *a == *e && !n.is_empty()) {
                n.clone()
            } else {
                format!("FUN_{:08x}", e)
            };
            merged.push(NativeFunction {
                entry: *e,
                name,
                size: 1,
            });
        }
    }
    merged.sort_by_key(|f| f.entry);
    merged.dedup_by_key(|f| f.entry);
    // sizes: distance to the next entry
    for i in 0..merged.len() {
        let end = merged.get(i + 1).map(|n| n.entry).unwrap_or(merged[i].entry + 16);
        merged[i].size = end.saturating_sub(merged[i].entry).max(1);
    }
    imp.functions = merged;
    // discovered calls become xrefs (dedup on (from,to)).
    let mut xrefs: Vec<NativeXref> = imp.xrefs.clone();
    for (from, to) in &d.calls {
        if !xrefs.iter().any(|x| x.from == *from && x.to == *to) {
            xrefs.push(NativeXref {
                from: *from,
                to: *to,
                kind: "UNCONDITIONAL_CALL".into(),
            });
        }
    }
    imp.xrefs = xrefs;
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
    let pid = db.upsert_program(program, "x86:LE:64:default", &native_provenance())?;
    let rows: Vec<FunctionRow> = functions
        .iter()
        .map(|f| FunctionRow {
            entry: format!("{:08x}", f.entry),
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
            from: format!("{:08x}", x.from),
            to: format!("{:08x}", x.to),
            kind: x.kind.clone(),
        })
        .collect();
    db.replace_xrefs(pid, &xrows)?;
    Ok(ProgramSummary {
        program: program.to_string(),
        functions: functions.len() as u64,
        language: "x86:LE:64:default".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn elf_load_populates_functions() {
        // Build a tiny synthetic ELF64 with one symtab entry.
        let mut b = vec![0u8; 0x1000];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
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
    }
}
