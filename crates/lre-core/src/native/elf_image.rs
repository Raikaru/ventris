//! ELF load bias and relative relocations, before discovery or memory reads.
//! REL/RELA/RELR layouts and R_*_RELATIVE numbers follow the public elf.h ABI.
use super::{ElfSection, ImportError, MemoryRelocation, NativeImport, NativeXref, Result};

fn bad(message: &str) -> ImportError {
    ImportError::Bad(message.into())
}

fn word(data: &[u8], offset: usize, width: usize, be: bool) -> Result<u64> {
    let end = offset
        .checked_add(width)
        .ok_or_else(|| bad("ELF word overflow"))?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| bad("truncated ELF relocation"))?;
    Ok(bytes.iter().enumerate().fold(0, |value, (i, byte)| {
        value | (*byte as u64) << (8 * if be { width - 1 - i } else { i })
    }))
}

pub(super) fn prepare(
    data: &[u8],
    sections: &mut [ElfSection],
    import: &mut NativeImport,
    width: usize,
    be: bool,
) -> Result<()> {
    let (_, bias) = super::elf_bases(data).ok_or_else(|| bad("invalid ELF image base"))?;
    let rebase = |address: u64| {
        address
            .checked_add(bias)
            .ok_or_else(|| bad("ELF address overflow"))
    };
    for mapping in &mut import.mappings {
        mapping.vaddr = rebase(mapping.vaddr)?;
        let end = mapping
            .vaddr
            .checked_add(mapping.size)
            .ok_or_else(|| bad("ELF mapping overflow"))?;
        if width == 4 && end > 1u64 << 32 {
            return Err(bad("ELF32 mapping exceeds address space"));
        }
    }
    for function in &mut import.functions {
        function.entry = rebase(function.entry)?;
    }
    for (address, _) in &mut import.externals {
        if *address != 0 {
            *address = rebase(*address)?;
        }
    }
    for section in sections.iter_mut().filter(|s| s.flags & 2 != 0) {
        section.addr = rebase(section.addr)?;
    }
    let machine = word(data, 18, 2, be)?;
    let linkage_types = match machine {
        3 | 62 => [6, 7],
        20 | 21 => [20, 21],
        183 => [1025, 1026],
        40 => [21, 22],
        8 => [51, 127],
        243 => [0, 5],
        _ => [0, 0],
    }; // Public elf.h: GLOB_DAT / JUMP_SLOT, not arbitrary symbol relocations.
    let relative_type = match machine {
        3 | 62 => Some(8),   // i386 / x86-64
        20 | 21 => Some(22), // PowerPC / PowerPC64
        183 => Some(1027),   // AArch64
        243 => Some(3),      // RISC-V
        _ => None,
    };
    for section in sections
        .iter()
        .filter(|s| matches!(s.typ, 4 | 9 | 19) && s.size != 0)
    {
        let start =
            usize::try_from(section.off).map_err(|_| bad("ELF relocation offset overflow"))?;
        let size =
            usize::try_from(section.size).map_err(|_| bad("ELF relocation size overflow"))?;
        let bytes = data
            .get(
                start
                    ..start
                        .checked_add(size)
                        .ok_or_else(|| bad("ELF relocation overflow"))?,
            )
            .ok_or_else(|| bad("truncated ELF relocation section"))?;
        let stride = width
            * match section.typ {
                4 => 3,
                9 => 2,
                _ => 1,
            };
        if bytes.len() % stride != 0 {
            return Err(bad("partial ELF relocation record"));
        }
        let mut next = None;
        for record in bytes.chunks_exact(stride) {
            let place = word(record, 0, width, be)?;
            if section.typ == 19 {
                if place & 1 == 0 {
                    apply(import, rebase(place)?, None, bias, width, be)?;
                    next = Some(
                        place
                            .checked_add(width as u64)
                            .ok_or_else(|| bad("RELR cursor overflow"))?,
                    );
                } else {
                    let cursor = next.ok_or_else(|| bad("RELR bitmap without address"))?;
                    for bit in 1..width * 8 {
                        if place & (1u64 << bit) != 0 {
                            let at = cursor
                                .checked_add(((bit - 1) * width) as u64)
                                .ok_or_else(|| bad("RELR bitmap overflow"))?;
                            apply(import, rebase(at)?, None, bias, width, be)?;
                        }
                    }
                    next = Some(
                        cursor
                            .checked_add(((width * 8 - 1) * width) as u64)
                            .ok_or_else(|| bad("RELR cursor overflow"))?,
                    );
                }
            } else {
                let info = word(record, width, width, be)?;
                let typ = info & if width == 8 { 0xffffffff } else { 0xff };
                if typ != 0 && linkage_types.contains(&typ) {
                    let index = info >> if width == 8 { 32 } else { 8 };
                    if let Some(name) =
                        external_name(data, sections, section.link, index, width, be)?
                    {
                        let address = rebase(place)?;
                        if !import.mappings.iter().any(|m| {
                            m.size >= width as u64
                                && address >= m.vaddr
                                && address - m.vaddr <= m.size - width as u64
                        }) {
                            return Err(bad("ELF external relocation place is unmapped"));
                        }
                        import
                            .externals
                            .push((address, String::from_utf8_lossy(name).into_owned()));
                    }
                }
                if relative_type != Some(typ) {
                    continue;
                }
                let addend = if section.typ == 4 {
                    Some(word(record, 2 * width, width, be)?)
                } else {
                    None
                };
                apply(import, rebase(place)?, addend, bias, width, be)?;
            }
        }
    }
    import.relocations.sort_by_key(|r| r.address);
    if import
        .relocations
        .windows(2)
        .any(|pair| pair[1].address - pair[0].address < width as u64)
    {
        return Err(bad("overlapping ELF relative relocations"));
    }
    import.externals.sort();
    import.externals.dedup();
    Ok(())
}

fn external_name<'a>(
    data: &'a [u8],
    sections: &[ElfSection],
    link: u32,
    index: u64,
    width: usize,
    be: bool,
) -> Result<Option<&'a [u8]>> {
    if index == 0 {
        return Ok(None);
    }
    let symbols = sections
        .get(link as usize)
        .filter(|s| s.typ == 11)
        .ok_or_else(|| bad("ELF external relocation has no dynamic symbol table"))?;
    let stride = if width == 8 { 24 } else { 16 };
    let relative = index
        .checked_mul(stride)
        .ok_or_else(|| bad("ELF symbol index overflow"))?;
    if relative
        .checked_add(stride)
        .is_none_or(|end| end > symbols.size)
    {
        return Err(bad("ELF relocation symbol index is out of bounds"));
    }
    let start = usize::try_from(
        symbols
            .off
            .checked_add(relative)
            .ok_or_else(|| bad("ELF symbol offset overflow"))?,
    )
    .map_err(|_| bad("ELF symbol offset overflow"))?;
    let symbol = data
        .get(
            start
                ..start
                    .checked_add(stride as usize)
                    .ok_or_else(|| bad("ELF symbol overflow"))?,
        )
        .ok_or_else(|| bad("truncated ELF dynamic symbol"))?;
    let info = symbol[if width == 8 { 4 } else { 12 }];
    if word(symbol, if width == 8 { 6 } else { 14 }, 2, be)? != 0 || !matches!(info & 15, 0 | 2) {
        return Ok(None);
    }
    let strings = sections
        .get(symbols.link as usize)
        .filter(|s| s.typ == 3)
        .ok_or_else(|| bad("ELF dynamic symbol has no string table"))?;
    let offset = word(symbol, 0, 4, be)?;
    if offset >= strings.size {
        return Err(bad("ELF symbol name is out of bounds"));
    }
    let start = usize::try_from(
        strings
            .off
            .checked_add(offset)
            .ok_or_else(|| bad("ELF string offset overflow"))?,
    )
    .map_err(|_| bad("ELF string offset overflow"))?;
    let end = usize::try_from(
        strings
            .off
            .checked_add(strings.size)
            .ok_or_else(|| bad("ELF string table overflow"))?,
    )
    .map_err(|_| bad("ELF string table overflow"))?;
    let bytes = data
        .get(start..end)
        .ok_or_else(|| bad("truncated ELF string table"))?;
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| bad("unterminated ELF symbol name"))?;
    Ok((end != 0).then_some(&bytes[..end]))
}

fn apply(
    import: &mut NativeImport,
    address: u64,
    addend: Option<u64>,
    bias: u64,
    width: usize,
    be: bool,
) -> Result<()> {
    let mapping = import
        .mappings
        .iter_mut()
        .find(|m| {
            address >= m.vaddr
                && address - m.vaddr <= m.size.saturating_sub(width as u64)
                && m.size >= width as u64
        })
        .ok_or_else(|| bad("ELF relocation place is unmapped"))?;
    let offset = usize::try_from(address - mapping.vaddr)
        .map_err(|_| bad("ELF relocation offset overflow"))?;
    let addend = match addend {
        Some(value) => value,
        None if mapping.bytes.is_empty() => 0, // SHT_NOBITS
        None => word(&mapping.bytes, offset, width, be)?,
    };
    // Word-sized modular arithmetic also preserves zero and negative addends.
    let mut value = bias.wrapping_add(addend);
    if width == 4 {
        value &= u32::MAX as u64;
    }
    let mut bytes = [0; 8];
    for (i, byte) in bytes[..width].iter_mut().enumerate() {
        *byte = (value >> (8 * if be { width - 1 - i } else { i })) as u8;
    }
    if !mapping.bytes.is_empty() {
        mapping
            .bytes
            .get_mut(offset..offset + width)
            .ok_or_else(|| bad("truncated ELF relocation place"))?
            .copy_from_slice(&bytes[..width]);
    }
    import.relocations.push(MemoryRelocation {
        address,
        bytes,
        width,
    });
    import.xrefs.push(NativeXref::with_provenance(
        address,
        value,
        "DATA",
        "native-import:elf-reloc",
    ));
    if import
        .mappings
        .iter()
        .any(|m| m.flags & 4 != 0 && value >= m.vaddr && value - m.vaddr < m.size)
    {
        import.reloc_candidates.push(value);
    }
    Ok(())
}
