use super::{ElfFacts, Endian, Format, FormatError};
use std::collections::BTreeMap;

/// Linker and loader facts that are useful to higher-level recovery.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ImageMetadata {
    pub symbols: Vec<ImageSymbol>,
    pub relocations: Vec<ImageRelocation>,
}

/// One named ELF symbol.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ImageSymbol {
    pub address: u64,
    pub name: String,
    pub size: u64,
    pub section: u16,
}

/// One ELF relocation and its resolved symbol name, when available.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ImageRelocation {
    pub address: u64,
    pub symbol: Option<String>,
    pub kind: u32,
    pub addend: Option<i64>,
}

#[derive(Copy, Clone, Debug)]
struct Section {
    kind: u32,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

/// Extract metadata from containers whose payload is an ELF image.
///
/// Other loaders return an empty set until their symbol formats are modeled.
/// The parser never guesses names: an unnamed relocation retains `None`.
pub fn extract(source: &[u8], format: &Format) -> Result<ImageMetadata, FormatError> {
    match format {
        Format::Elf(facts) => parse_elf(source, facts),
        Format::PspPrx(facts) => parse_elf(source, &facts.elf),
        Format::WiiURpl(facts) => parse_elf(source, &facts.elf),
        Format::SceSelf(facts) => {
            let start = usize::try_from(facts.elf_offset)
                .map_err(|_| FormatError::Malformed("SELF ELF offset"))?;
            let size = usize::try_from(facts.elf_filesize)
                .map_err(|_| FormatError::Malformed("SELF ELF size"))?;
            let end = start
                .checked_add(size)
                .ok_or(FormatError::Malformed("SELF ELF range"))?;
            let embedded = source
                .get(start..end)
                .ok_or(FormatError::Truncated("SELF embedded ELF"))?;
            parse_elf(embedded, &facts.elf)
        }
        _ => Ok(ImageMetadata::default()),
    }
}

fn parse_elf(source: &[u8], facts: &ElfFacts) -> Result<ImageMetadata, FormatError> {
    let (table, entry_size, count) = section_table(source, facts)?;
    if count == 0 {
        return Ok(ImageMetadata::default());
    }
    let sections = (0..count)
        .map(|index| section(source, facts, table, entry_size, index))
        .collect::<Result<Vec<_>, _>>()?;
    let mut metadata = ImageMetadata::default();
    let mut symbols_by_section: BTreeMap<usize, Vec<Option<String>>> = BTreeMap::new();

    for (index, current) in sections.iter().enumerate() {
        if !matches!(current.kind, 2 | 11) {
            continue;
        }
        let stride = symbol_stride(facts, current.entsize)?;
        let bytes = section_bytes(source, current, "ELF symbols")?;
        let count = bytes.len() / stride;
        let string_table = sections
            .get(usize::try_from(current.link).unwrap_or(usize::MAX))
            .and_then(|section| section_bytes(source, section, "ELF symbol strings").ok());
        let mut names = Vec::with_capacity(count);
        for ordinal in 0..count {
            let offset = ordinal
                .checked_mul(stride)
                .ok_or(FormatError::Malformed("ELF symbol index"))?;
            let (name_offset, address, size, section_index) =
                symbol_fields(facts, bytes, offset, string_table.as_deref())?;
            let name =
                name_offset.and_then(|name_offset| string_at(name_offset, string_table.as_deref()));
            names.push(name.clone());
            if let Some(name) = name.filter(|name| !name.is_empty()) {
                metadata.symbols.push(ImageSymbol {
                    address,
                    name,
                    size,
                    section: section_index,
                });
            }
        }
        symbols_by_section.insert(index, names);
    }

    for current in &sections {
        if !matches!(current.kind, 4 | 9) {
            continue;
        }
        let stride = relocation_stride(facts, current.kind, current.entsize)?;
        let bytes = section_bytes(source, current, "ELF relocations")?;
        let symbols = symbols_by_section.get(
            &usize::try_from(current.link)
                .map_err(|_| FormatError::Malformed("ELF relocation symbol table"))?,
        );
        for ordinal in 0..bytes.len() / stride {
            let offset = ordinal
                .checked_mul(stride)
                .ok_or(FormatError::Malformed("ELF relocation index"))?;
            let (address, symbol_index, kind, addend) =
                relocation_fields(facts, current.kind, bytes, offset)?;
            let symbol = symbols
                .and_then(|symbols| symbols.get(symbol_index as usize))
                .and_then(Clone::clone);
            metadata.relocations.push(ImageRelocation {
                address,
                symbol,
                kind,
                addend,
            });
        }
    }
    Ok(metadata)
}

fn section_table(source: &[u8], facts: &ElfFacts) -> Result<(usize, usize, usize), FormatError> {
    let (offset, entry_size, count) = if facts.class_bits == 64 {
        (
            u64_at(source, 40, facts.endian).ok_or(FormatError::Truncated("e_shoff"))?,
            u16_at(source, 58, facts.endian).ok_or(FormatError::Truncated("e_shentsize"))? as usize,
            u16_at(source, 60, facts.endian).ok_or(FormatError::Truncated("e_shnum"))? as usize,
        )
    } else {
        (
            u64::from(u32_at(source, 32, facts.endian).ok_or(FormatError::Truncated("e_shoff"))?),
            u16_at(source, 46, facts.endian).ok_or(FormatError::Truncated("e_shentsize"))? as usize,
            u16_at(source, 48, facts.endian).ok_or(FormatError::Truncated("e_shnum"))? as usize,
        )
    };
    let offset = usize::try_from(offset).map_err(|_| FormatError::Malformed("section offset"))?;
    if count == 0 {
        return Ok((offset, entry_size, 0));
    }
    if entry_size == 0 {
        return Err(FormatError::Malformed("ELF section entry size"));
    }
    Ok((offset, entry_size, count))
}

fn section(
    source: &[u8],
    facts: &ElfFacts,
    table: usize,
    entry_size: usize,
    index: usize,
) -> Result<Section, FormatError> {
    let offset = table
        .checked_add(
            index
                .checked_mul(entry_size)
                .ok_or(FormatError::Malformed("ELF section index"))?,
        )
        .ok_or(FormatError::Malformed("ELF section offset"))?;
    let header_size = if facts.class_bits == 64 { 64 } else { 40 };
    if entry_size < header_size || source.get(offset..offset + header_size).is_none() {
        return Err(FormatError::Truncated("ELF section header"));
    }
    let (kind, offset, size, link, entsize) = if facts.class_bits == 64 {
        (
            u32_at(source, offset + 4, facts.endian),
            u64_at(source, offset + 24, facts.endian),
            u64_at(source, offset + 32, facts.endian),
            u32_at(source, offset + 40, facts.endian),
            u64_at(source, offset + 56, facts.endian),
        )
    } else {
        (
            u32_at(source, offset + 4, facts.endian),
            u32_at(source, offset + 16, facts.endian).map(u64::from),
            u32_at(source, offset + 20, facts.endian).map(u64::from),
            u32_at(source, offset + 24, facts.endian),
            u32_at(source, offset + 36, facts.endian).map(u64::from),
        )
    };
    Ok(Section {
        kind: kind.ok_or(FormatError::Truncated("ELF section type"))?,
        offset: offset.ok_or(FormatError::Truncated("ELF section offset"))?,
        size: size.ok_or(FormatError::Truncated("ELF section size"))?,
        link: link.ok_or(FormatError::Truncated("ELF section link"))?,
        entsize: entsize.ok_or(FormatError::Truncated("ELF section entry size"))?,
    })
}

fn section_bytes<'a>(
    source: &'a [u8],
    section: &Section,
    label: &'static str,
) -> Result<&'a [u8], FormatError> {
    let start = usize::try_from(section.offset).map_err(|_| FormatError::Malformed(label))?;
    let size = usize::try_from(section.size).map_err(|_| FormatError::Malformed(label))?;
    let end = start
        .checked_add(size)
        .ok_or(FormatError::Malformed(label))?;
    source.get(start..end).ok_or(FormatError::Truncated(label))
}

fn symbol_stride(facts: &ElfFacts, declared: u64) -> Result<usize, FormatError> {
    let minimum: usize = if facts.class_bits == 64 { 24 } else { 16 };
    let stride = if declared == 0 {
        minimum
    } else {
        usize::try_from(declared).map_err(|_| FormatError::Malformed("ELF symbol stride"))?
    };
    if stride < minimum {
        return Err(FormatError::Malformed("ELF symbol stride"));
    }
    Ok(stride)
}

fn relocation_stride(facts: &ElfFacts, kind: u32, declared: u64) -> Result<usize, FormatError> {
    let minimum: usize = match (facts.class_bits, kind) {
        (64, 4) => 24,
        (64, 9) => 16,
        (32, 4) => 12,
        (32, 9) => 8,
        _ => return Err(FormatError::Malformed("ELF relocation type")),
    };
    let stride = if declared == 0 {
        minimum
    } else {
        usize::try_from(declared).map_err(|_| FormatError::Malformed("ELF relocation stride"))?
    };
    if stride < minimum {
        return Err(FormatError::Malformed("ELF relocation stride"));
    }
    Ok(stride)
}

fn symbol_fields(
    facts: &ElfFacts,
    bytes: &[u8],
    offset: usize,
    strings: Option<&[u8]>,
) -> Result<(Option<u32>, u64, u64, u16), FormatError> {
    let (name, address, size, section) = if facts.class_bits == 64 {
        (
            u32_at(bytes, offset, facts.endian),
            u64_at(bytes, offset + 8, facts.endian),
            u64_at(bytes, offset + 16, facts.endian),
            u16_at(bytes, offset + 6, facts.endian),
        )
    } else {
        (
            u32_at(bytes, offset, facts.endian),
            u32_at(bytes, offset + 4, facts.endian).map(u64::from),
            u32_at(bytes, offset + 8, facts.endian).map(u64::from),
            u16_at(bytes, offset + 14, facts.endian),
        )
    };
    let name = name.ok_or(FormatError::Truncated("ELF symbol name"))?;
    let address = address.ok_or(FormatError::Truncated("ELF symbol value"))?;
    let size = size.ok_or(FormatError::Truncated("ELF symbol size"))?;
    let section = section.ok_or(FormatError::Truncated("ELF symbol section"))?;
    let name = (name != 0 && strings.is_some()).then_some(name);
    Ok((name, address, size, section))
}

fn relocation_fields(
    facts: &ElfFacts,
    kind: u32,
    bytes: &[u8],
    offset: usize,
) -> Result<(u64, u64, u32, Option<i64>), FormatError> {
    if facts.class_bits == 64 {
        let address = u64_at(bytes, offset, facts.endian)
            .ok_or(FormatError::Truncated("ELF relocation address"))?;
        let info = u64_at(bytes, offset + 8, facts.endian)
            .ok_or(FormatError::Truncated("ELF relocation info"))?;
        let addend = if kind == 4 {
            Some(
                i64_at(bytes, offset + 16, facts.endian)
                    .ok_or(FormatError::Truncated("ELF relocation addend"))?,
            )
        } else {
            None
        };
        Ok((address, info >> 32, info as u32, addend))
    } else {
        let address = u64::from(
            u32_at(bytes, offset, facts.endian)
                .ok_or(FormatError::Truncated("ELF relocation address"))?,
        );
        let info = u32_at(bytes, offset + 4, facts.endian)
            .ok_or(FormatError::Truncated("ELF relocation info"))?;
        let addend = if kind == 4 {
            Some(
                i32_at(bytes, offset + 8, facts.endian)
                    .ok_or(FormatError::Truncated("ELF relocation addend"))? as i64,
            )
        } else {
            None
        };
        Ok((address, u64::from(info >> 8), info & 0xff, addend))
    }
}

fn string_at(offset: u32, strings: Option<&[u8]>) -> Option<String> {
    let strings = strings?;
    let start = usize::try_from(offset).ok()?;
    let bytes = strings.get(start..)?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn u16_at(bytes: &[u8], offset: usize, endian: Endian) -> Option<u16> {
    let bytes: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u16::from_le_bytes(bytes),
        Endian::Big => u16::from_be_bytes(bytes),
    })
}

fn u32_at(bytes: &[u8], offset: usize, endian: Endian) -> Option<u32> {
    let bytes: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u32::from_le_bytes(bytes),
        Endian::Big => u32::from_be_bytes(bytes),
    })
}

fn u64_at(bytes: &[u8], offset: usize, endian: Endian) -> Option<u64> {
    let bytes: [u8; 8] = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(match endian {
        Endian::Little => u64::from_le_bytes(bytes),
        Endian::Big => u64::from_be_bytes(bytes),
    })
}

fn i32_at(bytes: &[u8], offset: usize, endian: Endian) -> Option<i32> {
    Some(u32_at(bytes, offset, endian)? as i32)
}

fn i64_at(bytes: &[u8], offset: usize, endian: Endian) -> Option<i64> {
    Some(u64_at(bytes, offset, endian)? as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn section(
        bytes: &mut [u8],
        index: usize,
        name: u32,
        kind: u32,
        flags: u32,
        address: u32,
        offset: u32,
        size: u32,
        link: u32,
        entsize: u32,
    ) {
        let base = 0x100 + index * 40;
        put_u32(bytes, base, name);
        put_u32(bytes, base + 4, kind);
        put_u32(bytes, base + 8, flags);
        put_u32(bytes, base + 12, address);
        put_u32(bytes, base + 16, offset);
        put_u32(bytes, base + 20, size);
        put_u32(bytes, base + 24, link);
        put_u32(bytes, base + 36, entsize);
    }

    #[test]
    fn extracts_named_symbols_and_relocations_from_elf() {
        let mut bytes = vec![0; 0x390];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 1;
        bytes[5] = 1;
        put_u16(&mut bytes, 16, 2);
        put_u16(&mut bytes, 18, 8);
        put_u32(&mut bytes, 24, 0x1000);
        put_u32(&mut bytes, 32, 0x100);
        put_u16(&mut bytes, 40, 52);
        put_u16(&mut bytes, 46, 40);
        put_u16(&mut bytes, 48, 6);
        put_u16(&mut bytes, 50, 1);

        let section_names = b"\0.shstrtab\0.strtab\0.symtab\0.relimage\0";
        let symbol_names = b"\0func\0target\0";
        bytes[0x300..0x300 + section_names.len()].copy_from_slice(section_names);
        bytes[0x320..0x320 + symbol_names.len()].copy_from_slice(symbol_names);
        put_u32(&mut bytes, 0x350, 1);
        put_u32(&mut bytes, 0x354, 0x1000);
        put_u32(&mut bytes, 0x358, 8);
        bytes[0x35c] = 0x12;
        put_u16(&mut bytes, 0x35e, 5);
        put_u32(&mut bytes, 0x370, 0x1004);
        put_u32(&mut bytes, 0x374, (1 << 8) | 2);
        bytes[0x380..0x384].copy_from_slice(&[0, 0, 0, 0]);

        let section_name = |name: &[u8]| {
            section_names
                .windows(name.len())
                .position(|window| window == name)
                .unwrap() as u32
        };
        section(
            &mut bytes,
            1,
            section_name(b".shstrtab"),
            3,
            0,
            0,
            0x300,
            section_names.len() as u32,
            0,
            1,
        );
        section(
            &mut bytes,
            2,
            section_name(b".strtab"),
            3,
            0,
            0,
            0x320,
            symbol_names.len() as u32,
            0,
            1,
        );
        section(
            &mut bytes,
            3,
            section_name(b".symtab"),
            2,
            0,
            0,
            0x340,
            32,
            2,
            16,
        );
        section(
            &mut bytes,
            4,
            section_name(b".relimage"),
            9,
            0,
            0,
            0x370,
            8,
            3,
            8,
        );
        section(&mut bytes, 5, 0, 1, 6, 0x1000, 0x380, 4, 0, 0);

        let facts = ElfFacts {
            class_bits: 32,
            endian: Endian::Little,
            obj_type: 2,
            machine: 8,
            flags: 0,
        };
        let metadata = extract(&bytes, &Format::Elf(facts)).unwrap();
        assert_eq!(metadata.symbols.len(), 1);
        assert_eq!(metadata.symbols[0].name, "func");
        assert_eq!(metadata.symbols[0].address, 0x1000);
        assert_eq!(metadata.relocations.len(), 1);
        assert_eq!(metadata.relocations[0].address, 0x1004);
        assert_eq!(metadata.relocations[0].symbol.as_deref(), Some("func"));
        assert_eq!(metadata.relocations[0].kind, 2);
    }
}
