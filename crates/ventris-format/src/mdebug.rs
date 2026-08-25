//! MIPS symbolic debug reader for the `.mdebug` section.
//!
//! This is the format the PS2 toolchain emitted for the program's own
//! translation units. `dungeon_game.elf` carries DWARF 2 as well, but that
//! covers only the linked-in runtime: `GameWorld::allocEnemyEntity` and
//! `game_world.cpp` appear solely here, in a 240 KB section holding 205 file
//! descriptors, 785 procedure descriptors and 6346 local symbols. Reading it is
//! what lets a function be named by the symbol its compiler recorded and
//! attributed to the source file it came from.
//!
//! The layout is the ECOFF symbolic tables reached through an `HDRR` header.
//! Each file descriptor (`FDR`) names a range of symbols (`SYMR`) and its own
//! slice of the string space; a procedure symbol carries its entry address in
//! `value`.
//!
//! Every table offset in the header is a file offset, not a section-relative
//! one, which is why this reads from the whole image rather than the section
//! bytes.
//!
//! What this supplies is names and source files, and that is a deliberate limit
//! rather than an unfinished one. The auxiliary type table in the only image
//! available to test against is a placeholder: for `game_world.cpp` it holds the
//! monotonic sequence `0x03, 0x05, 0x07, …` at alternating slots, which decodes
//! as `long`, `unsigned long`, `char` and onwards in basic-type declaration order
//! rather than as any procedure's actual type, and the file emits no `stParam`
//! symbols at all. This toolchain recorded names, addresses and file names, and
//! no types. Decoding that table faithfully would hand the decompiler a `long`
//! return for a function that returns a pointer, and a confidently wrong type is
//! worse than none because it gets believed. When an image with genuine `TIR`
//! entries appears the decoder belongs here; writing it against placeholders
//! would only pin the placeholder.
//!
//! Also not read: line numbers, procedure descriptors, optimizer entries, and the
//! external symbol table.

use super::debuginfo::{DebugFunction, DebugInfo};
use super::{Endian, Format, FormatError};

/// Read MIPS symbolic debug information, or nothing when the image has none.
pub fn extract(source: &[u8], format: &Format) -> Result<DebugInfo, FormatError> {
    let facts = match format {
        Format::Elf(facts) => facts,
        Format::PspPrx(facts) => &facts.elf,
        Format::WiiURpl(facts) => &facts.elf,
        _ => return Ok(DebugInfo::default()),
    };
    let Some(sections) = super::dwarf::named_sections(source, facts)? else {
        return Ok(DebugInfo::default());
    };
    let Some(section) = sections.get(".mdebug").copied() else {
        return Ok(DebugInfo::default());
    };
    let endian = facts.endian;
    let Some(header) = Header::parse(section, endian) else {
        return Ok(DebugInfo::default());
    };
    let mut recovered = DebugInfo::default();
    for index in 0..header.file_count {
        // One unreadable file descriptor should not cost the names in the other
        // two hundred.
        if let Some(file) = FileDescriptor::parse(source, &header, index, endian) {
            read_file(source, &header, &file, endian, &mut recovered);
        }
    }
    Ok(recovered)
}

/// The `HDRR` header, reduced to the tables this reader walks.
struct Header {
    file_offset: usize,
    file_count: usize,
    symbol_offset: usize,
    symbol_count: usize,
    string_offset: usize,
    string_size: usize,
}

impl Header {
    fn parse(section: &[u8], endian: Endian) -> Option<Self> {
        // `magic` is the only self-identifying field. A section named `.mdebug`
        // without it is not this format and must not be guessed at.
        if read_u16(section, 0, endian)? != HDRR_MAGIC {
            return None;
        }
        let field = |index: usize| -> Option<usize> {
            usize::try_from(read_i32(section, 4 + index * 4, endian)?).ok()
        };
        // Field order after `magic` and `vstamp`: ilineMax, cbLine,
        // cbLineOffset, idnMax, cbDnOffset, ipdMax, cbPdOffset, isymMax,
        // cbSymOffset, ioptMax, cbOptOffset, iauxMax, cbAuxOffset, issMax,
        // cbSsOffset, issExtMax, cbSsExtOffset, ifdMax, cbFdOffset, crfd,
        // cbRfdOffset, iextMax, cbExtOffset.
        //
        // Indices five and six are the *procedure* descriptors, not the file
        // descriptors. Reading them as the file table walks 785 procedure
        // records as though they were 72-byte file headers, and every field
        // comes out as noise: a symbol count of two million and a negative
        // auxiliary base.
        Some(Self {
            file_count: field(17)?,
            file_offset: field(18)?,
            symbol_count: field(7)?,
            symbol_offset: field(8)?,
            string_size: field(13)?,
            string_offset: field(14)?,
        })
    }
}

/// One `FDR`: a translation unit's slice of the symbol and string tables.
struct FileDescriptor {
    /// Index of the file's own name within its string space.
    name: usize,
    string_base: usize,
    symbol_base: usize,
    symbol_count: usize,
}

impl FileDescriptor {
    fn parse(source: &[u8], header: &Header, index: usize, endian: Endian) -> Option<Self> {
        let at = header
            .file_offset
            .checked_add(index.checked_mul(FDR_SIZE)?)?;
        Some(Self {
            name: usize::try_from(read_i32(source, at + 4, endian)?).ok()?,
            string_base: usize::try_from(read_i32(source, at + 8, endian)?).ok()?,
            symbol_base: usize::try_from(read_i32(source, at + 16, endian)?).ok()?,
            symbol_count: usize::try_from(read_i32(source, at + 20, endian)?).ok()?,
        })
    }
}

/// One `SYMR`, reduced to the fields this reader consults.
struct Symbol {
    /// Index into the file's string space.
    name: usize,
    value: u64,
    /// Symbol type, `st*`.
    kind: u32,
}

impl Symbol {
    fn parse(source: &[u8], header: &Header, ordinal: usize, endian: Endian) -> Option<Self> {
        if ordinal >= header.symbol_count {
            return None;
        }
        let at = header
            .symbol_offset
            .checked_add(ordinal.checked_mul(SYMR_SIZE)?)?;
        // The trailing word packs six bits of symbol type, five of storage
        // class, one reserved bit and twenty of index. Only the type is read.
        let packed = read_u32(source, at + 8, endian)?;
        Some(Self {
            name: usize::try_from(read_i32(source, at, endian)?).ok()?,
            value: u64::from(read_u32(source, at + 4, endian)?),
            kind: packed & 0x3f,
        })
    }
}

/// Walk one file descriptor's symbols, recording its procedures.
fn read_file(
    source: &[u8],
    header: &Header,
    file: &FileDescriptor,
    endian: Endian,
    recovered: &mut DebugInfo,
) {
    let source_name =
        string_at(source, header, file.string_base + file.name).filter(|name| !name.is_empty());
    for ordinal in 0..file.symbol_count {
        let Some(symbol) = Symbol::parse(source, header, file.symbol_base + ordinal, endian) else {
            break;
        };
        if !matches!(symbol.kind, ST_PROC | ST_STATIC_PROC) {
            continue;
        }
        let Some(name) =
            string_at(source, header, file.string_base + symbol.name).filter(|n| !n.is_empty())
        else {
            continue;
        };
        recovered.functions.insert(
            symbol.value,
            DebugFunction {
                entry: symbol.value,
                name,
                return_type: None,
                parameters: Vec::new(),
                source: source_name.clone(),
            },
        );
    }
}

/// A string from the local string space, bounded by the table's declared size.
fn string_at(source: &[u8], header: &Header, offset: usize) -> Option<String> {
    if offset >= header.string_size {
        return None;
    }
    let start = header.string_offset.checked_add(offset)?;
    let end = header.string_offset.checked_add(header.string_size)?;
    let bytes = source.get(start..end.min(source.len()))?;
    let stop = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..stop]).into_owned())
}

fn read_uint(bytes: &[u8], offset: usize, width: usize, endian: Endian) -> Option<u64> {
    let slice = bytes.get(offset..offset.checked_add(width)?)?;
    let mut value = 0u64;
    match endian {
        Endian::Little => {
            for (index, byte) in slice.iter().enumerate() {
                value |= u64::from(*byte) << (8 * index);
            }
        }
        Endian::Big => {
            for byte in slice {
                value = (value << 8) | u64::from(*byte);
            }
        }
    }
    Some(value)
}

fn read_u16(bytes: &[u8], offset: usize, endian: Endian) -> Option<u16> {
    read_uint(bytes, offset, 2, endian).map(|value| value as u16)
}

fn read_u32(bytes: &[u8], offset: usize, endian: Endian) -> Option<u32> {
    read_uint(bytes, offset, 4, endian).map(|value| value as u32)
}

fn read_i32(bytes: &[u8], offset: usize, endian: Endian) -> Option<i32> {
    read_u32(bytes, offset, endian).map(|value| value as i32)
}

const HDRR_MAGIC: u16 = 0x7009;
const FDR_SIZE: usize = 72;
const SYMR_SIZE: usize = 12;

const ST_PROC: u32 = 6;
const ST_STATIC_PROC: u32 = 14;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_section_without_the_magic_contributes_nothing() {
        // A section named `.mdebug` that is not this format must be declined
        // rather than decoded into plausible addresses.
        assert!(Header::parse(&[0u8; 96], Endian::Little).is_none());
    }

    #[test]
    fn the_file_table_is_read_from_the_right_header_fields() {
        // Indices five and six hold the procedure descriptors. This pins the
        // distinction, because reading them instead produced a symbol count of
        // two million and every prototype was lost.
        let mut section = vec![0u8; 4 + 23 * 4];
        section[0..2].copy_from_slice(&HDRR_MAGIC.to_le_bytes());
        let put = |section: &mut Vec<u8>, index: usize, value: i32| {
            let at = 4 + index * 4;
            section[at..at + 4].copy_from_slice(&value.to_le_bytes());
        };
        put(&mut section, 5, 785); // ipdMax
        put(&mut section, 6, 0x1000); // cbPdOffset
        put(&mut section, 7, 6346); // isymMax
        put(&mut section, 8, 0x2000); // cbSymOffset
        put(&mut section, 13, 42736); // issMax
        put(&mut section, 14, 0x3000); // cbSsOffset
        put(&mut section, 17, 205); // ifdMax
        put(&mut section, 18, 0x4000); // cbFdOffset

        let header = Header::parse(&section, Endian::Little).expect("the header parses");
        assert_eq!(header.file_count, 205, "file count is ifdMax, not ipdMax");
        assert_eq!(header.file_offset, 0x4000);
        assert_eq!(header.symbol_count, 6346);
        assert_eq!(header.symbol_offset, 0x2000);
        assert_eq!(header.string_size, 42736);
        assert_eq!(header.string_offset, 0x3000);
    }
}
