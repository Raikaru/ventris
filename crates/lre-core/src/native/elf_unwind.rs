//! ELF .eh_frame_hdr index entries identify functions even when unreferenced.
//! Layout/encodings: LSB DWARF extensions and pinned Ghidra
//! ExceptionHandlerFrameHeader, FdeTable, DwarfEHDataDecodeFormat (Apache-2.0).
use super::{ElfSection, NativeFunction, NativeImport, NativeXref};

fn decode(bytes: &[u8], cursor: &mut usize, encoding: u8, base: u64, width: usize, be: bool) -> Option<u64> {
    let field = *cursor;
    if encoding & 0x80 != 0 { return None; }
    let form = encoding & 0xf;
    let mut value = 0u64;
    if form == 1 || form == 9 {
        let mut shift = 0;
        loop {
            let byte = *bytes.get(*cursor)?;
            *cursor += 1;
            if shift == 63 && byte & 0x7e != 0 && !(form == 9 && byte & 0x7e == 0x7e) { return None; }
            value |= ((byte & 0x7f) as u64).checked_shl(shift)?;
            shift += 7;
            if byte & 0x80 == 0 {
                if form == 9 && byte & 0x40 != 0 && shift < 64 { value |= u64::MAX << shift; }
                break;
            }
        }
    } else {
        let size = match form { 0 | 8 => width, 2 | 10 => 2, 3 | 11 => 4, 4 | 12 => 8, _ => return None };
        let chunk = bytes.get(*cursor..cursor.checked_add(size)?)?;
        *cursor += size;
        for i in 0..size { value |= (chunk[if be { size - 1 - i } else { i }] as u64) << (8 * i); }
        if form & 8 != 0 && size < 8 {
            value = ((value << (64 - size * 8)) as i64 >> (64 - size * 8)) as u64;
        }
    }
    match encoding & 0x70 {
        0 => Some(value),
        0x10 => Some(base.wrapping_add(field as u64).wrapping_add(value)),
        0x30 => Some(base.wrapping_add(value)),
        _ => None,
    }
}

pub(super) fn collect(data: &[u8], sections: &[ElfSection], import: &mut NativeImport, width: usize, be: bool) {
    for section in sections.iter().filter(|s| s.name == ".eh_frame_hdr" && s.flags & 2 != 0) {
        let Some(bytes) = section.off.checked_add(section.size)
            .and_then(|end| data.get(usize::try_from(section.off).ok()?..usize::try_from(end).ok()?)) else { continue; };
        if bytes.len() < 4 || bytes[0] != 1 { continue; }
        let mut cursor = 4;
        // Unsupported/omitted encodings supply no seeds; never guess a format.
        if decode(bytes, &mut cursor, bytes[1], section.addr, width, be).is_none() { continue; }
        let Some(count) = decode(bytes, &mut cursor, bytes[2], section.addr, width, be) else { continue; };
        if count > ((bytes.len() - cursor) / 2) as u64 { continue; }
        for _ in 0..count {
            let source = section.addr.wrapping_add(cursor as u64);
            let Some(entry) = decode(bytes, &mut cursor, bytes[3], section.addr, width, be) else { break; };
            let Some(fde) = decode(bytes, &mut cursor, bytes[3], section.addr, width, be) else { break; };
            if !sections.iter().any(|s| s.name == ".eh_frame" && fde >= s.addr && fde - s.addr < s.size) { continue; }
            if !import.mappings.iter().any(|m| m.flags & 4 != 0 && entry >= m.vaddr && entry - m.vaddr < m.size) { continue; }
            if !import.functions.iter().any(|f| f.entry == entry) {
                import.functions.push(NativeFunction { entry, name: format!("FUN_{entry:08x}"), size: 1 });
            }
            import.xrefs.push(NativeXref::with_provenance(source, entry, "DATA", "native-import:elf-unwind"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_relative_entries_and_truncation() {
        for be in [false, true] {
            let encoded = if be { (-0x3000i32).to_be_bytes() } else { (-0x3000i32).to_le_bytes() };
            let mut cursor = 0;
            assert_eq!(decode(&encoded, &mut cursor, 0x3b, 0x4000, 8, be), Some(0x1000));
            assert_eq!(decode(&encoded[..3], &mut 0, 0x3b, 0x4000, 8, be), None);
        }
        assert_eq!(decode(&[0x80; 11], &mut 0, 1, 0, 8, false), None);
    }
}
