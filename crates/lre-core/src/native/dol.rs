//! GameCube DOL section-table loader. Format reference: Dolphin DolReader.h
//! (GPL-2.0-or-later); independent implementation, no upstream code copied.
use super::{err, u32_be_at, Mapping, NativeFunction, NativeImport, Result};

pub(crate) fn import(data: &[u8]) -> Result<NativeImport> {
    const HEADER_SIZE: usize = 0xe4;
    if data.len() < HEADER_SIZE {
        return err("truncated DOL header");
    }
    let mut mappings: Vec<Mapping> = Vec::with_capacity(20);
    for index in 0..18 {
        let offset = u32_be_at(data, index * 4)? as usize;
        let address = u32_be_at(data, 0x48 + index * 4)? as u64;
        let size = u32_be_at(data, 0x90 + index * 4)? as u64;
        if size == 0 {
            continue;
        }
        let end = address + size;
        if end > 0x1_0000_0000 || (index < 7 && address % 4 != 0) {
            return err("invalid DOL section address range");
        }
        let file_end = offset.checked_add(size as usize)
            .ok_or_else(|| super::ImportError::Bad("DOL section file range overflow".into()))?;
        if offset < HEADER_SIZE || file_end > data.len() {
            return err("DOL section outside file");
        }
        if mappings.iter().any(|m| address < m.vaddr + m.size && m.vaddr < end) {
            return err("overlapping DOL initialized sections");
        }
        mappings.push(Mapping {
            vaddr: address,
            size,
            file_off: offset as u64,
            flags: if index < 7 { 6 } else { 3 },
            bytes: data[offset..file_end].to_vec(),
        });
    }
    let entry = u32_be_at(data, 0xe0)? as u64;
    if entry % 4 != 0 || !mappings.iter().any(|m| m.flags & 4 != 0 && entry >= m.vaddr && entry < m.vaddr + m.size) {
        return err("DOL entry is not inside a text section");
    }
    mappings.sort_unstable_by_key(|m| m.vaddr);
    let bss_start = u32_be_at(data, 0xd8)? as u64;
    let bss_end = bss_start + u32_be_at(data, 0xdc)? as u64;
    if bss_end > 0x1_0000_0000 {
        return err("DOL BSS address range overflow");
    }
    // DOL BSS bounds may encompass initialized small-data sections. Only
    // uncovered intervals are zero-filled; no allocation proportional to BSS.
    let mut zero_ranges = Vec::new();
    let mut cursor = bss_start;
    for m in &mappings {
        if cursor >= bss_end {
            break;
        }
        if m.vaddr + m.size <= cursor || m.vaddr >= bss_end {
            continue;
        }
        if cursor < m.vaddr {
            zero_ranges.push((cursor, m.vaddr));
        }
        cursor = cursor.max(m.vaddr + m.size);
    }
    if cursor < bss_end {
        zero_ranges.push((cursor, bss_end));
    }
    mappings.extend(zero_ranges.into_iter().map(|(start, end)| Mapping {
        vaddr: start, size: end - start, file_off: 0, flags: 3, bytes: Vec::new(),
    }));
    mappings.sort_unstable_by_key(|m| m.vaddr);
    Ok(NativeImport {
        mappings,
        functions: vec![NativeFunction { entry, name: "_entry".into(), size: 1 }],
        format: "dol".into(),
        language: "PowerPC:BE:32:default".into(),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut data = vec![0; 0x120];
        for (offset, value) in [(0, 0x100_u32), (0x48, 0x80001000), (0x90, 0x10),
                                (0x1c, 0x110), (0x64, 0x80002010), (0xac, 0x10),
                                (0xd8, 0x80002000), (0xdc, 0x30), (0xe0, 0x80001000)] {
            data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        data[0x110..0x120].fill(0xab);
        data
    }

    #[test]
    fn bss_preserves_initialized_small_data() {
        let parsed = import(&fixture()).unwrap();
        let data = parsed.mappings.iter().find(|m| m.vaddr == 0x80002010).unwrap();
        assert_eq!(data.bytes, vec![0xab; 16]);
        let zeros: Vec<_> = parsed.mappings.iter().filter(|m| m.bytes.is_empty())
            .map(|m| (m.vaddr, m.size)).collect();
        assert_eq!(zeros, [(0x80002000, 16), (0x80002020, 16)]);
    }

    #[test]
    fn malformed_ranges_and_entries_are_rejected() {
        for (offset, value) in [(0, 0x11f_u32), (0x48, 0xfffffff8),
                                (0x64, 0x80001000), (0xe0, 0x80002010),
                                (0xd8, 0xfffffff0)] {
            let mut data = fixture();
            data[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            assert!(import(&data).is_err(), "accepted malformed field {offset:#x}");
        }
        assert!(import(&[0; 0xe3]).is_err());
    }
}
