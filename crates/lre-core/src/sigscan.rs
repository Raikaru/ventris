//! Game-binary analysis surfaces (Phase 4): byte-pattern signature search
//! and vtable recovery. Both run over imported mappings, endianness-aware,
//! with no decompiler dependency — they work wherever import works.

use crate::native::Mapping;

/// One signature-search hit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigHit {
    pub address: u64,
    /// The mapping's name-ish context: section-relative index for display.
    pub mapping_index: usize,
}

/// Parses an IDA-style byte pattern: hex byte pairs with `??` wildcards,
/// separated by spaces or run together ("E8 ?? ?? ?? ??", "E8????").
/// Returns None on malformed input.
pub fn parse_pattern(pattern: &str) -> Option<Vec<Option<u8>>> {
    let cleaned: String = pattern
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != ',')
        .collect();
    if cleaned.is_empty() || cleaned.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = pair[0];
        let lo = pair[1];
        if hi == b'?' && lo == b'?' {
            out.push(None);
            continue;
        }
        let hex = |c: u8| -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            }
        };
        let h = hex(hi)?;
        let l = hex(lo)?;
        out.push(Some((h << 4) | l));
    }
    Some(out)
}

/// Scans every mapping for the pattern. Wildcards match any byte. Hits are
/// capped at `limit` (0 = no cap) so pathological patterns cannot flood.
pub fn search_bytes(mappings: &[Mapping], pattern: &[Option<u8>], limit: usize) -> Vec<SigHit> {
    let mut hits = Vec::new();
    for (mi, mapping) in mappings.iter().enumerate() {
        let bytes = &mapping.bytes;
        if bytes.len() < pattern.len() {
            continue;
        }
        'scan: for i in 0..=(bytes.len() - pattern.len()) {
            for (j, expected) in pattern.iter().enumerate() {
                if let Some(want) = expected {
                    if bytes[i + j] != *want {
                        continue 'scan;
                    }
                }
            }
            hits.push(SigHit {
                address: mapping.vaddr + i as u64,
                mapping_index: mi,
            });
            if limit != 0 && hits.len() >= limit {
                return hits;
            }
        }
    }
    hits
}

/// One recovered vtable: a run of consecutive code pointers in a data
/// mapping, plus the resolved targets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vtable {
    pub address: u64,
    pub targets: Vec<u64>,
}

/// Reads a pointer of `pointer_size` bytes at `offset` in `bytes`
/// (endianness-aware); None on bounds.
fn read_pointer(bytes: &[u8], offset: usize, pointer_size: usize, big_endian: bool) -> Option<u64> {
    if offset + pointer_size > bytes.len() {
        return None;
    }
    let mut value = 0u64;
    if big_endian {
        for i in 0..pointer_size {
            value = (value << 8) | bytes[offset + i] as u64;
        }
    } else {
        for i in (0..pointer_size).rev() {
            value = (value << 8) | bytes[offset + i] as u64;
        }
    }
    Some(value)
}

/// Recovers vtables: runs of `min_entries` consecutive pointers that land
/// inside executable mappings. `code_ranges` are (start, end) pairs of
/// executable mappings; `pointer_size` is 4 (GameCube/PS2) or 8; `base`
/// selects endianness via the import language.
pub fn recover_vtables(
    mappings: &[Mapping],
    code_ranges: &[(u64, u64)],
    pointer_size: usize,
    big_endian: bool,
    min_entries: usize,
    limit: usize,
) -> Vec<Vtable> {
    let in_code = |v: u64| code_ranges.iter().any(|(s, e)| v >= *s && v < *e);
    let mut vtables = Vec::new();
    for mapping in mappings {
        let exec = mapping.flags & 0x4 != 0; // SHF_EXECINSTR
        if exec {
            continue; // vtables live in data
        }
        let bytes = &mapping.bytes;
        let mut run: Vec<u64> = Vec::new();
        let mut run_start = 0u64;
        let mut i = 0usize;
        while i + pointer_size <= bytes.len() {
            let Some(value) = read_pointer(bytes, i, pointer_size, big_endian) else {
                break;
            };
            if value != 0 && value % pointer_size as u64 == 0 && in_code(value) {
                if run.is_empty() {
                    run_start = mapping.vaddr + i as u64;
                }
                run.push(value);
            } else {
                if run.len() >= min_entries {
                    vtables.push(Vtable {
                        address: run_start,
                        targets: run.clone(),
                    });
                    if limit != 0 && vtables.len() >= limit {
                        return vtables;
                    }
                }
                run.clear();
            }
            i += pointer_size;
        }
        if run.len() >= min_entries {
            vtables.push(Vtable {
                address: run_start,
                targets: run.clone(),
            });
            if limit != 0 && vtables.len() >= limit {
                return vtables;
            }
        }
    }
    vtables
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(vaddr: u64, bytes: Vec<u8>, exec: bool) -> Mapping {
        Mapping {
            vaddr,
            size: bytes.len() as u64,
            file_off: 0,
            flags: if exec { 0x6 } else { 0x2 },
            bytes,
        }
    }

    #[test]
    fn parses_ida_style_patterns() {
        assert_eq!(
            parse_pattern("E8 ?? ?? ?? ??"),
            Some(vec![
                Some(0xE8),
                None,
                None,
                None,
                None
            ])
        );
        assert_eq!(
            parse_pattern("e8????????"),
            parse_pattern("E8 ?? ?? ?? ??")
        );
        assert_eq!(parse_pattern("E8 ?"), None);
        assert_eq!(parse_pattern("ZZ"), None);
    }

    #[test]
    fn search_finds_wildcard_matches() {
        let mappings = [mapping(0x1000, vec![0x90, 0xE8, 0x11, 0x22, 0x33, 0x44, 0x90], true)];
        let pattern = parse_pattern("E8 ?? 22 ??").unwrap();
        let hits = search_bytes(&mappings, &pattern, 0);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].address, 0x1001);
    }

    #[test]
    fn vtables_need_consecutive_code_pointers() {
        // Data: [ptr 0x2000, ptr 0x2010, ptr 0x2020, 0, garbage]; code at
        // 0x2000..0x3000. BE pointers, 4 bytes.
        let ptr = |v: u32| v.to_be_bytes().to_vec();
        let mut data = Vec::new();
        data.extend_from_slice(&ptr(0x2000));
        data.extend_from_slice(&ptr(0x2010));
        data.extend_from_slice(&ptr(0x2020));
        data.extend_from_slice(&ptr(0));
        data.extend_from_slice(&[0xFF; 4]);
        let mappings = [
            mapping(0x1000, data, false),
            mapping(0x2000, vec![0x90; 0x100], true),
        ];
        let vtables = recover_vtables(&mappings, &[(0x2000, 0x3000)], 4, true, 3, 0);
        assert_eq!(vtables.len(), 1);
        assert_eq!(vtables[0].address, 0x1000);
        assert_eq!(vtables[0].targets, vec![0x2000, 0x2010, 0x2020]);
    }
}
