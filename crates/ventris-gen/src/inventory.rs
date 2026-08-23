//! Function and data inventory derived from a loaded image.
//!
//! These algorithms are library-owned because CLI projects and one-shot
//! inspection are only adapters over the same discovery facts.

use std::collections::{BTreeMap, BTreeSet};
use ventris_format::Image;
use ventris_lifter::{discover_functions, Architecture, FunctionDiscovery, Lifter};

const MAX_DATA_FACTS: usize = 4096;
const MAX_FUNCTIONS: usize = 4096;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SymbolFact {
    pub address: u64,
    pub size: u64,
    pub name: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RelocationFact {
    pub address: u64,
    pub symbol: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DataFact {
    pub address: u64,
    pub size: u64,
    pub name: Option<String>,
    pub type_name: Option<&'static str>,
    pub comment: Option<String>,
    pub confidence: u8,
    pub source: &'static str,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Inventory {
    pub functions: FunctionDiscovery,
    pub data: Vec<DataFact>,
}

pub fn code_address(image: &Image, address: u64) -> bool {
    let has_explicit_executable_segment = image
        .segments
        .iter()
        .any(|segment| segment.perms.exec == Some(true));
    image.segments.iter().any(|segment| {
        segment.addr <= address
            && address < segment.end()
            && if has_explicit_executable_segment {
                segment.perms.exec == Some(true)
            } else {
                segment.perms.exec != Some(false)
            }
    })
}

pub fn mapped_address(image: &Image, address: u64) -> bool {
    image
        .segments
        .iter()
        .any(|segment| segment.addr <= address && address < segment.end())
}

pub fn pointer_width(architecture: Architecture) -> usize {
    match architecture {
        Architecture::AArch64
        | Architecture::N64
        | Architecture::Ppc64
        | Architecture::Rv64
        | Architecture::X86_64 => 8,
        _ => 4,
    }
}

pub fn discovery_seeds(
    image: &Image,
    file: &[u8],
    architecture: Architecture,
    symbol_addresses: impl IntoIterator<Item = u64>,
) -> BTreeSet<u64> {
    let mut seeds = BTreeSet::new();
    if let Some(entry) = image.entry {
        seeds.insert(entry);
    }
    seeds.extend(
        symbol_addresses
            .into_iter()
            .filter(|address| code_address(image, *address)),
    );

    let has_explicit_data_segment = image
        .segments
        .iter()
        .any(|segment| segment.perms.exec == Some(false));
    let width = pointer_width(architecture);
    for segment in &image.segments {
        if segment.file_size == 0 || (has_explicit_data_segment && segment.perms.exec == Some(true))
        {
            continue;
        }
        let Some(bytes) = segment_bytes(file, segment.file_off, segment.file_size) else {
            continue;
        };
        for (_, little, big) in pointer_values(bytes, width) {
            if code_address(image, little) {
                seeds.insert(little);
            }
            if code_address(image, big) {
                seeds.insert(big);
            }
        }
    }

    if seeds.is_empty() {
        if let Some(segment) = image
            .segments
            .iter()
            .find(|segment| segment.perms.exec != Some(false))
        {
            seeds.insert(segment.addr);
        }
    }
    seeds
}

pub fn discover_data(
    image: &Image,
    file: &[u8],
    architecture: Architecture,
    symbols: &[SymbolFact],
    relocations: &[RelocationFact],
) -> Vec<DataFact> {
    let mut records = BTreeMap::<u64, DataFact>::new();
    for symbol in symbols {
        if code_address(image, symbol.address) {
            continue;
        }
        records.insert(
            symbol.address,
            DataFact {
                address: symbol.address,
                size: symbol.size.max(1),
                name: Some(symbol.name.clone()),
                type_name: None,
                comment: None,
                confidence: 90,
                source: "symbol-discovery",
            },
        );
    }

    let has_explicit_data_segment = image
        .segments
        .iter()
        .any(|segment| segment.perms.exec == Some(false));
    let width = pointer_width(architecture);
    for segment in &image.segments {
        if segment.file_size == 0 || (has_explicit_data_segment && segment.perms.exec == Some(true))
        {
            continue;
        }
        let Some(bytes) = segment_bytes(file, segment.file_off, segment.file_size) else {
            continue;
        };
        discover_strings(segment.addr, bytes, &mut records);

        if !has_explicit_data_segment || segment.perms.exec != Some(true) {
            for (offset, little, big) in pointer_values(bytes, width) {
                let value = if mapped_address(image, little) {
                    Some(little)
                } else if mapped_address(image, big) {
                    Some(big)
                } else {
                    None
                };
                let Some(value) = value else { continue };
                insert_if_stronger(
                    &mut records,
                    DataFact {
                        address: segment.addr.saturating_add(offset as u64),
                        size: width as u64,
                        name: None,
                        type_name: Some("pointer"),
                        comment: Some(format!("points to 0x{value:x}")),
                        confidence: 65,
                        source: "pointer-discovery",
                    },
                );
            }
        }
    }

    for relocation in relocations {
        if !mapped_address(image, relocation.address) {
            continue;
        }
        insert_if_stronger(
            &mut records,
            DataFact {
                address: relocation.address,
                size: width as u64,
                name: relocation.symbol.clone(),
                type_name: Some("global"),
                comment: None,
                confidence: 95,
                source: "relocation-discovery",
            },
        );
    }

    if records.is_empty() {
        for segment in image
            .segments
            .iter()
            .filter(|segment| segment.perms.exec == Some(false))
        {
            records.insert(
                segment.addr,
                DataFact {
                    address: segment.addr,
                    size: segment.size,
                    name: segment.name.clone(),
                    type_name: Some("segment"),
                    comment: None,
                    confidence: 70,
                    source: "segment-discovery",
                },
            );
        }
    }
    records.into_values().take(MAX_DATA_FACTS).collect()
}

pub fn discover_inventory(
    lifter: &dyn Lifter,
    image: &Image,
    file: &[u8],
    architecture: Architecture,
    symbols: &[SymbolFact],
    relocations: &[RelocationFact],
    instruction_limit: usize,
) -> Inventory {
    let seeds = discovery_seeds(
        image,
        file,
        architecture,
        symbols.iter().map(|symbol| symbol.address),
    );
    Inventory {
        functions: discover_functions(lifter, image, file, seeds, instruction_limit, MAX_FUNCTIONS),
        data: discover_data(image, file, architecture, symbols, relocations),
    }
}

fn segment_bytes(file: &[u8], file_offset: u64, file_size: u64) -> Option<&[u8]> {
    let start = usize::try_from(file_offset).ok()?;
    let length = usize::try_from(file_size).ok()?;
    file.get(start..start.checked_add(length)?)
}

fn pointer_values(bytes: &[u8], width: usize) -> impl Iterator<Item = (usize, u64, u64)> + '_ {
    let count = if width == 0 || width > bytes.len() {
        0
    } else {
        (bytes.len() - width) / width + 1
    };
    (0..count).map(move |index| {
        let offset = index * width;
        let (little, big) = match width {
            4 => (
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as u64,
                u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as u64,
            ),
            8 => (
                u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()),
                u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap()),
            ),
            _ => (0, 0),
        };
        (offset, little, big)
    })
}

fn discover_strings(base: u64, bytes: &[u8], records: &mut BTreeMap<u64, DataFact>) {
    let mut start = None;
    for (offset, byte) in bytes.iter().copied().enumerate() {
        if (0x20..=0x7e).contains(&byte) {
            start.get_or_insert(offset);
            continue;
        }
        if let Some(begin) = start.take() {
            insert_string(base, begin, offset, byte == 0, records);
        }
    }
    if let Some(begin) = start {
        insert_string(base, begin, bytes.len(), false, records);
    }
}

fn insert_string(
    base: u64,
    begin: usize,
    end: usize,
    terminated: bool,
    records: &mut BTreeMap<u64, DataFact>,
) {
    if end.saturating_sub(begin) < 4 {
        return;
    }
    insert_if_stronger(
        records,
        DataFact {
            address: base.saturating_add(begin as u64),
            size: (end - begin + usize::from(terminated)) as u64,
            name: None,
            type_name: Some("string"),
            comment: None,
            confidence: 75,
            source: "string-discovery",
        },
    );
}

fn insert_if_stronger(records: &mut BTreeMap<u64, DataFact>, fact: DataFact) {
    match records.get(&fact.address) {
        Some(existing) if existing.confidence > fact.confidence => {}
        _ if records.len() < MAX_DATA_FACTS || records.contains_key(&fact.address) => {
            records.insert(fact.address, fact);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_format::{Image, Loader};
    use ventris_lifter::{X86_32, X86_64};

    fn raw(bytes: &[u8], base: u64) -> (Vec<u8>, Image) {
        let loaded = Image::load(bytes, Loader::Raw, Some(base)).unwrap();
        (loaded.bytes, loaded.image)
    }

    #[test]
    fn recursive_function_discovery_records_calls() {
        let (file, image) = raw(&[0xe8, 0x01, 0, 0, 0, 0xc3, 0xc3], 0x1000);
        let inventory = discover_inventory(
            &X86_64::new(),
            &image,
            &file,
            Architecture::X86_64,
            &[],
            &[],
            32,
        );
        assert_eq!(inventory.functions.functions.len(), 2);
        assert_eq!(
            inventory.functions.calls,
            BTreeSet::from([(0x1000, 0x1006)])
        );
    }

    #[test]
    fn raw_data_code_pointer_becomes_a_discovery_seed() {
        let (file, image) = raw(&[0xc3, 0, 0, 0, 0x08, 0x10, 0, 0, 0xc3], 0x1000);
        let seeds = discovery_seeds(&image, &file, Architecture::X86_32, []);
        assert!(seeds.contains(&0x1000));
        assert!(seeds.contains(&0x1008));
        let functions = discover_functions(&X86_32, &image, &file, seeds, 32, MAX_FUNCTIONS);
        assert_eq!(functions.functions.len(), 2);
    }

    #[test]
    fn printable_run_becomes_string_data() {
        let (file, image) = raw(&[0xc3, 0, b'H', b'e', b'l', b'l', b'o', 0], 0x1000);
        let data = discover_data(&image, &file, Architecture::X86_64, &[], &[]);
        assert!(data.iter().any(|fact| {
            fact.address == 0x1002 && fact.type_name == Some("string") && fact.size == 6
        }));
    }
    #[test]
    fn relocation_data_uses_the_architecture_pointer_width() {
        let (file, image) = raw(&[0; 8], 0x1000);
        let relocation = RelocationFact {
            address: 0x1000,
            symbol: Some("global".into()),
        };
        let x86_32 = discover_data(
            &image,
            &file,
            Architecture::X86_32,
            &[],
            std::slice::from_ref(&relocation),
        );
        let x86_64 = discover_data(
            &image,
            &file,
            Architecture::X86_64,
            &[],
            std::slice::from_ref(&relocation),
        );
        assert_eq!(x86_32[0].size, 4);
        assert_eq!(x86_64[0].size, 8);
    }

    #[test]
    fn stronger_relocation_replaces_a_string_at_the_same_address() {
        let (file, image) = raw(b"hello\0\0\0", 0x1000);
        let data = discover_data(
            &image,
            &file,
            Architecture::X86_64,
            &[],
            &[RelocationFact {
                address: 0x1000,
                symbol: Some("message".into()),
            }],
        );
        assert_eq!(data.len(), 1);
        assert_eq!(data[0].source, "relocation-discovery");
        assert_eq!(data[0].confidence, 95);
        assert_eq!(data[0].name.as_deref(), Some("message"));
    }

    #[test]
    fn one_shot_inventory_reports_functions_and_data() {
        let (file, image) = raw(&[0xc3, 0, b'H', b'e', b'l', b'l', b'o', 0], 0x1000);
        let inventory = discover_inventory(
            &X86_64::new(),
            &image,
            &file,
            Architecture::X86_64,
            &[],
            &[],
            32,
        );
        assert_eq!(inventory.functions.functions.len(), 1);
        assert_eq!(
            inventory
                .data
                .iter()
                .filter(|fact| fact.type_name == Some("string"))
                .count(),
            1
        );
    }
}
