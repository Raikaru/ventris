//! Debug-information reader for the DWARF the corpus images actually carry.
//!
//! The purpose is narrow and worth stating: a decompiler that infers a return
//! type from one function's arithmetic cannot know that
//! `GameWorld::allocEnemyEntity` returns `GameWorld *`. Ghidra does not infer it
//! either — it reads the prototype out of `.debug_info`. Without that, a returned
//! member address is an integer of some width and every use of it carries a cast
//! the source never wrote.
//!
//! Scope is DWARF 2 with 32-bit offsets, which is what the pinned corpus images
//! contain: `dungeon_game.elf` declares version 2, four-byte addresses, 33 KB of
//! `.debug_info`. That dialect has no split units, no `.debug_addr`, and no
//! string-index forms, so a CU is a self-contained tree over `.debug_abbrev` and
//! `.debug_str`. Later versions are rejected by version rather than
//! misinterpreted: a wrong prototype is worse than no prototype, because it is
//! believed.
//!
//! What is deliberately not read: line tables (`.debug_line`), locations
//! (`DW_AT_location` expressions), and lexical-block structure. Those describe
//! where a value lives and which source line it came from, which this pipeline
//! has no way to consume yet. Declaring the section read and then ignoring its
//! contents would be worse than leaving it.

use std::collections::BTreeMap;

use super::{ElfFacts, Endian, Format, FormatError};

/// Everything the reader recovers from an image's debug information.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DebugInfo {
    /// Function prototypes, keyed by entry address.
    pub functions: BTreeMap<u64, DebugFunction>,
}

/// One function's prototype as the compiler recorded it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DebugFunction {
    pub entry: u64,
    /// The name as written, undecorated: DWARF records the source name.
    pub name: String,
    /// The declared return type. `None` is a function returning nothing, which
    /// DWARF spells as an absent `DW_AT_type` rather than a void type.
    pub return_type: Option<DebugType>,
    pub parameters: Vec<DebugParameter>,
    /// Source file, when the compilation unit named one.
    pub source: Option<String>,
}

/// One declared parameter.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DebugParameter {
    pub name: Option<String>,
    pub ty: DebugType,
}

/// A declared type, reduced to what a decompiler can act on.
///
/// Qualifiers (`const`, `volatile`) and typedefs are resolved through rather
/// than represented: they do not change storage, and the pipeline's own type
/// model has nowhere to put them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DebugType {
    Bool,
    Int {
        bits: u32,
        signed: bool,
    },
    Float {
        bits: u32,
    },
    Pointer {
        bits: u32,
        to: Box<DebugType>,
    },
    /// A named aggregate and its size in bytes. Members are not read yet.
    Aggregate {
        name: Option<String>,
        bytes: u32,
    },
    Array {
        element: Box<DebugType>,
        count: Option<u64>,
    },
    /// A type the reader understood the shape of but not the contents, carrying
    /// whatever width was declared.
    Opaque {
        bytes: Option<u32>,
    },
    /// `void`, reachable only as a pointer's target.
    Void,
}

impl DebugType {
    /// The storage width in bytes, when the declaration fixed one.
    pub fn byte_size(&self) -> Option<u32> {
        match self {
            Self::Bool => Some(1),
            Self::Int { bits, .. } | Self::Float { bits } => Some(bits.div_ceil(8)),
            Self::Pointer { bits, .. } => Some(bits.div_ceil(8)),
            Self::Aggregate { bytes, .. } => Some(*bytes),
            Self::Array { element, count } => {
                let stride = element.byte_size()?;
                let count = u32::try_from((*count)?).ok()?;
                stride.checked_mul(count)
            }
            Self::Opaque { bytes } => *bytes,
            Self::Void => None,
        }
    }

    /// Whether this type addresses memory, which is the fact a return type most
    /// needs to carry.
    pub fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer { .. })
    }
}

/// Read the debug information from an image, or nothing when it carries none.
///
/// An image without `.debug_info` is the normal case and not an error. A
/// malformed or unsupported unit is skipped rather than failing the whole read:
/// one compilation unit the reader cannot follow should not cost the prototypes
/// in every other unit.
pub fn extract(source: &[u8], format: &Format) -> Result<DebugInfo, FormatError> {
    let facts = match format {
        Format::Elf(facts) => facts,
        Format::PspPrx(facts) => &facts.elf,
        Format::WiiURpl(facts) => &facts.elf,
        _ => return Ok(DebugInfo::default()),
    };
    let Some(sections) = named_sections(source, facts)? else {
        return Ok(DebugInfo::default());
    };
    let (Some(info), Some(abbrev)) = (
        sections.get(".debug_info").copied(),
        sections.get(".debug_abbrev").copied(),
    ) else {
        return Ok(DebugInfo::default());
    };
    let strings = sections.get(".debug_str").copied().unwrap_or(&[]);
    let mut recovered = DebugInfo::default();
    let mut cursor = 0usize;
    while cursor + 11 <= info.len() {
        let Some(next) = read_unit(info, cursor, abbrev, strings, facts.endian, &mut recovered)
        else {
            break;
        };
        if next <= cursor {
            break;
        }
        cursor = next;
    }
    Ok(recovered)
}

/// Section contents keyed by name, when the image has a section-name table.
fn named_sections<'a>(
    source: &'a [u8],
    facts: &ElfFacts,
) -> Result<Option<BTreeMap<&'a str, &'a [u8]>>, FormatError> {
    let (table, entry_size, count) = super::metadata::section_table(source, facts)?;
    if count == 0 {
        return Ok(None);
    }
    let name_index = if facts.class_bits == 64 {
        super::metadata::u16_at(source, 62, facts.endian)
    } else {
        super::metadata::u16_at(source, 50, facts.endian)
    }
    .ok_or(FormatError::Truncated("e_shstrndx"))? as usize;
    if name_index >= count {
        return Ok(None);
    }
    let headers = (0..count)
        .map(|index| super::metadata::section(source, facts, table, entry_size, index))
        .collect::<Result<Vec<_>, _>>()?;
    let names = super::metadata::section_bytes(source, &headers[name_index], "ELF section names")?;
    let mut found = BTreeMap::new();
    for header in &headers {
        let start = header.name as usize;
        let Some(rest) = names.get(start..) else {
            continue;
        };
        let end = rest
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(rest.len());
        let Ok(name) = std::str::from_utf8(&rest[..end]) else {
            continue;
        };
        if !name.starts_with(".debug_") {
            continue;
        }
        if let Ok(bytes) = super::metadata::section_bytes(source, header, "ELF debug section") {
            found.insert(name, bytes);
        }
    }
    Ok(Some(found))
}

/// One abbreviation: the tag it introduces and the attributes that follow it.
struct Abbrev {
    tag: u64,
    has_children: bool,
    attributes: Vec<(u64, u64)>,
}

/// Read one compilation unit, returning the offset of the next.
fn read_unit(
    info: &[u8],
    start: usize,
    abbrev_section: &[u8],
    strings: &[u8],
    endian: Endian,
    recovered: &mut DebugInfo,
) -> Option<usize> {
    let unit_length = read_u32(info, start, endian)? as usize;
    // 0xffffffff introduces the 64-bit DWARF format, which the corpus does not
    // use. Guessing at it would produce plausible nonsense.
    if unit_length == 0 || unit_length >= 0xffff_fff0 {
        return None;
    }
    let end = start
        .checked_add(4)?
        .checked_add(unit_length)?
        .min(info.len());
    let version = read_u16(info, start + 4, endian)?;
    let abbrev_offset = read_u32(info, start + 6, endian)? as usize;
    let address_size = *info.get(start + 10)? as usize;
    // Versions 2 through 4 share this header shape. Version 5 moved the fields
    // and added a unit type, so it is skipped rather than misread.
    if !(2..=4).contains(&version) || !matches!(address_size, 4 | 8) {
        return Some(end);
    }
    let abbrevs = read_abbrevs(abbrev_section, abbrev_offset)?;

    // Two passes: the first records every DIE by its offset so a type reference
    // can be followed regardless of declaration order, the second builds the
    // prototypes. DWARF permits a reference to a later sibling.
    let mut dies: BTreeMap<usize, Die> = BTreeMap::new();
    let mut cursor = start + 11;
    let mut depth = 0usize;
    let mut stack: Vec<usize> = Vec::new();
    while cursor < end {
        let offset = cursor;
        let (code, next) = read_uleb(info, cursor)?;
        cursor = next;
        if code == 0 {
            // A null entry closes the innermost sibling chain.
            if depth == 0 {
                break;
            }
            depth -= 1;
            stack.pop();
            continue;
        }
        let abbrev = abbrevs.get(&code)?;
        let mut die = Die {
            tag: abbrev.tag,
            parent: stack.last().copied(),
            ..Die::default()
        };
        for (attribute, form) in &abbrev.attributes {
            let (value, next) =
                read_attribute(info, cursor, *form, address_size, endian, strings, start)?;
            cursor = next;
            die.apply(*attribute, value);
        }
        dies.insert(offset, die);
        if abbrev.has_children {
            depth += 1;
            stack.push(offset);
        }
    }

    let source_file = dies
        .values()
        .find(|die| die.tag == TAG_COMPILE_UNIT)
        .and_then(|die| die.name.clone());

    for (offset, die) in &dies {
        if die.tag != TAG_SUBPROGRAM {
            continue;
        }
        // A declaration without an entry address is a prototype, not a
        // definition, and has no code to attach to.
        let (Some(entry), Some(name)) = (die.low_pc, die.name.clone()) else {
            continue;
        };
        let return_type = die.type_ref.and_then(|target| resolve(&dies, target, 0));
        let parameters = dies
            .values()
            .filter(|child| child.tag == TAG_FORMAL_PARAMETER && child.parent == Some(*offset))
            .filter_map(|child| {
                Some(DebugParameter {
                    name: child.name.clone(),
                    ty: resolve(&dies, child.type_ref?, 0)?,
                })
            })
            .collect();
        recovered.functions.insert(
            entry,
            DebugFunction {
                entry,
                name,
                return_type,
                parameters,
                source: source_file.clone(),
            },
        );
    }
    Some(end)
}

/// One parsed debugging information entry, reduced to the attributes read.
#[derive(Default)]
struct Die {
    tag: u64,
    parent: Option<usize>,
    name: Option<String>,
    low_pc: Option<u64>,
    byte_size: Option<u32>,
    encoding: Option<u64>,
    type_ref: Option<usize>,
    upper_bound: Option<u64>,
}

impl Die {
    fn apply(&mut self, attribute: u64, value: Value) {
        match (attribute, value) {
            (AT_NAME, Value::Str(text)) => self.name = Some(text),
            (AT_LOW_PC, Value::Unsigned(address)) => self.low_pc = Some(address),
            (AT_BYTE_SIZE, Value::Unsigned(size)) => {
                self.byte_size = u32::try_from(size).ok();
            }
            (AT_ENCODING, Value::Unsigned(encoding)) => self.encoding = Some(encoding),
            (AT_TYPE, Value::Reference(offset)) => self.type_ref = Some(offset),
            (AT_UPPER_BOUND, Value::Unsigned(bound)) => self.upper_bound = Some(bound),
            _ => {}
        }
    }
}

/// Resolve a type reference into the reduced model.
///
/// Qualifiers and typedefs are followed through. The depth bound guards a
/// malformed cycle; a legitimate chain is a handful of links.
fn resolve(dies: &BTreeMap<usize, Die>, offset: usize, depth: usize) -> Option<DebugType> {
    if depth > 16 {
        return None;
    }
    let die = dies.get(&offset)?;
    match die.tag {
        TAG_BASE_TYPE => {
            let bits = die.byte_size.unwrap_or(4).saturating_mul(8);
            Some(match die.encoding.unwrap_or(ATE_SIGNED) {
                ATE_BOOLEAN => DebugType::Bool,
                ATE_FLOAT => DebugType::Float { bits },
                ATE_UNSIGNED | ATE_UNSIGNED_CHAR => DebugType::Int {
                    bits,
                    signed: false,
                },
                _ => DebugType::Int { bits, signed: true },
            })
        }
        TAG_POINTER_TYPE => {
            let bits = die.byte_size.unwrap_or(4).saturating_mul(8);
            let to = die
                .type_ref
                .and_then(|target| resolve(dies, target, depth + 1))
                .unwrap_or(DebugType::Void);
            Some(DebugType::Pointer {
                bits,
                to: Box::new(to),
            })
        }
        TAG_STRUCTURE_TYPE | TAG_CLASS_TYPE | TAG_UNION_TYPE => Some(DebugType::Aggregate {
            name: die.name.clone(),
            bytes: die.byte_size.unwrap_or(0),
        }),
        TAG_ENUMERATION_TYPE => Some(DebugType::Int {
            bits: die.byte_size.unwrap_or(4).saturating_mul(8),
            signed: true,
        }),
        TAG_ARRAY_TYPE => {
            let element = die
                .type_ref
                .and_then(|target| resolve(dies, target, depth + 1))?;
            // The count lives on a child subrange as an inclusive upper bound.
            let count = dies
                .values()
                .find(|child| child.tag == TAG_SUBRANGE_TYPE && child.parent == Some(offset))
                .and_then(|child| child.upper_bound)
                .map(|bound| bound.saturating_add(1));
            Some(DebugType::Array {
                element: Box::new(element),
                count,
            })
        }
        TAG_TYPEDEF | TAG_CONST_TYPE | TAG_VOLATILE_TYPE => match die.type_ref {
            Some(target) => resolve(dies, target, depth + 1),
            // `const void` and a typedef of nothing are both void.
            None => Some(DebugType::Void),
        },
        TAG_SUBROUTINE_TYPE => Some(DebugType::Opaque { bytes: None }),
        _ => Some(DebugType::Opaque {
            bytes: die.byte_size,
        }),
    }
}

/// Parse the abbreviation table beginning at an offset.
fn read_abbrevs(section: &[u8], start: usize) -> Option<BTreeMap<u64, Abbrev>> {
    let mut table = BTreeMap::new();
    let mut cursor = start;
    loop {
        let (code, next) = read_uleb(section, cursor)?;
        cursor = next;
        if code == 0 {
            return Some(table);
        }
        let (tag, next) = read_uleb(section, cursor)?;
        cursor = next;
        let has_children = *section.get(cursor)? != 0;
        cursor += 1;
        let mut attributes = Vec::new();
        loop {
            let (attribute, next) = read_uleb(section, cursor)?;
            cursor = next;
            let (form, next) = read_uleb(section, cursor)?;
            cursor = next;
            if attribute == 0 && form == 0 {
                break;
            }
            attributes.push((attribute, form));
        }
        table.insert(
            code,
            Abbrev {
                tag,
                has_children,
                attributes,
            },
        );
    }
}

/// An attribute value, in the three shapes the reader distinguishes.
enum Value {
    Unsigned(u64),
    Str(String),
    Reference(usize),
    Skipped,
}

/// Read one attribute, returning its value and the offset after it.
fn read_attribute(
    info: &[u8],
    start: usize,
    form: u64,
    address_size: usize,
    endian: Endian,
    strings: &[u8],
    unit_start: usize,
) -> Option<(Value, usize)> {
    let mut cursor = start;
    let value = match form {
        FORM_ADDR => {
            let value = read_uint(info, cursor, address_size, endian)?;
            cursor += address_size;
            Value::Unsigned(value)
        }
        FORM_DATA1 | FORM_FLAG | FORM_REF1 => {
            let value = u64::from(*info.get(cursor)?);
            cursor += 1;
            if form == FORM_REF1 {
                Value::Reference(unit_start + value as usize)
            } else {
                Value::Unsigned(value)
            }
        }
        FORM_DATA2 | FORM_REF2 => {
            let value = u64::from(read_u16(info, cursor, endian)?);
            cursor += 2;
            if form == FORM_REF2 {
                Value::Reference(unit_start + value as usize)
            } else {
                Value::Unsigned(value)
            }
        }
        FORM_DATA4 | FORM_REF4 => {
            let value = u64::from(read_u32(info, cursor, endian)?);
            cursor += 4;
            if form == FORM_REF4 {
                Value::Reference(unit_start + value as usize)
            } else {
                Value::Unsigned(value)
            }
        }
        FORM_DATA8 | FORM_REF8 => {
            let value = read_uint(info, cursor, 8, endian)?;
            cursor += 8;
            if form == FORM_REF8 {
                Value::Reference(unit_start + value as usize)
            } else {
                Value::Unsigned(value)
            }
        }
        FORM_REF_ADDR => {
            // A unit-relative reference in v2 is section-relative here.
            let value = read_u32(info, cursor, endian)? as usize;
            cursor += 4;
            Value::Reference(value)
        }
        FORM_SDATA => {
            let (value, next) = read_sleb(info, cursor)?;
            cursor = next;
            Value::Unsigned(value as u64)
        }
        FORM_UDATA | FORM_REF_UDATA => {
            let (value, next) = read_uleb(info, cursor)?;
            cursor = next;
            if form == FORM_REF_UDATA {
                Value::Reference(unit_start + value as usize)
            } else {
                Value::Unsigned(value)
            }
        }
        FORM_STRING => {
            let rest = info.get(cursor..)?;
            let end = rest.iter().position(|byte| *byte == 0)?;
            cursor += end + 1;
            Value::Str(String::from_utf8_lossy(&rest[..end]).into_owned())
        }
        FORM_STRP => {
            let offset = read_u32(info, cursor, endian)? as usize;
            cursor += 4;
            let rest = strings.get(offset..)?;
            let end = rest
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(rest.len());
            Value::Str(String::from_utf8_lossy(&rest[..end]).into_owned())
        }
        FORM_BLOCK1 => {
            let length = usize::from(*info.get(cursor)?);
            cursor += 1 + length;
            Value::Skipped
        }
        FORM_BLOCK2 => {
            let length = usize::from(read_u16(info, cursor, endian)?);
            cursor += 2 + length;
            Value::Skipped
        }
        FORM_BLOCK4 => {
            let length = read_u32(info, cursor, endian)? as usize;
            cursor += 4 + length;
            Value::Skipped
        }
        FORM_BLOCK => {
            let (length, next) = read_uleb(info, cursor)?;
            cursor = next + length as usize;
            Value::Skipped
        }
        // An indirect form names its real form in the data. Nothing in the
        // corpus uses it, and following it blindly risks desynchronising the
        // whole unit, so the unit is abandoned instead.
        _ => return None,
    };
    if cursor > info.len() {
        return None;
    }
    Some((value, cursor))
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

/// Unsigned little-endian base 128, returning the value and the offset after it.
fn read_uleb(bytes: &[u8], start: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut cursor = start;
    loop {
        let byte = *bytes.get(cursor)?;
        cursor += 1;
        if shift < 64 {
            value |= u64::from(byte & 0x7f) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((value, cursor));
        }
        if shift > 128 {
            return None;
        }
    }
}

/// Signed little-endian base 128.
fn read_sleb(bytes: &[u8], start: usize) -> Option<(i64, usize)> {
    let mut value = 0i64;
    let mut shift = 0u32;
    let mut cursor = start;
    loop {
        let byte = *bytes.get(cursor)?;
        cursor += 1;
        if shift < 64 {
            value |= i64::from(byte & 0x7f) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                value |= -1i64 << shift;
            }
            return Some((value, cursor));
        }
        if shift > 128 {
            return None;
        }
    }
}

const TAG_ARRAY_TYPE: u64 = 0x01;
const TAG_CLASS_TYPE: u64 = 0x02;
const TAG_ENUMERATION_TYPE: u64 = 0x04;
const TAG_FORMAL_PARAMETER: u64 = 0x05;
const TAG_POINTER_TYPE: u64 = 0x0f;
const TAG_COMPILE_UNIT: u64 = 0x11;
const TAG_STRUCTURE_TYPE: u64 = 0x13;
const TAG_SUBROUTINE_TYPE: u64 = 0x15;
const TAG_TYPEDEF: u64 = 0x16;
const TAG_UNION_TYPE: u64 = 0x17;
const TAG_SUBRANGE_TYPE: u64 = 0x21;
const TAG_BASE_TYPE: u64 = 0x24;
const TAG_CONST_TYPE: u64 = 0x26;
const TAG_SUBPROGRAM: u64 = 0x2e;
const TAG_VOLATILE_TYPE: u64 = 0x35;

const AT_NAME: u64 = 0x03;
const AT_BYTE_SIZE: u64 = 0x0b;
const AT_LOW_PC: u64 = 0x11;
const AT_UPPER_BOUND: u64 = 0x2f;
const AT_ENCODING: u64 = 0x3e;
const AT_TYPE: u64 = 0x49;

const FORM_ADDR: u64 = 0x01;
const FORM_BLOCK2: u64 = 0x03;
const FORM_BLOCK4: u64 = 0x04;
const FORM_DATA2: u64 = 0x05;
const FORM_DATA4: u64 = 0x06;
const FORM_DATA8: u64 = 0x07;
const FORM_STRING: u64 = 0x08;
const FORM_BLOCK: u64 = 0x09;
const FORM_BLOCK1: u64 = 0x0a;
const FORM_DATA1: u64 = 0x0b;
const FORM_FLAG: u64 = 0x0c;
const FORM_SDATA: u64 = 0x0d;
const FORM_UDATA: u64 = 0x0f;
const FORM_STRP: u64 = 0x0e;
const FORM_REF_ADDR: u64 = 0x10;
const FORM_REF1: u64 = 0x11;
const FORM_REF2: u64 = 0x12;
const FORM_REF4: u64 = 0x13;
const FORM_REF8: u64 = 0x14;
const FORM_REF_UDATA: u64 = 0x15;

const ATE_BOOLEAN: u64 = 0x02;
const ATE_FLOAT: u64 = 0x04;
const ATE_SIGNED: u64 = 0x05;
const ATE_UNSIGNED: u64 = 0x07;
const ATE_UNSIGNED_CHAR: u64 = 0x08;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_128_integers_round_trip_the_boundary_cases() {
        // A single byte, a multi-byte value, and a negative signed value: the
        // continuation bit and the sign extension are the whole format.
        assert_eq!(read_uleb(&[0x00], 0), Some((0, 1)));
        assert_eq!(read_uleb(&[0x7f], 0), Some((127, 1)));
        assert_eq!(read_uleb(&[0x80, 0x01], 0), Some((128, 2)));
        assert_eq!(read_uleb(&[0xe5, 0x8e, 0x26], 0), Some((624_485, 3)));
        assert_eq!(read_sleb(&[0x7f], 0), Some((-1, 1)));
        assert_eq!(read_sleb(&[0x3f], 0), Some((63, 1)));
        assert_eq!(read_sleb(&[0x40], 0), Some((-64, 1)));
        // A truncated value must fail rather than return a partial one.
        assert_eq!(read_uleb(&[0x80], 0), None);
    }

    /// Build one abbreviation table and one compilation unit describing a
    /// function that returns a pointer to a structure.
    fn synthetic() -> (Vec<u8>, Vec<u8>) {
        // Abbrev 1: compile_unit, has children, name as an inline string.
        // Abbrev 2: subprogram, no children, name, low_pc, type ref4.
        // Abbrev 3: pointer_type, no children, byte_size, type ref4.
        // Abbrev 4: structure_type, no children, name, byte_size.
        let abbrev = vec![
            1,
            TAG_COMPILE_UNIT as u8,
            1,
            AT_NAME as u8,
            FORM_STRING as u8,
            0,
            0,
            2,
            TAG_SUBPROGRAM as u8,
            0,
            AT_NAME as u8,
            FORM_STRING as u8,
            AT_LOW_PC as u8,
            FORM_ADDR as u8,
            AT_TYPE as u8,
            FORM_REF4 as u8,
            0,
            0,
            3,
            TAG_POINTER_TYPE as u8,
            0,
            AT_BYTE_SIZE as u8,
            FORM_DATA1 as u8,
            AT_TYPE as u8,
            FORM_REF4 as u8,
            0,
            0,
            4,
            TAG_STRUCTURE_TYPE as u8,
            0,
            AT_NAME as u8,
            FORM_STRING as u8,
            AT_BYTE_SIZE as u8,
            FORM_DATA2 as u8,
            0,
            0,
            0,
        ];

        let mut body: Vec<u8> = Vec::new();
        // compile_unit
        body.push(1);
        body.extend_from_slice(b"world.cpp\0");
        // subprogram at 0x1000 whose type is the pointer below
        let subprogram_type_fixup = {
            body.push(2);
            body.extend_from_slice(b"allocEntity\0");
            body.extend_from_slice(&0x1000u32.to_le_bytes());
            let at = body.len();
            body.extend_from_slice(&0u32.to_le_bytes());
            at
        };
        // pointer_type -> structure_type
        let pointer_offset = body.len();
        body.push(3);
        body.push(4);
        let pointer_type_fixup = body.len();
        body.extend_from_slice(&0u32.to_le_bytes());
        // structure_type
        let structure_offset = body.len();
        body.push(4);
        body.extend_from_slice(b"World\0");
        body.extend_from_slice(&0x500u16.to_le_bytes());
        // close the compile unit's children
        body.push(0);

        // References are unit-relative, and the header is eleven bytes.
        let header = 11usize;
        let pointer_ref = (pointer_offset + header) as u32;
        let structure_ref = (structure_offset + header) as u32;
        body[subprogram_type_fixup..subprogram_type_fixup + 4]
            .copy_from_slice(&pointer_ref.to_le_bytes());
        body[pointer_type_fixup..pointer_type_fixup + 4]
            .copy_from_slice(&structure_ref.to_le_bytes());

        let mut info: Vec<u8> = Vec::new();
        info.extend_from_slice(&((7 + body.len()) as u32).to_le_bytes());
        info.extend_from_slice(&2u16.to_le_bytes());
        info.extend_from_slice(&0u32.to_le_bytes());
        info.push(4);
        info.extend_from_slice(&body);
        (info, abbrev)
    }

    #[test]
    fn a_pointer_return_resolves_through_its_reference() {
        let (info, abbrev) = synthetic();
        let mut recovered = DebugInfo::default();
        let next = read_unit(&info, 0, &abbrev, &[], Endian::Little, &mut recovered)
            .expect("the unit parses");
        assert_eq!(next, info.len(), "the unit consumes exactly its length");

        let function = recovered
            .functions
            .get(&0x1000)
            .expect("the subprogram is recorded at its entry");
        assert_eq!(function.name, "allocEntity");
        assert_eq!(function.source.as_deref(), Some("world.cpp"));
        match function.return_type.as_ref().expect("a return type") {
            DebugType::Pointer { bits, to } => {
                assert_eq!(*bits, 32);
                assert_eq!(
                    to.as_ref(),
                    &DebugType::Aggregate {
                        name: Some("World".to_owned()),
                        bytes: 0x500
                    }
                );
            }
            other => panic!("expected a pointer return, got {other:?}"),
        }
    }

    #[test]
    fn a_later_dwarf_version_is_skipped_rather_than_misread() {
        // Version 5 moved the header fields. Reading it with this layout would
        // produce a confidently wrong prototype, which is worse than none.
        let (mut info, abbrev) = synthetic();
        info[4..6].copy_from_slice(&5u16.to_le_bytes());
        let mut recovered = DebugInfo::default();
        let next = read_unit(&info, 0, &abbrev, &[], Endian::Little, &mut recovered)
            .expect("the unit is skipped, not failed");
        assert_eq!(next, info.len());
        assert!(
            recovered.functions.is_empty(),
            "an unsupported version must contribute nothing"
        );
    }

    #[test]
    fn a_byte_size_gives_an_aggregate_its_width() {
        let (info, abbrev) = synthetic();
        let mut recovered = DebugInfo::default();
        read_unit(&info, 0, &abbrev, &[], Endian::Little, &mut recovered).expect("parses");
        let function = &recovered.functions[&0x1000];
        let DebugType::Pointer { to, .. } = function.return_type.as_ref().unwrap() else {
            panic!("expected a pointer");
        };
        assert_eq!(to.byte_size(), Some(0x500));
    }
}
