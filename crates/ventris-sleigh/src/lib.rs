//! Reader and execution model for Ghidra 12.1.3 compiled SLEIGH specifications.
//!
//! The `.sla` wire format is defined by Ghidra's Apache-2.0-licensed
//! `slaformat.cc` and `marshal.cc`. It is a four-byte `sla\x04` header followed
//! by a zlib stream containing packed element, attribute, and value records.

#![forbid(unsafe_code)]

use std::error::Error;
mod decision;
mod emit;
mod resolve;
mod template;

pub use decision::{
    Constructor, DecisionNode, DecisionPair, Pattern, PatternBlock, ResolveError, SleighSpec,
    SpecError, Subtable, SymbolHeader,
};
pub use emit::{EmitError, FixedHandle, TemplateContext, emit_template};
pub use resolve::{
    ConstructorEmitError, EmittedInstruction, HandleError, emit_constructor, emit_instruction,
    emit_instruction_details, resolve_operand_handles,
};
pub use template::{
    ConstTemplate, ConstructTemplate, HandleSelector, HandleTemplate, OperationTemplate,
    VarnodeTemplate,
};

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

/// Ghidra 12.1.3 PowerPC big-endian compiled language specification.
pub const POWERPC32_BE_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/ppc_32_be.sla");
/// Ghidra 12.1.3 Gekko/Broadway specification from Ghidra-GameCube-Loader.
pub const GAMECUBE_GEKKO_SLA: &[u8] =
    include_bytes!("../specs/Ghidra_12.1.3/ppc_gekko_broadway.sla");
/// Ghidra 12.1.3 x86-64 compiled language specification.
pub const X86_64_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/x86-64.sla");
/// Ghidra 12.1.3 x86-32 compiled language specification.
pub const X86_32_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/x86.sla");
/// Ghidra 12.1.3 little-endian AArch64 compiled language specification.
pub const AARCH64_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/AARCH64.sla");
/// Ghidra 12.1.3 ARMv8 little-endian compiled language specification.
pub const ARM32_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/ARM8_le.sla");
/// Ghidra 12.1.3 ARMv4T little-endian compiled language specification.
pub const THUMB_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/ARM4t_le.sla");
/// Ghidra 12.1.3 little-endian MIPS32 compiled language specification.
pub const MIPS32_LE_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/mips32le.sla");
/// Ghidra 12.1.3 big-endian MIPS32 compiled language specification.
pub const MIPS32_BE_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/mips32be.sla");
/// Ghidra 12.1.3 big-endian MIPS64 compiled language specification.
pub const MIPS64_BE_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/mips64be.sla");
/// Ghidra 12.1.3 little-endian MIPS64 compiled language specification.
pub const MIPS64_LE_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/mips64le.sla");
/// Apache-2.0 Emotion Engine R5900 specification from
/// chaoticgd/ghidra-emotionengine-reloaded, compiled by Ghidra 12.1.3.
///
/// The generic MIPS64 little-endian language cannot decode the R5900's
/// multimedia (MMI) or COP2/VU macro-mode instructions, so retail PS2 code
/// fails constructor resolution under it.
pub const PS2_R5900_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/r5900.sla");
/// Ghidra 12.1.3 big-endian PowerPC64 compiled language specification.
pub const POWERPC64_BE_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/ppc_64_be.sla");
/// Ghidra 12.1.3 RISC-V ILP32D compiled language specification.
pub const RISCV32_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/riscv.ilp32d.sla");
/// Ghidra 12.1.3 RISC-V LP64D compiled language specification.
pub const RISCV64_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/riscv.lp64d.sla");
/// Ghidra 12.1.3 Motorola 68020 compiled language specification.
pub const M68020_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/68020.sla");
/// Ghidra 12.1.3 SuperH-2 compiled language specification.
pub const SH2_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/sh-2.sla");
/// Ghidra 12.1.3 little-endian SuperH-4 compiled language specification.
pub const SH4_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/SuperH4_le.sla");
/// Ghidra 12.1.3 MOS 6502 compiled language specification.
pub const M6502_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/6502.sla");
/// Ghidra 12.1.3 Z80 compiled language specification.
pub const Z80_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/z80.sla");
/// Apache-2.0 Cell SPU specification from aerosoul94/GhidraSPU, compiled by Ghidra 12.1.3.
pub const SPU_SLA: &[u8] = include_bytes!("../specs/Ghidra_12.1.3/spu.sla");
/// Ghidra 12.1.3's compiled SLA container version.
pub const FORMAT_VERSION: u8 = 4;
/// Header accepted by Ghidra 12.1.3 `isSlaFormat`.
pub const MAGIC: [u8; 4] = [b's', b'l', b'a', FORMAT_VERSION];
/// Numeric identifier assigned to `ELEM_SLEIGH` in `slaformat.cc`.
pub const ELEM_SLEIGH: u16 = 33;
/// Default guard against decompression bombs in untrusted specifications.
pub const DEFAULT_DECOMPRESSED_LIMIT: usize = 64 * 1024 * 1024;

const HEADER_MASK: u8 = 0xc0;
const ELEMENT_START: u8 = 0x40;
const ELEMENT_END: u8 = 0x80;
const ATTRIBUTE: u8 = 0xc0;
const HEADER_EXTEND_MASK: u8 = 0x20;
const ELEMENT_ID_MASK: u8 = 0x1f;
const RAW_DATA_MASK: u8 = 0x7f;
const RAW_DATA_MARKER: u8 = 0x80;
const TYPE_CODE_SHIFT: u8 = 4;
const LENGTH_CODE_MASK: u8 = 0x0f;
const TYPE_BOOLEAN: u8 = 1;
const TYPE_SIGNED_POSITIVE: u8 = 2;
const TYPE_SIGNED_NEGATIVE: u8 = 3;
const TYPE_UNSIGNED: u8 = 4;
const TYPE_ADDRESS_SPACE: u8 = 5;
const TYPE_SPECIAL_SPACE: u8 = 6;
const TYPE_STRING: u8 = 7;
const MAX_ELEMENT_DEPTH: usize = 1024;

/// Fully decoded compiled-SLEIGH container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlaArtifact {
    pub root: Element,
    pub compressed_len: usize,
    pub decoded_len: usize,
}

impl SlaArtifact {
    /// Reads and decodes an SLA file with the default decompressed-size limit.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, SlaError> {
        let bytes = fs::read(path).map_err(SlaError::Io)?;
        Self::from_bytes(&bytes)
    }

    /// Decodes an SLA container with the default decompressed-size limit.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SlaError> {
        Self::from_bytes_with_limit(bytes, DEFAULT_DECOMPRESSED_LIMIT)
    }

    /// Decodes an SLA container while bounding its inflated payload.
    pub fn from_bytes_with_limit(bytes: &[u8], limit: usize) -> Result<Self, SlaError> {
        if bytes.len() < MAGIC.len() || bytes[..MAGIC.len()] != MAGIC {
            return Err(SlaError::InvalidHeader {
                actual: bytes.get(..MAGIC.len()).unwrap_or(bytes).to_vec(),
            });
        }

        let packed =
            miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&bytes[MAGIC.len()..], limit)
                .map_err(|error| SlaError::Decompression(format!("{error:?}")))?;
        let root = PackedDecoder::new(&packed).decode_document()?;
        if root.id != ELEM_SLEIGH {
            return Err(SlaError::WrongRoot {
                expected: ELEM_SLEIGH,
                actual: root.id,
            });
        }

        Ok(Self {
            root,
            compressed_len: bytes.len() - MAGIC.len(),
            decoded_len: packed.len(),
        })
    }
}

/// One packed element from the `ELEM_SLEIGH` hierarchy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Element {
    pub id: u16,
    pub attributes: Vec<Attribute>,
    pub children: Vec<Element>,
}

impl Element {
    pub fn attribute(&self, id: u16) -> Option<&AttributeValue> {
        self.attributes
            .iter()
            .find(|attribute| attribute.id == id)
            .map(|attribute| &attribute.value)
    }

    pub fn descendants(&self) -> Descendants<'_> {
        Descendants { stack: vec![self] }
    }
}

/// Pre-order iterator including the root element.
pub struct Descendants<'a> {
    stack: Vec<&'a Element>,
}

impl<'a> Iterator for Descendants<'a> {
    type Item = &'a Element;

    fn next(&mut self) -> Option<Self::Item> {
        let element = self.stack.pop()?;
        self.stack.extend(element.children.iter().rev());
        Some(element)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attribute {
    pub id: u16,
    pub value: AttributeValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttributeValue {
    Boolean(bool),
    Signed(i64),
    Unsigned(u64),
    AddressSpace(u64),
    SpecialSpace(SpecialSpace),
    String(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpecialSpace {
    Stack,
    Join,
    Fspec,
    Iop,
    Spacebase,
}

#[derive(Debug)]
pub enum SlaError {
    Io(io::Error),
    InvalidHeader { actual: Vec<u8> },
    Decompression(String),
    Packed { offset: usize, message: String },
    WrongRoot { expected: u16, actual: u16 },
}

impl fmt::Display for SlaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "failed to read SLA file: {error}"),
            Self::InvalidHeader { actual } => write!(
                formatter,
                "invalid SLA header: expected {:?}, found {actual:?}",
                MAGIC
            ),
            Self::Decompression(error) => {
                write!(formatter, "failed to inflate SLA payload: {error}")
            }
            Self::Packed { offset, message } => {
                write!(formatter, "invalid packed SLA at byte {offset}: {message}")
            }
            Self::WrongRoot { expected, actual } => write!(
                formatter,
                "invalid SLA root element: expected id {expected}, found {actual}"
            ),
        }
    }
}

impl Error for SlaError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

struct PackedDecoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> PackedDecoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn decode_document(mut self) -> Result<Element, SlaError> {
        if self.input.is_empty() {
            return self.fail("empty packed stream");
        }
        let root = self.decode_element(0)?;
        if self.offset != self.input.len() {
            return self.fail(format!(
                "{} trailing byte(s) after the root element",
                self.input.len() - self.offset
            ));
        }
        Ok(root)
    }

    fn decode_element(&mut self, depth: usize) -> Result<Element, SlaError> {
        if depth >= MAX_ELEMENT_DEPTH {
            return self.fail(format!("element nesting exceeds {MAX_ELEMENT_DEPTH}"));
        }
        let (kind, id) = self.read_header()?;
        if kind != ELEMENT_START {
            return self.fail(format!(
                "expected element start, found record kind {kind:#04x}"
            ));
        }

        let mut attributes = Vec::new();
        while self.peek_kind()? == ATTRIBUTE {
            attributes.push(self.decode_attribute()?);
        }

        let mut children = Vec::new();
        while self.peek_kind()? == ELEMENT_START {
            children.push(self.decode_element(depth + 1)?);
        }

        let (kind, closing_id) = self.read_header()?;
        if kind != ELEMENT_END {
            return self.fail(format!(
                "expected element end, found record kind {kind:#04x}"
            ));
        }
        if closing_id != id {
            return self.fail(format!(
                "closing element id {closing_id} does not match opening id {id}"
            ));
        }

        Ok(Element {
            id,
            attributes,
            children,
        })
    }

    fn decode_attribute(&mut self) -> Result<Attribute, SlaError> {
        let (kind, id) = self.read_header()?;
        if kind != ATTRIBUTE {
            return self.fail(format!("expected attribute, found record kind {kind:#04x}"));
        }
        let type_byte = self.read_byte()?;
        let type_code = type_byte >> TYPE_CODE_SHIFT;
        let length_code = usize::from(type_byte & LENGTH_CODE_MASK);
        let value = match type_code {
            TYPE_BOOLEAN => match length_code {
                0 => AttributeValue::Boolean(false),
                1 => AttributeValue::Boolean(true),
                _ => return self.fail(format!("invalid boolean code {length_code}")),
            },
            TYPE_SIGNED_POSITIVE => {
                let value = self.read_integer(length_code)?;
                let value = i64::try_from(value)
                    .map_err(|_| self.error("positive signed integer exceeds i64"))?;
                AttributeValue::Signed(value)
            }
            TYPE_SIGNED_NEGATIVE => {
                let magnitude = self.read_integer(length_code)?;
                let value = if magnitude == (1_u64 << 63) {
                    i64::MIN
                } else {
                    -i64::try_from(magnitude)
                        .map_err(|_| self.error("negative signed integer exceeds i64"))?
                };
                AttributeValue::Signed(value)
            }
            TYPE_UNSIGNED => AttributeValue::Unsigned(self.read_integer(length_code)?),
            TYPE_ADDRESS_SPACE => AttributeValue::AddressSpace(self.read_integer(length_code)?),
            TYPE_SPECIAL_SPACE => AttributeValue::SpecialSpace(match length_code {
                0 => SpecialSpace::Stack,
                1 => SpecialSpace::Join,
                2 => SpecialSpace::Fspec,
                3 => SpecialSpace::Iop,
                4 => SpecialSpace::Spacebase,
                _ => return self.fail(format!("invalid special address-space code {length_code}")),
            }),
            TYPE_STRING => {
                let length = self.read_integer(length_code)?;
                let length = usize::try_from(length)
                    .map_err(|_| self.error("string length exceeds platform usize"))?;
                let bytes = self.take(length)?;
                let value = std::str::from_utf8(bytes)
                    .map_err(|error| self.error(format!("invalid UTF-8 string: {error}")))?;
                AttributeValue::String(value.to_owned())
            }
            _ => return self.fail(format!("unknown attribute type code {type_code}")),
        };
        Ok(Attribute { id, value })
    }

    fn read_integer(&mut self, length: usize) -> Result<u64, SlaError> {
        if length > 10 {
            return self.fail(format!(
                "integer length {length} exceeds Ghidra uint8 encoding"
            ));
        }
        let mut value = 0_u64;
        for index in 0..length {
            let byte = self.read_byte()?;
            if byte & RAW_DATA_MARKER == 0 {
                return self.fail(format!(
                    "integer byte {index} is missing the packed-data marker"
                ));
            }
            value = value
                .checked_shl(7)
                .and_then(|shifted| shifted.checked_add(u64::from(byte & RAW_DATA_MASK)))
                .ok_or_else(|| self.error("integer overflows u64"))?;
        }
        Ok(value)
    }

    fn peek_kind(&self) -> Result<u8, SlaError> {
        self.input
            .get(self.offset)
            .map(|byte| byte & HEADER_MASK)
            .ok_or_else(|| self.error("unexpected end of packed stream"))
    }

    fn read_header(&mut self) -> Result<(u8, u16), SlaError> {
        let first = self.read_byte()?;
        let kind = first & HEADER_MASK;
        if !matches!(kind, ELEMENT_START | ELEMENT_END | ATTRIBUTE) {
            return self.fail(format!("unknown record kind {kind:#04x}"));
        }
        let mut id = u16::from(first & ELEMENT_ID_MASK);
        if first & HEADER_EXTEND_MASK != 0 {
            let extension = self.read_byte()?;
            if extension & RAW_DATA_MARKER == 0 {
                return self.fail("extended id is missing the packed-data marker");
            }
            id = (id << 7) | u16::from(extension & RAW_DATA_MASK);
        }
        Ok((kind, id))
    }

    fn read_byte(&mut self) -> Result<u8, SlaError> {
        let byte = self
            .input
            .get(self.offset)
            .copied()
            .ok_or_else(|| self.error("unexpected end of packed stream"))?;
        self.offset += 1;
        Ok(byte)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], SlaError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| self.error("record length overflow"))?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or_else(|| self.error(format!("record needs {length} byte(s)")))?;
        self.offset = end;
        Ok(bytes)
    }

    fn error(&self, message: impl Into<String>) -> SlaError {
        SlaError::Packed {
            offset: self.offset,
            message: message.into(),
        }
    }

    fn fail<T>(&self, message: impl Into<String>) -> Result<T, SlaError> {
        Err(self.error(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_sla_header() {
        let error = SlaArtifact::from_bytes(b"xml\0").unwrap_err();
        assert!(matches!(error, SlaError::InvalidHeader { .. }));
    }

    #[test]
    fn decodes_packed_tree_and_all_value_kinds() {
        // <sleigh bool=true signed=-5 unsigned=130 space=3 special=join text="ppc"/>
        let packed = [
            0x60, 0xa1, // start element 33
            0xc1, 0x11, // bool attribute 1 = true
            0xc2, 0x31, 0x85, // signed attribute 2 = -5
            0xc3, 0x42, 0x81, 0x82, // unsigned attribute 3 = 130
            0xc4, 0x51, 0x83, // address-space attribute 4 = 3
            0xc5, 0x61, // special-space attribute 5 = join
            0xc6, 0x71, 0x83, b'p', b'p', b'c', // string attribute 6
            0xa0, 0xa1, // end element 33
        ];
        let root = PackedDecoder::new(&packed).decode_document().unwrap();
        assert_eq!(root.id, ELEM_SLEIGH);
        assert_eq!(root.attribute(1), Some(&AttributeValue::Boolean(true)));
        assert_eq!(root.attribute(2), Some(&AttributeValue::Signed(-5)));
        assert_eq!(root.attribute(3), Some(&AttributeValue::Unsigned(130)));
        assert_eq!(root.attribute(4), Some(&AttributeValue::AddressSpace(3)));
        assert_eq!(
            root.attribute(5),
            Some(&AttributeValue::SpecialSpace(SpecialSpace::Join))
        );
        assert_eq!(
            root.attribute(6),
            Some(&AttributeValue::String("ppc".to_owned()))
        );
    }

    #[test]
    fn rejects_mismatched_close() {
        let error = PackedDecoder::new(&[0x41, 0x82])
            .decode_document()
            .unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }
}
