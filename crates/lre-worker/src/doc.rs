//! Packed-document decoder (WORKER-004).
//!
//! The decompiler's `<doc>` response is decoded with the same packed grammar
//! as `ghidra/program/model/pcode/PackedDecode.java` in the pinned Ghidra
//! source tree. This module never reconstructs metadata by parsing rendered
//! C text.
//!
//! `PackedDecode.java:55-77` defines the header and value codes:
//! `0x40` element start, `0x80` element end, `0xc0` attribute; ids use a
//! five-bit header and an optional seven-bit continuation. Attribute values
//! use type codes 1 (boolean), 2/3 (signed integer), 4 (unsigned integer),
//! 5 (address-space), 6 (special space), and 7 (string). Integer payloads
//! are big-endian seven-bit groups. String lengths are themselves encoded as
//! a packed integer before the string bytes (`PackedDecode.java:180-195`).

use lre_model::{Address, AddressSpace, DecompReference, DecompReferenceKind, DecompToken, TokenKind};

/// Token element ids, verified against `ElementId.java` and `ClangToken.java`.
const ELEM_VALUE: u32 = 9;
const ELEM_BREAK: u32 = 17;
const ELEM_FUNCNAME: u32 = 19;
const ELEM_LABEL: u32 = 21;
const ELEM_SYNTAX: u32 = 24;
const ELEM_VARIABLE: u32 = 26;
const ELEM_OP: u32 = 27;
const ELEM_FIELD: u32 = 49;
const ELEM_TYPE: u32 = 60;
const ELEM_COMMENT: u32 = 86;
const ELEM_BITFIELD: u32 = 289;

/// Attribute ids verified against `AttributeId.java` and the Clang token
/// decoders. `ATTRIB_OFF` is used by labels/comments; `ATTRIB_OFFSET` is used
/// by fields and is deliberately not treated as an address.
const ATTRIB_CONTENT: u32 = 1;
const ATTRIB_ID: u32 = 9;
const ATTRIB_NAME: u32 = 14;
const ATTRIB_OFFSET: u32 = 16;
const ATTRIB_SPACE: u32 = 20;
const ATTRIB_COLOR: u32 = 37;
const ATTRIB_OFF: u32 = 39;
const ATTRIB_OPREF: u32 = 41;
const ATTRIB_VARREF: u32 = 42;
const ATTRIB_INDENT: u32 = 38;

const TAG_ELEMENT_START: u8 = 0x40;
const TAG_ELEMENT_END: u8 = 0x80;
const TAG_ATTRIBUTE: u8 = 0xc0;

const TYPECODE_BOOLEAN: u8 = 1;
const TYPECODE_SIGNED_POSITIVE: u8 = 2;
const TYPECODE_SIGNED_NEGATIVE: u8 = 3;
const TYPECODE_UNSIGNED: u8 = 4;
const TYPECODE_SPACE: u8 = 5;
const TYPECODE_SPECIAL: u8 = 6;
const TYPECODE_STRING: u8 = 7;

fn kind_of(eid: u32) -> TokenKind {
    match eid {
        ELEM_VALUE => TokenKind::Value,
        ELEM_BREAK => TokenKind::Break,
        ELEM_FUNCNAME => TokenKind::FuncName,
        ELEM_LABEL => TokenKind::Label,
        ELEM_SYNTAX => TokenKind::Syntax,
        ELEM_VARIABLE => TokenKind::Variable,
        ELEM_OP => TokenKind::Op,
        ELEM_FIELD => TokenKind::Field,
        ELEM_TYPE => TokenKind::Type,
        ELEM_COMMENT => TokenKind::Comment,
        ELEM_BITFIELD => TokenKind::Bitfield,
        _ => TokenKind::Other,
    }
}

fn is_token(eid: u32) -> bool {
    matches!(
        eid,
        ELEM_VALUE
            | ELEM_BREAK
            | ELEM_FUNCNAME
            | ELEM_LABEL
            | ELEM_SYNTAX
            | ELEM_VARIABLE
            | ELEM_OP
            | ELEM_FIELD
            | ELEM_TYPE
            | ELEM_COMMENT
            | ELEM_BITFIELD
    )
}

#[derive(Clone, Debug)]
enum Value {
    Boolean(bool),
    Signed(i64),
    Unsigned(u64),
    Space(u64),
    Special(u8),
    String(String),
}

impl Value {
    fn unsigned(&self) -> Option<u64> {
        match self {
            Self::Unsigned(v) | Self::Space(v) => Some(*v),
            Self::Signed(v) if *v >= 0 => Some(*v as u64),
            _ => None,
        }
    }

    fn signed(&self) -> Option<i64> {
        match self {
            Self::Signed(v) => Some(*v),
            Self::Unsigned(v) => i64::try_from(*v).ok(),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Ctx {
    id: u32,
    color: u8,
    name: Option<String>,
    space: Option<u64>,
    address_offset: Option<u64>,
    reference: Option<DecompReference>,
    datatype_id: Option<u64>,
    indent: Option<i64>,
    content_seen: bool,
}

fn read_id_after_header(packed: &[u8], p: &mut usize, h: u8) -> Option<u32> {
    let mut id = (h & 0x1f) as u32;
    if h & 0x20 != 0 {
        id = (id << 7) | (*packed.get(*p)? & 0x7f) as u32;
        *p += 1;
    }
    Some(id)
}

/// Reads the packed integer used by `PackedDecode.readInteger`.
fn read_groups(packed: &[u8], p: &mut usize, groups: usize) -> Option<u64> {
    let mut value = 0u64;
    for _ in 0..groups {
        value = value.checked_shl(7)? | (*packed.get(*p)? & 0x7f) as u64;
        *p += 1;
    }
    Some(value)
}

/// Reads one complete attribute value, including the string length field.
fn read_value(packed: &[u8], p: &mut usize) -> Option<Value> {
    let type_byte = *packed.get(*p)?;
    *p += 1;
    let type_code = type_byte >> 4;
    let length = (type_byte & 0x0f) as usize;
    match type_code {
        TYPECODE_BOOLEAN => Some(Value::Boolean(length != 0)),
        TYPECODE_SIGNED_POSITIVE =>
            Some(Value::Signed(i64::try_from(read_groups(packed, p, length)?).ok()?)),
        TYPECODE_SIGNED_NEGATIVE => {
            let magnitude = i64::try_from(read_groups(packed, p, length)?).ok()?;
            Some(Value::Signed(magnitude.checked_neg()?))
        }
        TYPECODE_UNSIGNED => Some(Value::Unsigned(read_groups(packed, p, length)?)),
        TYPECODE_SPACE => Some(Value::Space(read_groups(packed, p, length)?)),
        TYPECODE_SPECIAL => Some(Value::Special(length as u8)),
        TYPECODE_STRING => {
            let byte_len = usize::try_from(read_groups(packed, p, length)?).ok()?;
            let bytes = packed.get(*p..p.checked_add(byte_len)?)?;
            *p += byte_len;
            Some(Value::String(String::from_utf8_lossy(bytes).into_owned()))
        }
        // PackedDecode skips unknown value types by their group count. Keep
        // the parser aligned and reject the value rather than guessing its
        // meaning.
        _ => {
            let _ = read_groups(packed, p, length)?;
            None
        }
    }
}

fn token_from_context(ctx: &Ctx, text: String, ram_space_index: Option<u64>) -> DecompToken {
    let address = match (ctx.space, ctx.address_offset) {
        (Some(space), Some(offset)) => {
            let space = match ram_space_index {
                Some(ram) if space == ram => AddressSpace::Ram,
                _ => AddressSpace::Other(format!("space:{space}")),
            };
            Some(Address { space, offset })
        }
        _ => None,
    };
    DecompToken {
        text,
        kind: kind_of(ctx.id),
        color: ctx.color,
        symbol: ctx.name.clone(),
        address,
        reference: ctx.reference.clone(),
        datatype_id: ctx.datatype_id,
        indent: ctx.indent,
    }
}

/// Decodes a packed `<doc>` payload without assuming a RAM-space index.
///
/// Addressed tokens retain the numeric Ghidra space identity as
/// `AddressSpace::Other("space:N")`. Call [`decode_tokens_with_ram_space`]
/// when the worker has loaded the language's actual RAM index.
pub fn decode_tokens(packed: &[u8]) -> Vec<DecompToken> {
    decode_tokens_with_ram_space(packed, None)
}

/// Decodes a packed `<doc>` payload and maps the configured RAM space to the
/// model's typed `AddressSpace::Ram`; all other numeric spaces remain named
/// `Other` values instead of being silently flattened into RAM.
pub fn decode_tokens_with_ram_space(
    packed: &[u8],
    ram_space_index: Option<u64>,
) -> Vec<DecompToken> {
    let mut tokens = Vec::new();
    let mut stack: Vec<Ctx> = Vec::new();
    let mut p = 0usize;
    while p < packed.len() {
        let header = packed[p];
        p += 1;
        match header & 0xc0 {
            TAG_ELEMENT_START => {
                let Some(id) = read_id_after_header(packed, &mut p, header) else {
                    break;
                };
                stack.push(Ctx {
                    id,
                    ..Ctx::default()
                });
            }
            TAG_ELEMENT_END => {
                let Some(id) = read_id_after_header(packed, &mut p, header) else {
                    break;
                };
                let Some(ctx) = stack.pop() else {
                    continue;
                };
                // A malformed close must not make us associate subsequent
                // content with the wrong element. Valid Ghidra streams always
                // close the top id (`PackedDecode.closeElement`, lines 318-330).
                if ctx.id != id {
                    stack.clear();
                    continue;
                }
                // ClangBreak intentionally has no XMLcontent; its Java
                // decoder sets text to empty and carries only ATTRIB_INDENT.
                if ctx.id == ELEM_BREAK && !ctx.content_seen {
                    tokens.push(token_from_context(&ctx, String::new(), ram_space_index));
                }
            }
            TAG_ATTRIBUTE => {
                let Some(attrid) = read_id_after_header(packed, &mut p, header) else {
                    break;
                };
                let Some(value) = read_value(packed, &mut p) else {
                    // A malformed/unknown value cannot be safely skipped
                    // beyond the type-specific parser; stop at this point.
                    break;
                };
                let Some(ctx) = stack.last_mut() else {
                    continue;
                };
                if attrid == ATTRIB_CONTENT {
                    if let Value::String(text) = value {
                        ctx.content_seen = true;
                        let snapshot = ctx.clone();
                        if is_token(snapshot.id) {
                            tokens.push(token_from_context(&snapshot, text, ram_space_index));
                        }
                    }
                } else {
                    match attrid {
                        ATTRIB_COLOR => {
                            if let Some(v) = value.unsigned() {
                                // ClangToken.decode resets out-of-range colors
                                // to DEFAULT_COLOR (ClangToken.java:200-214).
                                ctx.color = u8::try_from(v).ok().filter(|v| *v < 8).unwrap_or(0);
                            }
                        }
                        ATTRIB_NAME => {
                            if let Value::String(name) = value {
                                ctx.name = Some(name);
                            }
                        }
                        ATTRIB_SPACE => {
                            ctx.space = value.unsigned();
                        }
                        ATTRIB_OFF => {
                            ctx.address_offset = value.unsigned();
                        }
                        ATTRIB_OPREF => {
                            if let Some(id) = value.unsigned() {
                                ctx.reference = Some(DecompReference {
                                    kind: DecompReferenceKind::Operation,
                                    id,
                                });
                            }
                        }
                        ATTRIB_VARREF => {
                            if let Some(id) = value.unsigned() {
                                ctx.reference = Some(DecompReference {
                                    kind: DecompReferenceKind::Varnode,
                                    id,
                                });
                            }
                        }
                        ATTRIB_ID => {
                            ctx.datatype_id = value.unsigned();
                        }
                        ATTRIB_INDENT => {
                            ctx.indent = value.signed();
                        }
                        // ATTRIB_OFFSET is a structure-field offset, not a
                        // memory address; it is intentionally consumed but not
                        // exposed as `DecompToken.address`.
                        ATTRIB_OFFSET => {}
                        _ => {}
                    }
                }
            }
            // PackedDecode rejects these as top-level stream elements, but a
            // malformed payload should still terminate safely rather than
            // indexing past the buffer.
            _ => break,
        }
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{encode_attribute, encode_header, encode_string_attribute, attr_type};

    fn pack_token(eid: u32, color: u8, text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        encode_header(&mut out, TAG_ELEMENT_START, eid);
        encode_attribute(&mut out, ATTRIB_COLOR, attr_type::UNSIGNED_INT, color as u64);
        encode_string_attribute(&mut out, ATTRIB_CONTENT, text.as_bytes());
        encode_header(&mut out, TAG_ELEMENT_END, eid);
        out
    }

    #[test]
    fn decodes_synthetic_tokens_reconstructing_text() {
        let mut packed = Vec::new();
        packed.extend(pack_token(ELEM_FUNCNAME, 3, "add"));
        packed.extend(pack_token(ELEM_SYNTAX, 6, " "));
        packed.extend(pack_token(ELEM_VARIABLE, 4, "a"));
        let tokens = decode_tokens(&packed);
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0].kind, TokenKind::FuncName);
        assert_eq!(tokens[0].text, "add");
        assert_eq!(tokens[0].color, 3);
        assert_eq!(tokens[2].kind, TokenKind::Variable);
        let joined: String = tokens.iter().map(|t| t.text.as_str()).collect();
        assert_eq!(joined, "add a");
    }

    #[test]
    fn decodes_address_and_reference_attributes() {
        let mut packed = Vec::new();
        encode_header(&mut packed, TAG_ELEMENT_START, ELEM_LABEL);
        encode_attribute(&mut packed, ATTRIB_COLOR, attr_type::UNSIGNED_INT, 2);
        encode_attribute(&mut packed, ATTRIB_SPACE, attr_type::SPACE, 3);
        encode_attribute(&mut packed, ATTRIB_OFF, attr_type::UNSIGNED_INT, 0x400466);
        encode_attribute(&mut packed, ATTRIB_OPREF, attr_type::UNSIGNED_INT, 41);
        encode_string_attribute(&mut packed, ATTRIB_CONTENT, b"loc_400466");
        encode_header(&mut packed, TAG_ELEMENT_END, ELEM_LABEL);
        let tokens = decode_tokens_with_ram_space(&packed, Some(3));
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].address, Some(Address::ram(0x400466)));
        assert_eq!(tokens[0].reference.as_ref().map(|r| r.id), Some(41));
        assert_eq!(tokens[0].text, "loc_400466");
    }

    #[test]
    fn decodes_break_without_content() {
        let mut packed = Vec::new();
        encode_header(&mut packed, TAG_ELEMENT_START, ELEM_BREAK);
        encode_attribute(&mut packed, ATTRIB_INDENT, attr_type::POSITIVE_INT, 4);
        encode_header(&mut packed, TAG_ELEMENT_END, ELEM_BREAK);
        let tokens = decode_tokens(&packed);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].kind, TokenKind::Break);
        assert_eq!(tokens[0].text, "");
        assert_eq!(tokens[0].indent, Some(4));
    }

    #[test]
    fn decodes_captured_real_doc() {
        // Real packed `<doc>` from the pinned x86-64 decompiler worker.
        let raw = include_bytes!("../fixtures/doc_add.bin");
        let tokens = decode_tokens_with_ram_space(raw, Some(3));
        assert!(!tokens.is_empty(), "real doc decodes to tokens");
        let text: String = tokens.iter().map(|t| t.text.as_str()).collect();
        assert!(
            text.contains("add") && text.contains("return") && text.contains("param"),
            "reconstructed text should be the C body: {text}"
        );
        assert!(tokens.iter().any(|t| t.color > 0), "colors populated");
        assert!(tokens
            .iter()
            .any(|t| t.kind == TokenKind::FuncName || t.kind == TokenKind::Variable));
        assert!(
            tokens.iter().any(|t| t.reference.is_some()),
            "specialized token references are retained"
        );
    }
}
