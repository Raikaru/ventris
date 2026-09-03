//! Wire framing for the pinned `ghidra_opt` protocol.
//!
//! Two layers, both transcribed from the pinned C++ (third_party/ghidra/
//! decompiler/): burst framing from ghidra_arch.cc (comment block above
//! `readToAnyBurst`), and the packed element encoding from marshal.hh
//! (`PackedFormat` namespace constants). A mismatch here is a hung worker,
//! so every constant cites its source line semantics.

/// Header-mask comparisons for provider.rs (PackedFormat constants).
pub const HEADER_MASK_EQ: u8 = 0xc0;
pub const ELEMENT_START_EQ: u8 = 0x40;
pub const ELEMENT_END_EQ: u8 = 0x80;
pub const ATTRIBUTE_EQ: u8 = 0xc0;

/// Burst codes (ghidra_arch.cc: open alignment is even, close is odd).
pub mod burst {
    /// Command stream from the client (us) to the decompiler.
    pub const COMMAND_OPEN: u8 = 0x02;
    /// Command stream terminator.
    pub const COMMAND_CLOSE: u8 = 0x03;
    /// Query issued by the decompiler mid-command; we must answer.
    pub const QUERY_OPEN: u8 = 0x04;
    /// Query terminator.
    pub const QUERY_CLOSE: u8 = 0x05;
    /// Our answer to a decompiler command (e.g. registerProgram).
    pub const RESPONSE_OPEN: u8 = 0x06;
    /// Command-response terminator.
    pub const RESPONSE_CLOSE: u8 = 0x07;
    /// The decompiler's answer to our query.
    pub const QRESPONSE_OPEN: u8 = 0x08;
    /// Query-response terminator.
    pub const QRESPONSE_CLOSE: u8 = 0x09;
    /// Exception from either side; cancels the current command.
    pub const EXCEP_OPEN: u8 = 0x0a;
    /// Exception terminator.
    pub const EXCEP_CLOSE: u8 = 0x0b;
    /// Raw byte stream (e.g. getBytes payload in hex-ish 'A'-biased form).
    pub const BYTESTREAM_OPEN: u8 = 0x0c;
    /// Byte-stream terminator.
    pub const BYTESTREAM_CLOSE: u8 = 0x0d;
    /// UTF-8 string stream (most parameters and results).
    pub const STRINGSTREAM_OPEN: u8 = 0x0e;
    /// String-stream terminator.
    pub const STRINGSTREAM_CLOSE: u8 = 0x0f;
}

/// A burst is one or more NUL bytes, then 0x01, then the code byte.
pub fn encode_burst(out: &mut Vec<u8>, code: u8) {
    out.push(0);
    out.push(0);
    out.push(0x01);
    out.push(code);
}

/// Reads one burst from `data` at `*pos`, returning the code byte.
/// Returns `None` at end-of-input (peer closed the pipe).
pub fn decode_burst(data: &[u8], pos: &mut usize) -> Option<u8> {
    loop {
        if *pos >= data.len() {
            return None;
        }
        let b = data[*pos];
        *pos += 1;
        match b {
            0 => continue,              // alignment
            0x01 => {                    // code follows
                if *pos >= data.len() {
                    return None;
                }
                let code = data[*pos];
                *pos += 1;
                return Some(code);
            }
            _ => return Some(b),         // lenient: some peers emit bare codes
        }
    }
}

/// Wraps `payload` in a string stream (open code, bytes, close code).
pub fn encode_string_stream(out: &mut Vec<u8>, payload: &[u8]) {
    encode_burst(out, burst::STRINGSTREAM_OPEN);
    out.extend_from_slice(payload);
    encode_burst(out, burst::STRINGSTREAM_CLOSE);
}

// ---- Packed element encoding (marshal.hh PackedFormat) --------------------

/// Element-start header with a 5-bit id and no extension bit set.
pub const ELEMENT_START: u8 = 0x40;
/// Element-end header.
pub const ELEMENT_END: u8 = 0x80;
/// Attribute header.
pub const ATTRIBUTE: u8 = 0xc0;
// ---- Element/attribute ids (pinned from the C++ tables) -------------------
// marshal.cc:1264-1265 register ELEM_DATA/ELEM_INPUT; the ids below are the
// ones the protocol paths actually use, each cited to its defining file.
pub mod elem {
    /// ELEM_ADDR (address.cc:25)
    pub const ADDR: u32 = 11;
    /// ELEM_RANGELIST (address.cc:27)
    pub const RANGELIST: u32 = 13;
    /// ELEM_SYMBOL (marshal.cc type table)
    pub const SYMBOL: u32 = 6;
    /// ELEM_FUNCTIONSHELL (database.cc:34)
    pub const FUNCTIONSHELL: u32 = 72;
    /// ELEM_MAPSYM (database.cc:38)
    pub const MAPSYM: u32 = 76;
    /// ELEM_FUNCTION (funcdata.cc:23)
    pub const FUNCTION: u32 = 116;
    /// ELEM_DOC (ghidra_process.cc:73).
    pub const DOC: u32 = 229;
    /// ELEM_TRACKED_POINTSET (globalcontext.cc:25).
    pub const TRACKED_POINTSET: u32 = 125;
    /// ELEM_HOLE (database.cc:36).
    pub const HOLE: u32 = 74;
    /// ELEM_PARENT (database.cc:39).
    pub const PARENT: u32 = 77;
    /// ELEM_EXTERNREFSYMBOL (database.cc:32).
    pub const EXTERNREFSYMBOL: u32 = 70;
    /// ELEM_COMMENT (comment.cc:21).
    pub const COMMENT: u32 = 86;
    /// ELEM_COMMENTDB (comment.cc:22).
    pub const COMMENTDB: u32 = 87;
    /// ELEM_TEXT (comment.cc:23).
    pub const TEXT: u32 = 88;
    /// ELEM_TYPE (type.cc:67).
    pub const TYPE: u32 = 60;
    /// ELEM_TYPEREF (type.cc:70).
    pub const TYPEREF: u32 = 63;
}

pub mod attr {
    /// ATTRIB_CONTENT (marshal.cc:1232).
    pub const CONTENT: u32 = 1;
    /// ATTRIB_ID (marshal.cc:1240).
    pub const ID: u32 = 9;
    /// ATTRIB_NAME (marshal.cc:1245).
    pub const NAME: u32 = 14;
    /// ATTRIB_LABEL (jumptable.cc:23; shared marshaling id).
    pub const LABEL: u32 = 131;
    /// ATTRIB_OFFSET (marshal.cc:1247).
    pub const OFFSET: u32 = 16;
    /// ATTRIB_SIZE (marshal.cc:1252).
    pub const SIZE: u32 = 19;
    /// ATTRIB_SPACE (marshal.cc:1253).
    pub const SPACE: u32 = 20;
    /// ATTRIB_METATYPE (marshal.cc:1243).
    pub const METATYPE: u32 = 12;
    /// ATTRIB_TYPE (marshal.cc:1253).
    pub const TYPE: u32 = 22;
    /// ATTRIB_FIRST (address.cc:21).
    pub const FIRST: u32 = 27;
    /// ATTRIB_LAST (address.cc:22).
    pub const LAST: u32 = 28;
    /// ATTRIB_MAXSIZE (fspec.cc:27).
    pub const MAXSIZE: u32 = 120;
}

/// Query element ids (ghidra_arch.cc:30-48); these are what the decompiler
/// puts at the root of an interleaved query's packed payload.
pub mod query {
    pub const ISNAMEUSED: u32 = 239;
    pub const GETBYTES: u32 = 240;
    pub const GETCALLFIXUP: u32 = 241;
    pub const GETCALLMECH: u32 = 242;
    pub const GETCALLOTHERFIXUP: u32 = 243;
    pub const GETCODELABEL: u32 = 244;
    pub const GETCOMMENTS: u32 = 245;
    pub const GETCPOOLREF: u32 = 246;
    pub const GETDATATYPE: u32 = 247;
    pub const GETEXTERNALREF: u32 = 248;
    pub const GETMAPPEDSYMBOLS: u32 = 249;
    pub const GETNAMESPACEPATH: u32 = 250;
    pub const GETPCODE: u32 = 251;
    pub const GETPCODEEXECUTABLE: u32 = 252;
    pub const GETREGISTER: u32 = 253;
    pub const GETREGISTERNAME: u32 = 254;
    pub const GETSTRINGDATA: u32 = 255;
    pub const GETTRACKEDREGISTERS: u32 = 256;
    pub const GETUSEROPNAME: u32 = 257;
}

/// Follow-on bytes have bit 0x80 set, 7 bits of payload.
pub const RAWDATA_MARKER: u8 = 0x80;

/// Attribute type codes (marshal.hh).
pub mod attr_type {
    /// Boolean, lengthcode 0=false 1=true, no integer payload.
    pub const BOOLEAN: u8 = 1;
    /// Positive signed integer.
    pub const POSITIVE_INT: u8 = 2;
    /// Negative signed integer (negated form).
    pub const NEGATIVE_INT: u8 = 3;
    /// Unsigned integer.
    pub const UNSIGNED_INT: u8 = 4;
    /// Address space, encoded as its index.
    pub const SPACE: u8 = 5;
    /// String; integer payload is the byte length.
    pub const STRING: u8 = 7;
}

/// Encodes a 7-bit-per-byte integer, matching PackedEncode::encodeLength.
/// Zero emits a single type-byte with lengthcode 0.
pub fn encode_packed_int(out: &mut Vec<u8>, value: u64) {
    if value == 0 {
        return; // lengthcode 0 handled by the caller's type byte
    }
    // Ground truth (PackedEncode::encodeLength, marshal.cc): every 7-bit
    // group carries RAWDATA_MARKER, written most-significant group first.
    let mut sa = 63 - value.leading_zeros(); // highest set bit index
    sa -= sa % 7;                            // align to a group boundary
    while sa > 0 {
        let piece = ((value >> sa) & 0x7f) as u8 | RAWDATA_MARKER;
        out.push(piece);
        sa -= 7;
    }
    out.push(((value & 0x7f) as u8) | RAWDATA_MARKER);
}

/// Writes a packed element/attribute header per PackedEncode::writeHeader
/// (marshal.hh:661): ids <= 0x1f are one byte `base|id`; larger ids get the
/// extension bit plus `id>>7` in the header and one follow-on byte.
pub fn encode_header(out: &mut Vec<u8>, base: u8, id: u32) {
    if id > 0x1f {
        out.push(base | 0x20 | ((id >> 7) & 0x1f) as u8);
        out.push(0x80 | (id & 0x7f) as u8);
    } else {
        out.push(base | id as u8);
    }
}

/// Writes one attribute with a scalar integer value: header, type byte with
/// the group count, then the 7-bit groups (most significant first).
pub fn encode_attribute(out: &mut Vec<u8>, id: u32, type_code: u8, value: u64) {
    encode_header(out, ATTRIBUTE, id);
    let mut groups = Vec::new();
    encode_packed_int(&mut groups, value);
    out.push((type_code << 4) | groups.len() as u8);
    out.extend_from_slice(&groups);
}

/// Writes a string attribute (type 7): length-count groups + raw bytes.
pub fn encode_string_attribute(out: &mut Vec<u8>, id: u32, value: &[u8]) {
    encode_header(out, ATTRIBUTE, id);
    let mut groups = Vec::new();
    encode_packed_int(&mut groups, value.len() as u64);
    out.push((attr_type::STRING << 4) | groups.len() as u8);
    out.extend_from_slice(&groups);
    out.extend_from_slice(value);
}

/// Encodes a plain `<addr>` (ELEM_ADDR + space/offset), matching
/// AddressXML.encode(encoder, addr): NO size attribute.
pub fn encode_addr_element(out: &mut Vec<u8>, space_index: u32, offset: u64) {
    encode_header(out, ELEMENT_START, elem::ADDR);
    encode_attribute(out, attr::SPACE, attr_type::SPACE, space_index as u64);
    encode_attribute(out, attr::OFFSET, attr_type::UNSIGNED_INT, offset);
    encode_header(out, ELEMENT_END, elem::ADDR);
}

/// Encodes a `<addr>` with a size attribute (AddressXML.encode(addr, size)),
/// used for getregister answers and function storage entries. Size is a
/// signed integer (writeSignedInteger; positive values use type 2).
pub fn encode_addr_element_size(out: &mut Vec<u8>, space_index: u32, offset: u64, size: u64) {
    encode_header(out, ELEMENT_START, elem::ADDR);
    encode_attribute(out, attr::SPACE, attr_type::SPACE, space_index as u64);
    encode_attribute(out, attr::OFFSET, attr_type::UNSIGNED_INT, offset);
    encode_attribute(out, attr::SIZE, attr_type::POSITIVE_INT, size);
    encode_header(out, ELEMENT_END, elem::ADDR);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_roundtrip() {
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::COMMAND_OPEN);
        buf.extend_from_slice(b"registerProgram");
        assert_eq!(buf[3], 0x02);
        let mut pos = 0;
        assert_eq!(decode_burst(&buf, &mut pos), Some(burst::COMMAND_OPEN));
    }

    #[test]
    fn decode_skips_alignment_nuls() {
        let data = [0u8, 0, 0, 0x01, burst::QUERY_OPEN, 0, 0x01, burst::QUERY_CLOSE];
        let mut pos = 0;
        assert_eq!(decode_burst(&data, &mut pos), Some(burst::QUERY_OPEN));
        assert_eq!(decode_burst(&data, &mut pos), Some(burst::QUERY_CLOSE));
        assert_eq!(decode_burst(&data, &mut pos), None);
    }

    #[test]
    fn packed_int_most_significant_first() {
        // 300 = 0b10_0101100 -> groups 2, 0x2c -> 0x82, 0x2c
        let mut out = Vec::new();
        encode_packed_int(&mut out, 300);
        assert_eq!(out, vec![0x82, 0xac]);
    }

    #[test]
    fn header_extension_for_large_ids() {
        // PackedEncode::writeHeader (marshal.hh:661): id > 0x1f gets the
        // extension bit plus id>>7 in the header and one 0x80-marked byte.
        let mut out = Vec::new();
        encode_header(&mut out, ATTRIBUTE, 240);
        assert_eq!(out, vec![0xe1, 0xf0]);
        let mut out = Vec::new();
        encode_header(&mut out, ELEMENT_START, elem::DOC);
        assert_eq!(out, vec![0x61, 0xe5]);
    }

    #[test]
    fn addr_element_shape_matches_java() {
        // AddressXML.encode(encoder, addr): <addr space offset> packed.
        // Element 11; attrs SPACE(20,type 5) and OFFSET(16,type 4).
        let mut out = Vec::new();
        encode_addr_element(&mut out, 3, 0x40047a);
        assert_eq!(out, vec![
            0x4b,             // element 11
            0xd4, 0x51, 0x83, // attr 20, type 5, 1 group: 3
            0xd0, 0x44, 0x82, 0x80, 0x88, 0xfa, // attr 16, type 4, 4 groups
            0x8b,             // element end 11
        ]);
    }
}
