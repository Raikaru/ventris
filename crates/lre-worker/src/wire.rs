//! Wire framing for the pinned `ghidra_opt` protocol.
//!
//! Two layers, both transcribed from the pinned C++ (third_party/ghidra/
//! decompiler/): burst framing from ghidra_arch.cc (comment block above
//! `readToAnyBurst`), and the packed element encoding from marshal.hh
//! (`PackedFormat` namespace constants). A mismatch here is a hung worker,
//! so every constant cites its source line semantics.

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

/// Writes an attribute header: 0xc0 | (id5 & 0x1f), then the type byte
/// `ttttllll`, then the integer payload. `lengthcode` is caller-computed.
pub fn encode_attribute_header(out: &mut Vec<u8>, id: u32, type_code: u8, length_code: u8) {
    out.push(ATTRIBUTE | (id as u8 & 0x1f));
    out.push((type_code << 4) | length_code);
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
    fn attribute_header_shape() {
        let mut out = Vec::new();
        encode_attribute_header(&mut out, 240, attr_type::STRING, 2);
        // id 240 -> low 5 bits = 16 = 0x10; type STRING=7, len=2 -> 0x72
        assert_eq!(out, vec![0xc0 | 0x10, 0x72]);
    }
}
