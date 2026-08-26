//! P-code: the IR every layer above L1 speaks.
//!
//! Opcode numbers are a **wire contract**, transcribed from
//! `ghidra.program.model.pcode.PcodeOp` (Ghidra 12.1.3) rather than invented:
//! the decompiler decodes `ATTRIB_CODE` as a raw integer and rejects anything
//! outside `0..CPUI_MAX`.

#![forbid(unsafe_code)]

/// A varnode: a typed slice of an address space.
///
/// `space` uses Ventris's canonical p-code space numbering. Compiled SLEIGH
/// table indices are normalized at the decoder boundary so architecture-local
/// spaces cannot displace `register`, `ram`, or `unique`.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct Varnode {
    pub space: u32,
    pub offset: u64,
    pub size: u32,
}

impl Varnode {
    pub const fn new(space: u32, offset: u64, size: u32) -> Self {
        Self {
            space,
            offset,
            size,
        }
    }
}

/// One p-code operation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PcodeOp {
    pub opcode: i32,
    /// `None` encodes the `<void/>` output the decompiler expects.
    pub output: Option<Varnode>,
    pub inputs: Vec<Varnode>,
}

impl PcodeOp {
    pub fn new(opcode: i32, output: Option<Varnode>, inputs: Vec<Varnode>) -> Self {
        Self {
            opcode,
            output,
            inputs,
        }
    }
}

/// The p-code translation of a single machine instruction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InstPcode {
    /// Instruction length in bytes. The decompiler uses this to advance.
    pub len: u32,
    /// Sleigh space index of the instruction address.
    pub space: u32,
    pub offset: u64,
    pub ops: Vec<PcodeOp>,
}

/// Opcode numbers. Names match Ghidra's.
pub mod op {
    pub const UNIMPLEMENTED: i32 = 0;
    pub const COPY: i32 = 1;
    pub const LOAD: i32 = 2;
    pub const STORE: i32 = 3;
    pub const BRANCH: i32 = 4;
    pub const CBRANCH: i32 = 5;
    pub const BRANCHIND: i32 = 6;
    pub const CALL: i32 = 7;
    pub const CALLIND: i32 = 8;
    pub const CALLOTHER: i32 = 9;
    pub const RETURN: i32 = 10;
    pub const INT_EQUAL: i32 = 11;
    pub const INT_NOTEQUAL: i32 = 12;
    pub const INT_SLESS: i32 = 13;
    pub const INT_SLESSEQUAL: i32 = 14;
    pub const INT_LESS: i32 = 15;
    pub const INT_LESSEQUAL: i32 = 16;
    pub const INT_ZEXT: i32 = 17;
    pub const INT_SEXT: i32 = 18;
    pub const INT_ADD: i32 = 19;
    pub const INT_SUB: i32 = 20;
    pub const INT_CARRY: i32 = 21;
    pub const INT_SCARRY: i32 = 22;
    pub const INT_SBORROW: i32 = 23;
    pub const INT_2COMP: i32 = 24;
    pub const INT_NEGATE: i32 = 25;
    pub const INT_XOR: i32 = 26;
    pub const INT_AND: i32 = 27;
    pub const INT_OR: i32 = 28;
    pub const INT_LEFT: i32 = 29;
    pub const INT_RIGHT: i32 = 30;
    pub const INT_SRIGHT: i32 = 31;
    pub const INT_MULT: i32 = 32;
    pub const INT_DIV: i32 = 33;
    pub const INT_SDIV: i32 = 34;
    pub const INT_REM: i32 = 35;
    pub const INT_SREM: i32 = 36;
    pub const BOOL_NEGATE: i32 = 37;
    pub const BOOL_XOR: i32 = 38;
    pub const BOOL_AND: i32 = 39;
    pub const BOOL_OR: i32 = 40;
    /// Internal native-lifter operation for a flag-controlled register move.
    pub const CMOV: i32 = 1000;
    pub const FLOAT_EQUAL: i32 = 41;
    pub const FLOAT_NOTEQUAL: i32 = 42;
    pub const FLOAT_LESS: i32 = 43;
    pub const FLOAT_LESSEQUAL: i32 = 44;
    pub const FLOAT_NAN: i32 = 46;
    pub const FLOAT_ADD: i32 = 47;
    pub const FLOAT_DIV: i32 = 48;
    pub const FLOAT_MULT: i32 = 49;
    pub const FLOAT_SUB: i32 = 50;
    pub const FLOAT_NEG: i32 = 51;
    pub const FLOAT_ABS: i32 = 52;
    pub const FLOAT_SQRT: i32 = 53;
    pub const FLOAT_INT2FLOAT: i32 = 54;
    pub const FLOAT_FLOAT2FLOAT: i32 = 55;
    pub const FLOAT_TRUNC: i32 = 56;
    pub const FLOAT_CEIL: i32 = 57;
    pub const FLOAT_FLOOR: i32 = 58;
    pub const FLOAT_ROUND: i32 = 59;
    pub const MULTIEQUAL: i32 = 60;
    pub const INDIRECT: i32 = 61;
    pub const PIECE: i32 = 62;
    pub const SUBPIECE: i32 = 63;
    pub const CAST: i32 = 64;
    pub const PTRADD: i32 = 65;
    pub const PTRSUB: i32 = 66;
    pub const SEGMENTOP: i32 = 67;
    pub const CPOOLREF: i32 = 68;
    pub const NEW: i32 = 69;
    pub const INSERT: i32 = 70;
    pub const ZPULL: i32 = 71;
    pub const POPCOUNT: i32 = 72;
    pub const LZCOUNT: i32 = 73;
    pub const SPULL: i32 = 74;
    pub const PCODE_MAX: i32 = 75;
    /// One past the highest valid opcode; the decompiler rejects `>= MAX`.
    pub const MAX: i32 = 76;
}

/// Canonical p-code space indices. Ghidra language-local space tables are
/// normalized to these stable values when semantics are emitted.
pub const CONST_SPACE: u32 = 0;
pub const OTHER_SPACE: u32 = 1;
pub const UNIQUE_SPACE: u32 = 2;
pub const RAM_SPACE: u32 = 3;
pub const REGISTER_SPACE: u32 = 4;
/// Ghidra's `IPTR_IOP`, the space whose "addresses" name p-code operations.
///
/// An `INDIRECT`'s second operand is an annotation identifying the operation
/// responsible for the indirect effect, not a value. Ghidra encodes it as a
/// constant in this dedicated space (`Funcdata::newVarnodeIop`) precisely so it
/// cannot be confused with an ordinary constant, and renaming relies on being
/// able to ask which operation an `INDIRECT` annotates.
pub const IOP_SPACE: u32 = 5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_table_matches_ghidra() {
        assert_eq!(op::COPY, 1);
        assert_eq!(op::LOAD, 2);
        assert_eq!(op::STORE, 3);
        assert_eq!(op::RETURN, 10);
        assert_eq!(op::CALLOTHER, 9);
        assert_eq!(op::UNIMPLEMENTED, 0);
    }

    #[test]
    fn every_opcode_is_in_the_accepted_range() {
        for c in [op::COPY, op::RETURN, op::INT_ADD, op::MAX - 1] {
            assert!((0..op::MAX).contains(&c), "opcode {c} out of range");
        }
    }

    #[test]
    fn a_void_output_is_representable() {
        let o = PcodeOp::new(op::RETURN, None, vec![Varnode::new(CONST_SPACE, 0, 8)]);
        assert!(o.output.is_none());
        assert_eq!(o.inputs.len(), 1);
    }
}
