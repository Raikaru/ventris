//! Deciding whether two values are the same without solving the graph.
//!
//! Port of `functionalEqualityLevel0` and `functionalEqualityLevel` from
//! Ghidra 12.1.3's `expression.cc`. The question these answer is narrower than
//! equivalence: they compare two definition trees one level at a time and stop
//! at the first pair they cannot immediately settle, reporting that pair back to
//! the caller. `ConditionalJoin` uses that pair as the value the merged block
//! has to phi together.

use ventris_pcode::op;

use super::{Funcdata, VarnodeId};

/// What comparing one pair of values immediately establishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    /// The values are the same.
    Same,
    /// They are not, or it cannot be settled here.
    Different,
    /// Settled only by comparing their definitions.
    Deeper,
}

/// `functionalEqualityLevel0`: the comparison that needs no definitions.
fn level0(data: &Funcdata, first: VarnodeId, second: VarnodeId) -> Level {
    if first == second {
        return Level::Same;
    }
    let (left, right) = (data.varnode(first), data.varnode(second));
    if left.size != right.size {
        return Level::Different;
    }
    if left.flags.constant {
        return if right.flags.constant && left.offset == right.offset {
            Level::Same
        } else {
            Level::Different
        };
    }
    if right.flags.constant {
        return Level::Different;
    }
    // A free value has no definition and no guarantee of being the same value on
    // two different paths.
    if is_free(data, first) || is_free(data, second) {
        return Level::Different;
    }
    Level::Deeper
}

fn is_free(data: &Funcdata, value: VarnodeId) -> bool {
    let varnode = data.varnode(value);
    varnode.def.is_none() && !varnode.flags.constant && !varnode.flags.input
}

/// The outcome of comparing two values one level at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Equality {
    /// The two values are the same.
    Same,
    /// They are the same if this remaining pair is.
    Contingent(VarnodeId, VarnodeId),
    /// They are not, or it cannot be immediately verified.
    Different,
}

/// `functionalEqualityLevel`, restricted to the answers its callers accept.
///
/// Ghidra returns the number of unsettled pairs and hands back up to two; every
/// caller that matters here rejects anything above one, so this reports at most
/// one and calls two pairs `Different`.
pub fn functional_equality(data: &Funcdata, first: VarnodeId, second: VarnodeId) -> Equality {
    match level0(data, first, second) {
        Level::Same => return Equality::Same,
        Level::Different => return Equality::Different,
        Level::Deeper => {}
    }
    let (Some(def1), Some(def2)) = (data.varnode(first).def, data.varnode(second).def) else {
        return Equality::Different; // Not one level of match found.
    };
    let (op1, op2) = (data.op(def1), data.op(def2));
    let opcode = op1.opcode;
    if opcode != op2.opcode || op1.inputs.len() != op2.inputs.len() {
        return Equality::Different;
    }
    if is_marker(opcode) || is_call(op2.opcode) {
        return Equality::Different;
    }
    if opcode == op::LOAD && op1.seq.address != op2.seq.address {
        // Two loads are assumed to give the same result only when the address is
        // the same and they happen in the same instruction.
        return Equality::Different;
    }
    let mut count = op1.inputs.len();
    if count >= 3 {
        if opcode != op::PTRADD {
            return Equality::Different;
        }
        // The element size must match, and then only the pointer and index
        // matter.
        let (Some(size1), Some(size2)) = (op1.inputs.get(2), op2.inputs.get(2)) else {
            return Equality::Different;
        };
        if data.varnode(*size1).offset != data.varnode(*size2).offset {
            return Equality::Different;
        }
        count = 2;
    }
    let left = [op1.inputs[0], *op1.inputs.get(1).unwrap_or(&op1.inputs[0])];
    let right = [op2.inputs[0], *op2.inputs.get(1).unwrap_or(&op2.inputs[0])];

    let first_pair = level0(data, left[0], right[0]);
    if first_pair == Level::Same {
        // A match locks in this comparison ordering.
        if count == 1 {
            return Equality::Same;
        }
        return match level0(data, left[1], right[1]) {
            Level::Same => Equality::Same,
            Level::Different => Equality::Different,
            // Contingent on the second pair.
            Level::Deeper => Equality::Contingent(left[1], right[1]),
        };
    }
    if count == 1 {
        return match first_pair {
            Level::Deeper => Equality::Contingent(left[0], right[0]),
            _ => Equality::Different,
        };
    }
    let second_pair = level0(data, left[1], right[1]);
    if second_pair == Level::Same {
        // A match on the second locks the ordering, leaving the first.
        return match first_pair {
            Level::Deeper => Equality::Contingent(left[0], right[0]),
            _ => Equality::Different,
        };
    }
    // Both pairs unsettled: two remaining pairs, which no caller here accepts,
    // unless commuting the operands settles one of them outright.
    if !is_commutative(opcode) {
        return Equality::Different;
    }
    let crossed1 = level0(data, left[0], right[1]);
    let crossed2 = level0(data, left[1], right[0]);
    if crossed1 == Level::Same && crossed2 == Level::Same {
        return Equality::Same;
    }
    if crossed1 == Level::Different || crossed2 == Level::Different {
        return Equality::Different;
    }
    if crossed1 == Level::Same {
        return Equality::Contingent(left[1], right[0]);
    }
    if crossed2 == Level::Same {
        return Equality::Contingent(left[0], right[1]);
    }
    // Both orderings leave two pairs. Ghidra reports two and picks an ordering;
    // every caller here rejects two, so the ordering does not matter.
    Equality::Different
}

fn is_marker(opcode: i32) -> bool {
    matches!(opcode, op::MULTIEQUAL | op::INDIRECT)
}

fn is_call(opcode: i32) -> bool {
    matches!(opcode, op::CALL | op::CALLIND | op::CALLOTHER)
}

fn is_commutative(opcode: i32) -> bool {
    matches!(
        opcode,
        op::INT_EQUAL
            | op::INT_NOTEQUAL
            | op::INT_ADD
            | op::INT_CARRY
            | op::INT_SCARRY
            | op::INT_XOR
            | op::INT_AND
            | op::INT_OR
            | op::INT_MULT
            | op::BOOL_XOR
            | op::BOOL_AND
            | op::BOOL_OR
            | op::FLOAT_EQUAL
            | op::FLOAT_NOTEQUAL
            | op::FLOAT_ADD
            | op::FLOAT_MULT
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SeqNum;

    fn seq() -> SeqNum {
        SeqNum {
            address: 0x1000,
            order: 0,
        }
    }

    #[test]
    fn identical_values_and_constants_are_the_same() {
        let mut data = Funcdata::default();
        let value = data.new_varnode(ventris_lifter::REGISTER_SPACE, 0, 4);
        assert_eq!(functional_equality(&data, value, value), Equality::Same);

        let four = data.new_constant(4, 4);
        let also_four = data.new_constant(4, 4);
        let five = data.new_constant(5, 4);
        assert_eq!(
            functional_equality(&data, four, also_four),
            Equality::Same,
            "two constants of one value are one value"
        );
        assert_eq!(functional_equality(&data, four, five), Equality::Different);
    }

    #[test]
    fn one_differing_operand_is_reported_as_the_contingency() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let base = data.new_varnode(ventris_lifter::REGISTER_SPACE, 0, 4);
        // Both operands must be written: two values with no definition cannot be
        // assumed to hold the same thing, which is what `isFree` rules out.
        let one = {
            let source = data.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
            let copy = data.new_op(op::COPY, seq(), vec![source]);
            let out = data.new_unique(4);
            data.op_set_output(copy, Some(out));
            data.op_insert_end(copy, block);
            out
        };
        let other = {
            let source = data.new_varnode(ventris_lifter::REGISTER_SPACE, 16, 4);
            let copy = data.new_op(op::COPY, seq(), vec![source]);
            let out = data.new_unique(4);
            data.op_set_output(copy, Some(out));
            data.op_insert_end(copy, block);
            out
        };

        // base + one  versus  base + other
        let first = data.new_op(op::INT_ADD, seq(), vec![base, one]);
        let left = data.new_unique(4);
        data.op_set_output(first, Some(left));
        data.op_insert_end(first, block);
        let second = data.new_op(op::INT_ADD, seq(), vec![base, other]);
        let right = data.new_unique(4);
        data.op_set_output(second, Some(right));
        data.op_insert_end(second, block);

        assert_eq!(
            functional_equality(&data, left, right),
            Equality::Contingent(one, other),
            "the shared operand locks the ordering and leaves the pair that differs"
        );
    }

    #[test]
    fn different_operators_are_not_compared_further() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let base = data.new_varnode(ventris_lifter::REGISTER_SPACE, 0, 4);
        let zero = data.new_constant(0, 4);

        // The guard and latch of a rotated loop test opposite polarities, and
        // this is what stops them being treated as one test.
        let equal = data.new_op(op::INT_EQUAL, seq(), vec![base, zero]);
        let left = data.new_unique(1);
        data.op_set_output(equal, Some(left));
        data.op_insert_end(equal, block);
        let unequal = data.new_op(op::INT_NOTEQUAL, seq(), vec![base, zero]);
        let right = data.new_unique(1);
        data.op_set_output(unequal, Some(right));
        data.op_insert_end(unequal, block);

        assert_eq!(functional_equality(&data, left, right), Equality::Different);
    }
}
