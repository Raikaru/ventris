//! Expression rules, ported from Ghidra 12.1.3's `ruleaction.cc`.
//!
//! Machine code says things in ways source never does: a comparison against
//! zero of a subtraction, a mask that cannot remove any bit, a negation of a
//! comparison. Each rule here recognises one of those and rewrites it to what
//! the source said, on the graph, so later rules and the printer both see the
//! simpler form.
//!
//! Two of these need to know which bits of a value can be non-zero. That is
//! Ghidra's `Varnode::getNZMask`, computed forward from constants and the
//! operations that bound their results.
//!
//! Source authority: `RuleBoolNegate`, `RuleEquality`, `RuleAndMask`,
//! `RuleTrivialBool`, `RuleSubExtComm`, `RuleEqual2Zero`, and
//! `get_booleanflip` in `ruleaction.cc` and `opcodes.cc` at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use ventris_pcode::op;

use super::action::Rule;
use super::{Funcdata, OpId, VarnodeId};

/// All bits of a value of the given byte size.
fn calc_mask(size: u32) -> u64 {
    match size {
        0 => 0,
        size if size >= 8 => u64::MAX,
        size => (1u64 << (size * 8)) - 1,
    }
}

/// The bits of a value that can be non-zero.
///
/// Ghidra's `Varnode::getNZMask`, computed on demand. Recursion is bounded
/// because each step moves to an operand, and a value that is its own operand
/// through a merge yields the full mask rather than looping.
fn nonzero_mask(data: &Funcdata, value: VarnodeId, depth: u32) -> u64 {
    let varnode = data.varnode(value);
    let full = calc_mask(varnode.size);
    if varnode.flags.constant {
        return varnode.offset & full;
    }
    if depth == 0 {
        return full;
    }
    let Some(def) = varnode.def else { return full };
    let operation = data.op(def);
    let operand = |slot: usize| operation.inputs.get(slot).copied();
    let mask_of = |slot: usize| {
        operand(slot)
            .map(|value| nonzero_mask(data, value, depth - 1))
            .unwrap_or(u64::MAX)
    };
    match operation.opcode {
        op::COPY | op::CAST | op::INT_ZEXT => mask_of(0) & full,
        op::INT_AND => mask_of(0) & mask_of(1) & full,
        op::INT_OR | op::INT_XOR => (mask_of(0) | mask_of(1)) & full,
        op::MULTIEQUAL => {
            operation
                .inputs
                .iter()
                .copied()
                .filter(|input| *input != value)
                .map(|input| nonzero_mask(data, input, depth - 1))
                .fold(0, |accumulated, mask| accumulated | mask)
                & full
        }
        op::INT_LEFT => match operand(1).map(|shift| data.varnode(shift)) {
            Some(shift) if shift.flags.constant && shift.offset < 64 => {
                (mask_of(0) << shift.offset) & full
            }
            _ => full,
        },
        op::INT_RIGHT => match operand(1).map(|shift| data.varnode(shift)) {
            Some(shift) if shift.flags.constant && shift.offset < 64 => {
                (mask_of(0) >> shift.offset) & full
            }
            _ => full,
        },
        // A comparison and a boolean operation produce one bit.
        op::INT_EQUAL
        | op::INT_NOTEQUAL
        | op::INT_LESS
        | op::INT_LESSEQUAL
        | op::INT_SLESS
        | op::INT_SLESSEQUAL
        | op::BOOL_AND
        | op::BOOL_OR
        | op::BOOL_XOR
        | op::BOOL_NEGATE
        | op::FLOAT_EQUAL
        | op::FLOAT_NOTEQUAL
        | op::FLOAT_LESS
        | op::FLOAT_LESSEQUAL => 1,
        _ => full,
    }
}

const MASK_DEPTH: u32 = 8;

/// The opcode that computes the negation of a comparison, and whether its
/// operands must swap. Ghidra's `get_booleanflip`.
fn boolean_flip(opcode: i32) -> Option<(i32, bool)> {
    Some(match opcode {
        op::INT_EQUAL => (op::INT_NOTEQUAL, false),
        op::INT_NOTEQUAL => (op::INT_EQUAL, false),
        op::INT_SLESS => (op::INT_SLESSEQUAL, true),
        op::INT_SLESSEQUAL => (op::INT_SLESS, true),
        op::INT_LESS => (op::INT_LESSEQUAL, true),
        op::INT_LESSEQUAL => (op::INT_LESS, true),
        op::BOOL_NEGATE => (op::COPY, false),
        op::FLOAT_EQUAL => (op::FLOAT_NOTEQUAL, false),
        op::FLOAT_NOTEQUAL => (op::FLOAT_EQUAL, false),
        op::FLOAT_LESS => (op::FLOAT_LESSEQUAL, true),
        op::FLOAT_LESSEQUAL => (op::FLOAT_LESS, true),
        _ => return None,
    })
}

/// `!(a == b)` is `a != b`.
///
/// Ghidra's `RuleBoolNegate`. Every reader of the compared value must be a
/// negation, otherwise flipping the comparison changes what the others see.
pub struct RuleBoolNegate;

impl Rule for RuleBoolNegate {
    fn name(&self) -> &'static str {
        "bool-negate"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::BOOL_NEGATE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(compared) = data.op(id).inputs.first().copied() else {
            return 0;
        };
        let Some(comparison) = data.varnode(compared).def else {
            return 0;
        };
        let readers: Vec<OpId> = data.varnode(compared).descendants.iter().copied().collect();
        if readers.is_empty()
            || readers
                .iter()
                .any(|reader| data.opcode_of(*reader) != Some(op::BOOL_NEGATE))
        {
            return 0;
        }
        let Some((flipped, swap)) = boolean_flip(data.op(comparison).opcode) else {
            return 0;
        };
        data.op_set_opcode(comparison, flipped);
        if swap {
            let inputs = data.op(comparison).inputs.clone();
            if inputs.len() == 2 {
                data.op_set_inputs(comparison, vec![inputs[1], inputs[0]]);
            }
        }
        for reader in readers {
            data.op_set_opcode(reader, op::COPY);
        }
        1
    }
}

/// Comparing a value with itself is a constant.
///
/// Ghidra's `RuleEquality`.
pub struct RuleEquality;

impl Rule for RuleEquality {
    fn name(&self) -> &'static str {
        "equality"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_EQUAL, op::INT_NOTEQUAL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id);
        let (Some(left), Some(right)) = (
            operation.inputs.first().copied(),
            operation.inputs.get(1).copied(),
        ) else {
            return 0;
        };
        if left != right {
            return 0;
        }
        let answer = u64::from(operation.opcode == op::INT_EQUAL);
        let constant = data.new_constant(answer, 1);
        data.op_set_opcode(id, op::COPY);
        data.op_set_inputs(id, vec![constant]);
        1
    }
}

/// A mask that cannot clear a bit is not a mask.
///
/// Ghidra's `RuleAndMask`: if the operands share no possible non-zero bit the
/// result is zero, and if the mask covers every bit the value could have set,
/// the mask does nothing.
pub struct RuleAndMask;

impl Rule for RuleAndMask {
    fn name(&self) -> &'static str {
        "and-mask"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_AND]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id);
        let (Some(output), Some(left), Some(right)) = (
            operation.output,
            operation.inputs.first().copied(),
            operation.inputs.get(1).copied(),
        ) else {
            return 0;
        };
        let width = data.varnode(output).size;
        let left_mask = nonzero_mask(data, left, MASK_DEPTH);
        let right_mask = nonzero_mask(data, right, MASK_DEPTH);
        let combined = left_mask & right_mask;
        let replacement = if combined == 0 {
            data.new_constant(0, width)
        } else if combined == left_mask && data.varnode(right).flags.constant {
            left
        } else if combined == right_mask && data.varnode(left).flags.constant {
            right
        } else {
            return 0;
        };
        data.op_set_opcode(id, op::COPY);
        data.op_set_inputs(id, vec![replacement]);
        1
    }
}

/// A boolean operation against a constant is one of its operands.
///
/// Ghidra's `RuleTrivialBool`.
pub struct RuleTrivialBool;

impl Rule for RuleTrivialBool {
    fn name(&self) -> &'static str {
        "trivial-bool"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::BOOL_AND, op::BOOL_OR, op::BOOL_XOR]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id);
        let (Some(left), Some(right)) = (
            operation.inputs.first().copied(),
            operation.inputs.get(1).copied(),
        ) else {
            return 0;
        };
        let constant = data.varnode(right);
        if !constant.flags.constant {
            return 0;
        }
        let truth = constant.offset != 0;
        let opcode = operation.opcode;
        let (new_opcode, operand) = match (opcode, truth) {
            (op::BOOL_XOR, true) => (op::BOOL_NEGATE, left),
            (op::BOOL_XOR, false) => (op::COPY, left),
            (op::BOOL_AND, true) => (op::COPY, left),
            (op::BOOL_AND, false) => (op::COPY, data.new_constant(0, 1)),
            (op::BOOL_OR, true) => (op::COPY, data.new_constant(1, 1)),
            (op::BOOL_OR, false) => (op::COPY, left),
            _ => return 0,
        };
        data.op_set_opcode(id, new_opcode);
        data.op_set_inputs(id, vec![operand]);
        1
    }
}

/// Truncating an extension that the truncation does not reach.
///
/// Ghidra's `RuleSubExtComm`: `SUBPIECE(ZEXT(x), n)` reads only `x` when the
/// piece taken lies entirely inside `x`.
pub struct RuleSubExtComm;

impl Rule for RuleSubExtComm {
    fn name(&self) -> &'static str {
        "sub-ext-comm"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::SUBPIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id);
        let (Some(output), Some(base), Some(cut)) = (
            operation.output,
            operation.inputs.first().copied(),
            operation.inputs.get(1).copied(),
        ) else {
            return 0;
        };
        let cut = data.varnode(cut);
        if !cut.flags.constant {
            return 0;
        }
        let cut = cut.offset;
        let Some(extension) = data.varnode(base).def else {
            return 0;
        };
        if !matches!(data.op(extension).opcode, op::INT_ZEXT | op::INT_SEXT) {
            return 0;
        }
        let Some(source) = data.op(extension).inputs.first().copied() else {
            return 0;
        };
        let source_size = u64::from(data.varnode(source).size);
        let taken = u64::from(data.varnode(output).size);
        if taken + cut > source_size {
            return 0;
        }
        if source_size == taken && cut == 0 {
            data.op_set_opcode(id, op::COPY);
            data.op_set_inputs(id, vec![source]);
        } else {
            let cut_value = data.new_constant(cut, 4);
            data.op_set_inputs(id, vec![source, cut_value]);
        }
        1
    }
}

/// Comparing a difference with zero is comparing the values.
///
/// Ghidra's `RuleEqual2Zero`: `(x + -c) == 0` is `x == c`. Machine code
/// subtracts and tests the flags; source compares.
pub struct RuleEqual2Zero;

impl Rule for RuleEqual2Zero {
    fn name(&self) -> &'static str {
        "equal-to-zero"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_EQUAL, op::INT_NOTEQUAL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id);
        let (Some(left), Some(right)) = (
            operation.inputs.first().copied(),
            operation.inputs.get(1).copied(),
        ) else {
            return 0;
        };
        // One side must be the constant zero; the other is the difference.
        let (sum, _) = if is_zero(data, left) {
            (right, left)
        } else if is_zero(data, right) {
            (left, right)
        } else {
            return 0;
        };
        let Some(add) = data.varnode(sum).def else {
            return 0;
        };
        if data.op(add).opcode != op::INT_ADD {
            return 0;
        }
        // Rewriting the comparison leaves the sum's other readers reading a
        // value that is no longer compared, so require the sum be compared
        // only here.
        if data.varnode(sum).descendants.len() != 1 {
            return 0;
        }
        let (Some(base), Some(offset)) = (
            data.op(add).inputs.first().copied(),
            data.op(add).inputs.get(1).copied(),
        ) else {
            return 0;
        };
        let offset_value = data.varnode(offset);
        if !offset_value.flags.constant {
            return 0;
        }
        let width = offset_value.size;
        let negated = offset_value.offset.wrapping_neg() & calc_mask(width);
        let compared = data.new_constant(negated, width);
        data.op_set_inputs(id, vec![base, compared]);
        1
    }
}

fn is_zero(data: &Funcdata, value: VarnodeId) -> bool {
    let varnode = data.varnode(value);
    varnode.flags.constant && varnode.offset == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SeqNum;
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    #[test]
    fn negating_an_equality_flips_it() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_varnode(REGISTER_SPACE, 8, 4);
        let right = data.new_constant(5, 4);
        let compare = data.new_op(op::INT_EQUAL, seq(0x1000), vec![left, right]);
        let flag = data.new_unique(1);
        data.op_set_output(compare, Some(flag));
        data.op_insert_end(compare, block);
        let negate = data.new_op(op::BOOL_NEGATE, seq(0x1004), vec![flag]);
        let negated = data.new_unique(1);
        data.op_set_output(negate, Some(negated));
        data.op_insert_end(negate, block);

        assert_eq!(RuleBoolNegate.apply_op(negate, &mut data), 1);
        assert_eq!(data.op(compare).opcode, op::INT_NOTEQUAL);
        assert_eq!(data.op(negate).opcode, op::COPY);
    }

    #[test]
    fn negating_a_less_than_swaps_its_operands() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_varnode(REGISTER_SPACE, 8, 4);
        let right = data.new_varnode(REGISTER_SPACE, 16, 4);
        let compare = data.new_op(op::INT_LESS, seq(0x1000), vec![left, right]);
        let flag = data.new_unique(1);
        data.op_set_output(compare, Some(flag));
        data.op_insert_end(compare, block);
        let negate = data.new_op(op::BOOL_NEGATE, seq(0x1004), vec![flag]);
        let negated = data.new_unique(1);
        data.op_set_output(negate, Some(negated));
        data.op_insert_end(negate, block);

        assert_eq!(RuleBoolNegate.apply_op(negate, &mut data), 1);
        assert_eq!(data.op(compare).opcode, op::INT_LESSEQUAL);
        assert_eq!(
            data.op(compare).inputs,
            vec![right, left],
            "not (a < b) is b <= a"
        );
    }

    #[test]
    fn a_comparison_with_another_reader_is_left_alone() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_varnode(REGISTER_SPACE, 8, 4);
        let right = data.new_constant(5, 4);
        let compare = data.new_op(op::INT_EQUAL, seq(0x1000), vec![left, right]);
        let flag = data.new_unique(1);
        data.op_set_output(compare, Some(flag));
        data.op_insert_end(compare, block);
        let negate = data.new_op(op::BOOL_NEGATE, seq(0x1004), vec![flag]);
        let negated = data.new_unique(1);
        data.op_set_output(negate, Some(negated));
        data.op_insert_end(negate, block);
        let target = data.new_constant(0x1010, 4);
        let branch = data.new_op(op::CBRANCH, seq(0x1008), vec![target, flag]);
        data.op_insert_end(branch, block);

        assert_eq!(
            RuleBoolNegate.apply_op(negate, &mut data),
            0,
            "another reader still wants the unflipped comparison"
        );
    }

    #[test]
    fn comparing_a_value_with_itself_is_constant() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = data.new_varnode(REGISTER_SPACE, 8, 4);
        let compare = data.new_op(op::INT_EQUAL, seq(0x1000), vec![value, value]);
        let flag = data.new_unique(1);
        data.op_set_output(compare, Some(flag));
        data.op_insert_end(compare, block);

        assert_eq!(RuleEquality.apply_op(compare, &mut data), 1);
        assert_eq!(data.op(compare).opcode, op::COPY);
        let answer = data.op(compare).inputs[0];
        assert_eq!(data.varnode(answer).offset, 1);
    }

    #[test]
    fn masking_bits_a_value_cannot_have_set_yields_the_value() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        // A comparison produces one bit, so masking with 0xff changes nothing.
        let left = data.new_varnode(REGISTER_SPACE, 8, 4);
        let right = data.new_constant(0, 4);
        let compare = data.new_op(op::INT_EQUAL, seq(0x1000), vec![left, right]);
        let flag = data.new_unique(4);
        data.op_set_output(compare, Some(flag));
        data.op_insert_end(compare, block);
        let mask = data.new_constant(0xff, 4);
        let and = data.new_op(op::INT_AND, seq(0x1004), vec![flag, mask]);
        let masked = data.new_unique(4);
        data.op_set_output(and, Some(masked));
        data.op_insert_end(and, block);

        assert_eq!(RuleAndMask.apply_op(and, &mut data), 1);
        assert_eq!(data.op(and).opcode, op::COPY);
        assert_eq!(data.op(and).inputs, vec![flag]);
    }

    #[test]
    fn masking_away_every_bit_yields_zero() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = data.new_constant(0x0f, 4);
        let mask = data.new_constant(0xf0, 4);
        let and = data.new_op(op::INT_AND, seq(0x1000), vec![value, mask]);
        let masked = data.new_unique(4);
        data.op_set_output(and, Some(masked));
        data.op_insert_end(and, block);

        assert_eq!(RuleAndMask.apply_op(and, &mut data), 1);
        let result = data.op(and).inputs[0];
        assert!(data.varnode(result).flags.constant);
        assert_eq!(data.varnode(result).offset, 0);
    }

    #[test]
    fn a_real_mask_is_kept() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = data.new_varnode(REGISTER_SPACE, 8, 4);
        let mask = data.new_constant(0xff, 4);
        let and = data.new_op(op::INT_AND, seq(0x1000), vec![value, mask]);
        let masked = data.new_unique(4);
        data.op_set_output(and, Some(masked));
        data.op_insert_end(and, block);

        assert_eq!(
            RuleAndMask.apply_op(and, &mut data),
            0,
            "the mask really does clear the upper bytes"
        );
    }

    #[test]
    fn boolean_and_with_false_is_false() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = data.new_varnode(REGISTER_SPACE, 8, 1);
        let constant = data.new_constant(0, 1);
        let and = data.new_op(op::BOOL_AND, seq(0x1000), vec![value, constant]);
        let out = data.new_unique(1);
        data.op_set_output(and, Some(out));
        data.op_insert_end(and, block);

        assert_eq!(RuleTrivialBool.apply_op(and, &mut data), 1);
        assert_eq!(data.op(and).opcode, op::COPY);
        let result = data.op(and).inputs[0];
        assert!(data.varnode(result).flags.constant);
        assert_eq!(data.varnode(result).offset, 0);
    }

    #[test]
    fn boolean_xor_with_true_is_negation() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = data.new_varnode(REGISTER_SPACE, 8, 1);
        let constant = data.new_constant(1, 1);
        let xor = data.new_op(op::BOOL_XOR, seq(0x1000), vec![value, constant]);
        let out = data.new_unique(1);
        data.op_set_output(xor, Some(out));
        data.op_insert_end(xor, block);

        assert_eq!(RuleTrivialBool.apply_op(xor, &mut data), 1);
        assert_eq!(data.op(xor).opcode, op::BOOL_NEGATE);
        assert_eq!(data.op(xor).inputs, vec![value]);
    }

    #[test]
    fn truncating_inside_an_extension_reads_the_original() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let narrow = data.new_varnode(REGISTER_SPACE, 8, 4);
        let extend = data.new_op(op::INT_ZEXT, seq(0x1000), vec![narrow]);
        let wide = data.new_unique(8);
        data.op_set_output(extend, Some(wide));
        data.op_insert_end(extend, block);
        let cut = data.new_constant(0, 4);
        let truncate = data.new_op(op::SUBPIECE, seq(0x1004), vec![wide, cut]);
        let piece = data.new_unique(4);
        data.op_set_output(truncate, Some(piece));
        data.op_insert_end(truncate, block);

        assert_eq!(RuleSubExtComm.apply_op(truncate, &mut data), 1);
        assert_eq!(data.op(truncate).opcode, op::COPY);
        assert_eq!(data.op(truncate).inputs, vec![narrow]);
    }

    #[test]
    fn truncating_into_the_extended_bits_is_kept() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let narrow = data.new_varnode(REGISTER_SPACE, 8, 4);
        let extend = data.new_op(op::INT_ZEXT, seq(0x1000), vec![narrow]);
        let wide = data.new_unique(8);
        data.op_set_output(extend, Some(wide));
        data.op_insert_end(extend, block);
        let cut = data.new_constant(4, 4);
        let truncate = data.new_op(op::SUBPIECE, seq(0x1004), vec![wide, cut]);
        let piece = data.new_unique(4);
        data.op_set_output(truncate, Some(piece));
        data.op_insert_end(truncate, block);

        assert_eq!(
            RuleSubExtComm.apply_op(truncate, &mut data),
            0,
            "the piece taken is entirely extension"
        );
    }

    #[test]
    fn comparing_a_difference_with_zero_compares_the_values() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = data.new_varnode(REGISTER_SPACE, 8, 4);
        // Machine code computes x + (-5) and tests against zero.
        let offset = data.new_constant(0xffff_fffb, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![value, offset]);
        let difference = data.new_unique(4);
        data.op_set_output(add, Some(difference));
        data.op_insert_end(add, block);
        let zero = data.new_constant(0, 4);
        let compare = data.new_op(op::INT_EQUAL, seq(0x1004), vec![difference, zero]);
        let flag = data.new_unique(1);
        data.op_set_output(compare, Some(flag));
        data.op_insert_end(compare, block);

        assert_eq!(RuleEqual2Zero.apply_op(compare, &mut data), 1);
        assert_eq!(data.op(compare).inputs[0], value);
        let compared = data.op(compare).inputs[1];
        assert_eq!(data.varnode(compared).offset, 5, "x + -5 == 0 is x == 5");
    }

    #[test]
    fn a_difference_used_elsewhere_is_left_alone() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = data.new_varnode(REGISTER_SPACE, 8, 4);
        let offset = data.new_constant(0xffff_fffb, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![value, offset]);
        let difference = data.new_unique(4);
        data.op_set_output(add, Some(difference));
        data.op_insert_end(add, block);
        let zero = data.new_constant(0, 4);
        let compare = data.new_op(op::INT_EQUAL, seq(0x1004), vec![difference, zero]);
        let flag = data.new_unique(1);
        data.op_set_output(compare, Some(flag));
        data.op_insert_end(compare, block);
        let ret = data.new_op(op::RETURN, seq(0x1008), vec![difference]);
        data.op_insert_end(ret, block);

        assert_eq!(
            RuleEqual2Zero.apply_op(compare, &mut data),
            0,
            "the difference itself is still used"
        );
    }

    #[test]
    fn a_merge_of_bounded_values_stays_bounded() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let low = data.new_constant(0x0f, 4);
        let high = data.new_constant(0xf0, 4);
        let phi = data.new_op(op::MULTIEQUAL, seq(0x1000), vec![low, high]);
        let merged = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(phi, Some(merged));
        data.op_insert_end(phi, block);

        assert_eq!(
            nonzero_mask(&data, merged, MASK_DEPTH),
            0xff,
            "the merge can only have bits either path can set"
        );
    }
}
