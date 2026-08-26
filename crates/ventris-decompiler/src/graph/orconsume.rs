//! Ghidra's `RuleOrConsume` from `ruleaction.cc`.
//!
//! An `INT_OR` or `INT_XOR` whose operand can only set bits nobody reads
//! contributes nothing, so the operation collapses to a `COPY` of the other
//! operand.
//!
//! This rule was previously recorded as unportable because it needs
//! `Varnode::getConsume` - see the note it replaces in `graph/expr_piece.rs`.
//! `graph/consume.rs` now supplies that, so the gate is gone. Both inputs the
//! rule needs are present: `Funcdata::nonzero_masks` is `getNZMask`, and
//! `consume::consume_masks` is the backwards consume propagation with the
//! calling-convention seed.
//!
//! The two are not interchangeable, which is why the rule needs both: a nonzero
//! mask says which bits *can* be set, consume says which bits anyone reads.

use ventris_pcode::op;

use super::action::Rule;
use super::{Funcdata, OpId};

pub struct RuleOrConsume;

impl Rule for RuleOrConsume {
    fn name(&self) -> &'static str {
        "or_consume"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_OR, op::INT_XOR]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id);
        let Some(output) = operation.output else {
            return 0;
        };
        // `size > sizeof(uintb)` in Ghidra: the mask arithmetic is 64-bit.
        if data.varnode(output).size > 8 {
            return 0;
        }
        let inputs = operation.inputs.clone();
        if inputs.len() < 2 {
            return 0;
        }
        let consume = super::consume::consume_masks(data)
            .get(&output)
            .copied()
            .unwrap_or(0);
        let nonzero = data.nonzero_masks();
        let dead = |slot: usize| {
            let value = inputs[slot];
            let mask = nonzero.get(value.0 as usize).copied().unwrap_or(u64::MAX);
            consume & mask == 0
        };
        // Ghidra tests input 0 first and returns on the first match.
        let drop = if dead(0) {
            0
        } else if dead(1) {
            1
        } else {
            return 0;
        };
        data.op_remove_input(id, drop);
        data.op_set_opcode(id, op::COPY);
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SeqNum;
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    /// An operand that can only set bits nobody reads contributes nothing, so
    /// the `INT_OR` becomes a copy of the surviving operand.
    #[test]
    fn an_or_operand_setting_only_unread_bits_collapses_to_a_copy() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let live = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(live);
        // Only the high byte can be set.
        let high = data.new_constant(0xff00_0000, 4);
        let shifted = data.new_op(op::INT_AND, seq(0x1000), vec![live, high]);
        let high_only = data.new_varnode(REGISTER_SPACE, 4, 4);
        data.op_set_output(shifted, Some(high_only));
        data.op_insert_end(shifted, block);

        let combined = data.new_op(op::INT_OR, seq(0x1004), vec![live, high_only]);
        let result = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(combined, Some(result));
        data.op_insert_end(combined, block);

        // Only the low byte of the result is ever read.
        let low = data.new_constant(0xff, 4);
        let masked = data.new_op(op::INT_AND, seq(0x1008), vec![result, low]);
        let used = data.new_varnode(REGISTER_SPACE, 12, 4);
        data.op_set_output(masked, Some(used));
        data.op_insert_end(masked, block);
        let ret = data.new_op(op::RETURN, seq(0x100c), vec![used, used]);
        data.op_insert_end(ret, block);

        assert_eq!(RuleOrConsume.apply_op(combined, &mut data), 1);
        assert_eq!(data.op(combined).opcode, op::COPY);
        assert_eq!(data.op(combined).inputs, vec![live]);
    }

    /// Both operands reaching read bits means the operation stays.
    #[test]
    fn an_or_whose_operands_are_both_read_is_left_alone() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x2000);
        let left = data.new_varnode(REGISTER_SPACE, 0, 4);
        let right = data.new_varnode(REGISTER_SPACE, 4, 4);
        data.mark_input(left);
        data.mark_input(right);
        let combined = data.new_op(op::INT_OR, seq(0x2000), vec![left, right]);
        let result = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(combined, Some(result));
        data.op_insert_end(combined, block);
        let ret = data.new_op(op::RETURN, seq(0x2004), vec![result, result]);
        data.op_insert_end(ret, block);

        assert_eq!(RuleOrConsume.apply_op(combined, &mut data), 0);
        assert_eq!(data.op(combined).opcode, op::INT_OR);
    }
}
