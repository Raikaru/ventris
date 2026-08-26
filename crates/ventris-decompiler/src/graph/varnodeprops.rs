//! Ghidra's `ActionVarnodeProps` from `coreaction.cc`, for the branch this
//! graph can express.
//!
//! The pass has three arms. Two of them read state the graph does not carry:
//! `isAutoLiveHold`, and `hasActionProperty` with its read-only load-image
//! lookup and volatile replacement. Those are recorded as gaps rather than
//! guessed at.
//!
//! The third arm is portable and is the semantically load-bearing one:
//!
//! ```text
//! else if (((vn->getNZMask() & vn->getConsume())==0)&&(vnSize<=sizeof(uintb)))
//! ```
//!
//! A value whose possibly-nonzero bits are entirely unconsumed is provably zero
//! everywhere it is read, so Ghidra replaces it with the constant zero. Both
//! inputs exist here: `Funcdata::nonzero_masks` is `getNZMask`, and
//! `deadcode::propagate` is the backwards consume propagation behind
//! `getConsume`.
//!
//! NOT REGISTERED, and the blocker is measured, not assumed. Registering it
//! costs one agreeing corpus function and adds a `missing-parameters` entry.
//!
//! The first hypothesis was that the signature came from statements rather than
//! the prototype; that has since been fixed - `PrintC::emitFunctionDeclaration`
//! is ported and the printer reads the prototype - and the regression survived
//! it. The real cause is narrower: zeroing an input removes its descendants, and
//! a convention-claimed input with no reader is then judged not to be a
//! parameter, so the parameter disappears.
//!
//! Three hypotheses were tested and all three were wrong, so the record is
//! worth keeping:
//!
//! 1. That the signature came from statements rather than the prototype. Fixed -
//!    `PrintC::emitFunctionDeclaration` is ported - and the regression survived.
//! 2. That consume propagation lacked a convention sink. `graph/consume.rs` adds
//!    one, seeding storage `FuncProto::possible_input_param` claims, and the
//!    regression survived that too.
//! 3. That the trial decision counted readers instead of using
//!    `ancestorRealistic`. Switched to `callproto::ancestor_realistic`, and the
//!    regression still survived.
//!
//! The measurement that finally explains it: on
//! `gamecube-animal-crossing-gafe01/osContGetReadData` the Ghidra oracle renders
//! `void FUN_80060668(uint param_1)` - ONE parameter. Without this pass we render
//! `(uint32_t arg0, uint32_t arg1)` and with it `(void)`. So the parameter count
//! was already wrong before this pass ran; the pass converts a two-versus-one
//! error into a zero-versus-one error, and only the latter trips the
//! `missing-parameters` family.
//!
//! The real defect is therefore in the trial decision, which claims a second
//! parameter the convention does not pass. Fix that first; this pass is correct
//! and will register cleanly once the parameter count is right.
//!
//! Note the distinction, because conflating the two is wrong: a nonzero mask
//! says which bits *can* be set, consume says which bits anyone *reads*. Neither
//! substitutes for the other, and the arm needs both.

use std::collections::BTreeMap;

use ventris_pcode::op;

use super::action::Action;
use super::{Funcdata, VarnodeId};

/// Ghidra's `Varnode::getConsume`, which this graph computes rather than stores.
fn consume_masks(data: &Funcdata) -> BTreeMap<VarnodeId, u64> {
    super::consume::consume_masks(data)
}

/// Values that are provably zero at every read, in Ghidra's order.
fn provably_zero(data: &Funcdata) -> Vec<VarnodeId> {
    let nonzero = data.nonzero_masks();
    let consumed = consume_masks(data);
    (0..data.varnode_count())
        .map(|index| VarnodeId(index as u32))
        .filter(|value| {
            let varnode = data.varnode(*value);
            // `vnSize <= sizeof(uintb)`: the mask arithmetic is 64-bit.
            if varnode.size > 8 {
                return false;
            }
            // "Don't replace a constant."
            if varnode.flags.constant {
                return false;
            }
            let mask = nonzero.get(value.0 as usize).copied().unwrap_or(u64::MAX);
            let consume = consumed.get(value).copied().unwrap_or(0);
            if mask & consume != 0 {
                return false;
            }
            // A value nobody reads is dead code's business, not this pass's:
            // Ghidra requires `!vn->hasNoDescend()`.
            if varnode.descendants.is_empty() {
                return false;
            }
            // "Don't replace a COPY 0, with a zero, let constant propagation do
            // that. This prevents an infinite recursion."
            if let Some(def) = varnode.def {
                let definition = data.op(def);
                if definition.opcode == op::COPY
                    && let Some(source) = definition.inputs.first().copied()
                {
                    let source = data.varnode(source);
                    if source.flags.constant && source.offset == 0 {
                        return false;
                    }
                }
            }
            true
        })
        .collect()
}

/// Ports the consume arm of Ghidra's `ActionVarnodeProps`.
pub struct ActionVarnodeProps;

impl Action for ActionVarnodeProps {
    fn name(&self) -> &'static str {
        "varnodeprops"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let mut count = 0;
        for value in provably_zero(data) {
            let size = data.varnode(value).size;
            let zero = data.new_constant(0, size);
            data.total_replace(value, zero);
            count += 1;
        }
        count
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

    /// The whole point of the arm: bits that can be set but are never read make
    /// the value zero where it is used.
    #[test]
    fn a_value_whose_nonzero_bits_are_unconsumed_becomes_zero() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let wide = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(wide);
        // Only the low byte can be nonzero.
        let mask = data.new_constant(0xff00, 4);
        let masked_op = data.new_op(op::INT_AND, seq(0x1000), vec![wide, mask]);
        let masked = data.new_varnode(REGISTER_SPACE, 4, 4);
        data.op_set_output(masked_op, Some(masked));
        data.op_insert_end(masked_op, block);
        // Only the low byte is consumed, and it cannot be set.
        let low = data.new_constant(0xff, 4);
        let consume_op = data.new_op(op::INT_AND, seq(0x1004), vec![masked, low]);
        let consumed = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(consume_op, Some(consumed));
        data.op_insert_end(consume_op, block);
        let ret = data.new_op(op::RETURN, seq(0x1008), vec![consumed, consumed]);
        data.op_insert_end(ret, block);

        let zeroed = provably_zero(&data);
        assert!(
            zeroed.contains(&masked),
            "the masked value is unread in every bit it can set: {zeroed:?}"
        );
    }

    /// Ghidra explicitly refuses this one to avoid recursing with constant
    /// propagation.
    #[test]
    fn a_copy_of_zero_is_left_for_constant_propagation() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x2000);
        let zero = data.new_constant(0, 4);
        let copy = data.new_op(op::COPY, seq(0x2000), vec![zero]);
        let copied = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.op_set_output(copy, Some(copied));
        data.op_insert_end(copy, block);
        let ret = data.new_op(op::RETURN, seq(0x2004), vec![copied, copied]);
        data.op_insert_end(ret, block);

        assert!(!provably_zero(&data).contains(&copied));
    }

    /// A value with a live reader in a consumed bit must survive.
    #[test]
    fn a_consumed_value_is_left_alone() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x3000);
        let left = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(left);
        let one = data.new_constant(1, 4);
        let add = data.new_op(op::INT_ADD, seq(0x3000), vec![left, one]);
        let sum = data.new_varnode(REGISTER_SPACE, 4, 4);
        data.op_set_output(add, Some(sum));
        data.op_insert_end(add, block);
        let ret = data.new_op(op::RETURN, seq(0x3004), vec![sum, sum]);
        data.op_insert_end(ret, block);

        assert!(!provably_zero(&data).contains(&sum));
    }
}
