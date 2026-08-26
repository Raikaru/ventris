//! Non-zero bit masks for the graph, ported from Ghidra 12.1.3.
//!
//! The implementation follows `Funcdata::calcNZMask` in `funcdata_varnode.cc`,
//! `PcodeOp::getNZMaskLocal` in `op.cc`, and `Varnode::getNZMask` in
//! `varnode.hh` at commit `8b4c91d4d5bd1549622bfbade0df199585b98365`.
//!
//! A mask contains bits which may be non-zero.  Starting at the conservative
//! full mask and repeatedly applying the local transfer functions is important:
//! a loop-carried `MULTIEQUAL` is not a finite-depth expression tree.

use ventris_pcode::op;

use super::action::Action;
use super::{Funcdata, OpId, VarnodeId};

/// A non-zero mask for every varnode in a [`Funcdata`] graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonzeroMasks {
    masks: Vec<u64>,
}

impl NonzeroMasks {
    /// Calculate masks to a graph fixpoint.
    ///
    /// Prefer `Funcdata::nonzero_masks`, which caches this. Recomputing per
    /// rule application is what made the expression fixpoint quadratic.
    pub fn of(data: &Funcdata) -> Self {
        let mut masks = Vec::with_capacity(data.varnode_count());
        for index in 0..data.varnode_count() {
            let id = VarnodeId(index as u32);
            let value = data.varnode(id);
            let full = full_mask(value.size);
            masks.push(if value.flags.constant {
                value.offset & full
            } else {
                full
            });
        }

        // Every transfer is monotone over the "may be non-zero" lattice when
        // initialized to top.  Revisit the entire live graph until no output
        // changes; unlike a recursive depth limit this also settles cycles.
        loop {
            let mut changed = false;
            let operations: Vec<OpId> = data.live_ops().map(|(id, _)| id).collect();
            for id in operations {
                let operation = data.op(id);
                let Some(output) = operation.output else {
                    continue;
                };
                let next = local_mask(data, operation, &masks);
                if masks[output.0 as usize] != next {
                    masks[output.0 as usize] = next;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        Self { masks }
    }

    /// Return the mask for one varnode.
    pub fn mask(&self, value: VarnodeId) -> u64 {
        self.masks[value.0 as usize]
    }

    /// Number of values for which the analysis learned at least one zero bit.
    ///
    /// `Funcdata` deliberately does not store analysis properties, so an
    /// action cannot compare against an older graph-owned mask.  This count is
    /// the observable amount of information recovered over the initial full
    /// masks and is therefore the useful action change count.
    fn constrained_count(&self, data: &Funcdata) -> usize {
        self.masks
            .iter()
            .enumerate()
            .filter(|(index, mask)| {
                **mask != full_mask(data.varnode(VarnodeId(*index as u32)).size)
            })
            .count()
    }
}

/// Recompute all non-zero masks.
///
/// Ghidra's `ActionNonzeroMask::apply` calls `Funcdata::calcNZMask`.  The
/// graph model keeps analysis results outside `Funcdata`, so `apply` returns
/// the number of values made more precise than their conservative full mask.
pub struct ActionNonzeroMask;

impl Action for ActionNonzeroMask {
    fn name(&self) -> &'static str {
        "nonzeromask"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let masks = NonzeroMasks::of(data);
        masks.constrained_count(data)
    }
}

fn full_mask(size: u32) -> u64 {
    let bits = u64::from(size).saturating_mul(8);
    if bits == 0 {
        0
    } else if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn clip(mask: u64, size: u32) -> u64 {
    mask & full_mask(size)
}

fn low_mask(bits: u32) -> u64 {
    if bits == 0 {
        0
    } else if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn covering_mask(mask: u64) -> u64 {
    if mask == 0 {
        return 0;
    }
    let highest = 63 - mask.leading_zeros();
    low_mask(highest + 1)
}

fn least_set(mask: u64) -> Option<u32> {
    (mask != 0).then_some(mask.trailing_zeros())
}

fn most_set(mask: u64) -> Option<u32> {
    (mask != 0).then_some(63 - mask.leading_zeros())
}

fn sign_extend_mask(mask: u64, input_size: u32, output_size: u32) -> u64 {
    let input_bits = input_size.saturating_mul(8);
    let output_full = full_mask(output_size);
    let mut result = mask & output_full;
    if input_bits == 0 || input_bits >= 64 || output_size <= input_size {
        return result;
    }
    if (mask & (1u64 << (input_bits - 1))) != 0 {
        result |= output_full & !low_mask(input_bits);
    }
    result
}

fn add_mask(left: u64, right: u64, output_size: u32) -> u64 {
    let full = full_mask(output_size);
    let left = left & full;
    let right = right & full;
    let mut result = left;
    if result != full {
        if (right & result) == 0 {
            result |= right;
        } else {
            result |= right;
            result |= result << 1; // A shared possible bit can generate a carry.
        }
    }
    result & full
}

fn sub_mask(left: u64, right: u64, output_size: u32) -> u64 {
    let full = full_mask(output_size);
    let left = left & full;
    let right = right & full;
    if right == 0 {
        return left;
    }
    if left == 0 {
        let low = least_set(right).unwrap_or(0);
        return full & !low_mask(low);
    }

    // Subtraction preserves the common trailing zeroes, but a borrow may
    // affect every more-significant bit.  Start with the covering mask of the
    // operands, then widen through the complete borrow range.
    let low = least_set(left)
        .unwrap_or(0)
        .min(least_set(right).unwrap_or(0));
    let covered = covering_mask(left | right);
    let borrow_range = full & !low_mask(low);
    borrow_range | (covered & borrow_range)
}

fn multiply_mask(left: u64, right: u64, output_size: u32) -> u64 {
    let full = full_mask(output_size);
    if output_size > 8 {
        return full;
    }
    let Some(left_high) = most_set(left) else {
        return 0;
    };
    let Some(right_high) = most_set(right) else {
        return 0;
    };
    let left_low = left.trailing_zeros();
    let right_low = right.trailing_zeros();
    let shift = left_low.saturating_add(right_low);
    let bits = output_size.saturating_mul(8);
    if shift >= bits {
        return 0;
    }

    let left_width = left_high - left_low + 1;
    let right_width = right_high - right_low + 1;
    let mut total = left_width.saturating_add(right_width);
    if left_width == 1 || right_width == 1 {
        total = total.saturating_sub(1);
    }
    let mut result = full;
    if total < bits {
        result >>= bits - total;
    }
    (result << shift) & full
}

fn constant_shift(data: &Funcdata, value: VarnodeId) -> Option<u32> {
    let vn = data.varnode(value);
    vn.flags
        .constant
        .then_some(vn.offset.min(u64::from(u32::MAX)) as u32)
}

fn input_mask(masks: &[u64], inputs: &[VarnodeId], slot: usize) -> u64 {
    inputs.get(slot).map_or(0, |value| masks[value.0 as usize])
}

fn local_mask(data: &Funcdata, operation: &super::GraphOp, masks: &[u64]) -> u64 {
    let Some(output) = operation.output else {
        return 0;
    };
    let output_size = data.varnode(output).size;
    let full = full_mask(output_size);
    let input0 = input_mask(masks, &operation.inputs, 0);
    let input1 = input_mask(masks, &operation.inputs, 1);

    let result = match operation.opcode {
        op::INT_EQUAL
        | op::INT_NOTEQUAL
        | op::INT_SLESS
        | op::INT_SLESSEQUAL
        | op::INT_LESS
        | op::INT_LESSEQUAL
        | op::INT_CARRY
        | op::INT_SCARRY
        | op::INT_SBORROW
        | op::BOOL_NEGATE
        | op::BOOL_XOR
        | op::BOOL_AND
        | op::BOOL_OR
        | op::FLOAT_EQUAL
        | op::FLOAT_NOTEQUAL
        | op::FLOAT_LESS
        | op::FLOAT_LESSEQUAL
        | op::FLOAT_NAN => 1,
        op::COPY | op::CAST | op::INT_ZEXT => input0,
        op::INT_SEXT => operation.inputs.first().map_or(full, |input| {
            sign_extend_mask(input0, data.varnode(*input).size, output_size)
        }),
        op::INT_AND => input0 & input1,
        op::INT_OR | op::INT_XOR => input0 | input1,
        // Ghidra's local transfer treats an integer negate as an unknown
        // arithmetic result; a preceding constant fold normally removes it.
        op::INT_NEGATE | op::INT_2COMP => full,
        op::INT_LEFT => {
            let Some(shift) = operation
                .inputs
                .get(1)
                .and_then(|v| constant_shift(data, *v))
            else {
                return full;
            };
            if shift >= 64 {
                0
            } else {
                (input0 << shift) & full
            }
        }
        op::INT_RIGHT => {
            let Some(shift) = operation
                .inputs
                .get(1)
                .and_then(|v| constant_shift(data, *v))
            else {
                return full;
            };
            if shift >= 64 { 0 } else { input0 >> shift }
        }
        op::INT_SRIGHT => {
            let Some(shift) = operation
                .inputs
                .get(1)
                .and_then(|v| constant_shift(data, *v))
            else {
                return full;
            };
            if output_size > 8 {
                full
            } else {
                let input_size = operation
                    .inputs
                    .first()
                    .map_or(output_size, |input| data.varnode(*input).size);
                let sign_bit = input_size.saturating_mul(8).saturating_sub(1);
                let shifted = if shift >= 64 { 0 } else { input0 >> shift };
                if sign_bit < 64 && (input0 & (1u64 << sign_bit)) == 0 {
                    shifted
                } else if shift >= 64 {
                    full
                } else {
                    shifted | (full ^ (full >> shift))
                }
            }
        }
        op::INT_ADD => add_mask(input0, input1, output_size),
        op::INT_SUB => sub_mask(input0, input1, output_size),
        op::INT_MULT => multiply_mask(input0, input1, output_size),
        op::SUBPIECE => {
            let Some(offset) = operation
                .inputs
                .get(1)
                .and_then(|v| constant_shift(data, *v))
            else {
                return full;
            };
            let bytes = u64::from(offset);
            if bytes >= 8 {
                let input_size = operation
                    .inputs
                    .first()
                    .map_or(output_size, |input| data.varnode(*input).size);
                if input_size > 8 { full } else { 0 }
            } else {
                clip(input0 >> (bytes * 8), output_size)
            }
        }
        op::PIECE => {
            let Some(low) = operation.inputs.get(1) else {
                return full;
            };
            let shift = u64::from(data.varnode(*low).size).saturating_mul(8);
            if shift >= 64 {
                full
            } else {
                (input0 << shift | input1) & full
            }
        }
        op::MULTIEQUAL => operation
            .inputs
            .iter()
            .copied()
            .filter(|input| Some(*input) != operation.output)
            .fold(0, |mask, input| mask | masks[input.0 as usize]),
        // `PcodeOp::getNZMaskLocal` has no `CPUI_INDIRECT` case, so an
        // `INDIRECT` falls to its default and reports the full mask. Looking
        // through to the first operand is not equivalent: the operand of an
        // indirect *creation* is a placeholder standing for "no previous
        // value", so propagating its mask claimed a location a call destroyed
        // was provably zero, and `ActionVarnodeProps` then replaced it with the
        // constant zero.
        op::LOAD | op::CALL | op::CALLIND | op::INDIRECT => full,
        _ => full,
    };

    result & full
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SeqNum;
    use ventris_lifter::{REGISTER_SPACE, UNIQUE_SPACE};

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    #[test]
    fn masks_constants_and_and_surviving_bits() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = data.new_constant(0b1011_0000, 1);
        let mask = data.new_constant(0b0011_1111, 1);
        let and = data.new_op(op::INT_AND, seq(0x1000), vec![value, mask]);
        let output = data.new_unique(1);
        data.op_set_output(and, Some(output));
        data.op_insert_end(and, block);

        let masks = NonzeroMasks::of(&data);
        assert_eq!(masks.mask(value), 0b1011_0000);
        assert_eq!(masks.mask(output), 0b0011_0000);
    }

    #[test]
    fn self_referencing_phi_reaches_a_fixpoint() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x2000);
        let known = data.new_constant(0x20, 1);
        let phi = data.new_op(op::MULTIEQUAL, seq(0x2000), vec![known]);
        let merged = data.new_unique(1);
        data.op_set_output(phi, Some(merged));
        data.op_set_input(phi, merged, 1);
        data.op_insert_end(phi, block);

        let masks = NonzeroMasks::of(&data);
        assert_eq!(
            masks.mask(merged),
            0x20,
            "the loop edge must not force full mask"
        );
    }

    #[test]
    fn unknown_input_stays_full_and_action_reports_constraints() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x3000);
        let input = data.new_varnode(REGISTER_SPACE, 0, 1);
        data.mark_input(input);
        let zero = data.new_constant(0, 1);
        let and = data.new_op(op::INT_AND, seq(0x3000), vec![input, zero]);
        let result = data.new_unique(1);
        data.op_set_output(and, Some(result));
        data.op_insert_end(and, block);

        let masks = NonzeroMasks::of(&data);
        assert_eq!(masks.mask(input), 0xff);
        assert_eq!(masks.mask(result), 0);
        assert!(ActionNonzeroMask.apply(&mut data) >= 1);
        let _ = UNIQUE_SPACE;
    }
}

/// The fixpoint mask table, for `Funcdata`'s cache.
pub(crate) fn compute_masks(data: &Funcdata) -> Vec<u64> {
    NonzeroMasks::of(data).masks
}
