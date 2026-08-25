//! PIECE/SUBPIECE expression rewrites from Ghidra 12.1.3's `ruleaction.cc`.
//!
//! The implementations below follow the real `applyOp` bodies for
//! `RuleAndPiece`, `RuleConcatCommute`, `RuleConcatLeftShift`, `RuleConcatZero`,
//! `RuleConcatZext`, `RulePiece2Sext`, `RuleShiftPiece`, and `RuleOrMask`.
//!
//! Three requested rules are intentionally omitted because the graph does not
//! carry the state their guards and rewrites require:
//!
//! * `RuleOrConsume` needs `Varnode::getConsume` byte-consumption state.
//! * `RuleExtensionPush` needs address-force/address-tied and type/name-lock
//!   flags, plus `RulePushPtr::duplicateNeed`'s pointer/type machinery.
//! * `RulePushMulti` needs `functionalEqualityLevel`, earliest-use analysis,
//!   operation uninsertion, and the storage/spacebase metadata used by the
//!   original merge rewrite.
//!
//! Source authority: `Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.cc`
//! in the pinned Ghidra 12.1.3 tree.

use ventris_pcode::op;

use super::action::Rule;
use super::{Funcdata, OpId, SeqNum, VarnodeId};

fn mask_for_size(size: u32) -> u64 {
    let bits = u64::from(size).saturating_mul(8);
    if bits == 0 {
        0
    } else if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn shifted_right(value: u64, amount: u64) -> u64 {
    if amount >= 64 { 0 } else { value >> amount }
}

fn input(data: &Funcdata, id: OpId, slot: usize) -> Option<VarnodeId> {
    data.op(id).inputs.get(slot).copied()
}

fn output(data: &Funcdata, id: OpId) -> Option<VarnodeId> {
    data.op(id).output
}

fn is_constant(data: &Funcdata, value: VarnodeId) -> bool {
    data.varnode(value).flags.constant
}

/// The graph's conservative equivalent of Ghidra's `isHeritageKnown`.
fn heritage_known(data: &Funcdata, value: VarnodeId) -> bool {
    let varnode = data.varnode(value);
    varnode.flags.constant || varnode.flags.input || varnode.def.is_some()
}

/// Exact `Varnode::isFree`: constants are free as well as newly allocated
/// temporaries, while inputs and written values are not.
fn is_free(data: &Funcdata, value: VarnodeId) -> bool {
    let varnode = data.varnode(value);
    !(varnode.flags.written || varnode.flags.input)
}

fn def(data: &Funcdata, value: VarnodeId) -> Option<OpId> {
    data.varnode(value).def
}

/// `V & concat(W,X)` can discard the high part when the mask proves that no
/// high bit survives, or can zero the low part when the mask proves those bits
/// dead.  This is the graph form of `RuleAndPiece::applyOp`.
pub struct RuleAndPiece;

impl Rule for RuleAndPiece {
    fn name(&self) -> &'static str {
        "andpiece"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_AND]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(out) = output(data, id) else {
            return 0;
        };
        let size = data.varnode(out).size;
        if size > 8 {
            return 0;
        }
        let (Some(left), Some(right)) = (input(data, id, 0), input(data, id, 1)) else {
            return 0;
        };
        let masks = data.nonzero_masks();
        let full_mask = mask_for_size(size);

        let mut selected = None;
        for (slot, piece_value, other_value) in [(0usize, left, right), (1usize, right, left)] {
            let Some(piece_def) = def(data, piece_value) else {
                continue;
            };
            if data.opcode_of(piece_def) != Some(op::PIECE) {
                continue;
            }
            let other_mask = masks[other_value.0 as usize];
            if other_mask == full_mask || other_mask == 0 {
                continue;
            }
            let Some(high) = input(data, piece_def, 0) else {
                continue;
            };
            if !heritage_known(data, high) {
                continue;
            }
            let Some(low) = input(data, piece_def, 1) else {
                continue;
            };
            if !heritage_known(data, low) {
                continue;
            }
            let high_mask = masks[high.0 as usize];
            let low_mask = masks[low.0 as usize];
            let low_bits = u64::from(data.varnode(low).size).saturating_mul(8);
            if high_mask & shifted_right(other_mask, low_bits) == 0 {
                // A constant high zero is handled by RulePiece2Zext.  Keeping
                // this guard disjoint avoids recreating that rule's input.
                if high_mask == 0 && is_constant(data, high) {
                    continue;
                }
                selected = Some((slot, high, low, true));
                break;
            }
            if low_mask & other_mask == 0 {
                // A constant low zero is already the direct PIECE2ZEXT form;
                // changing it would not make progress.
                if is_constant(data, low) {
                    continue;
                }
                selected = Some((slot, high, low, false));
                break;
            }
        }

        let Some((slot, high, low, to_zext)) = selected else {
            return 0;
        };
        let seq = data.op(id).seq;
        if to_zext {
            let new_op = data.new_op(op::INT_ZEXT, seq, vec![low]);
            let new_value = data.new_unique(size);
            data.op_set_output(new_op, Some(new_value));
            data.op_insert_before(new_op, id);
            data.op_set_input(id, new_value, slot);
        } else {
            let zero = data.new_constant(0, data.varnode(low).size);
            let new_op = data.new_op(op::PIECE, seq, vec![high, zero]);
            let new_value = data.new_unique(size);
            data.op_set_output(new_op, Some(new_value));
            data.op_insert_before(new_op, id);
            data.op_set_input(id, new_value, slot);
        }
        1
    }
}

/// Commute a constant INT_AND/INT_OR/INT_XOR through one side of a PIECE.
pub struct RuleConcatCommute;

impl Rule for RuleConcatCommute {
    fn name(&self) -> &'static str {
        "concatcommute"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::PIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(out) = output(data, id) else {
            return 0;
        };
        let out_size = data.varnode(out).size;
        if out_size > 8 {
            return 0;
        }
        for slot in 0..2 {
            let Some(piece_value) = input(data, id, slot) else {
                continue;
            };
            let Some(logic_id) = def(data, piece_value) else {
                continue;
            };
            let Some(logic_code) = data.opcode_of(logic_id) else {
                continue;
            };
            if !matches!(logic_code, op::INT_AND | op::INT_OR | op::INT_XOR) {
                continue;
            }
            let Some(logic_constant) = input(data, logic_id, 1) else {
                continue;
            };
            if !is_constant(data, logic_constant) {
                continue;
            }
            let value = data.varnode(logic_constant).offset;
            let (high, low, mask_value) = if slot == 0 {
                let Some(low) = input(data, id, 1) else {
                    continue;
                };
                let Some(high) = input(data, logic_id, 0) else {
                    continue;
                };
                let shift = u64::from(data.varnode(low).size).saturating_mul(8);
                let shifted = if shift >= 64 {
                    0
                } else {
                    value.wrapping_shl(shift as u32)
                };
                let mask_value = if logic_code == op::INT_AND {
                    shifted | mask_for_size(data.varnode(low).size)
                } else {
                    shifted
                };
                (high, low, mask_value)
            } else {
                let Some(high) = input(data, id, 0) else {
                    continue;
                };
                let Some(low) = input(data, logic_id, 0) else {
                    continue;
                };
                let shift = u64::from(data.varnode(low).size).saturating_mul(8);
                let high_mask = if shift >= 64 {
                    0
                } else {
                    mask_for_size(data.varnode(high).size).wrapping_shl(shift as u32)
                };
                let mask_value = if logic_code == op::INT_AND {
                    value | high_mask
                } else {
                    value
                };
                (high, low, mask_value)
            };
            if is_free(data, high) || is_free(data, low) {
                continue;
            }
            let seq = data.op(id).seq;
            let new_concat = data.new_op(op::PIECE, seq, vec![high, low]);
            let new_value = data.new_unique(out_size);
            data.op_set_output(new_concat, Some(new_value));
            data.op_insert_before(new_concat, id);
            let mask_size = data.varnode(new_value).size;
            let mask = data.new_constant(mask_value, mask_size);
            data.op_set_opcode(id, logic_code);
            data.op_set_inputs(id, vec![new_value, mask]);
            return 1;
        }
        0
    }
}

/// Turn `PIECE(V, ZEXT(W) << c)` into `PIECE(PIECE(V,W),0)`.
pub struct RuleConcatLeftShift;

impl Rule for RuleConcatLeftShift {
    fn name(&self) -> &'static str {
        "concatleftshift"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::PIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(vn2) = input(data, id, 1) else {
            return 0;
        };
        let Some(shift_id) = def(data, vn2) else {
            return 0;
        };
        if data.opcode_of(shift_id) != Some(op::INT_LEFT) {
            return 0;
        }
        let Some(shift_amount) = input(data, shift_id, 1) else {
            return 0;
        };
        if !is_constant(data, shift_amount) {
            return 0;
        }
        let shift_bits = data.varnode(shift_amount).offset;
        if shift_bits % 8 != 0 {
            return 0;
        }
        let Some(tmp) = input(data, shift_id, 0) else {
            return 0;
        };
        let Some(zext_id) = def(data, tmp) else {
            return 0;
        };
        if data.opcode_of(zext_id) != Some(op::INT_ZEXT) {
            return 0;
        }
        let Some(b) = input(data, zext_id, 0) else {
            return 0;
        };
        let Some(vn1) = input(data, id, 0) else {
            return 0;
        };
        if is_free(data, b) || is_free(data, vn1) {
            return 0;
        }
        let shift_bytes = shift_bits / 8;
        if shift_bytes.saturating_add(u64::from(data.varnode(b).size))
            != u64::from(data.varnode(tmp).size)
        {
            return 0;
        }
        let Some(new_size) = data.varnode(vn1).size.checked_add(data.varnode(b).size) else {
            return 0;
        };
        let Some(out) = output(data, id) else {
            return 0;
        };
        let out_size = data.varnode(out).size;
        let Some(zero_size) = out_size.checked_sub(new_size) else {
            return 0;
        };
        let seq = data.op(id).seq;
        let new_piece = data.new_op(op::PIECE, seq, vec![vn1, b]);
        let new_value = data.new_unique(new_size);
        data.op_set_output(new_piece, Some(new_value));
        data.op_insert_before(new_piece, id);
        let zero = data.new_constant(0, zero_size);
        data.op_set_inputs(id, vec![new_value, zero]);
        1
    }
}

/// Turn `PIECE(V, 0)` into `ZEXT(V) << (8 * sizeof(0))`.
pub struct RuleConcatZero;

impl Rule for RuleConcatZero {
    fn name(&self) -> &'static str {
        "concatzero"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::PIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(low) = input(data, id, 1) else {
            return 0;
        };
        if !is_constant(data, low) || data.varnode(low).offset != 0 {
            return 0;
        }
        let Some(high) = input(data, id, 0) else {
            return 0;
        };
        let Some(out) = output(data, id) else {
            return 0;
        };
        let shift = u64::from(data.varnode(low).size).saturating_mul(8);
        let seq = data.op(id).seq;
        let new_zext = data.new_op(op::INT_ZEXT, seq, vec![high]);
        let ext_value = data.new_unique(data.varnode(out).size);
        data.op_set_output(new_zext, Some(ext_value));
        data.op_insert_before(new_zext, id);
        let amount = data.new_constant(shift, 4);
        data.op_set_opcode(id, op::INT_LEFT);
        data.op_set_inputs(id, vec![ext_value, amount]);
        1
    }
}

/// Commute a ZEXT through the high side of a PIECE.
pub struct RuleConcatZext;

impl Rule for RuleConcatZext {
    fn name(&self) -> &'static str {
        "concatzext"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::PIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(hi_value) = input(data, id, 0) else {
            return 0;
        };
        let Some(zext_id) = def(data, hi_value) else {
            return 0;
        };
        if data.opcode_of(zext_id) != Some(op::INT_ZEXT) {
            return 0;
        }
        let Some(hi) = input(data, zext_id, 0) else {
            return 0;
        };
        let Some(lo) = input(data, id, 1) else {
            return 0;
        };
        if is_free(data, hi) || is_free(data, lo) {
            return 0;
        }
        let Some(new_size) = data.varnode(hi).size.checked_add(data.varnode(lo).size) else {
            return 0;
        };
        let seq = data.op(id).seq;
        let new_concat = data.new_op(op::PIECE, seq, vec![hi, lo]);
        let new_value = data.new_unique(new_size);
        data.op_set_output(new_concat, Some(new_value));
        data.op_insert_before(new_concat, id);
        data.op_set_opcode(id, op::INT_ZEXT);
        data.op_set_inputs(id, vec![new_value]);
        1
    }
}

/// Turn `PIECE(V s>> (8*sizeof(V)-1), V)` into `SEXT(V)`.
pub struct RulePiece2Sext;

impl Rule for RulePiece2Sext {
    fn name(&self) -> &'static str {
        "piece2sext"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::PIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(shift_out) = input(data, id, 0) else {
            return 0;
        };
        let Some(x) = input(data, id, 1) else {
            return 0;
        };
        let Some(shift_id) = def(data, shift_out) else {
            return 0;
        };
        if data.opcode_of(shift_id) != Some(op::INT_SRIGHT) {
            return 0;
        }
        let Some(amount) = input(data, shift_id, 1) else {
            return 0;
        };
        if !is_constant(data, amount) {
            return 0;
        }
        let expected = u64::from(data.varnode(x).size)
            .saturating_mul(8)
            .checked_sub(1);
        if expected != Some(data.varnode(amount).offset) {
            return 0;
        }
        if input(data, shift_id, 0) != Some(x) {
            return 0;
        }
        data.op_set_opcode(id, op::INT_SEXT);
        data.op_set_inputs(id, vec![x]);
        1
    }
}

/// Convert shifted zero/sign extensions joined by an arithmetic operation into
/// a byte-aligned PIECE, including the CDQ sign-extension special case.
pub struct RuleShiftPiece;

impl Rule for RuleShiftPiece {
    fn name(&self) -> &'static str {
        "shiftpiece"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_OR, op::INT_XOR, op::INT_ADD]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(mut vn1) = input(data, id, 0) else {
            return 0;
        };
        let Some(mut vn2) = input(data, id, 1) else {
            return 0;
        };
        let Some(mut shift_id) = def(data, vn1) else {
            return 0;
        };
        let Some(mut low_ext_id) = def(data, vn2) else {
            return 0;
        };
        if data.opcode_of(shift_id) != Some(op::INT_LEFT) {
            if data.opcode_of(low_ext_id) != Some(op::INT_LEFT) {
                return 0;
            }
            std::mem::swap(&mut shift_id, &mut low_ext_id);
            std::mem::swap(&mut vn1, &mut vn2);
        }
        let Some(amount) = input(data, shift_id, 1) else {
            return 0;
        };
        if !is_constant(data, amount) {
            return 0;
        }
        let Some(shifted_source) = input(data, shift_id, 0) else {
            return 0;
        };
        let Some(high_ext_id) = def(data, shifted_source) else {
            return 0;
        };
        let high_ext_code = data.opcode_of(high_ext_id);
        if !matches!(high_ext_code, Some(op::INT_ZEXT | op::INT_SEXT)) {
            return 0;
        }
        let Some(high_root) = input(data, high_ext_id, 0) else {
            return 0;
        };
        if is_constant(data, high_root) {
            if data.varnode(high_root).size < 8 {
                return 0;
            }
        } else if is_free(data, high_root) {
            return 0;
        }
        let shift_bits = data.varnode(amount).offset;
        let concat_bits = shift_bits.saturating_add(u64::from(data.varnode(high_root).size) * 8);
        let Some(out) = output(data, id) else {
            return 0;
        };
        if u64::from(data.varnode(out).size).saturating_mul(8) < concat_bits {
            return 0;
        }

        if data.opcode_of(low_ext_id) != Some(op::INT_ZEXT) {
            // CDQ-style form: the low side is a sign extension whose source is
            // the low SUBPIECE of the same wider value.
            let Some(right_id) = def(data, high_root) else {
                return 0;
            };
            if data.opcode_of(right_id) != Some(op::INT_SRIGHT) {
                return 0;
            }
            let Some(right_amount) = input(data, right_id, 1) else {
                return 0;
            };
            if !is_constant(data, right_amount) {
                return 0;
            }
            let Some(right_source) = input(data, right_id, 0) else {
                return 0;
            };
            let Some(sub_id) = def(data, right_source) else {
                return 0;
            };
            if data.opcode_of(sub_id) != Some(op::SUBPIECE) {
                return 0;
            }
            let Some(sub_offset) = input(data, sub_id, 1) else {
                return 0;
            };
            if !is_constant(data, sub_offset) || data.varnode(sub_offset).offset != 0 {
                return 0;
            }
            let Some(big_value) = output(data, low_ext_id) else {
                return 0;
            };
            if input(data, sub_id, 0) != Some(big_value) {
                return 0;
            }
            let right_shift = data.varnode(right_amount).offset;
            let expected = u64::from(data.varnode(right_source).size)
                .saturating_mul(8)
                .saturating_sub(1);
            if right_shift != expected {
                return 0;
            }
            let masks = data.nonzero_masks();
            if shifted_right(masks[big_value.0 as usize], shift_bits) != 0 {
                return 0;
            }
            if shift_bits != u64::from(data.varnode(right_source).size) * 8 {
                return 0;
            }
            data.op_set_opcode(id, op::INT_SEXT);
            data.op_set_inputs(id, vec![right_source]);
            return 1;
        }

        let Some(low_root) = input(data, low_ext_id, 0) else {
            return 0;
        };
        if is_free(data, low_root) {
            return 0;
        }
        if shift_bits != u64::from(data.varnode(low_root).size) * 8 {
            return 0;
        }
        if shift_bits % 8 != 0 {
            return 0;
        }
        if concat_bits == u64::from(data.varnode(out).size) * 8 {
            data.op_set_opcode(id, op::PIECE);
            data.op_set_inputs(id, vec![high_root, low_root]);
        } else {
            let concat_size = (concat_bits / 8) as u32;
            if concat_size == 0 {
                return 0;
            }
            let seq = data.op(id).seq;
            let new_piece = data.new_op(op::PIECE, seq, vec![high_root, low_root]);
            let new_value = data.new_unique(concat_size);
            data.op_set_output(new_piece, Some(new_value));
            data.op_insert_before(new_piece, id);
            data.op_set_opcode(id, high_ext_code.unwrap());
            data.op_set_inputs(id, vec![new_value]);
        }
        1
    }
}

/// Collapse `W | full_mask` to a COPY of the constant mask.
pub struct RuleOrMask;

impl Rule for RuleOrMask {
    fn name(&self) -> &'static str {
        "ormask"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_OR]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(out) = output(data, id) else {
            return 0;
        };
        let size = data.varnode(out).size;
        if size > 8 {
            return 0;
        }
        let Some(constant) = input(data, id, 1) else {
            return 0;
        };
        if !is_constant(data, constant) {
            return 0;
        }
        let value = data.varnode(constant).offset;
        if value & mask_for_size(size) != mask_for_size(size) {
            return 0;
        }
        data.op_set_opcode(id, op::COPY);
        data.op_set_inputs(id, vec![constant]);
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    fn input_value(data: &mut Funcdata, size: u32) -> VarnodeId {
        let value = data.new_varnode(
            REGISTER_SPACE,
            (data.varnode_count() as u64).saturating_mul(0x10),
            size,
        );
        data.mark_input(value);
        value
    }

    fn unary(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        opcode: i32,
        value: VarnodeId,
        output_size: u32,
    ) -> (OpId, VarnodeId) {
        let id = data.new_op(
            opcode,
            seq(0x1000 + data.op_count() as u64 * 4),
            vec![value],
        );
        let out = data.new_unique(output_size);
        data.op_set_output(id, Some(out));
        data.op_insert_end(id, block);
        (id, out)
    }

    fn binary(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        opcode: i32,
        left: VarnodeId,
        right: VarnodeId,
        output_size: u32,
    ) -> (OpId, VarnodeId) {
        let id = data.new_op(
            opcode,
            seq(0x1000 + data.op_count() as u64 * 4),
            vec![left, right],
        );
        let out = data.new_unique(output_size);
        data.op_set_output(id, Some(out));
        data.op_insert_end(id, block);
        (id, out)
    }

    #[test]
    fn and_piece_to_zext_preserves_width() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let high = input_value(&mut data, 4);
        let low = input_value(&mut data, 4);
        let (_, piece_out) = binary(&mut data, block, op::PIECE, high, low, 8);
        let mask = data.new_constant(0xffff_ffff, 8);
        let (and, and_out) = binary(&mut data, block, op::INT_AND, piece_out, mask, 8);

        assert_eq!(RuleAndPiece.apply_op(and, &mut data), 1);
        let replacement = data.op(and).inputs[0];
        assert_eq!(
            data.op(data.varnode(replacement).def.unwrap()).opcode,
            op::INT_ZEXT
        );
        assert_eq!(
            data.op(data.varnode(replacement).def.unwrap()).inputs,
            vec![low]
        );
        assert_eq!(data.varnode(replacement).size, 8);
        assert_eq!(data.varnode(and_out).size, 8);
    }

    #[test]
    fn concat_commute_and_builds_wide_mask() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let high = input_value(&mut data, 4);
        let low = input_value(&mut data, 4);
        let and_mask = data.new_constant(0x0f, 4);
        let (_, masked_high) = binary(&mut data, block, op::INT_AND, high, and_mask, 4);
        let (piece, _) = binary(&mut data, block, op::PIECE, masked_high, low, 8);

        assert_eq!(RuleConcatCommute.apply_op(piece, &mut data), 1);
        assert_eq!(data.op(piece).opcode, op::INT_AND);
        let new_mask = data.op(piece).inputs[1];
        assert_eq!(data.varnode(new_mask).offset, 0x0000_000f_ffff_ffff);
        assert_eq!(data.varnode(new_mask).size, 8);
        let new_piece = data.op(piece).inputs[0];
        assert_eq!(
            data.op(data.varnode(new_piece).def.unwrap()).opcode,
            op::PIECE
        );
    }

    #[test]
    fn concat_left_shift_extracts_zero_tail() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let first = input_value(&mut data, 4);
        let second = input_value(&mut data, 2);
        let (_, extended) = unary(&mut data, block, op::INT_ZEXT, second, 4);
        let amount = data.new_constant(16, 4);
        let (_, shifted) = binary(&mut data, block, op::INT_LEFT, extended, amount, 4);
        let (piece, piece_out) = binary(&mut data, block, op::PIECE, first, shifted, 8);

        assert_eq!(RuleConcatLeftShift.apply_op(piece, &mut data), 1);
        assert_eq!(data.varnode(piece_out).size, 8);
        let inner = data.op(piece).inputs[0];
        assert_eq!(data.varnode(inner).size, 6);
        assert_eq!(data.op(data.varnode(inner).def.unwrap()).opcode, op::PIECE);
        let zero = data.op(piece).inputs[1];
        assert_eq!(data.varnode(zero).flags.constant, true);
        assert_eq!(data.varnode(zero).offset, 0);
        assert_eq!(data.varnode(zero).size, 2);
    }

    #[test]
    fn concat_zero_becomes_shifted_zext() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let high = input_value(&mut data, 4);
        let zero = data.new_constant(0, 2);
        let (piece, piece_out) = binary(&mut data, block, op::PIECE, high, zero, 6);

        assert_eq!(RuleConcatZero.apply_op(piece, &mut data), 1);
        assert_eq!(data.op(piece).opcode, op::INT_LEFT);
        assert_eq!(data.varnode(piece_out).size, 6);
        let ext = data.op(piece).inputs[0];
        assert_eq!(data.op(data.varnode(ext).def.unwrap()).opcode, op::INT_ZEXT);
        assert_eq!(data.varnode(ext).size, 6);
        assert_eq!(data.varnode(data.op(piece).inputs[1]).offset, 16);
    }

    #[test]
    fn concat_zext_moves_extension_outward() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let high = input_value(&mut data, 2);
        let (_, extended) = unary(&mut data, block, op::INT_ZEXT, high, 4);
        let low = input_value(&mut data, 2);
        let (piece, piece_out) = binary(&mut data, block, op::PIECE, extended, low, 6);

        assert_eq!(RuleConcatZext.apply_op(piece, &mut data), 1);
        assert_eq!(data.op(piece).opcode, op::INT_ZEXT);
        assert_eq!(data.varnode(piece_out).size, 6);
        let new_piece = data.op(piece).inputs[0];
        assert_eq!(data.varnode(new_piece).size, 4);
        assert_eq!(
            data.op(data.varnode(new_piece).def.unwrap()).inputs,
            vec![high, low]
        );
    }

    #[test]
    fn piece_sign_bits_become_sext() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let amount = data.new_constant(31, 4);
        let (_, sign_bits) = binary(&mut data, block, op::INT_SRIGHT, value, amount, 4);
        let (piece, piece_out) = binary(&mut data, block, op::PIECE, sign_bits, value, 8);

        assert_eq!(RulePiece2Sext.apply_op(piece, &mut data), 1);
        assert_eq!(data.op(piece).opcode, op::INT_SEXT);
        assert_eq!(data.op(piece).inputs, vec![value]);
        assert_eq!(data.varnode(piece_out).size, 8);
    }

    #[test]
    fn shift_piece_reconstructs_concat() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let high = input_value(&mut data, 2);
        let (_, high_ext) = unary(&mut data, block, op::INT_ZEXT, high, 4);
        let shift_amount = data.new_constant(16, 4);
        let (_, shifted) = binary(&mut data, block, op::INT_LEFT, high_ext, shift_amount, 4);
        let low = input_value(&mut data, 2);
        let (_, low_ext) = unary(&mut data, block, op::INT_ZEXT, low, 4);
        let (join, join_out) = binary(&mut data, block, op::INT_OR, shifted, low_ext, 4);

        assert_eq!(RuleShiftPiece.apply_op(join, &mut data), 1);
        assert_eq!(data.op(join).opcode, op::PIECE);
        assert_eq!(data.op(join).inputs, vec![high, low]);
        assert_eq!(data.varnode(join_out).size, 4);
    }

    #[test]
    fn or_full_mask_becomes_constant_copy() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let mask = data.new_constant(0xffff_ffff, 4);
        let (or, or_out) = binary(&mut data, block, op::INT_OR, value, mask, 4);

        assert_eq!(RuleOrMask.apply_op(or, &mut data), 1);
        assert_eq!(data.op(or).opcode, op::COPY);
        assert_eq!(data.op(or).inputs, vec![mask]);
        assert_eq!(data.varnode(or_out).size, 4);
    }
}

pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(RuleAndPiece),
        Box::new(RuleConcatCommute),
        Box::new(RuleConcatLeftShift),
        Box::new(RuleConcatZero),
        Box::new(RuleConcatZext),
        Box::new(RulePiece2Sext),
        Box::new(RuleShiftPiece),
        Box::new(RuleOrMask),
    ]
}
