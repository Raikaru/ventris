//! Expression rewrites from Ghidra 12.1.3's `ruleaction.cc`.
//!
//! The rules below preserve the machine-level idioms recognised by the C++
//! `applyOp` methods named in each section.  The graph deliberately has no
//! `TypeFactory`, symbol table, or range algebra, so rules whose correctness
//! depends on those facilities are listed as intentionally omitted below.
//!
//! Source authority: `RuleAddMultCollapse::applyOp`, `RuleIdentityEl::applyOp`,
//! `RuleShiftBitops::applyOp`, `RuleDoubleShift::applyOp`,
//! `RuleSubRight::applyOp`, `RuleTrivialShift::applyOp`,
//! `RuleAndDistribute::applyOp`, `RuleOrCollapse::applyOp`,
//! `RuleXorCollapse::applyOp`, `RuleAndCommute::applyOp`,
//! `RuleAndCompare::applyOp`, `RuleShift2Mult::applyOp`,
//! `RuleShiftSub::applyOp`, `RuleLess2Zero::applyOp`,
//! `RuleLessEqual2Zero::applyOp`, `RuleSLess2Zero::applyOp`,
//! `RuleLessNotEqual::applyOp`, `RuleLessOne::applyOp`,
//! `RuleEqual2Constant::applyOp`, `RuleNotDistribute::applyOp`,
//! `RuleZextEliminate::applyOp`, `RuleZextSless::applyOp`,
//! `RuleZextCommute::applyOp`, `RuleSubZext::applyOp`,
//! `RuleSubCancel::applyOp`, `RulePiece2Zext::applyOp`, and
//! `RuleConcatShift::applyOp` in
//! `Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.cc` at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.
//!
//! `RuleRangeMeld` is not ported: its real implementation is built on
//! `CircleRange::pullBack`, `CircleRange::intersect`/`circleUnion`, and
//! `translate2Op`, none of which the graph models.  `RuleShiftCast` and
//! `RuleSextSext` are not present in this pinned `ruleaction.cc`/`.hh`; the
//! two nearby real rules `RulePiece2Zext` and `RuleConcatShift` are ported as
//! replacements so the requested batch remains substantial.

use ventris_pcode::op;

use super::action::Rule;
use super::{Funcdata, OpId, VarnodeId};

const MASK_DEPTH: u32 = 8;

fn calc_mask(size: u32) -> u64 {
    match size {
        0 => 0,
        size if size >= 8 => u64::MAX,
        size => (1u64 << (size * 8)) - 1,
    }
}

fn shift_left(value: u64, amount: u64, size: u32) -> u64 {
    if amount >= 64 {
        0
    } else {
        value.wrapping_shl(amount as u32) & calc_mask(size)
    }
}

fn shift_right(value: u64, amount: u64, size: u32) -> u64 {
    if amount >= 64 {
        0
    } else {
        (value >> amount) & calc_mask(size)
    }
}

fn leastsigbit_set(value: u64) -> Option<u32> {
    (value != 0).then_some(value.trailing_zeros())
}

/// A bounded form of Ghidra's `Varnode::getNZMask`.
///
/// The graph does not expose Ghidra's full heritage cache, so this local
/// recursion is deliberately conservative at unknown definitions: returning
/// the full mask prevents a rewrite from assuming a bit is dead merely because
/// the graph lacks the analysis needed to prove it.
fn nonzero_mask(data: &Funcdata, value: VarnodeId, depth: u32) -> u64 {
    let varnode = data.varnode(value);
    let full = calc_mask(varnode.size);
    if varnode.flags.constant {
        return varnode.offset & full;
    }
    if depth == 0 {
        return full;
    }
    let Some(def) = varnode.def else {
        return full;
    };
    let operation = data.op(def);
    let mask_of = |slot: usize| {
        operation
            .inputs
            .get(slot)
            .copied()
            .map(|input| nonzero_mask(data, input, depth - 1))
            .unwrap_or(full)
    };
    match operation.opcode {
        op::COPY | op::CAST | op::INT_ZEXT => mask_of(0) & full,
        op::INT_SEXT => full,
        op::INT_AND => mask_of(0) & mask_of(1) & full,
        op::INT_OR | op::INT_XOR => (mask_of(0) | mask_of(1)) & full,
        op::INT_ADD | op::INT_SUB => full,
        op::INT_MULT => {
            let left = mask_of(0);
            let right = mask_of(1);
            let right_constant = operation
                .inputs
                .get(1)
                .copied()
                .filter(|input| data.varnode(*input).flags.constant);
            let left_constant = operation
                .inputs
                .first()
                .copied()
                .filter(|input| data.varnode(*input).flags.constant);
            if let Some(constant) = right_constant {
                let coefficient = data.varnode(constant).offset;
                if coefficient == 0 {
                    0
                } else if coefficient.is_power_of_two() {
                    shift_left(left, u64::from(coefficient.trailing_zeros()), varnode.size)
                } else {
                    full
                }
            } else if let Some(constant) = left_constant {
                let coefficient = data.varnode(constant).offset;
                if coefficient == 0 {
                    0
                } else if coefficient.is_power_of_two() {
                    shift_left(right, u64::from(coefficient.trailing_zeros()), varnode.size)
                } else {
                    full
                }
            } else {
                full
            }
        }
        op::MULTIEQUAL => {
            operation
                .inputs
                .iter()
                .copied()
                .filter(|input| *input != value)
                .map(|input| nonzero_mask(data, input, depth - 1))
                .fold(0, |acc, mask| acc | mask)
                & full
        }
        op::INT_LEFT => {
            let amount = operation
                .inputs
                .get(1)
                .copied()
                .filter(|input| data.varnode(*input).flags.constant)
                .map(|input| data.varnode(input).offset)
                .unwrap_or(64);
            shift_left(mask_of(0), amount, varnode.size)
        }
        op::INT_RIGHT | op::INT_SRIGHT => {
            let amount = operation
                .inputs
                .get(1)
                .copied()
                .filter(|input| data.varnode(*input).flags.constant)
                .map(|input| data.varnode(input).offset)
                .unwrap_or(64);
            shift_right(mask_of(0), amount, varnode.size)
        }
        op::SUBPIECE => {
            let amount = operation
                .inputs
                .get(1)
                .copied()
                .filter(|input| data.varnode(*input).flags.constant)
                .and_then(|input| data.varnode(input).offset.checked_mul(8))
                .unwrap_or(64);
            shift_right(mask_of(0), amount, varnode.size)
        }
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

fn inputs2(data: &Funcdata, id: OpId) -> Option<(VarnodeId, VarnodeId)> {
    let operation = data.op(id);
    Some((*operation.inputs.first()?, *operation.inputs.get(1)?))
}
fn is_constant(data: &Funcdata, value: VarnodeId) -> bool {
    data.varnode(value).flags.constant
}

/// A newly allocated, unmarked varnode has no heritage proof; constants,
/// inputs, and defined values are the graph's conservative approximation.
fn heritage_known(data: &Funcdata, value: VarnodeId) -> bool {
    let varnode = data.varnode(value);
    varnode.flags.constant || varnode.flags.input || varnode.def.is_some()
}

fn def_opcode(data: &Funcdata, value: VarnodeId) -> Option<i32> {
    data.varnode(value).def.and_then(|def| data.opcode_of(def))
}

fn set_copy(data: &mut Funcdata, id: OpId, value: VarnodeId) {
    data.op_set_opcode(id, op::COPY);
    data.op_set_inputs(id, vec![value]);
}

fn set_constant(data: &mut Funcdata, id: OpId, value: u64, size: u32) {
    let constant = data.new_constant(value, size);
    set_copy(data, id, constant);
}

fn bool_output(data: &Funcdata, value: VarnodeId) -> bool {
    data.varnode(value).size == 1
}

// Arithmetic and shifts: identities, masks, and shift/bitfield normalisation.

/// Collapse adjacent additions or multiplications by constants.
pub struct RuleAddMultCollapse;

impl Rule for RuleAddMultCollapse {
    fn name(&self) -> &'static str {
        "addmultcollapse"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_ADD, op::INT_MULT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((sub, outer_const)) = inputs2(data, id) else {
            return 0;
        };
        if !is_constant(data, outer_const) {
            return 0;
        }
        let Some(subop) = data.varnode(sub).def else {
            return 0;
        };
        let opcode = data.op(id).opcode;
        if data.opcode_of(subop) != Some(opcode) {
            return 0;
        }
        let Some((inner_base, inner_const)) = inputs2(data, subop) else {
            return 0;
        };
        if !is_constant(data, inner_const) {
            // The remaining C++ branch is specifically for spacebase and
            // symbol metadata, which this graph intentionally does not model.
            return 0;
        }
        let size = data.varnode(outer_const).size;
        let value = match opcode {
            op::INT_ADD => data
                .varnode(outer_const)
                .offset
                .wrapping_add(data.varnode(inner_const).offset),
            op::INT_MULT => data
                .varnode(outer_const)
                .offset
                .wrapping_mul(data.varnode(inner_const).offset),
            _ => return 0,
        } & calc_mask(size);
        let combined = data.new_constant(value, size);
        data.op_set_input(id, combined, 1);
        data.op_set_input(id, inner_base, 0);
        1
    }
}

/// Remove an additive, logical, boolean, or multiplicative identity.
pub struct RuleIdentityEl;

impl Rule for RuleIdentityEl {
    fn name(&self) -> &'static str {
        "identityel"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![
            op::INT_ADD,
            op::INT_XOR,
            op::INT_OR,
            op::BOOL_XOR,
            op::BOOL_OR,
            op::INT_MULT,
        ]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((left, right)) = inputs2(data, id) else {
            return 0;
        };
        if !is_constant(data, right) {
            return 0;
        }
        let value = data.varnode(right).offset;
        let opcode = data.op(id).opcode;
        if opcode != op::INT_MULT && value == 0 {
            set_copy(data, id, left);
            return 1;
        }
        if opcode != op::INT_MULT {
            return 0;
        }
        if value == 1 {
            set_copy(data, id, left);
            return 1;
        }
        if value == 0 {
            set_copy(data, id, right);
            return 1;
        }
        0
    }
}

/// Drop operands whose non-zero bits are shifted entirely out of a bitwise term.
pub struct RuleShiftBitops;

impl Rule for RuleShiftBitops {
    fn name(&self) -> &'static str {
        "shiftbitops"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_LEFT, op::INT_RIGHT, op::SUBPIECE, op::INT_MULT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((input, amount_vn)) = inputs2(data, id) else {
            return 0;
        };
        if !is_constant(data, amount_vn) || data.varnode(input).def.is_none() {
            return 0;
        }
        let size = data.varnode(input).size;
        if size > 8 {
            return 0;
        }
        let amount = match data.op(id).opcode {
            op::INT_LEFT | op::INT_RIGHT => Some(data.varnode(amount_vn).offset),
            op::SUBPIECE => data.varnode(amount_vn).offset.checked_mul(8),
            op::INT_MULT => leastsigbit_set(data.varnode(amount_vn).offset).map(u64::from),
            _ => None,
        };
        let Some(amount) = amount else {
            return 0;
        };
        let left_shift = matches!(data.op(id).opcode, op::INT_LEFT | op::INT_MULT);
        let Some(bitop) = data.varnode(input).def else {
            return 0;
        };
        let bitop_code = data.op(bitop).opcode;
        if !matches!(
            bitop_code,
            op::INT_AND | op::INT_OR | op::INT_XOR | op::INT_MULT | op::INT_ADD
        ) {
            return 0;
        }
        if !left_shift && matches!(bitop_code, op::INT_MULT | op::INT_ADD) {
            return 0;
        }
        let Some(output) = data.op(id).output else {
            return 0;
        };
        let output_size = data.varnode(output).size;
        let masked_out = (0..data.op(bitop).inputs.len()).find(|slot| {
            let mask = nonzero_mask(data, data.op(bitop).inputs[*slot], MASK_DEPTH);
            let shifted = if left_shift {
                shift_left(mask, amount, output_size)
            } else {
                shift_right(mask, amount, output_size)
            };
            shifted & calc_mask(output_size) == 0
        });
        let Some(slot) = masked_out else {
            return 0;
        };
        if matches!(bitop_code, op::INT_ADD | op::INT_XOR | op::INT_OR)
            && !heritage_known(data, data.op(bitop).inputs[1 - slot])
        {
            return 0;
        }
        match bitop_code {
            op::INT_MULT | op::INT_AND => {
                let zero = data.new_constant(0, size);
                data.op_set_input(id, zero, 0);
            }
            op::INT_ADD | op::INT_XOR | op::INT_OR => {
                let Some(other) = data.op(bitop).inputs.get(1 - slot).copied() else {
                    return 0;
                };
                data.op_set_input(id, other, 0);
            }
            _ => return 0,
        }
        1
    }
}

/// Combine two shifts, including the mask left by opposite shifts.
pub struct RuleDoubleShift;

impl Rule for RuleDoubleShift {
    fn name(&self) -> &'static str {
        "doubleshift"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_LEFT, op::INT_RIGHT, op::INT_MULT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((_, outer_amount)) = inputs2(data, id) else {
            return 0;
        };
        if !is_constant(data, outer_amount) {
            return 0;
        }
        let outer_input = data.op(id).inputs[0];
        let Some(inner_id) = data.varnode(outer_input).def else {
            return 0;
        };
        let Some((inner_input, inner_amount)) = inputs2(data, inner_id) else {
            return 0;
        };
        if !is_constant(data, inner_amount) {
            return 0;
        }
        let mut outer_code = data.op(id).opcode;
        let mut inner_code = data.op(inner_id).opcode;
        if !matches!(inner_code, op::INT_LEFT | op::INT_RIGHT | op::INT_MULT)
            || !matches!(outer_code, op::INT_LEFT | op::INT_RIGHT | op::INT_MULT)
        {
            return 0;
        }
        let mut outer_shift = data.varnode(outer_amount).offset;
        let mut inner_shift = data.varnode(inner_amount).offset;
        if outer_code == op::INT_MULT {
            let Some(shift) = leastsigbit_set(outer_shift) else {
                return 0;
            };
            if outer_shift >> shift != 1 {
                return 0;
            }
            outer_shift = u64::from(shift);
            outer_code = op::INT_LEFT;
        }
        if inner_code == op::INT_MULT {
            let Some(shift) = leastsigbit_set(inner_shift) else {
                return 0;
            };
            if inner_shift >> shift != 1 {
                return 0;
            }
            inner_shift = u64::from(shift);
            inner_code = op::INT_LEFT;
        }
        if outer_shift >= 64 || inner_shift >= 64 {
            return 0;
        }
        let size = data.varnode(outer_input).size;
        let width = u64::from(size) * 8;
        if inner_code == outer_code {
            let sum = outer_shift.saturating_add(inner_shift);
            if sum < width {
                let shift_constant = data.new_constant(sum, 4);
                data.op_set_opcode(id, outer_code);
                data.op_set_input(id, inner_input, 0);
                data.op_set_input(id, shift_constant, 1);
            } else {
                set_constant(data, id, 0, size);
            }
            return 1;
        }
        if size > 8 {
            return 0;
        }
        let full = calc_mask(size);
        let (mask, difference) = if outer_code == op::INT_LEFT {
            if data.varnode(outer_input).descendants.len() != 1 || outer_shift != inner_shift {
                return 0;
            }
            (shift_left(full, inner_shift, size), 0i64)
        } else {
            let diff = inner_shift as i64 - outer_shift as i64;
            (shift_right(full, inner_shift, size), diff)
        };
        if difference == 0 {
            let mask_constant = data.new_constant(mask, size);
            data.op_set_opcode(id, op::INT_AND);
            data.op_set_input(id, inner_input, 0);
            data.op_set_input(id, mask_constant, 1);
        } else {
            let mask_constant = data.new_constant(mask, size);
            let and_op = data.new_op(
                op::INT_AND,
                data.op(id).seq,
                vec![inner_input, mask_constant],
            );
            let and_out = data.new_unique(size);
            data.op_set_output(and_op, Some(and_out));
            data.op_insert_before(and_op, id);
            let final_code = if difference < 0 {
                op::INT_RIGHT
            } else {
                op::INT_LEFT
            };
            let magnitude = difference.unsigned_abs();
            let shift_constant = data.new_constant(magnitude, 4);
            data.op_set_opcode(id, final_code);
            data.op_set_input(id, and_out, 0);
            data.op_set_input(id, shift_constant, 1);
        }
        1
    }
}

/// Convert a non-low SUBPIECE into a right shift followed by a low SUBPIECE.
pub struct RuleSubRight;

impl Rule for RuleSubRight {
    fn name(&self) -> &'static str {
        "subright"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::SUBPIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((base, offset_vn)) = inputs2(data, id) else {
            return 0;
        };
        if !is_constant(data, offset_vn) {
            return 0;
        }
        let offset = data.varnode(offset_vn).offset;
        if offset == 0 {
            return 0;
        }
        let Some(bits) = offset.checked_mul(8) else {
            return 0;
        };
        let size = data.varnode(base).size;
        let seq = data.op(id).seq;
        let shift_constant = data.new_constant(bits, 4);
        let shift = data.new_op(op::INT_RIGHT, seq, vec![base, shift_constant]);
        let shifted = data.new_unique(size);
        data.op_set_output(shift, Some(shifted));
        data.op_insert_before(shift, id);
        let low = data.new_constant(0, 4);
        data.op_set_input(id, shifted, 0);
        data.op_set_input(id, low, 1);
        1
    }
}

/// Remove shifts by zero and shifts that have discarded the complete value.
pub struct RuleTrivialShift;

impl Rule for RuleTrivialShift {
    fn name(&self) -> &'static str {
        "trivialshift"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_LEFT, op::INT_RIGHT, op::INT_SRIGHT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((input, amount)) = inputs2(data, id) else {
            return 0;
        };
        if !is_constant(data, amount) {
            return 0;
        }
        let value = data.varnode(amount).offset;
        if value != 0 {
            if value < u64::from(data.varnode(input).size) * 8
                || data.op(id).opcode == op::INT_SRIGHT
            {
                return 0;
            }
            let zero = data.new_constant(0, data.varnode(input).size);
            data.op_set_inputs(id, vec![zero]);
        } else {
            data.op_set_inputs(id, vec![input]);
        }
        data.op_set_opcode(id, op::COPY);
        1
    }
}

/// Distribute an AND over an OR when one distributed term is cancelled.
pub struct RuleAndDistribute;

impl Rule for RuleAndDistribute {
    fn name(&self) -> &'static str {
        "anddistribute"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_AND]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((left, right)) = inputs2(data, id) else {
            return 0;
        };
        let Some(output) = data.op(id).output else {
            return 0;
        };
        let size = data.varnode(output).size;
        if size > 8 {
            return 0;
        }
        let full = calc_mask(size);
        let mut selected = None;
        for (or_slot, or_value) in [(0usize, left), (1usize, right)] {
            let other = if or_slot == 0 { right } else { left };
            let Some(or_id) = data.varnode(or_value).def else {
                continue;
            };
            if data.opcode_of(or_id) != Some(op::INT_OR) {
                continue;
            }
            let Some((or_left, or_right)) = inputs2(data, or_id) else {
                continue;
            };
            let other_mask = nonzero_mask(data, other, MASK_DEPTH);
            if other_mask == 0 || other_mask == full {
                continue;
            }
            let mask1 = nonzero_mask(data, or_left, MASK_DEPTH);
            let mask2 = nonzero_mask(data, or_right, MASK_DEPTH);
            if mask1 & other_mask == 0 || mask2 & other_mask == 0 {
                selected = Some((or_id, other));
                break;
            }
            if is_constant(data, other)
                && ((mask1 & other_mask) == mask1 || (mask2 & other_mask) == mask2)
            {
                selected = Some((or_id, other));
                break;
            }
        }
        let Some((or_id, other)) = selected else {
            return 0;
        };
        let (or_left, or_right) = inputs2(data, or_id).expect("selected OR has two inputs");
        let seq = data.op(id).seq;
        let first = data.new_op(op::INT_AND, seq, vec![or_left, other]);
        let first_out = data.new_unique(size);
        data.op_set_output(first, Some(first_out));
        data.op_insert_before(first, id);
        let second = data.new_op(op::INT_AND, seq, vec![or_right, other]);
        let second_out = data.new_unique(size);
        data.op_set_output(second, Some(second_out));
        data.op_insert_before(second, id);
        data.op_set_inputs(id, vec![first_out, second_out]);
        data.op_set_opcode(id, op::INT_OR);
        1
    }
}

/// Collapse an OR with a constant that already contains every possible bit.
pub struct RuleOrCollapse;

impl Rule for RuleOrCollapse {
    fn name(&self) -> &'static str {
        "orcollapse"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_OR]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((left, right)) = inputs2(data, id) else {
            return 0;
        };
        if !is_constant(data, right) {
            return 0;
        }
        let Some(output) = data.op(id).output else {
            return 0;
        };
        let size = data.varnode(output).size;
        if size > 8 {
            return 0;
        }
        let mask = nonzero_mask(data, left, MASK_DEPTH);
        let value = data.varnode(right).offset;
        if mask | value != value {
            return 0;
        }
        set_copy(data, id, right);
        1
    }
}

/// Move a mask through a shift when the shift's source is a useful OR/PIECE.
pub struct RuleAndCommute;

impl Rule for RuleAndCommute {
    fn name(&self) -> &'static str {
        "andcommute"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_AND]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((left, right)) = inputs2(data, id) else {
            return 0;
        };
        let Some(output) = data.op(id).output else {
            return 0;
        };
        let size = data.varnode(output).size;
        if size > 8 {
            return 0;
        }
        let full = calc_mask(size);
        let mut chosen = None;
        for slot in 0..2 {
            let shiftvn = if slot == 0 { left } else { right };
            let other = if slot == 0 { right } else { left };
            if !heritage_known(data, other) {
                continue;
            }
            let Some(shift_id) = data.varnode(shiftvn).def else {
                continue;
            };
            let shift_code = data.op(shift_id).opcode;
            if !matches!(shift_code, op::INT_LEFT | op::INT_RIGHT) {
                continue;
            }
            let Some((source, shift_amount)) = inputs2(data, shift_id) else {
                continue;
            };
            if !is_constant(data, shift_amount) {
                continue;
            }
            let amount = data.varnode(shift_amount).offset;
            if amount >= 64 {
                continue;
            }
            let mut other_mask = nonzero_mask(data, other, MASK_DEPTH);
            if shift_code == op::INT_RIGHT {
                if shift_right(full, amount, size) == other_mask {
                    continue;
                }
                other_mask = shift_left(other_mask, amount, size);
            } else {
                if shift_left(full, amount, size) == other_mask {
                    continue;
                }
                other_mask = shift_right(other_mask, amount, size);
            }
            if other_mask == 0 || other_mask == full {
                continue;
            }
            if shift_code == op::INT_LEFT
                && is_constant(data, other)
                && data.varnode(shiftvn).descendants.len() == 1
            {
                chosen = Some((shift_code, source, shift_amount, other));
                break;
            }
            let Some(source_id) = data.varnode(source).def else {
                continue;
            };
            let cancels = match data.op(source_id).opcode {
                op::INT_OR => match inputs2(data, source_id) {
                    Some((a, b)) => {
                        let mask_a = nonzero_mask(data, a, MASK_DEPTH);
                        let mask_b = nonzero_mask(data, b, MASK_DEPTH);
                        (mask_a & other_mask == 0)
                            || (mask_b & other_mask == 0)
                            || (is_constant(data, other)
                                && ((mask_a & other_mask) == mask_a
                                    || (mask_b & other_mask) == mask_b))
                    }
                    None => false,
                },
                op::PIECE => match inputs2(data, source_id) {
                    Some((high, low)) => {
                        let high_mask = shift_left(
                            nonzero_mask(data, high, MASK_DEPTH),
                            u64::from(data.varnode(low).size) * 8,
                            size,
                        );
                        let low_mask = nonzero_mask(data, low, MASK_DEPTH);
                        high_mask & other_mask == 0 || low_mask & other_mask == 0
                    }
                    None => false,
                },
                _ => false,
            };
            if cancels {
                chosen = Some((shift_code, source, shift_amount, other));
                break;
            }
        }
        let Some((shift_code, source, shift_amount, other)) = chosen else {
            return 0;
        };
        let new_shift_code = if shift_code == op::INT_LEFT {
            op::INT_RIGHT
        } else {
            op::INT_LEFT
        };
        let seq = data.op(id).seq;
        let moved_shift = data.new_op(new_shift_code, seq, vec![other, shift_amount]);
        let moved_out = data.new_unique(size);
        data.op_set_output(moved_shift, Some(moved_out));
        data.op_insert_before(moved_shift, id);
        let moved_and = data.new_op(op::INT_AND, seq, vec![source, moved_out]);
        let moved_and_out = data.new_unique(size);
        data.op_set_output(moved_and, Some(moved_and_out));
        data.op_insert_before(moved_and, id);
        data.op_set_inputs(id, vec![moved_and_out, shift_amount]);
        data.op_set_opcode(id, shift_code);
        1
    }
}

/// Widen a masked ZEXT/SUBPIECE comparison so the mask is applied to the source.
pub struct RuleAndCompare;

impl Rule for RuleAndCompare {
    fn name(&self) -> &'static str {
        "andcompare"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_EQUAL, op::INT_NOTEQUAL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((compared, compare_const)) = inputs2(data, id) else {
            return 0;
        };
        if !is_constant(data, compare_const) || data.varnode(compare_const).offset != 0 {
            return 0;
        }
        let Some(and_id) = data.varnode(compared).def else {
            return 0;
        };
        if data.opcode_of(and_id) != Some(op::INT_AND) {
            return 0;
        }
        let Some((masked, and_const)) = inputs2(data, and_id) else {
            return 0;
        };
        if !is_constant(data, and_const) {
            return 0;
        }
        let Some(sub_id) = data.varnode(masked).def else {
            return 0;
        };
        let (base, and_value) = match data.op(sub_id).opcode {
            op::SUBPIECE => {
                let Some((input, offset)) = inputs2(data, sub_id) else {
                    return 0;
                };
                if data.varnode(input).size > 8 || !is_constant(data, offset) {
                    return 0;
                }
                (
                    input,
                    shift_left(
                        data.varnode(and_const).offset,
                        data.varnode(offset).offset.saturating_mul(8),
                        data.varnode(input).size,
                    ),
                )
            }
            op::INT_ZEXT => {
                let Some(input) = data.op(sub_id).inputs.first().copied() else {
                    return 0;
                };
                (
                    input,
                    data.varnode(and_const).offset & calc_mask(data.varnode(input).size),
                )
            }
            _ => return 0,
        };
        if data.varnode(and_const).offset == calc_mask(data.varnode(compared).size) {
            return 0;
        }
        let new_const = data.new_constant(and_value, data.varnode(base).size);
        let seq = data.op(and_id).seq;
        let new_and = data.new_op(op::INT_AND, seq, vec![base, new_const]);
        let new_out = data.new_unique(data.varnode(base).size);
        data.op_set_output(new_and, Some(new_out));
        data.op_insert_before(new_and, and_id);
        let zero = data.new_constant(0, data.varnode(base).size);
        data.op_set_input(id, new_out, 0);
        data.op_set_input(id, zero, 1);
        1
    }
}

/// Turn a small left shift used by arithmetic into multiplication by a power of two.
pub struct RuleShift2Mult;

impl Rule for RuleShift2Mult {
    fn name(&self) -> &'static str {
        "shift2mult"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_LEFT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((input, amount)) = inputs2(data, id) else {
            return 0;
        };
        if !is_constant(data, amount) {
            return 0;
        }
        let shift = data.varnode(amount).offset;
        if shift >= 32 {
            return 0;
        }
        let Some(output) = data.op(id).output else {
            return 0;
        };
        let arithmetic_def = data.varnode(input).def;
        let involved = arithmetic_def
            .map(|def| {
                matches!(
                    data.op(def).opcode,
                    op::INT_ADD | op::INT_SUB | op::INT_MULT
                )
            })
            .unwrap_or(false)
            || data.varnode(output).descendants.iter().any(|desc| {
                matches!(
                    data.opcode_of(*desc),
                    Some(op::INT_ADD | op::INT_SUB | op::INT_MULT)
                )
            });
        if !involved {
            return 0;
        }
        let size = data.varnode(output).size;
        let constant = data.new_constant(1u64 << shift, size);
        data.op_set_input(id, constant, 1);
        data.op_set_opcode(id, op::INT_MULT);
        1
    }
}

/// Simplify a SUBPIECE of a byte-aligned left shift.
pub struct RuleShiftSub;

impl Rule for RuleShiftSub {
    fn name(&self) -> &'static str {
        "shiftsub"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::SUBPIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((shifted, offset)) = inputs2(data, id) else {
            return 0;
        };
        let Some(shift_id) = data.varnode(shifted).def else {
            return 0;
        };
        if data.opcode_of(shift_id) != Some(op::INT_LEFT) {
            return 0;
        }
        let Some((input, shift_amount)) = inputs2(data, shift_id) else {
            return 0;
        };
        if !is_constant(data, shift_amount) || !is_constant(data, offset) {
            return 0;
        }
        let amount = data.varnode(shift_amount).offset;
        if amount & 7 != 0 {
            return 0;
        }
        let new_offset = data.varnode(offset).offset as i64 - (amount / 8) as i64;
        let Some(output) = data.op(id).output else {
            return 0;
        };
        let output_size = data.varnode(output).size;
        let input_size = data.varnode(input).size;
        if new_offset < 0
            || (new_offset as u64).saturating_add(u64::from(output_size)) > u64::from(input_size)
        {
            return 0;
        }
        let offset_size = data.varnode(offset).size;
        let replacement = data.new_constant(new_offset as u64, offset_size);
        data.op_set_input(id, input, 0);
        data.op_set_input(id, replacement, 1);
        1
    }
}

/// Eliminate a PIECE whose high part is zero.
pub struct RulePiece2Zext;

impl Rule for RulePiece2Zext {
    fn name(&self) -> &'static str {
        "piece2zext"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::PIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((high, low)) = inputs2(data, id) else {
            return 0;
        };
        if !is_constant(data, high) || data.varnode(high).offset != 0 {
            return 0;
        }
        data.op_set_opcode(id, op::INT_ZEXT);
        data.op_set_inputs(id, vec![low]);
        1
    }
}

/// Simplify a right shift of a PIECE into an extension of its high part.
pub struct RuleConcatShift;

impl Rule for RuleConcatShift {
    fn name(&self) -> &'static str {
        "concatshift"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_RIGHT, op::INT_SRIGHT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((shifted, amount)) = inputs2(data, id) else {
            return 0;
        };
        if !is_constant(data, amount) {
            return 0;
        }
        let Some(concat_id) = data.varnode(shifted).def else {
            return 0;
        };
        if data.opcode_of(concat_id) != Some(op::PIECE) {
            return 0;
        }
        let Some((high, low)) = inputs2(data, concat_id) else {
            return 0;
        };
        let low_bits = u64::from(data.varnode(low).size) * 8;
        let mut shift = data.varnode(amount).offset;
        if shift < low_bits {
            return 0;
        }
        let extension = if data.op(id).opcode == op::INT_RIGHT {
            op::INT_ZEXT
        } else {
            op::INT_SEXT
        };
        shift -= low_bits;
        if shift == 0 {
            data.op_set_opcode(id, extension);
            data.op_set_inputs(id, vec![high]);
            return 1;
        }
        let seq = data.op(id).seq;
        let ext = data.new_op(extension, seq, vec![high]);
        let ext_out = data.new_unique(data.varnode(shifted).size);
        data.op_set_output(ext, Some(ext_out));
        data.op_insert_before(ext, id);
        let shift_constant = data.new_constant(shift, data.varnode(amount).size);
        data.op_set_opcode(
            id,
            if extension == op::INT_ZEXT {
                op::INT_RIGHT
            } else {
                op::INT_SRIGHT
            },
        );
        data.op_set_inputs(id, vec![ext_out, shift_constant]);
        1
    }
}

/// Fold an XOR under an equality/inequality comparison.
pub struct RuleXorCollapse;

impl Rule for RuleXorCollapse {
    fn name(&self) -> &'static str {
        "xorcollapse"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_EQUAL, op::INT_NOTEQUAL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((xor_value, compare_const)) = inputs2(data, id) else {
            return 0;
        };
        if !is_constant(data, compare_const) {
            return 0;
        }
        let Some(xor_id) = data.varnode(xor_value).def else {
            return 0;
        };
        if data.opcode_of(xor_id) != Some(op::INT_XOR)
            || data.varnode(xor_value).descendants.len() != 1
        {
            return 0;
        }
        let Some((left, right)) = inputs2(data, xor_id) else {
            return 0;
        };
        let coeff1 = data.varnode(compare_const).offset;
        if !is_constant(data, right) {
            if coeff1 != 0 {
                return 0;
            }
            data.op_set_inputs(id, vec![left, right]);
            return 1;
        }
        let coeff2 = data.varnode(right).offset;
        if coeff2 == 0 {
            return 0;
        }
        let constant = data.new_constant(coeff1 ^ coeff2, data.varnode(compare_const).size);
        data.op_set_inputs(id, vec![left, constant]);
        1
    }
}

// Comparisons: extremal constants, sign-bit extraction, and boolean composition.

/// Simplify unsigned less-than applied to zero or all ones.
pub struct RuleLess2Zero;

impl Rule for RuleLess2Zero {
    fn name(&self) -> &'static str {
        "less2zero"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_LESS]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((left, right)) = inputs2(data, id) else {
            return 0;
        };
        if is_constant(data, left) {
            let value = data.varnode(left).offset;
            if value == 0 {
                data.op_set_opcode(id, op::INT_NOTEQUAL);
                return 1;
            }
            if value == calc_mask(data.varnode(left).size) {
                set_constant(data, id, 0, 1);
                return 1;
            }
        } else if is_constant(data, right) {
            let value = data.varnode(right).offset;
            if value == 0 {
                set_constant(data, id, 0, 1);
                return 1;
            }
            if value == calc_mask(data.varnode(right).size) {
                data.op_set_opcode(id, op::INT_NOTEQUAL);
                return 1;
            }
        }
        0
    }
}

/// Simplify unsigned less-or-equal applied to zero or all ones.
pub struct RuleLessEqual2Zero;

impl Rule for RuleLessEqual2Zero {
    fn name(&self) -> &'static str {
        "lessequal2zero"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_LESSEQUAL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((left, right)) = inputs2(data, id) else {
            return 0;
        };
        if is_constant(data, left) {
            let value = data.varnode(left).offset;
            if value == 0 {
                set_constant(data, id, 1, 1);
                return 1;
            }
            if value == calc_mask(data.varnode(left).size) {
                data.op_set_opcode(id, op::INT_EQUAL);
                return 1;
            }
        } else if is_constant(data, right) {
            let value = data.varnode(right).offset;
            if value == 0 {
                data.op_set_opcode(id, op::INT_EQUAL);
                return 1;
            }
            if value == calc_mask(data.varnode(right).size) {
                set_constant(data, id, 1, 1);
                return 1;
            }
        }
        0
    }
}

fn high_bit(data: &Funcdata, operation: OpId) -> Option<VarnodeId> {
    let opcode = data.op(operation).opcode;
    if !matches!(opcode, op::INT_ADD | op::INT_OR | op::INT_XOR) {
        return None;
    }
    let (left, right) = inputs2(data, operation)?;
    let sign = calc_mask(data.varnode(left).size) ^ (calc_mask(data.varnode(left).size) >> 1);
    let left_mask = nonzero_mask(data, left, MASK_DEPTH);
    let right_mask = nonzero_mask(data, right, MASK_DEPTH);
    if left_mask != sign && left_mask & sign != 0 {
        return None;
    }
    if right_mask != sign && right_mask & sign != 0 {
        return None;
    }
    if left_mask == sign {
        Some(left)
    } else if right_mask == sign {
        Some(right)
    } else {
        None
    }
}

/// Simplify signed-less-than tests whose sign is controlled by one high bit.
pub struct RuleSLess2Zero;

impl Rule for RuleSLess2Zero {
    fn name(&self) -> &'static str {
        "sless2zero"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_SLESS]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((left, right)) = inputs2(data, id) else {
            return 0;
        };
        if is_constant(data, left) {
            if data.varnode(left).offset != calc_mask(data.varnode(left).size) {
                return 0;
            }
            let Some(feed) = data.varnode(right).def else {
                return 0;
            };
            if let Some(hibit) = high_bit(data, feed) {
                let replacement = if is_constant(data, hibit) {
                    data.new_constant(data.varnode(hibit).offset, data.varnode(hibit).size)
                } else {
                    hibit
                };
                let zero = data.new_constant(0, data.varnode(hibit).size);
                data.op_set_inputs(id, vec![zero, replacement]);
                data.op_set_opcode(id, op::INT_EQUAL);
                return 1;
            }
            match data.op(feed).opcode {
                op::SUBPIECE => {
                    let Some((base, offset)) = inputs2(data, feed) else {
                        return 0;
                    };
                    if !is_constant(data, offset)
                        || data.varnode(base).size > 8
                        || u64::from(data.varnode(right).size)
                            .saturating_add(data.varnode(offset).offset)
                            != u64::from(data.varnode(base).size)
                    {
                        return 0;
                    }
                    let full = data
                        .new_constant(calc_mask(data.varnode(base).size), data.varnode(base).size);
                    data.op_set_inputs(id, vec![full, base]);
                    return 1;
                }
                op::INT_NEGATE => {
                    let Some(value) = data.op(feed).inputs.first().copied() else {
                        return 0;
                    };
                    let zero = data.new_constant(0, data.varnode(value).size);
                    data.op_set_inputs(id, vec![value, zero]);
                    return 1;
                }
                op::INT_AND => {
                    let Some((value, mask)) = inputs2(data, feed) else {
                        return 0;
                    };
                    let sign = data
                        .varnode(value)
                        .size
                        .checked_mul(8)
                        .and_then(|bits| bits.checked_sub(1));
                    if !is_constant(data, mask)
                        || data.varnode(right).descendants.len() != 1
                        || sign.is_none_or(|bit| data.varnode(mask).offset & (1u64 << bit) == 0)
                    {
                        return 0;
                    }
                    data.op_set_input(id, value, 1);
                    return 1;
                }
                op::PIECE => {
                    let Some((high, _)) = inputs2(data, feed) else {
                        return 0;
                    };
                    let full = data
                        .new_constant(calc_mask(data.varnode(high).size), data.varnode(high).size);
                    data.op_set_inputs(id, vec![full, high]);
                    return 1;
                }
                op::INT_LEFT => {
                    let Some((value, amount)) = inputs2(data, feed) else {
                        return 0;
                    };
                    if !is_constant(data, amount)
                        || data.varnode(amount).offset != u64::from(data.varnode(left).size) * 8 - 1
                        || data.varnode(value).def.is_none()
                        || !bool_output(data, value)
                    {
                        return 0;
                    }
                    data.op_set_inputs(id, vec![value]);
                    data.op_set_opcode(id, op::BOOL_NEGATE);
                    return 1;
                }
                _ => {}
            }
        } else if is_constant(data, right) {
            if data.varnode(right).offset != 0 {
                return 0;
            }
            let Some(feed) = data.varnode(left).def else {
                return 0;
            };
            if let Some(hibit) = high_bit(data, feed) {
                let replacement = if is_constant(data, hibit) {
                    data.new_constant(data.varnode(hibit).offset, data.varnode(hibit).size)
                } else {
                    hibit
                };
                data.op_set_input(id, replacement, 0);
                data.op_set_opcode(id, op::INT_NOTEQUAL);
                return 1;
            }
            match data.op(feed).opcode {
                op::SUBPIECE => {
                    let Some((base, offset)) = inputs2(data, feed) else {
                        return 0;
                    };
                    if !is_constant(data, offset)
                        || data.varnode(base).size > 8
                        || u64::from(data.varnode(left).size)
                            .saturating_add(data.varnode(offset).offset)
                            != u64::from(data.varnode(base).size)
                    {
                        return 0;
                    }
                    let zero = data.new_constant(0, data.varnode(base).size);
                    data.op_set_inputs(id, vec![base, zero]);
                    return 1;
                }
                op::INT_NEGATE => {
                    let Some(value) = data.op(feed).inputs.first().copied() else {
                        return 0;
                    };
                    let full = data.new_constant(
                        calc_mask(data.varnode(value).size),
                        data.varnode(value).size,
                    );
                    data.op_set_inputs(id, vec![value, full]);
                    return 1;
                }
                op::INT_AND => {
                    let Some((value, mask)) = inputs2(data, feed) else {
                        return 0;
                    };
                    let sign = data
                        .varnode(value)
                        .size
                        .checked_mul(8)
                        .and_then(|bits| bits.checked_sub(1));
                    if !is_constant(data, mask)
                        || data.varnode(right).descendants.len() != 1
                        || sign.is_none_or(|bit| data.varnode(mask).offset & (1u64 << bit) == 0)
                    {
                        return 0;
                    }
                    data.op_set_input(id, value, 0);
                    return 1;
                }
                op::PIECE => {
                    let Some((high, _)) = inputs2(data, feed) else {
                        return 0;
                    };
                    let zero = data.new_constant(0, data.varnode(high).size);
                    data.op_set_inputs(id, vec![high, zero]);
                    return 1;
                }
                _ => {}
            }
        }
        0
    }
}

/// Turn a less-or-equal combined with not-equal into strict less-than.
pub struct RuleLessNotEqual;

impl Rule for RuleLessNotEqual {
    fn name(&self) -> &'static str {
        "lessnotequal"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::BOOL_AND]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((first, second)) = inputs2(data, id) else {
            return 0;
        };
        let Some(first_def) = data.varnode(first).def else {
            return 0;
        };
        let Some(second_def) = data.varnode(second).def else {
            return 0;
        };
        let first_code = data.op(first_def).opcode;
        let (less_id, equal_id, less_code) =
            if matches!(first_code, op::INT_LESSEQUAL | op::INT_SLESSEQUAL) {
                (first_def, second_def, first_code)
            } else if matches!(
                data.op(second_def).opcode,
                op::INT_LESSEQUAL | op::INT_SLESSEQUAL
            ) {
                (second_def, first_def, data.op(second_def).opcode)
            } else {
                return 0;
            };
        if data.opcode_of(equal_id) != Some(op::INT_NOTEQUAL) {
            return 0;
        }
        let Some((a, b)) = inputs2(data, less_id) else {
            return 0;
        };
        let Some((ea, eb)) = inputs2(data, equal_id) else {
            return 0;
        };
        if !((a == ea && b == eb) || (a == eb && b == ea)) {
            return 0;
        }
        data.op_set_inputs(id, vec![a, b]);
        data.op_set_opcode(
            id,
            if less_code == op::INT_SLESSEQUAL {
                op::INT_SLESS
            } else {
                op::INT_LESS
            },
        );
        1
    }
}

/// Transform `< 1` and `<= 0` into equality with zero.
pub struct RuleLessOne;

impl Rule for RuleLessOne {
    fn name(&self) -> &'static str {
        "lessone"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_LESS, op::INT_LESSEQUAL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((_, constant)) = inputs2(data, id) else {
            return 0;
        };
        if !is_constant(data, constant) {
            return 0;
        }
        let value = data.varnode(constant).offset;
        if (data.op(id).opcode == op::INT_LESS && value != 1)
            || (data.op(id).opcode == op::INT_LESSEQUAL && value != 0)
        {
            return 0;
        }
        data.op_set_opcode(id, op::INT_EQUAL);
        if value != 0 {
            let zero = data.new_constant(0, data.varnode(constant).size);
            data.op_set_input(id, zero, 1);
        }
        1
    }
}

/// Re-express equality against a constant after add, negate, or multiply-by-minus-one.
pub struct RuleEqual2Constant;

impl Rule for RuleEqual2Constant {
    fn name(&self) -> &'static str {
        "equal2constant"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_EQUAL, op::INT_NOTEQUAL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((lhs, compare_const)) = inputs2(data, id) else {
            return 0;
        };
        if !is_constant(data, compare_const) {
            return 0;
        }
        let Some(left_id) = data.varnode(lhs).def else {
            return 0;
        };
        let source;
        let new_value;
        match data.op(left_id).opcode {
            op::INT_ADD => {
                let Some((input, constant)) = inputs2(data, left_id) else {
                    return 0;
                };
                if !is_constant(data, constant) {
                    return 0;
                }
                source = input;
                new_value = data
                    .varnode(compare_const)
                    .offset
                    .wrapping_sub(data.varnode(constant).offset)
                    & calc_mask(data.varnode(compare_const).size);
            }
            op::INT_MULT => {
                let Some((input, constant)) = inputs2(data, left_id) else {
                    return 0;
                };
                if !is_constant(data, constant)
                    || data.varnode(constant).offset != calc_mask(data.varnode(constant).size)
                {
                    return 0;
                }
                source = input;
                new_value = data.varnode(compare_const).offset.wrapping_neg()
                    & calc_mask(data.varnode(constant).size);
            }
            op::INT_NEGATE => {
                let Some(input) = data.op(left_id).inputs.first().copied() else {
                    return 0;
                };
                source = input;
                new_value =
                    (!data.varnode(compare_const).offset) & calc_mask(data.varnode(lhs).size);
            }
            _ => return 0,
        }
        for descendant in data.varnode(lhs).descendants.iter().copied() {
            if descendant == id {
                continue;
            }
            if !matches!(
                data.opcode_of(descendant),
                Some(op::INT_EQUAL | op::INT_NOTEQUAL)
            ) {
                return 0;
            }
            let Some(other) = data.op(descendant).inputs.get(1).copied() else {
                return 0;
            };
            if !is_constant(data, other) {
                return 0;
            }
        }
        let replacement = data.new_constant(new_value, data.varnode(source).size);
        data.op_set_inputs(id, vec![source, replacement]);
        1
    }
}

/// Distribute boolean NOT over a boolean AND/OR.
pub struct RuleNotDistribute;

impl Rule for RuleNotDistribute {
    fn name(&self) -> &'static str {
        "notdistribute"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::BOOL_NEGATE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(input) = data.op(id).inputs.first().copied() else {
            return 0;
        };
        let Some(composite) = data.varnode(input).def else {
            return 0;
        };
        let new_code = match data.op(composite).opcode {
            op::BOOL_AND => op::BOOL_OR,
            op::BOOL_OR => op::BOOL_AND,
            _ => return 0,
        };
        let Some((left, right)) = inputs2(data, composite) else {
            return 0;
        };
        let seq = data.op(id).seq;
        let first = data.new_op(op::BOOL_NEGATE, seq, vec![left]);
        let first_out = data.new_unique(1);
        data.op_set_output(first, Some(first_out));
        data.op_insert_before(first, id);
        let second = data.new_op(op::BOOL_NEGATE, seq, vec![right]);
        let second_out = data.new_unique(1);
        data.op_set_output(second, Some(second_out));
        data.op_insert_before(second, id);
        data.op_set_opcode(id, new_code);
        data.op_set_inputs(id, vec![first_out, second_out]);
        1
    }
}

// Zext/Sext: remove, commute, or cancel zero extensions and truncations.

/// Remove a zero extension when the comparison constant fits the source width.
pub struct RuleZextEliminate;

impl Rule for RuleZextEliminate {
    fn name(&self) -> &'static str {
        "zexteliminate"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![
            op::INT_EQUAL,
            op::INT_NOTEQUAL,
            op::INT_LESS,
            op::INT_LESSEQUAL,
        ]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((first, second)) = inputs2(data, id) else {
            return 0;
        };
        let (zext_value, constant, zext_slot, other_slot) =
            if def_opcode(data, second) == Some(op::INT_ZEXT) && is_constant(data, first) {
                (second, first, 1usize, 0usize)
            } else if def_opcode(data, first) == Some(op::INT_ZEXT) && is_constant(data, second) {
                (first, second, 0usize, 1usize)
            } else {
                return 0;
            };
        if data.varnode(zext_value).descendants.len() != 1 {
            return 0;
        }
        let Some(zext_id) = data.varnode(zext_value).def else {
            return 0;
        };
        let Some(source) = data.op(zext_id).inputs.first().copied() else {
            return 0;
        };
        let small_size = data.varnode(source).size;
        let value = data.varnode(constant).offset;
        if small_size < 8 && value >> (small_size * 8) != 0 {
            return 0;
        }
        let new_constant = data.new_constant(value & calc_mask(small_size), small_size);
        let mut inputs = data.op(id).inputs.clone();
        inputs[zext_slot] = source;
        inputs[other_slot] = new_constant;
        data.op_set_inputs(id, inputs);
        1
    }
}

/// Convert signed comparison of a zero-extended value into unsigned comparison.
pub struct RuleZextSless;

impl Rule for RuleZextSless {
    fn name(&self) -> &'static str {
        "zextsless"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_SLESS, op::INT_SLESSEQUAL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((first, second)) = inputs2(data, id) else {
            return 0;
        };
        let (zext_value, constant, zext_slot, other_slot) =
            if def_opcode(data, second) == Some(op::INT_ZEXT) && is_constant(data, first) {
                (second, first, 1usize, 0usize)
            } else if def_opcode(data, first) == Some(op::INT_ZEXT) && is_constant(data, second) {
                (first, second, 0usize, 1usize)
            } else {
                return 0;
            };
        let Some(zext_id) = data.varnode(zext_value).def else {
            return 0;
        };
        let Some(source) = data.op(zext_id).inputs.first().copied() else {
            return 0;
        };
        let small_size = data.varnode(source).size;
        if small_size == 0 {
            return 0;
        }
        let sign_bit = 1u64 << (small_size * 8 - 1);
        if data.varnode(constant).offset & sign_bit != 0 {
            return 0;
        }
        let new_constant = data.new_constant(
            data.varnode(constant).offset & calc_mask(small_size),
            small_size,
        );
        let mut inputs = data.op(id).inputs.clone();
        inputs[zext_slot] = source;
        inputs[other_slot] = new_constant;
        data.op_set_inputs(id, inputs);
        let new_opcode = if data.op(id).opcode == op::INT_SLESS {
            op::INT_LESS
        } else {
            op::INT_LESSEQUAL
        };
        data.op_set_opcode(id, new_opcode);
        1
    }
}

/// Push an unsigned right shift through a zero extension.
pub struct RuleZextCommute;

impl Rule for RuleZextCommute {
    fn name(&self) -> &'static str {
        "zextcommute"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_RIGHT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((zext_value, amount)) = inputs2(data, id) else {
            return 0;
        };
        let Some(zext_id) = data.varnode(zext_value).def else {
            return 0;
        };
        if data.opcode_of(zext_id) != Some(op::INT_ZEXT) {
            return 0;
        }
        let Some(source) = data.op(zext_id).inputs.first().copied() else {
            return 0;
        };
        let size = data.varnode(source).size;
        let seq = data.op(id).seq;
        let inner = data.new_op(op::INT_RIGHT, seq, vec![source, amount]);
        let inner_out = data.new_unique(size);
        data.op_set_output(inner, Some(inner_out));
        data.op_insert_before(inner, id);
        data.op_set_inputs(id, vec![inner_out]);
        data.op_set_opcode(id, op::INT_ZEXT);
        1
    }
}

/// Turn zext(subpiece) into a mask, optionally shifting the source first.
pub struct RuleSubZext;

impl Rule for RuleSubZext {
    fn name(&self) -> &'static str {
        "subzext"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_ZEXT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(sub_value) = data.op(id).inputs.first().copied() else {
            return 0;
        };
        let Some(first_def) = data.varnode(sub_value).def else {
            return 0;
        };
        if data.opcode_of(first_def) == Some(op::SUBPIECE) {
            let sub_id = first_def;
            let Some((base, offset)) = inputs2(data, sub_id) else {
                return 0;
            };
            let Some(output) = data.op(id).output else {
                return 0;
            };
            let output_size = data.varnode(output).size;
            if data.varnode(base).size != output_size || data.varnode(base).size > 8 {
                return 0;
            }
            let offset_value = data.varnode(offset).offset;
            if offset_value != 0 {
                if data.varnode(sub_value).descendants.len() != 1 {
                    return 0;
                }
                let new_value = data.new_unique(data.varnode(base).size);
                let shift_amount =
                    data.new_constant(offset_value.saturating_mul(8), data.varnode(offset).size);
                data.op_set_input(id, new_value, 0);
                data.op_set_opcode(sub_id, op::INT_RIGHT);
                data.op_set_input(sub_id, shift_amount, 1);
                data.op_set_output(sub_id, Some(new_value));
            } else {
                data.op_set_input(id, base, 0);
            }
            let mask = data.new_constant(
                calc_mask(data.varnode(sub_value).size),
                data.varnode(base).size,
            );
            data.op_set_opcode(id, op::INT_AND);
            data.op_set_input(id, mask, 1);
            return 1;
        }
        if data.opcode_of(first_def) != Some(op::INT_RIGHT) {
            return 0;
        }
        let shift_id = first_def;
        let Some((middle, shift_amount)) = inputs2(data, shift_id) else {
            return 0;
        };
        if !is_constant(data, shift_amount) || data.varnode(middle).def.is_none() {
            return 0;
        }
        let sub_id = data.varnode(middle).def.expect("checked above");
        if data.opcode_of(sub_id) != Some(op::SUBPIECE) {
            return 0;
        }
        let Some((base, offset)) = inputs2(data, sub_id) else {
            return 0;
        };
        if !is_constant(data, offset) {
            return 0;
        }
        let Some(output) = data.op(id).output else {
            return 0;
        };
        let output_size = data.varnode(output).size;
        if data.varnode(base).size != output_size
            || data.varnode(middle).descendants.len() != 1
            || data.varnode(sub_value).descendants.len() != 1
            || !is_constant(data, offset)
        {
            return 0;
        }
        let shift = data.varnode(shift_amount).offset;
        let mask = shift_right(
            calc_mask(data.varnode(middle).size),
            shift,
            data.varnode(base).size,
        );
        let combined = data
            .varnode(offset)
            .offset
            .saturating_mul(8)
            .saturating_add(shift);
        let new_value = data.new_unique(data.varnode(base).size);
        let combined_constant = data.new_constant(combined, data.varnode(shift_amount).size);
        data.op_set_input(id, new_value, 0);
        data.op_set_input(shift_id, base, 0);
        data.op_set_input(shift_id, combined_constant, 1);
        data.op_set_output(shift_id, Some(new_value));
        data.op_set_opcode(id, op::INT_AND);
        let mask_constant = data.new_constant(mask, data.varnode(base).size);
        data.op_set_input(id, mask_constant, 1);
        1
    }
}

/// Cancel a low SUBPIECE against an extension or a matching mask.
pub struct RuleSubCancel;

impl Rule for RuleSubCancel {
    fn name(&self) -> &'static str {
        "subcancel"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::SUBPIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((base, offset_vn)) = inputs2(data, id) else {
            return 0;
        };
        if !is_constant(data, offset_vn) {
            return 0;
        }
        let Some(ext_id) = data.varnode(base).def else {
            return 0;
        };
        let ext_code = data.op(ext_id).opcode;
        if !matches!(ext_code, op::INT_ZEXT | op::INT_SEXT | op::INT_AND) {
            return 0;
        }
        let offset = data.varnode(offset_vn).offset;
        let Some(output) = data.op(id).output else {
            return 0;
        };
        let output_size = data.varnode(output).size;
        if ext_code == op::INT_AND {
            let Some((through, mask)) = inputs2(data, ext_id) else {
                return 0;
            };
            if offset == 0
                && is_constant(data, mask)
                && data.varnode(mask).offset == calc_mask(output_size)
            {
                data.op_set_input(id, through, 0);
                return 1;
            }
            return 0;
        }
        let Some(through) = data.op(ext_id).inputs.first().copied() else {
            return 0;
        };
        let input_size = data.varnode(through).size;
        let mut new_opcode = ext_code;
        let mut new_input = through;
        if offset == 0 {
            if output_size == input_size {
                new_opcode = op::COPY;
            } else if output_size < input_size {
                new_opcode = op::SUBPIECE;
            }
        } else if ext_code == op::INT_ZEXT && u64::from(input_size) <= offset {
            new_opcode = op::COPY;
            new_input = data.new_constant(0, output_size);
        } else {
            return 0;
        }
        data.op_set_opcode(id, new_opcode);
        data.op_set_input(id, new_input, 0);
        if new_opcode == op::SUBPIECE {
            data.op_set_input(id, offset_vn, 1);
        } else {
            data.op_set_inputs(id, vec![new_input]);
        }
        1
    }
}

// Every requested pass that needed CircleRange, type metadata, or a source
// class absent from the pinned tree is deliberately omitted above.

/// Every rule this module ports, for registration.
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(RuleAddMultCollapse),
        Box::new(RuleIdentityEl),
        Box::new(RuleShiftBitops),
        Box::new(RuleDoubleShift),
        Box::new(RuleSubRight),
        Box::new(RuleTrivialShift),
        Box::new(RuleAndDistribute),
        Box::new(RuleOrCollapse),
        Box::new(RuleXorCollapse),
        Box::new(RuleAndCommute),
        Box::new(RuleAndCompare),
        Box::new(RuleShift2Mult),
        Box::new(RuleShiftSub),
        Box::new(RulePiece2Zext),
        Box::new(RuleConcatShift),
        Box::new(RuleLess2Zero),
        Box::new(RuleLessEqual2Zero),
        Box::new(RuleSLess2Zero),
        Box::new(RuleLessNotEqual),
        Box::new(RuleLessOne),
        Box::new(RuleEqual2Constant),
        Box::new(RuleNotDistribute),
        Box::new(RuleZextEliminate),
        Box::new(RuleZextSless),
        Box::new(RuleZextCommute),
        Box::new(RuleSubZext),
        Box::new(RuleSubCancel),
    ]
}
#[cfg(test)]
mod tests {
    use super::super::{GraphBlockId, SeqNum};
    use super::*;
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    fn input(data: &mut Funcdata, size: u32) -> VarnodeId {
        let value = data.new_varnode(REGISTER_SPACE, (data.varnode_count() as u64) * 8, size);
        data.mark_input(value);
        value
    }

    fn binary(
        data: &mut Funcdata,
        block: GraphBlockId,
        opcode: i32,
        left: VarnodeId,
        right: VarnodeId,
        output_size: u32,
    ) -> (OpId, VarnodeId) {
        let address = 0x1000 + data.op_count() as u64 * 4;
        let id = data.new_op(opcode, seq(address), vec![left, right]);
        let output = data.new_unique(output_size);
        data.op_set_output(id, Some(output));
        data.op_insert_end(id, block);
        (id, output)
    }

    fn unary(
        data: &mut Funcdata,
        block: GraphBlockId,
        opcode: i32,
        input: VarnodeId,
        output_size: u32,
    ) -> (OpId, VarnodeId) {
        let address = 0x1000 + data.op_count() as u64 * 4;
        let id = data.new_op(opcode, seq(address), vec![input]);
        let output = data.new_unique(output_size);
        data.op_set_output(id, Some(output));
        data.op_insert_end(id, block);
        (id, output)
    }

    #[test]
    fn all_matches_the_number_of_rule_impls() {
        let marker = ["impl Rule", " for "].concat();
        let count = include_str!("expr_rules.rs").matches(&marker).count();
        assert_eq!(all().len(), count);
    }

    #[test]
    fn add_mult_collapse_fires_and_declines_without_nested_constant() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 4);
        let c1 = data.new_constant(3, 4);
        let (_, inner) = binary(&mut data, block, op::INT_ADD, value, c1, 4);
        let c2 = data.new_constant(5, 4);
        let (outer, _) = binary(&mut data, block, op::INT_ADD, inner, c2, 4);
        assert_eq!(RuleAddMultCollapse.apply_op(outer, &mut data), 1);
        assert_eq!(data.varnode(data.op(outer).inputs[1]).offset, 8);
        let (bad, _) = binary(&mut data, block, op::INT_ADD, inner, value, 4);
        assert_eq!(RuleAddMultCollapse.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn identity_el_fires_and_declines_for_nonidentity() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 4);
        let zero = data.new_constant(0, 4);
        let (add, _) = binary(&mut data, block, op::INT_ADD, value, zero, 4);
        assert_eq!(RuleIdentityEl.apply_op(add, &mut data), 1);
        let two = data.new_constant(2, 4);
        let (bad, _) = binary(&mut data, block, op::INT_ADD, value, two, 4);
        assert_eq!(RuleIdentityEl.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn shift_bitops_fires_and_declines_when_bits_survive() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let low = data.new_constant(0x0f, 4);
        let high = data.new_constant(0xf000_0000, 4);
        let (_, and_out) = binary(&mut data, block, op::INT_AND, low, high, 4);
        let amount = data.new_constant(4, 4);
        let (shift, _) = binary(&mut data, block, op::INT_LEFT, and_out, amount, 4);
        assert_eq!(RuleShiftBitops.apply_op(shift, &mut data), 1);
        assert!(data.varnode(data.op(shift).inputs[0]).flags.constant);
        let source = input(&mut data, 4);
        let (_, and_out2) = binary(&mut data, block, op::INT_AND, source, high, 4);
        let one = data.new_constant(1, 4);
        let (bad, _) = binary(&mut data, block, op::INT_LEFT, and_out2, one, 4);
        assert_eq!(RuleShiftBitops.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn double_shift_fires_and_declines_for_nonpower_multiply() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 4);
        let inner_amount = data.new_constant(2, 4);
        let (_, inner_out) = binary(&mut data, block, op::INT_LEFT, value, inner_amount, 4);
        let outer_amount = data.new_constant(3, 4);
        let (outer, _) = binary(&mut data, block, op::INT_LEFT, inner_out, outer_amount, 4);
        assert_eq!(RuleDoubleShift.apply_op(outer, &mut data), 1);
        assert_eq!(data.varnode(data.op(outer).inputs[1]).offset, 5);
        let bad_amount = data.new_constant(3, 4);
        let (_, bad_inner_out) = binary(&mut data, block, op::INT_MULT, value, bad_amount, 4);
        let (bad, _) = binary(
            &mut data,
            block,
            op::INT_LEFT,
            bad_inner_out,
            outer_amount,
            4,
        );
        assert_eq!(RuleDoubleShift.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn subright_fires_and_declines_at_low_piece() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 8);
        let offset = data.new_constant(2, 4);
        let (sub, _) = binary(&mut data, block, op::SUBPIECE, value, offset, 4);
        assert_eq!(RuleSubRight.apply_op(sub, &mut data), 1);
        assert_eq!(data.varnode(data.op(sub).inputs[1]).offset, 0);
        let zero = data.new_constant(0, 4);
        let (low, _) = binary(&mut data, block, op::SUBPIECE, value, zero, 4);
        assert_eq!(RuleSubRight.apply_op(low, &mut data), 0);
    }

    #[test]
    fn trivial_shift_fires_and_declines_for_partial_shift() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 4);
        let zero = data.new_constant(0, 4);
        let (shift, _) = binary(&mut data, block, op::INT_RIGHT, value, zero, 4);
        assert_eq!(RuleTrivialShift.apply_op(shift, &mut data), 1);
        let one = data.new_constant(1, 4);
        let (bad, _) = binary(&mut data, block, op::INT_RIGHT, value, one, 4);
        assert_eq!(RuleTrivialShift.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn and_distribute_fires_and_declines_when_no_term_cancels() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let a = data.new_constant(0x01, 4);
        let b = data.new_constant(0x02, 4);
        let (_, or_out) = binary(&mut data, block, op::INT_OR, a, b, 4);
        let mask = data.new_constant(0x01, 4);
        let (and, _) = binary(&mut data, block, op::INT_AND, or_out, mask, 4);
        assert_eq!(RuleAndDistribute.apply_op(and, &mut data), 1);
        let x = input(&mut data, 4);
        let y = input(&mut data, 4);
        let (_, or2) = binary(&mut data, block, op::INT_OR, x, y, 4);
        let full = data.new_constant(u32::MAX as u64, 4);
        let (bad, _) = binary(&mut data, block, op::INT_AND, or2, full, 4);
        assert_eq!(RuleAndDistribute.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn or_collapse_fires_and_declines_for_missing_bits() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = data.new_constant(0x03, 4);
        let mask = data.new_constant(0xff, 4);
        let (or, _) = binary(&mut data, block, op::INT_OR, value, mask, 4);
        assert_eq!(RuleOrCollapse.apply_op(or, &mut data), 1);
        let source = input(&mut data, 4);
        let partial = data.new_constant(0x0f, 4);
        let (bad, _) = binary(&mut data, block, op::INT_OR, source, partial, 4);
        assert_eq!(RuleOrCollapse.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn xor_collapse_fires_and_declines_for_zero_constant() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 4);
        let c = data.new_constant(3, 4);
        let (_, xor_out) = binary(&mut data, block, op::INT_XOR, value, c, 4);
        let target = data.new_constant(7, 4);
        let (cmp, _) = binary(&mut data, block, op::INT_EQUAL, xor_out, target, 1);
        assert_eq!(RuleXorCollapse.apply_op(cmp, &mut data), 1);
        assert_eq!(data.varnode(data.op(cmp).inputs[1]).offset, 4);
        let zero = data.new_constant(0, 4);
        let (_, xor_zero) = binary(&mut data, block, op::INT_XOR, value, zero, 4);
        let (bad, _) = binary(&mut data, block, op::INT_EQUAL, xor_zero, target, 1);
        assert_eq!(RuleXorCollapse.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn and_commute_fires_and_declines_without_shift_source() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let a = data.new_constant(0x03, 4);
        let b = data.new_constant(0x0c, 4);
        let (_, or_out) = binary(&mut data, block, op::INT_OR, a, b, 4);
        let shift_amount = data.new_constant(2, 4);
        let (_, shifted) = binary(&mut data, block, op::INT_LEFT, or_out, shift_amount, 4);
        let mask = data.new_constant(0x30, 4);
        let (and, _) = binary(&mut data, block, op::INT_AND, shifted, mask, 4);
        assert_eq!(RuleAndCommute.apply_op(and, &mut data), 1);
        let source = input(&mut data, 4);
        let (bad, _) = binary(&mut data, block, op::INT_AND, source, mask, 4);
        assert_eq!(RuleAndCommute.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn and_compare_fires_and_declines_for_nonzero_comparison() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let source = input(&mut data, 1);
        let (_, zext) = unary(&mut data, block, op::INT_ZEXT, source, 4);
        let mask = data.new_constant(0xff, 4);
        let (_, and_out) = binary(&mut data, block, op::INT_AND, zext, mask, 4);
        let cmp_zero = data.new_constant(0, 4);
        let (cmp, _) = binary(&mut data, block, op::INT_EQUAL, and_out, cmp_zero, 1);
        assert_eq!(RuleAndCompare.apply_op(cmp, &mut data), 1);
        let (_, and_bad) = binary(&mut data, block, op::INT_AND, zext, mask, 4);
        let nonzero = data.new_constant(1, 4);
        let (bad, _) = binary(&mut data, block, op::INT_EQUAL, and_bad, nonzero, 1);
        assert_eq!(RuleAndCompare.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn shift2mult_fires_only_when_arithmetic_use_exists() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 4);
        let amount = data.new_constant(2, 4);
        let (shift, shifted) = binary(&mut data, block, op::INT_LEFT, value, amount, 4);
        let one = data.new_constant(1, 4);
        let _ = binary(&mut data, block, op::INT_ADD, shifted, one, 4);
        assert_eq!(RuleShift2Mult.apply_op(shift, &mut data), 1);
        let (bad, _) = binary(&mut data, block, op::INT_LEFT, value, amount, 4);
        assert_eq!(RuleShift2Mult.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn shift_sub_fires_for_byte_aligned_shift_and_declines_other_alignment() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 8);
        let shift_amount = data.new_constant(8, 4);
        let (_, shifted) = binary(&mut data, block, op::INT_LEFT, value, shift_amount, 8);
        let offset = data.new_constant(2, 4);
        let (sub, _) = binary(&mut data, block, op::SUBPIECE, shifted, offset, 4);
        assert_eq!(RuleShiftSub.apply_op(sub, &mut data), 1);
        let non_byte = data.new_constant(1, 4);
        let (_, shifted2) = binary(&mut data, block, op::INT_LEFT, value, non_byte, 8);
        let (bad, _) = binary(&mut data, block, op::SUBPIECE, shifted2, offset, 4);
        assert_eq!(RuleShiftSub.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn piece_to_zext_fires_and_declines_for_nonzero_high_piece() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let high = data.new_constant(0, 2);
        let low = input(&mut data, 2);
        let (piece, _) = binary(&mut data, block, op::PIECE, high, low, 4);
        assert_eq!(RulePiece2Zext.apply_op(piece, &mut data), 1);
        let nonzero = data.new_constant(1, 2);
        let (bad, _) = binary(&mut data, block, op::PIECE, nonzero, low, 4);
        assert_eq!(RulePiece2Zext.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn concat_shift_fires_and_declines_before_low_piece_is_discarded() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let high = input(&mut data, 1);
        let low = input(&mut data, 1);
        let (_, piece) = binary(&mut data, block, op::PIECE, high, low, 2);
        let amount = data.new_constant(8, 4);
        let (shift, _) = binary(&mut data, block, op::INT_RIGHT, piece, amount, 2);
        assert_eq!(RuleConcatShift.apply_op(shift, &mut data), 1);
        let low_amount = data.new_constant(4, 4);
        let (_, piece_bad) = binary(&mut data, block, op::PIECE, high, low, 2);
        let (bad, _) = binary(&mut data, block, op::INT_RIGHT, piece_bad, low_amount, 2);
        assert_eq!(RuleConcatShift.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn less_zero_rules_fire_and_decline_on_interior_constants() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 4);
        let zero = data.new_constant(0, 4);
        let (less, _) = binary(&mut data, block, op::INT_LESS, value, zero, 1);
        assert_eq!(RuleLess2Zero.apply_op(less, &mut data), 1);
        let (le, _) = binary(&mut data, block, op::INT_LESSEQUAL, value, zero, 1);
        assert_eq!(RuleLessEqual2Zero.apply_op(le, &mut data), 1);
        let two = data.new_constant(2, 4);
        let (bad, _) = binary(&mut data, block, op::INT_LESS, value, two, 1);
        assert_eq!(RuleLess2Zero.apply_op(bad, &mut data), 0);
        let (le_bad, _) = binary(&mut data, block, op::INT_LESSEQUAL, value, two, 1);
        assert_eq!(RuleLessEqual2Zero.apply_op(le_bad, &mut data), 0);
    }

    #[test]
    fn sless_zero_fires_for_piece_sign_and_declines_without_extreme_constant() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let high = input(&mut data, 1);
        let low = input(&mut data, 1);
        let (_, piece) = binary(&mut data, block, op::PIECE, high, low, 2);
        let minus_one = data.new_constant(u16::MAX as u64, 2);
        let (cmp, _) = binary(&mut data, block, op::INT_SLESS, minus_one, piece, 1);
        assert_eq!(RuleSLess2Zero.apply_op(cmp, &mut data), 1);
        let one = data.new_constant(1, 2);
        let (bad, _) = binary(&mut data, block, op::INT_SLESS, one, piece, 1);
        assert_eq!(RuleSLess2Zero.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn less_not_equal_fires_and_declines_for_mismatched_operands() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let a = input(&mut data, 4);
        let b = input(&mut data, 4);
        let (_, le_out) = binary(&mut data, block, op::INT_LESSEQUAL, a, b, 1);
        let (_, ne_out) = binary(&mut data, block, op::INT_NOTEQUAL, a, b, 1);
        let (both, _) = binary(&mut data, block, op::BOOL_AND, le_out, ne_out, 1);
        assert_eq!(RuleLessNotEqual.apply_op(both, &mut data), 1);
        let c = input(&mut data, 4);
        let (_, ne_bad_out) = binary(&mut data, block, op::INT_NOTEQUAL, a, c, 1);
        let (bad, _) = binary(&mut data, block, op::BOOL_AND, le_out, ne_bad_out, 1);
        assert_eq!(RuleLessNotEqual.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn less_one_fires_and_declines_for_other_threshold() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 4);
        let one = data.new_constant(1, 4);
        let (less, _) = binary(&mut data, block, op::INT_LESS, value, one, 1);
        assert_eq!(RuleLessOne.apply_op(less, &mut data), 1);
        let two = data.new_constant(2, 4);
        let (bad, _) = binary(&mut data, block, op::INT_LESS, value, two, 1);
        assert_eq!(RuleLessOne.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn equal_two_constant_fires_and_declines_for_nonconstant_offset() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 4);
        let offset = data.new_constant(3, 4);
        let (_, added) = binary(&mut data, block, op::INT_ADD, value, offset, 4);
        let target = data.new_constant(8, 4);
        let (cmp, _) = binary(&mut data, block, op::INT_EQUAL, added, target, 1);
        assert_eq!(RuleEqual2Constant.apply_op(cmp, &mut data), 1);
        assert_eq!(data.varnode(data.op(cmp).inputs[1]).offset, 5);
        let nonconstant = input(&mut data, 4);
        let (_, bad_added) = binary(&mut data, block, op::INT_ADD, value, nonconstant, 4);
        let (bad, _) = binary(&mut data, block, op::INT_EQUAL, bad_added, target, 1);
        assert_eq!(RuleEqual2Constant.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn not_distribute_fires_and_declines_for_arithmetic_input() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let a = input(&mut data, 1);
        let b = input(&mut data, 1);
        let (_, and_out) = binary(&mut data, block, op::BOOL_AND, a, b, 1);
        let (neg, _) = unary(&mut data, block, op::BOOL_NEGATE, and_out, 1);
        assert_eq!(RuleNotDistribute.apply_op(neg, &mut data), 1);
        let (_, arithmetic) = binary(&mut data, block, op::INT_ADD, a, b, 1);
        let (bad, _) = unary(&mut data, block, op::BOOL_NEGATE, arithmetic, 1);
        assert_eq!(RuleNotDistribute.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn zext_eliminate_fires_and_declines_when_constant_does_not_fit() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 1);
        let (_, wide) = unary(&mut data, block, op::INT_ZEXT, value, 4);
        let small = data.new_constant(0x7f, 4);
        let (cmp, _) = binary(&mut data, block, op::INT_EQUAL, wide, small, 1);
        assert_eq!(RuleZextEliminate.apply_op(cmp, &mut data), 1);
        let too_wide = data.new_constant(0x100, 4);
        let (_, wide_bad) = unary(&mut data, block, op::INT_ZEXT, value, 4);
        let (bad, _) = binary(&mut data, block, op::INT_EQUAL, wide_bad, too_wide, 1);
        assert_eq!(RuleZextEliminate.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn zext_sless_fires_and_declines_when_sign_bit_is_set() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 1);
        let (_, wide) = unary(&mut data, block, op::INT_ZEXT, value, 4);
        let positive = data.new_constant(0x7f, 4);
        let (cmp, _) = binary(&mut data, block, op::INT_SLESS, wide, positive, 1);
        assert_eq!(RuleZextSless.apply_op(cmp, &mut data), 1);
        let negative = data.new_constant(0x80, 4);
        let (_, wide_bad) = unary(&mut data, block, op::INT_ZEXT, value, 4);
        let (bad, _) = binary(&mut data, block, op::INT_SLESS, wide_bad, negative, 1);
        assert_eq!(RuleZextSless.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn zext_commute_fires_and_declines_without_zext_definition() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 1);
        let (_, wide) = unary(&mut data, block, op::INT_ZEXT, value, 4);
        let amount = data.new_constant(1, 4);
        let (shift, _) = binary(&mut data, block, op::INT_RIGHT, wide, amount, 4);
        assert_eq!(RuleZextCommute.apply_op(shift, &mut data), 1);
        let source = input(&mut data, 4);
        let (bad, _) = binary(&mut data, block, op::INT_RIGHT, source, amount, 4);
        assert_eq!(RuleZextCommute.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn sub_zext_fires_and_declines_for_non_subpiece() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 4);
        let offset = data.new_constant(0, 4);
        let (_, piece) = binary(&mut data, block, op::SUBPIECE, value, offset, 2);
        let (zext, _) = unary(&mut data, block, op::INT_ZEXT, piece, 4);
        assert_eq!(RuleSubZext.apply_op(zext, &mut data), 1);
        let (other, _) = unary(&mut data, block, op::INT_SEXT, value, 4);
        assert_eq!(RuleSubZext.apply_op(other, &mut data), 0);
    }

    #[test]
    fn sub_cancel_fires_and_declines_for_nonmatching_mask() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input(&mut data, 1);
        let (_, wide) = unary(&mut data, block, op::INT_ZEXT, value, 4);
        let offset = data.new_constant(0, 4);
        let (sub, _) = binary(&mut data, block, op::SUBPIECE, wide, offset, 1);
        assert_eq!(RuleSubCancel.apply_op(sub, &mut data), 1);
        let mask = data.new_constant(0x7f, 4);
        let (_, masked) = binary(&mut data, block, op::INT_AND, wide, mask, 4);
        let (bad, _) = binary(&mut data, block, op::SUBPIECE, masked, offset, 1);
        assert_eq!(RuleSubCancel.apply_op(bad, &mut data), 0);
    }
}
