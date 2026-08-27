//! Bitfield expression rewrites ported from Ghidra 12.1.3's `bitfield.cc`.
//!
//! Ghidra registers `RuleBitFieldStore`, `RuleBitFieldOut`, `RuleBitFieldLoad`,
//! `RulePullAbsorb` and `RuleInsertAbsorb` in the
//! `cleanup` pool under the `bitfields` group. The graph model has no
//! `TypeBitField` or bit-range metadata: `DataType::Struct` records byte fields
//! only. The four discovery rules therefore implement the graph-expressible
//! contiguous-mask forms and decline patterns whose field range cannot be
//! proven from p-code. The two absorb rules do not need type metadata and are
//! direct graph rewrites.
//!
//! `RuleBitFieldIn` is **not** ported, and the prerequisite is larger than one
//! accessor. Its whole discovery is `invn->getTypeReadFacing(op)->hasBitfields()`
//! - there is no structural fallback - so it needs a varnode to carry a
//! *declared* aggregate type with bit ranges. Five links stand between the
//! image and that: the DWARF reader would have to extract `DW_TAG_member` with
//! `DW_AT_bit_size`/`DW_AT_bit_offset`, `debuginfo::DebugType::Aggregate` would
//! have to grow a member list (it records a name and a byte size today), the
//! decompiler would have to consume `Image::debug_info` at all (nothing does),
//! declared types would have to be applied to varnodes, and `DataType` would
//! need a `TypeBitField` and the `has_bitfields` flag. The bit ranges are real
//! and in reach - `dungeon_game.elf`'s `.debug_abbrev` declares both attributes
//! - so this is a missing declared-type import path, not a missing rule.
//!
//! Registering it unguarded was measured and reverted: it fires on ordinary
//! masked arithmetic, breaking `vm_boot`'s call recovery and `TRK_fill_mem`'s
//! parameters for a net loss of one agreeing function.

use std::collections::BTreeSet;

use super::action::Rule;
use super::{Funcdata, OpId, SeqNum, VarnodeId};
use ventris_pcode::op;

#[derive(Copy, Clone, Debug)]
struct BitRange {
    pos: u32,
    bits: u32,
}

#[derive(Copy, Clone, Debug)]
struct ExtractSpec {
    root: VarnodeId,
    pos: u32,
    bits: u32,
    signed: bool,
}

#[derive(Copy, Clone, Debug)]
struct InsertSpec {
    base: VarnodeId,
    value: VarnodeId,
    pos: u32,
    bits: u32,
}

fn full_mask(size: u32) -> u64 {
    let width = size.saturating_mul(8);
    if width == 0 {
        0
    } else if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
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

fn constant(data: &Funcdata, value: VarnodeId) -> Option<u64> {
    let node = data.varnode(value);
    node.flags.constant.then_some(node.offset)
}

fn input(data: &Funcdata, id: OpId, slot: usize) -> Option<VarnodeId> {
    data.op(id).inputs.get(slot).copied()
}

fn output(data: &Funcdata, id: OpId) -> Option<VarnodeId> {
    data.op(id).output
}

fn definition(data: &Funcdata, value: VarnodeId) -> Option<OpId> {
    data.varnode(value).def
}

fn opcode_of_value(data: &Funcdata, value: VarnodeId, opcode: i32) -> Option<OpId> {
    let definition = definition(data, value)?;
    (data.opcode_of(definition) == Some(opcode)).then_some(definition)
}

fn seq(data: &Funcdata, id: OpId) -> SeqNum {
    data.op(id).seq
}

fn contiguous_range(mask: u64, size: u32) -> Option<BitRange> {
    let width = size.saturating_mul(8);
    let clipped = mask & full_mask(size);
    if clipped == 0 {
        return None;
    }
    let pos = clipped.trailing_zeros();
    let bits = clipped.count_ones();
    if pos.saturating_add(bits) > width || clipped != low_mask(bits) << pos {
        return None;
    }
    Some(BitRange { pos, bits })
}

fn destroy_dead_value(data: &mut Funcdata, value: VarnodeId) {
    let (is_constant, is_input, has_descendants, definition) = {
        let node = data.varnode(value);
        (
            node.flags.constant,
            node.flags.input,
            !node.descendants.is_empty(),
            node.def,
        )
    };
    if is_constant || is_input || has_descendants {
        return;
    }
    let Some(definition) = definition else { return };
    let (dead, opcode, operands) = {
        let operation = data.op(definition);
        (operation.dead, operation.opcode, operation.inputs.clone())
    };
    if dead
        || matches!(
            opcode,
            op::STORE
                | op::LOAD
                | op::CALL
                | op::CALLIND
                | op::CALLOTHER
                | op::BRANCH
                | op::CBRANCH
                | op::BRANCHIND
                | op::RETURN
        )
    {
        return;
    }
    data.op_destroy(definition);
    for operand in operands {
        destroy_dead_value(data, operand);
    }
}

fn root_is_mapped(data: &Funcdata, value: VarnodeId) -> bool {
    let node = data.varnode(value);
    !node.flags.constant && !node.flags.unique
}

fn extract_from_op(data: &Funcdata, id: OpId) -> Option<ExtractSpec> {
    let operation = data.op(id);
    let out = operation.output?;
    match operation.opcode {
        op::INT_AND => {
            let (value, mask_value) = match (input(data, id, 0), input(data, id, 1)) {
                (Some(left), Some(right)) if constant(data, right).is_some() => (left, right),
                (Some(left), Some(right)) if constant(data, left).is_some() => (right, left),
                _ => return None,
            };
            let mask = constant(data, mask_value)?;
            if let Some(shift) = definition(data, value)
                && matches!(data.opcode_of(shift), Some(op::INT_RIGHT | op::INT_SRIGHT))
            {
                let amount = constant(data, input(data, shift, 1)?)? as u32;
                let source = input(data, shift, 0)?;
                let range = contiguous_range(mask, data.varnode(out).size)?;
                if amount != range.pos || data.varnode(source).size != data.varnode(out).size {
                    return None;
                }
                return Some(ExtractSpec {
                    root: source,
                    pos: amount,
                    bits: range.bits,
                    signed: data.opcode_of(shift) == Some(op::INT_SRIGHT),
                });
            }
            let range = contiguous_range(mask, data.varnode(value).size)?;
            (data.varnode(value).size == data.varnode(out).size).then_some(ExtractSpec {
                root: value,
                pos: range.pos,
                bits: range.bits,
                signed: false,
            })
        }
        op::INT_RIGHT | op::INT_SRIGHT => {
            let source = input(data, id, 0)?;
            let amount = constant(data, input(data, id, 1)?)? as u32;
            let and_op = definition(data, source)?;
            if data.opcode_of(and_op) != Some(op::INT_AND) {
                return None;
            }
            let (root, mask_value) = match (input(data, and_op, 0), input(data, and_op, 1)) {
                (Some(left), Some(right)) if constant(data, right).is_some() => (left, right),
                (Some(left), Some(right)) if constant(data, left).is_some() => (right, left),
                _ => return None,
            };
            let range = contiguous_range(constant(data, mask_value)?, data.varnode(root).size)?;
            if range.pos != amount
                || data.varnode(root).size != data.varnode(out).size
                || range.bits == 0
            {
                return None;
            }
            Some(ExtractSpec {
                root,
                pos: range.pos,
                bits: range.bits,
                signed: operation.opcode == op::INT_SRIGHT,
            })
        }
        op::COPY => {
            let source = input(data, id, 0)?;
            let source_op = definition(data, source)?;
            let spec = extract_from_op(data, source_op)?;
            (data.varnode(spec.root).size == data.varnode(out).size).then_some(spec)
        }
        _ => None,
    }
}

fn rewrite_extract_at(data: &mut Funcdata, id: OpId, expected_root: Option<VarnodeId>) -> bool {
    if data.opcode_of(id).is_none() {
        return false;
    }
    let Some(spec) = extract_from_op(data, id) else {
        return false;
    };
    if let Some(expected) = expected_root {
        if spec.root != expected {
            return false;
        }
    } else if !root_is_mapped(data, spec.root) {
        return false;
    }
    let Some(old_input) = input(data, id, 0) else {
        return false;
    };
    let Some(output) = output(data, id) else {
        return false;
    };
    if spec.bits == 0 || spec.bits > data.varnode(spec.root).size.saturating_mul(8) {
        return false;
    }
    let position = data.new_constant(u64::from(spec.pos), 4);
    let width = data.new_constant(u64::from(spec.bits), 4);
    data.op_set_opcode(id, if spec.signed { op::SPULL } else { op::ZPULL });
    data.op_set_inputs(id, vec![spec.root, position, width]);
    if old_input != spec.root && old_input != output {
        destroy_dead_value(data, old_input);
    }
    true
}

fn preserve_branch(data: &Funcdata, value: VarnodeId) -> Option<(VarnodeId, u64)> {
    let definition = definition(data, value)?;

    if data.opcode_of(definition) != Some(op::INT_AND) {
        return None;
    }
    let left = input(data, definition, 0)?;
    let right = input(data, definition, 1)?;
    if let Some(mask) = constant(data, right) {
        return Some((left, mask));
    }
    if let Some(mask) = constant(data, left) {
        return Some((right, mask));
    }
    None
}
fn rewrite_load_tree(
    data: &mut Funcdata,
    id: OpId,
    root: VarnodeId,
    seen: &mut BTreeSet<OpId>,
) -> bool {
    if !seen.insert(id) {
        return false;
    }
    if let Some(value) = output(data, id) {
        for descendant in data.varnode(value).descendants.clone() {
            if rewrite_load_tree(data, descendant, root, seen) {
                return true;
            }
        }
    }
    rewrite_extract_at(data, id, Some(root))
}

fn shifted_value(data: &Funcdata, value: VarnodeId, pos: u32) -> Option<VarnodeId> {
    let definition = definition(data, value)?;
    match data.opcode_of(definition)? {
        op::INT_LEFT => {
            let amount = constant(data, input(data, definition, 1)?)? as u32;
            (amount == pos)
                .then(|| input(data, definition, 0))
                .flatten()
        }
        _ if pos == 0 => Some(value),
        _ => None,
    }
}

fn insert_branch(
    data: &Funcdata,
    value: VarnodeId,
    field_mask: u64,
    pos: u32,
) -> Option<VarnodeId> {
    let definition = definition(data, value)?;
    if data.opcode_of(definition) == Some(op::INT_AND) {
        let left = input(data, definition, 0)?;
        let right = input(data, definition, 1)?;
        let (shifted, mask) = if let Some(mask) = constant(data, right) {
            (left, mask)
        } else if let Some(mask) = constant(data, left) {
            (right, mask)
        } else {
            return None;
        };
        if mask != field_mask {
            return None;
        }
        return shifted_value(data, shifted, pos);
    }
    shifted_value(data, value, pos)
}

fn insert_from_value(data: &Funcdata, value: VarnodeId) -> Option<InsertSpec> {
    let definition = definition(data, value)?;
    if data.opcode_of(definition) != Some(op::INT_OR) {
        return None;
    }
    let left = input(data, definition, 0)?;
    let right = input(data, definition, 1)?;
    let (left_base, left_mask) = preserve_branch(data, left)?;
    let width = data.varnode(value).size;
    let field_mask = full_mask(width) & !left_mask;
    let range = contiguous_range(field_mask, width)?;
    if let Some(inserted) = insert_branch(data, right, field_mask, range.pos) {
        return Some(InsertSpec {
            base: left_base,
            value: inserted,
            pos: range.pos,
            bits: range.bits,
        });
    }
    let (right_base, right_mask) = preserve_branch(data, right)?;
    let field_mask = full_mask(width) & !right_mask;
    let range = contiguous_range(field_mask, width)?;
    let inserted = insert_branch(data, left, field_mask, range.pos)?;
    Some(InsertSpec {
        base: right_base,
        value: inserted,
        pos: range.pos,
        bits: range.bits,
    })
}

fn rewrite_final_insert(data: &mut Funcdata, target: OpId, expression: VarnodeId) -> bool {
    let Some(spec) = insert_from_value(data, expression) else {
        return false;
    };
    let Some(output) = output(data, target) else {
        return false;
    };
    if data.varnode(output).size != data.varnode(spec.base).size {
        return false;
    }
    let position = data.new_constant(u64::from(spec.pos), 4);
    let width = data.new_constant(u64::from(spec.bits), 4);
    data.op_set_opcode(target, op::INSERT);
    data.op_set_inputs(target, vec![spec.base, spec.value, position, width]);
    if expression != output {
        destroy_dead_value(data, expression);
    }
    true
}

fn make_insert_before(data: &mut Funcdata, store: OpId, expression: VarnodeId) -> bool {
    let Some(spec) = insert_from_value(data, expression) else {
        return false;
    };
    let size = data.varnode(expression).size;
    if data.varnode(spec.base).size != size {
        return false;
    }
    let position = data.new_constant(u64::from(spec.pos), 4);
    let width = data.new_constant(u64::from(spec.bits), 4);
    let insert = data.new_op(
        op::INSERT,
        seq(data, store),
        vec![spec.base, spec.value, position, width],
    );
    let out = data.new_unique(size);
    data.op_set_output(insert, Some(out));
    data.op_insert_before(insert, store);
    data.op_set_input(store, out, 2);
    destroy_dead_value(data, expression);
    true
}

fn is_zero(data: &Funcdata, value: VarnodeId) -> bool {
    constant(data, value) == Some(0)
}

fn insert_bits(data: &Funcdata, insert: OpId) -> Option<u32> {
    constant(data, input(data, insert, 3)?)?.try_into().ok()
}

fn insert_mask(data: &Funcdata, insert: OpId) -> Option<u64> {
    Some(low_mask(insert_bits(data, insert)?))
}

fn left_shift_varnode(data: &Funcdata, value: VarnodeId, shift: u32) -> Option<VarnodeId> {
    let definition = definition(data, value)?;
    let amount = constant(data, input(data, definition, 1)?)?;
    let expected = match data.opcode_of(definition)? {
        op::INT_MULT if shift < 64 => 1u64 << shift,
        op::INT_LEFT => u64::from(shift),
        _ => return None,
    };
    (amount == expected)
        .then(|| input(data, definition, 0))
        .flatten()
}

fn absorb_pull_right_and_zero(data: &mut Funcdata, right: OpId, and_op: OpId, pull: OpId) -> usize {
    if data.opcode_of(pull) != Some(op::SPULL) {
        return 0;
    }
    let Some(shift) = input(data, right, 1).and_then(|value| constant(data, value)) else {
        return 0;
    };
    let Some(bits) = input(data, pull, 2).and_then(|value| constant(data, value)) else {
        return 0;
    };
    if bits == 0 || bits - 1 != shift {
        return 0;
    }
    if input(data, and_op, 1).is_none_or(|value| constant(data, value) != Some(1)) {
        return 0;
    }
    let Some(and_out) = output(data, and_op) else {
        return 0;
    };
    let Some(pull_out) = output(data, pull) else {
        return 0;
    };
    for compare in data.varnode(and_out).descendants.clone() {
        let opcode = data.opcode_of(compare);
        let Some(second) = input(data, compare, 1) else {
            continue;
        };
        if !matches!(opcode, Some(op::INT_EQUAL | op::INT_NOTEQUAL)) || !is_zero(data, second) {
            continue;
        }
        if opcode == Some(op::INT_EQUAL) {
            data.op_set_opcode(compare, op::INT_LESSEQUAL);
            data.op_set_input(compare, second, 0);
            data.op_set_input(compare, pull_out, 1);
        } else {
            data.op_set_opcode(compare, op::INT_SLESS);
            data.op_set_input(compare, pull_out, 0);
        }
        destroy_dead_value(data, and_out);
        return 1;
    }
    0
}

fn absorb_pull_right(data: &mut Funcdata, right: OpId, pull: OpId) -> usize {
    let Some(right_out) = output(data, right) else {
        return 0;
    };
    for and_op in data.varnode(right_out).descendants.clone() {
        if data.opcode_of(and_op) == Some(op::INT_AND) {
            let changed = absorb_pull_right_and_zero(data, right, and_op, pull);
            if changed != 0 {
                return changed;
            }
        }
    }
    0
}

fn absorb_pull_left_right(data: &mut Funcdata, right: OpId, left: OpId, pull: OpId) -> usize {
    let Some(left_shift) = input(data, left, 1).and_then(|value| constant(data, value)) else {
        return 0;
    };
    let Some(right_shift) = input(data, right, 1).and_then(|value| constant(data, value)) else {
        return 0;
    };
    let Some(bits) = input(data, pull, 2).and_then(|value| constant(data, value)) else {
        return 0;
    };
    let Some(root) = input(data, pull, 0) else {
        return 0;
    };
    let container_bits = u64::from(data.varnode(root).size).saturating_mul(8);
    if left_shift.saturating_add(bits) > container_bits {
        return 0;
    }
    let Some(right_out) = output(data, right) else {
        return 0;
    };
    let Some(left_out) = output(data, left) else {
        return 0;
    };
    let Some(pull_out) = output(data, pull) else {
        return 0;
    };
    if right_shift == left_shift {
        data.total_replace(right_out, pull_out);
        destroy_dead_value(data, right_out);
    } else {
        let (opcode, amount) = if right_shift > left_shift {
            (op::INT_RIGHT, right_shift - left_shift)
        } else {
            (op::INT_LEFT, left_shift - right_shift)
        };
        data.op_set_opcode(right, opcode);
        data.op_set_input(right, pull_out, 0);
        let amount_vn = data.new_constant(amount, 4);
        data.op_set_input(right, amount_vn, 1);
        destroy_dead_value(data, left_out);
    }
    1
}

fn absorb_pull_left_and(data: &mut Funcdata, and_op: OpId, left: OpId, _pull: OpId) -> usize {
    let Some(shift) = input(data, left, 1).and_then(|value| constant(data, value)) else {
        return 0;
    };
    if shift >= 64 {
        return 0;
    }
    let Some(mask_value) = input(data, and_op, 1).and_then(|value| constant(data, value)) else {
        return 0;
    };
    let Some(and_out) = output(data, and_op) else {
        return 0;
    };
    for compare in data.varnode(and_out).descendants.clone() {
        if !matches!(
            data.opcode_of(compare),
            Some(op::INT_EQUAL | op::INT_NOTEQUAL)
        ) {
            continue;
        }
        let Some(compared) = input(data, compare, 1) else {
            continue;
        };
        let Some(original) = constant(data, compared) else {
            continue;
        };
        let shifted = original >> shift;
        if shifted << shift != original {
            continue;
        }
        let Some(mask_input) = input(data, and_op, 1) else {
            return 0;
        };
        let mask_size = data.varnode(mask_input).size;
        let new_mask = data.new_constant(mask_value >> shift, mask_size);
        let Some(left_source) = input(data, left, 0) else {
            return 0;
        };
        data.op_set_input(and_op, new_mask, 1);
        if shifted != original {
            let new_value = data.new_constant(shifted, data.varnode(compared).size);
            data.op_set_input(compare, new_value, 1);
        }
        data.op_set_input(and_op, left_source, 0);
        if let Some(left_out) = output(data, left) {
            destroy_dead_value(data, left_out);
        }
        return 1;
    }
    0
}

fn absorb_pull_and(data: &mut Funcdata, and_op: OpId, pull: OpId) -> usize {
    if data.opcode_of(pull) != Some(op::SPULL) {
        return 0;
    }
    let Some(bits) = input(data, pull, 2).and_then(|value| constant(data, value)) else {
        return 0;
    };
    if bits == 0 || bits > 63 {
        return 0;
    }
    let expected = 1u64 << (bits - 1);
    let Some(mask) = input(data, and_op, 1).and_then(|value| constant(data, value)) else {
        return 0;
    };
    if mask != expected {
        return 0;
    }
    let Some(and_out) = output(data, and_op) else {
        return 0;
    };
    let Some(pull_out) = output(data, pull) else {
        return 0;
    };
    for compare in data.varnode(and_out).descendants.clone() {
        let opcode = data.opcode_of(compare);
        let Some(second) = input(data, compare, 1) else {
            continue;
        };
        if !matches!(opcode, Some(op::INT_EQUAL | op::INT_NOTEQUAL)) || !is_zero(data, second) {
            continue;
        }
        let zero = data.new_constant(0, data.varnode(pull_out).size);
        if opcode == Some(op::INT_EQUAL) {
            data.op_set_opcode(compare, op::INT_SLESSEQUAL);
            data.op_set_input(compare, zero, 0);
            data.op_set_input(compare, pull_out, 1);
        } else {
            data.op_set_opcode(compare, op::INT_SLESS);
            data.op_set_input(compare, pull_out, 0);
            data.op_set_input(compare, zero, 1);
        }
        destroy_dead_value(data, and_out);
        return 1;
    }
    0
}

fn absorb_pull_compare(
    data: &mut Funcdata,
    compare: OpId,
    left: Option<OpId>,
    pull: OpId,
) -> usize {
    let shift = match left {
        Some(left) => match input(data, left, 1).and_then(|value| constant(data, value)) {
            Some(value) => value,
            None => return 0,
        },
        None => 0,
    };
    let Some(bits) = input(data, pull, 2).and_then(|value| constant(data, value)) else {
        return 0;
    };
    let Some(root) = input(data, pull, 0) else {
        return 0;
    };
    let width = u64::from(data.varnode(root).size).saturating_mul(8);
    if bits.saturating_add(shift) != width {
        return 0;
    }
    let Some(source) = left
        .and_then(|id| output(data, id))
        .or_else(|| output(data, pull))
    else {
        return 0;
    };
    let Some(left_value) = input(data, compare, 0) else {
        return 0;
    };
    let Some(right_value) = input(data, compare, 1) else {
        return 0;
    };
    if data.opcode_of(compare) == Some(op::INT_SLESS) && bits == 1 {
        if left_value == source && is_zero(data, right_value) {
            let Some(old) = output(data, compare) else {
                return 0;
            };
            let Some(pull_out) = output(data, pull) else {
                return 0;
            };
            data.total_replace(old, pull_out);
            destroy_dead_value(data, old);
            return 1;
        }
        if right_value == source
            && constant(data, left_value) == Some(full_mask(data.varnode(source).size))
        {
            let Some(pull_out) = output(data, pull) else {
                return 0;
            };
            data.op_set_opcode(compare, op::BOOL_NEGATE);
            data.op_set_inputs(compare, vec![pull_out]);
            destroy_dead_value(data, source);
            return 1;
        }
    }
    if shift == 0 || shift >= 64 {
        return 0;
    }
    let low = low_mask(shift as u32);
    if left_value == source {
        let Some(original) = constant(data, right_value) else {
            return 0;
        };
        let low_bits = original & low;
        if low_bits == 0 || low_bits == 1 {
            let Some(pull_out) = output(data, pull) else {
                return 0;
            };
            data.op_set_input(compare, pull_out, 0);
            let size = data.varnode(source).size;
            let shifted = if low_bits == 1 {
                ((original.wrapping_sub(1) >> shift).wrapping_add(1)) & full_mask(size)
            } else {
                original >> shift
            };
            let value = data.new_constant(shifted, size);
            data.op_set_input(compare, value, 1);
            destroy_dead_value(data, source);
            return 1;
        }
    } else if right_value == source {
        let Some(original) = constant(data, left_value) else {
            return 0;
        };
        let low_bits = original & low;
        if low_bits == 0 || low_bits == low {
            let Some(pull_out) = output(data, pull) else {
                return 0;
            };
            data.op_set_input(compare, pull_out, 1);
            let size = data.varnode(source).size;
            let shifted = if low_bits == low {
                ((original.wrapping_add(1) >> shift).wrapping_sub(1)) & full_mask(size)
            } else {
                original >> shift
            };
            let value = data.new_constant(shifted, size);
            data.op_set_input(compare, value, 0);
            destroy_dead_value(data, source);
            return 1;
        }
    }
    0
}

fn absorb_pull_ext(data: &mut Funcdata, ext: OpId, pull: OpId) -> usize {
    let pull_signed = data.opcode_of(pull) == Some(op::SPULL);
    let ext_signed = data.opcode_of(ext) == Some(op::INT_SEXT);
    if pull_signed != ext_signed {
        return 0;
    }
    let Some(value) = input(data, ext, 0) else {
        return 0;
    };
    if data.lone_descend(value) != Some(ext) {
        return 0;
    }
    let (root, position, bits) = match (
        input(data, pull, 0),
        input(data, pull, 1),
        input(data, pull, 2),
    ) {
        (Some(root), Some(position), Some(bits)) => (root, position, bits),
        _ => return 0,
    };
    let Some(pull_opcode) = data.opcode_of(pull) else {
        return 0;
    };
    data.op_set_opcode(ext, pull_opcode);
    data.op_set_inputs(ext, vec![root, position, bits]);
    destroy_dead_value(data, value);
    1
}

fn absorb_pull_subpiece(data: &mut Funcdata, sub: OpId, pull: OpId) -> usize {
    if input(data, sub, 1).and_then(|value| constant(data, value)) != Some(0) {
        return 0;
    }
    let Some(bits) = input(data, pull, 2).and_then(|value| constant(data, value)) else {
        return 0;
    };
    let Some(out) = output(data, sub) else {
        return 0;
    };
    if bits > u64::from(data.varnode(out).size).saturating_mul(8) {
        return 0;
    }
    let Some(value) = input(data, sub, 0) else {
        return 0;
    };
    if data.lone_descend(value) != Some(sub) {
        return 0;
    }
    let (root, position, width) = match (
        input(data, pull, 0),
        input(data, pull, 1),
        input(data, pull, 2),
    ) {
        (Some(root), Some(position), Some(width)) => (root, position, width),
        _ => return 0,
    };
    let Some(pull_opcode) = data.opcode_of(pull) else {
        return 0;
    };
    data.op_set_opcode(sub, pull_opcode);
    data.op_set_inputs(sub, vec![root, position, width]);
    destroy_dead_value(data, value);
    1
}

fn absorb_pull_comp_zero(data: &mut Funcdata, compare: OpId, pull: OpId) -> usize {
    let Some(second) = input(data, compare, 1) else {
        return 0;
    };
    if !is_zero(data, second) {
        return 0;
    }
    let bits = input(data, pull, 2).and_then(|value| constant(data, value));
    if bits != Some(1) || data.opcode_of(pull) != Some(op::ZPULL) {
        return 0;
    }
    let Some(value) = input(data, compare, 0) else {
        return 0;
    };
    if data.lone_descend(value) != Some(compare)
        || data.varnode(value).size != 1
        || !data.varnode(value).flags.unique
    {
        return 0;
    }
    let Some(pull_opcode) = data.opcode_of(pull) else {
        return 0;
    };
    let (root, position, width) = match (
        input(data, pull, 0),
        input(data, pull, 1),
        input(data, pull, 2),
    ) {
        (Some(root), Some(position), Some(width)) => (root, position, width),
        _ => return 0,
    };
    match data.opcode_of(compare) {
        Some(op::INT_EQUAL) => {
            data.op_set_opcode(compare, op::BOOL_NEGATE);
            data.op_set_inputs(compare, vec![value]);
        }
        Some(op::INT_NOTEQUAL) => {
            data.op_set_opcode(compare, pull_opcode);
            data.op_set_inputs(compare, vec![root, position, width]);
        }
        _ => return 0,
    }
    destroy_dead_value(data, value);
    1
}

/// Collapse mask and shift extraction after a `LOAD` into Ghidra's
/// `RuleBitFieldLoad`. The load itself remains in place because only its
/// extracted descendants are rewritten.
pub struct RuleBitFieldLoad;

impl Rule for RuleBitFieldLoad {
    fn name(&self) -> &'static str {
        "bitfield_load"
    }
    fn op_list(&self) -> Vec<i32> {
        vec![op::LOAD]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(root) = output(data, id) else {
            return 0;
        };
        let mut seen = BTreeSet::new();
        for descendant in data.varnode(root).descendants.clone() {
            if rewrite_load_tree(data, descendant, root, &mut seen) {
                return 1;
            }
        }
        0
    }
}

/// Collapse a contiguous masked merge into Ghidra's `RuleBitFieldOut`.
/// Without field metadata the merge must explicitly preserve one contiguous
/// range and insert the complementary shifted value.
pub struct RuleBitFieldOut;

impl Rule for RuleBitFieldOut {
    fn name(&self) -> &'static str {
        "bitfield_out"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![
            op::COPY,
            op::INT_EQUAL,
            op::INT_NOTEQUAL,
            op::INT_SLESS,
            op::INT_SLESSEQUAL,
            op::INT_LESS,
            op::INT_LESSEQUAL,
            op::INT_ZEXT,
            op::INT_SEXT,
            op::INT_ADD,
            op::INT_CARRY,
            op::INT_SCARRY,
            op::INT_XOR,
            op::INT_AND,
            op::INT_OR,
            op::INT_LEFT,
            op::INT_RIGHT,
            op::INT_SRIGHT,
            op::INT_MULT,
            op::BOOL_NEGATE,
            op::BOOL_XOR,
            op::BOOL_AND,
            op::BOOL_OR,
            op::FLOAT_EQUAL,
            op::FLOAT_NOTEQUAL,
            op::FLOAT_LESS,
            op::FLOAT_LESSEQUAL,
            op::FLOAT_NAN,
            op::SUBPIECE,
            op::INDIRECT,
        ]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        if let Some(expression) = output(data, id) {
            if rewrite_final_insert(data, id, expression) {
                return 1;
            }
        }
        for expression in data.op(id).inputs.clone() {
            if rewrite_final_insert(data, id, expression) {
                return 1;
            }
        }
        0
    }
}

/// Insert a contiguous masked merge before a `STORE`, porting
/// `RuleBitFieldStore`. Type-based field discovery is unavailable, so the
/// source expression must contain the complete mask-and-merge idiom.
pub struct RuleBitFieldStore;

impl Rule for RuleBitFieldStore {
    fn name(&self) -> &'static str {
        "bitfield_store"
    }
    fn op_list(&self) -> Vec<i32> {
        vec![op::STORE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(value) = input(data, id, 2) else {
            return 0;
        };
        if opcode_of_value(data, value, op::INSERT).is_some() {
            return 0;
        }
        usize::from(make_insert_before(data, id, value))
    }
}

/// Simplify explicit `ZPULL` and `SPULL` expressions, porting
/// `RulePullAbsorb`. These rewrites use only operation shape and widths, which
/// is why they remain faithful even without recovered field types.
pub struct RulePullAbsorb;

impl Rule for RulePullAbsorb {
    fn name(&self) -> &'static str {
        "pull_absorb"
    }
    fn op_list(&self) -> Vec<i32> {
        vec![op::ZPULL, op::SPULL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(out) = output(data, id) else {
            return 0;
        };
        for read in data.varnode(out).descendants.clone() {
            let Some(opcode) = data.opcode_of(read) else {
                continue;
            };
            let changed = match opcode {
                op::INT_RIGHT | op::INT_SRIGHT => absorb_pull_right(data, read, id),
                op::INT_LEFT => {
                    let mut changed = 0;
                    let next: Vec<OpId> = output(data, read)
                        .map(|value| data.varnode(value).descendants.iter().copied().collect())
                        .unwrap_or_default();
                    for candidate in next {
                        changed = match data.opcode_of(candidate) {
                            Some(op::INT_RIGHT) => {
                                absorb_pull_left_right(data, candidate, read, id)
                            }
                            Some(op::INT_AND) => absorb_pull_left_and(data, candidate, read, id),
                            Some(op::INT_SLESS) => {
                                absorb_pull_compare(data, candidate, Some(read), id)
                            }
                            _ => 0,
                        };
                        if changed != 0 {
                            break;
                        }
                    }
                    changed
                }
                op::INT_AND => absorb_pull_and(data, read, id),
                op::INT_SLESS | op::INT_LESS => absorb_pull_compare(data, read, None, id),
                op::INT_ZEXT | op::INT_SEXT => absorb_pull_ext(data, read, id),
                op::SUBPIECE => absorb_pull_subpiece(data, read, id),
                op::INT_EQUAL | op::INT_NOTEQUAL => absorb_pull_comp_zero(data, read, id),
                _ => 0,
            };
            if changed != 0 {
                return changed;
            }
        }
        0
    }
}

/// Simplify explicit `INSERT` expressions, porting `RuleInsertAbsorb`.
/// Each helper removes a redundant producer only after the graph proves its
/// result has no remaining descendants.
pub struct RuleInsertAbsorb;

impl Rule for RuleInsertAbsorb {
    fn name(&self) -> &'static str {
        "insert_absorb"
    }
    fn op_list(&self) -> Vec<i32> {
        vec![op::INSERT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(value) = input(data, id, 1) else {
            return 0;
        };
        let Some(insert_definition) = definition(data, value) else {
            return 0;
        };
        let Some(opcode) = data.opcode_of(insert_definition) else {
            return 0;
        };
        match opcode {
            op::SUBPIECE => {
                if input(data, insert_definition, 1).and_then(|value| constant(data, value))
                    != Some(0)
                {
                    return 0;
                }
                let Some(source) = input(data, insert_definition, 0) else {
                    return 0;
                };
                data.op_set_input(id, source, 1);
                destroy_dead_value(data, value);
                1
            }
            op::INT_RIGHT | op::INT_SRIGHT => {
                if input(data, insert_definition, 1)
                    .and_then(|value| constant(data, value))
                    .is_none()
                {
                    return 0;
                }
                let Some(source) = input(data, insert_definition, 0) else {
                    return 0;
                };
                let Some(next) = definition(data, source) else {
                    return 0;
                };
                match data.opcode_of(next) {
                    Some(op::INT_ADD) => absorb_insert_shift_add(data, insert_definition, next, id),
                    Some(op::INT_LEFT) | Some(op::SUBPIECE) => {
                        absorb_insert_right_left(data, next, insert_definition, id)
                    }
                    _ => 0,
                }
            }
            op::INT_AND => absorb_insert_and(data, insert_definition, id),
            op::INT_ADD | op::INT_OR | op::INT_XOR | op::INT_MULT => {
                absorb_insert_nested_and(data, insert_definition, id)
            }
            _ => 0,
        }
    }
}

fn absorb_insert_and(data: &mut Funcdata, and_op: OpId, insert: OpId) -> usize {
    let Some(mask_value) = input(data, and_op, 1).and_then(|value| constant(data, value)) else {
        return 0;
    };
    let Some(mask) = insert_mask(data, insert) else {
        return 0;
    };
    if mask & mask_value != mask {
        return 0;
    }
    let Some(source) = input(data, and_op, 0) else {
        return 0;
    };
    let Some(old) = output(data, and_op) else {
        return 0;
    };
    data.op_set_input(insert, source, 1);
    destroy_dead_value(data, old);
    1
}

fn absorb_insert_right_left(data: &mut Funcdata, next: OpId, right: OpId, insert: OpId) -> usize {
    let left = if data.opcode_of(next) == Some(op::INT_LEFT) {
        next
    } else {
        if input(data, next, 1).and_then(|value| constant(data, value)) != Some(0) {
            return 0;
        }
        let Some(sub_input) = input(data, next, 0) else {
            return 0;
        };
        let Some(left) = definition(data, sub_input) else {
            return 0;
        };
        if data.opcode_of(left) != Some(op::INT_LEFT) {
            return 0;
        }
        left
    };
    let Some(left_amount) = input(data, left, 1).and_then(|value| constant(data, value)) else {
        return 0;
    };
    let Some(right_amount) = input(data, right, 1).and_then(|value| constant(data, value)) else {
        return 0;
    };
    if left_amount != right_amount {
        return 0;
    }
    let Some(bits) = input(data, insert, 3).and_then(|value| constant(data, value)) else {
        return 0;
    };
    let Some(insert_value) = input(data, insert, 1) else {
        return 0;
    };
    if bits
        > u64::from(data.varnode(insert_value).size)
            .saturating_mul(8)
            .saturating_sub(left_amount)
    {
        return 0;
    }
    let Some(old) = output(data, right) else {
        return 0;
    };
    let Some(source) = input(data, left, 0) else {
        return 0;
    };
    data.op_set_input(insert, source, 1);
    destroy_dead_value(data, old);
    1
}

fn absorb_insert_shift_add(data: &mut Funcdata, right: OpId, add: OpId, insert: OpId) -> usize {
    let Some(shift) = input(data, right, 1).and_then(|value| constant(data, value)) else {
        return 0;
    };
    if shift == 0 || shift >= 64 {
        return 0;
    }
    let Some(first_input) = input(data, add, 0) else {
        return 0;
    };
    let Some(first) = left_shift_varnode(data, first_input, shift as u32) else {
        return 0;
    };
    let second = if let Some(value) = input(data, add, 1).and_then(|id| constant(data, id)) {
        if value >> shift << shift != value {
            return 0;
        }
        data.new_constant(value >> shift, data.varnode(first).size)
    } else {
        let Some(second_input) = input(data, add, 1) else {
            return 0;
        };
        let Some(second) = left_shift_varnode(data, second_input, shift as u32) else {
            return 0;
        };
        second
    };
    let Some(bits) = input(data, insert, 3).and_then(|value| constant(data, value)) else {
        return 0;
    };
    if bits
        > u64::from(data.varnode(first).size)
            .saturating_mul(8)
            .saturating_sub(shift)
    {
        return 0;
    }
    let Some(old) = output(data, add) else {
        return 0;
    };
    data.op_set_opcode(right, op::INT_ADD);
    data.op_set_inputs(right, vec![first, second]);
    destroy_dead_value(data, old);
    1
}

fn absorb_insert_nested_and(data: &mut Funcdata, base: OpId, insert: OpId) -> usize {
    let Some(base_out) = output(data, base) else {
        return 0;
    };
    if data.lone_descend(base_out) != Some(insert) {
        return 0;
    }
    let Some(bits) = insert_bits(data, insert) else {
        return 0;
    };
    for slot in 0..2 {
        let Some(value) = input(data, base, slot) else {
            continue;
        };
        let Some(and_op) = definition(data, value) else {
            continue;
        };
        if data.opcode_of(and_op) != Some(op::INT_AND) {
            continue;
        }
        let Some(mask_value) = input(data, and_op, 1).and_then(|id| constant(data, id)) else {
            continue;
        };
        let mask_bits = mask_value.count_ones();
        if mask_value == 0
            || mask_value & 1 == 0
            || mask_value != low_mask(mask_bits)
            || mask_bits < bits
        {
            continue;
        }
        let Some(source) = input(data, and_op, 0) else {
            continue;
        };
        let Some(old) = output(data, and_op) else {
            continue;
        };
        data.op_set_input(base, source, slot);
        destroy_dead_value(data, old);
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::REGISTER_SPACE;

    fn block(data: &mut Funcdata) -> super::super::GraphBlockId {
        data.new_block(0x1000)
    }

    fn input_value(data: &mut Funcdata, size: u32) -> VarnodeId {
        let value = data.new_varnode(REGISTER_SPACE, data.varnode_count() as u64 * 8, size);
        data.mark_input(value);
        value
    }

    fn constant_value(data: &mut Funcdata, value: u64, size: u32) -> VarnodeId {
        data.new_constant(value, size)
    }

    fn op_with_output(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        opcode: i32,
        inputs: Vec<VarnodeId>,
        size: u32,
    ) -> (OpId, VarnodeId) {
        let id = data.new_op(
            opcode,
            SeqNum {
                address: 0x1000 + data.op_count() as u64 * 4,
                order: 0,
            },
            inputs,
        );
        let output = data.new_unique(size);
        data.op_set_output(id, Some(output));
        data.op_insert_end(id, block);
        (id, output)
    }

    fn merged_value(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        size: u32,
    ) -> VarnodeId {
        let base = input_value(data, size);
        let field = input_value(data, size);
        let preserve_mask = constant_value(data, 0xffff_ff0f, size);
        let field_mask = constant_value(data, 0xf0, size);
        let shift_amount = constant_value(data, 4, size);
        let (_, preserved) =
            op_with_output(data, block, op::INT_AND, vec![base, preserve_mask], size);
        let (_, shifted) =
            op_with_output(data, block, op::INT_LEFT, vec![field, shift_amount], size);
        let (_, inserted) =
            op_with_output(data, block, op::INT_AND, vec![shifted, field_mask], size);
        let (_, merged) = op_with_output(data, block, op::INT_OR, vec![preserved, inserted], size);
        merged
    }

    #[test]
    fn bitfield_load_fires_and_declines_without_extraction() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let space = constant_value(&mut data, 3, 4);
        let pointer = input_value(&mut data, 4);
        let (load, loaded) = op_with_output(&mut data, b, op::LOAD, vec![space, pointer], 4);
        let mask = constant_value(&mut data, 0xf0, 4);
        let (_, masked) = op_with_output(&mut data, b, op::INT_AND, vec![loaded, mask], 4);
        let shift = constant_value(&mut data, 4, 4);
        let (extract, _) = op_with_output(&mut data, b, op::INT_RIGHT, vec![masked, shift], 4);
        assert_eq!(RuleBitFieldLoad.apply_op(load, &mut data), 1);
        assert_eq!(data.op(extract).opcode, op::ZPULL);
        let (plain_load, _) = op_with_output(&mut data, b, op::LOAD, vec![space, pointer], 4);
        assert_eq!(RuleBitFieldLoad.apply_op(plain_load, &mut data), 0);
    }

    #[test]
    fn bitfield_out_fires_and_declines_noncontiguous_merge() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let merged = merged_value(&mut data, b, 4);
        let (out, _) = op_with_output(&mut data, b, op::COPY, vec![merged], 4);
        assert_eq!(RuleBitFieldOut.apply_op(out, &mut data), 1);
        assert_eq!(data.op(out).opcode, op::INSERT);
        assert_eq!(constant(&data, data.op(out).inputs[2]), Some(4));
        assert_eq!(constant(&data, data.op(out).inputs[3]), Some(4));
        let base = input_value(&mut data, 4);
        let value = input_value(&mut data, 4);
        let bad_preserve = constant_value(&mut data, 0xffff_ff05, 4);
        let (_, preserved) = op_with_output(&mut data, b, op::INT_AND, vec![base, bad_preserve], 4);
        let (_, bad_merge) = op_with_output(&mut data, b, op::INT_OR, vec![preserved, value], 4);
        let (bad_out, _) = op_with_output(&mut data, b, op::COPY, vec![bad_merge], 4);
        assert_eq!(RuleBitFieldOut.apply_op(bad_out, &mut data), 0);
    }

    #[test]
    fn bitfield_store_fires_and_declines_existing_insert() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let merged = merged_value(&mut data, b, 4);
        let space = constant_value(&mut data, 3, 4);
        let pointer = input_value(&mut data, 4);
        let (store, _) = op_with_output(&mut data, b, op::STORE, vec![space, pointer, merged], 4);
        assert_eq!(RuleBitFieldStore.apply_op(store, &mut data), 1);
        let inserted = data.op(store).inputs[2];
        assert_eq!(
            definition(&data, inserted).map(|id| data.op(id).opcode),
            Some(op::INSERT)
        );
        let base = input_value(&mut data, 4);
        let value = input_value(&mut data, 4);
        let position = constant_value(&mut data, 4, 4);
        let bits = constant_value(&mut data, 4, 4);
        let (insert, insert_out) = op_with_output(
            &mut data,
            b,
            op::INSERT,
            vec![base, value, position, bits],
            4,
        );
        let existing =
            op_with_output(&mut data, b, op::STORE, vec![space, pointer, insert_out], 4).0;
        assert_eq!(RuleBitFieldStore.apply_op(existing, &mut data), 0);
        assert_eq!(data.op(insert).opcode, op::INSERT);
    }

    #[test]
    fn pull_absorb_fires_on_extension_and_declines_signed_mismatch() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let root = input_value(&mut data, 4);
        let position = constant_value(&mut data, 4, 4);
        let bits = constant_value(&mut data, 4, 4);
        let (pull, pulled) = op_with_output(&mut data, b, op::ZPULL, vec![root, position, bits], 4);
        let (ext, _) = op_with_output(&mut data, b, op::INT_ZEXT, vec![pulled], 4);
        assert_eq!(RulePullAbsorb.apply_op(pull, &mut data), 1);
        assert_eq!(data.op(ext).opcode, op::ZPULL);
        assert_eq!(data.op(ext).inputs[0], root);
        let (signed_pull, signed_value) =
            op_with_output(&mut data, b, op::SPULL, vec![root, position, bits], 4);
        let (bad_ext, _) = op_with_output(&mut data, b, op::INT_ZEXT, vec![signed_value], 4);
        assert_eq!(RulePullAbsorb.apply_op(signed_pull, &mut data), 0);
        assert_eq!(data.op(bad_ext).opcode, op::INT_ZEXT);
    }

    #[test]
    fn insert_absorb_fires_on_and_and_declines_insufficient_mask() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let base = input_value(&mut data, 4);
        let value = input_value(&mut data, 4);
        let mask = constant_value(&mut data, 0x0f, 4);
        let (_, masked) = op_with_output(&mut data, b, op::INT_AND, vec![value, mask], 4);
        let position = constant_value(&mut data, 4, 4);
        let bits = constant_value(&mut data, 4, 4);
        let (insert, _) = op_with_output(
            &mut data,
            b,
            op::INSERT,
            vec![base, masked, position, bits],
            4,
        );
        assert_eq!(RuleInsertAbsorb.apply_op(insert, &mut data), 1);
        assert_eq!(data.op(insert).inputs[1], value);
        let narrow_mask = constant_value(&mut data, 0x03, 4);
        let (_, narrow) = op_with_output(&mut data, b, op::INT_AND, vec![value, narrow_mask], 4);
        let (bad_insert, _) = op_with_output(
            &mut data,
            b,
            op::INSERT,
            vec![base, narrow, position, bits],
            4,
        );
        assert_eq!(RuleInsertAbsorb.apply_op(bad_insert, &mut data), 0);
    }
}
