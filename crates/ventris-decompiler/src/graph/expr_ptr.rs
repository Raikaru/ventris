//! Pointer and structure-directed rewrites from Ghidra 12.1.3's
//! `ruleaction.cc`.
//!
//! The graph does not retain Ghidra's mutable `Datatype *` on every Varnode.
//! Each rule therefore runs the graph-facing type recovery pass and uses the
//! resulting [`DataType`] value for the same pointer/array/structure guards as
//! the C++ rule.  The transforms deliberately stay conservative when the
//! graph cannot prove that an integer expression is a pointer expression.
//!
//! Two requested rules are omitted.  `RulePtrFlow` needs the C++ `ptrflow`
//! property on both Varnodes and PcodeOps, together with address-space
//! truncation/default-code-space metadata; none of those graph facets exists.
//! `RulePtrsubCharConstant` needs `TypeSpacebase` (symbol-to-address mapping),
//! character-print classification, read-only memory/string-manager state, and
//! address-force locking.  A plain `Pointer` cannot establish those facts, so
//! registering a partial constant-fold would be unsound.
//!
//! `RulePtrArith` and `RulePushPtr` are intentionally complementary.  The
//! former only handles an INT_ADD whose result already reaches a non-ADD use
//! (or another pointer), while the latter only handles an INT_ADD whose every
//! use is another INT_ADD with a non-pointer sibling.  Thus a given operation
//! cannot be rewritten in both directions.  The undo rules use the converse
//! semantic guard: `RulePtraddUndo` declines a non-zero/dynamic index whose
//! stride matches the recovered pointee stride, and `RulePtrsubUndo` declines a
//! PTRSUB whose offset names a recovered component.  `RulePtrArith` can only
//! recreate a PTRADD/PTRSUB for those same valid cases, so an undo result cannot
//! immediately oscillate back.
//!
//! Source authority: the pinned Ghidra 12.1.3
//! `Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.cc`.

use std::collections::BTreeMap;

use ventris_pcode::op;

use super::action::Rule;
use super::typefactory::{DataType, RecoveredTypes, TypeFactory, infer};
use super::{Funcdata, OpId, SeqNum, VarnodeId};

fn constant_value(data: &Funcdata, value: VarnodeId) -> Option<u64> {
    let vn = data.varnode(value);
    (vn.flags.constant || vn.space == ventris_lifter::CONST_SPACE).then_some(vn.offset)
}

fn signed_constant(data: &Funcdata, value: VarnodeId) -> Option<i64> {
    let raw = constant_value(data, value)?;
    let bits = data.varnode(value).size.saturating_mul(8).min(64);
    if bits == 0 {
        return Some(0);
    }
    if bits == 64 {
        return Some(raw as i64);
    }
    let mask = (1u64 << bits) - 1;
    let value = raw & mask;
    let sign = 1u64 << (bits - 1);
    Some(if value & sign != 0 {
        (value | !mask) as i64
    } else {
        value as i64
    })
}

fn byte_width(ty: &DataType) -> u32 {
    match ty {
        DataType::Unknown(bits)
        | DataType::Int { bits, .. }
        | DataType::Float(bits)
        | DataType::Pointer { bits, .. }
        | DataType::PointerRel { bits, .. } => bits.saturating_add(7) / 8,
        DataType::Bool => 1,
        DataType::Void | DataType::Spacebase => 0,
        DataType::Array { element, count } => {
            if *count == 0 {
                0
            } else {
                byte_width(element).saturating_mul((*count).min(u32::MAX as usize) as u32)
            }
        }
        DataType::Struct { fields, .. } => fields.iter().fold(0, |end, field| {
            end.max(field.offset.saturating_add(byte_width(&field.ty)))
        }),
    }
}

/// The stride used by PTRADD.  An open-ended array has no total byte width,
/// but its element width is still the exact PTRADD stride.
fn pointer_stride(ty: &DataType) -> u32 {
    match ty {
        DataType::Array { element, .. } => byte_width(element),
        _ => byte_width(ty),
    }
}

fn pointer_target(types: &RecoveredTypes, value: VarnodeId) -> Option<DataType> {
    match types.get(value)? {
        DataType::Pointer { to, .. } => Some(to.as_ref().clone()),
        _ => None,
    }
}

/// The graph's cached type recovery.
///
/// Running `infer` here made every one of these rules re-derive the whole
/// function's types on each operation it examined, which cost five times the
/// expression phase's runtime on one corpus function.
fn recover_types(data: &Funcdata) -> std::rc::Rc<(TypeFactory, RecoveredTypes)> {
    data.recovered_types()
}

fn is_structured(ty: &DataType) -> bool {
    matches!(ty, DataType::Struct { .. } | DataType::Array { .. })
}

/// Whether the result of an INT_ADD is already at a pointer-expression sink.
/// This is the graph equivalent of `RulePtrArith::evaluatePointerExpression`
/// returning 2.  A chain made solely of ADDs is reserved for RulePushPtr.
fn pointer_add_needs_conversion(
    data: &Funcdata,
    result: VarnodeId,
    types: &RecoveredTypes,
) -> bool {
    let descendants: Vec<OpId> = data.varnode(result).descendants.iter().copied().collect();
    if descendants.is_empty() {
        return false;
    }
    descendants.into_iter().any(|descendant| {
        let operation = data.op(descendant);
        if operation.opcode != op::INT_ADD {
            return true;
        }
        let Some(slot) = operation.inputs.iter().position(|value| *value == result) else {
            return true;
        };
        operation
            .inputs
            .get(1 - slot)
            .is_some_and(|value| pointer_target(types, *value).is_some())
    })
}

fn pushable_pointer_add(data: &Funcdata, result: VarnodeId, types: &RecoveredTypes) -> bool {
    let descendants: Vec<OpId> = data.varnode(result).descendants.iter().copied().collect();
    !descendants.is_empty()
        && descendants.into_iter().all(|descendant| {
            let operation = data.op(descendant);
            if operation.opcode != op::INT_ADD {
                return false;
            }
            let Some(slot) = operation.inputs.iter().position(|value| *value == result) else {
                return false;
            };
            let Some(other) = operation.inputs.get(1 - slot).copied() else {
                return false;
            };
            pointer_target(types, other).is_none()
        })
}

fn pointer_slot(
    data: &Funcdata,
    id: OpId,
    types: &RecoveredTypes,
) -> Option<(usize, VarnodeId, VarnodeId)> {
    let operation = data.op(id);
    if operation.inputs.len() != 2 {
        return None;
    }
    for slot in 0..2 {
        let ptr = operation.inputs[slot];
        if pointer_target(types, ptr).is_some() {
            return Some((slot, ptr, operation.inputs[1 - slot]));
        }
    }
    None
}

/// Convert a directly representable pointer add in place.  The full Ghidra
/// AddTreeState flattens arbitrary ADD trees; this graph port handles the
/// exact one-level forms and constant-multiple terms, leaving ambiguous trees
/// for the complementary push rule.
fn convert_pointer_add(
    data: &mut Funcdata,
    id: OpId,
    ptr: VarnodeId,
    offset: VarnodeId,
    target: &DataType,
    factory: &TypeFactory,
) -> bool {
    let ptr_size = data.varnode(ptr).size;
    let Some(offset_value) = signed_constant(data, offset) else {
        // A constant-multiple term can be represented as PTRADD(index,stride)
        // only when its multiply is explicit and exact.
        let Some(definition) = data.varnode(offset).def else {
            return false;
        };
        let multiply = data.op(definition).clone();
        if multiply.opcode != op::INT_MULT || multiply.inputs.len() != 2 {
            return false;
        }
        let (index, stride_value) = if let Some(stride) = constant_value(data, multiply.inputs[0]) {
            (multiply.inputs[1], stride)
        } else if let Some(stride) = constant_value(data, multiply.inputs[1]) {
            (multiply.inputs[0], stride)
        } else {
            return false;
        };
        let Ok(stride) = u32::try_from(stride_value) else {
            return false;
        };
        if stride == 0 || pointer_stride(target) != stride {
            return false;
        }
        let zero = data.new_constant(stride_value, ptr_size);
        data.op_set_inputs(id, vec![ptr, index, zero]);
        data.op_set_opcode(id, op::PTRADD);
        return true;
    };

    if offset_value == 0 {
        // Zero is intentionally left alone.  StructOffset0 handles the LOAD /
        // STORE case, and this guard is also what keeps PTRADD undo disjoint.
        return false;
    }
    if offset_value < 0 {
        return false;
    }
    let Ok(offset_value) = u64::try_from(offset_value) else {
        return false;
    };
    let Ok(offset_bytes) = u32::try_from(offset_value) else {
        return false;
    };

    if let DataType::Array { element, .. } = target {
        let stride = byte_width(element);
        if stride == 0 || offset_bytes % stride != 0 {
            return false;
        }
        let index = data.new_constant(u64::from(offset_bytes / stride), ptr_size);
        let stride = data.new_constant(u64::from(stride), ptr_size);
        data.op_set_inputs(id, vec![ptr, index, stride]);
        data.op_set_opcode(id, op::PTRADD);
        return true;
    }

    if let DataType::Struct { .. } = target {
        let Some((_, remainder)) = factory.sub_type(target, offset_bytes) else {
            return false;
        };
        if remainder != 0 {
            return false;
        }
        let displacement = data.new_constant(offset_value, ptr_size);
        data.op_set_inputs(id, vec![ptr, displacement]);
        data.op_set_opcode(id, op::PTRSUB);
        return true;
    }

    let stride = byte_width(target);
    if stride == 0 || offset_bytes % stride != 0 {
        return false;
    }
    let index = data.new_constant(u64::from(offset_bytes / stride), ptr_size);
    let stride = data.new_constant(u64::from(stride), ptr_size);
    data.op_set_inputs(id, vec![ptr, index, stride]);
    data.op_set_opcode(id, op::PTRADD);
    true
}

/// Convert a PTRADD back to INT_ADD when its data-type/stride no longer agrees.
pub struct RulePtraddUndo;

impl Rule for RulePtraddUndo {
    fn name(&self) -> &'static str {
        "ptraddundo"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::PTRADD]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id).clone();
        if operation.inputs.len() != 3 {
            return 0;
        }
        let base = operation.inputs[0];
        let index = operation.inputs[1];
        let stride_value = match constant_value(data, operation.inputs[2]) {
            Some(value) if value != 0 => value,
            _ => return 0,
        };
        let cached = recover_types(data);
        let types = &cached.1;
        let expected_stride = pointer_target(&types, base).map(|target| pointer_stride(&target));
        let index_value = constant_value(data, index);

        // This is the exact inverse guard of the useful PTRADD form.  A
        // non-zero/dynamic index with the recovered element stride is already
        // semantically valid; zero is normalized back to INT_ADD.
        let stride_matches = u32::try_from(stride_value)
            .ok()
            .is_some_and(|stride| expected_stride == Some(stride));
        if stride_matches && index_value != Some(0) {
            return 0;
        }

        if let Some(index_value) = index_value {
            let offset = index_value.wrapping_mul(stride_value);
            let displacement = data.new_constant(offset, data.varnode(base).size);
            data.op_set_inputs(id, vec![base, displacement]);
        } else {
            let offset = if stride_value == 1 {
                index
            } else {
                let stride = data.new_constant(stride_value, data.varnode(base).size);
                let multiply = data.new_op(op::INT_MULT, operation.seq, vec![index, stride]);
                let product =
                    data.new_unique(data.varnode(index).size.max(data.varnode(base).size));
                data.op_set_output(multiply, Some(product));
                data.op_insert_before(multiply, id);
                product
            };
            data.op_set_inputs(id, vec![base, offset]);
        }
        data.op_set_opcode(id, op::INT_ADD);
        1
    }
}

/// Convert a PTRSUB back to INT_ADD when its offset does not name a recovered
/// structure/array component.  The C++ rule also folds local constants beyond
/// the PTRSUB; this graph-facing port keeps that expression intact because the
/// graph has no `opRemoveInput` primitive, while preserving the decisive type
/// guard and opcode conversion.
pub struct RulePtrsubUndo;

impl RulePtrsubUndo {
    fn extra_offset(data: &Funcdata, output: VarnodeId) -> i64 {
        let mut current = output;
        let mut total = 0i64;
        for _ in 0..8 {
            let Some(next) = data.lone_descend(current) else {
                break;
            };
            let operation = data.op(next);
            match operation.opcode {
                op::INT_ADD => {
                    let Some(slot) = operation.inputs.iter().position(|value| *value == current)
                    else {
                        break;
                    };
                    let Some(other) = operation.inputs.get(1 - slot) else {
                        break;
                    };
                    let Some(value) = signed_constant(data, *other) else {
                        break;
                    };
                    total = total.saturating_add(value);
                }
                op::PTRSUB => {
                    if operation.inputs.first().copied() != Some(current) {
                        break;
                    }
                    let Some(value) = operation
                        .inputs
                        .get(1)
                        .and_then(|v| signed_constant(data, *v))
                    else {
                        break;
                    };
                    total = total.saturating_add(value);
                }
                op::PTRADD => {
                    if operation.inputs.first().copied() != Some(current) {
                        break;
                    }
                    let Some(index) = operation
                        .inputs
                        .get(1)
                        .and_then(|v| constant_value(data, *v))
                    else {
                        break;
                    };
                    let Some(stride) = operation
                        .inputs
                        .get(2)
                        .and_then(|v| constant_value(data, *v))
                    else {
                        break;
                    };
                    total = total.saturating_add(index.saturating_mul(stride) as i64);
                }
                _ => break,
            }
            let Some(next_output) = operation.output else {
                break;
            };
            current = next_output;
        }
        total
    }
}

impl Rule for RulePtrsubUndo {
    fn name(&self) -> &'static str {
        "ptrsubundo"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::PTRSUB]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id).clone();
        if operation.inputs.len() < 2 {
            return 0;
        }
        let base = operation.inputs[0];
        let displacement = operation.inputs[1];
        let value = match signed_constant(data, displacement) {
            Some(value) if value >= 0 => value,
            _ => return 0,
        };
        let cached = recover_types(data);
        let (factory, types) = (&cached.0, &cached.1);
        let extra = operation
            .output
            .map(|result| Self::extra_offset(data, result))
            .unwrap_or(0);
        let effective = value.saturating_add(extra);
        let matches_component = pointer_target(&types, base)
            .filter(|target| is_structured(target))
            .and_then(|target| {
                let offset = u32::try_from(effective).ok()?;
                let (_, remainder) = factory.sub_type(&target, offset)?;
                Some(remainder == 0)
            })
            .unwrap_or(false);
        if matches_component {
            return 0;
        }

        data.op_set_opcode(id, op::INT_ADD);
        1
    }
}

/// Convert a typed INT_ADD into PTRADD/PTRSUB.  See `convert_pointer_add` for
/// the intentionally conservative one-level graph form.
pub struct RulePtrArith;

impl Rule for RulePtrArith {
    fn name(&self) -> &'static str {
        "ptrarith"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_ADD]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id).clone();
        if operation.opcode != op::INT_ADD || operation.inputs.len() != 2 {
            return 0;
        }
        let cached = recover_types(data);
        let (factory, types) = (&cached.0, &cached.1);
        let Some((_, ptr, offset)) = pointer_slot(data, id, &types) else {
            return 0;
        };
        let Some(result) = operation.output else {
            return 0;
        };
        if !pointer_add_needs_conversion(data, result, &types) {
            return 0;
        }
        let Some(target) = pointer_target(&types, ptr) else {
            return 0;
        };
        if convert_pointer_add(data, id, ptr, offset, &target, &factory) {
            1
        } else {
            0
        }
    }
}

/// Push a pointer through the bottom of an additive expression.  Every use of
/// the current result must be another INT_ADD with a non-pointer sibling; the
/// new sibling ADD is inserted immediately before that use.
pub struct RulePushPtr;

impl Rule for RulePushPtr {
    fn name(&self) -> &'static str {
        "pushptr"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_ADD]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id).clone();
        if operation.opcode != op::INT_ADD || operation.inputs.len() != 2 {
            return 0;
        }
        let cached = recover_types(data);
        let types = &cached.1;
        let Some((_, ptr, offset)) = pointer_slot(data, id, types) else {
            return 0;
        };
        let Some(result) = operation.output else {
            return 0;
        };
        if !pushable_pointer_add(data, result, &types) {
            return 0;
        }

        let descendants: Vec<OpId> = data.varnode(result).descendants.iter().copied().collect();
        for descendant in descendants {
            let use_operation = data.op(descendant).clone();
            let Some(result_slot) = use_operation
                .inputs
                .iter()
                .position(|value| *value == result)
            else {
                return 0;
            };
            let Some(other) = use_operation.inputs.get(1 - result_slot).copied() else {
                return 0;
            };
            let new_add = data.new_op(op::INT_ADD, use_operation.seq, vec![other, offset]);
            let new_output =
                data.new_unique(data.varnode(other).size.max(data.varnode(offset).size));
            data.op_set_output(new_add, Some(new_output));
            data.op_insert_before(new_add, descendant);
            data.op_set_input(descendant, ptr, result_slot);
            data.op_set_input(descendant, new_output, 1 - result_slot);
        }
        data.op_destroy(id);
        1
    }
}

/// Drill a LOAD/STORE through the first component of a recovered structure or
/// array by inserting PTRSUB(pointer,0).
/// `RuleStructOffset0`: an access through a pointer to a structure or array
/// whose first component fills the access is an access to that component.
///
/// Two facts had to exist before this could be registered, and each was found by
/// building the previous one and watching what broke. It inserts
/// `PTRSUB(ptr, 0)` and re-points the access, so with only a plain pointer the
/// result inferred as pointer-to-structure again and the guard matched its own
/// output forever: `DataType::PointerRel` fixed that. It then rewrote the stack
/// frame, printing a slot as `local_20->field_0`, because nothing distinguished
/// the frame from an aggregate: `DataType::Spacebase` fixed that.
pub struct RuleStructOffset0;

impl Rule for RuleStructOffset0 {
    fn name(&self) -> &'static str {
        "structoffset0"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::LOAD, op::STORE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id).clone();
        let move_size = match operation.opcode {
            op::LOAD => operation.output.map(|value| data.varnode(value).size),
            op::STORE => operation
                .inputs
                .get(2)
                .map(|value| data.varnode(*value).size),
            _ => None,
        };
        let Some(move_size) = move_size else {
            return 0;
        };
        let Some(ptr) = operation.inputs.get(1).copied() else {
            return 0;
        };
        let cached = recover_types(data);
        let (factory, types) = (&cached.0, &cached.1);
        // A plain pointer only. A `PointerRel` already points into a container,
        // so rewriting it again would re-derive what is already derived — the
        // loop this rule used to be unregistered for.
        if matches!(types.get(ptr), Some(DataType::PointerRel { .. })) {
            return 0;
        }
        let Some(target) = pointer_target(&types, ptr) else {
            return 0;
        };
        match &target {
            DataType::Struct { .. } => {
                if byte_width(&target) < move_size {
                    return 0;
                }
                let Some((field, remainder)) = factory.sub_type(&target, 0) else {
                    return 0;
                };
                if remainder != 0 || byte_width(&field) < move_size {
                    return 0;
                }
            }
            DataType::Array { count, .. } => {
                let total = byte_width(&target);
                if *count == 0 || total < move_size || (total == move_size && *count != 1) {
                    return 0;
                }
                let Some((element, remainder)) = factory.sub_type(&target, 0) else {
                    return 0;
                };
                if remainder != 0 || byte_width(&element) < move_size {
                    return 0;
                }
            }
            _ => return 0,
        }

        let displacement = data.new_constant(0, data.varnode(ptr).size);
        let ptrsub = data.new_op(op::PTRSUB, operation.seq, vec![ptr, displacement]);
        let narrowed = data.new_unique(data.varnode(ptr).size);
        data.op_set_output(ptrsub, Some(narrowed));
        data.op_insert_before(ptrsub, id);
        data.op_set_input(id, narrowed, 1);
        1
    }
}

/// A graph-facing portion of RulePieceStructure.  The storage/symbol half of
/// the C++ rule needs `partialRoot`, symbol-entry identity, address-tied and
/// proto-partial flags, none of which the graph models.  Its independent
/// INT_ZEXT-to-PIECE transform is fully representable and is retained here.
pub struct RulePieceStructure;

fn find_structured_type(
    types: &RecoveredTypes,
    output: VarnodeId,
    output_size: u32,
) -> Option<DataType> {
    if let Some(ty) = types.get(output) {
        if is_structured(ty) && byte_width(ty) == output_size {
            return Some(ty.clone());
        }
    }
    types.iter().find_map(|(_, ty)| match ty {
        DataType::Pointer { to, .. } if is_structured(to) && byte_width(to) == output_size => {
            Some(to.as_ref().clone())
        }
        _ => None,
    })
}

impl Rule for RulePieceStructure {
    fn name(&self) -> &'static str {
        "piecestructure"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::PIECE, op::INT_ZEXT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id).clone();
        let Some(output) = operation.output else {
            return 0;
        };
        let output_size = data.varnode(output).size;
        let cached = recover_types(data);
        let (factory, types) = (&cached.0, &cached.1);
        let Some(structured) = find_structured_type(&types, output, output_size) else {
            return 0;
        };

        if operation.opcode == op::PIECE {
            // Reassigning every leaf to a field address is the other half of
            // RulePieceStructure and requires graph fields deliberately absent
            // from VarnodeFlags.  Do not claim a rewrite without those locks.
            return 0;
        }
        if operation.opcode != op::INT_ZEXT || operation.inputs.len() != 1 {
            return 0;
        }
        let input_value = operation.inputs[0];
        if data.varnode(input_value).flags.constant || data.varnode(input_value).size >= output_size
        {
            return 0;
        }
        let high_size = output_size - data.varnode(input_value).size;
        if high_size == 0 || factory.sub_type(&structured, 0).is_none() {
            return 0;
        }
        let zero = data.new_constant(0, high_size);
        data.op_set_inputs(id, vec![zero, input_value]);
        data.op_set_opcode(id, op::PIECE);
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{RAM_SPACE, REGISTER_SPACE};

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    fn input_value(data: &mut Funcdata, offset: u64, size: u32) -> VarnodeId {
        let value = data.new_varnode(REGISTER_SPACE, offset, size);
        data.mark_input(value);
        value
    }

    fn binary(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        address: u64,
        opcode: i32,
        left: VarnodeId,
        right: VarnodeId,
        size: u32,
    ) -> (OpId, VarnodeId) {
        let operation = data.new_op(opcode, seq(address), vec![left, right]);
        let output = data.new_unique(size);
        data.op_set_output(operation, Some(output));
        data.op_insert_end(operation, block);
        (operation, output)
    }

    fn load(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        address: u64,
        pointer: VarnodeId,
        size: u32,
    ) -> (OpId, VarnodeId) {
        let space = data.new_constant(u64::from(RAM_SPACE), 4);
        let operation = data.new_op(op::LOAD, seq(address), vec![space, pointer]);
        let output = data.new_unique(size);
        data.op_set_output(operation, Some(output));
        data.op_insert_end(operation, block);
        (operation, output)
    }

    fn ptrsub_load(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        address: u64,
        base: VarnodeId,
        offset: u64,
        size: u32,
    ) -> VarnodeId {
        let displacement = data.new_constant(offset, 4);
        let (ptrsub, pointer) = binary(data, block, address, op::PTRSUB, base, displacement, 4);
        let _ = ptrsub;
        let _ = load(data, block, address + 4, pointer, size);
        pointer
    }

    #[test]
    fn ptrarith_fires_for_recovered_struct_field_and_declines_without_pointer_sink() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let base = input_value(&mut data, 0, 4);
        let displacement = data.new_constant(4, 4);
        let (add, pointer) = binary(&mut data, block, 0x1000, op::INT_ADD, base, displacement, 4);
        let (_, _) = load(&mut data, block, 0x1004, pointer, 4);
        assert_eq!(RulePtrArith.apply_op(add, &mut data), 1);
        assert_eq!(data.op(add).opcode, op::PTRSUB);
        assert_eq!(data.op(add).inputs[0], base);

        let mut decline = Funcdata::default();
        let block = decline.new_block(0x2000);
        let base = input_value(&mut decline, 0, 4);
        let displacement = decline.new_constant(4, 4);
        let (add, _) = binary(
            &mut decline,
            block,
            0x2000,
            op::INT_ADD,
            base,
            displacement,
            4,
        );
        assert_eq!(RulePtrArith.apply_op(add, &mut decline), 0);
        assert_eq!(decline.op(add).opcode, op::INT_ADD);
    }

    #[test]
    fn pushptr_fires_only_for_an_add_chain() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x3000);
        let base = input_value(&mut data, 0, 4);
        let first_offset = data.new_constant(4, 4);
        let (inner, inner_out) =
            binary(&mut data, block, 0x3000, op::INT_ADD, base, first_offset, 4);
        let second_offset = data.new_constant(8, 4);
        let (outer, outer_out) = binary(
            &mut data,
            block,
            0x3004,
            op::INT_ADD,
            inner_out,
            second_offset,
            4,
        );
        let _ = load(&mut data, block, 0x3008, outer_out, 4);
        assert_eq!(RulePushPtr.apply_op(inner, &mut data), 1);
        assert!(data.opcode_of(inner).is_none());
        assert_eq!(data.op(outer).inputs[0], base);
        let pushed = data.op(outer).inputs[1];
        assert_eq!(
            data.op(data.varnode(pushed).def.unwrap()).opcode,
            op::INT_ADD
        );

        let mut decline = Funcdata::default();
        let block = decline.new_block(0x3100);
        let base = input_value(&mut decline, 0, 4);
        let offset = decline.new_constant(4, 4);
        let (add, pointer) = binary(&mut decline, block, 0x3100, op::INT_ADD, base, offset, 4);
        let _ = load(&mut decline, block, 0x3104, pointer, 4);
        assert_eq!(RulePushPtr.apply_op(add, &mut decline), 0);
    }

    #[test]
    fn struct_offset0_inserts_ptrsub_and_declines_malformed_access() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x4000);
        let base = input_value(&mut data, 0, 4);
        let (load_op, _) = load(&mut data, block, 0x4000, base, 4);
        assert_eq!(RuleStructOffset0.apply_op(load_op, &mut data), 1);
        let narrowed = data.op(load_op).inputs[1];
        assert_eq!(
            data.op(data.varnode(narrowed).def.unwrap()).opcode,
            op::PTRSUB
        );

        let mut decline = Funcdata::default();
        let block = decline.new_block(0x4100);
        let base = input_value(&mut decline, 0, 4);
        let space = decline.new_constant(u64::from(RAM_SPACE), 4);
        let malformed = decline.new_op(op::LOAD, seq(0x4100), vec![space, base]);
        decline.op_insert_end(malformed, block);
        assert_eq!(RuleStructOffset0.apply_op(malformed, &mut decline), 0);
    }

    #[test]
    fn ptradd_undo_reverts_bad_stride_but_keeps_matching_indexed_pointer() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x5000);
        let base = input_value(&mut data, 0, 4);
        let index = input_value(&mut data, 4, 4);
        let stride = data.new_constant(8, 4);
        let (ptradd, _) = binary(&mut data, block, 0x5000, op::PTRADD, base, index, 4);
        data.op_set_input(ptradd, stride, 2);
        assert_eq!(RulePtraddUndo.apply_op(ptradd, &mut data), 1);
        assert_eq!(data.op(ptradd).opcode, op::INT_ADD);

        let mut decline = Funcdata::default();
        let block = decline.new_block(0x5100);
        let base = input_value(&mut decline, 0, 4);
        let index = input_value(&mut decline, 4, 4);
        let stride = decline.new_constant(4, 4);
        let (ptradd, pointer) = binary(&mut decline, block, 0x5100, op::PTRADD, base, index, 4);
        decline.op_set_input(ptradd, stride, 2);
        let _ = load(&mut decline, block, 0x5104, pointer, 4);
        assert_eq!(RulePtraddUndo.apply_op(ptradd, &mut decline), 0);
        assert_eq!(decline.op(ptradd).opcode, op::PTRADD);
    }

    #[test]
    fn ptrsub_undo_reverts_unknown_component_but_keeps_recovered_field() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x6000);
        let base = input_value(&mut data, 0, 4);
        let displacement = data.new_constant(4, 4);
        let (ptrsub, _) = binary(&mut data, block, 0x6000, op::PTRSUB, base, displacement, 4);
        assert_eq!(RulePtrsubUndo.apply_op(ptrsub, &mut data), 1);
        assert_eq!(data.op(ptrsub).opcode, op::INT_ADD);

        let mut decline = Funcdata::default();
        let block = decline.new_block(0x6100);
        let base = input_value(&mut decline, 0, 4);
        let pointer = ptrsub_load(&mut decline, block, 0x6100, base, 4, 4);
        let ptrsub = decline
            .varnode(pointer)
            .def
            .expect("PTRSUB output has a definition");
        assert_eq!(RulePtrsubUndo.apply_op(ptrsub, &mut decline), 0);
        assert_eq!(decline.op(ptrsub).opcode, op::PTRSUB);
    }

    #[test]
    fn piece_structure_converts_zext_across_recovered_storage_and_declines_plain_zext() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x7000);
        let base = input_value(&mut data, 0, 4);
        let _ = ptrsub_load(&mut data, block, 0x7000, base, 0, 4);
        let _ = ptrsub_load(&mut data, block, 0x7010, base, 4, 4);
        let zext_input = input_value(&mut data, 8, 4);
        let zext_zero = data.new_constant(0, 4);
        let (zext, output) = binary(
            &mut data,
            block,
            0x7020,
            op::INT_ZEXT,
            zext_input,
            zext_zero,
            8,
        );
        // INT_ZEXT is unary in p-code; remove the temporary second input used
        // only to share the binary test helper.
        data.op_set_inputs(zext, vec![zext_input]);
        assert_eq!(RulePieceStructure.apply_op(zext, &mut data), 1);
        assert_eq!(data.op(zext).opcode, op::PIECE);
        assert_eq!(data.op(zext).inputs.len(), 2);
        assert_eq!(data.varnode(output).size, 8);

        let mut decline = Funcdata::default();
        let block = decline.new_block(0x7100);
        let zext_input = input_value(&mut decline, 0, 4);
        let zext_zero = decline.new_constant(0, 4);
        let (zext, _) = binary(
            &mut decline,
            block,
            0x7100,
            op::INT_ZEXT,
            zext_input,
            zext_zero,
            8,
        );
        decline.op_set_inputs(zext, vec![zext_input]);
        assert_eq!(RulePieceStructure.apply_op(zext, &mut decline), 0);
        assert_eq!(decline.op(zext).opcode, op::INT_ZEXT);
    }
}

pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(RulePtrArith),
        Box::new(RulePtraddUndo),
        Box::new(RulePtrsubUndo),
        Box::new(RuleStructOffset0),
        Box::new(RulePushPtr),
        Box::new(RulePieceStructure),
    ]
}
