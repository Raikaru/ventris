//! Memory and address-space rewrites from Ghidra 12.1.3's
//! `ruleaction.cc`.
//!
//! The implementations below follow the real `applyOp` bodies for
//! `RuleEarlyRemoval`, `RuleLoadVarnode`, `RuleStoreVarnode`, and
//! `RuleExpandLoad`.  A LOAD/STORE whose address operand is a constant is
//! already a byte address in this graph, and the first p-code operand's
//! constant offset is the canonical integer space id.  That is enough to
//! preserve the exact addressed location without guessing a space.  The
//! spacebase-plus-constant form of the C++ helper remains deliberately
//! conservative: `Funcdata` carries a frame-base location, but the graph has
//! no architecture address-space association or address word-size table for
//! the `checkSpacebase`/`vnSpacebase` path.
//!
//! `RuleExpandLoad` is registered in Ghidra's cleanup pool
//! (`coreaction.cc:5753`).  Its root-pointer query uses
//! `getTypeReadFacing(defOp/op)` (`ruleaction.cc:10946-10961`) and its
//! natural-truncation query uses `getTypeDefFacing()` for the original LOAD
//! output (`ruleaction.cc:10981-10985`).  For every type that does not need
//! resolution, both C++ queries return the Varnode's own type
//! (`varnode.cc:626-645`), so this port uses the cached per-Varnode type after
//! the `needs_resolution` gate below.  That gate refuses the representable
//! array-of-one, whole-single-field structure, and pointer-to-either shapes
//! where an operation-facing query could resolve to a different type; the
//! refusal makes the substitution exact rather than silently testing a fact
//! different from Ghidra's.
//!
//! `RuleIndirectConcat` is disabled in the pinned C++ source: its `addRule`
//! line is commented out at `coreaction.cc:5718`.  IOP-space operation
//! references and address-force state are available in this graph, but its
//! body still needs `splitVarnode` and operation uninsertion, which have no
//! graph equivalent here.
//! `RuleEarlyRemoval` is registered in Ghidra's `actprop` pool in the
//! `deadcode` group (`coreaction.cc:5563`).  The graph-facing port below keeps
//! its `isCall`, `isIndirectSource`, and no-descendant checks
//! (`ruleaction.cc:30-35`), but deliberately refuses more aggressively for
//! liveness: address-tied/address-force, mapped, persistent/global, volatile,
//! and otherwise unclassified outputs are retained.  It also requires a
//! completed graph and an internal unique-space output because the graph has
//! no per-space `doesDeadcode`/`deadRemovalAllowedSeen` state
//! (`ruleaction.cc:36-40`).  These named refusals can only make the rule fire
//! less often than Ghidra.
//!
//! `deadcode::eliminate_dead_code` already removes most unread non-call and
//! non-store outputs as a separate bit-consumption pass
//! (`deadcode.rs:55-88`), but that pass is not the in-pool
//! `RuleEarlyRemoval`; registering this conservative rule can only remove an
//! operation earlier when its stricter private-temporary/completed-graph proof
//! succeeds.
//!
//! `RuleAddrForceRelease` is disabled/commented out in the pinned source.  The
//! graph now carries address-force state and its direct-write cleanup, but the
//! commented body also needs Varnode containment and `terminated` state.
//! `RuleShadowVar` is disabled/commented out in the pinned source; its
//! quadratic previous-MULTIEQUAL scan is not an active rule to port.
//!
//! The C++ metatypes `TYPE_UNKNOWN`, `TYPE_STRUCT`, and `TYPE_ARRAY` map to
//! `DataType::Unknown`, `Struct`, and `Array` in the explicit exclusion below.
//! There is no distinct partial-structure variant: the graph's
//! `DataType::Struct` also covers the exact-piece form used for
//! `TYPE_PARTIALSTRUCT`, so the same exclusion is conservatively applied.
//! `TYPE_UNION` and `TYPE_PARTIALUNION` have no union `DataType` variant and
//! are therefore vacuous.

use super::action::Rule;
use super::guard::Location;
use super::typefactory::{DataType, TypeFactory};
use super::{Funcdata, OpId, VarnodeId};
use ventris_lifter::{RAM_SPACE, UNIQUE_SPACE};
use ventris_pcode::{CONST_SPACE, op};

fn input(data: &Funcdata, id: OpId, slot: usize) -> Option<VarnodeId> {
    data.op(id).inputs.get(slot).copied()
}

fn constant_offset(data: &Funcdata, value: VarnodeId) -> Option<u64> {
    let varnode = data.varnode(value);
    varnode.flags.constant.then_some(varnode.offset)
}

/// Read the LOAD/STORE space operand without inventing an architecture map.
///
/// Ghidra's `getSpaceFromConst()` returns an address-space object.  Ventris
/// stores that object's canonical id in the constant's offset, so the checked
/// conversion is the corresponding graph operation.
fn constant_space(data: &Funcdata, value: VarnodeId) -> Option<u32> {
    let varnode = data.varnode(value);
    if !varnode.flags.constant || varnode.space != CONST_SPACE {
        return None;
    }
    u32::try_from(varnode.offset).ok()
}
/// Whether `ty` is one of the graph shapes for which Ghidra's
/// `Datatype::needsResolution()` is set.
///
/// `TypeArray` sets the flag for an array of one at `type.cc:1519`, and
/// `TypeStruct` sets it for a single field that fills the whole structure at
/// `type.cc:1746-1750` and `type.cc:2224-2228`.  `TypePointer` inherits the
/// flag from a non-pointer target at `type.cc:1205-1209`; the direct-target
/// check here therefore intentionally does not recurse through pointers.
/// Ghidra's union constructor also sets the flag (`type.cc:2857`), but this
/// graph has no union `DataType` variant.
///
/// `getTypeReadFacing()`/`getTypeDefFacing()` return the Varnode's own type
/// whenever this flag is clear (`varnode.cc:626-645`).  Refusing these
/// representable shapes is what makes the recovered per-Varnode type equal
/// the facing type used by `RuleExpandLoad`, rather than firing on a fact
/// that only the operation-specific C++ resolver could provide.
fn needs_resolution(ty: &DataType) -> bool {
    fn aggregate_shape(ty: &DataType) -> bool {
        match ty {
            DataType::Array { count, .. } => *count == 1,
            DataType::Struct { fields, .. } => {
                let [field] = fields.as_slice() else {
                    return false;
                };
                field.offset == 0
                    && TypeFactory::align_size(&field.ty) == TypeFactory::align_size(ty)
            }
            _ => false,
        }
    }

    aggregate_shape(ty)
        || matches!(
            ty,
            DataType::Pointer { to, .. } | DataType::PointerRel { to, .. }
                if aggregate_shape(to)
        )
}

fn pointer_target(ty: &DataType) -> Option<&DataType> {
    match ty {
        DataType::Pointer { to, .. } | DataType::PointerRel { to, .. } => Some(to.as_ref()),
        _ => None,
    }
}

fn is_call_opcode(opcode: i32) -> bool {
    matches!(opcode, op::CALL | op::CALLIND | op::CALLOTHER | op::NEW)
}

fn is_indirect_source(data: &Funcdata, target: OpId) -> bool {
    data.live_ops().any(|(_, candidate)| {
        candidate.opcode == op::INDIRECT
            && candidate
                .inputs
                .get(1)
                .is_some_and(|annotation| data.iop_target(*annotation) == Some(target))
    })
}

fn overlaps(left: Location, right: Location) -> bool {
    left.space == right.space
        && left.offset
            <= right
                .offset
                .saturating_add(u64::from(right.size).saturating_sub(1))
        && right.offset
            <= left
                .offset
                .saturating_add(u64::from(left.size).saturating_sub(1))
}

fn location(data: &Funcdata, value: VarnodeId) -> Location {
    let varnode = data.varnode(value);
    Location {
        space: varnode.space,
        offset: varnode.offset,
        size: varnode.size,
    }
}

fn has_persistent_symbol(data: &Funcdata, value: VarnodeId) -> bool {
    let Some(scope) = data.scope_local() else {
        return false;
    };
    let location = location(data, value);
    scope.scope().entries().any(|entry| {
        entry.location().is_some_and(|storage| {
            overlaps(storage, location)
                && scope
                    .scope()
                    .entry_symbol(entry.id())
                    .is_some_and(|symbol| symbol.is_persistent())
        })
    })
}

/// The graph-facing conservative form of Ghidra's `isAutoLive`.
fn is_auto_live(data: &Funcdata, value: VarnodeId) -> bool {
    let varnode = data.varnode(value);
    if data.is_addr_tied(value) || data.is_addr_force(value) || varnode.space == RAM_SPACE {
        return true;
    }
    let location = location(data, value);
    data.scope_local()
        .is_some_and(|scope| scope.is_mapped(location))
        || has_persistent_symbol(data, value)
}

/// Only an explicitly unique, non-volatile temporary can be proven private.
fn is_private_temporary(data: &Funcdata, value: VarnodeId) -> bool {
    let flags = data.varnode(value).flags;
    flags.unique && !flags.constant && !flags.volatile && !is_auto_live(data, value)
}

/// Ghidra's `Heritage::deadRemovalAllowed`: `pass > info->deadcodedelay`
/// (`heritage.cc:2829-2834`), a per-space counter that delays removal until the
/// space has stopped acquiring new varnodes.
///
/// This graph has no multi-pass heritage and therefore no delay to compare
/// against, and `graph::deadcode::eliminate_dead_code` already removes dead
/// operations in these spaces on every round with no delay - so the condition is
/// unconditionally true here, and the space test is what carries the caution.
///
/// It previously read `data.processing_complete`, which was not a stricter
/// certificate but an impossible one: only `ActionStop` sets that flag and
/// Ghidra runs `ActionStop` last (`coreaction.cc:5795`), while this rule lives in
/// `actprop` (`5563`) deep inside the main loop. The guard could never be true
/// where the rule runs, so the rule was decoration rather than a port.
fn dead_removal_allowed(data: &Funcdata, value: VarnodeId) -> bool {
    data.varnode(value).space == UNIQUE_SPACE
}

/// Remove an unread operation only when the graph can prove that its output is
/// a private temporary and all stricter liveness gates have passed.
pub struct RuleEarlyRemoval;

impl Rule for RuleEarlyRemoval {
    fn name(&self) -> &'static str {
        "earlyremoval"
    }

    fn op_list(&self) -> Vec<i32> {
        (0..op::MAX).collect()
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id).clone();
        if is_call_opcode(operation.opcode) || is_indirect_source(data, id) {
            return 0;
        }
        let Some(output) = operation.output else {
            return 0;
        };
        if !data.varnode(output).descendants.is_empty()
            || !is_private_temporary(data, output)
            || !dead_removal_allowed(data, output)
        {
            return 0;
        }
        data.op_destroy(id);
        1
    }
}

/// `LOAD(space, constant-address)` -> `COPY(addressed-varnode)`.
pub struct RuleLoadVarnode;

impl Rule for RuleLoadVarnode {
    fn name(&self) -> &'static str {
        "loadvarnode"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::LOAD]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(output) = data.op(id).output else {
            return 0;
        };
        let Some(space_input) = input(data, id, 0) else {
            return 0;
        };
        let Some(address_input) = input(data, id, 1) else {
            return 0;
        };
        let Some(space) = constant_space(data, space_input) else {
            return 0;
        };
        let Some(offset) = constant_offset(data, address_input) else {
            return 0;
        };
        let size = data.varnode(output).size;
        let addressed = data.new_varnode(space, offset, size);
        data.op_set_inputs(id, vec![addressed]);
        data.op_set_opcode(id, op::COPY);
        1
    }
}

/// `STORE(space, constant-address, value)` -> `COPY(value)` with a location
/// output representing the store destination.
pub struct RuleStoreVarnode;

impl Rule for RuleStoreVarnode {
    fn name(&self) -> &'static str {
        "storevarnode"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::STORE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(space_input) = input(data, id, 0) else {
            return 0;
        };
        let Some(address_input) = input(data, id, 1) else {
            return 0;
        };
        let Some(value) = input(data, id, 2) else {
            return 0;
        };
        let Some(space) = constant_space(data, space_input) else {
            return 0;
        };
        let Some(offset) = constant_offset(data, address_input) else {
            return 0;
        };
        let size = data.varnode(value).size;
        let destination = data.new_varnode(space, offset, size);
        data.op_set_output(id, Some(destination));
        data.op_set_inputs(id, vec![value]);
        data.op_set_opcode(id, op::COPY);
        1
    }
}

/// Check that every use of `value` is `(value & C) == D` or `(value & C) != D`.
///
/// This is `RuleExpandLoad::checkAndComparison` from `ruleaction.cc:10874-10892`.
fn check_and_comparison(data: &Funcdata, value: VarnodeId) -> bool {
    let descendants: Vec<OpId> = data.varnode(value).descendants.iter().copied().collect();
    descendants.into_iter().all(|and_id| {
        let and_op = data.op(and_id);
        if and_op.opcode != op::INT_AND
            || !input(data, and_id, 1).is_some_and(|mask| constant_offset(data, mask).is_some())
        {
            return false;
        }
        let Some(and_output) = and_op.output else {
            return false;
        };
        let Some(compare_id) = data.lone_descend(and_output) else {
            return false;
        };
        let compare = data.op(compare_id);
        matches!(compare.opcode, op::INT_EQUAL | op::INT_NOTEQUAL)
            && input(data, compare_id, 1)
                .is_some_and(|constant| constant_offset(data, constant).is_some())
    })
}

/// Widen the constants in the `(value & C) == D`/`!=` uses checked above.
///
/// This is `RuleExpandLoad::modifyAndComparison` from
/// `ruleaction.cc:10895-10925`.  The graph records constants by width and
/// value, so the C++ `updateType(dt)` annotations have no separate graph edge
/// to update; the unsigned fallback is represented by the same width/value
/// constants and the recovered type is used for the rule's guards.
fn modify_and_comparison(
    data: &mut Funcdata,
    old_value: VarnodeId,
    new_value: VarnodeId,
    ty: &DataType,
    offset: u32,
) {
    let descendants: Vec<OpId> = data
        .varnode(old_value)
        .descendants
        .iter()
        .copied()
        .collect();
    let shift = offset.saturating_mul(8);
    let size = TypeFactory::align_size(ty);
    for and_id in descendants {
        let Some(and_output) = data.op(and_id).output else {
            continue;
        };
        let Some(compare_id) = data.lone_descend(and_output) else {
            continue;
        };
        let Some(mask) = input(data, and_id, 1).and_then(|value| constant_offset(data, value))
        else {
            continue;
        };
        let widened_mask = data.new_constant(mask.wrapping_shl(shift), size);
        data.op_set_input(and_id, new_value, 0);
        data.op_set_input(and_id, widened_mask, 1);

        let Some(constant) =
            input(data, compare_id, 1).and_then(|value| constant_offset(data, value))
        else {
            continue;
        };
        let widened_constant = data.new_constant(constant.wrapping_shl(shift), size);
        data.op_set_input(compare_id, widened_constant, 1);
    }
}

/// `LOAD` widened to the recovered pointer target, with a truncating
/// `SUBPIECE` unless all output uses are integer mask comparisons.
///
/// Ported from Ghidra `RuleExpandLoad::applyOp`, `ruleaction.cc:10937-11017`.
/// This rule belongs to the cleanup pool (`coreaction.cc:5753`) and therefore
/// is intentionally not included in [`all`].
pub struct RuleExpandLoad;

impl Rule for RuleExpandLoad {
    fn name(&self) -> &'static str {
        "expandload"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::LOAD]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(output) = data.op(id).output else {
            return 0;
        };
        let Some(original_root) = input(data, id, 1) else {
            return 0;
        };
        let Some(space_input) = input(data, id, 0) else {
            return 0;
        };
        let out_size = data.varnode(output).size;
        let mut root = original_root;
        let mut offset = 0_u32;
        let mut add_op = None;

        if let Some(definition) = data.varnode(root).def {
            let definition_op = data.op(definition);
            let is_small_constant_add = definition_op.opcode == op::INT_ADD
                && input(data, definition, 1)
                    .is_some_and(|constant| constant_offset(data, constant).is_some());
            if is_small_constant_add {
                let Some(base) = input(data, definition, 0) else {
                    return 0;
                };
                let Some(raw_offset) =
                    input(data, definition, 1).and_then(|value| constant_offset(data, value))
                else {
                    return 0;
                };
                if raw_offset > 16 {
                    return 0;
                }
                let Some(add_output) = definition_op.output else {
                    return 0;
                };
                if data.lone_descend(add_output).is_none() {
                    return 0;
                }
                root = base;
                offset = raw_offset as u32;
                add_op = Some(definition);
            }
        }

        let recovered = data.recovered_types();
        let Some(root_type) = recovered.1.get(root).cloned() else {
            return 0;
        };
        if needs_resolution(&root_type) {
            return 0;
        }
        let Some(element_type) = pointer_target(&root_type).cloned() else {
            return 0;
        };
        let element_size = TypeFactory::align_size(&element_type);
        let Some(out_plus_offset) = out_size.checked_add(offset) else {
            return 0;
        };
        if element_size <= out_size || element_size < out_plus_offset {
            return 0;
        }
        // TYPE_UNKNOWN/STRUCT/ARRAY are the three represented exclusions.
        // TYPE_PARTIALSTRUCT is also a Struct in this graph; TYPE_UNION and
        // TYPE_PARTIALUNION have no representation and are vacuous.
        if matches!(
            &element_type,
            DataType::Unknown(_) | DataType::Struct { .. } | DataType::Array { .. }
        ) {
            return 0;
        }

        let add_form = check_and_comparison(data, output);
        if constant_space(data, space_input).is_none() {
            return 0;
        }
        let lsb_cut = if add_form {
            if data.big_endian {
                let Some(cut) = element_size.checked_sub(out_size) else {
                    return 0;
                };
                let Some(cut) = cut.checked_sub(offset) else {
                    return 0;
                };
                cut
            } else {
                offset
            }
        } else {
            // Natural integer truncation only accepts TYPE_INT/TYPE_UINT
            // pointed-to types.  `DataType::Int` covers both metatypes.
            if !matches!(&element_type, DataType::Int { .. }) {
                return 0;
            }
            let Some(output_type) = recovered.1.get(output) else {
                return 0;
            };
            if needs_resolution(output_type) {
                return 0;
            }
            if !matches!(
                output_type,
                DataType::Int { .. } | DataType::Unknown(_) | DataType::Bool
            ) {
                return 0;
            }
            if data.big_endian {
                if out_plus_offset != element_size {
                    return 0;
                }
            } else if offset != 0 {
                return 0;
            }
            0
        };

        let mut comparison_type = element_type.clone();
        if !matches!(comparison_type, DataType::Int { .. }) {
            comparison_type = DataType::Int {
                bits: element_size.saturating_mul(8),
                signed: false,
            };
        }
        let new_output = data.new_unique(element_size);
        data.op_set_output(id, Some(new_output));
        if let Some(add_op) = add_op {
            data.op_set_input(id, root, 1);
            data.op_destroy(add_op);
        }
        if add_form {
            modify_and_comparison(data, output, new_output, &comparison_type, lsb_cut);
        } else {
            let zero = data.new_constant(0, 4);
            let sequence = data.op(id).seq;
            let subpiece = data.new_op(op::SUBPIECE, sequence, vec![new_output, zero]);
            data.op_set_output(subpiece, Some(output));
            data.op_insert_after(subpiece, id);
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::super::SeqNum;
    use super::*;
    use ventris_pcode::{RAM_SPACE, REGISTER_SPACE};

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    #[test]
    fn load_varnode_fires_for_constant_address_and_preserves_space_id() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let space = data.new_constant(RAM_SPACE as u64, 4);
        let address = data.new_constant(0x8040, 4);
        let output = data.new_unique(4);
        let load = data.new_op(op::LOAD, seq(0x1000), vec![space, address]);
        data.op_set_output(load, Some(output));
        data.op_insert_end(load, block);

        assert_eq!(RuleLoadVarnode.apply_op(load, &mut data), 1);
        assert_eq!(data.op(load).opcode, op::COPY);
        assert_eq!(data.op(load).inputs.len(), 1);
        let addressed = data.varnode(data.op(load).inputs[0]);
        assert_eq!(addressed.space, RAM_SPACE);
        assert_eq!(addressed.offset, 0x8040);
        assert_eq!(addressed.size, 4);
    }

    #[test]
    fn load_varnode_declines_without_constant_address() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let space = data.new_constant(RAM_SPACE as u64, 4);
        let address = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        data.mark_input(address);
        let output = data.new_unique(4);
        let load = data.new_op(op::LOAD, seq(0x1000), vec![space, address]);
        data.op_set_output(load, Some(output));
        data.op_insert_end(load, block);

        assert_eq!(RuleLoadVarnode.apply_op(load, &mut data), 0);
        assert_eq!(data.op(load).opcode, op::LOAD);
        assert_eq!(data.op(load).inputs, vec![space, address]);
    }

    #[test]
    fn store_varnode_fires_for_constant_address_and_creates_destination() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x2000);
        let space = data.new_constant(RAM_SPACE as u64, 4);
        let address = data.new_constant(0x9000, 4);
        let value = data.new_unique(2);
        let store = data.new_op(op::STORE, seq(0x2000), vec![space, address, value]);
        data.op_insert_end(store, block);

        assert_eq!(RuleStoreVarnode.apply_op(store, &mut data), 1);
        assert_eq!(data.op(store).opcode, op::COPY);
        assert_eq!(data.op(store).inputs, vec![value]);
        let destination = data.op(store).output.expect("store destination");
        let destination = data.varnode(destination);
        assert_eq!(destination.space, RAM_SPACE);
        assert_eq!(destination.offset, 0x9000);
        assert_eq!(destination.size, 2);
    }

    #[test]
    fn store_varnode_declines_without_constant_address() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x2000);
        let space = data.new_constant(RAM_SPACE as u64, 4);
        let address = data.new_varnode(REGISTER_SPACE, 0x24, 4);
        data.mark_input(address);
        let value = data.new_unique(4);
        let store = data.new_op(op::STORE, seq(0x2000), vec![space, address, value]);
        data.op_insert_end(store, block);

        assert_eq!(RuleStoreVarnode.apply_op(store, &mut data), 0);
        assert!(data.op(store).output.is_none());
    }

    /// Ghidra's `RuleExpandLoad::applyOp` widens a natural integer truncation
    /// when the recovered pointer target is larger than the LOAD; the
    /// per-Varnode type is the facing type because `needsResolution` is clear
    /// (`varnode.cc:626-645`).
    #[test]
    fn expand_load_inserts_subpiece_for_natural_integer_truncation() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x2500);
        let base = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(base);
        let first_index = data.new_varnode(REGISTER_SPACE, 4, 4);
        data.mark_input(first_index);
        let stride = data.new_constant(4, 4);
        let wide_root = data.new_unique(4);
        let wide_ptr = data.new_op(op::PTRADD, seq(0x2500), vec![base, first_index, stride]);
        data.op_set_output(wide_ptr, Some(wide_root));
        data.op_insert_end(wide_ptr, block);

        let wide_space = data.new_constant(RAM_SPACE as u64, 4);
        let wide_value = data.new_unique(8);
        let wide_load = data.new_op(op::LOAD, seq(0x2504), vec![wide_space, wide_root]);
        data.op_set_output(wide_load, Some(wide_value));
        data.op_insert_end(wide_load, block);

        let second_index = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.mark_input(second_index);
        let root = data.new_unique(4);
        let root_ptr = data.new_op(op::PTRADD, seq(0x2508), vec![base, second_index, stride]);
        data.op_set_output(root_ptr, Some(root));
        data.op_insert_end(root_ptr, block);
        let load_space = data.new_constant(RAM_SPACE as u64, 4);
        let loaded = data.new_unique(4);
        let load = data.new_op(op::LOAD, seq(0x250c), vec![load_space, root]);
        data.op_set_output(load, Some(loaded));
        data.op_insert_end(load, block);

        // A non-comparison use selects the natural-truncation branch instead
        // of RuleExpandLoad's `(V & C) == D` fast path.
        let sink = data.new_unique(4);
        let use_op = data.new_op(op::COPY, seq(0x250c), vec![loaded]);
        data.op_set_output(use_op, Some(sink));
        data.op_insert_end(use_op, block);

        let recovered = data.recovered_types();
        assert!(
            matches!(
                recovered.1.get(root),
                Some(DataType::Pointer { to, .. })
                    if matches!(to.as_ref(), DataType::Int { bits: 64, .. })
            ),
            "unexpected recovered root type: {:?}",
            recovered.1.get(root)
        );

        assert_eq!(RuleExpandLoad.apply_op(load, &mut data), 1);
        let widened = data.op(load).output.expect("widened LOAD output");
        assert_eq!(data.varnode(widened).size, 8);
        let subpiece = data.varnode(loaded).def.expect("truncating SUBPIECE");
        assert_eq!(data.op(subpiece).opcode, op::SUBPIECE);
        let truncation = data.op(subpiece).inputs[1];
        assert!(data.varnode(truncation).flags.constant);
        assert_eq!(data.varnode(truncation).offset, 0);
    }

    /// Ghidra's `RuleEarlyRemoval` drops only unread, non-call outputs whose
    /// storage its liveness guards admit.
    ///
    /// The space test is the whole dead-removal gate here: `deadRemovalAllowed`
    /// is `pass > deadcodedelay` (`heritage.cc:2829-2834`) and this graph has no
    /// multi-pass heritage to delay. An earlier version also demanded
    /// `processing_complete`, which made the rule unreachable rather than
    /// cautious - `ActionStop` sets that flag last (`coreaction.cc:5795`) and
    /// this rule runs in `actprop` (`5563`).
    #[test]
    fn early_removal_drops_an_unread_private_temporary() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x3000);
        let input = data.new_varnode(REGISTER_SPACE, 0, 4);
        let one = data.new_constant(1, 4);
        let operation = data.new_op(op::INT_ADD, seq(0x3000), vec![input, one]);
        let output = data.new_unique(4);
        data.op_set_output(operation, Some(output));
        data.op_insert_end(operation, block);

        // Nothing reads the unique output, and no liveness guard claims it.
        assert_eq!(RuleEarlyRemoval.apply_op(operation, &mut data), 1);
        assert!(data.opcode_of(operation).is_none());

        // A reader keeps it, which is `hasNoDescend` doing its job.
        let mut read = Funcdata::default();
        let block = read.new_block(0x3008);
        let input = read.new_varnode(REGISTER_SPACE, 0, 4);
        let one = read.new_constant(1, 4);
        let operation = read.new_op(op::INT_ADD, seq(0x3008), vec![input, one]);
        let output = read.new_unique(4);
        read.op_set_output(operation, Some(output));
        read.op_insert_end(operation, block);
        let consumer = read.new_op(op::INT_ADD, seq(0x300c), vec![output, one]);
        let consumed = read.new_unique(4);
        read.op_set_output(consumer, Some(consumed));
        read.op_insert_end(consumer, block);
        assert_eq!(RuleEarlyRemoval.apply_op(operation, &mut read), 0);

        let mut tied = Funcdata::default();
        let block = tied.new_block(0x3010);
        let input = tied.new_varnode(REGISTER_SPACE, 0, 4);
        let one = tied.new_constant(1, 4);
        let operation = tied.new_op(op::INT_ADD, seq(0x3010), vec![input, one]);
        let output = tied.new_varnode(REGISTER_SPACE, 0x20, 4);
        tied.op_set_output(operation, Some(output));
        tied.op_insert_end(operation, block);
        assert_eq!(RuleEarlyRemoval.apply_op(operation, &mut tied), 0);

        let mut indirect = Funcdata::default();
        let block = indirect.new_block(0x3020);
        let input = indirect.new_varnode(REGISTER_SPACE, 0, 4);
        let one = indirect.new_constant(1, 4);
        let operation = indirect.new_op(op::INT_ADD, seq(0x3020), vec![input, one]);
        let output = indirect.new_unique(4);
        indirect.op_set_output(operation, Some(output));
        indirect.op_insert_end(operation, block);
        let marker_input = indirect.new_varnode(REGISTER_SPACE, 0x20, 4);
        let annotation = indirect.new_iop(operation);
        let marker = indirect.new_op(op::INDIRECT, seq(0x3024), vec![marker_input, annotation]);
        indirect.op_insert_end(marker, block);
        indirect.processing_complete = true;
        assert_eq!(RuleEarlyRemoval.apply_op(operation, &mut indirect), 0);
    }
}

/// Every non-cleanup requested rule with a faithful graph implementation.
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![Box::new(RuleEarlyRemoval)]
}
