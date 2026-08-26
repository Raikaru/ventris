//! Scope-backed actions and cleanup rules from Ghidra 12.1.3.
//!
//! Source authority:
//! * [`ActionRestructureVarnode`] and [`ActionMappedLocalSync`] are the
//!   `coreaction.cc` actions at lines 2315-2350.  Both belong to Ghidra's
//!   `localrecovery` group: `restructure_varnode` is registered at the
//!   main-loop position immediately after `dynamic` (coreaction.cc 5555-5557),
//!   and `mapped_local_sync` is registered after the full loop and before
//!   cleanup (coreaction.cc 5741-5743).
//! * [`RulePtrsubCharConstant`] is `ruleaction.cc` 7360-7421, in the
//!   `cleanup` pool immediately after `RuleExpandLoad` (coreaction.cc
//!   5753-5755).
//! * [`RuleStringCopy`] is `constseq.cc` 948-971, in the `constsequence`
//!   group after the cleanup pool's split-store rules (coreaction.cc
//!   5759-5761).
//!
//! `ScopeLocal` is intentionally passed in by the caller.  The graph pipeline
//! currently does not populate `Funcdata::scope_local`; the action wrappers
//! therefore return zero for a graph with no local scope.  The `apply_with`
//! entry points are the load-bearing surfaces used by tests and by the future
//! scope-population pass.
//!
//! Two graph boundaries require a conservative Rust adaptation:
//!
//! * Ghidra's `syncVarnodesWithSymbols` writes `mapped`, `addrtied`,
//!   `nolocalalias`, and datatype bits directly on Varnodes.  The graph has no
//!   such fields.  `ActionRestructureVarnode` still performs the scope
//!   restructuring and runs a fresh, local [`AliasChecker`] over every
//!   unmapped candidate, but does not smuggle an alias verdict into an
//!   unrelated Varnode flag.
//! * Ghidra's `StringSequence` builds an internal string and a target-specific
//!   `memcpy` user-op.  Ventris has no internal-string manager or builtin-userop
//!   registry.  [`RuleStringCopy`] instead packs a proved contiguous character
//!   run into one wide constant `COPY` and materializes `SUBPIECE`s for the
//!   original byte results.  This is graph-semantic equivalent, bounded by the
//!   graph's `u64` constants, and does not invent an unknown `CALLOTHER` id.

use ventris_pcode::op;

use super::action::{Action, Rule};
use super::alias::AliasChecker;
use super::scope::{Location, ScopeLocal, UsePoint};
use super::typefactory::DataType;
use super::{Funcdata, OpId, VarnodeId};

const MIN_STRING_SEQUENCE: usize = 4;
const MAX_PACKED_STRING_BYTES: usize = 8;

fn is_constant(data: &Funcdata, value: VarnodeId) -> bool {
    data.varnode(value).flags.constant || data.varnode(value).space == ventris_lifter::CONST_SPACE
}

fn constant_value(data: &Funcdata, value: VarnodeId) -> Option<u64> {
    is_constant(data, value).then_some(data.varnode(value).offset)
}

fn byte_width(ty: &DataType) -> u32 {
    match ty {
        DataType::Unknown(bits) | DataType::Int { bits, .. } | DataType::Float(bits) => {
            bits.saturating_add(7) / 8
        }
        DataType::Bool => 1,
        DataType::Void | DataType::Spacebase => 0,
        DataType::Pointer { bits, .. } | DataType::PointerRel { bits, .. } => {
            bits.saturating_add(7) / 8
        }
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

fn is_character(ty: &DataType) -> bool {
    matches!(ty, DataType::Int { bits: 8, .. })
}

/// Whether `ty` contains an eight-bit character at `offset`.
///
/// The returned width is the character width.  Keeping this query in this
/// module avoids treating every read-only integer as a string element: the
/// symbol must actually describe an array (possibly nested in a struct).
fn character_at(ty: &DataType, offset: u32) -> Option<u32> {
    match ty {
        DataType::Int { bits: 8, .. } if offset == 0 => Some(1),
        DataType::Array { element, count } => {
            let stride = byte_width(element);
            if stride == 0
                || (*count != 0 && u64::from(offset) >= u64::from(stride) * *count as u64)
            {
                return None;
            }
            character_at(element, offset % stride)
        }
        DataType::Struct { fields, .. } => fields.iter().find_map(|field| {
            let width = byte_width(&field.ty);
            (offset >= field.offset && offset - field.offset < width)
                .then(|| character_at(&field.ty, offset - field.offset))
                .flatten()
        }),
        _ => None,
    }
}

fn output_location(data: &Funcdata, value: VarnodeId) -> Location {
    let varnode = data.varnode(value);
    Location {
        space: varnode.space,
        offset: varnode.offset,
        size: varnode.size,
    }
}

/// Ghidra's `ActionRestructureVarnode`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ActionRestructureVarnode;

impl ActionRestructureVarnode {
    /// Apply restructuring against an explicitly supplied local scope.
    ///
    /// `aliasyes` is the same first/second-pass switch as Ghidra.  The graph
    /// has no `nolocalalias` Varnode bit, so the alias result is deliberately
    /// consumed only as the guard for the scope's alias-sensitive mode; the
    /// checker is local to this invocation and is dropped before returning.
    pub fn apply_with(data: &mut Funcdata, scope: &mut ScopeLocal, aliasyes: bool) -> usize {
        let locations: Vec<Location> = (0..data.varnode_count())
            .map(|index| output_location(data, VarnodeId(index as u32)))
            .filter(|location| location.space == scope.space())
            .filter(|location| scope.is_unmapped_unaliased(*location))
            .collect();

        let mut checker = AliasChecker::default();
        checker.gather(data, scope.space(), false);
        let has_unaliased = locations
            .iter()
            .any(|location| scope.is_unmapped_unaliased_with_alias(data, *location, &mut checker));

        // `ScopeLocal::restructure_varnode` owns the structural overlap bit.
        // Passing false when no candidate survived the alias guard preserves
        // Ghidra's "alias marking is optional" behavior without claiming that
        // this reduced graph can attach a nolocalalias property.
        usize::from(scope.restructure_varnode(aliasyes && has_unaliased))
    }
}

impl Action for ActionRestructureVarnode {
    fn name(&self) -> &'static str {
        "restructure_varnode"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let Some(mut scope) = data.scope_local().cloned() else {
            return 0;
        };
        let changes = Self::apply_with(data, &mut scope, true);
        data.set_scope_local(scope);
        changes
    }
}

/// Ghidra's `ActionMappedLocalSync`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ActionMappedLocalSync;

impl ActionMappedLocalSync {
    /// Synchronize explicit `INDIRECT` effects with a supplied local scope.
    ///
    /// `INDIRECT` is the graph's explicit representation of a call/store that
    /// may overwrite a location.  Such a location cannot safely retain a
    /// mapped local symbol, so it is passed through `mark_not_mapped`.  A
    /// parameter-range overlap is passed as `parameter=true`, matching
    /// Ghidra's special treatment of stack argument storage.
    pub fn apply_with(data: &mut Funcdata, scope: &mut ScopeLocal) -> usize {
        let locations: Vec<Location> = data
            .live_ops()
            .filter(|(_, operation)| operation.opcode == op::INDIRECT)
            .filter_map(|(_, operation)| operation.output)
            .map(|value| output_location(data, value))
            .filter(|location| location.space == scope.space())
            .collect();

        let mut changes = 0;
        for location in locations {
            let was_mapped = scope.is_mapped(location);
            let had_overlap = scope.find_overlap(location).is_some();
            let parameter = scope.is_parameter_location(location);
            scope.mark_not_mapped(location.space, location.offset, location.size, parameter);
            if was_mapped || had_overlap {
                changes += 1;
            }
        }

        if scope.has_overlap_problems()
            && data.warning("Could not reconcile some variable overlaps")
        {
            changes += 1;
        }
        changes
    }
}

impl Action for ActionMappedLocalSync {
    fn name(&self) -> &'static str {
        "mapped_local_sync"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let Some(mut scope) = data.scope_local().cloned() else {
            return 0;
        };
        let changes = Self::apply_with(data, &mut scope);
        data.set_scope_local(scope);
        changes
    }
}

/// Cleanup rule that turns a read-only spacebase character pointer into a
/// constant pointer.
#[derive(Clone, Copy, Debug, Default)]
pub struct RulePtrsubCharConstant;

impl RulePtrsubCharConstant {
    fn pointer_to_spacebase(ty: &DataType) -> bool {
        matches!(
            ty,
            DataType::Pointer { to, .. } if matches!(to.as_ref(), DataType::Spacebase)
        )
    }

    fn pointer_to_character(ty: &DataType) -> bool {
        matches!(
            ty,
            DataType::Pointer { to, .. } | DataType::PointerRel { to, .. }
                if is_character(to.as_ref())
        )
    }

    fn push_const_further(data: &mut Funcdata, operation: OpId, slot: usize, value: u64) -> bool {
        if data.op(operation).opcode != op::PTRADD || slot != 0 {
            return false;
        }
        let inputs = data.op(operation).inputs.clone();
        let (Some(index_id), Some(stride_id)) = (inputs.get(1), inputs.get(2)) else {
            return false;
        };
        let (Some(index), Some(stride)) = (
            constant_value(data, *index_id),
            constant_value(data, *stride_id),
        ) else {
            return false;
        };
        if data.op(operation).output.is_none() {
            return false;
        }
        let index_size = data.varnode(*index_id).size;
        let new_constant =
            data.new_constant(value.wrapping_add(index.wrapping_mul(stride)), index_size);
        data.op_set_inputs(operation, vec![new_constant]);
        data.op_set_opcode(operation, op::COPY);
        true
    }

    /// Apply to one `PTRSUB` using an explicitly supplied scope.
    pub fn apply_op_with(data: &mut Funcdata, scope: &ScopeLocal, id: OpId) -> usize {
        let Some(operation) = data
            .live_ops()
            .find_map(|(candidate, operation)| (candidate == id).then_some(operation.clone()))
        else {
            return 0;
        };
        if operation.opcode != op::PTRSUB || operation.inputs.len() < 2 {
            return 0;
        }
        let base = operation.inputs[0];
        let offset = operation.inputs[1];
        let Some(offset_value) = constant_value(data, offset) else {
            return 0;
        };
        let Some(output) = operation.output else {
            return 0;
        };

        let types = data.recovered_types();
        let Some(base_type) = types.1.get(base) else {
            return 0;
        };
        if !Self::pointer_to_spacebase(base_type) {
            return 0;
        }

        let point = UsePoint::from(operation.seq);
        let address = Location {
            space: scope.space(),
            offset: offset_value,
            size: 1,
        };
        if !scope.is_read_only(address, point) {
            return 0;
        }

        // Type recovery normally gives the output a character pointer.  A
        // spacebase PTRSUB can instead retain `PointerRel<Unknown>` because
        // the graph has no mutable TypeSpacebase map; the read-only symbol is
        // the remaining proof of character data in that reduced case.
        let output_is_character = types.1.get(output).is_some_and(Self::pointer_to_character)
            || scope
                .query_container(address, point)
                .and_then(|entry| scope.entry_symbol(entry.id()))
                .is_some_and(|symbol| character_at(symbol.ty(), 0).is_some());
        if !output_is_character {
            return 0;
        }

        let descendants: Vec<OpId> = data.varnode(output).descendants.iter().copied().collect();
        let mut remove_copy = !descendants.is_empty();
        for descendant in descendants {
            let slot = data
                .op(descendant)
                .inputs
                .iter()
                .position(|value| *value == output);
            let Some(slot) = slot else {
                remove_copy = false;
                continue;
            };
            if !Self::push_const_further(data, descendant, slot, offset_value) {
                remove_copy = false;
            }
        }

        if remove_copy {
            data.op_destroy(id);
        } else {
            let output_size = data.varnode(output).size;
            let new_constant = data.new_constant(offset_value, output_size);
            data.op_set_inputs(id, vec![new_constant]);
            data.op_set_opcode(id, op::COPY);
        }
        1
    }
}

impl Rule for RulePtrsubCharConstant {
    fn name(&self) -> &'static str {
        "ptrsubcharconstant"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::PTRSUB]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(scope) = data.scope_local().cloned() else {
            return 0;
        };
        Self::apply_op_with(data, &scope, id)
    }
}

/// Cleanup rule for a contiguous run of constant character `COPY`s.
#[derive(Clone, Copy, Debug, Default)]
pub struct RuleStringCopy;

impl RuleStringCopy {
    fn collect_sequence(
        data: &Funcdata,
        scope: &ScopeLocal,
        id: OpId,
    ) -> Option<Vec<(OpId, VarnodeId, u64)>> {
        let root = data.op(id);
        if root.opcode != op::COPY {
            return None;
        }
        let source = *root.inputs.first()?;
        let source_value = constant_value(data, source)?;
        if source_value > u8::MAX as u64 || source_value == 0 {
            return None;
        }
        let output = root.output?;
        let root_location = output_location(data, output);
        if root_location.space != scope.space() || root_location.size != 1 {
            return None;
        }
        let point = UsePoint::from(root.seq);
        let entry = scope.query_container(root_location, point)?;
        let symbol = scope.entry_symbol(entry.id())?;
        let relative = root_location.offset.checked_sub(entry.location()?.offset)?;
        if character_at(symbol.ty(), u32::try_from(relative).ok()?) != Some(1) {
            return None;
        }

        let block = root.parent?;
        let ordered = &data.block(block).ops;
        let start = ordered.iter().position(|candidate| *candidate == id)?;
        let mut expected = root_location.offset;
        let mut sequence = Vec::new();
        for candidate in ordered.iter().copied().skip(start) {
            let operation = data.op(candidate);
            if operation.dead || operation.opcode != op::COPY || operation.parent != Some(block) {
                break;
            }
            let Some(value) = operation.output else {
                break;
            };
            let location = output_location(data, value);
            if location.space != root_location.space
                || location.size != 1
                || location.offset != expected
            {
                break;
            }
            let Some(input) = operation.inputs.first().copied() else {
                break;
            };
            let Some(character) = constant_value(data, input) else {
                break;
            };
            if character > u8::MAX as u64 {
                break;
            }
            sequence.push((candidate, value, character));
            expected = expected.saturating_add(1);
            if sequence.len() == MAX_PACKED_STRING_BYTES {
                break;
            }
        }
        (sequence.len() >= MIN_STRING_SEQUENCE).then_some(sequence)
    }

    fn pack(sequence: &[(OpId, VarnodeId, u64)]) -> Option<u64> {
        let mut value = 0u64;
        for (index, (_, _, character)) in sequence.iter().enumerate() {
            value |= character << (index * 8);
        }
        Some(value)
    }

    /// Apply to one root `COPY` using an explicitly supplied scope.
    pub fn apply_op_with(data: &mut Funcdata, scope: &ScopeLocal, id: OpId) -> usize {
        let Some(sequence) = Self::collect_sequence(data, scope, id) else {
            return 0;
        };
        let Some(value) = Self::pack(&sequence) else {
            return 0;
        };
        let root = sequence[0].0;
        let root_output = sequence[0].1;
        let root_location = output_location(data, root_output);
        let total_size = sequence.len() as u32;
        let wide_output = data.new_varnode(root_location.space, root_location.offset, total_size);
        let packed = data.new_constant(value, total_size);
        let root_seq = data.op(root).seq;
        data.op_set_input(root, packed, 0);
        data.op_set_output(root, Some(wide_output));

        // Restore the original one-byte SSA result of the root COPY.
        let zero = data.new_constant(0, 4);
        let root_piece = data.new_op(op::SUBPIECE, root_seq, vec![wide_output, zero]);
        data.op_set_output(root_piece, Some(root_output));
        data.op_insert_after(root_piece, root);

        for (operation, output, _) in sequence.iter().skip(1).copied() {
            let offset = output_location(data, output)
                .offset
                .saturating_sub(root_location.offset);
            data.op_set_opcode(operation, op::SUBPIECE);
            let offset_constant = data.new_constant(offset, 4);
            data.op_set_inputs(operation, vec![wide_output, offset_constant]);
        }
        1
    }
}

impl Rule for RuleStringCopy {
    fn name(&self) -> &'static str {
        "stringcopy"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::COPY]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(scope) = data.scope_local().cloned() else {
            return 0;
        };
        Self::apply_op_with(data, &scope, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SeqNum;
    use crate::graph::scope::StorageRange;
    use crate::native::Type;
    use ventris_lifter::{RAM_SPACE, REGISTER_SPACE};

    fn seq(address: u64, order: u32) -> SeqNum {
        SeqNum { address, order }
    }

    fn local_scope(space: u32) -> ScopeLocal {
        ScopeLocal::new(space)
    }

    fn char_array(count: usize) -> DataType {
        DataType::Array {
            element: Box::new(DataType::Int {
                bits: 8,
                signed: false,
            }),
            count,
        }
    }

    #[test]
    fn restructure_marks_overlapping_populated_entries() {
        let mut data = Funcdata::default();
        let mut scope = local_scope(REGISTER_SPACE);
        let first = scope.scope_mut().add_symbol("first", Type::Unsigned(32));
        let second = scope.scope_mut().add_symbol("second", Type::Unsigned(32));
        let location = Location {
            space: REGISTER_SPACE,
            offset: 0x20,
            size: 4,
        };
        scope.scope_mut().add_map_point(first, location);
        scope.scope_mut().add_map_point(second, location);
        scope.mark_not_mapped(REGISTER_SPACE, 0x40, 4, false);
        data.new_varnode(REGISTER_SPACE, 0x40, 4);

        assert_eq!(
            ActionRestructureVarnode::apply_with(&mut data, &mut scope, true),
            1
        );
        assert!(scope.has_overlap_problems());
    }

    #[test]
    fn restructure_declines_when_populated_scope_is_already_consistent() {
        let mut data = Funcdata::default();
        let mut scope = local_scope(REGISTER_SPACE);
        let symbol = scope.scope_mut().add_symbol("value", Type::Unsigned(32));
        scope.scope_mut().add_map_point(
            symbol,
            Location {
                space: REGISTER_SPACE,
                offset: 0x20,
                size: 4,
            },
        );
        assert_eq!(
            ActionRestructureVarnode::apply_with(&mut data, &mut scope, true),
            0
        );
        assert!(!scope.has_overlap_problems());
    }

    #[test]
    fn mapped_local_sync_marks_indirect_storage_and_warns_on_locked_overlap() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let mut scope = local_scope(REGISTER_SPACE);
        let symbol = scope
            .scope_mut()
            .add_symbol("temporary", Type::Unsigned(32));
        let location = Location {
            space: REGISTER_SPACE,
            offset: 0x30,
            size: 4,
        };
        scope.scope_mut().add_map_point(symbol, location);
        let value = data.new_varnode(REGISTER_SPACE, location.offset, location.size);
        let cause = data.new_constant(0x1000, 4);
        let indirect = data.new_op(op::INDIRECT, seq(0x1000, 0), vec![value, cause]);
        data.op_set_output(indirect, Some(value));
        data.op_insert_end(indirect, block);

        let changes = ActionMappedLocalSync::apply_with(&mut data, &mut scope);
        assert_eq!(changes, 2);
        assert!(scope.is_unmapped(location));
        assert!(scope.scope().find_overlap(location).is_none());

        let mut locked_scope = local_scope(REGISTER_SPACE);
        let locked = locked_scope
            .scope_mut()
            .add_symbol("locked", Type::Unsigned(32));
        let sibling = locked_scope
            .scope_mut()
            .add_symbol("sibling", Type::Unsigned(32));
        locked_scope.scope_mut().add_map_point(locked, location);
        locked_scope.scope_mut().add_map_point(sibling, location);
        locked_scope
            .scope_mut()
            .symbol_mut(locked)
            .expect("locked symbol")
            .set_flag(super::super::scope::SymbolFlags::TYPE_LOCKED, true);
        assert!(locked_scope.restructure_varnode(true));
        let _ = ActionMappedLocalSync::apply_with(&mut data, &mut locked_scope);
        assert!(locked_scope.has_overlap_problems());
        assert_eq!(
            data.warnings(),
            &["Could not reconcile some variable overlaps"]
        );
    }

    #[test]
    fn mapped_local_sync_declines_without_indirect_storage() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let source = data.new_constant(1, 4);
        let output = data.new_varnode(REGISTER_SPACE, 0x30, 4);
        let copy = data.new_op(op::COPY, seq(0x1000, 0), vec![source]);
        data.op_set_output(copy, Some(output));
        data.op_insert_end(copy, block);
        let mut scope = local_scope(REGISTER_SPACE);
        let symbol = scope.scope_mut().add_symbol("value", Type::Unsigned(32));
        scope.scope_mut().add_map_point(
            symbol,
            Location {
                space: REGISTER_SPACE,
                offset: 0x30,
                size: 4,
            },
        );
        assert_eq!(ActionMappedLocalSync::apply_with(&mut data, &mut scope), 0);
        assert!(
            scope
                .scope()
                .find_overlap(output_location(&data, output))
                .is_some()
        );
    }

    fn ptrsub_graph() -> (Funcdata, ScopeLocal, OpId) {
        let mut data = Funcdata::default();
        let block = data.new_block(0x2000);
        let base_location = Location {
            space: REGISTER_SPACE,
            offset: 0x1d0,
            size: 4,
        };
        data.spacebase = Some(base_location);
        let base = data.new_varnode(
            base_location.space,
            base_location.offset,
            base_location.size,
        );
        let offset = data.new_constant(0x40, 4);
        let operation = data.new_op(op::PTRSUB, seq(0x2000, 0), vec![base, offset]);
        let output = data.new_unique(4);
        data.op_set_output(operation, Some(output));
        data.op_insert_end(operation, block);
        let mut scope = local_scope(RAM_SPACE);
        let symbol = scope.scope_mut().add_symbol("text", char_array(4));
        scope.scope_mut().add_map_point(
            symbol,
            Location {
                space: RAM_SPACE,
                offset: 0x40,
                size: 4,
            },
        );
        scope
            .scope_mut()
            .add_read_only_range(StorageRange::from_bounds(RAM_SPACE, 0x40, 0x43));
        (data, scope, operation)
    }

    #[test]
    fn ptrsub_char_constant_rewrites_read_only_spacebase_pointer() {
        let (mut data, scope, operation) = ptrsub_graph();
        assert_eq!(
            RulePtrsubCharConstant::apply_op_with(&mut data, &scope, operation),
            1
        );
        assert_eq!(data.op(operation).opcode, op::COPY);
        assert_eq!(data.op(operation).inputs.len(), 1);
        assert_eq!(data.varnode(data.op(operation).inputs[0]).offset, 0x40);
    }

    #[test]
    fn ptrsub_char_constant_declines_writable_spacebase_pointer() {
        let (mut data, _, operation) = ptrsub_graph();
        let scope = local_scope(RAM_SPACE);
        assert_eq!(
            RulePtrsubCharConstant::apply_op_with(&mut data, &scope, operation),
            0
        );
        assert_eq!(data.op(operation).opcode, op::PTRSUB);
    }

    fn string_graph(values: &[u64]) -> (Funcdata, ScopeLocal, OpId) {
        let mut data = Funcdata::default();
        let block = data.new_block(0x3000);
        let mut scope = local_scope(RAM_SPACE);
        let symbol = scope
            .scope_mut()
            .add_symbol("message", char_array(values.len()));
        scope.scope_mut().add_map_point(
            symbol,
            Location {
                space: RAM_SPACE,
                offset: 0x1000,
                size: values.len() as u32,
            },
        );
        let mut root = None;
        for (index, value) in values.iter().copied().enumerate() {
            let input = data.new_constant(value, 1);
            let output = data.new_varnode(RAM_SPACE, 0x1000 + index as u64, 1);
            let operation = data.new_op(op::COPY, seq(0x3000 + index as u64, 0), vec![input]);
            data.op_set_output(operation, Some(output));
            data.op_insert_end(operation, block);
            root.get_or_insert(operation);
        }
        (data, scope, root.expect("non-empty string"))
    }

    #[test]
    fn string_copy_packs_a_proved_character_run() {
        let (mut data, scope, root) =
            string_graph(&[b't' as u64, b'e' as u64, b's' as u64, b't' as u64]);
        assert_eq!(RuleStringCopy::apply_op_with(&mut data, &scope, root), 1);
        assert_eq!(data.op(root).opcode, op::COPY);
        assert_eq!(data.varnode(data.op(root).output.unwrap()).size, 4);
        let block = data.op(root).parent.unwrap();
        let subpieces = data
            .block(block)
            .ops
            .iter()
            .filter(|id| data.op(**id).opcode == op::SUBPIECE)
            .count();
        assert_eq!(subpieces, 4);
    }

    #[test]
    fn string_copy_declines_a_non_array_or_short_run() {
        let (mut data, scope, root) = string_graph(&[b'a' as u64, b'b' as u64, b'c' as u64]);
        assert_eq!(RuleStringCopy::apply_op_with(&mut data, &scope, root), 0);
        assert_eq!(data.op(root).opcode, op::COPY);
    }
}
