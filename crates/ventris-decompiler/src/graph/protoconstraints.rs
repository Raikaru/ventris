//! Prototype constraint actions and the PIECE pathology rule.
//!
//! The source authority is Ghidra 12.1.3 at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`: `ActionUnjustifiedParams`,
//! `ActionPrototypeWarnings`, `ActionExtraPopSetup`, and
//! `ActionInternalStorage` in `coreaction.cc`, plus `RulePiecePathology` in
//! `ruleaction.cc`.  The action groups and registration positions are kept
//! beside each implementation so the graph pipeline can preserve Ghidra's
//! phase boundaries.
//!
//! A graph owns at most one function prototype.  The action implementations
//! therefore clone that prototype through `Funcdata::func_proto`, delegate to
//! the public `apply_with` operation, and write it back when the operation can
//! update it.  This avoids holding a prototype borrow while mutating the graph
//! and leaves the standalone operations usable with a directly constructed
//! `FuncProto`.

use std::collections::BTreeSet;

use ventris_pcode::op;

use super::action::{Action, Rule};
use super::funcproto::{EXTRAPOP_UNKNOWN, FuncProto};
use super::guard::Location;
use super::{Funcdata, OpId, SeqNum, VarnodeId};

/// Action group names and registration positions from Ghidra's action database.
pub const ACTION_UNJUSTIFIED_GROUP: &str = "protorecovery";
pub const ACTION_WARNINGS_GROUP: &str = "protorecovery";
pub const ACTION_EXTRA_POP_GROUP: &str = "base";
pub const ACTION_INTERNAL_STORAGE_GROUP: &str = "base";
pub const RULE_PIECE_PATHOLOGY_GROUP: &str = "protorecovery";

/// A function input range that Ghidra would widen to a justified parameter
/// container.  The graph operation is deliberately kept private: callers use
/// [`ActionUnjustifiedParams::apply_with`] so the prototype and graph stay in
/// one operation.
fn input_location(data: &Funcdata, id: VarnodeId) -> Location {
    let value = data.varnode(id);
    Location {
        space: value.space,
        offset: value.offset,
        size: value.size,
    }
}

fn end_offset(location: Location) -> u64 {
    location.offset.saturating_add(u64::from(location.size))
}

fn input_ids(data: &Funcdata) -> Vec<VarnodeId> {
    (0..data.varnode_count())
        .map(|index| VarnodeId(index as u32))
        .filter(|id| {
            let value = data.varnode(*id);
            value.flags.input && value.def.is_none() && !value.descendants.is_empty()
        })
        .collect()
}

fn justified_piece_offset(container: Location, piece: Location, big_endian: bool) -> Option<u64> {
    if container.space != piece.space
        || piece.size == 0
        || container.size < piece.size
        || piece.offset < container.offset
        || end_offset(piece) > end_offset(container)
    {
        return None;
    }
    let offset = if big_endian {
        end_offset(container).checked_sub(end_offset(piece))?
    } else {
        piece.offset.checked_sub(container.offset)?
    };
    Some(offset)
}

/// Replace the current input pieces with one input covering `container`.
///
/// This is the graph equivalent of `Funcdata::adjustInputVarnodes`.  Ghidra
/// creates each SUBPIECE before wiring its input so `totalReplace` does not
/// redirect the new operation into a self-reference; the same ordering is
/// important here.
fn adjust_input_range(data: &mut Funcdata, container: Location, big_endian: bool) -> bool {
    let Some((entry, _)) = data.blocks().next() else {
        return false;
    };

    let old_inputs: Vec<VarnodeId> = input_ids(data)
        .into_iter()
        .filter(|id| {
            let piece = input_location(data, *id);
            piece.space == container.space
                && piece.offset >= container.offset
                && end_offset(piece) <= end_offset(container)
                && piece.size < container.size
        })
        .collect();

    if old_inputs.is_empty() {
        return false;
    }

    let seq = SeqNum {
        address: data.entry,
        order: 0,
    };
    let mut rewrites = Vec::with_capacity(old_inputs.len());
    for old in old_inputs.iter().copied() {
        let piece = input_location(data, old);
        let Some(offset) = justified_piece_offset(container, piece, big_endian) else {
            continue;
        };
        let sub = data.new_op(op::SUBPIECE, seq, Vec::new());
        let output = data.new_varnode(piece.space, piece.offset, piece.size);
        data.op_set_output(sub, Some(output));
        data.op_insert_front(sub, entry);
        data.total_replace(old, output);
        rewrites.push((sub, offset));
    }
    if rewrites.is_empty() {
        return false;
    }

    let replacement = data.new_varnode(container.space, container.offset, container.size);
    data.mark_input(replacement);
    for (sub, offset) in rewrites {
        let constant = data.new_constant(offset, 4);
        data.op_set_input(sub, replacement, 0);
        data.op_set_input(sub, constant, 1);
    }
    true
}

/// Widen input varnodes that occupy an unjustified part of a locked parameter.
///
/// This ports `ActionUnjustifiedParams::apply` and its call to
/// `Funcdata::adjustInputVarnodes`.  The returned count is the number of input
/// ranges actually replaced, matching Ghidra's action count.
pub struct ActionUnjustifiedParams;

impl ActionUnjustifiedParams {
    /// Apply the pass to an explicitly supplied prototype.
    pub fn apply_with(data: &mut Funcdata, proto: &mut FuncProto) -> usize {
        let mut changed = 0;
        let candidates = input_ids(data);
        for candidate in candidates {
            if candidate.0 as usize >= data.varnode_count() {
                continue;
            }
            let current = input_location(data, candidate);
            let Some(mut container) = proto.unjustified_input_param(current) else {
                continue;
            };

            // `beginDef(input)` is address ordered in Ghidra.  The graph arena
            // is creation ordered, so sort the equivalent input locations
            // before extending a container to the left.
            loop {
                let old_container = container;
                let mut extended = false;
                let mut inputs = input_ids(data);
                inputs.sort_by_key(|id| {
                    let value = data.varnode(*id);
                    (value.space, value.offset, value.size)
                });
                for id in inputs {
                    let piece = input_location(data, id);
                    if piece.space != container.space
                        || piece.offset >= container.offset
                        || end_offset(piece) < container.offset
                    {
                        continue;
                    }
                    let endpoint = end_offset(container);
                    container.offset = piece.offset;
                    container.size = endpoint
                        .saturating_sub(container.offset)
                        .min(u64::from(u32::MAX)) as u32;
                    extended = true;
                }
                if !extended {
                    break;
                }
                let Some(next) = proto.unjustified_input_param(container) else {
                    break;
                };
                container = next;
                if container == old_container {
                    break;
                }
            }

            if adjust_input_range(data, container, proto.is_big_endian()) {
                changed += 1;
            }
        }
        changed
    }
}

impl Action for ActionUnjustifiedParams {
    fn name(&self) -> &'static str {
        "unjustparams"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let Some(mut proto) = data.func_proto().cloned() else {
            return 0;
        };
        let changed = Self::apply_with(data, &mut proto);
        if changed != 0 {
            data.set_func_proto(proto);
        }
        changed
    }
}

/// Emit all diagnostics owned by the current prototype.
///
/// Ghidra registers this once in the `protorecovery` group near the end of the
/// main action sequence.  `FuncProto::emit_warnings` is the complete warning
/// body; this wrapper only supplies the Action interface and graph-owned
/// prototype lookup.
pub struct ActionPrototypeWarnings;

impl ActionPrototypeWarnings {
    /// Emit warnings for an explicitly supplied prototype.
    pub fn apply_with(data: &mut Funcdata, proto: &mut FuncProto) -> usize {
        proto.emit_warnings(data)
    }
}

impl Action for ActionPrototypeWarnings {
    fn name(&self) -> &'static str {
        "prototypewarnings"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let Some(mut proto) = data.func_proto().cloned() else {
            return 0;
        };
        Self::apply_with(data, &mut proto)
    }
}

/// One callsite and its already recovered callee prototype.
///
/// Ghidra's `ActionExtraPopSetup` reads `FuncCallSpecs::getExtraPop` for each
/// call.  The graph has no call-spec arena, so this explicit record is the
/// standalone bridge for callers that do have that metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtraPopCall {
    pub op: OpId,
    pub proto: FuncProto,
}

fn stack_adjustment_exists(data: &Funcdata, call: OpId, stack: Location, pop: i32) -> bool {
    let seq = data.op(call).seq;
    data.live_ops().any(|(_, candidate)| {
        candidate.seq == seq
            && candidate.opcode == op::INT_ADD
            && candidate
                .output
                .is_some_and(|output| input_location(data, output) == stack)
            && candidate.inputs.len() == 2
            && input_location(data, candidate.inputs[0]) == stack
            && data.varnode(candidate.inputs[1]).flags.constant
            && data.varnode(candidate.inputs[1]).offset
                == (pop as i64 as u64 & mask_for_size(stack.size))
    })
}

fn mask_for_size(size: u32) -> u64 {
    let bits = size.saturating_mul(8);
    if bits == 0 {
        0
    } else if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn insert_known_stack_adjustment(
    data: &mut Funcdata,
    call: OpId,
    stack: Location,
    pop: i32,
) -> bool {
    if pop == 0 || data.op(call).parent.is_none() || stack_adjustment_exists(data, call, stack, pop)
    {
        return false;
    }
    let seq = data.op(call).seq;
    let before = data.new_varnode(stack.space, stack.offset, stack.size);
    let constant = data.new_constant(pop as i64 as u64 & mask_for_size(stack.size), stack.size);
    let adjustment = data.new_op(op::INT_ADD, seq, vec![before, constant]);
    let after = data.new_varnode(stack.space, stack.offset, stack.size);
    data.op_set_output(adjustment, Some(after));
    data.op_insert_after(adjustment, call);
    true
}

/// Set up stack-pointer adjustment operations for explicit call prototypes.
///
/// The known-extra-pop branch is a direct port of the `INT_ADD` half of
/// `ActionExtraPopSetup::apply`.  Unknown extra-pop values would require an
/// IOP-space varnode and an `INDIRECT` creation; that metadata is not present
/// in the graph and is intentionally declined rather than approximated.
pub fn apply_extra_pop_calls(
    data: &mut Funcdata,
    stack: Location,
    calls: &[ExtraPopCall],
) -> usize {
    let mut changed = 0;
    for call in calls {
        if data.opcode_of(call.op).is_none() {
            continue;
        }
        let pop = call.proto.get_extra_pop();
        if pop == EXTRAPOP_UNKNOWN {
            continue;
        }
        if insert_known_stack_adjustment(data, call.op, stack, pop) {
            changed += 1;
        }
    }
    changed
}

/// The standalone bridge for `ActionExtraPopSetup` when the caller has the
/// per-call prototype records that Ghidra's `Funcdata` supplies.
pub struct ActionExtraPopSetup;

impl ActionExtraPopSetup {
    /// Apply the known-extra-pop branch to explicit callsite metadata.
    pub fn apply_with(data: &mut Funcdata, stack: Location, calls: &[ExtraPopCall]) -> usize {
        apply_extra_pop_calls(data, stack, calls)
    }
}

fn eventual_constant(data: &Funcdata, value: VarnodeId, max_binary: u8, mut max_load: u8) -> bool {
    let mut current = value;
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(current) {
            return false;
        }
        let node = data.varnode(current);
        if node.flags.constant {
            return true;
        }
        let Some(def) = node.def else {
            return false;
        };
        let operation = data.op(def);
        match operation.opcode {
            op::LOAD => {
                if max_load == 0 {
                    return false;
                }
                max_load -= 1;
                let Some(input) = operation.inputs.get(1).copied() else {
                    return false;
                };
                current = input;
            }
            op::INT_ADD | op::INT_SUB | op::INT_XOR | op::INT_OR | op::INT_AND => {
                if max_binary == 0 || operation.inputs.len() < 2 {
                    return false;
                }
                if !eventual_constant(data, operation.inputs[0], max_binary - 1, max_load) {
                    return false;
                }
                return eventual_constant(data, operation.inputs[1], max_binary - 1, max_load);
            }
            op::INT_ZEXT | op::INT_SEXT | op::COPY => {
                let Some(input) = operation.inputs.first().copied() else {
                    return false;
                };
                current = input;
            }
            op::INT_LEFT | op::INT_RIGHT | op::INT_SRIGHT | op::INT_MULT => {
                if operation.inputs.len() < 2 || !data.varnode(operation.inputs[1]).flags.constant {
                    return false;
                }
                current = operation.inputs[0];
            }
            _ => return false,
        }
    }
}

fn storage_store_candidates(data: &Funcdata, proto: &FuncProto) -> Vec<OpId> {
    let mut result = BTreeSet::new();
    for storage in proto.internal_storage() {
        for index in 0..data.varnode_count() {
            let value = VarnodeId(index as u32);
            let node = data.varnode(value);
            if node.space != storage.space
                || node.offset != storage.offset
                || node.size != storage.size
            {
                continue;
            }
            if !eventual_constant(data, value, 3, 0) {
                continue;
            }
            for descendant in node.descendants.iter().copied() {
                if data.opcode_of(descendant) == Some(op::STORE) {
                    result.insert(descendant);
                }
            }
        }
    }
    result.into_iter().collect()
}

/// Identify stores that Ghidra would mark as unmapped for internal compiler
/// constants.  The candidate list is useful to callers with an extended graph
/// carrying `storeUnmapped`; the current graph intentionally has no such flag,
/// so the operation declines the mutation while preserving the exact
/// precondition and candidate census.
pub struct ActionInternalStorage;

impl ActionInternalStorage {
    /// Return the stores selected by the `isEventualConstant(3,0)` guard.
    pub fn candidates(data: &Funcdata, proto: &FuncProto) -> Vec<OpId> {
        storage_store_candidates(data, proto)
    }

    /// Apply the representable portion of the pass.
    ///
    /// There is no `GraphOp::store_unmapped` bit to mutate, so a non-empty
    /// candidate list is deliberately reported as unchanged.  This method is
    /// still conditional on the prototype ranges and graph data, and never
    /// pretends that a STORE was marked.
    pub fn apply_with(data: &mut Funcdata, proto: &mut FuncProto) -> usize {
        let _candidates = storage_store_candidates(data, proto);
        0
    }
}

fn pathology_source(data: &Funcdata, root: VarnodeId) -> bool {
    let mut values = vec![root];
    let mut seen_values = BTreeSet::new();
    while let Some(value) = values.pop() {
        if !seen_values.insert(value) {
            continue;
        }
        let node = data.varnode(value);
        if node.flags.input {
            return true;
        }
        let Some(def) = node.def else {
            continue;
        };
        let operation = data.op(def);
        match operation.opcode {
            op::COPY => {
                if let Some(input) = operation.inputs.first().copied() {
                    values.push(input);
                }
            }
            op::MULTIEQUAL => values.extend(operation.inputs.iter().copied()),
            // The Ghidra branch needs an IOP-space operand naming a call and
            // the callee's output-active state.  Graph INDIRECTs use a plain
            // address constant and have neither fact, so declining is the
            // sound equivalent.
            op::INDIRECT | op::CALL | op::CALLIND => {}
            _ => {}
        }
    }
    false
}

fn trace_pathology_forward(
    data: &mut Funcdata,
    piece: OpId,
    proto: &mut FuncProto,
    consumed_size: u32,
) -> usize {
    if data.op(piece).output.is_none() {
        return 0;
    }
    let mut worklist = vec![piece];
    let mut seen = BTreeSet::new();
    let mut changed = 0;
    while let Some(current) = worklist.pop() {
        if !seen.insert(current) {
            continue;
        }
        let Some(out) = data.op(current).output else {
            continue;
        };
        let descendants: Vec<OpId> = data.varnode(out).descendants.iter().copied().collect();
        for descendant in descendants {
            let Some(operation) = data.opcode_of(descendant) else {
                continue;
            };
            match operation {
                op::COPY | op::INDIRECT | op::MULTIEQUAL => worklist.push(descendant),
                op::RETURN if !proto.is_output_locked() => {
                    if proto.set_return_bytes_consumed(consumed_size) {
                        changed += 1;
                    }
                }
                op::CALL | op::CALLIND => {
                    // Per-call input-active/locked state is absent from this
                    // graph. Do not guess a callee byte-consumption update.
                }
                _ => {}
            }
        }
    }
    changed
}

/// Search PIECE concatenations whose high part is a non-zero SUBPIECE of an
/// input and propagate the partial-consumption fact to RETURN operations.
pub struct RulePiecePathology;

impl RulePiecePathology {
    /// Apply the rule to an explicitly supplied prototype.
    pub fn apply_with(data: &mut Funcdata, id: OpId, proto: &mut FuncProto) -> usize {
        if data.opcode_of(id) != Some(op::PIECE) {
            return 0;
        }
        let Some(high) = data.op(id).inputs.first().copied() else {
            return 0;
        };
        if !data.varnode(high).flags.written {
            return 0;
        }
        let Some(def) = data.varnode(high).def else {
            return 0;
        };
        let operation = data.op(def);
        if operation.opcode != op::SUBPIECE || operation.inputs.len() < 2 {
            // The INDIRECT-creation branch needs Ghidra's isIndirectCreation
            // flag and contiguous address-space metadata, neither of which
            // GraphOp stores.
            return 0;
        }
        let offset = operation.inputs[1];
        if !data.varnode(offset).flags.constant || data.varnode(offset).offset == 0 {
            return 0;
        }
        let Some(source) = operation.inputs.first().copied() else {
            return 0;
        };
        if !pathology_source(data, source) {
            return 0;
        }
        let consumed_size = data
            .op(id)
            .inputs
            .get(1)
            .map(|value| data.varnode(*value).size)
            .unwrap_or(0);
        if consumed_size == 0 {
            return 0;
        }
        trace_pathology_forward(data, id, proto, consumed_size)
    }
}
impl Rule for RulePiecePathology {
    fn name(&self) -> &'static str {
        "piecepathology"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::PIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(mut proto) = data.func_proto().cloned() else {
            return 0;
        };
        let changed = Self::apply_with(data, id, &mut proto);
        if changed != 0 {
            data.set_func_proto(proto);
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{CONST_SPACE, REGISTER_SPACE};
    use ventris_target::TargetProfile;

    fn location(space: u32, offset: u64, size: u32) -> Location {
        Location {
            space,
            offset,
            size,
        }
    }

    fn prototype() -> FuncProto {
        FuncProto::with_storage(
            TargetProfile::Ps2.spec().abi,
            vec![location(REGISTER_SPACE, 0x20, 8)],
            vec![location(REGISTER_SPACE, 0x40, 8)],
        )
    }

    fn block_data() -> (Funcdata, super::super::GraphBlockId) {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(data.entry);
        (data, block)
    }

    #[test]
    fn unjustified_params_widen_input_and_build_subpiece() {
        let (mut data, block) = block_data();
        let input = data.new_varnode(REGISTER_SPACE, 0x24, 4);
        data.mark_input(input);
        let use_op = data.new_op(
            op::COPY,
            SeqNum {
                address: 0x1000,
                order: 0,
            },
            vec![input],
        );
        data.op_insert_end(use_op, block);

        let mut proto = prototype();
        proto.set_input_lock(true);
        proto.set_param_parts(
            0,
            "wide",
            location(REGISTER_SPACE, 0x20, 8),
            crate::native::Type::Unsigned(64),
        );
        proto.get_param_mut(0).unwrap().set_type_lock(true);

        assert_eq!(
            ActionUnjustifiedParams::apply_with(&mut data, &mut proto),
            1
        );
        assert_ne!(data.op(use_op).inputs[0], input);
        assert!(
            data.live_ops()
                .any(|(_, operation)| operation.opcode == op::SUBPIECE)
        );
        assert!(
            data.live_ops()
                .any(|(_, operation)| operation.opcode == op::COPY)
        );
    }

    #[test]
    fn prototype_warnings_reach_funcdata_sink_exactly() {
        let (mut data, _) = block_data();
        let mut proto = prototype();
        proto.set_input_errors(true);
        assert_eq!(
            ActionPrototypeWarnings::apply_with(&mut data, &mut proto),
            1
        );
        assert_eq!(
            data.warnings(),
            &["Cannot assign parameter locations for this function: Prototype may be inaccurate"]
        );
        assert_eq!(
            ActionPrototypeWarnings::apply_with(&mut data, &mut proto),
            0
        );
    }

    #[test]
    fn extra_pop_known_call_inserts_stack_adjustment() {
        let (mut data, block) = block_data();
        let target = data.new_constant(0x2000, 4);
        let call = data.new_op(
            op::CALL,
            SeqNum {
                address: 0x1010,
                order: 0,
            },
            vec![target],
        );
        data.op_insert_end(call, block);
        let stack = location(REGISTER_SPACE, 0x80, 4);
        let mut callee = prototype();
        callee.set_extra_pop(8);
        assert_eq!(
            ActionExtraPopSetup::apply_with(
                &mut data,
                stack,
                &[ExtraPopCall {
                    op: call,
                    proto: callee
                }]
            ),
            1
        );
        assert!(data.live_ops().any(|(_, operation)| {
            operation.opcode == op::INT_ADD
                && operation
                    .output
                    .is_some_and(|output| input_location(&data, output) == stack)
        }));
    }

    #[test]
    fn internal_storage_reports_eventual_constant_store_candidate_without_faking_flag() {
        let (mut data, block) = block_data();
        let address = data.new_constant(0x5000, 4);
        let value = data.new_constant(7, 4);
        let store = data.new_op(
            op::STORE,
            SeqNum {
                address: 0x1020,
                order: 0,
            },
            vec![address, address, value],
        );
        data.op_insert_end(store, block);
        let mut proto = prototype();
        proto.set_internal_storage(vec![location(CONST_SPACE, 0x5000, 4)]);
        assert_eq!(
            ActionInternalStorage::candidates(&data, &proto),
            vec![store]
        );
        assert_eq!(ActionInternalStorage::apply_with(&mut data, &mut proto), 0);
    }

    #[test]
    fn piece_pathology_sets_return_consumed_bytes() {
        let (mut data, block) = block_data();
        let source = data.new_varnode(REGISTER_SPACE, 0x20, 8);
        data.mark_input(source);
        let offset = data.new_constant(4, 4);
        let sub = data.new_op(
            op::SUBPIECE,
            SeqNum {
                address: 0x1030,
                order: 0,
            },
            vec![source, offset],
        );
        let sub_out = data.new_unique(4);
        data.op_set_output(sub, Some(sub_out));
        data.op_insert_end(sub, block);
        let low = data.new_constant(1, 4);
        let piece = data.new_op(
            op::PIECE,
            SeqNum {
                address: 0x1034,
                order: 0,
            },
            vec![sub_out, low],
        );
        let piece_out = data.new_unique(8);
        data.op_set_output(piece, Some(piece_out));
        data.op_insert_end(piece, block);
        let target = data.new_constant(0, 4);
        let ret = data.new_op(
            op::RETURN,
            SeqNum {
                address: 0x1038,
                order: 0,
            },
            vec![target, piece_out],
        );
        data.op_insert_end(ret, block);

        let mut proto = prototype();
        assert_eq!(
            RulePiecePathology::apply_with(&mut data, piece, &mut proto),
            1
        );
        assert_eq!(proto.get_return_bytes_consumed(), 4);
        assert_eq!(RulePiecePathology.op_list(), vec![op::PIECE]);
    }
}
