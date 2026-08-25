//! Stack-frame offsets and local-slot recovery, ported from Ghidra 12.1.3.
//!
//! The source authority is `ActionStackPtrFlow::apply`,
//! `ActionStackPtrFlow::analyzeExtraPop`, `ActionStackPtrFlow::repair`,
//! `ActionMapGlobals::apply`, `ActionRestrictLocal::apply`, and
//! `ActionMappedLocalSync::apply` in `coreaction.cc`; `ScopeLocal::restructureVarnode`,
//! `MapState`, `AliasChecker::gather`, `AliasChecker::hasLocalAlias`, and
//! `RangeHint` in `varmap.cc`; and `Funcdata::spacebaseConstant` in
//! `funcdata.cc` (the pinned tree's implementation of the requested
//! `funcdata_varnode.cc` helper family), all at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.
//!
//! The graph API deliberately has no `ScopeLocal`, `FuncCallSpecs`, symbol
//! table, or prototype/effect records.  This module therefore ports the
//! source-level facts that remain representable: additive spacebase recovery,
//! canonical `spacebase + constant` address expressions, access-width slot
//! collection, and the conservative escape bit used by `AliasChecker`.

use std::collections::{BTreeMap, BTreeSet};

use ventris_lifter::REGISTER_SPACE;
use ventris_pcode::op;

use super::action::Action;
use super::guard::Location;
use super::{Funcdata, OpId, VarnodeId};

/// One inferred stack-frame slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Slot {
    pub offset: i64,
    pub size: u32,
    pub aliased: bool,
}

/// Inferred stack-frame accesses and conservative alias information.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Frame {
    slots: Vec<Slot>,
    escaped: bool,
}

impl Frame {
    /// Recover frame slots from LOAD/STORE accesses relative to `stack_pointer`.
    ///
    /// `MapState::gatherVarnodes` records the width of each actual access, not
    /// merely the address expression's pointer width.  Keep `(offset, size)` as
    /// the key for the same reason: a byte lane and a word at one offset are
    /// distinct observations until the type/symbol pass reconciles them.
    pub fn of(data: &Funcdata, stack_pointer: Location) -> Self {
        let mut found: BTreeMap<(i64, u32), ()> = BTreeMap::new();
        for (_, operation) in data.live_ops() {
            match operation.opcode {
                op::LOAD => {
                    let Some(address) = operation.inputs.get(1).copied() else {
                        continue;
                    };
                    let Some(offset) = frame_offset(data, address, stack_pointer) else {
                        continue;
                    };
                    let Some(output) = operation.output else {
                        continue;
                    };
                    found.insert((offset, data.varnode(output).size), ());
                }
                op::STORE => {
                    let Some(address) = operation.inputs.get(1).copied() else {
                        continue;
                    };
                    let Some(offset) = frame_offset(data, address, stack_pointer) else {
                        continue;
                    };
                    let Some(value) = operation.inputs.get(2).copied() else {
                        continue;
                    };
                    found.insert((offset, data.varnode(value).size), ());
                }
                _ => {}
            }
        }

        let escaped = frame_address_escapes(data, stack_pointer);
        let slots = found
            .into_keys()
            .map(|(offset, size)| Slot {
                offset,
                size,
                // AliasChecker deliberately over-approximates: once any
                // pointer escapes, a callee may inspect every frame byte.
                aliased: escaped,
            })
            .collect();
        Self { slots, escaped }
    }

    /// Return a slot at `offset`, preferring the widest access if several widths
    /// begin at the same address.
    pub fn slot_at(&self, offset: i64) -> Option<&Slot> {
        self.slots
            .iter()
            .filter(|slot| slot.offset == offset)
            .max_by_key(|slot| slot.size)
    }

    /// Iterate slots in offset/width order.
    pub fn slots(&self) -> impl Iterator<Item = &Slot> {
        self.slots.iter()
    }

    /// Whether any frame address escapes to a call or outside-frame store.
    pub fn escapes(&self) -> bool {
        self.escaped
    }
}

/// The frame offset an address expression denotes.
///
/// This follows Ghidra's additive part of `AliasChecker::gatherOffset`: copies,
/// pointer additions/subtractions, and constant-index `PTRADD` expressions are
/// walked backwards to the incoming spacebase.  An expression involving a
/// dynamic index is still recognised as frame-derived for escape analysis, but
/// has no single offset and therefore returns `None` here.
pub fn frame_offset(data: &Funcdata, address: VarnodeId, stack_pointer: Location) -> Option<i64> {
    let mut active = BTreeSet::new();
    frame_offset_inner(data, address, stack_pointer, &mut active)
}

/// Canonicalise stack-pointer arithmetic into one spacebase plus a constant.
pub struct ActionStackPtrFlow;

impl Action for ActionStackPtrFlow {
    fn name(&self) -> &'static str {
        "stackptrflow"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let operations: Vec<OpId> = data.live_ops().map(|(id, _)| id).collect();
        let mut changed = 0;
        for id in operations {
            if data.opcode_of(id).is_none() {
                continue;
            }
            if canonicalize_arithmetic(data, id) {
                changed += 1;
            }
        }
        changed
    }
}

/// Restrict stack locations that cannot be mapped as ordinary locals.
///
/// Ghidra's implementation calls `ScopeLocal::markNotMapped` for locked
/// call-parameter and saved-register ranges.  The graph contract has neither
/// `FuncCallSpecs`/prototype locks nor a `ScopeLocal` range tree, so there is no
/// sound mutation this action can make.  It remains an explicit no-op rather
/// than guessing from raw CALL operands and misclassifying ordinary locals.
pub struct ActionRestrictLocal;

impl Action for ActionRestrictLocal {
    fn name(&self) -> &'static str {
        "restrictlocal"
    }

    fn apply(&self, _data: &mut Funcdata) -> usize {
        0
    }
}
/// Whether a value is derived from the frame base at all.
///
/// `frame_offset` answers "at which offset", and returns nothing when there is no
/// single answer. A frame pointer carried around a loop has no single offset —
/// `p = p + 0x20` each turn — yet it is still a frame pointer, and the question
/// of whether the frame may be treated as an ordinary structure needs that
/// weaker fact. This crosses phis for exactly that reason, and it is a
/// structural property, so unlike a recovered type it cannot be stale.
pub fn is_frame_derived(data: &Funcdata, address: VarnodeId, stack_pointer: Location) -> bool {
    let mut active = BTreeSet::new();
    frame_derived_inner(data, address, stack_pointer, &mut active)
}

fn frame_derived_inner(
    data: &Funcdata,
    address: VarnodeId,
    stack_pointer: Location,
    active: &mut BTreeSet<VarnodeId>,
) -> bool {
    if !active.insert(address) {
        // A cycle contributes nothing: the loop-carried edge is the one this
        // returns to, and the other operand decides.
        return false;
    }
    let varnode = data.varnode(address);
    let result = if varnode.space == stack_pointer.space && varnode.offset == stack_pointer.offset {
        true
    } else {
        match varnode.def {
            None => false,
            Some(def) => {
                let operation = data.op(def);
                let opcode = operation.opcode;
                let inputs = operation.inputs.clone();
                match opcode {
                    op::COPY | op::CAST | op::INDIRECT | op::MULTIEQUAL => inputs
                        .iter()
                        .any(|input| frame_derived_inner(data, *input, stack_pointer, active)),
                    // Only the base of an address computation carries the frame;
                    // the displacement is a number.
                    op::INT_ADD | op::INT_SUB | op::PTRADD | op::PTRSUB => {
                        inputs.first().is_some_and(|input| {
                            frame_derived_inner(data, *input, stack_pointer, active)
                        })
                    }
                    _ => false,
                }
            }
        }
    };
    active.remove(&address);
    result
}

fn frame_offset_inner(
    data: &Funcdata,
    address: VarnodeId,
    stack_pointer: Location,
    active: &mut BTreeSet<VarnodeId>,
) -> Option<i64> {
    if !active.insert(address) {
        return None;
    }

    let result = {
        let varnode = data.varnode(address);
        if varnode.space == stack_pointer.space && varnode.offset == stack_pointer.offset {
            match varnode.def {
                None => Some(0),
                Some(def) => frame_offset_op(data, def, stack_pointer, active),
            }
        } else {
            varnode
                .def
                .and_then(|def| frame_offset_op(data, def, stack_pointer, active))
        }
    };
    active.remove(&address);
    result
}

fn frame_offset_op(
    data: &Funcdata,
    def: OpId,
    stack_pointer: Location,
    active: &mut BTreeSet<VarnodeId>,
) -> Option<i64> {
    let operation = data.op(def);
    let opcode = operation.opcode;
    let inputs = operation.inputs.clone();
    match opcode {
        op::COPY | op::CAST | op::INDIRECT => {
            frame_offset_inner(data, inputs.first().copied()?, stack_pointer, active)
        }
        op::MULTIEQUAL => {
            let mut offsets = inputs
                .into_iter()
                .map(|input| frame_offset_inner(data, input, stack_pointer, active));
            let first = offsets.next()??;
            offsets.all(|offset| offset == Some(first)).then_some(first)
        }
        op::INT_ADD | op::PTRSUB => {
            let left = inputs.first().copied()?;
            let right = inputs.get(1).copied()?;
            if let Some(delta) = signed_constant(data, right) {
                return frame_offset_inner(data, left, stack_pointer, active)
                    .map(|base| base.wrapping_add(delta));
            }
            if opcode == op::INT_ADD
                && let Some(delta) = signed_constant(data, left)
            {
                return frame_offset_inner(data, right, stack_pointer, active)
                    .map(|base| base.wrapping_add(delta));
            }
            None
        }
        op::INT_SUB => {
            let left = inputs.first().copied()?;
            let right = inputs.get(1).copied()?;
            let delta = signed_constant(data, right)?;
            frame_offset_inner(data, left, stack_pointer, active)
                .map(|base| base.wrapping_sub(delta))
        }
        op::PTRADD => {
            let base = inputs.first().copied()?;
            let index = signed_constant(data, inputs.get(1).copied()?)?;
            let scale = match inputs.get(2) {
                Some(value) => signed_constant(data, *value)?,
                None => 1,
            };
            frame_offset_inner(data, base, stack_pointer, active)
                .map(|offset| offset.wrapping_add(index.wrapping_mul(scale)))
        }
        _ => None,
    }
}

fn signed_constant(data: &Funcdata, value: VarnodeId) -> Option<i64> {
    let varnode = data.varnode(value);
    varnode
        .flags
        .constant
        .then(|| sign_extend(varnode.offset, varnode.size))
}

fn sign_extend(value: u64, size: u32) -> i64 {
    match size {
        0 | 8.. => value as i64,
        size => {
            let bits = size * 8;
            let sign = 1u64 << (bits - 1);
            if value & sign != 0 {
                (value | !((1u64 << bits) - 1)) as i64
            } else {
                value as i64
            }
        }
    }
}

/// Whether an expression is rooted in the incoming spacebase even when its
/// final offset is dynamic.  AliasChecker uses this broader predicate for
/// pointer escape decisions than it can use for naming a fixed slot.
fn frame_derived(
    data: &Funcdata,
    value: VarnodeId,
    stack_pointer: Location,
    active: &mut BTreeSet<VarnodeId>,
) -> bool {
    if !active.insert(value) {
        return false;
    }
    let result = {
        let varnode = data.varnode(value);
        if varnode.space == stack_pointer.space && varnode.offset == stack_pointer.offset {
            match varnode.def {
                None => true,
                Some(def) => frame_derived_op(data, def, stack_pointer, active),
            }
        } else {
            varnode
                .def
                .is_some_and(|def| frame_derived_op(data, def, stack_pointer, active))
        }
    };
    active.remove(&value);
    result
}

fn frame_derived_op(
    data: &Funcdata,
    def: OpId,
    stack_pointer: Location,
    active: &mut BTreeSet<VarnodeId>,
) -> bool {
    let operation = data.op(def);
    let opcode = operation.opcode;
    let inputs = operation.inputs.clone();
    match opcode {
        op::COPY | op::CAST | op::INDIRECT => inputs
            .first()
            .copied()
            .is_some_and(|value| frame_derived(data, value, stack_pointer, active)),
        op::INT_ADD | op::PTRSUB | op::PTRADD => inputs
            .iter()
            .copied()
            .any(|value| frame_derived(data, value, stack_pointer, active)),
        op::INT_SUB => inputs
            .first()
            .copied()
            .is_some_and(|value| frame_derived(data, value, stack_pointer, active)),
        op::MULTIEQUAL => inputs
            .iter()
            .copied()
            .any(|value| frame_derived(data, value, stack_pointer, active)),
        _ => false,
    }
}

/// Whether a frame pointer reaches a call or is written to storage outside its
/// own frame.  A pointer stored back into the frame is private (the common
/// saved-stack-pointer prologue pattern), matching Ghidra's conservative
/// `AliasChecker` treatment.
fn frame_address_escapes(data: &Funcdata, stack_pointer: Location) -> bool {
    data.live_ops()
        .any(|(_, operation)| match operation.opcode {
            op::CALL | op::CALLIND | op::CALLOTHER | op::RETURN => {
                let skip = 1;
                operation
                    .inputs
                    .iter()
                    .skip(skip)
                    .copied()
                    .any(|value| frame_derived(data, value, stack_pointer, &mut BTreeSet::new()))
            }
            op::STORE => {
                let Some(value) = operation.inputs.get(2).copied() else {
                    return false;
                };
                if !frame_derived(data, value, stack_pointer, &mut BTreeSet::new()) {
                    return false;
                }
                let into_frame = operation.inputs.get(1).copied().is_some_and(|address| {
                    frame_derived(data, address, stack_pointer, &mut BTreeSet::new())
                });
                !into_frame
            }
            _ => false,
        })
}

/// Return the incoming register-space root and its constant displacement.
///
/// Graph construction does not carry Ghidra's `spacebase` Varnode flag, so the
/// only representable equivalent is a register-space input.  This is
/// intentionally narrower than "any pointer": unique temporaries without a
/// register root are not rewritten as stack-pointer flow.
fn register_root_offset(
    data: &Funcdata,
    value: VarnodeId,
    active: &mut BTreeSet<VarnodeId>,
) -> Option<(VarnodeId, i64)> {
    if !active.insert(value) {
        return None;
    }

    let result = {
        let varnode = data.varnode(value);
        if (varnode.space == REGISTER_SPACE || varnode.flags.input) && varnode.def.is_none() {
            Some((value, 0))
        } else {
            match varnode.def {
                Some(def) => register_root_offset_op(data, def, active),
                None => None,
            }
        }
    };
    active.remove(&value);
    result
}

fn register_root_offset_op(
    data: &Funcdata,
    def: OpId,
    active: &mut BTreeSet<VarnodeId>,
) -> Option<(VarnodeId, i64)> {
    let operation = data.op(def);
    let opcode = operation.opcode;
    let inputs = operation.inputs.clone();
    match opcode {
        op::COPY | op::CAST | op::INDIRECT => {
            register_root_offset(data, inputs.first().copied()?, active)
        }
        op::INT_ADD | op::PTRSUB => {
            let left = inputs.first().copied()?;
            let right = inputs.get(1).copied()?;
            if let Some(delta) = signed_constant(data, right) {
                let (root, offset) = register_root_offset(data, left, active)?;
                return Some((root, offset.wrapping_add(delta)));
            }
            if opcode == op::INT_ADD
                && let Some(delta) = signed_constant(data, left)
            {
                let (root, offset) = register_root_offset(data, right, active)?;
                return Some((root, offset.wrapping_add(delta)));
            }
            None
        }
        op::INT_SUB => {
            let left = inputs.first().copied()?;
            let delta = signed_constant(data, inputs.get(1).copied()?)?;
            let (root, offset) = register_root_offset(data, left, active)?;
            Some((root, offset.wrapping_sub(delta)))
        }
        op::PTRADD => {
            let base = inputs.first().copied()?;
            let index = signed_constant(data, inputs.get(1).copied()?)?;
            let scale = match inputs.get(2) {
                Some(value) => signed_constant(data, *value)?,
                None => 1,
            };
            let (root, offset) = register_root_offset(data, base, active)?;
            Some((root, offset.wrapping_add(index.wrapping_mul(scale))))
        }
        op::MULTIEQUAL => {
            let mut roots = inputs
                .into_iter()
                .map(|input| register_root_offset(data, input, active));
            let first = roots.next()??;
            roots
                .all(|candidate| candidate == Some(first))
                .then_some(first)
        }
        _ => None,
    }
}

fn canonicalize_arithmetic(data: &mut Funcdata, id: OpId) -> bool {
    let (opcode, output) = {
        let operation = data.op(id);
        (operation.opcode, operation.output)
    };
    if !matches!(opcode, op::INT_ADD | op::INT_SUB | op::PTRADD | op::PTRSUB) {
        return false;
    }
    let Some(output) = output else { return false };
    let Some((base, offset)) = register_root_offset(data, output, &mut BTreeSet::new()) else {
        return false;
    };

    let already_canonical = {
        let operation = data.op(id);
        operation.opcode == op::INT_ADD
            && operation.inputs.first().copied() == Some(base)
            && operation
                .inputs
                .get(1)
                .copied()
                .and_then(|value| signed_constant(data, value))
                == Some(offset)
    };
    if already_canonical {
        return false;
    }

    let width = data.varnode(output).size.max(1);
    let constant = data.new_constant(offset_bits(offset, width), width);
    data.op_set_opcode(id, op::INT_ADD);
    data.op_set_inputs(id, vec![base, constant]);
    true
}

fn offset_bits(offset: i64, size: u32) -> u64 {
    if size >= 8 {
        offset as u64
    } else if size == 0 {
        0
    } else {
        (offset as u64) & ((1u64 << (size * 8)) - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{CONST_SPACE, RAM_SPACE, REGISTER_SPACE};
    use ventris_pcode::op;

    use crate::graph::{GraphBlockId, SeqNum};

    fn stack_pointer() -> Location {
        Location {
            space: REGISTER_SPACE,
            offset: 0x1d0,
            size: 4,
        }
    }

    fn seq(address: u64, order: u32) -> SeqNum {
        SeqNum { address, order }
    }

    fn arithmetic(
        data: &mut Funcdata,
        block: GraphBlockId,
        opcode: i32,
        inputs: Vec<VarnodeId>,
        size: u32,
    ) -> (OpId, VarnodeId) {
        let address = 0x1000 + data.op_count() as u64 * 4;
        let operation = data.new_op(opcode, seq(address, 0), inputs);
        let output = data.new_unique(size);
        data.op_set_output(operation, Some(output));
        data.op_insert_end(operation, block);
        (operation, output)
    }

    fn frame_address(
        data: &mut Funcdata,
        block: GraphBlockId,
        offset: u64,
        size: u32,
    ) -> VarnodeId {
        let sp = data.new_varnode(REGISTER_SPACE, 0x1d0, size);
        let delta = data.new_constant(offset, size);
        arithmetic(data, block, op::INT_ADD, vec![sp, delta], size).1
    }

    #[test]
    fn stack_pointer_flow_collapses_chains_and_then_declines() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(data.entry);
        let sp = data.new_varnode(REGISTER_SPACE, 0x1d0, 4);
        let minus_twenty = data.new_constant(0x20, 4);
        let (_, first) = arithmetic(&mut data, block, op::INT_SUB, vec![sp, minus_twenty], 4);
        let plus_ten = data.new_constant(0x10, 4);
        let (_, chained) = arithmetic(&mut data, block, op::INT_ADD, vec![first, plus_ten], 4);
        let (_, direct) = arithmetic(&mut data, block, op::INT_SUB, vec![sp, plus_ten], 4);
        let unknown = data.new_unique(4);
        let (_, unrelated) = arithmetic(&mut data, block, op::INT_ADD, vec![unknown, plus_ten], 4);

        let action = ActionStackPtrFlow;
        assert_eq!(action.apply(&mut data), 3);
        assert_eq!(
            frame_offset(&data, chained, stack_pointer()),
            Some(-0x10),
            "sp-0x20 then +0x10 is one canonical slot"
        );
        assert_eq!(frame_offset(&data, direct, stack_pointer()), Some(-0x10));
        for value in [chained, direct] {
            let def = data.varnode(value).def.expect("arithmetic definition");
            assert_eq!(data.op(def).opcode, op::INT_ADD);
            assert_eq!(data.op(def).inputs[0], sp);
            assert_eq!(signed_constant(&data, data.op(def).inputs[1]), Some(-0x10));
        }
        assert_eq!(
            data.op(data.varnode(unrelated).def.expect("unrelated definition"))
                .opcode,
            op::INT_ADD,
            "a unique-root arithmetic expression is not treated as stack flow"
        );
        assert_eq!(action.apply(&mut data), 0, "canonical form is stable");
    }

    #[test]
    fn frame_offsets_accept_negative_constants_and_reject_other_roots() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(data.entry);
        let sp = data.new_varnode(REGISTER_SPACE, 0x1d0, 4);
        let negative = data.new_constant(0xffff_fff0, 4);
        let (_, address) = arithmetic(&mut data, block, op::INT_ADD, vec![sp, negative], 4);
        assert_eq!(frame_offset(&data, address, stack_pointer()), Some(-0x10));

        let unrelated = data.new_unique(4);
        let delta = data.new_constant(0x10, 4);
        let (_, other) = arithmetic(&mut data, block, op::INT_ADD, vec![unrelated, delta], 4);
        assert_eq!(frame_offset(&data, other, stack_pointer()), None);
    }

    #[test]
    fn frame_records_each_access_width_and_local_access_is_unaliased() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(data.entry);
        let address = frame_address(&mut data, block, 0xffff_fff0, 4);
        let word = data.new_varnode(REGISTER_SPACE, 0x200, 4);
        let space = data.new_constant(CONST_SPACE as u64, 4);
        let store = data.new_op(op::STORE, seq(0x3000, 0), vec![space, address, word]);
        data.op_insert_end(store, block);
        let load_space = data.new_constant(CONST_SPACE as u64, 4);
        let load = data.new_op(op::LOAD, seq(0x3004, 0), vec![load_space, address]);
        let loaded = data.new_unique(8);
        data.op_set_output(load, Some(loaded));
        data.op_insert_end(load, block);

        let frame = Frame::of(&data, stack_pointer());
        let slots: Vec<_> = frame.slots().collect();
        assert_eq!(slots.len(), 2, "the same offset keeps both observed widths");
        assert!(
            slots
                .iter()
                .any(|slot| slot.offset == -0x10 && slot.size == 4)
        );
        assert!(
            slots
                .iter()
                .any(|slot| slot.offset == -0x10 && slot.size == 8)
        );
        assert!(!frame.escapes());
        assert!(!frame.slot_at(-0x10).expect("slot").aliased);
    }

    #[test]
    fn escaped_frame_address_aliases_every_observed_slot() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(data.entry);
        let address = frame_address(&mut data, block, 0x10, 4);
        let value = data.new_varnode(REGISTER_SPACE, 0x200, 4);
        let space = data.new_constant(CONST_SPACE as u64, 4);
        let _store = data.new_op(op::STORE, seq(0x4000, 0), vec![space, address, value]);

        let target = data.new_varnode(RAM_SPACE, 0x5000, 4);
        let call = data.new_op(op::CALL, seq(0x4004, 0), vec![target, address]);
        data.op_insert_end(call, block);

        let frame = Frame::of(&data, stack_pointer());
        assert!(frame.escapes());
        assert!(frame.slot_at(0x10).expect("slot").aliased);
    }

    #[test]
    fn restrict_local_is_explicitly_conservative_without_scope_metadata() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(data.entry);
        let sp = data.new_varnode(REGISTER_SPACE, 0x1d0, 4);
        let delta = data.new_constant(0x10, 4);
        let (operation, _) = arithmetic(&mut data, block, op::INT_SUB, vec![sp, delta], 4);
        assert_eq!(ActionRestrictLocal.apply(&mut data), 0);
        assert_eq!(
            data.op(operation).opcode,
            op::INT_SUB,
            "without ScopeLocal metadata this action must not guess"
        );
    }
}
