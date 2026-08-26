//! Data-flow guards, ported from Ghidra 12.1.3's `Heritage`.
//!
//! Phi placement and renaming assume every definition of a location is an
//! explicit write. Calls, stores through unknown pointers, and returns break
//! that assumption: they may change or observe a location without naming it.
//! Ghidra repairs the assumption before renaming by inserting `INDIRECT` ops,
//! which give the location an explicit definition whose input is its previous
//! value. Renaming then handles calls and aliasing stores with no special case.
//!
//! Ventris previously deleted definitions at each call from an ad-hoc clobber
//! list, which loses the fact that a preserved register survives and cannot
//! express "changed by this operation, in a way we cannot describe".
//!
//! `guard_stores` keeps the two `Heritage::guardStores` space cases from
//! `heritage.cc:1541-1558`: a direct store-space match and a known
//! spacebase-relative store into the containing space. The graph has no
//! `AddrSpace` manager, so its stack locations use the canonical containing
//! space ID directly; `stackframe::frame_offset` supplies the fixed range that
//! this representation can prove. It deliberately cannot reproduce arbitrary
//! virtual/overlay containment, which needs `AddrSpace::getContain` and the
//! address-space objects from `space.hh:161-188`. A dynamic frame-derived
//! pointer also has no single offset here; narrowing that case needs Ghidra's
//! `LoadGuard` records from `Heritage::generateStoreGuard` and
//! `Heritage::analyzeNewLoadGuards` (`heritage.cc:827-933`), plus
//! `getStoreGuard`/`LoadGuard::isGuarded` (`merge.cc:78-86`), so it takes the
//! same whole-space fallback as an unknown pointer.
//!
//! That narrowing is what let memory join heritage at all. While `guard_stores`
//! guarded a whole space per store it had no production caller - the pipeline
//! guarded registers only, because the broad version really did invent a merge
//! for every address the function mentions. The pipeline now runs it over the
//! memory locations the function touches.
//!
//! Source authority: `Heritage::guard`, `guardCalls`, `guardStores`,
//! `guardReturns`, and `Funcdata::newIndirectOp` in `heritage.cc` and
//! `funcdata_op.cc` at commit `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use std::collections::BTreeSet;

use ventris_pcode::{CONST_SPACE, op};

use super::stackframe::frame_offset;
use super::{Funcdata, OpId, VarnodeId};

/// A storage location considered during heritage.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Location {
    pub space: u32,
    pub offset: u64,
    pub size: u32,
}

/// What a call does to a location, standing in for Ghidra's `EffectRecord`.
///
/// Ghidra reads the effect from the callee prototype and distinguishes three
/// outcomes, not two (`heritage.cc:1509-1524`):
///
/// * `unaffected` - no guard at all, the value simply survives.
/// * `killedbycall` - `newIndirectCreation`, an `INDIRECT` whose input is a
///   constant rather than the previous value. The location's value after the
///   call has *no data flow from before it*.
/// * `unknown_effect` / `return_address` - `newIndirectOp`, an `INDIRECT` that
///   threads the previous value through.
///
/// Collapsing the last two into one loses the distinction that matters most: a
/// threading `INDIRECT` lets a constant a caller-saved register held *before* a
/// call reach the code after it, so a later test on that register folds to a
/// constant and its conditional disappears. Ghidra keeps the conditional
/// because the killed register's post-call value is unrelated to its pre-call
/// value.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct CallEffects {
    pub preserved: BTreeSet<(u32, u64)>,
    /// Locations whose value after a call is unrelated to their value before it.
    ///
    /// Ghidra's `<killedbycall>` list. Reading the shipped cspecs shows what
    /// belongs here and, just as importantly, what does not: PowerPC lists
    /// `r3`, `r4`, `f1`; MIPS lists `v0`, `v1`, `f0`, `f1`, `at`. It is the
    /// convention's *result* storage, not every register the callee is free to
    /// clobber. A caller-saved register outside the list keeps `unknown_effect`,
    /// so its old value is threaded through - Ghidra is deliberately
    /// conservative there, because a callee that never touches the register
    /// leaves the caller's value in place.
    pub killed: BTreeSet<(u32, u64)>,
}

impl CallEffects {
    pub fn preserves(&self, location: &Location) -> bool {
        self.preserved.contains(&(location.space, location.offset))
    }

    /// Whether the callee destroys the location outright.
    pub fn kills(&self, location: &Location) -> bool {
        self.killed.contains(&(location.space, location.offset))
    }
}

/// Every non-constant location the graph touches.
pub fn heritaged_locations(data: &Funcdata) -> BTreeSet<Location> {
    (0..data.varnode_count())
        .map(|index| data.varnode(VarnodeId(index as u32)))
        .filter(|varnode| !varnode.flags.constant && varnode.size > 0)
        .map(|varnode| Location {
            space: varnode.space,
            offset: varnode.offset,
            size: varnode.size,
        })
        .collect()
}

/// Inserts `INDIRECT` definitions for locations a call may change, and gives the
/// call one operand per location the convention could pass a parameter in.
///
/// Ghidra's `Heritage::guardCalls`, both arms. The `INDIRECT` arm gives a
/// location an explicit definition whose input is its previous value, so
/// renaming records a real definition instead of the analysis silently
/// forgetting the location.
///
/// The second arm is the one that makes argument recovery possible at all
/// (`heritage.cc:1495-1507`):
///
/// ```text
/// if (fc->isInputActive() && tryregister) {
///   int4 inputCharacter = fc->characterizeAsInputParam(transAddr,size);
///   if (inputCharacter == ParamEntry::contains_justified) {
///     ...
///     active->registerTrial(transAddr,size);
///     Varnode *vn = fd->newVarnode(size,addr);
///     fd->opInsertInput(op,vn,op->numInput());
/// ```
///
/// A call instruction names no arguments, so Ghidra *appends a free varnode per
/// candidate parameter location before renaming*, and renaming binds each one to
/// the value live at the call. Only then can a trial be decided, because
/// `checkInputTrialUse` reads `op->getIn(slot)`. Recovering the values after
/// renaming instead - from the guards - sees only the locations that still had a
/// guard, which is why calls came out with too few arguments: the arm that fills
/// a `char *` and a literal zero into `FUN_8006909c(param_1,pcVar4,0)` was
/// reduced to `FUN_8006909c(param_1)`, and the values feeding the dropped
/// operands then died as unread.
pub fn guard_calls(
    data: &mut Funcdata,
    locations: &BTreeSet<Location>,
    effects: &CallEffects,
    argument_locations: &[Location],
) -> usize {
    let calls: Vec<OpId> = data
        .live_ops()
        .filter(|(_, candidate)| matches!(candidate.opcode, op::CALL | op::CALLIND))
        .map(|(id, _)| id)
        .collect();
    let mut inserted = 0;
    for call in calls {
        for location in locations {
            if effects.preserves(location) {
                continue;
            }
            if effects.kills(location) {
                insert_indirect_creation(data, call, *location);
            } else {
                insert_indirect(data, call, *location);
            }
            inserted += 1;
        }
        // Appended after the guards so the operand reads the location's value as
        // it is *at* the call, which is what the guard's own input names.
        for location in argument_locations {
            let value = data.new_varnode(location.space, location.offset, location.size);
            let slot = data.op(call).inputs.len();
            data.op_set_input(call, value, slot);
            inserted += 1;
        }
    }
    inserted
}

/// Inserts `INDIRECT` definitions for locations a store may alias.
///
/// `Heritage::guardStores` first compares the requested range's address space
/// with the store's space, and separately accepts a spacebase-marked store
/// whose physical space is the requested range's containing space
/// (`heritage.cc:1541-1558`). Stack locations in this graph are keyed by that
/// physical space ID, so the one representable containing-space test is the
/// same `location.space == store_space` check used for direct stores.
///
/// A fixed frame-relative pointer and a literal pointer are narrowed to their
/// actual byte ranges. A pointer with no recoverable address remains
/// conservative and guards every location in the matching space, as Ghidra
/// does before a `LoadGuard` range can be established.
pub fn guard_stores(data: &mut Funcdata, locations: &BTreeSet<Location>) -> usize {
    let stores: Vec<(OpId, u32, Option<VarnodeId>, u32)> = data
        .live_ops()
        .filter(|(_, candidate)| candidate.opcode == op::STORE)
        .filter_map(|(id, candidate)| {
            let store_space = candidate.inputs.first().and_then(|input| {
                let value = data.varnode(*input);
                if !value.flags.constant || value.space != CONST_SPACE {
                    return None;
                }
                u32::try_from(value.offset).ok()
            })?;
            let pointer = candidate.inputs.get(1).copied();
            let access_size = candidate
                .inputs
                .get(2)
                .map(|value| data.varnode(*value).size)
                .unwrap_or(1)
                .max(1);
            Some((id, store_space, pointer, access_size))
        })
        .collect();

    let mut inserted = 0;
    for (store, store_space, pointer, access_size) in stores {
        let pointer = classify_store_pointer(data, pointer);
        for location in locations.iter().filter(|location| {
            // `AddrSpace::getContain` is not represented separately: stack
            // ranges are stored under their physical containing-space ID.
            location.space == store_space
        }) {
            let aliases = match pointer {
                StorePointer::Constant(address) => {
                    ranges_overlap(location.offset, location.size, address, access_size)
                }
                StorePointer::Frame(offset) => {
                    ranges_overlap(location.offset, location.size, offset as u64, access_size)
                }
                StorePointer::Unknown => true,
            };
            if !aliases {
                continue;
            }
            insert_indirect(data, store, *location);
            inserted += 1;
        }
    }
    inserted
}

#[derive(Copy, Clone)]
enum StorePointer {
    Constant(u64),
    Frame(i64),
    Unknown,
}

fn classify_store_pointer(data: &Funcdata, pointer: Option<VarnodeId>) -> StorePointer {
    let Some(pointer) = pointer else {
        return StorePointer::Unknown;
    };
    if let Some(stack_pointer) = data.spacebase
        && let Some(offset) = frame_offset(data, pointer, stack_pointer)
    {
        return StorePointer::Frame(offset);
    }
    if data.varnode(pointer).flags.constant {
        StorePointer::Constant(data.varnode(pointer).offset)
    } else {
        StorePointer::Unknown
    }
}

fn ranges_overlap(left_offset: u64, left_size: u32, right_offset: u64, right_size: u32) -> bool {
    if left_size == 0 || right_size == 0 {
        return false;
    }
    let left_end = left_offset.saturating_add(u64::from(left_size));
    let right_end = right_offset.saturating_add(u64::from(right_size));
    left_offset < right_end && right_offset < left_end
}

/// Adds the return storage as an input of every `RETURN`.
///
/// Ghidra's `guardReturns` keeps the returned value live to the return site.
/// Without it, the definition that produces the result has no reader and dead
/// code elimination is free to delete the computation.
pub fn guard_returns(data: &mut Funcdata, storage: &[Location]) -> usize {
    let returns: Vec<OpId> = data
        .live_ops()
        .filter(|(_, candidate)| candidate.opcode == op::RETURN)
        .map(|(id, _)| id)
        .collect();
    let mut added = 0;
    for op in returns {
        for location in storage {
            let value = data.new_varnode(location.space, location.offset, location.size);
            let slot = data.op(op).inputs.len();
            data.op_set_input(op, value, slot);
            added += 1;
        }
    }
    added
}

/// Creates `out = INDIRECT(in, op)` immediately before `anchor`.
///
/// The second operand names the operation responsible, matching Ghidra's
/// convention of an annotation input identifying the indirect effect's cause.
fn insert_indirect(data: &mut Funcdata, anchor: OpId, location: Location) -> OpId {
    let seq = data.op(anchor).seq;
    let before = data.new_varnode(location.space, location.offset, location.size);
    // Ghidra's `newVarnodeIop`: the annotation names the *operation*, not its
    // address. Renaming has to ask "does this INDIRECT annotate the op I am
    // looking at", and two calls can share an address on a delay-slot
    // architecture, so an address cannot answer it.
    let cause = data.new_iop(anchor);
    let indirect = data.new_op(op::INDIRECT, seq, vec![before, cause]);
    let after = data.new_varnode(location.space, location.offset, location.size);
    data.op_set_output(indirect, Some(after));
    data.op_insert_before(indirect, anchor);
    indirect
}

/// Creates `out = INDIRECT(0, op)` immediately before `anchor`, where `out` has
/// no data flow from before the operation.
///
/// Ghidra's `Funcdata::newIndirectCreation`. The distinction from
/// `insert_indirect` is the whole point: the location's previous value is *not*
/// an operand, so nothing the caller had in a killed register can reach the code
/// after the call.
fn insert_indirect_creation(data: &mut Funcdata, anchor: OpId, location: Location) -> OpId {
    let seq = data.op(anchor).seq;
    let placeholder = data.new_constant(0, location.size);
    let cause = data.new_iop(anchor);
    let indirect = data.new_op(op::INDIRECT, seq, vec![placeholder, cause]);
    let after = data.new_varnode(location.space, location.offset, location.size);
    data.op_set_output(indirect, Some(after));
    data.mark_indirect_creation(indirect);
    data.op_insert_before(indirect, anchor);
    indirect
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SeqNum;
    use ventris_lifter::{RAM_SPACE, REGISTER_SPACE};

    fn graph_with(opcode: i32, extra_inputs: Vec<u64>) -> (Funcdata, OpId) {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let seq = SeqNum {
            address: 0x1000,
            order: 0,
        };
        let inputs = extra_inputs
            .into_iter()
            .map(|value| data.new_constant(value, 4))
            .collect();
        let op = data.new_op(opcode, seq, inputs);
        data.op_insert_end(op, block);
        (data, op)
    }

    fn location(offset: u64) -> Location {
        Location {
            space: REGISTER_SPACE,
            offset,
            size: 4,
        }
    }

    fn indirect_locations(data: &Funcdata) -> Vec<Location> {
        let mut locations: Vec<_> = data
            .live_ops()
            .filter(|(_, candidate)| candidate.opcode == op::INDIRECT)
            .filter_map(|(_, candidate)| candidate.output)
            .map(|output| {
                let value = data.varnode(output);
                Location {
                    space: value.space,
                    offset: value.offset,
                    size: value.size,
                }
            })
            .collect();
        locations.sort_unstable();
        locations
    }

    #[test]
    fn a_call_defines_every_location_it_may_change() {
        let (mut data, _) = graph_with(op::CALL, vec![0x2000]);
        let locations = BTreeSet::from([location(8), location(16)]);
        let effects = CallEffects::default();
        assert_eq!(guard_calls(&mut data, &locations, &effects, &[]), 2);
        let indirects: Vec<_> = data
            .live_ops()
            .filter(|(_, candidate)| candidate.opcode == op::INDIRECT)
            .collect();
        assert_eq!(indirects.len(), 2);
        for (_, indirect) in indirects {
            let before = data.varnode(indirect.inputs[0]);
            let after = data.varnode(indirect.output.expect("indirect defines a value"));
            assert_eq!(before.location(), after.location());
            assert!(after.flags.written, "the location gains a definition");
        }
    }

    #[test]
    fn a_preserved_location_is_left_alone_across_a_call() {
        let (mut data, _) = graph_with(op::CALL, vec![0x2000]);
        let locations = BTreeSet::from([location(8), location(16)]);
        let effects = CallEffects {
            killed: BTreeSet::new(),
            preserved: BTreeSet::from([(REGISTER_SPACE, 16)]),
        };
        assert_eq!(guard_calls(&mut data, &locations, &effects, &[]), 1);
    }

    #[test]
    fn a_constant_store_guards_only_the_named_location() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let seq = SeqNum {
            address: 0x1000,
            order: 0,
        };
        let space = data.new_constant(u64::from(RAM_SPACE), 4);
        let address = data.new_constant(0x40, 4);
        let value = data.new_constant(1, 4);
        let store = data.new_op(op::STORE, seq, vec![space, address, value]);
        data.op_insert_end(store, block);
        let named = Location {
            space: RAM_SPACE,
            offset: 0x40,
            size: 4,
        };
        let locations = BTreeSet::from([
            named,
            Location {
                space: RAM_SPACE,
                offset: 0x80,
                size: 4,
            },
            location(0x40),
        ]);

        assert_eq!(guard_stores(&mut data, &locations), 1);
        assert_eq!(indirect_locations(&data), vec![named]);
    }

    #[test]
    fn a_frame_relative_store_guards_only_its_frame_slot() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let stack_pointer = Location {
            space: REGISTER_SPACE,
            offset: 0x1d0,
            size: 4,
        };
        let pointer = data.new_varnode(REGISTER_SPACE, 0x1d0, 4);
        data.mark_input(pointer);
        data.spacebase = Some(stack_pointer);
        let delta = data.new_constant(0x10, 4);
        let add = data.new_op(
            op::INT_ADD,
            SeqNum {
                address: 0x1000,
                order: 0,
            },
            vec![pointer, delta],
        );
        let address = data.new_unique(4);
        data.op_set_output(add, Some(address));
        data.op_insert_end(add, block);

        let space = data.new_constant(u64::from(RAM_SPACE), 4);
        let value = data.new_constant(1, 4);
        let store = data.new_op(
            op::STORE,
            SeqNum {
                address: 0x1004,
                order: 0,
            },
            vec![space, address, value],
        );
        data.op_insert_end(store, block);
        let named = Location {
            space: RAM_SPACE,
            offset: 0x10,
            size: 4,
        };
        let locations = BTreeSet::from([
            named,
            Location {
                space: RAM_SPACE,
                offset: 0x20,
                size: 4,
            },
            location(0x10),
        ]);

        assert_eq!(guard_stores(&mut data, &locations), 1);
        assert_eq!(indirect_locations(&data), vec![named]);
    }

    #[test]
    fn an_unknown_store_pointer_guards_every_location_in_its_space() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let space = data.new_constant(u64::from(RAM_SPACE), 4);
        let pointer = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        data.mark_input(pointer);
        let value = data.new_constant(1, 4);
        let store = data.new_op(
            op::STORE,
            SeqNum {
                address: 0x1000,
                order: 0,
            },
            vec![space, pointer, value],
        );
        data.op_insert_end(store, block);
        let locations = BTreeSet::from([
            Location {
                space: RAM_SPACE,
                offset: 0x10,
                size: 4,
            },
            Location {
                space: RAM_SPACE,
                offset: 0x20,
                size: 4,
            },
            location(0x20),
        ]);

        assert_eq!(guard_stores(&mut data, &locations), 2);
        assert_eq!(
            indirect_locations(&data),
            vec![
                Location {
                    space: RAM_SPACE,
                    offset: 0x10,
                    size: 4,
                },
                Location {
                    space: RAM_SPACE,
                    offset: 0x20,
                    size: 4,
                },
            ]
        );
    }

    #[test]
    fn a_return_reads_its_result_storage() {
        let (mut data, ret) = graph_with(op::RETURN, vec![]);
        assert_eq!(guard_returns(&mut data, &[location(8)]), 1);
        let inputs = &data.op(ret).inputs;
        assert_eq!(inputs.len(), 1);
        assert_eq!(data.varnode(inputs[0]).offset, 8);
    }

    #[test]
    fn guards_are_inserted_before_the_operation_they_describe() {
        let (mut data, call) = graph_with(op::CALL, vec![0x2000]);
        guard_calls(
            &mut data,
            &BTreeSet::from([location(8)]),
            &CallEffects::default(),
            &[],
        );
        let block = data.op(call).parent.expect("the call has a block");
        let ops = &data.block(block).ops;
        let indirect = ops
            .iter()
            .position(|id| data.op(*id).opcode == op::INDIRECT)
            .expect("indirect present");
        let call_at = ops.iter().position(|id| *id == call).expect("call present");
        assert!(indirect < call_at);
    }
}
