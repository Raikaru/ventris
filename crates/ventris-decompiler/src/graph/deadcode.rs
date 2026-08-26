//! Dead code elimination, ported from Ghidra 12.1.3's `ActionDeadCode`.
//!
//! Removing operations whose results nothing reads is not a cosmetic pass here.
//! Guarding and SSA construction deliberately over-approximate: every location
//! a call may change gains an `INDIRECT`, and every location written on more
//! than one path gains a `MULTIEQUAL`. Most of those are never read. Without
//! this pass the graph pipeline emits them all, which is why its first output
//! was dominated by merges nothing observed.
//!
//! The liveness is bit-level, not operation-level. Ghidra tracks which *bits*
//! of each value are consumed, so a byte extracted from a word marks only that
//! byte live and the rest of the word can still die. Operation-level liveness
//! would keep the whole word and lose the distinction that makes sub-register
//! code readable.
//!
//! Source authority: `ActionDeadCode::apply`, `propagateConsumed`, and
//! `pushConsumed` in `coreaction.cc` at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use std::collections::{BTreeMap, BTreeSet};

use ventris_pcode::op;

use super::guard::Location;
use super::{Funcdata, OpId, VarnodeId};

/// All bits of a value of the given byte size.
fn calc_mask(size: u32) -> u64 {
    match size {
        0 => 0,
        size if size >= 8 => u64::MAX,
        size => (1u64 << (size * 8)) - 1,
    }
}

/// The smallest contiguous mask covering every set bit.
///
/// Addition and subtraction propagate carries upward, so consuming any bit of
/// the result means consuming every operand bit at or below it.
fn covering_mask(mask: u64) -> u64 {
    if mask == 0 {
        return 0;
    }
    let high = 63 - mask.leading_zeros();
    match high {
        63 => u64::MAX,
        high => (1u64 << (high + 1)) - 1,
    }
}

/// Removes every operation whose result no reachable sink consumes.
///
/// Returns the number of operations destroyed. A call keeps its side effect and
/// loses only its unread output, matching `opUnsetOutput`.
pub fn eliminate_dead_code(data: &mut Funcdata) -> usize {
    let consumed = propagate(data);
    let mut removed = 0;
    let candidates: Vec<(OpId, VarnodeId, i32)> = data
        .live_ops()
        .filter_map(|(id, operation)| {
            operation
                .output
                .map(|output| (id, output, operation.opcode))
        })
        .collect();
    for (id, output, opcode) in candidates {
        if consumed.get(&output).copied().unwrap_or(0) != 0 {
            continue;
        }
        if matches!(opcode, op::CALL | op::CALLIND | op::CALLOTHER) {
            // The call must still happen; only its unread result goes away.
            //
            // `CALLOTHER` belongs here too: a userop stands for behaviour the
            // p-code cannot express, so it may have effects even when nothing
            // reads what it returns. Destroying it emptied the paired-single
            // dispatch arms in `__FrameCallback__Fl` and lost one of the four
            // `ldexpf` calls the oracle makes.
            data.op_set_output(id, None);
            removed += 1;
            continue;
        }
        if matches!(opcode, op::STORE) {
            continue;
        }
        data.op_destroy(id);
        removed += 1;
    }
    removed
}

/// Removes stores to frame slots that nothing reads.
///
/// A store is normally a sink: its effect is visible outside the function. A
/// store into this function's own stack frame is different, because the frame
/// dies with the call. Ghidra reaches this by heritaging the stack space and
/// letting ordinary dead code remove the result, which is why a prologue that
/// saves registers and never reloads them does not appear in its output. Keeping
/// those stores puts the whole prologue in front of every function body.
///
/// The conditions are deliberately narrow, because getting this wrong deletes a
/// real memory write:
///   * the address is the stack pointer plus a constant, so the slot is known;
///   * no load in the function reads that slot;
///   * no frame address reaches a call or a store, so no callee can read it.
///
/// Source authority: `ActionHeritage` over `IPTR_SPACEBASE` plus
/// `ActionDeadCode` in `coreaction.cc`, and `Heritage::guardStores` in
/// `heritage.cc`.
pub fn eliminate_dead_frame_stores(data: &mut Funcdata, stack_pointer: Location) -> usize {
    if frame_address_escapes(data, stack_pointer) {
        return 0;
    }
    let read: BTreeSet<i64> = data
        .live_ops()
        .filter(|(_, operation)| operation.opcode == op::LOAD)
        .filter_map(|(_, operation)| operation.inputs.get(1).copied())
        .filter_map(|address| frame_offset(data, address, stack_pointer))
        .collect();
    let dead: Vec<OpId> = data
        .live_ops()
        .filter(|(_, operation)| operation.opcode == op::STORE)
        .filter(|(_, operation)| {
            operation
                .inputs
                .get(1)
                .copied()
                .and_then(|address| frame_offset(data, address, stack_pointer))
                .is_some_and(|offset| !read.contains(&offset))
        })
        .map(|(id, _)| id)
        .collect();
    let removed = dead.len();
    for id in dead {
        data.op_destroy(id);
    }
    removed
}

/// The frame offset an address denotes, or `None` when it is not frame relative.
fn frame_offset(data: &Funcdata, address: VarnodeId, stack_pointer: Location) -> Option<i64> {
    frame_offset_bounded(data, address, stack_pointer, 0)
}

fn frame_offset_bounded(
    data: &Funcdata,
    address: VarnodeId,
    stack_pointer: Location,
    depth: u32,
) -> Option<i64> {
    if depth > 8 {
        return None;
    }
    let varnode = data.varnode(address);
    if varnode.space == stack_pointer.space && varnode.offset == stack_pointer.offset {
        // The incoming stack pointer is offset zero of the frame.
        return match varnode.def {
            None => Some(0),
            Some(def) => frame_offset_from_op(data, def, stack_pointer, depth),
        };
    }
    let def = varnode.def?;
    frame_offset_from_op(data, def, stack_pointer, depth)
}

fn frame_offset_from_op(
    data: &Funcdata,
    def: OpId,
    stack_pointer: Location,
    depth: u32,
) -> Option<i64> {
    let operation = data.op(def);
    match operation.opcode {
        op::COPY | op::CAST | op::INDIRECT => frame_offset_bounded(
            data,
            operation.inputs.first().copied()?,
            stack_pointer,
            depth + 1,
        ),
        op::INT_ADD | op::PTRADD | op::PTRSUB | op::INT_SUB => {
            let left = operation.inputs.first().copied()?;
            let right = operation.inputs.get(1).copied()?;
            let constant = data.varnode(right);
            if !constant.flags.constant {
                return None;
            }
            let base = frame_offset_bounded(data, left, stack_pointer, depth + 1)?;
            let delta = sign_extend(constant.offset, constant.size);
            Some(if operation.opcode == op::INT_SUB {
                base - delta
            } else {
                base + delta
            })
        }
        _ => None,
    }
}

fn sign_extend(value: u64, size: u32) -> i64 {
    match size {
        0 | 8.. => value as i64,
        size => {
            let bits = size * 8;
            let sign = 1u64 << (bits - 1);
            if value & sign != 0 {
                (value | !calc_mask(size)) as i64
            } else {
                value as i64
            }
        }
    }
}

/// Whether any frame address reaches a call argument or is itself stored.
///
/// If a callee receives a pointer into the frame, it may read a slot this
/// function never loads, so no store into the frame can be proven dead.
fn frame_address_escapes(data: &Funcdata, stack_pointer: Location) -> bool {
    data.live_ops()
        .any(|(_, operation)| match operation.opcode {
            op::CALL | op::CALLIND | op::CALLOTHER | op::RETURN => operation
                .inputs
                .iter()
                .skip(1)
                .copied()
                .any(|value| frame_offset(data, value, stack_pointer).is_some()),
            // A frame address written *outside* the frame outlives it. Written
            // into the frame it stays private, which is what a saved frame pointer
            // is: the prologue stores the old stack pointer into its own slot.
            op::STORE => {
                let escapes_value = operation
                    .inputs
                    .get(2)
                    .copied()
                    .is_some_and(|value| frame_offset(data, value, stack_pointer).is_some());
                let into_frame =
                    operation.inputs.get(1).copied().is_some_and(|address| {
                        frame_offset(data, address, stack_pointer).is_some()
                    });
                escapes_value && !into_frame
            }
            _ => false,
        })
}

/// The consumed-bit mask of every value, propagated backwards from the sinks.
pub fn propagate(data: &Funcdata) -> BTreeMap<VarnodeId, u64> {
    let mut consumed: BTreeMap<VarnodeId, u64> = BTreeMap::new();
    let mut worklist: Vec<VarnodeId> = Vec::new();

    let push = |value: VarnodeId,
                mask: u64,
                consumed: &mut BTreeMap<VarnodeId, u64>,
                worklist: &mut Vec<VarnodeId>| {
        let entry = consumed.entry(value).or_insert(0);
        if mask & !*entry == 0 {
            return;
        }
        *entry |= mask;
        if data.varnode(value).def.is_some() {
            worklist.push(value);
        }
    };

    // Sinks: everything a program's observable behaviour depends on.
    for (_, operation) in data.live_ops() {
        let all = matches!(
            operation.opcode,
            op::STORE
                | op::RETURN
                | op::BRANCH
                | op::CBRANCH
                | op::BRANCHIND
                | op::CALL
                | op::CALLIND
                | op::CALLOTHER
        );
        if !all {
            continue;
        }
        // Every operand of a `RETURN` is fully consumed, its first included.
        // `ActionDeadCode::propagateConsumed` pushes `~0` on `getIn(0)` - the
        // return address - before pushing the convention's mask on the rest.
        // Skipping it kills the epilogue's register restore, which empties the
        // epilogue block; `ActionDoNothing` then removes the empty block and the
        // function's exit arms collapse into gotos.
        for input in operation.inputs.iter().copied() {
            let mask = calc_mask(data.varnode(input).size);
            push(input, mask, &mut consumed, &mut worklist);
        }
    }

    while let Some(value) = worklist.pop() {
        let out = consumed.get(&value).copied().unwrap_or(0);
        let Some(def) = data.varnode(value).def else {
            continue;
        };
        let operation = data.op(def);
        let input = |slot: usize| operation.inputs.get(slot).copied();
        let send = |slot: usize,
                    mask: u64,
                    consumed: &mut BTreeMap<VarnodeId, u64>,
                    worklist: &mut Vec<VarnodeId>| {
            if let Some(target) = input(slot) {
                push(target, mask, consumed, worklist);
            }
        };
        match operation.opcode {
            op::INT_ADD | op::INT_SUB | op::PTRADD | op::PTRSUB => {
                let mask = covering_mask(out);
                send(0, mask, &mut consumed, &mut worklist);
                send(1, mask, &mut consumed, &mut worklist);
            }
            op::INT_MULT => {
                let mask = covering_mask(out);
                send(0, mask, &mut consumed, &mut worklist);
                send(1, mask, &mut consumed, &mut worklist);
            }
            op::COPY | op::INT_NEGATE | op::INT_ZEXT | op::CAST => {
                send(0, out, &mut consumed, &mut worklist);
            }
            op::INT_XOR | op::INT_OR => {
                send(0, out, &mut consumed, &mut worklist);
                send(1, out, &mut consumed, &mut worklist);
            }
            op::INT_AND => {
                let narrowed = input(1)
                    .map(|value| data.varnode(value))
                    .filter(|value| value.flags.constant)
                    .map(|value| out & value.offset)
                    .unwrap_or(out);
                send(0, narrowed, &mut consumed, &mut worklist);
                send(1, out, &mut consumed, &mut worklist);
            }
            op::INT_SEXT => {
                let source = input(0).map(|value| data.varnode(value).size).unwrap_or(0);
                let source_mask = calc_mask(source);
                let mut mask = out & source_mask;
                if out > source_mask {
                    // The sign bit is read even when only the extension is.
                    mask |= source_mask ^ (source_mask >> 1);
                }
                send(0, mask, &mut consumed, &mut worklist);
            }
            op::SUBPIECE => {
                let shift = input(1)
                    .map(|value| data.varnode(value).offset)
                    .unwrap_or(0);
                let mask = if shift >= 8 { 0 } else { out << (shift * 8) };
                send(0, mask, &mut consumed, &mut worklist);
                send(
                    1,
                    if out == 0 { 0 } else { u64::MAX },
                    &mut consumed,
                    &mut worklist,
                );
            }
            op::PIECE => {
                let low = input(1).map(|value| data.varnode(value).size).unwrap_or(0);
                let high_mask = if low >= 8 { 0 } else { out >> (low * 8) };
                let low_mask = out ^ (high_mask << (low.min(7) * 8));
                send(0, high_mask, &mut consumed, &mut worklist);
                send(1, low_mask, &mut consumed, &mut worklist);
            }
            op::INT_LEFT => {
                let shift = input(1)
                    .map(|value| data.varnode(value))
                    .filter(|value| value.flags.constant)
                    .map(|value| value.offset);
                match shift {
                    Some(shift) if shift < 64 => {
                        send(0, out >> shift, &mut consumed, &mut worklist)
                    }
                    Some(_) => send(0, 0, &mut consumed, &mut worklist),
                    None => send(0, u64::MAX, &mut consumed, &mut worklist),
                }
                send(1, u64::MAX, &mut consumed, &mut worklist);
            }
            op::INT_RIGHT => {
                let shift = input(1)
                    .map(|value| data.varnode(value))
                    .filter(|value| value.flags.constant)
                    .map(|value| value.offset);
                match shift {
                    Some(shift) if shift < 64 => {
                        send(0, out << shift, &mut consumed, &mut worklist)
                    }
                    Some(_) => send(0, 0, &mut consumed, &mut worklist),
                    None => send(0, u64::MAX, &mut consumed, &mut worklist),
                }
                send(1, u64::MAX, &mut consumed, &mut worklist);
            }
            op::MULTIEQUAL | op::INDIRECT => {
                // An INDIRECT's second operand only names the responsible
                // operation, so it carries no value to consume.
                let limit = if operation.opcode == op::INDIRECT {
                    1
                } else {
                    operation.inputs.len()
                };
                for slot in 0..limit {
                    send(slot, out, &mut consumed, &mut worklist);
                }
            }
            _ => {
                let arity = operation.inputs.len();
                for slot in 0..arity {
                    let mask = input(slot)
                        .map(|value| calc_mask(data.varnode(value).size))
                        .unwrap_or(0);
                    send(slot, mask, &mut consumed, &mut worklist);
                }
            }
        }
    }
    consumed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{SeqNum, heritage::heritage};
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    /// A `RETURN` in its real p-code shape: return address first, then any
    /// returned value.
    fn returning(data: &mut Funcdata, address: u64, value: Option<VarnodeId>) -> OpId {
        let link = data.new_varnode(REGISTER_SPACE, 0x1f0, 8);
        let mut inputs = vec![link];
        inputs.extend(value);
        data.new_op(op::RETURN, seq(address), inputs)
    }

    #[test]
    fn an_unread_computation_is_removed() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_constant(2, 4);
        let right = data.new_constant(3, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![left, right]);
        let sum = data.new_unique(4);
        data.op_set_output(add, Some(sum));
        data.op_insert_end(add, block);
        let ret = returning(&mut data, 0x1004, None);
        data.op_insert_end(ret, block);

        assert_eq!(eliminate_dead_code(&mut data), 1);
        assert!(data.live_ops().all(|(_, op)| op.opcode != op::INT_ADD));
    }

    #[test]
    fn a_returned_computation_survives() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_constant(2, 4);
        let right = data.new_constant(3, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![left, right]);
        let sum = data.new_unique(4);
        data.op_set_output(add, Some(sum));
        data.op_insert_end(add, block);
        let ret = returning(&mut data, 0x1004, Some(sum));
        data.op_insert_end(ret, block);

        assert_eq!(eliminate_dead_code(&mut data), 0);
    }

    #[test]
    fn a_call_keeps_its_effect_and_loses_its_unread_result() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let target = data.new_constant(0x3000, 4);
        let call = data.new_op(op::CALL, seq(0x1000), vec![target]);
        let result = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(call, Some(result));
        data.op_insert_end(call, block);

        assert_eq!(eliminate_dead_code(&mut data), 1);
        let (_, operation) = data
            .live_ops()
            .find(|(_, operation)| operation.opcode == op::CALL)
            .expect("the call itself survives");
        assert!(operation.output.is_none());
    }

    /// A userop stands for behaviour the p-code cannot express, so it may have
    /// effects even when nothing reads what it returns. Destroying it emptied the
    /// paired-single dispatch arms in `__FrameCallback__Fl` and lost one of the
    /// four `ldexpf` calls the oracle makes.
    #[test]
    fn a_userop_keeps_its_effect_and_loses_its_unread_result() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let argument = data.new_constant(0x3f, 4);
        let userop = data.new_op(op::CALLOTHER, seq(0x1000), vec![argument]);
        let result = data.new_unique(4);
        data.op_set_output(userop, Some(result));
        data.op_insert_end(userop, block);

        assert_eq!(eliminate_dead_code(&mut data), 1);
        let (_, operation) = data
            .live_ops()
            .find(|(_, operation)| operation.opcode == op::CALLOTHER)
            .expect("the userop itself survives");
        assert!(operation.output.is_none());
    }

    #[test]
    fn an_unread_merge_is_removed() {
        let mut data = Funcdata::default();
        let entry = data.new_block(0x1000);
        let left = data.new_block(0x1010);
        let right = data.new_block(0x1020);
        let join = data.new_block(0x1030);
        data.add_edge(entry, left);
        data.add_edge(entry, right);
        data.add_edge(left, join);
        data.add_edge(right, join);
        for (block, value) in [(left, 1u64), (right, 2u64)] {
            let start = data.block(block).start;
            let constant = data.new_constant(value, 4);
            let copy = data.new_op(op::COPY, seq(start), vec![constant]);
            let out = data.new_varnode(REGISTER_SPACE, 8, 4);
            data.op_set_output(copy, Some(out));
            data.op_insert_end(copy, block);
        }
        let ret = returning(&mut data, 0x1030, None);
        data.op_insert_end(ret, join);

        assert_eq!(heritage(&mut data), 1);
        eliminate_dead_code(&mut data);
        assert!(
            data.live_ops().all(|(_, op)| op.opcode != op::MULTIEQUAL),
            "nothing reads the merge, so it does not survive"
        );
    }

    #[test]
    fn a_read_merge_survives() {
        let mut data = Funcdata::default();
        let entry = data.new_block(0x1000);
        let left = data.new_block(0x1010);
        let right = data.new_block(0x1020);
        let join = data.new_block(0x1030);
        data.add_edge(entry, left);
        data.add_edge(entry, right);
        data.add_edge(left, join);
        data.add_edge(right, join);
        for (block, value) in [(left, 1u64), (right, 2u64)] {
            let start = data.block(block).start;
            let constant = data.new_constant(value, 4);
            let copy = data.new_op(op::COPY, seq(start), vec![constant]);
            let out = data.new_varnode(REGISTER_SPACE, 8, 4);
            data.op_set_output(copy, Some(out));
            data.op_insert_end(copy, block);
        }
        let read = data.new_varnode(REGISTER_SPACE, 8, 4);
        let ret = returning(&mut data, 0x1030, Some(read));
        data.op_insert_end(ret, join);

        heritage(&mut data);
        eliminate_dead_code(&mut data);
        assert_eq!(
            data.live_ops()
                .filter(|(_, op)| op.opcode == op::MULTIEQUAL)
                .count(),
            1
        );
    }

    fn stack_pointer() -> Location {
        Location {
            space: REGISTER_SPACE,
            offset: 0x1d0,
            size: 4,
        }
    }

    /// Builds `store [sp + offset] = value`, with the address computed the way
    /// a prologue does.
    fn frame_store(
        data: &mut Funcdata,
        block: crate::graph::GraphBlockId,
        offset: u64,
        value: VarnodeId,
    ) -> OpId {
        let sp = data.new_varnode(REGISTER_SPACE, 0x1d0, 4);
        let delta = data.new_constant(offset, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![sp, delta]);
        let address = data.new_unique(4);
        data.op_set_output(add, Some(address));
        data.op_insert_end(add, block);
        let space = data.new_constant(0, 4);
        let store = data.new_op(op::STORE, seq(0x1004), vec![space, address, value]);
        data.op_insert_end(store, block);
        store
    }

    #[test]
    fn a_frame_slot_nothing_reads_loses_its_store() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let saved = data.new_varnode(REGISTER_SPACE, 0x1f0, 8);
        frame_store(&mut data, block, 0x10, saved);
        let ret = returning(&mut data, 0x1008, None);
        data.op_insert_end(ret, block);

        assert_eq!(eliminate_dead_frame_stores(&mut data, stack_pointer()), 1);
        assert!(data.live_ops().all(|(_, op)| op.opcode != op::STORE));
    }

    #[test]
    fn a_frame_slot_that_is_reloaded_keeps_its_store() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let saved = data.new_varnode(REGISTER_SPACE, 0x1f0, 8);
        frame_store(&mut data, block, 0x10, saved);
        let sp = data.new_varnode(REGISTER_SPACE, 0x1d0, 4);
        let delta = data.new_constant(0x10, 4);
        let add = data.new_op(op::INT_ADD, seq(0x100c), vec![sp, delta]);
        let address = data.new_unique(4);
        data.op_set_output(add, Some(address));
        data.op_insert_end(add, block);
        let space = data.new_constant(0, 4);
        let load = data.new_op(op::LOAD, seq(0x1010), vec![space, address]);
        let loaded = data.new_unique(8);
        data.op_set_output(load, Some(loaded));
        data.op_insert_end(load, block);
        let ret = returning(&mut data, 0x1014, Some(loaded));
        data.op_insert_end(ret, block);

        assert_eq!(eliminate_dead_frame_stores(&mut data, stack_pointer()), 0);
    }

    #[test]
    fn a_frame_address_passed_to_a_call_protects_every_slot() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let saved = data.new_varnode(REGISTER_SPACE, 0x1f0, 8);
        frame_store(&mut data, block, 0x10, saved);
        // The callee receives a pointer into the frame, so it may read the slot.
        let sp = data.new_varnode(REGISTER_SPACE, 0x1d0, 4);
        let delta = data.new_constant(0x20, 4);
        let add = data.new_op(op::INT_ADD, seq(0x100c), vec![sp, delta]);
        let argument = data.new_unique(4);
        data.op_set_output(add, Some(argument));
        data.op_insert_end(add, block);
        let target = data.new_varnode(ventris_lifter::RAM_SPACE, 0x3000, 4);
        let call = data.new_op(op::CALL, seq(0x1010), vec![target, argument]);
        data.op_insert_end(call, block);

        assert_eq!(
            eliminate_dead_frame_stores(&mut data, stack_pointer()),
            0,
            "a slot the callee can reach is not provably dead"
        );
    }

    #[test]
    fn saving_the_stack_pointer_into_the_frame_does_not_escape_it() {
        // A prologue stores the old stack pointer into its own slot. That keeps
        // the address inside the frame, so other slots stay provably private.
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let sp_value = data.new_varnode(REGISTER_SPACE, 0x1d0, 4);
        frame_store(&mut data, block, 0, sp_value);
        let saved = data.new_varnode(REGISTER_SPACE, 0x1f0, 8);
        frame_store(&mut data, block, 0x10, saved);
        let ret = returning(&mut data, 0x1020, None);
        data.op_insert_end(ret, block);

        assert_eq!(
            eliminate_dead_frame_stores(&mut data, stack_pointer()),
            2,
            "both prologue saves are private to the frame"
        );
    }

    #[test]
    fn a_frame_address_stored_outside_the_frame_does_escape() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let saved = data.new_varnode(REGISTER_SPACE, 0x1f0, 8);
        frame_store(&mut data, block, 0x10, saved);
        // The frame address is published through an unrelated pointer.
        let sp_value = data.new_varnode(REGISTER_SPACE, 0x1d0, 4);
        let space = data.new_constant(0, 4);
        let elsewhere = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        let store = data.new_op(op::STORE, seq(0x1030), vec![space, elsewhere, sp_value]);
        data.op_insert_end(store, block);

        assert_eq!(eliminate_dead_frame_stores(&mut data, stack_pointer()), 0);
    }

    #[test]
    fn a_store_through_an_unrelated_pointer_is_untouched() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let space = data.new_constant(0, 4);
        let address = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        let value = data.new_constant(7, 4);
        let store = data.new_op(op::STORE, seq(0x1000), vec![space, address, value]);
        data.op_insert_end(store, block);

        assert_eq!(eliminate_dead_frame_stores(&mut data, stack_pointer()), 0);
        assert!(data.live_ops().any(|(id, _)| id == store));
    }

    #[test]
    fn a_negative_frame_offset_is_recognised() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let sp = data.new_varnode(REGISTER_SPACE, 0x1d0, 4);
        // Prologues subtract, so the offset arrives as a negative constant.
        let delta = data.new_constant(0xffff_fff0, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![sp, delta]);
        let address = data.new_unique(4);
        data.op_set_output(add, Some(address));
        data.op_insert_end(add, block);
        assert_eq!(frame_offset(&data, address, stack_pointer()), Some(-0x10));
    }

    #[test]
    fn only_the_extracted_byte_of_a_masked_word_is_live() {
        // AND with 0xff consumes one byte, so a shift feeding the discarded
        // bytes is dead. Operation-level liveness would keep it.
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let word = data.new_varnode(REGISTER_SPACE, 8, 4);
        let shift = data.new_constant(8, 4);
        let shifted = data.new_op(op::INT_LEFT, seq(0x1000), vec![word, shift]);
        let high = data.new_unique(4);
        data.op_set_output(shifted, Some(high));
        data.op_insert_end(shifted, block);
        let mask = data.new_constant(0xff, 4);
        let masked = data.new_op(op::INT_AND, seq(0x1004), vec![high, mask]);
        let byte = data.new_unique(4);
        data.op_set_output(masked, Some(byte));
        data.op_insert_end(masked, block);
        let ret = returning(&mut data, 0x1008, Some(byte));
        data.op_insert_end(ret, block);

        let consumed = propagate(&data);
        assert_eq!(
            consumed.get(&byte).copied(),
            Some(0xffff_ffff),
            "a return reads every bit of its value"
        );
        assert_eq!(
            consumed.get(&high).copied(),
            Some(0xff),
            "only the low byte of the shift result is read"
        );
        assert_eq!(
            consumed.get(&word).copied(),
            Some(0),
            "shifting left by 8 puts nothing of the word into the low byte"
        );
    }

    #[test]
    fn addition_consumes_every_bit_below_the_one_read() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_varnode(REGISTER_SPACE, 8, 4);
        let right = data.new_varnode(REGISTER_SPACE, 16, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![left, right]);
        let sum = data.new_unique(4);
        data.op_set_output(add, Some(sum));
        data.op_insert_end(add, block);
        let mask = data.new_constant(0x100, 4);
        let masked = data.new_op(op::INT_AND, seq(0x1004), vec![sum, mask]);
        let bit = data.new_unique(4);
        data.op_set_output(masked, Some(bit));
        data.op_insert_end(masked, block);
        let ret = returning(&mut data, 0x1008, Some(bit));
        data.op_insert_end(ret, block);

        let consumed = propagate(&data);
        assert_eq!(consumed.get(&sum).copied(), Some(0x100));
        assert_eq!(
            consumed.get(&left).copied(),
            Some(0x1ff),
            "carries make every lower bit live"
        );
    }
}
