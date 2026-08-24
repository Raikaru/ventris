//! Function prototype and return-activity recovery on the p-code graph.
//!
//! The source decisions are `ActionInputPrototype::apply`,
//! `ActionOutputPrototype::apply`, `ActionReturnRecovery::apply`,
//! `ActionActiveParam::apply`, `ActionActiveReturn::apply`, and
//! `ActionDefaultParams::apply` in `coreaction.cc`, plus
//! `FuncProto::deriveInputMap` and `FuncProto::deriveOutputMap` in
//! `fspec.hh`, and `FuncCallSpecs::finalInputCheck` and
//! `FuncCallSpecs::checkOutputTrialUse` in `fspec.cc`, at Ghidra commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.
//!
//! This graph has no prototype-model object or trial arena. The public helper
//! functions below therefore expose the observable decisions directly: an
//! entry location is an input only while its incoming value is read before a
//! write, and a return is real only when its value has function-produced
//! ancestry. `ActionActiveReturn` is the one pass that can express the result
//! decision as a graph edit, by removing an unread call output.

use std::collections::BTreeSet;

use ventris_pcode::op;

use super::action::Action;
use super::{Funcdata, OpId, SeqNum, VarnodeId};

fn before(left: SeqNum, right: SeqNum) -> bool {
    left < right
}

fn entry_value(data: &Funcdata, location: (u32, u64, u32)) -> Option<VarnodeId> {
    data.at_location(location.0, location.1, location.2)
        .iter()
        .copied()
        .find(|value| {
            let varnode = data.varnode(*value);
            !varnode.flags.constant && (varnode.flags.input || varnode.def.is_none())
        })
}

fn first_write(data: &Funcdata, location: (u32, u64, u32), excluded: VarnodeId) -> Option<SeqNum> {
    data.at_location(location.0, location.1, location.2)
        .iter()
        .copied()
        .filter(|value| *value != excluded)
        .filter_map(|value| data.varnode(value).def)
        .filter_map(|def| data.opcode_of(def).map(|_| data.op(def).seq))
        .min()
}

fn reads_before_write(data: &Funcdata, value: VarnodeId, write: Option<SeqNum>) -> bool {
    data.varnode(value)
        .descendants
        .iter()
        .copied()
        .filter_map(|use_op| data.opcode_of(use_op).map(|_| use_op))
        .any(|use_op| write.is_none_or(|write| data.op(use_op).seq <= write))
}

/// Recovers contiguous convention locations used as this function's inputs.
///
/// `candidates` is already in the convention's order. A location with no
/// entry value, no read, or only a read after its first write terminates the
/// list; later locations cannot be claimed across that ABI hole.
pub fn input_locations(data: &Funcdata, candidates: &[(u32, u64, u32)]) -> Vec<(u32, u64, u32)> {
    let mut result = Vec::new();
    for &location in candidates {
        let Some(value) = entry_value(data, location) else {
            break;
        };
        let write = first_write(data, location, value);
        if !reads_before_write(data, value, write) {
            break;
        }
        result.push(location);
    }
    result
}

fn function_produced(data: &Funcdata, value: VarnodeId, seen: &mut BTreeSet<VarnodeId>) -> bool {
    if !seen.insert(value) {
        return false;
    }
    let varnode = data.varnode(value);
    if varnode.flags.constant {
        return true;
    }
    let Some(def) = varnode.def else {
        return false;
    };
    let operation = data.op(def);
    match operation.opcode {
        op::CALL | op::CALLIND | op::CALLOTHER => false,
        // An INDIRECT states that the named operation may have changed this
        // location. When that operation is a call, the value afterwards is
        // whatever the callee left, which is not a result this function
        // produced — following the operand through would credit the caller with
        // the callee's leftover register. Ghidra reports `void` for exactly
        // these functions.
        op::INDIRECT => false,
        op::MULTIEQUAL | op::COPY => operation
            .inputs
            .iter()
            .copied()
            .filter(|input| *input != value)
            .any(|input| function_produced(data, input, seen)),
        _ => true,
    }
}
fn produced(data: &Funcdata, value: VarnodeId) -> bool {
    function_produced(data, value, &mut BTreeSet::new())
}

fn latest_location_definition(
    data: &Funcdata,
    return_op: OpId,
    value: VarnodeId,
) -> Option<VarnodeId> {
    let varnode = data.varnode(value);
    let mut best: Option<(SeqNum, OpId, VarnodeId)> = None;
    for candidate in data
        .at_location(varnode.space, varnode.offset, varnode.size)
        .iter()
        .copied()
    {
        let Some(def) = data.varnode(candidate).def else {
            continue;
        };
        if data.opcode_of(def).is_none() || !before(data.op(def).seq, data.op(return_op).seq) {
            continue;
        }
        let key = (data.op(def).seq, def, candidate);
        if best.as_ref().is_none_or(|current| key > *current) {
            best = Some(key);
        }
    }
    best.map(|(_, _, candidate)| candidate)
}

fn returned_value(data: &Funcdata, return_op: OpId) -> Option<VarnodeId> {
    let value = data.op(return_op).inputs.get(1).copied()?;
    if produced(data, value) {
        return Some(value);
    }
    // guard_returns may create a free value at the result location. Resolve it
    // to the latest definition so a prior call's result is not mistaken for a
    // value computed by this function.
    latest_location_definition(data, return_op, value)
        .filter(|candidate| produced(data, *candidate))
}

/// Reports whether at least one return carries a value produced by this graph.
pub fn returns_value(data: &Funcdata) -> bool {
    data.live_ops()
        .filter(|(_, operation)| operation.opcode == op::RETURN)
        .any(|(id, _)| returned_value(data, id).is_some())
}

/// Reports the result storage location of the first real return value.
pub fn return_location(data: &Funcdata) -> Option<(u32, u64, u32)> {
    data.live_ops()
        .filter(|(_, operation)| operation.opcode == op::RETURN)
        .find_map(|(id, _)| {
            let value = returned_value(data, id)?;
            let varnode = data.varnode(value);
            Some((varnode.space, varnode.offset, varnode.size))
        })
}

fn consumed_value(data: &Funcdata, value: VarnodeId, seen: &mut BTreeSet<VarnodeId>) -> bool {
    if !seen.insert(value) {
        return false;
    }
    let descendants: Vec<OpId> = data.varnode(value).descendants.iter().copied().collect();
    for descendant in descendants {
        let Some(opcode) = data.opcode_of(descendant) else {
            continue;
        };
        match opcode {
            // These operations preserve the value's identity for activity
            // analysis. An unused chain of copies is still dead.
            op::COPY | op::INDIRECT | op::MULTIEQUAL => {
                if let Some(output) = data.op(descendant).output
                    && consumed_value(data, output, seen)
                {
                    return true;
                }
            }
            _ => return true,
        }
    }
    false
}

/// Reports whether a call's result reaches a real consumer.
pub fn call_result_consumed(data: &Funcdata, call: OpId) -> bool {
    let Some(output) = data.op(call).output else {
        return false;
    };
    consumed_value(data, output, &mut BTreeSet::new())
}

/// Removes return operands that are merely values left by a callee.
pub struct ActionReturnRecovery;

impl Action for ActionReturnRecovery {
    fn name(&self) -> &'static str {
        "return-recovery"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let returns: Vec<OpId> = data
            .live_ops()
            .filter(|(_, operation)| operation.opcode == op::RETURN)
            .map(|(id, _)| id)
            .collect();
        let mut changed = 0;
        for return_op in returns {
            let inputs = data.op(return_op).inputs.clone();
            if inputs.len() <= 1 {
                continue;
            }
            let mut kept = Vec::with_capacity(inputs.len());
            kept.push(inputs[0]);
            for value in inputs.iter().copied().skip(1) {
                let real = returned_value(data, return_op) == Some(value) || produced(data, value);
                if real {
                    kept.push(value);
                }
            }
            if kept.len() != inputs.len() {
                data.op_set_inputs(return_op, kept);
                changed += 1;
            }
        }
        changed
    }
}

/// Drops an unread result at each call site.
pub struct ActionActiveReturn;

impl Action for ActionActiveReturn {
    fn name(&self) -> &'static str {
        "active-return"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let calls: Vec<OpId> = data
            .live_ops()
            .filter(|(_, operation)| {
                matches!(operation.opcode, op::CALL | op::CALLIND | op::CALLOTHER)
            })
            .map(|(id, _)| id)
            .collect();
        let mut changed = 0;
        for call in calls {
            if data.op(call).output.is_some() && !call_result_consumed(data, call) {
                data.op_set_output(call, None);
                changed += 1;
            }
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{RAM_SPACE, REGISTER_SPACE};

    fn seq(address: u64, order: u32) -> SeqNum {
        SeqNum { address, order }
    }

    #[test]
    fn input_locations_stop_at_the_first_untouched_register() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let first = data.new_varnode(REGISTER_SPACE, 0x10, 4);
        data.mark_input(first);
        let untouched = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        data.mark_input(untouched);
        let later = data.new_varnode(REGISTER_SPACE, 0x30, 4);
        data.mark_input(later);
        let copy = data.new_op(op::COPY, seq(0x1000, 0), vec![first]);
        let copy_out = data.new_unique(4);
        data.op_set_output(copy, Some(copy_out));
        data.op_insert_end(copy, block);
        let later_copy = data.new_op(op::COPY, seq(0x1000, 1), vec![later]);
        let later_out = data.new_unique(4);
        data.op_set_output(later_copy, Some(later_out));
        data.op_insert_end(later_copy, block);
        assert_eq!(
            input_locations(
                &data,
                &[
                    (REGISTER_SPACE, 0x10, 4),
                    (REGISTER_SPACE, 0x20, 4),
                    (REGISTER_SPACE, 0x30, 4),
                ],
            ),
            vec![(REGISTER_SPACE, 0x10, 4)]
        );
    }

    #[test]
    fn input_locations_do_not_claim_an_unread_first_register() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let first = data.new_varnode(REGISTER_SPACE, 0x10, 4);
        data.mark_input(first);
        let second = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        data.mark_input(second);
        let copy = data.new_op(op::COPY, seq(0x1000, 0), vec![second]);
        let copy_out = data.new_unique(4);
        data.op_set_output(copy, Some(copy_out));
        data.op_insert_end(copy, block);
        assert!(
            input_locations(
                &data,
                &[(REGISTER_SPACE, 0x10, 4), (REGISTER_SPACE, 0x20, 4)]
            )
            .is_empty()
        );
    }

    fn return_graph(from_call: bool) -> (Funcdata, OpId, VarnodeId) {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let result = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        let source = if from_call {
            let target = data.new_varnode(RAM_SPACE, 0x3000, 4);
            let call = data.new_op(op::CALL, seq(0x1000, 0), vec![target]);
            data.op_set_output(call, Some(result));
            data.op_insert_end(call, block);
            result
        } else {
            let constant = data.new_constant(9, 4);
            let copy = data.new_op(op::COPY, seq(0x1000, 0), vec![constant]);
            data.op_set_output(copy, Some(result));
            data.op_insert_end(copy, block);
            result
        };
        let link = data.new_varnode(REGISTER_SPACE, 0x1f0, 8);
        let ret = data.new_op(op::RETURN, seq(0x1004, 0), vec![link, source]);
        data.op_insert_end(ret, block);
        (data, ret, result)
    }

    #[test]
    fn callee_left_result_is_not_a_function_return() {
        let (data, _, _) = return_graph(true);
        assert!(!returns_value(&data));
        assert_eq!(return_location(&data), None);
    }

    #[test]
    fn computed_result_register_is_a_function_return() {
        let (data, _, _) = return_graph(false);
        assert!(returns_value(&data));
        assert_eq!(return_location(&data), Some((REGISTER_SPACE, 0x20, 4)));
    }

    #[test]
    fn return_recovery_drops_only_the_callee_result() {
        let (mut data, ret, _) = return_graph(true);
        assert_eq!(ActionReturnRecovery.apply(&mut data), 1);
        assert_eq!(data.op(ret).inputs.len(), 1);
    }

    #[test]
    fn an_unread_call_result_is_dropped() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let target = data.new_varnode(RAM_SPACE, 0x3000, 4);
        let call = data.new_op(op::CALL, seq(0x1000, 0), vec![target]);
        let output = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        data.op_set_output(call, Some(output));
        data.op_insert_end(call, block);
        assert!(!call_result_consumed(&data, call));
        assert_eq!(ActionActiveReturn.apply(&mut data), 1);
        assert!(data.op(call).output.is_none());
    }

    #[test]
    fn a_returned_call_result_is_consumed() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let target = data.new_varnode(RAM_SPACE, 0x3000, 4);
        let call = data.new_op(op::CALL, seq(0x1000, 0), vec![target]);
        let output = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        data.op_set_output(call, Some(output));
        data.op_insert_end(call, block);
        let link = data.new_varnode(REGISTER_SPACE, 0x1f0, 8);
        let ret = data.new_op(op::RETURN, seq(0x1004, 0), vec![link, output]);
        data.op_insert_end(ret, block);
        assert!(call_result_consumed(&data, call));
        assert_eq!(ActionActiveReturn.apply(&mut data), 0);
        assert!(data.op(call).output.is_some());
    }
}
