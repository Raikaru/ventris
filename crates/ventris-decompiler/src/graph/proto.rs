//! Call prototype recovery, ported from Ghidra 12.1.3's `FuncCallSpecs`.
//!
//! A call instruction names no arguments. Ghidra recovers them by registering a
//! *trial* for each location the calling convention could pass a parameter in,
//! deciding which trials are actually used, and rebuilding the call's operand
//! list from the survivors.
//!
//! The decision needs the value each location holds *at the call*, which is
//! exactly what [`super::guard`] materialises: the `INDIRECT` inserted before
//! the call reads the location's incoming value and defines its outgoing one.
//! So a trial is used when its incoming value was computed by this function,
//! and unused when nothing ever wrote it.
//!
//! Register parameters are contiguous. A convention assigns them in order, so a
//! location nobody wrote ends the argument list rather than leaving a hole —
//! Ghidra's `ParamListStandard` behaves the same way.
//!
//! Source authority: `ParamActive::registerTrial`,
//! `FuncCallSpecs::checkInputTrialUse`, and
//! `FuncCallSpecs::buildInputFromTrials` in `fspec.cc` at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use std::collections::BTreeSet;
use ventris_pcode::op;

use super::guard::Location;
use super::{Funcdata, OpId, VarnodeId};

/// One candidate parameter, before it is known to be used.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct Trial {
    location: Location,
    value: VarnodeId,
    used: bool,
}

/// Rebuilds every call's operand list from its recovered parameters.
///
/// `argument_locations` is the convention's parameter storage, in the order the
/// convention assigns it. Returns the number of calls given arguments.
pub fn recover_call_arguments(
    data: &mut Funcdata,
    argument_locations: &[Location],
    arity_of: &dyn Fn(u64) -> Option<usize>,
) -> usize {
    let calls: Vec<(OpId, Option<u64>)> = data
        .live_ops()
        .filter(|(_, operation)| matches!(operation.opcode, op::CALL | op::CALLIND))
        .map(|(id, operation)| {
            let target = operation
                .inputs
                .first()
                .copied()
                .map(|value| data.varnode(value))
                .filter(|value| value.def.is_none())
                .map(|value| value.offset);
            (id, target)
        })
        .collect();
    let mut recovered = 0;
    for (call, target) in calls {
        let trials = register_trials(data, call, argument_locations);
        // A known callee states its own arity. Ghidra's `FuncCallSpecs` uses
        // the callee prototype when it has one, which is the only way to see
        // an argument this function forwards without touching.
        let arity = target.and_then(arity_of);
        let arguments: Vec<VarnodeId> = match arity {
            Some(arity) => trials.iter().take(arity).map(|trial| trial.value).collect(),
            None => trials
                .iter()
                .take_while(|trial| trial.used)
                .map(|trial| trial.value)
                .collect(),
        };
        if arguments.is_empty() {
            continue;
        }
        let Some(target) = data.op(call).inputs.first().copied() else {
            continue;
        };
        let mut inputs = vec![target];
        inputs.extend(arguments);
        data.op_set_inputs(call, inputs);
        recovered += 1;
    }
    recovered
}

/// One trial per parameter location, carrying the value that reaches the call.
fn register_trials(data: &Funcdata, call: OpId, argument_locations: &[Location]) -> Vec<Trial> {
    argument_locations
        .iter()
        .copied()
        .filter_map(|location| {
            let value = incoming_value(data, call, location)?;
            Some(Trial {
                location,
                value,
                used: is_used(data, value),
            })
        })
        .collect()
}

/// The value a location holds when control reaches the call.
///
/// The guard pass put an `INDIRECT` for this location immediately before the
/// call; its first operand is that value. Without a guard there is nothing to
/// read, and the location cannot be shown to carry an argument.
fn incoming_value(data: &Funcdata, call: OpId, location: Location) -> Option<VarnodeId> {
    let block = data.op(call).parent?;
    let ops = &data.block(block).ops;
    let position = ops.iter().position(|candidate| *candidate == call)?;
    ops[..position]
        .iter()
        .rev()
        .map(|id| data.op(*id))
        .filter(|operation| operation.opcode == op::INDIRECT)
        .find_map(|operation| {
            let output = operation.output?;
            let varnode = data.varnode(output);
            let matches = varnode.space == location.space
                && varnode.offset == location.offset
                && varnode.size == location.size;
            matches.then(|| operation.inputs.first().copied())?
        })
}

/// Whether a value is real enough to be an argument.
///
/// Ghidra asks whether the value has a realistic ancestry. A value this
/// function computed does; a register nobody ever wrote does not, and treating
/// it as an argument invents one.
fn is_used(data: &Funcdata, value: VarnodeId) -> bool {
    is_used_guarded(data, value, &mut BTreeSet::new())
}

fn is_used_guarded(data: &Funcdata, value: VarnodeId, seen: &mut BTreeSet<VarnodeId>) -> bool {
    // Two merges can name each other: that is what a loop-carried value looks
    // like, and excluding only the value itself was not enough to stop the
    // walk. `decompSZS_subroutine__FPUcPUc` recursed until the stack overflowed.
    if !seen.insert(value) {
        return false;
    }
    let varnode = data.varnode(value);
    if varnode.flags.constant {
        return true;
    }
    match varnode.def {
        // A merge or a guard is only as real as what flows into it, so look
        // through them rather than accepting them outright.
        Some(def) => match data.op(def).opcode {
            op::MULTIEQUAL | op::INDIRECT => data
                .op(def)
                .inputs
                .clone()
                .into_iter()
                .filter(|operand| *operand != value)
                .any(|operand| is_used_guarded(data, operand, seen)),
            _ => true,
        },
        // A value with no definition was never computed here. It can still be
        // an argument the function forwards, but only the callee's prototype
        // can say how many, so that case is decided by the arity bound rather
        // than by claiming every convention register.
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SeqNum;
    use crate::graph::guard::{CallEffects, guard_calls};
    use crate::graph::heritage::heritage;
    use std::collections::BTreeSet;
    use ventris_lifter::{RAM_SPACE, REGISTER_SPACE};

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    fn location(offset: u64) -> Location {
        Location {
            space: REGISTER_SPACE,
            offset,
            size: 4,
        }
    }

    /// A call preceded by a write to the first argument register only.
    fn one_argument_call() -> (Funcdata, OpId) {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let constant = data.new_constant(7, 4);
        let write = data.new_op(op::COPY, seq(0x1000), vec![constant]);
        let first = data.new_varnode(REGISTER_SPACE, 0x10, 4);
        data.op_set_output(write, Some(first));
        data.op_insert_end(write, block);
        let target = data.new_varnode(RAM_SPACE, 0x3000, 4);
        let call = data.new_op(op::CALL, seq(0x1004), vec![target]);
        data.op_insert_end(call, block);

        let locations = BTreeSet::from([location(0x10), location(0x20), location(0x30)]);
        guard_calls(&mut data, &locations, &CallEffects::default());
        heritage(&mut data);
        (data, call)
    }

    #[test]
    fn a_written_argument_register_becomes_a_call_argument() {
        let (mut data, call) = one_argument_call();
        let locations = [location(0x10), location(0x20), location(0x30)];
        assert_eq!(recover_call_arguments(&mut data, &locations, &|_| None), 1);
        assert_eq!(
            data.op(call).inputs.len(),
            2,
            "the target plus one argument, not three"
        );
        let argument = data.op(call).inputs[1];
        let definition = data
            .varnode(argument)
            .def
            .expect("the argument is a value the function computed");
        let source = data.op(definition).inputs[0];
        assert_eq!(
            data.varnode(source).offset,
            7,
            "the argument carries the value written into the register"
        );
    }

    #[test]
    fn an_unwritten_register_ends_the_argument_list() {
        let (mut data, call) = one_argument_call();
        // The convention's second and third registers were never written, so
        // they cannot be arguments and no later register can be either.
        let locations = [location(0x10), location(0x20), location(0x30)];
        recover_call_arguments(&mut data, &locations, &|_| None);
        for argument in data.op(call).inputs.iter().skip(1).copied() {
            assert!(
                data.varnode(argument).flags.constant || data.varnode(argument).def.is_some(),
                "every argument is a value the function produced"
            );
        }
    }

    #[test]
    fn a_call_with_no_written_argument_register_takes_none() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let target = data.new_varnode(RAM_SPACE, 0x3000, 4);
        let call = data.new_op(op::CALL, seq(0x1000), vec![target]);
        data.op_insert_end(call, block);
        let locations = BTreeSet::from([location(0x10)]);
        guard_calls(&mut data, &locations, &CallEffects::default());
        heritage(&mut data);

        assert_eq!(
            recover_call_arguments(&mut data, &[location(0x10)], &|_| None),
            0,
            "nothing wrote the argument register"
        );
        assert_eq!(data.op(call).inputs.len(), 1);
    }

    #[test]
    fn an_argument_written_on_one_path_of_a_merge_still_counts() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
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
            let write = data.new_op(op::COPY, seq(start), vec![constant]);
            let out = data.new_varnode(REGISTER_SPACE, 0x10, 4);
            data.op_set_output(write, Some(out));
            data.op_insert_end(write, block);
        }
        let target = data.new_varnode(RAM_SPACE, 0x3000, 4);
        let call = data.new_op(op::CALL, seq(0x1030), vec![target]);
        data.op_insert_end(call, join);

        let locations = BTreeSet::from([location(0x10)]);
        guard_calls(&mut data, &locations, &CallEffects::default());
        heritage(&mut data);
        assert_eq!(
            recover_call_arguments(&mut data, &[location(0x10)], &|_| None),
            1
        );
        assert_eq!(data.op(call).inputs.len(), 2);
    }

    #[test]
    fn mutually_referring_merges_do_not_recurse_forever() {
        // Two merges naming each other is what a loop-carried value looks like.
        // Excluding only the value itself left the walk cycling between them,
        // and `decompSZS_subroutine__FPUcPUc` overflowed the stack.
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let first = data.new_varnode(REGISTER_SPACE, 0, 4);
        let second = data.new_varnode(REGISTER_SPACE, 8, 4);

        let left = data.new_op(op::MULTIEQUAL, seq(0x1000), vec![second]);
        data.op_set_output(left, Some(first));
        data.op_insert_end(left, block);

        let right = data.new_op(op::MULTIEQUAL, seq(0x1004), vec![first]);
        data.op_set_output(right, Some(second));
        data.op_insert_end(right, block);

        assert!(!is_used(&data, first), "a cycle of merges carries no value");
    }
}
