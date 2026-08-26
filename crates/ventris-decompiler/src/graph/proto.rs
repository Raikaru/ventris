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

/// What `checkInputTrialUse` decided about a candidate parameter.
///
/// Ghidra's `ParamTrial` carries three states, not two, and the difference
/// drives `ParamListStandard::fillinMap`:
///
/// * `Active` - realistic ancestry and this call is its only reader
///   (`markActive`).
/// * `Inactive` - a value the function received but never wrote, "not likely a
///   parameter but maybe" (`markInactive`). A run of these below an active trial
///   is a hole the convention had to pass through, so it is filled in.
/// * `NoUse` - "An ancestor is unaffected, an unusual input, or killed by a
///   call" (`markNoUse`). `forceNoUse` never fills these and forces every later
///   trial inactive, so the argument list cannot be extended past one.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum TrialState {
    Active,
    Inactive,
    NoUse,
}

/// One candidate parameter, before it is known to be used.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct Trial {
    location: Location,
    value: VarnodeId,
    state: TrialState,
    used: bool,
}

/// Rebuilds every call's operand list from its recovered parameters.
///
/// `argument_sections` is the convention's parameter storage in the order the
/// convention assigns it, split into resource sections
/// (`ParamListStandard::separateSections`). The candidate operands are already
/// on the call - `guard::guard_calls` appended one per location before renaming,
/// exactly as `Heritage::guardCalls` does - so a trial's value is the operand
/// renaming bound to that slot, which is what `checkInputTrialUse` reads.
///
/// Returns the number of calls whose operand list changed.
pub fn recover_call_arguments(
    data: &mut Funcdata,
    argument_sections: &[Vec<Location>],
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
        let mut trials = register_trials(data, call, argument_sections);
        if trials.is_empty() {
            continue;
        }
        if std::env::var("VENTRIS_PROBE_TRIALS").is_ok() {
            eprintln!(
                "trials @{:#x} arity={:?} {:?}",
                data.op(call).seq.address,
                target.and_then(arity_of),
                trials
                    .iter()
                    .map(|trial| (trial.location.offset, trial.used))
                    .collect::<Vec<_>>()
            );
        }
        decide_trials(&mut trials, argument_sections);
        // A known callee's arity may only *extend* the list. Ghidra constrains a
        // call site by the callee's parameters exactly when the callee's input
        // prototype is locked, where `ActionFuncLink::funcLinkInput` marks every
        // parameter's trial active outright. An unlocked, *recovered* callee
        // prototype constrains nothing: it is a guess made from the callee's own
        // body, and truncating the caller's trials to it threw away arguments
        // the trials had already justified - `getFirstFile__10JKRArchiveCFPCc`
        // lost two of `FUN_8006909c`'s three, and the values feeding them then
        // died as unread, emptying the `if` arm that computed them.
        if let Some(arity) = target.and_then(arity_of) {
            for trial in trials.iter_mut().take(arity) {
                trial.used = true;
            }
        }
        let arguments: Vec<VarnodeId> = trials
            .iter()
            .filter(|trial| trial.used)
            .map(|trial| trial.value)
            .collect();
        let Some(target) = data.op(call).inputs.first().copied() else {
            continue;
        };
        let mut inputs = vec![target];
        inputs.extend(arguments);
        if inputs != data.op(call).inputs {
            data.op_set_inputs(call, inputs);
        }
        // `buildInputFromTrials` is followed by `clearActiveInput`: the operands
        // are the arguments from here on, so nothing may re-derive them from the
        // convention's candidate storage again.
        data.clear_input_active(call);
        recovered += 1;
    }
    recovered
}

/// How long a run of unused parameter slots may be before everything after it
/// is unused too.
///
/// `ParamListStandard::fillinMap` passes `maxchain = 2` to `forceInactiveChain`.
const MAX_INACTIVE_CHAIN: usize = 2;

/// Decides which trials are parameters.
///
/// `ParamListStandard::fillinMap`: `forceNoUse`, then `forceInactiveChain`, then
/// "mark every active trial as used".
///
/// The rule is *not* "stop at the first location nobody wrote". A convention may
/// leave a slot untouched and still use the next one, so up to
/// `MAX_INACTIVE_CHAIN` consecutive *inactive* slots are holes to be filled
/// rather than the end of the list. A `NoUse` trial is different: it is not a
/// hole, it is proof the convention stopped, and `forceNoUse` forces every later
/// trial inactive so nothing beyond it can anchor a fill. Each resource section
/// is decided on its own, because a run of untouched integer registers says
/// nothing about the floating-point ones.
fn decide_trials(trials: &mut [Trial], argument_sections: &[Vec<Location>]) {
    let mut start = 0;
    for section in argument_sections {
        let stop = (start + section.len()).min(trials.len());
        if start >= stop {
            break;
        }
        // `forceNoUse`: once a slot is definitely not used, nothing after it is
        // active either.
        let mut seen_no_use = false;
        for index in start..stop {
            if seen_no_use {
                trials[index].state = TrialState::Inactive;
            } else if trials[index].state == TrialState::NoUse {
                seen_no_use = true;
            }
        }
        // `forceInactiveChain`, with `maxchain = 2`.
        let mut chain = 0;
        let mut seen_chain = false;
        let mut last_active = None;
        for index in start..stop {
            if trials[index].state == TrialState::NoUse {
                continue;
            }
            if trials[index].state == TrialState::Active {
                chain = 0;
                if !seen_chain {
                    last_active = Some(index);
                }
            } else {
                chain += 1;
                if chain > MAX_INACTIVE_CHAIN {
                    seen_chain = true;
                }
            }
            if seen_chain {
                trials[index].state = TrialState::Inactive;
            }
        }
        // "Across the range of active trials, fill in holes of inactive trials".
        if let Some(last_active) = last_active {
            for trial in &mut trials[start..=last_active] {
                if trial.state == TrialState::Inactive {
                    trial.state = TrialState::Active;
                }
            }
        }
        // "Mark every active trial as used".
        for trial in &mut trials[start..stop] {
            trial.used = trial.state == TrialState::Active;
        }
        start = stop;
    }
}

/// One trial per parameter location, carrying the value bound to its operand.
///
/// The operand *is* the value: `guard::guard_calls` appended a free varnode per
/// candidate location before renaming, and renaming replaced it with whatever
/// definition reaches the call. `checkInputTrialUse` reads exactly that -
/// `op->getIn(slot)` - and never re-derives it from the location, which it
/// cannot: the reaching definition may be a temporary, a merge, or a constant.
fn register_trials(data: &Funcdata, call: OpId, argument_sections: &[Vec<Location>]) -> Vec<Trial> {
    let operands = data.op(call).inputs.clone();
    argument_sections
        .iter()
        .flatten()
        .copied()
        .enumerate()
        .filter_map(|(index, location)| {
            // Slot zero is the callee, so the candidates start at one - Ghidra's
            // `ParamTrial::slotbase`.
            let value = operands.get(index + 1).copied()?;
            // `checkInputTrialUse`: active when the ancestry is realistic *and*
            // `ancestorOpUse` agrees that this call is its only reader; inactive
            // when the value is an unwritten function input - "not likely a
            // parameter but maybe"; definitely not used otherwise.
            let state = if is_used(data, value)
                && super::callproto::only_call_use(data, value, call, &mut BTreeSet::new())
            {
                TrialState::Active
            } else if data.varnode(value).def.is_none() && !data.varnode(value).flags.constant {
                TrialState::Inactive
            } else {
                TrialState::NoUse
            };
            Some(Trial {
                location,
                value,
                state,
                used: false,
            })
        })
        .collect()
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
            // An indirect *creation* is where backtracking stops:
            // `AncestorRealistic::execute` returns `pop_failkill` for it, which
            // is "killedbycall". The value is whatever a previous callee left in
            // the register, so this call did not prepare it and it is not an
            // argument. Looking through would reach the placeholder constant and
            // report every convention register as a parameter.
            op::INDIRECT if data.is_indirect_creation(def) => false,
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
        // `guardCalls` appends one candidate operand per parameter location
        // before renaming; the trial values are read back from those operands.
        let candidates = [location(0x10), location(0x20), location(0x30)];
        guard_calls(&mut data, &locations, &CallEffects::default(), &candidates);
        heritage(&mut data);
        (data, call)
    }

    #[test]
    fn a_written_argument_register_becomes_a_call_argument() {
        let (mut data, call) = one_argument_call();
        let locations = [location(0x10), location(0x20), location(0x30)];
        assert_eq!(
            recover_call_arguments(&mut data, &[locations.to_vec()], &|_| None),
            1
        );
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
        recover_call_arguments(&mut data, &[locations.to_vec()], &|_| None);
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
        guard_calls(&mut data, &locations, &CallEffects::default(), &[]);
        heritage(&mut data);

        assert_eq!(
            recover_call_arguments(&mut data, &[vec![location(0x10)]], &|_| None),
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
        let candidates = [location(0x10)];
        guard_calls(&mut data, &locations, &CallEffects::default(), &candidates);
        heritage(&mut data);
        assert_eq!(
            recover_call_arguments(&mut data, &[vec![location(0x10)]], &|_| None),
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
