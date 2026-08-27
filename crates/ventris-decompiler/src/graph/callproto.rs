//! Call and parameter trial recovery on the mutable p-code graph.
//!
//! This module ports the trial decisions from Ghidra 12.1.3 at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`: `ParamTrial` and
//! `ParamActive` in `fspec.hh`/`fspec.cc`, `AncestorRealistic::execute` in
//! `funcdata.hh`/`funcdata_varnode.cc`, `FuncCallSpecs::checkInputTrialUse`,
//! `checkOutputTrialUse`, `buildInputFromTrials`, `buildOutputFromTrials`,
//! `deriveInputMap`, `deriveOutputMap`, and `ParamListStandard::assignMap` in
//! `fspec.hh`/`fspec.cc`, and `ActionActiveParam::apply`,
//! `ActionActiveReturn::apply`, `ActionFuncLink::apply`,
//! `ActionFuncLinkOutOnly::apply`, and `ActionParamDouble::apply` in
//! `coreaction.cc`. The graph API has no prototype-model, alias-checker, or
//! call-spec objects, so the public functions below expose the decisions that
//! can be represented by graph ancestry and convention locations. The
//! warning-only and prototype-defaulting actions (`ActionDefaultParams`,
//! `ActionUnjustifiedParams`, `ActionExtraPopSetup`, and
//! `ActionPrototypeWarnings`) have no graph equivalent: there is no model,
//! scope, stack-space descriptor, or warning sink to mutate here.

use std::collections::{BTreeMap, BTreeSet};

use ventris_pcode::op;

use super::action::Action;
use super::guard::Location;
use super::{Funcdata, OpId, VarnodeId};

/// One candidate parameter at a call site or function entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trial {
    pub location: Location,
    /// The CALL input slot. Ghidra reserves slot zero for the callee, so the
    /// first trial is slot one even though `used()` omits the target itself.
    pub slot: usize,
    pub value: Option<VarnodeId>,
    pub state: TrialState,
}

impl Trial {
    /// Port of `ParamTrial::markActive`.
    pub fn mark_active(&mut self) {
        self.state = TrialState::Active;
    }

    /// Port of `ParamTrial::markNoUse`.
    pub fn mark_no_use(&mut self) {
        self.state = TrialState::NoUse;
    }

    /// Port of `ParamTrial::markInactive`.
    pub fn mark_inactive(&mut self) {
        self.state = TrialState::Inactive;
    }

    pub fn is_active(&self) -> bool {
        matches!(self.state, TrialState::Active)
    }

    pub fn is_checked(&self) -> bool {
        !matches!(self.state, TrialState::Unchecked)
    }
}

/// The activity state of one parameter trial.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TrialState {
    Unchecked,
    Active,
    Inactive,
    NoUse,
}

/// Trials in convention order.
///
/// Ghidra's container also tracks model entries, exclusion groups, stack
/// placeholders, and analysis passes. The graph has none of those objects;
/// it retains only the trial order and the state needed to rebuild a CALL.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParamActive {
    trials: Vec<Trial>,
}

impl ParamActive {
    pub fn new() -> Self {
        Self::default()
    }

    /// Port of `ParamActive::registerTrial`.
    pub fn register(&mut self, location: Location) {
        // `ParamTrial::slotbase` starts at one because CALL input zero is the
        // callee expression. Keeping that numbering makes a trial directly
        // indexable in the operation when a call has already been linked.
        let slot = self.trials.len() + 1;
        self.trials.push(Trial {
            location,
            slot,
            value: None,
            state: TrialState::Unchecked,
        });
    }

    /// Borrow all trials for callers that need to inspect the non-used suffix.
    pub fn trials(&self) -> &[Trial] {
        &self.trials
    }

    /// Mutable access is intentionally narrow: it lets a graph adapter attach
    /// the value found at a call site without exposing the backing collection.
    pub fn trials_mut(&mut self) -> &mut [Trial] {
        &mut self.trials
    }

    /// Settle trials whose values have already been attached by a call-site
    /// collector. If a value was not attached, use the entry value at the
    /// exact location; this is the active-function analogue of
    /// `FuncCallSpecs::collectOutputTrialVarnodes`.
    ///
    /// `AncestorRealistic::execute` returns failure for an untouched input
    /// before it can inspect the rest of the graph (`funcdata_varnode.cc`,
    /// lines 2233-2239). `FuncCallSpecs::checkInputTrialUse` then marks an
    /// input Varnode `inactive`, not `defnouse` (lines 5644-5648). We retain
    /// that distinction: an entry value may be a pass-through parameter, while
    /// a value left by a callee is definitely not this function's parameter.
    pub fn final_trial_check(&mut self, data: &Funcdata) {
        for trial in &mut self.trials {
            if trial.value.is_none() {
                trial.value = entry_value(data, trial.location);
            }
            let Some(value) = trial.value else {
                trial.mark_no_use();
                continue;
            };
            match ancestor_verdict(data, value) {
                AncestorVerdict::Realistic => trial.mark_active(),
                AncestorVerdict::UntouchedInput => trial.mark_inactive(),
                AncestorVerdict::CalleeLeftBehind | AncestorVerdict::Unknown => trial.mark_no_use(),
            }
        }
    }

    /// Port of the contiguous part of `ParamListStandard::fillinMap`: active
    /// trials are formal parameters only until the first hole in convention
    /// order. In particular, a later active register cannot jump over an
    /// unused trial and become a parameter.
    pub fn used(&self) -> Vec<&Trial> {
        self.trials
            .iter()
            .take_while(|trial| trial.is_active())
            .collect()
    }

    /// Port of `ParamActive::sortFixedPosition`. Fixed vararg positions are
    /// not represented by this graph, whose input slice is already in ABI
    /// order; sorting by the original slot is therefore the stable equivalent.
    pub fn sort_fixed_position(&mut self) {
        self.trials.sort_by_key(|trial| trial.slot);
    }
}

const ANCESTOR_RECURSION_LIMIT: usize = 64;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum AncestorVerdict {
    Realistic,
    UntouchedInput,
    CalleeLeftBehind,
    Unknown,
}

fn combine_ancestry(results: impl IntoIterator<Item = AncestorVerdict>) -> AncestorVerdict {
    let mut saw_callee = false;
    let mut saw_unknown = false;
    for result in results {
        match result {
            AncestorVerdict::UntouchedInput => return AncestorVerdict::UntouchedInput,
            AncestorVerdict::CalleeLeftBehind => saw_callee = true,
            AncestorVerdict::Unknown => saw_unknown = true,
            AncestorVerdict::Realistic => {}
        }
    }
    if saw_callee {
        AncestorVerdict::CalleeLeftBehind
    } else if saw_unknown {
        AncestorVerdict::Unknown
    } else {
        AncestorVerdict::Realistic
    }
}

/// Walk backwards through the graph in the same places as
/// `AncestorRealistic::enterNode` (`funcdata_varnode.cc`, lines 2060-2166).
///
/// The graph has no `isUnaffected`, `isPersist`, `isDirectWrite`,
/// `isIndirectCreation`, or `isIndirectZero` flags. `input` is consequently
/// the only representable untouched-entry state; an `INDIRECT` is followed
/// through its value operand, as Ghidra does for a non-creation indirect. A
/// `CALL`-defined value is kept distinct as a value left behind by a callee.
/// Following an `INDIRECT` whose input is not itself a CALL result is WEAKER
/// than Ghidra for a call-created indirect output, because the missing
/// creation bit could make this walk fire where Ghidra declines. Call-site
/// recovery therefore reads operand zero of the guard (the pre-call value),
/// never the guard output.
fn ancestor_walk(
    data: &Funcdata,
    value: VarnodeId,
    depth: usize,
    seen: &mut BTreeSet<VarnodeId>,
) -> AncestorVerdict {
    if depth >= ANCESTOR_RECURSION_LIMIT {
        // The native implementation bounds equivalent ancestry walks with
        // `trim_recurse_max`; the graph has no Architecture knob, so use a
        // fixed conservative ceiling rather than risking an unbounded cycle.
        return AncestorVerdict::Unknown;
    }
    if !seen.insert(value) {
        // `AncestorRealistic::enterNode` treats a marked node as
        // `pop_success` to trim loop-carried cycles.
        return AncestorVerdict::Realistic;
    }

    let varnode = data.varnode(value);
    if varnode.flags.constant {
        return AncestorVerdict::Realistic;
    }
    let Some(def) = varnode.def else {
        // Ghidra's initial `execute` rejects an input Varnode before traversal;
        // the caller later records it as inactive so a known callee arity can
        // still preserve a pass-through argument. Free graph values are also
        // conservative untouched entries until heritage marks them otherwise.
        return AncestorVerdict::UntouchedInput;
    };
    if data.opcode_of(def).is_none() {
        return AncestorVerdict::Unknown;
    }
    let operation = data.op(def);
    let inputs = operation.inputs.clone();
    match operation.opcode {
        // A value defined by a call is exactly the "callee left this behind"
        // case that must not be credited to the caller. This is the graph
        // equivalent of `AncestorRealistic`'s `indirectZero`/`killedbycall`
        // failure path.
        op::CALL | op::CALLIND | op::CALLOTHER => AncestorVerdict::CalleeLeftBehind,
        // Guards preserve the value operand's ancestry. The cause operand is
        // an annotation, not data-flow, and is deliberately ignored.
        op::INDIRECT => inputs
            .first()
            .copied()
            .map_or(AncestorVerdict::Unknown, |input| {
                ancestor_walk(data, input, depth + 1, seen)
            }),
        // Phi values require every incoming path to be plausible. An
        // untouched or callee-left path therefore cannot be hidden by a
        // computed sibling; this is the conservative result of
        // `uponPop(pop_fail)` and `uponPop(pop_failkill)`.
        op::MULTIEQUAL => combine_ancestry(
            inputs
                .iter()
                .copied()
                .map(|input| ancestor_walk(data, input, depth + 1, seen)),
        ),
        // Transparent copies and pieces are the graph equivalents of the
        // recursive COPY/SUBPIECE cases in `enterNode`; they must not turn a
        // prior call result or untouched input into a real argument.
        op::COPY | op::SUBPIECE => inputs
            .first()
            .copied()
            .map_or(AncestorVerdict::Unknown, |input| {
                ancestor_walk(data, input, depth + 1, seen)
            }),
        op::PIECE => combine_ancestry(
            inputs
                .iter()
                .copied()
                .map(|input| ancestor_walk(data, input, depth + 1, seen)),
        ),
        // LOAD and arithmetic/logical operations are `pop_solid` in Ghidra:
        // the function performed a real operation even if its source is an
        // ordinary incoming value.
        _ => AncestorVerdict::Realistic,
    }
}

fn ancestor_verdict(data: &Funcdata, value: VarnodeId) -> AncestorVerdict {
    ancestor_walk(data, value, 0, &mut BTreeSet::new())
}

/// Whether the value at a trial has an ancestry that makes it a real argument.
pub fn ancestor_realistic(data: &Funcdata, value: VarnodeId) -> bool {
    matches!(ancestor_verdict(data, value), AncestorVerdict::Realistic)
}

/// The traversal outcomes of `AncestorRealistic`.
///
/// Ghidra's `pop_success`, `pop_fail`, `pop_failkill` and `pop_solid`. The last
/// two are what make the analysis more than a reachability walk: `pop_solid`
/// says the function performed a real operation on the way to the parameter, and
/// `pop_failkill` says one path arrived from a location a callee had destroyed.
/// Solid movement on one path of a merge overrides a failkill on another; a
/// failkill without solid movement is a failure.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Pop {
    Success,
    Fail,
    FailKill,
    Solid,
}

/// One frame of the depth-first ancestor traversal.
struct AncestorState {
    op: OpId,
    slot: usize,
    seen_solid: bool,
    seen_kill: bool,
}

/// Whether the value reaching `slot` of `op` arrived the way a parameter does.
///
/// A faithful port of `AncestorRealistic::execute`, `enterNode` and `uponPop`
/// (`funcdata_varnode.cc`). The conservative walk this replaces answered a
/// different question - "is anything on any path suspicious" - and so refused
/// arguments Ghidra accepts and accepted some it refuses.
///
/// Three of Ghidra's tests have no representation here and are read as false,
/// which is their default for operations this graph builds: `isIncidentalCopy`
/// (a copy the lifter marks as bookkeeping), `isStoreUnmapped`, and
/// `isReturnAddress` on a guard output. Each is set by a Ghidra pass this port
/// does not have; none can be inferred without inventing the fact.
pub fn ancestor_realistic_at(data: &Funcdata, op: OpId, slot: usize) -> bool {
    // `checkInputTrialUse` passes `allowFail = true` for a register location and
    // `false` only for a stack one, so a failkill that solid movement covers is
    // not an outright failure here.
    let allow_failing_path = data
        .op(op)
        .inputs
        .get(slot)
        .copied()
        .is_some_and(|value| data.varnode(value).space != ventris_lifter::RAM_SPACE);
    let Some(start) = data.op(op).inputs.get(slot).copied() else {
        return false;
    };
    // "If the parameter itself is an input, we don't consider this realistic, we
    // expect to see active movement into the parameter."
    if data.varnode(start).flags.input {
        return false;
    }
    let mut marked: BTreeSet<VarnodeId> = BTreeSet::new();
    let mut stack: Vec<AncestorState> = vec![AncestorState {
        op,
        slot,
        seen_solid: false,
        seen_kill: false,
    }];
    let mut multi_depth = 0usize;
    let mut command = None;
    // The traversal is bounded the way Ghidra bounds it with `trim_recurse_max`.
    for _ in 0..ANCESTOR_TRAVERSAL_STEPS {
        let popped = match command.take() {
            None => enter_ancestor_node(data, &mut stack, &mut marked, &mut multi_depth),
            Some(pop) => Some(pop),
        };
        let Some(pop) = popped else { continue };
        // `uponPop`.
        let Some(state) = stack.last() else {
            return matches!(pop, Pop::Success | Pop::Solid);
        };
        if data.op(state.op).opcode != op::MULTIEQUAL {
            stack.pop();
            if stack.is_empty() {
                return matches!(pop, Pop::Success | Pop::Solid);
            }
            command = Some(pop);
            continue;
        }
        let arity = data.op(state.op).inputs.len();
        if pop == Pop::Fail {
            multi_depth = multi_depth.saturating_sub(1);
            stack.pop();
            if stack.is_empty() {
                return false;
            }
            command = Some(Pop::Fail);
            continue;
        }
        // Ghidra records the "solid" and "failkill" observations on the frame
        // *below* the merge, which is where they are read once every sibling has
        // been traversed.
        let below = stack.len().checked_sub(2);
        if pop == Pop::Solid && multi_depth == 1 && arity == 2 {
            if let Some(below) = below {
                stack[below].seen_solid = true;
            }
        } else if pop == Pop::FailKill {
            if let Some(below) = below {
                stack[below].seen_kill = true;
            }
        }
        let state = stack.last_mut().expect("a frame");
        state.slot += 1;
        if state.slot < arity {
            continue;
        }
        let (solid, kill) = below
            .map(|below| (stack[below].seen_solid, stack[below].seen_kill))
            .unwrap_or((false, false));
        // With `allowFailingPath` set, solid movement makes the merge a success
        // even where one path arrived from a killed location: Ghidra slates the
        // trial for the extra conditional-execution test rather than failing it.
        // This graph has no cond-exe test, so the solid path stands.
        let outcome = if solid {
            if kill && !allow_failing_path {
                Pop::Fail
            } else {
                Pop::Success
            }
        } else if kill {
            Pop::FailKill
        } else {
            Pop::Success
        };
        multi_depth = multi_depth.saturating_sub(1);
        stack.pop();
        if stack.is_empty() {
            return matches!(outcome, Pop::Success | Pop::Solid);
        }
        command = Some(outcome);
    }
    false
}

/// How many traversal steps `ancestor_realistic_at` may take.
///
/// Ghidra bounds the equivalent walk with `Architecture::trim_recurse_max`; this
/// graph has no such knob, so the bound is fixed.
const ANCESTOR_TRAVERSAL_STEPS: usize = 4096;

/// `AncestorRealistic::enterNode`, returning `None` to push a new frame.
fn enter_ancestor_node(
    data: &Funcdata,
    stack: &mut Vec<AncestorState>,
    marked: &mut BTreeSet<VarnodeId>,
    multi_depth: &mut usize,
) -> Option<Pop> {
    let state = stack.last().expect("a frame");
    let value = data.op(state.op).inputs.get(state.slot).copied()?;
    // A value already visited truncates the traversal; the proper result comes
    // back along the first path.
    if marked.contains(&value) {
        return Some(Pop::Success);
    }
    let varnode = data.varnode(value);
    if !varnode.flags.written {
        if varnode.flags.input {
            if data.is_unaffected(value) {
                return Some(Pop::Fail);
            }
            // A global input is not active movement, but it is a possibility.
            if varnode.space == ventris_lifter::RAM_SPACE {
                return Some(Pop::Success);
            }
            if !varnode.flags.direct_write {
                return Some(Pop::Fail);
            }
        }
        // "Probably a normal parameter, not active movement, but valid".
        return Some(Pop::Success);
    }
    marked.insert(value);
    let definition = varnode.def?;
    let opcode = data.op(definition).opcode;
    match opcode {
        op::INDIRECT => {
            if data.is_indirect_creation(definition) {
                // Backtracking stops at a call. A creation whose placeholder is
                // the indirect zero is killedbycall outright.
                let zero = data
                    .op(definition)
                    .inputs
                    .first()
                    .copied()
                    .is_some_and(|input| data.varnode(input).flags.indirect_creation);
                return Some(if zero { Pop::FailKill } else { Pop::Success });
            }
            // Flow goes *through* a call: follow the value operand.
            stack.push(AncestorState {
                op: definition,
                slot: 0,
                seen_solid: false,
                seen_kill: false,
            });
            None
        }
        op::COPY | op::SUBPIECE => {
            let output = data.op(definition).output;
            let source = data.op(definition).inputs.first().copied()?;
            let incidental = match output {
                Some(output) => {
                    let out = data.varnode(output);
                    let inp = data.varnode(source);
                    out.flags.unique || (out.space == inp.space && out.offset == inp.offset)
                }
                None => false,
            };
            if incidental {
                stack.push(AncestorState {
                    op: definition,
                    slot: 0,
                    seen_solid: false,
                    seen_kill: false,
                });
                return None;
            }
            // "For other COPIES, do a minimal traversal to rule out unaffected
            // or other invalid inputs, but otherwise treat it as valid, active,
            // movement into the parameter."
            let mut cursor = source;
            for _ in 0..ANCESTOR_TRAVERSAL_STEPS {
                let held = data.varnode(cursor);
                if !marked.contains(&cursor) && held.flags.input {
                    if data.is_unaffected(cursor) || !held.flags.direct_write {
                        return Some(Pop::Fail);
                    }
                }
                let Some(next) = held.def else { break };
                cursor = match data.op(next).opcode {
                    op::COPY | op::SUBPIECE => match data.op(next).inputs.first().copied() {
                        Some(operand) => operand,
                        None => break,
                    },
                    // Follow the least significant piece.
                    op::PIECE => match data.op(next).inputs.get(1).copied() {
                        Some(operand) => operand,
                        None => break,
                    },
                    _ => break,
                };
            }
            Some(Pop::Solid)
        }
        op::MULTIEQUAL => {
            *multi_depth += 1;
            stack.push(AncestorState {
                op: definition,
                slot: 0,
                seen_solid: false,
                seen_kill: false,
            });
            None
        }
        // "Any other LOAD or arithmetic/logical operation is viewed as solid
        // movement." A `PIECE` reaching a location wider than the trial is
        // artificial data flow, but the trial's width is the operand's here, so
        // that arm cannot be distinguished and the solid answer stands.
        _ => Some(Pop::Solid),
    }
}

fn entry_value(data: &Funcdata, location: Location) -> Option<VarnodeId> {
    let values = data.at_location(location.space, location.offset, location.size);
    values
        .iter()
        .copied()
        .find(|value| {
            let varnode = data.varnode(*value);
            varnode.flags.input && varnode.def.is_none()
        })
        .or_else(|| {
            values
                .iter()
                .copied()
                .find(|value| data.varnode(*value).def.is_none())
        })
}

/// Find the value entering one call's guarded location. Ghidra's
/// `collectOutputTrialVarnodes`/input trial machinery associates a trial with
/// the exact storage Varnode immediately before the call; the graph's guard
/// `INDIRECT` carries that value as operand zero.
fn incoming_value(data: &Funcdata, call: OpId, location: Location) -> Option<VarnodeId> {
    let block = data.op(call).parent?;
    let ops = &data.block(block).ops;
    let position = ops.iter().position(|candidate| *candidate == call)?;
    for id in ops[..position].iter().rev().copied() {
        let operation = data.op(id);
        if operation.opcode != op::INDIRECT {
            continue;
        }
        let Some(output) = operation.output else {
            continue;
        };
        let out = data.varnode(output);
        if out.space == location.space && out.offset == location.offset && out.size == location.size
        {
            return operation.inputs.first().copied();
        }
    }
    // A caller that has already been linked may carry the trial directly in
    // CALL input slots. This is also the faithful fallback for a locked
    // prototype, where `ActionFuncLink` inserts the Varnode instead of a guard.
    for value in data.op(call).inputs.iter().copied().skip(1) {
        let varnode = data.varnode(value);
        if varnode.space == location.space
            && varnode.offset == location.offset
            && varnode.size == location.size
        {
            return Some(value);
        }
        let Some(def) = varnode.def else {
            continue;
        };
        let operation = data.op(def);
        if operation.opcode != op::PIECE {
            continue;
        }
        if let Some(piece) = operation.inputs.iter().copied().find(|piece| {
            let piece = data.varnode(*piece);
            piece.space == location.space
                && piece.offset == location.offset
                && piece.size == location.size
        }) {
            return Some(piece);
        }
    }
    None
}
fn guard_is_for_call(data: &Funcdata, guard: OpId, call: OpId) -> bool {
    let Some(block) = data.op(call).parent else {
        return false;
    };
    if data.op(guard).parent != Some(block) {
        return false;
    }
    let Some(guard_pos) = data
        .block(block)
        .ops
        .iter()
        .position(|candidate| *candidate == guard)
    else {
        return false;
    };
    let Some(call_pos) = data
        .block(block)
        .ops
        .iter()
        .position(|candidate| *candidate == call)
    else {
        return false;
    };
    guard_pos < call_pos
        && data.block(block).ops[guard_pos + 1..call_pos]
            .iter()
            .all(|candidate| data.op(*candidate).opcode == op::INDIRECT)
}

/// Approximate `Funcdata::ancestorOpUse` for the guard-shaped graph. Ghidra
/// follows copies and merges until every leaf is used only by the CALL or its
/// immediately preceding `INDIRECT`; any other reader makes a realistic value
/// inactive (`fspec.cc` 5626-5643). The graph has no call-spec edge on a guard,
/// so adjacency in the containing block is the available equivalent.
pub(super) fn only_call_use(
    data: &Funcdata,
    value: VarnodeId,
    call: OpId,
    seen: &mut BTreeSet<VarnodeId>,
) -> bool {
    if !seen.insert(value) {
        return true;
    }
    let descendants: Vec<OpId> = data.varnode(value).descendants.iter().copied().collect();
    if descendants.is_empty() {
        return false;
    }
    for descendant in descendants {
        let Some(opcode) = data.opcode_of(descendant) else {
            continue;
        };
        if descendant == call {
            continue;
        }
        if opcode == op::INDIRECT && guard_is_for_call(data, descendant, call) {
            continue;
        }
        if matches!(opcode, op::COPY | op::MULTIEQUAL | op::PIECE | op::SUBPIECE)
            && let Some(output) = data.op(descendant).output
            && only_call_use(data, output, call, seen)
        {
            continue;
        }
        return false;
    }
    true
}
fn transparent_origin(data: &Funcdata, value: VarnodeId, depth: usize) -> VarnodeId {
    if depth >= ANCESTOR_RECURSION_LIMIT {
        return value;
    }
    let Some(def) = data.varnode(value).def else {
        return value;
    };
    let operation = data.op(def);
    if matches!(operation.opcode, op::COPY | op::INDIRECT)
        && let Some(input) = operation.inputs.first().copied()
    {
        return transparent_origin(data, input, depth + 1);
    }
    value
}

fn call_like(opcode: i32) -> bool {
    matches!(opcode, op::CALL | op::CALLIND | op::CALLOTHER)
}

fn calls(data: &Funcdata) -> Vec<OpId> {
    data.live_ops()
        .filter(|(_, operation)| call_like(operation.opcode))
        .map(|(id, _)| id)
        .collect()
}

fn collapse_piece(data: &Funcdata, first: VarnodeId, second: VarnodeId) -> Option<VarnodeId> {
    // Ghidra also accepts a model-approved SplitVarnode pair even before a
    // PIECE/SUBPIECE is explicit (`coreaction.cc` 1665-1689). Requiring an
    // explicit graph relation is STRONGER than that check: without a
    // PrototypeModel this lane may decline a legitimate pair rather than
    // inventing a wider value.
    // If both halves are SUBPIECEs of the same whole, the whole is the one
    // logical parameter. This mirrors `ActionParamDouble`'s `SplitVarnode`
    // join branch without requiring a target endianness object.
    let first = transparent_origin(data, first, 0);
    let second = transparent_origin(data, second, 0);
    let first_def = data.varnode(first).def;
    let second_def = data.varnode(second).def;
    if let (Some(first_def), Some(second_def)) = (first_def, second_def) {
        let first_op = data.op(first_def);
        let second_op = data.op(second_def);
        if first_op.opcode == op::SUBPIECE
            && second_op.opcode == op::SUBPIECE
            && first_op.inputs.first() == second_op.inputs.first()
        {
            let whole = first_op.inputs.first().copied()?;
            let first_offset = first_op
                .inputs
                .get(1)
                .copied()
                .filter(|offset| data.varnode(*offset).flags.constant)
                .map(|offset| data.varnode(offset).offset)?;
            let second_offset = second_op
                .inputs
                .get(1)
                .copied()
                .filter(|offset| data.varnode(*offset).flags.constant)
                .map(|offset| data.varnode(offset).offset)?;
            let whole_size = u64::from(data.varnode(whole).size);
            let first_size = u64::from(data.varnode(first).size);
            let second_size = u64::from(data.varnode(second).size);
            let adjacent_offsets = (first_offset == 0 && second_offset == first_size)
                || (second_offset == 0 && first_offset == second_size);
            if adjacent_offsets
                && first_offset.saturating_add(first_size) <= whole_size
                && second_offset.saturating_add(second_size) <= whole_size
            {
                return Some(whole);
            }
        }
    }

    // A pre-existing PIECE is another representation used by Ghidra when
    // heritage grouped two adjacent locations. Find it through the first
    // half's descendant list so no new op is allocated for a read-only query.
    data.varnode(first)
        .descendants
        .iter()
        .copied()
        .find_map(|descendant| {
            let operation = data.op(descendant);
            (operation.opcode == op::PIECE
                && operation.inputs.len() >= 2
                && ((operation.inputs[0] == first && operation.inputs[1] == second)
                    || (operation.inputs[0] == second && operation.inputs[1] == first)))
                .then_some(operation.output)
                .flatten()
        })
}

fn adjacent(first: Location, second: Location) -> bool {
    first.space == second.space
        && first.offset.saturating_add(u64::from(first.size)) == second.offset
}

fn collapse_wide_arguments(
    data: &Funcdata,
    locations: &[Location],
    values: &[VarnodeId],
) -> Vec<VarnodeId> {
    let mut result = Vec::with_capacity(values.len());
    let mut index = 0;
    while index < values.len() {
        if index + 1 < values.len()
            && adjacent(locations[index], locations[index + 1])
            && let Some(whole) = collapse_piece(data, values[index], values[index + 1])
        {
            result.push(whole);
            index += 2;
        } else {
            result.push(values[index]);
            index += 1;
        }
    }
    result
}

fn trial_values(
    data: &Funcdata,
    call: OpId,
    argument_locations: &[Location],
) -> (ParamActive, Vec<VarnodeId>) {
    let mut active = ParamActive::new();
    let mut values = Vec::new();
    let mut stop_after_inactive = false;
    for &location in argument_locations {
        if stop_after_inactive {
            break;
        }
        active.register(location);
        let value = incoming_value(data, call, location);
        let Some(value) = value else {
            active
                .trials_mut()
                .last_mut()
                .expect("registered trial")
                .mark_no_use();
            break;
        };
        let trial = active.trials_mut().last_mut().expect("registered trial");
        trial.value = Some(value);
        match ancestor_verdict(data, value) {
            AncestorVerdict::Realistic
                if only_call_use(data, value, call, &mut BTreeSet::new()) =>
            {
                trial.mark_active();
            }
            AncestorVerdict::Realistic => {
                trial.mark_inactive();
                values.push(value);
                stop_after_inactive = true;
            }
            AncestorVerdict::UntouchedInput => {
                // A supplied location with an untouched input is retained as
                // one pass-through parameter. The next location is not
                // claimed, which is the contiguous assignment rule in
                // `ParamListStandard::fillinMap`.
                trial.mark_inactive();
                values.push(value);
                stop_after_inactive = true;
            }
            AncestorVerdict::CalleeLeftBehind | AncestorVerdict::Unknown => {
                trial.mark_no_use();
                break;
            }
        }
        if !stop_after_inactive {
            values.push(value);
        }
    }
    (
        active,
        collapse_wide_arguments(data, argument_locations, &values),
    )
}

/// Every call site with its recovered argument values in convention order.
///
/// `argument_locations` is the ABI's ordered candidate list. A missing guard
/// or a value left by a previous callee ends the list; a single untouched entry
/// value is retained as a pass-through argument, exactly as the caller's known
/// arity allows in Ghidra. The location after that first unused trial is not
/// claimed, matching `ParamListStandard::fillinMap`'s contiguous assignment.
pub fn call_arguments(
    data: &Funcdata,
    argument_locations: &[Location],
) -> BTreeMap<OpId, Vec<VarnodeId>> {
    calls(data)
        .into_iter()
        .map(|call| {
            let (_, values) = trial_values(data, call, argument_locations);
            (call, values)
        })
        .collect()
}

/// The candidate parameter locations for a call site.
///
/// Ghidra asks the call's own `FuncCallSpecs` for `getInputLocations`, so the
/// candidates are the *convention's* input storage in the order the convention
/// assigns it. Deriving them from whichever locations happen to be guarded is
/// not the same set: `guardCalls` guards every location a callee may change,
/// including the link register, and a guarded link register carrying the call's
/// own return address is a perfectly "used" value that would then be offered as
/// this call's first argument.
///
/// The guard-derived set remains the fallback for a graph with no recovered
/// prototype, where nothing else names the convention.
fn locations_before_call(data: &Funcdata, call: OpId) -> Vec<Location> {
    if let Some(proto) = data.func_proto() {
        let storage = proto.model_input_storage();
        if !storage.is_empty() {
            return storage.to_vec();
        }
    }
    let Some(block) = data.op(call).parent else {
        return Vec::new();
    };
    let Some(position) = data
        .block(block)
        .ops
        .iter()
        .position(|candidate| *candidate == call)
    else {
        return Vec::new();
    };
    let mut locations = BTreeSet::new();
    for id in data.block(block).ops[..position].iter().copied() {
        let operation = data.op(id);
        if operation.opcode != op::INDIRECT {
            continue;
        }
        let Some(output) = operation.output else {
            continue;
        };
        let value = data.varnode(output);
        locations.insert(Location {
            space: value.space,
            offset: value.offset,
            size: value.size,
        });
    }
    if locations.is_empty() {
        for value in data.op(call).inputs.iter().copied().skip(1) {
            let varnode = data.varnode(value);
            locations.insert(Location {
                space: varnode.space,
                offset: varnode.offset,
                size: varnode.size,
            });
        }
    }
    locations.into_iter().collect()
}

/// Recover call inputs from the convention locations already represented by
/// guards. This is the graph form of `ActionActiveParam::apply`; callers that
/// know an ABI should prefer `call_arguments` so its exact location order is
/// explicit.
pub struct ActionActiveParam;

impl Action for ActionActiveParam {
    fn name(&self) -> &'static str {
        "activeparam"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let mut changed = 0;
        for call in calls(data) {
            // `ActionActiveParam::apply` only touches a call whose trials are
            // still open. Once `buildInputFromTrials` has rebuilt the operand
            // list, the slots hold arguments rather than candidate locations.
            if !data.is_input_active(call) {
                continue;
            }
            let locations = locations_before_call(data, call);
            if locations.is_empty() {
                continue;
            }
            let Some(target) = data.op(call).inputs.first().copied() else {
                continue;
            };
            let (_, arguments) = trial_values(data, call, &locations);
            if arguments.is_empty() {
                continue;
            }
            let mut inputs = Vec::with_capacity(arguments.len() + 1);
            inputs.push(target);
            inputs.extend(arguments);
            // Never shorten a call. Ghidra does not remove an argument whose
            // ancestry it could not justify: `checkInputTrialUse` marks that
            // trial no-use and the slot becomes a zero constant, so the operand
            // count is preserved (`fspec.cc` 5645-5651). Rebuilding the list
            // instead dropped arguments this analysis merely failed to explain,
            // and because a dropped operand was often a value's only use, the
            // stores and loads feeding it were then eliminated as dead. That
            // turned two functions into stubs with no memory accesses at all.
            if inputs.len() < data.op(call).inputs.len() {
                continue;
            }
            if inputs != data.op(call).inputs {
                data.op_set_inputs(call, inputs);
                changed += 1;
            }
        }
        changed
    }
}

fn consumed_value(data: &Funcdata, value: VarnodeId, seen: &mut BTreeSet<VarnodeId>) -> bool {
    if !seen.insert(value) {
        return false;
    }
    for descendant in data.varnode(value).descendants.iter().copied() {
        let Some(opcode) = data.opcode_of(descendant) else {
            continue;
        };
        match opcode {
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

/// Remove an unread result from each call, porting `ActionActiveReturn::apply`.
pub struct ActionActiveReturn;

impl Action for ActionActiveReturn {
    fn name(&self) -> &'static str {
        "activereturn"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let mut changed = 0;
        for call in calls(data) {
            let Some(output) = data.op(call).output else {
                continue;
            };
            if !consumed_value(data, output, &mut BTreeSet::new()) {
                data.op_set_output(call, None);
                changed += 1;
            }
        }
        changed
    }
}

/// Link preparation is already represented by graph `CALL` operands and
/// `INDIRECT` guards. The full Ghidra action also consults a prototype model to
/// insert stack loads and output locations, which this graph API intentionally
/// does not carry; leaving those links untouched is safer than inventing an
/// ABI or deleting an unknown call result.
pub struct ActionFuncLink;

impl Action for ActionFuncLink {
    fn name(&self) -> &'static str {
        "funclink"
    }

    /// `ActionFuncLink::funcLinkInput`'s observable half already ran.
    ///
    /// Its job is to put the convention's candidate parameter operands on each
    /// call before renaming and to open the call's trials. Both happen earlier
    /// and unconditionally here: `guard::guard_calls` appends the operands - the
    /// same thing `Heritage::guardCalls` does for an unlocked callee - and
    /// `proto::recover_call_arguments` decides and closes the trials.
    ///
    /// What remains unrepresented is `funcLinkOutput`'s stack placeholder, which
    /// needs a stack-space model with `opStackLoad`; this graph reaches stack
    /// arguments through ordinary loads instead, so there is no placeholder to
    /// insert.
    fn apply(&self, _data: &mut Funcdata) -> usize {
        0
    }
}

/// Recover one wider value from adjacent parameter locations.
pub struct ActionParamDouble;

impl Action for ActionParamDouble {
    fn name(&self) -> &'static str {
        "paramdouble"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let mut changed = 0;
        for call in calls(data) {
            let old_inputs = data.op(call).inputs.clone();
            let locations: Vec<Location> = old_inputs
                .iter()
                .skip(1)
                .map(|value| {
                    let varnode = data.varnode(*value);
                    Location {
                        space: varnode.space,
                        offset: varnode.offset,
                        size: varnode.size,
                    }
                })
                .collect();
            let mut new_inputs = Vec::with_capacity(old_inputs.len());
            new_inputs.push(old_inputs[0]);
            let mut index = 0;
            while index < locations.len() {
                let first = old_inputs[index + 1];
                if index + 1 < locations.len()
                    && adjacent(locations[index], locations[index + 1])
                    && let Some(whole) = collapse_piece(data, first, old_inputs[index + 2])
                {
                    new_inputs.push(whole);
                    index += 2;
                } else {
                    new_inputs.push(first);
                    index += 1;
                }
            }
            if new_inputs != old_inputs {
                data.op_set_inputs(call, new_inputs);
                changed += 1;
            }
        }
        changed
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

    fn seq(address: u64, order: u32) -> SeqNum {
        SeqNum { address, order }
    }

    fn location(offset: u64) -> Location {
        Location {
            space: REGISTER_SPACE,
            offset,
            size: 4,
        }
    }

    fn call_with_locations(
        locations: &[Location],
        with_heritage: bool,
    ) -> (Funcdata, OpId, Vec<VarnodeId>) {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(data.entry);
        let inputs: Vec<VarnodeId> = locations
            .iter()
            .map(|location| {
                let value = data.new_varnode(location.space, location.offset, location.size);
                data.mark_input(value);
                value
            })
            .collect();
        let target = data.new_varnode(RAM_SPACE, 0x3000, 4);
        let call = data.new_op(op::CALL, seq(0x1000, 0), vec![target]);
        data.op_insert_end(call, block);
        let set = locations.iter().copied().collect::<BTreeSet<_>>();
        guard_calls(&mut data, &set, &CallEffects::default(), &[], &[]);
        if with_heritage {
            heritage(&mut data);
        }
        (data, call, inputs)
    }

    #[test]
    fn ancestor_realistic_distinguishes_computed_callee_and_entry_values() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let constant = data.new_constant(7, 4);
        let computed = data.new_unique(4);
        let add = data.new_op(op::INT_ADD, seq(0x1000, 0), vec![constant, constant]);
        data.op_set_output(add, Some(computed));
        data.op_insert_end(add, block);
        assert!(ancestor_realistic(&data, computed));

        let target = data.new_varnode(RAM_SPACE, 0x3000, 4);
        let call = data.new_op(op::CALL, seq(0x1004, 0), vec![target]);
        let leftover = data.new_varnode(REGISTER_SPACE, 0x10, 4);
        data.op_set_output(call, Some(leftover));
        data.op_insert_end(call, block);
        assert!(!ancestor_realistic(&data, leftover));

        let entry = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        data.mark_input(entry);
        assert!(!ancestor_realistic(&data, entry));
        // Ghidra chooses `inactive` for this third case in
        // `FuncCallSpecs::checkInputTrialUse`, rather than `defnouse`
        // (`fspec.cc` 5644-5646), so a known callee arity can still retain
        // the pass-through value.
    }

    #[test]
    fn untouched_pass_through_argument_is_recovered() {
        let loc = location(0x10);
        let (data, call, _inputs) = call_with_locations(&[loc], true);
        let arguments = call_arguments(&data, &[loc]);
        let argument = arguments[&call][0];
        assert_eq!(data.varnode(argument).space, REGISTER_SPACE);
        assert_eq!(data.varnode(argument).offset, loc.offset);
        assert!(data.varnode(argument).flags.input);
        let mut linked = data.clone();
        assert_eq!(ActionActiveParam.apply(&mut linked), 1);
        assert_eq!(linked.op(call).inputs.len(), 2);
        assert_eq!(ActionActiveParam.apply(&mut linked), 0);
    }

    #[test]
    fn a_wide_piece_is_one_argument() {
        let loc_lo = location(0x10);
        let loc_hi = location(0x14);
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(data.entry);
        let lo = data.new_constant(1, 4);
        let hi = data.new_constant(2, 4);
        let whole = data.new_unique(8);
        let piece = data.new_op(op::PIECE, seq(0x1000, 0), vec![hi, lo]);
        data.op_set_output(piece, Some(whole));
        data.op_insert_end(piece, block);
        let sub_lo = data.new_varnode(REGISTER_SPACE, loc_lo.offset, 4);
        let lo_zero = data.new_constant(0, 4);
        let lo_op = data.new_op(op::SUBPIECE, seq(0x1000, 1), vec![whole, lo_zero]);
        data.op_set_output(lo_op, Some(sub_lo));
        data.op_insert_end(lo_op, block);
        let sub_hi = data.new_varnode(REGISTER_SPACE, loc_hi.offset, 4);
        let hi_four = data.new_constant(4, 4);
        let hi_op = data.new_op(op::SUBPIECE, seq(0x1000, 2), vec![whole, hi_four]);
        data.op_set_output(hi_op, Some(sub_hi));
        data.op_insert_end(hi_op, block);
        let target = data.new_varnode(RAM_SPACE, 0x3000, 4);
        let call = data.new_op(op::CALL, seq(0x1004, 0), vec![target]);
        data.op_insert_end(call, block);
        guard_calls(
            &mut data,
            &BTreeSet::from([loc_lo, loc_hi]),
            &CallEffects::default(),
            &[],
            &[],
        );
        heritage(&mut data);
        let arguments = call_arguments(&data, &[loc_lo, loc_hi]);
        assert_eq!(arguments.get(&call), Some(&vec![whole]));

        let mut linked = data.clone();
        linked.op_set_inputs(call, vec![target, sub_lo, sub_hi]);
        assert_eq!(ActionParamDouble.apply(&mut linked), 1);
        assert_eq!(linked.op(call).inputs, vec![target, whole]);
        let mut declined = data.clone();
        declined.op_set_inputs(call, vec![target, sub_lo, hi]);
        assert_eq!(ActionParamDouble.apply(&mut declined), 0);
    }

    #[test]
    fn a_trial_after_the_first_unused_one_is_not_claimed() {
        let first = location(0x10);
        let gap = location(0x14);
        let later = location(0x18);
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(data.entry);
        let seven = data.new_constant(7, 4);
        let first_out = data.new_varnode(REGISTER_SPACE, first.offset, first.size);
        let first_copy = data.new_op(op::COPY, seq(0x1000, 0), vec![seven]);
        data.op_set_output(first_copy, Some(first_out));
        data.op_insert_end(first_copy, block);
        let old_target = data.new_varnode(RAM_SPACE, 0x4000, 4);
        let old_call = data.new_op(op::CALL, seq(0x1001, 0), vec![old_target]);
        let old_out = data.new_varnode(REGISTER_SPACE, gap.offset, gap.size);
        data.op_set_output(old_call, Some(old_out));
        data.op_insert_end(old_call, block);
        let later_out = data.new_varnode(REGISTER_SPACE, later.offset, later.size);
        let later_copy = data.new_op(op::COPY, seq(0x1002, 0), vec![seven]);
        data.op_set_output(later_copy, Some(later_out));
        data.op_insert_end(later_copy, block);
        let target = data.new_varnode(RAM_SPACE, 0x3000, 4);
        let call = data.new_op(op::CALL, seq(0x1004, 0), vec![target]);
        data.op_insert_end(call, block);
        guard_calls(
            &mut data,
            &BTreeSet::from([first, gap, later]),
            &CallEffects::default(),
            &[],
            &[],
        );
        heritage(&mut data);
        let arguments = call_arguments(&data, &[first, gap, later]);
        let argument = arguments[&call][0];
        assert_eq!(data.varnode(argument).space, REGISTER_SPACE);
        assert_eq!(data.varnode(argument).offset, first.offset);
        assert!(ancestor_realistic(&data, argument));
    }

    #[test]
    fn active_return_fires_only_for_unconsumed_output() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(data.entry);
        let target = data.new_varnode(RAM_SPACE, 0x3000, 4);
        let first = data.new_op(op::CALL, seq(0x1000, 0), vec![target]);
        let first_out = data.new_varnode(REGISTER_SPACE, 0x10, 4);
        data.op_set_output(first, Some(first_out));
        data.op_insert_end(first, block);
        let second = data.new_op(op::CALL, seq(0x1004, 0), vec![target]);
        let second_out = data.new_varnode(REGISTER_SPACE, 0x14, 4);
        data.op_set_output(second, Some(second_out));
        data.op_insert_end(second, block);
        let use_op = data.new_op(op::INT_ADD, seq(0x1008, 0), vec![second_out, second_out]);
        data.op_insert_end(use_op, block);
        assert_eq!(ActionActiveReturn.apply(&mut data), 1);
        assert!(data.op(first).output.is_none());
        assert!(data.op(second).output.is_some());
        assert_eq!(ActionActiveReturn.apply(&mut data), 0);
    }

    #[test]
    fn active_param_never_shortens_a_call() {
        // An argument this analysis cannot justify is not an argument that is
        // absent. Dropping the operand removes a value's only use, so the
        // stores feeding it are eliminated as dead and the function loses real
        // work. Ghidra keeps the slot and substitutes a zero constant.
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let target = data.new_constant(0x2000, 4);
        let first = data.new_varnode(REGISTER_SPACE, 0, 4);
        let second = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.mark_input(first);
        data.mark_input(second);
        let call = data.new_op(
            op::CALL,
            SeqNum {
                address: 0x1000,
                order: 0,
            },
            vec![target, first, second],
        );
        data.op_insert_end(call, block);

        let before = data.op(call).inputs.len();
        ActionActiveParam.apply(&mut data);
        assert!(
            data.op(call).inputs.len() >= before,
            "the call lost an argument: {:?}",
            data.op(call).inputs
        );
    }
}
