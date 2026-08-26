//! Jump-table recovery for indirect branches.
//!
//! This is the loader-independent part of Ghidra 12.1.3's jump-table pass at
//! commit `8b4c91d4d5bd1549622bfbade0df199585b98365`. The implementation is
//! based on `JumpTable::recoverAddresses`, `JumpTable::recoverModel`, and
//! `JumpTable::foldInNormalization` in `jumptable.cc`, with the primary model
//! from `JumpBasic::recoverModel`, `JumpBasic::findDeterminingVarnodes`, and
//! `JumpBasic::analyzeGuards`. `JumpValuesRange::initializeForReading` and
//! `JumpValuesRange::next` are represented by the bounded label loop.
//! `JumpBasic2::recoverModel` is deliberately not reproduced: this graph has
//! no `PathMeld::set`/`PathMeld::meld` or emulation state for a split-path
//! `MULTIEQUAL` model. The address walk corresponds to
//! `EmulateFunction::emulatePath` and its `executeLoad` hook, while the
//! one-edge fallback is `JumpModelTrivial::recoverModel`/`buildAddresses`.
//! `ActionSwitchNorm::apply` is represented by the local branch-input fold
//! below; the reduced graph has no `Funcdata` jump-table registry or loader
//! through which to perform Ghidra's later label and guard folding.

use std::collections::BTreeSet;

use super::action::Action;
use super::{Funcdata, GraphBlockId, OpId, VarnodeId};
use ventris_pcode::op;

pub(crate) const MAX_TABLE_ENTRIES: u64 = 0x1_0000;

/// One recovered switch: the value tested, and each case label with its target address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JumpTable {
    pub branch: OpId,
    pub switch_value: VarnodeId,
    pub cases: Vec<(u64, u64)>,
    pub default_target: Option<u64>,
}

#[derive(Copy, Clone)]
pub(crate) struct Scale {
    pub(crate) value: VarnodeId,
    pub(crate) stride: u64,
}

#[derive(Copy, Clone)]
pub(crate) struct AddressModel {
    pub(crate) base: u64,
    pub(crate) index: VarnodeId,
    pub(crate) stride: u64,
}

#[derive(Copy, Clone)]
pub(crate) struct DestinationModel {
    pub(crate) address: AddressModel,
    pub(crate) entry_size: u32,
    pub(crate) target_bias: u64,
}

#[derive(Copy, Clone)]
pub(crate) struct GuardModel {
    pub(crate) bound: u64,
    pub(crate) default_target: Option<u64>,
}

/// Strip operations which preserve the low-order value bits used by a switch.
///
/// Ghidra calls this a quasi-COPY while pulling a guard back through the data
/// flow (`GuardRecord::quasiCopy` in `jumptable.cc`).  `BOOL_NEGATE` is included
/// only for matching a condition value; it is never used while walking an
/// address calculation.
pub(crate) fn strip_alias(data: &Funcdata, start: VarnodeId) -> VarnodeId {
    let mut current = start;
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(current) {
            return current;
        }
        let Some(def) = data.varnode(current).def else {
            return current;
        };
        let operation = data.op(def);
        let source = match operation.opcode {
            op::COPY | op::INT_ZEXT | op::BOOL_NEGATE => operation.inputs.first().copied(),
            op::SUBPIECE => {
                let offset = operation.inputs.get(1).copied();
                offset
                    .filter(|value| {
                        data.varnode(*value).flags.constant && data.varnode(*value).offset == 0
                    })
                    .and_then(|_| operation.inputs.first().copied())
            }
            _ => None,
        };
        let Some(source) = source else {
            return current;
        };
        current = source;
    }
}

pub(crate) fn constant_value(data: &Funcdata, value: VarnodeId) -> Option<u64> {
    let value = strip_alias(data, value);
    data.varnode(value)
        .flags
        .constant
        .then_some(data.varnode(value).offset)
}

pub(crate) fn same_value(data: &Funcdata, left: VarnodeId, right: VarnodeId) -> bool {
    strip_alias(data, left) == strip_alias(data, right)
}

/// Recover an index and its scale from the address calculation.
///
/// The accepted forms are the reversible operations used by Ghidra's basic
/// model: `INT_MULT(index, constant)`, `INT_LEFT(index, constant)`, and the
/// quasi-copy operations handled by `strip_alias`.  A LOAD result is also a
/// valid determining varnode: Ghidra's `JumpBasic::isprune` walks through a
/// LOAD, but `findSmallestNormal` can select the loaded value itself (and
/// explicitly permits a one-byte value when a LOAD occurs in the path).
/// Defined values from other operations are not treated as an index; accepting
/// them would turn an arbitrary pointer expression into a switch.
pub(crate) fn parse_scaled(data: &Funcdata, value: VarnodeId) -> Option<Scale> {
    let value = strip_alias(data, value);
    if data.varnode(value).flags.constant {
        return None;
    }
    let Some(def) = data.varnode(value).def else {
        return Some(Scale { value, stride: 1 });
    };
    let operation = data.op(def);
    if operation.opcode == op::LOAD {
        return Some(Scale { value, stride: 1 });
    }
    match operation.opcode {
        op::INT_MULT if operation.inputs.len() >= 2 => {
            let (index, scale) = if let Some(scale) = constant_value(data, operation.inputs[1]) {
                (operation.inputs[0], scale)
            } else if let Some(scale) = constant_value(data, operation.inputs[0]) {
                (operation.inputs[1], scale)
            } else {
                return None;
            };
            if scale == 0 {
                return None;
            }
            let nested = parse_scaled(data, index)?;
            Some(Scale {
                value: nested.value,
                stride: nested.stride.checked_mul(scale)?,
            })
        }
        op::INT_LEFT if operation.inputs.len() >= 2 => {
            let shift = constant_value(data, operation.inputs[1])?;
            if shift >= u64::from(u64::BITS) {
                return None;
            }
            let nested = parse_scaled(data, operation.inputs[0])?;
            Some(Scale {
                value: nested.value,
                stride: nested.stride.checked_shl(shift as u32)?,
            })
        }
        // A free, non-constant varnode is the determining value.  Defined
        // values reach this point only when their producer was unsupported.
        _ => None,
    }
}

/// Recover `constant base + scaled index` from a LOAD address.
pub(crate) fn parse_address(data: &Funcdata, value: VarnodeId) -> Option<AddressModel> {
    let value = strip_alias(data, value);
    let def = data.varnode(value).def?;
    let operation = data.op(def);
    if operation.opcode != op::INT_ADD || operation.inputs.len() < 2 {
        return None;
    }

    if let Some(base) = constant_value(data, operation.inputs[0]) {
        if let Some(scale) = parse_scaled(data, operation.inputs[1]) {
            return Some(AddressModel {
                base,
                index: scale.value,
                stride: scale.stride,
            });
        }
        // Permit a second constant add around an already recognized table
        // address.  Both constants still collapse to one fixed table base.
        if let Some(mut nested) = parse_address(data, operation.inputs[1]) {
            nested.base = nested.base.wrapping_add(base);
            return Some(nested);
        }
    }
    if let Some(base) = constant_value(data, operation.inputs[1]) {
        if let Some(scale) = parse_scaled(data, operation.inputs[0]) {
            return Some(AddressModel {
                base,
                index: scale.value,
                stride: scale.stride,
            });
        }
        if let Some(mut nested) = parse_address(data, operation.inputs[0]) {
            nested.base = nested.base.wrapping_add(base);
            return Some(nested);
        }
    }
    // In particular, an input/global base plus an index is rejected here.
    // A table address must be anchored by a literal constant.
    None
}

/// Trace a BRANCHIND destination back to a loaded table entry.
pub(crate) fn parse_destination(data: &Funcdata, value: VarnodeId) -> Option<DestinationModel> {
    let value = strip_alias(data, value);
    let def = data.varnode(value).def?;
    let operation = data.op(def);
    match operation.opcode {
        op::LOAD => {
            let address = parse_address(data, *operation.inputs.get(1)?)?;
            let output = operation.output?;
            let entry_size = data.varnode(output).size;
            (entry_size != 0).then_some(DestinationModel {
                address,
                entry_size,
                target_bias: 0,
            })
        }
        op::INT_ADD if operation.inputs.len() >= 2 => {
            if let Some(bias) = constant_value(data, operation.inputs[0]) {
                let mut nested = parse_destination(data, operation.inputs[1])?;
                nested.target_bias = nested.target_bias.wrapping_add(bias);
                return Some(nested);
            }
            if let Some(bias) = constant_value(data, operation.inputs[1]) {
                let mut nested = parse_destination(data, operation.inputs[0])?;
                nested.target_bias = nested.target_bias.wrapping_add(bias);
                return Some(nested);
            }
            None
        }
        _ => None,
    }
}

/// Keep a table-shaped destination from falling through to the trivial model
/// when its address failed validation (for example, because the base is
/// dynamic). This is only a shape check, not a recovery.
fn contains_load(data: &Funcdata, value: VarnodeId) -> bool {
    let value = strip_alias(data, value);
    let Some(def) = data.varnode(value).def else {
        return false;
    };
    let operation = data.op(def);
    match operation.opcode {
        op::LOAD => true,
        op::INT_ADD if operation.inputs.len() >= 2 => {
            contains_load(data, operation.inputs[0]) || contains_load(data, operation.inputs[1])
        }
        _ => false,
    }
}

pub(crate) fn block_reaches(data: &Funcdata, start: GraphBlockId, target: GraphBlockId) -> bool {
    let mut pending = vec![start];
    let mut seen = BTreeSet::new();
    while let Some(block) = pending.pop() {
        if !seen.insert(block) {
            continue;
        }
        if block == target {
            return true;
        }
        pending.extend(data.block(block).successors.iter().copied());
    }
    false
}

fn guard_relation(
    data: &Funcdata,
    guard_block: GraphBlockId,
    branch_block: GraphBlockId,
    guard: OpId,
    branch: OpId,
) -> Option<Option<u64>> {
    if guard_block == branch_block {
        // A CBRANCH normally terminates its block, but hand-built graphs and
        // partially lifted code can place both ops together. Sequence order
        // is enough to preserve the "preceding guard" invariant there.
        return (data.op(guard).seq < data.op(branch).seq).then_some(None);
    }
    let successors = &data.block(guard_block).successors;
    if successors.len() == 2 {
        let first = block_reaches(data, successors[0], branch_block);
        let second = block_reaches(data, successors[1], branch_block);
        if first == second {
            return None;
        }
        let default = if first {
            data.block(successors[1]).start
        } else {
            data.block(successors[0]).start
        };
        return Some(Some(default));
    }
    block_reaches(data, guard_block, branch_block).then_some(None)
}

/// Return whether the condition-true edge reaches the indirect branch.
///
/// The reverse comparison form (`constant < switch`) is an upper-bound guard
/// only when its false edge reaches the table.  The edge list is not enough to
/// infer that polarity: a CBRANCH's target is carried by its first input, so
/// resolve that target against the CFG explicitly.
fn condition_to_switch(
    data: &Funcdata,
    guard_block: GraphBlockId,
    branch_block: GraphBlockId,
    cbranch: OpId,
) -> Option<bool> {
    let target = data.branch_target(cbranch)?;
    let successors = &data.block(guard_block).successors;
    if successors.len() != 2 {
        return None;
    }
    let first = block_reaches(data, successors[0], branch_block);
    let second = block_reaches(data, successors[1], branch_block);
    let switch_successor = match (first, second) {
        (true, false) => successors[0],
        (false, true) => successors[1],
        _ => return None,
    };
    Some(switch_successor == target)
}

fn guard_bound(data: &Funcdata, compare: OpId, switch_value: VarnodeId) -> Option<u64> {
    let operation = data.op(compare);
    let left = *operation.inputs.first()?;
    let right = *operation.inputs.get(1)?;
    if same_value(data, left, switch_value) {
        let limit = constant_value(data, right)?;
        return match operation.opcode {
            op::INT_LESS => Some(limit),
            op::INT_LESSEQUAL => limit.checked_add(1),
            _ => None,
        };
    }
    // `limit < switch` reaching the table through the false edge means
    // `switch <= limit`; `limit <= switch` through false means `switch <
    // limit`.  The caller checks that this is the edge actually reaching the
    // BRANCHIND before accepting the reversed form.
    if !same_value(data, right, switch_value) {
        return None;
    }
    let limit = constant_value(data, left)?;
    match operation.opcode {
        op::INT_LESS => limit.checked_add(1),
        op::INT_LESSEQUAL => Some(limit),
        _ => None,
    }
}

/// Find the smallest range reaching the indirect branch, like
/// `JumpBasic::findSmallestNormal` after `analyzeGuards` has populated its
/// `GuardRecord`s.
pub(crate) fn find_guard(
    data: &Funcdata,
    branch: OpId,
    switch_value: VarnodeId,
) -> Option<GuardModel> {
    let branch_block = data.op(branch).parent?;
    let condition = |candidate: OpId| {
        let operation = data.op(candidate);
        (operation.opcode == op::CBRANCH)
            .then(|| operation.inputs.get(1).copied())
            .flatten()
    };
    let mut best: Option<GuardModel> = None;

    for (cbranch, operation) in data.live_ops() {
        let Some(condition_value) = condition(cbranch) else {
            continue;
        };
        let compare = strip_alias(data, condition_value);
        let Some(compare_def) = data.varnode(compare).def else {
            continue;
        };
        if compare_def != cbranch
            && data.op(compare_def).opcode != op::INT_LESS
            && data.op(compare_def).opcode != op::INT_LESSEQUAL
        {
            continue;
        }
        let Some(guard_block) = operation.parent else {
            continue;
        };
        let reversed = {
            let inputs = &data.op(compare_def).inputs;
            inputs.len() >= 2
                && same_value(data, inputs[1], switch_value)
                && !same_value(data, inputs[0], switch_value)
        };
        let Some(bound) = guard_bound(data, compare_def, switch_value) else {
            continue;
        };
        if reversed && condition_to_switch(data, guard_block, branch_block, cbranch) != Some(false)
        {
            continue;
        }
        if bound == 0 || bound > MAX_TABLE_ENTRIES {
            continue;
        }
        let Some(default_target) = guard_relation(data, guard_block, branch_block, cbranch, branch)
        else {
            continue;
        };
        let candidate = GuardModel {
            bound,
            default_target,
        };
        if best.is_none_or(|current| candidate.bound < current.bound) {
            best = Some(candidate);
        }
    }
    best
}

fn recover_basic(
    data: &Funcdata,
    branch: OpId,
    read_memory: &dyn Fn(u64, u32) -> Option<u64>,
) -> Option<JumpTable> {
    let destination = *data.op(branch).inputs.first()?;
    let model = parse_destination(data, destination)?;
    let guard = find_guard(data, branch, model.address.index)?;
    let mut cases = Vec::with_capacity(guard.bound as usize);
    for label in 0..guard.bound {
        let offset = label.checked_mul(model.address.stride)?;
        let address = model.address.base.checked_add(offset)?;
        let target = read_memory(address, model.entry_size)?;
        cases.push((label, target.wrapping_add(model.target_bias)));
    }
    Some(JumpTable {
        branch,
        switch_value: model.address.index,
        cases,
        default_target: guard.default_target,
    })
}

/// `JumpModelTrivial` uses the outgoing edges themselves as the address table.
/// A literal BRANCHIND target is also unambiguous in a graph with no edges.
/// A destination whose whole computation is over constants.
///
/// MIPS `jr` clears the target's low bits before branching, so a computed
/// address that folded to a constant arrives as `INT_AND(INT_2COMP(2), target)`
/// rather than as a bare constant. Evaluating that is arithmetic, not a guess,
/// but it is kept local to the trivial model: making a value known that the
/// shared helpers report as unknown changes which operand the address parser
/// reads as a table base, and that misclassification broke a real switch when
/// tried globally.
fn folded_constant(data: &Funcdata, value: VarnodeId, depth: u32) -> Option<u64> {
    let value = strip_alias(data, value);
    if let Some(target) = constant_value(data, value) {
        return Some(target);
    }
    let definition = data.varnode(value).def.filter(|_| depth > 0)?;
    let operation = data.op(definition);
    let input = |slot: usize| {
        operation
            .inputs
            .get(slot)
            .copied()
            .and_then(|operand| folded_constant(data, operand, depth - 1))
    };
    let left = input(0)?;
    match operation.opcode {
        op::COPY | op::INT_ZEXT | op::INT_SEXT => Some(left),
        op::INT_2COMP => Some(left.wrapping_neg()),
        op::INT_NEGATE => Some(!left),
        op::INT_AND => Some(left & input(1)?),
        op::INT_OR => Some(left | input(1)?),
        op::INT_XOR => Some(left ^ input(1)?),
        op::INT_ADD => Some(left.wrapping_add(input(1)?)),
        _ => None,
    }
}

fn recover_trivial(data: &Funcdata, branch: OpId) -> Option<JumpTable> {
    let operation = data.op(branch);
    let destination = *operation.inputs.first()?;
    let parent = operation.parent?;
    let target = if let Some(target) = folded_constant(data, destination, 8) {
        target
    } else {
        let successors = &data.block(parent).successors;
        (successors.len() == 1).then(|| data.block(successors[0]).start)?
    };
    Some(JumpTable {
        branch,
        switch_value: destination,
        cases: vec![(target, target)],
        default_target: None,
    })
}

/// Recovers every jump table in the function.
///
/// `read_memory` reads the image, because a table's targets live in data, not code.
/// A failed read rejects the whole model: a partial table would invent a
/// different control-flow graph from the one represented by the image.
pub fn recover_jump_tables(
    data: &Funcdata,
    read_memory: &dyn Fn(u64, u32) -> Option<u64>,
) -> Vec<JumpTable> {
    data.live_ops()
        .filter(|(_, operation)| operation.opcode == op::BRANCHIND)
        .filter_map(|(branch, _)| {
            let destination = data.op(branch).inputs.first().copied()?;
            // A destination that evaluates to one constant is unambiguous,
            // whatever shape it evaluated from. The alignment mask on a MIPS
            // `jr` gives the address parser a table-shaped computation to read,
            // and every table model then fails on a target already known.
            if folded_constant(data, destination, 8).is_some() {
                return recover_trivial(data, branch);
            }
            // Once the destination has the shape of a table load, a missing or
            // unbounded guard must not fall through to the one-edge model.
            if parse_destination(data, destination).is_some() || contains_load(data, destination) {
                // Ghidra's model order: `JumpBasic` first, then `JumpBasic2`
                // for the two-stage shape where the index arrives through a
                // phi, then the trivial one-edge model.
                recover_basic(data, branch, read_memory)
                    .or_else(|| super::jumpmodel::recover_jump_basic2(data, branch, read_memory))
                    .or_else(|| {
                        super::tablebase::recover_jump_table_base(data, branch, read_memory)
                    })
            } else {
                recover_trivial(data, branch)
            }
        })
        .collect()
}
/// Turns a computed jump with one known destination into an ordinary branch.
///
/// Once the destination folds to a constant the jump is not computed any more,
/// and Ghidra's flow analysis records it as a normal edge. Left as a
/// `BRANCHIND` it renders as `goto *(...)`, which is how `preamble` and
/// `vm_boot` still read as unstructured after their targets were recovered.
///
/// Deliberately narrow: it acts only when the block already reaches exactly the
/// folded target, so no edge is invented and no multi-way construct is touched.
pub struct ActionResolvedIndirect;

impl Action for ActionResolvedIndirect {
    fn name(&self) -> &'static str {
        "resolved-indirect"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let candidates: Vec<(OpId, GraphBlockId)> = data
            .live_ops()
            .filter(|(_, operation)| operation.opcode == op::BRANCHIND)
            .filter_map(|(branch, operation)| {
                let destination = operation.inputs.first().copied()?;
                let target = folded_constant(data, destination, 8)?;
                let parent = operation.parent?;
                let successors = &data.block(parent).successors;
                if successors.len() != 1 {
                    return None;
                }
                let reached = successors[0];
                data.block_covers(reached, target, 0).then_some((branch, reached))
            })
            .collect();
        let mut changed = 0;
        for (branch, target) in candidates {
            let size = data
                .op(branch)
                .inputs
                .first()
                .map(|value| data.varnode(*value).size)
                .unwrap_or(4);
            let address = data.new_varnode(
                ventris_lifter::RAM_SPACE,
                data.block(target).start,
                size.max(1),
            );
            data.op_set_opcode(branch, op::BRANCH);
            data.op_set_inputs(branch, vec![address]);
            changed += 1;
        }
        changed
    }
}

/// Folds a switch's range-check guard into the switch itself.
///
/// Ghidra's `JumpBasic::foldInOneGuard`. A `switch` compiled with a bounds check
/// reaches its default twice: once from the guard that rejects an out-of-range
/// selector, and once from the jump table's own default entry. Both name the same
/// block, so that block has two incoming edges and `ruleBlockSwitch` refuses it -
/// "a case can only have the switch fall into it" - which costs a case, leaves the
/// guard as an extra `if`, and turns the case's edges into `goto`s.
///
/// Ghidra neutralises the guard: the comparison feeding its `CBRANCH` becomes a
/// constant, so control always falls into the switch and the default is reached
/// only through the table. This ports the branch of `foldInOneGuard` that applies
/// when the guard's target is *already* one of the switch's destinations; the other
/// branch, which adds a new unlabelled destination, needs the recovered table and
/// is not reachable from the control-flow graph alone.
/// Ghidra folds guards *after* the table is recovered, and the order matters
/// here too: the bound `recover_basic` reads comes from the guard's own
/// comparison, so neutralising the guard first loses the table entirely.
pub fn fold_in_guards(data: &mut Funcdata, tables: &[JumpTable]) -> usize {
    let switches: Vec<GraphBlockId> = tables
        .iter()
        .filter_map(|table| data.op(table.branch).parent)
        .collect();
    let mut folds: Vec<(OpId, usize, GraphBlockId, GraphBlockId)> = Vec::new();
    for switch in switches {
        // `noInterveningStatement`: nothing may happen between the guard's
        // test and the branch, or folding the guard away would move it.
        if !no_intervening_statement(data, switch) {
            continue;
        }
        let targets = data.block(switch).successors.clone();
        for guard in data.block(switch).predecessors.clone() {
            let outs = data.block(guard).successors.clone();
            if outs.len() != 2 {
                continue;
            }
            // One arm must enter the switch directly, and the other must
            // already be a destination of the switch.
            let Some(into) = outs.iter().position(|out| *out == switch) else {
                continue;
            };
            let target = outs[1 - into];
            if target == switch || !targets.contains(&target) {
                continue;
            }
            let Some(cbranch) = data
                .block(guard)
                .ops
                .iter()
                .copied()
                .find(|candidate| data.op(*candidate).opcode == op::CBRANCH)
            else {
                continue;
            };
            folds.push((cbranch, into, guard, target));
            break;
        }
    }
    let mut changed = 0;
    for (cbranch, into, guard, target) in folds {
        let Some(condition) = data.op(cbranch).inputs.get(1).copied() else {
            continue;
        };
        // `CBRANCH` takes its taken edge when the condition holds, and our
        // successor list is taken-first, so the constant that always enters
        // the switch is 1 when the switch is the taken arm and 0 otherwise.
        let width = data.varnode(condition).size.max(1);
        let always = data.new_constant(u64::from(into == 0), width);
        data.op_set_input(cbranch, always, 1);
        if data.remove_edge(guard, target) {
            changed += 1;
        }
    }
    changed
}

/// Ghidra's `BlockBasic::noInterveningStatement`.
///
/// Whether the block does nothing a reader would call a statement: no call, no
/// store, nothing written to a tied address, and no value it computes read
/// anywhere else.
fn no_intervening_statement(data: &Funcdata, block: GraphBlockId) -> bool {
    for operation in data.block(block).ops.iter().copied() {
        let op = data.op(operation);
        if matches!(
            op.opcode,
            op::MULTIEQUAL | op::INDIRECT | op::BRANCH | op::CBRANCH | op::BRANCHIND | op::RETURN
        ) {
            continue;
        }
        if matches!(
            op.opcode,
            op::CALL | op::CALLIND | op::CALLOTHER | op::STORE
        ) {
            return false;
        }
        if matches!(op.opcode, op::COPY | op::SUBPIECE) {
            continue;
        }
        let Some(output) = op.output else {
            return false;
        };
        if data
            .varnode(output)
            .descendants
            .iter()
            .any(|reader| data.op(*reader).parent != Some(block))
        {
            return false;
        }
    }
    true
}

/// Normalizes a recovered switch before structure recovery.
///
/// Ghidra's `ActionSwitchNorm::apply` calls `JumpTable::foldInNormalization`,
/// which makes BRANCHIND consume the unnormalized switch variable and leaves
/// the address-calculation ops for dead-code cleanup.  This reduced graph has
/// no jump-table registry, so the action performs that local fold for every
/// guarded basic-model branch; label recovery remains the explicit
/// `recover_jump_tables` API above.
pub struct ActionSwitchNorm;

impl Action for ActionSwitchNorm {
    fn name(&self) -> &'static str {
        "switchnorm"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let candidates: Vec<(OpId, VarnodeId)> = data
            .live_ops()
            .filter(|(_, operation)| operation.opcode == op::BRANCHIND)
            .filter_map(|(branch, operation)| {
                let destination = operation.inputs.first().copied()?;
                let model = parse_destination(data, destination)?;
                find_guard(data, branch, model.address.index).map(|_| (branch, model.address.index))
            })
            .collect();
        let mut changed = 0;
        for (branch, switch_value) in candidates {
            if data.op(branch).inputs.first().copied() != Some(switch_value) {
                data.op_set_input(branch, switch_value, 0);
                changed += 1;
            }
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{CONST_SPACE, RAM_SPACE, REGISTER_SPACE};

    fn seq(order: u32) -> super::super::SeqNum {
        super::super::SeqNum {
            address: 0x1000 + u64::from(order),
            order,
        }
    }

    struct Fixture {
        data: Funcdata,
        branch: OpId,
        index: VarnodeId,
        table_base: u64,
        entries: Vec<u64>,
    }

    fn bounded_fixture() -> Fixture {
        let mut data = Funcdata {
            entry: 0x1000,
            ..Funcdata::default()
        };
        let entry = data.new_block(0x1000);
        let guarded = data.new_block(0x1010);
        let default = data.new_block(0x2000);
        let switch = data.new_block(0x1020);
        data.add_edge(entry, guarded);
        data.add_edge(guarded, default);
        data.add_edge(guarded, switch);

        let index = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(index);
        let bound = data.new_constant(3, 4);
        let compare = data.new_op(op::INT_LESS, seq(0), vec![index, bound]);
        let comparison = data.new_unique(1);
        data.op_set_output(compare, Some(comparison));
        data.op_insert_end(compare, guarded);
        let guard_target = data.new_constant(data.block(switch).start, 8);
        let cbranch = data.new_op(op::CBRANCH, seq(1), vec![guard_target, comparison]);
        data.op_insert_end(cbranch, guarded);

        let shift_amount = data.new_constant(2, 4);
        let scaled = data.new_unique(4);
        let shift = data.new_op(op::INT_LEFT, seq(2), vec![index, shift_amount]);
        data.op_set_output(shift, Some(scaled));
        data.op_insert_end(shift, switch);
        let base = 0x8000;
        let base_value = data.new_constant(base, 8);
        let address = data.new_unique(8);
        let add = data.new_op(op::INT_ADD, seq(3), vec![base_value, scaled]);
        data.op_set_output(add, Some(address));
        data.op_insert_end(add, switch);
        let space = data.new_constant(RAM_SPACE as u64, 4);
        let loaded = data.new_unique(8);
        let load = data.new_op(op::LOAD, seq(4), vec![space, address]);
        data.op_set_output(load, Some(loaded));
        data.op_insert_end(load, switch);
        let branch = data.new_op(op::BRANCHIND, seq(5), vec![loaded]);
        data.op_insert_end(branch, switch);

        Fixture {
            data,
            branch,
            index,
            table_base: base,
            entries: vec![0x3000, 0x3010, 0x3020],
        }
    }

    #[test]
    fn bounded_scaled_table_recovers_all_entries_and_default() {
        let fixture = bounded_fixture();
        let entries = fixture.entries.clone();
        let base = fixture.table_base;
        let recovered = recover_jump_tables(&fixture.data, &move |address, width| {
            assert_eq!(width, 8);
            let index = usize::try_from((address - base) / 4).ok()?;
            entries.get(index).copied()
        });
        assert_eq!(recovered.len(), 1);
        let table = &recovered[0];
        assert_eq!(table.branch, fixture.branch);
        assert_eq!(table.switch_value, fixture.index);
        assert_eq!(table.cases, vec![(0, 0x3000), (1, 0x3010), (2, 0x3020)]);
        assert_eq!(table.default_target, Some(0x2000));
    }

    #[test]
    fn byte_load_inside_scaled_index_is_recovered() {
        let mut fixture = bounded_fixture();
        let switch_block = fixture
            .data
            .op(fixture.branch)
            .parent
            .expect("switch block");
        let space = fixture.data.new_constant(RAM_SPACE as u64, 4);
        let address = fixture.data.new_constant(0x4000, 4);
        let loaded = fixture.data.new_unique(1);
        let load = fixture.data.new_op(op::LOAD, seq(6), vec![space, address]);
        fixture.data.op_set_output(load, Some(loaded));
        let shift = fixture
            .data
            .live_ops()
            .find(|(_, operation)| operation.opcode == op::INT_LEFT)
            .map(|(id, _)| id)
            .expect("scaled index");
        fixture.data.op_insert_before(load, shift);
        fixture.data.op_set_input(shift, loaded, 0);
        let compare = fixture
            .data
            .live_ops()
            .find(|(_, operation)| operation.opcode == op::INT_LESS)
            .map(|(id, _)| id)
            .expect("guard compare");
        fixture.data.op_set_input(compare, loaded, 0);

        let entries = fixture.entries.clone();
        let base = fixture.table_base;
        let recovered = recover_jump_tables(&fixture.data, &move |table_address, width| {
            assert_eq!(width, 8);
            let index = usize::try_from((table_address - base) / 4).ok()?;
            entries.get(index).copied()
        });
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].switch_value, loaded);
        assert_eq!(
            recovered[0].cases,
            vec![(0, 0x3000), (1, 0x3010), (2, 0x3020)]
        );
        assert_eq!(fixture.data.op(load).parent, Some(switch_block));
    }

    #[test]
    fn unbounded_index_is_rejected() {
        let mut fixture = bounded_fixture();
        let compare = fixture
            .data
            .live_ops()
            .find(|(_, operation)| operation.opcode == op::INT_LESS)
            .map(|(id, _)| id)
            .expect("guard compare");
        fixture.data.op_destroy(compare);
        assert!(recover_jump_tables(&fixture.data, &|_, _| Some(0x3000)).is_empty());
    }

    #[test]
    fn nonconstant_table_base_is_rejected() {
        let mut fixture = bounded_fixture();
        let add = fixture
            .data
            .live_ops()
            .find(|(_, operation)| operation.opcode == op::INT_ADD)
            .map(|(id, _)| id)
            .expect("address add");
        let dynamic_base = fixture.data.new_varnode(REGISTER_SPACE, 0x40, 8);
        fixture.data.mark_input(dynamic_base);
        fixture.data.op_set_input(add, dynamic_base, 0);
        let branch_block = fixture
            .data
            .op(fixture.branch)
            .parent
            .expect("switch block");
        let trivial_target = fixture.data.new_block(0x4000);
        fixture.data.add_edge(branch_block, trivial_target);
        assert!(recover_jump_tables(&fixture.data, &|_, _| Some(0x3000)).is_empty());
    }

    #[test]
    fn trivial_single_target_uses_the_edge_target() {
        let mut data = Funcdata {
            entry: 0x1000,
            ..Funcdata::default()
        };
        let source = data.new_block(0x1000);
        let target = data.new_block(0x1234);
        data.add_edge(source, target);
        let destination = data.new_unique(8);
        data.mark_input(destination);
        let branch = data.new_op(op::BRANCHIND, seq(0), vec![destination]);
        data.op_insert_end(branch, source);

        let recovered = recover_jump_tables(&data, &|_, _| None);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].branch, branch);
        assert_eq!(recovered[0].switch_value, destination);
        assert_eq!(recovered[0].cases, vec![(0x1234, 0x1234)]);
        assert_eq!(recovered[0].default_target, None);
    }

    /// Ghidra's flow analysis only creates an edge to an address it is
    /// decompiling, so a computed jump that leaves the function is a call through
    /// the address. `vm_boot`'s `jr` to `0x700016cc` reads as
    /// `(*(code *)&DAT_700016cc)()` there; here the trivial model recovered the
    /// one constant destination, `truncate_indirect_jumps` saw a recovered table
    /// and left it alone, and it rendered as `goto *(...)`.
    #[test]
    fn a_computed_jump_out_of_the_function_becomes_a_call() {
        let build = || {
            let mut data = Funcdata::default();
            data.entry = 0x1000;
            let block = data.new_block(0x1000);
            let target = data.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
            let branch = data.new_op(op::BRANCHIND, seq(0x1000), vec![target]);
            data.op_insert_end(branch, block);
            (data, branch, target)
        };

        let (mut data, branch, target) = build();
        let outside = vec![JumpTable {
            branch,
            switch_value: target,
            cases: vec![(0, 0x700016cc)],
            default_target: None,
        }];
        assert_eq!(truncate_indirect_jumps(&mut data, &outside), 1);
        assert_eq!(data.op(branch).opcode, op::CALLIND);

        // A destination inside the function is a real branch and stays one.
        let (mut data, branch, target) = build();
        let landing = data.new_block(0x1010);
        data.add_edge(GraphBlockId(0), landing);
        let inside = vec![JumpTable {
            branch,
            switch_value: target,
            cases: vec![(0, 0x1010)],
            default_target: None,
        }];
        assert_eq!(truncate_indirect_jumps(&mut data, &inside), 0);
        assert_eq!(data.op(branch).opcode, op::BRANCHIND);
    }

    /// A `switch` with a bounds check reaches its default twice: from the guard
    /// that rejects an out-of-range selector, and from the table's own default
    /// entry. Two incoming edges make `ruleBlockSwitch` refuse that block as a
    /// case, so `dl_G_MOVEWORD` lost a case, kept the guard as a third `if`, and
    /// turned the case exits into `goto`s. Ghidra neutralises the guard.
    #[test]
    fn a_range_check_guard_folds_into_its_switch() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let guard = data.new_block(0x1000);
        let switch = data.new_block(0x1010);
        let case = data.new_block(0x1020);
        let default = data.new_block(0x1030);
        let selector = data.new_varnode(ventris_lifter::REGISTER_SPACE, 4, 4);
        let condition = data.new_unique(1);
        let compare = data.new_op(op::INT_LESS, seq(0x1000), vec![selector]);
        data.op_set_output(compare, Some(condition));
        data.op_insert_end(compare, guard);
        let elsewhere = data.new_varnode(RAM_SPACE, 0x1030, 4);
        let cbranch = data.new_op(op::CBRANCH, seq(0x1004), vec![elsewhere, condition]);
        data.op_insert_end(cbranch, guard);
        let target = data.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
        let branch = data.new_op(op::BRANCHIND, seq(0x1010), vec![target]);
        data.op_insert_end(branch, switch);
        // The guard's rejecting arm and the table's default name one block.
        data.add_edge(guard, default);
        data.add_edge(guard, switch);
        data.add_edge(switch, case);
        data.add_edge(switch, default);

        let tables = vec![JumpTable {
            branch,
            switch_value: target,
            cases: vec![(0, 0x1020)],
            default_target: Some(0x1030),
        }];
        assert_eq!(fold_in_guards(&mut data, &tables), 1);
        assert_eq!(
            data.block(guard).successors,
            vec![switch],
            "the guard now falls straight into the switch"
        );
        assert_eq!(
            data.block(default).predecessors,
            vec![switch],
            "the default is reached only through the table"
        );

        // A guard whose rejecting arm is *not* one of the switch's destinations
        // is the other branch of `foldInOneGuard`, which needs a new table entry.
        let mut untouched = Funcdata::default();
        untouched.entry = 0x1000;
        let guard = untouched.new_block(0x1000);
        let switch = untouched.new_block(0x1010);
        let case = untouched.new_block(0x1020);
        let elsewhere = untouched.new_block(0x1040);
        let target = untouched.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
        let branch = untouched.new_op(op::BRANCHIND, seq(0x1010), vec![target]);
        untouched.op_insert_end(branch, switch);
        untouched.add_edge(guard, elsewhere);
        untouched.add_edge(guard, switch);
        untouched.add_edge(switch, case);
        let tables = vec![JumpTable {
            branch,
            switch_value: target,
            cases: vec![(0, 0x1020)],
            default_target: None,
        }];
        assert_eq!(fold_in_guards(&mut untouched, &tables), 0);
    }

    #[test]
    fn action_switch_norm_folds_the_branch_destination() {
        let mut fixture = bounded_fixture();
        // Make the branch consume the loaded result through an explicit COPY.
        let loaded = fixture.data.op(fixture.branch).inputs[0];
        let copy_out = fixture.data.new_unique(8);
        let copy = fixture.data.new_op(op::COPY, seq(5), vec![loaded]);
        fixture.data.op_set_output(copy, Some(copy_out));
        fixture.data.op_insert_before(copy, fixture.branch);
        fixture.data.op_set_input(fixture.branch, copy_out, 0);
        assert_eq!(ActionSwitchNorm.apply(&mut fixture.data), 1);
        assert_eq!(fixture.data.op(fixture.branch).inputs[0], fixture.index);
    }
    #[test]
    fn action_switch_norm_declines_without_a_guard() {
        let mut fixture = bounded_fixture();
        let compare = fixture
            .data
            .live_ops()
            .find(|(_, operation)| operation.opcode == op::INT_LESS)
            .map(|(id, _)| id)
            .expect("guard compare");
        fixture.data.op_destroy(compare);
        let destination = fixture.data.op(fixture.branch).inputs[0];
        assert_eq!(ActionSwitchNorm.apply(&mut fixture.data), 0);
        assert_eq!(fixture.data.op(fixture.branch).inputs[0], destination);
    }

    /// A computed jump whose destination folds to a constant is an ordinary
    /// branch. Left indirect it renders as `goto *(...)`, which is how
    /// `preamble` read as unstructured after its target was recovered. The mask
    /// a MIPS `jr` applies is why the fold has to look through arithmetic.
    #[test]
    fn a_computed_jump_with_one_known_destination_becomes_a_branch() {
        let mut data = Funcdata {
            entry: 0x1000,
            ..Funcdata::default()
        };
        let from = data.new_block(0x1000);
        let to = data.new_block(0x1050);
        data.add_edge(from, to);

        // `0x1051 & -2` is `0x1050`: the low-bit clear a `jr` performs.
        let raw = data.new_constant(0x1051, 8);
        let two = data.new_constant(2, 8);
        let negated = data.new_unique(8);
        let negate = data.new_op(op::INT_2COMP, seq(0), vec![two]);
        data.op_set_output(negate, Some(negated));
        data.op_insert_end(negate, from);
        let masked = data.new_unique(8);
        let and = data.new_op(op::INT_AND, seq(1), vec![raw, negated]);
        data.op_set_output(and, Some(masked));
        data.op_insert_end(and, from);
        let branch = data.new_op(op::BRANCHIND, seq(2), vec![masked]);
        data.op_insert_end(branch, from);

        assert_eq!(
            folded_constant(&data, masked, 8),
            Some(0x1050),
            "the mask folds through INT_2COMP and INT_AND"
        );
        assert_eq!(ActionResolvedIndirect.apply(&mut data), 1);
        assert_eq!(
            data.op(branch).opcode,
            op::BRANCH,
            "the jump is no longer computed"
        );
        assert_eq!(
            data.branch_target(branch),
            Some(to),
            "and its single destination resolves as an address"
        );
    }

    /// Nothing is normalized when the block reaches more than one place: that is
    /// a switch, and its edges belong to the table models.
    #[test]
    fn a_computed_jump_with_several_successors_is_left_alone() {
        let mut fixture = bounded_fixture();
        assert_eq!(ActionResolvedIndirect.apply(&mut fixture.data), 0);
        assert_eq!(fixture.data.op(fixture.branch).opcode, op::BRANCHIND);
    }

    #[allow(dead_code)]
    fn _spaces_are_canonical() {
        let _ = (CONST_SPACE, RAM_SPACE);
    }
}

/// Turn an indirect jump with no recovered table into an indirect call.
///
/// Port of `FlowInfo::truncateIndirectJump`, the `fail_normal` arm. A `BRANCHIND`
/// whose table could not be recovered has no known destinations, so leaving it
/// as a branch says control goes somewhere the graph cannot name and the printer
/// spells that as a computed `goto`. Ghidra reads the same situation as a call:
/// control leaves through a value and comes back, which is what a tail call
/// through a register is. The alternative arm, `fail_return`, turns it into a
/// `RETURN` instead, and is reached only when the analysis proves control does
/// not come back - the graph here has no such proof, so it takes the call arm.
///
/// Returns the number of jumps converted.
pub fn truncate_indirect_jumps(data: &mut Funcdata, tables: &[JumpTable]) -> usize {
    // A recovered table whose every destination lies outside this function is not
    // a branch either. Ghidra's flow analysis only ever creates an edge to an
    // address it is decompiling; a computed jump that leaves the function is a
    // call through the address, which is how `vm_boot`'s `jr` to `0x700016cc`
    // reads as `(*(code *)&DAT_700016cc)()` there and as `goto *(...)` here.
    let inside: BTreeSet<u64> = data.blocks().map(|(_, block)| block.start).collect();
    let recovered: BTreeSet<OpId> = tables
        .iter()
        .filter(|table| {
            table
                .cases
                .iter()
                .map(|(_, target)| *target)
                .chain(table.default_target)
                .any(|target| inside.contains(&target))
        })
        .map(|table| table.branch)
        .collect();
    let unrecovered: Vec<OpId> = data
        .live_ops()
        .filter(|(id, operation)| operation.opcode == op::BRANCHIND && !recovered.contains(id))
        .map(|(id, _)| id)
        .collect();
    let mut changed = 0;
    for branch in unrecovered {
        // The destination becomes the callee, which is where a CALLIND keeps it
        // too, so the operands need no rearranging.
        data.op_set_opcode(branch, op::CALLIND);
        changed += 1;
    }
    changed
}
