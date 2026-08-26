//! Control-flow cleanup and common-subexpression actions on the p-code graph.
//!
//! The control-flow actions follow `ActionDeterminedBranch::apply`,
//! `ActionRedundBranch::apply`, `ActionUnreachable::apply`, and
//! `ActionDoNothing::apply` in `coreaction.cc`, together with
//! `Funcdata::removeBranch`, `Funcdata::spliceBlockBasic`, and
//! `Funcdata::removeUnreachableBlocks` in `funcdata_block.cc`.
//! Branch-test normalization follows `ActionNormalizeBranches::apply` in
//! `blockaction.cc`. The CSE actions follow `ActionCse::apply`,
//! `ActionMultiCse::apply`, `Funcdata::cseEliminateList`,
//! `Funcdata::cseElimination`, and `PcodeOp::isCseMatch` in `coreaction.cc`,
//! `funcdata_op.cc`, and `op.cc`, at Ghidra commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.
//!
//! A branch edge is part of the SSA contract: removing it also removes the
//! matching `MULTIEQUAL` operand. The graph owns that bookkeeping in
//! `Funcdata::remove_edge`; this module deliberately does not duplicate it.

use ventris_lifter::RAM_SPACE;
use ventris_pcode::op;

use super::action::Action;
use super::heritage::compute_dominance;
use super::{Funcdata, GraphBlockId, OpId, VarnodeId};

fn last_live_op(data: &Funcdata, block: GraphBlockId) -> Option<OpId> {
    data.block(block)
        .ops
        .iter()
        .rev()
        .copied()
        .find(|id| data.opcode_of(*id).is_some())
}

fn branch_target_block(data: &Funcdata, branch: OpId) -> Option<GraphBlockId> {
    // A relative p-code destination names an operation, not an address, so the
    // shared resolver is the only correct way to ask where a branch goes.
    data.branch_target(branch)
}

fn address_for_block(data: &mut Funcdata, block: GraphBlockId, size: u32) -> VarnodeId {
    data.new_varnode(RAM_SPACE, data.block(block).start, size.max(1))
}

fn set_branch_target(data: &mut Funcdata, branch: OpId, target: GraphBlockId, size: u32) {
    let target_value = data
        .op(branch)
        .inputs
        .first()
        .copied()
        .filter(|value| {
            let varnode = data.varnode(*value);
            varnode.offset == data.block(target).start
        })
        .unwrap_or_else(|| address_for_block(data, target, size));
    let condition = (data.op(branch).opcode == op::CBRANCH)
        .then(|| data.op(branch).inputs.get(1).copied())
        .flatten();
    let mut inputs = vec![target_value];
    if let Some(condition) = condition {
        inputs.push(condition);
    }
    data.op_set_inputs(branch, inputs);
}

/// Folds a constant conditional transfer and drops the edge that cannot run.
pub struct ActionDeterminedBranch;

impl Action for ActionDeterminedBranch {
    fn name(&self) -> &'static str {
        "determined-branch"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let candidates: Vec<(GraphBlockId, OpId)> = data
            .blocks()
            .filter_map(|(block, _)| {
                let op = last_live_op(data, block)?;
                (data.op(op).opcode == op::CBRANCH).then_some((block, op))
            })
            .collect();
        let mut changed = 0;
        for (block, branch) in candidates {
            let (condition, target_size, successors) = {
                let operation = data.op(branch);
                let Some(condition) = operation.inputs.get(1).copied() else {
                    continue;
                };
                (
                    condition,
                    operation
                        .inputs
                        .first()
                        .map(|value| data.varnode(*value).size)
                        .unwrap_or(4),
                    data.block(block).successors.clone(),
                )
            };
            if !data.varnode(condition).flags.constant || successors.len() < 2 {
                continue;
            }
            let Some(target) = branch_target_block(data, branch) else {
                continue;
            };
            let Some(&other) = successors.iter().find(|successor| **successor != target) else {
                continue;
            };
            let taken = data.varnode(condition).offset != 0;
            let keep = if taken { target } else { other };
            let drop = if taken { other } else { target };
            if !data.remove_edge(block, drop) {
                continue;
            }
            // Keeping a real BRANCH makes the remaining edge explicit even when
            // the constant selected the old fall-through side.
            data.op_set_opcode(branch, op::BRANCH);
            set_branch_target(data, branch, keep, target_size);
            changed += 1;
        }
        changed
    }
}

/// Removes a branch that decides nothing, and merges the blocks it joined.
///
/// `ActionRedundBranch::apply` has two arms, and only the second is about
/// conditionals. A block with a *single* way out whose successor has a single
/// way in is spliced into that successor outright - the pass is Ghidra's main
/// straight-line block merger, and skipping it leaves every instruction-level
/// split in the graph for structuring to account for. The exclusions are exact:
/// not the entry block, because it anchors the function, and not a switch-out
/// block, because "this prevents possible second stage recovery" of the jump
/// table.
///
/// The second arm is the conditional one: when every edge out of a block goes
/// to the same place, the test is dead and Ghidra removes the branch.
pub struct ActionRedundBranch;

impl Action for ActionRedundBranch {
    fn name(&self) -> &'static str {
        "redundant-branch"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let mut changed = 0;
        // Splicing removes a block, so the walk restarts - as Ghidra's `i = -1`
        // does - rather than continuing over identifiers it has just retired.
        loop {
            let spliceable = data.blocks().find(|(block, graph_block)| {
                if graph_block.successors.len() != 1 {
                    return false;
                }
                // This graph interns duplicate edges, so a block still holding
                // a `CBRANCH` with one successor is Ghidra's two-identical-edges
                // block, where `sizeOut()` is 2 and the splice arm is not
                // reached. It belongs to the conditional arm below.
                if last_live_op(data, *block)
                    .is_some_and(|operation| data.op(operation).opcode == op::CBRANCH)
                {
                    return false;
                }
                let successor = graph_block.successors[0];
                successor != *block
                    && data.block(successor).predecessors.len() == 1
                    && !data.is_entry_block(successor)
                    && !data.is_switch_out(*block)
            });
            let Some((block, _)) = spliceable else { break };
            if !data.splice_block_basic(block) {
                break;
            }
            changed += 1;
        }
        let candidates: Vec<(GraphBlockId, OpId)> = data
            .blocks()
            .filter_map(|(block, _)| {
                let operation = last_live_op(data, block)?;
                (data.op(operation).opcode == op::CBRANCH).then_some((block, operation))
            })
            .collect();
        for (block, branch) in candidates {
            let successors = data.block(block).successors.clone();
            if successors.is_empty() || successors.windows(2).any(|pair| pair[0] != pair[1]) {
                // The graph normally interns duplicate edges. A one-edge
                // CBRANCH is still redundant after an earlier edge cleanup.
                if successors.len() != 1 {
                    continue;
                }
            }
            let target_size = data
                .op(branch)
                .inputs
                .first()
                .map(|value| data.varnode(*value).size)
                .unwrap_or(4);
            let target = successors[0];
            data.op_set_opcode(branch, op::BRANCH);
            set_branch_target(data, branch, target, target_size);
            changed += 1;
        }
        changed
    }
}

/// Repairs a terminator that still names a block the graph no longer has.
///
/// Ghidra's branch operands are block references, so removing a block cannot
/// leave a predecessor pointing at it. Here they are addresses, and unreachable
/// removal drops the edge without touching the operand - leaving a `goto` to a
/// label that is never emitted, because the block it names was never printed.
/// `__FrameCallback__Fl` and `TRK_fill_mem` both carried such jumps.
///
/// A conditional whose remaining destination is its own fall-through decides
/// nothing and goes; an unconditional one naming nothing at all goes with it.
pub struct ActionPruneDeadTargets;

impl Action for ActionPruneDeadTargets {
    fn name(&self) -> &'static str {
        "prune-dead-targets"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        // A block that has absorbed another still covers the absorbed block's
        // address, so a branch naming it is not stale.
        let starts: std::collections::BTreeSet<u64> = data
            .blocks()
            .flat_map(|(_, block)| {
                std::iter::once((block.start, block.start_order))
                    .chain(block.absorbed.iter().copied())
            })
            .filter(|(_, order)| *order == 0)
            .map(|(start, _)| start)
            .collect();
        let stale: Vec<(OpId, GraphBlockId)> = data
            .blocks()
            .filter_map(|(block, _)| {
                let terminator = last_live_op(data, block)?;
                let operation = data.op(terminator);
                if !matches!(operation.opcode, op::BRANCH | op::CBRANCH) {
                    return None;
                }
                let target = operation.inputs.first().copied()?;
                let varnode = data.varnode(target);
                // A relative p-code destination names an operation, not an
                // address, and is resolved elsewhere.
                if varnode.space == ventris_lifter::CONST_SPACE {
                    return None;
                }
                (!starts.contains(&varnode.offset)).then_some((terminator, block))
            })
            .collect();
        let mut changed = 0;
        for (terminator, block) in stale {
            let successors = data.block(block).successors.clone();
            match successors.len() {
                // One destination left: say so plainly instead of naming a
                // block that is gone.
                1 => {
                    let size = data
                        .op(terminator)
                        .inputs
                        .first()
                        .map(|value| data.varnode(*value).size)
                        .unwrap_or(4);
                    data.op_set_opcode(terminator, op::BRANCH);
                    set_branch_target(data, terminator, successors[0], size);
                }
                // A conditional branch that still has both its edges keeps
                // its test: only the *operand* is stale, because the block it
                // named was merged away while the edge was rewired to the
                // survivor. Destroying it left a two-way block with nothing to
                // test, which the emitter could only render as a fabricated
                // constant - `DBGEXIImm` printed `if (!1)` where the oracle has
                // `if (param_3 == 0)`.
                //
                // The taken edge is the successor that is *not* this block's
                // sequential fallthrough, and blocks are created in address
                // order, so the fallthrough is the successor whose start is the
                // next block start after this one.
                2 if data.op(terminator).opcode == op::CBRANCH => {
                    let here = data.block(block).start;
                    let sequential = starts.range(here + 1..).next().copied();
                    let taken: Vec<GraphBlockId> = successors
                        .iter()
                        .copied()
                        .filter(|successor| Some(data.block(*successor).start) != sequential)
                        .collect();
                    match taken.as_slice() {
                        [taken] => {
                            let size = data
                                .op(terminator)
                                .inputs
                                .first()
                                .map(|value| data.varnode(*value).size)
                                .unwrap_or(4);
                            set_branch_target(data, terminator, *taken, size);
                        }
                        // Neither or both look like the fallthrough: there is no
                        // edge to name, so the branch cannot be repaired here.
                        _ => data.op_destroy(terminator),
                    }
                }
                // Nothing left to branch to at all.
                _ => data.op_destroy(terminator),
            }
            changed += 1;
        }
        changed
    }
}

/// Removes blocks unreachable from the entry, including their merge inputs.
pub struct ActionUnreachable;

impl Action for ActionUnreachable {
    fn name(&self) -> &'static str {
        "unreachable"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        // Funcdata::remove_unreachable_blocks owns predecessor/phi alignment;
        // doing that work here would duplicate a subtle positional invariant.
        data.remove_unreachable_blocks()
    }
}

/// Removes a block that performs no operations.
///
/// `ActionDoNothing::apply`. The candidate test is `BlockBasic::isDoNothing`,
/// which accepts any block with one way out, at least one way in, and nothing
/// but markers and a branch inside - a block holding only merges, or nothing at
/// all, qualifies just as much as one holding a lone `BRANCH`. Removal goes
/// through `Funcdata::removeDoNothingBlock`, which relocates the merges the
/// block carried; the wider test is only correct together with that relocation,
/// and Ghidra pairs them for exactly that reason.
///
/// A self-loop that does nothing is an infinite loop, and Ghidra warns rather
/// than removing it, because removing it would delete the loop.
pub struct ActionDoNothing;

impl Action for ActionDoNothing {
    fn name(&self) -> &'static str {
        "do-nothing"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let candidates: Vec<GraphBlockId> = data.blocks().map(|(block, _)| block).collect();
        for block in candidates {
            if !data.is_do_nothing(block) {
                continue;
            }
            let successors = data.block(block).successors.clone();
            if successors.first() == Some(&block) {
                continue;
            }
            if !data.unblocked_multi(block, 0) {
                continue;
            }
            if data.remove_do_nothing_block(block) {
                return 1;
            }
        }
        0
    }
}

fn inverse_test(data: &Funcdata, operation: OpId) -> Option<i32> {
    let opcode = data.op(operation).opcode;
    match opcode {
        // Equality is ambivalent in Ghidra's opFlipInPlaceTest: inverting it
        // does not make the surrounding branch layout more canonical.
        op::INT_NOTEQUAL => Some(op::INT_EQUAL),
        op::FLOAT_NOTEQUAL => Some(op::FLOAT_EQUAL),
        op::INT_SLESS
            if data
                .op(operation)
                .inputs
                .first()
                .is_some_and(|value| data.varnode(*value).flags.constant) =>
        {
            Some(op::INT_SLESSEQUAL)
        }
        op::INT_LESS
            if data
                .op(operation)
                .inputs
                .first()
                .is_some_and(|value| data.varnode(*value).flags.constant) =>
        {
            Some(op::INT_LESSEQUAL)
        }
        op::INT_SLESSEQUAL
            if data
                .op(operation)
                .inputs
                .get(1)
                .is_some_and(|value| data.varnode(*value).flags.constant) =>
        {
            Some(op::INT_SLESS)
        }
        op::INT_LESSEQUAL
            if data
                .op(operation)
                .inputs
                .get(1)
                .is_some_and(|value| data.varnode(*value).flags.constant) =>
        {
            Some(op::INT_LESS)
        }
        _ => None,
    }
}

/// Folds a branch's negated condition into the branch itself.
pub struct ActionCbranchFlip;

impl Action for ActionCbranchFlip {
    fn name(&self) -> &'static str {
        "cbranch-flip"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let candidates: Vec<(GraphBlockId, OpId)> = data
            .blocks()
            .filter_map(|(block, _)| {
                let branch = last_live_op(data, block)?;
                (data.op(branch).opcode == op::CBRANCH).then_some((block, branch))
            })
            .collect();
        let mut changed = 0;
        for (block, branch) in candidates {
            if data.block(block).successors.len() != 2 {
                continue;
            }
            let Some(condition) = data.op(branch).inputs.get(1).copied() else {
                continue;
            };
            let Some(def) = data.varnode(condition).def else {
                continue;
            };
            if data.op(def).opcode != op::BOOL_NEGATE {
                continue;
            }
            let Some(target) = branch_target_block(data, branch) else {
                continue;
            };
            let other = data
                .block(block)
                .successors
                .iter()
                .copied()
                .find(|successor| *successor != target);
            let Some(other) = other else { continue };
            let Some(source) = data.op(def).inputs.first().copied() else {
                continue;
            };
            let size = data
                .op(branch)
                .inputs
                .first()
                .map(|value| data.varnode(*value).size)
                .unwrap_or(4);
            data.op_set_input(branch, source, 1);
            set_branch_target(data, branch, other, size);
            changed += 1;
        }
        changed
    }
}

/// Normalizes a branch by inverting a branch-only comparison and its target.
pub struct ActionNormalizeBranches;

impl Action for ActionNormalizeBranches {
    fn name(&self) -> &'static str {
        "normalize-branches"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let candidates: Vec<(GraphBlockId, OpId)> = data
            .blocks()
            .filter_map(|(block, _)| {
                let branch = last_live_op(data, block)?;
                (data.op(branch).opcode == op::CBRANCH).then_some((block, branch))
            })
            .collect();
        let mut changed = 0;
        for (block, branch) in candidates {
            if data.block(block).successors.len() != 2 {
                continue;
            }
            let condition = match data.op(branch).inputs.get(1).copied() {
                Some(condition) => condition,
                None => continue,
            };
            let Some(def) = data.varnode(condition).def else {
                continue;
            };
            if data.lone_descend(condition) != Some(branch) {
                continue;
            }
            let target = match branch_target_block(data, branch) {
                Some(target) => target,
                None => continue,
            };
            let other = data
                .block(block)
                .successors
                .iter()
                .copied()
                .find(|successor| *successor != target);
            let Some(other) = other else { continue };
            let size = data
                .op(branch)
                .inputs
                .first()
                .map(|value| data.varnode(*value).size)
                .unwrap_or(4);
            let Some(inverse) = inverse_test(data, def) else {
                continue;
            };
            let original = data.op(def).opcode;
            if matches!(
                original,
                op::INT_SLESS | op::INT_SLESSEQUAL | op::INT_LESS | op::INT_LESSEQUAL
            ) {
                let mut inputs = data.op(def).inputs.clone();
                if inputs.len() >= 2 {
                    inputs.swap(0, 1);
                    data.op_set_inputs(def, inputs);
                }
            }
            data.op_set_opcode(def, inverse);
            set_branch_target(data, branch, other, size);
            changed += 1;
        }
        changed
    }
}

fn side_effect(opcode: i32) -> bool {
    matches!(
        opcode,
        op::LOAD
            | op::STORE
            | op::CALL
            | op::CALLIND
            | op::CALLOTHER
            | op::INDIRECT
            | op::MULTIEQUAL
            | op::RETURN
            | op::BRANCH
            | op::CBRANCH
            | op::BRANCHIND
    )
}

fn same_value(data: &Funcdata, left: VarnodeId, right: VarnodeId) -> bool {
    if left == right {
        return true;
    }
    let left = data.varnode(left);
    let right = data.varnode(right);
    if left.flags.constant && right.flags.constant {
        return left.space == right.space && left.offset == right.offset && left.size == right.size;
    }
    left.def.is_none()
        && right.def.is_none()
        && left.space == right.space
        && left.offset == right.offset
        && left.size == right.size
}

fn dominates_block(
    dominators: &super::heritage::Dominance,
    dominator: GraphBlockId,
    block: GraphBlockId,
) -> bool {
    if dominator == block {
        return true;
    }
    let mut cursor = block;
    let mut guard = 0;
    while guard <= dominators.immediate.len() {
        let Some(parent) = dominators.immediate.get(&cursor).copied().flatten() else {
            return false;
        };
        if parent == cursor {
            return false;
        }
        if parent == dominator {
            return true;
        }
        cursor = parent;
        guard += 1;
    }
    false
}

fn dominates_op(
    data: &Funcdata,
    dominators: &super::heritage::Dominance,
    first: OpId,
    second: OpId,
) -> bool {
    let Some(first_block) = data.op(first).parent else {
        return false;
    };
    let Some(second_block) = data.op(second).parent else {
        return false;
    };
    if first_block == second_block {
        let first_seq = data.op(first).seq;
        let second_seq = data.op(second).seq;
        return first_seq < second_seq || (first_seq == second_seq && first <= second);
    }
    dominates_block(dominators, first_block, second_block)
}

fn eliminate_common(data: &mut Funcdata) -> usize {
    let mut changes = 0;
    // Every elimination removes one live operation, so the cap is only a guard
    // against malformed graphs whose dominance map cannot make progress.
    for _ in 0..=data.op_count() {
        let dominators = compute_dominance(data);
        let operations: Vec<OpId> = data.live_ops().map(|(id, _)| id).collect();
        let mut eliminated = false;
        'pairs: for (index, left) in operations.iter().copied().enumerate() {
            let Some(left_opcode) = data.opcode_of(left) else {
                continue;
            };
            if side_effect(left_opcode) || data.op(left).output.is_none() {
                continue;
            }
            for right in operations.iter().copied().skip(index + 1) {
                let Some(right_opcode) = data.opcode_of(right) else {
                    continue;
                };
                if right_opcode != left_opcode
                    || side_effect(right_opcode)
                    || data.op(right).output.is_none()
                {
                    continue;
                }
                let left_inputs = data.op(left).inputs.clone();
                let right_inputs = data.op(right).inputs.clone();
                if left_inputs.len() != right_inputs.len()
                    || !left_inputs
                        .iter()
                        .zip(right_inputs.iter())
                        .all(|(a, b)| same_value(data, *a, *b))
                {
                    continue;
                }
                let (dominating, dominated) = if dominates_op(data, &dominators, left, right) {
                    (left, right)
                } else if dominates_op(data, &dominators, right, left) {
                    (right, left)
                } else {
                    continue;
                };
                let Some(old) = data.op(dominated).output else {
                    continue;
                };
                let Some(new) = data.op(dominating).output else {
                    continue;
                };
                if old == new {
                    continue;
                }
                data.total_replace(old, new);
                data.op_destroy(dominated);
                changes += 1;
                eliminated = true;
                break 'pairs;
            }
        }
        if !eliminated {
            break;
        }
    }
    changes
}

/// Eliminates pure duplicate calculations whose defining block dominates use.
pub struct ActionCse;

impl Action for ActionCse {
    fn name(&self) -> &'static str {
        "cse"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        eliminate_common(data)
    }
}

/// Repeats common-subexpression elimination after earlier rewrites expose pairs.
pub struct ActionMultiCse;

impl Action for ActionMultiCse {
    fn name(&self) -> &'static str {
        "multi-cse"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        eliminate_common(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SeqNum;

    fn seq(address: u64, order: u32) -> SeqNum {
        SeqNum { address, order }
    }

    fn branch_graph(condition: u64) -> (Funcdata, GraphBlockId, GraphBlockId, GraphBlockId, OpId) {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        let target = data.new_block(0x1010);
        let fallthrough = data.new_block(0x1020);
        data.add_edge(entry, target);
        data.add_edge(entry, fallthrough);
        let destination = data.new_varnode(RAM_SPACE, 0x1010, 4);
        let value = data.new_constant(condition, 1);
        let branch = data.new_op(op::CBRANCH, seq(0x1000, 0), vec![destination, value]);
        data.op_insert_end(branch, entry);
        (data, entry, target, fallthrough, branch)
    }

    #[test]
    fn determined_branch_removes_the_untaken_edge_and_unreachable_block() {
        let (mut data, entry, target, fallthrough, branch) = branch_graph(1);
        assert_eq!(ActionDeterminedBranch.apply(&mut data), 1);
        assert_eq!(data.op(branch).opcode, op::BRANCH);
        assert_eq!(data.block(entry).successors, vec![target]);
        assert_eq!(ActionUnreachable.apply(&mut data), 1);
        assert!(data.block(fallthrough).dead);
    }

    #[test]
    fn determined_branch_does_not_touch_nonconstant_conditions() {
        let (mut data, entry, _, _, branch) = branch_graph(1);
        let condition = data.new_unique(1);
        data.op_set_input(branch, condition, 1);
        assert_eq!(ActionDeterminedBranch.apply(&mut data), 0);
        assert_eq!(data.op(branch).opcode, op::CBRANCH);
        assert_eq!(data.block(entry).successors.len(), 2);
    }

    #[test]
    fn redundant_single_edge_cbranch_becomes_branch() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        let target = data.new_block(0x1010);
        data.add_edge(entry, target);
        let address = data.new_varnode(RAM_SPACE, 0x1010, 4);
        let flag = data.new_unique(1);
        let branch = data.new_op(op::CBRANCH, seq(0x1000, 0), vec![address, flag]);
        data.op_insert_end(branch, entry);
        assert_eq!(ActionRedundBranch.apply(&mut data), 1);
        assert_eq!(data.op(branch).opcode, op::BRANCH);
        assert_eq!(data.op(branch).inputs.len(), 1);
    }

    #[test]
    fn redundant_branch_requires_one_effective_destination() {
        let (mut data, _, _, _, branch) = branch_graph(1);
        assert_eq!(ActionRedundBranch.apply(&mut data), 0);
        assert_eq!(data.op(branch).opcode, op::CBRANCH);
    }

    #[test]
    fn unreachable_action_removes_disconnected_block() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let _entry = data.new_block(0x1000);
        let dead = data.new_block(0x2000);
        let value = data.new_constant(7, 4);
        let copy = data.new_op(op::COPY, seq(0x2000, 0), vec![value]);
        let output = data.new_unique(4);
        data.op_set_output(copy, Some(output));

        data.op_insert_end(copy, dead);
        assert_eq!(ActionUnreachable.apply(&mut data), 1);
        assert!(data.block(dead).dead);
    }

    /// A block holding only merges does nothing just as much as one holding a
    /// lone `BRANCH`, and `BlockBasic::isDoNothing` accepts it. The removal has
    /// to relocate the merge it carried, which is the half that makes the wider
    /// test safe: the successor's merge loses the operand this block delivered
    /// and gains that merge's own operand per predecessor.
    #[test]
    fn do_nothing_removes_a_block_holding_only_a_merge_and_relocates_it() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        let left = data.new_block(0x1010);
        let right = data.new_block(0x1020);
        let middle = data.new_block(0x1030);
        let exit = data.new_block(0x1040);
        data.add_edge(entry, left);
        data.add_edge(entry, right);
        data.add_edge(left, middle);
        data.add_edge(right, middle);
        data.add_edge(middle, exit);

        // Each arm computes the value it delivers, so the arms are not
        // themselves do-nothing blocks.
        let from_left = data.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
        let left_value = data.new_constant(1, 4);
        let left_write = data.new_op(op::COPY, seq(0x1010, 0), vec![left_value]);
        data.op_set_output(left_write, Some(from_left));
        data.op_insert_end(left_write, left);
        let from_right = data.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
        let right_value = data.new_constant(2, 4);
        let right_write = data.new_op(op::COPY, seq(0x1020, 0), vec![right_value]);
        data.op_set_output(right_write, Some(from_right));
        data.op_insert_end(right_write, right);
        let inner = data.new_op(op::MULTIEQUAL, seq(0x1030, 0), vec![from_left, from_right]);
        let merged = data.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
        data.op_set_output(inner, Some(merged));
        data.op_insert_end(inner, middle);

        // The successor merges the value the removed block produced with one
        // arriving on an edge of its own.
        let other = data.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
        data.add_edge(entry, exit);
        let outer = data.new_op(op::MULTIEQUAL, seq(0x1040, 0), vec![merged, other]);
        let result = data.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
        data.op_set_output(outer, Some(result));
        data.op_insert_end(outer, exit);

        assert!(data.is_do_nothing(middle), "only a marker inside");
        assert_eq!(ActionDoNothing.apply(&mut data), 1);
        assert!(data.block(middle).dead);
        // Both arms now reach the exit directly, and the merge there reads one
        // operand per edge - the inner merge's own operands, not a copy of it.
        assert_eq!(
            data.block(exit).predecessors.len(),
            data.op(outer).inputs.len(),
            "one operand per edge"
        );
        assert!(
            data.op(outer).inputs.contains(&from_left)
                && data.op(outer).inputs.contains(&from_right),
            "each predecessor contributes the merge's own operand"
        );
    }

    /// `BlockBasic::isDoNothing` refuses a single-out computed jump: that is a
    /// jump-table stage, not a transfer.
    #[test]
    fn do_nothing_refuses_a_single_out_computed_jump() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        let middle = data.new_block(0x1010);
        let exit = data.new_block(0x1020);
        data.add_edge(entry, middle);
        data.add_edge(middle, exit);
        let target = data.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
        let jump = data.new_op(op::BRANCHIND, seq(0x1010, 0), vec![target]);
        data.op_insert_end(jump, middle);
        assert!(!data.is_do_nothing(middle));
        assert_eq!(ActionDoNothing.apply(&mut data), 0);
    }

    /// `ActionRedundBranch`'s first arm: a single-out block whose successor has a
    /// single way in is spliced, and the survivor keeps the earlier address.
    #[test]
    fn redundant_branch_splices_a_straight_line_pair() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        let tail = data.new_block(0x1010);
        data.add_edge(entry, tail);
        let value = data.new_constant(1, 4);
        let work = data.new_op(op::COPY, seq(0x1010, 0), vec![value]);
        let out = data.new_unique(4);
        data.op_set_output(work, Some(out));
        data.op_insert_end(work, tail);

        assert!(ActionRedundBranch.apply(&mut data) > 0);
        assert!(data.block(tail).dead);
        assert!(data.block(entry).ops.contains(&work));
        // The absorbed block's position still resolves, so a branch naming it is
        // not left pointing at a label nothing emits.
        assert_eq!(data.block_starting_at(0x1010), Some(entry));
    }

    #[test]
    fn unreachable_action_does_not_remove_entry_component() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        assert_eq!(ActionUnreachable.apply(&mut data), 0);
        assert!(!data.block(entry).dead);
    }

    #[test]
    fn do_nothing_splices_transfer_only_block() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        let middle = data.new_block(0x1010);
        let exit = data.new_block(0x1020);
        data.add_edge(entry, middle);
        data.add_edge(middle, exit);
        let target = data.new_varnode(RAM_SPACE, 0x1020, 4);
        let jump = data.new_op(op::BRANCH, seq(0x1010, 0), vec![target]);
        data.op_insert_end(jump, middle);
        assert_eq!(ActionDoNothing.apply(&mut data), 1);
        assert!(data.block(middle).dead);
        assert_eq!(data.block(entry).successors, vec![exit]);
    }

    #[test]
    fn do_nothing_does_not_splice_a_computing_block() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        let middle = data.new_block(0x1010);
        let exit = data.new_block(0x1020);
        data.add_edge(entry, middle);
        data.add_edge(middle, exit);
        let value = data.new_constant(1, 4);
        let copy = data.new_op(op::COPY, seq(0x1010, 0), vec![value]);
        data.op_insert_end(copy, middle);
        let target = data.new_varnode(RAM_SPACE, 0x1020, 4);
        let jump = data.new_op(op::BRANCH, seq(0x1010, 1), vec![target]);
        data.op_insert_end(jump, middle);
        assert_eq!(ActionDoNothing.apply(&mut data), 0);
        assert!(!data.block(middle).dead);
    }

    #[test]
    fn normalize_branches_inverts_a_branch_only_comparison() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        let target = data.new_block(0x1010);
        let other = data.new_block(0x1020);
        data.add_edge(entry, target);
        data.add_edge(entry, other);
        let left = data.new_constant(1, 4);
        let right = data.new_constant(1, 4);
        let comparison = data.new_op(op::INT_NOTEQUAL, seq(0x1000, 0), vec![left, right]);
        let condition = data.new_unique(1);
        data.op_set_output(comparison, Some(condition));
        data.op_insert_end(comparison, entry);
        let destination = data.new_varnode(RAM_SPACE, 0x1010, 4);
        let branch = data.new_op(op::CBRANCH, seq(0x1000, 1), vec![destination, condition]);
        data.op_insert_end(branch, entry);
        assert_eq!(ActionNormalizeBranches.apply(&mut data), 1);
        assert_eq!(data.op(comparison).opcode, op::INT_EQUAL);
        assert_eq!(data.varnode(data.op(branch).inputs[0]).offset, 0x1020);
    }

    #[test]
    fn normalize_branches_does_not_flip_a_shared_condition() {
        let (mut data, entry, _, _, branch) = branch_graph(1);
        let condition = data.new_unique(1);
        data.op_set_input(branch, condition, 1);
        let use_op = data.new_op(op::BOOL_NEGATE, seq(0x1000, 1), vec![condition]);
        data.op_insert_before(use_op, branch);
        assert_eq!(ActionNormalizeBranches.apply(&mut data), 0);
        assert_eq!(data.op(branch).opcode, op::CBRANCH);
        assert_eq!(data.block(entry).successors.len(), 2);
    }

    fn two_adds() -> (Funcdata, OpId, OpId) {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let first_block = data.new_block(0x1000);
        let second_block = data.new_block(0x1010);
        data.add_edge(first_block, second_block);
        let left = data.new_constant(2, 4);
        let right = data.new_constant(3, 4);
        let first = data.new_op(op::INT_ADD, seq(0x1000, 0), vec![left, right]);
        let first_out = data.new_unique(4);
        data.op_set_output(first, Some(first_out));
        data.op_insert_end(first, first_block);
        let second = data.new_op(op::INT_ADD, seq(0x1010, 0), vec![left, right]);
        let second_out = data.new_unique(4);
        data.op_set_output(second, Some(second_out));
        data.op_insert_end(second, second_block);
        (data, first, second)
    }

    #[test]
    fn cse_collapses_a_dominated_identical_add() {
        let (mut data, first, second) = two_adds();
        let second_out = data.op(second).output.expect("second result");
        let second_block = data.op(second).parent.expect("second block");
        let use_op = data.new_op(op::INT_NEGATE, seq(0x1010, 1), vec![second_out]);
        data.op_insert_end(use_op, second_block);
        assert_eq!(ActionCse.apply(&mut data), 1);
        let first_out = data.op(first).output.expect("first result");
        assert_eq!(data.op(use_op).inputs, vec![first_out]);
        assert!(data.op(second).dead);
    }

    #[test]
    fn cse_does_not_collapse_identical_loads() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let space = data.new_constant(RAM_SPACE as u64, 4);
        let address = data.new_constant(0x2000, 4);
        let first = data.new_op(op::LOAD, seq(0x1000, 0), vec![space, address]);
        let first_out = data.new_unique(4);
        data.op_set_output(first, Some(first_out));
        data.op_insert_end(first, block);
        let second = data.new_op(op::LOAD, seq(0x1000, 1), vec![space, address]);
        let second_out = data.new_unique(4);
        data.op_set_output(second, Some(second_out));
        data.op_insert_end(second, block);
        assert_eq!(ActionCse.apply(&mut data), 0);
        assert!(!data.op(first).dead && !data.op(second).dead);
    }

    #[test]
    fn multi_cse_also_respects_dominance_and_effects() {
        let (mut data, _, second) = two_adds();
        assert_eq!(ActionMultiCse.apply(&mut data), 1);
        assert!(data.op(second).dead);
    }

    /// A conditional branch that still has *both* its edges keeps its test: only
    /// the operand is stale, because the block it named was merged away while the
    /// edge was rewired to the survivor. Destroying it left a two-way block with
    /// nothing to test, which the emitter could only render as a fabricated
    /// constant - `DBGEXIImm` printed `if (!1)` where the oracle has
    /// `if (param_3 == 0)`.
    #[test]
    fn a_stale_operand_on_a_live_two_way_branch_is_renamed_not_removed() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        // The sequential fallthrough, and the block the edge was rewired to.
        let fallthrough = data.new_block(0x1010);
        let survivor = data.new_block(0x1020);
        data.add_edge(entry, fallthrough);
        data.add_edge(entry, survivor);
        // The operand names a block that no longer exists.
        let destination = data.new_varnode(RAM_SPACE, 0x1018, 4);
        let condition = data.new_unique(1);
        let branch = data.new_op(op::CBRANCH, seq(0x1000, 0), vec![destination, condition]);
        data.op_insert_end(branch, entry);

        assert_eq!(ActionPruneDeadTargets.apply(&mut data), 1);
        assert!(!data.op(branch).dead, "the test survives");
        assert_eq!(data.op(branch).opcode, op::CBRANCH);
        assert_eq!(
            data.op(branch)
                .inputs
                .first()
                .map(|value| data.varnode(*value).offset),
            Some(0x1020),
            "the operand names the taken edge, not the sequential fallthrough"
        );
        assert_eq!(data.block(entry).successors.len(), 2, "both edges remain");
    }

    /// Unreachable removal drops the edge but not the operand, so a terminator
    /// can outlive the block it names. Left alone it prints a `goto` to a label
    /// nothing emits, because the named block was never printed.
    #[test]
    fn a_terminator_naming_a_removed_block_is_repaired() {
        let (mut data, entry, target, fallthrough, branch) = branch_graph(0);
        // Remove the taken side the way unreachable removal does: the edge goes,
        // the operand still names 0x1010.
        assert!(data.remove_edge(entry, target));
        assert_eq!(ActionUnreachable.apply(&mut data), 1);
        assert_eq!(
            data.op(branch)
                .inputs
                .first()
                .map(|value| data.varnode(*value).offset),
            Some(0x1010),
            "the operand still names the removed block"
        );

        assert_eq!(ActionPruneDeadTargets.apply(&mut data), 1);

        assert_eq!(
            data.op(branch).opcode,
            op::BRANCH,
            "one destination left, so the test decides nothing"
        );
        assert_eq!(
            data.branch_target(branch),
            Some(fallthrough),
            "and it names the block that is still there"
        );
    }
}
