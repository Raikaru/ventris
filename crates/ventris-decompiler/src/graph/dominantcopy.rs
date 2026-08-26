//! Port of Ghidra 12.1.3's `ActionDominantCopy` and the `Merge` methods it
//! drives: `processCopyTrims`, `processHighDominantCopy` and
//! `buildDominantCopy` from `merge.cc`.
//!
//! Merging inserts a COPY wherever it trims a value's live range, so one
//! variable can end up written by several COPYs that all read the same source.
//! Where one of those COPYs dominates the others, a single COPY placed at the
//! dominating block does the work of all of them and the rest can read its
//! result instead.
//!
//! Two parts of the C++ are deliberately absent, and neither is reachable here.
//! `buildDominantCopy` consults `Datatype::needsResolution` and calls
//! `forceFacingType`/`getTypeReadFacing` to carry a union's resolved field onto
//! the COPY it creates; `DataType` has no union variant, so that branch cannot
//! be entered. `processCopyTrims` also drives `processHighRedundantCopy`, which
//! marks a COPY non-printing rather than removing it, and `GraphOp` has no
//! non-printing flag — that pass is not ported rather than approximated, since
//! removing what Ghidra only hides would delete an assignment.

use std::collections::{BTreeMap, BTreeSet};

use ventris_pcode::op;

use super::action::Action;
use super::cover::Cover;
use super::heritage::compute_dominance;
use super::mergeaction::merge_all;
use super::{Funcdata, GraphBlockId, OpId, VarnodeId};

/// Replaces a group of COPYs from one source with a single dominating COPY.
pub struct ActionDominantCopy;

impl Action for ActionDominantCopy {
    fn name(&self) -> &'static str {
        "dominantcopy"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let mut changed = 0;
        for group in copy_groups(data) {
            // `processCopyTrims` drives both halves. The redundant-copy half
            // runs first, because a `COPY` a dominating one already performed is
            // not a trim to rebuild - it is an assignment to stop printing.
            changed += mark_redundant_copies(data, &group);
            changed += build_dominant_copy(data, &group);
        }
        changed
    }
}

/// Silences each `COPY` a dominating `COPY` from the same source already made.
///
/// Ghidra's `Merge::processHighRedundantCopy` and `markRedundantCopies`. Two
/// `COPY`s of one value into one variable are one assignment in the source; the
/// later one is marked non-printing rather than removed, because the value it
/// defines is still read. Removing it instead would delete an assignment, which
/// is why this pass was previously left out entirely.
///
/// `checkCopyPair` is the guard: the earlier `COPY` must dominate the later one,
/// and no other write of the same variable may intervene between them - such a
/// write means the later `COPY` is restoring a value that changed, so it says
/// something.
fn mark_redundant_copies(data: &mut Funcdata, group: &CopyGroup) -> usize {
    if group.copies.len() < 2 {
        return 0;
    }
    let dominance = compute_dominance(data);
    let variables = merge_all(data);
    let mut changed = 0;
    for (position, subordinate) in group.copies.iter().copied().enumerate().skip(1).rev() {
        if data.opcode_of(subordinate).is_none() || data.is_non_printing(subordinate) {
            continue;
        }
        for dominant in group.copies[..position].iter().copied().rev() {
            if data.opcode_of(dominant).is_none() {
                continue;
            }
            if check_copy_pair(data, &dominance, &variables, dominant, subordinate) {
                data.op_mark_non_printing(subordinate);
                changed += 1;
                break;
            }
        }
    }
    changed
}

/// Whether the later `COPY` says nothing the earlier one did not.
///
/// Ghidra's `Merge::checkCopyPair`.
fn check_copy_pair(
    data: &Funcdata,
    dominance: &super::heritage::Dominance,
    variables: &super::mergeaction::Variables,
    dominant: OpId,
    subordinate: OpId,
) -> bool {
    let (Some(dominant_block), Some(subordinate_block)) =
        (data.op(dominant).parent, data.op(subordinate).parent)
    else {
        return false;
    };
    if !dominators(dominance, subordinate_block).contains(&dominant_block) {
        return false;
    }
    let (Some(output), Some(source)) = (
        data.op(dominant).output,
        data.op(dominant).inputs.first().copied(),
    ) else {
        return false;
    };
    let variable = variables.high_of(output);
    // The range between the two copies: from the dominating copy's definition
    // to the subordinate's read of the same source.
    let range = Cover::of(data, output, dominance);
    for index in 0..data.varnode_count() {
        let candidate = VarnodeId(index as u32);
        if variables.high_of(candidate) != variable {
            continue;
        }
        let Some(definition) = data.varnode(candidate).def else {
            continue;
        };
        // A write that is itself a copy of the same value is not intervening.
        if data.op(definition).opcode == op::COPY
            && data.op(definition).inputs.first().copied() == Some(source)
        {
            continue;
        }
        let Some(block) = data.op(definition).parent else {
            continue;
        };
        let position = data
            .block(block)
            .ops
            .iter()
            .position(|held| *held == definition);
        if let Some(position) = position
            && range.contains(block, position)
        {
            return false;
        }
    }
    true
}

/// A set of COPY operations writing one variable from one source value.
struct CopyGroup {
    source: VarnodeId,
    copies: Vec<OpId>,
}

/// Every group of two or more COPYs that write one variable from one source.
///
/// This is `processCopyTrims` followed by `processHighDominantCopy`: the first
/// collects the variables written by more than one COPY, the second splits each
/// variable's COPYs into groups sharing a source. Ghidra tracks the candidates
/// in a `copyTrims` list accumulated while merging; the same set is recovered
/// here by reading the graph, which needs no extra state.
fn copy_groups(data: &Funcdata) -> Vec<CopyGroup> {
    let variables = merge_all(data);
    // Keyed by (variable, source) so a variable written from two different
    // sources yields two groups, exactly as the C++ grouping loop does.
    let mut grouped: BTreeMap<(u32, VarnodeId), Vec<OpId>> = BTreeMap::new();
    for (id, operation) in data.live_ops() {
        if operation.opcode != op::COPY {
            continue;
        }
        let (Some(output), Some(source)) = (operation.output, operation.inputs.first().copied())
        else {
            continue;
        };
        // `findAllIntoCopies` with `filterTemps` set takes only COPYs whose
        // output is a temporary. A named machine location is not a trim.
        if !data.varnode(output).flags.unique {
            continue;
        }
        grouped
            .entry((variables.high_of(output), source))
            .or_default()
            .push(id);
    }
    grouped
        .into_iter()
        .filter(|(_, copies)| copies.len() > 1)
        .map(|((_, source), copies)| CopyGroup { source, copies })
        .collect()
}

/// Every block that dominates the given one, itself included.
fn dominators(
    dominance: &super::heritage::Dominance,
    mut block: GraphBlockId,
) -> Vec<GraphBlockId> {
    let mut chain = vec![block];
    // The immediate-dominator map is a tree rooted at the entry, so walking it
    // terminates; the bound guards a malformed map rather than a real cycle.
    for _ in 0..dominance.immediate.len() {
        match dominance.immediate.get(&block).copied().flatten() {
            Some(parent) if parent != block => {
                chain.push(parent);
                block = parent;
            }
            _ => break,
        }
    }
    chain
}

/// The block dominating every block in the set.
///
/// Ghidra's `FlowBlock::findCommonBlock`. Walking each block's dominator chain
/// and taking the deepest shared entry gives the same answer without a
/// persistent block tree.
fn common_dominator(
    dominance: &super::heritage::Dominance,
    blocks: &[GraphBlockId],
) -> Option<GraphBlockId> {
    let first = blocks.first().copied()?;
    let mut shared: Vec<GraphBlockId> = dominators(dominance, first);
    for block in blocks.iter().skip(1).copied() {
        let chain: BTreeSet<GraphBlockId> = dominators(dominance, block).into_iter().collect();
        shared.retain(|candidate| chain.contains(candidate));
    }
    // `dominators` yields the chain innermost first, so the first survivor is
    // the deepest block dominating all of them.
    shared.first().copied()
}

/// Places one COPY where it dominates the group and redirects the rest to it.
fn build_dominant_copy(data: &mut Funcdata, group: &CopyGroup) -> usize {
    let dominance = compute_dominance(data);
    let blocks: Vec<GraphBlockId> = group
        .copies
        .iter()
        .filter_map(|id| data.op(*id).parent)
        .collect();
    if blocks.len() != group.copies.len() {
        return 0;
    }
    let Some(dominator) = common_dominator(&dominance, &blocks) else {
        return 0;
    };

    // The COPY already in the dominating block, if there is one, is the
    // dominating COPY; otherwise one is created there.
    let existing = group
        .copies
        .iter()
        .copied()
        .find(|id| data.op(*id).parent == Some(dominator));
    let (dominant_op, dominant_value, created) = match existing {
        Some(id) => {
            let Some(output) = data.op(id).output else {
                return 0;
            };
            (id, output, false)
        }
        None => {
            let size = data.varnode(group.source).size;
            let seq = data.op(group.copies[0]).seq;
            let copy = data.new_op(op::COPY, seq, vec![group.source]);
            let output = data.new_unique(size);
            data.op_set_output(copy, Some(output));
            data.op_insert_end(copy, dominator);
            (copy, output, true)
        }
    };

    // A COPY whose result is still live where the dominating value is live
    // cannot be replaced by it: the two would need the same name at the same
    // time. Ghidra tests this with `Cover::intersect` against the cover the
    // variable would have once the group's COPYs are gone.
    let dominance = compute_dominance(data);
    let dominant_cover = Cover::of(data, dominant_value, &dominance);
    let mut replaceable = Vec::new();
    for id in group.copies.iter().copied() {
        if id == dominant_op {
            continue;
        }
        let Some(output) = data.op(id).output else {
            continue;
        };
        if Cover::of(data, output, &dominance).intersects(&dominant_cover) {
            continue;
        }
        replaceable.push((id, output));
    }

    if replaceable.is_empty() {
        // Replacing one COPY with another gains nothing, and a COPY created for
        // a group that turned out to be unreplaceable is left behind.
        if created {
            data.op_destroy(dominant_op);
        }
        return 0;
    }

    let mut changed = 0;
    for (id, output) in replaceable {
        data.total_replace(output, dominant_value);
        data.op_destroy(id);
        changed += 1;
    }
    changed
}

pub fn all() -> Vec<Box<dyn Action>> {
    vec![Box::new(ActionDominantCopy)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SeqNum;
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    /// Entry block dominating two arms that rejoin, with a COPY of one source
    /// in each arm.
    fn diamond_with_two_copies() -> (Funcdata, Vec<OpId>, VarnodeId) {
        let mut data = Funcdata::default();
        let entry = data.new_block(0x1000);
        let left = data.new_block(0x1010);
        let right = data.new_block(0x1020);
        let join = data.new_block(0x1030);
        data.add_edge(entry, left);
        data.add_edge(entry, right);
        data.add_edge(left, join);
        data.add_edge(right, join);

        let source = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(source);

        let mut copies = Vec::new();
        for (block, address) in [(left, 0x1010), (right, 0x1020)] {
            let copy = data.new_op(op::COPY, seq(address), vec![source]);
            let output = data.new_unique(4);
            data.op_set_output(copy, Some(output));
            data.op_insert_end(copy, block);
            // A reader in the same block, so the value is used where defined.
            let read = data.new_op(op::INT_NEGATE, seq(address + 4), vec![output]);
            let negated = data.new_unique(4);
            data.op_set_output(read, Some(negated));
            data.op_insert_end(read, block);
            copies.push(copy);
        }
        (data, copies, source)
    }

    #[test]
    fn two_copies_of_one_source_collapse_to_a_dominating_copy() {
        let (mut data, copies, source) = diamond_with_two_copies();
        let before = data
            .live_ops()
            .filter(|(_, o)| o.opcode == op::COPY)
            .count();
        assert_eq!(before, 2, "fixture has two COPYs");

        let changed = ActionDominantCopy.apply(&mut data);
        assert!(changed > 0, "a dominating COPY should have been built");

        let after: Vec<OpId> = data
            .live_ops()
            .filter(|(_, o)| o.opcode == op::COPY)
            .map(|(id, _)| id)
            .collect();
        assert_eq!(after.len(), 1, "one COPY remains: {after:?}");
        assert_eq!(
            data.op(after[0]).inputs.first().copied(),
            Some(source),
            "the surviving COPY reads the original source"
        );
        assert!(
            copies.iter().all(|id| data.op(*id).dead || *id == after[0]),
            "the replaced COPYs are gone"
        );
    }

    #[test]
    fn a_second_application_reports_no_change() {
        // The pipeline runs actions to a fixpoint, so a pass that keeps
        // reporting work never terminates.
        let (mut data, _, _) = diamond_with_two_copies();
        ActionDominantCopy.apply(&mut data);
        assert_eq!(
            ActionDominantCopy.apply(&mut data),
            0,
            "nothing left to collapse"
        );
    }

    #[test]
    fn copies_from_different_sources_are_left_alone() {
        // Only COPYs sharing a source describe the same value; two sources are
        // two values and collapsing them would change the program.
        let mut data = Funcdata::default();
        let block = data.new_block(0x2000);
        let first = data.new_varnode(REGISTER_SPACE, 0, 4);
        let second = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.mark_input(first);
        data.mark_input(second);
        for (index, source) in [first, second].into_iter().enumerate() {
            let copy = data.new_op(op::COPY, seq(0x2000 + index as u64 * 4), vec![source]);
            let output = data.new_unique(4);
            data.op_set_output(copy, Some(output));
            data.op_insert_end(copy, block);
        }
        assert_eq!(
            ActionDominantCopy.apply(&mut data),
            0,
            "distinct sources are distinct values"
        );
    }

    #[test]
    fn a_named_output_is_not_a_trim() {
        // `findAllIntoCopies` takes only temporaries. A COPY into a machine
        // location is the program's own assignment, not one merging inserted.
        let mut data = Funcdata::default();
        let block = data.new_block(0x3000);
        let source = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(source);
        for index in 0..2u64 {
            let copy = data.new_op(op::COPY, seq(0x3000 + index * 4), vec![source]);
            let output = data.new_varnode(REGISTER_SPACE, 16 + index * 8, 4);
            data.op_set_output(copy, Some(output));
            data.op_insert_end(copy, block);
        }
        assert_eq!(
            ActionDominantCopy.apply(&mut data),
            0,
            "named outputs are not merge trims"
        );
    }
}
