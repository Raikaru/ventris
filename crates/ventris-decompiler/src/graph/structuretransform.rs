//! Final control-flow structure transforms ported from Ghidra's
//! `blockaction.cc`.
//!
//! Ghidra keeps a persistent `BlockGraph` on `Funcdata`; Ventris instead builds
//! an immutable [`super::structure::Structured`] tree from the mutable p-code
//! graph when it is needed.  The actions therefore use that tree as the same
//! traversal boundary, then apply the changes that are representable in
//! `Funcdata`: complementing a structured conditional rewrites the boolean
//! expression and each branch target, and the final structure transform moves
//! a verified loop iterator to the terminal position used by the emitter.
//!
//! The registration slot is Ghidra's `blockrecovery` group, after cleanup and
//! in this order: `ActionPreferComplement`, `ActionStructureTransform`, then
//! `ActionNormalizeBranches`.

use std::collections::BTreeSet;

use ventris_lifter::RAM_SPACE;
use ventris_pcode::op;

use super::action::Action;
use super::forloop::ForLoop;
use super::structure::{self, Condition, Structured};
use super::{Funcdata, GraphBlockId, OpId};

/// A planned rewrite of one conditional branch while complementing a
/// structured `if/else`.
#[derive(Clone, Copy)]
struct BranchFlip {
    branch: OpId,
    target: GraphBlockId,
    target_size: u32,
}

/// The p-code operations that have to be complemented for one condition.
#[derive(Default)]
struct FlipPlan {
    operations: Vec<OpId>,
    branches: Vec<BranchFlip>,
    branch_ids: BTreeSet<GraphBlockId>,
}

/// Result of Ghidra's `Funcdata::opFlipInPlaceTest`.
///
/// `Normalizing` is Ghidra's return value 0, `Ambiguous` is 1, and
/// `Unsupported` is 2.  `ActionPreferComplement` only executes a simple
/// condition when it is normalizing.  For a short-circuit condition the first
/// child decides whether the whole condition is preferred, exactly as
/// `BlockCondition::flipInPlaceTest` does; the second child may be ambiguous.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FlipResult {
    Normalizing,
    Ambiguous,
    Unsupported,
}

/// Attempt to flip a condition in place, collecting the operations that must
/// change but not mutating the graph.
fn test_flip_operation(data: &Funcdata, operation: OpId, fliplist: &mut Vec<OpId>) -> FlipResult {
    let Some(opcode) = data.opcode_of(operation) else {
        return FlipResult::Unsupported;
    };
    match opcode {
        op::CBRANCH => {
            let Some(condition) = data.op(operation).inputs.get(1).copied() else {
                return FlipResult::Unsupported;
            };
            if data.lone_descend(condition) != Some(operation) {
                return FlipResult::Unsupported;
            }
            let Some(definition) = data.varnode(condition).def else {
                return FlipResult::Unsupported;
            };
            test_flip_operation(data, definition, fliplist)
        }
        op::INT_EQUAL | op::FLOAT_EQUAL => {
            fliplist.push(operation);
            FlipResult::Ambiguous
        }
        op::BOOL_NEGATE | op::INT_NOTEQUAL | op::FLOAT_NOTEQUAL => {
            fliplist.push(operation);
            FlipResult::Normalizing
        }
        op::INT_SLESS | op::INT_LESS => {
            let Some(first) = data.op(operation).inputs.first().copied() else {
                return FlipResult::Unsupported;
            };
            fliplist.push(operation);
            if data.varnode(first).flags.constant {
                FlipResult::Normalizing
            } else {
                FlipResult::Ambiguous
            }
        }
        op::INT_SLESSEQUAL | op::INT_LESSEQUAL => {
            let Some(second) = data.op(operation).inputs.get(1).copied() else {
                return FlipResult::Unsupported;
            };
            fliplist.push(operation);
            if data.varnode(second).flags.constant {
                FlipResult::Normalizing
            } else {
                FlipResult::Ambiguous
            }
        }
        op::BOOL_OR | op::BOOL_AND => {
            let Some(first) = data.op(operation).inputs.first().copied() else {
                return FlipResult::Unsupported;
            };
            if data.lone_descend(first) != Some(operation) {
                return FlipResult::Unsupported;
            }
            let Some(first_definition) = data.varnode(first).def else {
                return FlipResult::Unsupported;
            };
            let first_result = test_flip_operation(data, first_definition, fliplist);
            if first_result == FlipResult::Unsupported {
                return FlipResult::Unsupported;
            }

            let Some(second) = data.op(operation).inputs.get(1).copied() else {
                return FlipResult::Unsupported;
            };
            if data.lone_descend(second) != Some(operation) {
                return FlipResult::Unsupported;
            }
            let Some(second_definition) = data.varnode(second).def else {
                return FlipResult::Unsupported;
            };
            if test_flip_operation(data, second_definition, fliplist) == FlipResult::Unsupported {
                return FlipResult::Unsupported;
            }
            fliplist.push(operation);
            first_result
        }
        _ => FlipResult::Unsupported,
    }
}

/// Find the final live operation in a basic block.
fn last_live_op(data: &Funcdata, block: GraphBlockId) -> Option<OpId> {
    data.block(block)
        .ops
        .iter()
        .rev()
        .copied()
        .find(|operation| data.opcode_of(*operation).is_some())
}

/// Find the block named by a branch target varnode.
fn target_block(data: &Funcdata, target: super::VarnodeId) -> Option<GraphBlockId> {
    // Only an instruction-boundary block can be named by an address; a relative
    // p-code destination is resolved by `Funcdata::branch_target` from its op.
    data.block_starting_at(data.varnode(target).offset)
}

/// Plan the branch-edge part of complementing one condition leaf.
fn plan_branch_flip(data: &Funcdata, block: GraphBlockId, plan: &mut FlipPlan) -> Option<OpId> {
    if !plan.branch_ids.insert(block) {
        return None;
    }
    let branch = last_live_op(data, block)?;
    if data.opcode_of(branch) != Some(op::CBRANCH) {
        return None;
    }
    let target_value = data.op(branch).inputs.first().copied()?;
    let target = target_block(data, target_value)?;
    let successors = &data.block(block).successors;
    if successors.len() != 2 || !successors.contains(&target) {
        return None;
    }
    let other = successors
        .iter()
        .copied()
        .find(|successor| *successor != target)?;
    let target_size = data.varnode(target_value).size.max(1);
    plan.branches.push(BranchFlip {
        branch,
        target: other,
        target_size,
    });
    Some(branch)
}

/// Plan the complete complement for a [`Condition`] tree.
fn test_condition(
    data: &Funcdata,
    condition: &Condition,
    plan: &mut FlipPlan,
) -> Option<FlipResult> {
    match condition {
        Condition::Branch { block, .. } => {
            let branch = plan_branch_flip(data, *block, plan)?;
            let result = test_flip_operation(data, branch, &mut plan.operations);
            (result != FlipResult::Unsupported).then_some(result)
        }
        // A sequenced test's prelude is statements, not a branch, so the
        // complement plan concerns only the test itself.
        Condition::Sequenced { test, .. } => test_condition(data, test, plan),
        Condition::Or(left, right) | Condition::And(left, right) => {
            let left_result = test_condition(data, left, plan)?;
            let right_result = test_condition(data, right, plan)?;
            // BlockCondition::flipInPlaceTest returns the first child's result;
            // the first short-circuit test determines whether the combined
            // condition has a preferred orientation.
            let _ = right_result;
            Some(left_result)
        }
    }
}

/// Find a pre-existing target varnode where possible, otherwise create the
/// address-tied value used by the graph's branch representation.
fn target_value(data: &mut Funcdata, target: GraphBlockId, size: u32) -> super::VarnodeId {
    let address = data.block(target).start;
    if let Some(value) = data
        .at_location(RAM_SPACE, address, size.max(1))
        .first()
        .copied()
    {
        return value;
    }
    data.new_varnode(RAM_SPACE, address, size.max(1))
}

/// Replace a branch's target input without disturbing merge predecessor slots.
fn set_branch_target(data: &mut Funcdata, branch: OpId, target: GraphBlockId, size: u32) {
    let mut inputs = data.op(branch).inputs.clone();
    if inputs.is_empty() {
        return;
    }
    inputs[0] = target_value(data, target, size);
    data.op_set_inputs(branch, inputs);
}

/// The opcode and operand ordering used by Ghidra's `get_booleanflip`.
fn boolean_flip(opcode: i32) -> Option<(i32, bool)> {
    Some(match opcode {
        op::INT_EQUAL => (op::INT_NOTEQUAL, false),
        op::INT_NOTEQUAL => (op::INT_EQUAL, false),
        op::INT_SLESS => (op::INT_SLESSEQUAL, true),
        op::INT_SLESSEQUAL => (op::INT_SLESS, true),
        op::INT_LESS => (op::INT_LESSEQUAL, true),
        op::INT_LESSEQUAL => (op::INT_LESS, true),
        op::BOOL_NEGATE => (op::COPY, false),
        op::FLOAT_EQUAL => (op::FLOAT_NOTEQUAL, false),
        op::FLOAT_NOTEQUAL => (op::FLOAT_EQUAL, false),
        op::FLOAT_LESS => (op::FLOAT_LESSEQUAL, true),
        op::FLOAT_LESSEQUAL => (op::FLOAT_LESS, true),
        op::BOOL_OR => (op::BOOL_AND, false),
        op::BOOL_AND => (op::BOOL_OR, false),
        _ => return None,
    })
}

/// Rewrite `c <= x` to `c-1 < x`, or `x <= c` to `x < c+1`, when the adjusted
/// constant is representable.  This is Ghidra's `replaceLessequal`; keeping it
/// here preserves the final operation shape after an ordered comparison is
/// flipped in place.
fn replace_less_equal(data: &mut Funcdata, operation: OpId) {
    let opcode = data.op(operation).opcode;
    let (less, signed) = match opcode {
        op::INT_SLESSEQUAL => (op::INT_SLESS, true),
        op::INT_LESSEQUAL => (op::INT_LESS, false),
        _ => return,
    };
    let Some((slot, constant)) = data
        .op(operation)
        .inputs
        .iter()
        .copied()
        .enumerate()
        .find(|(_, value)| data.varnode(*value).flags.constant)
    else {
        return;
    };
    let size = data.varnode(constant).size;
    let bits = size.saturating_mul(8);
    if bits == 0 || bits > 64 {
        return;
    }
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let value = data.varnode(constant).offset & mask;
    let (overflow, adjusted) = if slot == 0 {
        let minimum = if bits == 64 {
            1u64 << 63
        } else {
            1u64 << (bits - 1)
        };
        (
            value == if signed { minimum } else { 0 },
            value.wrapping_sub(1) & mask,
        )
    } else {
        let maximum = if signed {
            if bits == 64 {
                (1u64 << 63) - 1
            } else {
                (1u64 << (bits - 1)) - 1
            }
        } else {
            mask
        };
        (value == maximum, value.wrapping_add(1) & mask)
    };
    if overflow {
        return;
    }
    data.op_set_opcode(operation, less);
    let adjusted = data.new_constant(adjusted, size);
    data.op_set_input(operation, adjusted, slot);
}

/// Execute a previously validated complement plan.
fn execute_flip(data: &mut Funcdata, plan: &FlipPlan) {
    for operation in plan.operations.iter().copied() {
        let Some(opcode) = data.opcode_of(operation) else {
            continue;
        };
        let Some((flipped, reorder)) = boolean_flip(opcode) else {
            continue;
        };
        if flipped == op::COPY {
            let Some(source) = data.op(operation).inputs.first().copied() else {
                continue;
            };
            let Some(output) = data.op(operation).output else {
                continue;
            };
            let Some(descendant) = data.lone_descend(output) else {
                continue;
            };
            let Some(slot) = data
                .op(descendant)
                .inputs
                .iter()
                .position(|value| *value == output)
            else {
                continue;
            };
            data.op_set_input(descendant, source, slot);
            data.op_destroy(operation);
            continue;
        }
        data.op_set_opcode(operation, flipped);
        if reorder {
            let mut inputs = data.op(operation).inputs.clone();
            if inputs.len() >= 2 {
                inputs.swap(0, 1);
                data.op_set_inputs(operation, inputs);
            }
        }
        replace_less_equal(data, operation);
    }
    for branch in plan.branches.iter().copied() {
        set_branch_target(data, branch.branch, branch.target, branch.target_size);
    }
}

/// Collect full `if/else` conditions in the same depth-first order as the
/// persistent Ghidra block graph traversal.
fn collect_if_else_conditions(node: &Structured, into: &mut Vec<Condition>) {
    match node {
        Structured::IfElse {
            header,
            test,
            then_body,
            else_body,
            ..
        } => {
            if else_body.is_some() {
                into.push(test.clone());
            }
            collect_if_else_conditions(header, into);
            collect_if_else_conditions(then_body, into);
            if let Some(else_body) = else_body {
                collect_if_else_conditions(else_body, into);
            }
        }
        Structured::WhileDo { header, body, .. } => {
            collect_if_else_conditions(header, into);
            collect_if_else_conditions(body, into);
        }
        Structured::DoWhile { body, .. } | Structured::InfLoop { body } => {
            collect_if_else_conditions(body, into)
        }
        Structured::List(members) => {
            for member in members {
                collect_if_else_conditions(member, into);
            }
        }
        Structured::Switch { header, cases, .. } => {
            collect_if_else_conditions(header, into);
            for (_, case) in cases {
                collect_if_else_conditions(case, into);
            }
        }
        Structured::Basic(_)
        | Structured::Goto { .. }
        | Structured::Break
        | Structured::IfBreak { .. }
        | Structured::IfGoto { .. } => {}
    }
}

/// Flip full conditionals to their preferred complement, matching
/// `ActionPreferComplement::apply` and `BlockIf::preferComplement`.
pub struct ActionPreferComplement;

impl Action for ActionPreferComplement {
    fn name(&self) -> &'static str {
        "prefercomplement"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let tree = structure::structure(data, &[]);
        let mut conditions = Vec::new();
        collect_if_else_conditions(&tree, &mut conditions);

        let mut changed = 0;
        let mut flipped_blocks = BTreeSet::new();
        for condition in conditions {
            let mut plan = FlipPlan::default();
            let Some(result) = test_condition(data, &condition, &mut plan) else {
                continue;
            };
            if result != FlipResult::Normalizing
                || plan
                    .branch_ids
                    .iter()
                    .any(|block| flipped_blocks.contains(block))
            {
                continue;
            }
            execute_flip(data, &plan);
            flipped_blocks.extend(plan.branch_ids);
            changed += 1;
        }
        changed
    }
}

/// Whether an operation is omitted from the terminal statement position used
/// by the for-loop transform.
fn is_nonprinting_marker(opcode: i32) -> bool {
    matches!(
        opcode,
        op::CBRANCH | op::BRANCH | op::BRANCHIND | op::RETURN | op::MULTIEQUAL | op::INDIRECT
    )
}

fn last_printing_op(data: &Funcdata, block: GraphBlockId) -> Option<OpId> {
    data.block(block)
        .ops
        .iter()
        .copied()
        .filter(|operation| {
            data.opcode_of(*operation)
                .is_some_and(|opcode| !is_nonprinting_marker(opcode))
        })
        .next_back()
}

/// Move one operation to the terminal statement position in its block.  The
/// caller has already applied Ghidra's move-safety checks through
/// `forloop::find_for_loops`.
fn move_after_terminal(data: &mut Funcdata, operation: OpId) -> bool {
    let Some(block) = data.op(operation).parent else {
        return false;
    };
    let Some(anchor) = last_printing_op(data, block) else {
        return false;
    };
    if anchor == operation {
        return false;
    }
    let Some(from) = data.block(block).ops.iter().position(|id| *id == operation) else {
        return false;
    };
    let Some(to) = data.block(block).ops.iter().position(|id| *id == anchor) else {
        return false;
    };
    if from > to {
        return false;
    }
    data.op_uninsert(operation);
    data.op_insert_after(operation, anchor);
    true
}

/// Recurse in the same order as `BlockGraph::finalTransform`, applying the
/// loop-local final transform after child structures have been visited.
fn final_transform_tree(
    data: &mut Funcdata,
    node: &Structured,
    loops: &std::collections::BTreeMap<GraphBlockId, ForLoop>,
    moved: &mut BTreeSet<OpId>,
) -> usize {
    let mut changed = 0;
    match node {
        Structured::WhileDo { header, body, .. } => {
            changed += final_transform_tree(data, header, loops, moved);
            changed += final_transform_tree(data, body, loops, moved);
            if let Some(entry) = structure::front_block(header) {
                if let Some(parts) = loops.get(&entry) {
                    if moved.insert(parts.iterate) && move_after_terminal(data, parts.iterate) {
                        changed += 1;
                    }
                }
            }
        }
        Structured::IfElse {
            header,
            then_body,
            else_body,
            ..
        } => {
            changed += final_transform_tree(data, header, loops, moved);
            changed += final_transform_tree(data, then_body, loops, moved);
            if let Some(else_body) = else_body {
                changed += final_transform_tree(data, else_body, loops, moved);
            }
        }
        Structured::DoWhile { body, .. } | Structured::InfLoop { body } => {
            changed += final_transform_tree(data, body, loops, moved);
        }
        Structured::List(members) => {
            for member in members {
                changed += final_transform_tree(data, member, loops, moved);
            }
        }
        Structured::Switch { header, cases, .. } => {
            changed += final_transform_tree(data, header, loops, moved);
            for (_, case) in cases {
                changed += final_transform_tree(data, case, loops, moved);
            }
        }
        Structured::Basic(_)
        | Structured::Goto { .. }
        | Structured::Break
        | Structured::IfBreak { .. }
        | Structured::IfGoto { .. } => {}
    }
    changed
}

/// Give every representable structured node its final transform.  In the
/// current graph, the observable part of `BlockWhileDo::finalTransform` is the
/// safe iterator move; the emitter derives the temporary non-printing marks
/// from the same `ForLoop` records when it prints the tree.
pub struct ActionStructureTransform;

impl Action for ActionStructureTransform {
    fn name(&self) -> &'static str {
        "structuretransform"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let tree = structure::structure(data, &[]);
        let loops = super::forloop::find_for_loops(data, &tree);
        let mut moved = BTreeSet::new();
        final_transform_tree(data, &tree, &loops, &mut moved)
    }
}

/// The two block-recovery actions in their Ghidra registration order.
pub fn all() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(ActionPreferComplement),
        Box::new(ActionStructureTransform),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SeqNum;

    fn seq(address: u64, order: u32) -> SeqNum {
        SeqNum { address, order }
    }

    fn target(data: &mut Funcdata, address: u64) -> super::super::VarnodeId {
        data.new_varnode(RAM_SPACE, address, 4)
    }

    fn full_diamond() -> (
        Funcdata,
        GraphBlockId,
        GraphBlockId,
        GraphBlockId,
        OpId,
        OpId,
    ) {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        let then_block = data.new_block(0x1010);
        let else_block = data.new_block(0x1020);
        let join = data.new_block(0x1030);
        data.add_edge(entry, then_block);
        data.add_edge(entry, else_block);
        data.add_edge(then_block, join);
        data.add_edge(else_block, join);

        let left = data.new_constant(3, 4);
        let right = data.new_constant(4, 4);
        let comparison = data.new_op(op::INT_NOTEQUAL, seq(0x1000, 0), vec![left, right]);
        let condition = data.new_unique(1);
        data.op_set_output(comparison, Some(condition));
        data.op_insert_end(comparison, entry);
        let branch_target = target(&mut data, then_block_start());
        let branch = data.new_op(op::CBRANCH, seq(0x1000, 1), vec![branch_target, condition]);
        data.op_insert_end(branch, entry);
        (data, entry, then_block, else_block, comparison, branch)
    }

    fn then_block_start() -> u64 {
        0x1010
    }

    fn full_if_else_bodies(node: &Structured) -> Option<(GraphBlockId, GraphBlockId)> {
        match node {
            Structured::IfElse {
                then_body,
                else_body: Some(else_body),
                ..
            } => {
                if let (Structured::Basic(then_block), Structured::Basic(else_block)) =
                    (&**then_body, &**else_body)
                {
                    return Some((*then_block, *else_block));
                }
                None
            }
            Structured::IfElse {
                header,
                then_body,
                else_body: None,
                ..
            } => full_if_else_bodies(header).or_else(|| full_if_else_bodies(then_body)),
            Structured::List(members) => members.iter().find_map(full_if_else_bodies),
            Structured::WhileDo { header, body, .. } => {
                full_if_else_bodies(header).or_else(|| full_if_else_bodies(body))
            }
            Structured::DoWhile { body, .. } | Structured::InfLoop { body } => {
                full_if_else_bodies(body)
            }
            Structured::Switch { header, cases, .. } => full_if_else_bodies(header)
                .or_else(|| cases.iter().find_map(|(_, case)| full_if_else_bodies(case))),
            Structured::Basic(_)
            | Structured::Goto { .. }
            | Structured::Break
            | Structured::IfBreak { .. }
            | Structured::IfGoto { .. } => None,
        }
    }

    #[test]
    fn prefer_complement_swaps_full_if_else_and_flips_the_test() {
        let (mut data, entry, then_block, else_block, comparison, branch) = full_diamond();
        assert!(full_if_else_bodies(&structure::structure(&data, &[])).is_some());
        assert_eq!(ActionPreferComplement.apply(&mut data), 1);
        assert_eq!(data.op(comparison).opcode, op::INT_EQUAL);
        assert_eq!(
            data.varnode(data.op(branch).inputs[0]).offset,
            data.block(else_block).start
        );
        assert_eq!(
            full_if_else_bodies(&structure::structure(&data, &[])),
            Some((else_block, then_block))
        );
        assert_eq!(data.block(entry).successors.len(), 2);
    }

    #[test]
    fn prefer_complement_keeps_an_ambiguous_equality_orientation() {
        let (mut data, _entry, then_block, _else_block, comparison, branch) = full_diamond();
        data.op_set_opcode(comparison, op::INT_EQUAL);
        assert_eq!(ActionPreferComplement.apply(&mut data), 0);
        assert_eq!(data.op(comparison).opcode, op::INT_EQUAL);
        assert_eq!(
            data.varnode(data.op(branch).inputs[0]).offset,
            data.block(then_block).start
        );
    }

    #[test]
    fn structure_transform_moves_a_verified_iterator_to_the_tail() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        let head = data.new_block(0x1010);
        let body = data.new_block(0x1020);
        let exit = data.new_block(0x1030);
        data.add_edge(entry, head);
        data.add_edge(head, body);
        data.add_edge(head, exit);
        data.add_edge(body, head);

        let one = data.new_constant(1, 4);
        let initial_value = data.new_op(op::COPY, seq(0x1000, 0), vec![one]);
        let initial = data.new_unique(4);
        data.op_set_output(initial_value, Some(initial));
        data.op_insert_end(initial_value, entry);
        let entry_target = target(&mut data, 0x1010);
        let entry_branch = data.new_op(op::BRANCH, seq(0x1000, 1), vec![entry_target]);
        data.op_insert_end(entry_branch, entry);

        let carried = data.new_unique(4);
        let phi = data.new_op(op::MULTIEQUAL, seq(0x1010, 0), vec![initial, carried]);
        let loop_value = data.new_unique(4);
        data.op_set_output(phi, Some(loop_value));
        data.op_insert_end(phi, head);
        let limit = data.new_constant(8, 4);
        let comparison = data.new_op(op::INT_SLESS, seq(0x1010, 1), vec![loop_value, limit]);
        let condition = data.new_unique(1);
        data.op_set_output(comparison, Some(condition));
        data.op_insert_end(comparison, head);
        let head_target = target(&mut data, 0x1020);
        let head_branch = data.new_op(op::CBRANCH, seq(0x1010, 2), vec![head_target, condition]);
        data.op_insert_end(head_branch, head);

        let iterate = data.new_op(op::INT_ADD, seq(0x1020, 0), vec![loop_value, one]);
        data.op_set_output(iterate, Some(carried));
        data.op_insert_end(iterate, body);
        let filler = data.new_op(op::INT_ADD, seq(0x1020, 1), vec![one, one]);
        let filler_output = data.new_unique(4);
        data.op_set_output(filler, Some(filler_output));
        data.op_insert_end(filler, body);
        let body_target = target(&mut data, 0x1010);
        let body_branch = data.new_op(op::BRANCH, seq(0x1020, 2), vec![body_target]);
        data.op_insert_end(body_branch, body);
        let exit_return = data.new_op(op::RETURN, seq(0x1030, 0), Vec::new());
        data.op_insert_end(exit_return, exit);

        assert_eq!(data.block(body).ops, vec![iterate, filler, body_branch]);
        assert_eq!(ActionStructureTransform.apply(&mut data), 1);
        assert_eq!(data.block(body).ops, vec![filler, iterate, body_branch]);
        assert_eq!(data.op(iterate).parent, Some(body));
    }
}
