//! Control-flow block transformations ported from Ghidra's `blockaction.cc`.
//!
//! The graph currently has no persistent `BlockGraph`/construct object.  The
//! two actions below therefore operate only on the information that is
//! represented by [`Funcdata`]: basic-block edges and p-code operations.
//! Actions whose real implementation only walks or annotates Ghidra's
//! persistent structured tree are deliberately not registered here.

use std::collections::BTreeMap;

use ventris_pcode::op;

use super::action::Action;
use super::{Funcdata, GraphBlockId, OpId, SeqNum, VarnodeId};

fn last_live_op(data: &Funcdata, block: GraphBlockId) -> Option<OpId> {
    data.block(block)
        .ops
        .iter()
        .rev()
        .copied()
        .find(|id| data.opcode_of(*id).is_some())
}

fn branch_target(data: &Funcdata, branch: OpId) -> Option<GraphBlockId> {
    let target = data.op(branch).inputs.first().copied()?;
    let address = data.varnode(target).offset;
    data.blocks()
        .find(|(_, block)| block.start == address)
        .map(|(id, _)| id)
}

fn can_clone_return_value(data: &Funcdata, value: VarnodeId) -> bool {
    let flags = data.varnode(value).flags;
    flags.constant || flags.input || flags.written
}

/// The conservative form of `ActionReturnSplit::isSplittable`.
///
/// `Funcdata` does not model annotation varnodes, so those cannot be
/// distinguished from free values.  Rejecting an unclassified input is the
/// safe side of Ghidra's `isFree()` check.
fn is_splittable_return(data: &Funcdata, block: GraphBlockId) -> bool {
    data.block(block).ops.iter().copied().all(|id| {
        let Some(opcode) = data.opcode_of(id) else {
            return true;
        };
        match opcode {
            op::MULTIEQUAL => true,
            op::COPY | op::RETURN => data
                .op(id)
                .inputs
                .iter()
                .copied()
                .all(|value| can_clone_return_value(data, value)),
            _ => false,
        }
    })
}

/// Clone a return epilog onto one incoming edge.
///
/// This is the graph equivalent of `Funcdata::nodeSplit` plus
/// `CloneBlockOps::cloneBlock`.  The graph API intentionally has no direct
/// block-split operation, but all of the required edge and op primitives are
/// available here.  A `MULTIEQUAL` becomes a `COPY` in the one-edge clone and
/// the original merge loses that incoming slot through `remove_edge`.
fn split_return_edge(
    data: &mut Funcdata,
    parent: GraphBlockId,
    predecessor: GraphBlockId,
    edge_index: usize,
) -> bool {
    let predecessors = data.block(parent).predecessors.clone();
    if predecessors.get(edge_index).copied() != Some(predecessor)
        || !predecessors.contains(&predecessor)
    {
        return false;
    }

    let specs: Vec<(i32, SeqNum, Vec<VarnodeId>, Option<VarnodeId>)> = data
        .block(parent)
        .ops
        .iter()
        .copied()
        .filter_map(|id| {
            let operation = data.op(id);
            (!operation.dead).then_some((
                operation.opcode,
                operation.seq,
                operation.inputs.clone(),
                operation.output,
            ))
        })
        .collect();

    let duplicate = data.new_block(data.block(parent).start);
    let mut outputs = BTreeMap::new();

    for (opcode, seq, inputs, output) in specs {
        let (clone_opcode, clone_inputs) = if opcode == op::MULTIEQUAL {
            let Some(value) = inputs.get(edge_index).copied() else {
                return false;
            };
            (op::COPY, vec![value])
        } else {
            let mapped = inputs
                .into_iter()
                .map(|value| outputs.get(&value).copied().unwrap_or(value))
                .collect();
            (opcode, mapped)
        };
        let clone = data.new_op(clone_opcode, seq, clone_inputs);
        if let Some(original_output) = output {
            let source = data.varnode(original_output);
            let cloned_output = data.new_varnode(source.space, source.offset, source.size);
            data.op_set_output(clone, Some(cloned_output));
            outputs.insert(original_output, cloned_output);
        }
        data.op_insert_end(clone, duplicate);
    }

    if !data.remove_edge(predecessor, parent) {
        return false;
    }
    data.add_edge(predecessor, duplicate);

    // A remaining one-input merge is the COPY that Ghidra leaves in the
    // original return block after moving this predecessor.
    let remaining_phis: Vec<OpId> = data
        .block(parent)
        .ops
        .iter()
        .copied()
        .take_while(|id| data.opcode_of(*id) == Some(op::MULTIEQUAL))
        .collect();
    for phi in remaining_phis {
        if data.op(phi).inputs.len() == 1 {
            data.op_set_opcode(phi, op::COPY);
        }
    }
    true
}

/// Split a shared return epilog so an explicit goto path owns a private copy.
pub struct ActionReturnSplit;

impl Action for ActionReturnSplit {
    fn name(&self) -> &'static str {
        "returnsplit"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let returns: Vec<GraphBlockId> = data
            .blocks()
            .filter(|(_, block)| {
                block
                    .ops
                    .iter()
                    .copied()
                    .any(|id| data.opcode_of(id) == Some(op::RETURN))
            })
            .map(|(id, _)| id)
            .collect();

        let mut changed = 0;
        for parent in returns {
            let predecessors = data.block(parent).predecessors.clone();
            if predecessors.len() <= 1 || !is_splittable_return(data, parent) {
                continue;
            }

            // `gatherReturnGotos` walks the persistent structure to find only
            // goto paths.  In this graph a branch whose target is the return
            // block is the strongest available equivalent; a fallthrough edge
            // is left alone rather than guessed to be a goto.
            let mut candidates: Vec<(usize, GraphBlockId)> = predecessors
                .iter()
                .copied()
                .enumerate()
                .filter_map(|(index, predecessor)| {
                    let branch = last_live_op(data, predecessor)?;
                    if !matches!(data.op(branch).opcode, op::BRANCH | op::CBRANCH)
                        || branch_target(data, branch) != Some(parent)
                    {
                        return None;
                    }
                    Some((index, predecessor))
                })
                .collect();
            if candidates.is_empty() {
                continue;
            }

            // Never split every incoming edge: the original node remains the
            // canonical epilog, exactly as ActionReturnSplit's pop_back does.
            if candidates.len() == predecessors.len() {
                let preserve = candidates
                    .iter()
                    .map(|(index, _)| *index)
                    .min()
                    .expect("non-empty candidates");
                candidates.retain(|(index, _)| *index != preserve);
            }
            // Removing edges changes phi slot indices, so work from the
            // largest predecessor index toward the smallest.
            candidates.sort_by_key(|(index, _)| std::cmp::Reverse(*index));
            for (index, predecessor) in candidates {
                if split_return_edge(data, parent, predecessor, index) {
                    changed += 1;
                }
            }
        }
        changed
    }
}

#[derive(Clone)]
struct PhiPlan {
    op: OpId,
    left: VarnodeId,
    right: VarnodeId,
    size: u32,
    seq: SeqNum,
}

fn leading_phi_plans(
    data: &Funcdata,
    exit: GraphBlockId,
    left_index: usize,
    right_index: usize,
) -> Option<Vec<PhiPlan>> {
    let mut plans = Vec::new();
    for id in data.block(exit).ops.iter().copied() {
        if data.opcode_of(id) != Some(op::MULTIEQUAL) {
            break;
        }
        let operation = data.op(id);
        let left = operation.inputs.get(left_index).copied()?;
        let right = operation.inputs.get(right_index).copied()?;
        let output = operation.output?;
        plans.push(PhiPlan {
            op: id,
            left,
            right,
            size: data.varnode(output).size,
            seq: operation.seq,
        });
    }
    Some(plans)
}

/// Join two basic blocks containing the same conditional expression.
///
/// The full Ghidra `ConditionalJoin` also proves one-level functional
/// equality and carries a persistent `BlockGraph` copy map.  This graph has
/// neither, so matching requires the exact same condition varnode and keeps
/// all other data-flow edits explicit.
pub struct ActionNodeJoin;

impl Action for ActionNodeJoin {
    fn name(&self) -> &'static str {
        "nodejoin"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let mut changed = 0;
        loop {
            let candidates: Vec<(GraphBlockId, OpId)> = data
                .blocks()
                .filter_map(|(block, _)| {
                    let branch = last_live_op(data, block)?;
                    (data.op(branch).opcode == op::CBRANCH).then_some((block, branch))
                })
                .collect();
            let mut joined = false;

            'pairs: for (index, (block1, branch1)) in candidates.iter().copied().enumerate() {
                for (block2, branch2) in candidates.iter().copied().skip(index + 1) {
                    if block1 == block2 {
                        continue;
                    }
                    let (exita, exitb, condition, target) = {
                        let first = data.block(block1);
                        let second = data.block(block2);
                        if first.successors.len() != 2
                            || second.successors.len() != 2
                            || first.successors[0] == first.successors[1]
                            || first.successors != second.successors
                        {
                            continue;
                        }
                        let first_op = data.op(branch1);
                        let second_op = data.op(branch2);
                        if first_op.inputs.len() < 2
                            || second_op.inputs.len() < 2
                            || first_op.inputs[1] != second_op.inputs[1]
                        {
                            continue;
                        }
                        let target = first_op.inputs[0];
                        let first_target = branch_target(data, branch1);
                        let second_target = branch_target(data, branch2);
                        if first_target != second_target
                            || !matches!(
                                first_target,
                                Some(target)
                                    if target == first.successors[0]
                                        || target == first.successors[1]
                            )
                        {
                            continue;
                        }
                        (
                            first.successors[0],
                            first.successors[1],
                            first_op.inputs[1],
                            target,
                        )
                    };

                    let a_in1 = data
                        .block(exita)
                        .predecessors
                        .iter()
                        .position(|candidate| *candidate == block1);
                    let a_in2 = data
                        .block(exita)
                        .predecessors
                        .iter()
                        .position(|candidate| *candidate == block2);
                    let b_in1 = data
                        .block(exitb)
                        .predecessors
                        .iter()
                        .position(|candidate| *candidate == block1);
                    let b_in2 = data
                        .block(exitb)
                        .predecessors
                        .iter()
                        .position(|candidate| *candidate == block2);
                    let (Some(a_in1), Some(a_in2), Some(b_in1), Some(b_in2)) =
                        (a_in1, a_in2, b_in1, b_in2)
                    else {
                        continue;
                    };
                    let Some(a_phis) = leading_phi_plans(data, exita, a_in1, a_in2) else {
                        continue;
                    };
                    let Some(b_phis) = leading_phi_plans(data, exitb, b_in1, b_in2) else {
                        continue;
                    };

                    let join = data.new_block(data.op(branch1).seq.address);
                    let mut merged_values: BTreeMap<OpId, VarnodeId> = BTreeMap::new();
                    for plan in a_phis.iter().chain(b_phis.iter()) {
                        let value = if plan.left == plan.right {
                            plan.left
                        } else {
                            let merge =
                                data.new_op(op::MULTIEQUAL, plan.seq, vec![plan.left, plan.right]);
                            let output = data.new_unique(plan.size);
                            data.op_set_output(merge, Some(output));
                            data.op_insert_end(merge, join);
                            output
                        };
                        merged_values.insert(plan.op, value);
                    }

                    // Remove both old edges for each exit, then re-add the
                    // single edge from the join.  `remove_edge` also removes
                    // the corresponding phi operands.
                    for (left, right, exit) in [(block1, block2, exita), (block1, block2, exitb)] {
                        if !data.remove_edge(left, exit) || !data.remove_edge(right, exit) {
                            continue 'pairs;
                        }
                        data.add_edge(join, exit);
                    }
                    data.add_edge(block1, join);
                    data.add_edge(block2, join);

                    for plan in a_phis.iter().chain(b_phis.iter()) {
                        let inputs = data.op(plan.op).inputs.clone();
                        let value = merged_values[&plan.op];
                        let mut rebuilt = inputs;
                        rebuilt.push(value);
                        data.op_set_inputs(plan.op, rebuilt);
                    }

                    let branch =
                        data.new_op(op::CBRANCH, data.op(branch1).seq, vec![target, condition]);
                    data.op_insert_end(branch, join);
                    data.op_destroy(branch1);
                    data.op_destroy(branch2);
                    changed += 1;
                    joined = true;
                    break 'pairs;
                }
            }
            if !joined {
                break;
            }
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::RAM_SPACE;

    fn seq(address: u64, order: u32) -> SeqNum {
        SeqNum { address, order }
    }

    fn return_graph() -> (Funcdata, GraphBlockId, GraphBlockId, GraphBlockId) {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let left = data.new_block(0x1000);
        let right = data.new_block(0x1010);
        let parent = data.new_block(0x1020);
        data.add_edge(left, parent);
        data.add_edge(right, parent);

        let left_value = data.new_constant(7, 4);
        let right_value = data.new_constant(9, 4);
        for (block, address) in [(left, 0x1000), (right, 0x1010)] {
            let target = data.new_varnode(RAM_SPACE, 0x1020, 4);
            let branch = data.new_op(op::BRANCH, seq(address, 0), vec![target]);
            data.op_insert_end(branch, block);
        }
        let merged = data.new_op(
            op::MULTIEQUAL,
            seq(0x1020, 0),
            vec![left_value, right_value],
        );
        let result = data.new_unique(4);
        data.op_set_output(merged, Some(result));
        data.op_insert_end(merged, parent);
        let ret = data.new_op(op::RETURN, seq(0x1020, 1), vec![result]);
        data.op_insert_end(ret, parent);
        (data, left, right, parent)
    }

    #[test]
    fn return_split_clones_the_shared_epilog_for_one_goto_path() {
        let (mut data, _left, _right, parent) = return_graph();
        let before = data.blocks().count();
        assert_eq!(ActionReturnSplit.apply(&mut data), 1);
        assert_eq!(data.blocks().count(), before + 1);
        assert_eq!(data.block(parent).predecessors.len(), 1);
        let duplicate = data
            .blocks()
            .find(|(id, block)| {
                *id != parent && block.start == data.block(parent).start && block.ops.len() == 2
            })
            .map(|(id, _)| id)
            .expect("split return block");
        assert_eq!(data.block(duplicate).ops.len(), 2);
        assert_eq!(data.opcode_of(data.block(duplicate).ops[0]), Some(op::COPY));
        assert_eq!(
            data.opcode_of(data.block(duplicate).ops[1]),
            Some(op::RETURN)
        );
        assert_eq!(ActionReturnSplit.apply(&mut data), 0);
    }

    #[test]
    fn return_split_declines_a_return_block_with_substantive_work() {
        let (mut data, _left, _right, parent) = return_graph();
        let value = data.new_constant(3, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1020, 2), vec![value, value]);
        data.op_insert_before(add, data.block(parent).ops[0]);
        let before = data.blocks().count();
        assert_eq!(ActionReturnSplit.apply(&mut data), 0);
        assert_eq!(data.blocks().count(), before);
    }

    fn node_join_graph(same_condition: bool) -> (Funcdata, GraphBlockId, GraphBlockId) {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let first = data.new_block(0x1000);
        let second = data.new_block(0x1010);
        let exita = data.new_block(0x1020);
        let exitb = data.new_block(0x1030);
        for source in [first, second] {
            data.add_edge(source, exita);
            data.add_edge(source, exitb);
        }
        let condition = data.new_unique(1);
        let other_condition = data.new_unique(1);
        for (block, address, value) in [
            (first, 0x1000, condition),
            (
                second,
                0x1010,
                if same_condition {
                    condition
                } else {
                    other_condition
                },
            ),
        ] {
            let target = data.new_varnode(RAM_SPACE, 0x1030, 4);
            let branch = data.new_op(op::CBRANCH, seq(address, 0), vec![target, value]);
            data.op_insert_end(branch, block);
        }
        (data, first, second)
    }

    #[test]
    fn node_join_merges_duplicate_conditional_nodes() {
        let (mut data, first, second) = node_join_graph(true);
        let before = data.blocks().count();
        assert_eq!(ActionNodeJoin.apply(&mut data), 1);
        assert_eq!(data.blocks().count(), before + 1);
        assert_eq!(data.block(first).successors.len(), 1);
        assert_eq!(data.block(second).successors.len(), 1);
        let join = data.block(first).successors[0];
        assert_eq!(data.block(join).successors.len(), 2);
        assert_eq!(
            data.opcode_of(*data.block(join).ops.last().expect("join branch")),
            Some(op::CBRANCH)
        );
        assert_eq!(ActionNodeJoin.apply(&mut data), 0);
    }

    #[test]
    fn node_join_declines_different_conditions() {
        let (mut data, first, second) = node_join_graph(false);
        let before = data.blocks().count();
        assert_eq!(ActionNodeJoin.apply(&mut data), 0);
        assert_eq!(data.blocks().count(), before);
        assert_eq!(data.block(first).successors.len(), 2);
        assert_eq!(data.block(second).successors.len(), 2);
    }
}

/// Return the block actions that can mutate the graph representation.
///
/// `ActionStructureTransform`, `ActionPreferComplement`,
/// `ActionBlockStructure`, and `ActionFinalStructure` are intentionally
/// omitted: their real `apply` methods require Ghidra's persistent
/// `BlockGraph`/structured tree and its tree-specific mutation/annotation
/// methods, none of which exists on `Funcdata`.
pub fn all() -> Vec<Box<dyn Action>> {
    vec![Box::new(ActionReturnSplit), Box::new(ActionNodeJoin)]
}
