//! Merging two conditional blocks that test the same thing.
//!
//! Port of `ConditionalJoin` and `ActionNodeJoin` from Ghidra 12.1.3's
//! `blockaction.cc`, with `Funcdata::nodeJoinCreateBlock` from
//! `funcdata_block.cc`.
//!
//! Two blocks that end in a CBRANCH on the same value and lead to the same two
//! places are performing one test twice. Merging them into a new block that
//! holds the test once removes a whole edge from the graph, and that is what
//! lets the structuring rules see constructs they otherwise cannot: a guarded
//! bottom-tested loop, whose guard and whose loop-back test are exactly such a
//! pair, becomes a single `while` loop rather than an `if` wrapped around a
//! `do`/`while`. That in turn is the shape for-loop recovery needs.

use std::collections::BTreeMap;

use ventris_pcode::op;

use super::equality::{Equality, functional_equality};
use super::{Funcdata, GraphBlockId, OpId, VarnodeId};

/// Merges conditional blocks that test the same thing.
pub struct ActionNodeJoin;

impl super::action::Action for ActionNodeJoin {
    fn name(&self) -> &'static str {
        "node-join"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        join_all(data)
    }
}

/// Merge every pair of conditional blocks that qualifies.
///
/// `ActionNodeJoin::apply`. Returns the number of joins performed.
fn join_all(data: &mut Funcdata) -> usize {
    let mut count = 0;
    // The blocks present when the pass starts. A joined block is new work the
    // next pass will see; feeding it back into this one lets a join build on a
    // graph the captured operand slots no longer describe.
    let original = data.blocks.len();
    let mut index = 0;
    while index < original {
        let block = GraphBlockId(index as u32);
        index += 1;
        if data.block(block).successors.len() != 2 {
            continue;
        }
        let (first, second) = (
            data.block(block).successors[0],
            data.block(block).successors[1],
        );
        // Take the exit with fewer ways in: it is the one whose other
        // predecessors are worth testing against this block.
        let fewest = if data.block(first).predecessors.len() < data.block(second).predecessors.len()
        {
            first
        } else {
            second
        };
        if data.block(fewest).predecessors.len() == 1 {
            continue;
        }
        let candidates: Vec<GraphBlockId> = data
            .block(fewest)
            .predecessors
            .iter()
            .copied()
            .filter(|predecessor| *predecessor != block)
            .collect();
        for other in candidates {
            if let Some(join) = Join::of(data, block, other) {
                join.execute(data);
                count += 1;
                break;
            }
        }
    }
    count
}

/// A pair of conditional blocks that may be merged, and what merging them needs.
struct Join {
    block1: GraphBlockId,
    block2: GraphBlockId,
    exita: GraphBlockId,
    exitb: GraphBlockId,
    /// The edge indices into each exit, needed to know which phi input belongs
    /// to which of the two blocks.
    a_in1: usize,
    a_in2: usize,
    b_in1: usize,
    b_in2: usize,
    cbranch1: OpId,
    cbranch2: OpId,
    /// Value pairs the joined block must merge, in a stable order so the phis it
    /// builds do not depend on hash iteration.
    mergeneed: Vec<(VarnodeId, VarnodeId)>,
}

impl Join {
    /// `ConditionalJoin::match`: the two blocks must split the same two ways.
    fn of(data: &Funcdata, block1: GraphBlockId, block2: GraphBlockId) -> Option<Self> {
        if block1 == block2 {
            return None;
        }
        if data.block(block1).successors.len() != 2 || data.block(block2).successors.len() != 2 {
            return None;
        }
        let exita = data.block(block1).successors[0];
        let exitb = data.block(block1).successors[1];
        if exita == exitb {
            return None;
        }
        // The false exits must match, and so must the true exits.
        if data.block(block2).successors[0] != exita || data.block(block2).successors[1] != exitb {
            return None;
        }
        let a_in1 = edge_index(data, exita, block1)?;
        let a_in2 = edge_index(data, exita, block2)?;
        let b_in1 = edge_index(data, exitb, block1)?;
        let b_in2 = edge_index(data, exitb, block2)?;

        let mut join = Self {
            block1,
            block2,
            exita,
            exitb,
            a_in1,
            a_in2,
            b_in1,
            b_in2,
            cbranch1: OpId(0),
            cbranch2: OpId(0),
            mergeneed: Vec::new(),
        };
        join.find_dups(data)?;
        join.check_exit_block(data, exita, a_in1, a_in2);
        join.check_exit_block(data, exitb, b_in1, b_in2);
        Some(join)
    }

    /// `findDups`: the two tests must be on the same value, or on one pair of
    /// values the joined block can merge.
    fn find_dups(&mut self, data: &Funcdata) -> Option<()> {
        self.cbranch1 = terminal_cbranch(data, self.block1)?;
        self.cbranch2 = terminal_cbranch(data, self.block2)?;
        let value1 = *data.op(self.cbranch1).inputs.get(1)?;
        let value2 = *data.op(self.cbranch2).inputs.get(1)?;
        if value1 == value2 {
            return Some(());
        }
        // The join is only worth doing if the values will actually merge, which
        // is the same question `RulePushMulti` asks afterwards.
        if data.varnode(value1).def.is_none() || data.varnode(value2).def.is_none() {
            return None;
        }
        match functional_equality(data, value1, value2) {
            Equality::Same => Some(()),
            Equality::Different => None,
            Equality::Contingent(..) => {
                // A COPY or SUBPIECE definition would make the merged value a
                // narrowing of something already merged elsewhere.
                let definition = data.op(data.varnode(value1).def?);
                if matches!(definition.opcode, op::COPY | op::SUBPIECE) {
                    return None;
                }
                self.need(value1, value2);
                Some(())
            }
        }
    }

    /// `checkExitBlock`: whatever an exit already merges across these two edges
    /// must be merged in the joined block instead.
    fn check_exit_block(&mut self, data: &Funcdata, exit: GraphBlockId, in1: usize, in2: usize) {
        for operation in data.block(exit).ops.clone() {
            let held = data.op(operation);
            if held.opcode == op::MULTIEQUAL {
                let (Some(value1), Some(value2)) =
                    (held.inputs.get(in1).copied(), held.inputs.get(in2).copied())
                else {
                    continue;
                };
                if value1 != value2 {
                    self.need(value1, value2);
                }
            } else if held.opcode != op::COPY {
                // The phis are at the head of a block, so the first thing that
                // is neither a phi nor a copy ends them.
                break;
            }
        }
    }

    fn need(&mut self, value1: VarnodeId, value2: VarnodeId) {
        if !self.mergeneed.iter().any(|pair| *pair == (value1, value2)) {
            self.mergeneed.push((value1, value2));
        }
    }

    /// Perform the join.
    fn execute(&self, data: &mut Funcdata) {
        let join = self.create_block(data);
        let merged = self.setup_multiequals(data, join);
        self.move_cbranch(data, join, &merged);
        self.cut_down_multiequals(data, self.exita, self.a_in1, self.a_in2, &merged);
        self.cut_down_multiequals(data, self.exitb, self.b_in1, self.b_in2, &merged);
    }

    /// `Funcdata::nodeJoinCreateBlock`: a new block takes one out-edge to each
    /// exit, and both original blocks flow into it.
    fn create_block(&self, data: &mut Funcdata) -> GraphBlockId {
        let address = data.op(self.cbranch1).seq.address;
        let join = data.new_block(address);
        // Of the two edges into each exit, drop the one from the block whose
        // edge index is higher, and move the survivor onto the new block.
        let (dropa, keepa) = if self.a_in1 > self.a_in2 {
            (self.block1, self.block2)
        } else {
            (self.block2, self.block1)
        };
        let (dropb, keepb) = if self.b_in1 > self.b_in2 {
            (self.block1, self.block2)
        } else {
            (self.block2, self.block1)
        };
        // Control flow only: the phis in the exits are repaired by
        // `cut_down_multiequals`, from the slots as they were before this.
        data.remove_edge_keeping_merges(dropa, self.exita);
        data.remove_edge_keeping_merges(dropb, self.exitb);
        data.move_out_edge(keepa, self.exita, join);
        data.move_out_edge(keepb, self.exitb, join);
        data.add_edge(self.block1, join);
        data.add_edge(self.block2, join);
        join
    }

    /// `setupMultiequals`: one phi in the joined block per pair that needs it.
    fn setup_multiequals(
        &self,
        data: &mut Funcdata,
        join: GraphBlockId,
    ) -> BTreeMap<(VarnodeId, VarnodeId), VarnodeId> {
        let mut merged = BTreeMap::new();
        let seq = data.op(self.cbranch1).seq;
        for (value1, value2) in self.mergeneed.iter().copied() {
            let size = data.varnode(value1).size;
            let phi = data.new_op(op::MULTIEQUAL, seq, vec![value1, value2]);
            let output = data.new_unique(size);
            data.op_set_output(phi, Some(output));
            data.op_insert_end(phi, join);
            merged.insert((value1, value2), output);
        }
        merged
    }

    /// `moveCbranch`: the first test moves into the joined block and reads the
    /// merged value; the second is destroyed.
    fn move_cbranch(
        &self,
        data: &mut Funcdata,
        join: GraphBlockId,
        merged: &BTreeMap<(VarnodeId, VarnodeId), VarnodeId>,
    ) {
        let value1 = data.op(self.cbranch1).inputs[1];
        let value2 = data.op(self.cbranch2).inputs[1];
        data.op_uninsert(self.cbranch1);
        data.op_insert_end(self.cbranch1, join);
        let value = if value1 == value2 {
            value1
        } else {
            merged.get(&(value1, value2)).copied().unwrap_or(value1)
        };
        data.op_set_input(self.cbranch1, value, 1);
        data.op_destroy(self.cbranch2);
    }

    /// `cutDownMultiequals`: an exit that merged across two edges now sees one,
    /// carrying the value the joined block merged.
    fn cut_down_multiequals(
        &self,
        data: &mut Funcdata,
        exit: GraphBlockId,
        in1: usize,
        in2: usize,
        merged: &BTreeMap<(VarnodeId, VarnodeId), VarnodeId>,
    ) {
        let (low, high) = if in1 > in2 { (in2, in1) } else { (in1, in2) };
        for operation in data.block(exit).ops.clone() {
            let held = data.op(operation);
            if held.opcode == op::MULTIEQUAL {
                let (Some(value1), Some(value2)) =
                    (held.inputs.get(in1).copied(), held.inputs.get(in2).copied())
                else {
                    continue;
                };
                if value1 == value2 {
                    data.op_remove_input(operation, high);
                } else {
                    let Some(substitute) = merged.get(&(value1, value2)).copied() else {
                        continue;
                    };
                    data.op_remove_input(operation, high);
                    data.op_set_input(operation, substitute, low);
                }
                if data.op(operation).inputs.len() == 1 {
                    // A phi with one input is a copy, and it belongs at the head
                    // of the block rather than among the phis.
                    data.op_uninsert(operation);
                    data.op_set_opcode(operation, op::COPY);
                    data.op_insert_begin(operation, exit);
                }
            } else if held.opcode != op::COPY {
                break;
            }
        }
    }
}

/// The index of the edge from a predecessor into a block.
fn edge_index(data: &Funcdata, block: GraphBlockId, predecessor: GraphBlockId) -> Option<usize> {
    data.block(block)
        .predecessors
        .iter()
        .position(|held| *held == predecessor)
}

/// The CBRANCH a block ends with, if it ends with one that has not had a pending
/// boolean flip.
fn terminal_cbranch(data: &Funcdata, block: GraphBlockId) -> Option<OpId> {
    let last = data.block(block).ops.last().copied()?;
    if data.op(last).opcode != op::CBRANCH {
        return None;
    }
    Some(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SeqNum;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    /// Two blocks testing one value and splitting the same two ways become one
    /// block that performs the test once.
    #[test]
    fn two_blocks_testing_the_same_value_merge_into_one() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let guard = data.new_block(0x1000);
        let latch = data.new_block(0x1010);
        let taken = data.new_block(0x1020);
        let fallthrough = data.new_block(0x1030);

        // One value, tested by both blocks.
        let counter = data.new_varnode(ventris_lifter::REGISTER_SPACE, 0, 4);
        let zero = data.new_constant(0, 4);
        let test = data.new_op(op::INT_NOTEQUAL, seq(0x1000), vec![counter, zero]);
        let condition = data.new_unique(1);
        data.op_set_output(test, Some(condition));
        data.op_insert_end(test, guard);

        for (block, address) in [(guard, 0x1020u64), (latch, 0x1020)] {
            let target = data.new_varnode(ventris_lifter::RAM_SPACE, address, 4);
            let branch = data.new_op(op::CBRANCH, seq(address), vec![target, condition]);
            data.op_insert_end(branch, block);
        }
        // Both split the same two ways, in the same order.
        data.add_edge(guard, taken);
        data.add_edge(guard, fallthrough);
        data.add_edge(latch, taken);
        data.add_edge(latch, fallthrough);

        let before = data.blocks.len();
        assert_eq!(join_all(&mut data), 1, "the pair should have merged");
        assert_eq!(data.blocks.len(), before + 1, "a joined block is created");

        let join = GraphBlockId(before as u32);
        assert_eq!(
            data.block(join).successors,
            vec![taken, fallthrough],
            "the joined block takes both exits"
        );
        assert_eq!(data.block(guard).successors, vec![join]);
        assert_eq!(data.block(latch).successors, vec![join]);
        assert_eq!(
            data.block(join)
                .ops
                .iter()
                .filter(|op| data.op(**op).opcode == op::CBRANCH)
                .count(),
            1,
            "the test is performed once"
        );
        // The exits each lost an edge, so neither block reaches them directly.
        assert!(!data.block(guard).successors.contains(&taken));
        assert!(!data.block(latch).successors.contains(&fallthrough));
    }

    /// Blocks that split to different places are not a pair, however alike
    /// their tests are.
    #[test]
    fn blocks_splitting_to_different_places_do_not_merge() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let guard = data.new_block(0x1000);
        let latch = data.new_block(0x1010);
        let shared = data.new_block(0x1020);
        let one = data.new_block(0x1030);
        let other = data.new_block(0x1040);

        let counter = data.new_varnode(ventris_lifter::REGISTER_SPACE, 0, 4);
        let zero = data.new_constant(0, 4);
        let test = data.new_op(op::INT_NOTEQUAL, seq(0x1000), vec![counter, zero]);
        let condition = data.new_unique(1);
        data.op_set_output(test, Some(condition));
        data.op_insert_end(test, guard);
        for block in [guard, latch] {
            let target = data.new_varnode(ventris_lifter::RAM_SPACE, 0x1020, 4);
            let branch = data.new_op(op::CBRANCH, seq(0x1020), vec![target, condition]);
            data.op_insert_end(branch, block);
        }
        data.add_edge(guard, shared);
        data.add_edge(guard, one);
        data.add_edge(latch, shared);
        data.add_edge(latch, other);

        let before = data.blocks.len();
        assert_eq!(join_all(&mut data), 0);
        assert_eq!(data.blocks.len(), before, "no block is created");
    }
    /// The edge primitives the join relies on must preserve merge-operand
    /// alignment, because `cut_down_multiequals` repairs the phis afterwards
    /// using the slots as they were before any edge moved.
    #[test]
    fn moving_an_edge_keeps_its_position_in_the_predecessor_list() {
        let mut data = Funcdata::default();
        let first = data.new_block(0x1000);
        let second = data.new_block(0x1010);
        let third = data.new_block(0x1020);
        let exit = data.new_block(0x1030);
        let replacement = data.new_block(0x1040);
        for block in [first, second, third] {
            data.add_edge(block, exit);
        }
        assert_eq!(data.block(exit).predecessors, vec![first, second, third]);

        data.move_out_edge(second, exit, replacement);
        assert_eq!(
            data.block(exit).predecessors,
            vec![first, replacement, third],
            "the new source takes the old slot rather than being appended"
        );
        assert!(!data.block(second).successors.contains(&exit));
        assert!(data.block(replacement).successors.contains(&exit));
    }

    #[test]
    fn removing_an_edge_for_the_join_leaves_merge_operands_alone() {
        let mut data = Funcdata::default();
        let first = data.new_block(0x1000);
        let second = data.new_block(0x1010);
        let exit = data.new_block(0x1020);
        data.add_edge(first, exit);
        data.add_edge(second, exit);

        let one = data.new_varnode(ventris_lifter::REGISTER_SPACE, 0, 4);
        let two = data.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
        let phi = data.new_op(op::MULTIEQUAL, seq(0x1020), vec![one, two]);
        let output = data.new_unique(4);
        data.op_set_output(phi, Some(output));
        data.op_insert_end(phi, exit);

        assert!(data.remove_edge_keeping_merges(first, exit));
        assert_eq!(data.block(exit).predecessors, vec![second]);
        assert_eq!(
            data.op(phi).inputs,
            vec![one, two],
            "the operands are the caller's to repair, and the slots must still \
             mean what they meant"
        );
    }
}

/// Simplify a merge whose branches build the same value.
///
/// Port of `RulePushMulti` from `ruleaction.cc`. `ConditionalJoin` merges two
/// blocks that test the same thing and leaves behind a phi of the two tests;
/// `findDups` accepts the join in the first place *because* this rule will
/// apply afterwards - the comment there says so. Pushing the merge below the
/// duplicated operation turns `phi(a == 0, b == 0)` into `phi(a, b) == 0`, which
/// is what leaves the branch reading one comparison of one merged value.
///
/// That shape is also what for-loop recovery looks for: a condition whose
/// definition leads to the loop's phi, rather than being a phi itself.
pub struct RulePushMulti;

impl super::action::Rule for RulePushMulti {
    fn name(&self) -> &'static str {
        "pushmulti"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::MULTIEQUAL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        if data.op(id).inputs.len() != 2 {
            return 0;
        }
        let first = data.op(id).inputs[0];
        let second = data.op(id).inputs[1];
        let (Some(def1), Some(def2)) = (data.varnode(first).def, data.varnode(second).def) else {
            return 0;
        };
        let contingent = match functional_equality(data, first, second) {
            Equality::Same => None,
            Equality::Contingent(left, right) => Some((left, right)),
            Equality::Different => return 0,
        };
        // A SUBPIECE is pulled towards its reader, not pushed towards its
        // definition, so pushing a merge below one would fight that.
        if data.op(def1).opcode == op::SUBPIECE {
            return 0;
        }
        // The COPY case merges two shadowing values and needs an existing merge
        // to fold into; without one there is nothing to gain.
        if data.op(def1).opcode == op::COPY {
            return 0;
        }
        let Some(block) = data.op(id).parent else {
            return 0;
        };
        // Each branch's value must exist only for this merge, or moving its
        // definition would move it away from another reader.
        if data.lone_descend(first) != Some(id) || data.lone_descend(second) != Some(id) {
            return 0;
        }
        let Some(output) = data.op(id).output else {
            return 0;
        };
        // The surviving definition takes over the merge's output and moves into
        // the merge block.
        data.op_set_output(def1, Some(output));
        data.op_uninsert(def1);
        match contingent {
            Some((left, right)) => {
                let Some(slot) = data.op(def1).inputs.iter().position(|held| *held == left) else {
                    // The operand order was settled by commuting, which this
                    // move cannot express; leave the merge alone.
                    data.op_set_output(def1, None);
                    return 0;
                };
                let size = data.varnode(left).size;
                let seq = data.op(id).seq;
                let merged = existing_merge(data, block, left, right).unwrap_or_else(|| {
                    let phi = data.new_op(op::MULTIEQUAL, seq, vec![left, right]);
                    let value = data.new_unique(size);
                    data.op_set_output(phi, Some(value));
                    data.op_insert_begin(phi, block);
                    phi
                });
                let Some(value) = data.op(merged).output else {
                    data.op_set_output(def1, None);
                    return 0;
                };
                data.op_set_input(def1, value, slot);
                data.op_insert_after(def1, merged);
            }
            None => data.op_insert_begin(def1, block),
        }
        data.op_destroy(id);
        data.op_destroy(def2);
        1
    }
}

/// A merge of exactly these two values already in this block.
///
/// The first half of Ghidra's `findSubstitute`. The second half searches for a
/// common subexpression to reuse; skipping it only means building a merge that
/// could have been shared, never a wrong one.
fn existing_merge(
    data: &Funcdata,
    block: GraphBlockId,
    first: VarnodeId,
    second: VarnodeId,
) -> Option<OpId> {
    data.block(block).ops.iter().copied().find(|held| {
        let operation = data.op(*held);
        operation.opcode == op::MULTIEQUAL && operation.inputs == vec![first, second]
    })
}
