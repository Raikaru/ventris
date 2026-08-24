//! Topological live ranges used by speculative variable merging.
//!
//! This is a Rust port of `CoverBlock::intersect`, `CoverBlock::merge`,
//! `CoverBlock::setBegin`, `CoverBlock::setEnd`, `Cover::addDefPoint`,
//! `Cover::addRefPoint`, `Cover::intersect`, and `Cover::contain` from
//! Ghidra 12.1.3's `cover.cc`/`cover.hh` at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.
//!
//! A range endpoint is an operation index. `None` is the beginning or end of
//! a block, as in Ghidra's special boundary PcodeOps. Intersections distinguish
//! a shared transfer boundary from an interval overlap: a COPY may end one
//! value and begin another at the same operation without forcing two C locals.

use std::collections::{BTreeMap, BTreeSet};

use ventris_pcode::op;

use super::heritage::Dominance;
use super::{Funcdata, GraphBlockId, OpId, VarnodeId};

/// The covered part of one basic block.
///
/// `begin == None` denotes the block's first program point and `end == None`
/// denotes its last program point. `covered` is separate because the pair of
/// boundary markers is also the valid representation of an entirely covered
/// block.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoverBlock {
    begin: Option<usize>,
    end: Option<usize>,
    covered: bool,
}

impl CoverBlock {
    /// Construct an uncovered block.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this block has no live program point.
    pub fn is_empty(&self) -> bool {
        !self.covered
    }

    /// Set the beginning endpoint, retaining the existing tail endpoint.
    ///
    /// Ghidra's setter turns an empty block into a range reaching the end;
    /// callers that need a singleton definition set the end immediately after.
    pub fn set_begin(&mut self, begin: usize) {
        if !self.covered {
            self.covered = true;
            self.end = None;
        }
        self.begin = Some(begin);
    }

    /// Set the ending endpoint, retaining the existing beginning endpoint.
    pub fn set_end(&mut self, end: usize) {
        if !self.covered {
            self.covered = true;
            self.begin = None;
        }
        self.end = Some(end);
    }

    /// Mark every point in the block as covered.
    pub fn set_all(&mut self) {
        self.covered = true;
        self.begin = None;
        self.end = None;
    }

    /// Remove all coverage from this block.
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Beginning endpoint, or `None` for the block beginning.
    pub fn begin(&self) -> Option<usize> {
        self.begin
    }

    /// Ending endpoint, or `None` for the block end.
    pub fn end(&self) -> Option<usize> {
        self.end
    }

    fn begin_value(&self) -> usize {
        self.begin.unwrap_or(0)
    }

    fn end_value(&self) -> usize {
        self.end.unwrap_or(usize::MAX)
    }

    /// Whether an operation index is inside this range, including endpoints.
    pub fn contains(&self, index: usize) -> bool {
        if self.is_empty() {
            return false;
        }
        let begin = self.begin_value();
        let end = self.end_value();
        if begin <= end {
            (begin..=end).contains(&index)
        } else {
            index >= begin || index <= end
        }
    }

    /// Characterize intersection with another range.
    ///
    /// Returns `0` for no intersection, `1` when only an endpoint is shared,
    /// and `2` when an interval of program points is shared. This is the same
    /// distinction made by Ghidra's `CoverBlock::intersect`; merge decisions
    /// reject only the last case.
    pub fn intersect(&self, other: &Self) -> u8 {
        if self.is_empty() || other.is_empty() {
            return 0;
        }

        let start = self.begin_value();
        let stop = self.end_value();
        let other_start = other.begin_value();
        let other_stop = other.end_value();

        if start <= stop {
            if other_start <= other_stop {
                // Both ranges are one piece of the block's linear order.
                if stop <= other_start || other_stop <= start {
                    if start == other_stop || stop == other_start {
                        return 1;
                    }
                    return 0;
                }
            } else if start >= other_stop && stop <= other_start {
                // `other` wraps around the block boundary.
                if start == other_stop || stop == other_start {
                    return 1;
                }
                return 0;
            }
        } else if other_start <= other_stop {
            // `self` wraps and `other` does not.
            if other_start >= stop && other_stop <= start {
                if other_start == stop || other_stop == start {
                    return 1;
                }
                return 0;
            }
        }
        // Both ranges wrap, or one strictly crosses the other.
        2
    }

    /// Merge another range into this one, filling the interval between them.
    ///
    /// Filling a gap is intentional: a Varnode's cover is a control-flow
    /// scope, not merely the set of its direct use instructions.
    pub fn merge(&mut self, other: &Self) {
        if other.is_empty() {
            return;
        }
        if self.is_empty() {
            *self = *other;
            return;
        }

        let start = self.begin_value();
        let other_start = other.begin_value();
        // Is this range's start contained in `other`?
        let other_contains_start = (start == 0 && other.end.is_none()) || other.contains(start);
        // Is `other`'s start contained in this range?
        let this_contains_other_start =
            (other_start == 0 && self.end.is_none()) || self.contains(other_start);

        let other_covers_beginning = other_start == 0 && self.end.is_none();
        let self_covers_beginning = start == 0 && other.end.is_none();

        if other_contains_start && this_contains_other_start {
            if start != other_start || self_covers_beginning || other_covers_beginning {
                self.set_all();
                return;
            }
        }
        if other_contains_start {
            self.begin = other.begin;
        } else if !other_contains_start && !this_contains_other_start {
            // Disjoint ranges are joined in the block's circular order.
            if start < other_start {
                self.end = other.end;
            } else {
                self.begin = other.begin;
            }
            self.covered = true;
            return;
        }
        if other_covers_beginning || other.contains(self.end_value()) {
            self.end = other.end;
        }
        self.covered = true;
    }
}

/// The topological scope of one SSA Varnode.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cover {
    blocks: BTreeMap<GraphBlockId, CoverBlock>,
}

impl Cover {
    /// Build a cover from a Varnode definition and all of its readers.
    ///
    /// A reader in a later block walks backwards over predecessor edges. The
    /// walk stops at a definition already in the cover; an empty intermediate
    /// block is therefore covered in full. Dominance rejects predecessor paths
    /// that cannot contain this SSA definition, while the MULTIEQUAL case
    /// follows only the predecessor supplying this particular input.
    pub fn of(data: &Funcdata, value: VarnodeId, dominance: &Dominance) -> Self {
        let mut cover = Self::default();
        let indices = operation_indices(data);
        let definition_block = data.varnode(value).def.and_then(|def| data.op(def).parent);
        let entry = dominance
            .reverse_postorder
            .first()
            .copied()
            .or_else(|| data.blocks().next().map(|(id, _)| id));

        if let Some(def) = data.varnode(value).def {
            if let Some(block) = data.op(def).parent {
                let index = indices.get(&def).copied().unwrap_or(0);
                let block_cover = cover.blocks.entry(block).or_default();
                block_cover.set_begin(index);
                block_cover.set_end(index);
            }
        } else if data.varnode(value).flags.input {
            if let Some(block) = entry {
                let block_cover = cover.blocks.entry(block).or_default();
                // Ghidra's input marker has order zero but is not a real op.
                block_cover.set_begin(0);
                block_cover.set_end(0);
            }
        }

        let mut readers: Vec<OpId> = data.varnode(value).descendants.iter().copied().collect();
        let rank: BTreeMap<GraphBlockId, usize> = dominance
            .reverse_postorder
            .iter()
            .copied()
            .enumerate()
            .map(|(rank, block)| (block, rank))
            .collect();
        readers.sort_by_key(|reader| {
            let parent = data.op(*reader).parent;
            (
                parent
                    .and_then(|block| rank.get(&block).copied())
                    .unwrap_or(usize::MAX),
                indices.get(reader).copied().unwrap_or(usize::MAX),
                reader.0,
            )
        });
        for reader in readers {
            if data.opcode_of(reader).is_none() {
                continue;
            }
            cover.add_ref_point(data, value, reader, dominance, &indices, definition_block);
        }
        cover
    }

    /// Whether the two covers overlap over an interval of operations.
    ///
    /// A shared endpoint is only a transfer boundary. This permits the normal
    /// COPY shape where the input dies at the COPY and the result starts there.
    pub fn intersects(&self, other: &Self) -> bool {
        self.blocks.iter().any(|(block, left)| {
            other
                .blocks
                .get(block)
                .is_some_and(|right| left.intersect(right) >= 2)
        })
    }

    /// Whether a block operation index belongs to this cover.
    pub fn contains(&self, block: GraphBlockId, index: usize) -> bool {
        self.blocks
            .get(&block)
            .is_some_and(|cover| cover.contains(index))
    }

    /// Return the block range when one exists. This is useful to renderers and
    /// keeps the representation read-only outside this module.
    pub fn block(&self, block: GraphBlockId) -> Option<&CoverBlock> {
        self.blocks.get(&block)
    }

    fn add_ref_point(
        &mut self,
        data: &Funcdata,
        value: VarnodeId,
        reader: OpId,
        dominance: &Dominance,
        indices: &BTreeMap<OpId, usize>,
        definition_block: Option<GraphBlockId>,
    ) {
        let operation = data.op(reader);
        let Some(block) = operation.parent else {
            return;
        };
        let index = indices
            .get(&reader)
            .copied()
            .unwrap_or_else(|| operation_index(data, block, reader));
        let opcode = operation.opcode;
        let mut recurse_all = false;
        let mut recurse = true;

        let existing = self.blocks.get(&block).copied().unwrap_or_default();
        if existing.is_empty() {
            self.blocks.entry(block).or_default().set_end(index);
        } else if existing.contains(index) {
            // A normal read already lies in the known range. A PHI still
            // carries a separate edge use, so its incoming predecessor must be
            // traversed even when the PHI marker itself is covered.
            recurse = opcode == op::MULTIEQUAL;
        } else {
            let old_end = existing.end;
            let old_begin_is_block_start = existing.begin.is_none();
            let mut updated = existing;
            updated.set_end(index);
            self.blocks.insert(block, updated);
            if index >= updated.begin_value() {
                if old_begin_is_block_start
                    && old_end
                        .and_then(|old| data.block(block).ops.get(old).copied())
                        .and_then(|old_op| data.opcode_of(old_op))
                        == Some(op::MULTIEQUAL)
                {
                    recurse_all = true;
                }
                recurse = false;
            }
        }

        if !recurse && !recurse_all {
            return;
        }
        if opcode == op::MULTIEQUAL && !recurse_all {
            let predecessors = &data.block(block).predecessors;
            for (slot, input) in data.op(reader).inputs.iter().copied().enumerate() {
                if input != value {
                    continue;
                }
                if let Some(predecessor) = predecessors.get(slot).copied() {
                    self.add_ref_recurse(
                        data,
                        predecessor,
                        dominance,
                        definition_block,
                        &mut BTreeSet::new(),
                    );
                }
            }
        } else {
            for predecessor in data.block(block).predecessors.iter().copied() {
                self.add_ref_recurse(
                    data,
                    predecessor,
                    dominance,
                    definition_block,
                    &mut BTreeSet::new(),
                );
            }
        }
    }

    fn add_ref_recurse(
        &mut self,
        data: &Funcdata,
        block: GraphBlockId,
        dominance: &Dominance,
        definition_block: Option<GraphBlockId>,
        visited: &mut BTreeSet<GraphBlockId>,
    ) {
        if !visited.insert(block) {
            return;
        }
        if !dominance.reverse_postorder.is_empty() && !dominance.reverse_postorder.contains(&block)
        {
            return;
        }
        if let Some(definition_block) = definition_block
            && !dominates(dominance, definition_block, block)
        {
            return;
        }

        let existing = self.blocks.get(&block).copied().unwrap_or_default();
        if existing.is_empty() {
            self.blocks.entry(block).or_default().set_all();
            let predecessors = data.block(block).predecessors.clone();
            for predecessor in predecessors {
                self.add_ref_recurse(data, predecessor, dominance, definition_block, visited);
            }
            return;
        }

        let stop = existing.end_value();
        if stop != usize::MAX && stop >= existing.begin_value() {
            let mut extended = existing;
            extended.end = None;
            self.blocks.insert(block, extended);
            let stop_is_phi = existing
                .end
                .and_then(|index| data.block(block).ops.get(index).copied())
                .and_then(|op_id| data.opcode_of(op_id))
                == Some(op::MULTIEQUAL);
            if existing.begin.is_none() && stop_is_phi {
                let predecessors = data.block(block).predecessors.clone();
                for predecessor in predecessors {
                    self.add_ref_recurse(data, predecessor, dominance, definition_block, visited);
                }
            }
        } else if stop == 0 && existing.begin.is_none() {
            let stop_is_phi = existing
                .end
                .and_then(|index| data.block(block).ops.get(index).copied())
                .and_then(|op_id| data.opcode_of(op_id))
                == Some(op::MULTIEQUAL);
            if stop_is_phi {
                let predecessors = data.block(block).predecessors.clone();
                for predecessor in predecessors {
                    self.add_ref_recurse(data, predecessor, dominance, definition_block, visited);
                }
            }
        }
    }
}

fn operation_indices(data: &Funcdata) -> BTreeMap<OpId, usize> {
    data.blocks()
        .flat_map(|(_, graph_block)| {
            graph_block
                .ops
                .iter()
                .copied()
                .enumerate()
                .map(|(index, op)| (op, index))
        })
        .collect()
}

fn operation_index(data: &Funcdata, block: GraphBlockId, operation: OpId) -> usize {
    data.block(block)
        .ops
        .iter()
        .position(|candidate| *candidate == operation)
        .unwrap_or(0)
}

fn dominates(dominance: &Dominance, ancestor: GraphBlockId, mut block: GraphBlockId) -> bool {
    if ancestor == block {
        return true;
    }
    if dominance.immediate.is_empty() {
        return true;
    }
    let mut seen = BTreeSet::new();
    while seen.insert(block) {
        let Some(parent) = dominance.immediate.get(&block).copied().flatten() else {
            return false;
        };
        if parent == block {
            return false;
        }
        if parent == ancestor {
            return true;
        }
        block = parent;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::heritage::compute_dominance;
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64) -> super::super::SeqNum {
        super::super::SeqNum { address, order: 0 }
    }

    #[test]
    fn a_later_reader_covers_an_intervening_block() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let first = data.new_block(0x1000);
        let middle = data.new_block(0x1010);
        let last = data.new_block(0x1020);
        data.add_edge(first, middle);
        data.add_edge(middle, last);

        let input = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(input);
        let define = data.new_op(op::COPY, seq(0x1000), vec![input]);
        let value = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.op_set_output(define, Some(value));
        data.op_insert_end(define, first);
        let branch = data.new_op(op::BRANCH, seq(0x1010), Vec::new());
        data.op_insert_end(branch, middle);
        let read = data.new_op(op::RETURN, seq(0x1020), vec![value]);
        data.op_insert_end(read, last);

        let cover = Cover::of(&data, value, &compute_dominance(&data));
        assert!(cover.contains(middle, 0));
        assert!(cover.contains(first, 0));
        assert!(cover.contains(last, 0));
    }

    #[test]
    fn endpoint_touch_is_not_an_interval_intersection() {
        let mut left = CoverBlock::new();
        left.set_begin(1);
        left.set_end(3);
        let mut right = CoverBlock::new();
        right.set_begin(3);
        right.set_end(5);
        assert_eq!(left.intersect(&right), 1);
        assert!(
            !Cover {
                blocks: [(GraphBlockId(0), left)].into_iter().collect(),
            }
            .intersects(&Cover {
                blocks: [(GraphBlockId(0), right)].into_iter().collect(),
            })
        );
    }

    #[test]
    fn interior_overlap_is_detected() {
        let mut left = CoverBlock::new();
        left.set_begin(1);
        left.set_end(4);
        let mut right = CoverBlock::new();
        right.set_begin(3);
        right.set_end(5);
        assert_eq!(left.intersect(&right), 2);
    }
}
