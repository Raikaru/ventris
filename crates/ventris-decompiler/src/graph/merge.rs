//! Variable merging, ported from Ghidra 12.1.3's `Merge` and `HighVariable`.
//!
//! SSA gives every definition its own value, which is what makes analysis
//! sound and what makes output unreadable: a register written on three paths
//! becomes four names, and the merge between them becomes three assignments
//! that say nothing.
//!
//! A `HighVariable` is the C-level variable a set of SSA values share. Merging
//! across a `MULTIEQUAL` is *required*, not cosmetic: the merge means "these
//! are the same variable on different paths", so once they share a name the
//! merge has no content left and the assignments disappear. Ghidra does the
//! same for `INDIRECT`, where the value before and after an operation is one
//! variable whose contents that operation may have changed.
//!
//! Source authority: `Merge::mergeOpcode`, `Merge::mergeTestBasic`,
//! `HighVariable` in `merge.cc` and `variable.cc` at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use ventris_pcode::op;

use super::{Funcdata, VarnodeId};

/// The C-level variable a set of SSA values share.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct HighId(pub u32);

/// Disjoint sets of values that name one variable each.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct HighVariables {
    parent: Vec<u32>,
}

impl HighVariables {
    fn new(count: usize) -> Self {
        Self {
            parent: (0..count as u32).collect(),
        }
    }

    /// The variable a value belongs to.
    pub fn high_of(&self, value: VarnodeId) -> HighId {
        HighId(self.find(value.0))
    }

    /// Whether two values are the same variable, so an assignment between them
    /// would be a no-op.
    pub fn same(&self, left: VarnodeId, right: VarnodeId) -> bool {
        self.find(left.0) == self.find(right.0)
    }

    fn find(&self, mut index: u32) -> u32 {
        while self.parent[index as usize] != index {
            index = self.parent[index as usize];
        }
        index
    }

    fn union(&mut self, left: VarnodeId, right: VarnodeId) -> bool {
        let (left, right) = (self.find(left.0), self.find(right.0));
        if left == right {
            return false;
        }
        // Keep the lower index as the representative so names are stable.
        let (keep, drop) = if left < right {
            (left, right)
        } else {
            (right, left)
        };
        self.parent[drop as usize] = keep;
        true
    }
}

/// Whether a value can belong to a merged variable at all.
///
/// Ghidra's `mergeTestBasic`. A constant is not a variable, and a value with no
/// definition and no reader has no live range to merge.
fn can_merge(data: &Funcdata, value: VarnodeId) -> bool {
    let varnode = data.varnode(value);
    !varnode.flags.constant && (varnode.def.is_some() || !varnode.descendants.is_empty())
}

/// Performs the merges the graph's own structure requires.
///
/// Returns the resulting variable partition.
pub fn merge_required(data: &Funcdata) -> HighVariables {
    let mut highs = HighVariables::new(data.varnode_count());
    for opcode in [op::MULTIEQUAL, op::INDIRECT] {
        for (_, operation) in data.live_ops() {
            if operation.opcode != opcode {
                continue;
            }
            let Some(output) = operation.output else {
                continue;
            };
            if !can_merge(data, output) {
                continue;
            }
            // An INDIRECT's second operand names the responsible operation
            // rather than carrying a value.
            let limit = if opcode == op::INDIRECT {
                1
            } else {
                operation.inputs.len()
            };
            for operand in operation.inputs.iter().take(limit).copied() {
                if can_merge(data, operand) {
                    highs.union(output, operand);
                }
            }
        }
    }
    highs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{SeqNum, heritage::heritage};
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    /// entry -> two arms -> join, each arm writing the location.
    fn diamond() -> Funcdata {
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
            let copy = data.new_op(op::COPY, seq(start), vec![constant]);
            let out = data.new_varnode(REGISTER_SPACE, 8, 4);
            data.op_set_output(copy, Some(out));
            data.op_insert_end(copy, block);
        }
        let read = data.new_varnode(REGISTER_SPACE, 8, 4);
        let ret = data.new_op(op::RETURN, seq(0x1030), vec![read]);
        data.op_insert_end(ret, join);
        heritage(&mut data);
        data
    }

    #[test]
    fn a_merge_makes_its_operands_and_result_one_variable() {
        let data = diamond();
        let highs = merge_required(&data);
        let phi = data
            .live_ops()
            .find(|(_, operation)| operation.opcode == op::MULTIEQUAL)
            .expect("a merge was placed")
            .1
            .clone();
        let result = phi.output.expect("the merge defines a value");
        for operand in phi.inputs {
            assert!(
                highs.same(result, operand),
                "each incoming value is the same variable as the result"
            );
        }
    }

    #[test]
    fn unrelated_values_stay_separate() {
        let data = diamond();
        let highs = merge_required(&data);
        let phi = data
            .live_ops()
            .find(|(_, operation)| operation.opcode == op::MULTIEQUAL)
            .expect("a merge was placed")
            .1
            .clone();
        let result = phi.output.expect("the merge defines a value");
        let unrelated = data
            .live_ops()
            .filter(|(_, operation)| operation.opcode == op::COPY)
            .filter_map(|(_, operation)| operation.inputs.first().copied())
            .next()
            .expect("an arm's constant operand");
        assert!(!highs.same(result, unrelated));
    }

    #[test]
    fn a_constant_is_not_merged_into_a_variable() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let constant = data.new_constant(5, 4);
        let phi = data.new_op(op::MULTIEQUAL, seq(0x1000), vec![constant]);
        let out = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(phi, Some(out));
        data.op_insert_end(phi, block);

        let highs = merge_required(&data);
        assert!(!highs.same(out, constant));
    }

    #[test]
    fn a_guarded_location_is_one_variable_across_the_call() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let before = data.new_varnode(REGISTER_SPACE, 8, 4);
        let cause = data.new_constant(0x1000, 4);
        let indirect = data.new_op(op::INDIRECT, seq(0x1000), vec![before, cause]);
        let after = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(indirect, Some(after));
        data.op_insert_end(indirect, block);
        let ret = data.new_op(op::RETURN, seq(0x1004), vec![after]);
        data.op_insert_end(ret, block);

        let highs = merge_required(&data);
        assert!(
            highs.same(before, after),
            "the value before and after the call is one variable"
        );
        assert!(
            !highs.same(before, cause),
            "the annotation naming the operation is not part of the variable"
        );
    }

    #[test]
    fn merging_is_transitive_across_chained_merges() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let first = data.new_varnode(REGISTER_SPACE, 8, 4);
        let second = data.new_varnode(REGISTER_SPACE, 8, 4);
        let inner = data.new_op(op::MULTIEQUAL, seq(0x1000), vec![first, second]);
        let middle = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(inner, Some(middle));
        data.op_insert_end(inner, block);
        let third = data.new_varnode(REGISTER_SPACE, 8, 4);
        let outer = data.new_op(op::MULTIEQUAL, seq(0x1004), vec![middle, third]);
        let result = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(outer, Some(result));
        data.op_insert_end(outer, block);
        let ret = data.new_op(op::RETURN, seq(0x1008), vec![result]);
        data.op_insert_end(ret, block);

        let highs = merge_required(&data);
        assert!(highs.same(first, third));
        assert!(highs.same(first, result));
    }
}
