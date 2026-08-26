//! Speculative variable partitioning over the graph's SSA values.
//!
//! The source algorithms are `Merge::mergeOpcode`, `Merge::mergeLinear`,
//! `Merge::mergeTestBasic`, `Merge::mergeTestAdjacent`,
//! `Merge::mergeTestSpeculative`, `Merge::mergeAddrTied`,
//! `Merge::inflateTest`, `Merge::merge`, and `HighIntersectTest::updateHigh`
//! in Ghidra 12.1.3's `merge.cc`, plus `ActionMergeCopy`,
//! `ActionMergeAdjacent`, `ActionMergeType`, and `ActionMergeRequired` in
//! `coreaction.cc`/`coreaction.hh`, all at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.
//!
//! Ghidra keeps the resulting HighVariables on Funcdata. This graph's
//! Funcdata intentionally remains a data-flow-only structure, so these action
//! registrations are honest no-ops: `merge_all` computes the side partition
//! consumed by the renderer and does not pretend that a mutable graph changed.
//! The graph's recovered `Types` table is computed locally for this pass;
//! values with no stronger evidence fall back to their storage width, while
//! constants remain excluded exactly as in `Merge::mergeTestBasic`.

use std::collections::BTreeMap;

use ventris_pcode::op;

use crate::native::Type;

use super::action::Action;
use super::cover::Cover;
use super::heritage::compute_dominance;
use super::types::{Types, infer_types};
use super::{Funcdata, VarnodeId};

/// A disjoint-set partition of SSA Varnodes into C-level variables.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Variables {
    parent: Vec<u32>,
}

impl Variables {
    fn new(count: usize) -> Self {
        Self {
            parent: (0..count as u32).collect(),
        }
    }

    /// Whether two SSA values are assigned to the same C-level variable.
    pub fn same(&self, left: VarnodeId, right: VarnodeId) -> bool {
        self.find(left.0) == self.find(right.0)
    }

    /// Return the stable representative of the variable containing `value`.
    pub fn high_of(&self, value: VarnodeId) -> u32 {
        self.find(value.0)
    }

    fn find(&self, mut value: u32) -> u32 {
        // The renderer may retain a partition while a later graph rewrite
        // allocates a Varnode. Treat that unseen value as its own singleton
        // instead of indexing past the snapshot's parent array.
        if value as usize >= self.parent.len() {
            return value;
        }
        while self.parent[value as usize] != value {
            value = self.parent[value as usize];
        }
        value
    }

    fn union(&mut self, left: VarnodeId, right: VarnodeId) -> bool {
        let left = self.find(left.0);
        let right = self.find(right.0);
        if left == right {
            return false;
        }
        let (keep, drop) = if left < right {
            (left, right)
        } else {
            (right, left)
        };
        self.parent[drop as usize] = keep;
        true
    }
}

fn can_merge(data: &Funcdata, value: VarnodeId) -> bool {
    let varnode = data.varnode(value);
    !varnode.flags.constant && (varnode.def.is_some() || !varnode.descendants.is_empty())
}

/// Whether a value is a copy, extension or truncation of a single constant.
fn respells_a_constant(data: &Funcdata, value: VarnodeId) -> bool {
    let Some(def) = data.varnode(value).def else {
        return false;
    };
    let operation = data.op(def);
    if !matches!(
        operation.opcode,
        op::COPY | op::INT_SEXT | op::INT_ZEXT | op::SUBPIECE
    ) {
        return false;
    }
    operation
        .inputs
        .first()
        .is_some_and(|input| data.varnode(*input).flags.constant)
}

/// Whether the recovered graph types agree for two values.
///
/// A value not reached by inference still has the same unsigned-width
/// fallback used by `ActionInferTypes::buildLocaltypes`.
fn same_type(data: &Funcdata, types: &Types, left: VarnodeId, right: VarnodeId) -> bool {
    let fallback = |value: VarnodeId| Type::Unsigned(data.varnode(value).size.saturating_mul(8));
    let left_type = types.get(left).cloned().unwrap_or_else(|| fallback(left));
    let right_type = types.get(right).cloned().unwrap_or_else(|| fallback(right));
    left_type == right_type
}

fn required_union(data: &Funcdata, variables: &mut Variables) {
    for (_, operation) in data.live_ops() {
        let Some(output) = operation.output else {
            continue;
        };
        if !can_merge(data, output) {
            continue;
        }
        let limit = if operation.opcode == op::INDIRECT {
            1
        } else if operation.opcode == op::MULTIEQUAL {
            operation.inputs.len()
        } else {
            0
        };
        for input in operation.inputs.iter().take(limit).copied() {
            if can_merge(data, input) {
                // MULTIEQUAL and INDIRECT merges are required by SSA's
                // control-flow meaning; unlike speculative merges they do not
                // get vetoed by an already-overlapping cover.
                variables.union(output, input);
            }
        }
    }
}

fn groups_intersect(
    data: &Funcdata,
    variables: &Variables,
    left: VarnodeId,
    right: VarnodeId,
    covers: &[Cover],
) -> bool {
    let left_high = variables.high_of(left);
    let right_high = variables.high_of(right);
    for left_index in 0..data.varnode_count() {
        let left_value = VarnodeId(left_index as u32);
        if variables.high_of(left_value) != left_high {
            continue;
        }
        for right_index in 0..data.varnode_count() {
            let right_value = VarnodeId(right_index as u32);
            if variables.high_of(right_value) != right_high {
                continue;
            }
            if covers[left_index].intersects(&covers[right_index]) {
                return true;
            }
        }
    }
    false
}

/// Whether any value already in this variable is a function input.
///
/// The test is on the whole group, not the one candidate, because a merge is
/// transitive: joining a group that already contains an input would smuggle the
/// input in through a value that is not itself one.
fn group_holds_input(data: &Funcdata, variables: &Variables, value: VarnodeId) -> bool {
    let group = variables.high_of(value);
    (0..data.varnode_count()).any(|index| {
        let candidate = VarnodeId(index as u32);
        variables.high_of(candidate) == group && data.varnode(candidate).flags.input
    })
}
/// Ghidra's `Varnode::isAddrTied`: the value's address maps into a scope, so a
/// symbol names that storage.
///
/// Ghidra sets the flag in `Scope::queryProperties` when the address falls in a
/// scope's range - stack slots and globals. A register carrying no symbol is not
/// tied, so registers are still eligible for a speculative merge.
fn is_address_tied(data: &Funcdata, value: VarnodeId) -> bool {
    let varnode = data.varnode(value);
    varnode.flags.volatile || varnode.space == ventris_lifter::RAM_SPACE
}


fn speculative_union(
    data: &Funcdata,
    variables: &mut Variables,
    types: &Types,
    left: VarnodeId,
    right: VarnodeId,
    covers: &[Cover],
) -> bool {
    if !can_merge(data, left) || !can_merge(data, right) {
        return false;
    }
    // `Merge::mergeTestSpeculative` refuses to merge anything speculatively
    // with a function input. An input is the only evidence that a location
    // carries a parameter, and folding it into a variable the function later
    // overwrites destroys that evidence: the recovered prototype loses the
    // argument and every read of it renders as a local.
    if group_holds_input(data, variables, left) || group_holds_input(data, variables, right) {
        return false;
    }
    // A value that only re-spells a constant is that constant in different
    // storage. Merging one into a named group gives the constant a declaration
    // and a cast no reader needs, and the name then spreads to every other
    // member. This is refused for speculative merges only: `required_union`
    // must still put a phi's operands in the phi's variable, whatever they hold.
    // `Merge::mergeTestSpeculative` refuses an address-tied value. A machine
    // location has an identity the reader can name, so folding two of them into
    // one variable claims they are the same storage across their whole live
    // range when they are only the same register at different times.
    //
    // Skipping this cost real accuracy: two distinct branch conditions in one
    // register became one variable, and `decompSZS_subroutine` rendered four
    // different tests as `!b || !b || !b || !b`.
    if is_address_tied(data, left) || is_address_tied(data, right) {
        return false;
    }
    if respells_a_constant(data, left) || respells_a_constant(data, right) {
        return false;
    }
    if !same_type(data, types, left, right) {
        return false;
    }
    if variables.same(left, right) {
        return true;
    }
    if groups_intersect(data, variables, left, right, covers) {
        return false;
    }
    variables.union(left, right)
}

fn merge_copy(data: &Funcdata, variables: &mut Variables, types: &Types, covers: &[Cover]) {
    for (_, operation) in data.live_ops() {
        if operation.opcode != op::COPY {
            continue;
        }
        let Some(output) = operation.output else {
            continue;
        };
        if !can_merge(data, output) {
            continue;
        }
        for input in operation.inputs.iter().copied() {
            speculative_union(data, variables, types, output, input, covers);
        }
    }
}

fn merge_adjacent(data: &Funcdata, variables: &mut Variables, types: &Types, covers: &[Cover]) {
    for (_, operation) in data.live_ops() {
        if matches!(operation.opcode, op::CALL | op::CALLIND | op::CALLOTHER) {
            continue;
        }
        let Some(output) = operation.output else {
            continue;
        };
        if !can_merge(data, output) {
            continue;
        }
        for input in operation.inputs.iter().copied() {
            // Ghidra requires a written or input Varnode here. Constants and
            // annotation-only values must not acquire a named local.
            if !can_merge(data, input) || !same_type(data, types, output, input) {
                continue;
            }
            speculative_union(data, variables, types, output, input, covers);
        }
    }
}

fn merge_type(data: &Funcdata, variables: &mut Variables, types: &Types, covers: &[Cover]) {
    let values: Vec<VarnodeId> = (0..data.varnode_count())
        .map(|index| VarnodeId(index as u32))
        .filter(|value| can_merge(data, *value))
        .collect();
    // `mergeLinear` orders HighVariables by their first cover block. The
    // fallback order below is deterministic and gives definitions before later
    // values while leaving the cover test responsible for legality.
    for (position, left) in values.iter().copied().enumerate() {
        for right in values.iter().copied().skip(position + 1) {
            if !same_type(data, types, left, right) {
                continue;
            }
            speculative_union(data, variables, types, left, right, covers);
        }
    }
}

/// Compute required, COPY, adjacent, and same-type speculative merges.
///
/// This is intentionally a pure side computation. The action wrappers below
/// return zero because applying them cannot mutate a partition held elsewhere;
/// callers should run this function once and pass its result to the renderer.
pub fn merge_all(data: &Funcdata) -> Variables {
    let dominance = compute_dominance(data);
    let covers: Vec<Cover> = (0..data.varnode_count())
        .map(|index| Cover::of(data, VarnodeId(index as u32), &dominance))
        .collect();
    let seed = BTreeMap::new();
    let types = infer_types(data, &seed);
    let mut variables = Variables::new(data.varnode_count());
    required_union(data, &mut variables);
    merge_copy(data, &mut variables, &types, &covers);
    merge_adjacent(data, &mut variables, &types, &covers);
    merge_type(data, &mut variables, &types, &covers);
    variables
}

/// Registration marker for Ghidra's `ActionMergeCopy`.
///
/// The actual side-partition work is performed by [`merge_all`].
pub struct ActionMergeCopy;

impl Action for ActionMergeCopy {
    fn name(&self) -> &'static str {
        "mergecopy"
    }

    fn apply(&self, _data: &mut Funcdata) -> usize {
        0
    }
}

/// Registration marker for Ghidra's `ActionMergeAdjacent`.
///
/// The actual side-partition work is performed by [`merge_all`].
pub struct ActionMergeAdjacent;

impl Action for ActionMergeAdjacent {
    fn name(&self) -> &'static str {
        "mergeadjacent"
    }

    fn apply(&self, _data: &mut Funcdata) -> usize {
        0
    }
}

/// Registration marker for Ghidra's `ActionMergeType`.
///
/// The actual side-partition work is performed by [`merge_all`].
pub struct ActionMergeType;

impl Action for ActionMergeType {
    fn name(&self) -> &'static str {
        "mergetype"
    }

    fn apply(&self, _data: &mut Funcdata) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64) -> super::super::SeqNum {
        super::super::SeqNum { address, order: 0 }
    }

    fn copy_chain(with_overlap: bool) -> (Funcdata, VarnodeId, VarnodeId) {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let source = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(source);
        let first_def = data.new_op(op::COPY, seq(0x1000), vec![source]);
        let first = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.op_set_output(first_def, Some(first));
        data.op_insert_end(first_def, block);
        let second_def = data.new_op(op::COPY, seq(0x1004), vec![first]);
        let second = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.op_set_output(second_def, Some(second));
        data.op_insert_end(second_def, block);
        if with_overlap {
            let first_read = data.new_op(op::RETURN, seq(0x1008), vec![first]);
            data.op_insert_end(first_read, block);
        }
        let second_read = data.new_op(
            op::RETURN,
            seq(if with_overlap { 0x100c } else { 0x1008 }),
            vec![second],
        );
        data.op_insert_end(second_read, block);
        (data, first, second)
    }

    #[test]
    fn overlapping_copy_values_stay_separate() {
        let (data, first, second) = copy_chain(true);
        let variables = merge_all(&data);
        assert!(!variables.same(first, second));
    }

    #[test]
    fn disjoint_copy_values_merge_at_the_transfer_boundary() {
        let (data, first, second) = copy_chain(false);
        let variables = merge_all(&data);
        assert!(variables.same(first, second));
    }

    #[test]
    fn required_merges_are_transitive_and_never_absorb_constants() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let first = data.new_varnode(REGISTER_SPACE, 0, 4);
        let second = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(first);
        data.mark_input(second);
        let constant = data.new_constant(9, 4);
        let inner = data.new_op(op::MULTIEQUAL, seq(0x1000), vec![first, second, constant]);
        let middle = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.op_set_output(inner, Some(middle));
        data.op_insert_end(inner, block);
        let outer = data.new_op(op::MULTIEQUAL, seq(0x1004), vec![middle, first]);
        let result = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.op_set_output(outer, Some(result));
        data.op_insert_end(outer, block);
        let read = data.new_op(op::RETURN, seq(0x1008), vec![result]);
        data.op_insert_end(read, block);

        let variables = merge_all(&data);
        assert!(variables.same(first, second));
        assert!(variables.same(first, middle));
        assert!(variables.same(first, result));
        assert!(!variables.same(result, constant));
    }

    #[test]
    fn a_function_input_is_never_merged_speculatively() {
        // An input is the only evidence a location carries a parameter. Folding
        // it into a variable the function overwrites loses the argument from the
        // recovered prototype, which is what `Merge::mergeTestSpeculative`
        // prevents.
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let argument = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(argument);
        let copy = data.new_op(op::COPY, seq(0x1000), vec![argument]);
        let local = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.op_set_output(copy, Some(local));
        data.op_insert_end(copy, block);
        let read = data.new_op(op::RETURN, seq(0x1004), vec![local]);
        data.op_insert_end(read, block);

        let variables = merge_all(&data);
        assert!(
            !variables.same(argument, local),
            "the parameter must keep its own identity"
        );
    }

    #[test]
    fn adjacent_merge_requires_a_non_call_operation() {
        let mut data = Funcdata::default();
        data.entry = 0x2000;
        let block = data.new_block(0x2000);
        // Deliberately neither a function input nor a constant: the first is
        // refused by `Merge::mergeTestSpeculative` and the second by the
        // constant re-spelling rule, so either would make the adjacency test
        // unobservable. A load is a real computation with neither property.
        let space = data.new_constant(u64::from(ventris_lifter::RAM_SPACE), 4);
        let address = data.new_constant(0x9000, 4);
        let seeded = data.new_op(op::LOAD, seq(0x1ffc), vec![space, address]);
        let input = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.op_set_output(seeded, Some(input));
        data.op_insert_end(seeded, block);
        let constant = data.new_constant(1, 4);
        let add = data.new_op(op::INT_ADD, seq(0x2000), vec![input, constant]);
        let output = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.op_set_output(add, Some(output));
        data.op_insert_end(add, block);
        let read = data.new_op(op::RETURN, seq(0x2004), vec![output]);
        data.op_insert_end(read, block);
        let dominance = compute_dominance(&data);
        let covers: Vec<Cover> = (0..data.varnode_count())
            .map(|index| Cover::of(&data, VarnodeId(index as u32), &dominance))
            .collect();
        let seed = BTreeMap::new();
        let types = infer_types(&data, &seed);
        let mut variables = Variables::new(data.varnode_count());
        merge_adjacent(&data, &mut variables, &types, &covers);
        assert!(variables.same(input, output));

        let mut call_data = Funcdata::default();
        call_data.entry = 0x3000;
        let call_block = call_data.new_block(0x3000);
        let call_input = call_data.new_varnode(REGISTER_SPACE, 0, 4);
        call_data.mark_input(call_input);
        let call = call_data.new_op(op::CALL, seq(0x3000), vec![call_input]);
        let call_output = call_data.new_varnode(REGISTER_SPACE, 0, 4);
        call_data.op_set_output(call, Some(call_output));
        call_data.op_insert_end(call, call_block);
        let call_read = call_data.new_op(op::RETURN, seq(0x3004), vec![call_output]);
        call_data.op_insert_end(call_read, call_block);
        let call_dominance = compute_dominance(&call_data);
        let call_covers: Vec<Cover> = (0..call_data.varnode_count())
            .map(|index| Cover::of(&call_data, VarnodeId(index as u32), &call_dominance))
            .collect();
        let call_types = infer_types(&call_data, &BTreeMap::new());
        let mut call_variables = Variables::new(call_data.varnode_count());
        merge_adjacent(&call_data, &mut call_variables, &call_types, &call_covers);
        assert!(!call_variables.same(call_input, call_output));
    }

    #[test]
    fn type_merge_accepts_disjoint_equal_types_and_rejects_float_integer_mix() {
        let mut data = Funcdata::default();
        data.entry = 0x4000;
        let block = data.new_block(0x4000);
        let left_constant = data.new_constant(1, 4);
        let right_constant = data.new_constant(2, 4);
        let left_op = data.new_op(op::INT_ADD, seq(0x4000), vec![left_constant, left_constant]);
        let left = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.op_set_output(left_op, Some(left));
        data.op_insert_end(left_op, block);
        let left_read = data.new_op(op::RETURN, seq(0x4004), vec![left]);
        data.op_insert_end(left_read, block);
        let right_op = data.new_op(
            op::INT_ADD,
            seq(0x4008),
            vec![right_constant, right_constant],
        );
        let right = data.new_varnode(REGISTER_SPACE, 4, 4);
        data.op_set_output(right_op, Some(right));
        data.op_insert_end(right_op, block);
        let right_read = data.new_op(op::RETURN, seq(0x400c), vec![right]);
        data.op_insert_end(right_read, block);
        let dominance = compute_dominance(&data);
        let covers: Vec<Cover> = (0..data.varnode_count())
            .map(|index| Cover::of(&data, VarnodeId(index as u32), &dominance))
            .collect();
        let types = infer_types(&data, &BTreeMap::new());
        let mut variables = Variables::new(data.varnode_count());
        merge_type(&data, &mut variables, &types, &covers);
        assert!(variables.same(left, right));

        let mut mixed = Funcdata::default();
        mixed.entry = 0x5000;
        let mixed_block = mixed.new_block(0x5000);
        let float_input = mixed.new_varnode(REGISTER_SPACE, 0, 4);
        let int_input = mixed.new_varnode(REGISTER_SPACE, 4, 4);
        mixed.mark_input(float_input);
        mixed.mark_input(int_input);
        let float_op = mixed.new_op(op::FLOAT_ADD, seq(0x5000), vec![float_input, float_input]);
        let float_output = mixed.new_varnode(REGISTER_SPACE, 0, 4);
        mixed.op_set_output(float_op, Some(float_output));
        mixed.op_insert_end(float_op, mixed_block);
        let float_read = mixed.new_op(op::RETURN, seq(0x5004), vec![float_output]);
        mixed.op_insert_end(float_read, mixed_block);
        let int_op = mixed.new_op(op::INT_ADD, seq(0x5008), vec![int_input, int_input]);
        let int_output = mixed.new_varnode(REGISTER_SPACE, 4, 4);
        mixed.op_set_output(int_op, Some(int_output));
        mixed.op_insert_end(int_op, mixed_block);
        let int_read = mixed.new_op(op::RETURN, seq(0x500c), vec![int_output]);
        mixed.op_insert_end(int_read, mixed_block);
        let mixed_dominance = compute_dominance(&mixed);
        let mixed_covers: Vec<Cover> = (0..mixed.varnode_count())
            .map(|index| Cover::of(&mixed, VarnodeId(index as u32), &mixed_dominance))
            .collect();
        let mixed_types = infer_types(&mixed, &BTreeMap::new());
        let mut mixed_variables = Variables::new(mixed.varnode_count());
        merge_type(&mixed, &mut mixed_variables, &mixed_types, &mixed_covers);
        assert!(!mixed_variables.same(float_output, int_output));
    }

    #[test]
    fn values_allocated_after_the_snapshot_are_singletons() {
        let variables = Variables::new(1);
        assert_eq!(variables.high_of(VarnodeId(7)), 7);
        assert!(!variables.same(VarnodeId(0), VarnodeId(7)));
        assert!(variables.same(VarnodeId(7), VarnodeId(7)));
    }

    #[test]
    fn action_wrappers_report_no_fake_graph_change() {
        let mut data = Funcdata::default();
        assert_eq!(ActionMergeCopy.apply(&mut data), 0);
        assert_eq!(ActionMergeAdjacent.apply(&mut data), 0);
        assert_eq!(ActionMergeType.apply(&mut data), 0);
    }
}
