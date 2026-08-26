//! Conditional-value propagation, conditional execution pruning, call
//! de-indirection, and constant-pointer discovery on the p-code graph.
//!
//! The conditional-value pass follows Ghidra's
//! `ActionConditionalConst::apply`, `ActionConditionalConst::findConstCompare`,
//! and `ActionConditionalConst::propagateConstant` (including the edge-flow
//! invariant implemented by `collectReachable` and `flowToAlternatePath`) in
//! `coreaction.cc`.  The branch proof used here is the same branch/target
//! convention as `ActionDeterminedBranch::apply` in `coreaction.cc`.
//! `ActionConditionalExe::apply` is from `condexe.cc`, while
//! `ActionDeindirect::apply` and `ActionConstantPtr::apply` are from
//! `coreaction.cc`, all at Ghidra commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.
//!
//! Ghidra's constant-pointer action also needs the architecture's inferred
//! pointer spaces, address decoding, and symbol table (`spacebaseConstant`).
//! Those stateful services are not present in [`Funcdata`], so this port keeps
//! the graph-observable part: a constant in a LOAD address slot is reported as
//! a pointer to its literal address by [`constant_pointer_targets`].

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ventris_pcode::op;

use super::action::Action;
use super::heritage::{Dominance, compute_dominance};
use super::{Funcdata, GraphBlockId, OpId, VarnodeId};

/// Return the final live operation in a block.
fn last_live_op(data: &Funcdata, block: GraphBlockId) -> Option<OpId> {
    data.block(block)
        .ops
        .iter()
        .rev()
        .copied()
        .find(|id| data.opcode_of(*id).is_some())
}

/// Return the target and fall-through successors of a CBRANCH.
///
/// The edge order in a graph assembled from a `BTreeSet` is address order, not
/// necessarily p-code's taken/fall-through order.  The CBRANCH's first input
/// is therefore the only reliable way to identify its taken successor.
fn branch_edges(
    data: &Funcdata,
    block: GraphBlockId,
    branch: OpId,
) -> Option<(GraphBlockId, GraphBlockId)> {
    let operation = data.op(branch);
    if operation.opcode != op::CBRANCH {
        return None;
    }
    let target_address = data.varnode(*operation.inputs.first()?).offset;
    let successors = &data.block(block).successors;
    if successors.len() != 2 {
        return None;
    }
    let target = successors
        .iter()
        .copied()
        .find(|successor| data.block_covers(*successor, target_address, 0))?;
    let fallthrough = successors
        .iter()
        .copied()
        .find(|successor| *successor != target)?;
    Some((target, fallthrough))
}

/// Follow a constant-producing expression only when every input is itself a
/// known integer.  This is deliberately a proof, rather than a value guess:
/// unknown registers and unsupported operations return `None`.
fn known_integer_inner(
    data: &Funcdata,
    value: VarnodeId,
    active: &mut BTreeSet<VarnodeId>,
) -> Option<u64> {
    let varnode = data.varnode(value);
    if varnode.flags.constant {
        return Some(varnode.offset);
    }
    if !active.insert(value) {
        return None;
    }
    let result = varnode.def.and_then(|definition| {
        let operation = data.op(definition);
        let mut input = |slot: usize| {
            operation
                .inputs
                .get(slot)
                .copied()
                .and_then(|input| known_integer_inner(data, input, active))
        };
        let mask = |size: u32| {
            let bits = size.saturating_mul(8);
            if bits >= 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            }
        };
        let width = varnode.size;
        match operation.opcode {
            op::COPY | op::CAST => input(0),
            op::INT_ADD => Some(input(0)?.wrapping_add(input(1)?) & mask(width)),
            op::INT_SUB => Some(input(0)?.wrapping_sub(input(1)?) & mask(width)),
            op::INT_MULT => Some(input(0)?.wrapping_mul(input(1)?) & mask(width)),
            op::INT_AND => Some(input(0)? & input(1)?),
            op::INT_OR => Some(input(0)? | input(1)?),
            op::INT_XOR => Some(input(0)? ^ input(1)?),
            op::INT_LEFT => {
                let amount = input(1)?;
                Some(input(0)?.wrapping_shl(amount as u32) & mask(width))
            }
            op::INT_RIGHT => Some(input(0)?.wrapping_shr(input(1)? as u32)),
            op::INT_2COMP => Some(input(0)?.wrapping_neg() & mask(width)),
            _ => None,
        }
    });
    active.remove(&value);
    result
}

fn known_integer(data: &Funcdata, value: VarnodeId) -> Option<u64> {
    known_integer_inner(data, value, &mut BTreeSet::new())
}

/// Prove a boolean value from constants.  A nonzero integer is true, matching
/// the p-code CBRANCH convention.
fn known_boolean(data: &Funcdata, value: VarnodeId) -> Option<bool> {
    if let Some(integer) = known_integer(data, value) {
        return Some(integer != 0);
    }
    let definition = data.varnode(value).def?;
    let operation = data.op(definition);
    match operation.opcode {
        op::BOOL_NEGATE => operation
            .inputs
            .first()
            .copied()
            .and_then(|input| known_boolean(data, input))
            .map(|known| !known),
        op::COPY | op::CAST => operation
            .inputs
            .first()
            .copied()
            .and_then(|input| known_boolean(data, input)),
        op::INT_EQUAL | op::INT_NOTEQUAL => {
            let left = operation
                .inputs
                .first()
                .copied()
                .and_then(|input| known_integer(data, input));
            let right = operation
                .inputs
                .get(1)
                .copied()
                .and_then(|input| known_integer(data, input));
            let (Some(left), Some(right)) = (left, right) else {
                return None;
            };
            Some(if operation.opcode == op::INT_EQUAL {
                left == right
            } else {
                left != right
            })
        }
        _ => None,
    }
}

/// Whether `dominator` dominates `block` in a computed dominator tree.
fn block_dominates(dominance: &Dominance, dominator: GraphBlockId, block: GraphBlockId) -> bool {
    let mut current = block;
    let mut seen = BTreeSet::new();
    loop {
        if current == dominator {
            return true;
        }
        if !seen.insert(current) {
            return false;
        }
        let Some(parent) = dominance.immediate.get(&current).copied().flatten() else {
            return false;
        };
        if parent == current {
            return false;
        }
        current = parent;
    }
}

/// Test edge dominance, not just target-block dominance.
///
/// A target block may have another incoming path.  In that case checking only
/// that the target dominates a read is unsound: the read can arrive through
/// the other predecessor with a different value.  The second reachability test
/// removes the candidate edge conceptually and proves that no such path
/// remains.  The dominator check is kept as the cheap first filter and mirrors
/// Ghidra's `FlowBlock::dominates` guard in `propagateConstant`.
fn edge_dominates_block(
    data: &Funcdata,
    dominance: &Dominance,
    source: GraphBlockId,
    target: GraphBlockId,
    read_block: GraphBlockId,
) -> bool {
    if !block_dominates(dominance, target, read_block) {
        return false;
    }
    let Some(&entry) = dominance.reverse_postorder.first() else {
        return false;
    };
    if entry == read_block {
        return false;
    }
    let mut seen = BTreeSet::from([entry]);
    let mut pending = VecDeque::from([entry]);
    while let Some(current) = pending.pop_front() {
        if current == read_block {
            return false;
        }
        for successor in data.block(current).successors.iter().copied() {
            if current == source && successor == target {
                continue;
            }
            if seen.insert(successor) {
                pending.push_back(successor);
            }
        }
    }
    true
}

/// Replace direct reads of `value` only in blocks proven to be below one edge.
fn replace_dominated_reads(
    data: &mut Funcdata,
    dominance: &Dominance,
    source: GraphBlockId,
    target: GraphBlockId,
    value: VarnodeId,
    replacement: VarnodeId,
) -> usize {
    let readers: Vec<OpId> = data.varnode(value).descendants.iter().copied().collect();
    let mut changed = 0;
    for reader in readers {
        let Some(read_block) = data.op(reader).parent else {
            continue;
        };
        if data.opcode_of(reader) == Some(op::INDIRECT)
            || !edge_dominates_block(data, dominance, source, target, read_block)
        {
            continue;
        }
        let slots: Vec<usize> = data
            .op(reader)
            .inputs
            .iter()
            .enumerate()
            .filter_map(|(slot, input)| (*input == value).then_some(slot))
            .collect();
        for slot in slots.iter().copied() {
            data.op_set_input(reader, replacement, slot);
        }
        if !slots.is_empty() {
            changed += 1;
        }
    }
    changed
}

/// Find the nonconstant side and the edge on which it equals the constant.
fn constant_compare(data: &Funcdata, condition: VarnodeId) -> Option<(VarnodeId, VarnodeId, bool)> {
    let mut condition = condition;
    let mut flip = false;
    let mut definition = data.varnode(condition).def?;
    if data.op(definition).opcode == op::BOOL_NEGATE {
        condition = data.op(definition).inputs.first().copied()?;
        flip = true;
        definition = data.varnode(condition).def?;
    }
    let operation = data.op(definition);
    let constant_edge = match operation.opcode {
        op::INT_EQUAL => true,
        op::INT_NOTEQUAL => false,
        _ => return None,
    };
    let left = operation.inputs.first().copied()?;
    let right = operation.inputs.get(1).copied()?;
    let (value, constant) = if data.varnode(left).flags.constant {
        (right, left)
    } else if data.varnode(right).flags.constant {
        (left, right)
    } else {
        return None;
    };
    if data.varnode(value).flags.constant {
        return None;
    }
    Some((value, constant, constant_edge ^ flip))
}

/// Conditional propagation from `ActionConditionalConst`.
///
/// The action intentionally edits only reads whose *edge* dominates them.  A
/// block-level target check alone would incorrectly rewrite a join that can be
/// entered from both sides of the branch.
pub struct ActionConditionalConst;

impl Action for ActionConditionalConst {
    fn name(&self) -> &'static str {
        "conditional-constant"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let dominance = compute_dominance(data);
        let branches: Vec<(GraphBlockId, OpId, GraphBlockId, GraphBlockId)> = data
            .blocks()
            .filter_map(|(block, _)| {
                let branch = last_live_op(data, block)?;
                let (target, fallthrough) = branch_edges(data, block, branch)?;
                Some((block, branch, target, fallthrough))
            })
            .collect();
        let mut changed = 0;
        for (source, branch, target, fallthrough) in branches {
            let Some(condition) = data.op(branch).inputs.get(1).copied() else {
                continue;
            };
            let comparison = constant_compare(data, condition);

            // A shared boolean itself is known on each outgoing edge.  This is
            // the direct `bool=0`/`bool=1` part of Ghidra's apply method; a
            // condition used only by this CBRANCH has nothing to rewrite.
            if data.varnode(condition).descendants.len() > 1 {
                let bool_size = data.varnode(condition).size.max(1);
                for (edge, value) in [(fallthrough, 0u64), (target, 1u64)] {
                    let constant = data.new_constant(value, bool_size);
                    changed += replace_dominated_reads(
                        data, &dominance, source, edge, condition, constant,
                    );
                }
            }

            let Some((value, constant, equality_edge_is_true)) = comparison else {
                continue;
            };
            let edge = if equality_edge_is_true {
                target
            } else {
                fallthrough
            };
            let replacement = if data.varnode(constant).size == data.varnode(value).size {
                constant
            } else {
                data.new_constant(data.varnode(constant).offset, data.varnode(value).size)
            };
            changed += replace_dominated_reads(data, &dominance, source, edge, value, replacement);
        }
        changed
    }
}

/// Remove an edge that a constant branch condition proves impossible.
///
/// This is the graph-level, constant-proof part of Ghidra's
/// `ActionConditionalExe::apply`.  The larger upstream action also rewires
/// removable computations in specially shaped conditional-execution regions;
/// that transformation needs block split/merge APIs absent from this graph.
pub struct ActionConditionalExe;

impl Action for ActionConditionalExe {
    fn name(&self) -> &'static str {
        "conditional-execution"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let branches: Vec<(GraphBlockId, OpId, GraphBlockId, GraphBlockId)> = data
            .blocks()
            .filter_map(|(block, _)| {
                let branch = last_live_op(data, block)?;
                let (target, fallthrough) = branch_edges(data, block, branch)?;
                Some((block, branch, target, fallthrough))
            })
            .collect();
        let mut changed = 0;
        for (source, branch, target, fallthrough) in branches {
            let Some(condition) = data.op(branch).inputs.get(1).copied() else {
                continue;
            };
            let Some(taken) = known_boolean(data, condition) else {
                continue;
            };
            let impossible = if taken { fallthrough } else { target };
            if data.remove_edge(source, impossible) {
                changed += 1;
            }
        }
        changed
    }
}

/// Turn a CALLIND with a constant (possibly COPY-wrapped) target into CALL.
pub struct ActionDeindirect;

impl Action for ActionDeindirect {
    fn name(&self) -> &'static str {
        "deindirect"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let calls: Vec<OpId> = data
            .live_ops()
            .filter_map(|(id, operation)| (operation.opcode == op::CALLIND).then_some(id))
            .collect();
        let mut changed = 0;
        for call in calls {
            let Some(mut target) = data.op(call).inputs.first().copied() else {
                continue;
            };
            let mut seen = BTreeSet::new();
            while !data.varnode(target).flags.constant {
                let Some(definition) = data.varnode(target).def else {
                    break;
                };
                if data.op(definition).opcode != op::COPY || !seen.insert(target) {
                    break;
                }
                let Some(input) = data.op(definition).inputs.first().copied() else {
                    break;
                };
                target = input;
            }
            if data.varnode(target).flags.constant {
                data.op_set_opcode(call, op::CALL);
                changed += 1;
            }
        }
        changed
    }
}

/// Recover literal addresses used as LOAD pointers.
///
/// The key is the address-input VarnodeId, not the loaded result: that is the
/// value whose renderer spelling changes from an integer literal to a global
/// address.  A register-addressed LOAD has no constant pointer to recover.
pub fn constant_pointer_targets(data: &Funcdata) -> BTreeMap<VarnodeId, u64> {
    let mut targets = BTreeMap::new();
    for (_, operation) in data.live_ops() {
        if operation.opcode != op::LOAD {
            continue;
        }
        let Some(address) = operation.inputs.get(1).copied() else {
            continue;
        };
        if data.varnode(address).flags.constant {
            targets.insert(address, data.varnode(address).offset);
        }
    }
    targets
}

/// Address-only projection of Ghidra's `ActionConstantPtr`.
pub struct ActionConstantPtr;

impl Action for ActionConstantPtr {
    fn name(&self) -> &'static str {
        "constant-pointer"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        constant_pointer_targets(data).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{RAM_SPACE, REGISTER_SPACE};

    fn seq(address: u64, order: u32) -> super::super::SeqNum {
        super::super::SeqNum { address, order }
    }

    #[test]
    fn conditional_equal_reaches_only_the_dominated_edge() {
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

        let value = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.mark_input(value);
        let constant = data.new_constant(7, 4);
        let comparison = data.new_op(op::INT_EQUAL, seq(0x1000, 0), vec![value, constant]);
        let condition = data.new_unique(1);
        data.op_set_output(comparison, Some(condition));
        data.op_insert_end(comparison, entry);
        let destination = data.new_varnode(RAM_SPACE, 0x1010, 4);
        let branch = data.new_op(op::CBRANCH, seq(0x1000, 1), vec![destination, condition]);
        data.op_insert_end(branch, entry);

        let left_read = data.new_op(op::RETURN, seq(0x1010, 0), vec![value]);
        data.op_insert_end(left_read, left);
        let right_read = data.new_op(op::RETURN, seq(0x1020, 0), vec![value]);
        data.op_insert_end(right_read, right);
        let join_read = data.new_op(op::RETURN, seq(0x1030, 0), vec![value]);
        data.op_insert_end(join_read, join);

        assert_eq!(ActionConditionalConst.apply(&mut data), 1);
        let rewritten = data.op(left_read).inputs[0];
        assert!(data.varnode(rewritten).flags.constant);
        assert_eq!(data.varnode(rewritten).offset, 7);
        assert_eq!(data.op(right_read).inputs[0], value);
        assert_eq!(data.op(join_read).inputs[0], value);
    }

    #[test]
    fn conditional_notequal_places_equality_on_the_false_edge() {
        let mut data = Funcdata::default();
        data.entry = 0x2000;
        let entry = data.new_block(0x2000);
        let target = data.new_block(0x2010);
        let fallthrough = data.new_block(0x2020);
        data.add_edge(entry, target);
        data.add_edge(entry, fallthrough);
        let value = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(value);
        let constant = data.new_constant(3, 4);
        let comparison = data.new_op(op::INT_NOTEQUAL, seq(0x2000, 0), vec![value, constant]);
        let condition = data.new_unique(1);
        data.op_set_output(comparison, Some(condition));
        data.op_insert_end(comparison, entry);
        let target_address = data.new_varnode(RAM_SPACE, 0x2010, 4);
        let branch = data.new_op(op::CBRANCH, seq(0x2000, 1), vec![target_address, condition]);
        data.op_insert_end(branch, entry);
        let false_read = data.new_op(op::RETURN, seq(0x2020, 0), vec![value]);
        data.op_insert_end(false_read, fallthrough);

        assert_eq!(ActionConditionalConst.apply(&mut data), 1);
        let replacement = data.op(false_read).inputs[0];
        assert!(data.varnode(replacement).flags.constant);
        assert_eq!(data.varnode(replacement).offset, 3);
    }

    #[test]
    fn conditional_constant_declines_when_comparison_is_unknown() {
        let mut data = Funcdata::default();
        data.entry = 0x3000;
        let entry = data.new_block(0x3000);
        let target = data.new_block(0x3010);
        let fallthrough = data.new_block(0x3020);
        data.add_edge(entry, target);
        data.add_edge(entry, fallthrough);
        let value = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(value);
        let other = data.new_varnode(REGISTER_SPACE, 4, 4);
        data.mark_input(other);
        let comparison = data.new_op(op::INT_EQUAL, seq(0x3000, 0), vec![value, other]);
        let condition = data.new_unique(1);
        data.op_set_output(comparison, Some(condition));
        data.op_insert_end(comparison, entry);
        let target_address = data.new_varnode(RAM_SPACE, 0x3010, 4);
        let branch = data.new_op(op::CBRANCH, seq(0x3000, 1), vec![target_address, condition]);
        data.op_insert_end(branch, entry);
        let read = data.new_op(op::RETURN, seq(0x3010, 0), vec![value]);
        data.op_insert_end(read, target);

        assert_eq!(ActionConditionalConst.apply(&mut data), 0);
        assert_eq!(data.op(read).inputs[0], value);
    }

    #[test]
    fn conditional_execution_removes_only_a_provably_false_edge() {
        let false_condition;
        let (mut data, entry, target, fallthrough, branch) = {
            let mut data = Funcdata::default();
            data.entry = 0x4000;
            let entry = data.new_block(0x4000);
            let target = data.new_block(0x4010);
            let fallthrough = data.new_block(0x4020);
            data.add_edge(entry, target);
            data.add_edge(entry, fallthrough);
            let left = data.new_constant(4, 4);
            let right = data.new_constant(9, 4);
            let comparison = data.new_op(op::INT_EQUAL, seq(0x4000, 0), vec![left, right]);
            let condition = data.new_unique(1);
            data.op_set_output(comparison, Some(condition));
            data.op_insert_end(comparison, entry);
            let destination = data.new_varnode(RAM_SPACE, 0x4010, 4);
            let branch = data.new_op(op::CBRANCH, seq(0x4000, 1), vec![destination, condition]);
            data.op_insert_end(branch, entry);
            (data, entry, target, fallthrough, branch)
        };
        false_condition = data.op(branch).inputs[1];
        assert_eq!(ActionConditionalExe.apply(&mut data), 1);
        assert!(!data.block(entry).successors.contains(&target));
        assert!(data.block(entry).successors.contains(&fallthrough));
        assert_eq!(data.varnode(false_condition).flags.constant, false);
    }

    #[test]
    fn conditional_execution_declines_unknown_conditions() {
        let mut condition_data = Funcdata::default();
        condition_data.entry = 0x5000;
        let entry = condition_data.new_block(0x5000);
        let target = condition_data.new_block(0x5010);
        let fallthrough = condition_data.new_block(0x5020);
        condition_data.add_edge(entry, target);
        condition_data.add_edge(entry, fallthrough);
        let condition = condition_data.new_unique(1);
        condition_data.mark_input(condition);
        let destination = condition_data.new_varnode(RAM_SPACE, 0x5010, 4);
        let branch =
            condition_data.new_op(op::CBRANCH, seq(0x5000, 0), vec![destination, condition]);
        condition_data.op_insert_end(branch, entry);

        assert_eq!(ActionConditionalExe.apply(&mut condition_data), 0);
        assert_eq!(condition_data.block(entry).successors.len(), 2);
    }

    #[test]
    fn deindirect_retypes_constant_target_and_declines_register_target() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x6000);
        let target = data.new_constant(0x7000, 8);
        let call = data.new_op(op::CALLIND, seq(0x6000, 0), vec![target]);
        data.op_insert_end(call, block);
        assert_eq!(ActionDeindirect.apply(&mut data), 1);
        assert_eq!(data.op(call).opcode, op::CALL);

        let register = data.new_unique(8);
        let indirect = data.new_op(op::CALLIND, seq(0x6004, 0), vec![register]);
        data.op_insert_end(indirect, block);
        assert_eq!(ActionDeindirect.apply(&mut data), 0);
        assert_eq!(data.op(indirect).opcode, op::CALLIND);
    }

    #[test]
    fn constant_pointer_targets_report_load_constants_not_registers() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x7000);
        let space = data.new_constant(RAM_SPACE as u64, 4);
        let address = data.new_constant(0x9000, 8);
        let load = data.new_op(op::LOAD, seq(0x7000, 0), vec![space, address]);
        let output = data.new_unique(4);
        data.op_set_output(load, Some(output));
        data.op_insert_end(load, block);
        let register_address = data.new_varnode(REGISTER_SPACE, 0x20, 8);
        data.mark_input(register_address);
        let register_load = data.new_op(op::LOAD, seq(0x7004, 0), vec![space, register_address]);
        let register_output = data.new_unique(4);
        data.op_set_output(register_load, Some(register_output));
        data.op_insert_end(register_load, block);

        let targets = constant_pointer_targets(&data);
        assert_eq!(targets.get(&address), Some(&0x9000));
        assert_eq!(targets.len(), 1);
        assert_eq!(ActionConstantPtr.apply(&mut data), 1);
    }

    #[test]
    fn constant_pointer_action_declines_register_address() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x7100);
        let space = data.new_constant(RAM_SPACE as u64, 4);
        let register_address = data.new_varnode(REGISTER_SPACE, 0x28, 8);
        data.mark_input(register_address);
        let load = data.new_op(op::LOAD, seq(0x7100, 0), vec![space, register_address]);
        let output = data.new_unique(4);
        data.op_set_output(load, Some(output));
        data.op_insert_end(load, block);

        assert_eq!(constant_pointer_targets(&data), BTreeMap::new());
        assert_eq!(ActionConstantPtr.apply(&mut data), 0);
    }
}
