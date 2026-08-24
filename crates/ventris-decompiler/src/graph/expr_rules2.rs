//! A second batch of expression rewrites from Ghidra 12.1.3's `ruleaction.cc`.
//!
//! Source authority for this module is the pinned Ghidra tree at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.  The C++ symbols used here are
//! `RuleCollectTerms::{getOpList,applyOp}`, `RulePullsubMulti::{getOpList,applyOp}`,
//! `RuleTermOrder::{getOpList,applyOp}`, `RuleSelectCse::{getOpList,applyOp}`,
//! `RuleXorSwap::{getOpList,applyOp}`, `RuleOrPredicate::{getOpList,applyOp}`,
//! `RuleBooleanNegate::{getOpList,applyOp}`, `RuleDoubleSub::{getOpList,applyOp}`,
//! `RuleHumptyDumpty::{getOpList,applyOp}`, `RuleDumptyHump::{getOpList,applyOp}`,
//! `RuleHumptyOr::{getOpList,applyOp}`, `RuleNegateIdentity::{getOpList,applyOp}`,
//! `RuleSubNormal::{getOpList,applyOp}`, `RulePositiveDiv::{getOpList,applyOp}`,
//! `RuleDivTermAdd::{getOpList,applyOp}`, `RuleSignForm::{getOpList,applyOp}`,
//! `RuleSignDiv2::{getOpList,applyOp}`, `RuleSignNearMult::{getOpList,applyOp}`,
//! `RuleModOpt::{getOpList,applyOp}`, and `RuleFloatCast::{getOpList,applyOp}`.
//!
//! The requested rules below are intentionally not half-implemented where the
//! graph has no faithful input for their preconditions:
//!
//! * `RulePullsubIndirect` needs IOP-space operation references, indirect
//!   creation, address-force flags, and the byte-consumption machinery used by
//!   `RulePullsubMulti`.
//! * `RulePushPtr`, `RulePtrArith`, `RuleStructOffset0`, `RulePtraddUndo`, and
//!   `RulePtrsubUndo` need `TypeFactory`/`Datatype` pointer, struct, and array
//!   metadata plus type-recovery state and stop-type-propagation controls.
//! * `RuleSegment` needs the architecture's `SegmentOp` registry and its
//!   emulator; the graph only stores the raw SEGMENTOP operands.
//! * `RuleDoubleIn` needs precise-high/precise-low flags and `SplitVarnode`'s
//!   double-precision whole-value recovery.
//! * `RuleSplitFlow` needs the `SplitFlow` worklist and cross-block subvariable
//!   trace, which cannot be represented by a local graph edit.
//! * `RulePiecePathology` needs `FuncCallSpecs`/`FuncProto` byte-consumption
//!   state and call-output locking.
//! * `RuleCondNegate` needs the encoded CBRANCH boolean-flip bit and
//!   `opFlipCondition`.
//! * `RuleSwitchSingle` needs the jump-table registry, labelled table entries,
//!   and CodeRef construction.
//! * `RuleIgnoreNan` needs the architecture `nan_ignore_all` setting and the
//!   floating-point comparison/type classification used by `checkBackForCompare`.
//! * `RuleFuncPtrEncoding` needs the architecture's `funcptr_align` setting.
//!
//! A few implemented rules are conservative because the graph deliberately
//! lacks a Ghidra side table.  They decline more often (a stronger precondition,
//! never an eager rewrite): `RuleCollectTerms` accepts the direct two-multiply
//! form rather than the full `TermOrder` tree; `RulePullsubMulti` accepts one
//! partial SUBPIECE use and rejects loop/consume cases; `RuleBooleanNegate`
//! proves booleanness from one-byte boolean-producing operations because the
//! graph has no type lock; and `RuleDivTermAdd` limits its constant arithmetic
//! to the graph's 64-bit constant representation.
//!
//! Four preconditions are necessarily weaker because the graph omits metadata
//! that Ghidra tests: `RulePullsubMulti` and `RuleSubNormal` cannot inspect
//! precise-high/precise-low flags, `RuleOrPredicate` cannot inspect the
//! CBRANCH boolean-flip bit, and `RuleSelectCse` cannot inspect Ghidra's CSE
//! hash/side tables.  Those forms may fire where the C++ rule declines; the
//! implementations otherwise use structural guards and do not pretend the
//! metadata exists.
//!

use super::action::Rule;
use super::heritage::compute_dominance;
use super::{Funcdata, GraphBlockId, OpId, SeqNum, VarnodeId};
use ventris_pcode::op;

fn mask(size: u32) -> u64 {
    let bits = size.saturating_mul(8);
    if bits == 0 {
        0
    } else if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn is_constant(data: &Funcdata, value: VarnodeId) -> bool {
    data.varnode(value).flags.constant
}

/// Exact `Varnode::isFree`: no write and no input flag.
fn is_free(data: &Funcdata, value: VarnodeId) -> bool {
    let node = data.varnode(value);
    !(node.flags.written || node.flags.input)
}

/// Exact graph contract for `Varnode::isHeritageKnown` used by this port.
fn heritage_known(data: &Funcdata, value: VarnodeId) -> bool {
    let node = data.varnode(value);
    node.flags.constant || node.flags.input || node.def.is_some()
}
/// Detect a natural-loop back edge without relying on block-address ordering.
/// `BlockBasic::hasLoopIn` is represented by a predecessor dominated by the
/// candidate header; this is the graph fact available to `RulePullsubMulti`.
fn has_loop_in(data: &Funcdata, block: GraphBlockId) -> bool {
    let dominance = compute_dominance(data);
    let max_steps = data.blocks().count();
    for predecessor in data.block(block).predecessors.iter().copied() {
        let mut current = predecessor;
        for _ in 0..=max_steps {
            if current == block {
                return true;
            }
            let Some(next) = dominance.immediate.get(&current).copied().flatten() else {
                break;
            };
            if next == current {
                break;
            }
            current = next;
        }
    }
    false
}
fn block_dominates(data: &Funcdata, dominator: GraphBlockId, block: GraphBlockId) -> bool {
    let dominance = compute_dominance(data);
    let max_steps = data.blocks().count();
    let mut current = block;
    for _ in 0..=max_steps {
        if current == dominator {
            return true;
        }
        let Some(next) = dominance.immediate.get(&current).copied().flatten() else {
            break;
        };
        if next == current {
            break;
        }
        current = next;
    }
    false
}

fn def(data: &Funcdata, value: VarnodeId) -> Option<OpId> {
    data.varnode(value).def
}

fn input(data: &Funcdata, id: OpId, slot: usize) -> Option<VarnodeId> {
    data.op(id).inputs.get(slot).copied()
}

fn output(data: &Funcdata, id: OpId) -> Option<VarnodeId> {
    data.op(id).output
}

fn seq(data: &Funcdata, id: OpId) -> SeqNum {
    data.op(id).seq
}

fn new_op_before(
    data: &mut Funcdata,
    anchor: OpId,
    opcode: i32,
    inputs: Vec<VarnodeId>,
    output_size: u32,
) -> (OpId, VarnodeId) {
    let id = data.new_op(opcode, seq(data, anchor), inputs);
    let out = data.new_unique(output_size);
    data.op_set_output(id, Some(out));
    data.op_insert_before(id, anchor);
    (id, out)
}

fn is_zero_copy(data: &Funcdata, value: VarnodeId) -> bool {
    let Some(copy) = def(data, value) else {
        return false;
    };
    if data.opcode_of(copy) != Some(op::COPY) {
        return false;
    }
    let Some(source) = input(data, copy, 0) else {
        return false;
    };
    is_constant(data, source) && data.varnode(source).offset == 0
}

fn boolean_value(data: &Funcdata, value: VarnodeId) -> bool {
    let node = data.varnode(value);
    if node.size != 1 {
        return false;
    }
    if node.flags.constant {
        return node.offset <= 1;
    }
    let Some(defop) = node.def else { return false };
    matches!(
        data.opcode_of(defop),
        Some(
            op::INT_EQUAL
                | op::INT_NOTEQUAL
                | op::INT_LESS
                | op::INT_LESSEQUAL
                | op::INT_SLESS
                | op::INT_SLESSEQUAL
                | op::BOOL_AND
                | op::BOOL_OR
                | op::BOOL_XOR
                | op::BOOL_NEGATE
        )
    )
}

// -------------------------------------------------------------------------
// Additive-term collection: normalize the direct V*c + V*d machine idiom.

pub struct RuleCollectTerms;

impl Rule for RuleCollectTerms {
    fn name(&self) -> &'static str {
        "collectterms"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_ADD]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        if data.opcode_of(id) != Some(op::INT_ADD) {
            return 0;
        }
        let Some(out) = output(data, id) else {
            return 0;
        };
        if data.lone_descend(out).and_then(|next| data.opcode_of(next)) == Some(op::INT_ADD) {
            return 0;
        }
        let (Some(left), Some(right)) = (input(data, id, 0), input(data, id, 1)) else {
            return 0;
        };
        let (Some(left_def), Some(right_def)) = (def(data, left), def(data, right)) else {
            return 0;
        };
        if data.opcode_of(left_def) != Some(op::INT_MULT)
            || data.opcode_of(right_def) != Some(op::INT_MULT)
        {
            return 0;
        }
        let (Some(base_left), Some(coef_left), Some(base_right), Some(coef_right)) = (
            input(data, left_def, 0),
            input(data, left_def, 1),
            input(data, right_def, 0),
            input(data, right_def, 1),
        ) else {
            return 0;
        };
        if !is_constant(data, coef_left) || !is_constant(data, coef_right) {
            return 0;
        }
        if base_left != base_right {
            return 0;
        }
        let size = data.varnode(base_left).size;
        let coefficient = data
            .varnode(coef_left)
            .offset
            .wrapping_add(data.varnode(coef_right).offset)
            & mask(size);
        let zero_coefficient = data.new_constant(0, size);
        let combined_coefficient = data.new_constant(coefficient, size);
        data.op_set_input(left_def, zero_coefficient, 1);
        data.op_set_input(right_def, combined_coefficient, 1);
        1
    }
}

// -------------------------------------------------------------------------
// SSA truncation: pull one partial SUBPIECE through a MULTIEQUAL.

pub struct RulePullsubMulti;

impl Rule for RulePullsubMulti {
    fn name(&self) -> &'static str {
        "pullsubmulti"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::SUBPIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        if data.opcode_of(id) != Some(op::SUBPIECE) {
            return 0;
        }
        let (Some(vn), Some(offset_vn), Some(out)) =
            (input(data, id, 0), input(data, id, 1), output(data, id))
        else {
            return 0;
        };
        let Some(offset) = is_constant(data, offset_vn).then(|| data.varnode(offset_vn).offset)
        else {
            return 0;
        };
        let Some(phi) = def(data, vn) else { return 0 };
        if data.opcode_of(phi) != Some(op::MULTIEQUAL) || data.op(phi).inputs.len() < 2 {
            return 0;
        }
        if data.lone_descend(vn) != Some(id) {
            return 0;
        }
        let Some(parent) = data.op(phi).parent else {
            return 0;
        };
        // Do not split a loop-carried phi: Ghidra's `hasLoopIn` is the
        // natural-loop back-edge fact, recovered here from dominance.
        if has_loop_in(data, parent) {
            return 0;
        }
        let out_size = data.varnode(out).size;
        let in_size = data.varnode(vn).size;
        if offset.saturating_add(u64::from(out_size)) > u64::from(in_size)
            || out_size == 0
            || !(out_size == 1 || out_size == 2 || out_size == 4 || out_size == 8 || out_size >= 8)
            || out_size >= in_size
        {
            return 0;
        }
        let old_inputs = data.op(phi).inputs.clone();
        let selected_end = offset.saturating_add(u64::from(out_size));
        if old_inputs.iter().any(|value| {
            data.varnode(*value).size < selected_end as u32 || !heritage_known(data, *value)
        }) {
            return 0;
        }
        // Ghidra's `minMaxUse`/consume check protects bytes still observed
        // by immediate descendants.  The graph has no consume mask, so reject
        for value in &old_inputs {
            for descendant in data.varnode(*value).descendants.iter().copied() {
                if descendant == phi {
                    continue;
                }
                let Some(desc_offset) = input(data, descendant, 1)
                    .filter(|offset_vn| is_constant(data, *offset_vn))
                    .map(|offset_vn| data.varnode(offset_vn).offset)
                else {
                    return 0;
                };
                let Some(desc_out) = output(data, descendant) else {
                    return 0;
                };
                let desc_end = desc_offset.saturating_add(u64::from(data.varnode(desc_out).size));
                if data.opcode_of(descendant) != Some(op::SUBPIECE)
                    || desc_offset < offset
                    || desc_end > selected_end
                {
                    return 0;
                }
            }
        }
        let new_phi = data.new_op(op::MULTIEQUAL, seq(data, phi), Vec::new());
        let new_out = data.new_unique(out_size);
        data.op_set_output(new_phi, Some(new_out));
        data.op_insert_front(new_phi, parent);
        for (slot, value) in old_inputs.iter().copied().enumerate() {
            let sub = data.new_op(op::SUBPIECE, seq(data, phi), vec![value, offset_vn]);
            let sub_out = data.new_unique(out_size);
            data.op_set_output(sub, Some(sub_out));
            data.op_insert_before(sub, new_phi);
            data.op_set_input(new_phi, sub_out, slot);
        }
        data.op_set_opcode(id, op::COPY);
        data.op_set_inputs(id, vec![new_out]);
        data.op_destroy(phi);
        1
    }
}

// -------------------------------------------------------------------------
// Commutative ordering and restricted common-subexpression elimination.

pub struct RuleTermOrder;

impl Rule for RuleTermOrder {
    fn name(&self) -> &'static str {
        "termorder"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![
            op::INT_EQUAL,
            op::INT_NOTEQUAL,
            op::INT_ADD,
            op::INT_CARRY,
            op::INT_SCARRY,
            op::INT_XOR,
            op::INT_AND,
            op::INT_OR,
            op::INT_MULT,
            op::BOOL_XOR,
            op::BOOL_AND,
            op::BOOL_OR,
            op::FLOAT_EQUAL,
            op::FLOAT_NOTEQUAL,
            op::FLOAT_ADD,
            op::FLOAT_MULT,
        ]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let (Some(left), Some(right)) = (input(data, id, 0), input(data, id, 1)) else {
            return 0;
        };
        if is_constant(data, left) && !is_constant(data, right) {
            data.op_set_inputs(id, vec![right, left]);
            1
        } else {
            0
        }
    }
}

pub struct RuleSelectCse;

impl Rule for RuleSelectCse {
    fn name(&self) -> &'static str {
        "selectcse"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::SUBPIECE, op::INT_SRIGHT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(opcode) = data.opcode_of(id) else {
            return 0;
        };
        if opcode != op::SUBPIECE && opcode != op::INT_SRIGHT {
            return 0;
        }
        let (Some(source), Some(old_out)) = (input(data, id, 0), output(data, id)) else {
            return 0;
        };
        let current_seq = seq(data, id);
        let current_parent = data.op(id).parent;
        let readers: Vec<OpId> = data.varnode(source).descendants.iter().copied().collect();
        let Some(previous) = readers.into_iter().find(|candidate| {
            *candidate != id
                && data.opcode_of(*candidate) == Some(opcode)
                && output(data, *candidate).is_some()
                && seq(data, *candidate) < current_seq
                && data.op(*candidate).inputs == data.op(id).inputs
                && match (data.op(*candidate).parent, current_parent) {
                    (Some(candidate_parent), Some(current_parent)) => {
                        block_dominates(data, candidate_parent, current_parent)
                    }
                    _ => false,
                }
        }) else {
            return 0;
        };
        let Some(new_out) = output(data, previous) else {
            return 0;
        };
        data.total_replace(old_out, new_out);
        data.op_destroy(id);
        1
    }
}

// -------------------------------------------------------------------------
// XOR cancellation and conditional predicate folding.

pub struct RuleXorSwap;

impl Rule for RuleXorSwap {
    fn name(&self) -> &'static str {
        "xorswap"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_XOR]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        for slot in 0..2 {
            let Some(candidate) = input(data, id, slot) else {
                continue;
            };
            let Some(inner) = def(data, candidate) else {
                continue;
            };
            if data.opcode_of(inner) != Some(op::INT_XOR) {
                continue;
            }
            let Some(other) = input(data, id, 1 - slot) else {
                continue;
            };
            let (Some(a), Some(b)) = (input(data, inner, 0), input(data, inner, 1)) else {
                continue;
            };
            if other == a && !is_free(data, b) {
                data.op_set_opcode(id, op::COPY);
                data.op_set_inputs(id, vec![b]);
                return 1;
            }
            if other == b && !is_free(data, a) {
                data.op_set_opcode(id, op::COPY);
                data.op_set_inputs(id, vec![a]);
                return 1;
            }
        }
        0
    }
}

#[derive(Copy, Clone)]
struct PredicateShape {
    multi: OpId,
    zero_slot: usize,
    zero_path_true: bool,
}

fn discover_predicate(data: &Funcdata, value: VarnodeId) -> Option<PredicateShape> {
    let multi = def(data, value)?;
    if data.opcode_of(multi) != Some(op::MULTIEQUAL) || data.op(multi).inputs.len() != 2 {
        return None;
    }
    let mut zero_slot = None;
    for slot in 0..2 {
        let input = data.op(multi).inputs[slot];
        if is_zero_copy(data, input) {
            zero_slot = Some(slot);
            break;
        }
    }
    let zero_slot = zero_slot?;
    let other = data.op(multi).inputs[1 - zero_slot];
    if is_free(data, other) {
        return None;
    }
    let parent = data.op(multi).parent?;
    let zero_block = *data.block(parent).predecessors.get(zero_slot)?;
    let other_block = *data.block(parent).predecessors.get(1 - zero_slot)?;
    let (cond_block, zero_path_true) = if data.block(zero_block).successors.len() == 1 {
        if data.block(zero_block).predecessors.len() != 1 {
            return None;
        }
        let cond = data.block(zero_block).predecessors[0];
        if data.block(cond).successors.len() != 2 {
            return None;
        }
        if data.block(other_block).successors.len() == 1 {
            if data.block(other_block).predecessors != vec![cond] {
                return None;
            }
        } else if data.block(other_block).successors.len() != 2 || other_block != cond {
            return None;
        }
        (cond, data.block(cond).successors[0] == zero_block)
    } else if data.block(zero_block).successors.len() == 2 {
        if data.block(other_block).successors.len() != 2 || other_block != zero_block {
            return None;
        }
        (zero_block, true)
    } else {
        return None;
    };
    let cbranch = *data.block(cond_block).ops.last()?;
    if data.opcode_of(cbranch) != Some(op::CBRANCH) {
        return None;
    }
    let condition = input(data, cbranch, 1)?;
    let compare = def(data, condition)?;
    let compare_code = data.opcode_of(compare)?;
    if compare_code != op::INT_EQUAL && compare_code != op::INT_NOTEQUAL {
        return None;
    }
    let (left, right) = (input(data, compare, 0)?, input(data, compare, 1)?);
    let zero = if left == other {
        right
    } else if right == other {
        left
    } else {
        return None;
    };
    if !is_constant(data, zero) || data.varnode(zero).offset != 0 {
        return None;
    }
    let zero_path_true = if compare_code == op::INT_NOTEQUAL {
        !zero_path_true
    } else {
        zero_path_true
    };
    Some(PredicateShape {
        multi,
        zero_slot,
        zero_path_true,
    })
}

pub struct RuleOrPredicate;

impl Rule for RuleOrPredicate {
    fn name(&self) -> &'static str {
        "orpredicate"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_OR, op::INT_XOR]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let (Some(left), Some(right)) = (input(data, id, 0), input(data, id, 1)) else {
            return 0;
        };
        let left_shape = discover_predicate(data, left);
        let right_shape = discover_predicate(data, right);
        let (shape, value) = match (left_shape, right_shape) {
            (Some(shape), None) => (shape, right),
            (None, Some(shape)) => (shape, left),
            _ => return 0,
        };
        let Some(multi_out) = output(data, shape.multi) else {
            return 0;
        };
        if shape.zero_path_true || data.lone_descend(multi_out) != Some(id) {
            return 0;
        }
        if is_free(data, value) {
            return 0;
        }
        data.op_set_input(shape.multi, value, shape.zero_slot);
        data.op_set_opcode(id, op::COPY);
        data.op_set_inputs(id, vec![multi_out]);
        1
    }
}

pub struct RuleBooleanNegate;

impl Rule for RuleBooleanNegate {
    fn name(&self) -> &'static str {
        "booleannegate"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_NOTEQUAL, op::INT_EQUAL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(opcode) = data.opcode_of(id) else {
            return 0;
        };
        let (Some(subbool), Some(constant)) = (input(data, id, 0), input(data, id, 1)) else {
            return 0;
        };
        if !is_constant(data, constant)
            || data.varnode(constant).offset > 1
            || !boolean_value(data, subbool)
        {
            return 0;
        }
        let mut negate = opcode == op::INT_NOTEQUAL;
        if data.varnode(constant).offset == 0 {
            negate = !negate;
        }
        data.op_set_inputs(id, vec![subbool]);
        data.op_set_opcode(id, if negate { op::BOOL_NEGATE } else { op::COPY });
        1
    }
}

// -------------------------------------------------------------------------
// Byte-piece identities: cancel adjacent slicing and concatenation.

pub struct RuleDoubleSub;

impl Rule for RuleDoubleSub {
    fn name(&self) -> &'static str {
        "doublesub"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::SUBPIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let (Some(mid), Some(outer_offset)) = (input(data, id, 0), input(data, id, 1)) else {
            return 0;
        };
        let Some(inner) = def(data, mid) else {
            return 0;
        };
        if data.opcode_of(inner) != Some(op::SUBPIECE) || !is_constant(data, outer_offset) {
            return 0;
        }
        let Some(root) = input(data, inner, 0) else {
            return 0;
        };
        let Some(inner_offset) = input(data, inner, 1) else {
            return 0;
        };
        if !is_constant(data, inner_offset) || is_free(data, root) {
            return 0;
        }
        let total = data
            .varnode(outer_offset)
            .offset
            .wrapping_add(data.varnode(inner_offset).offset);
        let total_vn = data.new_constant(total, 4);
        data.op_set_inputs(id, vec![root, total_vn]);
        1
    }
}

pub struct RuleHumptyDumpty;

impl Rule for RuleHumptyDumpty {
    fn name(&self) -> &'static str {
        "humptydumpty"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::PIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let (Some(first), Some(second)) = (input(data, id, 0), input(data, id, 1)) else {
            return 0;
        };
        let (Some(sub1), Some(sub2)) = (def(data, first), def(data, second)) else {
            return 0;
        };
        if data.opcode_of(sub1) != Some(op::SUBPIECE) || data.opcode_of(sub2) != Some(op::SUBPIECE)
        {
            return 0;
        }
        let (Some(root1), Some(root2), Some(pos1), Some(pos2)) = (
            input(data, sub1, 0),
            input(data, sub2, 0),
            input(data, sub1, 1),
            input(data, sub2, 1),
        ) else {
            return 0;
        };
        if root1 != root2 || !is_constant(data, pos1) || !is_constant(data, pos2) {
            return 0;
        }
        let pos1 = data.varnode(pos1).offset;
        let pos2 = data.varnode(pos2).offset;
        let size1 = data.varnode(first).size;
        let size2 = data.varnode(second).size;
        if pos1 != pos2.saturating_add(u64::from(size2)) {
            return 0;
        }
        if pos2 == 0 && size1.saturating_add(size2) == data.varnode(root1).size {
            data.op_set_opcode(id, op::COPY);
            data.op_set_inputs(id, vec![root1]);
        } else {
            data.op_set_opcode(id, op::SUBPIECE);
            let offset_vn = data.new_constant(pos2, 4);
            data.op_set_inputs(id, vec![root1, offset_vn]);
        }
        1
    }
}

pub struct RuleDumptyHump;

impl Rule for RuleDumptyHump {
    fn name(&self) -> &'static str {
        "dumptyhump"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::SUBPIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let (Some(base), Some(offset_vn), Some(out)) =
            (input(data, id, 0), input(data, id, 1), output(data, id))
        else {
            return 0;
        };
        let Some(piece) = def(data, base) else {
            return 0;
        };
        if data.opcode_of(piece) != Some(op::PIECE) || !is_constant(data, offset_vn) {
            return 0;
        }
        let mut offset = data.varnode(offset_vn).offset;
        let out_size = data.varnode(out).size;
        let (Some(high), Some(low)) = (input(data, piece, 0), input(data, piece, 1)) else {
            return 0;
        };
        let selected = if offset < u64::from(data.varnode(low).size) {
            if offset.saturating_add(u64::from(out_size)) > u64::from(data.varnode(low).size) {
                return 0;
            }
            low
        } else {
            offset -= u64::from(data.varnode(low).size);
            high
        };
        if is_free(data, selected) && !is_constant(data, selected) {
            return 0;
        }
        if offset == 0 && out_size == data.varnode(selected).size {
            data.op_set_opcode(id, op::COPY);
            data.op_set_inputs(id, vec![selected]);
        } else {
            let offset_vn = data.new_constant(offset, 4);
            data.op_set_inputs(id, vec![selected, offset_vn]);
        }
        1
    }
}

pub struct RuleHumptyOr;

impl Rule for RuleHumptyOr {
    fn name(&self) -> &'static str {
        "humptyor"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_OR]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let (Some(left), Some(right)) = (input(data, id, 0), input(data, id, 1)) else {
            return 0;
        };
        let (Some(and1), Some(and2)) = (def(data, left), def(data, right)) else {
            return 0;
        };
        if data.opcode_of(and1) != Some(op::INT_AND) || data.opcode_of(and2) != Some(op::INT_AND) {
            return 0;
        }
        let (Some(mut a), Some(mut b), Some(mut c), Some(d)) = (
            input(data, and1, 0),
            input(data, and1, 1),
            input(data, and2, 0),
            input(data, and2, 1),
        ) else {
            return 0;
        };
        if a == c {
            c = d;
        } else if a == d {
            // common `a` already has the desired orientation
        } else if b == c {
            b = a;
            a = c;
            c = d;
        } else if b == d {
            b = a;
            a = d;
        } else {
            return 0;
        }
        let common_size = data.varnode(a).size;
        if is_constant(data, b) && is_constant(data, c) {
            let total = (data.varnode(b).offset | data.varnode(c).offset) & mask(common_size);
            if total == mask(common_size) {
                data.op_set_opcode(id, op::COPY);
                data.op_set_inputs(id, vec![a]);
            } else {
                data.op_set_opcode(id, op::INT_AND);
                let total_vn = data.new_constant(total, common_size);
                data.op_set_inputs(id, vec![a, total_vn]);
            }
            return 1;
        }
        if !heritage_known(data, b) || !heritage_known(data, c) {
            return 0;
        }
        let masks = data.nonzero_masks();
        let a_mask = masks[a.0 as usize];
        let (b_mask, c_mask) = (masks[b.0 as usize], masks[c.0 as usize]);
        if b_mask & a_mask == 0 || c_mask & a_mask == 0 {
            // RuleAndDistribute would reverse us.
            return 0;
        }
        // Stronger than Ghidra, deliberately. `RuleAndDistribute` also fires
        // when the shared operand is constant and one distributed AND becomes
        // trivial, and Ghidra does not exclude that here: with a constant `a`
        // of mask 0xfb over operands of mask 0xf7 and 0x8, both rules' guards
        // pass. Ghidra survives it because its pool visits an operation a
        // bounded number of times; this pool revisits until nothing changes, so
        // the pair rewrote each other and grew the graph without limit. Making
        // the two conditions actually disjoint is the fix that does not depend
        // on iteration order.
        if data.varnode(a).flags.constant
            && ((b_mask & a_mask) == b_mask || (c_mask & a_mask) == c_mask)
        {
            return 0;
        }
        let (new_or, or_out) = new_op_before(data, id, op::INT_OR, vec![b, c], common_size);
        let _ = new_or;
        data.op_set_opcode(id, op::INT_AND);
        data.op_set_inputs(id, vec![a, or_out]);
        1
    }
}

pub struct RuleNegateIdentity;

impl Rule for RuleNegateIdentity {
    fn name(&self) -> &'static str {
        "negateidentity"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_NEGATE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(value) = input(data, id, 0) else {
            return 0;
        };
        let Some(negated) = output(data, id) else {
            return 0;
        };
        let descendants: Vec<OpId> = data.varnode(negated).descendants.iter().copied().collect();
        for logic in descendants {
            let Some(logic_code) = data.opcode_of(logic) else {
                continue;
            };
            if logic_code != op::INT_AND && logic_code != op::INT_OR && logic_code != op::INT_XOR {
                continue;
            }
            let (Some(left), Some(right)) = (input(data, logic, 0), input(data, logic, 1)) else {
                continue;
            };
            if left != value && right != value {
                continue;
            }
            let result = if logic_code == op::INT_AND {
                0
            } else {
                mask(data.varnode(value).size)
            };
            data.op_set_opcode(logic, op::COPY);
            let result_vn = data.new_constant(result, data.varnode(value).size);
            data.op_set_inputs(logic, vec![result_vn]);
            return 1;
        }
        0
    }
}

// -------------------------------------------------------------------------
// Integer truncation and signed-division normalization.

pub struct RuleSubNormal;

impl Rule for RuleSubNormal {
    fn name(&self) -> &'static str {
        "subnormal"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::SUBPIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let (Some(shift_out), Some(c_vn), Some(out)) =
            (input(data, id, 0), input(data, id, 1), output(data, id))
        else {
            return 0;
        };
        let Some(shift_op) = def(data, shift_out) else {
            return 0;
        };
        let shift_code = data.opcode_of(shift_op);
        if shift_code != Some(op::INT_RIGHT) && shift_code != Some(op::INT_SRIGHT) {
            return 0;
        }
        let (Some(shift_vn), Some(n_vn)) = (input(data, shift_op, 0), input(data, shift_op, 1))
        else {
            return 0;
        };
        if !is_constant(data, n_vn) || !is_constant(data, c_vn) || is_free(data, shift_vn) {
            return 0;
        }
        let mut n = data.varnode(n_vn).offset;
        let mut c = data.varnode(c_vn).offset;
        let k0 = n / 8;
        let in_size = u64::from(data.varnode(shift_vn).size);
        let out_size = u64::from(data.varnode(out).size);
        if n.saturating_add(8 * c).saturating_add(8 * out_size) < 8 * in_size && n != k0 * 8 {
            return 0;
        }
        let mut k = k0;
        if k.saturating_add(c).saturating_add(out_size) > in_size {
            if c.saturating_add(k) > in_size {
                return 0;
            }
            let trunc_size = in_size - c - k;
            if n == k * 8 && trunc_size > 0 && trunc_size.is_power_of_two() {
                let cut = data.new_constant(c + k, 4);
                let (_, new_out) = new_op_before(
                    data,
                    id,
                    op::SUBPIECE,
                    vec![shift_vn, cut],
                    trunc_size as u32,
                );
                data.op_set_opcode(
                    id,
                    if shift_code == Some(op::INT_SRIGHT) {
                        op::INT_SEXT
                    } else {
                        op::INT_ZEXT
                    },
                );
                data.op_set_inputs(id, vec![new_out]);
                return 1;
            }
            k = in_size - c - out_size;
        }
        c = c.saturating_add(k);
        n = n.saturating_sub(k * 8);
        if n == 0 {
            let cut = data.new_constant(c, 4);
            data.op_set_inputs(id, vec![shift_vn, cut]);
            return 1;
        }
        if n >= out_size * 8 {
            n = out_size * 8;
            if shift_code == Some(op::INT_SRIGHT) {
                n = n.saturating_sub(1);
            }
        }
        let cut = data.new_constant(c, 4);
        let (_, new_out) =
            new_op_before(data, id, op::SUBPIECE, vec![shift_vn, cut], out_size as u32);
        let amount = data.new_constant(n, 4);
        data.op_set_opcode(id, shift_code.unwrap());
        data.op_set_inputs(id, vec![new_out, amount]);
        1
    }
}

pub struct RulePositiveDiv;

impl Rule for RulePositiveDiv {
    fn name(&self) -> &'static str {
        "positivediv"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_SDIV, op::INT_SREM]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(out) = output(data, id) else {
            return 0;
        };
        let size = data.varnode(out).size;
        if size == 0 || size > 8 {
            return 0;
        }
        let sign = size * 8 - 1;
        let masks = data.nonzero_masks();
        let (Some(left), Some(right)) = (input(data, id, 0), input(data, id, 1)) else {
            return 0;
        };
        if ((masks[left.0 as usize] >> sign) & 1) != 0
            || ((masks[right.0 as usize] >> sign) & 1) != 0
        {
            return 0;
        }
        data.op_set_opcode(
            id,
            if data.opcode_of(id) == Some(op::INT_SDIV) {
                op::INT_DIV
            } else {
                op::INT_REM
            },
        );
        1
    }
}

fn find_subshift(data: &Funcdata, id: OpId) -> Option<(OpId, u64, i32)> {
    let code = data.opcode_of(id)?;
    let (sub, mut n, shift_code) = if code == op::SUBPIECE {
        (id, 0, op::MAX)
    } else {
        if code != op::INT_RIGHT && code != op::INT_SRIGHT {
            return None;
        }
        let shifted = input(data, id, 0)?;
        let sub = def(data, shifted)?;
        if data.opcode_of(sub) != Some(op::SUBPIECE) || !is_constant(data, input(data, id, 1)?) {
            return None;
        }
        (sub, data.varnode(input(data, id, 1)?).offset, code)
    };
    let cut = input(data, sub, 1)?;
    let whole = input(data, sub, 0)?;
    if !is_constant(data, cut)
        || u64::from(data.varnode(output(data, sub)?).size).saturating_add(data.varnode(cut).offset)
            != u64::from(data.varnode(whole).size)
    {
        return None;
    }
    n = n.saturating_add(8 * data.varnode(cut).offset);
    Some((sub, n, shift_code))
}

pub struct RuleDivTermAdd;

impl Rule for RuleDivTermAdd {
    fn name(&self) -> &'static str {
        "divtermadd"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::SUBPIECE, op::INT_RIGHT, op::INT_SRIGHT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((sub, n, mut shift_code)) = find_subshift(data, id) else {
            return 0;
        };
        if n > 63 {
            return 0;
        }
        let Some(mult_vn) = input(data, sub, 0) else {
            return 0;
        };
        let Some(mult) = def(data, mult_vn) else {
            return 0;
        };
        if data.opcode_of(mult) != Some(op::INT_MULT) {
            return 0;
        }
        let (Some(ext_vn), Some(mult_const)) = (input(data, mult, 0), input(data, mult, 1)) else {
            return 0;
        };
        if !is_constant(data, mult_const) {
            return 0;
        }
        let Some(ext) = def(data, ext_vn) else {
            return 0;
        };
        let Some(ext_code) = data.opcode_of(ext) else {
            return 0;
        };
        if ext_code != op::INT_ZEXT && ext_code != op::INT_SEXT {
            return 0;
        }
        if (ext_code == op::INT_ZEXT && data.opcode_of(id) == Some(op::INT_SRIGHT))
            || (ext_code == op::INT_SEXT && data.opcode_of(id) == Some(op::INT_RIGHT))
        {
            return 0;
        }
        let power = 1u64 << n;
        let new_constant =
            data.varnode(mult_const).offset.wrapping_add(power) & mask(data.varnode(ext_vn).size);
        let Some(out) = output(data, id) else {
            return 0;
        };
        let descendants: Vec<OpId> = data.varnode(out).descendants.iter().copied().collect();
        for add in descendants {
            if data.opcode_of(add) != Some(op::INT_ADD) {
                continue;
            }
            let Some(left) = input(data, add, 0) else {
                continue;
            };
            let Some(right) = input(data, add, 1) else {
                continue;
            };
            if left != ext_vn && right != ext_vn {
                continue;
            }
            let mult_factor = data.new_constant(new_constant, data.varnode(ext_vn).size);
            let (new_mult, mult_out) = new_op_before(
                data,
                id,
                op::INT_MULT,
                vec![ext_vn, mult_factor],
                data.varnode(ext_vn).size,
            );
            let _ = new_mult;
            if shift_code == op::MAX {
                shift_code = op::INT_RIGHT;
            }
            let shift_amount = data.new_constant(n, 4);
            let (_, shift_out) = new_op_before(
                data,
                id,
                shift_code,
                vec![mult_out, shift_amount],
                data.varnode(ext_vn).size,
            );
            let zero = data.new_constant(0, 4);
            data.op_set_opcode(add, op::SUBPIECE);
            data.op_set_inputs(add, vec![shift_out, zero]);
            return 1;
        }
        0
    }
}

// -------------------------------------------------------------------------
// Sign extraction and division-by-two idioms.

pub struct RuleSignForm;

impl Rule for RuleSignForm {
    fn name(&self) -> &'static str {
        "signform"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::SUBPIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let (Some(sext_out), Some(c_vn)) = (input(data, id, 0), input(data, id, 1)) else {
            return 0;
        };
        let Some(sext) = def(data, sext_out) else {
            return 0;
        };
        if data.opcode_of(sext) != Some(op::INT_SEXT) || !is_constant(data, c_vn) {
            return 0;
        }
        let Some(a) = input(data, sext, 0) else {
            return 0;
        };
        let c = data.varnode(c_vn).offset;
        if c < u64::from(data.varnode(a).size) || is_free(data, a) {
            return 0;
        }
        let n = data.varnode(a).size * 8 - 1;
        let amount = data.new_constant(u64::from(n), 4);
        data.op_set_opcode(id, op::INT_SRIGHT);
        data.op_set_inputs(id, vec![a, amount]);
        1
    }
}

pub struct RuleSignDiv2;

impl Rule for RuleSignDiv2 {
    fn name(&self) -> &'static str {
        "signdiv2"
    }
    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_SRIGHT]
    }
    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(shift_amount) = input(data, id, 1) else {
            return 0;
        };
        if !is_constant(data, shift_amount) || data.varnode(shift_amount).offset != 1 {
            return 0;
        }
        let Some(add_out) = input(data, id, 0) else {
            return 0;
        };
        let Some(add) = def(data, add_out) else {
            return 0;
        };
        if data.opcode_of(add) != Some(op::INT_ADD) {
            return 0;
        }
        for slot in 0..2 {
            let Some(mult_out) = input(data, add, slot) else {
                continue;
            };
            let Some(mult) = def(data, mult_out) else {
                continue;
            };
            let Some(coefficient) = input(data, mult, 1) else {
                continue;
            };
            if data.opcode_of(mult) != Some(op::INT_MULT) || !is_constant(data, coefficient) {
                continue;
            }
            if data.varnode(coefficient).offset != mask(data.varnode(coefficient).size) {
                continue;
            }
            let Some(shift_out) = input(data, mult, 0) else {
                continue;
            };
            let Some(shift) = def(data, shift_out) else {
                continue;
            };
            let Some(shift_amount_vn) = input(data, shift, 1) else {
                continue;
            };
            let Some(value) = input(data, shift, 0) else {
                continue;
            };
            let Some(other_add) = input(data, add, 1 - slot) else {
                continue;
            };
            if data.opcode_of(shift) != Some(op::INT_SRIGHT)
                || !is_constant(data, shift_amount_vn)
                || value != other_add
                || data.varnode(shift_amount_vn).offset
                    != u64::from(data.varnode(value).size * 8 - 1)
                || is_free(data, value)
            {
                continue;
            }
            let divisor = data.new_constant(2, data.varnode(value).size);
            data.op_set_opcode(id, op::INT_SDIV);
            data.op_set_inputs(id, vec![value, divisor]);
            return 1;
        }
        0
    }
}

pub struct RuleSignNearMult;

impl Rule for RuleSignNearMult {
    fn name(&self) -> &'static str {
        "signnearmult"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_AND]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let (Some(add_out), Some(and_mask)) = (input(data, id, 0), input(data, id, 1)) else {
            return 0;
        };
        if !is_constant(data, and_mask) {
            return 0;
        }
        let Some(add) = def(data, add_out) else {
            return 0;
        };
        if data.opcode_of(add) != Some(op::INT_ADD) {
            return 0;
        }
        let mut shift = None;
        let mut x = None;
        for slot in 0..2 {
            let Some(value) = input(data, add, slot) else {
                continue;
            };
            let Some(defop) = def(data, value) else {
                continue;
            };
            let Some(amount_vn) = input(data, defop, 1) else {
                continue;
            };
            if data.opcode_of(defop) == Some(op::INT_RIGHT) && is_constant(data, amount_vn) {
                shift = Some(defop);
                x = input(data, add, 1 - slot);
                break;
            }
        }
        let (Some(shift), Some(x)) = (shift, x) else {
            return 0;
        };
        if is_free(data, x) {
            return 0;
        }
        let Some(amount_vn) = input(data, shift, 1) else {
            return 0;
        };
        let Some(shifted_vn) = input(data, shift, 0) else {
            return 0;
        };
        let amount = data.varnode(amount_vn).offset;
        if amount == 0 {
            return 0;
        }
        let size = data.varnode(shifted_vn).size;
        let n = u64::from(size * 8).saturating_sub(amount);
        if n == 0 || ((mask(size) << n) & mask(size)) != data.varnode(and_mask).offset {
            return 0;
        }
        let Some(sign_shift) = input(data, shift, 0) else {
            return 0;
        };
        let Some(sign_op) = def(data, sign_shift) else {
            return 0;
        };
        let (Some(sign_amount), Some(sign_value)) =
            (input(data, sign_op, 1), input(data, sign_op, 0))
        else {
            return 0;
        };
        if data.opcode_of(sign_op) != Some(op::INT_SRIGHT)
            || !is_constant(data, sign_amount)
            || sign_value != x
            || data.varnode(sign_amount).offset != u64::from(data.varnode(x).size * 8 - 1)
        {
            return 0;
        }
        let Some(power) = 1u64.checked_shl(n as u32) else {
            return 0;
        };
        let divisor = data.new_constant(power, data.varnode(x).size);
        let (_, div_out) = new_op_before(
            data,
            id,
            op::INT_SDIV,
            vec![x, divisor],
            data.varnode(x).size,
        );
        let multiplier = data.new_constant(power, data.varnode(x).size);
        data.op_set_opcode(id, op::INT_MULT);
        data.op_set_inputs(id, vec![div_out, multiplier]);
        1
    }
}

pub struct RuleModOpt;

impl Rule for RuleModOpt {
    fn name(&self) -> &'static str {
        "modopt"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_DIV, op::INT_SDIV]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let (Some(x), Some(divisor), Some(out)) =
            (input(data, id, 0), input(data, id, 1), output(data, id))
        else {
            return 0;
        };
        let mults: Vec<OpId> = data.varnode(out).descendants.iter().copied().collect();
        for mult in mults {
            if data.opcode_of(mult) != Some(op::INT_MULT) {
                continue;
            }
            let (Some(mut div2), Some(other)) = (input(data, mult, 0), input(data, mult, 1)) else {
                continue;
            };
            if div2 == out {
                div2 = other;
            }
            let divisor_matches = if is_constant(data, div2) {
                is_constant(data, divisor)
                    && (((data.varnode(div2).offset ^ mask(data.varnode(div2).size))
                        .wrapping_add(1)
                        & mask(data.varnode(div2).size))
                        == data.varnode(divisor).offset)
            } else {
                def(data, div2)
                    .filter(|neg| data.opcode_of(*neg) == Some(op::INT_2COMP))
                    .and_then(|neg| input(data, neg, 0))
                    == Some(divisor)
            };
            if !divisor_matches {
                continue;
            }
            let Some(mult_out) = output(data, mult) else {
                continue;
            };
            let adds: Vec<OpId> = data.varnode(mult_out).descendants.iter().copied().collect();
            for add in adds {
                if data.opcode_of(add) != Some(op::INT_ADD) {
                    continue;
                }
                let (Some(left), Some(right)) = (input(data, add, 0), input(data, add, 1)) else {
                    continue;
                };
                let other_input = if left == mult_out {
                    right
                } else if right == mult_out {
                    left
                } else {
                    continue;
                };
                if other_input != x {
                    continue;
                }
                let remainder = if data.opcode_of(id) == Some(op::INT_DIV) {
                    op::INT_REM
                } else {
                    op::INT_SREM
                };
                data.op_set_opcode(add, remainder);
                data.op_set_inputs(add, vec![x, divisor]);
                return 1;
            }
        }
        0
    }
}

// -------------------------------------------------------------------------
// Floating-point cast composition.

pub struct RuleFloatCast;

impl Rule for RuleFloatCast {
    fn name(&self) -> &'static str {
        "floatcast"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::FLOAT_FLOAT2FLOAT, op::FLOAT_TRUNC]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(opcode1) = data.opcode_of(id) else {
            return 0;
        };
        let Some(vn1) = input(data, id, 0) else {
            return 0;
        };
        let Some(cast) = def(data, vn1) else { return 0 };
        let Some(opcode2) = data.opcode_of(cast) else {
            return 0;
        };
        if opcode2 != op::FLOAT_FLOAT2FLOAT && opcode2 != op::FLOAT_INT2FLOAT {
            return 0;
        }
        let Some(vn2) = input(data, cast, 0) else {
            return 0;
        };
        if is_free(data, vn2) {
            return 0;
        }
        let in_size1 = data.varnode(vn1).size;
        let in_size2 = data.varnode(vn2).size;
        let Some(out_vn) = output(data, id) else {
            return 0;
        };
        let out_size = data.varnode(out_vn).size;
        if opcode2 == op::FLOAT_FLOAT2FLOAT && opcode1 == op::FLOAT_FLOAT2FLOAT {
            if in_size1 > out_size {
                data.op_set_inputs(id, vec![vn2]);
                if out_size == in_size2 {
                    data.op_set_opcode(id, op::COPY);
                }
                return 1;
            }
            if in_size2 < in_size1 {
                data.op_set_inputs(id, vec![vn2]);
                return 1;
            }
        } else if opcode2 == op::FLOAT_INT2FLOAT && opcode1 == op::FLOAT_FLOAT2FLOAT {
            data.op_set_inputs(id, vec![vn2]);
            data.op_set_opcode(id, op::FLOAT_INT2FLOAT);
            return 1;
        } else if opcode2 == op::FLOAT_FLOAT2FLOAT && opcode1 == op::FLOAT_TRUNC {
            data.op_set_inputs(id, vec![vn2]);
            return 1;
        }
        0
    }
}

/// Every `impl Rule for` block above contributes one registry entry.
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(RuleCollectTerms),
        Box::new(RulePullsubMulti),
        Box::new(RuleTermOrder),
        Box::new(RuleSelectCse),
        Box::new(RuleXorSwap),
        Box::new(RuleOrPredicate),
        Box::new(RuleBooleanNegate),
        Box::new(RuleDoubleSub),
        Box::new(RuleHumptyDumpty),
        Box::new(RuleDumptyHump),
        Box::new(RuleHumptyOr),
        Box::new(RuleNegateIdentity),
        Box::new(RuleSubNormal),
        Box::new(RulePositiveDiv),
        Box::new(RuleDivTermAdd),
        Box::new(RuleSignForm),
        Box::new(RuleSignDiv2),
        Box::new(RuleSignNearMult),
        Box::new(RuleModOpt),
        Box::new(RuleFloatCast),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{CONST_SPACE, REGISTER_SPACE};

    fn block(data: &mut Funcdata) -> GraphBlockId {
        data.new_block(0x1000)
    }

    fn input_value(data: &mut Funcdata, size: u32) -> VarnodeId {
        let value = data.new_varnode(REGISTER_SPACE, data.varnode_count() as u64 * 8, size);
        data.mark_input(value);
        value
    }

    fn op_with_output(
        data: &mut Funcdata,
        block: GraphBlockId,
        opcode: i32,
        inputs: Vec<VarnodeId>,
        size: u32,
    ) -> (OpId, VarnodeId) {
        let id = data.new_op(
            opcode,
            SeqNum {
                address: 0x1000 + data.op_count() as u64 * 4,
                order: 0,
            },
            inputs,
        );
        let output = data.new_unique(size);
        data.op_set_output(id, Some(output));
        data.op_insert_end(id, block);
        (id, output)
    }

    fn no_output(
        data: &mut Funcdata,
        block: GraphBlockId,
        opcode: i32,
        inputs: Vec<VarnodeId>,
    ) -> OpId {
        let id = data.new_op(
            opcode,
            SeqNum {
                address: 0x1000 + data.op_count() as u64 * 4,
                order: 0,
            },
            inputs,
        );
        data.op_insert_end(id, block);
        id
    }

    #[test]
    fn collect_terms_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let x = input_value(&mut data, 4);
        let c3 = data.new_constant(3, 4);
        let c4 = data.new_constant(4, 4);
        let (_, m1) = op_with_output(&mut data, b, op::INT_MULT, vec![x, c3], 4);
        let (_, m2) = op_with_output(&mut data, b, op::INT_MULT, vec![x, c4], 4);
        let (add, _) = op_with_output(&mut data, b, op::INT_ADD, vec![m1, m2], 4);
        assert_eq!(RuleCollectTerms.apply_op(add, &mut data), 1);
        assert_eq!(data.op(add).opcode, op::INT_ADD);
        assert_eq!(
            data.varnode(data.op(add).inputs[0])
                .def
                .map(|op| data.varnode(data.op(op).inputs[1]).offset),
            Some(0)
        );
        assert_eq!(
            data.varnode(data.op(add).inputs[1])
                .def
                .map(|op| data.varnode(data.op(op).inputs[1]).offset),
            Some(7)
        );
        let y = input_value(&mut data, 4);
        let (_, m3) = op_with_output(&mut data, b, op::INT_MULT, vec![y, c4], 4);
        let (bad, _) = op_with_output(&mut data, b, op::INT_ADD, vec![m1, m3], 4);
        assert_eq!(RuleCollectTerms.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn pullsub_multi_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let a = input_value(&mut data, 4);
        let c = input_value(&mut data, 4);
        let phi = data.new_op(
            op::MULTIEQUAL,
            SeqNum {
                address: 0x1000,
                order: 0,
            },
            vec![a, c],
        );
        let p = data.new_unique(4);
        data.op_set_output(phi, Some(p));
        data.op_insert_end(phi, b);
        let offset = data.new_constant(1, 4);
        let (sub, _) = op_with_output(&mut data, b, op::SUBPIECE, vec![p, offset], 2);
        assert_eq!(RulePullsubMulti.apply_op(sub, &mut data), 1);
        let zero_full = data.new_constant(0, 4);
        let (full, _) = op_with_output(&mut data, b, op::SUBPIECE, vec![p, zero_full], 4);
        assert_eq!(RulePullsubMulti.apply_op(full, &mut data), 0);
    }

    #[test]
    fn term_order_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let x = input_value(&mut data, 4);
        let c = data.new_constant(1, 4);
        let (id, _) = op_with_output(&mut data, b, op::INT_ADD, vec![c, x], 4);
        assert_eq!(RuleTermOrder.apply_op(id, &mut data), 1);
        assert_eq!(data.op(id).inputs, vec![x, c]);
        assert_eq!(RuleTermOrder.apply_op(id, &mut data), 0);
    }

    #[test]
    fn select_cse_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let x = input_value(&mut data, 4);
        let zero = data.new_constant(0, 4);
        let (_, first_out) = op_with_output(&mut data, b, op::SUBPIECE, vec![x, zero], 2);
        let (second, second_out) = op_with_output(&mut data, b, op::SUBPIECE, vec![x, zero], 2);
        let one_add = data.new_constant(1, 2);
        let (use_op, _) = op_with_output(&mut data, b, op::INT_ADD, vec![second_out, one_add], 2);
        assert_eq!(RuleSelectCse.apply_op(second, &mut data), 1);
        assert_eq!(data.op(use_op).inputs[0], first_out);
        let one_diff = data.new_constant(1, 4);
        let (different, _) = op_with_output(&mut data, b, op::SUBPIECE, vec![x, one_diff], 2);
        assert_eq!(RuleSelectCse.apply_op(different, &mut data), 0);
    }

    #[test]
    fn xor_swap_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let a = input_value(&mut data, 4);
        let c = input_value(&mut data, 4);
        let (_, inner) = op_with_output(&mut data, b, op::INT_XOR, vec![a, c], 4);
        let (outer, _) = op_with_output(&mut data, b, op::INT_XOR, vec![inner, a], 4);
        assert_eq!(RuleXorSwap.apply_op(outer, &mut data), 1);
        assert_eq!(data.op(outer).inputs, vec![c]);
        let d = input_value(&mut data, 4);
        let (bad, _) = op_with_output(&mut data, b, op::INT_XOR, vec![inner, d], 4);
        assert_eq!(RuleXorSwap.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn boolean_negate_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let a = input_value(&mut data, 4);
        let c = input_value(&mut data, 4);
        let (_, cmp) = op_with_output(&mut data, b, op::INT_EQUAL, vec![a, c], 1);
        let zero_bool = data.new_constant(0, 1);
        let (eq, _) = op_with_output(&mut data, b, op::INT_EQUAL, vec![cmp, zero_bool], 1);
        assert_eq!(RuleBooleanNegate.apply_op(eq, &mut data), 1);
        assert_eq!(data.op(eq).opcode, op::BOOL_NEGATE);
        let zero_wide = data.new_constant(0, 4);
        let (wide, _) = op_with_output(&mut data, b, op::INT_EQUAL, vec![a, zero_wide], 1);
        assert_eq!(RuleBooleanNegate.apply_op(wide, &mut data), 0);
    }

    #[test]
    fn double_sub_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let x = input_value(&mut data, 8);
        let one_mid = data.new_constant(1, 4);
        let (_, mid) = op_with_output(&mut data, b, op::SUBPIECE, vec![x, one_mid], 4);
        let two_outer = data.new_constant(2, 4);
        let (outer, _) = op_with_output(&mut data, b, op::SUBPIECE, vec![mid, two_outer], 2);
        assert_eq!(RuleDoubleSub.apply_op(outer, &mut data), 1);
        assert_eq!(data.varnode(data.op(outer).inputs[1]).offset, 3);
        let y = data.new_varnode(REGISTER_SPACE, 0x400, 8);
        let one_bad = data.new_constant(1, 4);
        let (bad, _) = op_with_output(&mut data, b, op::SUBPIECE, vec![y, one_bad], 2);
        assert_eq!(RuleDoubleSub.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn humpty_dumpty_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let root = input_value(&mut data, 4);
        let two_hi = data.new_constant(2, 4);
        let (_, hi) = op_with_output(&mut data, b, op::SUBPIECE, vec![root, two_hi], 2);
        let zero_lo = data.new_constant(0, 4);
        let (_, lo) = op_with_output(&mut data, b, op::SUBPIECE, vec![root, zero_lo], 2);
        let (piece, _) = op_with_output(&mut data, b, op::PIECE, vec![hi, lo], 4);
        assert_eq!(RuleHumptyDumpty.apply_op(piece, &mut data), 1);
        assert_eq!(data.op(piece).opcode, op::COPY);
        let one_bad_hi = data.new_constant(1, 4);
        let (_, bad_hi) = op_with_output(&mut data, b, op::SUBPIECE, vec![root, one_bad_hi], 1);
        let (bad, _) = op_with_output(&mut data, b, op::PIECE, vec![bad_hi, lo], 3);
        assert_eq!(RuleHumptyDumpty.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn dumpty_hump_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let hi = input_value(&mut data, 2);
        let lo = input_value(&mut data, 2);
        let (_, piece) = op_with_output(&mut data, b, op::PIECE, vec![hi, lo], 4);
        let zero_sub = data.new_constant(0, 4);
        let (sub, _) = op_with_output(&mut data, b, op::SUBPIECE, vec![piece, zero_sub], 2);
        assert_eq!(RuleDumptyHump.apply_op(sub, &mut data), 1);
        assert_eq!(data.op(sub).inputs, vec![lo]);
        let one_bad_sub = data.new_constant(1, 4);
        let (bad, _) = op_with_output(&mut data, b, op::SUBPIECE, vec![piece, one_bad_sub], 4);
        assert_eq!(RuleDumptyHump.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn humpty_or_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let x = input_value(&mut data, 1);
        let a = data.new_constant(0xf0, 1);
        let c = data.new_constant(0x0f, 1);
        let (_, l) = op_with_output(&mut data, b, op::INT_AND, vec![x, a], 1);
        let (_, r) = op_with_output(&mut data, b, op::INT_AND, vec![x, c], 1);
        let (or, _) = op_with_output(&mut data, b, op::INT_OR, vec![l, r], 1);
        assert_eq!(RuleHumptyOr.apply_op(or, &mut data), 1);
        assert_eq!(data.op(or).opcode, op::COPY);
        let y = input_value(&mut data, 1);
        let (_, bad_l) = op_with_output(&mut data, b, op::INT_AND, vec![x, a], 1);
        let (bad, _) = op_with_output(&mut data, b, op::INT_OR, vec![bad_l, y], 1);
        assert_eq!(RuleHumptyOr.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn negate_identity_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let x = input_value(&mut data, 4);
        let (_, neg) = op_with_output(&mut data, b, op::INT_NEGATE, vec![x], 4);
        let (logic, _) = op_with_output(&mut data, b, op::INT_AND, vec![x, neg], 4);
        assert_eq!(
            RuleNegateIdentity.apply_op(data.varnode(neg).def.unwrap(), &mut data),
            1
        );
        assert_eq!(data.op(logic).opcode, op::COPY);
        let (_, neg2) = op_with_output(&mut data, b, op::INT_NEGATE, vec![x], 4);
        let y = input_value(&mut data, 4);
        let (bad, _) = op_with_output(&mut data, b, op::INT_ADD, vec![neg2, y], 4);
        assert_eq!(
            RuleNegateIdentity.apply_op(data.varnode(neg2).def.unwrap(), &mut data),
            0
        );
        assert_eq!(data.op(bad).opcode, op::INT_ADD);
    }

    #[test]
    fn sub_normal_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let x = input_value(&mut data, 8);
        let eight_shift = data.new_constant(8, 4);
        let (_, shifted) = op_with_output(&mut data, b, op::INT_RIGHT, vec![x, eight_shift], 8);
        let zero_sub = data.new_constant(0, 4);
        let (sub, _) = op_with_output(&mut data, b, op::SUBPIECE, vec![shifted, zero_sub], 4);
        assert_eq!(RuleSubNormal.apply_op(sub, &mut data), 1);
        let free = data.new_varnode(REGISTER_SPACE, 0x800, 8);
        let eight_bad_shift = data.new_constant(8, 4);
        let (_, bad_shift) =
            op_with_output(&mut data, b, op::INT_RIGHT, vec![free, eight_bad_shift], 8);
        let zero_bad_sub = data.new_constant(0, 4);
        let (bad, _) = op_with_output(&mut data, b, op::SUBPIECE, vec![bad_shift, zero_bad_sub], 4);
        assert_eq!(RuleSubNormal.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn positive_div_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let a = data.new_constant(3, 4);
        let c = data.new_constant(2, 4);
        let (div, _) = op_with_output(&mut data, b, op::INT_SDIV, vec![a, c], 4);
        assert_eq!(RulePositiveDiv.apply_op(div, &mut data), 1);
        assert_eq!(data.op(div).opcode, op::INT_DIV);
        let x = input_value(&mut data, 4);
        let (bad, _) = op_with_output(&mut data, b, op::INT_SDIV, vec![x, c], 4);
        assert_eq!(RulePositiveDiv.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn div_term_add_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let x = input_value(&mut data, 1);
        let (_, ext) = op_with_output(&mut data, b, op::INT_ZEXT, vec![x], 4);
        let three_mult = data.new_constant(3, 4);
        let (_, mult) = op_with_output(&mut data, b, op::INT_MULT, vec![ext, three_mult], 4);
        let three_sub = data.new_constant(3, 4);
        let (sub, sub_out) = op_with_output(&mut data, b, op::SUBPIECE, vec![mult, three_sub], 1);
        let (add, _) = op_with_output(&mut data, b, op::INT_ADD, vec![sub_out, ext], 1);
        assert_eq!(RuleDivTermAdd.apply_op(sub, &mut data), 1);
        assert_eq!(data.op(add).opcode, op::SUBPIECE);
        let two_bad_div = data.new_constant(2, 4);
        let (bad, _) = op_with_output(&mut data, b, op::SUBPIECE, vec![mult, two_bad_div], 1);
        assert_eq!(RuleDivTermAdd.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn sign_form_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let x = input_value(&mut data, 1);
        let (_, sext) = op_with_output(&mut data, b, op::INT_SEXT, vec![x], 4);
        let one_sign_form = data.new_constant(1, 4);
        let (sub, _) = op_with_output(&mut data, b, op::SUBPIECE, vec![sext, one_sign_form], 1);
        assert_eq!(RuleSignForm.apply_op(sub, &mut data), 1);
        assert_eq!(data.op(sub).opcode, op::INT_SRIGHT);
        let zero_bad_form = data.new_constant(0, 4);
        let (bad, _) = op_with_output(&mut data, b, op::SUBPIECE, vec![sext, zero_bad_form], 1);
        assert_eq!(RuleSignForm.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn sign_div2_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let x = input_value(&mut data, 4);
        let thirty_one = data.new_constant(31, 4);
        let (_, sign) = op_with_output(&mut data, b, op::INT_SRIGHT, vec![x, thirty_one], 4);
        let minus_one = data.new_constant(u32::MAX as u64, 4);
        let (_, neg) = op_with_output(&mut data, b, op::INT_MULT, vec![sign, minus_one], 4);
        let (_, add) = op_with_output(&mut data, b, op::INT_ADD, vec![x, neg], 4);
        let one_div = data.new_constant(1, 4);
        let (div, _) = op_with_output(&mut data, b, op::INT_SRIGHT, vec![add, one_div], 4);
        assert_eq!(RuleSignDiv2.apply_op(div, &mut data), 1);
        assert_eq!(data.op(div).opcode, op::INT_SDIV);
        let y = input_value(&mut data, 4);
        let two_bad = data.new_constant(2, 4);
        let (bad, _) = op_with_output(&mut data, b, op::INT_SRIGHT, vec![y, two_bad], 4);
        assert_eq!(RuleSignDiv2.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn sign_near_mult_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let x = input_value(&mut data, 4);
        let thirty_one_near = data.new_constant(31, 4);
        let (_, sign) = op_with_output(&mut data, b, op::INT_SRIGHT, vec![x, thirty_one_near], 4);
        let twenty_nine = data.new_constant(29, 4);
        let (_, unsigned) = op_with_output(&mut data, b, op::INT_RIGHT, vec![sign, twenty_nine], 4);
        let (_, add) = op_with_output(&mut data, b, op::INT_ADD, vec![x, unsigned], 4);
        let mask_near = data.new_constant(0xfffffff8, 4);
        let (and, _) = op_with_output(&mut data, b, op::INT_AND, vec![add, mask_near], 4);
        assert_eq!(RuleSignNearMult.apply_op(and, &mut data), 1);
        assert_eq!(data.op(and).opcode, op::INT_MULT);
        let mask_bad_near = data.new_constant(0xfffffff0, 4);
        let (bad, _) = op_with_output(&mut data, b, op::INT_AND, vec![add, mask_bad_near], 4);
        assert_eq!(RuleSignNearMult.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn mod_opt_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let x = input_value(&mut data, 4);
        let d = data.new_constant(3, 4);
        let (_, div) = op_with_output(&mut data, b, op::INT_DIV, vec![x, d], 4);
        let neg = data.new_constant((!3u32 as u64).wrapping_add(1), 4);
        let (_, mult) = op_with_output(&mut data, b, op::INT_MULT, vec![div, neg], 4);
        let (add, _) = op_with_output(&mut data, b, op::INT_ADD, vec![mult, x], 4);
        let divop = data.varnode(div).def.unwrap();
        assert_eq!(RuleModOpt.apply_op(divop, &mut data), 1);
        assert_eq!(data.op(add).opcode, op::INT_REM);
        let four_bad = data.new_constant(4, 4);
        let (bad, _) = op_with_output(&mut data, b, op::INT_DIV, vec![x, four_bad], 4);
        assert_eq!(RuleModOpt.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn float_cast_fires_and_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let x = input_value(&mut data, 4);
        let (_, first) = op_with_output(&mut data, b, op::FLOAT_FLOAT2FLOAT, vec![x], 8);
        let (second, _) = op_with_output(&mut data, b, op::FLOAT_FLOAT2FLOAT, vec![first], 4);
        assert_eq!(RuleFloatCast.apply_op(second, &mut data), 1);
        assert_eq!(data.op(second).opcode, op::COPY);
        let free = data.new_varnode(REGISTER_SPACE, 0x900, 4);
        let (_, inner) = op_with_output(&mut data, b, op::FLOAT_FLOAT2FLOAT, vec![free], 8);
        let (bad, _) = op_with_output(&mut data, b, op::FLOAT_FLOAT2FLOAT, vec![inner], 4);
        assert_eq!(RuleFloatCast.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn or_predicate_fires_and_declines() {
        let mut data = Funcdata::default();
        let cond = data.new_block(0x1100);
        let zero_block = data.new_block(0x1200);
        let other_block = data.new_block(0x1300);
        let merge = data.new_block(0x1400);
        data.add_edge(cond, other_block);
        data.add_edge(cond, zero_block);
        data.add_edge(zero_block, merge);
        data.add_edge(other_block, merge);
        let x = input_value(&mut data, 1);
        let y = input_value(&mut data, 1);
        let zero = data.new_constant(0, 1);
        let (_, compare_out) = op_with_output(&mut data, cond, op::INT_EQUAL, vec![x, zero], 1);
        let branch_target = data.new_constant(0x1200, 4);
        no_output(
            &mut data,
            cond,
            op::CBRANCH,
            vec![branch_target, compare_out],
        );
        let zero_copy_input = data.new_constant(0, 1);
        let (_, zero_copy) =
            op_with_output(&mut data, zero_block, op::COPY, vec![zero_copy_input], 1);
        let phi = data.new_op(
            op::MULTIEQUAL,
            SeqNum {
                address: 0x1400,
                order: 0,
            },
            vec![zero_copy, x],
        );
        let phi_out = data.new_unique(1);
        data.op_set_output(phi, Some(phi_out));
        data.op_insert_end(phi, merge);
        let (or, _) = op_with_output(&mut data, merge, op::INT_OR, vec![phi_out, y], 1);
        assert_eq!(RuleOrPredicate.apply_op(or, &mut data), 1);
        assert_eq!(data.op(or).opcode, op::COPY);
        assert_eq!(data.op(or).inputs, vec![phi_out]);

        let (unrelated, _) = op_with_output(&mut data, merge, op::INT_OR, vec![x, y], 1);
        assert_eq!(RuleOrPredicate.apply_op(unrelated, &mut data), 0);
    }

    #[test]
    fn all_registry_rules_are_nonempty() {
        assert!(
            all()
                .iter()
                .all(|rule| !rule.name().is_empty() && !rule.op_list().is_empty())
        );
    }

    #[allow(dead_code)]
    fn _space_constants_are_available() {
        let _ = CONST_SPACE;
    }

    #[test]
    fn humptyor_declines_what_anddistribute_would_reverse() {
        // These two rules are exact inverses. If both accept one operand set,
        // the expression fixpoint rewrites forever and the graph grows without
        // limit. The masks here are the ones measured on
        // `Na_CheckRestartReady`: a constant shared operand of mask 0xfb over
        // operands of mask 0xf7 and 0x8.
        use crate::graph::expr_rules::RuleAndDistribute;

        let mut data = Funcdata::default();
        let block = block(&mut data);
        let shared = data.new_constant(0xfb, 1);
        let left = input_value(&mut data, 1);
        let right = data.new_constant(0x8, 1);
        let (_, and1) = op_with_output(&mut data, block, op::INT_AND, vec![shared, left], 1);
        let (_, and2) = op_with_output(&mut data, block, op::INT_AND, vec![shared, right], 1);
        let (or, _) = op_with_output(&mut data, block, op::INT_OR, vec![and1, and2], 1);

        let humpty = RuleHumptyOr.apply_op(or, &mut data);
        let distribute = RuleAndDistribute.apply_op(or, &mut data);
        assert!(
            humpty == 0 || distribute == 0,
            "both rules accepted the same operands, so each would undo the other forever"
        );
    }
}
