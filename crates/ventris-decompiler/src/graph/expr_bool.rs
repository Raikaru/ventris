//! Boolean and comparison rewrites from Ghidra 12.1.3's `ruleaction.cc`.
//!
//! The implementations below follow the real `applyOp` bodies for
//! `RuleBooleanDedup`, `RuleBooleanUndistribute`, `RuleBxor2NotEqual`,
//! `RuleOrCompare`, `RuleIntLessEqual`, `RuleLessEqual`, `RuleSlessToLess`,
//! `RuleShiftCompare`, `RuleTestSign`, `RuleThreeWayCompare`,
//! `RulePopcountBoolXor`, `RuleLzcountShiftBool`, and `RuleNegateNegate`.
//!
//! `RuleShiftLess` is intentionally omitted because its implementation is
//! commented out in the pinned C++ source.  `RuleConditionalMove` is omitted
//! because its real implementation needs `FlowBlock`/CBRANCH condition
//! metadata, `CloneBlockOps`, address-tied/evaluation-type flags, and the
//! uninsert/reinsert and boolean-negation helpers absent from this graph.

use ventris_pcode::op;

use super::action::Rule;
use super::{Funcdata, OpId, VarnodeId};

const UNCORRELATED: i32 = -1;
const SAME: i32 = 0;
const COMPLEMENTARY: i32 = 1;

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

fn sign_bit(size: u32) -> Option<u64> {
    let bits = size.checked_mul(8)?;
    (bits > 0 && bits <= 64).then_some(1u64 << (bits - 1))
}

fn shift_left(value: u64, amount: u64) -> u64 {
    (amount < 64).then_some(value << amount).unwrap_or(0)
}

fn shift_right(value: u64, amount: u64) -> u64 {
    (amount < 64).then_some(value >> amount).unwrap_or(0)
}

fn input(data: &Funcdata, id: OpId, slot: usize) -> Option<VarnodeId> {
    data.op(id).inputs.get(slot).copied()
}

fn inputs2(data: &Funcdata, id: OpId) -> Option<(VarnodeId, VarnodeId)> {
    Some((input(data, id, 0)?, input(data, id, 1)?))
}

fn def(data: &Funcdata, value: VarnodeId) -> Option<OpId> {
    data.varnode(value)
        .def
        .filter(|id| data.opcode_of(*id).is_some())
}

fn is_constant(data: &Funcdata, value: VarnodeId) -> bool {
    data.varnode(value).flags.constant
}

/// Exact graph approximation of Ghidra's `Varnode::isFree`.
fn is_free(data: &Funcdata, value: VarnodeId) -> bool {
    let node = data.varnode(value);
    !(node.flags.written || node.flags.input)
}

/// The graph's heritage-known predicate.  Constants are both free and known.
fn heritage_known(data: &Funcdata, value: VarnodeId) -> bool {
    let node = data.varnode(value);
    node.flags.constant || node.flags.input || node.def.is_some()
}

fn nonzero_mask(data: &Funcdata, value: VarnodeId) -> u64 {
    data.nonzero_masks()[value.0 as usize]
}

fn varnode_same(data: &Funcdata, left: VarnodeId, right: VarnodeId) -> bool {
    left == right
        || (is_constant(data, left)
            && is_constant(data, right)
            && data.varnode(left).offset == data.varnode(right).offset)
}

fn bool_combiner(code: i32) -> bool {
    matches!(code, op::BOOL_AND | op::BOOL_OR | op::BOOL_XOR)
}

fn bool_output(data: &Funcdata, value: VarnodeId) -> bool {
    data.varnode(value).size == 1
}

/// Return the opcode that complements a comparison, and whether its operands
/// need to be exchanged.  This is the subset of Ghidra's `get_booleanflip`
/// used by `BooleanMatch`.
fn boolean_flip(code: i32) -> Option<(i32, bool)> {
    Some(match code {
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
        _ => return None,
    })
}

/// The special same-op complement test used by Ghidra's `BooleanMatch`.
fn same_op_complement(data: &Funcdata, left: OpId, right: OpId) -> bool {
    let code = data.op(left).opcode;
    if code != op::INT_SLESS && code != op::INT_LESS {
        return false;
    }
    let Some(left0) = input(data, left, 0) else {
        return false;
    };
    let Some(left1) = input(data, left, 1) else {
        return false;
    };
    let Some(right0) = input(data, right, 0) else {
        return false;
    };
    let Some(right1) = input(data, right, 1) else {
        return false;
    };
    let const_slot = if is_constant(data, left1) { 1 } else { 0 };
    let left_const = if const_slot == 0 { left0 } else { left1 };
    let left_other = if const_slot == 0 { left1 } else { left0 };
    let right_const = if const_slot == 0 { right1 } else { right0 };
    let right_other = if const_slot == 0 { right0 } else { right1 };
    if !is_constant(data, left_const)
        || !is_constant(data, right_const)
        || !varnode_same(data, left_other, right_other)
    {
        return false;
    }
    let mut val1 = data.varnode(left_const).offset;
    let mut val2 = data.varnode(right_const).offset;
    if const_slot != 0 {
        std::mem::swap(&mut val1, &mut val2);
    }
    if val1.wrapping_add(1) != val2 {
        return false;
    }
    if code == op::INT_LESS && val2 == 0 {
        return false;
    }
    if code == op::INT_SLESS {
        let Some(bit) = sign_bit(data.varnode(left_const).size) else {
            return false;
        };
        if val2 & bit != 0 && val1 & bit == 0 {
            return false;
        }
    }
    true
}

/// Depth-bounded port of Ghidra's `BooleanMatch::evaluate(...,1)`.
fn boolean_match(data: &Funcdata, left: VarnodeId, right: VarnodeId, depth: u32) -> i32 {
    if left == right {
        return SAME;
    }

    let left_def = def(data, left);
    let left_code = left_def.map(|id| data.op(id).opcode);
    if left_code == Some(op::BOOL_NEGATE) {
        let Some(inner) = input(data, left_def.expect("BOOL_NEGATE has a definition"), 0) else {
            return UNCORRELATED;
        };
        let mut result = boolean_match(data, inner, right, depth);
        if result == SAME {
            result = COMPLEMENTARY;
        } else if result == COMPLEMENTARY {
            result = SAME;
        }
        return result;
    }

    let right_def = def(data, right);
    let right_code = right_def.map(|id| data.op(id).opcode);
    if right_code == Some(op::BOOL_NEGATE) {
        let Some(inner) = input(data, right_def.expect("BOOL_NEGATE has a definition"), 0) else {
            return UNCORRELATED;
        };
        let mut result = boolean_match(data, left, inner, depth);
        if result == SAME {
            result = COMPLEMENTARY;
        } else if result == COMPLEMENTARY {
            result = SAME;
        }
        return result;
    }

    let (Some(left_def), Some(right_def)) = (left_def, right_def) else {
        return UNCORRELATED;
    };
    let left_code = data.op(left_def).opcode;
    let right_code = data.op(right_def).opcode;
    if !bool_output(data, left) || !bool_output(data, right) {
        return UNCORRELATED;
    }

    if depth != 0 && bool_combiner(left_code) && bool_combiner(right_code) {
        let compatible = left_code == right_code
            || (left_code == op::BOOL_AND && right_code == op::BOOL_OR)
            || (left_code == op::BOOL_OR && right_code == op::BOOL_AND);
        if compatible {
            let Some(left0) = input(data, left_def, 0) else {
                return UNCORRELATED;
            };
            let Some(left1) = input(data, left_def, 1) else {
                return UNCORRELATED;
            };
            let Some(right0) = input(data, right_def, 0) else {
                return UNCORRELATED;
            };
            let Some(right1) = input(data, right_def, 1) else {
                return UNCORRELATED;
            };
            let mut pair1 = boolean_match(data, left0, right0, depth - 1);
            let pair2;
            if pair1 == UNCORRELATED {
                pair1 = boolean_match(data, left0, right1, depth - 1);
                if pair1 == UNCORRELATED {
                    return UNCORRELATED;
                }
                pair2 = boolean_match(data, left1, right0, depth - 1);
            } else {
                pair2 = boolean_match(data, left1, right1, depth - 1);
            }
            if pair2 == UNCORRELATED {
                return UNCORRELATED;
            }
            if left_code == right_code {
                if pair1 == SAME && pair2 == SAME {
                    return SAME;
                }
                if left_code == op::BOOL_XOR && pair1 == COMPLEMENTARY && pair2 == COMPLEMENTARY {
                    return SAME;
                }
                if left_code == op::BOOL_XOR
                    && (pair1 == SAME || pair1 == COMPLEMENTARY)
                    && (pair2 == SAME || pair2 == COMPLEMENTARY)
                {
                    return COMPLEMENTARY;
                }
            } else if pair1 == COMPLEMENTARY && pair2 == COMPLEMENTARY {
                return COMPLEMENTARY;
            }
        }
        return UNCORRELATED;
    }

    if left_code == right_code {
        let Some(left0) = input(data, left_def, 0) else {
            return UNCORRELATED;
        };
        let Some(left1) = input(data, left_def, 1) else {
            return UNCORRELATED;
        };
        let Some(right0) = input(data, right_def, 0) else {
            return UNCORRELATED;
        };
        let Some(right1) = input(data, right_def, 1) else {
            return UNCORRELATED;
        };
        if varnode_same(data, left0, right0) && varnode_same(data, left1, right1) {
            return SAME;
        }
        if same_op_complement(data, left_def, right_def) {
            return COMPLEMENTARY;
        }
        return UNCORRELATED;
    }

    let Some((complement, reorder)) = boolean_flip(right_code) else {
        return UNCORRELATED;
    };
    if left_code != complement {
        return UNCORRELATED;
    }
    let (left_slot, right_slot) = if reorder { (0, 1) } else { (0, 0) };
    let Some(left0) = input(data, left_def, left_slot) else {
        return UNCORRELATED;
    };
    let Some(left1) = input(data, left_def, 1 - left_slot) else {
        return UNCORRELATED;
    };
    let Some(right0) = input(data, right_def, right_slot) else {
        return UNCORRELATED;
    };
    let Some(right1) = input(data, right_def, 1 - right_slot) else {
        return UNCORRELATED;
    };
    if varnode_same(data, left0, right0) && varnode_same(data, left1, right1) {
        COMPLEMENTARY
    } else {
        UNCORRELATED
    }
}

fn insert_bool_negate(data: &mut Funcdata, value: VarnodeId, before: OpId) -> VarnodeId {
    let seq = data.op(before).seq;
    let negate = data.new_op(op::BOOL_NEGATE, seq, vec![value]);
    let output = data.new_unique(1);
    data.op_set_output(negate, Some(output));
    data.op_insert_before(negate, before);
    output
}

fn new_op_before(
    data: &mut Funcdata,
    before: OpId,
    opcode: i32,
    inputs: Vec<VarnodeId>,
    output_size: u32,
) -> (OpId, VarnodeId) {
    let seq = data.op(before).seq;
    let new_op = data.new_op(opcode, seq, inputs);
    let output = data.new_unique(output_size);
    data.op_set_output(new_op, Some(output));
    data.op_insert_before(new_op, before);
    (new_op, output)
}

pub struct RuleBooleanUndistribute;

impl Rule for RuleBooleanUndistribute {
    fn name(&self) -> &'static str {
        "booleanundistribute"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_EQUAL, op::INT_NOTEQUAL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(vn0) = input(data, id, 0) else {
            return 0;
        };
        let Some(vn1) = input(data, id, 1) else {
            return 0;
        };
        let (Some(op0), Some(op1)) = (def(data, vn0), def(data, vn1)) else {
            return 0;
        };
        let opc0 = data.op(op0).opcode;
        let opc1 = data.op(op1).opcode;
        if !matches!(opc0, op::BOOL_AND | op::BOOL_OR)
            || !matches!(opc1, op::BOOL_AND | op::BOOL_OR)
        {
            return 0;
        }
        let Some(ins0) = input(data, op0, 0) else {
            return 0;
        };
        let Some(ins1) = input(data, op0, 1) else {
            return 0;
        };
        let Some(ins2) = input(data, op1, 0) else {
            return 0;
        };
        let Some(ins3) = input(data, op1, 1) else {
            return 0;
        };
        let ins = [ins0, ins1, ins2, ins3];
        if ins.iter().copied().any(|value| is_free(data, value)) {
            return 0;
        }
        let mut flipped = [false; 4];
        let mut central_equal = data.op(id).opcode == op::INT_EQUAL;
        if opc0 == op::BOOL_OR {
            flipped[0] = true;
            flipped[1] = true;
            central_equal = !central_equal;
        }
        if opc1 == op::BOOL_OR {
            flipped[2] = true;
            flipped[3] = true;
            central_equal = !central_equal;
        }

        let (left_slot, right_slot) = if boolean_match(data, ins[0], ins[2], 1) == SAME
            || boolean_match(data, ins[0], ins[2], 1) == COMPLEMENTARY
        {
            let mut right_flip = flipped[2];
            if boolean_match(data, ins[0], ins[2], 1) == COMPLEMENTARY {
                right_flip = !right_flip;
            }
            flipped[2] = right_flip;
            (0, 2)
        } else if boolean_match(data, ins[0], ins[3], 1) != UNCORRELATED {
            let mut right_flip = flipped[3];
            if boolean_match(data, ins[0], ins[3], 1) == COMPLEMENTARY {
                right_flip = !right_flip;
            }
            flipped[3] = right_flip;
            (0, 3)
        } else if boolean_match(data, ins[1], ins[2], 1) != UNCORRELATED {
            let mut right_flip = flipped[2];
            if boolean_match(data, ins[1], ins[2], 1) == COMPLEMENTARY {
                right_flip = !right_flip;
            }
            flipped[2] = right_flip;
            (1, 2)
        } else if boolean_match(data, ins[1], ins[3], 1) != UNCORRELATED {
            let mut right_flip = flipped[3];
            if boolean_match(data, ins[1], ins[3], 1) == COMPLEMENTARY {
                right_flip = !right_flip;
            }
            flipped[3] = right_flip;
            (1, 3)
        } else {
            return 0;
        };
        if flipped[left_slot] != flipped[right_slot] {
            return 0;
        }

        let combine_opcode;
        if central_equal {
            combine_opcode = op::BOOL_OR;
            flipped[left_slot] = !flipped[left_slot];
        } else {
            combine_opcode = op::BOOL_AND;
        }
        let mut final_a = ins[left_slot];
        if flipped[left_slot] {
            final_a = insert_bool_negate(data, final_a, id);
        }
        if flipped[1 - left_slot] {
            central_equal = !central_equal;
        }
        if flipped[5 - right_slot] {
            central_equal = !central_equal;
        }
        let final_b = ins[1 - left_slot];
        let final_c = ins[5 - right_slot];
        let (_, eq_output) = new_op_before(
            data,
            id,
            if central_equal {
                op::INT_EQUAL
            } else {
                op::INT_NOTEQUAL
            },
            vec![final_b, final_c],
            1,
        );
        data.op_set_opcode(id, combine_opcode);
        data.op_set_inputs(id, vec![final_a, eq_output]);
        1
    }
}

pub struct RuleBooleanDedup;

impl Rule for RuleBooleanDedup {
    fn name(&self) -> &'static str {
        "booleandedup"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::BOOL_AND, op::BOOL_OR]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(vn0) = input(data, id, 0) else {
            return 0;
        };
        let Some(vn1) = input(data, id, 1) else {
            return 0;
        };
        let (Some(op0), Some(op1)) = (def(data, vn0), def(data, vn1)) else {
            return 0;
        };
        let opc0 = data.op(op0).opcode;
        let opc1 = data.op(op1).opcode;
        if !matches!(opc0, op::BOOL_AND | op::BOOL_OR)
            || !matches!(opc1, op::BOOL_AND | op::BOOL_OR)
        {
            return 0;
        }
        let Some(ins0) = input(data, op0, 0) else {
            return 0;
        };
        let Some(ins1) = input(data, op0, 1) else {
            return 0;
        };
        let Some(ins2) = input(data, op1, 0) else {
            return 0;
        };
        let Some(ins3) = input(data, op1, 1) else {
            return 0;
        };
        let ins = [ins0, ins1, ins2, ins3];
        if ins.iter().copied().any(|value| is_free(data, value)) {
            return 0;
        }
        let pairs = [
            (ins[0], ins[2]),
            (ins[0], ins[3]),
            (ins[1], ins[2]),
            (ins[1], ins[3]),
        ];
        let mut matched_pair = None;
        for (index, (left, right)) in pairs.into_iter().enumerate() {
            let result = boolean_match(data, left, right, 1);
            if result != UNCORRELATED {
                matched_pair = Some((index, result == COMPLEMENTARY));
                break;
            }
        }
        let Some((matched, is_flipped)) = matched_pair else {
            return 0;
        };
        let (left_a, right_a, left_o, right_o) = match matched {
            0 => (ins[0], ins[2], ins[1], ins[3]),
            1 => (ins[0], ins[3], ins[1], ins[2]),
            2 => (ins[1], ins[2], ins[0], ins[3]),
            _ => (ins[1], ins[3], ins[0], ins[2]),
        };

        let central_opcode = data.op(id).opcode;
        let (final_opcode, branch_opcode, final_a) = if is_flipped {
            if central_opcode == op::BOOL_AND && opc0 == op::BOOL_AND && opc1 == op::BOOL_AND {
                let false_value = data.new_constant(0, 1);
                data.op_set_opcode(id, op::COPY);
                data.op_set_inputs(id, vec![false_value]);
                return 1;
            }
            if central_opcode == op::BOOL_OR && opc0 == op::BOOL_OR && opc1 == op::BOOL_OR {
                let true_value = data.new_constant(1, 1);
                data.op_set_opcode(id, op::COPY);
                data.op_set_inputs(id, vec![true_value]);
                return 1;
            }
            if central_opcode == op::BOOL_OR && opc0 != opc1 {
                let common = if opc0 == op::BOOL_OR { left_a } else { right_a };
                (op::BOOL_OR, op::BOOL_OR, common)
            } else {
                return 0;
            }
        } else if central_opcode == opc0 && central_opcode == opc1 {
            (central_opcode, central_opcode, left_a)
        } else if opc0 == opc1 && central_opcode != opc0 {
            (opc0, central_opcode, left_a)
        } else {
            return 0;
        };

        let (_, temporary) = new_op_before(data, id, branch_opcode, vec![left_o, right_o], 1);
        data.op_set_opcode(id, final_opcode);
        data.op_set_inputs(id, vec![final_a, temporary]);
        let _ = right_a;
        1
    }
}

pub struct RuleBxor2NotEqual;

impl Rule for RuleBxor2NotEqual {
    fn name(&self) -> &'static str {
        "bxor2notequal"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::BOOL_XOR]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        data.op_set_opcode(id, op::INT_NOTEQUAL);
        1
    }
}

pub struct RuleOrCompare;

impl Rule for RuleOrCompare {
    fn name(&self) -> &'static str {
        "orcompare"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_OR]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(out) = data.op(id).output else {
            return 0;
        };
        let descendants: Vec<OpId> = data.varnode(out).descendants.iter().copied().collect();
        if descendants.is_empty() {
            return 0;
        }
        for compare in &descendants {
            let code = data.op(*compare).opcode;
            if !matches!(code, op::INT_EQUAL | op::INT_NOTEQUAL)
                || input(data, *compare, 1).is_none_or(|value| {
                    !is_constant(data, value) || data.varnode(value).offset != 0
                })
            {
                return 0;
            }
        }
        let Some(left) = input(data, id, 0) else {
            return 0;
        };
        let Some(right) = input(data, id, 1) else {
            return 0;
        };
        if is_free(data, left) || is_free(data, right) {
            return 0;
        }
        let left_size = data.varnode(left).size;
        let right_size = data.varnode(right).size;
        for compare in descendants {
            let code = data.op(compare).opcode;
            let left_zero = data.new_constant(0, left_size);
            let (_, left_bool) = new_op_before(data, compare, code, vec![left, left_zero], 1);
            let right_zero = data.new_constant(0, right_size);
            let (_, right_bool) = new_op_before(data, compare, code, vec![right, right_zero], 1);
            data.op_set_opcode(
                compare,
                if code == op::INT_EQUAL {
                    op::BOOL_AND
                } else {
                    op::BOOL_OR
                },
            );
            data.op_set_inputs(compare, vec![left_bool, right_bool]);
        }
        1
    }
}

fn replace_lessequal(id: OpId, data: &mut Funcdata) -> bool {
    let Some((left, right)) = inputs2(data, id) else {
        return false;
    };
    let (constant, slot, diff) = if is_constant(data, left) {
        (left, 0usize, -1i8)
    } else if is_constant(data, right) {
        (right, 1usize, 1i8)
    } else {
        return false;
    };
    let size = data.varnode(constant).size;
    let value = data.varnode(constant).offset;
    let code = data.op(id).opcode;
    let new_code = match code {
        op::INT_SLESSEQUAL => {
            let Some(sign) = sign_bit(size) else {
                return false;
            };
            let max = sign.wrapping_sub(1);
            if (diff < 0 && value == sign) || (diff > 0 && value == max) {
                return false;
            }
            op::INT_SLESS
        }
        op::INT_LESSEQUAL => {
            if (diff < 0 && value == 0) || (diff > 0 && value == mask(size)) {
                return false;
            }
            op::INT_LESS
        }
        _ => return false,
    };
    let new_value = if diff < 0 {
        value.wrapping_sub(1)
    } else {
        value.wrapping_add(1)
    } & mask(size);
    let replacement = data.new_constant(new_value, size);
    data.op_set_opcode(id, new_code);
    data.op_set_input(id, replacement, slot);
    true
}

pub struct RuleIntLessEqual;

impl Rule for RuleIntLessEqual {
    fn name(&self) -> &'static str {
        "intlessequal"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_LESSEQUAL, op::INT_SLESSEQUAL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        replace_lessequal(id, data) as usize
    }
}

pub struct RuleLessEqual;

impl Rule for RuleLessEqual {
    fn name(&self) -> &'static str {
        "lessequal"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::BOOL_OR]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(vn0) = input(data, id, 0) else {
            return 0;
        };
        let Some(vn1) = input(data, id, 1) else {
            return 0;
        };
        let Some(first_def) = def(data, vn0) else {
            return 0;
        };
        let first_code = data.op(first_def).opcode;
        let (less_op, equal_op) = if matches!(first_code, op::INT_LESS | op::INT_SLESS) {
            let Some(second_def) = def(data, vn1) else {
                return 0;
            };
            (first_def, second_def)
        } else {
            let Some(second_def) = def(data, vn1) else {
                return 0;
            };
            let second_code = data.op(second_def).opcode;
            if !matches!(second_code, op::INT_LESS | op::INT_SLESS) {
                return 0;
            }
            (second_def, first_def)
        };
        let less_code = data.op(less_op).opcode;
        let equal_code = data.op(equal_op).opcode;
        if !matches!(equal_code, op::INT_EQUAL | op::INT_NOTEQUAL) {
            return 0;
        }
        let Some(comp0) = input(data, less_op, 0) else {
            return 0;
        };
        let Some(comp1) = input(data, less_op, 1) else {
            return 0;
        };
        let Some(eq0) = input(data, equal_op, 0) else {
            return 0;
        };
        let Some(eq1) = input(data, equal_op, 1) else {
            return 0;
        };
        if !heritage_known(data, comp0) || !heritage_known(data, comp1) {
            return 0;
        }
        let same_order = varnode_same(data, comp0, eq0) && varnode_same(data, comp1, eq1);
        let swapped_order = varnode_same(data, comp0, eq1) && varnode_same(data, comp1, eq0);
        if !same_order && !swapped_order {
            return 0;
        }
        if equal_code == op::INT_NOTEQUAL {
            let Some(equal_output) = data.op(equal_op).output else {
                return 0;
            };
            data.op_set_opcode(id, op::COPY);
            data.op_set_inputs(id, vec![equal_output]);
        } else {
            data.op_set_opcode(
                id,
                if less_code == op::INT_SLESS {
                    op::INT_SLESSEQUAL
                } else {
                    op::INT_LESSEQUAL
                },
            );
            data.op_set_inputs(id, vec![comp0, comp1]);
        }
        1
    }
}

pub struct RuleSlessToLess;

impl Rule for RuleSlessToLess {
    fn name(&self) -> &'static str {
        "slesstoless"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_SLESS, op::INT_SLESSEQUAL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some((left, right)) = inputs2(data, id) else {
            return 0;
        };
        let size = data.varnode(left).size;
        let Some(sign) = sign_bit(size) else {
            return 0;
        };
        if nonzero_mask(data, left) & sign != 0 || nonzero_mask(data, right) & sign != 0 {
            return 0;
        }
        match data.op(id).opcode {
            op::INT_SLESS => data.op_set_opcode(id, op::INT_LESS),
            op::INT_SLESSEQUAL => data.op_set_opcode(id, op::INT_LESSEQUAL),
            _ => return 0,
        }
        1
    }
}

pub struct RuleShiftCompare;

impl Rule for RuleShiftCompare {
    fn name(&self) -> &'static str {
        "shiftcompare"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_EQUAL, op::INT_NOTEQUAL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(shift_value) = input(data, id, 0) else {
            return 0;
        };
        let Some(compare_constant) = input(data, id, 1) else {
            return 0;
        };
        if !is_constant(data, compare_constant) {
            return 0;
        }
        let Some(shift_op) = def(data, shift_value) else {
            return 0;
        };
        let shift_code = data.op(shift_op).opcode;
        let Some(shift_amount_vn) = input(data, shift_op, 1) else {
            return 0;
        };
        if !is_constant(data, shift_amount_vn) {
            return 0;
        }
        let (is_left, shift_amount) = match shift_code {
            op::INT_LEFT => (true, data.varnode(shift_amount_vn).offset),
            op::INT_RIGHT => {
                if data.lone_descend(shift_value) != Some(id) {
                    return 0;
                }
                (false, data.varnode(shift_amount_vn).offset)
            }
            op::INT_MULT => {
                let value = data.varnode(shift_amount_vn).offset;
                if value == 0 || !value.is_power_of_two() {
                    return 0;
                }
                (true, u64::from(value.trailing_zeros()))
            }
            op::INT_DIV => {
                let value = data.varnode(shift_amount_vn).offset;
                if value == 0 || !value.is_power_of_two() {
                    return 0;
                }
                if data.lone_descend(shift_value) != Some(id) {
                    return 0;
                }
                (false, u64::from(value.trailing_zeros()))
            }
            _ => return 0,
        };
        if shift_amount == 0 || shift_amount >= 64 {
            return 0;
        }
        let Some(main) = input(data, shift_op, 0) else {
            return 0;
        };
        if is_free(data, main) || data.varnode(main).size > 8 {
            return 0;
        }
        let compare_value = data.varnode(compare_constant).offset;
        let main_mask = nonzero_mask(data, main);
        let shifted_size = data.varnode(shift_value).size;
        let shifted_mask = mask(shifted_size);
        if is_left {
            let new_constant = shift_right(compare_value, shift_amount);
            if shift_left(new_constant, shift_amount) != compare_value {
                return 0;
            }
            let tmp = shift_left(main_mask, shift_amount) & shifted_mask;
            if shift_right(tmp, shift_amount) != main_mask {
                if data.lone_descend(shift_value) != Some(id) {
                    return 0;
                }
                let total_bits = u64::from(shifted_size).saturating_mul(8);
                if shift_amount >= total_bits {
                    return 0;
                }
                let remaining = total_bits - shift_amount;
                let new_mask = if remaining >= 64 {
                    u64::MAX
                } else {
                    (1u64 << remaining) - 1
                };
                let compare_size = data.varnode(compare_constant).size;
                let mask_value = data.new_constant(new_mask, compare_size);
                let (_, masked) = new_op_before(
                    data,
                    shift_op,
                    op::INT_AND,
                    vec![main, mask_value],
                    compare_size,
                );
                let adjusted_constant = data.new_constant(new_constant, compare_size);
                data.op_set_inputs(id, vec![masked, adjusted_constant]);
                return 1;
            }
            let compare_size = data.varnode(compare_constant).size;
            let adjusted_constant = data.new_constant(new_constant, compare_size);
            data.op_set_inputs(id, vec![main, adjusted_constant]);
        } else {
            if shift_left(shift_right(main_mask, shift_amount), shift_amount) != main_mask {
                return 0;
            }
            let new_constant = shift_left(compare_value, shift_amount) & shifted_mask;
            if shift_right(new_constant, shift_amount) != compare_value {
                return 0;
            }
            let compare_size = data.varnode(compare_constant).size;
            let adjusted_constant = data.new_constant(new_constant, compare_size);
            data.op_set_inputs(id, vec![main, adjusted_constant]);
        }
        1
    }
}

pub struct RuleTestSign;

impl Rule for RuleTestSign {
    fn name(&self) -> &'static str {
        "testsign"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_SRIGHT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(shift_amount) = input(data, id, 1) else {
            return 0;
        };
        if !is_constant(data, shift_amount) {
            return 0;
        }
        let Some(main) = input(data, id, 0) else {
            return 0;
        };
        let expected = u64::from(data.varnode(main).size)
            .saturating_mul(8)
            .saturating_sub(1);
        if data.varnode(shift_amount).offset != expected || is_free(data, main) {
            return 0;
        }
        let Some(out) = data.op(id).output else {
            return 0;
        };
        let comparisons: Vec<OpId> = data.varnode(out).descendants.iter().copied().collect();
        let mut changed = 0;
        for compare in comparisons {
            let code = data.op(compare).opcode;
            if !matches!(code, op::INT_EQUAL | op::INT_NOTEQUAL) {
                continue;
            }
            let Some(compare_constant) = input(data, compare, 1) else {
                continue;
            };
            if !is_constant(data, compare_constant) {
                continue;
            }
            let compare_size = data.varnode(input(data, compare, 0).unwrap_or(main)).size;
            let compare_value = data.varnode(compare_constant).offset;
            let sign = if compare_value == 0 {
                1i8
            } else if compare_value == mask(compare_size) {
                -1i8
            } else {
                continue;
            };
            let sign = if code == op::INT_NOTEQUAL {
                -sign
            } else {
                sign
            };
            let zero = data.new_constant(0, data.varnode(main).size);
            if sign == 1 {
                data.op_set_inputs(compare, vec![zero, main]);
                data.op_set_opcode(compare, op::INT_SLESSEQUAL);
            } else {
                data.op_set_inputs(compare, vec![main, zero]);
                data.op_set_opcode(compare, op::INT_SLESS);
            }
            changed = 1;
        }
        changed
    }
}

#[derive(Copy, Clone)]
struct ThreeWayForm {
    less: OpId,
    partial: bool,
}

fn compare_equivalence(data: &Funcdata, less: OpId, less_equal: OpId) -> Option<(bool, bool)> {
    let less_code = data.op(less).opcode;
    let less_equal_code = data.op(less_equal).opcode;
    let mut two_less = match less_code {
        op::INT_LESS => match less_equal_code {
            op::INT_LESSEQUAL => false,
            op::INT_LESS => true,
            _ => return None,
        },
        op::INT_SLESS => match less_equal_code {
            op::INT_SLESSEQUAL => false,
            op::INT_SLESS => true,
            _ => return None,
        },
        op::FLOAT_LESS if less_equal_code == op::FLOAT_LESSEQUAL => false,
        _ => return None,
    };
    let mut swap = false;
    let pairs = [(0usize, 0usize), (1usize, 1usize)];
    for (left_slot, right_slot) in pairs {
        let (Some(left), Some(right)) = (
            input(data, less, left_slot),
            input(data, less_equal, right_slot),
        ) else {
            return None;
        };
        if varnode_same(data, left, right) {
            continue;
        }
        if !is_constant(data, left) || !is_constant(data, right) || !two_less {
            return None;
        }
        let left_value = data.varnode(left).offset;
        let right_value = data.varnode(right).offset;
        if right_value.wrapping_add(1) == left_value {
            two_less = false;
        } else if left_value.wrapping_add(1) == right_value {
            two_less = false;
            swap = true;
        } else {
            return None;
        }
    }
    if two_less { None } else { Some((swap, false)) }
}

fn detect_three_way(data: &Funcdata, root: OpId) -> Option<ThreeWayForm> {
    let (vn1, vn2) = inputs2(data, root)?;
    let mut partial = false;
    let (zext1, zext2) = if is_constant(data, vn2) {
        if data.varnode(vn2).offset != mask(data.varnode(vn2).size) {
            return None;
        }
        let addop = def(data, vn1)?;
        if data.op(addop).opcode != op::INT_ADD {
            return None;
        }
        (
            def(data, input(data, addop, 0)?)?,
            def(data, input(data, addop, 1)?)?,
        )
    } else if let Some(vn2_def) = def(data, vn2) {
        if data.op(vn2_def).opcode == op::INT_ZEXT {
            let zext2 = vn2_def;
            let add_input = input(data, root, 0)?;
            let addop = def(data, add_input)?;
            if data.op(addop).opcode != op::INT_ADD {
                if data.op(addop).opcode != op::INT_ZEXT {
                    return None;
                }
                partial = true;
                (addop, zext2)
            } else {
                let minus_one = input(data, addop, 1)?;
                if !is_constant(data, minus_one)
                    || data.varnode(minus_one).offset != mask(data.varnode(minus_one).size)
                {
                    return None;
                }
                (def(data, input(data, addop, 0)?)?, zext2)
            }
        } else if data.op(vn2_def).opcode == op::INT_ADD {
            let addop = vn2_def;
            let first_zext = def(data, vn1)?;
            if data.op(first_zext).opcode != op::INT_ZEXT {
                return None;
            }
            let minus_one = input(data, addop, 1)?;
            if !is_constant(data, minus_one)
                || data.varnode(minus_one).offset != mask(data.varnode(minus_one).size)
            {
                return None;
            }
            (first_zext, def(data, input(data, addop, 0)?)?)
        } else {
            return None;
        }
    } else {
        return None;
    };
    if data.op(zext1).opcode != op::INT_ZEXT || data.op(zext2).opcode != op::INT_ZEXT {
        return None;
    }
    let less_candidate = def(data, input(data, zext1, 0)?)?;
    let equal_candidate = def(data, input(data, zext2, 0)?)?;
    let (less, other) = if matches!(
        data.op(less_candidate).opcode,
        op::INT_LESS | op::INT_SLESS | op::FLOAT_LESS
    ) {
        (less_candidate, equal_candidate)
    } else {
        (equal_candidate, less_candidate)
    };
    let Some((swap, _)) = compare_equivalence(data, less, other) else {
        return None;
    };
    Some(ThreeWayForm {
        less: if swap { other } else { less },
        partial,
    })
}

pub struct RuleThreeWayCompare;

impl Rule for RuleThreeWayCompare {
    fn name(&self) -> &'static str {
        "threewaycompare"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![
            op::INT_SLESS,
            op::INT_SLESSEQUAL,
            op::INT_EQUAL,
            op::INT_NOTEQUAL,
        ]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let (mut const_slot, mut constant) = (0usize, input(data, id, 0));
        if constant.is_none_or(|value| !is_constant(data, value)) {
            const_slot = 1;
            constant = input(data, id, 1);
        }
        let Some(constant) = constant else {
            return 0;
        };
        if !is_constant(data, constant) {
            return 0;
        }
        let value = data.varnode(constant).offset;
        let mut form = if value <= 2 {
            value as i32 + 1
        } else if value == mask(data.varnode(constant).size) {
            0
        } else {
            return 0;
        };
        let Some(threeway_input) = input(data, id, 1 - const_slot) else {
            return 0;
        };
        let Some(threeway) = def(data, threeway_input) else {
            return 0;
        };
        if data.op(threeway).opcode != op::INT_ADD {
            return 0;
        }
        let Some(detected) = detect_three_way(data, threeway) else {
            return 0;
        };
        if detected.partial {
            if form == 0 {
                return 0;
            }
            form -= 1;
        }
        form <<= 1;
        if const_slot == 1 {
            form += 1;
        }
        let less = detected.less;
        let less_form = data.op(less).opcode;
        form <<= 2;
        match data.op(id).opcode {
            op::INT_SLESSEQUAL => form += 1,
            op::INT_EQUAL => form += 2,
            op::INT_NOTEQUAL => form += 3,
            op::INT_SLESS => {}
            _ => return 0,
        }
        let Some(less_first) = input(data, less, 0) else {
            return 0;
        };
        let Some(less_second) = input(data, less, 1) else {
            return 0;
        };
        let avn = less_second;
        let bvn = less_first;
        if (!is_constant(data, avn) && is_free(data, avn))
            || (!is_constant(data, bvn) && is_free(data, bvn))
        {
            return 0;
        }
        let set_compare = |data: &mut Funcdata, code: i32, left: VarnodeId, right: VarnodeId| {
            data.op_set_opcode(id, code);
            data.op_set_inputs(id, vec![left, right]);
        };
        match form {
            1 | 21 => {
                let one = data.new_constant(0, 1);
                data.op_set_opcode(id, op::INT_EQUAL);
                data.op_set_inputs(id, vec![one, one]);
            }
            4 | 16 => {
                let one = data.new_constant(0, 1);
                data.op_set_opcode(id, op::INT_NOTEQUAL);
                data.op_set_inputs(id, vec![one, one]);
            }
            2 | 5 | 6 | 12 => set_compare(data, less_form, avn, bvn),
            13 | 19 | 20 | 23 => {
                let code = match less_form {
                    op::INT_LESS => op::INT_LESSEQUAL,
                    op::INT_SLESS => op::INT_SLESSEQUAL,
                    op::FLOAT_LESS => op::FLOAT_LESSEQUAL,
                    _ => return 0,
                };
                set_compare(data, code, avn, bvn);
            }
            8 | 17 | 18 | 22 => set_compare(data, less_form, bvn, avn),
            0 | 3 | 7 | 9 => {
                let code = match less_form {
                    op::INT_LESS => op::INT_LESSEQUAL,
                    op::INT_SLESS => op::INT_SLESSEQUAL,
                    op::FLOAT_LESS => op::FLOAT_LESSEQUAL,
                    _ => return 0,
                };
                set_compare(data, code, bvn, avn);
            }
            10 | 14 => set_compare(
                data,
                if less_form == op::FLOAT_LESS {
                    op::FLOAT_EQUAL
                } else {
                    op::INT_EQUAL
                },
                avn,
                bvn,
            ),
            11 | 15 => set_compare(
                data,
                if less_form == op::FLOAT_LESS {
                    op::FLOAT_NOTEQUAL
                } else {
                    op::INT_NOTEQUAL
                },
                avn,
                bvn,
            ),
            _ => return 0,
        }
        1
    }
}

#[derive(Copy, Clone)]
enum BooleanResult {
    Value(VarnodeId),
    Constant(i32),
}

fn boolean_result(
    data: &Funcdata,
    mut value: VarnodeId,
    mut bit_pos: u32,
) -> Option<BooleanResult> {
    if bit_pos >= 64 {
        return None;
    }
    let mut bit_mask = 1u64 << bit_pos;
    loop {
        if is_constant(data, value) {
            return Some(BooleanResult::Constant(
                ((data.varnode(value).offset >> bit_pos) & 1) as i32,
            ));
        }
        let value_def = def(data, value)?;
        if bit_pos == 0 && data.varnode(value).size == 1 && nonzero_mask(data, value) == bit_mask {
            return Some(BooleanResult::Value(value));
        }
        let code = data.op(value_def).opcode;
        match code {
            op::INT_AND => {
                if !is_constant(data, input(data, value_def, 1)?) {
                    return None;
                }
                value = input(data, value_def, 0)?;
            }
            op::INT_XOR | op::INT_OR => {
                let left = input(data, value_def, 0)?;
                let right = input(data, value_def, 1)?;
                let left_has = nonzero_mask(data, left) & bit_mask != 0;
                let right_has = nonzero_mask(data, right) & bit_mask != 0;
                if left_has && right_has {
                    return None;
                }
                value = if left_has {
                    left
                } else if right_has {
                    right
                } else {
                    return None;
                };
            }
            op::INT_ZEXT | op::INT_SEXT => {
                value = input(data, value_def, 0)?;
                if bit_pos >= data.varnode(value).size.saturating_mul(8) {
                    return None;
                }
            }
            op::SUBPIECE => {
                let offset = data.varnode(input(data, value_def, 1)?).offset;
                let shift = offset.saturating_mul(8);
                if shift >= 64 || bit_pos.saturating_add(shift as u32) >= 64 {
                    return None;
                }
                bit_pos += shift as u32;
                bit_mask <<= shift;
                value = input(data, value_def, 0)?;
            }
            op::PIECE => {
                let high = input(data, value_def, 0)?;
                let low = input(data, value_def, 1)?;
                let low_bits = data.varnode(low).size.saturating_mul(8);
                if bit_pos >= low_bits {
                    value = high;
                    bit_pos -= low_bits;
                    bit_mask = if low_bits >= 64 {
                        0
                    } else {
                        bit_mask >> low_bits
                    };
                } else {
                    value = low;
                }
            }
            op::INT_LEFT => {
                let amount = data.varnode(input(data, value_def, 1)?).offset;
                if !is_constant(data, input(data, value_def, 1)?) || amount > u64::from(bit_pos) {
                    return None;
                }
                bit_pos -= amount as u32;
                bit_mask = if amount >= 64 { 0 } else { bit_mask >> amount };
                value = input(data, value_def, 0)?;
            }
            op::INT_RIGHT | op::INT_SRIGHT => {
                let amount_vn = input(data, value_def, 1)?;
                if !is_constant(data, amount_vn) {
                    return None;
                }
                let amount = data.varnode(amount_vn).offset;
                value = input(data, value_def, 0)?;
                bit_pos = bit_pos.saturating_add(amount as u32);
                if bit_pos >= data.varnode(value).size.saturating_mul(8) || amount >= 64 {
                    return None;
                }
                bit_mask <<= amount;
            }
            _ => return None,
        }
    }
}

pub struct RulePopcountBoolXor;

impl Rule for RulePopcountBoolXor {
    fn name(&self) -> &'static str {
        "popcountboolxor"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::POPCOUNT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(out) = data.op(id).output else {
            return 0;
        };
        let descendants: Vec<OpId> = data.varnode(out).descendants.iter().copied().collect();
        for base in descendants {
            if data.op(base).opcode != op::INT_AND {
                continue;
            }
            let Some(mask_vn) = input(data, base, 1) else {
                continue;
            };
            if !is_constant(data, mask_vn)
                || data.varnode(mask_vn).offset != 1
                || data.varnode(mask_vn).size != 1
            {
                continue;
            }
            let Some(source) = input(data, id, 0) else {
                return 0;
            };
            let count = nonzero_mask(data, source).count_ones();
            if count == 1 {
                let position = nonzero_mask(data, source).trailing_zeros();
                let Some(BooleanResult::Value(boolean)) = boolean_result(data, source, position)
                else {
                    continue;
                };
                data.op_set_opcode(base, op::COPY);
                data.op_set_inputs(base, vec![boolean]);
                return 1;
            }
            if count == 2 {
                let position0 = nonzero_mask(data, source).trailing_zeros();
                let position1 = 63 - nonzero_mask(data, source).leading_zeros();
                let first = boolean_result(data, source, position0);
                let second = boolean_result(data, source, position1);
                let (first, first_constant) = match first {
                    Some(BooleanResult::Value(value)) => (Some(value), -1),
                    Some(BooleanResult::Constant(value)) => (None, value),
                    None => (None, -1),
                };
                let (second, second_constant) = match second {
                    Some(BooleanResult::Value(value)) => (Some(value), -1),
                    Some(BooleanResult::Constant(value)) => (None, value),
                    None => (None, -1),
                };
                if (first.is_none() && first_constant != 1)
                    || (second.is_none() && second_constant != 1)
                    || (first.is_none() && second.is_none())
                {
                    continue;
                }
                let first = first.unwrap_or_else(|| data.new_constant(1, 1));
                let second = second.unwrap_or_else(|| data.new_constant(1, 1));
                data.op_set_opcode(base, op::INT_XOR);
                data.op_set_inputs(base, vec![first, second]);
                return 1;
            }
        }
        0
    }
}

pub struct RuleLzcountShiftBool;

impl Rule for RuleLzcountShiftBool {
    fn name(&self) -> &'static str {
        "lzcountshiftbool"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::LZCOUNT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(out) = data.op(id).output else {
            return 0;
        };
        let Some(source) = input(data, id, 0) else {
            return 0;
        };
        let max_return = u64::from(data.varnode(source).size).saturating_mul(8);
        if max_return == 0 || !max_return.is_power_of_two() {
            return 0;
        }
        let descendants: Vec<OpId> = data.varnode(out).descendants.iter().copied().collect();
        for base in descendants {
            if !matches!(data.op(base).opcode, op::INT_RIGHT | op::INT_SRIGHT) {
                continue;
            }
            let Some(shift_vn) = input(data, base, 1) else {
                continue;
            };
            if !is_constant(data, shift_vn) {
                continue;
            }
            let shift = data.varnode(shift_vn).offset;
            if shift >= 64 || (max_return >> shift) != 1 {
                continue;
            }
            let source_size = data.varnode(source).size;
            let zero = data.new_constant(0, source_size);
            let (_, equal_result) = new_op_before(data, base, op::INT_EQUAL, vec![source, zero], 1);
            let base_output_size = data
                .op(base)
                .output
                .map_or(1, |value| data.varnode(value).size);
            data.op_set_inputs(base, vec![equal_result]);
            data.op_set_opcode(
                base,
                if base_output_size == 1 {
                    op::COPY
                } else {
                    op::INT_ZEXT
                },
            );
            return 1;
        }
        0
    }
}

pub struct RuleNegateNegate;

impl Rule for RuleNegateNegate {
    fn name(&self) -> &'static str {
        "negatenegate"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_NEGATE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(first) = input(data, id, 0) else {
            return 0;
        };
        let Some(inner) = def(data, first) else {
            return 0;
        };
        if data.op(inner).opcode != op::INT_NEGATE {
            return 0;
        }
        let Some(source) = input(data, inner, 0) else {
            return 0;
        };
        if is_free(data, source) {
            return 0;
        }
        data.op_set_inputs(id, vec![source]);
        data.op_set_opcode(id, op::COPY);
        1
    }
}

#[cfg(test)]
mod tests {
    use super::super::SeqNum;
    use super::*;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }
    use ventris_lifter::REGISTER_SPACE;
    use ventris_pcode::op;

    fn input_value(data: &mut Funcdata, size: u32) -> VarnodeId {
        let value = data.new_varnode(REGISTER_SPACE, data.varnode_count() as u64 * 8, size);
        data.mark_input(value);
        value
    }

    fn binary(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        opcode: i32,
        left: VarnodeId,
        right: VarnodeId,
        output_size: u32,
    ) -> (OpId, VarnodeId) {
        let id = data.new_op(
            opcode,
            seq(0x1000 + data.op_count() as u64 * 4),
            vec![left, right],
        );
        let output = data.new_unique(output_size);
        data.op_set_output(id, Some(output));
        data.op_insert_end(id, block);
        (id, output)
    }

    fn unary(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        opcode: i32,
        value: VarnodeId,
        output_size: u32,
    ) -> (OpId, VarnodeId) {
        let id = data.new_op(
            opcode,
            seq(0x1000 + data.op_count() as u64 * 4),
            vec![value],
        );
        let output = data.new_unique(output_size);
        data.op_set_output(id, Some(output));
        data.op_insert_end(id, block);
        (id, output)
    }

    #[test]
    fn boolean_dedup_fires_and_declines_without_shared_clause() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let a = input_value(&mut data, 1);
        let b = input_value(&mut data, 1);
        let c = input_value(&mut data, 1);
        let (_, left) = binary(&mut data, block, op::BOOL_AND, a, b, 1);
        let (_, right) = binary(&mut data, block, op::BOOL_AND, a, c, 1);
        let (outer, _) = binary(&mut data, block, op::BOOL_OR, left, right, 1);
        assert_eq!(RuleBooleanDedup.apply_op(outer, &mut data), 1);
        assert_eq!(data.op(outer).opcode, op::BOOL_AND);
        assert_eq!(
            data.varnode(data.op(outer).inputs[1])
                .def
                .map(|id| data.op(id).opcode),
            Some(op::BOOL_OR)
        );

        let d = input_value(&mut data, 1);
        let (_, right_bad) = binary(&mut data, block, op::BOOL_AND, c, d, 1);
        let (bad, _) = binary(&mut data, block, op::BOOL_OR, left, right_bad, 1);
        assert_eq!(RuleBooleanDedup.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn boolean_undistribute_fires_and_declines_without_common_term() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let a = input_value(&mut data, 1);
        let b = input_value(&mut data, 1);
        let c = input_value(&mut data, 1);
        let (_, left) = binary(&mut data, block, op::BOOL_OR, a, b, 1);
        let (_, right) = binary(&mut data, block, op::BOOL_OR, a, c, 1);
        let (outer, _) = binary(&mut data, block, op::INT_EQUAL, left, right, 1);
        assert_eq!(RuleBooleanUndistribute.apply_op(outer, &mut data), 1);
        assert_eq!(data.op(outer).opcode, op::BOOL_OR);
        let d = input_value(&mut data, 1);
        let (_, right_bad) = binary(&mut data, block, op::BOOL_OR, c, d, 1);
        let (bad, _) = binary(&mut data, block, op::INT_EQUAL, left, right_bad, 1);
        assert_eq!(RuleBooleanUndistribute.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn bxor_to_notequal_always_retypes_boolean_xor() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let a = input_value(&mut data, 1);
        let b = input_value(&mut data, 1);
        let (xor, _) = binary(&mut data, block, op::BOOL_XOR, a, b, 1);
        assert_eq!(RuleBxor2NotEqual.apply_op(xor, &mut data), 1);
        assert_eq!(data.op(xor).opcode, op::INT_NOTEQUAL);
    }

    #[test]
    fn or_compare_fires_and_declines_for_nonzero_comparison() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let a = input_value(&mut data, 4);
        let b = input_value(&mut data, 4);
        let (joined_op, joined) = binary(&mut data, block, op::INT_OR, a, b, 4);
        let zero = data.new_constant(0, 4);
        let (compare, _) = binary(&mut data, block, op::INT_EQUAL, joined, zero, 1);
        assert_eq!(RuleOrCompare.apply_op(joined_op, &mut data), 1);
        assert_eq!(data.op(compare).opcode, op::BOOL_AND);

        let (joined_bad_op, joined_bad) = binary(&mut data, block, op::INT_OR, a, b, 4);
        let one = data.new_constant(1, 4);
        let (bad, _) = binary(&mut data, block, op::INT_EQUAL, joined_bad, one, 1);
        assert_eq!(RuleOrCompare.apply_op(joined_bad_op, &mut data), 0);
        assert_eq!(data.op(bad).opcode, op::INT_EQUAL);
    }

    #[test]
    fn int_less_equal_replaces_constant_boundary_and_declines_overflow() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let constant = data.new_constant(7, 4);
        let (compare, _) = binary(&mut data, block, op::INT_LESSEQUAL, value, constant, 1);
        assert_eq!(RuleIntLessEqual.apply_op(compare, &mut data), 1);
        assert_eq!(data.op(compare).opcode, op::INT_LESS);
        assert_eq!(data.varnode(data.op(compare).inputs[1]).offset, 8);

        let max = data.new_constant(u32::MAX as u64, 4);
        let (bad, _) = binary(&mut data, block, op::INT_LESSEQUAL, value, max, 1);
        assert_eq!(RuleIntLessEqual.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn less_equal_combines_matching_less_and_equal() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let a = input_value(&mut data, 4);
        let b = input_value(&mut data, 4);
        let (_, less) = binary(&mut data, block, op::INT_LESS, a, b, 1);
        let (_, equal) = binary(&mut data, block, op::INT_EQUAL, a, b, 1);
        let (outer, _) = binary(&mut data, block, op::BOOL_OR, less, equal, 1);
        assert_eq!(RuleLessEqual.apply_op(outer, &mut data), 1);
        assert_eq!(data.op(outer).opcode, op::INT_LESSEQUAL);

        let c = input_value(&mut data, 4);
        let (_, bad_equal) = binary(&mut data, block, op::INT_EQUAL, a, c, 1);
        let (bad, _) = binary(&mut data, block, op::BOOL_OR, less, bad_equal, 1);
        assert_eq!(RuleLessEqual.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn sless_to_less_uses_nonzero_masks_and_declines_possible_sign() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let positive = data.new_constant(3, 4);
        let other = data.new_constant(9, 4);
        let (compare, _) = binary(&mut data, block, op::INT_SLESS, positive, other, 1);
        assert_eq!(RuleSlessToLess.apply_op(compare, &mut data), 1);
        assert_eq!(data.op(compare).opcode, op::INT_LESS);

        let input = input_value(&mut data, 4);
        let (bad, _) = binary(&mut data, block, op::INT_SLESS, input, other, 1);
        assert_eq!(RuleSlessToLess.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn shift_compare_moves_right_shift_and_declines_zero_shift() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let source = input_value(&mut data, 4);
        let one = data.new_constant(1, 4);
        let (_, shifted_source) = binary(&mut data, block, op::INT_LEFT, source, one, 4);
        let (_, shifted) = binary(&mut data, block, op::INT_RIGHT, shifted_source, one, 4);
        let target = data.new_constant(3, 4);
        let (compare, _) = binary(&mut data, block, op::INT_EQUAL, shifted, target, 1);
        assert_eq!(RuleShiftCompare.apply_op(compare, &mut data), 1);
        assert_eq!(data.op(compare).inputs[0], shifted_source);
        assert_eq!(data.varnode(data.op(compare).inputs[1]).offset, 6);

        let zero = data.new_constant(0, 4);
        let (_, shifted_zero) = binary(&mut data, block, op::INT_RIGHT, source, zero, 4);
        let (bad, _) = binary(&mut data, block, op::INT_EQUAL, shifted_zero, target, 1);
        assert_eq!(RuleShiftCompare.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn test_sign_rewrites_sign_bit_comparisons_and_declines_wrong_shift() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let sign_shift = data.new_constant(31, 4);
        let (shift, shifted) = binary(&mut data, block, op::INT_SRIGHT, value, sign_shift, 4);
        let zero = data.new_constant(0, 4);
        let (compare, _) = binary(&mut data, block, op::INT_NOTEQUAL, shifted, zero, 1);
        assert_eq!(RuleTestSign.apply_op(shift, &mut data), 1);
        assert_eq!(data.op(compare).opcode, op::INT_SLESS);

        let wrong = data.new_constant(30, 4);
        let (bad_shift, bad_out) = binary(&mut data, block, op::INT_SRIGHT, value, wrong, 4);
        let (_, _) = binary(&mut data, block, op::INT_EQUAL, bad_out, zero, 1);
        assert_eq!(RuleTestSign.apply_op(bad_shift, &mut data), 0);
    }

    #[test]
    fn three_way_compare_rewrites_secondary_compare_and_declines_bad_constant() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let a = input_value(&mut data, 4);
        let b = input_value(&mut data, 4);
        let (_, less) = binary(&mut data, block, op::INT_SLESS, a, b, 1);
        let (_, less_equal) = binary(&mut data, block, op::INT_SLESSEQUAL, a, b, 1);
        let (_, less_wide) = unary(&mut data, block, op::INT_ZEXT, less, 4);
        let (_, less_equal_wide) = unary(&mut data, block, op::INT_ZEXT, less_equal, 4);
        let (_, sum) = binary(&mut data, block, op::INT_ADD, less_wide, less_equal_wide, 4);
        let minus_one = data.new_constant(u32::MAX as u64, 4);
        let (_, three_way) = binary(&mut data, block, op::INT_ADD, sum, minus_one, 4);
        let zero = data.new_constant(0, 4);
        let (compare, _) = binary(&mut data, block, op::INT_SLESSEQUAL, three_way, zero, 1);
        assert_eq!(RuleThreeWayCompare.apply_op(compare, &mut data), 1);
        assert_eq!(data.op(compare).opcode, op::INT_SLESSEQUAL);
        assert_eq!(data.op(compare).inputs[0], b);
        assert_eq!(data.op(compare).inputs[1], a);

        let invalid = data.new_constant(3, 4);
        let (bad, _) = binary(&mut data, block, op::INT_SLESSEQUAL, three_way, invalid, 1);
        assert_eq!(RuleThreeWayCompare.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn popcount_bool_xor_rewrites_two_shifted_bits_and_declines_wrong_mask() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let raw1 = input_value(&mut data, 1);
        let raw2 = input_value(&mut data, 1);
        let (_, b1) = unary(&mut data, block, op::BOOL_NEGATE, raw1, 1);
        let (_, b2) = unary(&mut data, block, op::BOOL_NEGATE, raw2, 1);
        let six = data.new_constant(6, 1);
        let two = data.new_constant(2, 1);
        let (_, left) = binary(&mut data, block, op::INT_LEFT, b1, six, 1);
        let (_, right) = binary(&mut data, block, op::INT_LEFT, b2, two, 1);
        let (_, joined) = binary(&mut data, block, op::INT_OR, left, right, 1);
        let (popcount, pop) = unary(&mut data, block, op::POPCOUNT, joined, 1);
        let one = data.new_constant(1, 1);
        let (base, _) = binary(&mut data, block, op::INT_AND, pop, one, 1);
        assert_eq!(RulePopcountBoolXor.apply_op(popcount, &mut data), 1);
        assert_eq!(data.op(base).opcode, op::INT_XOR);

        let two_mask = data.new_constant(2, 1);
        let (bad, _) = binary(&mut data, block, op::INT_AND, pop, two_mask, 1);
        assert_eq!(RulePopcountBoolXor.apply_op(popcount, &mut data), 0);
        assert_eq!(data.op(bad).opcode, op::INT_AND);
    }

    #[test]
    fn lzcount_shift_bool_rewrites_power_of_two_width_and_declines_other_shift() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let (lzcount, lz) = unary(&mut data, block, op::LZCOUNT, value, 4);
        let shift = data.new_constant(5, 4);
        let (right, _shifted) = binary(&mut data, block, op::INT_RIGHT, lz, shift, 4);
        assert_eq!(RuleLzcountShiftBool.apply_op(lzcount, &mut data), 1);
        assert_eq!(data.op(right).opcode, op::INT_ZEXT);
        let equal = data
            .varnode(data.op(right).inputs[0])
            .def
            .expect("new equality");
        assert_eq!(data.op(equal).opcode, op::INT_EQUAL);

        let bad_shift = data.new_constant(4, 4);
        let (bad_right, _) = binary(&mut data, block, op::INT_RIGHT, lz, bad_shift, 4);
        assert_eq!(RuleLzcountShiftBool.apply_op(lzcount, &mut data), 0);
        assert_eq!(data.op(bad_right).opcode, op::INT_RIGHT);
    }

    #[test]
    fn negate_negate_collapses_and_declines_free_source() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let (_, first_out) = unary(&mut data, block, op::INT_NEGATE, value, 4);
        let (outer, _) = unary(&mut data, block, op::INT_NEGATE, first_out, 4);
        assert_eq!(RuleNegateNegate.apply_op(outer, &mut data), 1);
        assert_eq!(data.op(outer).opcode, op::COPY);
        assert_eq!(data.op(outer).inputs[0], value);

        let free = data.new_varnode(ventris_lifter::REGISTER_SPACE, 0x400, 4);
        let (_, free_first) = unary(&mut data, block, op::INT_NEGATE, free, 4);
        let (bad, _) = unary(&mut data, block, op::INT_NEGATE, free_first, 4);
        assert_eq!(RuleNegateNegate.apply_op(bad, &mut data), 0);
    }
}

pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(RuleBooleanDedup),
        Box::new(RuleBooleanUndistribute),
        Box::new(RuleBxor2NotEqual),
        Box::new(RuleOrCompare),
        Box::new(RuleIntLessEqual),
        Box::new(RuleLessEqual),
        Box::new(RuleSlessToLess),
        Box::new(RuleShiftCompare),
        Box::new(RuleTestSign),
        Box::new(RuleThreeWayCompare),
        Box::new(RulePopcountBoolXor),
        Box::new(RuleLzcountShiftBool),
        Box::new(RuleNegateNegate),
    ]
}
