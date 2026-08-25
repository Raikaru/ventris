//! Floating-point expression rewrites from Ghidra 12.1.3's `ruleaction.cc`.
//!
//! The implementations below follow the real `Rule*::applyOp` bodies in the
//! pinned C++ source.  The graph has no architecture object, so
//! `RuleIgnoreNan` is intentionally omitted: its first and most important
//! branch is controlled by `Architecture::nan_ignore_all`, and assuming a
//! value would change NaN semantics.  `RuleFloatSignCleanup` reconstructs the
//! one type fact it needs through the graph's bounded type inference rather
//! than treating every integer bit operation as a float.
//!
//! All requested p-code names used here (`BOOL_AND`, `BOOL_OR`, the floating
//! comparisons/arithmetic/conversions, `FLOAT_NAN`, `INT_AND`, `INT_OR`,
//! `INT_RIGHT`, `INT_ZEXT`, `SUBPIECE`, and `MULTIEQUAL`) are present in
//! `ventris_pcode::op`.

use std::collections::{BTreeMap, BTreeSet};

use super::action::Rule;
use super::typefactory::{DataType, TypeFactory, infer};
use super::{Funcdata, GraphBlockId, OpId, VarnodeId};
use ventris_pcode::op;

fn input(data: &Funcdata, id: OpId, slot: usize) -> Option<VarnodeId> {
    data.op(id).inputs.get(slot).copied()
}

fn output(data: &Funcdata, id: OpId) -> Option<VarnodeId> {
    data.op(id).output
}

fn def(data: &Funcdata, value: VarnodeId) -> Option<OpId> {
    data.varnode(value)
        .def
        .filter(|candidate| data.opcode_of(*candidate).is_some())
}

fn is_constant(data: &Funcdata, value: VarnodeId) -> bool {
    data.varnode(value).flags.constant
}

fn constant_value(data: &Funcdata, value: VarnodeId) -> Option<u64> {
    is_constant(data, value).then(|| data.varnode(value).offset)
}

/// Exact graph equivalent of Ghidra's `Varnode::isFree` for these rules.
fn is_free(data: &Funcdata, value: VarnodeId) -> bool {
    let node = data.varnode(value);
    !node.flags.written && !node.flags.input
}

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

/// `TypeOpFloatInt2Float::preferredZextSize` from `typeop.cc`.
fn preferred_zext_size(input_size: u32) -> u32 {
    if input_size < 4 {
        4
    } else if input_size < 8 {
        8
    } else {
        input_size.saturating_add(1)
    }
}

/// Return the float operation equivalent to a sign-bit integer manipulation.
///
/// This is the exact `TypeOp::floatSignManipulation` test: the constant is
/// the complete value mask with either the sign bit cleared (`ABS`) or flipped
/// (`NEG`).
fn float_sign_manipulation(data: &Funcdata, id: OpId) -> Option<i32> {
    let code = data.op(id).opcode;
    let constant = input(data, id, 1).and_then(|value| constant_value(data, value))?;
    let size = input(data, id, 1).map(|value| data.varnode(value).size)?;
    let full = mask(size);
    match code {
        op::INT_AND if constant == (full >> 1) => Some(op::FLOAT_ABS),
        op::INT_XOR if constant == (full ^ (full >> 1)) => Some(op::FLOAT_NEG),
        _ => None,
    }
}

fn is_float_bool_output(code: i32) -> bool {
    matches!(
        code,
        op::FLOAT_EQUAL | op::FLOAT_NOTEQUAL | op::FLOAT_LESS | op::FLOAT_LESSEQUAL | op::FLOAT_NAN
    )
}

/// Infer whether a value is floating-point in the same graph state seen by a
/// type-dependent rule.  The type factory starts storage values as integers,
/// then propagates FLOAT operations backwards through their inputs.
fn is_inferred_float(data: &Funcdata, value: VarnodeId) -> bool {
    let factory = TypeFactory::new(64);
    let types = infer(data, &factory, &BTreeMap::new());
    matches!(types.get(value), Some(DataType::Float(_)))
}

/// Port of `RuleFloatRange`.
///
/// `(V f< W) || (V f== W) -> V f<= W`, and
/// `(V f<= W) && (V f!= W) -> V f< W`, including the operand/constant
/// orientations accepted by the C++ implementation.
pub struct RuleFloatRange;

impl Rule for RuleFloatRange {
    fn name(&self) -> &'static str {
        "floatrange"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::BOOL_OR, op::BOOL_AND]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(vn1) = input(data, id, 0) else {
            return 0;
        };
        let Some(vn2) = input(data, id, 1) else {
            return 0;
        };
        let Some(mut cmp1) = def(data, vn1) else {
            return 0;
        };
        let Some(mut cmp2) = def(data, vn2) else {
            return 0;
        };

        let mut cmp1_code = data.op(cmp1).opcode;
        if !matches!(cmp1_code, op::FLOAT_LESS | op::FLOAT_LESSEQUAL) {
            std::mem::swap(&mut cmp1, &mut cmp2);
            cmp1_code = data.op(cmp1).opcode;
        }
        let result = match (cmp1_code, data.op(cmp2).opcode, data.op(id).opcode) {
            (op::FLOAT_LESS, op::FLOAT_EQUAL, op::BOOL_OR) => op::FLOAT_LESSEQUAL,
            (op::FLOAT_LESSEQUAL, op::FLOAT_NOTEQUAL, op::BOOL_AND) => op::FLOAT_LESS,
            _ => return 0,
        };

        let Some(cmp1_left) = input(data, cmp1, 0) else {
            return 0;
        };
        let Some(cmp1_right) = input(data, cmp1, 1) else {
            return 0;
        };
        let (slot1, nvn1) = if is_constant(data, cmp1_left) {
            if is_constant(data, cmp1_right) {
                return 0;
            }
            (1, cmp1_right)
        } else {
            (0, cmp1_left)
        };
        if is_free(data, nvn1) {
            return 0;
        }
        let cvn1 = if slot1 == 0 { cmp1_right } else { cmp1_left };

        let Some(cmp2_left) = input(data, cmp2, 0) else {
            return 0;
        };
        let Some(cmp2_right) = input(data, cmp2, 1) else {
            return 0;
        };
        let (slot2, matchvn) = if nvn1 == cmp2_left {
            (0, cmp2_right)
        } else if nvn1 == cmp2_right {
            (1, cmp2_left)
        } else {
            return 0;
        };
        let _ = slot2;
        if is_constant(data, cvn1) {
            if !is_constant(data, matchvn)
                || data.varnode(matchvn).offset != data.varnode(cvn1).offset
            {
                return 0;
            }
        } else if cvn1 != matchvn || is_free(data, cvn1) {
            return 0;
        }

        let replacement = if is_constant(data, cvn1) {
            data.new_constant(data.varnode(cvn1).offset, data.varnode(cvn1).size)
        } else {
            cvn1
        };
        data.op_set_opcode(id, result);
        if slot1 == 0 {
            data.op_set_inputs(id, vec![nvn1, replacement]);
        } else {
            data.op_set_inputs(id, vec![replacement, nvn1]);
        }
        1
    }
}

/// Port of `RuleFloatSign`.
///
/// A float operation identifies integer sign-bit manipulations by use, then
/// rewrites those defining operations.  It also looks through one level of
/// descendants, except for boolean outputs and FLOAT_TRUNC.
pub struct RuleFloatSign;

impl Rule for RuleFloatSign {
    fn name(&self) -> &'static str {
        "floatsign"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![
            op::FLOAT_EQUAL,
            op::FLOAT_NOTEQUAL,
            op::FLOAT_LESS,
            op::FLOAT_LESSEQUAL,
            op::FLOAT_NAN,
            op::FLOAT_ADD,
            op::FLOAT_DIV,
            op::FLOAT_MULT,
            op::FLOAT_SUB,
            op::FLOAT_NEG,
            op::FLOAT_ABS,
            op::FLOAT_SQRT,
            op::FLOAT_FLOAT2FLOAT,
            op::FLOAT_CEIL,
            op::FLOAT_FLOOR,
            op::FLOAT_ROUND,
            op::FLOAT_INT2FLOAT,
            op::FLOAT_TRUNC,
        ]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let current_code = data.op(id).opcode;
        let mut changed = 0;
        if current_code != op::FLOAT_INT2FLOAT {
            let slots = if data.op(id).inputs.len() == 2 {
                vec![0, 1]
            } else {
                vec![0]
            };
            for slot in slots {
                let Some(value) = input(data, id, slot) else {
                    continue;
                };
                let Some(sign_op) = def(data, value) else {
                    continue;
                };
                let Some(replacement) = float_sign_manipulation(data, sign_op) else {
                    continue;
                };
                let Some(source) = input(data, sign_op, 0) else {
                    continue;
                };
                data.op_set_opcode(sign_op, replacement);
                data.op_set_inputs(sign_op, vec![source]);
                changed = 1;
            }
        }

        if is_float_bool_output(current_code) || current_code == op::FLOAT_TRUNC {
            return changed;
        }
        let Some(value) = output(data, id) else {
            return changed;
        };
        let descendants: Vec<OpId> = data.varnode(value).descendants.iter().copied().collect();
        for reader in descendants {
            let Some(replacement) = float_sign_manipulation(data, reader) else {
                continue;
            };
            let Some(source) = input(data, reader, 0) else {
                continue;
            };
            data.op_set_opcode(reader, replacement);
            data.op_set_inputs(reader, vec![source]);
            changed = 1;
        }
        changed
    }
}

/// Port of `RuleFloatSignCleanup`.
///
/// Unlike `RuleFloatSign`, this rule is offered directly on INT_AND/INT_XOR
/// and requires the result's recovered type to be Float.
pub struct RuleFloatSignCleanup;

impl Rule for RuleFloatSignCleanup {
    fn name(&self) -> &'static str {
        "floatsigncleanup"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_AND, op::INT_XOR]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(value) = output(data, id) else {
            return 0;
        };
        if !is_inferred_float(data, value) {
            return 0;
        }
        let Some(replacement) = float_sign_manipulation(data, id) else {
            return 0;
        };
        let Some(source) = input(data, id, 0) else {
            return 0;
        };
        data.op_set_opcode(id, replacement);
        data.op_set_inputs(id, vec![source]);
        1
    }
}

/// Port of `RuleUnsigned2Float`.
///
/// Recognizes the software unsigned-conversion idiom and folds the duplicated
/// converted value into one zero-extension followed by FLOAT_INT2FLOAT.
pub struct RuleUnsigned2Float;

impl Rule for RuleUnsigned2Float {
    fn name(&self) -> &'static str {
        "unsigned2float"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::FLOAT_INT2FLOAT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(invn) = input(data, id, 0) else {
            return 0;
        };
        let Some(orop) = def(data, invn) else {
            return 0;
        };
        if data.op(orop).opcode != op::INT_OR {
            return 0;
        }
        let Some(or_left) = input(data, orop, 0) else {
            return 0;
        };
        let Some(or_right) = input(data, orop, 1) else {
            return 0;
        };
        if !data.varnode(or_left).flags.written || !data.varnode(or_right).flags.written {
            return 0;
        }

        let Some(mut shiftop) = def(data, or_left) else {
            return 0;
        };
        let mut andop;
        if data.op(shiftop).opcode != op::INT_RIGHT {
            andop = shiftop;
            let Some(candidate) = def(data, or_right) else {
                return 0;
            };
            shiftop = candidate;
        } else {
            let Some(candidate) = def(data, or_right) else {
                return 0;
            };
            andop = candidate;
        }
        if data.op(shiftop).opcode != op::INT_RIGHT {
            return 0;
        }
        let Some(shift_amount) = input(data, shiftop, 1) else {
            return 0;
        };
        if constant_value(data, shift_amount) != Some(1) {
            return 0;
        }
        let Some(basevn) = input(data, shiftop, 0) else {
            return 0;
        };
        if is_free(data, basevn) {
            return 0;
        }

        if data.op(andop).opcode == op::INT_ZEXT {
            let Some(and_input) = input(data, andop, 0) else {
                return 0;
            };
            let Some(inner) = def(data, and_input) else {
                return 0;
            };
            andop = inner;
        }
        if data.op(andop).opcode != op::INT_AND {
            return 0;
        }
        let Some(and_amount) = input(data, andop, 1) else {
            return 0;
        };
        if constant_value(data, and_amount) != Some(1) {
            return 0;
        }
        let Some(mut vn) = input(data, andop, 0) else {
            return 0;
        };
        if basevn != vn {
            let Some(subop) = def(data, vn) else {
                return 0;
            };
            if data.op(subop).opcode != op::SUBPIECE {
                return 0;
            }
            let Some(piece_offset) = input(data, subop, 1) else {
                return 0;
            };
            if data.varnode(piece_offset).offset != 0 {
                return 0;
            }
            let Some(piece_base) = input(data, subop, 0) else {
                return 0;
            };
            vn = piece_base;
            if basevn != vn {
                return 0;
            }
        }

        let Some(outvn) = output(data, id) else {
            return 0;
        };
        let descendants: Vec<OpId> = data.varnode(outvn).descendants.iter().copied().collect();
        for addop in descendants {
            if data.opcode_of(addop) != Some(op::FLOAT_ADD)
                || input(data, addop, 0) != Some(outvn)
                || input(data, addop, 1) != Some(outvn)
            {
                continue;
            }
            let seq = data.op(addop).seq;
            let zextop = data.new_op(op::INT_ZEXT, seq, vec![basevn]);
            let zextout = data.new_unique(preferred_zext_size(data.varnode(basevn).size));
            data.op_set_output(zextop, Some(zextout));
            data.op_set_opcode(addop, op::FLOAT_INT2FLOAT);
            data.op_set_inputs(addop, vec![zextout]);
            data.op_insert_before(zextop, addop);
            return 1;
        }
        0
    }
}

/// Find the conditional block that controls two incoming paths to a join.
///
/// This is the graph-facing equivalent of `FlowBlock::findCondition`.  The
/// graph stores predecessor slots, so the walk can preserve the MULTIEQUAL
/// input-to-edge relationship.  The branch target is also checked below to
/// recover the unflipped true direction from the p-code CBRANCH itself.
fn find_condition(
    data: &Funcdata,
    join: GraphBlockId,
    first_slot: usize,
    second_slot: usize,
) -> Option<(GraphBlockId, usize)> {
    let mut first_block = join;
    let first_edge = first_slot;
    let mut condition = *data.block(first_block).predecessors.get(first_edge)?;
    let mut seen = BTreeSet::new();
    while data.block(condition).successors.len() != 2 {
        if data.block(condition).successors.len() != 1 || !seen.insert(condition) {
            return None;
        }
        first_block = condition;
        condition = *data.block(first_block).predecessors.first()?;
    }

    let mut second_block = join;
    let mut second = *data.block(second_block).predecessors.get(second_slot)?;
    let mut seen_second = BTreeSet::new();
    while condition != second {
        if !seen_second.insert(second) || data.block(second).successors.len() != 1 {
            return None;
        }
        second_block = second;
        second = *data.block(second_block).predecessors.first()?;
    }
    let branch_slot = data
        .block(condition)
        .successors
        .iter()
        .position(|successor| *successor == first_block)?;
    Some((condition, branch_slot))
}

fn branch_taken_slot(data: &Funcdata, condition: GraphBlockId, branch: OpId) -> Option<usize> {
    let target = input(data, branch, 0)?;
    let target_address = data.varnode(target).offset;
    data.block(condition)
        .successors
        .iter()
        .position(|successor| data.block(*successor).start == target_address)
}

/// Port of `RuleInt2FloatCollapse`.
///
/// The graph does not carry Ghidra's mutable block insertion cursor or the
/// C++ boolean-flip bit.  This port therefore follows the exact structural
/// condition path and accepts the raw, target-addressed CBRANCH representation
/// (which is the representation produced by this graph); it declines when a
/// path or target cannot be proven.
pub struct RuleInt2FloatCollapse;

impl Rule for RuleInt2FloatCollapse {
    fn name(&self) -> &'static str {
        "int2floatcollapse"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::FLOAT_INT2FLOAT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(unsigned_input) = input(data, id, 0) else {
            return 0;
        };
        let Some(zextop) = def(data, unsigned_input) else {
            return 0;
        };
        if data.op(zextop).opcode != op::INT_ZEXT {
            return 0;
        }
        let Some(basevn) = input(data, zextop, 0) else {
            return 0;
        };
        if is_free(data, basevn) {
            return 0;
        }

        let Some(unsigned_output) = output(data, id) else {
            return 0;
        };
        let Some(multiop) = data.lone_descend(unsigned_output) else {
            return 0;
        };
        if data.opcode_of(multiop) != Some(op::MULTIEQUAL) {
            return 0;
        }
        if data.op(multiop).inputs.len() != 2 {
            return 0;
        }
        let Some(slot) = data
            .op(multiop)
            .inputs
            .iter()
            .position(|value| *value == unsigned_output)
        else {
            return 0;
        };
        let other_output = data.op(multiop).inputs[1 - slot];
        let Some(other_op) = def(data, other_output) else {
            return 0;
        };
        if data.op(other_op).opcode != op::FLOAT_INT2FLOAT
            || input(data, other_op, 0) != Some(basevn)
        {
            return 0;
        }
        let Some(join) = data.op(multiop).parent else {
            return 0;
        };
        let Some((condition, unsigned_branch_slot)) = find_condition(data, join, slot, 1 - slot)
        else {
            return 0;
        };
        let Some(branch) = data
            .block(condition)
            .ops
            .iter()
            .rev()
            .copied()
            .find(|candidate| data.opcode_of(*candidate).is_some())
        else {
            return 0;
        };
        if data.opcode_of(branch) != Some(op::CBRANCH) {
            return 0;
        }
        let Some(condition_value) = input(data, branch, 1) else {
            return 0;
        };
        let Some(compare) = def(data, condition_value) else {
            return 0;
        };
        if data.op(compare).opcode != op::INT_SLESS {
            return 0;
        }
        let Some(compare_left) = input(data, compare, 0) else {
            return 0;
        };
        let Some(compare_right) = input(data, compare, 1) else {
            return 0;
        };
        let Some(taken_slot) = branch_taken_slot(data, condition, branch) else {
            return 0;
        };
        let is_base_less_zero =
            compare_left == basevn && constant_value(data, compare_right) == Some(0);
        let is_minus_one_less_base = constant_value(data, compare_left)
            == Some(mask(data.varnode(basevn).size))
            && compare_right == basevn;
        if !is_base_less_zero && !is_minus_one_less_base {
            return 0;
        }
        if is_base_less_zero {
            if unsigned_branch_slot != taken_slot {
                return 0;
            }
        } else if unsigned_branch_slot == taken_slot {
            return 0;
        }

        let seq = data.op(multiop).seq;
        let newzext = data.new_op(op::INT_ZEXT, seq, vec![basevn]);
        let newout = data.new_unique(preferred_zext_size(data.varnode(basevn).size));
        data.op_set_output(newzext, Some(newout));
        data.op_set_opcode(multiop, op::FLOAT_INT2FLOAT);
        data.op_set_inputs(multiop, vec![newout]);
        data.op_insert_before(newzext, multiop);
        1
    }
}

/// Every requested floating rule whose graph dependencies are expressible.
/// `RuleIgnoreNan` is omitted because `Funcdata` has no architecture handle or
/// `nan_ignore_all` setting; its comparison-protecting fallback is not a safe
/// substitute for that gate.
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(RuleFloatRange),
        Box::new(RuleFloatSign),
        Box::new(RuleFloatSignCleanup),
        Box::new(RuleUnsigned2Float),
        Box::new(RuleInt2FloatCollapse),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::REGISTER_SPACE;

    fn operation(
        data: &mut Funcdata,
        block: GraphBlockId,
        code: i32,
        inputs: Vec<VarnodeId>,
        size: u32,
    ) -> OpId {
        let address = data.block(block).start + data.block(block).ops.len() as u64 * 4;
        let id = data.new_op(code, super::super::SeqNum { address, order: 0 }, inputs);
        if size != 0 {
            let out = data.new_unique(size);
            data.op_set_output(id, Some(out));
        }
        data.op_insert_end(id, block);
        id
    }

    fn input_value(data: &mut Funcdata, offset: u64, size: u32) -> VarnodeId {
        let value = data.new_varnode(REGISTER_SPACE, offset, size);
        data.mark_input(value);
        value
    }

    fn output_of(data: &Funcdata, id: OpId) -> VarnodeId {
        data.op(id).output.expect("test operation has an output")
    }

    #[test]
    fn float_range_fires_and_rejects_wrong_boolean_combiner() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = input_value(&mut data, 0, 4);
        let right = input_value(&mut data, 4, 4);
        let less = operation(&mut data, block, op::FLOAT_LESS, vec![left, right], 1);
        let equal = operation(&mut data, block, op::FLOAT_EQUAL, vec![left, right], 1);
        let less_out = output_of(&data, less);
        let equal_out = output_of(&data, equal);
        let joined = operation(&mut data, block, op::BOOL_OR, vec![less_out, equal_out], 1);
        assert_eq!(RuleFloatRange.apply_op(joined, &mut data), 1);
        assert_eq!(data.op(joined).opcode, op::FLOAT_LESSEQUAL);
        assert_eq!(data.op(joined).inputs, vec![left, right]);

        let mut declined = Funcdata::default();
        let block = declined.new_block(0x2000);
        let left = input_value(&mut declined, 0, 4);
        let right = input_value(&mut declined, 4, 4);
        let less = operation(&mut declined, block, op::FLOAT_LESS, vec![left, right], 1);
        let equal = operation(&mut declined, block, op::FLOAT_EQUAL, vec![left, right], 1);
        let less_out = output_of(&declined, less);
        let equal_out = output_of(&declined, equal);
        let joined = operation(
            &mut declined,
            block,
            op::BOOL_AND,
            vec![less_out, equal_out],
            1,
        );
        assert_eq!(RuleFloatRange.apply_op(joined, &mut declined), 0);
        assert_eq!(declined.op(joined).opcode, op::BOOL_AND);
    }

    #[test]
    fn float_sign_fires_and_rejects_non_sign_mask() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x3000);
        let source = input_value(&mut data, 0, 4);
        let sign_mask = data.new_constant(0x7fff_ffff, 4);
        let sign = operation(&mut data, block, op::INT_AND, vec![source, sign_mask], 4);
        let sign_out = output_of(&data, sign);
        let consumer = operation(&mut data, block, op::FLOAT_ADD, vec![sign_out, source], 4);
        assert_eq!(RuleFloatSign.apply_op(consumer, &mut data), 1);
        assert_eq!(data.op(sign).opcode, op::FLOAT_ABS);
        assert_eq!(data.op(sign).inputs, vec![source]);

        let mut declined = Funcdata::default();
        let block = declined.new_block(0x4000);
        let source = input_value(&mut declined, 0, 4);
        let sign_mask = declined.new_constant(0x7fff_fffe, 4);
        let sign = operation(
            &mut declined,
            block,
            op::INT_AND,
            vec![source, sign_mask],
            4,
        );
        let sign_out = output_of(&declined, sign);
        let consumer = operation(
            &mut declined,
            block,
            op::FLOAT_ADD,
            vec![sign_out, source],
            4,
        );
        assert_eq!(RuleFloatSign.apply_op(consumer, &mut declined), 0);
        assert_eq!(declined.op(sign).opcode, op::INT_AND);
    }

    #[test]
    fn float_sign_cleanup_uses_recovered_float_type_and_declines_integer_use() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x5000);
        let source = input_value(&mut data, 0, 4);
        let sign_mask = data.new_constant(0x8000_0000, 4);
        let sign = operation(&mut data, block, op::INT_XOR, vec![source, sign_mask], 4);
        let sign_out = output_of(&data, sign);
        let _float_use = operation(&mut data, block, op::FLOAT_ADD, vec![sign_out, source], 4);
        assert_eq!(RuleFloatSignCleanup.apply_op(sign, &mut data), 1);
        assert_eq!(data.op(sign).opcode, op::FLOAT_NEG);
        assert_eq!(data.op(sign).inputs, vec![source]);

        let mut declined = Funcdata::default();
        let block = declined.new_block(0x6000);
        let source = input_value(&mut declined, 0, 4);
        let sign_mask = declined.new_constant(0x8000_0000, 4);
        let sign = operation(
            &mut declined,
            block,
            op::INT_XOR,
            vec![source, sign_mask],
            4,
        );
        let sign_out = output_of(&declined, sign);
        let _integer_use = operation(&mut declined, block, op::INT_ADD, vec![sign_out, source], 4);
        assert_eq!(RuleFloatSignCleanup.apply_op(sign, &mut declined), 0);
        assert_eq!(declined.op(sign).opcode, op::INT_XOR);
    }

    #[test]
    fn unsigned2float_collapses_double_add_and_rejects_other_shift() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x7000);
        let source = input_value(&mut data, 0, 4);
        let one = data.new_constant(1, 4);
        let shifted = operation(&mut data, block, op::INT_RIGHT, vec![source, one], 4);
        let mask_one = data.new_constant(1, 4);
        let masked = operation(&mut data, block, op::INT_AND, vec![source, mask_one], 4);
        let shifted_out = output_of(&data, shifted);
        let masked_out = output_of(&data, masked);
        let joined = operation(
            &mut data,
            block,
            op::INT_OR,
            vec![shifted_out, masked_out],
            4,
        );
        let joined_out = output_of(&data, joined);
        let converted = operation(&mut data, block, op::FLOAT_INT2FLOAT, vec![joined_out], 4);
        let converted_out = output_of(&data, converted);
        let add = operation(
            &mut data,
            block,
            op::FLOAT_ADD,
            vec![converted_out, converted_out],
            4,
        );
        assert_eq!(RuleUnsigned2Float.apply_op(converted, &mut data), 1);
        assert_eq!(data.op(add).opcode, op::FLOAT_INT2FLOAT);
        assert_eq!(data.op(add).inputs.len(), 1);
        let zext = def(&data, data.op(add).inputs[0]).expect("inserted zext");
        assert_eq!(data.op(zext).opcode, op::INT_ZEXT);
        assert_eq!(data.op(zext).inputs, vec![source]);

        let mut declined = Funcdata::default();
        let block = declined.new_block(0x8000);
        let source = input_value(&mut declined, 0, 4);
        let shift_amount = declined.new_constant(2, 4);
        let shifted = operation(
            &mut declined,
            block,
            op::INT_RIGHT,
            vec![source, shift_amount],
            4,
        );
        let mask_one = declined.new_constant(1, 4);
        let masked = operation(&mut declined, block, op::INT_AND, vec![source, mask_one], 4);
        let shifted_out = output_of(&declined, shifted);
        let masked_out = output_of(&declined, masked);
        let joined = operation(
            &mut declined,
            block,
            op::INT_OR,
            vec![shifted_out, masked_out],
            4,
        );
        let joined_out = output_of(&declined, joined);
        let converted = operation(
            &mut declined,
            block,
            op::FLOAT_INT2FLOAT,
            vec![joined_out],
            4,
        );
        let converted_out = output_of(&declined, converted);
        let add = operation(
            &mut declined,
            block,
            op::FLOAT_ADD,
            vec![converted_out, converted_out],
            4,
        );
        assert_eq!(RuleUnsigned2Float.apply_op(converted, &mut declined), 0);
        assert_eq!(declined.op(add).opcode, op::FLOAT_ADD);
    }

    fn collapse_fixture(compare_right: u64) -> (Funcdata, OpId, OpId) {
        let mut data = Funcdata::default();
        data.entry = 0x9000;
        let condition = data.new_block(0x9000);
        let unsigned_path = data.new_block(0x9010);
        let signed_path = data.new_block(0x9020);
        let join = data.new_block(0x9030);
        data.add_edge(condition, unsigned_path);
        data.add_edge(condition, signed_path);
        data.add_edge(unsigned_path, join);
        data.add_edge(signed_path, join);

        let source = input_value(&mut data, 0, 4);
        let compare_constant = data.new_constant(compare_right, 4);
        let compare = operation(
            &mut data,
            condition,
            op::INT_SLESS,
            vec![source, compare_constant],
            1,
        );
        let target = data.new_constant(data.block(unsigned_path).start, 4);
        let compare_out = output_of(&data, compare);
        let _branch = operation(
            &mut data,
            condition,
            op::CBRANCH,
            vec![target, compare_out],
            0,
        );
        let zext = operation(&mut data, unsigned_path, op::INT_ZEXT, vec![source], 8);
        let zext_out = output_of(&data, zext);
        let unsigned = operation(
            &mut data,
            unsigned_path,
            op::FLOAT_INT2FLOAT,
            vec![zext_out],
            4,
        );
        let signed = operation(&mut data, signed_path, op::FLOAT_INT2FLOAT, vec![source], 4);
        let unsigned_out = output_of(&data, unsigned);
        let signed_out = output_of(&data, signed);
        let multi = operation(
            &mut data,
            join,
            op::MULTIEQUAL,
            vec![unsigned_out, signed_out],
            4,
        );
        (data, unsigned, multi)
    }

    #[test]
    fn int2floatcollapse_merges_signed_unsigned_paths_and_declines_bad_compare() {
        let (mut data, unsigned, multi) = collapse_fixture(0);
        assert_eq!(RuleInt2FloatCollapse.apply_op(unsigned, &mut data), 1);
        assert_eq!(data.op(multi).opcode, op::FLOAT_INT2FLOAT);
        assert_eq!(data.op(multi).inputs.len(), 1);
        let zext = def(&data, data.op(multi).inputs[0]).expect("inserted join zext");
        assert_eq!(data.op(zext).opcode, op::INT_ZEXT);

        let (mut declined, unsigned, multi) = collapse_fixture(1);
        assert_eq!(RuleInt2FloatCollapse.apply_op(unsigned, &mut declined), 0);
        assert_eq!(declined.op(multi).opcode, op::MULTIEQUAL);
    }
}
