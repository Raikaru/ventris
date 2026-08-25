//! Division, modulo, carry, and borrow expression rules from Ghidra 12.1.3.
//!
//! The structural tests in this module follow the real `applyOp` bodies in
//! `ruleaction.cc`, rather than matching names or comments.  The graph stores
//! constants in one `u64` offset, so the extended-constant paths in Ghidra's
//! rules are accepted only when the complete value fits that representation.
//!
//! `RuleRangeMeld` is intentionally omitted.  Its implementation needs
//! `CircleRange::pullBack`, `intersect`/`circleUnion`, `translate2Op`, and
//! range markup propagation; none of those are represented by `Funcdata`.

use super::action::Rule;
use super::{Funcdata, OpId, SeqNum, VarnodeId};
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

fn input(data: &Funcdata, id: OpId, slot: usize) -> Option<VarnodeId> {
    data.op(id).inputs.get(slot).copied()
}

fn output(data: &Funcdata, id: OpId) -> Option<VarnodeId> {
    data.op(id).output
}

fn def(data: &Funcdata, value: VarnodeId) -> Option<OpId> {
    data.varnode(value).def
}

fn opcode(data: &Funcdata, id: OpId) -> Option<i32> {
    data.opcode_of(id)
}

fn is_constant(data: &Funcdata, value: VarnodeId) -> bool {
    data.varnode(value).flags.constant
}

/// Ghidra's `Varnode::isFree`: a value with no definition and no input flag.
fn is_free(data: &Funcdata, value: VarnodeId) -> bool {
    let node = data.varnode(value);
    !node.flags.written && !node.flags.input
}

fn is_written(data: &Funcdata, value: VarnodeId) -> bool {
    data.varnode(value).flags.written
}

fn constant_value(data: &Funcdata, value: VarnodeId) -> Option<u64> {
    is_constant(data, value).then(|| data.varnode(value).offset)
}

fn is_zero(data: &Funcdata, value: VarnodeId) -> bool {
    constant_value(data, value) == Some(0)
}

fn new_op_before(
    data: &mut Funcdata,
    anchor: OpId,
    code: i32,
    inputs: Vec<VarnodeId>,
    output_size: u32,
) -> (OpId, VarnodeId) {
    let seq = data.op(anchor).seq;
    let id = data.new_op(code, seq, inputs);
    let out = data.new_unique(output_size);
    data.op_set_output(id, Some(out));
    data.op_insert_before(id, anchor);
    (id, out)
}

fn set_copy(data: &mut Funcdata, id: OpId, value: VarnodeId) {
    data.op_set_opcode(id, op::COPY);
    data.op_set_inputs(id, vec![value]);
}

fn sign_bit(size: u32) -> Option<u64> {
    let bits = size.checked_mul(8)?;
    (bits > 0 && bits <= 64).then(|| 1u64 << (bits - 1))
}

fn signbit_negative(value: u64, size: u32) -> bool {
    sign_bit(size).is_some_and(|bit| value & bit != 0)
}

fn mostsigbit_set(value: u64) -> u32 {
    debug_assert!(value != 0);
    u64::BITS - value.leading_zeros() - 1
}

fn matches_negated(data: &Funcdata, value: VarnodeId, base: VarnodeId) -> bool {
    let Some(defop) = def(data, value) else {
        return false;
    };
    match opcode(data, defop) {
        Some(op::INT_2COMP) => input(data, defop, 0) == Some(base),
        Some(op::INT_MULT) => {
            let Some(left) = input(data, defop, 0) else {
                return false;
            };
            let Some(right) = input(data, defop, 1) else {
                return false;
            };
            (left == base && constant_value(data, right) == Some(mask(data.varnode(right).size)))
                || (right == base
                    && constant_value(data, left) == Some(mask(data.varnode(left).size)))
        }
        _ => false,
    }
}

/// A conservative structural equivalent of `AddExpression::gatherTwoTermsSubtract`.
/// The graph has no expression-term normalizer, so accept the direct p-code
/// forms and their explicit two's-complement spelling only.
fn matches_subtract(data: &Funcdata, value: VarnodeId, left: VarnodeId, right: VarnodeId) -> bool {
    let Some(defop) = def(data, value) else {
        return false;
    };
    if opcode(data, defop) == Some(op::INT_SUB) {
        return input(data, defop, 0) == Some(left) && input(data, defop, 1) == Some(right);
    }
    if opcode(data, defop) != Some(op::INT_ADD) {
        return false;
    }
    (input(data, defop, 0) == Some(left)
        && input(data, defop, 1).is_some_and(|v| matches_negated(data, v, right)))
        || (input(data, defop, 1) == Some(left)
            && input(data, defop, 0).is_some_and(|v| matches_negated(data, v, right)))
}

fn matches_add(data: &Funcdata, value: VarnodeId, left: VarnodeId, right: VarnodeId) -> bool {
    let Some(defop) = def(data, value) else {
        return false;
    };
    opcode(data, defop) == Some(op::INT_ADD)
        && ((input(data, defop, 0) == Some(left) && input(data, defop, 1) == Some(right))
            || (input(data, defop, 0) == Some(right) && input(data, defop, 1) == Some(left)))
}

/// Collapse two consecutive constant divisions.
pub struct RuleDivChain;

impl Rule for RuleDivChain {
    fn name(&self) -> &'static str {
        "divchain"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_DIV, op::INT_SDIV]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(opc2) = opcode(data, id) else {
            return 0;
        };
        let Some(const_vn2) = input(data, id, 1) else {
            return 0;
        };
        let Some(val2) = constant_value(data, const_vn2) else {
            return 0;
        };
        let Some(vn) = input(data, id, 0) else {
            return 0;
        };
        let Some(div_op) = def(data, vn) else {
            return 0;
        };
        let Some(opc1) = opcode(data, div_op) else {
            return 0;
        };
        if opc1 != opc2 && !(opc2 == op::INT_DIV && opc1 == op::INT_RIGHT) {
            return 0;
        }
        let Some(const_vn1) = input(data, div_op, 1) else {
            return 0;
        };
        let Some(mut val1) = constant_value(data, const_vn1) else {
            return 0;
        };
        // The intermediate quotient must have no other reader.  This is the
        // same modulo-preservation guard as Ghidra's `loneDescend` check.
        if data.lone_descend(vn).is_none() {
            return 0;
        }
        if opc1 != opc2 {
            let shift = val1;
            if shift >= 64 {
                return 0;
            }
            val1 = 1u64 << shift;
        }
        let Some(base_vn) = input(data, div_op, 0) else {
            return 0;
        };
        if is_free(data, base_vn) {
            return 0;
        }
        let size = data.varnode(vn).size;
        let result = val1.wrapping_mul(val2) & mask(size);
        if result == 0 {
            return 0;
        }
        let mut val1_abs = val1;
        if signbit_negative(val1_abs, size) {
            val1_abs = val1_abs.wrapping_neg() & mask(size);
        }
        let mut val2_abs = val2;
        if signbit_negative(val2_abs, size) {
            val2_abs = val2_abs.wrapping_neg() & mask(size);
        }
        let bitcount = mostsigbit_set(val1_abs) + mostsigbit_set(val2_abs) + 2;
        let bits = size.saturating_mul(8);
        if opc2 == op::INT_DIV && bitcount > bits {
            return 0;
        }
        if opc2 == op::INT_SDIV && (bits < 2 || bitcount > bits - 2) {
            return 0;
        }
        data.op_set_input(id, base_vn, 0);
        let result_constant = data.new_constant(result, size);
        data.op_set_input(id, result_constant, 1);
        1
    }
}

struct DivForm {
    input: VarnodeId,
    truncation: u64,
    multiplier: u128,
    xsize: u32,
    extension: i32,
}

/// Recover the multiply/shift form consumed by `RuleDivOpt::applyOp`.
fn find_div_form(data: &Funcdata, id: OpId) -> Option<DivForm> {
    let root_code = opcode(data, id)?;
    let mut current = id;
    let (shift_code, mut truncation) = if root_code == op::INT_RIGHT || root_code == op::INT_SRIGHT
    {
        let shifted = input(data, id, 0)?;
        let amount = constant_value(data, input(data, id, 1)?)?;
        current = def(data, shifted)?;
        (root_code, amount)
    } else {
        if root_code != op::SUBPIECE {
            return None;
        }
        (op::MAX, 0)
    };

    if opcode(data, current) == Some(op::SUBPIECE) {
        let cut = input(data, current, 1)?;
        let cut_amount = constant_value(data, cut)?;
        let whole = input(data, current, 0)?;
        let whole_def = def(data, whole)?;
        let output_size = data.varnode(output(data, current)?).size;
        if output_size.checked_add(u32::try_from(cut_amount).ok()?)
            != Some(data.varnode(whole).size)
        {
            return None;
        }
        truncation = truncation.checked_add(cut_amount.checked_mul(8)?)?;
        current = whole_def;
    }
    if opcode(data, current) != Some(op::INT_MULT) {
        return None;
    }
    let left = input(data, current, 0)?;
    let right = input(data, current, 1)?;
    let (multiplier, extended) = if let Some(value) = constant_value(data, left) {
        (u128::from(value), right)
    } else if let Some(value) = constant_value(data, right) {
        (u128::from(value), left)
    } else {
        return None;
    };
    if !is_written(data, extended) {
        return None;
    }
    let extension_op = def(data, extended)?;
    let mut extension = opcode(data, extension_op)?;
    let input_size = data.varnode(extended).size;
    let xsize = if extension == op::INT_SEXT {
        let source = input(data, extension_op, 0)?;
        data.varnode(source).size.saturating_mul(8)
    } else {
        let nz_mask = if extension == op::INT_ZEXT {
            let source = input(data, extension_op, 0)?;
            data.nonzero_masks()[source.0 as usize]
        } else {
            data.nonzero_masks()[extended.0 as usize]
        };
        let bits = 64 - nz_mask.leading_zeros();
        if bits == 0 || bits > input_size.saturating_mul(4) {
            return None;
        }
        bits
    };
    let root_output_size = data.varnode(output(data, id)?).size;
    let result = if extension == op::INT_ZEXT || extension == op::INT_SEXT {
        let source = input(data, extension_op, 0)?;
        if is_free(data, source) {
            return None;
        }
        if input_size == root_output_size {
            extended
        } else {
            source
        }
    } else {
        extension = op::INT_ZEXT;
        extended
    };
    if ((extension == op::INT_ZEXT && shift_code == op::INT_SRIGHT)
        || (extension == op::INT_SEXT && shift_code == op::INT_RIGHT))
        && (root_output_size.saturating_mul(8) as u64).checked_sub(truncation)
            != Some(u64::from(xsize))
    {
        return None;
    }
    Some(DivForm {
        input: result,
        truncation,
        multiplier,
        xsize,
        extension,
    })
}

/// Exact port of `RuleDivOpt::calcDivisor`, using Rust's native 128-bit value
/// in place of Ghidra's two-word multiprecision arrays.
fn calc_divisor(n: u64, multiplier: u128, xsize: u32) -> Option<u64> {
    if n > 127 || xsize > 64 {
        return None;
    }
    let power = 1u128.checked_shl(n as u32)?;
    if multiplier <= 1 {
        return None;
    }
    let y = multiplier - 1;
    let mut quotient = power / y;
    let mut remainder = power % y;
    if quotient > u128::from(u64::MAX) || y < quotient {
        return None;
    }
    let mut diff = 0u128;
    let quotient_low = quotient as u64;
    if remainder >= quotient {
        // Ghidra increments q[0] directly, so reproduce its low-word wrap.
        let adjusted = quotient_low.wrapping_add(1);
        quotient = u128::from(adjusted);
        remainder = remainder.wrapping_sub(y).wrapping_add(u128::from(adjusted));
        if remainder >= quotient {
            return None;
        }
        diff = u128::from(adjusted);
    }
    let q_low = quotient as u64;
    let r_low = remainder as u64;
    diff = diff.wrapping_add(u128::from(q_low) - u128::from(r_low));
    if diff == 0 {
        return None;
    }
    let trial = power / diff;
    if trial > u128::from(u64::MAX) {
        return (q_low != 0).then_some(q_low);
    }
    let max_x = if xsize == 64 {
        u128::MAX
    } else {
        (1u128 << xsize) - 1
    };
    if trial <= max_x {
        return None;
    }
    (q_low != 0).then_some(q_low)
}

fn move_sign_bit_extraction(data: &mut Funcdata, first: VarnodeId, replacement: VarnodeId) {
    let mut test_list = vec![first];
    if let Some(first_def) = def(data, first)
        && opcode(data, first_def) == Some(op::INT_SRIGHT)
        && let Some(previous) = input(data, first_def, 0)
    {
        test_list.push(previous);
    }
    let mut index = 0;
    while index < test_list.len() {
        let value = test_list[index];
        index += 1;
        let descendants: Vec<OpId> = data.varnode(value).descendants.iter().copied().collect();
        for descendant in descendants {
            match opcode(data, descendant) {
                Some(op::INT_RIGHT) | Some(op::INT_SRIGHT) => {
                    let Some(mut constant_vn) = input(data, descendant, 1) else {
                        continue;
                    };
                    if let Some(const_def) = def(data, constant_vn) {
                        match opcode(data, const_def) {
                            Some(op::COPY) => {
                                if let Some(source) = input(data, const_def, 0) {
                                    constant_vn = source;
                                }
                            }
                            Some(op::INT_AND) => {
                                let Some(and_left) = input(data, const_def, 0) else {
                                    continue;
                                };
                                let Some(and_right) = input(data, const_def, 1) else {
                                    continue;
                                };
                                let Some(and_mask) = constant_value(data, and_right) else {
                                    continue;
                                };
                                if data.varnode(and_left).offset
                                    != data.varnode(and_left).offset & and_mask
                                {
                                    continue;
                                }
                                constant_vn = and_left;
                            }
                            _ => {}
                        }
                    }
                    let Some(shift) = constant_value(data, constant_vn) else {
                        continue;
                    };
                    let Some(size_bits) = data.varnode(first).size.checked_mul(8) else {
                        continue;
                    };
                    if size_bits > 0 && shift == u64::from(size_bits - 1) {
                        data.op_set_input(descendant, replacement, 0);
                    }
                }
                Some(op::COPY) => {
                    if let Some(copy_output) = output(data, descendant) {
                        test_list.push(copy_output);
                    }
                }
                _ => {}
            }
        }
    }
}

fn check_form_overlap(data: &Funcdata, id: OpId) -> bool {
    if opcode(data, id) != Some(op::SUBPIECE) {
        return false;
    }
    let Some(root_output) = output(data, id) else {
        return false;
    };
    let descendants: Vec<OpId> = data
        .varnode(root_output)
        .descendants
        .iter()
        .copied()
        .collect();
    for super_op in descendants {
        let Some(super_code) = opcode(data, super_op) else {
            continue;
        };
        if super_code != op::INT_RIGHT && super_code != op::INT_SRIGHT {
            continue;
        }
        let Some(amount) = input(data, super_op, 1) else {
            return true;
        };
        if !is_constant(data, amount) || find_div_form(data, super_op).is_some() {
            return true;
        }
    }
    false
}

/// Convert a multiply/shift reciprocal into an integer division.
pub struct RuleDivOpt;

impl Rule for RuleDivOpt {
    fn name(&self) -> &'static str {
        "divopt"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::SUBPIECE, op::INT_RIGHT, op::INT_SRIGHT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(form) = find_div_form(data, id) else {
            return 0;
        };
        if check_form_overlap(data, id) {
            return 0;
        }
        let mut xsize = form.xsize;
        if form.extension == op::INT_SEXT {
            xsize = xsize.saturating_sub(1);
        }
        let Some(divisor) = calc_divisor(form.truncation, form.multiplier, xsize) else {
            return 0;
        };
        let Some(original_output) = output(data, id) else {
            return 0;
        };
        let mut target = id;
        let mut input_vn = form.input;
        let mut output_size = data.varnode(original_output).size;
        if data.varnode(input_vn).size < output_size {
            let (_, extension_out) =
                new_op_before(data, target, form.extension, vec![input_vn], output_size);
            input_vn = extension_out;
        } else if data.varnode(input_vn).size > output_size {
            let input_size = data.varnode(input_vn).size;
            let (new_target, new_output) = new_op_before(
                data,
                target,
                op::INT_ADD,
                vec![input_vn, input_vn],
                input_size,
            );
            data.op_set_opcode(target, op::SUBPIECE);
            let zero = data.new_constant(0, 4);
            data.op_set_inputs(target, vec![new_output, zero]);
            target = new_target;
            output_size = input_size;
        }
        if form.extension == op::INT_ZEXT {
            let divisor_vn = data.new_constant(divisor, output_size);
            data.op_set_opcode(target, op::INT_DIV);
            data.op_set_inputs(target, vec![input_vn, divisor_vn]);
        } else {
            let Some(target_output) = output(data, target) else {
                return 0;
            };
            move_sign_bit_extraction(data, target_output, input_vn);
            let divisor_vn = data.new_constant(divisor, output_size);
            let (_, division_out) = new_op_before(
                data,
                target,
                op::INT_SDIV,
                vec![input_vn, divisor_vn],
                output_size,
            );
            let sign_amount = data.new_constant(
                u64::from(output_size.saturating_mul(8).saturating_sub(1)),
                output_size,
            );
            let (_, sign_out) = new_op_before(
                data,
                target,
                op::INT_SRIGHT,
                vec![input_vn, sign_amount],
                output_size,
            );
            data.op_set_opcode(target, op::INT_ADD);
            data.op_set_inputs(target, vec![division_out, sign_out]);
        }
        1
    }
}

/// Rewrite the second optimized-division correction term.
pub struct RuleDivTermAdd2;

impl Rule for RuleDivTermAdd2 {
    fn name(&self) -> &'static str {
        "divtermadd2"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_RIGHT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(shift_amount) = input(data, id, 1) else {
            return 0;
        };
        if constant_value(data, shift_amount) != Some(1) {
            return 0;
        }
        let Some(add_out) = input(data, id, 0) else {
            return 0;
        };
        let Some(add_op) = def(data, add_out) else {
            return 0;
        };
        if opcode(data, add_op) != Some(op::INT_ADD) {
            return 0;
        }
        let mut x = None;
        let mut matched_mult = None;
        for slot in 0..2 {
            let Some(candidate) = input(data, add_op, slot) else {
                continue;
            };
            let Some(candidate_def) = def(data, candidate) else {
                continue;
            };
            if opcode(data, candidate_def) != Some(op::INT_MULT) {
                continue;
            }
            let Some(inverse) = input(data, candidate_def, 1) else {
                continue;
            };
            if constant_value(data, inverse) == Some(mask(data.varnode(inverse).size)) {
                x = input(data, add_op, 1 - slot);
                matched_mult = Some(candidate_def);
                break;
            }
        }
        let Some(comp_op) = matched_mult else {
            return 0;
        };
        let Some(x) = x else {
            return 0;
        };
        let Some(z) = input(data, comp_op, 0) else {
            return 0;
        };
        let Some(subpiece_output_def) = def(data, z) else {
            return 0;
        };
        if opcode(data, subpiece_output_def) != Some(op::SUBPIECE) {
            return 0;
        }
        let Some(cut) = input(data, subpiece_output_def, 1) else {
            return 0;
        };
        let Some(cut_amount) = constant_value(data, cut) else {
            return 0;
        };
        let Some(subpiece_whole) = input(data, subpiece_output_def, 0) else {
            return 0;
        };
        let Some(n) = cut_amount.checked_mul(8) else {
            return 0;
        };
        let expected_n = u64::from(
            data.varnode(subpiece_whole)
                .size
                .saturating_sub(data.varnode(z).size),
        ) * 8;
        if n != expected_n {
            return 0;
        }
        let Some(mult_vn) = def(data, subpiece_whole) else {
            return 0;
        };
        if opcode(data, mult_vn) != Some(op::INT_MULT) {
            return 0;
        }
        let Some(mult_const) = input(data, mult_vn, 1) else {
            return 0;
        };
        let Some(mult_const_value) = constant_value(data, mult_const) else {
            return 0;
        };
        let Some(zext_vn) = input(data, mult_vn, 0) else {
            return 0;
        };
        let Some(zext_op) = def(data, zext_vn) else {
            return 0;
        };
        if opcode(data, zext_op) != Some(op::INT_ZEXT) || input(data, zext_op, 0) != Some(x) {
            return 0;
        }
        let zext_size = data.varnode(zext_vn).size;
        if zext_size > 8 || n >= 64 {
            return 0;
        }
        let new_constant = mult_const_value.wrapping_add(1u64 << n) & mask(zext_size);
        let new_mult_constant = data.new_constant(new_constant, zext_size);
        let (_, new_mult_out) = new_op_before(
            data,
            id,
            op::INT_MULT,
            vec![zext_vn, new_mult_constant],
            zext_size,
        );
        let new_shift_amount = data.new_constant(n + 1, 4);
        let (_, new_shift_out) = new_op_before(
            data,
            id,
            op::INT_RIGHT,
            vec![new_mult_out, new_shift_amount],
            zext_size,
        );
        let Some(root_output) = output(data, id) else {
            return 0;
        };
        let descendants: Vec<OpId> = data
            .varnode(root_output)
            .descendants
            .iter()
            .copied()
            .collect();
        for descendant in descendants {
            if opcode(data, descendant) != Some(op::INT_ADD) {
                continue;
            }
            if input(data, descendant, 0) != Some(z) && input(data, descendant, 1) != Some(z) {
                continue;
            }
            data.op_set_opcode(descendant, op::SUBPIECE);
            let zero = data.new_constant(0, 4);
            data.op_set_inputs(descendant, vec![new_shift_out, zero]);
            return 1;
        }
        0
    }
}

/// Normalize a sign extraction through a high multiply truncation.
pub struct RuleSignForm2;

impl Rule for RuleSignForm2 {
    fn name(&self) -> &'static str {
        "signform2"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_SRIGHT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(const_vn) = input(data, id, 1) else {
            return 0;
        };
        let Some(shift) = constant_value(data, const_vn) else {
            return 0;
        };
        let Some(in_vn) = input(data, id, 0) else {
            return 0;
        };
        let size_out = data.varnode(in_vn).size;
        if shift != u64::from(size_out.saturating_mul(8).saturating_sub(1)) {
            return 0;
        }
        let Some(sub_op) = def(data, in_vn) else {
            return 0;
        };
        if opcode(data, sub_op) != Some(op::SUBPIECE) {
            return 0;
        }
        let Some(cut_vn) = input(data, sub_op, 1) else {
            return 0;
        };
        let Some(cut) = constant_value(data, cut_vn) else {
            return 0;
        };
        let Some(mult_out) = input(data, sub_op, 0) else {
            return 0;
        };
        let mult_size = data.varnode(mult_out).size;
        if cut.checked_add(u64::from(size_out)) != Some(u64::from(mult_size)) {
            return 0;
        }
        let Some(mult_op) = def(data, mult_out) else {
            return 0;
        };
        if opcode(data, mult_op) != Some(op::INT_MULT) {
            return 0;
        }
        let mut sext_op = None;
        let mut sext_slot = 0;
        for slot in 0..2 {
            let Some(value) = input(data, mult_op, slot) else {
                continue;
            };
            let Some(value_def) = def(data, value) else {
                continue;
            };
            if opcode(data, value_def) == Some(op::INT_SEXT) {
                sext_op = Some(value_def);
                sext_slot = slot;
                break;
            }
        }
        let Some(sext_op) = sext_op else {
            return 0;
        };
        let Some(base) = input(data, sext_op, 0) else {
            return 0;
        };
        if is_free(data, base) || data.varnode(base).size != size_out {
            return 0;
        }
        let Some(other) = input(data, mult_op, 1 - sext_slot) else {
            return 0;
        };
        if let Some(value) = constant_value(data, other) {
            if value > mask(size_out) || size_out.saturating_mul(2) > mult_size {
                return 0;
            }
        } else {
            let Some(other_def) = def(data, other) else {
                return 0;
            };
            if opcode(data, other_def) != Some(op::INT_ZEXT) {
                return 0;
            }
            let Some(source) = input(data, other_def, 0) else {
                return 0;
            };
            if data.varnode(source).size.saturating_add(size_out) > mult_size {
                return 0;
            }
        }
        data.op_set_input(id, base, 0);
        1
    }
}

fn check_sign_extraction(data: &Funcdata, value: VarnodeId) -> Option<VarnodeId> {
    let sign_op = def(data, value)?;
    if opcode(data, sign_op) != Some(op::INT_SRIGHT) {
        return None;
    }
    let amount = constant_value(data, input(data, sign_op, 1)?)?;
    let source = input(data, sign_op, 0)?;
    if amount
        != u64::from(
            data.varnode(source)
                .size
                .saturating_mul(8)
                .saturating_sub(1),
        )
    {
        return None;
    }
    Some(source)
}

/// Recognize the general signed modulo-by-power-of-two correction.
pub struct RuleSignMod2nOpt;

impl Rule for RuleSignMod2nOpt {
    fn name(&self) -> &'static str {
        "signmod2nopt"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_RIGHT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(shift_vn) = input(data, id, 1) else {
            return 0;
        };
        let Some(shift_amount) = constant_value(data, shift_vn) else {
            return 0;
        };
        let Some(sign_value) = input(data, id, 0) else {
            return 0;
        };
        let Some(a) = check_sign_extraction(data, sign_value) else {
            return 0;
        };
        if is_free(data, a) {
            return 0;
        }
        let total_bits = u64::from(data.varnode(a).size.saturating_mul(8));
        if shift_amount >= total_bits {
            return 0;
        }
        let n = total_bits - shift_amount;
        if n == 0 || n >= 64 {
            return 0;
        }
        let modulo_mask = (1u64 << n) - 1;
        let Some(correct_vn) = output(data, id) else {
            return 0;
        };
        let descendants: Vec<OpId> = data
            .varnode(correct_vn)
            .descendants
            .iter()
            .copied()
            .collect();
        for mult_op in descendants {
            if opcode(data, mult_op) != Some(op::INT_MULT) {
                continue;
            }
            let Some(neg_one) = input(data, mult_op, 1) else {
                continue;
            };
            if constant_value(data, neg_one) != Some(mask(data.varnode(correct_vn).size)) {
                continue;
            }
            let Some(mult_out) = output(data, mult_op) else {
                continue;
            };
            let Some(base_op) = data.lone_descend(mult_out) else {
                continue;
            };
            if opcode(data, base_op) != Some(op::INT_ADD) {
                continue;
            }
            let Some(mult_slot) = data.op(base_op).inputs.iter().position(|v| *v == mult_out)
            else {
                continue;
            };
            let Some(mut and_out) = input(data, base_op, 1 - mult_slot) else {
                continue;
            };
            let mut trunc_size = None;
            let Some(mut and_op) = def(data, and_out) else {
                continue;
            };
            if opcode(data, and_op) == Some(op::INT_ZEXT) {
                let Some(unextended) = input(data, and_op, 0) else {
                    continue;
                };
                and_out = unextended;
                trunc_size = Some(data.varnode(and_out).size);
                let Some(unextended_def) = def(data, and_out) else {
                    continue;
                };
                and_op = unextended_def;
            }
            if opcode(data, and_op) != Some(op::INT_AND) {
                continue;
            }
            let Some(and_constant) = input(data, and_op, 1) else {
                continue;
            };
            if constant_value(data, and_constant) != Some(modulo_mask) {
                continue;
            }
            let Some(add_out) = input(data, and_op, 0) else {
                continue;
            };
            let Some(add_op) = def(data, add_out) else {
                continue;
            };
            if opcode(data, add_op) != Some(op::INT_ADD) {
                continue;
            }
            let mut a_slot = None;
            for slot in 0..2 {
                let Some(mut value) = input(data, add_op, slot) else {
                    continue;
                };
                if let Some(truncated) = trunc_size {
                    let Some(sub_op) = def(data, value) else {
                        continue;
                    };
                    let Some(sub_amount) = input(data, sub_op, 1) else {
                        continue;
                    };
                    let Some(sub_source) = input(data, sub_op, 0) else {
                        continue;
                    };
                    if opcode(data, sub_op) != Some(op::SUBPIECE)
                        || constant_value(data, sub_amount) != Some(0)
                    {
                        continue;
                    }
                    let _ = truncated;
                    value = sub_source;
                }
                if value == a {
                    a_slot = Some(slot);
                    break;
                }
            }
            let Some(a_slot) = a_slot else {
                continue;
            };
            let Some(ext_vn) = input(data, add_op, 1 - a_slot) else {
                continue;
            };
            let Some(shift_op) = def(data, ext_vn) else {
                continue;
            };
            if opcode(data, shift_op) != Some(op::INT_RIGHT) {
                continue;
            }
            let Some(ext_amount_vn) = input(data, shift_op, 1) else {
                continue;
            };
            let Some(ext_amount) = constant_value(data, ext_amount_vn) else {
                continue;
            };
            let truncation_bits = trunc_size.map_or(0, |truncated| {
                u64::from(data.varnode(a).size.saturating_sub(truncated)) * 8
            });
            let Some(shift_value) = ext_amount.checked_add(truncation_bits) else {
                continue;
            };
            if shift_value != shift_amount {
                continue;
            }
            let Some(extracted_input) = input(data, shift_op, 0) else {
                continue;
            };
            let Some(mut extracted) = check_sign_extraction(data, extracted_input) else {
                continue;
            };
            if let Some(truncated) = trunc_size {
                let Some(sub_op) = def(data, extracted) else {
                    continue;
                };
                let Some(sub_amount) = input(data, sub_op, 1) else {
                    continue;
                };
                let Some(sub_source) = input(data, sub_op, 0) else {
                    continue;
                };
                if opcode(data, sub_op) != Some(op::SUBPIECE)
                    || constant_value(data, sub_amount) != Some(u64::from(truncated))
                {
                    continue;
                }
                extracted = sub_source;
            }
            if extracted != a {
                continue;
            }
            data.op_set_opcode(base_op, op::INT_SREM);
            let result_size = data.varnode(a).size;
            let divisor = data.new_constant(modulo_mask + 1, result_size);
            data.op_set_inputs(base_op, vec![a, divisor]);
            return 1;
        }
        0
    }
}

/// Specialized signed modulo-by-two correction.
pub struct RuleSignMod2Opt;

impl Rule for RuleSignMod2Opt {
    fn name(&self) -> &'static str {
        "signmod2opt"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_AND]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(and_constant) = input(data, id, 1) else {
            return 0;
        };
        if constant_value(data, and_constant) != Some(1) {
            return 0;
        }
        let Some(add_out) = input(data, id, 0) else {
            return 0;
        };
        let Some(add_op) = def(data, add_out) else {
            return 0;
        };
        if opcode(data, add_op) != Some(op::INT_ADD) {
            return 0;
        }
        let mut mult_slot = None;
        let mut mult_op = None;
        for slot in 0..2 {
            let Some(value) = input(data, add_op, slot) else {
                continue;
            };
            let Some(value_def) = def(data, value) else {
                continue;
            };
            if opcode(data, value_def) != Some(op::INT_MULT) {
                continue;
            }
            let Some(coefficient) = input(data, value_def, 1) else {
                continue;
            };
            if constant_value(data, coefficient) == Some(mask(data.varnode(coefficient).size)) {
                mult_slot = Some(slot);
                mult_op = Some(value_def);
                break;
            }
        }
        let (Some(mult_slot), Some(mult_op)) = (mult_slot, mult_op) else {
            return 0;
        };
        let Some(sign_value) = input(data, mult_op, 0) else {
            return 0;
        };
        let Some(base_sign) = check_sign_extraction(data, sign_value) else {
            return 0;
        };
        let mut base = base_sign;
        let Some(mut other_base) = input(data, add_op, 1 - mult_slot) else {
            return 0;
        };
        let mut truncated = false;
        if base != other_base {
            if !is_written(data, base) || !is_written(data, other_base) {
                return 0;
            }
            let Some(base_sub) = def(data, base) else {
                return 0;
            };
            if opcode(data, base_sub) != Some(op::SUBPIECE) {
                return 0;
            }
            let Some(trunc_vn) = input(data, base_sub, 1) else {
                return 0;
            };
            let Some(trunc_amount) = constant_value(data, trunc_vn) else {
                return 0;
            };
            let Some(base_source) = input(data, base_sub, 0) else {
                return 0;
            };
            if trunc_amount + u64::from(data.varnode(base).size)
                != u64::from(data.varnode(base_source).size)
            {
                return 0;
            }
            base = base_source;
            let Some(other_sub) = def(data, other_base) else {
                return 0;
            };
            let Some(other_amount) = input(data, other_sub, 1) else {
                return 0;
            };
            let Some(other_source) = input(data, other_sub, 0) else {
                return 0;
            };
            if opcode(data, other_sub) != Some(op::SUBPIECE)
                || constant_value(data, other_amount) != Some(0)
            {
                return 0;
            }
            other_base = other_source;
            if other_base != base {
                return 0;
            }
            truncated = true;
        }
        if is_free(data, base) {
            return 0;
        }
        let Some(mut and_out) = output(data, id) else {
            return 0;
        };
        if truncated {
            let Some(extension_op) = data.lone_descend(and_out) else {
                return 0;
            };
            if opcode(data, extension_op) != Some(op::INT_ZEXT) {
                return 0;
            }
            let Some(extension_out) = output(data, extension_op) else {
                return 0;
            };
            and_out = extension_out;
        }
        let descendants: Vec<OpId> = data.varnode(and_out).descendants.iter().copied().collect();
        for root_op in descendants {
            if opcode(data, root_op) != Some(op::INT_ADD) {
                continue;
            }
            let slot = if input(data, root_op, 0) == Some(and_out) {
                0
            } else if input(data, root_op, 1) == Some(and_out) {
                1
            } else {
                continue;
            };
            let Some(sign_source) = input(data, root_op, 1 - slot) else {
                continue;
            };
            if check_sign_extraction(data, sign_source) != Some(base) {
                continue;
            }
            data.op_set_opcode(root_op, op::INT_SREM);
            let divisor = data.new_constant(2, data.varnode(base).size);
            data.op_set_inputs(root_op, vec![base, divisor]);
            return 1;
        }
        0
    }
}

/// Convert the second power-of-two modulo idiom.
pub struct RuleSignMod2nOpt2;

impl Rule for RuleSignMod2nOpt2 {
    fn name(&self) -> &'static str {
        "signmod2nopt2"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_MULT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(multiplier) = input(data, id, 1) else {
            return 0;
        };
        let Some(multiplier_value) = constant_value(data, multiplier) else {
            return 0;
        };
        let value_size = data.varnode(multiplier).size;
        let value_mask = mask(value_size);
        if multiplier_value != value_mask {
            return 0;
        }
        let Some(and_out) = input(data, id, 0) else {
            return 0;
        };
        let Some(and_op) = def(data, and_out) else {
            return 0;
        };
        if opcode(data, and_op) != Some(op::INT_AND) {
            return 0;
        }
        let Some(and_constant) = input(data, and_op, 1) else {
            return 0;
        };
        let Some(and_value) = constant_value(data, and_constant) else {
            return 0;
        };
        let npow = (!and_value).wrapping_add(1) & value_mask;
        if npow.count_ones() != 1 || npow == 1 {
            return 0;
        }
        let Some(adj_vn) = input(data, and_op, 0) else {
            return 0;
        };
        let Some(adj_op) = def(data, adj_vn) else {
            return 0;
        };
        let base = if opcode(data, adj_op) == Some(op::INT_ADD) && npow == 2 {
            check_sign_ext_form(data, adj_op)
        } else {
            // The MULTIEQUAL branch in Ghidra additionally inspects the
            // conditional block's CBRANCH boolean-flip state.  That metadata
            // is absent from GraphOp, so decline that branch-form variant.
            None
        };
        let Some(base) = base else {
            return 0;
        };
        if is_free(data, base) {
            return 0;
        }
        let Some(mult_out) = output(data, id) else {
            return 0;
        };
        let descendants: Vec<OpId> = data.varnode(mult_out).descendants.iter().copied().collect();
        for root_op in descendants {
            if opcode(data, root_op) != Some(op::INT_ADD) {
                continue;
            }
            let slot = if input(data, root_op, 0) == Some(mult_out) {
                0
            } else if input(data, root_op, 1) == Some(mult_out) {
                1
            } else {
                continue;
            };
            if input(data, root_op, 1 - slot) != Some(base) {
                continue;
            }
            if slot == 0 {
                data.op_set_input(root_op, base, 0);
            }
            let divisor = data.new_constant(npow, data.varnode(base).size);
            data.op_set_input(root_op, divisor, 1);
            data.op_set_opcode(root_op, op::INT_SREM);
            return 1;
        }
        0
    }
}

fn check_sign_ext_form(data: &Funcdata, add_op: OpId) -> Option<VarnodeId> {
    for slot in 0..2 {
        let Some(minus_vn) = input(data, add_op, slot) else {
            continue;
        };
        let Some(mult_op) = def(data, minus_vn) else {
            continue;
        };
        if opcode(data, mult_op) != Some(op::INT_MULT) {
            continue;
        }
        let Some(coefficient) = input(data, mult_op, 1) else {
            continue;
        };
        if constant_value(data, coefficient) != Some(mask(data.varnode(coefficient).size)) {
            continue;
        }
        let Some(base) = input(data, add_op, 1 - slot) else {
            continue;
        };
        let Some(sign_ext) = input(data, mult_op, 0) else {
            continue;
        };
        let Some(shift_op) = def(data, sign_ext) else {
            continue;
        };
        if opcode(data, shift_op) != Some(op::INT_SRIGHT) || input(data, shift_op, 0) != Some(base)
        {
            continue;
        }
        let Some(shift_vn) = input(data, shift_op, 1) else {
            continue;
        };
        let Some(shift) = constant_value(data, shift_vn) else {
            continue;
        };
        if shift != u64::from(data.varnode(base).size.saturating_mul(8).saturating_sub(1)) {
            continue;
        }
        return Some(base);
    }
    None
}

/// Eliminate a carry against a constant.
pub struct RuleCarryElim;

impl Rule for RuleCarryElim {
    fn name(&self) -> &'static str {
        "carryelim"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_CARRY]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(value) = input(data, id, 0) else {
            return 0;
        };
        let Some(constant) = input(data, id, 1) else {
            return 0;
        };
        let Some(offset) = constant_value(data, constant) else {
            return 0;
        };
        if is_free(data, value) {
            return 0;
        }
        if offset == 0 {
            let false_value = data.new_constant(0, 1);
            set_copy(data, id, false_value);
            return 1;
        }
        let new_offset = offset.wrapping_neg() & mask(data.varnode(constant).size);
        let new_constant = data.new_constant(new_offset, data.varnode(value).size);
        data.op_set_opcode(id, op::INT_LESSEQUAL);
        data.op_set_inputs(id, vec![new_constant, value]);
        1
    }
}

/// Simplify signed-borrow comparisons.
pub struct RuleSborrow;

impl Rule for RuleSborrow {
    fn name(&self) -> &'static str {
        "sborrow"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_SBORROW]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(borrow) = output(data, id) else {
            return 0;
        };
        let Some(a) = input(data, id, 0) else {
            return 0;
        };
        let Some(b) = input(data, id, 1) else {
            return 0;
        };
        if is_zero(data, b) {
            let false_value = data.new_constant(0, 1);
            set_copy(data, id, false_value);
            return 1;
        }
        let descendants: Vec<OpId> = data.varnode(borrow).descendants.iter().copied().collect();
        for compare in descendants {
            let compare_code = opcode(data, compare);
            if compare_code != Some(op::INT_EQUAL) && compare_code != Some(op::INT_NOTEQUAL) {
                continue;
            }
            let compare_value = if input(data, compare, 0) == Some(borrow) {
                input(data, compare, 1)
            } else if input(data, compare, 1) == Some(borrow) {
                input(data, compare, 0)
            } else {
                None
            };
            let Some(cvn) = compare_value else {
                continue;
            };
            let Some(sign_op) = def(data, cvn) else {
                continue;
            };
            if opcode(data, sign_op) != Some(op::INT_SLESS) {
                continue;
            }
            let Some(sign_left) = input(data, sign_op, 0) else {
                continue;
            };
            let Some(sign_right) = input(data, sign_op, 1) else {
                continue;
            };
            let (zside, x) = if is_zero(data, sign_left) {
                (0usize, sign_right)
            } else if is_zero(data, sign_right) {
                (1usize, sign_left)
            } else {
                continue;
            };
            if !matches_subtract(data, x, a, b) {
                continue;
            }
            if compare_code == Some(op::INT_NOTEQUAL) {
                data.op_set_opcode(compare, op::INT_SLESS);
                data.op_set_inputs(compare, if zside == 0 { vec![b, a] } else { vec![a, b] });
            } else {
                data.op_set_opcode(compare, op::INT_SLESSEQUAL);
                data.op_set_inputs(compare, if zside == 0 { vec![a, b] } else { vec![b, a] });
            }
            return 1;
        }
        0
    }
}

/// Simplify signed-carry comparisons.
pub struct RuleScarry;

impl Rule for RuleScarry {
    fn name(&self) -> &'static str {
        "scarry"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_SCARRY]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(mut a) = input(data, id, 0) else {
            return 0;
        };
        let Some(mut b) = input(data, id, 1) else {
            return 0;
        };
        if is_zero(data, a) || is_zero(data, b) {
            let false_value = data.new_constant(0, 1);
            set_copy(data, id, false_value);
            return 1;
        }
        if !is_constant(data, b) {
            if !is_constant(data, a) {
                return 0;
            }
            std::mem::swap(&mut a, &mut b);
        }
        let Some(b_value) = constant_value(data, b) else {
            return 0;
        };
        let bits = data.varnode(b).size.saturating_mul(8);
        if bits == 0 || bits > 64 || b_value == (1u64 << (bits - 1)) {
            return 0;
        }
        let new_value = b_value.wrapping_neg() & mask(data.varnode(b).size);
        let Some(carry) = output(data, id) else {
            return 0;
        };
        let descendants: Vec<OpId> = data.varnode(carry).descendants.iter().copied().collect();
        for compare in descendants {
            let compare_code = opcode(data, compare);
            if compare_code != Some(op::INT_EQUAL) && compare_code != Some(op::INT_NOTEQUAL) {
                continue;
            }
            let compare_value = if input(data, compare, 0) == Some(carry) {
                input(data, compare, 1)
            } else if input(data, compare, 1) == Some(carry) {
                input(data, compare, 0)
            } else {
                None
            };
            let Some(cvn) = compare_value else {
                continue;
            };
            let Some(sign_op) = def(data, cvn) else {
                continue;
            };
            if opcode(data, sign_op) != Some(op::INT_SLESS) {
                continue;
            }
            let Some(sign_left) = input(data, sign_op, 0) else {
                continue;
            };
            let Some(sign_right) = input(data, sign_op, 1) else {
                continue;
            };
            let (zside, x) = if is_zero(data, sign_left) {
                (0usize, sign_right)
            } else if is_zero(data, sign_right) {
                (1usize, sign_left)
            } else {
                continue;
            };
            if !matches_add(data, x, a, b) {
                continue;
            }
            let replacement = data.new_constant(new_value, data.varnode(b).size);
            if compare_code == Some(op::INT_NOTEQUAL) {
                data.op_set_opcode(compare, op::INT_SLESS);
                data.op_set_inputs(
                    compare,
                    if zside == 0 {
                        vec![replacement, a]
                    } else {
                        vec![a, replacement]
                    },
                );
            } else {
                data.op_set_opcode(compare, op::INT_SLESSEQUAL);
                data.op_set_inputs(
                    compare,
                    if zside == 0 {
                        vec![a, replacement]
                    } else {
                        vec![replacement, a]
                    },
                );
            }
            return 1;
        }
        0
    }
}

/// Every requested rule whose real structural dependencies are present in the graph.
/// `RuleRangeMeld` is omitted because the graph has no CircleRange/range-pullback API.
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(RuleDivChain),
        Box::new(RuleDivOpt),
        Box::new(RuleDivTermAdd2),
        Box::new(RuleSignForm2),
        Box::new(RuleSignMod2Opt),
        Box::new(RuleSignMod2nOpt),
        Box::new(RuleSignMod2nOpt2),
        Box::new(RuleCarryElim),
        Box::new(RuleSborrow),
        Box::new(RuleScarry),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    fn operation(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        code: i32,
        inputs: Vec<VarnodeId>,
        size: u32,
    ) -> OpId {
        let address = data.block(block).start + data.block(block).ops.len() as u64 * 4;
        let id = data.new_op(code, seq(address), inputs);
        let out = data.new_unique(size);
        data.op_set_output(id, Some(out));
        data.op_insert_end(id, block);
        id
    }

    macro_rules! operation_with {
        ($data:expr, $block:expr, $code:expr, [$($value:expr),* $(,)?], $size:expr) => {{
            let mut inputs = Vec::new();
            $(inputs.push($value);)*
            operation($data, $block, $code, inputs, $size)
        }};
    }

    fn output_of(data: &Funcdata, id: OpId) -> VarnodeId {
        data.op(id).output.expect("test operation has an output")
    }

    fn input_value(data: &Funcdata, id: OpId, slot: usize) -> VarnodeId {
        data.op(id).inputs[slot]
    }

    fn input_value_node(data: &mut Funcdata, offset: u64, size: u32) -> VarnodeId {
        let value = data.new_varnode(REGISTER_SPACE, offset, size);
        data.mark_input(value);
        value
    }

    #[test]
    fn divopt_recovers_three_from_gcc_magic_sequence() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let x = input_value_node(&mut data, 0, 4);
        let zext = operation_with!(&mut data, block, op::INT_ZEXT, [x], 8);
        let magic = data.new_constant(0xaaaa_aaab, 8);
        let product = operation_with!(
            &mut data,
            block,
            op::INT_MULT,
            [output_of(&data, zext), magic],
            8
        );
        let high = data.new_constant(4, 4);
        let high_piece = operation_with!(
            &mut data,
            block,
            op::SUBPIECE,
            [output_of(&data, product), high],
            4
        );
        let shift_one = data.new_constant(1, 4);
        let quotient = operation_with!(
            &mut data,
            block,
            op::INT_RIGHT,
            [output_of(&data, high_piece), shift_one],
            4
        );

        assert_eq!(RuleDivOpt.apply_op(quotient, &mut data), 1);
        assert_eq!(data.op(quotient).opcode, op::INT_DIV);
        assert_eq!(input_value(&data, quotient, 0), x);
        let divisor = input_value(&data, quotient, 1);
        assert!(is_constant(&data, divisor));
        assert_eq!(data.varnode(divisor).offset, 3);
    }

    #[test]
    fn divchain_multiplies_constant_divisors() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let x = input_value_node(&mut data, 0, 4);
        let first_divisor = data.new_constant(3, 4);
        let inner = operation_with!(&mut data, block, op::INT_DIV, [x, first_divisor], 4);
        let second_divisor = data.new_constant(5, 4);
        let outer = operation_with!(
            &mut data,
            block,
            op::INT_DIV,
            [output_of(&data, inner), second_divisor],
            4
        );
        assert_eq!(RuleDivChain.apply_op(outer, &mut data), 1);
        assert_eq!(data.op(outer).inputs[0], x);
        assert_eq!(data.varnode(data.op(outer).inputs[1]).offset, 15);
    }

    #[test]
    fn divtermadd2_rewrites_the_second_correction() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let x = input_value_node(&mut data, 0, 4);
        let zext = operation_with!(&mut data, block, op::INT_ZEXT, [x], 8);
        let coefficient = data.new_constant(0x1234, 8);
        let product = operation_with!(
            &mut data,
            block,
            op::INT_MULT,
            [output_of(&data, zext), coefficient],
            8
        );
        let cut = data.new_constant(4, 4);
        let high = operation_with!(
            &mut data,
            block,
            op::SUBPIECE,
            [output_of(&data, product), cut],
            4
        );
        let neg_one = data.new_constant(mask(4), 4);
        let neg = operation_with!(
            &mut data,
            block,
            op::INT_MULT,
            [output_of(&data, high), neg_one],
            4
        );
        let add = operation_with!(&mut data, block, op::INT_ADD, [output_of(&data, neg), x], 4);
        let one = data.new_constant(1, 4);
        let shift = operation_with!(
            &mut data,
            block,
            op::INT_RIGHT,
            [output_of(&data, add), one],
            4
        );
        let after = operation_with!(
            &mut data,
            block,
            op::INT_ADD,
            [output_of(&data, shift), output_of(&data, high)],
            4
        );

        assert_eq!(RuleDivTermAdd2.apply_op(shift, &mut data), 1);
        assert_eq!(data.op(after).opcode, op::SUBPIECE);
        let new_shift = data.op(after).inputs[0];
        let new_shift_def = def(&data, new_shift).expect("new shift definition");
        assert_eq!(data.op(new_shift_def).opcode, op::INT_RIGHT);
        assert_eq!(data.varnode(data.op(new_shift_def).inputs[1]).offset, 33);
    }

    #[test]
    fn signform2_replaces_high_product_with_base() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let base = input_value_node(&mut data, 0, 4);
        let sext = operation_with!(&mut data, block, op::INT_SEXT, [base], 8);
        let small = data.new_constant(3, 8);
        let product = operation_with!(
            &mut data,
            block,
            op::INT_MULT,
            [output_of(&data, sext), small],
            8
        );
        let cut = data.new_constant(4, 4);
        let high = operation_with!(
            &mut data,
            block,
            op::SUBPIECE,
            [output_of(&data, product), cut],
            4
        );
        let amount = data.new_constant(31, 4);
        let sign = operation_with!(
            &mut data,
            block,
            op::INT_SRIGHT,
            [output_of(&data, high), amount],
            4
        );
        assert_eq!(RuleSignForm2.apply_op(sign, &mut data), 1);
        assert_eq!(data.op(sign).inputs[0], base);
    }

    #[test]
    fn signmod2opt_rewrites_outer_add_to_srem() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let base = input_value_node(&mut data, 0, 4);
        let amount = data.new_constant(31, 4);
        let sign = operation_with!(&mut data, block, op::INT_SRIGHT, [base, amount], 4);
        let neg_one = data.new_constant(mask(4), 4);
        let neg = operation_with!(
            &mut data,
            block,
            op::INT_MULT,
            [output_of(&data, sign), neg_one],
            4
        );
        let inner = operation_with!(
            &mut data,
            block,
            op::INT_ADD,
            [output_of(&data, neg), base],
            4
        );
        let one = data.new_constant(1, 4);
        let and = operation_with!(
            &mut data,
            block,
            op::INT_AND,
            [output_of(&data, inner), one],
            4
        );
        let outer = operation_with!(
            &mut data,
            block,
            op::INT_ADD,
            [output_of(&data, and), output_of(&data, sign)],
            4
        );
        assert_eq!(RuleSignMod2Opt.apply_op(and, &mut data), 1);
        assert_eq!(data.op(outer).opcode, op::INT_SREM);
        assert_eq!(data.op(outer).inputs[0], base);
        assert_eq!(data.varnode(data.op(outer).inputs[1]).offset, 2);
    }

    #[test]
    fn signmod2nopt_rewrites_power_of_two_correction() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let base = input_value_node(&mut data, 0, 4);
        let sign_amount = data.new_constant(31, 4);
        let sign = operation_with!(&mut data, block, op::INT_SRIGHT, [base, sign_amount], 4);
        let correction_amount = data.new_constant(30, 4);
        let correction = operation_with!(
            &mut data,
            block,
            op::INT_RIGHT,
            [output_of(&data, sign), correction_amount],
            4
        );
        let neg_one = data.new_constant(mask(4), 4);
        let neg = operation_with!(
            &mut data,
            block,
            op::INT_MULT,
            [output_of(&data, correction), neg_one],
            4
        );
        let add = operation_with!(
            &mut data,
            block,
            op::INT_ADD,
            [base, output_of(&data, correction)],
            4
        );
        let modulo_mask = data.new_constant(3, 4);
        let and = operation_with!(
            &mut data,
            block,
            op::INT_AND,
            [output_of(&data, add), modulo_mask],
            4
        );
        let outer = operation_with!(
            &mut data,
            block,
            op::INT_ADD,
            [output_of(&data, and), output_of(&data, neg)],
            4
        );
        assert_eq!(RuleSignMod2nOpt.apply_op(correction, &mut data), 1);
        assert_eq!(data.op(outer).opcode, op::INT_SREM);
        assert_eq!(data.op(outer).inputs[0], base);
        assert_eq!(data.varnode(data.op(outer).inputs[1]).offset, 4);
    }

    #[test]
    fn signmod2nopt2_rewrites_sign_extension_adjustment() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let base = input_value_node(&mut data, 0, 4);
        let sign_amount = data.new_constant(31, 4);
        let sign = operation_with!(&mut data, block, op::INT_SRIGHT, [base, sign_amount], 4);
        let neg_one = data.new_constant(mask(4), 4);
        let neg_sign = operation_with!(
            &mut data,
            block,
            op::INT_MULT,
            [output_of(&data, sign), neg_one],
            4
        );
        let adjusted = operation_with!(
            &mut data,
            block,
            op::INT_ADD,
            [base, output_of(&data, neg_sign)],
            4
        );
        let and_mask = data.new_constant(mask(4) - 1, 4);
        let and = operation_with!(
            &mut data,
            block,
            op::INT_AND,
            [output_of(&data, adjusted), and_mask],
            4
        );
        let root_neg_one = data.new_constant(mask(4), 4);
        let root = operation_with!(
            &mut data,
            block,
            op::INT_MULT,
            [output_of(&data, and), root_neg_one],
            4
        );
        let outer = operation_with!(
            &mut data,
            block,
            op::INT_ADD,
            [output_of(&data, root), base],
            4
        );
        assert_eq!(RuleSignMod2nOpt2.apply_op(root, &mut data), 1);
        assert_eq!(data.op(outer).opcode, op::INT_SREM);
        assert_eq!(data.op(outer).inputs[0], base);
        assert_eq!(data.varnode(data.op(outer).inputs[1]).offset, 2);
    }

    #[test]
    fn carryelim_turns_constant_carry_into_less_equal() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value_node(&mut data, 0, 4);
        let carry_constant = data.new_constant(3, 4);
        let carry = operation_with!(&mut data, block, op::INT_CARRY, [value, carry_constant], 1);
        assert_eq!(RuleCarryElim.apply_op(carry, &mut data), 1);
        assert_eq!(data.op(carry).opcode, op::INT_LESSEQUAL);
        assert_eq!(data.varnode(data.op(carry).inputs[0]).offset, mask(4) - 2);
        assert_eq!(data.op(carry).inputs[1], value);
    }

    #[test]
    fn sborrow_rewrites_subtraction_sign_test() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let a = input_value_node(&mut data, 0, 4);
        let b = input_value_node(&mut data, 4, 4);
        let subtract = operation_with!(&mut data, block, op::INT_SUB, [a, b], 4);
        let zero = data.new_constant(0, 4);
        let sign = operation_with!(
            &mut data,
            block,
            op::INT_SLESS,
            [zero, output_of(&data, subtract)],
            1
        );
        let borrow = operation_with!(&mut data, block, op::INT_SBORROW, [a, b], 1);
        let compare = operation_with!(
            &mut data,
            block,
            op::INT_NOTEQUAL,
            [output_of(&data, borrow), output_of(&data, sign)],
            1
        );
        assert_eq!(RuleSborrow.apply_op(borrow, &mut data), 1);
        assert_eq!(data.op(compare).opcode, op::INT_SLESS);
        assert_eq!(data.op(compare).inputs, vec![b, a]);
    }

    #[test]
    fn scarry_rewrites_addition_sign_test() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let a = input_value_node(&mut data, 0, 4);
        let b = data.new_constant(3, 4);
        let add = operation_with!(&mut data, block, op::INT_ADD, [a, b], 4);
        let zero = data.new_constant(0, 4);
        let sign = operation_with!(
            &mut data,
            block,
            op::INT_SLESS,
            [zero, output_of(&data, add)],
            1
        );
        let carry = operation_with!(&mut data, block, op::INT_SCARRY, [a, b], 1);
        let compare = operation_with!(
            &mut data,
            block,
            op::INT_NOTEQUAL,
            [output_of(&data, carry), output_of(&data, sign)],
            1
        );
        assert_eq!(RuleScarry.apply_op(carry, &mut data), 1);
        assert_eq!(data.op(compare).opcode, op::INT_SLESS);
        assert_eq!(data.varnode(data.op(compare).inputs[0]).offset, mask(4) - 2);
        assert_eq!(data.op(compare).inputs[1], a);
    }
}
