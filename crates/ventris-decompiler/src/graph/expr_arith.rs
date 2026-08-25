//! Integer arithmetic and shift rewrites from Ghidra 12.1.3's
//! `ruleaction.cc`.
//!
//! Source authority for every implementation below is the corresponding
//! `Rule*::applyOp` in
//! `C:/Tools/ghidra_12.1.3_PUBLIC/Ghidra/Features/Decompiler/src/decompile/cpp/ruleaction.cc`.
//! The graph deliberately exposes only SSA structure, constants, locations,
//! and the cached non-zero mask table, so the rules that require Ghidra's type,
//! address, or precision side tables are omitted rather than approximated.
//!
//! Omitted requested rules:
//!
//! * `RuleAddUnsigned` requires `Datatype::getMetatype`, character-printing
//!   classification, enum named-value lookup, and equate-symbol lock state.
//! * `RuleLeftRight` requires address endianness, address renormalization, and
//!   `Funcdata::newVarnodeOut`'s location-aware allocator. `GraphVarnode` stores
//!   a location but `Funcdata` does not expose the architecture endianness that
//!   selects the SUBPIECE offset.
//! * `RuleSubCommute` requires precise-low/precise-high flags, spacebase
//!   classification, and the C++ `shortenExtension`/location-aware partial
//!   commute machinery.
//! * `RuleMultNegOne` is the exact inverse of the implemented
//!   `Rule2Comp2Mult`. The graph has no provenance bit with which to make the
//!   two guards disjoint, so registering both would make the fixed-point pool
//!   alternate forever. It is intentionally omitted; `Rule2Comp2Mult` is the
//!   canonical direction in this module.
//!
//! `RuleBitUndistribute` is not an inverse of the live `RuleAndDistribute` on
//! any accepted shape here: `RuleAndDistribute` is offered only an outer
//! `INT_AND` with an inner `INT_OR`, while this rule requires equal inner
//! extensions or equal shifts and then changes the outer opcode to that
//! extension/shift. Their opcode/shape guards are therefore disjoint.
//!
//! All bit reasoning goes through `Funcdata::nonzero_masks`; duplicating the
//! mask transfer here would let inverse rules disagree and oscillate.

use super::action::Rule;
use super::{Funcdata, OpId, VarnodeId};
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

fn definition(data: &Funcdata, value: VarnodeId) -> Option<OpId> {
    data.varnode(value).def
}

fn is_constant(data: &Funcdata, value: VarnodeId) -> bool {
    data.varnode(value).flags.constant
}

/// Exact graph equivalent of Ghidra's `Varnode::isFree`.
fn is_free(data: &Funcdata, value: VarnodeId) -> bool {
    let node = data.varnode(value);
    !node.flags.written && !node.flags.input
}

/// Read the one graph-wide non-zero mask cache used by all mask rules.
fn nonzero_mask(data: &Funcdata, value: VarnodeId) -> u64 {
    data.nonzero_masks()[value.0 as usize]
}

/// `-V -> V * -1`.
pub struct Rule2Comp2Mult;

impl Rule for Rule2Comp2Mult {
    fn name(&self) -> &'static str {
        "2comp2mult"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_2COMP]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(value) = input(data, id, 0) else {
            return 0;
        };
        let size = data.varnode(value).size;
        let neg_one = data.new_constant(mask(size), size);
        data.op_set_opcode(id, op::INT_MULT);
        data.op_set_inputs(id, vec![value, neg_one]);
        1
    }
}

/// `V - W -> V + (W * -1)`.
pub struct RuleSub2Add;

impl Rule for RuleSub2Add {
    fn name(&self) -> &'static str {
        "sub2add"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_SUB]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(left) = input(data, id, 0) else {
            return 0;
        };
        let Some(subtrahend) = input(data, id, 1) else {
            return 0;
        };
        let seq = data.op(id).seq;
        let size = data.varnode(subtrahend).size;
        let neg_one = data.new_constant(mask(size), size);
        let multiply = data.new_op(op::INT_MULT, seq, vec![subtrahend, neg_one]);
        let multiply_out = data.new_unique(size);
        data.op_set_output(multiply, Some(multiply_out));
        data.op_insert_before(multiply, id);
        data.op_set_opcode(id, op::INT_ADD);
        data.op_set_inputs(id, vec![left, multiply_out]);
        1
    }
}

/// `-W` feeding `V + -W` is printed as `V - W`.
pub struct Rule2Comp2Sub;

impl Rule for Rule2Comp2Sub {
    fn name(&self) -> &'static str {
        "2comp2sub"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_2COMP]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(negated) = output(data, id) else {
            return 0;
        };
        let Some(add) = data.lone_descend(negated) else {
            return 0;
        };
        if data.opcode_of(add) != Some(op::INT_ADD) {
            return 0;
        }
        let Some(source) = input(data, id, 0) else {
            return 0;
        };
        let Some(add_left) = input(data, add, 0) else {
            return 0;
        };
        let Some(add_right) = input(data, add, 1) else {
            return 0;
        };
        if add_left == negated {
            data.op_set_input(add, add_right, 0);
        }
        data.op_set_input(add, source, 1);
        data.op_set_opcode(add, op::INT_SUB);
        data.op_destroy(id);
        1
    }
}

/// Collapse nested constant AND/OR/XOR operations.
pub struct RuleAndOrLump;

impl Rule for RuleAndOrLump {
    fn name(&self) -> &'static str {
        "andorlump"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_AND, op::INT_OR, op::INT_XOR]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(constant) = input(data, id, 1) else {
            return 0;
        };
        if !is_constant(data, constant) {
            return 0;
        }
        let Some(inner_value) = input(data, id, 0) else {
            return 0;
        };
        if !data.varnode(inner_value).flags.written {
            return 0;
        }
        let Some(inner) = definition(data, inner_value) else {
            return 0;
        };
        let opcode = data.op(id).opcode;
        if data.opcode_of(inner) != Some(opcode) {
            return 0;
        }
        let Some(inner_constant) = input(data, inner, 1) else {
            return 0;
        };
        if !is_constant(data, inner_constant) {
            return 0;
        }
        let Some(base) = input(data, inner, 0) else {
            return 0;
        };
        if is_free(data, base) {
            return 0;
        }

        let value = data.varnode(constant).offset;
        let value2 = data.varnode(inner_constant).offset;
        let combined = match opcode {
            op::INT_AND => value & value2,
            op::INT_OR => value | value2,
            op::INT_XOR => value ^ value2,
            _ => return 0,
        };
        let size = data.varnode(base).size;
        let folded = data.new_constant(combined, size);
        data.op_set_inputs(id, vec![base, folded]);
        1
    }
}

/// Remove an AND whose discarded bits are already impossible after a shift.
pub struct RuleShiftAnd;

impl Rule for RuleShiftAnd {
    fn name(&self) -> &'static str {
        "shiftand"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_RIGHT, op::INT_LEFT, op::INT_MULT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(shift_constant) = input(data, id, 1) else {
            return 0;
        };
        if !is_constant(data, shift_constant) {
            return 0;
        }
        let Some(shifted) = input(data, id, 0) else {
            return 0;
        };
        let Some(and_op) = definition(data, shifted) else {
            return 0;
        };
        if data.opcode_of(and_op) != Some(op::INT_AND) {
            return 0;
        }
        let Some(and_mask) = input(data, and_op, 1) else {
            return 0;
        };
        if !is_constant(data, and_mask) {
            return 0;
        }
        let Some(root) = input(data, and_op, 0) else {
            return 0;
        };
        if is_free(data, root) {
            return 0;
        }

        let raw_amount = data.varnode(shift_constant).offset;
        let opcode = data.op(id).opcode;
        let (normalized, amount) = if opcode == op::INT_MULT {
            if raw_amount == 0 {
                return 0;
            }
            let amount = raw_amount.trailing_zeros() as u64;
            if amount == 0 || amount >= 64 || (1u64 << amount) != raw_amount {
                return 0;
            }
            (op::INT_LEFT, amount)
        } else if matches!(opcode, op::INT_RIGHT | op::INT_LEFT) {
            if raw_amount >= 64 {
                return 0;
            }
            (opcode, raw_amount)
        } else {
            return 0;
        };

        let root_mask = nonzero_mask(data, root);
        let full = mask(data.varnode(root).size);
        let mut possible = root_mask;
        let mut retained = data.varnode(and_mask).offset;
        if normalized == op::INT_RIGHT {
            possible >>= amount;
            retained >>= amount;
        } else {
            possible = possible.wrapping_shl(amount as u32) & full;
            retained = retained.wrapping_shl(amount as u32) & full;
        }
        if retained & possible != possible {
            return 0;
        }
        data.op_set_input(id, root, 0);
        1
    }
}

/// Remove a complete high-bit mask before a right shift.
pub struct RuleRightShiftAnd;

impl Rule for RuleRightShiftAnd {
    fn name(&self) -> &'static str {
        "rightshiftand"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_RIGHT, op::INT_SRIGHT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(shift_constant) = input(data, id, 1) else {
            return 0;
        };
        if !is_constant(data, shift_constant) {
            return 0;
        }
        let Some(shifted) = input(data, id, 0) else {
            return 0;
        };
        let Some(and_op) = definition(data, shifted) else {
            return 0;
        };
        if data.opcode_of(and_op) != Some(op::INT_AND) {
            return 0;
        }
        let Some(and_mask) = input(data, and_op, 1) else {
            return 0;
        };
        if !is_constant(data, and_mask) {
            return 0;
        }
        let Some(root) = input(data, and_op, 0) else {
            return 0;
        };
        if is_free(data, root) {
            return 0;
        }
        let amount = data.varnode(shift_constant).offset;
        if amount >= 64 {
            return 0;
        }
        let shifted_mask = data.varnode(and_mask).offset >> amount;
        let expected = mask(data.varnode(root).size) >> amount;
        if shifted_mask != expected {
            return 0;
        }
        data.op_set_input(id, root, 0);
        1
    }
}

/// Move a high-order mask through an aligned addition.
pub struct RuleHighOrderAnd;

impl Rule for RuleHighOrderAnd {
    fn name(&self) -> &'static str {
        "highorderand"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_AND]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(and_constant) = input(data, id, 1) else {
            return 0;
        };
        if !is_constant(data, and_constant) {
            return 0;
        }
        let Some(added_value) = input(data, id, 0) else {
            return 0;
        };
        let Some(add_op) = definition(data, added_value) else {
            return 0;
        };
        if data.opcode_of(add_op) != Some(op::INT_ADD) {
            return 0;
        }
        let value = data.varnode(and_constant).offset;
        let size = data.varnode(and_constant).size;
        let full = mask(size);
        if (value.wrapping_sub(1) | value) != full {
            return 0;
        }
        let Some(add_constant) = input(data, add_op, 1) else {
            return 0;
        };
        let Some(add_left) = input(data, add_op, 0) else {
            return 0;
        };

        if is_constant(data, add_constant) {
            if is_free(data, add_left) {
                return 0;
            }
            let possible = nonzero_mask(data, add_left);
            if possible & value != possible {
                return 0;
            }
            let folded = data.new_constant(value & data.varnode(add_constant).offset, size);
            data.op_set_opcode(id, op::INT_ADD);
            data.op_set_inputs(id, vec![add_left, folded]);
            return 1;
        }

        if data.varnode(added_value).descendants.len() != 1 {
            return 0;
        }
        for zero_slot in 0..2 {
            let Some(zero_value) = input(data, add_op, zero_slot) else {
                continue;
            };
            let zero_mask = nonzero_mask(data, zero_value);
            if zero_mask & value != zero_mask {
                continue;
            }
            let nonzero_slot = 1 - zero_slot;
            let Some(nonzero_value) = input(data, add_op, nonzero_slot) else {
                continue;
            };
            let Some(add2_op) = definition(data, nonzero_value) else {
                continue;
            };
            if data.opcode_of(add2_op) != Some(op::INT_ADD) {
                continue;
            }
            if data.varnode(nonzero_value).descendants.len() != 1 {
                continue;
            }
            let Some(add2_constant) = input(data, add2_op, 1) else {
                continue;
            };
            if !is_constant(data, add2_constant) {
                continue;
            }
            let Some(add2_left) = input(data, add2_op, 0) else {
                continue;
            };
            if nonzero_mask(data, add2_left) & value != nonzero_mask(data, add2_left) {
                continue;
            }
            let folded = data.new_constant(value & data.varnode(add2_constant).offset, size);
            data.op_set_input(add2_op, folded, 1);
            let retained = input(data, id, 0).expect("the AND input was checked above");
            data.op_set_inputs(id, vec![retained]);
            data.op_set_opcode(id, op::COPY);
            return 1;
        }
        0
    }
}

/// Combine two equal extensions or shifts around one bitwise operation.
pub struct RuleBitUndistribute;

impl Rule for RuleBitUndistribute {
    fn name(&self) -> &'static str {
        "bitundistribute"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_AND, op::INT_OR, op::INT_XOR]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(first) = input(data, id, 0) else {
            return 0;
        };
        let Some(second) = input(data, id, 1) else {
            return 0;
        };
        let Some(first_def) = definition(data, first) else {
            return 0;
        };
        let Some(second_def) = definition(data, second) else {
            return 0;
        };
        let Some(inner_opcode) = data.opcode_of(first_def) else {
            return 0;
        };
        if data.opcode_of(second_def) != Some(inner_opcode) {
            return 0;
        }
        let outer_opcode = data.op(id).opcode;
        let (small_first, small_second, extra) = match inner_opcode {
            op::INT_ZEXT | op::INT_SEXT => {
                let Some(left) = input(data, first_def, 0) else {
                    return 0;
                };
                let Some(right) = input(data, second_def, 0) else {
                    return 0;
                };
                if is_free(data, left) || is_free(data, right) {
                    return 0;
                }
                if data.varnode(left).size != data.varnode(right).size {
                    return 0;
                }
                (left, right, None)
            }
            op::INT_LEFT | op::INT_RIGHT | op::INT_SRIGHT => {
                let Some(left_shift) = input(data, first_def, 1) else {
                    return 0;
                };
                let Some(right_shift) = input(data, second_def, 1) else {
                    return 0;
                };
                let shift = if is_constant(data, left_shift) && is_constant(data, right_shift) {
                    if data.varnode(left_shift).offset != data.varnode(right_shift).offset {
                        return 0;
                    }
                    data.new_constant(
                        data.varnode(left_shift).offset,
                        data.varnode(left_shift).size,
                    )
                } else {
                    if left_shift != right_shift || is_free(data, left_shift) {
                        return 0;
                    }
                    left_shift
                };
                let Some(left) = input(data, first_def, 0) else {
                    return 0;
                };
                let Some(right) = input(data, second_def, 0) else {
                    return 0;
                };
                if is_free(data, left) || is_free(data, right) {
                    return 0;
                }
                (left, right, Some(shift))
            }
            _ => return 0,
        };

        let size = data.varnode(small_first).size;
        let seq = data.op(id).seq;
        let new_inner = data.new_op(outer_opcode, seq, vec![small_first, small_second]);
        let small_logic = data.new_unique(size);
        data.op_set_output(new_inner, Some(small_logic));
        data.op_insert_before(new_inner, id);

        if let Some(extra) = extra {
            data.op_set_opcode(id, inner_opcode);
            data.op_set_inputs(id, vec![small_logic, extra]);
        } else {
            data.op_set_opcode(id, inner_opcode);
            data.op_set_inputs(id, vec![small_logic]);
        }
        1
    }
}

/// Remove a redundant nested zero-extension, or preserve a left shift while
/// collapsing its inner zero-extension.
pub struct RuleZextShiftZext;

impl Rule for RuleZextShiftZext {
    fn name(&self) -> &'static str {
        "zextshiftzext"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_ZEXT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(inner_value) = input(data, id, 0) else {
            return 0;
        };
        let Some(inner_op) = definition(data, inner_value) else {
            return 0;
        };
        match data.opcode_of(inner_op) {
            Some(op::INT_ZEXT) => {
                let Some(root) = input(data, inner_op, 0) else {
                    return 0;
                };
                if is_free(data, root) || data.lone_descend(inner_value) != Some(id) {
                    return 0;
                }
                data.op_set_input(id, root, 0);
                1
            }
            Some(op::INT_LEFT) => {
                let Some(amount) = input(data, inner_op, 1) else {
                    return 0;
                };
                if !is_constant(data, amount) {
                    return 0;
                }
                let Some(zext_input) = input(data, inner_op, 0) else {
                    return 0;
                };
                let Some(zext_op) = definition(data, zext_input) else {
                    return 0;
                };
                if data.opcode_of(zext_op) != Some(op::INT_ZEXT) {
                    return 0;
                }
                let Some(root) = input(data, zext_op, 0) else {
                    return 0;
                };
                if is_free(data, root) {
                    return 0;
                }
                let shift = data.varnode(amount).offset;
                let Some(zext_size) = data
                    .op(inner_op)
                    .output
                    .map(|value| data.varnode(value).size)
                else {
                    return 0;
                };
                let Some(outer_output) = output(data, id) else {
                    return 0;
                };
                let root_size = data.varnode(root).size;
                let widened = zext_size.saturating_sub(root_size).saturating_mul(8);
                if shift > u64::from(widened) {
                    return 0;
                }
                let seq = data.op(id).seq;
                let new_zext = data.new_op(op::INT_ZEXT, seq, vec![root]);
                let new_out = data.new_unique(data.varnode(outer_output).size);
                data.op_set_output(new_zext, Some(new_out));
                data.op_insert_before(new_zext, id);
                let shift_constant = data.new_constant(shift, 4);
                data.op_set_opcode(id, op::INT_LEFT);
                data.op_set_inputs(id, vec![new_out, shift_constant]);
                1
            }
            _ => 0,
        }
    }
}

/// Convert a sign-extension masked to its source width into a zero-extension.
pub struct RuleAndZext;

impl Rule for RuleAndZext {
    fn name(&self) -> &'static str {
        "andzext"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_AND]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(and_constant) = input(data, id, 1) else {
            return 0;
        };
        if !is_constant(data, and_constant) {
            return 0;
        }
        let Some(extended) = input(data, id, 0) else {
            return 0;
        };
        let Some(extension) = definition(data, extended) else {
            return 0;
        };
        let extension_opcode = data.opcode_of(extension);
        let source_slot = match extension_opcode {
            Some(op::INT_SEXT) => 0,
            Some(op::PIECE) => 1,
            _ => return 0,
        };
        let Some(root) = input(data, extension, source_slot) else {
            return 0;
        };
        if data.varnode(root).size > 8 || is_free(data, root) {
            return 0;
        }
        if mask(data.varnode(root).size) != data.varnode(and_constant).offset {
            return 0;
        }
        data.op_set_opcode(id, op::INT_ZEXT);
        data.op_set_inputs(id, vec![root]);
        1
    }
}

/// Turn a sign-bit logical shift used arithmetically into a signed shift and
/// multiplication by all ones.
pub struct RuleSignShift;

impl Rule for RuleSignShift {
    fn name(&self) -> &'static str {
        "signshift"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_RIGHT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(amount) = input(data, id, 1) else {
            return 0;
        };
        if !is_constant(data, amount) {
            return 0;
        }
        let Some(root) = input(data, id, 0) else {
            return 0;
        };
        let bits = data.varnode(root).size.saturating_mul(8);
        if bits == 0 || data.varnode(amount).offset != u64::from(bits - 1) || is_free(data, root) {
            return 0;
        }
        let Some(sign_value) = output(data, id) else {
            return 0;
        };
        let should_convert =
            data.varnode(sign_value)
                .descendants
                .iter()
                .copied()
                .any(|descendant| match data.opcode_of(descendant) {
                    Some(op::INT_EQUAL | op::INT_NOTEQUAL) => {
                        input(data, descendant, 1).is_some_and(|value| is_constant(data, value))
                    }
                    Some(op::INT_ADD | op::INT_MULT) => true,
                    _ => false,
                });
        if !should_convert {
            return 0;
        }

        let seq = data.op(id).seq;
        let signed_shift = data.new_op(op::INT_SRIGHT, seq, vec![root, amount]);
        let signed_out = data.new_unique(data.varnode(root).size);
        data.op_set_output(signed_shift, Some(signed_out));
        data.op_insert_before(signed_shift, id);
        let all_ones = data.new_constant(mask(data.varnode(root).size), data.varnode(root).size);
        data.op_set_opcode(id, op::INT_MULT);
        data.op_set_inputs(id, vec![signed_out, all_ones]);
        1
    }
}

/// Combine sequential signed right shifts, saturating at the sign bit.
pub struct RuleDoubleArithShift;

impl Rule for RuleDoubleArithShift {
    fn name(&self) -> &'static str {
        "doublearithshift"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_SRIGHT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(outer_amount) = input(data, id, 1) else {
            return 0;
        };
        if !is_constant(data, outer_amount) {
            return 0;
        }
        let Some(shifted) = input(data, id, 0) else {
            return 0;
        };
        let Some(inner) = definition(data, shifted) else {
            return 0;
        };
        if data.opcode_of(inner) != Some(op::INT_SRIGHT) {
            return 0;
        }
        let Some(inner_amount) = input(data, inner, 1) else {
            return 0;
        };
        if !is_constant(data, inner_amount) {
            return 0;
        }
        let Some(root) = input(data, inner, 0) else {
            return 0;
        };
        if is_free(data, root) {
            return 0;
        }
        let Some(result) = output(data, id) else {
            return 0;
        };
        let max = data
            .varnode(result)
            .size
            .saturating_mul(8)
            .saturating_sub(1);
        let inner_shift = data.varnode(inner_amount).offset;
        let outer_shift = data.varnode(outer_amount).offset;
        let Some(mut combined) = inner_shift.checked_add(outer_shift) else {
            return 0;
        };
        if combined == 0 {
            return 0;
        }
        if combined > u64::from(max) {
            combined = u64::from(max);
        }
        data.op_set_input(id, root, 0);
        let shift = data.new_constant(combined, 4);
        data.op_set_input(id, shift, 1);
        1
    }
}

#[cfg(test)]
mod tests {
    use super::super::{GraphBlockId, SeqNum};
    use super::*;
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    fn input_value(data: &mut Funcdata, size: u32) -> VarnodeId {
        let value = data.new_varnode(REGISTER_SPACE, data.varnode_count() as u64 * 8, size);
        data.mark_input(value);
        value
    }

    fn free_value(data: &mut Funcdata, size: u32) -> VarnodeId {
        data.new_varnode(REGISTER_SPACE, data.varnode_count() as u64 * 8, size)
    }

    fn unary(
        data: &mut Funcdata,
        block: GraphBlockId,
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

    fn binary(
        data: &mut Funcdata,
        block: GraphBlockId,
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

    #[test]
    fn two_comp_to_mult_fires() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let (op_id, _) = unary(&mut data, block, op::INT_2COMP, value, 4);
        assert_eq!(Rule2Comp2Mult.apply_op(op_id, &mut data), 1);
        assert_eq!(data.op(op_id).opcode, op::INT_MULT);
        assert_eq!(data.op(op_id).inputs.len(), 2);
        assert_eq!(data.varnode(data.op(op_id).inputs[1]).offset, 0xffff_ffff);
    }

    #[test]
    fn two_comp_to_sub_fires_and_declines_without_lone_add_use() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let (negate, negated) = unary(&mut data, block, op::INT_2COMP, value, 4);
        let other = input_value(&mut data, 4);
        let (add, _) = binary(&mut data, block, op::INT_ADD, negated, other, 4);
        assert_eq!(Rule2Comp2Sub.apply_op(negate, &mut data), 1);
        assert_eq!(data.op(add).opcode, op::INT_SUB);
        assert_eq!(data.op(add).inputs, vec![other, value]);
        assert!(data.opcode_of(negate).is_none());

        let (unused, _) = unary(&mut data, block, op::INT_2COMP, value, 4);
        assert_eq!(Rule2Comp2Sub.apply_op(unused, &mut data), 0);
    }

    #[test]
    fn sub_to_add_fires() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = input_value(&mut data, 4);
        let right = input_value(&mut data, 4);
        let (sub, _) = binary(&mut data, block, op::INT_SUB, left, right, 4);
        assert_eq!(RuleSub2Add.apply_op(sub, &mut data), 1);
        assert_eq!(data.op(sub).opcode, op::INT_ADD);
        let product = data.op(sub).inputs[1];
        let product_def = data.varnode(product).def.expect("inserted multiply");
        assert_eq!(data.op(product_def).opcode, op::INT_MULT);
        assert_eq!(
            data.varnode(data.op(product_def).inputs[1]).offset,
            0xffff_ffff
        );
    }

    #[test]
    fn and_or_lump_fires_and_declines_for_free_base() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let first = data.new_constant(0xf0, 4);
        let (_, inner_out) = binary(&mut data, block, op::INT_AND, value, first, 4);
        let second = data.new_constant(0x0f, 4);
        let (outer, _) = binary(&mut data, block, op::INT_AND, inner_out, second, 4);
        assert_eq!(RuleAndOrLump.apply_op(outer, &mut data), 1);
        assert_eq!(data.op(outer).inputs[0], value);
        assert_eq!(data.varnode(data.op(outer).inputs[1]).offset, 0);

        let free = free_value(&mut data, 4);
        let (_, free_inner_out) = binary(&mut data, block, op::INT_AND, free, first, 4);
        let (bad, _) = binary(&mut data, block, op::INT_AND, free_inner_out, second, 4);
        assert_eq!(RuleAndOrLump.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn shift_and_fires_and_declines_when_a_bit_survives() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let inner_mask = data.new_constant(0xffff_ff00, 4);
        let (_, and_out) = binary(&mut data, block, op::INT_AND, value, inner_mask, 4);
        let amount = data.new_constant(8, 4);
        let (shift, _) = binary(&mut data, block, op::INT_RIGHT, and_out, amount, 4);
        assert_eq!(RuleShiftAnd.apply_op(shift, &mut data), 1);
        assert_eq!(data.op(shift).inputs[0], value);

        let bad_mask = data.new_constant(0x0000_ff00, 4);
        let (_, bad_and_out) = binary(&mut data, block, op::INT_AND, value, bad_mask, 4);
        let (bad, _) = binary(&mut data, block, op::INT_RIGHT, bad_and_out, amount, 4);
        assert_eq!(RuleShiftAnd.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn right_shift_and_fires_and_declines_for_partial_mask() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let full_mask = data.new_constant(0xffff_ffff, 4);
        let (_, and_out) = binary(&mut data, block, op::INT_AND, value, full_mask, 4);
        let amount = data.new_constant(8, 4);
        let (shift, _) = binary(&mut data, block, op::INT_RIGHT, and_out, amount, 4);
        assert_eq!(RuleRightShiftAnd.apply_op(shift, &mut data), 1);
        assert_eq!(data.op(shift).inputs[0], value);

        let partial = data.new_constant(0x0fff_ffff, 4);
        let (_, partial_out) = binary(&mut data, block, op::INT_AND, value, partial, 4);
        let (bad, _) = binary(&mut data, block, op::INT_RIGHT, partial_out, amount, 4);
        assert_eq!(RuleRightShiftAnd.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn high_order_and_fires_and_declines_for_non_high_mask() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let align_mask = data.new_constant(0xffff_fff0, 4);
        let (_, aligned) = binary(&mut data, block, op::INT_AND, value, align_mask, 4);
        let addend = data.new_constant(3, 4);
        let (_, sum) = binary(&mut data, block, op::INT_ADD, aligned, addend, 4);
        let high_mask = data.new_constant(0xffff_fff0, 4);
        let (and, _) = binary(&mut data, block, op::INT_AND, sum, high_mask, 4);
        assert_eq!(RuleHighOrderAnd.apply_op(and, &mut data), 1);
        assert_eq!(data.op(and).opcode, op::INT_ADD);
        assert_eq!(data.op(and).inputs[0], aligned);
        assert_eq!(data.varnode(data.op(and).inputs[1]).offset, 0);

        let bad_mask = data.new_constant(0xf0f0_f0f0, 4);
        let (bad, _) = binary(&mut data, block, op::INT_AND, sum, bad_mask, 4);
        assert_eq!(RuleHighOrderAnd.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn bit_undistribute_fires_for_equal_zexts_and_declines_for_free_source() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = input_value(&mut data, 1);
        let right = input_value(&mut data, 1);
        let (_, left_ext) = unary(&mut data, block, op::INT_ZEXT, left, 4);
        let (_, right_ext) = unary(&mut data, block, op::INT_ZEXT, right, 4);
        let (and, _) = binary(&mut data, block, op::INT_AND, left_ext, right_ext, 4);
        assert_eq!(RuleBitUndistribute.apply_op(and, &mut data), 1);
        assert_eq!(data.op(and).opcode, op::INT_ZEXT);
        assert_eq!(data.op(and).inputs.len(), 1);
        let inner = data
            .varnode(data.op(and).inputs[0])
            .def
            .expect("new small AND");
        assert_eq!(data.op(inner).opcode, op::INT_AND);

        let free = free_value(&mut data, 1);
        let (_, free_ext) = unary(&mut data, block, op::INT_ZEXT, free, 4);
        let (_, right_ext2) = unary(&mut data, block, op::INT_ZEXT, right, 4);
        let (bad, _) = binary(&mut data, block, op::INT_AND, free_ext, right_ext2, 4);
        assert_eq!(RuleBitUndistribute.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn zext_shift_zext_fires_and_declines_when_inner_value_has_two_uses() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 1);
        let (_, inner) = unary(&mut data, block, op::INT_ZEXT, value, 2);
        let (outer, _) = unary(&mut data, block, op::INT_ZEXT, inner, 4);
        assert_eq!(RuleZextShiftZext.apply_op(outer, &mut data), 1);
        assert_eq!(data.op(outer).inputs[0], value);

        let (_, inner2) = unary(&mut data, block, op::INT_ZEXT, value, 2);
        let (_, _) = unary(&mut data, block, op::COPY, inner2, 2);
        let (bad, _) = unary(&mut data, block, op::INT_ZEXT, inner2, 4);
        assert_eq!(RuleZextShiftZext.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn and_zext_fires_and_declines_for_free_source() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 1);
        let (_, signed) = unary(&mut data, block, op::INT_SEXT, value, 4);
        let limit = data.new_constant(0xff, 4);
        let (and, _) = binary(&mut data, block, op::INT_AND, signed, limit, 4);
        assert_eq!(RuleAndZext.apply_op(and, &mut data), 1);
        assert_eq!(data.op(and).opcode, op::INT_ZEXT);
        assert_eq!(data.op(and).inputs, vec![value]);

        let free = free_value(&mut data, 1);
        let (_, free_signed) = unary(&mut data, block, op::INT_SEXT, free, 4);
        let (bad, _) = binary(&mut data, block, op::INT_AND, free_signed, limit, 4);
        assert_eq!(RuleAndZext.apply_op(bad, &mut data), 0);
    }

    #[test]
    fn sign_shift_fires_for_arithmetic_use_and_declines_when_unused() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let amount = data.new_constant(31, 4);
        let (shift, sign) = binary(&mut data, block, op::INT_RIGHT, value, amount, 4);
        let addend = input_value(&mut data, 4);
        let (_, _) = binary(&mut data, block, op::INT_ADD, sign, addend, 4);
        assert_eq!(RuleSignShift.apply_op(shift, &mut data), 1);
        assert_eq!(data.op(shift).opcode, op::INT_MULT);
        let signed = data
            .varnode(data.op(shift).inputs[0])
            .def
            .expect("signed shift");
        assert_eq!(data.op(signed).opcode, op::INT_SRIGHT);

        let (unused, _) = binary(&mut data, block, op::INT_RIGHT, value, amount, 4);
        assert_eq!(RuleSignShift.apply_op(unused, &mut data), 0);
    }

    #[test]
    fn double_arith_shift_fires_and_declines_for_dynamic_amount() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let first_amount = data.new_constant(8, 4);
        let (_, first) = binary(&mut data, block, op::INT_SRIGHT, value, first_amount, 4);
        let second_amount = data.new_constant(4, 4);
        let (outer, _) = binary(&mut data, block, op::INT_SRIGHT, first, second_amount, 4);
        assert_eq!(RuleDoubleArithShift.apply_op(outer, &mut data), 1);
        assert_eq!(data.op(outer).inputs[0], value);
        assert_eq!(data.varnode(data.op(outer).inputs[1]).offset, 12);

        let dynamic = input_value(&mut data, 4);
        let (bad, _) = binary(&mut data, block, op::INT_SRIGHT, first, dynamic, 4);
        assert_eq!(RuleDoubleArithShift.apply_op(bad, &mut data), 0);
    }
}

/// Every requested rule with a faithful graph implementation.
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(Rule2Comp2Mult),
        Box::new(Rule2Comp2Sub),
        Box::new(RuleSub2Add),
        Box::new(RuleAndOrLump),
        Box::new(RuleShiftAnd),
        Box::new(RuleRightShiftAnd),
        Box::new(RuleHighOrderAnd),
        Box::new(RuleBitUndistribute),
        Box::new(RuleZextShiftZext),
        Box::new(RuleAndZext),
        Box::new(RuleSignShift),
        Box::new(RuleDoubleArithShift),
    ]
}
