//! Integer arithmetic and shift rewrites from Ghidra 12.1.3's
//! `ruleaction.cc`.
//!
//! Source authority for every implementation below is the corresponding
//! `Rule*::applyOp` in
//! `C:/tmp/ghidra-cpp-full/ruleaction.cc`.
//! The graph exposes SSA structure, constants, locations, endianness,
//! recovered integer signedness, and the precision flags needed by these
//! rewrites. Cleanup rules are implemented here but are registered by the
//! cleanup pool rather than this module's expression-rule list.
//! `RuleBitUndistribute` is not an inverse of the live `RuleAndDistribute` on
//! any accepted shape here: `RuleAndDistribute` is offered only an outer
//! `INT_AND` with an inner `INT_OR`, while this rule requires equal inner
//! extensions or equal shifts and then changes the outer opcode to that
//! extension/shift. Their opcode/shape guards are therefore disjoint.
//!
//! All bit reasoning goes through `Funcdata::nonzero_masks`; duplicating the
//! mask transfer here would let inverse rules disagree and oscillate.

use super::action::Rule;
use super::typefactory::DataType;
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

/// The graph's location equivalent of Ghidra's `Varnode::isSpacebase`.
fn is_spacebase(data: &Funcdata, value: VarnodeId) -> bool {
    let Some(spacebase) = data.spacebase else {
        return false;
    };
    let node = data.varnode(value);
    node.space == spacebase.space && node.offset == spacebase.offset && node.size == spacebase.size
}

/// Sign-extend a value between byte-sized integer containers.
fn sign_extend_bytes(value: u64, input_size: u32, output_size: u32) -> u64 {
    if input_size == 0 {
        return 0;
    }
    let input_mask = mask(input_size);
    let sign_bit = if input_size >= 8 {
        1u64 << 63
    } else {
        1u64 << (input_size * 8 - 1)
    };
    let value = value & input_mask;
    let extended = if value & sign_bit != 0 {
        value | !input_mask
    } else {
        value
    };
    extended & mask(output_size)
}

/// Shrink an extension's output while preserving its storage location.
fn shorten_extension(data: &mut Funcdata, ext_op: OpId, max_size: u32) -> Option<VarnodeId> {
    let original = output(data, ext_op)?;
    let location = data.varnode(original).clone();
    if max_size == 0 || max_size > location.size {
        return None;
    }
    let offset = if data.big_endian {
        location
            .offset
            .wrapping_add(u64::from(location.size - max_size))
    } else {
        location.offset
    };
    data.op_set_output(ext_op, None);
    let replacement = data.new_varnode(location.space, offset, max_size);
    data.op_set_output(ext_op, Some(replacement));
    Some(replacement)
}

/// Cancel extensions around a binary operation, leaving a partial SUBPIECE.
fn cancel_extensions(
    data: &mut Funcdata,
    longform: OpId,
    sub_op: OpId,
    mut ext0_in: VarnodeId,
    mut ext1_in: VarnodeId,
) -> bool {
    let Some(longform_out) = output(data, longform) else {
        return false;
    };
    if data.lone_descend(longform_out) != Some(sub_op) {
        return false;
    }

    let max_size;
    if data.varnode(ext0_in).size == data.varnode(ext1_in).size {
        max_size = data.varnode(ext0_in).size;
        if is_free(data, ext0_in) || is_free(data, ext1_in) {
            return false;
        }
    } else if data.varnode(ext0_in).size < data.varnode(ext1_in).size {
        max_size = data.varnode(ext1_in).size;
        if is_free(data, ext1_in) {
            return false;
        }
        let Some(longform_in0) = input(data, longform, 0) else {
            return false;
        };
        if data.lone_descend(longform_in0) != Some(longform) {
            return false;
        }
        let Some(ext0_op) = definition(data, longform_in0) else {
            return false;
        };
        let Some(shortened) = shorten_extension(data, ext0_op, max_size) else {
            return false;
        };
        ext0_in = shortened;
    } else {
        max_size = data.varnode(ext0_in).size;
        if is_free(data, ext0_in) {
            return false;
        }
        let Some(longform_in1) = input(data, longform, 1) else {
            return false;
        };
        if data.lone_descend(longform_in1) != Some(longform) {
            return false;
        }
        let Some(ext1_op) = definition(data, longform_in1) else {
            return false;
        };
        let Some(shortened) = shorten_extension(data, ext1_op, max_size) else {
            return false;
        };
        ext1_in = shortened;
    }

    data.op_set_output(longform, None);
    let new_output = data.new_unique(max_size);
    data.op_set_output(longform, Some(new_output));
    data.op_set_input(longform, ext0_in, 0);
    data.op_set_input(longform, ext1_in, 1);
    data.op_set_input(sub_op, new_output, 0);
    true
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

/// `V * -1 -> -V`.
///
/// Ghidra registers this rule in the cleanup pool at `coreaction.cc:5747`.
pub struct RuleMultNegOne;

impl Rule for RuleMultNegOne {
    fn name(&self) -> &'static str {
        "multnegone"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_MULT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(constant) = input(data, id, 1) else {
            return 0;
        };
        if !is_constant(data, constant) {
            return 0;
        }
        let node = data.varnode(constant);
        if node.offset != mask(node.size) {
            return 0;
        }
        data.op_set_opcode(id, op::INT_2COMP);
        data.op_remove_input(id, 1);
        1
    }
}

/// `V + 0xff... -> V - 0x00...` for unsigned integer constants.
///
/// Ghidra registers this rule in the cleanup pool at `coreaction.cc:5748`;
/// the character, enum, and named-equate refusals are vacuous because this
/// graph's `DataType` has no such metadata.
pub struct RuleAddUnsigned;

impl Rule for RuleAddUnsigned {
    fn name(&self) -> &'static str {
        "addunsigned"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_ADD]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(constant) = input(data, id, 1) else {
            return 0;
        };
        if !is_constant(data, constant) {
            return 0;
        }
        let is_unsigned = {
            let recovered = data.recovered_types();
            matches!(
                recovered.1.get(constant),
                Some(DataType::Int { signed: false, .. })
            )
        };
        if !is_unsigned {
            return 0;
        }
        let node = data.varnode(constant).clone();
        let value = node.offset;
        let full_mask = mask(node.size);
        let quarter_shift = node.size.saturating_mul(6);
        if quarter_shift >= 64 {
            return 0;
        }
        let quarter = (full_mask >> quarter_shift) << quarter_shift;
        if value & quarter != quarter {
            return 0;
        }
        let negated = value.wrapping_neg() & full_mask;
        data.op_set_opcode(id, op::INT_SUB);
        let replacement = data.new_constant(negated, node.size);
        data.op_set_input(id, replacement, 1);
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

/// `(V << c) >> c -> ZEXT(SUBPIECE(V, 0))`.
///
/// `INT_SRIGHT` produces `SEXT` instead. The source rule is
/// `ruleaction.cc:2028`; its opcode list is the two right-shift forms at
/// `ruleaction.cc:2021-2026`.
pub struct RuleLeftRight;

impl Rule for RuleLeftRight {
    fn name(&self) -> &'static str {
        "leftright"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_RIGHT, op::INT_SRIGHT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(right_amount) = input(data, id, 1) else {
            return 0;
        };
        if !is_constant(data, right_amount) {
            return 0;
        }
        let Some(shiftin) = input(data, id, 0) else {
            return 0;
        };
        let Some(leftshift) = definition(data, shiftin) else {
            return 0;
        };
        if data.opcode_of(leftshift) != Some(op::INT_LEFT) {
            return 0;
        }
        let Some(left_amount) = input(data, leftshift, 1) else {
            return 0;
        };
        if !is_constant(data, left_amount) {
            return 0;
        }
        let shift = data.varnode(right_amount).offset;
        if data.varnode(left_amount).offset != shift || shift & 7 != 0 {
            return 0;
        }
        let isa = shift / 8;
        let shiftin_size = data.varnode(shiftin).size;
        let Some(tsz) = shiftin_size.checked_sub(isa as u32) else {
            return 0;
        };
        if !matches!(tsz, 1 | 2 | 4 | 8) {
            return 0;
        }
        if data.lone_descend(shiftin) != Some(id) {
            return 0;
        }

        let location = data.varnode(shiftin).clone();
        let offset = if data.big_endian {
            location.offset.wrapping_add(isa)
        } else {
            location.offset
        };
        let left_amount_size = data.varnode(left_amount).size;
        let right_opcode = data.op(id).opcode;

        data.op_set_output(leftshift, None);
        let newvn = data.new_varnode(location.space, offset, tsz);
        data.op_set_output(leftshift, Some(newvn));
        data.op_set_opcode(leftshift, op::SUBPIECE);
        let zero = data.new_constant(0, left_amount_size);
        data.op_set_input(leftshift, zero, 1);
        data.op_set_input(id, newvn, 0);
        data.op_remove_input(id, 1);
        data.op_set_opcode(
            id,
            if right_opcode == op::INT_SRIGHT {
                op::INT_SEXT
            } else {
                op::INT_ZEXT
            },
        );
        1
    }
}

/// Commute `SUBPIECE` inward through compatible integer operations.
///
/// This is Ghidra's `RuleSubCommute::applyOp` at `ruleaction.cc:4532`, with
/// `cancelExtensions` and `shortenExtension` above porting the partial
/// extension case.
pub struct RuleSubCommute;

impl Rule for RuleSubCommute {
    fn name(&self) -> &'static str {
        "subcommute"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::SUBPIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(base) = input(data, id, 0) else {
            return 0;
        };
        if !data.varnode(base).flags.written {
            return 0;
        }
        let Some(offset_value) = input(data, id, 1) else {
            return 0;
        };
        let offset = data.varnode(offset_value).offset;
        let Some(outvn) = output(data, id) else {
            return 0;
        };
        let out_flags = data.varnode(outvn).flags;
        if out_flags.precis_lo || out_flags.precis_hi {
            return 0;
        }
        let insize = data.varnode(base).size;
        let Some(longform) = definition(data, base) else {
            return 0;
        };
        let Some(longform_opcode) = data.opcode_of(longform) else {
            return 0;
        };
        let out_size = data.varnode(outvn).size;
        let mut shift_slot = None;

        match longform_opcode {
            op::INT_LEFT => {
                shift_slot = Some(1);
                if offset != 0 {
                    return 0;
                }
                let Some(longform_input) = input(data, longform, 0) else {
                    return 0;
                };
                if !data.varnode(longform_input).flags.written {
                    return 0;
                }
                let Some(inner) = definition(data, longform_input) else {
                    return 0;
                };
                if !matches!(data.opcode_of(inner), Some(op::INT_ZEXT) | Some(op::PIECE)) {
                    return 0;
                }
            }
            op::INT_REM | op::INT_DIV => {
                if offset != 0 {
                    return 0;
                }
                let Some(longform_input0) = input(data, longform, 0) else {
                    return 0;
                };
                if !data.varnode(longform_input0).flags.written {
                    return 0;
                }
                let Some(zext0) = definition(data, longform_input0) else {
                    return 0;
                };
                if data.opcode_of(zext0) != Some(op::INT_ZEXT) {
                    return 0;
                }
                let Some(zext0_in) = input(data, zext0, 0) else {
                    return 0;
                };
                let Some(longform_input1) = input(data, longform, 1) else {
                    return 0;
                };
                if data.varnode(longform_input1).flags.written {
                    let Some(zext1) = definition(data, longform_input1) else {
                        return 0;
                    };
                    if data.opcode_of(zext1) != Some(op::INT_ZEXT) {
                        return 0;
                    }
                    let Some(zext1_in) = input(data, zext1, 0) else {
                        return 0;
                    };
                    if data.varnode(zext1_in).size > out_size
                        || data.varnode(zext0_in).size > out_size
                    {
                        return if cancel_extensions(data, longform, id, zext0_in, zext1_in) {
                            1
                        } else {
                            0
                        };
                    }
                } else if is_constant(data, longform_input1)
                    && data.varnode(zext0_in).size <= out_size
                {
                    let value = data.varnode(longform_input1).offset;
                    let small_value = value & mask(out_size);
                    if value != small_value {
                        return 0;
                    }
                } else {
                    return 0;
                }
            }
            op::INT_SREM | op::INT_SDIV => {
                if offset != 0 {
                    return 0;
                }
                let Some(longform_input0) = input(data, longform, 0) else {
                    return 0;
                };
                if !data.varnode(longform_input0).flags.written {
                    return 0;
                }
                let Some(sext0) = definition(data, longform_input0) else {
                    return 0;
                };
                if data.opcode_of(sext0) != Some(op::INT_SEXT) {
                    return 0;
                }
                let Some(sext0_in) = input(data, sext0, 0) else {
                    return 0;
                };
                let Some(longform_input1) = input(data, longform, 1) else {
                    return 0;
                };
                if data.varnode(longform_input1).flags.written {
                    let Some(sext1) = definition(data, longform_input1) else {
                        return 0;
                    };
                    if data.opcode_of(sext1) != Some(op::INT_SEXT) {
                        return 0;
                    }
                    let Some(sext1_in) = input(data, sext1, 0) else {
                        return 0;
                    };
                    if data.varnode(sext1_in).size > out_size
                        || data.varnode(sext0_in).size > out_size
                    {
                        return if cancel_extensions(data, longform, id, sext0_in, sext1_in) {
                            1
                        } else {
                            0
                        };
                    }
                } else if is_constant(data, longform_input1)
                    && data.varnode(sext0_in).size <= out_size
                {
                    let value = data.varnode(longform_input1).offset;
                    let small_value = value & mask(out_size);
                    let extended = sign_extend_bytes(small_value, out_size, insize);
                    if value != extended {
                        return 0;
                    }
                } else {
                    return 0;
                }
            }
            op::INT_ADD => {
                if offset != 0 {
                    return 0;
                }
                let Some(longform_input0) = input(data, longform, 0) else {
                    return 0;
                };
                if is_spacebase(data, longform_input0) {
                    return 0;
                }
            }
            op::INT_MULT => {
                if offset != 0 {
                    return 0;
                }
            }
            op::INT_NEGATE | op::INT_XOR | op::INT_AND | op::INT_OR => {}
            _ => return 0,
        }

        if data.lone_descend(base) != Some(id) {
            return 0;
        }
        if offset == 0 {
            if let Some(nextop) = data.lone_descend(outvn) {
                if data.opcode_of(nextop) == Some(op::INT_ZEXT) {
                    if let Some(next_output) = output(data, nextop)
                        && data.varnode(next_output).size == insize
                    {
                        return 0;
                    }
                }
            }
        }

        let longform_inputs = data.op(longform).inputs.clone();
        let sequence = data.op(id).seq;
        let mut last_input = None;
        let mut new_vn = None;
        for (index, value) in longform_inputs.into_iter().enumerate() {
            if shift_slot != Some(index) {
                if last_input != Some(value) || new_vn.is_none() {
                    let newsub = data.new_op(op::SUBPIECE, sequence, Vec::new());
                    let sub_output = data.new_unique(out_size);
                    data.op_set_output(newsub, Some(sub_output));
                    data.op_set_input(longform, sub_output, index);
                    data.op_set_input(newsub, value, 0);
                    let sub_offset = data.new_constant(offset, 4);
                    data.op_set_input(newsub, sub_offset, 1);
                    data.op_insert_before(newsub, longform);
                    new_vn = Some(sub_output);
                } else if let Some(new_vn) = new_vn {
                    data.op_set_input(longform, new_vn, index);
                }
            }
            last_input = Some(value);
        }
        data.op_set_output(longform, Some(outvn));
        data.op_destroy(id);
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

    /// Ghidra's `RuleMultNegOne` at `ruleaction.cc:7179` retags a multiply by
    /// an all-ones constant as `INT_2COMP`.
    #[test]
    fn mult_neg_one_rewrites_all_ones_constant() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let all_ones = data.new_constant(0xffff_ffff, 4);
        let (multiply, _) = binary(&mut data, block, op::INT_MULT, value, all_ones, 4);

        assert_eq!(RuleMultNegOne.apply_op(multiply, &mut data), 1);
        assert_eq!(data.op(multiply).opcode, op::INT_2COMP);
        assert_eq!(data.op(multiply).inputs, vec![value]);
    }

    /// Ghidra's `RuleAddUnsigned` at `ruleaction.cc:7200` requires an unsigned
    /// constant whose high quarter is all ones before forming `INT_SUB`.
    #[test]
    fn add_unsigned_rewrites_high_quarter_constant() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let constant = data.new_constant(0xffff_ff00, 4);
        let (add, _) = binary(&mut data, block, op::INT_ADD, value, constant, 4);

        assert_eq!(RuleAddUnsigned.apply_op(add, &mut data), 1);
        assert_eq!(data.op(add).opcode, op::INT_SUB);
        let replacement = data.op(add).inputs[1];
        assert_eq!(data.varnode(replacement).offset, 0x100);
    }

    /// Ghidra's `RuleLeftRight` at `ruleaction.cc:2028` retypes the existing
    /// shift operations and selects the SUBPIECE offset according to endian.
    #[test]
    fn left_right_retypes_existing_shifts_and_honors_endian() {
        for (big_endian, right_opcode, extension) in [
            (false, op::INT_RIGHT, op::INT_ZEXT),
            (true, op::INT_SRIGHT, op::INT_SEXT),
        ] {
            let mut data = Funcdata::default();
            data.big_endian = big_endian;
            let block = data.new_block(0x1000);
            let value = input_value(&mut data, 4);
            let amount = data.new_constant(16, 4);
            let shifted = data.new_varnode(REGISTER_SPACE, 0x80, 4);
            let left = data.new_op(op::INT_LEFT, seq(0x1000), vec![value, amount]);
            data.op_set_output(left, Some(shifted));
            data.op_insert_end(left, block);
            let right = data.new_op(right_opcode, seq(0x1004), vec![shifted, amount]);
            let right_output = data.new_unique(4);
            data.op_set_output(right, Some(right_output));
            data.op_insert_end(right, block);

            assert_eq!(RuleLeftRight.apply_op(right, &mut data), 1);
            assert_eq!(data.op(left).opcode, op::SUBPIECE);
            assert_eq!(data.op(left).inputs[0], value);
            let zero = data.op(left).inputs[1];
            assert!(is_constant(&data, zero));
            assert_eq!(data.varnode(zero).offset, 0);
            let piece = data.op(left).output.expect("SUBPIECE output");
            assert_eq!(data.varnode(piece).size, 2);
            assert_eq!(
                data.varnode(piece).offset,
                if big_endian { 0x82 } else { 0x80 }
            );
            assert_eq!(data.op(right).opcode, extension);
            assert_eq!(data.op(right).inputs, vec![piece]);
        }
    }

    /// Ghidra's `RuleSubCommute` at `ruleaction.cc:4532` pushes a SUBPIECE
    /// through a unary integer operation by reusing the existing output.
    #[test]
    fn sub_commute_pushes_piece_through_negate() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = input_value(&mut data, 4);
        let (negate, negated) = unary(&mut data, block, op::INT_NEGATE, value, 4);
        let offset = data.new_constant(0, 4);
        let (subpiece, piece) = binary(&mut data, block, op::SUBPIECE, negated, offset, 2);

        assert_eq!(RuleSubCommute.apply_op(subpiece, &mut data), 1);
        assert!(data.opcode_of(subpiece).is_none());
        assert_eq!(data.op(negate).opcode, op::INT_NEGATE);
        assert_eq!(data.op(negate).output, Some(piece));
        let inner = data.op(negate).inputs[0];
        let inner_def = data.varnode(inner).def.expect("commuted SUBPIECE");
        assert_eq!(data.op(inner_def).opcode, op::SUBPIECE);
        assert_eq!(data.varnode(inner).size, 2);
        assert_eq!(data.op(inner_def).inputs[0], value);
        // Ghidra mints a *fresh* four-byte constant for the commuted offset -
        // `data.opSetInput(newsub,data.newConstant(4,offset),1)` - rather than
        // reusing the original operand, so the identity differs and only the
        // value is the contract.
        let commuted_offset = data.op(inner_def).inputs[1];
        assert!(is_constant(&data, commuted_offset));
        assert_eq!(data.varnode(commuted_offset).offset, 0);
        assert_eq!(data.varnode(commuted_offset).size, 4);
    }

    /// `cancelExtensions` at `ruleaction.cc:4501` shrinks both extensions to the
    /// wider operand's size and truncates the operation's own output to match.
    ///
    /// The reachable arm matters: only `INT_DIV`/`INT_REM` and their signed
    /// counterparts call `cancelExtensions`, because only there does the
    /// SUBPIECE cancel the extensions rather than commute through them. An
    /// `INT_ADD` fixture takes the generic commute path instead and proves
    /// nothing about this helper.
    #[test]
    fn sub_commute_cancels_mismatched_extensions() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let narrow = input_value(&mut data, 1);
        let wide = input_value(&mut data, 2);
        let (narrow_ext_op, narrow_ext) = unary(&mut data, block, op::INT_ZEXT, narrow, 4);
        let (_, wide_ext) = unary(&mut data, block, op::INT_ZEXT, wide, 4);
        let (divide, quotient) = binary(&mut data, block, op::INT_DIV, narrow_ext, wide_ext, 4);
        let offset = data.new_constant(0, 4);
        let (subpiece, _) = binary(&mut data, block, op::SUBPIECE, quotient, offset, 1);

        assert_eq!(RuleSubCommute.apply_op(subpiece, &mut data), 1);
        assert_eq!(data.op(divide).opcode, op::INT_DIV);
        // `maxSize` is the *wider* pre-extension operand, so both the shortened
        // extension and the truncated output are two bytes, not one.
        let divide_output = data.op(divide).output.expect("shortened output");
        assert_eq!(data.varnode(divide_output).size, 2);
        assert_eq!(
            data.varnode(data.op(narrow_ext_op).output.expect("shortened extension"))
                .size,
            2
        );
        assert_eq!(data.op(subpiece).inputs[0], divide_output);
        // The SUBPIECE itself survives: it still truncates to one byte.
        assert_eq!(data.op(subpiece).inputs[1], offset);
        assert_eq!(
            data.varnode(data.op(subpiece).output.expect("surviving truncation"))
                .size,
            1
        );
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

/// Expression/analysis rules from this module; cleanup rules are wired into
/// the separate cleanup pool by the action pipeline.
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(Rule2Comp2Mult),
        Box::new(RuleLeftRight),
        Box::new(RuleSub2Add),
        Box::new(RuleSubCommute),
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
