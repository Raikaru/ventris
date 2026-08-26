//! Recovery for jump tables whose fixed base is materialized in a register.
//!
//! Ghidra's `RuleCollapseConstants` only accepts an operation whose *direct*
//! inputs are literal constant varnodes (`ruleaction.cc:3878-3897`).  The
//! graph's expression pool has the same contract.  On PowerPC, however, a
//! `lis` followed by `addi` can leave a register-written `COPY`/arithmetic
//! chain behind when the producer is visited before copy propagation removes
//! its output.  The rendered expression can still be folded, but
//! `jumptable::constant_value` must correctly refuse it: treating every
//! constant-valued expression as a literal would also make a computed index
//! look like a table base.
//!
//! This module keeps that distinction.  Its local evaluator is only reached
//! for the base operand of an address, requires the root to be register
//! derived, and accepts a value only when every leaf in the materialization
//! chain is a literal constant.  The scaled-index parser remains the strict
//! literal-only parser in [`super::jumptable`].
//!
//! MEASURED LIMIT. On the motivating function - `animal_crossing_gafe01.dol` at
//! `0x800576c0` - this model also declines, so the switch there is still lost.
//! Instrumenting the chain showed why: for that `BRANCHIND`,
//! `parse_destination` itself returns `None` while `contains_load` is true. So
//! the destination never becomes a `DestinationModel` at all, and no base model
//! - basic, `JumpBasic2`, or this one - is ever given a scale and index to work
//! with. The register-rooted base was a real defect and this fixes it for the
//! shape it covers, but it is not the whole cause for that function.
//!
//! The remaining work is in `parse_destination`: establish why the load's
//! address does not parse, rather than adding another base model behind it.

use std::collections::BTreeSet;

use super::jumptable::{self, AddressModel, JumpTable, MAX_TABLE_ENTRIES};
use super::{Funcdata, OpId, VarnodeId};
use ventris_lifter::REGISTER_SPACE;
use ventris_pcode::op;

/// Bound recursion in malformed graphs while preserving the finite p-code
/// chains produced by the native lifters.
const MAX_CONSTANT_DEPTH: usize = 128;

fn mask_for_size(size: u32) -> u64 {
    let bits = size.saturating_mul(8);
    if bits == 0 {
        0
    } else if bits >= u64::BITS {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn mask_value(value: u64, size: u32) -> u64 {
    value & mask_for_size(size)
}

fn sign_extend(value: u64, size: u32) -> u64 {
    let mask = mask_for_size(size);
    let value = value & mask;
    let bits = size.saturating_mul(8);
    if bits == 0 || bits >= u64::BITS {
        value
    } else if value & (1u64 << (bits - 1)) != 0 {
        value | !mask
    } else {
        value
    }
}

/// Address expressions use the same quasi-copy forms as the ordinary model,
/// except that `BOOL_NEGATE` is deliberately not an alias here.  Ghidra's
/// `strip_alias` helper is also used for guard conditions, where a boolean
/// negation is transparent to the range walk; it would be a value-changing
/// operation in a table address.
fn strip_address_alias(data: &Funcdata, start: VarnodeId) -> VarnodeId {
    let mut current = start;
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(current) {
            return current;
        }
        let Some(def) = data.varnode(current).def else {
            return current;
        };
        let operation = data.op(def);
        let source = match operation.opcode {
            op::COPY | op::INT_ZEXT => operation.inputs.first().copied(),
            op::SUBPIECE => operation.inputs.get(1).copied().and_then(|offset| {
                (data.varnode(offset).flags.constant && data.varnode(offset).offset == 0)
                    .then(|| operation.inputs.first().copied())
                    .flatten()
            }),
            _ => None,
        };
        let Some(source) = source else {
            return current;
        };
        current = source;
    }
}

/// Evaluate a constant materialization chain without changing the graph's
/// ordinary constant predicate.
///
/// Every non-leaf operation must be an integer assignment whose inputs are
/// themselves fully constant.  In particular, a free register or an
/// expression containing the switch index returns `None`; identities such as
/// `x * 0` are not folded because that would no longer be a proof that the
/// address is a fixed table base.
fn evaluate_constant(
    data: &Funcdata,
    value: VarnodeId,
    depth: usize,
    seen: &mut BTreeSet<VarnodeId>,
) -> Option<u64> {
    if depth >= MAX_CONSTANT_DEPTH {
        return None;
    }
    let value = strip_address_alias(data, value);
    let varnode = data.varnode(value);
    if varnode.flags.constant {
        return Some(mask_value(varnode.offset, varnode.size));
    }
    if !seen.insert(value) {
        return None;
    }

    let result = (|| {
        let def = data.varnode(value).def?;
        let operation = data.op(def);
        let output = operation.output?;
        let output_size = data.varnode(output).size;
        let mut input =
            |slot: usize| evaluate_constant(data, *operation.inputs.get(slot)?, depth + 1, seen);
        let mut binary = || Some((input(0)?, input(1)?));

        let result = match operation.opcode {
            op::INT_ADD => {
                let (left, right) = binary()?;
                left.wrapping_add(right)
            }
            op::INT_SUB => {
                let (left, right) = binary()?;
                left.wrapping_sub(right)
            }
            op::INT_MULT => {
                let (left, right) = binary()?;
                left.wrapping_mul(right)
            }
            op::INT_AND => {
                let (left, right) = binary()?;
                left & right
            }
            op::INT_OR => {
                let (left, right) = binary()?;
                left | right
            }
            op::INT_XOR => {
                let (left, right) = binary()?;
                left ^ right
            }
            op::INT_LEFT => {
                let (left, right) = binary()?;
                left.checked_shl(u32::try_from(right).ok()?).unwrap_or(0)
            }
            op::INT_RIGHT => {
                let (left, right) = binary()?;
                left.checked_shr(u32::try_from(right).ok()?).unwrap_or(0)
            }
            op::INT_SRIGHT => {
                let (left, right) = binary()?;
                sign_extend(left, data.varnode(operation.inputs[0]).size)
                    .wrapping_shr(u32::try_from(right).ok()?)
            }
            op::INT_NEGATE => !input(0)?,
            op::INT_2COMP => input(0)?.wrapping_neg(),
            op::INT_SEXT => sign_extend(input(0)?, data.varnode(operation.inputs[0]).size),
            op::INT_EQUAL => {
                let (left, right) = binary()?;
                u64::from(left == right)
            }
            op::INT_NOTEQUAL => {
                let (left, right) = binary()?;
                u64::from(left != right)
            }
            op::INT_LESS => {
                let (left, right) = binary()?;
                u64::from(left < right)
            }
            op::INT_LESSEQUAL => {
                let (left, right) = binary()?;
                u64::from(left <= right)
            }
            _ => return None,
        };
        Some(mask_value(result, output_size))
    })();

    seen.remove(&value);
    result
}

/// Resolve a fixed base only when the root value is a register definition.
///
/// A direct constant (or a copy that aliases one) is left to the ordinary
/// jump-table model so the fallback cannot produce duplicate tables.
fn register_constant(data: &Funcdata, value: VarnodeId) -> Option<u64> {
    let value = strip_address_alias(data, value);
    let varnode = data.varnode(value);
    if varnode.flags.constant || varnode.space != REGISTER_SPACE || varnode.def.is_none() {
        return None;
    }
    evaluate_constant(data, value, 0, &mut BTreeSet::new())
}

/// Recover `constant(register materialization) + scaled index` from an address.
fn parse_address(data: &Funcdata, value: VarnodeId) -> Option<AddressModel> {
    let value = strip_address_alias(data, value);
    let def = data.varnode(value).def?;
    let operation = data.op(def);
    if operation.opcode != op::INT_ADD || operation.inputs.len() < 2 {
        return None;
    }

    if let Some(base) = register_constant(data, operation.inputs[0]) {
        if let Some(scale) = jumptable::parse_scaled(data, operation.inputs[1]) {
            return Some(AddressModel {
                base,
                index: scale.value,
                stride: scale.stride,
            });
        }
        if let Some(mut nested) = parse_address(data, operation.inputs[1]) {
            nested.base = nested.base.wrapping_add(base);
            return Some(nested);
        }
    }
    if let Some(base) = register_constant(data, operation.inputs[1]) {
        if let Some(scale) = jumptable::parse_scaled(data, operation.inputs[0]) {
            return Some(AddressModel {
                base,
                index: scale.value,
                stride: scale.stride,
            });
        }
        if let Some(mut nested) = parse_address(data, operation.inputs[0]) {
            nested.base = nested.base.wrapping_add(base);
            return Some(nested);
        }
    }
    None
}

fn parse_destination(data: &Funcdata, value: VarnodeId) -> Option<(AddressModel, u32, u64)> {
    let value = strip_address_alias(data, value);
    let def = data.varnode(value).def?;
    let operation = data.op(def);
    match operation.opcode {
        op::LOAD => {
            let address = parse_address(data, *operation.inputs.get(1)?)?;
            let output = operation.output?;
            let entry_size = data.varnode(output).size;
            (entry_size != 0).then_some((address, entry_size, 0))
        }
        op::INT_ADD if operation.inputs.len() >= 2 => {
            if let Some(bias) = jumptable::constant_value(data, operation.inputs[0]) {
                let (address, entry_size, nested_bias) =
                    parse_destination(data, operation.inputs[1])?;
                return Some((address, entry_size, nested_bias.wrapping_add(bias)));
            }
            if let Some(bias) = jumptable::constant_value(data, operation.inputs[1]) {
                let (address, entry_size, nested_bias) =
                    parse_destination(data, operation.inputs[0])?;
                return Some((address, entry_size, nested_bias.wrapping_add(bias)));
            }
            None
        }
        _ => None,
    }
}

/// Recover one register-based jump table.
///
/// This is intentionally a per-`BRANCHIND` entry point, matching
/// [`super::jumpmodel::recover_jump_basic2`].  Main can place it after the
/// ordinary basic and two-stage models.  A table with a literal base is not
/// claimed here, and a non-constant register base is rejected.
pub fn recover_jump_table_base(
    data: &Funcdata,
    branch: OpId,
    read_memory: &dyn Fn(u64, u32) -> Option<u64>,
) -> Option<JumpTable> {
    if data.op(branch).opcode != op::BRANCHIND {
        return None;
    }
    let destination = *data.op(branch).inputs.first()?;
    // The ordinary model owns literal-base tables.  Besides avoiding duplicate
    // entries, this preserves its exact parser semantics for all other forms.
    if jumptable::parse_destination(data, destination).is_some() {
        return None;
    }
    let (address, entry_size, target_bias) = parse_destination(data, destination)?;
    let guard = jumptable::find_guard(data, branch, address.index)?;
    if guard.bound == 0 || guard.bound > MAX_TABLE_ENTRIES {
        return None;
    }

    let count = usize::try_from(guard.bound).ok()?;
    let mut cases = Vec::with_capacity(count);
    for label in 0..guard.bound {
        let offset = label.checked_mul(address.stride)?;
        let table_address = address.base.checked_add(offset)?;
        let target = read_memory(table_address, entry_size)?;
        cases.push((label, target.wrapping_add(target_bias)));
    }
    Some(JumpTable {
        branch,
        switch_value: address.index,
        cases,
        default_target: guard.default_target,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{RAM_SPACE, REGISTER_SPACE};

    fn seq(order: u32) -> super::super::SeqNum {
        super::super::SeqNum {
            address: 0x1000 + u64::from(order),
            order,
        }
    }

    struct Fixture {
        data: Funcdata,
        branch: OpId,
        index: VarnodeId,
        table_base: u64,
        entries: Vec<u64>,
    }

    fn register_base_fixture() -> Fixture {
        let mut data = Funcdata {
            entry: 0x1000,
            ..Funcdata::default()
        };
        let entry = data.new_block(0x1000);
        let guarded = data.new_block(0x1010);
        let default = data.new_block(0x2000);
        let switch = data.new_block(0x1020);
        data.add_edge(entry, guarded);
        data.add_edge(guarded, default);
        data.add_edge(guarded, switch);

        let index = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(index);
        let bound = data.new_constant(15, 4);
        let compare = data.new_op(op::INT_LESS, seq(0), vec![index, bound]);
        let comparison = data.new_unique(1);
        data.op_set_output(compare, Some(comparison));
        data.op_insert_end(compare, guarded);
        let guard_target = data.new_constant(data.block(switch).start, 8);
        let cbranch = data.new_op(op::CBRANCH, seq(1), vec![guard_target, comparison]);
        data.op_insert_end(cbranch, guarded);

        let shift_amount = data.new_constant(2, 4);
        let scaled = data.new_unique(4);
        let shift = data.new_op(op::INT_LEFT, seq(2), vec![index, shift_amount]);
        data.op_set_output(shift, Some(scaled));
        data.op_insert_end(shift, switch);

        // PPC `lis r3,0x800e` is INT_LEFT(sign-extended immediate,16).
        let high = data.new_constant(0xffff_800e, 4);
        let sixteen = data.new_constant(16, 4);
        let lis_output = data.new_varnode(REGISTER_SPACE, 12, 4);
        let lis = data.new_op(op::INT_LEFT, seq(3), vec![high, sixteen]);
        data.op_set_output(lis, Some(lis_output));
        data.op_insert_end(lis, switch);

        let low = data.new_constant(0xffff_c004, 4);
        let base_output = data.new_varnode(REGISTER_SPACE, 12, 4);
        let addi = data.new_op(op::INT_ADD, seq(4), vec![lis_output, low]);
        data.op_set_output(addi, Some(base_output));
        data.op_insert_end(addi, switch);

        let address = data.new_unique(4);
        let add = data.new_op(op::INT_ADD, seq(5), vec![base_output, scaled]);
        data.op_set_output(add, Some(address));
        data.op_insert_end(add, switch);
        let space = data.new_constant(RAM_SPACE as u64, 4);
        let loaded = data.new_unique(4);
        let load = data.new_op(op::LOAD, seq(6), vec![space, address]);
        data.op_set_output(load, Some(loaded));
        data.op_insert_end(load, switch);
        let branch = data.new_op(op::BRANCHIND, seq(7), vec![loaded]);
        data.op_insert_end(branch, switch);

        Fixture {
            data,
            branch,
            index,
            table_base: 0x800d_c004,
            entries: vec![
                0x8005_78a8,
                0x8005_78a8,
                0x8005_7818,
                0x8005_78a8,
                0x8005_780c,
                0x8005_78a8,
                0x8005_771c,
                0x8005_78a8,
                0x8005_788c,
                0x8005_78a8,
                0x8005_7848,
                0x8005_78a8,
                0x8005_78a8,
                0x8005_78a8,
                0x8005_78c4,
            ],
        }
    }

    #[test]
    fn register_derived_base_recovers_exact_cases_and_targets() {
        let fixture = register_base_fixture();
        let entries = fixture.entries.clone();
        let base = fixture.table_base;
        let recovered =
            recover_jump_table_base(&fixture.data, fixture.branch, &move |address, width| {
                assert_eq!(width, 4);
                let index = usize::try_from((address - base) / 4).ok()?;
                entries.get(index).copied()
            })
            .expect("register-derived table");

        assert_eq!(recovered.branch, fixture.branch);
        assert_eq!(recovered.switch_value, fixture.index);
        assert_eq!(
            recovered.cases,
            (0..15).zip(fixture.entries).collect::<Vec<_>>()
        );
        assert_eq!(recovered.default_target, Some(0x2000));
    }

    #[test]
    fn nonconstant_register_base_is_rejected() {
        let mut fixture = register_base_fixture();
        let addi = fixture
            .data
            .live_ops()
            .find(|(_, operation)| operation.seq.order == 4)
            .map(|(id, _)| id)
            .expect("register addi");
        let dynamic = fixture.data.new_varnode(REGISTER_SPACE, 0x40, 4);
        fixture.data.mark_input(dynamic);
        fixture.data.op_set_input(addi, dynamic, 0);
        assert!(recover_jump_table_base(&fixture.data, fixture.branch, &|_, _| Some(0)).is_none());
    }
}
