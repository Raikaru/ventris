//! Type inference, ported from Ghidra 12.1.3's `ActionInferTypes`.
//!
//! Every value starts with the weakest type its storage admits, and types flow
//! along data-flow edges. An operation decides, per edge, whether and how a
//! type crosses it: a `LOAD` turns a pointer into what it points at, a `COPY`
//! or `MULTIEQUAL` passes a type through unchanged in both directions, and a
//! comparison produces a boolean regardless of its operands.
//!
//! The direction that matters is *backwards*. Ventris' existing type solver
//! collects constraints per value and merges them, which can only ever
//! strengthen a value from its own uses. Propagation across edges is what lets
//! a pointer discovered at a dereference travel back to the argument register
//! it arrived in, and forward into every value derived from it.
//!
//! Settling is bounded. Ghidra caps propagation at seven passes and warns when
//! it has not settled, because the lattice has cycles through merges.
//!
//! Source authority: `ActionInferTypes::apply`, `buildLocaltypes`,
//! `propagateOneType`, `propagateTypeEdge`, `writeBack`, and
//! `Datatype::typeOrder` in `coreaction.cc` and `type.cc` at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use std::collections::BTreeMap;

use ventris_pcode::op;

use super::{Funcdata, OpId, VarnodeId};
use crate::native::Type;

/// How many propagation passes may run before the result is accepted as is.
const PASS_CAP: usize = 7;

/// Recovered types, keyed by value.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Types {
    types: BTreeMap<VarnodeId, Type>,
    /// Set when propagation was still changing types at the cap.
    pub unsettled: bool,
}

impl Types {
    /// A shared empty set, for callers with no recovered types.
    pub fn empty_ref() -> &'static Self {
        static EMPTY: std::sync::LazyLock<Types> = std::sync::LazyLock::new(Types::default);
        &EMPTY
    }

    pub fn get(&self, value: VarnodeId) -> Option<&Type> {
        self.types.get(&value)
    }

    pub fn len(&self) -> usize {
        self.types.len()
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }
}

/// Where a type is more specific than another.
///
/// Ghidra's `Datatype::typeOrder`: a smaller order is more specific and wins.
/// `Unknown` is weakest, an unsigned integer is weaker than a signed one of the
/// same width, and a pointer or float carries real information so it outranks
/// both. Without a total order, propagation would oscillate between two
/// equally-ranked types forever.
fn specificity(ty: &Type) -> u8 {
    match ty {
        Type::Unknown => 5,
        Type::Unsigned(_) => 4,
        Type::Signed(_) => 3,
        Type::Bool => 2,
        Type::Float(_) => 1,
        Type::Pointer(_) => 0,
        Type::Void => 6,
    }
}

/// Whether `candidate` should replace `current`.
fn improves(candidate: &Type, current: &Type) -> bool {
    if candidate == current {
        return false;
    }
    specificity(candidate) < specificity(current)
}

/// Infers a type for every value in the graph.
///
/// `seed` supplies types known from outside the graph — an ABI's argument
/// classes, a callee prototype, a symbol's declared type. Those are locks:
/// propagation never weakens them.
pub fn infer_types(data: &Funcdata, seed: &BTreeMap<VarnodeId, Type>) -> Types {
    let mut types: BTreeMap<VarnodeId, Type> = BTreeMap::new();

    // Local types: what each value's own storage and definition already say.
    for index in 0..data.varnode_count() {
        let id = VarnodeId(index as u32);
        let varnode = data.varnode(id);
        if varnode.def.is_none() && varnode.descendants.is_empty() {
            continue;
        }
        types.insert(id, Type::Unsigned(varnode.size.saturating_mul(8)));
    }
    for (value, ty) in seed {
        types.insert(*value, ty.clone());
    }

    let mut unsettled = true;
    for _ in 0..PASS_CAP {
        let mut changed = false;
        for (id, operation) in data.live_ops() {
            changed |= propagate_op(data, id, operation.opcode, &mut types, seed);
        }
        if !changed {
            unsettled = false;
            break;
        }
    }

    Types { types, unsettled }
}

/// Propagates types across every edge of one operation.
fn propagate_op(
    data: &Funcdata,
    id: OpId,
    opcode: i32,
    types: &mut BTreeMap<VarnodeId, Type>,
    locks: &BTreeMap<VarnodeId, Type>,
) -> bool {
    let operation = data.op(id);
    let mut changed = false;
    let set = |value: VarnodeId, ty: Type, types: &mut BTreeMap<VarnodeId, Type>| -> bool {
        if locks.contains_key(&value) {
            return false;
        }
        let current = types.get(&value).cloned().unwrap_or(Type::Unknown);
        if !improves(&ty, &current) {
            return false;
        }
        types.insert(value, ty);
        true
    };

    match opcode {
        // A copy or merge is the same value, so a type crosses in both
        // directions. This is what carries a type discovered at a dereference
        // back to the register the pointer arrived in.
        op::COPY | op::MULTIEQUAL | op::INDIRECT | op::CAST => {
            let limit = if opcode == op::INDIRECT {
                1
            } else {
                operation.inputs.len()
            };
            let Some(output) = operation.output else {
                return false;
            };
            let mut best = types.get(&output).cloned().unwrap_or(Type::Unknown);
            for operand in operation.inputs.iter().take(limit).copied() {
                if let Some(candidate) = types.get(&operand)
                    && improves(candidate, &best)
                {
                    best = candidate.clone();
                }
            }
            changed |= set(output, best.clone(), types);
            for operand in operation.inputs.iter().take(limit).copied() {
                changed |= set(operand, best.clone(), types);
            }
        }
        // The address operand of a load or store is a pointer to the accessed
        // value's type. This is the only place a pointer originates.
        op::LOAD => {
            let (Some(output), Some(address)) =
                (operation.output, operation.inputs.get(1).copied())
            else {
                return false;
            };
            let pointee = types.get(&output).cloned().unwrap_or(Type::Unknown);
            changed |= set(address, Type::Pointer(Box::new(pointee)), types);
        }
        op::STORE => {
            let (Some(address), Some(value)) = (
                operation.inputs.get(1).copied(),
                operation.inputs.get(2).copied(),
            ) else {
                return false;
            };
            let pointee = types.get(&value).cloned().unwrap_or(Type::Unknown);
            changed |= set(address, Type::Pointer(Box::new(pointee)), types);
        }
        // Adding an integer to a pointer is still that pointer.
        op::INT_ADD | op::INT_SUB | op::PTRADD | op::PTRSUB => {
            let Some(output) = operation.output else {
                return false;
            };
            let pointer = operation
                .inputs
                .iter()
                .copied()
                .filter_map(|operand| types.get(&operand))
                .find(|ty| matches!(ty, Type::Pointer(_)))
                .cloned()
                .or_else(|| {
                    // Backwards too: an offset that turned out to be a pointer
                    // means the base it was computed from is one. This is what
                    // types the struct pointer a field access starts from.
                    types
                        .get(&output)
                        .filter(|ty| matches!(ty, Type::Pointer(_)))
                        .cloned()
                });
            if let Some(pointer) = pointer {
                changed |= set(output, pointer.clone(), types);
                for operand in operation.inputs.iter().copied() {
                    if !data.varnode(operand).flags.constant {
                        changed |= set(operand, pointer.clone(), types);
                    }
                }
            }
        }
        // A comparison is a boolean whatever it compares.
        op::INT_EQUAL
        | op::INT_NOTEQUAL
        | op::INT_LESS
        | op::INT_LESSEQUAL
        | op::INT_SLESS
        | op::INT_SLESSEQUAL
        | op::BOOL_AND
        | op::BOOL_OR
        | op::BOOL_NEGATE
        | op::FLOAT_EQUAL
        | op::FLOAT_NOTEQUAL
        | op::FLOAT_LESS
        | op::FLOAT_LESSEQUAL => {
            if let Some(output) = operation.output {
                changed |= set(output, Type::Bool, types);
            }
        }
        // A signed operation says its operands and result are signed.
        op::INT_SDIV | op::INT_SREM | op::INT_SRIGHT | op::INT_SEXT | op::INT_2COMP => {
            if let Some(output) = operation.output {
                let width = data.varnode(output).size.saturating_mul(8);
                changed |= set(output, Type::Signed(width), types);
            }
            if let Some(operand) = operation.inputs.first().copied() {
                let width = data.varnode(operand).size.saturating_mul(8);
                changed |= set(operand, Type::Signed(width), types);
            }
        }
        // Float operations are the strongest evidence there is: the register
        // file itself does not distinguish, only the instruction does.
        op::FLOAT_ADD
        | op::FLOAT_SUB
        | op::FLOAT_MULT
        | op::FLOAT_DIV
        | op::FLOAT_NEG
        | op::FLOAT_ABS
        | op::FLOAT_SQRT
        | op::FLOAT_INT2FLOAT
        | op::FLOAT_FLOAT2FLOAT => {
            if let Some(output) = operation.output {
                let width = data.varnode(output).size.saturating_mul(8);
                changed |= set(output, Type::Float(width), types);
            }
            if opcode != op::FLOAT_INT2FLOAT {
                for operand in operation.inputs.iter().copied() {
                    let width = data.varnode(operand).size.saturating_mul(8);
                    changed |= set(operand, Type::Float(width), types);
                }
            }
        }
        op::FLOAT_TRUNC | op::FLOAT_CEIL | op::FLOAT_FLOOR | op::FLOAT_ROUND => {
            if let Some(operand) = operation.inputs.first().copied() {
                let width = data.varnode(operand).size.saturating_mul(8);
                changed |= set(operand, Type::Float(width), types);
            }
        }
        // A conditional branch reads a boolean.
        op::CBRANCH => {
            if let Some(condition) = operation.inputs.get(1).copied() {
                changed |= set(condition, Type::Bool, types);
            }
        }
        _ => {}
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{SeqNum, heritage::heritage};
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    #[test]
    fn a_dereferenced_value_is_a_pointer() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let space = data.new_constant(0, 4);
        let address = data.new_varnode(REGISTER_SPACE, 8, 4);
        let load = data.new_op(op::LOAD, seq(0x1000), vec![space, address]);
        let loaded = data.new_unique(4);
        data.op_set_output(load, Some(loaded));
        data.op_insert_end(load, block);
        let ret = data.new_op(op::RETURN, seq(0x1004), vec![loaded]);
        data.op_insert_end(ret, block);

        let types = infer_types(&data, &BTreeMap::new());
        assert!(matches!(types.get(address), Some(Type::Pointer(_))));
    }

    #[test]
    fn a_pointer_travels_back_through_a_copy_to_its_argument_register() {
        // The address-map solver could not do this: the dereference is below
        // the copy, so nothing carried the pointer type upward.
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let argument = data.new_varnode(REGISTER_SPACE, 8, 4);
        let copy = data.new_op(op::COPY, seq(0x1000), vec![argument]);
        let local = data.new_varnode(REGISTER_SPACE, 16, 4);
        data.op_set_output(copy, Some(local));
        data.op_insert_end(copy, block);
        let space = data.new_constant(0, 4);
        let load = data.new_op(op::LOAD, seq(0x1004), vec![space, local]);
        let loaded = data.new_unique(4);
        data.op_set_output(load, Some(loaded));
        data.op_insert_end(load, block);
        let ret = data.new_op(op::RETURN, seq(0x1008), vec![loaded]);
        data.op_insert_end(ret, block);

        let types = infer_types(&data, &BTreeMap::new());
        assert!(
            matches!(types.get(argument), Some(Type::Pointer(_))),
            "got {:?}",
            types.get(argument)
        );
    }

    #[test]
    fn a_pointer_survives_offsetting() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let base = data.new_varnode(REGISTER_SPACE, 8, 4);
        let offset = data.new_constant(0x10, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![base, offset]);
        let field = data.new_unique(4);
        data.op_set_output(add, Some(field));
        data.op_insert_end(add, block);
        let space = data.new_constant(0, 4);
        let load = data.new_op(op::LOAD, seq(0x1004), vec![space, field]);
        let loaded = data.new_unique(4);
        data.op_set_output(load, Some(loaded));
        data.op_insert_end(load, block);
        let ret = data.new_op(op::RETURN, seq(0x1008), vec![loaded]);
        data.op_insert_end(ret, block);

        let types = infer_types(&data, &BTreeMap::new());
        assert!(matches!(types.get(field), Some(Type::Pointer(_))));
        assert!(
            matches!(types.get(base), Some(Type::Pointer(_))),
            "the base of a field access is a pointer too"
        );
    }

    #[test]
    fn a_comparison_result_is_a_boolean() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_varnode(REGISTER_SPACE, 8, 4);
        let right = data.new_constant(0, 4);
        let compare = data.new_op(op::INT_EQUAL, seq(0x1000), vec![left, right]);
        let flag = data.new_unique(1);
        data.op_set_output(compare, Some(flag));
        data.op_insert_end(compare, block);
        let target = data.new_constant(0x1010, 4);
        let branch = data.new_op(op::CBRANCH, seq(0x1004), vec![target, flag]);
        data.op_insert_end(branch, block);

        let types = infer_types(&data, &BTreeMap::new());
        assert_eq!(types.get(flag), Some(&Type::Bool));
    }

    #[test]
    fn a_float_operation_types_its_operands_as_floats() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_varnode(REGISTER_SPACE, 8, 4);
        let right = data.new_varnode(REGISTER_SPACE, 16, 4);
        let add = data.new_op(op::FLOAT_ADD, seq(0x1000), vec![left, right]);
        let sum = data.new_unique(4);
        data.op_set_output(add, Some(sum));
        data.op_insert_end(add, block);
        let ret = data.new_op(op::RETURN, seq(0x1004), vec![sum]);
        data.op_insert_end(ret, block);

        let types = infer_types(&data, &BTreeMap::new());
        assert_eq!(types.get(sum), Some(&Type::Float(32)));
        assert_eq!(types.get(left), Some(&Type::Float(32)));
        assert_eq!(types.get(right), Some(&Type::Float(32)));
    }

    #[test]
    fn a_seeded_type_is_never_weakened() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let argument = data.new_varnode(REGISTER_SPACE, 8, 4);
        let copy = data.new_op(op::COPY, seq(0x1000), vec![argument]);
        let out = data.new_unique(4);
        data.op_set_output(copy, Some(out));
        data.op_insert_end(copy, block);
        let ret = data.new_op(op::RETURN, seq(0x1004), vec![out]);
        data.op_insert_end(ret, block);

        let seed = BTreeMap::from([(argument, Type::Float(32))]);
        let types = infer_types(&data, &seed);
        assert_eq!(types.get(argument), Some(&Type::Float(32)));
        assert_eq!(
            types.get(out),
            Some(&Type::Float(32)),
            "the seeded type propagates through the copy"
        );
    }

    #[test]
    fn a_type_crosses_a_merge_to_every_incoming_value() {
        let mut data = Funcdata::default();
        let entry = data.new_block(0x1000);
        let left = data.new_block(0x1010);
        let right = data.new_block(0x1020);
        let join = data.new_block(0x1030);
        data.add_edge(entry, left);
        data.add_edge(entry, right);
        data.add_edge(left, join);
        data.add_edge(right, join);
        for block in [left, right] {
            let start = data.block(block).start;
            let source = data.new_varnode(REGISTER_SPACE, 16, 4);
            let copy = data.new_op(op::COPY, seq(start), vec![source]);
            let out = data.new_varnode(REGISTER_SPACE, 8, 4);
            data.op_set_output(copy, Some(out));
            data.op_insert_end(copy, block);
        }
        let space = data.new_constant(0, 4);
        let read = data.new_varnode(REGISTER_SPACE, 8, 4);
        let load = data.new_op(op::LOAD, seq(0x1030), vec![space, read]);
        let loaded = data.new_unique(4);
        data.op_set_output(load, Some(loaded));
        data.op_insert_end(load, join);
        let ret = data.new_op(op::RETURN, seq(0x1034), vec![loaded]);
        data.op_insert_end(ret, join);
        heritage(&mut data);

        let types = infer_types(&data, &BTreeMap::new());
        let phi = data
            .live_ops()
            .find(|(_, operation)| operation.opcode == op::MULTIEQUAL)
            .expect("a merge was placed")
            .1
            .clone();
        for operand in phi.inputs {
            assert!(
                matches!(types.get(operand), Some(Type::Pointer(_))),
                "each incoming value is the pointer the join dereferences"
            );
        }
    }

    #[test]
    fn propagation_settles_on_a_loop() {
        // A merge that feeds itself makes the lattice cyclic. The pass must
        // report settling rather than run to its cap.
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let seed_value = data.new_varnode(REGISTER_SPACE, 8, 4);
        let phi = data.new_op(op::MULTIEQUAL, seq(0x1000), vec![seed_value]);
        let result = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(phi, Some(result));
        data.op_insert_end(phi, block);
        data.op_set_inputs(phi, vec![seed_value, result]);
        let space = data.new_constant(0, 4);
        let load = data.new_op(op::LOAD, seq(0x1004), vec![space, result]);
        let loaded = data.new_unique(4);
        data.op_set_output(load, Some(loaded));
        data.op_insert_end(load, block);

        let types = infer_types(&data, &BTreeMap::new());
        assert!(!types.unsettled, "propagation reached a fixed point");
        assert!(matches!(types.get(seed_value), Some(Type::Pointer(_))));
    }
}
