use super::*;
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub(super) struct ValueKey {
    pub(super) space: u32,
    pub(super) offset: u64,
    pub(super) width: u32,
}

impl From<Varnode> for ValueKey {
    fn from(v: Varnode) -> Self {
        Self {
            space: v.space,
            offset: v.offset,
            width: v.size,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TypeConstraint {
    pub value: Varnode,
    pub ty: Type,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SsaValue {
    pub id: u32,
    pub origin: Varnode,
    pub ty: Type,
    pub version: u32,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SsaFunction {
    pub values: Vec<SsaValue>,
    pub constraints: Vec<TypeConstraint>,
}

/// Build versioned definitions from p-code outputs. A definition gets a new
/// version even when the machine register is reused; this is the invariant that
/// prevents a later assignment from rewriting an earlier expression.
///
/// Constraints are emitted for both definitions and their typed uses. This
/// keeps width facts attached to the value that crosses an instruction
/// boundary instead of treating every input register as an untyped name.
pub fn build_ssa(function: &NativeFunction) -> SsaFunction {
    use super::heritage::{OperationId, VersionedValue};

    let heritage = super::heritage::build_heritage(function);
    let operations: BTreeMap<OperationId, &PcodeOp> = function
        .instructions
        .iter()
        .flat_map(|(address, instruction)| {
            instruction
                .pcode
                .ops
                .iter()
                .enumerate()
                .map(move |(index, operation)| {
                    (
                        OperationId {
                            address: *address,
                            index: index as u32,
                        },
                        operation,
                    )
                })
        })
        .collect();

    let mut facts = BTreeMap::<VersionedValue, Type>::new();
    let mut equivalent = BTreeSet::<(VersionedValue, VersionedValue)>::new();
    let mut pointer_flows = Vec::<(Vec<VersionedValue>, VersionedValue)>::new();
    for block in &heritage.blocks {
        for phi in &block.phis {
            for input in &phi.inputs {
                equivalent.insert(ordered_pair(phi.output, input.value));
            }
        }
        for record in &block.operations {
            let Some(operation) = operations.get(&record.id).copied() else {
                continue;
            };
            let definition = record.defs.first().copied();
            if let (Some(definition), Some(output)) = (definition, operation.output) {
                constrain_version(
                    &mut facts,
                    definition,
                    operation_type(operation.opcode, output.size),
                );
            }

            let mut uses = record.uses.iter().copied();
            let mut data_uses = Vec::new();
            for (index, input) in operation.inputs.iter().copied().enumerate() {
                if input.space == ventris_lifter::CONST_SPACE {
                    continue;
                }
                let Some(value) = uses.next() else {
                    continue;
                };
                data_uses.push(value);
                if let Some(ty) = input_type(
                    operation.opcode,
                    index,
                    input,
                    operation
                        .output
                        .map(|output| operation_type(operation.opcode, output.size))
                        .as_ref(),
                ) {
                    constrain_version(&mut facts, value, ty);
                }
                if definition.is_some_and(|_| {
                    operation.opcode == op::COPY
                        || operation.opcode == op::MULTIEQUAL
                        || operation.opcode == op::INDIRECT
                        || (operation.opcode == op::CMOV && index > 0)
                }) {
                    equivalent.insert(ordered_pair(definition.unwrap(), value));
                }
            }
            if let Some(definition) = definition {
                if matches!(
                    operation.opcode,
                    op::INT_ADD | op::INT_SUB | op::PTRADD | op::PTRSUB
                ) {
                    pointer_flows.push((data_uses, definition));
                }
            }
        }
    }
    propagate_version_types(&mut facts, &equivalent, &pointer_flows);

    let versions: BTreeMap<(u64, u32, ValueKey), u32> = heritage
        .blocks
        .iter()
        .flat_map(|block| {
            block.operations.iter().flat_map(|operation| {
                operation.defs.iter().map(move |definition| {
                    (
                        (
                            operation.id.address,
                            operation.id.index,
                            definition.location,
                        ),
                        definition.version,
                    )
                })
            })
        })
        .collect();
    let mut out = SsaFunction::default();
    let mut constraints = BTreeMap::<ValueKey, Type>::new();
    for (address, instruction) in &function.instructions {
        for (operation_index, operation) in instruction.pcode.ops.iter().enumerate() {
            let output_ty = operation
                .output
                .map(|output| operation_type(operation.opcode, output.size));
            if let Some(output) = operation.output {
                let key = ValueKey::from(output);
                let version = versions
                    .get(&(*address, operation_index as u32, key))
                    .copied()
                    .unwrap_or(0);
                let versioned = VersionedValue {
                    location: key,
                    version,
                };
                let ty = facts
                    .get(&versioned)
                    .cloned()
                    .unwrap_or_else(|| operation_type(operation.opcode, output.size));
                merge_constraint(&mut constraints, key, ty.clone());
                out.constraints.push(TypeConstraint {
                    value: output,
                    ty: output_ty
                        .clone()
                        .unwrap_or_else(|| Type::from_width(output.size)),
                });
                out.values.push(SsaValue {
                    id: out.values.len() as u32,
                    origin: output,
                    ty,
                    version,
                });
            }
            for (index, input) in operation.inputs.iter().copied().enumerate() {
                if input.space == ventris_lifter::CONST_SPACE
                    || input.space == ventris_lifter::UNIQUE_SPACE
                {
                    continue;
                }
                if let Some(ty) = input_type(operation.opcode, index, input, output_ty.as_ref()) {
                    out.constraints.push(TypeConstraint { value: input, ty });
                }
            }
        }
    }
    for block in &heritage.blocks {
        for phi in &block.phis {
            if phi.operation.is_some() {
                continue;
            }
            let ty = facts
                .get(&phi.output)
                .cloned()
                .unwrap_or_else(|| Type::from_width(phi.location.width));
            merge_constraint(&mut constraints, phi.location, ty.clone());
            out.values.push(SsaValue {
                id: out.values.len() as u32,
                origin: Varnode::new(phi.location.space, phi.location.offset, phi.location.width),
                ty,
                version: phi.output.version,
            });
        }
    }
    for (value, ty) in facts {
        if value.location.space != ventris_lifter::UNIQUE_SPACE {
            merge_constraint(&mut constraints, value.location, ty);
        }
    }
    out.constraints
        .extend(constraints.into_iter().map(|(key, ty)| TypeConstraint {
            value: Varnode::new(key.space, key.offset, key.width),
            ty,
        }));
    out
}

fn ordered_pair(
    left: super::heritage::VersionedValue,
    right: super::heritage::VersionedValue,
) -> (
    super::heritage::VersionedValue,
    super::heritage::VersionedValue,
) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn constrain_version(
    facts: &mut BTreeMap<super::heritage::VersionedValue, Type>,
    value: super::heritage::VersionedValue,
    ty: Type,
) -> bool {
    match facts.get_mut(&value) {
        Some(old) => {
            let merged = merge_types(old, &ty);
            let changed = *old != merged;
            *old = merged;
            changed
        }
        None => {
            facts.insert(value, ty);
            true
        }
    }
}

fn propagate_version_types(
    facts: &mut BTreeMap<super::heritage::VersionedValue, Type>,
    equivalent: &BTreeSet<(
        super::heritage::VersionedValue,
        super::heritage::VersionedValue,
    )>,
    pointer_flows: &[(
        Vec<super::heritage::VersionedValue>,
        super::heritage::VersionedValue,
    )],
) {
    let iteration_cap = facts
        .len()
        .saturating_add(equivalent.len())
        .saturating_add(pointer_flows.len())
        .max(1);
    for _ in 0..=iteration_cap {
        let mut changed = false;
        for (left, right) in equivalent {
            let merged = merge_types(
                facts.get(left).unwrap_or(&Type::Unknown),
                facts.get(right).unwrap_or(&Type::Unknown),
            );
            changed |= constrain_version(facts, *left, merged.clone());
            changed |= constrain_version(facts, *right, merged);
        }
        for (inputs, output) in pointer_flows {
            if inputs
                .iter()
                .filter_map(|input| facts.get(input))
                .any(|ty| matches!(ty, Type::Pointer(_)))
            {
                changed |=
                    constrain_version(facts, *output, Type::Pointer(Box::new(Type::Unknown)));
            }
        }
        if !changed {
            break;
        }
    }
}

fn merge_constraint(constraints: &mut BTreeMap<ValueKey, Type>, key: ValueKey, ty: Type) {
    constraints
        .entry(key)
        .and_modify(|old| *old = merge_types(old, &ty))
        .or_insert(ty);
}

fn operation_type(opcode: i32, width: u32) -> Type {
    match opcode {
        op::BOOL_NEGATE
        | op::BOOL_XOR
        | op::BOOL_AND
        | op::BOOL_OR
        | op::INT_EQUAL
        | op::INT_NOTEQUAL
        | op::INT_LESS
        | op::INT_LESSEQUAL
        | op::INT_SLESS
        | op::INT_SLESSEQUAL
        | op::INT_CARRY
        | op::INT_SCARRY
        | op::INT_SBORROW
        | op::FLOAT_EQUAL
        | op::FLOAT_NOTEQUAL
        | op::FLOAT_LESS
        | op::FLOAT_LESSEQUAL
        | op::FLOAT_NAN => Type::Bool,
        op::INT_SDIV | op::INT_SREM | op::INT_SRIGHT | op::INT_SEXT | op::FLOAT_TRUNC => {
            Type::Signed(width.saturating_mul(8))
        }
        op::FLOAT_ADD
        | op::FLOAT_DIV
        | op::FLOAT_MULT
        | op::FLOAT_SUB
        | op::FLOAT_NEG
        | op::FLOAT_ABS
        | op::FLOAT_SQRT
        | op::FLOAT_INT2FLOAT
        | op::FLOAT_FLOAT2FLOAT
        | op::FLOAT_CEIL
        | op::FLOAT_FLOOR
        | op::FLOAT_ROUND => Type::Float(width.saturating_mul(8)),
        op::PTRADD | op::PTRSUB | op::NEW => Type::Pointer(Box::new(Type::Unknown)),
        _ => Type::from_width(width),
    }
}

fn input_type(opcode: i32, index: usize, input: Varnode, output_ty: Option<&Type>) -> Option<Type> {
    match opcode {
        op::BOOL_NEGATE | op::BOOL_XOR | op::BOOL_AND | op::BOOL_OR => Some(Type::Bool),
        op::CBRANCH if index == 1 => Some(Type::Bool),
        op::INT_EQUAL | op::INT_NOTEQUAL | op::INT_LESS | op::INT_LESSEQUAL => {
            Some(Type::from_width(input.size))
        }
        op::INT_SLESS | op::INT_SLESSEQUAL | op::INT_SCARRY | op::INT_SBORROW => {
            Some(Type::Signed(input.size.saturating_mul(8)))
        }
        op::CMOV if index == 0 => Some(Type::Bool),
        op::COPY | op::MULTIEQUAL | op::CMOV | op::INDIRECT => output_ty.cloned(),
        op::INT_2COMP | op::INT_NEGATE | op::INT_ZEXT | op::SUBPIECE | op::CAST => {
            Some(Type::from_width(input.size))
        }
        op::INT_SEXT => Some(Type::Signed(input.size.saturating_mul(8))),
        op::LOAD if index == 1 => Some(Type::Pointer(Box::new(Type::Unknown))),
        op::STORE if index == 1 => Some(Type::Pointer(Box::new(Type::Unknown))),
        op::STORE if index == 2 => Some(Type::from_width(input.size)),
        op::BRANCHIND | op::CALLIND if index == 0 => Some(Type::Pointer(Box::new(Type::Unknown))),
        op::PTRADD | op::PTRSUB if index == 0 => Some(Type::Pointer(Box::new(Type::Unknown))),
        op::PTRADD | op::PTRSUB => Some(Type::from_width(input.size)),
        op::NEW => Some(Type::from_width(input.size)),
        op::INT_SDIV | op::INT_SREM => Some(Type::Signed(input.size.saturating_mul(8))),
        op::INT_SRIGHT if index == 0 => Some(Type::Signed(input.size.saturating_mul(8))),
        op::FLOAT_EQUAL
        | op::FLOAT_NOTEQUAL
        | op::FLOAT_LESS
        | op::FLOAT_LESSEQUAL
        | op::FLOAT_NAN
        | op::FLOAT_ADD
        | op::FLOAT_DIV
        | op::FLOAT_MULT
        | op::FLOAT_SUB
        | op::FLOAT_NEG
        | op::FLOAT_ABS
        | op::FLOAT_SQRT
        | op::FLOAT_FLOAT2FLOAT
        | op::FLOAT_TRUNC
        | op::FLOAT_CEIL
        | op::FLOAT_FLOOR
        | op::FLOAT_ROUND => Some(Type::Float(input.size.saturating_mul(8))),
        op::FLOAT_INT2FLOAT => Some(Type::Signed(input.size.saturating_mul(8))),
        op::INT_ADD
        | op::INT_SUB
        | op::INT_MULT
        | op::INT_DIV
        | op::INT_REM
        | op::INT_AND
        | op::INT_OR
        | op::INT_XOR
        | op::INT_LEFT
        | op::INT_RIGHT
        | op::INT_SRIGHT
        | op::INT_CARRY
        | op::PIECE
        | op::INSERT
        | op::POPCOUNT
        | op::LZCOUNT => Some(Type::from_width(input.size)),
        _ => None,
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct TypeSolver {
    constraints: BTreeMap<ValueKey, Type>,
}

impl TypeSolver {
    pub fn constrain(&mut self, value: Varnode, ty: Type) {
        let key = ValueKey::from(value);
        self.constraints
            .entry(key)
            .and_modify(|old| *old = merge_types(old, &ty))
            .or_insert(ty);
    }

    pub fn solve(&self) -> Vec<TypeConstraint> {
        self.constraints
            .iter()
            .map(|(key, ty)| TypeConstraint {
                value: Varnode::new(key.space, key.offset, key.width),
                ty: ty.clone(),
            })
            .collect()
    }
}

pub(super) fn merge_types(old: &Type, new: &Type) -> Type {
    if old == new {
        return old.clone();
    }
    match (old, new) {
        (Type::Unknown, ty) | (ty, Type::Unknown) => ty.clone(),
        (Type::Unsigned(left), Type::Unsigned(right)) => Type::Unsigned((*left).max(*right)),
        (Type::Signed(left), Type::Signed(right)) => Type::Signed((*left).max(*right)),
        (Type::Float(left), Type::Float(right)) => Type::Float((*left).max(*right)),
        (Type::Pointer(left), Type::Pointer(right)) => {
            Type::Pointer(Box::new(merge_types(left, right)))
        }
        (Type::Void, ty) | (ty, Type::Void) => ty.clone(),
        (left, right) => {
            if type_rank(left) >= type_rank(right) {
                left.clone()
            } else {
                right.clone()
            }
        }
    }
}

fn type_rank(ty: &Type) -> u8 {
    match ty {
        Type::Unknown => 0,
        Type::Unsigned(_) => 2,
        Type::Signed(_) => 1,
        Type::Bool => 3,
        Type::Float(_) => 4,
        Type::Pointer(_) => 5,
        Type::Void => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{Flow, LiftedInstruction};
    use ventris_pcode::InstPcode;

    fn function(operations: Vec<PcodeOp>) -> NativeFunction {
        NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([(
                0x1000,
                LiftedInstruction {
                    address: 0x1000,
                    bytes: vec![0],
                    pcode: InstPcode {
                        len: 1,
                        space: ventris_lifter::RAM_SPACE,
                        offset: 0x1000,
                        ops: operations,
                    },
                    flow: Flow::Return,
                    embedded_delay_slot_bytes: 0,
                },
            )]),
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        }
    }

    #[test]
    fn float_type_propagates_through_copy_versions() {
        let left = Varnode::new(ventris_lifter::REGISTER_SPACE, 0, 4);
        let right = Varnode::new(ventris_lifter::REGISTER_SPACE, 4, 4);
        let temporary = Varnode::new(ventris_lifter::UNIQUE_SPACE, 0x100, 4);
        let result = Varnode::new(ventris_lifter::REGISTER_SPACE, 8, 4);
        let ssa = build_ssa(&function(vec![
            PcodeOp::new(op::FLOAT_ADD, Some(temporary), vec![left, right]),
            PcodeOp::new(op::COPY, Some(result), vec![temporary]),
            PcodeOp::new(op::RETURN, None, vec![result]),
        ]));

        assert_eq!(
            ssa.values
                .iter()
                .find(|value| value.origin == result)
                .map(|value| &value.ty),
            Some(&Type::Float(32))
        );
    }

    #[test]
    fn explicit_pointer_arithmetic_types_base_and_result() {
        let base = Varnode::new(ventris_lifter::REGISTER_SPACE, 0, 8);
        let index = Varnode::new(ventris_lifter::REGISTER_SPACE, 8, 8);
        let result = Varnode::new(ventris_lifter::UNIQUE_SPACE, 0x100, 8);
        let ssa = build_ssa(&function(vec![
            PcodeOp::new(
                op::PTRADD,
                Some(result),
                vec![base, index, Varnode::new(ventris_lifter::CONST_SPACE, 4, 8)],
            ),
            PcodeOp::new(op::RETURN, None, vec![result]),
        ]));

        assert!(ssa.constraints.iter().any(|constraint| {
            constraint.value == base && matches!(constraint.ty, Type::Pointer(_))
        }));
        assert!(
            ssa.values
                .iter()
                .any(|value| value.origin == result && matches!(value.ty, Type::Pointer(_)))
        );
    }

    #[test]
    fn type_merge_is_commutative_for_conflicting_evidence() {
        let integer = Type::Unsigned(64);
        let pointer = Type::Pointer(Box::new(Type::Unsigned(8)));
        assert_eq!(
            merge_types(&integer, &pointer),
            merge_types(&pointer, &integer)
        );
        assert_eq!(
            merge_types(&integer, &pointer),
            Type::Pointer(Box::new(Type::Unsigned(8)))
        );
    }
}
