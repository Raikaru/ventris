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
    let mut out = SsaFunction::default();
    let mut versions: BTreeMap<ValueKey, u32> = BTreeMap::new();
    for instruction in function.instructions.values() {
        for operation in &instruction.pcode.ops {
            let output_ty = operation
                .output
                .map(|output| operation_type(operation.opcode, output.size));
            if let Some(output) = operation.output {
                let key = ValueKey::from(output);
                let version = versions.entry(key).or_insert(0);
                let current = *version;
                *version = version.saturating_add(1);
                let ty = output_ty.clone().unwrap_or(Type::Unknown);
                out.constraints.push(TypeConstraint {
                    value: output,
                    ty: ty.clone(),
                });
                out.values.push(SsaValue {
                    id: out.values.len() as u32,
                    origin: output,
                    ty,
                    version: current,
                });
            }
            for (index, input) in operation.inputs.iter().copied().enumerate() {
                let Some(ty) = input_type(operation.opcode, index, input, output_ty.as_ref())
                else {
                    continue;
                };
                if input.space != ventris_lifter::CONST_SPACE
                    && input.space != ventris_lifter::UNIQUE_SPACE
                {
                    out.constraints.push(TypeConstraint { value: input, ty });
                }
            }
        }
    }
    out
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
        | op::INT_SBORROW => Type::Bool,
        op::INT_SDIV | op::INT_SREM | op::INT_SRIGHT => Type::Signed(width.saturating_mul(8)),
        op::INT_SEXT => Type::Signed(width.saturating_mul(8)),
        _ => Type::from_width(width),
    }
}

fn input_type(opcode: i32, index: usize, input: Varnode, output_ty: Option<&Type>) -> Option<Type> {
    match opcode {
        op::BOOL_NEGATE | op::BOOL_XOR | op::BOOL_AND | op::BOOL_OR => Some(Type::Bool),
        op::INT_EQUAL
        | op::INT_NOTEQUAL
        | op::INT_LESS
        | op::INT_LESSEQUAL
        | op::INT_SLESS
        | op::INT_SLESSEQUAL => Some(Type::from_width(input.size)),
        op::CMOV if index == 0 => Some(Type::Bool),
        op::COPY | op::MULTIEQUAL | op::CMOV => output_ty.cloned(),
        op::INT_2COMP | op::INT_NEGATE | op::INT_ZEXT | op::SUBPIECE | op::CAST => {
            Some(Type::from_width(input.size))
        }
        op::INT_SEXT => Some(Type::Signed(input.size.saturating_mul(8))),
        op::LOAD if index == 1 => Some(Type::Pointer(Box::new(Type::Unknown))),
        op::STORE if index == 1 => Some(Type::Pointer(Box::new(Type::Unknown))),
        op::STORE if index == 2 => Some(Type::from_width(input.size)),
        op::INT_SDIV | op::INT_SREM | op::INT_SRIGHT => {
            Some(Type::Signed(input.size.saturating_mul(8)))
        }
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
        | op::INT_CARRY
        | op::INT_SCARRY
        | op::INT_SBORROW => Some(Type::from_width(input.size)),
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
    match (old, new) {
        (Type::Unknown, ty) | (ty, Type::Unknown) => ty.clone(),
        (Type::Unsigned(left), Type::Unsigned(right)) => Type::Unsigned((*left).max(*right)),
        (Type::Signed(left), Type::Signed(right)) => Type::Signed((*left).max(*right)),
        (Type::Pointer(left), Type::Pointer(right)) => {
            Type::Pointer(Box::new(merge_types(left, right)))
        }
        (left, _) => left.clone(),
    }
}
