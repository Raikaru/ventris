use super::*;
impl BinaryOp {
    pub(super) fn build(op: Self, left: Expr, right: Expr) -> Expr {
        Expr::Binary {
            op,
            left: Box::new(left),
            right: Box::new(right),
        }
    }
}

pub(super) fn simplify(value: Expr) -> Expr {
    match value {
        Expr::Binary {
            op: binary,
            left,
            right,
        } => {
            let left = simplify(*left);
            let right = simplify(*right);
            if matches!(binary, BinaryOp::Xor | BinaryOp::Sub) && left == right {
                return Expr::constant(0, 8);
            }
            if matches!(binary, BinaryOp::And | BinaryOp::Or) && left == right {
                return left;
            }
            if matches!(binary, BinaryOp::Add | BinaryOp::Or | BinaryOp::Xor) && right.is_zero() {
                return left;
            }
            if matches!(binary, BinaryOp::Add | BinaryOp::Or | BinaryOp::Xor) && left.is_zero() {
                return right;
            }
            Expr::Binary {
                op: binary,
                left: Box::new(left),
                right: Box::new(right),
            }
        }
        Expr::Not(value) => Expr::Not(Box::new(simplify(*value))),
        Expr::Neg(value) => Expr::Neg(Box::new(simplify(*value))),
        Expr::BitNot(value) => Expr::BitNot(Box::new(simplify(*value))),
        Expr::Builtin { name, args } => Expr::Builtin {
            name,
            args: args.into_iter().map(simplify).collect(),
        },
        Expr::Cast { ty, value } => {
            let value = simplify(*value);
            if let Expr::Constant { value, width } = value {
                Expr::Constant { value, width }
            } else {
                Expr::Cast {
                    ty,
                    value: Box::new(value),
                }
            }
        }
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => Expr::Select {
            condition: Box::new(simplify(*condition)),
            when_true: Box::new(simplify(*when_true)),
            when_false: Box::new(simplify(*when_false)),
        },
        value => value,
    }
}
#[cfg(test)]
fn invert_condition(value: Expr) -> Expr {
    match value {
        Expr::Not(inner) => *inner,
        value => Expr::Not(Box::new(value)),
    }
}
#[cfg(test)]
fn has_other_branch_to(
    statements: &[NativeStatement],
    excluded_indices: &[usize],
    target: u64,
) -> bool {
    statements.iter().enumerate().any(|(index, statement)| {
        !excluded_indices.contains(&index)
            && match statement {
                NativeStatement::Goto(branch_target)
                | NativeStatement::IfGoto {
                    target: branch_target,
                    ..
                } => *branch_target == target,
                NativeStatement::IndirectGoto(_) => true,
                _ => false,
            }
    })
}

#[cfg(test)]
pub(super) fn structure_control_flow(statements: Vec<NativeStatement>) -> Vec<NativeStatement> {
    let mut structured = Vec::with_capacity(statements.len());
    let mut index = 0usize;
    while index < statements.len() {
        if index + 3 < statements.len() {
            if let (
                NativeStatement::IfGoto { condition, target },
                NativeStatement::Return(value),
                NativeStatement::Label(label),
                NativeStatement::Return(joined),
            ) = (
                &statements[index],
                &statements[index + 1],
                &statements[index + 2],
                &statements[index + 3],
            ) {
                if target == label && !has_other_branch_to(&statements, &[index], *target) {
                    structured.push(NativeStatement::IfReturn {
                        condition: invert_condition(condition.clone()),
                        value: value.clone(),
                    });
                    structured.push(NativeStatement::Return(joined.clone()));
                    index += 4;
                    continue;
                }
            }
        }

        if let NativeStatement::IfGoto { condition, target } = &statements[index] {
            let target_index = statements[index + 1..]
                .iter()
                .position(|statement| {
                    matches!(statement, NativeStatement::Label(label) if label == target)
                })
                .map(|relative| index + 1 + relative);
            if let Some(target_index) =
                target_index.filter(|target_index| *target_index > index + 1)
            {
                if !has_other_branch_to(&statements, &[index], *target) {
                    if let Some(NativeStatement::Return(value)) = statements.get(target_index + 1) {
                        structured.push(NativeStatement::IfReturn {
                            condition: condition.clone(),
                            value: value.clone(),
                        });
                        structured.extend(statements[index + 1..target_index].iter().cloned());
                        structured.push(NativeStatement::Return(value.clone()));
                        index = target_index + 2;
                        continue;
                    }
                }
            }
        }

        if let NativeStatement::IfGoto { condition, target } = &statements[index] {
            let target_index = statements[index + 1..]
                .iter()
                .position(|statement| {
                    matches!(statement, NativeStatement::Label(label) if label == target)
                })
                .map(|relative| index + 1 + relative);
            if let Some(target_index) =
                target_index.filter(|target_index| *target_index > index + 1)
            {
                if let Some(NativeStatement::Goto(join)) = statements.get(target_index - 1) {
                    let join_index = statements[target_index + 1..]
                        .iter()
                        .position(|statement| {
                            matches!(statement, NativeStatement::Label(label) if label == join)
                        })
                        .map(|relative| target_index + 1 + relative);
                    if let Some(join_index) = join_index {
                        let consumed_join_branch = target_index - 1;
                        if !has_other_branch_to(&statements, &[index], *target)
                            && !has_other_branch_to(&statements, &[consumed_join_branch], *join)
                        {
                            let then_body = statements[target_index + 1..join_index].to_vec();
                            let else_body = statements[index + 1..consumed_join_branch].to_vec();
                            if !then_body.is_empty() || !else_body.is_empty() {
                                structured.push(NativeStatement::IfElse {
                                    condition: condition.clone(),
                                    then_body,
                                    else_body,
                                });
                                index = join_index + 1;
                                continue;
                            }
                        }
                    }
                }
            }
        }

        structured.push(statements[index].clone());
        index += 1;
    }
    structured
}
