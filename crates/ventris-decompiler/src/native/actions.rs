use std::cell::RefCell;

use super::*;

const DEFAULT_ITERATION_CAP: usize = 16;

/// A source-level rule that can be scheduled in an [`ActionGroup`].
///
/// Keeping the rule as a value (rather than hiding it in a monolithic pass) is
/// intentional: Ghidra's action database treats every rule as an independently
/// named unit, and the explicit names make a pipeline trace reproducible.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(super) enum ActionRuleKind {
    ConstantFolding,
    AlgebraicSimplification,
    CopyCastCleanup,
    BooleanNormalization,
    CommutativeCanonicalization,
    DeadTemporaryAssignmentElimination,
    BranchConditionSimplification,
    ConsecutiveLabelGotoCleanup,
    DeclarationNarrowing,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct ActionRule {
    kind: ActionRuleKind,
}

impl ActionRule {
    pub(super) const fn new(kind: ActionRuleKind) -> Self {
        Self { kind }
    }

    pub(super) const fn constant_folding() -> Self {
        Self::new(ActionRuleKind::ConstantFolding)
    }

    pub(super) const fn algebraic_simplification() -> Self {
        Self::new(ActionRuleKind::AlgebraicSimplification)
    }

    pub(super) const fn copy_cast_cleanup() -> Self {
        Self::new(ActionRuleKind::CopyCastCleanup)
    }

    pub(super) const fn boolean_normalization() -> Self {
        Self::new(ActionRuleKind::BooleanNormalization)
    }

    pub(super) const fn commutative_canonicalization() -> Self {
        Self::new(ActionRuleKind::CommutativeCanonicalization)
    }

    pub(super) const fn dead_temporary_assignment_elimination() -> Self {
        Self::new(ActionRuleKind::DeadTemporaryAssignmentElimination)
    }

    pub(super) const fn branch_condition_simplification() -> Self {
        Self::new(ActionRuleKind::BranchConditionSimplification)
    }

    pub(super) const fn consecutive_label_goto_cleanup() -> Self {
        Self::new(ActionRuleKind::ConsecutiveLabelGotoCleanup)
    }

    pub(super) const fn declaration_narrowing() -> Self {
        Self::new(ActionRuleKind::DeclarationNarrowing)
    }

    pub(super) const fn name(self) -> &'static str {
        match self.kind {
            ActionRuleKind::ConstantFolding => "constant-folding",
            ActionRuleKind::AlgebraicSimplification => "algebraic-simplification",
            ActionRuleKind::CopyCastCleanup => "copy-cast-cleanup",
            ActionRuleKind::BooleanNormalization => "boolean-normalization",
            ActionRuleKind::CommutativeCanonicalization => "commutative-canonicalization",
            ActionRuleKind::DeadTemporaryAssignmentElimination => {
                "dead-temporary-assignment-elimination"
            }
            ActionRuleKind::BranchConditionSimplification => "branch-condition-simplification",
            ActionRuleKind::ConsecutiveLabelGotoCleanup => "consecutive-label-goto-cleanup",
            ActionRuleKind::DeclarationNarrowing => "declaration-narrowing",
        }
    }

    fn apply(self, statements: &mut Vec<NativeStatement>) -> bool {
        match self.kind {
            ActionRuleKind::ConstantFolding => rewrite_statement_expressions(statements, fold_expr),
            ActionRuleKind::AlgebraicSimplification => {
                rewrite_statement_expressions(statements, simplify_algebraic_expr)
            }
            ActionRuleKind::CopyCastCleanup => apply_copy_cast_cleanup(statements),
            ActionRuleKind::BooleanNormalization => {
                rewrite_statement_expressions(statements, normalize_boolean_expr)
            }
            ActionRuleKind::CommutativeCanonicalization => {
                rewrite_statement_expressions(statements, canonicalize_commutative_expr)
            }
            ActionRuleKind::DeadTemporaryAssignmentElimination => {
                eliminate_dead_temporary_assignments(statements)
            }
            ActionRuleKind::BranchConditionSimplification => simplify_branch_conditions(statements),
            ActionRuleKind::ConsecutiveLabelGotoCleanup => cleanup_labels_and_gotos(statements),
            ActionRuleKind::DeclarationNarrowing => narrow_declarations_to_used_width(statements),
        }
    }
}

/// An ordered collection of rules. Fixed-point groups rerun their complete rule
/// list, not an individual rule, so a later rule can expose work for an earlier
/// rule without changing the declared ordering.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct ActionGroup {
    name: String,
    rules: Vec<ActionRule>,
    fixed_point: bool,
    iteration_cap: usize,
}

impl ActionGroup {
    pub(super) fn new(
        name: impl Into<String>,
        rules: Vec<ActionRule>,
        fixed_point: bool,
        iteration_cap: usize,
    ) -> Self {
        Self {
            name: name.into(),
            rules,
            fixed_point,
            // A zero-length fixed-point loop would never get a chance to prove
            // convergence. Treat zero as the smallest useful deterministic cap.
            iteration_cap: iteration_cap.max(1),
        }
    }

    pub(super) fn fixed_point(
        name: impl Into<String>,
        rules: Vec<ActionRule>,
        iteration_cap: usize,
    ) -> Self {
        Self::new(name, rules, true, iteration_cap)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct ActionRuleTrace {
    pub(super) name: &'static str,
    pub(super) changed: bool,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct ActionIterationTrace {
    pub(super) group: String,
    pub(super) iteration: usize,
    pub(super) changed: bool,
    pub(super) rules: Vec<ActionRuleTrace>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct ActionGroupTrace {
    pub(super) group: String,
    pub(super) iterations: usize,
    pub(super) converged: bool,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct ActionRunResult {
    pub(super) statements: Vec<NativeStatement>,
    pub(super) trace: Vec<ActionIterationTrace>,
    pub(super) groups: Vec<ActionGroupTrace>,
    pub(super) converged: bool,
}

/// The ordered action database used by the native middle/end stages.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct ActionDatabase {
    groups: Vec<ActionGroup>,
}

impl ActionDatabase {
    pub(super) fn new() -> Self {
        Self { groups: Vec::new() }
    }

    /// Construct the default source-level pipeline. The group boundaries mirror
    /// Ghidra's broad rule stages while retaining a small, deterministic rule set
    /// appropriate for the expression representation used by Ventris.
    pub(super) fn default_database() -> Self {
        let mut database = Self::new();
        database.add_group(ActionGroup::fixed_point(
            "expression-normalization",
            vec![
                ActionRule::constant_folding(),
                ActionRule::algebraic_simplification(),
                ActionRule::copy_cast_cleanup(),
                ActionRule::boolean_normalization(),
                ActionRule::commutative_canonicalization(),
                ActionRule::branch_condition_simplification(),
            ],
            DEFAULT_ITERATION_CAP,
        ));
        database.add_group(ActionGroup::fixed_point(
            "temporary-cleanup",
            vec![
                ActionRule::dead_temporary_assignment_elimination(),
                ActionRule::declaration_narrowing(),
            ],
            DEFAULT_ITERATION_CAP,
        ));
        database.add_group(ActionGroup::fixed_point(
            "control-flow-cleanup",
            vec![ActionRule::consecutive_label_goto_cleanup()],
            DEFAULT_ITERATION_CAP,
        ));
        database
    }

    pub(super) fn add_group(&mut self, group: ActionGroup) {
        self.groups.push(group);
    }

    pub(super) fn run(&self, mut statements: Vec<NativeStatement>) -> ActionRunResult {
        let mut trace = Vec::new();
        let mut group_trace = Vec::new();
        let mut converged = true;

        for group in &self.groups {
            let mut group_converged = !group.fixed_point;
            let max_iterations = if group.fixed_point {
                group.iteration_cap
            } else {
                1
            };
            let mut iterations = 0usize;

            for iteration in 0..max_iterations {
                iterations += 1;
                let mut changed = false;
                let mut rule_trace = Vec::with_capacity(group.rules.len());
                for rule in &group.rules {
                    let rule_changed = rule.apply(&mut statements);
                    changed |= rule_changed;
                    rule_trace.push(ActionRuleTrace {
                        name: rule.name(),
                        changed: rule_changed,
                    });
                }
                trace.push(ActionIterationTrace {
                    group: group.name.clone(),
                    iteration: iteration + 1,
                    changed,
                    rules: rule_trace,
                });

                if !group.fixed_point || !changed {
                    group_converged = true;
                    break;
                }
            }

            if !group_converged {
                converged = false;
            }
            group_trace.push(ActionGroupTrace {
                group: group.name.clone(),
                iterations,
                converged: group_converged,
            });
        }

        ActionRunResult {
            statements,
            trace,
            groups: group_trace,
            converged,
        }
    }
}

impl Default for ActionDatabase {
    fn default() -> Self {
        Self::default_database()
    }
}

/// Narrows a declared temporary to the width every use asks for.
///
/// A 32-bit result computed in a 64-bit register is declared wide and narrowed
/// again at each use, which reads as two casts stating one fact. When every use
/// applies the same narrowing cast, the declaration can carry that type and all
/// the casts disappear. A bare use, or two uses that disagree, blocks the
/// rewrite because the wide value is then observable.
fn narrow_declarations_to_used_width(statements: &mut Vec<NativeStatement>) -> bool {
    let mut candidates = BTreeMap::new();
    collect_wide_declarations(statements, &mut candidates);
    if candidates.is_empty() {
        return false;
    }
    // The traversal is bottom-up, so a temporary is visited both on its own and
    // again inside its parent cast. Counting instead of flagging keeps the
    // decision independent of visit order: every use must be a narrowing cast.
    let uses = RefCell::new(BTreeMap::<String, (usize, usize, Option<Type>)>::new());
    rewrite_statement_expressions(statements, |value: Expr| {
        walk_expr(value, &mut |value| {
            if let Expr::Cast { ty, value: inner } = &value
                && let Expr::Temporary { name, .. } = inner.as_ref()
                && candidates.contains_key(name)
                && matches!(ty, Type::Signed(bits) | Type::Unsigned(bits) if *bits < 64)
            {
                let mut uses = uses.borrow_mut();
                let entry = uses.entry(name.clone()).or_insert((0, 0, None));
                if entry.1 == 0 {
                    entry.2 = Some(ty.clone());
                } else if entry.2.as_ref() != Some(ty) {
                    entry.2 = None;
                }
                entry.1 += 1;
                return value;
            }
            if let Expr::Temporary { name, .. } = &value
                && candidates.contains_key(name)
            {
                let mut uses = uses.borrow_mut();
                uses.entry(name.clone()).or_insert((0, 0, None)).0 += 1;
            }
            value
        })
    });
    let chosen = uses
        .into_inner()
        .into_iter()
        .filter_map(|(name, (total, narrowed, ty))| {
            (total > 0 && total == narrowed)
                .then_some(ty)
                .flatten()
                .map(|ty| (name, ty))
        })
        .collect::<BTreeMap<_, _>>();
    if chosen.is_empty() {
        return false;
    }
    let mut changed = rewrite_statement_expressions(statements, |value: Expr| {
        walk_expr(value, &mut |value| match value {
            Expr::Cast { ty, value: inner }
                if matches!(inner.as_ref(), Expr::Temporary { name, .. }
                    if chosen.get(name) == Some(&ty)) =>
            {
                match *inner {
                    Expr::Temporary { name, .. } => Expr::Temporary {
                        name,
                        width: type_width(&ty),
                    },
                    inner => inner,
                }
            }
            value => value,
        })
    });
    changed |= retype_narrowed_declarations(statements, &chosen);
    changed
}

fn collect_wide_declarations(
    statements: &[NativeStatement],
    candidates: &mut BTreeMap<String, Type>,
) {
    for statement in statements {
        match statement {
            NativeStatement::Declare { name, ty, value } => {
                if matches!(ty, Type::Signed(64) | Type::Unsigned(64))
                    && matches!(value, Expr::Cast { ty: cast_ty, .. } if cast_ty == ty)
                {
                    candidates.insert(name.clone(), ty.clone());
                }
            }
            NativeStatement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                collect_wide_declarations(then_body, candidates);
                collect_wide_declarations(else_body, candidates);
            }
            NativeStatement::While { body, .. }
            | NativeStatement::DoWhile { body, .. }
            | NativeStatement::For { body, .. } => {
                collect_wide_declarations(body, candidates);
            }
            NativeStatement::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    collect_wide_declarations(body, candidates);
                }
                collect_wide_declarations(default, candidates);
            }
            _ => {}
        }
    }
}

fn retype_narrowed_declarations(
    statements: &mut [NativeStatement],
    chosen: &BTreeMap<String, Type>,
) -> bool {
    let mut changed = false;
    for statement in statements {
        match statement {
            NativeStatement::Declare { name, ty, value } => {
                if let Some(narrow) = chosen.get(name)
                    && ty != narrow
                {
                    *ty = narrow.clone();
                    if let Expr::Cast { value: inner, .. } = value {
                        *value = (**inner).clone();
                    }
                    changed = true;
                }
            }
            NativeStatement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                changed |= retype_narrowed_declarations(then_body, chosen);
                changed |= retype_narrowed_declarations(else_body, chosen);
            }
            NativeStatement::While { body, .. }
            | NativeStatement::DoWhile { body, .. }
            | NativeStatement::For { body, .. } => {
                changed |= retype_narrowed_declarations(body, chosen);
            }
            NativeStatement::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    changed |= retype_narrowed_declarations(body, chosen);
                }
                changed |= retype_narrowed_declarations(default, chosen);
            }
            _ => {}
        }
    }
    changed
}

/// Run the default action database over a native statement stream.
pub(super) fn run_action_database(statements: Vec<NativeStatement>) -> Vec<NativeStatement> {
    ActionDatabase::default().run(statements).statements
}

fn rewrite_statement_expressions<R: FnMut(Expr) -> Expr + Copy>(
    statements: &mut Vec<NativeStatement>,
    rewrite: R,
) -> bool {
    let mut changed = false;
    for statement in statements {
        changed |= rewrite_statement_expressions_in_place(statement, rewrite);
    }
    changed
}

fn rewrite_statement_expressions_in_place<R: FnMut(Expr) -> Expr + Copy>(
    statement: &mut NativeStatement,
    mut rewrite: R,
) -> bool {
    let before = statement.clone();
    match statement {
        NativeStatement::Store { address, value, .. } => {
            *address = rewrite(address.clone());
            *value = rewrite(value.clone());
        }
        NativeStatement::Copy {
            destination,
            source,
            ..
        }
        | NativeStatement::Assign {
            destination,
            source,
        } => {
            *destination = rewrite(destination.clone());
            *source = rewrite(source.clone());
        }
        NativeStatement::DeclareLocal { .. } => {}
        NativeStatement::Call(call)
        | NativeStatement::IndirectGoto(call)
        | NativeStatement::Expression(call) => {
            *call = rewrite(call.clone());
        }
        NativeStatement::Declare { value, .. } => {
            *value = rewrite(value.clone());
        }
        NativeStatement::IfGoto { condition, .. } => {
            *condition = rewrite(condition.clone());
        }
        NativeStatement::IfReturn { condition, value } => {
            *condition = rewrite(condition.clone());
            if let Some(value) = value {
                *value = rewrite(value.clone());
            }
        }
        NativeStatement::IfElse {
            condition,
            then_body,
            else_body,
        } => {
            *condition = rewrite(condition.clone());
            for nested in then_body {
                rewrite_statement_expressions_in_place(nested, rewrite);
            }
            for nested in else_body {
                rewrite_statement_expressions_in_place(nested, rewrite);
            }
        }
        NativeStatement::While { condition, body } => {
            *condition = rewrite(condition.clone());
            for nested in body {
                rewrite_statement_expressions_in_place(nested, rewrite);
            }
        }
        NativeStatement::DoWhile { body, condition } => {
            for nested in body {
                rewrite_statement_expressions_in_place(nested, rewrite);
            }
            *condition = rewrite(condition.clone());
        }
        NativeStatement::For {
            initializer,
            condition,
            step,
            body,
        } => {
            if let Some(initializer) = initializer {
                rewrite_statement_expressions_in_place(initializer, rewrite);
            }
            if let Some(condition) = condition {
                *condition = rewrite(condition.clone());
            }
            if let Some(step) = step {
                rewrite_statement_expressions_in_place(step, rewrite);
            }
            for nested in body {
                rewrite_statement_expressions_in_place(nested, rewrite);
            }
        }
        NativeStatement::Switch {
            expression,
            cases,
            default,
        } => {
            *expression = rewrite(expression.clone());
            for (_, body) in cases {
                for nested in body {
                    rewrite_statement_expressions_in_place(nested, rewrite);
                }
            }
            for nested in default {
                rewrite_statement_expressions_in_place(nested, rewrite);
            }
        }
        NativeStatement::Return(value) => {
            if let Some(value) = value {
                *value = rewrite(value.clone());
            }
        }
        NativeStatement::Label(_)
        | NativeStatement::Goto(_)
        | NativeStatement::Break
        | NativeStatement::Continue => {}
    }
    *statement != before
}

/// Walk an expression bottom-up, applying a local rewrite after all children
/// have been visited. This one traversal shape is shared by all expression
/// rules so nested calls/loads keep their original evaluation order.
fn walk_expr(value: Expr, rewrite: &mut impl FnMut(Expr) -> Expr) -> Expr {
    let value = match value {
        Expr::Binary { op, left, right } => Expr::Binary {
            op,
            left: Box::new(walk_expr(*left, rewrite)),
            right: Box::new(walk_expr(*right, rewrite)),
        },
        Expr::Not(inner) => Expr::Not(Box::new(walk_expr(*inner, rewrite))),
        Expr::Neg(inner) => Expr::Neg(Box::new(walk_expr(*inner, rewrite))),
        Expr::BitNot(inner) => Expr::BitNot(Box::new(walk_expr(*inner, rewrite))),
        Expr::Cast { ty, value } => Expr::Cast {
            ty,
            value: Box::new(walk_expr(*value, rewrite)),
        },
        Expr::Typed { ty, value } => Expr::Typed {
            ty,
            value: Box::new(walk_expr(*value, rewrite)),
        },
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => Expr::Select {
            condition: Box::new(walk_expr(*condition, rewrite)),
            when_true: Box::new(walk_expr(*when_true, rewrite)),
            when_false: Box::new(walk_expr(*when_false, rewrite)),
        },
        Expr::Load { address, width } => Expr::Load {
            address: Box::new(walk_expr(*address, rewrite)),
            width,
        },
        Expr::Call {
            target,
            callee,
            args,
        } => Expr::Call {
            target,
            callee: callee.map(|callee| Box::new(walk_expr(*callee, rewrite))),
            args: args
                .into_iter()
                .map(|arg| walk_expr(arg, rewrite))
                .collect(),
        },
        Expr::Builtin { name, args } => Expr::Builtin {
            name,
            args: args
                .into_iter()
                .map(|arg| walk_expr(arg, rewrite))
                .collect(),
        },
        value => value,
    };
    rewrite(value)
}

fn fold_expr(value: Expr) -> Expr {
    walk_expr(value, &mut fold_expr_local)
}

fn fold_expr_local(value: Expr) -> Expr {
    match value {
        Expr::Binary { op, left, right } => {
            if let Some(result) = fold_binary(op, left.as_ref(), right.as_ref()) {
                result
            } else {
                Expr::Binary { op, left, right }
            }
        }
        Expr::Not(inner) => match *inner {
            Expr::Constant { value, width } => Expr::Constant {
                value: u64::from(masked(value, width) == 0),
                width: 1,
            },
            inner => Expr::Not(Box::new(inner)),
        },
        Expr::Neg(inner) => match *inner {
            Expr::Constant { value, width } => Expr::Constant {
                value: 0u64.wrapping_sub(masked(value, width)) & width_mask(width),
                width,
            },
            inner => Expr::Neg(Box::new(inner)),
        },
        Expr::BitNot(inner) => match *inner {
            Expr::Constant { value, width } => Expr::Constant {
                value: !masked(value, width) & width_mask(width),
                width,
            },
            inner => Expr::BitNot(Box::new(inner)),
        },
        Expr::Cast { ty, value } => match *value {
            Expr::Constant { value, width } if !matches!(&ty, Type::Float(_)) => {
                fold_constant_cast(&ty, value, width)
            }
            value => Expr::Cast {
                ty,
                value: Box::new(value),
            },
        },
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => {
            if let Expr::Constant { value, width } = condition.as_ref() {
                if masked(*value, *width) != 0 {
                    *when_true
                } else {
                    *when_false
                }
            } else if when_true == when_false && is_pure_expr(condition.as_ref()) {
                *when_true
            } else {
                Expr::Select {
                    condition,
                    when_true,
                    when_false,
                }
            }
        }
        value => value,
    }
}

fn fold_binary(op: BinaryOp, left: &Expr, right: &Expr) -> Option<Expr> {
    let (left, left_width) = constant_parts(left)?;
    let (right, right_width) = constant_parts(right)?;
    let width = left_width.max(right_width);
    let left_value = masked(left, left_width);
    let right_value = masked(right, right_width);
    let result = match op {
        BinaryOp::Add => left_value.wrapping_add(right_value),
        BinaryOp::Sub => left_value.wrapping_sub(right_value),
        BinaryOp::Mul => left_value.wrapping_mul(right_value),
        BinaryOp::Div => {
            if right_value == 0 {
                return None;
            }
            left_value / right_value
        }
        BinaryOp::Rem => {
            if right_value == 0 {
                return None;
            }
            left_value % right_value
        }
        BinaryOp::SignedDiv => {
            let left_value = signed_value(left_value, left_width);
            let right_value = signed_value(right_value, right_width);
            if right_value == 0 || (left_value == i64::MIN && right_value == -1) {
                return None;
            }
            (left_value / right_value) as u64
        }
        BinaryOp::SignedRem => {
            let left_value = signed_value(left_value, left_width);
            let right_value = signed_value(right_value, right_width);
            if right_value == 0 {
                return None;
            }
            if left_value == i64::MIN && right_value == -1 {
                0
            } else {
                (left_value % right_value) as u64
            }
        }
        BinaryOp::And => left_value & right_value,
        BinaryOp::Or => left_value | right_value,
        BinaryOp::Xor => left_value ^ right_value,
        BinaryOp::LogicalAnd => u64::from(left_value != 0 && right_value != 0),
        BinaryOp::LogicalOr => u64::from(left_value != 0 || right_value != 0),
        BinaryOp::Equal => u64::from(left_value == right_value),
        BinaryOp::NotEqual => u64::from(left_value != right_value),
        BinaryOp::Less => u64::from(left_value < right_value),
        BinaryOp::LessEqual => u64::from(left_value <= right_value),
        BinaryOp::SignedLess => {
            u64::from(signed_value(left_value, left_width) < signed_value(right_value, right_width))
        }
        BinaryOp::SignedLessEqual => u64::from(
            signed_value(left_value, left_width) <= signed_value(right_value, right_width),
        ),
        BinaryOp::Left => {
            let shift = right_value;
            if shift >= 64 {
                return None;
            }
            left_value.wrapping_shl(shift as u32)
        }
        BinaryOp::Right => {
            let shift = right_value;
            if shift >= 64 {
                return None;
            }
            left_value.wrapping_shr(shift as u32)
        }
        BinaryOp::SignedRight => {
            let shift = right_value;
            if shift >= 64 {
                return None;
            }
            (signed_value(left_value, left_width) >> (shift as u32)) as u64
        }
    };
    let result_width = if matches!(
        op,
        BinaryOp::Equal
            | BinaryOp::NotEqual
            | BinaryOp::Less
            | BinaryOp::LessEqual
            | BinaryOp::SignedLess
            | BinaryOp::SignedLessEqual
            | BinaryOp::LogicalAnd
            | BinaryOp::LogicalOr
    ) {
        1
    } else {
        width
    };
    Some(Expr::Constant {
        value: result & width_mask(result_width),
        width: result_width,
    })
}

fn simplify_algebraic_expr(value: Expr) -> Expr {
    walk_expr(value, &mut simplify_algebraic_expr_local)
}

fn simplify_algebraic_expr_local(value: Expr) -> Expr {
    let Expr::Binary { op, left, right } = value else {
        return value;
    };
    let left_width = expression_width(left.as_ref());
    let right_width = expression_width(right.as_ref());
    let width = left_width.max(right_width);
    let same_width = left_width == right_width;
    let zero = || Expr::Constant { value: 0, width };
    let boolean = |value| Expr::Constant { value, width: 1 };

    if left == right && is_pure_expr(left.as_ref()) {
        return match op {
            BinaryOp::And | BinaryOp::Or => *left,
            BinaryOp::Sub | BinaryOp::Xor => zero(),
            BinaryOp::Equal | BinaryOp::LessEqual | BinaryOp::SignedLessEqual => boolean(1),
            BinaryOp::NotEqual | BinaryOp::Less | BinaryOp::SignedLess => boolean(0),
            _ => Expr::Binary { op, left, right },
        };
    }

    // Shift amounts are unrelated to the shifted value's width, so these two
    // rules must not wait for matching operand widths. PowerPC rotate-and-mask
    // instructions lift to `x << 0 | x >> 32`, which is just `x`.
    if matches!(op, BinaryOp::Left | BinaryOp::Right | BinaryOp::SignedRight)
        && is_zero_constant(right.as_ref())
    {
        return *left;
    }
    if matches!(op, BinaryOp::Left | BinaryOp::Right)
        && is_pure_expr(left.as_ref())
        && let Some((shift, _)) = constant_parts(right.as_ref())
        && left_width > 0
        && shift >= u64::from(left_width).saturating_mul(8)
    {
        return Expr::Constant {
            value: 0,
            width: left_width,
        };
    }

    // Truncation commutes with addition: `(uint32_t)x + c` and
    // `(uint32_t)(x + c)` are the same value modulo 2^32. Sinking the constant
    // lets the offset chain below fold, which is what turns
    // `(uint32_t)(sp - 0x40) + 0x40` back into `sp`.
    if matches!(op, BinaryOp::Add | BinaryOp::Sub)
        && let Some((_, outer_width)) = constant_parts(right.as_ref())
        && let Expr::Cast {
            ty: cast_ty,
            value: inner,
        } = left.as_ref()
        && matches!(cast_ty, Type::Unsigned(_))
        && type_width(cast_ty) == outer_width
        && type_width(cast_ty) <= expression_width(inner)
        && matches!(
            inner.as_ref(),
            Expr::Binary {
                op: BinaryOp::Add | BinaryOp::Sub,
                ..
            }
        )
    {
        return Expr::Cast {
            ty: cast_ty.clone(),
            value: Box::new(Expr::Binary {
                op,
                left: inner.clone(),
                right,
            }),
        };
    }

    // `x + c1 + c2` is one addition. PowerPC address arithmetic produces long
    // chains of these, and leaving them unfolded hides that an offset is zero.
    if matches!(op, BinaryOp::Add | BinaryOp::Sub)
        && let Some((outer, outer_width)) = constant_parts(right.as_ref())
        && let Expr::Binary {
            op: inner_op @ (BinaryOp::Add | BinaryOp::Sub),
            left: base,
            right: inner,
        } = left.as_ref()
        && let Some((inner_value, inner_width)) = constant_parts(inner.as_ref())
        && inner_width == outer_width
    {
        let signed = |value: u64, subtract: bool| {
            if subtract {
                0_u64.wrapping_sub(value)
            } else {
                value
            }
        };
        let total = masked(
            signed(inner_value, *inner_op == BinaryOp::Sub)
                .wrapping_add(signed(outer, op == BinaryOp::Sub)),
            outer_width,
        );
        if total == 0 {
            return base.as_ref().clone();
        }
        return Expr::Binary {
            op: BinaryOp::Add,
            left: base.clone(),
            right: Box::new(Expr::Constant {
                value: total,
                width: outer_width,
            }),
        };
    }

    // A rotate-and-mask keeps only one of its two halves. Dropping the half the
    // mask erases turns `x << 27 | x >> 5 & 0x7ffffff` back into a shift.
    if op == BinaryOp::And
        && let Some((mask, _)) = constant_parts(right.as_ref())
        && let Expr::Binary {
            op: BinaryOp::Or,
            left: or_left,
            right: or_right,
        } = left.as_ref()
    {
        let keep = |value: &Expr| Expr::Binary {
            op: BinaryOp::And,
            left: Box::new(value.clone()),
            right: right.clone(),
        };
        if mask_erases(or_left.as_ref(), mask) && is_pure_expr(or_left.as_ref()) {
            return keep(or_right.as_ref());
        }
        if mask_erases(or_right.as_ref(), mask) && is_pure_expr(or_right.as_ref()) {
            return keep(or_left.as_ref());
        }
    }

    if same_width && is_zero_constant(right.as_ref()) {
        return match op {
            BinaryOp::Add
            | BinaryOp::Sub
            | BinaryOp::Or
            | BinaryOp::Xor
            | BinaryOp::Left
            | BinaryOp::Right
            | BinaryOp::SignedRight => *left,
            BinaryOp::Mul | BinaryOp::And if is_pure_expr(left.as_ref()) => zero(),
            _ => Expr::Binary { op, left, right },
        };
    }
    if op == BinaryOp::And
        && is_one_constant(right.as_ref())
        && let Some(bit) = extract_condition_bit(left.as_ref(), 0)
    {
        return bit;
    }
    if same_width && is_one_constant(right.as_ref()) {
        return match op {
            BinaryOp::Mul | BinaryOp::Div | BinaryOp::SignedDiv => *left,
            _ => Expr::Binary { op, left, right },
        };
    }
    if same_width && is_all_ones_constant(right.as_ref(), width) {
        return match op {
            BinaryOp::And => *left,
            BinaryOp::Or if is_pure_expr(left.as_ref()) => *right,
            _ => Expr::Binary { op, left, right },
        };
    }
    if same_width && is_zero_constant(left.as_ref()) {
        return match op {
            BinaryOp::Add | BinaryOp::Or | BinaryOp::Xor => *right,
            BinaryOp::Mul | BinaryOp::And if is_pure_expr(right.as_ref()) => zero(),
            _ => Expr::Binary { op, left, right },
        };
    }
    if same_width && is_one_constant(left.as_ref()) && op == BinaryOp::Mul {
        return *right;
    }
    if same_width && is_all_ones_constant(left.as_ref(), width) {
        return match op {
            BinaryOp::And => *right,
            BinaryOp::Or if is_pure_expr(right.as_ref()) => *left,
            _ => Expr::Binary { op, left, right },
        };
    }

    Expr::Binary { op, left, right }
}

/// True when every bit `value` could set falls outside `mask`.
///
/// Only shapes with a provable zero pattern qualify; anything else is treated
/// as possibly-set so the mask is preserved.
fn mask_erases(value: &Expr, mask: u64) -> bool {
    if mask == 0 {
        return true;
    }
    match value {
        Expr::Constant { value, width } => masked(*value, *width) & mask == 0,
        Expr::Binary {
            op: BinaryOp::Left,
            left: _,
            right,
        } => constant_parts(right)
            .and_then(|(shift, _)| u32::try_from(shift).ok())
            .is_some_and(|shift| shift >= 64 || mask >> shift == 0),
        Expr::Binary {
            op: BinaryOp::And,
            left,
            right,
        } => {
            constant_parts(right)
                .is_some_and(|(inner, inner_width)| masked(inner, inner_width) & mask == 0)
                || mask_erases(left, mask)
        }
        value if is_boolean_expr(value) => mask & 1 == 0,
        _ => false,
    }
}

/// Recovers the expression for one bit of a packed flag word.
///
/// PowerPC writes a comparison into a condition-register field as
/// `(a < b) << 3 | (b < a) << 2 | (a == b) << 1 | summary_overflow`, and a
/// conditional branch then extracts a single bit. Without this reduction the
/// whole packed word survives into the branch condition, structuring cannot
/// recognize the comparison, and every loop degenerates into `goto`.
///
/// Returns `None` unless the bit is derivable, so an unknown flag word is left
/// alone rather than guessed.
fn extract_condition_bit(value: &Expr, bit: u32) -> Option<Expr> {
    if bit >= 64 {
        return None;
    }
    let clear = || Expr::Constant { value: 0, width: 1 };
    // Bits past a value's own width are zero, and a boolean occupies only bit
    // zero of its byte. Both facts keep a packed field from blocking recovery.
    if u64::from(bit) >= u64::from(expression_width(value)).saturating_mul(8)
        || (bit > 0 && is_boolean_expr(value))
    {
        return Some(clear());
    }
    match value {
        Expr::Constant { value, width } => Some(Expr::Constant {
            value: (masked(*value, *width) >> bit) & 1,
            width: 1,
        }),
        Expr::Binary {
            op: BinaryOp::Left,
            left,
            right,
        } => {
            let shift = u32::try_from(constant_parts(right)?.0).ok()?;
            if bit < shift {
                Some(clear())
            } else {
                extract_condition_bit(left, bit - shift)
            }
        }
        Expr::Binary {
            op: BinaryOp::Right,
            left,
            right,
        } => {
            let shift = u32::try_from(constant_parts(right)?.0).ok()?;
            extract_condition_bit(left, bit.checked_add(shift)?)
        }
        Expr::Binary {
            op: op @ (BinaryOp::Or | BinaryOp::And | BinaryOp::Xor),
            left,
            right,
        } => {
            if *op == BinaryOp::And
                && let Some((mask, mask_width)) = constant_parts(right)
            {
                return if (masked(mask, mask_width) >> bit) & 1 == 0 {
                    Some(clear())
                } else {
                    extract_condition_bit(left, bit)
                };
            }
            let left = extract_condition_bit(left, bit)?;
            let right = extract_condition_bit(right, bit)?;
            match op {
                BinaryOp::Or if is_zero_constant(&left) => Some(right),
                BinaryOp::Or if is_zero_constant(&right) => Some(left),
                BinaryOp::And if is_zero_constant(&left) || is_zero_constant(&right) => {
                    Some(clear())
                }
                BinaryOp::Xor if is_zero_constant(&left) => Some(right),
                BinaryOp::Xor if is_zero_constant(&right) => Some(left),
                op => Some(Expr::Binary {
                    op: *op,
                    left: Box::new(left),
                    right: Box::new(right),
                }),
            }
        }
        value if bit == 0 && is_boolean_expr(value) => Some(value.clone()),
        _ => None,
    }
}

fn is_zero_constant(value: &Expr) -> bool {
    matches!(value, Expr::Constant { value: 0, .. })
}

fn is_one_constant(value: &Expr) -> bool {
    matches!(value, Expr::Constant { value: 1, .. })
}

fn is_all_ones_constant(value: &Expr, width: u32) -> bool {
    matches!(
        value,
        Expr::Constant {
            value,
            width: constant_width,
        } if *constant_width == width && masked(*value, *constant_width) == width_mask(width)
    )
}

fn constant_parts(value: &Expr) -> Option<(u64, u32)> {
    match value {
        Expr::Constant { value, width } => Some((*value, *width)),
        _ => None,
    }
}

fn width_mask(width: u32) -> u64 {
    let bits = width.saturating_mul(8);
    if bits == 0 {
        0
    } else if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn masked(value: u64, width: u32) -> u64 {
    value & width_mask(width)
}

fn signed_value(value: u64, width: u32) -> i64 {
    let bits = width.saturating_mul(8).min(64);
    let value = masked(value, width);
    if bits == 0 {
        0
    } else if bits == 64 {
        value as i64
    } else {
        ((value << (64 - bits)) as i64) >> (64 - bits)
    }
}

/// Folds a cast of a constant, honouring the cast's declared width.
///
/// The result adopts the target type's width, sign-extending for signed targets
/// and truncating for narrower ones. Keeping the operand's width instead would
/// let a 16-bit immediate masquerade as a 16-bit value after a widening cast.
pub(super) fn fold_constant_cast(ty: &Type, value: u64, width: u32) -> Expr {
    let result_width = type_width(ty);
    let result = match ty {
        Type::Bool => u64::from(masked(value, width) != 0),
        Type::Signed(_) => (signed_value(value, width) as u64) & width_mask(result_width),
        _ => masked(value, width) & width_mask(result_width),
    };
    Expr::Constant {
        value: result,
        width: result_width,
    }
}

pub(super) fn type_width(ty: &Type) -> u32 {
    match ty {
        Type::Bool => 1,
        Type::Unsigned(bits) | Type::Signed(bits) | Type::Float(bits) => {
            bits.saturating_add(7).saturating_div(8).clamp(1, 8)
        }
        Type::Pointer(_) | Type::Unknown => 8,
        Type::Void => 0,
    }
}

pub(super) fn expression_width(value: &Expr) -> u32 {
    match value {
        Expr::Constant { width, .. }
        | Expr::Register { width, .. }
        | Expr::Temporary { width, .. }
        | Expr::Global { width, .. }
        | Expr::Load { width, .. }
        | Expr::Field { width, .. } => *width,
        Expr::Parameter { ty, .. } | Expr::Cast { ty, .. } | Expr::Typed { ty, .. } => {
            type_width(ty)
        }
        // A comma expression is as wide as its value, the last element; an
        // assignment is as wide as what it assigns to.
        Expr::Comma(members) => members.last().map(expression_width).unwrap_or(0),
        Expr::Assign { destination, .. } => expression_width(destination),
        Expr::Binary { op, left, right } => {
            if matches!(
                op,
                BinaryOp::Equal
                    | BinaryOp::NotEqual
                    | BinaryOp::Less
                    | BinaryOp::LessEqual
                    | BinaryOp::SignedLess
                    | BinaryOp::SignedLessEqual
                    | BinaryOp::LogicalAnd
                    | BinaryOp::LogicalOr
            ) {
                1
            } else {
                expression_width(left).max(expression_width(right))
            }
        }
        Expr::Not(_) => 1,
        Expr::Neg(inner) | Expr::BitNot(inner) => expression_width(inner),
        Expr::Select {
            when_true,
            when_false,
            ..
        } => expression_width(when_true).max(expression_width(when_false)),
        Expr::Call { .. } | Expr::Builtin { .. } => 8,
    }
}

/// The type a value already carries, when it is unambiguous.
fn natural_type(value: &Expr) -> Option<Type> {
    match value {
        Expr::Load { width, .. }
        | Expr::Global { width, .. }
        | Expr::Register { width, .. }
        | Expr::Temporary { width, .. } => Some(Type::Unsigned(width.saturating_mul(8))),
        Expr::Parameter { ty, .. } | Expr::Typed { ty, .. } | Expr::Cast { ty, .. } => {
            Some(ty.clone())
        }
        _ => None,
    }
}

fn is_pure_expr(value: &Expr) -> bool {
    match value {
        Expr::Constant { .. }
        | Expr::Parameter { .. }
        | Expr::Register { .. }
        | Expr::Temporary { .. }
        | Expr::Global { .. } => true,
        // A field read is a memory read, so it is no purer than a load.
        Expr::Field { .. } => false,
        // An assignment is the definition of impure, and a comma expression
        // exists to carry one.
        Expr::Assign { .. } | Expr::Comma(_) => false,
        Expr::Binary { left, right, .. } => is_pure_expr(left) && is_pure_expr(right),
        Expr::Not(inner)
        | Expr::Neg(inner)
        | Expr::BitNot(inner)
        | Expr::Cast { value: inner, .. }
        | Expr::Typed { value: inner, .. } => is_pure_expr(inner),
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => is_pure_expr(condition) && is_pure_expr(when_true) && is_pure_expr(when_false),
        // Loads, calls, and builtins are conservatively effectful. This keeps
        // a cleanup rule from deleting an observable operation merely because
        // the current native IR lacks a finer-grained memory-effect lattice.
        Expr::Load { .. } | Expr::Call { .. } | Expr::Builtin { .. } => false,
    }
}

fn is_integer_type(ty: &Type) -> bool {
    matches!(ty, Type::Unsigned(_) | Type::Signed(_))
}

/// True when `Cast{outer, Cast{inner, value}}` can drop the inner cast.
///
/// Widening an integer and immediately narrowing it back to the value's own
/// width preserves every live bit, so the inner cast carries no meaning. Float
/// and boolean conversions are excluded because they change the value, not just
/// its declared width.
fn is_value_preserving_widening(outer: &Type, inner: &Type, value: &Expr) -> bool {
    is_integer_type(outer)
        && is_integer_type(inner)
        && type_width(inner) > type_width(outer)
        && type_width(outer) == expression_width(value)
}

fn copy_cast_cleanup_expr(value: Expr) -> Expr {
    walk_expr(value, &mut copy_cast_cleanup_expr_local)
}

fn copy_cast_cleanup_expr_local(value: Expr) -> Expr {
    match value {
        // A cast to the type a value already carries says nothing. Keeping it
        // triples the cast count of an ordinary field read.
        Expr::Cast { ref ty, ref value } if natural_type(value).as_ref() == Some(ty) => {
            (**value).clone()
        }
        Expr::Cast { ty, value } => match *value {
            Expr::Cast {
                ty: inner_ty,
                value: inner_value,
            } if ty == inner_ty => Expr::Cast {
                ty,
                value: inner_value,
            },
            // A widen-then-narrow pair is the identity when the narrow type is
            // already the value's own width: nothing is truncated. The R5900
            // makes these pervasive because 32-bit arithmetic is defined to
            // sign-extend through 64-bit registers.
            Expr::Cast {
                ty: inner_ty,
                value: inner_value,
            } if is_value_preserving_widening(&ty, &inner_ty, &inner_value) => Expr::Cast {
                ty,
                value: inner_value,
            },
            Expr::Typed {
                ty: inner_ty,
                value: inner_value,
            } if ty == inner_ty => Expr::Typed {
                ty,
                value: inner_value,
            },
            Expr::Parameter {
                name,
                ty: parameter_ty,
            } if ty == parameter_ty => Expr::Parameter {
                name,
                ty: parameter_ty,
            },
            value => Expr::Cast {
                ty,
                value: Box::new(value),
            },
        },
        Expr::Typed { ty, value } => match *value {
            Expr::Typed {
                ty: inner_ty,
                value: inner_value,
            } if ty == inner_ty => Expr::Typed {
                ty,
                value: inner_value,
            },
            value => Expr::Typed {
                ty,
                value: Box::new(value),
            },
        },
        value => value,
    }
}

fn apply_copy_cast_cleanup(statements: &mut Vec<NativeStatement>) -> bool {
    let mut changed = rewrite_statement_expressions(statements, copy_cast_cleanup_expr);
    let mut rewritten = Vec::with_capacity(statements.len());
    for statement in statements.drain(..) {
        match statement {
            NativeStatement::Copy {
                destination:
                    Expr::Temporary {
                        name: destination_name,
                        width: destination_width,
                    },
                source:
                    Expr::Temporary {
                        name: source_name,
                        width: source_width,
                    },
                volatile: false,
                ..
            } if destination_name == source_name && destination_width == source_width => {
                changed = true;
            }
            statement => rewritten.push(statement),
        }
    }
    *statements = rewritten;
    changed
}

fn normalize_boolean_expr(value: Expr) -> Expr {
    walk_expr(value, &mut normalize_boolean_expr_local)
}

fn normalize_boolean_expr_local(value: Expr) -> Expr {
    match value {
        Expr::Not(inner) => match *inner {
            Expr::Binary { op, left, right } => match op {
                BinaryOp::Equal => Expr::Binary {
                    op: BinaryOp::NotEqual,
                    left,
                    right,
                },
                BinaryOp::NotEqual => Expr::Binary {
                    op: BinaryOp::Equal,
                    left,
                    right,
                },
                op => Expr::Not(Box::new(Expr::Binary { op, left, right })),
            },
            Expr::Not(inner) => boolize_expr(*inner),
            Expr::Constant { value, width } => Expr::Constant {
                value: u64::from(masked(value, width) == 0),
                width: 1,
            },
            inner => Expr::Not(Box::new(inner)),
        },
        Expr::Select {
            condition,
            when_true,
            when_false,
        } if is_zero_or_one_constant(when_true.as_ref())
            && is_zero_or_one_constant(when_false.as_ref())
            && is_pure_expr(condition.as_ref())
            && is_opposite_boolean_constants(when_true.as_ref(), when_false.as_ref()) =>
        {
            boolize_expr(*condition)
        }
        value => value,
    }
}

fn boolize_expr(value: Expr) -> Expr {
    if is_boolean_expr(&value) {
        return value;
    }
    if let Expr::Constant { value, width } = value {
        return Expr::Constant {
            value: u64::from(masked(value, width) != 0),
            width: 1,
        };
    }
    let width = expression_width(&value).max(1);
    Expr::Binary {
        op: BinaryOp::NotEqual,
        left: Box::new(value),
        right: Box::new(Expr::Constant { value: 0, width }),
    }
}

fn is_boolean_expr(value: &Expr) -> bool {
    match value {
        Expr::Constant { value, width } => *width == 1 && *value <= 1,
        Expr::Not(_) => true,
        Expr::Cast { ty: Type::Bool, .. } | Expr::Typed { ty: Type::Bool, .. } => true,
        Expr::Binary { op, .. } => matches!(
            op,
            BinaryOp::Equal
                | BinaryOp::NotEqual
                | BinaryOp::Less
                | BinaryOp::LessEqual
                | BinaryOp::SignedLess
                | BinaryOp::SignedLessEqual
                | BinaryOp::LogicalAnd
                | BinaryOp::LogicalOr
        ),
        Expr::Select {
            when_true,
            when_false,
            ..
        } => is_zero_or_one_constant(when_true) && is_zero_or_one_constant(when_false),
        _ => false,
    }
}

fn is_zero_or_one_constant(value: &Expr) -> bool {
    matches!(value, Expr::Constant { value: 0..=1, .. })
}

fn is_opposite_boolean_constants(left: &Expr, right: &Expr) -> bool {
    match (left, right) {
        (Expr::Constant { value: left, .. }, Expr::Constant { value: right, .. }) => {
            (*left == 0 && *right == 1) || (*left == 1 && *right == 0)
        }
        _ => false,
    }
}

fn canonicalize_commutative_expr(value: Expr) -> Expr {
    walk_expr(value, &mut canonicalize_commutative_expr_local)
}

fn canonicalize_commutative_expr_local(value: Expr) -> Expr {
    let Expr::Binary { op, left, right } = value else {
        return value;
    };
    if !is_commutative(op) || !is_pure_expr(left.as_ref()) || !is_pure_expr(right.as_ref()) {
        return Expr::Binary { op, left, right };
    }
    if matches!(left.as_ref(), Expr::Constant { .. })
        && !matches!(right.as_ref(), Expr::Constant { .. })
    {
        Expr::Binary {
            op,
            left: right,
            right: left,
        }
    } else {
        Expr::Binary { op, left, right }
    }
}

fn is_commutative(op: BinaryOp) -> bool {
    matches!(
        op,
        BinaryOp::Add
            | BinaryOp::Mul
            | BinaryOp::And
            | BinaryOp::Or
            | BinaryOp::Xor
            | BinaryOp::LogicalAnd
            | BinaryOp::LogicalOr
            | BinaryOp::Equal
            | BinaryOp::NotEqual
    )
}

fn simplify_branch_conditions(statements: &mut Vec<NativeStatement>) -> bool {
    let mut output = Vec::with_capacity(statements.len());
    let mut changed = false;
    for statement in statements.drain(..) {
        match statement {
            NativeStatement::IfGoto { condition, target } => {
                let original_condition = condition.clone();
                let condition = normalize_boolean_expr(fold_expr(condition));
                changed |= condition != original_condition;
                if let Some(taken) = constant_truth(&condition) {
                    changed = true;
                    if taken {
                        output.push(NativeStatement::Goto(target));
                    }
                } else {
                    output.push(NativeStatement::IfGoto { condition, target });
                }
            }
            NativeStatement::IfReturn { condition, value } => {
                let original_condition = condition.clone();
                let condition = normalize_boolean_expr(fold_expr(condition));
                changed |= condition != original_condition;
                if let Some(taken) = constant_truth(&condition) {
                    changed = true;
                    if taken {
                        output.push(NativeStatement::Return(value));
                    }
                } else {
                    output.push(NativeStatement::IfReturn { condition, value });
                }
            }
            NativeStatement::IfElse {
                condition,
                mut then_body,
                mut else_body,
            } => {
                changed |= simplify_branch_conditions(&mut then_body);
                changed |= simplify_branch_conditions(&mut else_body);
                let original_condition = condition.clone();
                let condition = normalize_boolean_expr(fold_expr(condition));
                changed |= condition != original_condition;
                if let Some(taken) = constant_truth(&condition) {
                    changed = true;
                    if taken {
                        output.extend(then_body);
                    } else {
                        output.extend(else_body);
                    }
                } else if then_body.is_empty() && else_body.is_empty() {
                    changed = true;
                    if expr_has_effect(&condition) {
                        output.push(NativeStatement::Expression(condition));
                    }
                } else {
                    output.push(NativeStatement::IfElse {
                        condition,
                        then_body,
                        else_body,
                    });
                }
            }
            NativeStatement::While {
                condition,
                mut body,
            } => {
                changed |= simplify_branch_conditions(&mut body);
                let original_condition = condition.clone();
                let condition = normalize_boolean_expr(fold_expr(condition));
                changed |= condition != original_condition;
                if matches!(constant_truth(&condition), Some(false)) {
                    // A constant false condition has no evaluation effect and
                    // cannot enter the body, so removing the loop is safe.
                    changed = true;
                } else {
                    output.push(NativeStatement::While { condition, body });
                }
            }
            NativeStatement::DoWhile {
                mut body,
                condition,
            } => {
                changed |= simplify_branch_conditions(&mut body);
                let original_condition = condition.clone();
                let condition = normalize_boolean_expr(fold_expr(condition));
                changed |= condition != original_condition;
                output.push(NativeStatement::DoWhile { body, condition });
            }
            NativeStatement::For {
                mut initializer,
                condition,
                mut step,
                mut body,
            } => {
                // Initializer and step are single statements in the IR. Keep
                // them in place if a nested rewrite would expand to multiple
                // statements; only commit a one-for-one rewrite.
                changed |= simplify_single_nested_statement(&mut initializer);
                changed |= simplify_single_nested_statement(&mut step);
                changed |= simplify_branch_conditions(&mut body);
                let original_condition = condition.clone();
                let condition =
                    condition.map(|condition| normalize_boolean_expr(fold_expr(condition)));
                changed |= condition != original_condition;
                output.push(NativeStatement::For {
                    initializer,
                    condition,
                    step,
                    body,
                });
            }
            NativeStatement::Switch {
                expression,
                mut cases,
                mut default,
            } => {
                let original_expression = expression.clone();
                let expression = normalize_boolean_expr(fold_expr(expression));
                changed |= expression != original_expression;
                for (_, body) in &mut cases {
                    changed |= simplify_branch_conditions(body);
                }
                changed |= simplify_branch_conditions(&mut default);
                output.push(NativeStatement::Switch {
                    expression,
                    cases,
                    default,
                });
            }
            statement => output.push(statement),
        }
    }
    *statements = output;
    changed
}

fn simplify_single_nested_statement(statement: &mut Option<Box<NativeStatement>>) -> bool {
    let Some(original) = statement.as_ref() else {
        return false;
    };
    let mut one = vec![(**original).clone()];
    let changed = simplify_branch_conditions(&mut one);
    if one.len() == 1 {
        *statement = one.pop().map(Box::new);
        changed
    } else {
        false
    }
}

fn constant_truth(value: &Expr) -> Option<bool> {
    match value {
        Expr::Constant { value, width } => Some(masked(*value, *width) != 0),
        _ => None,
    }
}

fn expr_has_effect(value: &Expr) -> bool {
    !is_pure_expr(value)
}

fn eliminate_dead_temporary_assignments(statements: &mut Vec<NativeStatement>) -> bool {
    // A backwards edge can make a lexically earlier use execute after an
    // assignment. Only straight-line blocks get the precise liveness pass;
    // nested blocks are visited independently with all enclosing uses marked
    // live, which is conservative across branch/loop boundaries.
    let protected = statement_list_temporary_uses(statements);
    let mut changed = false;
    for statement in statements.iter_mut() {
        changed |= eliminate_nested_temporary_assignments(statement, &protected);
    }
    if !contains_control_flow(statements) {
        changed |= eliminate_linear_temporary_assignments(statements, &BTreeSet::new());
    }
    changed
}

fn eliminate_nested_temporary_assignments(
    statement: &mut NativeStatement,
    protected: &BTreeSet<String>,
) -> bool {
    match statement {
        NativeStatement::Declare { name, value, .. }
            if !protected.contains(name) && expr_has_effect(value) =>
        {
            let value = value.clone();
            *statement = match value {
                Expr::Call { .. } => NativeStatement::Call(value),
                _ => NativeStatement::Expression(value),
            };
            true
        }
        NativeStatement::IfElse {
            then_body,
            else_body,
            ..
        } => {
            eliminate_nested_temporary_block(then_body, protected)
                | eliminate_nested_temporary_block(else_body, protected)
        }
        NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
            eliminate_nested_temporary_block(body, protected)
        }
        NativeStatement::For {
            initializer,
            step,
            body,
            ..
        } => {
            let mut changed = eliminate_nested_temporary_block(body, protected);
            if let Some(initializer) = initializer {
                changed |= eliminate_nested_temporary_assignments(initializer, protected);
            }
            if let Some(step) = step {
                changed |= eliminate_nested_temporary_assignments(step, protected);
            }
            changed
        }
        NativeStatement::Switch { cases, default, .. } => {
            let mut changed = false;
            for (_, body) in cases {
                changed |= eliminate_nested_temporary_block(body, protected);
            }
            changed | eliminate_nested_temporary_block(default, protected)
        }
        _ => false,
    }
}

fn eliminate_nested_temporary_block(
    statements: &mut Vec<NativeStatement>,
    protected: &BTreeSet<String>,
) -> bool {
    let mut changed = false;
    if !contains_control_flow(statements) {
        changed |= eliminate_linear_temporary_assignments(statements, protected);
    }
    for statement in statements.iter_mut() {
        changed |= eliminate_nested_temporary_assignments(statement, protected);
    }
    changed
}

fn eliminate_linear_temporary_assignments(
    statements: &mut Vec<NativeStatement>,
    protected: &BTreeSet<String>,
) -> bool {
    let mut live = protected.clone();
    let mut replacements: Vec<Option<NativeStatement>> = vec![None; statements.len()];
    let mut changed = false;

    for (index, statement) in statements.iter().enumerate().rev() {
        let uses = statement_temporary_uses(statement);
        let definition = direct_temporary_definition(statement);
        let dead = definition.as_ref().is_some_and(|name| !live.contains(name));

        if dead {
            match statement {
                NativeStatement::Copy { source, .. } if expr_has_effect(source) => {
                    replacements[index] = Some(NativeStatement::Expression(source.clone()));
                }
                NativeStatement::Declare { value, .. } if expr_has_effect(value) => {
                    replacements[index] = Some(match value {
                        Expr::Call { .. } => NativeStatement::Call(value.clone()),
                        _ => NativeStatement::Expression(value.clone()),
                    });
                }
                _ => {}
            }
            changed = true;
        } else {
            replacements[index] = Some(statement.clone());
        }

        if let Some(name) = definition {
            live.remove(&name);
        }
        live.extend(uses);
    }

    let mut output = Vec::with_capacity(statements.len());
    for replacement in replacements {
        if let Some(statement) = replacement {
            output.push(statement);
        }
    }
    *statements = output;
    changed
}

fn statement_list_temporary_uses(statements: &[NativeStatement]) -> BTreeSet<String> {
    let mut uses = BTreeSet::new();
    for statement in statements {
        uses.extend(statement_temporary_uses(statement));
    }
    uses
}

fn contains_control_flow(statements: &[NativeStatement]) -> bool {
    statements.iter().any(|statement| match statement {
        NativeStatement::Label(_)
        | NativeStatement::Goto(_)
        | NativeStatement::IfGoto { .. }
        | NativeStatement::IfReturn { .. }
        | NativeStatement::IfElse { .. }
        | NativeStatement::While { .. }
        | NativeStatement::DoWhile { .. }
        | NativeStatement::For { .. }
        | NativeStatement::Switch { .. }
        | NativeStatement::IndirectGoto(_)
        | NativeStatement::Break
        | NativeStatement::Continue => true,
        NativeStatement::Store { .. }
        | NativeStatement::Copy { .. }
        | NativeStatement::Assign { .. }
        | NativeStatement::DeclareLocal { .. }
        | NativeStatement::Call(_)
        | NativeStatement::Declare { .. }
        | NativeStatement::Return(_)
        | NativeStatement::Expression(_) => false,
    })
}

fn direct_temporary_definition(statement: &NativeStatement) -> Option<String> {
    match statement {
        NativeStatement::Copy {
            destination: Expr::Temporary { name, .. },
            volatile: false,
            ..
        }
        | NativeStatement::Declare { name, .. } => Some(name.clone()),
        _ => None,
    }
}

pub(super) fn statement_temporary_uses(statement: &NativeStatement) -> BTreeSet<String> {
    let mut uses = BTreeSet::new();
    match statement {
        NativeStatement::Store { address, value, .. } => {
            collect_temporary_uses(address, &mut uses);
            collect_temporary_uses(value, &mut uses);
        }
        NativeStatement::Copy {
            destination,
            source,
            ..
        }
        | NativeStatement::Assign {
            destination,
            source,
        } => {
            if !matches!(destination, Expr::Temporary { .. }) {
                collect_temporary_uses(destination, &mut uses);
            }
            collect_temporary_uses(source, &mut uses);
        }
        NativeStatement::DeclareLocal { .. } => {}
        NativeStatement::Call(call)
        | NativeStatement::IndirectGoto(call)
        | NativeStatement::Expression(call) => collect_temporary_uses(call, &mut uses),
        NativeStatement::Declare { value, .. } => collect_temporary_uses(value, &mut uses),
        NativeStatement::IfGoto { condition, .. } => collect_temporary_uses(condition, &mut uses),
        NativeStatement::IfReturn { condition, value } => {
            collect_temporary_uses(condition, &mut uses);
            if let Some(value) = value {
                collect_temporary_uses(value, &mut uses);
            }
        }
        NativeStatement::IfElse {
            condition,
            then_body,
            else_body,
        } => {
            collect_temporary_uses(condition, &mut uses);
            for statement in then_body {
                uses.extend(statement_temporary_uses(statement));
            }
            for statement in else_body {
                uses.extend(statement_temporary_uses(statement));
            }
        }
        NativeStatement::While { condition, body }
        | NativeStatement::DoWhile { body, condition } => {
            collect_temporary_uses(condition, &mut uses);
            for statement in body {
                uses.extend(statement_temporary_uses(statement));
            }
        }
        NativeStatement::For {
            initializer,
            condition,
            step,
            body,
        } => {
            if let Some(initializer) = initializer {
                uses.extend(statement_temporary_uses(initializer));
            }
            if let Some(condition) = condition {
                collect_temporary_uses(condition, &mut uses);
            }
            if let Some(step) = step {
                uses.extend(statement_temporary_uses(step));
            }
            for statement in body {
                uses.extend(statement_temporary_uses(statement));
            }
        }
        NativeStatement::Switch {
            expression,
            cases,
            default,
        } => {
            collect_temporary_uses(expression, &mut uses);
            for (_, body) in cases {
                for statement in body {
                    uses.extend(statement_temporary_uses(statement));
                }
            }
            for statement in default {
                uses.extend(statement_temporary_uses(statement));
            }
        }
        NativeStatement::Return(value) => {
            if let Some(value) = value {
                collect_temporary_uses(value, &mut uses);
            }
        }
        NativeStatement::Label(_)
        | NativeStatement::Goto(_)
        | NativeStatement::Break
        | NativeStatement::Continue => {}
    }
    uses
}

fn collect_temporary_uses(value: &Expr, uses: &mut BTreeSet<String>) {
    match value {
        Expr::Temporary { name, .. } => {
            uses.insert(name.clone());
        }
        Expr::Binary { left, right, .. } => {
            collect_temporary_uses(left, uses);
            collect_temporary_uses(right, uses);
        }
        Expr::Assign {
            destination,
            source,
        } => {
            collect_temporary_uses(destination, uses);
            collect_temporary_uses(source, uses);
        }
        Expr::Comma(members) => {
            for member in members {
                collect_temporary_uses(member, uses);
            }
        }
        Expr::Not(inner)
        | Expr::Neg(inner)
        | Expr::BitNot(inner)
        | Expr::Cast { value: inner, .. }
        | Expr::Typed { value: inner, .. }
        | Expr::Field { base: inner, .. } => collect_temporary_uses(inner, uses),
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => {
            collect_temporary_uses(condition, uses);
            collect_temporary_uses(when_true, uses);
            collect_temporary_uses(when_false, uses);
        }
        Expr::Load { address, .. } => collect_temporary_uses(address, uses),
        Expr::Call { callee, args, .. } => {
            if let Some(callee) = callee {
                collect_temporary_uses(callee, uses);
            }
            for arg in args {
                collect_temporary_uses(arg, uses);
            }
        }
        Expr::Builtin { args, .. } => {
            for arg in args {
                collect_temporary_uses(arg, uses);
            }
        }
        Expr::Constant { .. }
        | Expr::Parameter { .. }
        | Expr::Register { .. }
        | Expr::Global { .. } => {}
    }
}

fn cleanup_labels_and_gotos(statements: &mut Vec<NativeStatement>) -> bool {
    let mut changed = inline_trivial_return_targets(statements);
    let mut aliases = BTreeMap::new();
    // An indirect transfer may compute any label address. Keep every label
    // identity in that case; only remove a fall-through goto whose target
    // label is still present.
    if !contains_indirect_goto(statements) {
        collect_label_aliases(statements, &mut aliases);
    }
    if aliases.is_empty() {
        return remove_redundant_gotos(statements, &BTreeMap::new()) || changed;
    }

    remap_targets(statements, &aliases);
    changed |= remove_duplicate_labels(statements);
    changed |= remove_redundant_gotos(statements, &aliases);
    changed
}

/// Replaces a jump to a bare `return` with the return itself.
///
/// Compilers give a function one epilogue and jump to it from everywhere. The
/// shared block carries no work, so every jump to it reads better as the return
/// it performs, and removing the jumps lets the structurer see a plain
/// sequence of early returns instead of a web of labels.
fn inline_trivial_return_targets(statements: &mut [NativeStatement]) -> bool {
    let mut returns: BTreeMap<u64, Option<Expr>> = BTreeMap::new();
    let mut index = 0usize;
    while index < statements.len() {
        let NativeStatement::Label(label) = statements[index] else {
            index += 1;
            continue;
        };
        let mut next = index + 1;
        while matches!(statements.get(next), Some(NativeStatement::Label(_))) {
            next += 1;
        }
        if let Some(NativeStatement::Return(value)) = statements.get(next) {
            returns.insert(label, value.clone());
        }
        index = next.max(index + 1);
    }
    if returns.is_empty() {
        return false;
    }
    let mut changed = false;
    for statement in statements.iter_mut() {
        changed |= inline_return_in_statement(statement, &returns);
    }
    changed
}

fn inline_return_in_statement(
    statement: &mut NativeStatement,
    returns: &BTreeMap<u64, Option<Expr>>,
) -> bool {
    match statement {
        NativeStatement::Goto(target) => match returns.get(target) {
            Some(value) => {
                *statement = NativeStatement::Return(value.clone());
                true
            }
            None => false,
        },
        NativeStatement::IfGoto { condition, target } => match returns.get(target) {
            Some(value) => {
                *statement = NativeStatement::IfReturn {
                    condition: condition.clone(),
                    value: value.clone(),
                };
                true
            }
            None => false,
        },
        NativeStatement::IfElse {
            then_body,
            else_body,
            ..
        } => {
            let mut changed = false;
            for nested in then_body.iter_mut().chain(else_body) {
                changed |= inline_return_in_statement(nested, returns);
            }
            changed
        }
        NativeStatement::While { body, .. }
        | NativeStatement::DoWhile { body, .. }
        | NativeStatement::For { body, .. } => {
            let mut changed = false;
            for nested in body {
                changed |= inline_return_in_statement(nested, returns);
            }
            changed
        }
        NativeStatement::Switch { cases, default, .. } => {
            let mut changed = false;
            for (_, body) in cases {
                for nested in body {
                    changed |= inline_return_in_statement(nested, returns);
                }
            }
            for nested in default {
                changed |= inline_return_in_statement(nested, returns);
            }
            changed
        }
        _ => false,
    }
}

#[cfg(test)]
mod epilogue_tests {
    use super::*;

    #[test]
    fn a_jump_to_a_bare_return_becomes_that_return() {
        let mut statements = vec![
            NativeStatement::IfGoto {
                condition: Expr::constant(1, 1),
                target: 0x2000,
            },
            NativeStatement::Goto(0x2000),
            NativeStatement::Label(0x2000),
            NativeStatement::Return(Some(Expr::constant(7, 4))),
        ];
        assert!(inline_trivial_return_targets(&mut statements));
        assert_eq!(
            statements[0],
            NativeStatement::IfReturn {
                condition: Expr::constant(1, 1),
                value: Some(Expr::constant(7, 4)),
            }
        );
        assert_eq!(
            statements[1],
            NativeStatement::Return(Some(Expr::constant(7, 4)))
        );
    }

    #[test]
    fn a_jump_to_a_block_that_does_work_is_left_alone() {
        let statements = vec![
            NativeStatement::Goto(0x2000),
            NativeStatement::Label(0x2000),
            NativeStatement::Store {
                address: Expr::constant(0x3000, 4),
                value: Expr::constant(1, 4),
                width: 4,
                volatile: false,
            },
            NativeStatement::Return(None),
        ];
        let mut candidate = statements.clone();
        assert_eq!(inline_trivial_return_targets(&mut candidate), false);
        assert_eq!(candidate, statements);
    }
}

fn contains_indirect_goto(statements: &[NativeStatement]) -> bool {
    statements.iter().any(|statement| match statement {
        NativeStatement::IndirectGoto(_) => true,
        NativeStatement::IfElse {
            then_body,
            else_body,
            ..
        } => contains_indirect_goto(then_body) || contains_indirect_goto(else_body),
        NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
            contains_indirect_goto(body)
        }
        NativeStatement::For {
            initializer,
            step,
            body,
            ..
        } => {
            initializer.as_deref().is_some_and(|initializer| {
                contains_indirect_goto(std::slice::from_ref(initializer))
            }) || step
                .as_deref()
                .is_some_and(|step| contains_indirect_goto(std::slice::from_ref(step)))
                || contains_indirect_goto(body)
        }
        NativeStatement::Switch { cases, default, .. } => {
            cases.iter().any(|(_, body)| contains_indirect_goto(body))
                || contains_indirect_goto(default)
        }
        _ => false,
    })
}

fn collect_label_aliases(statements: &[NativeStatement], aliases: &mut BTreeMap<u64, u64>) {
    let mut index = 0usize;
    while index < statements.len() {
        if let NativeStatement::Label(first) = statements[index] {
            let first = resolve_label(first, aliases);
            let mut next = index + 1;
            while let Some(NativeStatement::Label(label)) = statements.get(next) {
                let label = resolve_label(*label, aliases);
                if label != first {
                    aliases.insert(label, first);
                }
                next += 1;
            }
            index = next;
        } else {
            index += 1;
        }
    }
    for statement in statements {
        match statement {
            NativeStatement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                collect_label_aliases(then_body, aliases);
                collect_label_aliases(else_body, aliases);
            }
            NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
                collect_label_aliases(body, aliases)
            }
            NativeStatement::For {
                initializer,
                step,
                body,
                ..
            } => {
                collect_label_aliases(body, aliases);
                if let Some(initializer) = initializer {
                    collect_label_aliases(std::slice::from_ref(initializer.as_ref()), aliases);
                }
                if let Some(step) = step {
                    collect_label_aliases(std::slice::from_ref(step.as_ref()), aliases);
                }
            }
            NativeStatement::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    collect_label_aliases(body, aliases);
                }
                collect_label_aliases(default, aliases);
            }
            _ => {}
        }
    }
}

fn resolve_label(label: u64, aliases: &BTreeMap<u64, u64>) -> u64 {
    let mut current = label;
    let mut visited = BTreeSet::new();
    while let Some(next) = aliases.get(&current).copied() {
        if !visited.insert(current) {
            break;
        }
        current = next;
    }
    current
}

fn remap_targets(statements: &mut [NativeStatement], aliases: &BTreeMap<u64, u64>) {
    for statement in statements {
        match statement {
            NativeStatement::DeclareLocal { .. } | NativeStatement::Assign { .. } => {}
            NativeStatement::Goto(target) => *target = resolve_label(*target, aliases),
            NativeStatement::IfGoto { target, .. } => *target = resolve_label(*target, aliases),
            NativeStatement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                remap_targets(then_body, aliases);
                remap_targets(else_body, aliases);
            }
            NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
                remap_targets(body, aliases)
            }
            NativeStatement::For {
                initializer,
                step,
                body,
                ..
            } => {
                remap_targets(body, aliases);
                if let Some(initializer) = initializer {
                    remap_targets(std::slice::from_mut(initializer.as_mut()), aliases);
                }
                if let Some(step) = step {
                    remap_targets(std::slice::from_mut(step.as_mut()), aliases);
                }
            }
            NativeStatement::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    remap_targets(body, aliases);
                }
                remap_targets(default, aliases);
            }
            NativeStatement::Label(_)
            | NativeStatement::Store { .. }
            | NativeStatement::Copy { .. }
            | NativeStatement::Call(_)
            | NativeStatement::Declare { .. }
            | NativeStatement::IfReturn { .. }
            | NativeStatement::IndirectGoto(_)
            | NativeStatement::Return(_)
            | NativeStatement::Expression(_)
            | NativeStatement::Break
            | NativeStatement::Continue => {}
        }
    }
}

fn remove_duplicate_labels(statements: &mut Vec<NativeStatement>) -> bool {
    let mut output = Vec::with_capacity(statements.len());
    let mut changed = false;
    let mut previous_was_label = false;
    for statement in statements.drain(..) {
        if matches!(statement, NativeStatement::Label(_)) {
            if previous_was_label {
                changed = true;
                continue;
            }
            previous_was_label = true;
        } else {
            previous_was_label = false;
        }
        output.push(statement);
    }
    *statements = output;

    for statement in statements {
        changed |= remove_duplicate_labels_in_statement(statement);
    }
    changed
}

fn remove_duplicate_labels_in_statement(statement: &mut NativeStatement) -> bool {
    match statement {
        NativeStatement::IfElse {
            then_body,
            else_body,
            ..
        } => remove_duplicate_labels(then_body) | remove_duplicate_labels(else_body),
        NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
            remove_duplicate_labels(body)
        }
        NativeStatement::For {
            initializer,
            step,
            body,
            ..
        } => {
            let mut changed = remove_duplicate_labels(body);
            if let Some(initializer) = initializer {
                changed |= remove_duplicate_labels_in_statement(initializer);
            }
            if let Some(step) = step {
                changed |= remove_duplicate_labels_in_statement(step);
            }
            changed
        }
        NativeStatement::Switch { cases, default, .. } => {
            let mut changed = false;
            for (_, body) in cases {
                changed |= remove_duplicate_labels(body);
            }
            changed | remove_duplicate_labels(default)
        }
        _ => false,
    }
}

fn remove_redundant_gotos(
    statements: &mut Vec<NativeStatement>,
    aliases: &BTreeMap<u64, u64>,
) -> bool {
    let mut output = Vec::with_capacity(statements.len());
    let mut changed = false;
    let mut index = 0usize;
    while index < statements.len() {
        if let NativeStatement::Goto(target) = statements[index] {
            if let Some(NativeStatement::Label(label)) = statements.get(index + 1) {
                if resolve_label(target, aliases) == *label {
                    changed = true;
                    index += 1;
                    continue;
                }
            }
        }
        output.push(statements[index].clone());
        index += 1;
    }
    *statements = output;

    for statement in statements {
        changed |= remove_redundant_gotos_in_statement(statement, aliases);
    }
    changed
}

fn remove_redundant_gotos_in_statement(
    statement: &mut NativeStatement,
    aliases: &BTreeMap<u64, u64>,
) -> bool {
    match statement {
        NativeStatement::IfElse {
            then_body,
            else_body,
            ..
        } => {
            remove_redundant_gotos(then_body, aliases) | remove_redundant_gotos(else_body, aliases)
        }
        NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
            remove_redundant_gotos(body, aliases)
        }
        NativeStatement::For {
            initializer,
            step,
            body,
            ..
        } => {
            let mut changed = remove_redundant_gotos(body, aliases);
            if let Some(initializer) = initializer {
                changed |= remove_redundant_gotos_in_statement(initializer, aliases);
            }
            if let Some(step) = step {
                changed |= remove_redundant_gotos_in_statement(step, aliases);
            }
            changed
        }
        NativeStatement::Switch { cases, default, .. } => {
            let mut changed = false;
            for (_, body) in cases {
                changed |= remove_redundant_gotos(body, aliases);
            }
            changed | remove_redundant_gotos(default, aliases)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary(name: &str, width: u32) -> Expr {
        Expr::Temporary {
            name: name.to_owned(),
            width,
        }
    }

    fn copy(destination: Expr, source: Expr, width: u32) -> NativeStatement {
        NativeStatement::Copy {
            destination,
            source,
            width,
            volatile: false,
        }
    }

    #[test]
    fn a_cast_restating_a_value_s_own_type_is_dropped() {
        let load = Expr::Load {
            address: Box::new(temporary("u_1", 4)),
            width: 4,
        };
        let restated = Expr::Cast {
            ty: Type::Unsigned(32),
            value: Box::new(load.clone()),
        };
        assert_eq!(copy_cast_cleanup_expr(restated), load);
    }

    #[test]
    fn a_narrowing_cast_of_a_value_is_kept() {
        let load = Expr::Load {
            address: Box::new(temporary("u_1", 4)),
            width: 4,
        };
        let narrowed = Expr::Cast {
            ty: Type::Unsigned(8),
            value: Box::new(load),
        };
        assert_eq!(copy_cast_cleanup_expr(narrowed.clone()), narrowed);
    }

    #[test]
    fn a_wide_temporary_narrowed_at_every_use_is_declared_narrow() {
        let mut statements = vec![
            NativeStatement::Declare {
                name: "mem_1000_0".into(),
                ty: Type::Signed(64),
                value: Expr::Cast {
                    ty: Type::Signed(64),
                    value: Box::new(temporary("u_1", 4)),
                },
            },
            NativeStatement::Return(Some(Expr::Cast {
                ty: Type::Unsigned(32),
                value: Box::new(temporary("mem_1000_0", 8)),
            })),
        ];
        assert!(narrow_declarations_to_used_width(&mut statements));
        assert_eq!(
            statements,
            vec![
                NativeStatement::Declare {
                    name: "mem_1000_0".into(),
                    ty: Type::Unsigned(32),
                    value: temporary("u_1", 4),
                },
                NativeStatement::Return(Some(temporary("mem_1000_0", 4))),
            ]
        );
    }

    #[test]
    fn a_wide_temporary_used_bare_keeps_its_width() {
        let declaration = NativeStatement::Declare {
            name: "mem_1000_0".into(),
            ty: Type::Signed(64),
            value: Expr::Cast {
                ty: Type::Signed(64),
                value: Box::new(temporary("u_1", 4)),
            },
        };
        let mut statements = vec![
            declaration.clone(),
            NativeStatement::Return(Some(temporary("mem_1000_0", 8))),
        ];
        assert_eq!(narrow_declarations_to_used_width(&mut statements), false);
        assert_eq!(statements[0], declaration);
    }

    /// Builds PowerPC's condition-register field for `left` versus `right`.
    fn condition_field(left: Expr, right: Expr, summary_overflow: Expr) -> Expr {
        let shifted = |value: Expr, bit: u64| Expr::Binary {
            op: BinaryOp::Left,
            left: Box::new(value),
            right: Box::new(Expr::constant(bit, 4)),
        };
        let compare = |op: BinaryOp, left: Expr, right: Expr| Expr::Binary {
            op,
            left: Box::new(left),
            right: Box::new(right),
        };
        let or = |left: Expr, right: Expr| Expr::Binary {
            op: BinaryOp::Or,
            left: Box::new(left),
            right: Box::new(right),
        };
        or(
            or(
                or(
                    shifted(compare(BinaryOp::Less, left.clone(), right.clone()), 3),
                    shifted(compare(BinaryOp::Less, right.clone(), left.clone()), 2),
                ),
                shifted(compare(BinaryOp::Equal, left, right), 1),
            ),
            Expr::Binary {
                op: BinaryOp::And,
                left: Box::new(summary_overflow),
                right: Box::new(Expr::constant(1, 1)),
            },
        )
    }

    fn extracted_bit(field: Expr, bit: u64) -> Expr {
        Expr::Binary {
            op: BinaryOp::And,
            left: Box::new(Expr::Binary {
                op: BinaryOp::Right,
                left: Box::new(field),
                right: Box::new(Expr::constant(bit, 4)),
            }),
            right: Box::new(Expr::constant(1, 1)),
        }
    }

    #[test]
    fn condition_register_field_reduces_to_the_selected_comparison() {
        let counter = temporary("u_1", 4);
        let limit = Expr::constant(0x20, 4);
        let field = || {
            condition_field(
                counter.clone(),
                limit.clone(),
                Expr::Register {
                    name: "xer_so".into(),
                    width: 1,
                },
            )
        };
        let less = Expr::Binary {
            op: BinaryOp::Less,
            left: Box::new(counter.clone()),
            right: Box::new(limit.clone()),
        };
        let greater = Expr::Binary {
            op: BinaryOp::Less,
            left: Box::new(limit.clone()),
            right: Box::new(counter.clone()),
        };
        let equal = Expr::Binary {
            op: BinaryOp::Equal,
            left: Box::new(counter.clone()),
            right: Box::new(limit.clone()),
        };
        assert_eq!(simplify_algebraic_expr(extracted_bit(field(), 3)), less);
        assert_eq!(simplify_algebraic_expr(extracted_bit(field(), 2)), greater);
        assert_eq!(simplify_algebraic_expr(extracted_bit(field(), 1)), equal);
    }

    #[test]
    fn summary_overflow_bit_is_left_alone_rather_than_guessed() {
        let field = condition_field(
            temporary("u_1", 4),
            Expr::constant(0x20, 4),
            Expr::Register {
                name: "xer_so".into(),
                width: 1,
            },
        );
        let reduced = simplify_algebraic_expr(extracted_bit(field, 0));
        assert!(
            matches!(
                reduced,
                Expr::Binary {
                    op: BinaryOp::And,
                    ..
                }
            ),
            "{reduced:?}"
        );
    }

    #[test]
    fn rotate_and_mask_collapses_to_one_shift() {
        let value = temporary("u_1", 4);
        let rotated = Expr::Binary {
            op: BinaryOp::And,
            left: Box::new(Expr::Binary {
                op: BinaryOp::Or,
                left: Box::new(Expr::Binary {
                    op: BinaryOp::Left,
                    left: Box::new(value.clone()),
                    right: Box::new(Expr::constant(0x1b, 4)),
                }),
                right: Box::new(Expr::Binary {
                    op: BinaryOp::Right,
                    left: Box::new(value.clone()),
                    right: Box::new(Expr::constant(5, 4)),
                }),
            }),
            right: Box::new(Expr::constant(0x7ffffff, 4)),
        };
        let reduced = simplify_algebraic_expr(rotated);
        let rendered = format!("{reduced:?}");
        assert!(!rendered.contains("Left"), "{rendered}");
        assert!(rendered.contains("Right"), "{rendered}");
    }

    #[test]
    fn shifting_a_value_past_its_width_yields_zero() {
        let value = temporary("u_1", 4);
        let shifted = Expr::Binary {
            op: BinaryOp::Right,
            left: Box::new(value),
            right: Box::new(Expr::constant(0x20, 4)),
        };
        assert_eq!(
            simplify_algebraic_expr(shifted),
            Expr::Constant { value: 0, width: 4 }
        );
    }

    #[test]
    fn constant_offsets_fold_into_one_addition() {
        let base = temporary("u_1", 4);
        let chained = Expr::Binary {
            op: BinaryOp::Add,
            left: Box::new(Expr::Binary {
                op: BinaryOp::Add,
                left: Box::new(base.clone()),
                right: Box::new(Expr::constant(0xffffffff, 4)),
            }),
            right: Box::new(Expr::constant(1, 4)),
        };
        assert_eq!(simplify_algebraic_expr(chained), base);
    }

    #[test]
    fn algebraic_rule_reaches_a_named_fixed_point() {
        let value = temporary("u_1", 4);
        let nested = Expr::Binary {
            op: BinaryOp::Add,
            left: Box::new(Expr::Binary {
                op: BinaryOp::Add,
                left: Box::new(value.clone()),
                right: Box::new(Expr::constant(0, 4)),
            }),
            right: Box::new(Expr::constant(0, 4)),
        };
        let mut database = ActionDatabase::new();
        database.add_group(ActionGroup::fixed_point(
            "algebraic",
            vec![ActionRule::algebraic_simplification()],
            DEFAULT_ITERATION_CAP,
        ));
        let result = database.run(vec![
            copy(temporary("u_2", 4), nested, 4),
            NativeStatement::Return(Some(temporary("u_2", 4))),
        ]);

        assert!(result.converged);
        assert_eq!(
            result.statements,
            vec![
                copy(temporary("u_2", 4), value, 4),
                NativeStatement::Return(Some(temporary("u_2", 4))),
            ]
        );
        assert_eq!(result.trace[0].rules[0].name, "algebraic-simplification");
        assert!(result.trace[0].rules[0].changed);
    }

    #[test]
    fn dead_temporary_elimination_preserves_effectful_loads() {
        let load = Expr::Load {
            address: Box::new(Expr::constant(0x2000, 8)),
            width: 4,
        };
        let result = ActionRule::dead_temporary_assignment_elimination().apply(&mut vec![copy(
            temporary("u_dead", 4),
            load.clone(),
            4,
        )]);
        assert!(result);

        let mut statements = vec![copy(temporary("u_dead", 4), load.clone(), 4)];
        ActionRule::dead_temporary_assignment_elimination().apply(&mut statements);
        assert_eq!(statements, vec![NativeStatement::Expression(load)]);
    }

    #[test]
    fn algebraic_absorption_does_not_discard_effectful_operands() {
        let load = Expr::Load {
            address: Box::new(Expr::constant(0x2000, 8)),
            width: 4,
        };
        let expression = Expr::Binary {
            op: BinaryOp::Mul,
            left: Box::new(load.clone()),
            right: Box::new(Expr::constant(0, 4)),
        };
        assert_eq!(simplify_algebraic_expr(expression.clone()), expression);

        let pure = Expr::Binary {
            op: BinaryOp::Mul,
            left: Box::new(temporary("u_1", 4)),
            right: Box::new(Expr::constant(0, 4)),
        };
        assert_eq!(simplify_algebraic_expr(pure), Expr::constant(0, 4));
    }

    #[test]
    fn algebraic_identities_respect_operand_widths() {
        let value = temporary("u_1", 8);
        let narrow_mask = Expr::Binary {
            op: BinaryOp::And,
            left: Box::new(value.clone()),
            right: Box::new(Expr::constant(u32::MAX.into(), 4)),
        };
        assert_eq!(
            simplify_algebraic_expr(narrow_mask.clone()),
            narrow_mask,
            "a 32-bit mask is not an identity for a 64-bit value"
        );

        let full_mask = Expr::Binary {
            op: BinaryOp::And,
            left: Box::new(value.clone()),
            right: Box::new(Expr::constant(u64::MAX, 8)),
        };
        assert_eq!(simplify_algebraic_expr(full_mask), value);
    }
}
