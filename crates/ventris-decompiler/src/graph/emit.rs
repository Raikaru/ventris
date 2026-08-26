//! Statement emission from the SSA graph.
//!
//! Ghidra's printer walks the structured block tree and asks each varnode for
//! its expression, which the graph already answers. Ventris' old emitter did
//! the opposite: it walked instructions in address order while maintaining a
//! map of what each location currently held, and every control-flow join needed
//! bespoke repair — intersecting predecessor states, proving path invariance,
//! and dropping any value it could not prove. Those repairs are unnecessary
//! here, because [`super::heritage`] already placed a `MULTIEQUAL` wherever
//! paths disagree and [`super::value`] already named it.
//!
//! The output is the label-and-goto form the existing structuring pass
//! consumes, so control-flow recovery is unchanged by this stage.
//!
//! Source authority: `PrintC::emitBlockBasic` and `Funcdata::opCode` handling in
//! `printc.cc` at commit `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use std::collections::{BTreeMap, BTreeSet};

use ventris_lifter::RAM_SPACE;
use ventris_pcode::op;

use super::mergeaction::merge_all;
use super::structure::Condition;
use super::types::Types;
use super::value::{Naming, Resolver, mark_explicit_named, mark_explicit_with};
use super::{Funcdata, GraphBlockId, OpId};
use crate::native::{Expr, NativeStatement, Type};

/// Emits statements for a heritage'd graph.
pub fn emit(
    data: &Funcdata,
    register_name: &dyn Fn(u32, u64, u32) -> Option<String>,
    architecture: ventris_lifter::Architecture,
) -> Vec<NativeStatement> {
    emit_with_types(data, register_name, &Types::default(), architecture)
}

/// Emits statements, declaring each named value at its recovered type.
pub fn emit_with_types(
    data: &Funcdata,
    register_name: &dyn Fn(u32, u64, u32) -> Option<String>,
    types: &Types,
    architecture: ventris_lifter::Architecture,
) -> Vec<NativeStatement> {
    let naming = mark_explicit_with(data, merge_all(data));
    let resolver = Resolver::with_types(data, &naming, register_name, types);
    Emitter {
        data,
        naming: &naming,
        resolver,
        types,
        architecture,
        // The address-ordered path has no construct tree, so it recovers no
        // `for` loops.
        for_loops: BTreeMap::new(),
        nonprinting: BTreeSet::new(),
    }
    .run()
}

/// Emits statements following a recovered construct tree.
///
/// The label-and-goto form exists for flow no construct claimed. Everything the
/// structuring pass recovered is emitted as the construct it recovered, so no
/// later pass has to infer it back from labels.
pub fn emit_structured(
    tables: &[super::jumptable::JumpTable],
    data: &Funcdata,
    register_name: &dyn Fn(u32, u64, u32) -> Option<String>,
    types: &Types,
    parameters: &BTreeMap<(u32, u64), (String, Type)>,
    stack_pointer: Option<super::guard::Location>,
    architecture: ventris_lifter::Architecture,
    rich: &super::typefactory::RecoveredTypes,
    factory: &super::typefactory::TypeFactory,
) -> Vec<NativeStatement> {
    let naming = mark_explicit_named(data, merge_all(data), types, stack_pointer);
    let resolver = Resolver::with_types(data, &naming, register_name, types)
        .with_parameters(parameters)
        .with_rich(rich, factory);
    let tree = super::structure::structure(data, tables);
    // `ActionStructureTransform` decides which loops print as `for` loops
    // before anything is emitted, because the choice moves two statements out
    // of the body and into the loop header.
    let for_loops = super::forloop::find_for_loops(data, &tree);
    let mut emitter = Emitter {
        data,
        naming: &naming,
        resolver,
        types,
        architecture,
        for_loops,
        nonprinting: BTreeSet::new(),
    };
    let scoped = emitter.scoped_names();
    // Only suppress a statement the `for` header can actually spell. An
    // initializer that produces no statement of its own is left where it is,
    // which is what Ghidra does when `testTerminal` rejects it.
    emitter.nonprinting = emitter
        .for_loops
        .values()
        .flat_map(|parts| [Some(parts.iterate), parts.initialize])
        .flatten()
        // A statement that says nothing is not worth lifting into the header,
        // and suppressing it in the body while the header declines to print it
        // would lose it entirely.
        .filter(|op| {
            emitter
                .render(*op, &scoped)
                .is_some_and(|statement| !is_self_assignment(&statement))
        })
        .collect();
    let mut phi_copies: BTreeMap<GraphBlockId, Vec<NativeStatement>> = BTreeMap::new();
    for (block, copy) in emitter.resolver.phi_copies() {
        let copies = phi_copies.entry(block).or_default();
        if !copies.contains(&copy) {
            copies.push(copy);
        }
    }
    let mut statements = emitter.phi_declarations();
    let targets = goto_targets(data, &tree);
    // The root is not pruned. Its members are independent regions, each
    // reached by a jump from elsewhere, so a statement after a transfer there
    // is reachable even without a label of its own. Pruning applies inside a
    // construct's body, where the only way in is through the construct.
    statements.extend(emitter.emit_construct(&tree, &scoped, &phi_copies, &targets));
    drop_self_assignments(&mut statements);
    drop_gotos_to_next_statement(&mut statements);
    drop_trailing_gotos_to_following_label(&mut statements);
    prefer_non_empty_then(&mut statements);
    drop_self_assignments(&mut statements);
    drop_transfers_after_a_transfer(&mut statements);
    // Each substitution can expose another: collapsing one link of an address
    // chain leaves the next with a single reader.
    for _ in 0..8 {
        let before = count_statements(&statements);
        propagate_single_use_copies(&mut statements);
        drop_assignments_nothing_reads(&mut statements);
        if count_statements(&statements) == before {
            break;
        }
    }
    drop_labels_nothing_needs(&mut statements);
    // Last: the guard clause needs the exit to be the statement after the test,
    // and a label sits between them until the labels nothing needs are gone.
    prefer_guard_clause(&mut statements);
    statements
}

/// Turns a negated test wrapped around the whole body into a guard clause.
///
/// `if (!C) { BODY } return;` and `if (C) { return; } BODY` describe the same
/// program, but the second is what the condition means: C is the case that has
/// nothing to do. Recovered structuring produces the first, because it names the
/// edge the branch takes rather than the edge that leaves.
fn prefer_guard_clause(statements: &mut Vec<NativeStatement>) {
    // Two statements: the test around everything, and the function's own exit.
    if statements.len() < 2 {
        return;
    }
    if !matches!(statements.last(), Some(NativeStatement::Return(None))) {
        return;
    }
    let at = statements.len() - 2;
    let NativeStatement::IfElse {
        condition,
        then_body,
        else_body,
    } = &statements[at]
    else {
        return;
    };
    // An `else` already says which side is which, and a single-statement body
    // reads better inline than behind a guard.
    if !else_body.is_empty() || then_body.len() < 2 {
        return;
    }
    let condition = invert(condition.clone());
    let body = then_body.clone();
    statements.splice(
        at..=at,
        std::iter::once(NativeStatement::IfElse {
            condition,
            then_body: vec![NativeStatement::Return(None)],
            else_body: Vec::new(),
        })
        .chain(body),
    );
}

/// The negation of a condition, undoing one rather than stacking two.
fn invert(condition: Expr) -> Expr {
    match condition {
        Expr::Not(inner) => *inner,
        other => Expr::Not(Box::new(other)),
    }
}

/// How deep an expression may grow before it is left behind a name.
///
/// `graph::marking`'s `MAX_EXPRESSION_DEPTH` guards against pathological
/// graphs; this bound is about a line staying readable, so it is much tighter.
/// Folding eight single-use shifts together produced a 411-character line in
/// `DBGEXIImm`, where the oracle's widest is 87.
const MAX_INLINE_DEPTH: usize = 4;

/// The nesting depth of an expression.
fn expression_depth(value: &Expr) -> usize {
    match value {
        Expr::Binary { left, right, .. } => 1 + expression_depth(left).max(expression_depth(right)),
        Expr::Not(inner)
        | Expr::Neg(inner)
        | Expr::BitNot(inner)
        | Expr::Cast { value: inner, .. }
        | Expr::Typed { value: inner, .. }
        | Expr::Load { address: inner, .. }
        | Expr::Field { base: inner, .. } => 1 + expression_depth(inner),
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => {
            1 + expression_depth(condition)
                .max(expression_depth(when_true))
                .max(expression_depth(when_false))
        }
        Expr::Call { args, .. } | Expr::Builtin { args, .. } => {
            1 + args.iter().map(expression_depth).max().unwrap_or(0)
        }
        _ => 0,
    }
}

/// Substitutes a name that is assigned once and read once.
///
/// Naming a value is what makes it read its operands where it is defined rather
/// than where it is used, so a name that carries a value to exactly one reader
/// and nothing else has served its purpose and can be spelled at that reader
/// instead. The substitution is refused when anything between the two writes a
/// name the expression reads, which is the same condition that decided to name
/// the value in the first place.
fn propagate_single_use_copies(statements: &mut Vec<NativeStatement>) {
    propagate_within(statements, None);
}

/// As [`propagate_single_use_copies`], told which names the enclosing loop reads
/// on its next iteration.
///
/// A loop body's back edge is a reader the statement list cannot show. A name
/// assigned in the body and read by the loop's test, or by a statement at or
/// before the assignment, is read again on the next iteration, so the assignment
/// is not dead once its forward reader has absorbed it: removing it left a loop
/// counter at its initial value and the loop never terminated.
fn propagate_within(statements: &mut Vec<NativeStatement>, carried: Option<&BTreeSet<String>>) {
    // Only within one straight run of statements. Crossing into or out of a
    // construct's body changes how many times the expression is evaluated.
    for statement in statements.iter_mut() {
        match statement {
            NativeStatement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                propagate_within(then_body, carried);
                propagate_within(else_body, carried);
            }
            NativeStatement::While { condition, body }
            | NativeStatement::DoWhile { body, condition } => {
                let inner = source_names(condition);
                propagate_within(body, Some(&inner));
            }
            NativeStatement::For {
                condition, body, ..
            } => {
                let inner = condition.as_ref().map(source_names).unwrap_or_default();
                propagate_within(body, Some(&inner));
            }
            _ => {}
        }
    }
    let mut index = 0;
    while index < statements.len() {
        let Some((name, source)) = assigned_name_and_value(&statements[index]) else {
            index += 1;
            continue;
        };
        if !expression_is_pure(&source) || expression_depth(&source) > MAX_INLINE_DEPTH {
            index += 1;
            continue;
        }
        // Inside a loop the next iteration reads this name, either through the
        // loop's test or through a statement it reaches before this assignment
        // runs again - including the assignment itself, for an update like
        // `i = i - 1`. Removing it once a later reader had absorbed it left a
        // loop counter at its initial value and the loop never terminated.
        if let Some(carried) = carried
            && (carried.contains(&name) || {
                let mut read = BTreeSet::new();
                collect_read_names(&statements[..=index], &mut read, false);
                read.contains(&name)
            })
        {
            index += 1;
            continue;
        }
        // A constant has no operands that anything could invalidate, so it goes
        // to every reader rather than to one. Naming one costs a declaration and
        // says the value came from somewhere, which it did not.
        if matches!(source, Expr::Constant { .. }) {
            let mut substituted = false;
            for at in (index + 1)..statements.len() {
                if writes_name(&statements[at], &name) {
                    break;
                }
                substituted |= substitute_name(&mut statements[at], &name, &source);
            }
            if substituted {
                statements.remove(index);
                continue;
            }
        }
        let mut reads = source_names(&source);
        reads.insert(name.clone());
        match single_reader_after(statements, index, &name, &reads) {
            Some(at) if substitute_name(&mut statements[at], &name, &source) => {
                statements.remove(index);
            }
            _ => index += 1,
        }
    }
}

/// Whether a statement can read `name` before it writes it.
///
/// This decides whether a construct that writes a name may nonetheless be a
/// reader of the value arriving at it. Walking in order answers that for an
/// `if`: a body that assigns the name first reads only its own value afterwards.
/// A loop cannot be answered that way - control returns to its top, so any read
/// it contains can be of the incoming value - and is reported as reading first
/// whenever it reads at all.
fn reads_before_write(statement: &NativeStatement, name: &str) -> bool {
    let reads = |value: &Expr| source_names(value).contains(name);
    let body_reads = |body: &[NativeStatement]| {
        let mut read = BTreeSet::new();
        collect_read_names(body, &mut read, false);
        read.contains(name)
    };
    match statement {
        NativeStatement::While { condition, body }
        | NativeStatement::DoWhile { body, condition } => reads(condition) || body_reads(body),
        NativeStatement::For {
            initializer,
            condition,
            step,
            body,
        } => {
            condition.as_ref().is_some_and(reads)
                || initializer
                    .as_ref()
                    .is_some_and(|held| reads_before_write(held, name))
                || step
                    .as_ref()
                    .is_some_and(|held| reads_before_write(held, name))
                || body_reads(body)
        }
        NativeStatement::IfElse {
            condition,
            then_body,
            else_body,
        } => {
            if reads(condition) {
                return true;
            }
            [then_body, else_body]
                .into_iter()
                .any(|body| run_reads_before_write(body, name))
        }
        NativeStatement::Switch {
            expression,
            cases,
            default,
        } => {
            reads(expression)
                || cases
                    .iter()
                    .any(|(_, body)| run_reads_before_write(body, name))
                || run_reads_before_write(default, name)
        }
        // A read in a simple statement is counted before its own write, the way
        // `p = p + q` reads the carried value and then replaces it.
        other => {
            let mut read = BTreeSet::new();
            collect_read_names(std::slice::from_ref(other), &mut read, false);
            read.contains(name)
        }
    }
}

/// As [`reads_before_write`], over a straight run that stops at the first write.
fn run_reads_before_write(statements: &[NativeStatement], name: &str) -> bool {
    for statement in statements {
        if reads_before_write(statement, name) {
            return true;
        }
        if writes_name(statement, name) {
            return false;
        }
    }
    false
}

/// Whether a statement writes `name` anywhere inside it, bodies included.
///
/// `assigned_name_and_value` sees only a statement that *is* an assignment, so a
/// write nested in an `if` or a loop body is invisible to it. Both propagation
/// windows below close on a write, and closing them on the top-level test alone
/// let a stale value cross a reassignment it could not see: a constant assigned
/// before a construct was substituted into readers that follow a reassignment
/// inside that construct, which is how `uVar6 < 1` became `0 < 1` on a corpus
/// function.
fn writes_name(statement: &NativeStatement, name: &str) -> bool {
    if assigned_name_and_value(statement).is_some_and(|(written, _)| written == name) {
        return true;
    }
    nested_bodies_ref(statement)
        .into_iter()
        .flatten()
        .any(|nested| writes_name(nested, name))
}

fn assigned_name_and_value(statement: &NativeStatement) -> Option<(String, Expr)> {
    match statement {
        NativeStatement::Declare { name, value, .. } => Some((name.clone(), value.clone())),
        NativeStatement::Assign {
            destination: Expr::Temporary { name, .. },
            source,
        } => Some((name.clone(), source.clone())),
        _ => None,
    }
}

fn source_names(value: &Expr) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    collect_expr_names(value, &mut names);
    names
}

/// The index of the only later statement reading `name`, if the substitution is
/// safe up to that point.
fn single_reader_after(
    statements: &[NativeStatement],
    from: usize,
    name: &str,
    reads: &BTreeSet<String>,
) -> Option<usize> {
    let mut found = None;
    for (offset, statement) in statements.iter().enumerate().skip(from + 1) {
        let mut used = BTreeSet::new();
        collect_read_names(std::slice::from_ref(statement), &mut used, false);
        let ends_window = reads.iter().any(|read| writes_name(statement, read));
        // A construct that writes the name may still read it first, and then
        // the read is of the value being propagated. A loop is always in that
        // position: its reads and writes are circular, so a read anywhere in it
        // can be of the incoming value. Exempting a construct without asking
        // let an initializer be substituted into a guard, and the loop after it
        // ran on whatever the variable happened to hold.
        let compound = matches!(
            statement,
            NativeStatement::IfElse { .. }
                | NativeStatement::While { .. }
                | NativeStatement::DoWhile { .. }
                | NativeStatement::For { .. }
        ) && !reads_before_write(statement, name);
        // That ordering is only knowable for a simple assignment. A construct
        // that writes one of these names somewhere in its body may well read it
        // *after* that write, in which case the read is of the new value and not
        // of the one being propagated. Counting it anyway substituted a constant
        // into a reader that follows a reassignment, which is how `uVar6 < 1`
        // became `0 < 1` on a corpus function.
        if used.contains(name) && !(compound && ends_window) {
            if found.is_some() {
                return None;
            }
            // A construct evaluates its body an unknown number of times, so a
            // value carried into one is not carried to a single reader.
            if matches!(
                statement,
                NativeStatement::While { .. } | NativeStatement::DoWhile { .. }
            ) {
                return None;
            }
            found = Some(offset);
        }
        // A statement that writes any name the expression reads ends the window,
        // wherever inside it the write happens.
        if ends_window {
            return found;
        }
    }
    found
}

fn substitute_name(statement: &mut NativeStatement, name: &str, value: &Expr) -> bool {
    match statement {
        NativeStatement::Declare { value: target, .. } => substitute_expr(target, name, value),
        NativeStatement::Assign {
            destination,
            source,
        } => {
            // A plain name on the left is being written, not read. Substituting
            // there produced `(uintptr_t)(iVar5) = ...`, which is not an lvalue.
            let wrote_here =
                matches!(destination, Expr::Temporary { name: other, .. } if other == name);
            let mut replaced = substitute_expr(source, name, value);
            if !wrote_here {
                replaced |= substitute_expr(destination, name, value);
            }
            replaced
        }
        NativeStatement::Store {
            address, value: v, ..
        } => substitute_expr(address, name, value) | substitute_expr(v, name, value),
        NativeStatement::Copy {
            destination,
            source,
            ..
        } => substitute_expr(destination, name, value) | substitute_expr(source, name, value),
        NativeStatement::Call(call) => substitute_expr(call, name, value),
        NativeStatement::Return(Some(result)) => substitute_expr(result, name, value),
        NativeStatement::IfGoto { condition, .. } => substitute_expr(condition, name, value),
        NativeStatement::IfReturn {
            condition,
            value: result,
        } => {
            let mut replaced = substitute_expr(condition, name, value);
            if let Some(result) = result {
                replaced |= substitute_expr(result, name, value);
            }
            replaced
        }
        NativeStatement::IndirectGoto(target) => substitute_expr(target, name, value),
        NativeStatement::IfElse { condition, .. } => substitute_expr(condition, name, value),
        _ => false,
    }
}

fn flip_boolean(condition: &Expr) -> Option<Expr> {
    use crate::native::BinaryOp;
    match condition {
        // `!!x` is `x`: Ghidra's flip of `BOOL_NEGATE` is a `COPY`, which it
        // then removes entirely.
        Expr::Not(inner) => Some((**inner).clone()),
        Expr::Binary { op, left, right } => {
            let (flipped, reorder) = match op {
                BinaryOp::Equal => (BinaryOp::NotEqual, false),
                BinaryOp::NotEqual => (BinaryOp::Equal, false),
                BinaryOp::Less => (BinaryOp::LessEqual, true),
                BinaryOp::LessEqual => (BinaryOp::Less, true),
                BinaryOp::SignedLess => (BinaryOp::SignedLessEqual, true),
                BinaryOp::SignedLessEqual => (BinaryOp::SignedLess, true),
                _ => return None,
            };
            let (left, right) = if reorder {
                (right.clone(), left.clone())
            } else {
                (left.clone(), right.clone())
            };
            Some(Expr::Binary {
                op: flipped,
                left,
                right,
            })
        }
        _ => None,
    }
}

fn substitute_expr(target: &mut Expr, name: &str, value: &Expr) -> bool {
    if matches!(target, Expr::Temporary { name: other, .. } if other == name) {
        *target = value.clone();
        return true;
    }
    let mut replaced = false;
    match target {
        Expr::Binary { left, right, .. } => {
            replaced |= substitute_expr(left, name, value);
            replaced |= substitute_expr(right, name, value);
            // Substituting a named zero into an addition leaves `x + 0`, which
            // the expression builder would never have emitted: it folds a zero
            // displacement when it builds the operation. The literal only
            // appears here, after propagation spends the name, so the fold has
            // to happen here too.
            if let Expr::Binary {
                op: crate::native::BinaryOp::Add,
                left,
                right,
            } = target
                && matches!(right.as_ref(), Expr::Constant { value: 0, .. })
            {
                *target = (**left).clone();
            }
        }
        Expr::Not(inner)
        | Expr::Neg(inner)
        | Expr::BitNot(inner)
        | Expr::Cast { value: inner, .. }
        | Expr::Typed { value: inner, .. }
        | Expr::Load { address: inner, .. }
        | Expr::Field { base: inner, .. } => {
            replaced |= substitute_expr(inner, name, value);
        }
        Expr::Call { callee, args, .. } => {
            if let Some(callee) = callee {
                replaced |= substitute_expr(callee, name, value);
            }
            for arg in args {
                replaced |= substitute_expr(arg, name, value);
            }
        }
        Expr::Builtin { args, .. } => {
            for arg in args {
                replaced |= substitute_expr(arg, name, value);
            }
        }
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => {
            replaced |= substitute_expr(condition, name, value);
            replaced |= substitute_expr(when_true, name, value);
            replaced |= substitute_expr(when_false, name, value);
        }
        _ => {}
    }
    replaced
}

/// Removes an assignment to a name that nothing afterwards reads.
///
/// Address arithmetic that folds into a field access leaves its temporary
/// behind: the read became `p->field_4a4`, so the `pVar1 = p + 0x4a4` that fed
/// it has no reader left. Only pure right-hand sides are removed — a call or a
/// memory read is kept whatever its result is used for.
fn drop_assignments_nothing_reads(statements: &mut Vec<NativeStatement>) {
    for _ in 0..8 {
        let before = count_statements(statements);
        drop_overwritten_assignments(statements);
        let mut read = BTreeSet::new();
        collect_read_names(statements, &mut read, true);
        retain_live_assignments(statements, &read);
        if count_statements(statements) == before {
            break;
        }
    }
}

/// Removes an assignment whose value is replaced before anything reads it.
///
/// Liveness by name alone is not enough: a variable reused for several values
/// is read later under the same name, which kept every earlier assignment to it
/// alive. `allocEnemyEntity` carried a dead `pVar1 = arg0 + 0x4b0` because the
/// field access that replaced its only reader left the name in use further down.
fn drop_overwritten_assignments(statements: &mut Vec<NativeStatement>) {
    for statement in statements.iter_mut() {
        for body in nested_bodies(statement) {
            drop_overwritten_assignments(body);
        }
    }
    let mut index = 0;
    while index < statements.len() {
        let Some((name, source)) = assigned_name_and_value(&statements[index]) else {
            index += 1;
            continue;
        };
        if !expression_is_pure(&source) {
            index += 1;
            continue;
        }
        if overwritten_before_read(statements, index, &name) {
            statements.remove(index);
            continue;
        }
        index += 1;
    }
}

/// Whether the next thing to touch `name` after `from` writes it rather than
/// reads it.
fn overwritten_before_read(statements: &[NativeStatement], from: usize, name: &str) -> bool {
    for statement in statements.iter().skip(from + 1) {
        // A loop can run again, so a read anywhere inside one may observe this
        // assignment on the next iteration.
        if matches!(
            statement,
            NativeStatement::While { .. } | NativeStatement::DoWhile { .. }
        ) {
            return false;
        }
        let mut used = BTreeSet::new();
        collect_read_names(std::slice::from_ref(statement), &mut used, false);
        if used.contains(name) {
            return false;
        }
        // A branch that writes the name on one side only leaves the other side
        // reading this value, so only an unconditional write ends the range.
        if matches!(statement, NativeStatement::IfElse { .. }) {
            continue;
        }
        if let Some((written, _)) = assigned_name_and_value(statement)
            && written == name
        {
            return true;
        }
    }
    false
}

fn count_statements(statements: &[NativeStatement]) -> usize {
    statements
        .iter()
        .map(|statement| {
            1 + nested_bodies_ref(statement)
                .into_iter()
                .map(|body| count_statements(body))
                .sum::<usize>()
        })
        .sum()
}

/// Names read by any expression, excluding the destination of an assignment.
fn collect_read_names(statements: &[NativeStatement], read: &mut BTreeSet<String>, _top: bool) {
    for statement in statements {
        match statement {
            NativeStatement::Declare { value, .. } => collect_expr_names(value, read),
            NativeStatement::Assign {
                destination,
                source,
            } => {
                // A destination that is not a plain name reads whatever it
                // computes, so those operands stay live. A plain name is being
                // written, not read — but it does keep its declaration alive.
                match destination {
                    Expr::Temporary { name, .. } => {
                        read.insert(format!("declared:{name}"));
                    }
                    other => collect_expr_names(other, read),
                }
                collect_expr_names(source, read);
            }
            NativeStatement::Store { address, value, .. } => {
                collect_expr_names(address, read);
                collect_expr_names(value, read);
            }
            NativeStatement::Copy {
                destination,
                source,
                ..
            } => {
                collect_expr_names(destination, read);
                collect_expr_names(source, read);
            }
            NativeStatement::Call(call) => collect_expr_names(call, read),
            NativeStatement::Return(Some(value)) => collect_expr_names(value, read),
            NativeStatement::IfGoto { condition, .. } => collect_expr_names(condition, read),
            NativeStatement::IfReturn { condition, value } => {
                collect_expr_names(condition, read);
                if let Some(value) = value {
                    collect_expr_names(value, read);
                }
            }
            NativeStatement::IndirectGoto(target) => collect_expr_names(target, read),
            // An expression statement is kept for its effect, so everything it
            // mentions is read. This arm was missing entirely, so those reads
            // were invisible to liveness.
            NativeStatement::Expression(value) => collect_expr_names(value, read),
            // A construct's own test is a read, and so is everything its
            // bodies read. The bodies go through the accessor so no construct
            // can be forgotten here - liveness is consulted before deleting an
            // assignment, so a missed read deletes live code.
            other => {
                match other {
                    NativeStatement::IfElse { condition, .. }
                    | NativeStatement::While { condition, .. }
                    | NativeStatement::DoWhile { condition, .. } => {
                        collect_expr_names(condition, read);
                    }
                    NativeStatement::For {
                        initializer,
                        condition,
                        step,
                        ..
                    } => {
                        if let Some(condition) = condition {
                            collect_expr_names(condition, read);
                        }
                        for held in [initializer, step].into_iter().flatten() {
                            collect_read_names(std::slice::from_ref(held.as_ref()), read, false);
                        }
                    }
                    NativeStatement::Switch { expression, .. } => {
                        collect_expr_names(expression, read);
                    }
                    _ => {}
                }
                for body in nested_bodies_ref(other) {
                    collect_read_names(body, read, false);
                }
            }
        }
    }
}

fn retain_live_assignments(statements: &mut Vec<NativeStatement>, read: &BTreeSet<String>) {
    statements.retain_mut(|statement| {
        match statement {
            NativeStatement::Declare { name, value, .. } => {
                if !read.contains(name) && expression_is_pure(value) {
                    return false;
                }
            }
            NativeStatement::Assign {
                destination: Expr::Temporary { name, .. },
                source,
            } => {
                if !read.contains(name) && expression_is_pure(source) {
                    return false;
                }
            }
            // A local declared for a merged value that nothing reads any more
            // is left over from the same folding.
            NativeStatement::DeclareLocal { name, .. } => {
                if !read.contains(name) && !read.contains(&format!("declared:{name}")) {
                    return false;
                }
            }
            other => {
                for body in nested_bodies(other) {
                    retain_live_assignments(body, read);
                }
            }
        }
        true
    });
}

/// Whether an expression can be removed with its result.
fn expression_is_pure(value: &Expr) -> bool {
    match value {
        Expr::Constant { .. }
        | Expr::Parameter { .. }
        | Expr::Register { .. }
        | Expr::Temporary { .. }
        | Expr::Global { .. } => true,
        // A read touches memory whose contents may change, and a call does
        // anything at all.
        Expr::Load { .. } | Expr::Field { .. } | Expr::Call { .. } | Expr::Builtin { .. } => false,
        Expr::Binary { left, right, .. } => expression_is_pure(left) && expression_is_pure(right),
        Expr::Not(inner)
        | Expr::Neg(inner)
        | Expr::BitNot(inner)
        | Expr::Cast { value: inner, .. }
        | Expr::Typed { value: inner, .. } => expression_is_pure(inner),
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => {
            expression_is_pure(condition)
                && expression_is_pure(when_true)
                && expression_is_pure(when_false)
        }
    }
}

fn collect_expr_names(value: &Expr, read: &mut BTreeSet<String>) {
    match value {
        Expr::Temporary { name, .. } | Expr::Register { name, .. } => {
            read.insert(name.clone());
        }
        Expr::Binary { left, right, .. } => {
            collect_expr_names(left, read);
            collect_expr_names(right, read);
        }
        Expr::Not(inner)
        | Expr::Neg(inner)
        | Expr::BitNot(inner)
        | Expr::Cast { value: inner, .. }
        | Expr::Typed { value: inner, .. }
        | Expr::Load { address: inner, .. }
        | Expr::Field { base: inner, .. } => collect_expr_names(inner, read),
        Expr::Call { callee, args, .. } => {
            if let Some(callee) = callee {
                collect_expr_names(callee, read);
            }
            for arg in args {
                collect_expr_names(arg, read);
            }
        }
        Expr::Builtin { args, .. } => {
            for arg in args {
                collect_expr_names(arg, read);
            }
        }
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => {
            collect_expr_names(condition, read);
            collect_expr_names(when_true, read);
            collect_expr_names(when_false, read);
        }
        _ => {}
    }
}

/// Removes a jump or return that directly follows another, with no label
/// between them.
///
/// This is the one thing safe to delete after an unconditional transfer: a
/// transfer computes nothing, so removing an unreachable one loses no work.
/// Anything else that follows may be reached by a jump from elsewhere and gets
/// a label instead.
fn drop_transfers_after_a_transfer(statements: &mut Vec<NativeStatement>) {
    for statement in statements.iter_mut() {
        for body in nested_bodies(statement) {
            drop_transfers_after_a_transfer(body);
        }
    }
    let mut index = 1;
    while index < statements.len() {
        let unreachable_transfer = matches!(
            statements[index - 1],
            NativeStatement::Goto(_) | NativeStatement::Return(_)
        ) && matches!(
            statements[index],
            NativeStatement::Goto(_) | NativeStatement::Return(_)
        );
        if unreachable_transfer {
            statements.remove(index);
            continue;
        }
        index += 1;
    }
}

/// Removes labels no jump names and no transfer strands.
///
/// A block is labelled whenever control could arrive other than by falling
/// through, which is deliberately generous: emission order does not have to
/// follow the control-flow graph, so a block reached by fallthrough in the
/// graph can land after an unrelated jump in the output. Labelling it is the
/// only honest way to say it is still reachable. This pass then drops the ones
/// that turned out to be unnecessary, so the generosity costs nothing in the
/// common case.
fn drop_labels_nothing_needs(statements: &mut Vec<NativeStatement>) {
    let mut named = BTreeSet::new();
    collect_jump_targets(statements, &mut named);
    // Nothing precedes the first statement, so the function's own entry is not
    // "after a transfer". Passing `true` here kept a label on every leading
    // block, which printed a run of empty `loc_*:` lines.
    retain_needed_labels(statements, &named, false);
}

fn collect_jump_targets(statements: &[NativeStatement], named: &mut BTreeSet<u64>) {
    for statement in statements {
        match statement {
            NativeStatement::Goto(target) | NativeStatement::IfGoto { target, .. } => {
                named.insert(*target);
            }
            other => {
                for body in nested_bodies_ref(other) {
                    collect_jump_targets(body, named);
                }
            }
        }
    }
}

fn retain_needed_labels(
    statements: &mut Vec<NativeStatement>,
    named: &BTreeSet<u64>,
    mut after_transfer: bool,
) {
    let mut index = 0;
    while index < statements.len() {
        let drop = match &statements[index] {
            // A label right after a transfer is what makes the statements
            // following it reachable, so it stays whether or not a jump in
            // this function names it.
            NativeStatement::Label(label) => !named.contains(label) && !after_transfer,
            _ => false,
        };
        if drop {
            statements.remove(index);
            continue;
        }
        after_transfer = match &mut statements[index] {
            NativeStatement::Goto(_) | NativeStatement::Return(_) => true,
            NativeStatement::Label(_) => after_transfer,
            // A construct's body starts reachable, so its labels are judged on
            // their own.
            other => {
                for body in nested_bodies(other) {
                    retain_needed_labels(body, named, false);
                }
                false
            }
        };
        index += 1;
    }
}

/// Removes a jump at the end of a construct's body when the label it names is
/// the statement right after that construct.
///
/// Control already arrives there by leaving the construct. Ghidra never emits
/// the jump because its block tree ends the region at that point; the collapse
/// here surrenders the edge before knowing where the target lands.
fn drop_trailing_gotos_to_following_label(statements: &mut Vec<NativeStatement>) {
    for index in 0..statements.len() {
        let following = match statements.get(index + 1) {
            Some(NativeStatement::Label(label)) => Some(*label),
            _ => None,
        };
        match &mut statements[index] {
            NativeStatement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                if let Some(label) = following {
                    drop_trailing_goto(then_body, label);
                    drop_trailing_goto(else_body, label);
                }
                drop_trailing_gotos_to_following_label(then_body);
                drop_trailing_gotos_to_following_label(else_body);
            }
            other => {
                for body in nested_bodies(other) {
                    drop_trailing_gotos_to_following_label(body);
                }
            }
        }
    }
}

/// Removes an unconditional jump left at the end of a construct's header.
///
/// The construct decides where control goes from its header, so a jump the
/// header still carries describes an edge the construct already claimed. It is
/// not a reachability question: the test after it always runs.
fn drop_stale_header_transfer(statements: &mut Vec<NativeStatement>) {
    while matches!(statements.last(), Some(NativeStatement::Goto(_))) {
        statements.pop();
    }
}

/// Drops a `goto label` that sits in trailing position, however deeply nested
/// inside trailing `if` bodies, when `label` is what follows the whole
/// construct.
///
/// Falling out of a trailing `if` lands exactly where the jump was going, so the
/// jump says nothing. Ghidra renders these as plain nesting: `__osRealloc` has
/// five jumps to its shared epilogue and the oracle emits none.
///
/// Only `if` is followed. A trailing jump out of a loop is an early exit, and
/// out of a `switch` case it is a `break` - dropping either would fall into the
/// loop's next iteration or the next case instead.
fn drop_trailing_goto(body: &mut Vec<NativeStatement>, label: u64) {
    match body.last_mut() {
        Some(NativeStatement::Goto(target)) if *target == label => {
            body.pop();
        }
        Some(NativeStatement::IfElse {
            then_body,
            else_body,
            ..
        }) => {
            drop_trailing_goto(then_body, label);
            drop_trailing_goto(else_body, label);
        }
        _ => {}
    }
}

/// Inverts a conditional whose taken branch is empty.
///
/// `if (c) {} else { work }` says the same thing as `if (!c) { work }` and reads
/// as source rather than as a branch table. Ghidra normalises the same way
/// through `negateCondition` when it chooses which clause to print.
fn prefer_non_empty_then(statements: &mut Vec<NativeStatement>) {
    for statement in statements.iter_mut() {
        match statement {
            NativeStatement::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                if then_body.is_empty() && !else_body.is_empty() {
                    std::mem::swap(then_body, else_body);
                    let inverted = match condition.clone() {
                        Expr::Not(inner) => *inner,
                        other => Expr::Not(Box::new(other)),
                    };
                    *condition = inverted;
                }
                prefer_non_empty_then(then_body);
                prefer_non_empty_then(else_body);
            }
            NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
                prefer_non_empty_then(body);
            }
            _ => {}
        }
    }
}

/// Removes assignments whose two sides are the same variable.
///
/// Merging is what creates these: two SSA values that a `COPY` related become
/// one C variable, and the copy between them then reads and writes the same
/// name. The statement carries no information once that has happened.
/// Whether a statement assigns a name to itself.
///
/// The two sides need not be the same expression: one may carry a cast or a
/// different storage width while naming the same variable, which is exactly what
/// a copy between two versions of one variable looks like.
fn is_self_assignment(statement: &NativeStatement) -> bool {
    let NativeStatement::Assign {
        destination,
        source,
    } = statement
    else {
        return false;
    };
    let bare = |value: &Expr| -> Option<String> {
        let mut current = value;
        loop {
            match current {
                Expr::Cast { value, .. } => current = value,
                Expr::Temporary { name, .. } | Expr::Register { name, .. } => {
                    return Some(name.clone());
                }
                Expr::Parameter { name, .. } => return Some(name.clone()),
                _ => return None,
            }
        }
    };
    match (bare(destination), bare(source)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn drop_self_assignments(statements: &mut Vec<NativeStatement>) {
    statements.retain(|statement| !is_self_assignment(statement));
    for statement in statements.iter_mut() {
        for body in nested_bodies(statement) {
            drop_self_assignments(body);
        }
    }
}

/// Removes a jump to the label that immediately follows it.
///
/// The collapse surrenders an edge as a `goto` without knowing where the target
/// will be emitted. When it lands next, the jump says nothing, and it is the
/// difference between output that reads as a `goto` ladder and output that
/// reads as straight-line code.

/// Every statement list nested inside a statement.
///
/// Each walker below has to visit these, and teaching them one construct at a
/// time is how they fall behind: `For` was added after most of them were
/// written and thirteen skipped its body, `Switch` was never taught at all. So a
/// no-op `goto` survived inside a `for`, and - worse - `collect_read_names` did
/// not see reads inside either construct, which is what `retain_live_assignments`
/// consults before deleting an assignment. Routing every walker through one
/// accessor makes a new construct a compile error here instead of a silent gap
/// in thirteen places.
fn nested_bodies(statement: &mut NativeStatement) -> Vec<&mut Vec<NativeStatement>> {
    match statement {
        NativeStatement::IfElse {
            then_body,
            else_body,
            ..
        } => vec![then_body, else_body],
        NativeStatement::While { body, .. }
        | NativeStatement::DoWhile { body, .. }
        | NativeStatement::For { body, .. } => vec![body],
        NativeStatement::Switch { cases, default, .. } => cases
            .iter_mut()
            .map(|(_, body)| body)
            .chain(std::iter::once(default))
            .collect(),
        NativeStatement::Declare { .. }
        | NativeStatement::DeclareLocal { .. }
        | NativeStatement::Assign { .. }
        | NativeStatement::Copy { .. }
        | NativeStatement::Store { .. }
        | NativeStatement::Call(_)
        | NativeStatement::IfGoto { .. }
        | NativeStatement::IfReturn { .. }
        | NativeStatement::Break
        | NativeStatement::Continue
        | NativeStatement::Goto(_)
        | NativeStatement::IndirectGoto(_)
        | NativeStatement::Return(_)
        | NativeStatement::Expression(_)
        | NativeStatement::Label(_) => Vec::new(),
    }
}

/// As [`nested_bodies`], without needing a mutable borrow.
fn nested_bodies_ref(statement: &NativeStatement) -> Vec<&Vec<NativeStatement>> {
    match statement {
        NativeStatement::IfElse {
            then_body,
            else_body,
            ..
        } => vec![then_body, else_body],
        NativeStatement::While { body, .. }
        | NativeStatement::DoWhile { body, .. }
        | NativeStatement::For { body, .. } => vec![body],
        NativeStatement::Switch { cases, default, .. } => cases
            .iter()
            .map(|(_, body)| body)
            .chain(std::iter::once(default))
            .collect(),
        _ => Vec::new(),
    }
}

fn drop_gotos_to_next_statement(statements: &mut Vec<NativeStatement>) {
    let mut index = 0;
    while index + 1 < statements.len() {
        let redundant = matches!(
            (&statements[index], &statements[index + 1]),
            (NativeStatement::Goto(target), NativeStatement::Label(label)) if target == label
        );
        if redundant {
            statements.remove(index);
            continue;
        }
        // Recurse into nested bodies, where the same shape occurs.
        for body in nested_bodies(&mut statements[index]) {
            drop_gotos_to_next_statement(body);
        }
        index += 1;
    }
    if let Some(last) = statements.last_mut() {
        for body in nested_bodies(last) {
            drop_gotos_to_next_statement(body);
        }
        match last {
            _ => {}
        }
    }
}

/// Blocks a surviving `goto` still names, which therefore need labels.
///
/// A jump reaches the tree two ways. The structurer can leave an explicit
/// `Goto` node, and a basic block can keep its own branch because no construct
/// claimed that edge. Both print a `goto`, so both need the target labelled;
/// collecting only the first kind emits a jump to a label that does not exist.
fn goto_targets(data: &Funcdata, tree: &super::structure::Structured) -> BTreeSet<GraphBlockId> {
    use super::structure::Structured;
    let mut targets = BTreeSet::new();
    let mut pending = vec![tree];
    while let Some(node) = pending.pop() {
        match node {
            Structured::Goto { target, .. } | Structured::IfGoto { target, .. } => {
                targets.insert(*target);
            }
            Structured::List(members) => pending.extend(members.iter()),
            Structured::IfElse {
                header,
                then_body,
                else_body,
                ..
            } => {
                pending.push(header);
                pending.push(then_body);
                if let Some(body) = else_body {
                    pending.push(body);
                }
            }
            Structured::WhileDo { header, body, .. } => {
                pending.push(header);
                pending.push(body);
            }
            Structured::DoWhile { body, .. } | Structured::InfLoop { body } => pending.push(body),
            Structured::Switch { header, cases, .. } => {
                pending.push(header);
                pending.extend(cases.iter().map(|(_, case)| case));
            }
            // A `break` names no target, so it needs no label.
            Structured::Break | Structured::IfBreak { .. } => {}
            Structured::Basic(block) => {
                // An unclaimed branch stays in the block that owns it, so its
                // target needs a label just as much as an explicit `Goto`'s.
                targets.extend(unclaimed_branch_targets(data, *block));
            }
        }
    }
    targets
}

/// The blocks a basic block's own surviving branch still names.
fn unclaimed_branch_targets(data: &Funcdata, block: GraphBlockId) -> Vec<GraphBlockId> {
    let branches = data
        .block(block)
        .ops
        .iter()
        .rev()
        .find(|id| !data.op(**id).dead)
        .map(|id| {
            matches!(
                data.op(*id).opcode,
                op::BRANCH | op::CBRANCH | op::BRANCHIND
            )
        })
        .unwrap_or(false);
    if !branches {
        return Vec::new();
    }
    data.block(block).successors.clone()
}

struct Emitter<'a> {
    data: &'a Funcdata,
    naming: &'a Naming,
    resolver: Resolver<'a>,
    types: &'a Types,
    /// The `for` loops the structurer recovered, keyed by the block their header
    /// enters.
    for_loops: BTreeMap<super::GraphBlockId, super::forloop::ForLoop>,
    /// The initializer and iterator operations of those loops. Ghidra calls
    /// `opMarkNonPrinting` on them, because the `for` header prints them and
    /// they must not appear a second time in the body.
    nonprinting: BTreeSet<OpId>,
    /// Needed to name SLEIGH userops: a `CALLOTHER` index means nothing without
    /// the architecture whose table defines it.
    architecture: ventris_lifter::Architecture,
}

impl Emitter<'_> {
    /// The recovered type of a value, falling back to its storage width.
    fn type_of(&self, value: super::VarnodeId) -> Type {
        self.types
            .get(value)
            .cloned()
            .unwrap_or_else(|| Type::Unsigned(self.data.varnode(value).size.saturating_mul(8)))
    }
}

impl Emitter<'_> {
    /// Statements for one construct, recursing into its parts.
    fn emit_tree(
        &self,
        node: &super::structure::Structured,
        scoped: &BTreeSet<String>,
        phi_copies: &BTreeMap<GraphBlockId, Vec<NativeStatement>>,
        targets: &BTreeSet<GraphBlockId>,
    ) -> Vec<NativeStatement> {
        // No unreachable-code pruning happens here. It looks safe — nothing
        // after an unconditional transfer can run — but a block reached only by
        // falling through carries no label, so a spurious `goto` anywhere in a
        // body made the whole rest of that body look dead. That deleted real
        // code, including entire inner loops and the calls inside them. An ugly
        // jump is a cosmetic defect; deleting a reachable statement is a wrong
        // answer, so the jump stays and gets fixed at its source instead.
        self.emit_construct(node, scoped, phi_copies, targets)
    }

    fn emit_construct(
        &self,
        node: &super::structure::Structured,
        scoped: &BTreeSet<String>,
        phi_copies: &BTreeMap<GraphBlockId, Vec<NativeStatement>>,
        targets: &BTreeSet<GraphBlockId>,
    ) -> Vec<NativeStatement> {
        use super::structure::Structured;
        match node {
            Structured::Basic(block) => {
                let mut statements = Vec::new();
                // Every block that anything reaches is labelled here, and
                // `drop_labels_nothing_needs` removes the ones that turn out
                // to be unnecessary. Deciding locally is not possible: whether
                // a block needs a label depends on what ends up emitted before
                // it, which this recursion cannot see.
                if targets.contains(block) || !self.data.block(*block).predecessors.is_empty() {
                    statements.push(NativeStatement::Label(self.data.block(*block).start));
                }
                let terminator = self.emit_body(*block, scoped, &mut statements);
                if let Some(copies) = phi_copies.get(block) {
                    statements.extend(copies.iter().cloned());
                }
                // A conditional branch's own transfer is replaced by whichever
                // construct claimed its edges; only a return or an unclaimed
                // jump still belongs here.
                statements.extend(
                    terminator
                        .into_iter()
                        .filter(|statement| !matches!(statement, NativeStatement::IfGoto { .. })),
                );
                statements
            }
            Structured::List(members) => members
                .iter()
                .flat_map(|member| self.emit_construct(member, scoped, phi_copies, targets))
                .collect(),
            Structured::IfElse {
                header,
                test,
                taken_first,
                then_body,
                else_body,
            } => {
                let mut statements = self.emit_tree(header, scoped, phi_copies, targets);
                // The construct claimed both of the header's edges, so a jump
                // the header still carries is stale. Printing it puts an `if`
                // after an unconditional transfer, which claims the test never
                // runs.
                drop_stale_header_transfer(&mut statements);
                statements.push(NativeStatement::IfElse {
                    condition: self.condition_of(test, *taken_first),
                    then_body: self.emit_tree(then_body, scoped, phi_copies, targets),
                    else_body: else_body
                        .as_ref()
                        .map(|body| self.emit_tree(body, scoped, phi_copies, targets))
                        .unwrap_or_default(),
                });
                statements
            }
            Structured::WhileDo {
                header,
                test,
                body_taken,
                body,
            } => {
                // The header runs before the first test and again after each
                // iteration, so it appears twice: once ahead of the loop and
                // once at the end of the body.
                let mut statements = self.emit_tree(header, scoped, phi_copies, targets);
                drop_stale_header_transfer(&mut statements);
                let mut inner = self.emit_tree(body, scoped, phi_copies, targets);
                let body_only = inner.clone();
                let mut repeat = self.emit_tree(header, scoped, phi_copies, targets);
                drop_stale_header_transfer(&mut repeat);
                inner.extend(repeat);
                let condition = self.condition_of(test, *body_taken);
                // A loop whose variable was found prints as a `for`, with the
                // initializer and iterator lifted into its header.
                let parts = super::structure::front_block(header)
                    .and_then(|entry| self.for_loops.get(&entry));
                if let Some(parts) = parts {
                    // The header spells exactly what the body no longer does:
                    // a statement is only lifted into it if it was suppressed.
                    let lifted = |op: OpId| {
                        self.nonprinting
                            .contains(&op)
                            .then(|| self.render(op, scoped))
                            .flatten()
                            .map(Box::new)
                    };
                    statements.push(NativeStatement::For {
                        initializer: parts.initialize.and_then(lifted),
                        condition: Some(condition),
                        step: lifted(parts.iterate),
                        // A `for` advances through its own header, so the body
                        // does not repeat the test block the way a `while` does.
                        body: body_only,
                    });
                    return statements;
                }
                statements.push(NativeStatement::While {
                    condition,
                    body: inner,
                });
                statements
            }
            Structured::DoWhile {
                body,
                test,
                body_taken,
            } => {
                vec![NativeStatement::DoWhile {
                    body: self.emit_tree(body, scoped, phi_copies, targets),
                    condition: self.condition_of(test, *body_taken),
                }]
            }
            Structured::InfLoop { body } => {
                vec![NativeStatement::While {
                    condition: Expr::Constant { value: 1, width: 1 },
                    body: self.emit_tree(body, scoped, phi_copies, targets),
                }]
            }
            Structured::Switch {
                header,
                selector,
                cases,
                has_exit,
            } => {
                let mut statements = self.emit_tree(header, scoped, phi_copies, targets);
                // The indirect transfer the header ends with is replaced by the
                // construct that claimed its edges.
                statements
                    .retain(|statement| !matches!(statement, NativeStatement::IndirectGoto(_)));
                let mut labelled = Vec::new();
                let mut default = Vec::new();
                for (label, case) in cases {
                    let mut body = self.emit_tree(case, scoped, phi_copies, targets);
                    if *has_exit {
                        body.push(NativeStatement::Break);
                    }
                    match label {
                        Some(label) => labelled.push((*label, body)),
                        None => default = body,
                    }
                }
                statements.push(NativeStatement::Switch {
                    expression: self.resolver.resolve(*selector),
                    cases: labelled,
                    default,
                });
                statements
            }
            Structured::Break => vec![NativeStatement::Break],
            Structured::IfBreak { test, taken } => {
                vec![NativeStatement::IfElse {
                    condition: self.condition_of(test, *taken),
                    then_body: vec![NativeStatement::Break],
                    else_body: Vec::new(),
                }]
            }
            Structured::Goto { target, .. } => {
                vec![NativeStatement::Goto(self.data.block(*target).start)]
            }
            Structured::IfGoto {
                test,
                taken,
                target,
            } => {
                vec![NativeStatement::IfGoto {
                    condition: self.condition_of(test, *taken),
                    target: self.data.block(*target).start,
                }]
            }
        }
    }

    /// The condition a construct evaluates, negated when the construct runs on
    /// the test's untaken side.
    fn condition_of(&self, test: &Condition, taken: bool) -> Expr {
        let condition = self.condition_expr(test);
        if taken {
            return condition;
        }
        // `ActionPreferComplement`. Ghidra does not wrap a negated branch in a
        // `!`: `Funcdata::opFlipInPlaceTest` asks whether the comparison can
        // absorb the negation, and where it can `get_booleanflip` rewrites the
        // operator — swapping the operands for the ordered ones — so the printed
        // condition is the positive form. The `!` remains only for a condition
        // that cannot absorb it.
        flip_boolean(&condition).unwrap_or_else(|| Expr::Not(Box::new(condition)))
    }

    /// The expression for a condition tree.
    ///
    /// A short-circuit operator keeps its operand order, because the second
    /// test only runs when the first did not decide the branch.
    fn condition_expr(&self, test: &Condition) -> Expr {
        match test {
            Condition::Branch { block, taken } => {
                let condition = self
                    .data
                    .block(*block)
                    .ops
                    .iter()
                    .copied()
                    .map(|op| self.data.op(op))
                    .find(|operation| operation.opcode == op::CBRANCH)
                    .and_then(|operation| operation.inputs.get(1).copied())
                    .map(|value| self.resolver.resolve(value))
                    .unwrap_or(Expr::Constant { value: 1, width: 1 });
                if *taken {
                    condition
                } else {
                    Expr::Not(Box::new(condition))
                }
            }
            Condition::Or(left, right) => Expr::Binary {
                op: crate::native::BinaryOp::LogicalOr,
                left: Box::new(self.condition_expr(left)),
                right: Box::new(self.condition_expr(right)),
            },
            Condition::And(left, right) => Expr::Binary {
                op: crate::native::BinaryOp::LogicalAnd,
                left: Box::new(self.condition_expr(left)),
                right: Box::new(self.condition_expr(right)),
            },
        }
    }

    fn run(&self) -> Vec<NativeStatement> {
        let scoped = self.scoped_names();
        let mut phi_copies: BTreeMap<GraphBlockId, Vec<NativeStatement>> = BTreeMap::new();
        for (block, copy) in self.resolver.phi_copies() {
            let copies = phi_copies.entry(block).or_default();
            // A block that reaches a join on two edges contributes the same
            // value twice; one assignment already says it.
            if !copies.contains(&copy) {
                copies.push(copy);
            }
        }

        // Blocks are emitted in address order so that a fallthrough stays
        // adjacent to its predecessor and needs no goto.
        let mut blocks: Vec<(GraphBlockId, u64)> = self
            .data
            .blocks()
            .map(|(id, block)| (id, block.start))
            .collect();
        blocks.sort_by_key(|(_, start)| *start);

        let mut emitted: Vec<(u64, Vec<NativeStatement>)> = Vec::new();
        for (index, (block, start)) in blocks.iter().copied().enumerate() {
            let mut body = Vec::new();
            let terminator = self.emit_body(block, &scoped, &mut body);
            if let Some(copies) = phi_copies.get(&block) {
                body.extend(copies.iter().cloned());
            }
            body.extend(terminator);
            let next = blocks.get(index + 1).map(|(_, start)| *start);
            if let Some(target) = self.explicit_fallthrough(block, next, &body) {
                body.push(NativeStatement::Goto(target));
            }
            emitted.push((start, body));
        }

        // A label is needed exactly where control arrives other than by
        // falling through: at every address some emitted transfer names.
        let targets: BTreeSet<u64> = emitted
            .iter()
            .flat_map(|(_, body)| body.iter())
            .filter_map(|statement| match statement {
                NativeStatement::Goto(target) | NativeStatement::IfGoto { target, .. } => {
                    Some(*target)
                }
                _ => None,
            })
            .collect();

        let mut statements = self.phi_declarations();
        for (start, body) in emitted {
            if targets.contains(&start) {
                statements.push(NativeStatement::Label(start));
            }
            statements.extend(body);
        }
        statements
    }

    /// Declares every merged value at function scope.
    ///
    /// A phi's value depends on the path taken, so its name must be visible to
    /// each assignment and to the join that reads it. C spells that as one
    /// declaration dominating every assignment.
    fn phi_declarations(&self) -> Vec<NativeStatement> {
        // A variable written at more than one place cannot be declared at each
        // of them, so it is declared once at function scope and assigned
        // afterwards. Merging is what creates these: several definitions of one
        // C variable. A merge is always such a case, because each incoming path
        // writes it.
        let mut sites: BTreeMap<String, usize> = BTreeMap::new();
        for (_, operation) in self.data.live_ops() {
            let Some(output) = operation.output else {
                continue;
            };
            if let Some(name) = self.naming.name_of(output) {
                *sites.entry(name.to_string()).or_default() += 1;
            }
        }
        let mut declarations = Vec::new();
        let mut declared: BTreeSet<String> = BTreeSet::new();
        for (_, operation) in self.data.live_ops() {
            let multiply_defined = operation
                .output
                .and_then(|output| self.naming.name_of(output))
                .and_then(|name| sites.get(name))
                .is_some_and(|count| *count > 1);
            if operation.opcode != op::MULTIEQUAL && !multiply_defined {
                continue;
            }
            let Some(output) = operation.output else {
                continue;
            };
            let Some(name) = self.naming.name_of(output) else {
                continue;
            };
            let width = self.data.varnode(output).size;
            let _ = width;
            if !declared.insert(name.to_string()) {
                continue;
            }
            declarations.push(NativeStatement::DeclareLocal {
                name: name.to_string(),
                ty: self.type_of(output),
            });
        }
        declarations
    }

    /// Emits the block's non-terminator statements, returning the terminator so
    /// the caller can place phi assignments before it.
    /// The names declared once at function scope, which later writes assign to
    /// rather than redeclare.
    fn scoped_names(&self) -> BTreeSet<String> {
        self.phi_declarations()
            .into_iter()
            .filter_map(|statement| match statement {
                NativeStatement::DeclareLocal { name, .. } => Some(name),
                _ => None,
            })
            .collect()
    }

    /// One operation as a statement, ignoring the non-printing marks. This is
    /// how the initializer and iterator reach the `for` header they belong in.
    fn render(&self, op: OpId, scoped: &BTreeSet<String>) -> Option<NativeStatement> {
        match self.classify_op(op, scoped) {
            Emission::Body(statement) | Emission::Terminator(statement) => Some(statement),
            Emission::Skip => None,
        }
    }

    fn emit_body(
        &self,
        block: GraphBlockId,
        scoped: &BTreeSet<String>,
        statements: &mut Vec<NativeStatement>,
    ) -> Vec<NativeStatement> {
        let mut terminator = Vec::new();
        for op in self.data.block(block).ops.iter().copied() {
            match self.classify(op, scoped) {
                Emission::Skip => {}
                Emission::Body(statement) => statements.push(statement),
                Emission::Terminator(statement) => terminator.push(statement),
            }
        }
        terminator
    }

    fn classify(&self, op: OpId, scoped: &BTreeSet<String>) -> Emission {
        if self.nonprinting.contains(&op) {
            return Emission::Skip;
        }
        // A copy whose two ends print as one name says nothing. These are what a
        // merge becomes when it loses all but one input, which `cutDownMultiequals`
        // leaves behind once a join has removed an edge; Ghidra's copy marking
        // reaches the same conclusion. The test is here rather than in
        // `classify_op` so that `render` can still spell such a copy when a `for`
        // header needs it as an initializer.
        let operation = self.data.op(op);
        if operation.opcode == op::COPY
            && let (Some(output), Some(input)) =
                (operation.output, operation.inputs.first().copied())
            && let Some(name) = self.naming.name_of(output)
            && self.naming.name_of(input) == Some(name)
        {
            return Emission::Skip;
        }
        self.classify_op(op, scoped)
    }

    fn classify_op(&self, op: OpId, scoped: &BTreeSet<String>) -> Emission {
        let operation = self.data.op(op);
        match operation.opcode {
            // A named result is declared where it is defined; an unnamed one
            // inlines into its reader and produces no statement here.
            op::MULTIEQUAL | op::INDIRECT => Emission::Skip,
            op::STORE => {
                let (Some(address), Some(value)) = (
                    operation.inputs.get(1).copied(),
                    operation.inputs.get(2).copied(),
                ) else {
                    return Emission::Skip;
                };
                let width = self.data.varnode(value).size;
                if let Some(field) = self.resolver.field_lvalue(address, width) {
                    return Emission::Body(NativeStatement::Assign {
                        destination: field,
                        source: self.resolver.resolve(value),
                    });
                }
                Emission::Body(NativeStatement::Store {
                    address: self
                        .resolver
                        .as_address(address, self.resolver.resolve(address)),
                    value: self.resolver.resolve(value),
                    width,
                    volatile: false,
                })
            }
            op::CALL | op::CALLIND => {
                let call = self.call_expression(op);
                match operation.output.and_then(|output| {
                    self.naming
                        .name_of(output)
                        .map(|name| (name.to_string(), output))
                }) {
                    Some((name, output)) => Emission::Body(self.bind(name, output, call, scoped)),
                    None => Emission::Body(NativeStatement::Call(call)),
                }
            }
            op::RETURN => {
                // A `RETURN`'s first operand is the return address, not a
                // result. Reading it as the result made every function claim to
                // return a value.
                let value = operation
                    .inputs
                    .get(1)
                    .copied()
                    .map(|value| self.resolver.resolve(value));
                Emission::Terminator(NativeStatement::Return(value))
            }
            op::BRANCH => match self.branch_target(op, 0) {
                Some(target) => Emission::Terminator(NativeStatement::Goto(target)),
                None => Emission::Skip,
            },
            op::CBRANCH => {
                let (Some(target), Some(condition)) =
                    (self.branch_target(op, 0), operation.inputs.get(1).copied())
                else {
                    return Emission::Skip;
                };
                Emission::Terminator(NativeStatement::IfGoto {
                    condition: self.resolver.resolve(condition),
                    target,
                })
            }
            op::BRANCHIND => match operation.inputs.first().copied() {
                Some(destination) => Emission::Terminator(NativeStatement::IndirectGoto(
                    self.resolver.resolve(destination),
                )),
                None => Emission::Skip,
            },
            // A userop is real machine behaviour. Skipping it because it has
            // no output silently deleted every coprocessor write: the N64
            // `preamble` lost six TLB and COP0 operations and rendered as a
            // loop with nothing after it.
            op::CALLOTHER => match self.userop_call(op) {
                Some(call) => match operation
                    .output
                    .and_then(|output| self.naming.name_of(output).map(|_| output))
                {
                    Some(output) => {
                        let name = self
                            .naming
                            .name_of(output)
                            .expect("checked above")
                            .to_string();
                        Emission::Body(self.bind(name, output, call, scoped))
                    }
                    None => Emission::Body(NativeStatement::Call(call)),
                },
                None => Emission::Skip,
            },
            _ => match operation.output {
                Some(output) => match self.naming.name_of(output) {
                    Some(_) => Emission::Body(self.declaration_of(output, scoped)),
                    None => Emission::Skip,
                },
                None => Emission::Skip,
            },
        }
    }

    /// A userop rendered as the pseudo-call Ghidra prints for it.
    ///
    /// Returns `None` for the userops the MIPS and Arm lifters use to record
    /// branch state, which have no source-level effect.
    fn userop_call(&self, op: OpId) -> Option<Expr> {
        let operation = self.data.op(op);
        let index = operation
            .inputs
            .first()
            .copied()
            .filter(|value| self.data.varnode(*value).flags.constant)
            .map(|value| self.data.varnode(value).offset);
        let name =
            index.and_then(|index| ventris_lifter::sleigh_userop_name(self.architecture, index));
        if operation.output.is_none()
            && (name == Some("setISAMode")
                || matches!(
                    self.architecture,
                    ventris_lifter::Architecture::Mips32
                        | ventris_lifter::Architecture::Mips32Be
                        | ventris_lifter::Architecture::Ps1
                        | ventris_lifter::Architecture::Ps2
                        | ventris_lifter::Architecture::N64
                ) && index == Some(0))
        {
            return None;
        }
        Some(Expr::Builtin {
            name: name.unwrap_or("__ventris_callother"),
            args: operation
                .inputs
                .iter()
                .skip(usize::from(name.is_some()))
                .copied()
                .map(|value| self.resolver.resolve(value))
                .collect(),
        })
    }

    fn declaration_of(
        &self,
        output: super::VarnodeId,
        scoped: &BTreeSet<String>,
    ) -> NativeStatement {
        let name = self
            .naming
            .name_of(output)
            .expect("caller checked the value is named")
            .to_string();
        let value = self.resolver.resolve_definition(output);
        self.bind(name, output, value, scoped)
    }

    /// Gives a name a value: an assignment when the name is already declared at
    /// function scope, a declaration at its single definition otherwise.
    ///
    /// A merged variable is written on several paths, so redeclaring it at each
    /// write would not compile.
    fn bind(
        &self,
        name: String,
        output: super::VarnodeId,
        value: Expr,
        scoped: &BTreeSet<String>,
    ) -> NativeStatement {
        if scoped.contains(&name) {
            return NativeStatement::Assign {
                destination: Expr::Temporary {
                    name,
                    width: self.data.varnode(output).size,
                },
                source: value,
            };
        }
        NativeStatement::Declare {
            name,
            ty: self.type_of(output),
            value,
        }
    }

    fn call_expression(&self, op: OpId) -> Expr {
        let operation = self.data.op(op);
        let mut inputs = operation.inputs.iter().copied();
        let destination = inputs.next();
        let args: Vec<Expr> = inputs.map(|value| self.resolver.resolve(value)).collect();
        match destination {
            Some(_) if self.branch_target(op, 0).is_some() => Expr::Call {
                target: self.branch_target(op, 0),
                callee: None,
                args,
            },
            Some(destination) => Expr::Call {
                target: None,
                callee: Some(Box::new(self.resolver.resolve(destination))),
                args,
            },
            None => Expr::Call {
                target: None,
                callee: None,
                args,
            },
        }
    }

    /// The address a branch or call names.
    ///
    /// A code address is a `ram` space varnode whose offset is the address, not
    /// a `const` space constant. Treating only constants as targets loses every
    /// direct branch and call, which is how a conditional branch first came out
    /// as an unconditional one.
    fn branch_target(&self, op: OpId, slot: usize) -> Option<u64> {
        let value = self.data.op(op).inputs.get(slot).copied()?;
        let varnode = self.data.varnode(value);
        // Only a `ram` space operand names a code address. A `const` space
        // operand on a branch is a p-code-relative offset for a branch *within*
        // one instruction's expansion, which the lifter has already resolved.
        // Reading it as an address produced jumps to nonsense addresses like
        // `loc_2`, and because a jump terminates the block, everything after it
        // was dropped as unreachable.
        let is_address = varnode.space == RAM_SPACE && varnode.def.is_none() && varnode.size > 0;
        is_address.then_some(varnode.offset)
    }

    /// The jump a block needs because its remaining successor is not the block
    /// emitted next.
    ///
    /// Successors an emitted transfer already names are excluded: a conditional
    /// branch's taken target is reached by its own `IfGoto`, so only the
    /// untaken edge can need a jump.
    fn explicit_fallthrough(
        &self,
        block: GraphBlockId,
        next: Option<u64>,
        emitted: &[NativeStatement],
    ) -> Option<u64> {
        let leaves = emitted.iter().any(|statement| {
            matches!(
                statement,
                NativeStatement::Goto(_)
                    | NativeStatement::IndirectGoto(_)
                    | NativeStatement::Return(_)
            )
        });
        if leaves {
            return None;
        }
        let named: BTreeSet<u64> = emitted
            .iter()
            .filter_map(|statement| match statement {
                NativeStatement::IfGoto { target, .. } | NativeStatement::Goto(target) => {
                    Some(*target)
                }
                _ => None,
            })
            .collect();
        self.data
            .block(block)
            .successors
            .iter()
            .copied()
            .map(|successor| self.data.block(successor).start)
            .find(|start| !named.contains(start) && Some(*start) != next)
    }
}

enum Emission {
    Skip,
    Body(NativeStatement),
    Terminator(NativeStatement),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{SeqNum, heritage::heritage};
    use ventris_lifter::REGISTER_SPACE;

    fn names(space: u32, offset: u64, _size: u32) -> Option<String> {
        (space == REGISTER_SPACE).then(|| format!("r{offset}"))
    }

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    #[test]
    fn a_store_renders_its_address_and_value() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let space = data.new_constant(0, 4);
        let address = data.new_constant(0x2000, 4);
        let value = data.new_constant(7, 4);
        let store = data.new_op(op::STORE, seq(0x1000), vec![space, address, value]);
        data.op_insert_end(store, block);

        let statements = emit(&data, &names, ventris_lifter::Architecture::Mips32);
        assert_eq!(
            statements,
            vec![NativeStatement::Store {
                address: Expr::Constant {
                    value: 0x2000,
                    width: 4
                },
                value: Expr::Constant { value: 7, width: 4 },
                width: 4,
                volatile: false,
            }]
        );
    }

    #[test]
    fn a_direct_call_names_its_target_and_arguments() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        // A call's target is a code address, which lives in the `ram` space.
        let target = data.new_varnode(ventris_lifter::RAM_SPACE, 0x3000, 4);
        let argument = data.new_constant(1, 4);
        let call = data.new_op(op::CALL, seq(0x1000), vec![target, argument]);
        data.op_insert_end(call, block);

        let statements = emit(&data, &names, ventris_lifter::Architecture::Mips32);
        assert_eq!(
            statements,
            vec![NativeStatement::Call(Expr::Call {
                target: Some(0x3000),
                callee: None,
                args: vec![Expr::Constant { value: 1, width: 4 }],
            })]
        );
    }

    #[test]
    fn a_return_carries_the_resolved_result() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_constant(2, 4);
        let right = data.new_constant(3, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![left, right]);
        let sum = data.new_unique(4);
        data.op_set_output(add, Some(sum));
        data.op_insert_end(add, block);
        let link = data.new_varnode(REGISTER_SPACE, 0x1f0, 8);
        let ret = data.new_op(op::RETURN, seq(0x1004), vec![link, sum]);
        data.op_insert_end(ret, block);

        let statements = emit(&data, &names, ventris_lifter::Architecture::Mips32);
        assert_eq!(
            statements,
            vec![NativeStatement::Return(Some(Expr::Binary {
                op: crate::native::BinaryOp::Add,
                left: Box::new(Expr::Constant { value: 2, width: 4 }),
                right: Box::new(Expr::Constant { value: 3, width: 4 }),
            }))]
        );
    }

    #[test]
    fn a_merged_return_value_is_assigned_on_each_path_and_then_returned() {
        let mut data = Funcdata::default();
        let entry = data.new_block(0x1000);
        let left = data.new_block(0x1010);
        let right = data.new_block(0x1020);
        let join = data.new_block(0x1030);
        data.add_edge(entry, left);
        data.add_edge(entry, right);
        data.add_edge(left, join);
        data.add_edge(right, join);
        let condition = data.new_constant(1, 1);
        let target = data.new_constant(0x1020, 4);
        let branch = data.new_op(op::CBRANCH, seq(0x1000), vec![target, condition]);
        data.op_insert_end(branch, entry);
        for (block, value) in [(left, 7u64), (right, 9u64)] {
            let start = data.block(block).start;
            let constant = data.new_constant(value, 4);
            let copy = data.new_op(op::COPY, seq(start), vec![constant]);
            let out = data.new_varnode(REGISTER_SPACE, 8, 4);
            data.op_set_output(copy, Some(out));
            data.op_insert_end(copy, block);
        }
        let read = data.new_varnode(REGISTER_SPACE, 8, 4);
        let link = data.new_varnode(REGISTER_SPACE, 0x1f0, 8);
        let ret = data.new_op(op::RETURN, seq(0x1030), vec![link, read]);
        data.op_insert_end(ret, join);

        heritage(&mut data);
        let statements = emit(&data, &names, ventris_lifter::Architecture::Mips32);

        assert!(
            statements
                .iter()
                .any(|statement| matches!(statement, NativeStatement::DeclareLocal { .. })),
            "the merged value is declared once"
        );
        let assignments: Vec<&NativeStatement> = statements
            .iter()
            .filter(|statement| matches!(statement, NativeStatement::Assign { .. }))
            .collect();
        assert_eq!(assignments.len(), 2, "each path assigns the merged value");
        let NativeStatement::Return(Some(Expr::Temporary { name, .. })) = statements
            .iter()
            .rev()
            .find(|statement| matches!(statement, NativeStatement::Return(_)))
            .expect("a return is emitted")
        else {
            panic!("the merged value must be returned by name, not dropped");
        };
        for assignment in assignments {
            let NativeStatement::Assign { destination, .. } = assignment else {
                unreachable!()
            };
            assert_eq!(
                destination,
                &Expr::Temporary {
                    name: name.clone(),
                    width: 4
                }
            );
        }
    }

    #[test]
    fn a_join_block_receives_a_label() {
        let mut data = Funcdata::default();
        let entry = data.new_block(0x1000);
        let left = data.new_block(0x1010);
        let join = data.new_block(0x1020);
        data.add_edge(entry, left);
        data.add_edge(entry, join);
        data.add_edge(left, join);
        let condition = data.new_constant(1, 1);
        let target = data.new_varnode(ventris_lifter::RAM_SPACE, 0x1020, 4);
        let branch = data.new_op(op::CBRANCH, seq(0x1000), vec![target, condition]);
        data.op_insert_end(branch, entry);
        let ret = data.new_op(op::RETURN, seq(0x1020), vec![]);
        data.op_insert_end(ret, join);

        let statements = emit(&data, &names, ventris_lifter::Architecture::Mips32);
        assert!(statements.contains(&NativeStatement::Label(0x1020)));
        assert!(statements.contains(&NativeStatement::IfGoto {
            condition: Expr::Constant { value: 1, width: 1 },
            target: 0x1020
        }));
    }

    #[test]
    fn a_shared_computation_is_assigned_once_and_reused() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_constant(2, 4);
        let right = data.new_constant(3, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![left, right]);
        let sum = data.new_unique(4);
        data.op_set_output(add, Some(sum));
        data.op_insert_end(add, block);
        let space = data.new_constant(0, 4);
        for address in [0x1004u64, 0x1008] {
            let store = data.new_op(op::STORE, seq(address), vec![space, sum, sum]);
            data.op_insert_end(store, block);
        }

        let statements = emit(&data, &names, ventris_lifter::Architecture::Mips32);
        let declarations = statements
            .iter()
            .filter(|statement| matches!(statement, NativeStatement::Declare { .. }))
            .count();
        assert_eq!(declarations, 1, "the computation is spelled once");
        for statement in &statements {
            if let NativeStatement::Store { address, value, .. } = statement {
                assert!(matches!(address, Expr::Temporary { .. }));
                assert!(matches!(value, Expr::Temporary { .. }));
            }
        }
    }

    #[test]
    fn a_userop_without_a_result_is_still_emitted() {
        // A coprocessor write has no result, and skipping every resultless
        // operation deleted it. That is real machine behaviour disappearing
        // from the output, not a cosmetic difference.
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let index = data.new_constant(9, 4);
        let value = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.mark_input(value);
        let userop = data.new_op(op::CALLOTHER, seq(0x1000), vec![index, value]);
        data.op_insert_end(userop, block);

        let names = |_: u32, _: u64, _: u32| Some("reg".to_owned());
        let statements = emit(&data, &names, ventris_lifter::Architecture::Mips32);
        assert!(
            statements
                .iter()
                .any(|statement| matches!(statement, NativeStatement::Call(Expr::Builtin { .. }))),
            "the userop was dropped: {statements:?}"
        );
    }

    #[test]
    fn the_branch_state_userop_is_not_emitted() {
        // MIPS lifters use userop zero to record branch state. It has no
        // source-level effect, so printing it would be noise.
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let index = data.new_constant(0, 4);
        let userop = data.new_op(op::CALLOTHER, seq(0x1000), vec![index]);
        data.op_insert_end(userop, block);

        let names = |_: u32, _: u64, _: u32| Some("reg".to_owned());
        let statements = emit(&data, &names, ventris_lifter::Architecture::Mips32);
        assert!(
            !statements
                .iter()
                .any(|statement| matches!(statement, NativeStatement::Call(Expr::Builtin { .. }))),
            "branch-state bookkeeping was printed: {statements:?}"
        );
    }

    #[test]
    fn a_carried_value_is_spelled_at_its_only_reader() {
        let mut statements = vec![
            NativeStatement::Declare {
                name: "iVar4".into(),
                ty: Type::Signed(32),
                value: Expr::Temporary {
                    name: "iVar3".into(),
                    width: 4,
                },
            },
            NativeStatement::Return(Some(Expr::Temporary {
                name: "iVar4".into(),
                width: 4,
            })),
        ];
        propagate_single_use_copies(&mut statements);
        assert_eq!(
            statements,
            vec![NativeStatement::Return(Some(Expr::Temporary {
                name: "iVar3".into(),
                width: 4,
            }))]
        );
    }

    #[test]
    fn a_definition_survives_when_no_use_is_replaced() {
        // Removing the definition without replacing a use leaves an undefined
        // value, which is a wrong answer rather than a tidier one.
        let mut statements = vec![
            NativeStatement::Declare {
                name: "iVar3".into(),
                ty: Type::Signed(32),
                value: Expr::Constant {
                    value: 0x70,
                    width: 4,
                },
            },
            NativeStatement::Return(Some(Expr::Temporary {
                name: "other".into(),
                width: 4,
            })),
        ];
        let before = statements.clone();
        propagate_single_use_copies(&mut statements);
        assert_eq!(statements, before);
    }

    #[test]
    fn a_value_read_twice_is_not_substituted() {
        let mut statements = vec![
            NativeStatement::Declare {
                name: "iVar3".into(),
                ty: Type::Signed(32),
                value: Expr::Temporary {
                    name: "base".into(),
                    width: 4,
                },
            },
            NativeStatement::Call(Expr::Builtin {
                name: "f",
                args: vec![Expr::Temporary {
                    name: "iVar3".into(),
                    width: 4,
                }],
            }),
            NativeStatement::Return(Some(Expr::Temporary {
                name: "iVar3".into(),
                width: 4,
            })),
        ];
        let before = statements.clone();
        propagate_single_use_copies(&mut statements);
        assert_eq!(statements, before);
    }

    #[test]
    fn a_negated_test_around_the_body_becomes_a_guard_clause() {
        let body: Vec<NativeStatement> = (0..2)
            .map(|index| NativeStatement::Assign {
                destination: Expr::Temporary {
                    name: format!("v{index}"),
                    width: 4,
                },
                source: Expr::Constant {
                    value: index,
                    width: 4,
                },
            })
            .collect();
        let mut statements = vec![
            NativeStatement::IfElse {
                condition: Expr::Not(Box::new(Expr::Temporary {
                    name: "done".into(),
                    width: 1,
                })),
                then_body: body.clone(),
                else_body: Vec::new(),
            },
            NativeStatement::Return(None),
        ];
        prefer_guard_clause(&mut statements);
        assert_eq!(
            statements[0],
            NativeStatement::IfElse {
                condition: Expr::Temporary {
                    name: "done".into(),
                    width: 1,
                },
                then_body: vec![NativeStatement::Return(None)],
                else_body: Vec::new(),
            },
            "the guard tests the case with nothing to do"
        );
        assert_eq!(&statements[1..3], &body[..]);
    }

    #[test]
    fn a_test_with_an_else_is_left_alone() {
        // An `else` already says which side is which, so inverting the test
        // would only move the bodies around.
        let mut statements = vec![
            NativeStatement::IfElse {
                condition: Expr::Temporary {
                    name: "c".into(),
                    width: 1,
                },
                then_body: vec![NativeStatement::Return(None), NativeStatement::Return(None)],
                else_body: vec![NativeStatement::Return(None)],
            },
            NativeStatement::Return(None),
        ];
        let before = statements.clone();
        prefer_guard_clause(&mut statements);
        assert_eq!(statements, before);
    }

    #[test]
    fn a_write_target_is_never_substituted() {
        // The name on the left of an assignment is written, not read. Replacing
        // it yields something that is not an lvalue.
        let mut statements = vec![
            NativeStatement::Declare {
                name: "p".into(),
                ty: Type::Unsigned(32),
                value: Expr::Constant { value: 8, width: 4 },
            },
            NativeStatement::Assign {
                destination: Expr::Temporary {
                    name: "p".into(),
                    width: 4,
                },
                source: Expr::Binary {
                    op: crate::native::BinaryOp::Add,
                    left: Box::new(Expr::Temporary {
                        name: "p".into(),
                        width: 4,
                    }),
                    right: Box::new(Expr::Constant { value: 1, width: 4 }),
                },
            },
        ];
        propagate_single_use_copies(&mut statements);
        let NativeStatement::Assign { destination, .. } = &statements[statements.len() - 1] else {
            panic!("expected the assignment to survive: {statements:?}");
        };
        assert_eq!(
            destination,
            &Expr::Temporary {
                name: "p".into(),
                width: 4,
            },
            "the assignment target must stay a name"
        );
    }

    #[test]
    fn a_deep_expression_keeps_its_name() {
        // Folding every single-use term into one statement produced a
        // 411-character line where the oracle's widest was 87.
        let mut deep = Expr::Temporary {
            name: "base".into(),
            width: 4,
        };
        for _ in 0..MAX_INLINE_DEPTH + 1 {
            deep = Expr::Binary {
                op: crate::native::BinaryOp::Or,
                left: Box::new(deep),
                right: Box::new(Expr::Constant { value: 1, width: 4 }),
            };
        }
        assert!(expression_depth(&deep) > MAX_INLINE_DEPTH);
        let mut statements = vec![
            NativeStatement::Declare {
                name: "wide".into(),
                ty: Type::Unsigned(32),
                value: deep,
            },
            NativeStatement::Return(Some(Expr::Temporary {
                name: "wide".into(),
                width: 4,
            })),
        ];
        let before = statements.clone();
        propagate_single_use_copies(&mut statements);
        assert_eq!(
            statements, before,
            "a deep expression is left behind a name"
        );
    }

    #[test]
    fn propagating_a_named_zero_leaves_no_addition() {
        // The expression builder folds a zero displacement when it builds the
        // operation, so `x + 0` can only appear later: propagation spends a name
        // that held zero and writes the literal into an addition already built.
        // That artifact put a `+ 0` beside every access the structure-offset
        // rule rewrote, and it made a label read as a call site to the census.
        let mut statements = vec![
            NativeStatement::Declare {
                name: "zero".into(),
                ty: Type::Unsigned(32),
                value: Expr::Constant { value: 0, width: 4 },
            },
            NativeStatement::Assign {
                destination: Expr::Field {
                    base: Box::new(Expr::Binary {
                        op: crate::native::BinaryOp::Add,
                        left: Box::new(Expr::Temporary {
                            name: "p".into(),
                            width: 4,
                        }),
                        right: Box::new(Expr::Temporary {
                            name: "zero".into(),
                            width: 4,
                        }),
                    }),
                    name: "field_0".into(),
                    width: 4,
                },
                source: Expr::Constant { value: 7, width: 4 },
            },
        ];
        propagate_single_use_copies(&mut statements);
        drop_assignments_nothing_reads(&mut statements);

        let destination = statements
            .iter()
            .find_map(|statement| match statement {
                NativeStatement::Assign { destination, .. } => Some(destination),
                _ => None,
            })
            .expect("the assignment survives");
        let Expr::Field { base, .. } = destination else {
            panic!("expected a field access, got {destination:?}");
        };
        assert_eq!(
            base.as_ref(),
            &Expr::Temporary {
                name: "p".into(),
                width: 4
            },
            "a propagated zero must not leave an addition behind"
        );
    }

    #[test]
    fn a_value_is_not_propagated_past_a_reassignment_inside_a_construct() {
        // The window-closing test used to look only at whether the statement
        // *was* an assignment, and the read-before-write allowance applied to
        // every statement. A construct that reassigns the name in its body and
        // then reads it therefore counted as the single reader of the old value,
        // and the old value was substituted in: `uVar6 < 1` rendered as
        // `0 < 1` on a corpus function, which is a wrong condition rather than
        // an ugly one.
        let mut statements = vec![
            NativeStatement::Declare {
                name: "v".into(),
                ty: Type::Unsigned(32),
                value: Expr::Constant { value: 0, width: 4 },
            },
            NativeStatement::IfElse {
                condition: Expr::Temporary {
                    name: "guard".into(),
                    width: 4,
                },
                then_body: vec![
                    // Reassigns `v`, so the read below is of the new value.
                    NativeStatement::Assign {
                        destination: Expr::Temporary {
                            name: "v".into(),
                            width: 4,
                        },
                        source: Expr::Temporary {
                            name: "other".into(),
                            width: 4,
                        },
                    },
                    NativeStatement::Return(Some(Expr::Temporary {
                        name: "v".into(),
                        width: 4,
                    })),
                ],
                else_body: Vec::new(),
            },
        ];
        propagate_single_use_copies(&mut statements);

        let NativeStatement::IfElse { then_body, .. } = statements
            .iter()
            .find(|statement| matches!(statement, NativeStatement::IfElse { .. }))
            .expect("the construct survives")
        else {
            unreachable!()
        };
        let returned = then_body
            .iter()
            .find_map(|statement| match statement {
                NativeStatement::Return(Some(value)) => Some(value),
                _ => None,
            })
            .expect("the return survives");
        // Within the body `v = other; return v;` legitimately collapses to
        // `return other;`. What must not happen is the outer constant reaching
        // it: the read follows a reassignment, so the old value is dead there.
        assert_ne!(
            returned,
            &Expr::Constant { value: 0, width: 4 },
            "a value was propagated past a reassignment inside the construct"
        );
    }

    #[test]
    fn a_carried_value_still_reaches_its_reader_in_a_simple_assignment() {
        // The allowance this narrows is load-bearing: `p = p + q` reads the
        // carried value before replacing it, and refusing that would give every
        // link of an address chain its own name.
        let mut statements = vec![
            NativeStatement::Declare {
                name: "p".into(),
                ty: Type::Unsigned(32),
                value: Expr::Constant { value: 8, width: 4 },
            },
            NativeStatement::Assign {
                destination: Expr::Temporary {
                    name: "p".into(),
                    width: 4,
                },
                source: Expr::Binary {
                    op: crate::native::BinaryOp::Add,
                    left: Box::new(Expr::Temporary {
                        name: "p".into(),
                        width: 4,
                    }),
                    right: Box::new(Expr::Constant { value: 1, width: 4 }),
                },
            },
        ];
        propagate_single_use_copies(&mut statements);
        assert_eq!(
            statements.len(),
            1,
            "the carried constant should reach its reader and the name disappear"
        );
    }

    #[test]
    fn a_negated_comparison_flips_its_operator_instead_of_wearing_a_bang() {
        use crate::native::BinaryOp;
        let less = Expr::Binary {
            op: BinaryOp::SignedLess,
            left: Box::new(Expr::Temporary {
                name: "x".into(),
                width: 4,
            }),
            right: Box::new(Expr::Constant { value: 1, width: 4 }),
        };
        // `!(x < 1)` is `1 <= x`: the operator flips and the operands swap,
        // because the expression tree has no `>=`.
        assert_eq!(
            flip_boolean(&less),
            Some(Expr::Binary {
                op: BinaryOp::SignedLessEqual,
                left: Box::new(Expr::Constant { value: 1, width: 4 }),
                right: Box::new(Expr::Temporary {
                    name: "x".into(),
                    width: 4
                }),
            })
        );
        // Equality absorbs the negation without reordering.
        let equal = Expr::Binary {
            op: BinaryOp::Equal,
            left: Box::new(Expr::Temporary {
                name: "x".into(),
                width: 4,
            }),
            right: Box::new(Expr::Constant { value: 0, width: 4 }),
        };
        let Some(Expr::Binary { op, left, .. }) = flip_boolean(&equal) else {
            panic!("equality should flip");
        };
        assert_eq!(op, BinaryOp::NotEqual);
        assert_eq!(
            left.as_ref(),
            &Expr::Temporary {
                name: "x".into(),
                width: 4
            },
            "an unordered comparison keeps its operand order"
        );
        // A double negation collapses, matching Ghidra's flip of `BOOL_NEGATE`
        // to a `COPY` that it then removes.
        let negated = Expr::Not(Box::new(Expr::Temporary {
            name: "flag".into(),
            width: 1,
        }));
        assert_eq!(
            flip_boolean(&negated),
            Some(Expr::Temporary {
                name: "flag".into(),
                width: 1
            })
        );
        // A plain boolean cannot absorb it, so the `!` has to stay.
        assert_eq!(
            flip_boolean(&Expr::Temporary {
                name: "flag".into(),
                width: 1
            }),
            None
        );
    }
    fn temp(name: &str) -> Expr {
        Expr::Temporary {
            name: name.into(),
            width: 4,
        }
    }

    fn assign(name: &str, source: Expr) -> NativeStatement {
        NativeStatement::Assign {
            destination: temp(name),
            source,
        }
    }

    fn minus_one(name: &str) -> Expr {
        Expr::Binary {
            op: crate::native::BinaryOp::Sub,
            left: Box::new(temp(name)),
            right: Box::new(Expr::Constant { value: 1, width: 4 }),
        }
    }

    /// A loop body's update must survive even when its only forward reader
    /// absorbs it: the next iteration reads it again through the back edge.
    #[test]
    fn a_loop_carried_update_is_not_propagated_away() {
        let mut statements = vec![NativeStatement::While {
            condition: temp("flag"),
            body: vec![
                assign("i", minus_one("i")),
                assign(
                    "flag",
                    Expr::Binary {
                        op: crate::native::BinaryOp::Equal,
                        left: Box::new(temp("i")),
                        right: Box::new(Expr::Constant { value: 0, width: 4 }),
                    },
                ),
            ],
        }];
        propagate_single_use_copies(&mut statements);
        let NativeStatement::While { body, .. } = &statements[0] else {
            panic!("expected the loop");
        };
        assert_eq!(
            body.len(),
            2,
            "the update must remain a statement, got {body:?}"
        );
        assert!(
            matches!(
                &body[0],
                NativeStatement::Assign { destination, .. }
                    if *destination == temp("i")
            ),
            "the counter's own assignment is what advances it"
        );
    }

    /// An initializer read by a following loop has more than one reader, whether
    /// or not the loop also writes the name.
    #[test]
    fn an_initializer_is_not_substituted_into_a_guard_a_loop_follows() {
        let mut statements = vec![
            assign("i", temp("count")),
            NativeStatement::While {
                condition: temp("i"),
                body: vec![assign("i", minus_one("i"))],
            },
        ];
        propagate_single_use_copies(&mut statements);
        assert_eq!(
            statements.len(),
            2,
            "the initializer must survive, got {statements:?}"
        );
        assert!(matches!(&statements[0], NativeStatement::Assign { .. }));
    }

    /// The ordered test that decides whether a construct writing a name may
    /// still be a reader of the value arriving at it.
    #[test]
    fn a_construct_reads_before_writing_unless_it_assigns_first() {
        let name = "i";
        // An `if` that assigns before reading reads only its own value.
        let assigns_first = NativeStatement::IfElse {
            condition: temp("flag"),
            then_body: vec![assign("i", temp("start")), assign("j", temp("i"))],
            else_body: Vec::new(),
        };
        assert!(!reads_before_write(&assigns_first, name));

        // The same `if` reading first does read the incoming value.
        let reads_first = NativeStatement::IfElse {
            condition: temp("flag"),
            then_body: vec![assign("j", temp("i")), assign("i", temp("start"))],
            else_body: Vec::new(),
        };
        assert!(reads_before_write(&reads_first, name));

        // A loop is circular, so assigning first proves nothing.
        let loop_assigns_first = NativeStatement::While {
            condition: temp("flag"),
            body: vec![assign("i", temp("start")), assign("j", temp("i"))],
        };
        assert!(
            reads_before_write(&loop_assigns_first, name),
            "control returns to the top, so the read can be of the incoming value"
        );
    }
    /// Thirteen walkers recursed into `if`/`while`/`do-while` only, so a
    /// no-op transfer inside a `for` body survived to the rendered output.
    #[test]
    fn a_goto_to_the_next_label_is_dropped_inside_a_for_body() {
        let mut statements = vec![NativeStatement::For {
            initializer: None,
            condition: None,
            step: None,
            body: vec![
                NativeStatement::Goto(0x2000),
                NativeStatement::Label(0x2000),
                NativeStatement::Return(None),
            ],
        }];
        drop_gotos_to_next_statement(&mut statements);
        let NativeStatement::For { body, .. } = &statements[0] else {
            panic!("the for statement is gone");
        };
        assert_eq!(
            body,
            &vec![
                NativeStatement::Label(0x2000),
                NativeStatement::Return(None)
            ]
        );
    }

    /// The same gap in `collect_read_names` was the dangerous half: liveness
    /// consults it before deleting an assignment, so a read that only happens
    /// inside a `for` or `switch` body made the assignment look dead.
    #[test]
    fn a_read_inside_a_for_body_keeps_its_assignment_alive() {
        let assignment = NativeStatement::Assign {
            destination: Expr::Temporary {
                name: "counter".into(),
                width: 4,
            },
            source: Expr::Constant { value: 0, width: 4 },
        };
        let mut statements = vec![
            assignment.clone(),
            NativeStatement::For {
                initializer: None,
                condition: None,
                step: None,
                body: vec![NativeStatement::Expression(Expr::Temporary {
                    name: "counter".into(),
                    width: 4,
                })],
            },
        ];
        let mut read = BTreeSet::new();
        collect_read_names(&statements, &mut read, false);
        assert!(
            read.contains("counter"),
            "the read inside the for was missed"
        );
        retain_live_assignments(&mut statements, &read);
        assert_eq!(statements[0], assignment);
    }

    #[test]
    fn a_read_inside_a_switch_case_keeps_its_assignment_alive() {
        let assignment = NativeStatement::Assign {
            destination: Expr::Temporary {
                name: "selected".into(),
                width: 4,
            },
            source: Expr::Constant { value: 1, width: 4 },
        };
        let mut statements = vec![
            assignment.clone(),
            NativeStatement::Switch {
                expression: Expr::Constant { value: 0, width: 4 },
                cases: vec![(
                    0,
                    vec![NativeStatement::Expression(Expr::Temporary {
                        name: "selected".into(),
                        width: 4,
                    })],
                )],
                default: Vec::new(),
            },
        ];
        let mut read = BTreeSet::new();
        collect_read_names(&statements, &mut read, false);
        assert!(
            read.contains("selected"),
            "the read inside the switch case was missed"
        );
        retain_live_assignments(&mut statements, &read);
        assert_eq!(statements[0], assignment);
    }
    /// `__osRealloc` reached its shared epilogue with five jumps where the
    /// oracle emits none: each sat in trailing position inside nested `if`s,
    /// so falling out already lands on the label.
    #[test]
    fn a_trailing_goto_nested_in_ifs_is_dropped() {
        let mut statements = vec![
            NativeStatement::IfElse {
                condition: Expr::Constant { value: 1, width: 1 },
                then_body: vec![NativeStatement::IfElse {
                    condition: Expr::Constant { value: 1, width: 1 },
                    then_body: vec![NativeStatement::Goto(0x3000)],
                    else_body: Vec::new(),
                }],
                else_body: Vec::new(),
            },
            NativeStatement::Label(0x3000),
            NativeStatement::Return(None),
        ];
        drop_trailing_gotos_to_following_label(&mut statements);
        let NativeStatement::IfElse { then_body, .. } = &statements[0] else {
            panic!("the outer if is gone");
        };
        let NativeStatement::IfElse { then_body, .. } = &then_body[0] else {
            panic!("the inner if is gone");
        };
        assert!(
            then_body.is_empty(),
            "the redundant jump survived: {then_body:?}"
        );
    }

    /// A trailing jump out of a loop is an early exit, not a fallthrough:
    /// dropping it would fall into the next iteration instead.
    #[test]
    fn a_trailing_goto_out_of_a_loop_is_kept() {
        let mut statements = vec![
            NativeStatement::While {
                condition: Expr::Constant { value: 1, width: 1 },
                body: vec![NativeStatement::Goto(0x3000)],
            },
            NativeStatement::Label(0x3000),
            NativeStatement::Return(None),
        ];
        drop_trailing_gotos_to_following_label(&mut statements);
        let NativeStatement::While { body, .. } = &statements[0] else {
            panic!("the loop is gone");
        };
        assert_eq!(body, &vec![NativeStatement::Goto(0x3000)]);
    }
}
