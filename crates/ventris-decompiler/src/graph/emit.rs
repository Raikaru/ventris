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
    }
    .run()
}

/// Emits statements following a recovered construct tree.
///
/// The label-and-goto form exists for flow no construct claimed. Everything the
/// structuring pass recovered is emitted as the construct it recovered, so no
/// later pass has to infer it back from labels.
pub fn emit_structured(
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
    let emitter = Emitter {
        data,
        naming: &naming,
        resolver,
        types,
        architecture,
    };
    let tree = super::structure::structure(data);
    let scoped = emitter.scoped_names();
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
    drop_gotos_to_next_statement(&mut statements);
    drop_trailing_gotos_to_following_label(&mut statements);
    prefer_non_empty_then(&mut statements);
    drop_self_assignments(&mut statements);
    drop_transfers_after_a_transfer(&mut statements);
    drop_labels_nothing_needs(&mut statements);
    statements
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
        match statement {
            NativeStatement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                drop_transfers_after_a_transfer(then_body);
                drop_transfers_after_a_transfer(else_body);
            }
            NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
                drop_transfers_after_a_transfer(body);
            }
            _ => {}
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
    retain_needed_labels(statements, &named, true);
}

fn collect_jump_targets(statements: &[NativeStatement], named: &mut BTreeSet<u64>) {
    for statement in statements {
        match statement {
            NativeStatement::Goto(target) | NativeStatement::IfGoto { target, .. } => {
                named.insert(*target);
            }
            NativeStatement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                collect_jump_targets(then_body, named);
                collect_jump_targets(else_body, named);
            }
            NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
                collect_jump_targets(body, named);
            }
            _ => {}
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
            NativeStatement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                retain_needed_labels(then_body, named, false);
                retain_needed_labels(else_body, named, false);
                false
            }
            NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
                retain_needed_labels(body, named, false);
                false
            }
            NativeStatement::Label(_) => after_transfer,
            _ => false,
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
            NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
                drop_trailing_gotos_to_following_label(body);
            }
            _ => {}
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

fn drop_trailing_goto(body: &mut Vec<NativeStatement>, label: u64) {
    if matches!(body.last(), Some(NativeStatement::Goto(target)) if *target == label) {
        body.pop();
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
fn drop_self_assignments(statements: &mut Vec<NativeStatement>) {
    statements.retain(|statement| match statement {
        NativeStatement::Assign {
            destination,
            source,
        } => destination != source,
        _ => true,
    });
    for statement in statements.iter_mut() {
        match statement {
            NativeStatement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                drop_self_assignments(then_body);
                drop_self_assignments(else_body);
            }
            NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
                drop_self_assignments(body);
            }
            _ => {}
        }
    }
}

/// Removes a jump to the label that immediately follows it.
///
/// The collapse surrenders an edge as a `goto` without knowing where the target
/// will be emitted. When it lands next, the jump says nothing, and it is the
/// difference between output that reads as a `goto` ladder and output that
/// reads as straight-line code.
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
        match &mut statements[index] {
            NativeStatement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                drop_gotos_to_next_statement(then_body);
                drop_gotos_to_next_statement(else_body);
            }
            NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
                drop_gotos_to_next_statement(body);
            }
            _ => {}
        }
        index += 1;
    }
    if let Some(last) = statements.last_mut() {
        match last {
            NativeStatement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                drop_gotos_to_next_statement(then_body);
                drop_gotos_to_next_statement(else_body);
            }
            NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
                drop_gotos_to_next_statement(body);
            }
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
                let mut repeat = self.emit_tree(header, scoped, phi_copies, targets);
                drop_stale_header_transfer(&mut repeat);
                inner.extend(repeat);
                statements.push(NativeStatement::While {
                    condition: self.condition_of(test, *body_taken),
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
            condition
        } else {
            Expr::Not(Box::new(condition))
        }
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
                Emission::Body(NativeStatement::Store {
                    address: self
                        .resolver
                        .as_address(address, self.resolver.resolve(address)),
                    value: self.resolver.resolve(value),
                    width: self.data.varnode(value).size,
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
}
