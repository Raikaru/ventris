//! Deciding which `while` loops print as `for` loops.
//!
//! Port of `BlockWhileDo::finalTransform`, `findLoopVariable`, `findInitializer`
//! and the parts of `testTerminal`/`testIterateForm` that gate the result, all
//! from Ghidra 12.1.3's `block.cc`. `ActionStructureTransform` runs the first of
//! these, and `ActionFinalStructure` the printing tests.
//!
//! A `for` loop needs three statements that a `while` loop leaves scattered: an
//! initializer in the block ahead of the loop, a condition in its header, and an
//! iterator at the end of its body. The loop variable is what ties them
//! together, and it is found from the condition rather than guessed: the value
//! the header tests must depend on a phi in the header whose loop-carried input
//! is written in the loop's tail.

use std::collections::{BTreeMap, BTreeSet};

use super::structure::{Condition, Structured, front_block};
use ventris_pcode::op;

use super::{Funcdata, GraphBlockId, OpId, VarnodeId};

/// The two statements a `for` loop lifts out of the body of a `while`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForLoop {
    /// Advances the loop variable; the last statement of the loop's tail.
    pub iterate: OpId,
    /// Gives the loop variable its first value, when the loop has one.
    pub initialize: Option<OpId>,
}

/// The recovered `for` loops of a construct tree, keyed by the block the loop
/// header enters, which is how the emitter identifies a loop.
pub fn find_for_loops(data: &Funcdata, tree: &Structured) -> BTreeMap<GraphBlockId, ForLoop> {
    let mut found = BTreeMap::new();
    walk(data, tree, &mut found);
    found
}

fn walk(data: &Funcdata, node: &Structured, found: &mut BTreeMap<GraphBlockId, ForLoop>) {
    match node {
        Structured::WhileDo {
            header, test, body, ..
        } => {
            if let (Some(entry), Some(parts)) =
                (front_block(header), for_loop(data, header, test, body))
            {
                found.insert(entry, parts);
            }
            walk(data, header, found);
            walk(data, body, found);
        }
        Structured::List(members) => {
            for member in members {
                walk(data, member, found);
            }
        }
        Structured::IfElse {
            header,
            then_body,
            else_body,
            ..
        } => {
            walk(data, header, found);
            walk(data, then_body, found);
            if let Some(body) = else_body {
                walk(data, body, found);
            }
        }
        Structured::DoWhile { body, .. } | Structured::InfLoop { body } => walk(data, body, found),
        Structured::Switch { header, cases, .. } => {
            walk(data, header, found);
            for (_, case) in cases {
                walk(data, case, found);
            }
        }
        Structured::Basic(_)
        | Structured::Goto { .. }
        | Structured::IfGoto { .. }
        | Structured::Break
        | Structured::IfBreak { .. } => {}
    }
}

/// The `for` statements of one loop, or nothing if it must stay a `while`.
fn for_loop(
    data: &Funcdata,
    header: &Structured,
    test: &Condition,
    body: &Structured,
) -> Option<ForLoop> {
    let Some(head) = front_block(header) else {
        return None; // no head
    };
    // The condition has to be a single test on a block: a short-circuit
    // condition has no one loop variable to advance.
    let Condition::Branch { block, .. } = test else {
        return None; // condition is not a single test
    };
    let condition = data
        .block(*block)
        .ops
        .iter()
        .copied()
        .map(|id| (id, data.op(id)))
        .find(|(_, operation)| operation.opcode == op::CBRANCH)
        .and_then(|(_, operation)| operation.inputs.get(1).copied());
    let Some(condition) = condition else {
        return None; // no cbranch condition
    };

    // The tail is the block the body leaves through, and it must flow only back
    // to the head - otherwise the last statement of the body is not the
    // iterator.
    let Some(tail) = tail_block(data, body, head) else {
        return None; // no single tail flowing back to the head
    };
    let slot = data
        .block(head)
        .predecessors
        .iter()
        .position(|predecessor| *predecessor == tail);
    let Some(slot) = slot else {
        return None; // tail is not a predecessor of the head
    };

    let Some((loop_def, iterate)) = find_loop_variable(data, condition, head, tail, slot) else {
        return None; // no loop variable
    };
    // `testIterateForm`: the iterator must actually read the loop variable.
    let Some(variable) = data.op(loop_def).output else {
        return None; // loop phi has no output
    };
    if !reads(data, iterate, variable) {
        return None; // iterator does not read the loop variable
    }
    Some(ForLoop {
        iterate,
        initialize: find_initializer(data, head, loop_def, slot),
    })
}

/// The block a loop body leaves through, when it leaves through exactly one that
/// flows only back to the head.
fn tail_block(data: &Funcdata, body: &Structured, head: GraphBlockId) -> Option<GraphBlockId> {
    let mut blocks = BTreeSet::new();
    super::structure::collect_blocks(body, &mut blocks);
    let mut tail = None;
    for block in blocks {
        let successors = &data.block(block).successors;
        if successors.len() == 1 && successors[0] == head {
            if tail.is_some() {
                return None; // Several tails: no single iterator statement.
            }
            tail = Some(block);
        }
    }
    tail
}

/// The loop variable's phi and the statement that advances it.
///
/// Port of `findLoopVariable`. The search starts at the tested value and walks
/// up its definitions - Ghidra bounds the walk at four - looking for a phi in
/// the head whose loop-carried input is written in the tail.
fn find_loop_variable(
    data: &Funcdata,
    condition: VarnodeId,
    head: GraphBlockId,
    tail: GraphBlockId,
    slot: usize,
) -> Option<(OpId, OpId)> {
    let root = data.varnode(condition).def?;
    if is_call_or_marker(data, root) {
        return None;
    }
    let mut path = vec![root];
    let mut seen = BTreeSet::from([root]);
    while let Some(current) = path.pop() {
        for input in data.op(current).inputs.clone() {
            let Some(definition) = data.varnode(input).def else {
                continue;
            };
            if data.op(definition).opcode == op::MULTIEQUAL {
                if data.op(definition).parent != Some(head) {
                    continue;
                }
                let Some(carried) = data.op(definition).inputs.get(slot).copied() else {
                    continue;
                };
                let Some(iterate) = data.varnode(carried).def else {
                    continue;
                };
                if data.op(iterate).parent != Some(tail) || is_call_or_marker(data, iterate) {
                    continue;
                }
                // `testTerminal` requires the statement be the last in its
                // block, and Ghidra only moves it there when that move is
                // provably safe. Requiring it already be last keeps the port on
                // the side that needs no move.
                if last_printing_op(data, tail) != Some(iterate) {
                    continue;
                }
                return Some((definition, iterate));
            }
            // Ghidra's `path[4]`: the tested value may sit up to four
            // definitions above the loop variable.
            if path.len() >= 3 || is_call_or_marker(data, definition) || !seen.insert(definition) {
                continue;
            }
            path.push(definition);
        }
    }
    None
}

/// The statement that gives the loop variable its first value.
///
/// Port of `findInitializer`. The head must have exactly two predecessors, and
/// the initializer must terminate the one that is not the loop's tail, in a
/// block that flows nowhere else.
fn find_initializer(
    data: &Funcdata,
    head: GraphBlockId,
    loop_def: OpId,
    slot: usize,
) -> Option<OpId> {
    if data.block(head).predecessors.len() != 2 {
        return None;
    }
    let entry = 1 - slot;
    let initial = data.block(head).predecessors.get(entry).copied()?;
    let value = data.op(loop_def).inputs.get(entry).copied()?;
    let definition = data.varnode(value).def?;
    if is_call_or_marker(data, definition) || data.op(definition).parent != Some(initial) {
        return None;
    }
    if data.block(initial).successors.len() != 1 {
        return None; // The initializer block must flow only into the loop.
    }
    if last_printing_op(data, initial) != Some(definition) {
        return None;
    }
    Some(definition)
}

/// Whether an operation's inputs reach a value, truncating at each definition
/// the way `testIterateForm` truncates at an explicit variable.
fn reads(data: &Funcdata, operation: OpId, value: VarnodeId) -> bool {
    let mut path = vec![operation];
    let mut seen = BTreeSet::from([operation]);
    while let Some(current) = path.pop() {
        for input in data.op(current).inputs.clone() {
            if input == value {
                return true;
            }
            if let Some(definition) = data.varnode(input).def {
                if data.op(definition).opcode != op::MULTIEQUAL && seen.insert(definition) {
                    path.push(definition);
                }
            }
        }
    }
    false
}

/// The last operation in a block that becomes a statement.
///
/// A branch never does, and the markers - phis and indirect effects - are not
/// printed either, so `testTerminal`'s "last op except for the branch" is this.
fn last_printing_op(data: &Funcdata, block: GraphBlockId) -> Option<OpId> {
    data.block(block)
        .ops
        .iter()
        .copied()
        .filter(|id| {
            !matches!(
                data.op(*id).opcode,
                op::CBRANCH
                    | op::BRANCH
                    | op::BRANCHIND
                    | op::RETURN
                    | op::MULTIEQUAL
                    | op::INDIRECT
            )
        })
        .next_back()
}

fn is_call_or_marker(data: &Funcdata, operation: OpId) -> bool {
    matches!(
        data.op(operation).opcode,
        op::CALL | op::CALLIND | op::CALLOTHER | op::MULTIEQUAL | op::INDIRECT
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gates are all conjunctive, so a shape that fails one must not
    /// produce a `for`. This pins the two that carry the most weight: a
    /// condition that is not a single test, and a loop with no single tail.
    #[test]
    fn a_short_circuit_condition_never_becomes_a_for_loop() {
        let data = Funcdata::default();
        let header = Structured::Basic(GraphBlockId(0));
        let body = Structured::Basic(GraphBlockId(1));
        let test = Condition::And(
            Box::new(Condition::Branch {
                block: GraphBlockId(0),
                taken: true,
            }),
            Box::new(Condition::Branch {
                block: GraphBlockId(1),
                taken: true,
            }),
        );
        assert_eq!(
            for_loop(&data, &header, &test, &body),
            None,
            "a short-circuit condition has no single loop variable to advance"
        );
    }

    #[test]
    fn a_tree_with_no_loops_recovers_no_for_loops() {
        let data = Funcdata::default();
        let tree = Structured::List(vec![
            Structured::Basic(GraphBlockId(0)),
            Structured::Basic(GraphBlockId(1)),
        ]);
        assert!(find_for_loops(&data, &tree).is_empty());
    }
}
