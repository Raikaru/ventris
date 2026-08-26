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

/// The block whose branch decides a condition.
///
/// A short-circuit chain is evaluated left to right and the *last* test is the one
/// that transfers, so that is the block holding the `CBRANCH` Ghidra reads the
/// loop variable from.
fn deciding_block(test: &Condition) -> Option<GraphBlockId> {
    match test {
        Condition::Branch { block, .. } => Some(*block),
        Condition::Or(_, last) | Condition::And(_, last) => deciding_block(last),
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
    // Ghidra reads the loop variable off the loop's own `CBRANCH`, whatever the
    // condition spans: `findLoopVariable` takes `cbranch->getIn(1)` and walks the
    // data flow back to a `MULTIEQUAL` in the head. A short-circuit condition
    // still has exactly one deciding branch - its last test - so refusing them
    // cost both of `queryMapAddress_single`'s `for` loops, whose conditions in
    // the oracle are `&&` chains.
    let Some(block) = deciding_block(test) else {
        return None; // condition names no branch
    };
    let condition = data
        .block(block)
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
    slot_of_tail: usize,
) -> Option<(OpId, OpId)> {
    let root = data.varnode(condition).def?;
    if is_call_or_marker(data, root) {
        return None;
    }
    // Ghidra's exact walk: a depth-first cursor over `path[4]`, each frame
    // remembering which operand it has reached, bounded at four frames. Ours had
    // used a work stack with a visited set and bounded the stack's *length*. The
    // visited set is the substantive difference - Ghidra has none, and will reach
    // the same definition again by a second route, which is how it finds the loop
    // variable of `queryMapAddress_single`'s second `for`.
    let mut path: Vec<(OpId, usize)> = vec![(root, 0)];
    while let Some((current, slot)) = path.pop() {
        let inputs = data.op(current).inputs.clone();
        if slot >= inputs.len() {
            continue;
        }
        // Advance this frame's cursor before descending, as `path[count].slot++`
        // does, so the frame resumes at the next operand when the child returns.
        path.push((current, slot + 1));
        let input = inputs[slot];
        let Some(definition) = data.varnode(input).def else {
            continue;
        };
        if data.op(definition).opcode == op::MULTIEQUAL {
            if data.op(definition).parent != Some(head) {
                continue;
            }
            let Some(carried) = data.op(definition).inputs.get(slot_of_tail).copied() else {
                continue;
            };
            let Some(iterate) = data.varnode(carried).def else {
                continue;
            };
            if data.op(iterate).parent != Some(tail) || is_call_or_marker(data, iterate) {
                continue;
            }
            // `testTerminal` wants the statement last in its block, and Ghidra
            // moves it to the end of the tail rather than requiring it be there,
            // so long as the move is safe - which `is_moveable` checks.
            let Some(last) = last_printing_op(data, tail) else {
                continue;
            };
            if !is_moveable(data, iterate, last) {
                continue;
            }
            return Some((definition, iterate));
        }
        // `if (count == 3) continue;`: four frames, so a tested value may sit up
        // to four definitions above the loop variable.
        if path.len() >= 4 || is_call_or_marker(data, definition) {
            continue;
        }
        path.push((definition, 0));
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

    /// `findLoopVariable` walks up to four frames above the tested value, each
    /// frame remembering which operand it has reached. Bounding the work stack's
    /// length instead cut the walk short of a loop variable that far up.
    #[test]
    fn a_loop_variable_high_above_the_test_is_found() {
        use crate::graph::SeqNum;
        use ventris_lifter::REGISTER_SPACE;
        let seq = |address: u64| SeqNum { address, order: 0 };
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let head = data.new_block(0x1000);
        let tail = data.new_block(0x1010);
        let exit = data.new_block(0x1020);
        data.add_edge(head, tail);
        data.add_edge(head, exit);
        data.add_edge(tail, head);

        // The loop variable, merged at the head from an entry value and the tail.
        let entry_value = data.new_constant(0, 4);
        let carried = data.new_varnode(REGISTER_SPACE, 16, 4);
        let phi = data.new_op(op::MULTIEQUAL, seq(0x1000), vec![entry_value, carried]);
        let merged = data.new_varnode(REGISTER_SPACE, 16, 4);
        data.op_set_output(phi, Some(merged));
        data.op_insert_end(phi, head);

        // Four definitions between the merged value and the tested one.
        let mut value = merged;
        for step in 0..3u64 {
            let zero = data.new_constant(0, 4);
            let op = data.new_op(op::INT_ADD, seq(0x1002 + step), vec![value, zero]);
            let out = data.new_unique(4);
            data.op_set_output(op, Some(out));
            data.op_insert_end(op, head);
            value = out;
        }
        let condition = data.new_unique(1);
        let zero = data.new_constant(0, 4);
        let test = data.new_op(op::INT_NOTEQUAL, seq(0x1008), vec![value, zero]);
        data.op_set_output(test, Some(condition));
        data.op_insert_end(test, head);
        let destination = data.new_varnode(ventris_lifter::RAM_SPACE, 0x1010, 4);
        let branch = data.new_op(op::CBRANCH, seq(0x1009), vec![destination, condition]);
        data.op_insert_end(branch, head);

        // The iterator, last in the tail.
        let one = data.new_constant(1, 4);
        let iterate = data.new_op(op::INT_ADD, seq(0x1010), vec![merged, one]);
        data.op_set_output(iterate, Some(carried));
        data.op_insert_end(iterate, tail);

        let found = find_loop_variable(&data, condition, head, tail, 1);
        assert_eq!(
            found.map(|(_, iterate)| iterate),
            Some(iterate),
            "the loop variable sits at the top of the four frames"
        );
    }

    /// Ghidra's `findLoopVariable` reads the loop variable off the loop's own
    /// `CBRANCH` whatever the condition spans, so a short-circuit chain is not
    /// disqualifying - its *last* test is the one that transfers. Refusing them
    /// outright cost both of `queryMapAddress_single`'s `for` loops, whose
    /// conditions in the oracle are `&&` chains.
    #[test]
    fn a_short_circuit_condition_is_decided_by_its_last_test() {
        let branch = |block: u32| Condition::Branch {
            block: GraphBlockId(block),
            taken: true,
        };
        assert_eq!(deciding_block(&branch(3)), Some(GraphBlockId(3)));
        assert_eq!(
            deciding_block(&Condition::And(Box::new(branch(0)), Box::new(branch(1)))),
            Some(GraphBlockId(1)),
            "the second arm is evaluated last"
        );
        assert_eq!(
            deciding_block(&Condition::Or(
                Box::new(branch(0)),
                Box::new(Condition::And(Box::new(branch(1)), Box::new(branch(2))))
            )),
            Some(GraphBlockId(2)),
            "the deciding test is the innermost last one"
        );
    }

    /// The remaining gates are conjunctive, so a shape that fails one must not
    /// produce a `for`. Here the deciding block holds no branch at all.
    #[test]
    fn a_condition_with_no_branch_never_becomes_a_for_loop() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let head = data.new_block(0x1000);
        let tail = data.new_block(0x1010);
        data.add_edge(head, tail);
        data.add_edge(tail, head);
        let test = Condition::And(
            Box::new(Condition::Branch {
                block: head,
                taken: true,
            }),
            Box::new(Condition::Branch {
                block: tail,
                taken: true,
            }),
        );
        assert_eq!(
            for_loop(
                &data,
                &Structured::Basic(head),
                &test,
                &Structured::Basic(tail)
            ),
            None,
            "no CBRANCH in the deciding block means no loop variable"
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
    /// A for-loop's iterator has to end the body, and Ghidra moves it there
    /// rather than insisting it already is. The move must not cross a read of
    /// the value it produces, nor carry a memory write across another.
    #[test]
    fn an_operation_moves_down_unless_something_in_between_conflicts() {
        use crate::graph::SeqNum;
        let seq = |address: u64| SeqNum { address, order: 0 };
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let counter = data.new_varnode(ventris_lifter::REGISTER_SPACE, 0, 4);
        let one = data.new_constant(1, 4);

        // step: counter - 1
        let step = data.new_op(op::INT_SUB, seq(0x1000), vec![counter, one]);
        let stepped = data.new_unique(4);
        data.op_set_output(step, Some(stepped));
        data.op_insert_end(step, block);
        // Two unrelated computations follow it.
        let filler = data.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
        let mut last = step;
        for _ in 0..2 {
            let held = data.new_op(op::INT_ADD, seq(0x1004), vec![filler, one]);
            let out = data.new_unique(4);
            data.op_set_output(held, Some(out));
            data.op_insert_end(held, block);
            last = held;
        }
        assert!(
            is_moveable(&data, step, last),
            "nothing in between touches the value or its operands"
        );
        assert!(is_moveable(&data, step, step), "no movement is needed");

        // A reader of the stepped value in between blocks the move.
        let reader = data.new_op(op::INT_ADD, seq(0x1008), vec![stepped, one]);
        let out = data.new_unique(4);
        data.op_set_output(reader, Some(out));
        data.op_insert_end(reader, block);
        let tail = data.new_op(op::INT_ADD, seq(0x100c), vec![filler, one]);
        let tail_out = data.new_unique(4);
        data.op_set_output(tail, Some(tail_out));
        data.op_insert_end(tail, block);
        assert!(
            !is_moveable(&data, step, tail),
            "the result cannot move past something that reads it"
        );
    }

    /// A memory operand cannot be reordered against a store that might alias it.
    #[test]
    fn a_memory_operand_does_not_cross_a_store() {
        use crate::graph::SeqNum;
        let seq = |address: u64| SeqNum { address, order: 0 };
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let held = data.new_varnode(ventris_lifter::RAM_SPACE, 0x2000, 4);
        let one = data.new_constant(1, 4);
        let step = data.new_op(op::INT_SUB, seq(0x1000), vec![held, one]);
        let stepped = data.new_unique(4);
        data.op_set_output(step, Some(stepped));
        data.op_insert_end(step, block);

        let address = data.new_varnode(ventris_lifter::REGISTER_SPACE, 0, 4);
        let space = data.new_constant(u64::from(ventris_lifter::RAM_SPACE), 4);
        let store = data.new_op(op::STORE, seq(0x1004), vec![space, address, one]);
        data.op_insert_end(store, block);
        assert!(
            !is_moveable(&data, step, store),
            "the store may write the location the operand reads"
        );
    }
}

/// Whether an operation can move down to a point in its own block.
///
/// Port of `PcodeOp::isMoveable`. A for-loop's iterator has to be the last
/// statement of the body, and Ghidra moves it there instead of insisting it
/// already is. The move is refused when it would cross a read of its own result,
/// when it would carry a memory access across a conflicting one, or when either
/// end is tied to an address that something in between also touches.
fn is_moveable(data: &Funcdata, operation: OpId, point: OpId) -> bool {
    if operation == point {
        return true; // No movement necessary.
    }
    let held = data.op(operation);
    let moving_load = held.opcode == op::LOAD;
    if is_special(held.opcode) && !moving_load {
        return false; // Anything else special stays where it is.
    }
    let Some(block) = held.parent else {
        return false;
    };
    if data.op(point).parent != Some(block) {
        return false; // Not in the same block.
    }
    let ops = &data.block(block).ops;
    let (Some(from), Some(to)) = (
        ops.iter().position(|id| *id == operation),
        ops.iter().position(|id| *id == point),
    ) else {
        return false;
    };
    if from > to {
        return false; // This is a move downwards only.
    }
    // The result cannot move past anything that reads it.
    if let Some(output) = held.output {
        for reader in data.varnode(output).descendants.iter().copied() {
            if data.op(reader).parent != Some(block) {
                continue;
            }
            if ops
                .iter()
                .position(|id| *id == reader)
                .is_some_and(|at| at <= to)
            {
                return false;
            }
        }
    }
    // A value in a location the program can name elsewhere cannot be reordered
    // against anything that might touch that location.
    let tied: Vec<VarnodeId> = held
        .inputs
        .iter()
        .copied()
        .filter(|value| is_addrtied(data, *value))
        .collect();
    let output_tied = held.output.is_some_and(|value| is_addrtied(data, value));
    // Crossing a call needs every operand and the result to be untied.
    let cross_calls = !is_special(held.opcode)
        && held.output.is_some()
        && !output_tied
        && held.inputs.iter().all(|value| !is_addrtied(data, *value));
    for crossed in ops[from + 1..=to].iter().copied() {
        let over = data.op(crossed);
        if is_special(over.opcode) {
            match over.opcode {
                op::LOAD => {
                    if output_tied {
                        return false;
                    }
                }
                op::STORE => {
                    if moving_load || !tied.is_empty() || output_tied {
                        return false;
                    }
                }
                // These say something happened without saying what, so they do
                // not themselves conflict.
                op::INDIRECT | op::SEGMENTOP | op::CPOOLREF => {}
                op::CALL | op::CALLIND => {
                    if !cross_calls {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        if let Some(written) = over.output {
            if moving_load && is_addrtied(data, written) {
                return false;
            }
            if tied.iter().any(|value| overlaps(data, *value, written)) {
                return false;
            }
        }
    }
    true
}

/// An operation whose effect is more than computing its result.
fn is_special(opcode: i32) -> bool {
    matches!(
        opcode,
        op::LOAD
            | op::STORE
            | op::CALL
            | op::CALLIND
            | op::CALLOTHER
            | op::RETURN
            | op::BRANCH
            | op::CBRANCH
            | op::BRANCHIND
            | op::INDIRECT
            | op::MULTIEQUAL
            | op::SEGMENTOP
            | op::CPOOLREF
            | op::NEW
    )
}

/// Whether a value lives at an address the rest of the program can name.
///
/// Ghidra carries this as `addrtied`/`persist` flags. This model has no such
/// flag, so the question is answered from the storage: a value in memory can be
/// reached through a pointer and so conflicts with any access that might alias
/// it, while a register or a temporary cannot. A volatile value conflicts with
/// everything by definition.
fn is_addrtied(data: &Funcdata, value: VarnodeId) -> bool {
    let varnode = data.varnode(value);
    varnode.flags.volatile || varnode.space == ventris_lifter::RAM_SPACE
}

/// Whether two values share any byte of storage.
fn overlaps(data: &Funcdata, first: VarnodeId, second: VarnodeId) -> bool {
    let (left, right) = (data.varnode(first), data.varnode(second));
    if left.space != right.space {
        return false;
    }
    let left_end = left.offset.saturating_add(u64::from(left.size));
    let right_end = right.offset.saturating_add(u64::from(right.size));
    left.offset < right_end && right.offset < left_end
}
