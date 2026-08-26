//! Core graph actions ported from Ghidra 12.1.3's `coreaction.cc`.
//!
//! `ActionDeadCode` is registerable here because `deadcode` owns a graph
//! mutation and reports the number of operations it removes.  The other
//! requested actions are intentionally not registered: this graph does not
//! carry the state their real `apply` methods mutate (direct-write marks,
//! override/forced-goto state, tracked context and injection payloads, or
//! high-level cast/type attachments).

use super::Funcdata;
use super::action::Action;

/// Remove operations whose results have no observable consumer.
///
/// The implementation and change count belong to `graph::deadcode`; this
/// wrapper only gives that pass the named `Action` interface expected by the
/// pipeline.
pub struct ActionDeadCode;

impl Action for ActionDeadCode {
    fn name(&self) -> &'static str {
        "deadcode"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        super::deadcode::eliminate_dead_code(data)
    }
}

/// Every core action whose graph mutation is representable is registered here.
///
/// Accounted for outside this registry:
///
/// * `ActionDirectWrite` is ported, in `graph::protoaction`, and registered in
///   both of Ghidra's positions by the pipeline rather than here.
/// * `ActionVarnodeProps` is ported, in `graph::varnodeprops`, for the arm that
///   is not inert; the module proves the other two are.
/// * `ActionConstbase` needs the architecture's tracked-context set and the
///   entry-injection payload. Both are inputs, not analysis: a tracked set says
///   "this register holds this constant on entry", which is how a GameCube
///   binary's small-data base gets its value. Nothing in `LoadOptions` or
///   `Hints` supplies either, so the action would iterate an empty set. Ghidra
///   run on this corpus is in the same position - its output names `unaff_r13`
///   rather than a constant - so the omission is not a divergence.
/// * `ActionForceGoto` applies `Override::applyForceGoto`. All of Ghidra's
///   override sources are user input, and nothing here can populate an
///   `Override`; this is the same reasoning that leaves `ActionRestartGroup`
///   out, recorded in `graph::action`.
/// * `ActionSetCasts` is ported as a decision rather than a pass: `graph::casts`
///   holds `castStandard`'s rule and the emitter consults it per operand, which
///   is where a cast is observable. What a graph pass would add is the
///   union-resolution attachment `tryResolutionAdjustment` makes, and
///   `DataType` has no union variant for it to resolve.
pub fn all() -> Vec<Box<dyn Action>> {
    vec![Box::new(ActionDeadCode)]
}

#[cfg(test)]
mod tests {
    use super::super::SeqNum;
    use super::*;
    use ventris_lifter::REGISTER_SPACE;
    use ventris_pcode::op;

    fn seq(address: u64, order: u32) -> SeqNum {
        SeqNum { address, order }
    }

    #[test]
    fn registry_deadcode_removes_an_unread_result_and_then_converges() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_constant(2, 4);
        let right = data.new_constant(3, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000, 0), vec![left, right]);
        let result = data.new_unique(4);
        data.op_set_output(add, Some(result));
        data.op_insert_end(add, block);

        let action = ActionDeadCode;
        assert_eq!(action.apply(&mut data), 1);
        assert_eq!(data.opcode_of(add), None);
        assert_eq!(action.apply(&mut data), 0);
    }

    #[test]
    fn registry_deadcode_declines_a_result_consumed_by_return() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x2000);
        let left = data.new_constant(2, 4);
        let right = data.new_constant(3, 4);
        let add = data.new_op(op::INT_ADD, seq(0x2000, 0), vec![left, right]);
        let result = data.new_unique(4);
        data.op_set_output(add, Some(result));
        data.op_insert_end(add, block);

        // RETURN slot 0 is the machine return address; slot 1 is the value
        // returned by the function and is therefore a dead-code sink.
        let return_address = data.new_varnode(REGISTER_SPACE, 0x1f0, 4);
        let ret = data.new_op(op::RETURN, seq(0x2004, 0), vec![return_address, result]);
        data.op_insert_end(ret, block);

        let action = ActionDeadCode;
        assert_eq!(action.apply(&mut data), 0);
        assert_eq!(data.opcode_of(add), Some(op::INT_ADD));
        assert_eq!(action.apply(&mut data), 0);
    }
}
