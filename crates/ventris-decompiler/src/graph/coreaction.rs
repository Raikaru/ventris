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
/// Omitted from this registry:
///
/// * `ActionDirectWrite`: `GraphVarnode` has no direct-write flag or equivalent
///   storage.
/// * `ActionConstbase`: `Funcdata` has no architecture tracked-context set,
///   entry-injection payload lookup, or live-injection operation.
/// * `ActionVarnodeProps`: the graph has no auto-live-hold/action-property,
///   read-only, consumed-mask, or no-descend state required by its `apply`.
/// * `ActionForceGoto`: `Funcdata` has no override object or forced-goto
///   application API.
/// * `ActionSetCasts`: `graph::casts` exposes only the pure `needs_cast` and
///   `address_needs_cast` predicates; no graph operation stores the required
///   high-level type/union-resolution attachments, and the module exposes no
///   graph mutation or change-count entrypoint for an action to call.
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
