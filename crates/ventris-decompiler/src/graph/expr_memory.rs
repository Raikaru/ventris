//! Memory and address-space rewrites from Ghidra 12.1.3's
//! `ruleaction.cc`.
//!
//! The implementations below follow the real `applyOp` bodies for
//! `RuleEarlyRemoval`, `RuleLoadVarnode`, and `RuleStoreVarnode`.  A LOAD/STORE
//! whose address operand is a constant is already a byte address in this graph,
//! the first p-code operand's constant offset is the canonical integer space id.
//! That is enough to preserve the exact addressed location without guessing a
//! space.  The spacebase form of the C++ helper is deliberately not inferred:
//! the graph has no architecture spacebase association or address word-size
//! table.
//!
//! Requested rules are either ported below or omitted because their real
//! preconditions or rewrites are not represented by this graph:
//!
//! * `RuleExpandLoad` is registered in Ghidra's cleanup pool
//!   (`coreaction.cc:5753`).  Its decisive type queries are operation-facing:
//!   `getTypeReadFacing(defOp/op)` for the root pointer
//!   (`ruleaction.cc:10946-10961`) and `getTypeDefFacing()` for the original
//!   LOAD output (`ruleaction.cc:10981-10985`).  Ventris's
//!   `RecoveredTypes` is keyed only by Varnode and has no per-operation
//!   read-facing or definition-facing type, so substituting a per-varnode type
//!   would make the rule fire on a materially different fact.
//! * `RuleIndirectConcat` is disabled in the pinned C++ source: its
//!   `addRule` line is commented out at `coreaction.cc:5718`.  IOP-space
//!   operation references are available in this graph, but its body still
//!   needs `splitVarnode`, operation uninsertion, and address-force state.
//! * `RuleEarlyRemoval` is registered in Ghidra's `actprop` pool in the
//!   `deadcode` group (`coreaction.cc:5563`).  The graph-facing port below
//!   keeps its `isCall`, `isIndirectSource`, and no-descendant checks
//!   (`ruleaction.cc:30-35`), but deliberately refuses more aggressively for
//!   liveness: address-tied/address-force, mapped, persistent/global, volatile,
//!   and otherwise unclassified outputs are retained.  It also requires a
//!   completed graph and an internal unique-space output because the graph has
//!   no per-space `doesDeadcode`/`deadRemovalAllowedSeen` state
//!   (`ruleaction.cc:36-40`).  These named refusals can only make the rule fire
//!   less often than Ghidra.
//!
//! `deadcode::eliminate_dead_code` already removes most unread non-call and
//! non-store outputs as a separate bit-consumption pass
//! (`deadcode.rs:55-88`), but that pass is not the in-pool
//! `RuleEarlyRemoval`; registering this conservative rule can only remove an
//! operation earlier when its stricter private-temporary/completed-graph
//! proof succeeds.
//!
//! * `RuleAddrForceRelease` is disabled/commented out in the pinned source and
//!   needs `addrforce`/`terminated` flags plus `clear_addrforce`.
//! * `RuleShadowVar` is disabled/commented out in the pinned source; its
//!   quadratic previous-MULTIEQUAL scan is not an active rule to port.

use super::action::Rule;
use super::guard::Location;
use super::{Funcdata, OpId, VarnodeId};
use ventris_lifter::{RAM_SPACE, UNIQUE_SPACE};
use ventris_pcode::{CONST_SPACE, op};

fn input(data: &Funcdata, id: OpId, slot: usize) -> Option<VarnodeId> {
    data.op(id).inputs.get(slot).copied()
}

fn constant_offset(data: &Funcdata, value: VarnodeId) -> Option<u64> {
    let varnode = data.varnode(value);
    varnode.flags.constant.then_some(varnode.offset)
}

/// Read the LOAD/STORE space operand without inventing an architecture map.
///
/// Ghidra's `getSpaceFromConst()` returns an address-space object.  Ventris
/// stores that object's canonical id in the constant's offset, so the checked
/// conversion is the corresponding graph operation.
fn constant_space(data: &Funcdata, value: VarnodeId) -> Option<u32> {
    let varnode = data.varnode(value);
    if !varnode.flags.constant || varnode.space != CONST_SPACE {
        return None;
    }
    u32::try_from(varnode.offset).ok()
}

fn is_call_opcode(opcode: i32) -> bool {
    matches!(opcode, op::CALL | op::CALLIND | op::CALLOTHER | op::NEW)
}

fn is_indirect_source(data: &Funcdata, target: OpId) -> bool {
    data.live_ops().any(|(_, candidate)| {
        candidate.opcode == op::INDIRECT
            && candidate
                .inputs
                .get(1)
                .is_some_and(|annotation| data.iop_target(*annotation) == Some(target))
    })
}

fn overlaps(left: Location, right: Location) -> bool {
    left.space == right.space
        && left.offset
            <= right
                .offset
                .saturating_add(u64::from(right.size).saturating_sub(1))
        && right.offset
            <= left
                .offset
                .saturating_add(u64::from(left.size).saturating_sub(1))
}

fn location(data: &Funcdata, value: VarnodeId) -> Location {
    let varnode = data.varnode(value);
    Location {
        space: varnode.space,
        offset: varnode.offset,
        size: varnode.size,
    }
}

fn has_persistent_symbol(data: &Funcdata, value: VarnodeId) -> bool {
    let Some(scope) = data.scope_local() else {
        return false;
    };
    let location = location(data, value);
    scope.scope().entries().any(|entry| {
        entry.location().is_some_and(|storage| {
            overlaps(storage, location)
                && scope
                    .scope()
                    .entry_symbol(entry.id())
                    .is_some_and(|symbol| symbol.is_persistent())
        })
    })
}

/// The graph-facing conservative form of Ghidra's `isAutoLive`.
fn is_auto_live(data: &Funcdata, value: VarnodeId) -> bool {
    let varnode = data.varnode(value);
    if data.is_addr_tied(value) || data.is_addr_force(value) || varnode.space == RAM_SPACE {
        return true;
    }
    let location = location(data, value);
    data.scope_local()
        .is_some_and(|scope| scope.is_mapped(location))
        || has_persistent_symbol(data, value)
}

/// Only an explicitly unique, non-volatile temporary can be proven private.
fn is_private_temporary(data: &Funcdata, value: VarnodeId) -> bool {
    let flags = data.varnode(value).flags;
    flags.unique && !flags.constant && !flags.volatile && !is_auto_live(data, value)
}

/// `deadRemovalAllowedSeen` is per-space in Ghidra.  Requiring a completed
/// graph and the internal unique space is a stricter global certificate.
fn dead_removal_allowed(data: &Funcdata, value: VarnodeId) -> bool {
    data.processing_complete && data.varnode(value).space == UNIQUE_SPACE
}

/// Remove an unread operation only when the graph can prove that its output is
/// a private temporary and all stricter liveness gates have passed.
pub struct RuleEarlyRemoval;

impl Rule for RuleEarlyRemoval {
    fn name(&self) -> &'static str {
        "earlyremoval"
    }

    fn op_list(&self) -> Vec<i32> {
        (0..op::MAX).collect()
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id).clone();
        if is_call_opcode(operation.opcode) || is_indirect_source(data, id) {
            return 0;
        }
        let Some(output) = operation.output else {
            return 0;
        };
        if !data.varnode(output).descendants.is_empty()
            || !is_private_temporary(data, output)
            || !dead_removal_allowed(data, output)
        {
            return 0;
        }
        data.op_destroy(id);
        1
    }
}

/// `LOAD(space, constant-address)` -> `COPY(addressed-varnode)`.
pub struct RuleLoadVarnode;

impl Rule for RuleLoadVarnode {
    fn name(&self) -> &'static str {
        "loadvarnode"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::LOAD]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(output) = data.op(id).output else {
            return 0;
        };
        let Some(space_input) = input(data, id, 0) else {
            return 0;
        };
        let Some(address_input) = input(data, id, 1) else {
            return 0;
        };
        let Some(space) = constant_space(data, space_input) else {
            return 0;
        };
        let Some(offset) = constant_offset(data, address_input) else {
            return 0;
        };
        let size = data.varnode(output).size;
        let addressed = data.new_varnode(space, offset, size);
        data.op_set_inputs(id, vec![addressed]);
        data.op_set_opcode(id, op::COPY);
        1
    }
}

/// `STORE(space, constant-address, value)` -> `COPY(value)` with a location
/// output representing the store destination.
pub struct RuleStoreVarnode;

impl Rule for RuleStoreVarnode {
    fn name(&self) -> &'static str {
        "storevarnode"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::STORE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(space_input) = input(data, id, 0) else {
            return 0;
        };
        let Some(address_input) = input(data, id, 1) else {
            return 0;
        };
        let Some(value) = input(data, id, 2) else {
            return 0;
        };
        let Some(space) = constant_space(data, space_input) else {
            return 0;
        };
        let Some(offset) = constant_offset(data, address_input) else {
            return 0;
        };
        let size = data.varnode(value).size;
        let destination = data.new_varnode(space, offset, size);
        data.op_set_output(id, Some(destination));
        data.op_set_inputs(id, vec![value]);
        data.op_set_opcode(id, op::COPY);
        1
    }
}

#[cfg(test)]
mod tests {
    use super::super::SeqNum;
    use super::*;
    use ventris_pcode::{RAM_SPACE, REGISTER_SPACE};

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    #[test]
    fn load_varnode_fires_for_constant_address_and_preserves_space_id() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let space = data.new_constant(RAM_SPACE as u64, 4);
        let address = data.new_constant(0x8040, 4);
        let output = data.new_unique(4);
        let load = data.new_op(op::LOAD, seq(0x1000), vec![space, address]);
        data.op_set_output(load, Some(output));
        data.op_insert_end(load, block);

        assert_eq!(RuleLoadVarnode.apply_op(load, &mut data), 1);
        assert_eq!(data.op(load).opcode, op::COPY);
        assert_eq!(data.op(load).inputs.len(), 1);
        let addressed = data.varnode(data.op(load).inputs[0]);
        assert_eq!(addressed.space, RAM_SPACE);
        assert_eq!(addressed.offset, 0x8040);
        assert_eq!(addressed.size, 4);
    }

    #[test]
    fn load_varnode_declines_without_constant_address() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let space = data.new_constant(RAM_SPACE as u64, 4);
        let address = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        data.mark_input(address);
        let output = data.new_unique(4);
        let load = data.new_op(op::LOAD, seq(0x1000), vec![space, address]);
        data.op_set_output(load, Some(output));
        data.op_insert_end(load, block);

        assert_eq!(RuleLoadVarnode.apply_op(load, &mut data), 0);
        assert_eq!(data.op(load).opcode, op::LOAD);
        assert_eq!(data.op(load).inputs, vec![space, address]);
    }

    #[test]
    fn store_varnode_fires_for_constant_address_and_creates_destination() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x2000);
        let space = data.new_constant(RAM_SPACE as u64, 4);
        let address = data.new_constant(0x9000, 4);
        let value = data.new_unique(2);
        let store = data.new_op(op::STORE, seq(0x2000), vec![space, address, value]);
        data.op_insert_end(store, block);

        assert_eq!(RuleStoreVarnode.apply_op(store, &mut data), 1);
        assert_eq!(data.op(store).opcode, op::COPY);
        assert_eq!(data.op(store).inputs, vec![value]);
        let destination = data.op(store).output.expect("store destination");
        let destination = data.varnode(destination);
        assert_eq!(destination.space, RAM_SPACE);
        assert_eq!(destination.offset, 0x9000);
        assert_eq!(destination.size, 2);
    }

    #[test]
    fn store_varnode_declines_without_constant_address() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x2000);
        let space = data.new_constant(RAM_SPACE as u64, 4);
        let address = data.new_varnode(REGISTER_SPACE, 0x24, 4);
        data.mark_input(address);
        let value = data.new_unique(4);
        let store = data.new_op(op::STORE, seq(0x2000), vec![space, address, value]);
        data.op_insert_end(store, block);

        assert_eq!(RuleStoreVarnode.apply_op(store, &mut data), 0);
        assert_eq!(data.op(store).opcode, op::STORE);
        assert_eq!(data.op(store).inputs, vec![space, address, value]);
        assert!(data.op(store).output.is_none());
    }
    /// Ghidra's RuleEarlyRemoval drops only unread, non-call outputs after its
    /// liveness and dead-removal guards have admitted the storage.
    #[test]
    fn early_removal_requires_private_temporary_and_completed_graph() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x3000);
        let input = data.new_varnode(REGISTER_SPACE, 0, 4);
        let one = data.new_constant(1, 4);
        let operation = data.new_op(op::INT_ADD, seq(0x3000), vec![input, one]);
        let output = data.new_unique(4);
        data.op_set_output(operation, Some(output));
        data.op_insert_end(operation, block);

        // The missing per-space permission is treated as live until the graph
        // has reached its completed state.
        assert_eq!(RuleEarlyRemoval.apply_op(operation, &mut data), 0);
        data.processing_complete = true;
        assert_eq!(RuleEarlyRemoval.apply_op(operation, &mut data), 1);
        assert!(data.opcode_of(operation).is_none());

        let mut tied = Funcdata::default();
        let block = tied.new_block(0x3010);
        let input = tied.new_varnode(REGISTER_SPACE, 0, 4);
        let one = tied.new_constant(1, 4);
        let operation = tied.new_op(op::INT_ADD, seq(0x3010), vec![input, one]);
        let output = tied.new_varnode(REGISTER_SPACE, 0x20, 4);
        tied.op_set_output(operation, Some(output));
        tied.op_insert_end(operation, block);
        tied.processing_complete = true;
        assert_eq!(RuleEarlyRemoval.apply_op(operation, &mut tied), 0);

        let mut indirect = Funcdata::default();
        let block = indirect.new_block(0x3020);
        let input = indirect.new_varnode(REGISTER_SPACE, 0, 4);
        let one = indirect.new_constant(1, 4);
        let operation = indirect.new_op(op::INT_ADD, seq(0x3020), vec![input, one]);
        let output = indirect.new_unique(4);
        indirect.op_set_output(operation, Some(output));
        indirect.op_insert_end(operation, block);
        let marker_input = indirect.new_varnode(REGISTER_SPACE, 0x20, 4);
        let annotation = indirect.new_iop(operation);
        let marker = indirect.new_op(op::INDIRECT, seq(0x3024), vec![marker_input, annotation]);
        indirect.op_insert_end(marker, block);
        indirect.processing_complete = true;
        assert_eq!(RuleEarlyRemoval.apply_op(operation, &mut indirect), 0);
    }
}

/// Every requested rule with a faithful graph implementation.
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(RuleEarlyRemoval),
        Box::new(RuleLoadVarnode),
        Box::new(RuleStoreVarnode),
    ]
}
