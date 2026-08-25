//! Memory and address-space rewrites from Ghidra 12.1.3's
//! `ruleaction.cc`.
//!
//! The implementations below follow the real `applyOp` bodies for
//! `RuleLoadVarnode` and `RuleStoreVarnode`.  A LOAD/STORE whose address
//! operand is a constant is already a byte address in this graph, and the
//! first p-code operand's constant offset is the canonical integer space id.
//! That is enough to preserve the exact addressed location without guessing a
//! space.  The spacebase form of the C++ helper is deliberately not inferred:
//! the graph has no architecture spacebase association or address word-size
//! table.
//!
//! Requested rules omitted because their real preconditions or rewrites are
//! not represented by this graph:
//!
//! * `RuleExpandLoad` needs the read-facing pointer datatype *and* the target
//!   address-space endianness to decide both whether a narrow LOAD is the
//!   natural truncation and which byte offset to use when widening comparison
//!   constants.  `typefactory::infer` can recover a type snapshot, but
//!   `Funcdata` carries no endianness, so registering a little- or big-endian
//!   guess would change values for the other target class.
//! * `RuleIndirectConcat` is disabled in the pinned C++ source (its declaration
//!   and `applyOp` are commented out), and its body needs IOP-space operation
//!   references, `splitVarnode`, operation uninsertion, and address-force
//!   state.
//! * `RuleEarlyRemoval` needs `isIndirectSource`, `isAutoLive`, per-space
//!   dead-code policy, and `deadRemovalAllowedSeen`; deleting every
//!   no-descendant operation without those flags is unsound.
//! * `RuleAddrForceRelease` is disabled/commented out in the pinned source and
//!   needs `addrforce`/`terminated` flags plus `clear_addrforce`.
//! * `RuleShadowVar` is disabled/commented out in the pinned source; its
//!   quadratic previous-MULTIEQUAL scan is not an active rule to port.
//! * `RuleCondNegate` needs Ghidra's encoded CBRANCH boolean-flip bit and
//!   `opFlipCondition`.  `GraphOp` has no such bit, so flipping a CBRANCH
//!   without it would invert the program.

use super::action::Rule;
use super::{Funcdata, OpId, VarnodeId};
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
}

/// Every requested rule with a faithful graph implementation.
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![Box::new(RuleLoadVarnode), Box::new(RuleStoreVarnode)]
}
