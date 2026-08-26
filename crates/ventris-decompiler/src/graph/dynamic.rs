//! Dynamic graph identity support ported from Ghidra 12.1.3.
//!
//! The pinned `ActionDynamicMapping::apply` and `ActionDynamicSymbols::apply`
//! only iterate `ScopeLocal::beginDynamic` entries and delegate the actual
//! lookup and mutation to `Funcdata::attemptDynamicMapping` and
//! `Funcdata::attemptDynamicMappingLate`. Ventris has no `ScopeLocal`,
//! `SymbolEntry`, or symbol attachment state, so those actions are not
//! represented here. `ActionParamShiftStart::apply` and
//! `ActionParamShiftStop::apply` are likewise not represented: their calls
//! operate on `FuncCallSpecs`, `FuncProto::paramShift`, `ParamActive`, and
//! call operands, none of which are part of this graph model.
//!
//! `DynamicHash::uniqueHash` is different. Its Varnode-side hash only needs
//! operation sequence numbers, opcodes, operands, defining operations, and
//! descendants, all of which `Funcdata` exposes. The public function below
//! ports that load-bearing identity computation without pretending to create
//! or attach symbols.
//!
//! Source authority: `ActionDynamicMapping::apply`,
//! `ActionDynamicSymbols::apply`, `ActionParamShiftStart::apply`, and
//! `ActionParamShiftStop::apply` in `coreaction.cc`; `DynamicHash` and
//! `ToOpEdge` in `dynamic.cc`/`dynamic.hh`; `Funcdata::buildDynamicSymbol`,
//! `Funcdata::attemptDynamicMapping`, and
//! `Funcdata::attemptDynamicMappingLate` in `funcdata_varnode.cc`;
//! `ScopeLocal` and `SymbolEntry` in `varmap.hh`/`database.hh`; and
//! `ParamActive`, `FuncProto::paramShift`, and `FuncCallSpecs` in
//! `fspec.hh`/`fspec.cc`, all at Ghidra commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use std::collections::BTreeSet;

use ventris_pcode::op;

use super::{Funcdata, OpId, SeqNum, VarnodeId};

const HASH_SEED: u32 = 0x3ba0_fe06;
const MAX_DUPLICATES: usize = 8;
const OUTPUT_SLOT: i32 = -1;
const HASH_SLOT_SHIFT: u32 = 32;
const HASH_OPCODE_SHIFT: u32 = 37;
const HASH_METHOD_SHIFT: u32 = 44;
const HASH_NOT_ATTACHED_SHIFT: u32 = 48;
const HASH_POSITION_SHIFT: u32 = 49;
const HASH_TOTAL_SHIFT: u32 = 52;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct ToOpEdge {
    op: OpId,
    slot: i32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct HashCandidate {
    seq: SeqNum,
    hash: u64,
}

#[derive(Default)]
struct DynamicHasher {
    mark_ops: Vec<OpId>,
    mark_varnodes: Vec<VarnodeId>,
    marked_ops: BTreeSet<OpId>,
    marked_varnodes: BTreeSet<VarnodeId>,
    staged_varnodes: Vec<VarnodeId>,
    edges: Vec<ToOpEdge>,
    op_edge_cursor: usize,
    op_cursor: usize,
    varnode_cursor: usize,
}

impl DynamicHasher {
    fn clear(&mut self) {
        self.mark_ops.clear();
        self.mark_varnodes.clear();
        self.marked_ops.clear();
        self.marked_varnodes.clear();
        self.staged_varnodes.clear();
        self.edges.clear();
        self.op_edge_cursor = 0;
        self.op_cursor = 0;
        self.varnode_cursor = 0;
    }

    fn gather_unmarked_varnodes(&mut self) {
        let staged = std::mem::take(&mut self.staged_varnodes);
        for value in staged {
            if self.marked_varnodes.insert(value) {
                self.mark_varnodes.push(value);
            }
        }
    }

    fn gather_unmarked_ops(&mut self, data: &Funcdata) {
        while self.op_edge_cursor < self.edges.len() {
            let edge = self.edges[self.op_edge_cursor];
            self.op_edge_cursor += 1;
            if self.marked_ops.insert(edge.op) {
                self.mark_ops.push(edge.op);
            }
        }
        self.mark_ops.retain(|op_id| data.op(*op_id).dead == false);
    }

    fn build_varnode_up(&mut self, data: &Funcdata, value: VarnodeId) {
        let mut current = value;
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(current) {
                return;
            }
            let Some(def) = data.varnode(current).def else {
                return;
            };
            let operation = data.op(def);
            if operation.dead {
                return;
            }
            if translated_opcode(operation.opcode).is_some() {
                self.edges.push(ToOpEdge {
                    op: def,
                    slot: OUTPUT_SLOT,
                });
                return;
            }
            let Some(next) = operation.inputs.first().copied() else {
                return;
            };
            current = next;
        }
    }

    fn build_varnode_down(&mut self, data: &Funcdata, value: VarnodeId) {
        let descendants: Vec<OpId> = data.varnode(value).descendants.iter().copied().collect();
        let edge_start = self.edges.len();
        for descendant in descendants {
            let mut operation_id = descendant;
            let mut attached_value = value;
            let mut visited = BTreeSet::new();
            loop {
                let operation = data.op(operation_id);
                if operation.dead {
                    break;
                }
                if translated_opcode(operation.opcode).is_some() {
                    if let Some(slot) = operation
                        .inputs
                        .iter()
                        .position(|input| *input == attached_value)
                    {
                        self.edges.push(ToOpEdge {
                            op: operation_id,
                            slot: slot as i32,
                        });
                    }
                    break;
                }
                if !visited.insert(operation_id) {
                    break;
                }
                let Some(output) = operation.output else {
                    break;
                };
                let Some(next_operation) = data.lone_descend(output) else {
                    break;
                };
                attached_value = output;
                operation_id = next_operation;
            }
        }
        if self.edges.len() - edge_start > 1 {
            self.edges[edge_start..].sort_by_key(|edge| {
                let sequence = data.op(edge.op).seq;
                (sequence, edge.slot)
            });
        }
    }

    fn build_op_up(&mut self, data: &Funcdata, operation: OpId) {
        self.staged_varnodes
            .extend(data.op(operation).inputs.iter().copied());
    }

    fn build_op_down(&mut self, data: &Funcdata, operation: OpId) {
        if let Some(output) = data.op(operation).output {
            self.staged_varnodes.push(output);
        }
    }

    fn calc_hash(
        &mut self,
        data: &Funcdata,
        root: VarnodeId,
        method: u32,
    ) -> Option<HashCandidate> {
        self.clear();
        self.staged_varnodes.push(root);
        self.gather_unmarked_varnodes();

        let initial_varnodes = self.mark_varnodes.len();
        for index in 0..initial_varnodes {
            self.build_varnode_up(data, self.mark_varnodes[index]);
        }
        while self.varnode_cursor < self.mark_varnodes.len() {
            let value = self.mark_varnodes[self.varnode_cursor];
            self.varnode_cursor += 1;
            self.build_varnode_down(data, value);
        }

        match method {
            0 => {}
            1 => {
                self.gather_unmarked_ops(data);
                while self.op_cursor < self.mark_ops.len() {
                    let operation = self.mark_ops[self.op_cursor];
                    self.op_cursor += 1;
                    self.build_op_up(data, operation);
                }
                self.gather_unmarked_varnodes();
                while self.varnode_cursor < self.mark_varnodes.len() {
                    let value = self.mark_varnodes[self.varnode_cursor];
                    self.varnode_cursor += 1;
                    self.build_varnode_up(data, value);
                }
            }
            2 => {
                self.gather_unmarked_ops(data);
                while self.op_cursor < self.mark_ops.len() {
                    let operation = self.mark_ops[self.op_cursor];
                    self.op_cursor += 1;
                    self.build_op_down(data, operation);
                }
                self.gather_unmarked_varnodes();
                while self.varnode_cursor < self.mark_varnodes.len() {
                    let value = self.mark_varnodes[self.varnode_cursor];
                    self.varnode_cursor += 1;
                    self.build_varnode_down(data, value);
                }
            }
            3 => {
                self.gather_unmarked_ops(data);
                while self.op_cursor < self.mark_ops.len() {
                    let operation = self.mark_ops[self.op_cursor];
                    self.op_cursor += 1;
                    self.build_op_up(data, operation);
                }
                self.gather_unmarked_varnodes();
                while self.varnode_cursor < self.mark_varnodes.len() {
                    let value = self.mark_varnodes[self.varnode_cursor];
                    self.varnode_cursor += 1;
                    self.build_varnode_down(data, value);
                }
            }
            _ => return None,
        }

        self.piece_together_hash(data, root, method)
    }

    fn piece_together_hash(
        &self,
        data: &Funcdata,
        root: VarnodeId,
        method: u32,
    ) -> Option<HashCandidate> {
        if self.edges.is_empty() {
            return None;
        }

        let root_node = data.varnode(root);
        let mut register = HASH_SEED;
        register = crc_update(register, root_node.size);
        if root_node.flags.constant {
            let mut value = root_node.offset;
            for _ in 0..root_node.size {
                register = crc_update(register, value as u32);
                value >>= 8;
            }
        }
        for edge in &self.edges {
            let operation = data.op(edge.op);
            let translated = translated_opcode(operation.opcode)?;
            register = crc_update(register, edge.slot as u32);
            register = crc_update(register, translated);
            let mut address = operation.seq.address;
            for _ in 0..8 {
                register = crc_update(register, address as u32);
                address >>= 8;
            }
        }

        let (selected_edge, attached) = self
            .edges
            .iter()
            .find_map(|edge| {
                let operation = data.op(edge.op);
                let directly_attached = if edge.slot < 0 {
                    operation.output == Some(root)
                } else {
                    operation.inputs.get(edge.slot as usize).copied() == Some(root)
                };
                directly_attached.then_some((*edge, true))
            })
            .unwrap_or((self.edges[0], false));
        let operation = data.op(selected_edge.op);
        let translated = translated_opcode(operation.opcode)? as u64;
        let slot = if selected_edge.slot < 0 {
            0x1f
        } else {
            (selected_edge.slot as u64) & 0x1f
        };

        let mut hash = u64::from(!attached) << HASH_NOT_ATTACHED_SHIFT;
        hash |= u64::from(method & 0xf) << HASH_METHOD_SHIFT;
        hash |= translated << HASH_OPCODE_SHIFT;
        hash |= slot << HASH_SLOT_SHIFT;
        hash |= u64::from(register);
        Some(HashCandidate {
            seq: operation.seq,
            hash,
        })
    }

    fn gather_first_level_varnodes(
        &self,
        data: &Funcdata,
        candidate: HashCandidate,
    ) -> Vec<VarnodeId> {
        let opcode = ((candidate.hash >> HASH_OPCODE_SHIFT) & 0x7f) as u32;
        let slot = ((candidate.hash >> HASH_SLOT_SHIFT) & 0x1f) as i32;
        let slot = if slot == 0x1f { OUTPUT_SLOT } else { slot };
        let not_attached = ((candidate.hash >> HASH_NOT_ATTACHED_SHIFT) & 1) != 0;

        let mut operations: Vec<(OpId, SeqNum)> = data
            .live_ops()
            .filter(|(_, operation)| operation.seq.address == candidate.seq.address)
            .map(|(id, operation)| (id, operation.seq))
            .collect();
        operations.sort_by_key(|(id, sequence)| (*sequence, *id));

        let mut result = Vec::new();
        let mut seen = BTreeSet::new();
        for (operation_id, _) in operations {
            let operation = data.op(operation_id);
            if translated_opcode(operation.opcode) != Some(opcode) {
                continue;
            }
            if slot < 0 {
                let Some(output) = operation.output else {
                    continue;
                };
                let mut value = output;
                if not_attached {
                    if let Some(next_operation) = data.lone_descend(value) {
                        if translated_opcode(data.op(next_operation).opcode).is_none() {
                            let Some(next_value) = data.op(next_operation).output else {
                                continue;
                            };
                            value = next_value;
                        }
                    }
                }
                if seen.insert(value) {
                    result.push(value);
                }
            } else {
                let Some(input) = operation.inputs.get(slot as usize).copied() else {
                    continue;
                };
                let mut value = input;
                if not_attached {
                    if let Some(definition) = data.varnode(value).def {
                        if translated_opcode(data.op(definition).opcode).is_none() {
                            let Some(next_value) = data.op(definition).inputs.first().copied()
                            else {
                                continue;
                            };
                            value = next_value;
                        }
                    }
                }
                if seen.insert(value) {
                    result.push(value);
                }
            }
        }
        result
    }

    fn unique_varnode(&mut self, data: &Funcdata, root: VarnodeId) -> Option<HashCandidate> {
        let mut champion = Vec::new();
        let mut champion_candidate = None;

        for method in 0..4 {
            let candidate = self.calc_hash(data, root, method)?;
            let first_level = self.gather_first_level_varnodes(data, candidate);
            let mut collisions = Vec::new();
            for value in first_level {
                let other = self.calc_hash(data, value, method)?;
                if (other.hash as u32) == (candidate.hash as u32) {
                    collisions.push(value);
                    if collisions.len() > MAX_DUPLICATES {
                        break;
                    }
                }
            }
            if collisions.len() <= MAX_DUPLICATES
                && (champion.is_empty() || collisions.len() < champion.len())
            {
                champion = collisions;
                champion_candidate = Some(candidate);
                if champion.len() == 1 {
                    break;
                }
            }
        }

        let candidate = champion_candidate?;
        let position = champion.iter().position(|value| *value == root)?;
        let total = champion.len().checked_sub(1)?;
        let hash = candidate.hash
            | ((position as u64) << HASH_POSITION_SHIFT)
            | ((total as u64) << HASH_TOTAL_SHIFT);
        Some(HashCandidate {
            seq: candidate.seq,
            hash,
        })
    }
}

/// Return Ghidra's `DynamicHash::uniqueHash` identity for a graph Varnode.
///
/// The returned sequence number is the defining or first-reading operation
/// address that Ghidra stores beside a dynamic `SymbolEntry`; the `u64` keeps
/// the original method, translated opcode, slot, attachment bit, collision
/// position, collision total, and neighborhood hash packing. The graph only
/// carries a 64-bit `SeqNum::address`, so this port feeds eight address bytes
/// into the CRC rather than guessing an architecture-specific address width.
pub fn dynamic_hash(data: &Funcdata, value: VarnodeId) -> Option<(SeqNum, u64)> {
    let mut hasher = DynamicHasher::default();
    hasher
        .unique_varnode(data, value)
        .map(|candidate| (candidate.seq, candidate.hash))
}

fn translated_opcode(opcode: i32) -> Option<u32> {
    if !(0..op::PCODE_MAX).contains(&opcode) {
        return None;
    }
    let translated = match opcode {
        op::INT_NOTEQUAL => op::INT_EQUAL,
        op::INT_SLESSEQUAL => op::INT_SLESS,
        op::INT_LESSEQUAL => op::INT_LESS,
        op::INT_SUB => op::INT_ADD,
        op::INT_LEFT => op::INT_MULT,
        op::FLOAT_NOTEQUAL => op::FLOAT_EQUAL,
        op::FLOAT_LESSEQUAL => op::FLOAT_LESS,
        45 => 0,
        op::FLOAT_SUB => op::FLOAT_ADD,
        op::CAST | op::UNIMPLEMENTED => 0,
        op::PTRADD | op::PTRSUB => op::INT_ADD,
        _ => opcode,
    };
    (translated != 0).then_some(translated as u32)
}

fn crc_update(register: u32, value: u32) -> u32 {
    let mut table_value = (register ^ value) & 0xff;
    for _ in 0..8 {
        table_value = if table_value & 1 != 0 {
            (table_value >> 1) ^ 0xedb8_8320
        } else {
            table_value >> 1
        };
    }
    table_value ^ (register >> 8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::REGISTER_SPACE;

    fn sequence(address: u64, order: u32) -> SeqNum {
        SeqNum { address, order }
    }

    fn input(data: &mut Funcdata, offset: u64) -> VarnodeId {
        let value = data.new_varnode(REGISTER_SPACE, offset, 4);
        data.mark_input(value);
        value
    }

    fn output_of(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        opcode: i32,
        seq: SeqNum,
        inputs: Vec<VarnodeId>,
    ) -> VarnodeId {
        let operation = data.new_op(opcode, seq, inputs);
        let output = data.new_unique(4);
        data.op_set_output(operation, Some(output));
        data.op_insert_end(operation, block);
        output
    }

    #[test]
    fn dynamic_hash_is_stable_for_the_same_graph_value() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let source = input(&mut data, 0x10);
        let value = output_of(
            &mut data,
            block,
            op::COPY,
            sequence(0x1000, 0),
            vec![source],
        );

        let first = dynamic_hash(&data, value);
        let second = dynamic_hash(&data, value);
        assert_eq!(first, second);
        assert!(first.is_some_and(|(_, hash)| hash != 0));
    }

    #[test]
    fn collision_position_keeps_distinct_values_identifiable() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x2000);
        let first_input = input(&mut data, 0x20);
        let second_input = input(&mut data, 0x24);
        let first = output_of(
            &mut data,
            block,
            op::INT_ADD,
            sequence(0x2000, 0),
            vec![first_input, second_input],
        );
        let second = output_of(
            &mut data,
            block,
            op::INT_ADD,
            sequence(0x2000, 1),
            vec![first_input, second_input],
        );

        let first_hash = dynamic_hash(&data, first).expect("first dynamic hash");
        let second_hash = dynamic_hash(&data, second).expect("second dynamic hash");
        assert_eq!(first_hash.0.address, second_hash.0.address);
        assert_ne!(first_hash.1, second_hash.1);
        assert_eq!((first_hash.1 >> HASH_POSITION_SHIFT) & 7, 0);
        assert_eq!((second_hash.1 >> HASH_POSITION_SHIFT) & 7, 1);
    }

    #[test]
    fn first_method_collision_advances_to_a_larger_neighborhood() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x4000);
        let common = input(&mut data, 0x30);
        let free = input(&mut data, 0x34);
        let copied = output_of(
            &mut data,
            block,
            op::COPY,
            sequence(0x3000, 0),
            vec![common],
        );
        let first = output_of(
            &mut data,
            block,
            op::INT_ADD,
            sequence(0x4000, 0),
            vec![free, common],
        );
        let second = output_of(
            &mut data,
            block,
            op::INT_ADD,
            sequence(0x4000, 1),
            vec![copied, common],
        );

        let first_hash = dynamic_hash(&data, first).expect("first dynamic hash");
        let second_hash = dynamic_hash(&data, second).expect("second dynamic hash");
        assert_eq!((first_hash.1 >> HASH_METHOD_SHIFT) & 0xf, 1);
        assert_eq!((second_hash.1 >> HASH_METHOD_SHIFT) & 0xf, 1);
        assert_ne!(first_hash.1 as u32, second_hash.1 as u32);
    }
}
