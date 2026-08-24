//! A mutable p-code data-flow graph, ported from Ghidra 12.1.3's `Funcdata`.
//!
//! Ghidra's decompiler is not a pipeline of expression builders. Every one of
//! its Actions and Rules rewrites a live graph of `Varnode`s and `PcodeOp`s in
//! place: it sets an operand, inserts an op before another, replaces a varnode
//! everywhere it is read, and deletes what becomes unreachable. `Heritage`
//! inserts MULTIEQUAL and INDIRECT ops into that graph; type inference walks
//! it; `Merge` coalesces varnodes across it; the printer consumes what is left.
//!
//! Ventris previously built C expressions directly from immutable lifter
//! output, which makes those algorithms unportable: there is nowhere to insert
//! the SUBPIECE that a refined sub-register read needs, and no descendant list
//! to redirect when a rule replaces a value. This module supplies the missing
//! object model so the passes can be ported rather than reinvented.
//!
//! Source authority: `varnode.hh`, `op.hh`, `funcdata.hh`, `funcdata_varnode.cc`,
//! `funcdata_op.cc` at commit `8b4c91d4d5bd1549622bfbade0df199585b98365`.

pub mod guard;
pub mod heritage;
pub mod refine;

use std::collections::{BTreeMap, BTreeSet};

use ventris_lifter::{CONST_SPACE, NativeFunction, UNIQUE_SPACE};
use ventris_pcode::{PcodeOp, Varnode};

/// Index of a varnode in a [`Funcdata`] arena.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct VarnodeId(pub u32);

/// Index of an operation in a [`Funcdata`] arena.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct OpId(pub u32);

/// Index of a basic block in a [`Funcdata`] arena.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct GraphBlockId(pub u32);

/// Varnode properties that the ported passes depend on.
///
/// Ghidra keeps thirty-two flags on every varnode. Only the ones a ported pass
/// actually reads are modelled here; adding a flag without a consumer would be
/// unverifiable decoration.
#[derive(Copy, Clone, Default, PartialEq, Eq, Debug)]
pub struct VarnodeFlags {
    /// The varnode holds a constant, so it has no defining operation.
    pub constant: bool,
    /// The varnode enters the function without a definition.
    pub input: bool,
    /// The varnode has a defining operation.
    pub written: bool,
    /// The varnode is a compiler temporary rather than a machine location.
    pub unique: bool,
    /// Reads and writes of this location may not be reordered or removed.
    pub volatile: bool,
}

/// One value in the data-flow graph.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GraphVarnode {
    pub space: u32,
    pub offset: u64,
    pub size: u32,
    pub flags: VarnodeFlags,
    /// The operation that writes this value, when it has one.
    pub def: Option<OpId>,
    /// Every operation that reads this value. Ghidra calls these descendants,
    /// and keeping them current is what makes a value replacement O(uses).
    pub descendants: BTreeSet<OpId>,
}

impl GraphVarnode {
    /// The location as a plain lifter varnode.
    pub fn location(&self) -> Varnode {
        Varnode::new(self.space, self.offset, self.size)
    }

    /// Whether this value and `other` share any byte of storage.
    pub fn overlaps(&self, other: &Self) -> bool {
        self.space == other.space
            && self.offset < other.offset.saturating_add(u64::from(other.size))
            && other.offset < self.offset.saturating_add(u64::from(self.size))
    }
}

/// Position of an operation within the function, mirroring Ghidra's `SeqNum`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SeqNum {
    pub address: u64,
    pub order: u32,
}

/// One operation in the data-flow graph.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GraphOp {
    pub opcode: i32,
    pub seq: SeqNum,
    pub output: Option<VarnodeId>,
    pub inputs: Vec<VarnodeId>,
    pub parent: Option<GraphBlockId>,
    /// Set when the operation has been removed from the graph but its slot is
    /// retained so existing identifiers stay valid.
    pub dead: bool,
}

/// One basic block, holding its operations in execution order.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct GraphBlock {
    pub start: u64,
    pub ops: Vec<OpId>,
    pub predecessors: Vec<GraphBlockId>,
    pub successors: Vec<GraphBlockId>,
}

/// A function's mutable p-code graph.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Funcdata {
    pub entry: u64,
    varnodes: Vec<GraphVarnode>,
    ops: Vec<GraphOp>,
    blocks: Vec<GraphBlock>,
    /// Interning table so one machine location yields one varnode per version.
    located: BTreeMap<(u32, u64, u32), Vec<VarnodeId>>,
    next_unique: u64,
}

impl Funcdata {
    pub fn varnode(&self, id: VarnodeId) -> &GraphVarnode {
        &self.varnodes[id.0 as usize]
    }

    pub fn op(&self, id: OpId) -> &GraphOp {
        &self.ops[id.0 as usize]
    }

    pub fn block(&self, id: GraphBlockId) -> &GraphBlock {
        &self.blocks[id.0 as usize]
    }

    pub fn blocks(&self) -> impl Iterator<Item = (GraphBlockId, &GraphBlock)> {
        self.blocks
            .iter()
            .enumerate()
            .map(|(index, block)| (GraphBlockId(index as u32), block))
    }

    pub fn live_ops(&self) -> impl Iterator<Item = (OpId, &GraphOp)> {
        self.ops
            .iter()
            .enumerate()
            .filter(|(_, op)| !op.dead)
            .map(|(index, op)| (OpId(index as u32), op))
    }

    pub fn varnode_count(&self) -> usize {
        self.varnodes.len()
    }

    pub fn op_count(&self) -> usize {
        self.ops.iter().filter(|op| !op.dead).count()
    }

    /// Creates a value at a machine location. Each call produces a distinct
    /// varnode, because SSA needs one identity per definition of a location.
    pub fn new_varnode(&mut self, space: u32, offset: u64, size: u32) -> VarnodeId {
        let id = VarnodeId(self.varnodes.len() as u32);
        self.varnodes.push(GraphVarnode {
            space,
            offset,
            size,
            flags: VarnodeFlags {
                unique: space == UNIQUE_SPACE,
                ..VarnodeFlags::default()
            },
            def: None,
            descendants: BTreeSet::new(),
        });
        self.located
            .entry((space, offset, size))
            .or_default()
            .push(id);
        id
    }

    /// Creates a fresh temporary, as Ghidra's `newUnique` does.
    pub fn new_unique(&mut self, size: u32) -> VarnodeId {
        let offset = self.next_unique;
        self.next_unique = self.next_unique.saturating_add(u64::from(size).max(1));
        self.new_varnode(UNIQUE_SPACE, offset, size)
    }

    pub fn new_constant(&mut self, value: u64, size: u32) -> VarnodeId {
        let id = self.new_varnode(CONST_SPACE, value, size);
        self.varnodes[id.0 as usize].flags.constant = true;
        id
    }

    /// Marks a value as entering the function without a definition.
    pub fn mark_input(&mut self, id: VarnodeId) {
        self.varnodes[id.0 as usize].flags.input = true;
    }

    /// Every varnode recorded at one exact location, oldest first.
    pub fn at_location(&self, space: u32, offset: u64, size: u32) -> &[VarnodeId] {
        self.located
            .get(&(space, offset, size))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// The single operation reading a value, when there is exactly one.
    ///
    /// Ghidra's `loneDescend`: a refinement rewrite is only valid on a value
    /// with one reader, because the rewrite replaces that operand.
    pub fn lone_descend(&self, id: VarnodeId) -> Option<OpId> {
        let descendants = &self.varnode(id).descendants;
        (descendants.len() == 1).then(|| *descendants.iter().next().expect("one descendant"))
    }

    pub fn new_block(&mut self, start: u64) -> GraphBlockId {
        let id = GraphBlockId(self.blocks.len() as u32);
        self.blocks.push(GraphBlock {
            start,
            ..GraphBlock::default()
        });
        id
    }

    pub fn add_edge(&mut self, from: GraphBlockId, to: GraphBlockId) {
        let successors = &mut self.blocks[from.0 as usize].successors;
        if !successors.contains(&to) {
            successors.push(to);
        }
        let predecessors = &mut self.blocks[to.0 as usize].predecessors;
        if !predecessors.contains(&from) {
            predecessors.push(from);
        }
    }

    /// Creates an unattached operation. It becomes live once inserted.
    pub fn new_op(&mut self, opcode: i32, seq: SeqNum, inputs: Vec<VarnodeId>) -> OpId {
        let id = OpId(self.ops.len() as u32);
        self.ops.push(GraphOp {
            opcode,
            seq,
            output: None,
            inputs: Vec::new(),
            parent: None,
            dead: false,
        });
        for (slot, input) in inputs.into_iter().enumerate() {
            self.op_set_input(id, input, slot);
        }
        id
    }

    /// Sets one operand, maintaining the descendant list on both sides.
    pub fn op_set_input(&mut self, op: OpId, value: VarnodeId, slot: usize) {
        let previous = self.ops[op.0 as usize].inputs.get(slot).copied();
        if let Some(previous) = previous
            && previous != value
            && !self.ops[op.0 as usize]
                .inputs
                .iter()
                .enumerate()
                .any(|(index, input)| index != slot && *input == previous)
        {
            self.varnodes[previous.0 as usize].descendants.remove(&op);
        }
        let inputs = &mut self.ops[op.0 as usize].inputs;
        if inputs.len() <= slot {
            inputs.resize(slot + 1, value);
        }
        inputs[slot] = value;
        self.varnodes[value.0 as usize].descendants.insert(op);
    }

    /// Assigns the operation's result, recording the definition on the value.
    pub fn op_set_output(&mut self, op: OpId, value: Option<VarnodeId>) {
        if let Some(previous) = self.ops[op.0 as usize].output {
            let varnode = &mut self.varnodes[previous.0 as usize];
            varnode.def = None;
            varnode.flags.written = false;
        }
        self.ops[op.0 as usize].output = value;
        if let Some(value) = value {
            let varnode = &mut self.varnodes[value.0 as usize];
            varnode.def = Some(op);
            varnode.flags.written = true;
        }
    }

    /// Places an operation immediately before another in its block.
    pub fn op_insert_before(&mut self, op: OpId, before: OpId) {
        let Some(parent) = self.ops[before.0 as usize].parent else {
            return;
        };
        let position = self.blocks[parent.0 as usize]
            .ops
            .iter()
            .position(|candidate| *candidate == before)
            .unwrap_or(0);
        self.ops[op.0 as usize].parent = Some(parent);
        self.blocks[parent.0 as usize].ops.insert(position, op);
    }

    /// Places an operation immediately after another in its block.
    pub fn op_insert_after(&mut self, op: OpId, after: OpId) {
        let Some(parent) = self.ops[after.0 as usize].parent else {
            return;
        };
        let position = self.blocks[parent.0 as usize]
            .ops
            .iter()
            .position(|candidate| *candidate == after)
            .map_or(self.blocks[parent.0 as usize].ops.len(), |index| index + 1);
        self.ops[op.0 as usize].parent = Some(parent);
        self.blocks[parent.0 as usize].ops.insert(position, op);
    }

    /// Places an operation at the head of a block, before every existing op.
    ///
    /// Phi operations must precede all other operations in their block, which
    /// is what lets a predecessor find them by scanning from the block start.
    pub fn op_insert_front(&mut self, op: OpId, block: GraphBlockId) {
        self.ops[op.0 as usize].parent = Some(block);
        self.blocks[block.0 as usize].ops.insert(0, op);
    }

    /// Appends an operation to the end of a block.
    pub fn op_insert_end(&mut self, op: OpId, block: GraphBlockId) {
        self.ops[op.0 as usize].parent = Some(block);
        self.blocks[block.0 as usize].ops.push(op);
    }

    /// Removes an operation from the graph, releasing its operand links.
    pub fn op_destroy(&mut self, op: OpId) {
        let inputs = std::mem::take(&mut self.ops[op.0 as usize].inputs);
        for input in inputs {
            self.varnodes[input.0 as usize].descendants.remove(&op);
        }
        self.op_set_output(op, None);
        if let Some(parent) = self.ops[op.0 as usize].parent.take() {
            self.blocks[parent.0 as usize]
                .ops
                .retain(|candidate| *candidate != op);
        }
        self.ops[op.0 as usize].dead = true;
    }

    /// Redirects every read of `old` to `new`.
    ///
    /// This is Ghidra's `totalReplace`, the operation that makes a rewrite rule
    /// a local edit instead of a whole-function rebuild.
    pub fn total_replace(&mut self, old: VarnodeId, new: VarnodeId) {
        let readers: Vec<OpId> = self.varnode(old).descendants.iter().copied().collect();
        for reader in readers {
            let slots: Vec<usize> = self.ops[reader.0 as usize]
                .inputs
                .iter()
                .enumerate()
                .filter(|(_, input)| **input == old)
                .map(|(slot, _)| slot)
                .collect();
            for slot in slots {
                self.op_set_input(reader, new, slot);
            }
        }
    }

    /// Builds the graph from immutable lifter output.
    ///
    /// Locations become one varnode per definition, so the result is already in
    /// the shape Heritage expects to renumber: reads point at whichever
    /// definition the linear order makes current, and Heritage replaces those
    /// links with dominance-correct ones.
    pub fn from_lifted(function: &NativeFunction) -> Self {
        let mut data = Self {
            entry: function.entry,
            ..Self::default()
        };
        let leaders = block_leaders(function);
        let mut block_of_address = BTreeMap::new();
        for leader in &leaders {
            let id = data.new_block(*leader);
            block_of_address.insert(*leader, id);
        }
        let mut current: BTreeMap<(u32, u64, u32), VarnodeId> = BTreeMap::new();
        let mut block = None;
        for (address, instruction) in &function.instructions {
            if let Some(id) = block_of_address.get(address) {
                block = Some(*id);
            }
            let Some(block) = block else { continue };
            for (index, operation) in instruction.pcode.ops.iter().enumerate() {
                let inputs = operation
                    .inputs
                    .iter()
                    .map(|input| data.value_for_read(*input, &mut current))
                    .collect();
                let seq = SeqNum {
                    address: *address,
                    order: index as u32,
                };
                let op = data.new_op(operation.opcode, seq, inputs);
                data.op_insert_end(op, block);
                if let Some(output) = operation.output {
                    let value = data.new_varnode(output.space, output.offset, output.size);
                    data.op_set_output(op, Some(value));
                    current.insert((output.space, output.offset, output.size), value);
                }
            }
        }
        for (source, target) in &function.edges {
            if let (Some(from), Some(to)) = (
                enclosing_block(&block_of_address, *source),
                block_of_address.get(target).copied(),
            ) {
                data.add_edge(from, to);
            }
        }
        data
    }

    fn value_for_read(
        &mut self,
        input: Varnode,
        current: &mut BTreeMap<(u32, u64, u32), VarnodeId>,
    ) -> VarnodeId {
        if input.space == CONST_SPACE {
            return self.new_constant(input.offset, input.size);
        }
        let key = (input.space, input.offset, input.size);
        if let Some(existing) = current.get(&key) {
            return *existing;
        }
        let value = self.new_varnode(input.space, input.offset, input.size);
        self.mark_input(value);
        current.insert(key, value);
        value
    }
}

/// Addresses that begin a basic block: the entry and every branch target.
fn block_leaders(function: &NativeFunction) -> BTreeSet<u64> {
    let mut leaders = BTreeSet::from([function.entry]);
    for (source, target) in &function.edges {
        leaders.insert(*target);
        if let Some(instruction) = function.instructions.get(source) {
            let sequential = source.wrapping_add(u64::from(instruction.pcode.len));
            if *target != sequential {
                leaders.insert(sequential);
            }
        }
    }
    leaders.retain(|address| function.instructions.contains_key(address));
    leaders
}

fn enclosing_block(
    block_of_address: &BTreeMap<u64, GraphBlockId>,
    address: u64,
) -> Option<GraphBlockId> {
    block_of_address
        .range(..=address)
        .next_back()
        .map(|(_, id)| *id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_pcode::op;

    fn lifted() -> NativeFunction {
        use std::collections::BTreeMap as Map;
        use ventris_lifter::{Flow, LiftedInstruction, REGISTER_SPACE};
        use ventris_pcode::InstPcode;
        let mut instructions = Map::new();
        // v0 = 1; v0 = v0 + 1; return
        instructions.insert(
            0x1000,
            LiftedInstruction {
                address: 0x1000,
                bytes: vec![0, 0, 0, 0],
                pcode: InstPcode {
                    len: 4,
                    space: ventris_lifter::RAM_SPACE,
                    offset: 0x1000,
                    ops: vec![
                        PcodeOp::new(
                            op::COPY,
                            Some(Varnode::new(REGISTER_SPACE, 8, 4)),
                            vec![Varnode::new(CONST_SPACE, 1, 4)],
                        ),
                        PcodeOp::new(
                            op::INT_ADD,
                            Some(Varnode::new(REGISTER_SPACE, 8, 4)),
                            vec![
                                Varnode::new(REGISTER_SPACE, 8, 4),
                                Varnode::new(CONST_SPACE, 1, 4),
                            ],
                        ),
                    ],
                },
                flow: Flow::Return,
                embedded_delay_slot_bytes: 0,
            },
        );
        NativeFunction {
            entry: 0x1000,
            instructions,
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        }
    }

    #[test]
    fn each_definition_of_a_location_gets_its_own_value() {
        let data = Funcdata::from_lifted(&lifted());
        let versions = data.at_location(ventris_lifter::REGISTER_SPACE, 8, 4);
        assert_eq!(versions.len(), 2, "one varnode per definition");
        assert!(data.varnode(versions[0]).flags.written);
        assert!(data.varnode(versions[1]).flags.written);
    }

    #[test]
    fn a_read_links_to_the_definition_that_reaches_it() {
        let data = Funcdata::from_lifted(&lifted());
        let add = data
            .live_ops()
            .find(|(_, op)| op.opcode == op::INT_ADD)
            .expect("the add survives")
            .0;
        let first = data.at_location(ventris_lifter::REGISTER_SPACE, 8, 4)[0];
        assert_eq!(data.op(add).inputs[0], first);
        assert!(data.varnode(first).descendants.contains(&add));
    }

    #[test]
    fn replacing_a_value_redirects_every_reader() {
        let mut data = Funcdata::from_lifted(&lifted());
        let add = data
            .live_ops()
            .find(|(_, op)| op.opcode == op::INT_ADD)
            .expect("the add survives")
            .0;
        let old = data.op(add).inputs[0];
        let new = data.new_constant(7, 4);
        data.total_replace(old, new);
        assert_eq!(data.op(add).inputs[0], new);
        assert!(data.varnode(old).descendants.is_empty());
        assert!(data.varnode(new).descendants.contains(&add));
    }

    #[test]
    fn an_inserted_operation_joins_its_block_in_order() {
        let mut data = Funcdata::from_lifted(&lifted());
        let add = data
            .live_ops()
            .find(|(_, op)| op.opcode == op::INT_ADD)
            .expect("the add survives")
            .0;
        let piece = data.new_unique(4);
        let seq = data.op(add).seq;
        let inserted = data.new_op(op::COPY, seq, vec![piece]);
        data.op_insert_before(inserted, add);
        let block = data.op(add).parent.expect("the add has a block");
        let ops = &data.block(block).ops;
        let inserted_at = ops.iter().position(|id| *id == inserted).expect("inserted");
        let add_at = ops.iter().position(|id| *id == add).expect("add");
        assert!(inserted_at < add_at);
    }

    #[test]
    fn destroying_an_operation_releases_its_operands() {
        let mut data = Funcdata::from_lifted(&lifted());
        let add = data
            .live_ops()
            .find(|(_, op)| op.opcode == op::INT_ADD)
            .expect("the add survives")
            .0;
        let operand = data.op(add).inputs[0];
        let before = data.op_count();
        data.op_destroy(add);
        assert_eq!(data.op_count(), before - 1);
        assert!(data.varnode(operand).descendants.is_empty());
    }

    #[test]
    fn overlap_is_recognized_within_one_space() {
        let mut data = Funcdata::default();
        let wide = data.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
        let byte = data.new_varnode(ventris_lifter::REGISTER_SPACE, 9, 1);
        let other = data.new_varnode(ventris_lifter::REGISTER_SPACE, 16, 4);
        assert!(data.varnode(wide).overlaps(data.varnode(byte)));
        assert_eq!(data.varnode(wide).overlaps(data.varnode(other)), false);
    }
}
