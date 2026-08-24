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

pub mod action;
pub mod branchaction;
pub mod casts;
pub mod cover;
pub mod deadcode;
pub mod emit;
pub mod expr_rules;
pub mod guard;
pub mod heritage;
pub mod merge;
pub mod mergeaction;
pub mod nonzero;
pub mod proto;
pub mod protoaction;
pub mod refine;
pub mod rules;
pub mod structure;
pub mod subflow;
pub mod types;
pub mod value;

use std::collections::{BTreeMap, BTreeSet};

use ventris_lifter::{CONST_SPACE, NativeFunction, UNIQUE_SPACE};
use ventris_pcode::Varnode;

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
    /// Set when the block is unreachable from the entry. Its slot is retained
    /// so existing identifiers stay valid.
    pub dead: bool,
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
            .filter(|(_, block)| !block.dead)
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
    /// The opcode of a live operation, or `None` once it has been destroyed.
    ///
    /// A rule may destroy or retype the operation it is applied to, so callers
    /// re-read rather than caching what they were handed.
    pub fn opcode_of(&self, op: OpId) -> Option<i32> {
        let candidate = &self.ops[op.0 as usize];
        (!candidate.dead).then_some(candidate.opcode)
    }

    /// Whether any live operation begins at the given address.
    pub fn has_op_at(&self, address: u64) -> bool {
        self.live_ops().any(|(_, op)| op.seq.address == address)
    }

    /// Retypes an operation, keeping its operands and output.
    pub fn op_set_opcode(&mut self, op: OpId, opcode: i32) {
        self.ops[op.0 as usize].opcode = opcode;
    }

    /// Replaces every operand, releasing the readers of the old ones.
    pub fn op_set_inputs(&mut self, op: OpId, inputs: Vec<VarnodeId>) {
        for existing in self.ops[op.0 as usize].inputs.clone() {
            self.varnodes[existing.0 as usize].descendants.remove(&op);
        }
        for input in &inputs {
            self.varnodes[input.0 as usize].descendants.insert(op);
        }
        self.ops[op.0 as usize].inputs = inputs;
    }

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

    /// Removes one control-flow edge.
    ///
    /// The merge operand the predecessor contributed goes with it, because a
    /// `MULTIEQUAL`'s operand slots are positional against the predecessor
    /// list: leaving a stale operand would silently reassign every later path's
    /// value to the wrong edge.
    pub fn remove_edge(&mut self, from: GraphBlockId, to: GraphBlockId) -> bool {
        if !self.blocks[from.0 as usize].successors.contains(&to) {
            return false;
        }
        self.blocks[from.0 as usize]
            .successors
            .retain(|candidate| *candidate != to);
        self.detach_predecessor(to, from);
        true
    }

    /// Removes a block that only transfers control, connecting its predecessors
    /// straight to its successor.
    ///
    /// Ported from `Funcdata::spliceBlockBasic`. A block holding nothing but a
    /// jump is an artefact of instruction-level block splitting; keeping it
    /// forces structuring to account for a region that computes nothing.
    /// Refuses when the block merges values, has other than one successor, or
    /// is the entry, since each of those makes the removal observable.
    pub fn splice_block(&mut self, block: GraphBlockId) -> bool {
        let candidate = &self.blocks[block.0 as usize];
        if candidate.dead || candidate.successors.len() != 1 || candidate.start == self.entry {
            return false;
        }
        let successor = candidate.successors[0];
        if successor == block {
            return false;
        }
        let carries_work = candidate
            .ops
            .iter()
            .any(|op| !matches!(self.ops[op.0 as usize].opcode, ventris_pcode::op::BRANCH));
        if carries_work {
            return false;
        }
        // A merge at the successor reads one operand per predecessor. Splicing
        // would change how many arrive, so leave it alone.
        let merges = self.blocks[successor.0 as usize]
            .ops
            .iter()
            .any(|op| self.ops[op.0 as usize].opcode == ventris_pcode::op::MULTIEQUAL);
        if merges {
            return false;
        }
        for predecessor in self.blocks[block.0 as usize].predecessors.clone() {
            let successors = &mut self.blocks[predecessor.0 as usize].successors;
            for entry in successors.iter_mut() {
                if *entry == block {
                    *entry = successor;
                }
            }
            if !self.blocks[successor.0 as usize]
                .predecessors
                .contains(&predecessor)
            {
                self.blocks[successor.0 as usize]
                    .predecessors
                    .push(predecessor);
            }
        }
        self.blocks[successor.0 as usize]
            .predecessors
            .retain(|predecessor| *predecessor != block);
        for op in self.blocks[block.0 as usize].ops.clone() {
            self.op_destroy(op);
        }
        let removed = &mut self.blocks[block.0 as usize];
        removed.ops.clear();
        removed.predecessors.clear();
        removed.successors.clear();
        removed.dead = true;
        true
    }

    /// Removes blocks the entry cannot reach.
    ///
    /// Ported from `Funcdata::removeUnreachableBlocks`. Branch folding and
    /// constant conditions leave whole blocks with no path from the entry;
    /// emitting them produces statements after an unconditional transfer.
    /// Removing a predecessor also removes the operand it contributed to each
    /// merge at its successors, which keeps operand slots aligned with the
    /// predecessor list renaming relies on.
    pub fn remove_unreachable_blocks(&mut self) -> usize {
        let entry = self
            .blocks()
            .find(|(_, block)| block.start == self.entry)
            .map(|(id, _)| id)
            .or_else(|| self.blocks().next().map(|(id, _)| id));
        let Some(entry) = entry else { return 0 };

        let mut reachable = BTreeSet::from([entry]);
        let mut pending = vec![entry];
        while let Some(id) = pending.pop() {
            for successor in self.blocks[id.0 as usize].successors.clone() {
                if reachable.insert(successor) {
                    pending.push(successor);
                }
            }
        }

        let unreachable: Vec<GraphBlockId> = self
            .blocks()
            .map(|(id, _)| id)
            .filter(|id| !reachable.contains(id))
            .collect();
        for id in unreachable.iter().copied() {
            for successor in self.blocks[id.0 as usize].successors.clone() {
                self.detach_predecessor(successor, id);
            }
            for predecessor in self.blocks[id.0 as usize].predecessors.clone() {
                self.blocks[predecessor.0 as usize]
                    .successors
                    .retain(|candidate| *candidate != id);
            }
            for op in self.blocks[id.0 as usize].ops.clone() {
                self.op_destroy(op);
            }
            let block = &mut self.blocks[id.0 as usize];
            block.ops.clear();
            block.predecessors.clear();
            block.successors.clear();
            block.dead = true;
        }
        unreachable.len()
    }

    /// Drops one incoming edge, along with the merge operand it fed.
    fn detach_predecessor(&mut self, block: GraphBlockId, predecessor: GraphBlockId) {
        let Some(slot) = self.blocks[block.0 as usize]
            .predecessors
            .iter()
            .position(|candidate| *candidate == predecessor)
        else {
            return;
        };
        self.blocks[block.0 as usize].predecessors.remove(slot);
        let phis: Vec<OpId> = self.blocks[block.0 as usize]
            .ops
            .iter()
            .copied()
            .take_while(|op| self.ops[op.0 as usize].opcode == ventris_pcode::op::MULTIEQUAL)
            .collect();
        for phi in phis {
            let mut inputs = self.ops[phi.0 as usize].inputs.clone();
            if slot < inputs.len() {
                inputs.remove(slot);
                self.op_set_inputs(phi, inputs);
            }
        }
    }

    /// Builds the graph from immutable lifter output.
    ///
    /// Every read becomes its own *free* varnode: unwritten, unlinked, and
    /// carrying only a location. Nothing here decides which definition a read
    /// sees. That is renaming's job, and pre-linking reads in address order
    /// defeats it — a read already bound to a lower definition is skipped by
    /// renaming, so a value written on a path that dominates the read is lost.
    /// A call whose result is read afterwards showed the pre-call value.
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
                    .map(|input| data.value_for_read(*input))
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

    /// A fresh varnode for one read, with no definition attached.
    fn value_for_read(&mut self, input: Varnode) -> VarnodeId {
        if input.space == CONST_SPACE {
            return self.new_constant(input.offset, input.size);
        }
        self.new_varnode(input.space, input.offset, input.size)
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
    use ventris_pcode::PcodeOp;
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
        let written = versions
            .iter()
            .filter(|value| data.varnode(**value).flags.written)
            .count();
        assert_eq!(written, 2, "one varnode per definition");
        assert_eq!(
            versions.len() - written,
            1,
            "the read is its own free varnode, unlinked until renaming"
        );
    }

    #[test]
    fn renaming_links_a_read_to_the_definition_that_reaches_it() {
        let mut data = Funcdata::from_lifted(&lifted());
        heritage::heritage(&mut data);
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
    fn an_unreachable_block_and_its_merge_operand_are_removed() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        let orphan = data.new_block(0x1010);
        let join = data.new_block(0x1020);
        data.add_edge(entry, join);
        data.add_edge(orphan, join);
        let seq = SeqNum {
            address: 0x1020,
            order: 0,
        };
        let left = data.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
        let right = data.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
        let phi = data.new_op(op::MULTIEQUAL, seq, vec![left, right]);
        let out = data.new_varnode(ventris_lifter::REGISTER_SPACE, 8, 4);
        data.op_set_output(phi, Some(out));
        data.op_insert_front(phi, join);

        assert_eq!(data.remove_unreachable_blocks(), 1);
        assert!(data.blocks().all(|(id, _)| id != orphan));
        assert_eq!(data.block(join).predecessors, vec![entry]);
        assert_eq!(
            data.op(phi).inputs,
            vec![left],
            "the operand the removed path contributed is gone"
        );
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
