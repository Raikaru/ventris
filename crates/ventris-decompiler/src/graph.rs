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
pub mod actiondb;
pub mod alias;
pub mod bitfield;
pub mod blockaction;
pub mod branchaction;
pub mod callproto;
pub mod callspecs;
pub mod casts;
pub mod condprop;
pub mod consume;
pub mod coreaction;
pub mod cover;
pub mod deadcode;
pub mod dominantcopy;
pub mod dynamic;
pub mod emit;
pub mod equality;
pub mod expr_arith;
pub mod expr_bool;
pub mod expr_divmod;
pub mod expr_float;
pub mod expr_memory;
pub mod expr_piece;
pub mod expr_ptr;
pub mod expr_rules;
pub mod expr_rules2;
pub mod forloop;
pub mod funcproto;
pub mod guard;
pub mod heritage;
pub mod jumpmodel;
pub mod jumptable;
pub mod marking;
pub mod merge;
pub mod mergeaction;
pub mod namevars;
pub mod nodejoin;
pub mod nonzero;
pub mod orconsume;
pub mod parampromote;
pub mod proto;
pub mod protoaction;
pub mod protoconstraints;
pub mod protorecovery;
pub mod rangeutil;
pub mod refine;
pub mod rules;
pub mod scope;
pub mod scopeconsumers;
pub mod scopepopulate;
pub mod splitdatatype;
pub mod splitvarnode;
pub mod stackframe;
pub mod storageaction;
pub mod structure;
pub mod structuretransform;
pub mod subfloat;
pub mod subflow;
pub mod tablebase;
pub mod tracedag;
pub mod typefactory;
pub mod types;
pub mod value;
pub mod varnodeprops;

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
    /// The value may be directly affected by a legal function input.
    ///
    /// Ghidra's `Varnode::directwrite` bit excludes an input from the abnormal
    /// inputs that `Funcdata::markIndirectOnly` examines.
    pub direct_write: bool,
    /// Every use of an abnormal input reaches an `INDIRECT` marker.
    ///
    /// Ghidra's `Varnode::indirectonly` bit lets merge and variable naming
    /// retain an otherwise illegal input when it has no ordinary data-flow use.
    pub indirect_only: bool,
    /// The value is the least significant piece of a double-precision whole.
    ///
    /// Ghidra's `Varnode::precislo`, set by `RuleDoubleIn::attemptMarking` and
    /// `RuleDoubleOut::attemptMarking` from the shape of the graph rather than
    /// supplied from outside.
    pub precis_lo: bool,
    /// The value is the most significant piece of a double-precision whole.
    ///
    /// Ghidra's `Varnode::precishi`.
    pub precis_hi: bool,
    /// The value is created by an `INDIRECT` and has no data flow before it.
    ///
    /// Ghidra's `Varnode::indirect_creation`, set by `newIndirectCreation` for a
    /// location a call destroys.
    pub indirect_creation: bool,
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
    /// The operation indirectly creates its output.
    ///
    /// Ghidra's `PcodeOp::indirect_creation`. Only an `INDIRECT` standing for a
    /// location a call destroys carries it, and no rule may collapse such an
    /// `INDIRECT` into its first operand.
    pub indirect_creation: bool,
    /// The operation's assignment is not printed.
    ///
    /// Ghidra's `PcodeOp::nonprinting`, set by `Merge::markRedundantCopies` for
    /// a `COPY` that a dominating `COPY` from the same source already performed.
    /// The operation stays in the graph - the value is still defined, and other
    /// passes still read it - but the emitter says nothing about it, because
    /// saying it twice invents an assignment the source never wrote.
    pub non_printing: bool,
    /// The call's parameter trials have not been decided yet.
    ///
    /// Ghidra's `FuncCallSpecs::isInputActive`. `ActionActiveParam` decides the
    /// trials while it is set and calls `clearActiveInput` once
    /// `buildInputFromTrials` has rebuilt the operand list. After that the
    /// operands are the arguments, not the candidate locations, so re-deriving
    /// them from the convention's storage would read the wrong slots.
    pub input_active: bool,
    /// Set when the operation has been removed from the graph but its slot is
    /// retained so existing identifiers stay valid.
    pub dead: bool,
}

/// One basic block, holding its operations in execution order.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct GraphBlock {
    pub start: u64,
    /// Index of the block's first p-code operation within `start`'s
    /// instruction.
    ///
    /// Ghidra's basic blocks are p-code level, not instruction level: a
    /// `CBRANCH` whose destination is in the constant space branches *within*
    /// one instruction's operations, so a block can begin part-way through an
    /// instruction and two blocks can share a start address. PPC paired-single
    /// arithmetic lifts to exactly that shape.
    pub start_order: u32,
    pub ops: Vec<OpId>,
    pub predecessors: Vec<GraphBlockId>,
    pub successors: Vec<GraphBlockId>,
    /// Positions of blocks this one has absorbed, in absorption order.
    ///
    /// Ghidra's `BlockBasic::mergeRange`, which extends a block's address cover
    /// when `spliceBlockBasic` folds its successor into it. Ghidra needs the
    /// cover only for reporting, because its branch destinations are block
    /// references. Here they are addresses, so the cover is load-bearing: a
    /// branch naming an absorbed block has to resolve to the block that
    /// absorbed it, or the destination silently disappears.
    pub absorbed: Vec<(u64, u32)>,
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
    /// Cached "may be non-zero" masks, cleared whenever the graph changes.
    ///
    /// Ghidra caches this on the varnode because rules consult it constantly and
    /// two rules disagreeing about one value's mask is not a precision
    /// difference but a correctness bug: `RuleHumptyOr` and `RuleAndDistribute`
    /// are exact inverses whose guards are complements, so two mask
    /// implementations made both fire and the fixpoint never converged.
    masks: Cache<Vec<u64>>,
    /// Cached rich type recovery, cleared whenever the graph changes.
    ///
    /// The pointer rules each need the recovered types, and running the
    /// seven-pass inference inside `apply_op` made the expression phase five
    /// times slower on one corpus function. This is the same reason the masks
    /// are cached.
    recovered_types: Cache<(typefactory::TypeFactory, typefactory::RecoveredTypes)>,
    /// Whether the target's memory is big endian.
    ///
    /// Ghidra reads this from the address space. The graph has no architecture,
    /// so the fact is carried explicitly: which end of a value a piece comes from
    /// decides what every split of an aggregate means.
    pub big_endian: bool,
    /// The register that holds the frame base, when the caller knows it.
    ///
    /// Ghidra's `Funcdata` reaches its architecture's stack space and
    /// `ActionSpacebase` marks the varnode holding it. This is the same fact,
    /// carried explicitly because the graph has no architecture: it is what lets
    /// type recovery tell the frame apart from an ordinary object.
    pub spacebase: Option<guard::Location>,
    /// Locations a call leaves alone, by space and offset.
    ///
    /// Ghidra records this per varnode: `setInputVarnode` consults
    /// `FuncProto::hasEffect` and sets `Varnode::unaffected` on an input at an
    /// `unaffected` location. `AncestorRealistic` then fails outright on such an
    /// input, because a register the callee preserves cannot be how this call's
    /// argument arrived.
    pub unaffected: BTreeSet<(u32, u64)>,
    /// Whether raw p-code processing has started.
    ///
    /// This is Ghidra's `processing_started` flag. Front-end lifecycle checks
    /// and the printer read it before treating the graph as decompiled.
    pub processing_started: bool,
    /// Whether post-processing has completed.
    ///
    /// This is Ghidra's `processing_complete` flag. Signature and output
    /// clients read it before accepting the graph as fully analyzed.
    pub processing_complete: bool,
    /// Whether type recovery is enabled for this function.
    ///
    /// This is Ghidra's `typerecovery_on` flag. Type-sensitive rules and
    /// prototype recovery read it when deciding whether recovered types are
    /// authoritative.
    pub type_recovery_on: bool,
    /// Whether type recovery has begun its propagation passes.
    ///
    /// This is Ghidra's `typerecovery_start` flag. The type-recovery action,
    /// pointer rules, and spacebase recovery use it as their start gate.
    pub type_recovery_started: bool,
    /// Varnode creation index at the beginning of cleanup.
    ///
    /// This is Ghidra's `clean_up_index`. Cleanup rules read it to distinguish
    /// values made before cleanup from values introduced during cleanup.
    pub clean_up_index: usize,
    /// Varnode creation index at the beginning of high-level assignment.
    ///
    /// This is Ghidra's `high_level_index`. Merge, cast, and variable-naming
    /// passes use the boundary when they reason about high-level values.
    pub high_level_index: usize,
    /// Whether high-level variable assignment is enabled.
    ///
    /// This is Ghidra's `highlevel_on` flag. The printer and prototype recovery
    /// read it to select high-level variables instead of raw SSA values.
    pub high_level_on: bool,
    /// Diagnostics a pass wants the reader to see, standing in for Ghidra's
    /// `Funcdata::warning` and `warningHeader`.
    ///
    /// Ghidra's actions report recovery they could not complete - an
    /// unjustified parameter, a prototype it had to guess - and the printer
    /// emits them as comments. Without a sink an action has nowhere to put that,
    /// so the choice is between staying silent and not porting the action at
    /// all. Duplicates are dropped: a pass that runs to a fixed point would
    /// otherwise repeat itself once per round.
    warnings: Vec<String>,
    /// The function's recovered prototype, once a calling convention is known.
    ///
    /// `None` is a real state rather than a missing value: a bare architecture
    /// with no target supplies no convention, so there is nothing to recover
    /// parameter storage against.
    func_proto: Option<funcproto::FuncProto>,
    /// The function's local symbol table, once something builds one.
    scope_local: Option<scope::ScopeLocal>,
}

/// A derived value held beside the graph it was computed from.
///
/// A cache is not part of the graph's value, so it takes no part in equality:
/// two graphs that differ only in what has been computed about them are the
/// same graph. It is also not cloned, because a clone's cache would describe
/// the original.
#[derive(Debug)]
struct Cache<T>(std::cell::RefCell<Option<std::rc::Rc<T>>>);

impl<T> Default for Cache<T> {
    // Derived `Default` would require `T: Default`; an empty cache needs no
    // such thing.
    fn default() -> Self {
        Self(std::cell::RefCell::new(None))
    }
}

impl<T> Cache<T> {
    fn get(&self) -> Option<std::rc::Rc<T>> {
        self.0.borrow().clone()
    }

    fn set(&self, value: T) -> std::rc::Rc<T> {
        let value = std::rc::Rc::new(value);
        *self.0.borrow_mut() = Some(value.clone());
        value
    }

    fn clear(&self) {
        self.0.borrow_mut().take();
    }
}

impl<T> Clone for Cache<T> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<T> PartialEq for Cache<T> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<T> Eq for Cache<T> {}

impl Funcdata {
    /// The cached "may be non-zero" mask of every value.
    ///
    /// Every rule that reasons about which bits can be set MUST read this, so
    /// that two rules never disagree about one value.
    pub fn nonzero_masks(&self) -> std::rc::Rc<Vec<u64>> {
        if let Some(cached) = self.masks.get() {
            return cached;
        }
        self.masks.set(crate::graph::nonzero::compute_masks(self))
    }

    /// Drops the mask cache. Called by every mutator.
    ///
    /// The recovered types are deliberately not dropped here. Ghidra recovers
    /// types in `ActionInferTypes`, a pass in the pool, and rules read the types
    /// left on the varnodes; it does not re-derive the whole function's types
    /// after each rewrite. Dropping the snapshot per mutation made the pointer
    /// rules re-run seven-pass inference once per rewrite: 5000 full inferences
    /// on a 10,000-varnode function, and fifty seconds where the address-ordered
    /// path took a quarter of one.
    fn invalidate_masks(&self) {
        self.masks.clear();
    }

    /// Drops the recovered types, for a caller at a pass boundary.
    ///
    /// This is `ActionInferTypes` running again: the point at which the graph has
    /// settled enough for its types to be worth re-deriving.
    pub fn invalidate_types(&self) {
        self.recovered_types.clear();
    }

    /// The cached rich type recovery for this graph.
    ///
    /// Every rule that reasons about pointers, structures or arrays MUST read
    /// this rather than running inference itself.
    pub fn recovered_types(
        &self,
    ) -> std::rc::Rc<(typefactory::TypeFactory, typefactory::RecoveredTypes)> {
        if let Some(cached) = self.recovered_types.get() {
            return cached;
        }
        let factory = typefactory::TypeFactory::new(32);
        // `ActionSpacebase`: the varnode holding the frame base is typed as a
        // pointer to the space, and locked, so access-pattern recovery cannot
        // relabel the frame as a structure.
        let mut seed = BTreeMap::new();
        if let Some(location) = self.spacebase {
            let pointer = factory.get_type_pointer_with_bits(
                typefactory::DataType::Spacebase,
                location.size.saturating_mul(8),
            );
            for index in 0..self.varnode_count() {
                let id = VarnodeId(index as u32);
                let value = self.varnode(id);
                if value.space == location.space
                    && value.offset == location.offset
                    && value.def.is_none()
                {
                    seed.insert(id, pointer.clone());
                }
            }
        }
        let types = typefactory::infer(self, &factory, &seed);
        self.recovered_types.set((factory, types))
    }

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
        self.invalidate_masks();
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
        self.invalidate_masks();
        let offset = self.next_unique;
        self.next_unique = self.next_unique.saturating_add(u64::from(size).max(1));
        self.new_varnode(UNIQUE_SPACE, offset, size)
    }

    /// The function's input value at a location, creating it only if absent.
    ///
    /// Ghidra's `Funcdata::setInputVarnode`, which returns the *existing* input
    /// varnode when one already covers the location. Minting a fresh input per
    /// read instead gives one location several "entry values", and parameter
    /// promotion and naming then disagree about which is the parameter - a
    /// recovered pointer parameter came out as a file-scope global.
    pub fn set_input_varnode(&mut self, space: u32, offset: u64, size: u32) -> VarnodeId {
        if let Some(existing) = self.located.get(&(space, offset, size)).and_then(|held| {
            held.iter()
                .copied()
                .find(|id| self.varnodes[id.0 as usize].flags.input)
        }) {
            return existing;
        }
        let id = self.new_varnode(space, offset, size);
        self.mark_input(id);
        id
    }

    /// The earliest operation in a block that reads a value.
    ///
    /// Ghidra's `BlockBasic::earliestUse`, ordered by sequence number.
    pub fn earliest_use(&self, block: GraphBlockId, value: VarnodeId) -> Option<OpId> {
        self.varnodes[value.0 as usize]
            .descendants
            .iter()
            .copied()
            .filter(|op| self.ops[op.0 as usize].parent == Some(block))
            .min_by_key(|op| self.ops[op.0 as usize].seq.order)
    }

    /// An operation in a block that already computes what `op` computes.
    ///
    /// Ghidra's `Funcdata::cseFindInBlock`. The search runs over the readers of
    /// one of `op`'s operands, because a common subexpression has to read the
    /// same value; `earliest` bounds it so the substitute is available where the
    /// caller needs it.
    pub fn cse_find_in_block(
        &self,
        op: OpId,
        value: VarnodeId,
        block: GraphBlockId,
        earliest: Option<OpId>,
    ) -> Option<OpId> {
        let output = self.ops[op.0 as usize].output?;
        let bound = earliest.map(|id| self.ops[id.0 as usize].seq.order);
        self.varnodes[value.0 as usize]
            .descendants
            .iter()
            .copied()
            .filter(|candidate| *candidate != op)
            .filter(|candidate| self.ops[candidate.0 as usize].parent == Some(block))
            .filter(|candidate| {
                bound.is_none_or(|bound| bound >= self.ops[candidate.0 as usize].seq.order)
            })
            .find(|candidate| {
                self.ops[candidate.0 as usize].output.is_some_and(|other| {
                    equality::functional_equality(self, output, other) == equality::Equality::Same
                })
            })
    }

    pub fn new_constant(&mut self, value: u64, size: u32) -> VarnodeId {
        self.invalidate_masks();
        let id = self.new_varnode(CONST_SPACE, value, size);
        self.varnodes[id.0 as usize].flags.constant = true;
        id
    }

    /// Creates the annotation naming an operation, as Ghidra's `newVarnodeIop`
    /// does.
    ///
    /// The value is not a value: it is an `INDIRECT`'s second operand, saying
    /// which operation is responsible for the indirect effect.
    pub fn new_iop(&mut self, target: OpId) -> VarnodeId {
        self.invalidate_masks();
        let id = self.new_varnode(ventris_lifter::IOP_SPACE, u64::from(target.0), 4);
        self.varnodes[id.0 as usize].flags.constant = true;
        id
    }

    /// The operation an `INDIRECT` annotates, if its second operand names one.
    ///
    /// Ghidra's `PcodeOp::getOpFromConst`.
    pub fn iop_target(&self, value: VarnodeId) -> Option<OpId> {
        let varnode = &self.varnodes[value.0 as usize];
        if varnode.space != ventris_lifter::IOP_SPACE {
            return None;
        }
        let index = u32::try_from(varnode.offset).ok()?;
        ((index as usize) < self.ops.len()).then_some(OpId(index))
    }

    /// Marks an `INDIRECT` as indirectly *creating* its output.
    ///
    /// Ghidra's `Funcdata::markIndirectCreation`. The output has no data flow
    /// before this operation, so no rule may collapse the `INDIRECT` into its
    /// first operand: doing so would claim the killed location still holds
    /// whatever it held before.
    pub fn mark_indirect_creation(&mut self, op: OpId) {
        self.invalidate_masks();
        self.ops[op.0 as usize].indirect_creation = true;
        if let Some(output) = self.ops[op.0 as usize].output {
            self.varnodes[output.0 as usize].flags.indirect_creation = true;
        }
    }

    /// Whether the operation indirectly creates its output.
    pub fn is_indirect_creation(&self, op: OpId) -> bool {
        self.ops[op.0 as usize].indirect_creation
    }

    /// Marks the operation's assignment as one the emitter must not print.
    ///
    /// Ghidra's `Funcdata::opMarkNonPrinting`.
    pub fn op_mark_non_printing(&mut self, op: OpId) {
        self.ops[op.0 as usize].non_printing = true;
    }

    /// Marks a value as one piece of a double-precision whole.
    ///
    /// Ghidra's `Varnode::setPrecisLo`/`setPrecisHi`. The marks are set by the
    /// double-precision rules themselves, from the shape of the graph.
    pub fn mark_precision(&mut self, value: VarnodeId, high: bool) {
        self.invalidate_masks();
        if high {
            self.varnodes[value.0 as usize].flags.precis_hi = true;
        } else {
            self.varnodes[value.0 as usize].flags.precis_lo = true;
        }
    }

    /// Whether the graph still holds a block the entry cannot reach.
    ///
    /// Ghidra's `Funcdata::hasUnreachableBlocks`, which the double-precision
    /// rules consult before rewriting: an unreachable block's data flow is not
    /// trustworthy evidence about how a value is pieced together.
    pub fn has_unreachable_blocks(&self) -> bool {
        let Some(entry) = self.entry_block() else {
            return false;
        };
        let mut reachable = BTreeSet::from([entry]);
        let mut pending = vec![entry];
        while let Some(id) = pending.pop() {
            for successor in self.blocks[id.0 as usize].successors.iter().copied() {
                if reachable.insert(successor) {
                    pending.push(successor);
                }
            }
        }
        self.blocks().any(|(id, _)| !reachable.contains(&id))
    }

    /// Whether an input value sits at a location every callee preserves.
    ///
    /// Ghidra's `Varnode::isUnaffected`.
    pub fn is_unaffected(&self, value: VarnodeId) -> bool {
        let varnode = &self.varnodes[value.0 as usize];
        varnode.flags.input && self.unaffected.contains(&(varnode.space, varnode.offset))
    }

    /// Whether the operation's assignment is printed.
    pub fn is_non_printing(&self, op: OpId) -> bool {
        self.ops[op.0 as usize].non_printing
    }

    /// Whether a call's parameter trials are still open.
    ///
    /// Ghidra's `FuncCallSpecs::isInputActive`.
    pub fn is_input_active(&self, op: OpId) -> bool {
        self.ops[op.0 as usize].input_active
    }

    /// Records that a call's operand list is now its argument list.
    ///
    /// Ghidra's `FuncCallSpecs::clearActiveInput`, called once
    /// `buildInputFromTrials` has run.
    pub fn clear_input_active(&mut self, op: OpId) {
        self.ops[op.0 as usize].input_active = false;
    }

    /// Marks a value as entering the function without a definition.
    pub fn mark_input(&mut self, id: VarnodeId) {
        self.invalidate_masks();
        self.varnodes[id.0 as usize].flags.input = true;
    }
    /// Marks an input as directly affected by a legal function input.
    ///
    /// Ghidra's `Varnode::directwrite` bit makes the value a legal input for
    /// `Funcdata::markIndirectOnly`, so it must not receive the
    /// `indirectonly` mark.
    pub fn mark_direct_write(&mut self, id: VarnodeId) {
        self.invalidate_masks();
        self.varnodes[id.0 as usize].flags.direct_write = true;
    }

    /// Clears the direct-write mark, as `ActionDirectWrite` does before it
    /// recomputes the property from scratch.
    pub fn clear_direct_write(&mut self, id: VarnodeId) {
        self.invalidate_masks();
        self.varnodes[id.0 as usize].flags.direct_write = false;
    }

    /// Marks abnormal inputs whose complete use chain reaches `INDIRECT`.
    ///
    /// Ghidra's `Funcdata::markIndirectOnly` follows `MULTIEQUAL` outputs and
    /// accepts `INDIRECT` terminals. The graph has no indirect-store marker, so
    /// every `INDIRECT` is the representable terminal form.
    pub fn func_proto(&self) -> Option<&funcproto::FuncProto> {
        self.func_proto.as_ref()
    }

    pub fn func_proto_mut(&mut self) -> Option<&mut funcproto::FuncProto> {
        self.func_proto.as_mut()
    }

    pub fn set_func_proto(&mut self, proto: funcproto::FuncProto) {
        self.func_proto = Some(proto);
    }

    pub fn scope_local(&self) -> Option<&scope::ScopeLocal> {
        self.scope_local.as_ref()
    }

    pub fn scope_local_mut(&mut self) -> Option<&mut scope::ScopeLocal> {
        self.scope_local.as_mut()
    }

    pub fn set_scope_local(&mut self, scope: scope::ScopeLocal) {
        self.scope_local = Some(scope);
    }

    /// Records a diagnostic, ignoring one already present.
    pub fn warning(&mut self, message: impl Into<String>) -> bool {
        let message = message.into();
        if self.warnings.contains(&message) {
            return false;
        }
        self.warnings.push(message);
        true
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn mark_indirect_only(&mut self) -> usize {
        let candidates: Vec<VarnodeId> = self
            .varnodes
            .iter()
            .enumerate()
            .filter(|(_, value)| value.flags.input && !value.flags.direct_write)
            .map(|(index, _)| VarnodeId(index as u32))
            .collect();
        let mut marked = 0;
        for id in candidates {
            if !self.uses_only_indirect(id) {
                continue;
            }
            let value = &mut self.varnodes[id.0 as usize];
            if !value.flags.indirect_only {
                value.flags.indirect_only = true;
                marked += 1;
            }
        }
        marked
    }

    fn uses_only_indirect(&self, root: VarnodeId) -> bool {
        let mut pending = vec![root];
        let mut seen = BTreeSet::new();
        while let Some(value) = pending.pop() {
            if !seen.insert(value) {
                continue;
            }
            let descendants: Vec<OpId> = self.varnode(value).descendants.iter().copied().collect();
            for operation in descendants {
                let operation = self.op(operation);
                if operation.dead {
                    continue;
                }
                match operation.opcode {
                    ventris_pcode::op::INDIRECT => {}
                    ventris_pcode::op::MULTIEQUAL => {
                        let Some(output) = operation.output else {
                            return false;
                        };
                        pending.push(output);
                    }
                    _ => return false,
                }
            }
        }
        true
    }

    /// Starts raw p-code processing for this graph.
    ///
    /// Ghidra's `Funcdata::startProcessing` sets `processing_started`; the
    /// graph is already built by `from_lifted`, so flow tracing and warnings
    /// belong to the lifter rather than this lifecycle marker.
    pub fn start_processing(&mut self) {
        self.processing_started = true;
    }

    /// Marks this graph as fully processed.
    ///
    /// Ghidra's `Funcdata::stopProcessing` sets `processing_complete`; dead-op
    /// reclamation and warning emission are not represented by this graph.
    pub fn stop_processing(&mut self) {
        self.processing_complete = true;
    }

    /// Enables or disables type recovery for this graph.
    ///
    /// This is Ghidra's `Funcdata::setTypeRecovery`. The type-sensitive rules
    /// read `type_recovery_on` to decide whether recovered types may guide a
    /// rewrite.
    pub fn set_type_recovery(&mut self, enabled: bool) {
        self.type_recovery_on = enabled;
    }

    /// Starts type-recovery propagation once.
    ///
    /// This is Ghidra's `Funcdata::startTypeRecovery`, whose boolean result
    /// distinguishes the first start from repeated action-loop visits.
    pub fn start_type_recovery(&mut self) -> bool {
        if self.type_recovery_started {
            return false;
        }
        self.type_recovery_started = true;
        true
    }

    /// Records the beginning of cleanup at the current varnode creation index.
    ///
    /// This is Ghidra's `Funcdata::startCleanUp`; cleanup rules use the saved
    /// boundary when applying transformations to newly created values.
    pub fn start_clean_up(&mut self) {
        self.clean_up_index = self.varnodes.len();
    }

    /// Enables high-level variable assignment at the current creation index.
    ///
    /// This is Ghidra's `Funcdata::setHighLevel`. The graph has no
    /// `HighVariable` arena, so the flag and boundary are retained for merge,
    /// naming, casting, and printing passes without fabricating high objects.
    pub fn set_high_level(&mut self) {
        if self.high_level_on {
            return;
        }
        self.high_level_on = true;
        self.high_level_index = self.varnodes.len();
    }

    /// Whether raw p-code processing has begun.
    ///
    /// This mirrors Ghidra's `Funcdata::isProcStarted` query for front-end and
    /// printer lifecycle checks.
    pub fn is_proc_started(&self) -> bool {
        self.processing_started
    }

    /// Whether processing has completed.
    ///
    /// This mirrors Ghidra's `Funcdata::isProcComplete` query for signature and
    /// output clients.
    pub fn is_proc_complete(&self) -> bool {
        self.processing_complete
    }

    /// Whether type recovery is enabled.
    ///
    /// This mirrors Ghidra's `Funcdata::isTypeRecoveryOn` query used by
    /// type-sensitive rules and prototype recovery.
    pub fn is_type_recovery_on(&self) -> bool {
        self.type_recovery_on
    }

    /// Whether type recovery has started.
    ///
    /// This mirrors Ghidra's `Funcdata::hasTypeRecoveryStarted` query used by
    /// propagation and pointer-recovery rules.
    pub fn has_type_recovery_started(&self) -> bool {
        self.type_recovery_started
    }

    /// Whether high-level variables are enabled.
    ///
    /// This mirrors Ghidra's `Funcdata::isHighOn` query used by printers and
    /// prototype recovery.
    pub fn is_high_on(&self) -> bool {
        self.high_level_on
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
        self.new_block_at(start, 0)
    }

    /// A block beginning at one p-code operation of an instruction.
    ///
    /// Only `from_lifted` needs a non-zero order, to split an instruction whose
    /// own operations branch among themselves.
    pub fn new_block_at(&mut self, start: u64, start_order: u32) -> GraphBlockId {
        self.invalidate_masks();
        let id = GraphBlockId(self.blocks.len() as u32);
        self.blocks.push(GraphBlock {
            start,
            start_order,
            ..GraphBlock::default()
        });
        id
    }

    pub fn add_edge(&mut self, from: GraphBlockId, to: GraphBlockId) {
        self.invalidate_masks();
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
        self.invalidate_masks();
        let id = OpId(self.ops.len() as u32);
        self.ops.push(GraphOp {
            opcode,
            seq,
            output: None,
            inputs: Vec::new(),
            parent: None,
            indirect_creation: false,
            non_printing: false,
            input_active: true,
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
        self.invalidate_masks();
        self.ops[op.0 as usize].opcode = opcode;
    }

    /// Replaces every operand, releasing the readers of the old ones.
    pub fn op_set_inputs(&mut self, op: OpId, inputs: Vec<VarnodeId>) {
        self.invalidate_masks();
        for existing in self.ops[op.0 as usize].inputs.clone() {
            self.varnodes[existing.0 as usize].descendants.remove(&op);
        }
        for input in &inputs {
            self.varnodes[input.0 as usize].descendants.insert(op);
        }
        self.ops[op.0 as usize].inputs = inputs;
    }

    pub fn op_set_input(&mut self, op: OpId, value: VarnodeId, slot: usize) {
        self.invalidate_masks();
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
        self.invalidate_masks();
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
        self.invalidate_masks();
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
        self.invalidate_masks();
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
        self.invalidate_masks();
        self.ops[op.0 as usize].parent = Some(block);
        self.blocks[block.0 as usize].ops.insert(0, op);
    }

    /// Appends an operation to the end of a block.
    pub fn op_insert_end(&mut self, op: OpId, block: GraphBlockId) {
        self.invalidate_masks();
        self.ops[op.0 as usize].parent = Some(block);
        self.blocks[block.0 as usize].ops.push(op);
    }

    /// Detaches an operation from its block without destroying it.
    ///
    /// Ghidra's `opUninsert`. The operation keeps its operands and identity, so
    /// it can be re-inserted elsewhere - which is how a merged CBRANCH moves
    /// into the block that now performs the test.
    pub fn op_uninsert(&mut self, op: OpId) {
        self.invalidate_masks();
        if let Some(block) = self.ops[op.0 as usize].parent.take() {
            self.blocks[block.0 as usize].ops.retain(|held| *held != op);
        }
    }

    /// Places an operation at the head of a block.
    pub fn op_insert_begin(&mut self, op: OpId, block: GraphBlockId) {
        self.invalidate_masks();
        self.ops[op.0 as usize].parent = Some(block);
        self.blocks[block.0 as usize].ops.insert(0, op);
    }

    /// Drops one operand, keeping the operand links of the rest current.
    ///
    /// Ghidra's `opRemoveInput`. A phi loses an input when the edge it stood for
    /// is gone.
    pub fn op_remove_input(&mut self, op: OpId, slot: usize) {
        self.invalidate_masks();
        if slot >= self.ops[op.0 as usize].inputs.len() {
            return;
        }
        let removed = self.ops[op.0 as usize].inputs.remove(slot);
        // The value keeps this reader only if another slot still holds it.
        if !self.ops[op.0 as usize].inputs.contains(&removed) {
            self.varnodes[removed.0 as usize].descendants.remove(&op);
        }
    }

    /// Appends one operand at a chosen slot, keeping operand links current.
    ///
    /// Ghidra's `opInsertInput`. A merge gains an input when a new edge stands
    /// for a path that did not exist before.
    pub fn op_insert_input(&mut self, op: OpId, value: VarnodeId, slot: usize) {
        self.invalidate_masks();
        let slot = slot.min(self.ops[op.0 as usize].inputs.len());
        self.ops[op.0 as usize].inputs.insert(slot, value);
        self.varnodes[value.0 as usize].descendants.insert(op);
    }

    /// Whether a value's storage can be named from outside its own definition.
    ///
    /// Ghidra's `Varnode::isAddrTied`, whose flag is written by
    /// `syncVarnodesWithSymbols` from the local symbol scope. This graph decides
    /// it from the storage instead: a temporary is private to the expression
    /// that produced it and a constant has no storage, while every other
    /// location is one the rest of the function can read.
    pub fn is_addr_tied(&self, value: VarnodeId) -> bool {
        let flags = self.varnodes[value.0 as usize].flags;
        !flags.unique && !flags.constant
    }

    /// Gives one edge a different source, keeping its position.
    ///
    /// Ghidra's `BlockGraph::moveOutEdge`, which reaches the target through
    /// `replaceInEdge` and so preserves the in-edge *index*. That matters more
    /// than it looks: a `MULTIEQUAL`'s operand slots are positional against the
    /// predecessor list, so appending the new source instead of replacing in
    /// place would silently reassign every operand from that slot onward.
    ///
    /// Merge operands are deliberately untouched. The edge still delivers the
    /// same value, it simply arrives from somewhere else.
    pub fn move_out_edge(&mut self, from: GraphBlockId, to: GraphBlockId, new_from: GraphBlockId) {
        self.invalidate_masks();
        let Some(slot) = self.blocks[to.0 as usize]
            .predecessors
            .iter()
            .position(|candidate| *candidate == from)
        else {
            return;
        };
        self.blocks[to.0 as usize].predecessors[slot] = new_from;
        self.blocks[from.0 as usize]
            .successors
            .retain(|candidate| *candidate != to);
        let successors = &mut self.blocks[new_from.0 as usize].successors;
        if !successors.contains(&to) {
            successors.push(to);
        }
    }

    /// Removes one edge and leaves the merge operands alone.
    ///
    /// Ghidra's `BlockGraph::removeEdge`, which is a control-flow operation
    /// only: `ConditionalJoin` repairs the affected `MULTIEQUAL`s itself, in
    /// `cutDownMultiequals`, using the operand slots as they were before any
    /// edge moved. Dropping an operand here would leave that repair working
    /// from indices that no longer mean anything.
    ///
    /// Callers own the repair. `remove_edge` is the one to reach for otherwise.
    pub fn remove_edge_keeping_merges(&mut self, from: GraphBlockId, to: GraphBlockId) -> bool {
        self.invalidate_masks();
        if !self.blocks[from.0 as usize].successors.contains(&to) {
            return false;
        }
        self.blocks[from.0 as usize]
            .successors
            .retain(|candidate| *candidate != to);
        if let Some(slot) = self.blocks[to.0 as usize]
            .predecessors
            .iter()
            .position(|candidate| *candidate == from)
        {
            self.blocks[to.0 as usize].predecessors.remove(slot);
        }
        true
    }

    /// Removes an operation from the graph, releasing its operand links.
    pub fn op_destroy(&mut self, op: OpId) {
        self.invalidate_masks();
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
        self.invalidate_masks();
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
        self.invalidate_masks();
        if !self.blocks[from.0 as usize].successors.contains(&to) {
            return false;
        }
        self.blocks[from.0 as usize]
            .successors
            .retain(|candidate| *candidate != to);
        self.detach_predecessor(to, from);
        true
    }

    /// Whether the block covers a position, directly or by absorption.
    pub fn block_covers(&self, block: GraphBlockId, address: u64, order: u32) -> bool {
        let candidate = &self.blocks[block.0 as usize];
        (candidate.start == address && candidate.start_order == order)
            || candidate.absorbed.contains(&(address, order))
    }

    /// The live block covering a p-code position.
    ///
    /// One instruction can hold several blocks, so an address alone is not a
    /// block identity: the position is an address *and* a p-code index. A block
    /// that has absorbed another covers the absorbed block's position too, which
    /// is what keeps an address-valued branch destination resolvable after a
    /// splice.
    pub fn block_at_position(&self, address: u64, order: u32) -> Option<GraphBlockId> {
        self.blocks()
            .map(|(id, _)| id)
            .find(|id| self.block_covers(*id, address, order))
    }

    /// The block beginning at an instruction boundary.
    pub fn block_starting_at(&self, address: u64) -> Option<GraphBlockId> {
        self.block_at_position(address, 0)
    }

    /// The block a branch transfers to when taken.
    ///
    /// A destination in the constant space is a relative p-code branch within
    /// the branching instruction, so it names an operation rather than an
    /// address. Resolving it as an address finds the wrong block or none, which
    /// silently disables every pass that asks where a branch goes.
    pub fn branch_target(&self, branch: OpId) -> Option<GraphBlockId> {
        let operation = &self.ops[branch.0 as usize];
        let target = *operation.inputs.first()?;
        let varnode = &self.varnodes[target.0 as usize];
        if varnode.space == CONST_SPACE {
            let seq = operation.seq;
            let relative = varnode.offset as i64;
            let order = u32::try_from(i64::from(seq.order).checked_add(relative)?).ok()?;
            return self.block_at_position(seq.address, order);
        }
        self.block_starting_at(varnode.offset)
    }

    /// Removes blocks the entry cannot reach.
    ///
    /// Ported from `Funcdata::removeUnreachableBlocks`. Branch folding and
    /// constant conditions leave whole blocks with no path from the entry;
    /// emitting them produces statements after an unconditional transfer.
    ///
    /// The order is Ghidra's, and it is not incidental. Every block is marked
    /// dead *first*, then every out edge is severed - which drops the operand
    /// each removed edge contributed to a merge in a live successor - and only
    /// then are the blocks themselves removed. Doing it block by block would
    /// let one removal strand a value another removal was still going to
    /// repair. A reader left behind in a live block reads
    /// `Funcdata::descend2Undef`'s marker constant rather than a definition
    /// that no longer exists.
    pub fn remove_unreachable_blocks(&mut self) -> usize {
        self.invalidate_masks();
        let entry = self
            .entry_block()
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
            self.blocks[id.0 as usize].dead = true;
        }
        for id in unreachable.iter().copied() {
            for successor in self.blocks[id.0 as usize].successors.clone() {
                self.remove_edge(id, successor);
            }
        }
        for id in unreachable.iter().copied() {
            self.block_remove_internal(id, true);
        }
        unreachable.len()
    }

    /// Drops one incoming edge, along with the merge operand it fed.
    ///
    /// Ghidra's `Funcdata::branchRemoveInternal` follows the operand removal
    /// with `opZeroMulti`, so a merge left holding a single operand becomes the
    /// copy it now is instead of staying a marker.
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
            if slot < self.ops[phi.0 as usize].inputs.len() {
                self.op_remove_input(phi, slot);
                self.op_zero_multi(phi);
            }
        }
    }

    /// Turns a merge that no longer merges into the copy it has become.
    ///
    /// Ghidra's `Funcdata::opZeroMulti`. With no operands left the block is
    /// unreachable, so the value becomes a function input; with one operand the
    /// marker is simply a `COPY`. The difference is load-bearing rather than
    /// cosmetic: a marker is exactly what `has_only_markers` counts as "does
    /// nothing", so leaving a one-operand `MULTIEQUAL` behind decides whether a
    /// later pass may remove the block at all.
    pub fn op_zero_multi(&mut self, op: OpId) {
        let count = self.ops[op.0 as usize].inputs.len();
        if count == 1 {
            self.op_set_opcode(op, ventris_pcode::op::COPY);
            return;
        }
        if count != 0 {
            return;
        }
        let Some(output) = self.ops[op.0 as usize].output else {
            return;
        };
        let varnode = &self.varnodes[output.0 as usize];
        let (space, offset, size) = (varnode.space, varnode.offset, varnode.size);
        let replacement = self.new_varnode(space, offset, size);
        self.mark_input(replacement);
        self.op_set_inputs(op, vec![replacement]);
        self.op_set_opcode(op, ventris_pcode::op::COPY);
    }

    /// Whether the block holds nothing but SSA markers and a branch.
    ///
    /// Ghidra's `BlockBasic::hasOnlyMarkers`: `MULTIEQUAL` and `INDIRECT` are
    /// placeholders for data flowing *through* the block, and a branch is how
    /// every block ends, so neither counts as work.
    pub fn has_only_markers(&self, block: GraphBlockId) -> bool {
        self.blocks[block.0 as usize].ops.iter().all(|op| {
            matches!(
                self.ops[op.0 as usize].opcode,
                ventris_pcode::op::MULTIEQUAL
                    | ventris_pcode::op::INDIRECT
                    | ventris_pcode::op::BRANCH
                    | ventris_pcode::op::CBRANCH
                    | ventris_pcode::op::BRANCHIND
            )
        })
    }

    /// The block's last live operation.
    fn last_opcode(&self, block: GraphBlockId) -> Option<i32> {
        self.blocks[block.0 as usize]
            .ops
            .iter()
            .rev()
            .find_map(|op| {
                let operation = &self.ops[op.0 as usize];
                (!operation.dead).then_some(operation.opcode)
            })
    }

    /// Whether the block ends in a computed jump.
    ///
    /// Ghidra's `FlowBlock::isSwitchOut`, which flow analysis sets on the block
    /// holding a `BRANCHIND`.
    pub fn is_switch_out(&self, block: GraphBlockId) -> bool {
        self.last_opcode(block) == Some(ventris_pcode::op::BRANCHIND)
    }

    /// Whether the block begins the function.
    pub fn is_entry_block(&self, block: GraphBlockId) -> bool {
        self.block_covers(block, self.entry, 0)
    }

    /// The live block the function enters through.
    pub fn entry_block(&self) -> Option<GraphBlockId> {
        self.block_starting_at(self.entry)
    }

    /// Whether the block does nothing and should be removed.
    ///
    /// Ghidra's `BlockBasic::isDoNothing`. The test is *not* "holds a single
    /// `BRANCH`": a block holding only merges, or holding nothing at all, does
    /// nothing just as much, and Ghidra removes all three. The guards carry the
    /// rest - a switch target whose successor several blocks reach may still be
    /// propagating the value its own switch edge selected, and a single-out
    /// computed jump is a jump-table stage rather than a transfer.
    pub fn is_do_nothing(&self, block: GraphBlockId) -> bool {
        let candidate = &self.blocks[block.0 as usize];
        if candidate.dead || candidate.successors.len() != 1 {
            return false;
        }
        // A block with no way in may be the placeholder holding persistent
        // values, so Ghidra keeps it.
        if candidate.predecessors.is_empty() {
            return false;
        }
        let successor = candidate.successors[0];
        for predecessor in candidate.predecessors.clone() {
            if !self.is_switch_out(predecessor) {
                continue;
            }
            if self.blocks[predecessor.0 as usize].successors.len() > 1
                && self.blocks[successor.0 as usize].predecessors.len() > 1
            {
                return false;
            }
        }
        if self.last_opcode(block) == Some(ventris_pcode::op::BRANCHIND) {
            return false;
        }
        self.has_only_markers(block)
    }

    /// Whether removing this block would leave two edges into its successor
    /// disagreeing about a merged value.
    ///
    /// Ghidra's `BlockBasic::unblockedMulti`. Removing the block makes each of
    /// its predecessors a direct predecessor of the successor, so a predecessor
    /// that *already* reaches the successor would then reach it twice - and a
    /// merge there reads one operand per edge. The removal is only sound when
    /// both edges deliver the same value.
    pub fn unblocked_multi(&self, block: GraphBlockId, out_slot: usize) -> bool {
        let Some(&successor) = self.blocks[block.0 as usize].successors.get(out_slot) else {
            return true;
        };
        let redundant: Vec<GraphBlockId> = self.blocks[block.0 as usize]
            .predecessors
            .iter()
            .copied()
            .filter(|predecessor| {
                self.blocks[predecessor.0 as usize]
                    .successors
                    .contains(&successor)
            })
            .collect();
        if redundant.is_empty() {
            return true;
        }
        let slot_of = |candidate: GraphBlockId| {
            self.blocks[successor.0 as usize]
                .predecessors
                .iter()
                .position(|held| *held == candidate)
        };
        let Some(removed_slot) = slot_of(block) else {
            return true;
        };
        for op in self.blocks[successor.0 as usize].ops.clone() {
            if self.ops[op.0 as usize].opcode != ventris_pcode::op::MULTIEQUAL {
                continue;
            }
            let Some(&through_removed) = self.ops[op.0 as usize].inputs.get(removed_slot) else {
                continue;
            };
            for predecessor in redundant.iter().copied() {
                let Some(slot) = slot_of(predecessor) else {
                    continue;
                };
                let Some(&competing) = self.ops[op.0 as usize].inputs.get(slot) else {
                    continue;
                };
                // A merge *in the removed block* stands for whatever each of
                // its own predecessors delivers, so the comparison is against
                // the operand this predecessor contributes to that merge.
                let mut arriving = through_removed;
                if let Some(definition) = self.varnodes[through_removed.0 as usize].def
                    && self.ops[definition.0 as usize].opcode == ventris_pcode::op::MULTIEQUAL
                    && self.ops[definition.0 as usize].parent == Some(block)
                    && let Some(inner) = self.blocks[block.0 as usize]
                        .predecessors
                        .iter()
                        .position(|held| *held == predecessor)
                    && let Some(&operand) = self.ops[definition.0 as usize].inputs.get(inner)
                {
                    arriving = operand;
                }
                if arriving != competing {
                    return false;
                }
            }
        }
        true
    }

    /// Rehomes the merges *defined in* a block about to be removed.
    ///
    /// Ghidra's `Funcdata::pushMultiequals`. A merge in the removed block can
    /// still have readers beyond its successor, and those readers cannot be left
    /// naming a definition that no longer exists. The replacement is an
    /// artificial merge at the head of the successor: on the edge from the
    /// removed block it delivers the original value, and on every other edge it
    /// delivers itself, because the removed block dominates those edges and so
    /// nothing else can arrive along them.
    fn push_multiequals(&mut self, block: GraphBlockId) {
        let successors = self.blocks[block.0 as usize].successors.clone();
        let Some(&successor) = successors.first() else {
            return;
        };
        let Some(removed_slot) = self.blocks[successor.0 as usize]
            .predecessors
            .iter()
            .position(|held| *held == block)
        else {
            return;
        };
        let phis: Vec<OpId> = self.blocks[block.0 as usize]
            .ops
            .iter()
            .copied()
            .filter(|op| self.ops[op.0 as usize].opcode == ventris_pcode::op::MULTIEQUAL)
            .collect();
        for phi in phis {
            let Some(original) = self.ops[phi.0 as usize].output else {
                continue;
            };
            if self.varnodes[original.0 as usize].descendants.is_empty() {
                continue;
            }
            let mut needs_replacement = false;
            let mut needs_unique = false;
            let readers: Vec<OpId> = self.varnodes[original.0 as usize]
                .descendants
                .iter()
                .copied()
                .collect();
            for reader in readers {
                let operation = &self.ops[reader.0 as usize];
                if operation.opcode == ventris_pcode::op::MULTIEQUAL
                    && operation.parent == Some(successor)
                {
                    let dead_edge = !operation
                        .inputs
                        .iter()
                        .enumerate()
                        .any(|(slot, input)| slot != removed_slot && *input == original);
                    if dead_edge {
                        // An address-tied value feeding a merge at its own
                        // address means every use beyond the successor reached
                        // that use through some other register, so the
                        // artificial merge must not claim the address.
                        if let Some(output) = operation.output
                            && self.varnodes[output.0 as usize].space
                                == self.varnodes[original.0 as usize].space
                            && self.varnodes[output.0 as usize].offset
                                == self.varnodes[original.0 as usize].offset
                            && self.is_addr_tied(original)
                        {
                            needs_unique = true;
                        }
                        continue;
                    }
                }
                needs_replacement = true;
                break;
            }
            if !needs_replacement {
                continue;
            }
            let varnode = &self.varnodes[original.0 as usize];
            let (space, offset, size) = (varnode.space, varnode.offset, varnode.size);
            let replacement = if needs_unique {
                self.new_unique(size)
            } else {
                self.new_varnode(space, offset, size)
            };
            let branches: Vec<VarnodeId> = self.blocks[successor.0 as usize]
                .predecessors
                .clone()
                .into_iter()
                .map(|predecessor| {
                    if predecessor == block {
                        original
                    } else {
                        replacement
                    }
                })
                .collect();
            let seq = SeqNum {
                address: self.blocks[successor.0 as usize].start,
                order: self.blocks[successor.0 as usize].start_order,
            };
            let artificial = self.new_op(ventris_pcode::op::MULTIEQUAL, seq, branches);
            self.op_set_output(artificial, Some(replacement));
            self.op_insert_begin(artificial, successor);
            let readers: Vec<OpId> = self.varnodes[original.0 as usize]
                .descendants
                .iter()
                .copied()
                .collect();
            for reader in readers {
                if reader == artificial {
                    continue;
                }
                let slots: Vec<usize> = self.ops[reader.0 as usize]
                    .inputs
                    .iter()
                    .enumerate()
                    .filter(|(_, input)| **input == original)
                    .map(|(slot, _)| slot)
                    .collect();
                for slot in slots {
                    if slot == removed_slot
                        && self.ops[reader.0 as usize].parent == Some(successor)
                        && self.ops[reader.0 as usize].opcode == ventris_pcode::op::MULTIEQUAL
                    {
                        continue;
                    }
                    self.op_set_input(reader, replacement, slot);
                    break;
                }
            }
        }
    }

    /// Removes a block, patching the data flow that ran through it.
    ///
    /// Ghidra's `Funcdata::blockRemoveInternal`. Two repairs make this more than
    /// an edge rewrite. A merge in the successor loses the operand this block
    /// delivered and gains one per predecessor of this block - and where the
    /// lost operand was itself a merge *here*, each predecessor contributes that
    /// merge's own operand rather than a copy of the whole. Then
    /// `push_multiequals` rehomes the merges defined here whose readers are
    /// elsewhere. Dropping either repair loses the phi structure a loop's shape
    /// depends on, which is why widening the removal test without them cost
    /// three corpus functions.
    ///
    /// Both the new operands and the new predecessor edges are *appended*, and
    /// they have to be: `BlockGraph::removeFromFlow` severs this block's own
    /// edge to the successor before retargeting anything, so the retargeted
    /// edges land at the end of the successor's in-edge list, which is exactly
    /// where `opInsertInput(op,...,op->numInput())` puts the operands.
    ///
    /// One divergence is forced by this graph interning duplicate edges where
    /// Ghidra keeps them: a predecessor that already reaches the successor gains
    /// no second edge here, so it contributes no operand either. That case is
    /// only reached with `unblocked_multi`'s agreement, which is precisely the
    /// guarantee that the operand it would have contributed is the one already
    /// present.
    fn block_remove_internal(&mut self, block: GraphBlockId, unreachable: bool) {
        if !unreachable {
            self.push_multiequals(block);
            let predecessors = self.blocks[block.0 as usize].predecessors.clone();
            for successor in self.blocks[block.0 as usize].successors.clone() {
                if self.blocks[successor.0 as usize].dead {
                    continue;
                }
                let Some(slot) = self.blocks[successor.0 as usize]
                    .predecessors
                    .iter()
                    .position(|held| *held == block)
                else {
                    continue;
                };
                // The edges that will actually be appended, in order, skipping
                // the predecessors this graph has already interned.
                let arriving: Vec<usize> = predecessors
                    .iter()
                    .enumerate()
                    .filter(|(_, predecessor)| {
                        !self.blocks[successor.0 as usize]
                            .predecessors
                            .contains(predecessor)
                    })
                    .map(|(index, _)| index)
                    .collect();
                let phis: Vec<OpId> = self.blocks[successor.0 as usize]
                    .ops
                    .iter()
                    .copied()
                    .filter(|op| self.ops[op.0 as usize].opcode == ventris_pcode::op::MULTIEQUAL)
                    .collect();
                for phi in phis {
                    let Some(&dead_value) = self.ops[phi.0 as usize].inputs.get(slot) else {
                        continue;
                    };
                    self.op_remove_input(phi, slot);
                    let inner = self.varnodes[dead_value.0 as usize]
                        .def
                        .filter(|definition| {
                            self.ops[definition.0 as usize].opcode == ventris_pcode::op::MULTIEQUAL
                                && self.ops[definition.0 as usize].parent == Some(block)
                        });
                    for index in arriving.iter().copied() {
                        let operand = match inner {
                            Some(definition) => self.ops[definition.0 as usize]
                                .inputs
                                .get(index)
                                .copied()
                                .unwrap_or(dead_value),
                            None => dead_value,
                        };
                        let end = self.ops[phi.0 as usize].inputs.len();
                        self.op_insert_input(phi, operand, end);
                    }
                    self.op_zero_multi(phi);
                }
            }
        }
        // `BlockGraph::removeFromFlow`: sever this block's out edge first, then
        // retarget every in edge at the successor, appending as it goes.
        //
        // Ghidra's branch destinations are block references, so retargeting an
        // edge is all it has to do. Here a destination is an address, and the
        // removed block's address is about to name nothing - a predecessor's
        // `BRANCH` would be left pointing at a label that is never emitted.
        // The successor therefore inherits this block's position: control that
        // arrived here now arrives there, which is exactly what the retargeted
        // edge says.
        for successor in self.blocks[block.0 as usize].successors.clone() {
            self.blocks[block.0 as usize]
                .successors
                .retain(|held| *held != successor);
            self.blocks[successor.0 as usize]
                .predecessors
                .retain(|held| *held != block);
            if !unreachable {
                let inherited = {
                    let removed = &self.blocks[block.0 as usize];
                    let mut inherited = vec![(removed.start, removed.start_order)];
                    inherited.extend(removed.absorbed.iter().copied());
                    inherited
                };
                self.blocks[successor.0 as usize].absorbed.extend(inherited);
            }
            for predecessor in self.blocks[block.0 as usize].predecessors.clone() {
                self.blocks[predecessor.0 as usize]
                    .successors
                    .retain(|held| *held != block);
                if predecessor == block {
                    continue;
                }
                self.add_edge(predecessor, successor);
            }
        }
        for predecessor in self.blocks[block.0 as usize].predecessors.clone() {
            self.blocks[predecessor.0 as usize]
                .successors
                .retain(|held| *held != block);
        }
        for op in self.blocks[block.0 as usize].ops.clone() {
            if unreachable && let Some(output) = self.ops[op.0 as usize].output {
                self.descend_to_undef(output);
            }
            self.op_destroy(op);
        }
        let removed = &mut self.blocks[block.0 as usize];
        removed.ops.clear();
        removed.predecessors.clear();
        removed.successors.clear();
        removed.dead = true;
    }

    /// Replaces every live read of a stranded value with a marker constant.
    ///
    /// Ghidra's `Funcdata::descend2Undef`, reached when unreachable-block
    /// removal leaves a reader behind. A merge cannot take a constant operand
    /// directly, so the constant arrives through a `COPY` placed in the
    /// predecessor whose edge the operand stands for.
    fn descend_to_undef(&mut self, value: VarnodeId) -> bool {
        let mut modified = false;
        let size = self.varnodes[value.0 as usize].size;
        let readers: Vec<OpId> = self.varnodes[value.0 as usize]
            .descendants
            .iter()
            .copied()
            .collect();
        for reader in readers {
            let Some(parent) = self.ops[reader.0 as usize].parent else {
                continue;
            };
            if self.blocks[parent.0 as usize].dead {
                continue;
            }
            if !self.blocks[parent.0 as usize].predecessors.is_empty() {
                modified = true;
            }
            let Some(slot) = self.ops[reader.0 as usize]
                .inputs
                .iter()
                .position(|input| *input == value)
            else {
                continue;
            };
            let marker = self.new_constant(0x00BA_DDEF, size);
            if self.ops[reader.0 as usize].opcode == ventris_pcode::op::MULTIEQUAL {
                let Some(&source) = self.blocks[parent.0 as usize].predecessors.get(slot) else {
                    continue;
                };
                let seq = SeqNum {
                    address: self.blocks[source.0 as usize].start,
                    order: self.blocks[source.0 as usize].start_order,
                };
                let copy = self.new_op(ventris_pcode::op::COPY, seq, vec![marker]);
                let carried = self.new_unique(size);
                self.op_set_output(copy, Some(carried));
                self.op_insert_end(copy, source);
                self.op_set_input(reader, carried, slot);
            } else if self.ops[reader.0 as usize].opcode == ventris_pcode::op::INDIRECT {
                let seq = self.ops[reader.0 as usize].seq;
                let copy = self.new_op(ventris_pcode::op::COPY, seq, vec![marker]);
                let carried = self.new_unique(size);
                self.op_set_output(copy, Some(carried));
                self.op_insert_begin(copy, parent);
                self.op_set_input(reader, carried, slot);
            } else {
                self.op_set_input(reader, marker, slot);
            }
        }
        modified
    }

    /// Removes a block that performs no operations.
    ///
    /// Ghidra's `Funcdata::removeDoNothingBlock`, which is `blockRemoveInternal`
    /// on a *live* block: the phi repairs run, so every value that flowed
    /// through the block still reaches its readers afterwards.
    pub fn remove_do_nothing_block(&mut self, block: GraphBlockId) -> bool {
        self.invalidate_masks();
        if self.blocks[block.0 as usize].dead || self.blocks[block.0 as usize].successors.len() > 1
        {
            return false;
        }
        self.block_remove_internal(block, false);
        true
    }

    /// Merges a block with the single block it flows into.
    ///
    /// Ghidra's `Funcdata::spliceBlockBasic`: the *successor's* operations move
    /// into this block, and this block inherits the successor's out edges. Which
    /// block survives is observable - the survivor keeps this block's start
    /// address, so emitted order and labels follow the earlier address, as
    /// Ghidra's do.
    pub fn splice_block_basic(&mut self, block: GraphBlockId) -> bool {
        self.invalidate_masks();
        let candidate = &self.blocks[block.0 as usize];
        if candidate.dead || candidate.successors.len() != 1 {
            return false;
        }
        let successor = candidate.successors[0];
        if successor == block
            || self.blocks[successor.0 as usize].dead
            || self.blocks[successor.0 as usize].predecessors.len() != 1
        {
            return false;
        }
        // Ghidra throws here: a merge at the head of the successor reads one
        // operand per edge, and the successor is about to have no edges at all.
        if self.blocks[successor.0 as usize]
            .ops
            .first()
            .is_some_and(|op| self.ops[op.0 as usize].opcode == ventris_pcode::op::MULTIEQUAL)
        {
            return false;
        }
        if let Some(&last) = self.blocks[block.0 as usize].ops.last()
            && matches!(
                self.ops[last.0 as usize].opcode,
                ventris_pcode::op::BRANCH
                    | ventris_pcode::op::CBRANCH
                    | ventris_pcode::op::BRANCHIND
            )
        {
            self.op_destroy(last);
        }
        for op in self.blocks[successor.0 as usize].ops.clone() {
            self.ops[op.0 as usize].parent = Some(block);
            self.blocks[block.0 as usize].ops.push(op);
        }
        self.blocks[successor.0 as usize].ops.clear();
        self.blocks[block.0 as usize]
            .successors
            .retain(|held| *held != successor);
        self.blocks[successor.0 as usize].predecessors.clear();
        for target in self.blocks[successor.0 as usize].successors.clone() {
            if target == successor {
                // A self-loop on the removed block becomes a self-loop here.
                self.blocks[successor.0 as usize]
                    .successors
                    .retain(|held| *held != target);
                self.add_edge(block, block);
                continue;
            }
            self.move_out_edge(successor, target, block);
        }
        // `BlockBasic::mergeRange`: the survivor covers the absorbed block's
        // position, and everything that block had itself absorbed.
        let merged = {
            let removed = &self.blocks[successor.0 as usize];
            let mut merged = vec![(removed.start, removed.start_order)];
            merged.extend(removed.absorbed.iter().copied());
            merged
        };
        self.blocks[block.0 as usize].absorbed.extend(merged);
        self.blocks[successor.0 as usize].absorbed.clear();
        self.blocks[successor.0 as usize].predecessors.clear();
        self.blocks[successor.0 as usize].successors.clear();
        self.blocks[successor.0 as usize].dead = true;
        true
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
        let mut block_of_position: BTreeMap<(u64, u32), GraphBlockId> = BTreeMap::new();
        for (address, order) in &leaders {
            let id = data.new_block_at(*address, *order);
            block_of_position.insert((*address, *order), id);
        }
        let mut block = None;
        // Branches taken within one instruction, recorded while the operations
        // are walked and wired once every block exists.
        let mut internal: Vec<((u64, u32), (u64, u32), (u64, u32))> = Vec::new();
        // A transfer whose delay slot the lifter already folded into it has that
        // instruction's operations twice: once in the right place, before the
        // transfer, and once as an instruction of its own after it. Executing the
        // second copy is wrong on any delay-slot architecture, and it reads
        // registers the call has meanwhile killed - `getBuiltInTexture` compared
        // `memcmp`'s result against the address a `lui` had left in `$v0`,
        // because the `addiu` that consumed it ran again after the call.
        let embedded_delay_slots = embedded_delay_slot_addresses(function);
        for (address, instruction) in &function.instructions {
            if embedded_delay_slots.contains(address) {
                continue;
            }
            for (index, operation) in instruction.pcode.ops.iter().enumerate() {
                let order = index as u32;
                if let Some(id) = block_of_position.get(&(*address, order)) {
                    block = Some(*id);
                }
                let Some(block) = block else { continue };
                if let Some(target) = internal_branch_target(operation, index) {
                    // A relative destination past the last operation leaves the
                    // instruction, so it transfers to the next one - dropping it
                    // instead left the branch with a single successor and a test
                    // that decided nothing.
                    let taken = if (target as usize) < instruction.pcode.ops.len() {
                        (*address, target)
                    } else {
                        (address.wrapping_add(u64::from(instruction.pcode.len)), 0)
                    };
                    internal.push(((*address, order), taken, (*address, order + 1)));
                } else if operation.opcode == ventris_pcode::op::CBRANCH
                    && (index + 1) < instruction.pcode.ops.len()
                    && let Some(destination) = operation.inputs.first()
                    && destination.space != CONST_SPACE
                {
                    // A conditional whose remaining operations are its own
                    // not-taken arm: the taken side is the named address, the
                    // other side is the rest of this instruction.
                    internal.push((
                        (*address, order),
                        (destination.offset, 0),
                        (*address, order + 1),
                    ));
                }
                let inputs = operation
                    .inputs
                    .iter()
                    .map(|input| data.value_for_read(*input))
                    .collect();
                let seq = SeqNum {
                    address: *address,
                    order,
                };
                let op = data.new_op(operation.opcode, seq, inputs);
                data.op_insert_end(op, block);
                if let Some(output) = operation.output {
                    let value = data.new_varnode(output.space, output.offset, output.size);
                    data.op_set_output(op, Some(value));
                }
                // A relative destination that lands outside the instruction is
                // an ordinary branch to the next address, so spell it as one.
                // Left as a p-code index, every pass that resolves a branch
                // target found nothing and skipped the block.
                if let Some(target) = internal_branch_target(operation, index)
                    && (target as usize) >= instruction.pcode.ops.len()
                {
                    let next = data.new_varnode(
                        ventris_lifter::RAM_SPACE,
                        address.wrapping_add(u64::from(instruction.pcode.len)),
                        4,
                    );
                    data.op_set_input(op, next, 0);
                }
            }
        }
        // The taken side first, so `successors[0]` is the branch's own taken
        // target exactly as it is for a machine-level conditional branch.
        for (source, taken, fallthrough) in internal {
            let Some(from) = enclosing_block(&block_of_position, source) else {
                continue;
            };
            for destination in [taken, fallthrough] {
                if let Some(to) = block_of_position.get(&destination).copied() {
                    data.add_edge(from, to);
                }
            }
        }
        // Consecutive blocks within one instruction fall through to each other.
        // Without this the guarded body of an internal branch has no successor
        // at all, so it reads as a dead end and structuring emits a goto rather
        // than the `if` the guard actually is.
        let positions: Vec<((u64, u32), GraphBlockId)> =
            block_of_position.iter().map(|(k, v)| (*k, *v)).collect();
        for pair in positions.windows(2) {
            let ((address, _), from) = pair[0];
            let ((next_address, _), to) = pair[1];
            if address != next_address {
                continue; // The machine edges below carry flow between instructions.
            }
            let terminal = data
                .block(from)
                .ops
                .last()
                .copied()
                .is_some_and(|op| leaves_block_unconditionally(data.op(op).opcode));
            if !terminal {
                data.add_edge(from, to);
            }
        }
        for (source, target) in &function.edges {
            if let (Some(from), Some(to)) = (
                // A machine edge leaves the last operation of its instruction,
                // which is the last block that instruction was split into.
                enclosing_block(&block_of_position, (*source, u32::MAX)),
                block_of_position.get(&(*target, 0)).copied(),
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

/// Addresses that begin a basic block.
///
/// A basic block runs from a leader to the next, and Ghidra's are maximal: flow
/// enters only at the top and leaves only at the bottom. So a leader is the
/// entry, a branch target, the instruction after a branch, or a join - and
/// crucially *not* the target of a plain fall-through that nothing else reaches.
///
/// Treating every fall-through target as a leader gives one block per
/// instruction. The graph is still correct, and structuring still recovers the
/// same constructs by concatenating, but every ported algorithm that reasons
/// about a block as a unit is then working on the wrong unit: "the last
/// operation in the block", which decides a for-loop's iterator, a condition
/// block's complexity and where a statement may be moved to, means nothing when
/// the block holds one instruction.
/// Delay-slot instructions whose operations a preceding transfer already carries.
///
/// The lifter folds a delay slot into the transfer that owns it and reports how
/// many bytes it absorbed. The absorbed instruction is still present in the
/// listing, so a graph built straight from the listing runs it a second time,
/// after the transfer instead of before it.
///
/// A delay slot that begins a block is left alone: something branches to it, so
/// it has to keep its own identity.
fn embedded_delay_slot_addresses(function: &NativeFunction) -> BTreeSet<u64> {
    let mut embedded = BTreeSet::new();
    for (address, instruction) in &function.instructions {
        if instruction.embedded_delay_slot_bytes == 0 {
            continue;
        }
        // `pcode.len` is the transfer's own length; the folded bytes are
        // reported separately, so the slot begins just past it - the same
        // arithmetic the address-ordered emitter uses.
        let Some(delay) = address.checked_add(u64::from(instruction.pcode.len)) else {
            continue;
        };
        if function.instructions.contains_key(&delay) {
            embedded.insert(delay);
        }
    }
    embedded
}

fn block_leaders(function: &NativeFunction) -> BTreeSet<(u64, u32)> {
    let mut leaders = BTreeSet::from([(function.entry, 0u32)]);
    let mut arrivals: BTreeMap<u64, usize> = BTreeMap::new();
    let mut departures: BTreeMap<u64, usize> = BTreeMap::new();
    for (source, target) in &function.edges {
        *arrivals.entry(*target).or_default() += 1;
        *departures.entry(*source).or_default() += 1;
    }
    for (source, target) in &function.edges {
        // A join: flow arrives from more than one place, so it cannot be in the
        // middle of a block.
        if arrivals.get(target).copied().unwrap_or(0) > 1 {
            leaders.insert((*target, 0));
        }
        let Some(instruction) = function.instructions.get(source) else {
            continue;
        };
        let sequential = source.wrapping_add(u64::from(instruction.pcode.len));
        if *target != sequential {
            // A branch ends its block, and both of its destinations begin one.
            leaders.insert((*target, 0));
            leaders.insert((sequential, 0));
        } else if departures.get(source).copied().unwrap_or(0) > 1 {
            // The fall-through side of a conditional branch.
            leaders.insert((*target, 0));
        }
    }
    leaders.retain(|(address, _)| function.instructions.contains_key(address));
    // A branch among one instruction's own operations splits it, exactly as a
    // machine branch splits a function. Both destinations begin a block.
    //
    // This covers a destination in the constant space - a relative p-code branch
    // - and equally a `CBRANCH` to an address that is simply not the last
    // operation of its instruction. PPC `beqlr` is the second shape: it lifts to
    // `if (!cond) goto <next>; return;`, so the conditional return lives inside
    // one instruction, and leaving it unsplit merged the guard away entirely.
    for (address, instruction) in &function.instructions {
        let last = instruction.pcode.ops.len().saturating_sub(1);
        for (index, operation) in instruction.pcode.ops.iter().enumerate() {
            if let Some(target) = internal_branch_target(operation, index) {
                if (target as usize) < instruction.pcode.ops.len() {
                    leaders.insert((*address, target));
                } else {
                    // Past the last operation is out of the instruction: the
                    // branch transfers to the next one, which therefore begins a
                    // block.
                    leaders.insert((address.wrapping_add(u64::from(instruction.pcode.len)), 0));
                }
                leaders.insert((*address, index as u32 + 1));
            } else if operation.opcode == ventris_pcode::op::CBRANCH && index < last {
                // The operations after it are the taken-or-not remainder of this
                // instruction, so they are their own block - and the address it
                // names begins one, exactly as a machine branch target does.
                leaders.insert((*address, index as u32 + 1));
                // A target that is simply this instruction's own successor is
                // already where the following block begins; splitting there as
                // well separates operations Ghidra keeps in one block. Only a
                // target elsewhere needs a leader of its own.
                let sequential = address.wrapping_add(u64::from(instruction.pcode.len));
                if let Some(destination) = operation.inputs.first()
                    && destination.space != CONST_SPACE
                    && destination.offset != sequential
                    && function.instructions.contains_key(&destination.offset)
                {
                    leaders.insert((destination.offset, 0));
                }
            }
        }
    }
    // Every leader must name a lifted instruction, and an intra-instruction one
    // must land on an operation that exists - otherwise the block gets no
    // operations at all while still carrying the edges that named it, which is a
    // block with two successors and no branch to choose between them.
    leaders.retain(|(address, order)| {
        function
            .instructions
            .get(address)
            .is_some_and(|instruction| {
                *order == 0 || (*order as usize) < instruction.pcode.ops.len()
            })
    });
    leaders
}

/// Whether an operation always transfers control away from its block.
///
/// A block ending in one of these does not fall through, so no fall-through
/// edge may be drawn out of it. `CBRANCH` is deliberately absent: it falls
/// through when not taken.
fn leaves_block_unconditionally(opcode: i32) -> bool {
    use ventris_pcode::op;
    matches!(opcode, op::BRANCH | op::BRANCHIND | op::RETURN)
}

/// The p-code index a `CBRANCH` inside one instruction transfers to.
///
/// A destination in the constant space is a *relative* p-code branch: the
/// constant is added to the branching operation's own index. This is how SLEIGH
/// expresses a guard over part of one instruction - PPC paired-single arithmetic
/// and MIPS likely-branch delay slots both emit it - and treating it as an
/// ordinary conditional branch to an address loses the guard entirely.
fn internal_branch_target(operation: &ventris_pcode::PcodeOp, index: usize) -> Option<u32> {
    if operation.opcode != ventris_pcode::op::CBRANCH {
        return None;
    }
    let destination = operation.inputs.first()?;
    if destination.space != CONST_SPACE {
        return None;
    }
    let relative = destination.offset as i64;
    let target = i64::try_from(index).ok()?.checked_add(relative)?;
    u32::try_from(target).ok().filter(|target| *target > 0)
}

fn enclosing_block(
    block_of_position: &BTreeMap<(u64, u32), GraphBlockId>,
    position: (u64, u32),
) -> Option<GraphBlockId> {
    block_of_position
        .range(..=position)
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

    /// A transfer's delay slot is folded into the transfer by the lifter, which
    /// reports the bytes it absorbed - but the absorbed instruction is still in
    /// the listing. Building the graph straight from the listing ran it a second
    /// time, after the transfer instead of before it, and the second copy read
    /// registers the call had meanwhile killed.
    /// `Funcdata::spliceBlockBasic` refuses unless the successor has exactly one
    /// way in - it throws otherwise - because splicing moves the successor's
    /// operations into this block, and any other predecessor of the successor
    /// would then reach code that has moved.
    #[test]
    fn a_splice_refuses_a_successor_several_blocks_reach() {
        use ventris_lifter::RAM_SPACE;
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        let transfer = data.new_block(0x1010);
        let shared = data.new_block(0x1020);
        data.add_edge(entry, transfer);
        data.add_edge(entry, shared);
        data.add_edge(transfer, shared);
        let destination = data.new_varnode(RAM_SPACE, 0x1020, 4);
        let branch = data.new_op(
            op::BRANCH,
            SeqNum {
                address: 0x1010,
                order: 0,
            },
            vec![destination],
        );
        data.op_insert_end(branch, transfer);

        assert!(
            !data.splice_block_basic(transfer),
            "the shared successor is reached from two blocks"
        );

        // With the other edge gone the splice is safe again.
        assert!(data.remove_edge(entry, shared));
        assert!(data.splice_block_basic(transfer));
        // Ghidra keeps the *earlier* block: the successor's operations move into
        // it, so labels and emitted order follow the lower address.
        assert!(data.block(shared).dead);
        assert!(!data.block(transfer).dead);
        assert_eq!(data.block(transfer).start, 0x1010);
    }

    #[test]
    fn an_embedded_delay_slot_is_not_executed_a_second_time() {
        use std::collections::BTreeMap as Map;
        use ventris_lifter::{Flow, LiftedInstruction, RAM_SPACE, REGISTER_SPACE};
        use ventris_pcode::InstPcode;
        let slot = |address: u64| PcodeOp {
            opcode: op::INT_ADD,
            output: Some(Varnode::new(REGISTER_SPACE, 8, 4)),
            inputs: vec![
                Varnode::new(REGISTER_SPACE, 16, 4),
                Varnode::new(CONST_SPACE, address, 4),
            ],
        };
        let mut instructions = Map::new();
        // The call carries its slot's operation, and names one byte of slot.
        instructions.insert(
            0x1000,
            LiftedInstruction {
                address: 0x1000,
                bytes: vec![0, 0, 0, 0],
                pcode: InstPcode {
                    len: 4,
                    space: RAM_SPACE,
                    offset: 0x1000,
                    ops: vec![
                        slot(0x40),
                        PcodeOp {
                            opcode: op::CALL,
                            output: None,
                            inputs: vec![Varnode::new(RAM_SPACE, 0x2000, 4)],
                        },
                    ],
                },
                flow: Flow::Call {
                    target: 0x2000,
                    fallthrough: 0x1004,
                },
                embedded_delay_slot_bytes: 1,
            },
        );
        // The same instruction, still present in the listing.
        instructions.insert(
            0x1004,
            LiftedInstruction {
                address: 0x1004,
                bytes: vec![0, 0, 0, 0],
                pcode: InstPcode {
                    len: 4,
                    space: RAM_SPACE,
                    offset: 0x1004,
                    ops: vec![slot(0x40)],
                },
                flow: Flow::FallThrough(0x1008),
                embedded_delay_slot_bytes: 0,
            },
        );
        instructions.insert(
            0x1008,
            LiftedInstruction {
                address: 0x1008,
                bytes: vec![0, 0, 0, 0],
                pcode: InstPcode {
                    len: 4,
                    space: RAM_SPACE,
                    offset: 0x1008,
                    ops: vec![PcodeOp {
                        opcode: op::RETURN,
                        output: None,
                        inputs: vec![Varnode::new(REGISTER_SPACE, 496, 4)],
                    }],
                },
                flow: Flow::Return,
                embedded_delay_slot_bytes: 0,
            },
        );
        let mut function = lifted();
        function.entry = 0x1000;
        function.instructions = instructions;
        let data = Funcdata::from_lifted(&function);
        let adds = data
            .live_ops()
            .filter(|(_, operation)| operation.opcode == op::INT_ADD)
            .count();
        assert_eq!(adds, 1, "the delay slot runs once, before the call");
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
    /// A straight run of instructions is one block, and only a branch, a join or
    /// the instruction after a branch starts a new one.
    #[test]
    fn a_straight_run_of_instructions_is_a_single_block() {
        use ventris_lifter::{Flow, LiftedInstruction};
        use ventris_pcode::InstPcode;
        let instruction = |address: u64, flow: Flow| LiftedInstruction {
            address,
            bytes: vec![0, 0, 0, 0],
            pcode: InstPcode {
                len: 4,
                space: ventris_lifter::RAM_SPACE,
                offset: address,
                ops: Vec::new(),
            },
            flow,
            embedded_delay_slot_bytes: 0,
        };
        let mut instructions = BTreeMap::new();
        for address in [0x1000u64, 0x1004, 0x1008] {
            instructions.insert(
                address,
                instruction(address, Flow::FallThrough(address + 4)),
            );
        }
        instructions.insert(
            0x100c,
            instruction(
                0x100c,
                Flow::Conditional {
                    target: 0x1004,
                    fallthrough: 0x1010,
                },
            ),
        );
        instructions.insert(0x1010, instruction(0x1010, Flow::Return));
        let function = NativeFunction {
            entry: 0x1000,
            instructions,
            // The back edge makes 0x1004 a join; 0x1010 is the branch's other
            // destination.
            edges: BTreeSet::from([
                (0x1000, 0x1004),
                (0x1004, 0x1008),
                (0x1008, 0x100c),
                (0x100c, 0x1004),
                (0x100c, 0x1010),
            ]),
            calls: BTreeSet::new(),
        };
        assert_eq!(
            block_leaders(&function).iter().copied().collect::<Vec<_>>(),
            vec![(0x1000, 0), (0x1004, 0), (0x1010, 0)],
            "0x1008 and 0x100c continue their block, and nothing branches inside an instruction"
        );
    }

    /// A `CBRANCH` to the constant space branches within one instruction, so it
    /// splits that instruction into blocks exactly as a machine branch splits a
    /// function. PPC paired-single arithmetic lifts to this shape, and treating
    /// the instruction as one block loses the guard entirely.
    #[test]
    fn a_branch_inside_one_instruction_splits_it() {
        use ventris_lifter::{CONST_SPACE, Flow, LiftedInstruction, REGISTER_SPACE};
        use ventris_pcode::{InstPcode, PcodeOp, Varnode};
        let condition = Varnode::new(REGISTER_SPACE, 8, 1);
        // op 0 computes, op 1 skips op 2, op 2 is guarded, op 3 always runs.
        let ops = vec![
            PcodeOp::new(op::COPY, Some(condition), vec![condition]),
            PcodeOp::new(
                op::CBRANCH,
                None,
                vec![Varnode::new(CONST_SPACE, 2, 4), condition],
            ),
            PcodeOp::new(op::COPY, Some(condition), vec![condition]),
            PcodeOp::new(op::COPY, Some(condition), vec![condition]),
        ];
        let mut instructions = BTreeMap::new();
        instructions.insert(
            0x1000u64,
            LiftedInstruction {
                address: 0x1000,
                bytes: vec![0, 0, 0, 0],
                pcode: InstPcode {
                    len: 4,
                    space: ventris_lifter::RAM_SPACE,
                    offset: 0x1000,
                    ops,
                },
                flow: Flow::Return,
                embedded_delay_slot_bytes: 0,
            },
        );
        let function = NativeFunction {
            entry: 0x1000,
            instructions,
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        };

        assert_eq!(
            block_leaders(&function).iter().copied().collect::<Vec<_>>(),
            vec![(0x1000, 0), (0x1000, 2), (0x1000, 3)],
            "the branch ends a block and both destinations begin one"
        );

        let data = Funcdata::from_lifted(&function);
        let blocks: Vec<(u64, u32, usize)> = data
            .blocks()
            .map(|(_, block)| (block.start, block.start_order, block.ops.len()))
            .collect();
        assert_eq!(
            blocks,
            vec![(0x1000, 0, 2), (0x1000, 2, 1), (0x1000, 3, 1)],
            "one instruction became three blocks: {blocks:?}"
        );
        let at = |order: u32| {
            data.blocks()
                .find(|(_, block)| block.start_order == order)
                .map(|(id, _)| id)
                .expect("the block exists")
        };
        assert_eq!(
            data.block(at(0)).successors.len(),
            2,
            "the guard reaches both the skipped body and the join"
        );
        assert_eq!(
            data.block(at(2)).successors,
            vec![at(3)],
            "the guarded body falls through to the join rather than dead-ending"
        );
        // Every pass that asks where a branch goes must resolve the relative
        // destination, not read it as an address. Reading it as an address finds
        // nothing here, which silently turned those passes into no-ops.
        let branch = data
            .block(at(0))
            .ops
            .last()
            .copied()
            .expect("the guard ends in the branch");
        assert_eq!(
            data.branch_target(branch),
            Some(at(3)),
            "the branch is taken to the join, skipping the guarded body"
        );
        assert_eq!(
            data.block_starting_at(0x1000),
            Some(at(0)),
            "only the block at p-code index zero begins at the address"
        );
    }

    /// A `CBRANCH` to an address that is not its instruction's last operation
    /// splits the instruction too. PPC `beqlr` is exactly this: it lifts to
    /// `if (!cond) goto <next>; return;`, so the conditional return lives inside
    /// one instruction, and leaving it unsplit merged the guard away -
    /// `TRK_fill_mem` lost the oracle's `if (param_3 != 0)` and one of its two
    /// returns.
    #[test]
    fn a_conditional_return_inside_one_instruction_splits_it() {
        use ventris_lifter::{Flow, LiftedInstruction, RAM_SPACE, REGISTER_SPACE};
        use ventris_pcode::{InstPcode, PcodeOp, Varnode};
        let condition = Varnode::new(REGISTER_SPACE, 8, 1);
        let body = |address: u64, ops: Vec<PcodeOp>, flow: Flow| LiftedInstruction {
            address,
            bytes: vec![0, 0, 0, 0],
            pcode: InstPcode {
                len: 4,
                space: RAM_SPACE,
                offset: address,
                ops,
            },
            flow,
            embedded_delay_slot_bytes: 0,
        };
        let mut instructions = BTreeMap::new();
        // `if (!cond) goto 0x1004; return;`
        instructions.insert(
            0x1000u64,
            body(
                0x1000,
                vec![
                    PcodeOp::new(
                        op::CBRANCH,
                        None,
                        vec![Varnode::new(RAM_SPACE, 0x1008, 4), condition],
                    ),
                    PcodeOp::new(op::RETURN, None, vec![condition]),
                ],
                Flow::FallThrough(0x1004),
            ),
        );
        for address in [0x1004u64, 0x1008u64] {
            instructions.insert(
                address,
                body(
                    address,
                    vec![PcodeOp::new(op::RETURN, None, vec![condition])],
                    Flow::Return,
                ),
            );
        }
        let function = NativeFunction {
            entry: 0x1000,
            instructions,
            edges: BTreeSet::from([(0x1000u64, 0x1004u64)]),
            calls: BTreeSet::new(),
        };

        assert_eq!(
            block_leaders(&function).iter().copied().collect::<Vec<_>>(),
            vec![(0x1000, 0), (0x1000, 1), (0x1008, 0)],
            "the conditional ends a block, the return after it begins one, and so \
             does the address it names"
        );
        let data = Funcdata::from_lifted(&function);
        let guard = data
            .block_starting_at(0x1000)
            .expect("the conditional begins a block");
        assert_eq!(
            data.block(guard).successors.len(),
            2,
            "it reaches both the next instruction and its own return: {:?}",
            data.block(guard).successors
        );
        let returning = data
            .blocks()
            .find(|(_, block)| block.start == 0x1000 && block.start_order == 1)
            .map(|(id, _)| id)
            .expect("the guarded return is its own block");
        let first = data.block(returning).ops[0];
        assert_eq!(
            data.op(first).opcode,
            op::RETURN,
            "and it begins with the guarded return"
        );
    }

    /// A relative destination past an instruction's last operation leaves the
    /// instruction, so it is a branch to the next address. Dropping it left the
    /// branch with one successor and a test that decided nothing, and every pass
    /// that resolves a branch target skipped the block.
    #[test]
    fn a_relative_branch_past_the_last_operation_reaches_the_next_instruction() {
        use ventris_lifter::{CONST_SPACE, Flow, LiftedInstruction, RAM_SPACE, REGISTER_SPACE};
        use ventris_pcode::{InstPcode, PcodeOp, Varnode};
        let condition = Varnode::new(REGISTER_SPACE, 8, 1);
        let body = |address: u64, ops: Vec<PcodeOp>, flow: Flow| LiftedInstruction {
            address,
            bytes: vec![0, 0, 0, 0],
            pcode: InstPcode {
                len: 4,
                space: RAM_SPACE,
                offset: address,
                ops,
            },
            flow,
            embedded_delay_slot_bytes: 0,
        };
        let mut instructions = BTreeMap::new();
        // Two operations, and the branch at index 1 targets index 4 - past the
        // end, so it leaves for 0x1004.
        instructions.insert(
            0x1000u64,
            body(
                0x1000,
                vec![
                    PcodeOp::new(op::COPY, Some(condition), vec![condition]),
                    PcodeOp::new(
                        op::CBRANCH,
                        None,
                        vec![Varnode::new(CONST_SPACE, 3, 4), condition],
                    ),
                ],
                Flow::FallThrough(0x1004),
            ),
        );
        instructions.insert(
            0x1004u64,
            body(
                0x1004,
                vec![PcodeOp::new(op::RETURN, None, vec![condition])],
                Flow::Return,
            ),
        );
        let function = NativeFunction {
            entry: 0x1000,
            instructions,
            edges: BTreeSet::from([(0x1000u64, 0x1004u64)]),
            calls: BTreeSet::new(),
        };

        let data = Funcdata::from_lifted(&function);
        let first = data
            .block_starting_at(0x1000)
            .expect("the first instruction begins a block");
        let next = data
            .block_starting_at(0x1004)
            .expect("the second instruction begins a block");
        assert!(
            data.block(first).successors.contains(&next),
            "the branch out of the instruction reaches the next one: {:?}",
            data.block(first).successors
        );
        let branch = data
            .block(first)
            .ops
            .last()
            .copied()
            .expect("the block ends in the branch");
        assert_eq!(
            data.branch_target(branch),
            Some(next),
            "and its destination resolves as an ordinary address"
        );
    }
}
