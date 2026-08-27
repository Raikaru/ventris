//! Split-value recovery from Ghidra 12.1.3's `double.cc`.
//!
//! `SplitVarnode` models one logical value whose little-endian storage is held
//! in a low and a high piece.  `Varnode::precislo` and `precishi` are carried on
//! the varnode, as they are in Ghidra, and set by
//! `RuleDoubleIn::attemptMarking` and `RuleDoubleOut::attemptMarking`
//! (`double.cc:3210-3329`) from the shape of the graph rather than supplied from
//! outside.
//!
//! The registered double-precision rules now include `RuleDoubleIn` and
//! `RuleDoubleOut`, in addition to the contiguous load/store rules.  The
//! input rule discovers marked SUBPIECE pairs and rewrites all thirteen
//! arithmetic, compare, control-flow, merge, indirect, and address-forced
//! forms (`AddForm`, `SubForm`, `LogicalForm`, `Equal3Form`, `MultForm`,
//! `ShiftForm`, `Equal1Form`, `Equal2Form`, `LessConstForm`, `LessThreeWay`,
//! `PhiForm`, `IndirectForm`, and `CopyForceForm`) through whole-value
//! operations (`double.cc:1090-1233`).  The output rule combines contiguous
//! input pieces after an arithmetic or floating-point consumer is found.  The
//! three-way compare uses the graph's explicit successor lists and leaves
//! constant-branch cleanup to the conditional-execution/reachability passes,
//! matching Ghidra's `double.cc:2026-2495` rewrite without edge surgery.
//!
//! The input/output rules deliberately use the graph's structural opcode and
//! size evidence in place of Ghidra's type-lock and recovered-type checks:
//! representing those checks would require `Varnode::isTypeLock`,
//! `Varnode::getType`, and the full `TypeOp` type lattice.  The graph also has
//! no symbol-entry metadata; `RuleDoubleOut` therefore applies its contiguous
//! storage test only to input locations.  `Funcdata::hasUnreachableBlocks` is
//! ported and its guard is honoured.
//!
//! `RuleDoubleStore` is ported whole, `testIndirectUse` and
//! `reassignIndirects` included, and with them `noWriteConflict`'s two details
//! that only matter once guards are in play: the scan starts *before* the first
//! `STORE`, walking back over the `INDIRECT`s that annotate it, and an
//! `INDIRECT` caused by either store of the pair is one of those annotations
//! rather than an aliasing conflict.  The rule also honours `isPrecisLo` and
//! `isPrecisHi` now that `RuleDoubleIn`/`RuleDoubleOut`'s `attemptMarking` sets
//! them, so its discovery is no longer purely structural.
//!
//! `RuleSplitCopy`, `RuleSplitLoad`, and `RuleSplitStore` are ported and
//! registered, in `graph::splitdatatype`, which is where the `SplitDatatype`
//! aggregate layout they need lives.
//! `RuleStringCopy` and `RuleStringStore` remain unported because they require
//! `StringSequence`/`HeapSequence` validation and transformation,
//! character/opaque-string datatypes, `ScopeLocal::queryContainer`, pointer
//! target types, and user-op construction.
//!
//! Source authority: the pinned Ghidra `double.hh`, `double.cc`,
//! `subflow.cc`, and `constseq.cc`.
use std::collections::BTreeSet;

use ventris_pcode::op;

use super::action::Rule;
use super::{Funcdata, GraphBlockId, OpId, SeqNum, VarnodeId};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Precision {
    Lo,
    Hi,
}

/// Whether a value carries one of Ghidra's double-precision marks.
///
/// `Varnode::isPrecisLo`/`isPrecisHi`. The marks live on the varnode, as they do
/// in Ghidra: keying them by the graph's address instead made two graphs that
/// happened to reuse one allocation share stale marks.
fn precision_marked(data: &Funcdata, value: VarnodeId, precision: Precision) -> bool {
    let flags = data.varnode(value).flags;
    match precision {
        Precision::Lo => flags.precis_lo,
        Precision::Hi => flags.precis_hi,
    }
}

/// `Varnode::setPrecisLo`/`setPrecisHi`.
fn set_precision(data: &mut Funcdata, value: VarnodeId, precision: Precision) {
    data.mark_precision(value, precision == Precision::Hi);
}

fn input(data: &Funcdata, id: OpId, slot: usize) -> Option<VarnodeId> {
    data.op(id).inputs.get(slot).copied()
}

fn output(data: &Funcdata, id: OpId) -> Option<VarnodeId> {
    data.op(id).output
}

fn constant(data: &Funcdata, id: VarnodeId) -> Option<u64> {
    data.varnode(id)
        .flags
        .constant
        .then_some(data.varnode(id).offset)
}

fn operation_parent(data: &Funcdata, id: OpId) -> Option<GraphBlockId> {
    data.op(id).parent
}

fn definition(data: &Funcdata, id: VarnodeId) -> Option<OpId> {
    data.varnode(id).def
}

fn is_written(data: &Funcdata, id: VarnodeId) -> bool {
    data.varnode(id).flags.written && data.varnode(id).def.is_some()
}

fn sequence_order(data: &Funcdata, id: OpId) -> u32 {
    data.op(id).seq.order
}

fn op_position(data: &Funcdata, id: OpId) -> Option<(GraphBlockId, usize)> {
    let parent = operation_parent(data, id)?;
    data.block(parent)
        .ops
        .iter()
        .position(|candidate| *candidate == id)
        .map(|position| (parent, position))
}

/// One logical value represented by two physical pieces.
///
/// `lo` is the least-significant piece and `hi` is the most-significant
/// piece.  A missing `hi` means an implied zero extension.  Constants use
/// neither piece and keep their value in `val`, matching Ghidra's internal
/// representation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SplitVarnode {
    lo: Option<VarnodeId>,
    hi: Option<VarnodeId>,
    whole: Option<VarnodeId>,
    defpoint: Option<OpId>,
    defblock: Option<GraphBlockId>,
    val: Option<u64>,
    wholesize: u32,
}

impl SplitVarnode {
    /// Construct a logical constant of `size` bytes.
    pub fn new_constant(size: u32, value: u64) -> Self {
        Self {
            val: Some(value),
            wholesize: size,
            ..Self::default()
        }
    }

    /// Construct from pieces, folding an all-constant pair into one value.
    pub fn from_parts(data: &Funcdata, lo: VarnodeId, hi: Option<VarnodeId>) -> Self {
        let size = data.varnode(lo).size + hi.map(|value| data.varnode(value).size).unwrap_or(0);
        Self::from_parts_with_size(data, size, lo, hi)
    }

    /// Construct from pieces with an explicit logical size.
    ///
    /// The explicit size is useful for the C++ `initPartial(sz, lo, hi)` form,
    /// where the virtual whole can be larger than the currently materialized
    /// pieces.
    pub fn from_parts_with_size(
        data: &Funcdata,
        size: u32,
        lo: VarnodeId,
        hi: Option<VarnodeId>,
    ) -> Self {
        let lo_constant = constant(data, lo);
        let hi_constant = hi.and_then(|value| constant(data, value));
        if let Some(lo_value) = lo_constant {
            if hi.is_none() {
                return Self::new_constant(size, lo_value);
            }
            if let Some(hi_value) = hi_constant {
                let shift = data.varnode(lo).size.saturating_mul(8);
                let value = if shift >= 64 {
                    lo_value
                } else {
                    lo_value | hi_value.wrapping_shl(shift)
                };
                return Self::new_constant(size, value);
            }
        }
        Self {
            lo: Some(lo),
            hi,
            wholesize: size,
            ..Self::default()
        }
    }

    /// Construct when the whole Varnode is already known.
    pub fn with_whole(
        data: &Funcdata,
        whole: VarnodeId,
        lo: VarnodeId,
        hi: Option<VarnodeId>,
    ) -> Self {
        let mut result = Self::from_parts_with_size(data, data.varnode(whole).size, lo, hi);
        if !result.is_constant() {
            result.whole = Some(whole);
        }
        result
    }

    /// Set the fields in the C++ `initAll` form.
    pub fn init_all(
        &mut self,
        data: &Funcdata,
        whole: VarnodeId,
        lo: VarnodeId,
        hi: Option<VarnodeId>,
    ) {
        *self = Self::with_whole(data, whole, lo, hi);
    }

    /// Set the fields in the C++ `initPartial(sz, lo, hi)` form.
    pub fn init_partial(
        &mut self,
        data: &Funcdata,
        size: u32,
        lo: VarnodeId,
        hi: Option<VarnodeId>,
    ) {
        *self = Self::from_parts_with_size(data, size, lo, hi);
    }

    /// Return whether this value is represented as a logical constant.
    ///
    /// This is Ghidra's `SplitVarnode::isConstant` (`double.hh:55`).
    pub fn is_constant(&self) -> bool {
        self.val.is_some()
    }

    /// Whether a constant whole exceeds the graph's 64-bit constant carrier.
    ///
    /// This is Ghidra's `SplitVarnode::exceedsConstPrecision`
    /// (`double.cc:696-702`); the Rust graph stores constants in `u64`.
    pub fn exceeds_const_precision(&self) -> bool {
        self.is_constant() && self.wholesize > 8
    }

    /// Return whether both the low and high pieces are present.
    ///
    /// This is Ghidra's `SplitVarnode::hasBothPieces` (`double.hh:56`).
    pub fn has_both_pieces(&self) -> bool {
        self.lo.is_some() && self.hi.is_some()
    }

    /// Return the logical whole size in bytes.
    ///
    /// This is Ghidra's `SplitVarnode::getSize` (`double.hh:57`).
    pub fn size(&self) -> u32 {
        self.wholesize
    }

    /// Return the logical whole width in bits, derived from `getSize`.
    ///
    /// Ghidra uses the byte size in the double-precision forms
    /// (`double.cc:1090-1233`); this convenience converts it to bits.
    pub fn bit_width(&self) -> u32 {
        self.wholesize.saturating_mul(8)
    }

    /// Return the least-significant piece, if one is present.
    ///
    /// This is Ghidra's `SplitVarnode::getLo` (`double.hh:58`).
    pub fn lo(&self) -> Option<VarnodeId> {
        self.lo
    }

    /// Return the most-significant piece, if one is present.
    ///
    /// This is Ghidra's `SplitVarnode::getHi` (`double.hh:59`).
    pub fn hi(&self) -> Option<VarnodeId> {
        self.hi
    }

    /// Return the representative whole Varnode, if one is present.
    ///
    /// This is Ghidra's `SplitVarnode::getWhole` (`double.hh:60`).
    pub fn whole(&self) -> Option<VarnodeId> {
        self.whole
    }

    /// Return the final operation defining both pieces, if known.
    ///
    /// This is Ghidra's `SplitVarnode::getDefPoint` (`double.hh:61`).
    pub fn definition_point(&self) -> Option<OpId> {
        self.defpoint
    }

    /// Return the block defining both pieces, if known.
    ///
    /// This is Ghidra's `SplitVarnode::getDefBlock` (`double.hh:62`).
    pub fn definition_block(&self) -> Option<GraphBlockId> {
        self.defblock
    }

    /// Return the logical constant value, if this is a constant.
    ///
    /// This is Ghidra's `SplitVarnode::getValue` (`double.hh:63`).
    pub fn value(&self) -> Option<u64> {
        self.val
    }

    /// Find the whole from matching SUBPIECEs of one source Varnode.
    ///
    /// This is the graph equivalent of Ghidra's private
    /// `SplitVarnode::findWholeSplitToPieces` (`double.cc:269-314`).  One
    /// transparent COPY around a SUBPIECE is accepted because address-forced
    /// pieces commonly carry that copy.
    pub fn find_whole_split_to_pieces(&mut self, data: &Funcdata) -> bool {
        if self.is_constant() {
            return false;
        }
        let (Some(lo), Some(hi)) = (self.lo, self.hi) else {
            return false;
        };
        let Some((lo_source, lo_offset)) = subpiece_source(data, lo) else {
            return false;
        };
        let Some((hi_source, hi_offset)) = subpiece_source(data, hi) else {
            return false;
        };
        if lo_source != hi_source || lo_offset != 0 {
            return false;
        }
        let hi_size = data.varnode(hi).size;
        let source_size = data.varnode(lo_source).size;
        if source_size != self.wholesize
            || hi_offset != u64::from(source_size.saturating_sub(hi_size))
            || data.varnode(lo).size.saturating_add(hi_size) != source_size
        {
            return false;
        }
        self.whole = Some(lo_source);
        self.record_whole_definition(data, lo_source);
        true
    }

    /// Find a PIECE operation that already combines this pair.
    ///
    /// This is Ghidra's `SplitVarnode::findWholeBuiltFromPieces`
    /// (`double.cc:392-439`).
    pub fn find_whole_built_from_pieces(&mut self, data: &Funcdata) -> bool {
        if self.is_constant() || self.whole.is_some() {
            return self.whole.is_some();
        }
        let (Some(lo), Some(hi)) = (self.lo, self.hi) else {
            return false;
        };
        let parent = definition(data, lo).and_then(|id| operation_parent(data, id));
        let mut candidate = None;
        for id in data.varnode(lo).descendants.iter().copied() {
            let operation = data.op(id);
            if operation.dead || operation.opcode != op::PIECE {
                continue;
            }
            if operation.inputs.get(0).copied() != Some(hi)
                || operation.inputs.get(1).copied() != Some(lo)
            {
                continue;
            }
            let Some(out) = operation.output else {
                continue;
            };
            if data.varnode(out).size != self.wholesize {
                continue;
            }
            if let Some(parent) = parent {
                if operation.parent != Some(parent) {
                    continue;
                }
            } else if operation
                .parent
                .is_none_or(|block| !data.is_entry_block(block))
            {
                continue;
            }
            if candidate
                .map(|old: OpId| sequence_order(data, id) < sequence_order(data, old))
                .unwrap_or(true)
            {
                candidate = Some(id);
            }
        }
        let Some(piece) = candidate else { return false };
        self.whole = output(data, piece);
        self.defpoint = Some(piece);
        self.defblock = operation_parent(data, piece);
        self.whole.is_some()
    }

    /// Find an existing whole using either split pieces or a PIECE result.
    ///
    /// This is the combined lookup used by Ghidra's
    /// `SplitVarnode::isWholeFeasible` (`double.cc:441-467`).
    pub fn find_whole(&mut self, data: &Funcdata) -> bool {
        self.whole.is_some()
            || self.find_whole_split_to_pieces(data)
            || self.find_whole_built_from_pieces(data)
    }

    fn record_whole_definition(&mut self, data: &Funcdata, whole: VarnodeId) {
        let Some(defpoint) = definition(data, whole) else {
            self.defpoint = None;
            self.defblock = None;
            return;
        };
        self.defpoint = Some(defpoint);
        self.defblock = operation_parent(data, defpoint);
    }

    /// Find the earliest operation defining both pieces.
    ///
    /// Cross-block dominance is not represented by this graph, so a pair of
    /// written pieces from different blocks is conservatively rejected.  This
    /// is the same safety condition as Ghidra's dominance walk, restricted to
    /// the metadata available here.
    pub fn find_definition_point(&mut self, data: &Funcdata) -> bool {
        if self.is_constant() {
            return false;
        }
        let Some(lo) = self.lo else { return false };
        if constant(data, lo).is_some() || self.hi.and_then(|id| constant(data, id)).is_some() {
            return false;
        }
        let Some(hi) = self.hi else {
            if data.varnode(lo).flags.input {
                self.defpoint = None;
                self.defblock = None;
                return true;
            }
            if let Some(defpoint) = definition(data, lo) {
                self.defpoint = Some(defpoint);
                self.defblock = operation_parent(data, defpoint);
                return self.defblock.is_some();
            }
            return false;
        };

        let lo_input = data.varnode(lo).flags.input;
        let hi_input = data.varnode(hi).flags.input;
        let lo_written = is_written(data, lo);
        let hi_written = is_written(data, hi);
        if lo_input != hi_input || lo_written != hi_written {
            return false;
        }
        if lo_input && hi_input {
            self.defpoint = None;
            self.defblock = None;
            return true;
        }
        if !lo_written || !hi_written {
            return false;
        }
        let Some(lo_def) = definition(data, lo) else {
            return false;
        };
        let Some(hi_def) = definition(data, hi) else {
            return false;
        };
        if operation_parent(data, lo_def) != operation_parent(data, hi_def) {
            return false;
        }
        let defpoint = if sequence_order(data, lo_def) >= sequence_order(data, hi_def) {
            lo_def
        } else {
            hi_def
        };
        self.defpoint = Some(defpoint);
        self.defblock = operation_parent(data, defpoint);
        self.defblock.is_some()
    }

    /// Whether this logical whole exists, or can be made to exist before `op`.
    ///
    /// This is Ghidra's `SplitVarnode::isWholeFeasible`
    /// (`double.cc:441-467`).
    pub fn is_whole_feasible(&mut self, data: &Funcdata, op: OpId) -> bool {
        if self.is_constant() {
            return true;
        }
        if self.lo.and_then(|id| constant(data, id)).is_some()
            != self.hi.and_then(|id| constant(data, id)).is_some()
        {
            return false;
        }
        if !self.find_whole(data) && !self.find_definition_point(data) {
            return false;
        }
        let Some(defblock) = self.defblock else {
            return true;
        };
        let Some(opblock) = operation_parent(data, op) else {
            return false;
        };
        if defblock != opblock {
            return false;
        }
        let Some(defpoint) = self.defpoint else {
            return true;
        };
        sequence_order(data, defpoint) <= sequence_order(data, op)
    }

    /// Create a whole before `exist_op` if it does not already exist.
    ///
    /// This is Ghidra's `SplitVarnode::findCreateWhole`
    /// (`double.cc:493-552`).  The operation is a PIECE for a two-piece value
    /// and an INT_ZEXT for an implied-zero high piece.  The method returns the
    /// whole Varnode.
    pub fn find_create_whole(
        &mut self,
        data: &mut Funcdata,
        exist_op: Option<OpId>,
    ) -> Option<VarnodeId> {
        if let Some(value) = self.val {
            let whole = data.new_constant(value, self.wholesize);
            self.whole = Some(whole);
            return Some(whole);
        }
        if let Some(lo) = self.lo {
            set_precision(data, lo, Precision::Lo);
        }
        if let Some(hi) = self.hi {
            set_precision(data, hi, Precision::Hi);
        }
        if let Some(whole) = self.whole {
            return Some(whole);
        }
        let lo = self.lo?;
        let seq = exist_op
            .map(|id| data.op(id).seq)
            .or_else(|| self.defpoint.map(|id| data.op(id).seq))
            .unwrap_or(SeqNum {
                address: 0,
                order: 0,
            });
        let opcode = if self.hi.is_some() {
            op::PIECE
        } else {
            op::INT_ZEXT
        };
        let mut inputs = vec![lo];
        if let Some(hi) = self.hi {
            inputs = vec![hi, lo];
        }
        let create = data.new_op(opcode, seq, inputs);
        let whole = data.new_unique(self.wholesize);
        data.op_set_output(create, Some(whole));

        if let Some(exist_op) = exist_op {
            if let Some(defpoint) = self.defpoint {
                if operation_parent(data, defpoint) == operation_parent(data, exist_op) {
                    data.op_insert_after(create, defpoint);
                } else {
                    data.op_insert_before(create, exist_op);
                }
            } else {
                data.op_insert_before(create, exist_op);
            }
        } else if let Some(defpoint) = self.defpoint {
            data.op_insert_after(create, defpoint);
        } else {
            let first_block = data.blocks().next().map(|(id, _)| id);
            if let Some(block) = first_block {
                data.op_insert_front(create, block);
            }
        }
        self.whole = Some(whole);
        self.defpoint = Some(create);
        self.defblock = operation_parent(data, create);
        Some(whole)
    }

    /// Allocate a whole result without defining it yet.
    ///
    /// This is Ghidra's `SplitVarnode::findCreateOutputWhole`
    /// (`double.cc:553-580`).
    pub fn find_create_output_whole(&mut self, data: &mut Funcdata) -> Option<VarnodeId> {
        if self.is_constant() {
            return self.find_create_whole(data, None);
        }
        if let Some(lo) = self.lo {
            set_precision(data, lo, Precision::Lo);
        }
        if let Some(hi) = self.hi {
            set_precision(data, hi, Precision::Hi);
        }
        if self.whole.is_none() {
            self.whole = Some(data.new_unique(self.wholesize));
        }
        self.whole
    }
    /// Discover every marked low/high SUBPIECE pair extracted from `whole`.
    ///
    /// This is Ghidra's `SplitVarnode::wholeList` (`double.cc:828-864`).
    /// Direct pairs are returned first; address-contiguous COPY pairs are
    /// included by the corresponding `findCopies` scan.
    pub fn whole_list(data: &Funcdata, whole: VarnodeId) -> Vec<Self> {
        let whole_size = data.varnode(whole).size;
        let mut low = None;
        let mut high = None;
        let mut found = 0u8;
        let descendants: Vec<OpId> = data.varnode(whole).descendants.iter().copied().collect();
        for id in descendants {
            if data.opcode_of(id) != Some(op::SUBPIECE) {
                continue;
            }
            let Some(piece) = output(data, id) else {
                continue;
            };
            let Some(offset) = input(data, id, 1).and_then(|value| constant(data, value)) else {
                continue;
            };
            if precision_marked(data, piece, Precision::Hi)
                && offset == u64::from(whole_size.saturating_sub(data.varnode(piece).size))
            {
                high = Some(piece);
                found |= 2;
            } else if precision_marked(data, piece, Precision::Lo) && offset == 0 {
                low = Some(piece);
                found |= 1;
            }
        }
        if found == 0
            || (found == 3
                && low.zip(high).is_none_or(|(lo, hi)| {
                    data.varnode(lo).size.saturating_add(data.varnode(hi).size) != whole_size
                }))
        {
            return Vec::new();
        }

        let mut result = vec![Self {
            lo: low,
            hi: high,
            whole: Some(whole),
            defpoint: definition(data, whole),
            defblock: definition(data, whole).and_then(|id| operation_parent(data, id)),
            val: None,
            wholesize: whole_size,
        }];
        if let Some(base) = result.first().cloned() {
            find_copies(data, &base, &mut result);
        }
        result
    }

    /// Try one input-side double-precision rewrite.
    ///
    /// This is Ghidra's `SplitVarnode::applyRuleIn` dispatch
    /// (`double.cc:1090-1233`).  The dispatch intentionally excludes forms
    /// whose graph metadata is not representable; every included form below
    /// performs its own source-level verification before mutating the graph.
    pub fn apply_rule_in(&mut self, data: &mut Funcdata) -> usize {
        for (piece, workishi) in [(self.hi, true), (self.lo, false)] {
            let Some(piece) = piece else {
                continue;
            };
            let descendants: Vec<OpId> = data.varnode(piece).descendants.iter().copied().collect();
            for workop in descendants {
                let Some(opcode) = data.opcode_of(workop) else {
                    continue;
                };
                let changed = match opcode {
                    op::INT_ADD => {
                        add_form_apply(self, workop, workishi, data)
                            || sub_form_apply(self, workop, workishi, data)
                    }
                    op::INT_AND => {
                        equal3_form_apply(self, workop, workishi, data)
                            || logical_form_apply(self, workop, workishi, data)
                    }
                    op::INT_OR | op::INT_XOR => logical_form_apply(self, workop, workishi, data),
                    op::INT_EQUAL | op::INT_NOTEQUAL => {
                        less_three_way_apply(self, workop, workishi, data)
                            || equal1_form_apply(self, workop, workishi, data)
                            || equal2_form_apply(self, workop, workishi, data)
                    }
                    op::INT_LESS | op::INT_LESSEQUAL => {
                        less_three_way_apply(self, workop, workishi, data)
                            || less_const_form_apply(self, workop, workishi, data)
                    }
                    op::INT_SLESS | op::INT_SLESSEQUAL => {
                        less_const_form_apply(self, workop, workishi, data)
                    }
                    op::INT_LEFT => shift_form_apply(self, workop, workishi, true, data),
                    op::INT_RIGHT | op::INT_SRIGHT => {
                        shift_form_apply(self, workop, workishi, false, data)
                    }
                    op::INT_MULT => mult_form_apply(self, workop, workishi, data),
                    op::MULTIEQUAL => phi_form_apply(self, workop, workishi, data),
                    op::INDIRECT => indirect_form_apply(self, workop, workishi, data),
                    op::COPY => copy_force_form_apply(self, workop, workishi, data),
                    _ => false,
                };
                if changed {
                    return 1;
                }
            }
        }
        0
    }
}

/// Return the source and byte offset of a SUBPIECE, allowing one COPY wrapper.
fn subpiece_source(data: &Funcdata, value: VarnodeId) -> Option<(VarnodeId, u64)> {
    let mut def = definition(data, value)?;
    if data.opcode_of(def) == Some(op::COPY) {
        let source = input(data, def, 0)?;
        def = definition(data, source)?;
    }
    if data.opcode_of(def) != Some(op::SUBPIECE) {
        return None;
    }
    let source = input(data, def, 0)?;
    let offset = constant(data, input(data, def, 1)?)?;
    Some((source, offset))
}

/// A pointer represented as `base + constant`, matching `adjacentOffsets`.
#[derive(Copy, Clone)]
enum PointerForm {
    Constant(u64),
    Base(VarnodeId, u64),
}

fn pointer_form(data: &Funcdata, value: VarnodeId) -> PointerForm {
    if let Some(value) = constant(data, value) {
        return PointerForm::Constant(value);
    }
    if let Some(def) = definition(data, value)
        && data.opcode_of(def) == Some(op::INT_ADD)
        && let (Some(base), Some(offset)) = (input(data, def, 0), input(data, def, 1))
        && let Some(offset) = constant(data, offset)
    {
        return PointerForm::Base(base, offset);
    }
    PointerForm::Base(value, 0)
}

/// Return true when `second` begins `size` bytes after `first`.
fn adjacent_pointers(data: &Funcdata, first: VarnodeId, second: VarnodeId, size: u32) -> bool {
    match (pointer_form(data, first), pointer_form(data, second)) {
        (PointerForm::Constant(first), PointerForm::Constant(second)) => {
            first.checked_add(u64::from(size)) == Some(second)
        }
        (
            PointerForm::Base(first_base, first_offset),
            PointerForm::Base(second_base, second_offset),
        ) => {
            first_base == second_base
                && first_offset.checked_add(u64::from(size)) == Some(second_offset)
        }
        _ => false,
    }
}

fn memory_space(data: &Funcdata, id: OpId) -> Option<u64> {
    constant(data, input(data, id, 0)?)
}

/// Reject a pair if a same-space write, call, or control transfer intervenes,
/// and collect the `INDIRECT`s the pair itself caused.
///
/// `RuleDoubleLoad::noWriteConflict`. Two details matter and were missing. The
/// scan starts *before* the first `STORE`, walking back over the `INDIRECT`s
/// that annotate it, because those are the ones the combined store has to
/// inherit. And an `INDIRECT` caused by either op of the pair is not a conflict
/// at all - it is one of those annotations - so it is collected rather than
/// rejected. Treating it as a conflict refused every pair whose stores had
/// guards, which is most of them.
fn no_write_conflict(
    data: &Funcdata,
    first: OpId,
    second: OpId,
    space: u64,
    indirects: &mut Vec<OpId>,
) -> Option<OpId> {
    let (block_first, pos_first) = op_position(data, first)?;
    let (block_second, pos_second) = op_position(data, second)?;
    if block_first != block_second {
        return None;
    }
    let (early, late, mut start, end) = if pos_first <= pos_second {
        (first, second, pos_first, pos_second)
    } else {
        (second, first, pos_second, pos_first)
    };
    // "Extend the range of PcodeOps to include any CPUI_INDIRECTs associated
    // with the initial STORE".
    if data.opcode_of(early) == Some(op::STORE) {
        while start > 0 {
            let previous = data.block(block_first).ops[start - 1];
            if data.opcode_of(previous) != Some(op::INDIRECT) {
                break;
            }
            start -= 1;
        }
    }
    let block = data.block(block_first);
    for candidate in block.ops[start..end].to_vec() {
        let operation = data.op(candidate);
        if operation.dead || candidate == early {
            continue;
        }
        match operation.opcode {
            op::CALL
            | op::CALLIND
            | op::CALLOTHER
            | op::RETURN
            | op::BRANCH
            | op::CBRANCH
            | op::BRANCHIND => return None,
            op::STORE => {
                if memory_space(data, candidate) == Some(space) {
                    return None;
                }
            }
            op::INDIRECT => {
                let affector = input(data, candidate, 1).and_then(|value| data.iop_target(value));
                if affector == Some(early) || affector == Some(late) {
                    indirects.push(candidate);
                } else if output(data, candidate)
                    .map(|value| data.varnode(value).space == space as u32)
                    .unwrap_or(false)
                {
                    return None;
                }
            }
            _ => {
                if output(data, candidate)
                    .map(|value| data.varnode(value).space == space as u32)
                    .unwrap_or(false)
                {
                    return None;
                }
            }
        }
    }
    Some(late)
}

/// Whether the pair's `INDIRECT`s may be moved to a combined store.
///
/// `RuleDoubleStore::testIndirectUse`. An `INDIRECT` output read between the two
/// stores by anything other than a later `INDIRECT` of the second store cannot
/// be relocated: the reader expects the value the first store left. The pairing
/// count is the subtle half - an output that feeds a later `INDIRECT` must feed
/// *only* later `INDIRECT`s, and only one of them, because the earlier op is
/// about to be removed.
fn test_indirect_use(data: &Funcdata, first: OpId, second: OpId, indirects: &[OpId]) -> bool {
    let (early, late) = if sequence_order(data, second) < sequence_order(data, first) {
        (second, first)
    } else {
        (first, second)
    };
    let Some((block, early_position)) = op_position(data, early) else {
        return false;
    };
    let Some((_, late_position)) = op_position(data, late) else {
        return false;
    };
    for guard in indirects.iter().copied() {
        let Some(out) = output(data, guard) else {
            continue;
        };
        let mut uses = 0usize;
        let mut paired = 0usize;
        for reader in data.varnode(out).descendants.iter().copied() {
            uses += 1;
            let Some((reader_block, reader_position)) = op_position(data, reader) else {
                continue;
            };
            if reader_block != block
                || reader_position < early_position
                || reader_position > late_position
            {
                continue;
            }
            let annotates_late = data.opcode_of(reader) == Some(op::INDIRECT)
                && input(data, reader, 1).and_then(|value| data.iop_target(value)) == Some(late);
            if annotates_late {
                paired += 1;
                continue;
            }
            return false;
        }
        if paired > 0 && uses != paired {
            return false;
        }
        if paired > 1 {
            return false;
        }
    }
    true
}

/// Moves the pair's `INDIRECT`s onto the combined store.
///
/// `RuleDoubleStore::reassignIndirects`. A pair of `INDIRECT`s where the later
/// reads the earlier's output collapses to the later one, which takes over the
/// earlier's input; then every survivor moves in front of the new store and its
/// annotation is repointed at it. Without this the guards keep annotating
/// destroyed operations, and the combined store's own indirect effect goes
/// unrecorded.
fn reassign_indirects(data: &mut Funcdata, new_store: OpId, indirects: &[OpId]) {
    let members: BTreeSet<OpId> = indirects.iter().copied().collect();
    for guard in indirects.iter().copied() {
        let Some(value) = input(data, guard, 0) else {
            continue;
        };
        let Some(earlier) = definition(data, value) else {
            continue;
        };
        if !members.contains(&earlier) {
            continue;
        }
        if let Some(inherited) = input(data, earlier, 0) {
            data.op_set_input(guard, inherited, 0);
        }
        data.op_destroy(earlier);
    }
    for guard in indirects.iter().copied() {
        if data.opcode_of(guard).is_none() {
            continue;
        }
        data.op_uninsert(guard);
        data.op_insert_before(guard, new_store);
        let annotation = data.new_iop(new_store);
        data.op_set_input(guard, annotation, 1);
    }
}

fn direct_load(data: &Funcdata, piece: VarnodeId) -> Option<OpId> {
    let def = definition(data, piece)?;
    if data.opcode_of(def) != Some(op::LOAD) {
        return None;
    }
    (output(data, def) == Some(piece)).then_some(def)
}
fn slot_of(data: &Funcdata, id: OpId, value: VarnodeId) -> Option<usize> {
    data.op(id).inputs.iter().position(|input| *input == value)
}

fn other_input(data: &Funcdata, id: OpId, value: VarnodeId) -> Option<VarnodeId> {
    let slot = slot_of(data, id, value)?;
    input(data, id, 1usize.saturating_sub(slot))
}

/// Classify the operations Ghidra treats as arithmetic/floating-point whole
/// consumers.
///
/// This mirrors `TypeOp::isArithmeticOp` and `TypeOp::isFloatingPointOp`
/// (`typeop.hh:139-146`), which `RuleDoubleIn::attemptMarking` and
/// `RuleDoubleOut::attemptMarking` use rather than treating every opcode as a
/// double-precision consumer.
fn is_arithmetic_or_float_opcode(opcode: i32) -> bool {
    matches!(
        opcode,
        op::INT_ADD
            | op::INT_SUB
            | op::INT_CARRY
            | op::INT_SCARRY
            | op::INT_SBORROW
            | op::INT_2COMP
            | op::INT_MULT
            | op::INT_DIV
            | op::INT_SDIV
            | op::INT_REM
            | op::INT_SREM
            | op::PTRADD
            | op::PTRSUB
            | op::FLOAT_EQUAL
            | op::FLOAT_NOTEQUAL
            | op::FLOAT_LESS
            | op::FLOAT_LESSEQUAL
            | op::FLOAT_NAN
            | op::FLOAT_ADD
            | op::FLOAT_DIV
            | op::FLOAT_MULT
            | op::FLOAT_SUB
            | op::FLOAT_NEG
            | op::FLOAT_ABS
            | op::FLOAT_SQRT
            | op::FLOAT_INT2FLOAT
            | op::FLOAT_FLOAT2FLOAT
            | op::FLOAT_TRUNC
            | op::FLOAT_CEIL
            | op::FLOAT_FLOOR
            | op::FLOAT_ROUND
    )
}

fn earliest_split_point(data: &Funcdata, split: &SplitVarnode) -> Option<OpId> {
    let (Some(lo), Some(hi)) = (split.lo, split.hi) else {
        return None;
    };
    let lo_def = definition(data, lo)?;
    let hi_def = definition(data, hi)?;
    if operation_parent(data, lo_def) != operation_parent(data, hi_def) {
        return None;
    }
    (sequence_order(data, lo_def) <= sequence_order(data, hi_def))
        .then_some(lo_def)
        .or(Some(hi_def))
}

fn output_exist(data: &mut Funcdata, split: &mut SplitVarnode) -> Option<OpId> {
    if split.find_whole_built_from_pieces(data) {
        return split.defpoint;
    }
    earliest_split_point(data, split)
}

fn prepare_binary(
    data: &mut Funcdata,
    output_split: &mut SplitVarnode,
    input_one: &mut SplitVarnode,
    input_two: &mut SplitVarnode,
) -> Option<OpId> {
    let exist = output_exist(data, output_split)?;
    if !input_one.is_whole_feasible(data, exist) || !input_two.is_whole_feasible(data, exist) {
        return None;
    }
    Some(exist)
}

fn rebuild_piece(data: &mut Funcdata, piece: VarnodeId, whole: VarnodeId, offset: u32) -> bool {
    let Some(def) = definition(data, piece) else {
        return false;
    };
    if data.opcode_of(def).is_none() {
        return false;
    }
    data.op_set_opcode(def, op::SUBPIECE);
    let offset = data.new_constant(u64::from(offset), 4);
    data.op_set_inputs(def, vec![whole, offset]);
    true
}

fn create_binary(
    data: &mut Funcdata,
    output_split: &mut SplitVarnode,
    input_one: &mut SplitVarnode,
    input_two: &mut SplitVarnode,
    exist: OpId,
    opcode: i32,
) -> bool {
    let Some(whole) = output_split.find_create_output_whole(data) else {
        return false;
    };
    let Some(first) = input_one.find_create_whole(data, Some(exist)) else {
        return false;
    };
    let Some(second) = input_two.find_create_whole(data, Some(exist)) else {
        return false;
    };
    if data.opcode_of(exist) == Some(op::PIECE) && output(data, exist) == Some(whole) {
        data.op_set_opcode(exist, opcode);
        data.op_set_inputs(exist, vec![first, second]);
        return true;
    }

    let seq = data.op(exist).seq;
    let newop = data.new_op(opcode, seq, vec![first, second]);
    data.op_set_output(newop, Some(whole));
    data.op_insert_before(newop, exist);
    let (Some(lo), Some(hi)) = (output_split.lo, output_split.hi) else {
        return false;
    };
    rebuild_piece(data, lo, whole, 0) && rebuild_piece(data, hi, whole, data.varnode(lo).size)
}

fn create_shift(
    data: &mut Funcdata,
    output_split: &mut SplitVarnode,
    input_split: &mut SplitVarnode,
    shift: VarnodeId,
    exist: OpId,
    opcode: i32,
) -> bool {
    let Some(whole) = output_split.find_create_output_whole(data) else {
        return false;
    };
    let Some(input_whole) = input_split.find_create_whole(data, Some(exist)) else {
        return false;
    };
    let shift = constant(data, shift)
        .map(|value| data.new_constant(value, data.varnode(shift).size))
        .unwrap_or(shift);
    if data.opcode_of(exist) == Some(op::PIECE) && output(data, exist) == Some(whole) {
        data.op_set_opcode(exist, opcode);
        data.op_set_inputs(exist, vec![input_whole, shift]);
        return true;
    }

    let seq = data.op(exist).seq;
    let newop = data.new_op(opcode, seq, vec![input_whole, shift]);
    data.op_set_output(newop, Some(whole));
    data.op_insert_before(newop, exist);
    let (Some(lo), Some(hi)) = (output_split.lo, output_split.hi) else {
        return false;
    };
    rebuild_piece(data, lo, whole, 0) && rebuild_piece(data, hi, whole, data.varnode(lo).size)
}

fn replace_bool(
    data: &mut Funcdata,
    compare: OpId,
    first: &mut SplitVarnode,
    second: &mut SplitVarnode,
    opcode: i32,
) -> bool {
    if !first.is_whole_feasible(data, compare) || !second.is_whole_feasible(data, compare) {
        return false;
    }
    let Some(first_whole) = first.find_create_whole(data, Some(compare)) else {
        return false;
    };
    let Some(second_whole) = second.find_create_whole(data, Some(compare)) else {
        return false;
    };
    data.op_set_opcode(compare, opcode);
    data.op_set_inputs(compare, vec![first_whole, second_whole]);
    true
}
/// Return a conditional branch's true and false successors.
///
/// `GraphOp` has no encoded `PcodeOp::isBooleanFlip` bit.  The graph's
/// first branch input names the taken successor, so the caller-requested flip
/// is represented by swapping the two explicit successors.  This is the
/// structural information consumed by Ghidra's `getTrueFalse`
/// (`double.cc:908-930`).
fn branch_true_false(
    data: &Funcdata,
    branch: OpId,
    flip: bool,
) -> Option<(GraphBlockId, GraphBlockId)> {
    if data.opcode_of(branch) != Some(op::CBRANCH) {
        return None;
    }
    let parent = operation_parent(data, branch)?;
    let target = data.branch_target(branch)?;
    let other = data
        .block(parent)
        .successors
        .iter()
        .copied()
        .find(|successor| *successor != target)?;
    if flip {
        Some((other, target))
    } else {
        Some((target, other))
    }
}

/// Return the last live operation in a block.
fn last_live_op(data: &Funcdata, block: GraphBlockId) -> Option<OpId> {
    data.block(block)
        .ops
        .iter()
        .rev()
        .copied()
        .find(|id| data.opcode_of(*id).is_some())
}

/// Whether a branch's parent contains only its condition producer and branch.
///
/// This is `SplitVarnode::otherwiseEmpty` (`double.cc:932-958`).  The
/// predecessor-count check prevents accepting a branch block whose fallthrough
/// is not the single edge represented by the pattern.
fn otherwise_empty(data: &Funcdata, branch: OpId) -> bool {
    let Some(parent) = operation_parent(data, branch) else {
        return false;
    };
    if data.block(parent).predecessors.len() != 1 {
        return false;
    }
    let condition = input(data, branch, 1);
    let condition_def = condition
        .filter(|value| is_written(data, *value))
        .and_then(|value| definition(data, value));
    data.block(parent)
        .ops
        .iter()
        .copied()
        .filter_map(|id| data.opcode_of(id).map(|_| id))
        .all(|id| id == branch || Some(id) == condition_def)
}

/// Create a whole-value comparison immediately before a conditional branch.
///
/// This is Ghidra's `SplitVarnode::createBoolOp` (`double.cc:1270-1296`).
fn create_bool_op(
    data: &mut Funcdata,
    branch: OpId,
    first: &mut SplitVarnode,
    second: &mut SplitVarnode,
    opcode: i32,
) -> bool {
    let Some(parent) = operation_parent(data, branch) else {
        return false;
    };
    let condition = input(data, branch, 1);
    let anchor = condition
        .filter(|value| is_written(data, *value))
        .and_then(|value| definition(data, value))
        .unwrap_or(branch);
    let seq = data.op(anchor).seq;
    let Some(first_whole) = first.find_create_whole(data, Some(branch)) else {
        return false;
    };
    let Some(second_whole) = second.find_create_whole(data, Some(branch)) else {
        return false;
    };
    let newop = data.new_op(opcode, seq, vec![first_whole, second_whole]);
    let newbool = data.new_unique(1);
    data.op_set_output(newop, Some(newbool));
    data.op_insert_before(newop, branch);
    if data.op(newop).parent != Some(parent) {
        return false;
    }
    data.op_set_input(branch, newbool, 1);
    true
}

/// Return the storage base and total size of contiguous low/high pieces.
///
/// This is the address half of `SplitVarnode::isAddrTiedContiguous`, used by
/// `CopyForceForm` and `IndirectForm` (`double.cc:3103-3107`,
/// `double.cc:3158-3159`).  The graph's storage predicate is the available
/// representation of Ghidra's address-tied/forced distinction.
fn contiguous_piece_storage(
    data: &Funcdata,
    lo: VarnodeId,
    hi: VarnodeId,
) -> Option<(u32, u64, u32)> {
    if !data.is_addr_tied(lo) || !data.is_addr_tied(hi) {
        return None;
    }
    let low = data.varnode(lo);
    let high = data.varnode(hi);
    if low.space != high.space {
        return None;
    }
    let base = if data.big_endian {
        high.offset
            .checked_add(u64::from(high.size))
            .filter(|end| *end == low.offset)
            .map(|_| high.offset)?
    } else {
        low.offset
            .checked_add(u64::from(low.size))
            .filter(|end| *end == high.offset)
            .map(|_| low.offset)?
    };
    Some((low.space, base, low.size.saturating_add(high.size)))
}

/// Rebuild an output piece as a SUBPIECE of a newly created whole.
///
/// Phi and indirect definitions need reinsertion to preserve Ghidra's
/// placement constraints (`double.cc:583-654`); ordinary definitions stay in
/// place.
fn rebuild_piece_from_whole(
    data: &mut Funcdata,
    piece: VarnodeId,
    whole: VarnodeId,
    offset: u32,
) -> bool {
    let Some(def) = definition(data, piece) else {
        return false;
    };
    let Some(parent) = operation_parent(data, def) else {
        return false;
    };
    let opcode = data.opcode_of(def);
    let reinsert_front = opcode == Some(op::MULTIEQUAL);
    let reinsert_after_affector = opcode == Some(op::INDIRECT);
    let affector = reinsert_after_affector
        .then(|| input(data, def, 1))
        .flatten()
        .and_then(|value| data.iop_target(value));
    if reinsert_front || reinsert_after_affector {
        data.op_uninsert(def);
    }
    data.op_set_opcode(def, op::SUBPIECE);
    let offset = data.new_constant(u64::from(offset), 4);
    data.op_set_inputs(def, vec![whole, offset]);
    if reinsert_front {
        data.op_insert_front(def, parent);
    } else if reinsert_after_affector {
        if let Some(affector) = affector.filter(|id| data.opcode_of(*id).is_some()) {
            data.op_insert_after(def, affector);
        } else {
            data.op_insert_end(def, parent);
        }
    }
    true
}

/// Create an output whole in the storage occupied by contiguous pieces.
fn create_joined_output_whole(data: &mut Funcdata, split: &mut SplitVarnode) -> Option<VarnodeId> {
    if let Some(whole) = split.whole {
        return Some(whole);
    }
    let (lo, hi) = (split.lo?, split.hi?);
    let (space, offset, _) = contiguous_piece_storage(data, lo, hi)?;
    let whole = data.new_varnode(space, offset, split.wholesize);
    split.whole = Some(whole);
    Some(whole)
}

/// Return the blocks dominated by each live block.
///
/// Phi feasibility needs the same dominance fact as
/// `SplitVarnode::isWholePhiFeasible` (`double.cc:473-491`).  The graph does
/// not cache an immediate-dominator tree, so this small fixed-point calculation
/// supplies the exact set needed by the phi form.
fn dominators(data: &Funcdata) -> std::collections::BTreeMap<GraphBlockId, BTreeSet<GraphBlockId>> {
    let blocks: Vec<GraphBlockId> = data.blocks().map(|(id, _)| id).collect();
    let Some(entry) = data.entry_block().or_else(|| blocks.first().copied()) else {
        return std::collections::BTreeMap::new();
    };
    let all: BTreeSet<GraphBlockId> = blocks.iter().copied().collect();
    let mut result = std::collections::BTreeMap::new();
    for block in blocks.iter().copied() {
        result.insert(
            block,
            if block == entry {
                BTreeSet::from([entry])
            } else {
                all.clone()
            },
        );
    }
    let mut changed = true;
    while changed {
        changed = false;
        for block in blocks.iter().copied().filter(|block| *block != entry) {
            let predecessors: Vec<GraphBlockId> = data
                .block(block)
                .predecessors
                .iter()
                .copied()
                .filter(|pred| !data.block(*pred).dead)
                .collect();
            let mut next = if let Some(first) = predecessors.first() {
                result.get(first).cloned().unwrap_or_default()
            } else {
                BTreeSet::new()
            };
            for predecessor in predecessors.iter().skip(1) {
                if let Some(other) = result.get(predecessor) {
                    next.retain(|candidate| other.contains(candidate));
                } else {
                    next.clear();
                }
            }
            next.insert(block);
            if result.get(&block) != Some(&next) {
                result.insert(block, next);
                changed = true;
            }
        }
    }
    result
}

/// Test whether a split can feed one predecessor of a phi.
fn whole_phi_feasible(
    data: &Funcdata,
    split: &mut SplitVarnode,
    predecessor: GraphBlockId,
    dom: &std::collections::BTreeMap<GraphBlockId, BTreeSet<GraphBlockId>>,
) -> bool {
    if split.is_constant() {
        return false;
    }
    if split.lo.and_then(|id| constant(data, id)).is_some()
        != split.hi.and_then(|id| constant(data, id)).is_some()
    {
        return false;
    }
    if !split.find_whole(data) && !split.find_definition_point(data) {
        return false;
    }
    let Some(defblock) = split.defblock else {
        return true;
    };
    dom.get(&predecessor)
        .is_some_and(|dominated| dominated.contains(&defblock))
}

/// Locate the whole-value existence point and check every phi input.
fn prepare_phi(
    data: &mut Funcdata,
    output_split: &mut SplitVarnode,
    inputs: &mut [SplitVarnode],
) -> Option<OpId> {
    let exist = earliest_split_point(data, output_split)?;
    if data.opcode_of(exist) != Some(op::MULTIEQUAL) {
        return None;
    }
    let parent = operation_parent(data, exist)?;
    let predecessors = data.block(parent).predecessors.clone();
    let dom = dominators(data);
    for (index, input_split) in inputs.iter_mut().enumerate() {
        let predecessor = predecessors.get(index).copied()?;
        if !whole_phi_feasible(data, input_split, predecessor, &dom) {
            return None;
        }
    }
    Some(exist)
}

fn find_copies(data: &Funcdata, input_split: &SplitVarnode, result: &mut Vec<SplitVarnode>) {
    let (Some(lo), Some(hi), Some(whole)) = (input_split.lo, input_split.hi, input_split.whole)
    else {
        return;
    };
    let low_copies: Vec<(VarnodeId, GraphBlockId)> = data
        .varnode(lo)
        .descendants
        .iter()
        .copied()
        .filter_map(|id| {
            if data.opcode_of(id) != Some(op::COPY) {
                return None;
            }
            Some((output(data, id)?, operation_parent(data, id)?))
        })
        .collect();
    let high_copies: Vec<(VarnodeId, GraphBlockId)> = data
        .varnode(hi)
        .descendants
        .iter()
        .copied()
        .filter_map(|id| {
            if data.opcode_of(id) != Some(op::COPY) {
                return None;
            }
            Some((output(data, id)?, operation_parent(data, id)?))
        })
        .collect();
    for (low_copy, low_block) in low_copies {
        let low = data.varnode(low_copy);
        if !data.is_addr_tied(low_copy) {
            continue;
        }
        for (high_copy, high_block) in high_copies.iter().copied() {
            let high = data.varnode(high_copy);
            if low_block != high_block || !data.is_addr_tied(high_copy) || low.space != high.space {
                continue;
            }
            let contiguous = if data.big_endian {
                high.offset.checked_add(u64::from(high.size)) == Some(low.offset)
            } else {
                low.offset.checked_add(u64::from(low.size)) == Some(high.offset)
            };
            if contiguous {
                result.push(SplitVarnode::with_whole(
                    data,
                    whole,
                    low_copy,
                    Some(high_copy),
                ));
            }
        }
    }
}
fn mask_for_size(size: u32) -> u64 {
    let bits = size.saturating_mul(8);
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits).wrapping_sub(1)
    }
}

fn check_add_carry(
    data: &Funcdata,
    zextop: OpId,
    lo1: VarnodeId,
) -> Option<(Option<VarnodeId>, u64)> {
    if data.opcode_of(zextop) != Some(op::INT_ZEXT) {
        return None;
    }
    let carry = input(data, zextop, 0)?;
    let carryop = definition(data, carry)?;
    match data.opcode_of(carryop)? {
        op::INT_CARRY => {
            let lo2 = if input(data, carryop, 0)? == lo1 {
                input(data, carryop, 1)?
            } else if input(data, carryop, 1)? == lo1 {
                input(data, carryop, 0)?
            } else {
                return None;
            };
            (!data.varnode(lo2).flags.constant).then_some((Some(lo2), 0))
        }
        op::INT_LESS => {
            let first = input(data, carryop, 0)?;
            let second = input(data, carryop, 1)?;
            if let Some(value) = constant(data, first) {
                if second != lo1 {
                    return None;
                }
                return Some((None, (!value) & mask_for_size(data.varnode(lo1).size)));
            }
            let add = definition(data, first)?;
            if data.opcode_of(add) != Some(op::INT_ADD) {
                return None;
            }
            let other = other_input(data, add, lo1)?;
            if let Some(value) = constant(data, other) {
                if second != lo1 && constant(data, second) != Some(value) {
                    return None;
                }
                return Some((None, value));
            }
            if second == other || second == lo1 {
                Some((Some(other), 0))
            } else {
                None
            }
        }
        op::INT_NOTEQUAL => {
            if input(data, carryop, 0)? != lo1 || constant(data, input(data, carryop, 1)?)? != 0 {
                return None;
            }
            Some((None, mask_for_size(data.varnode(lo1).size)))
        }
        _ => None,
    }
}

/// Match Ghidra's `CopyForceForm::applyRule` (`double.cc:3131-3196`).
///
/// The graph has no separate `Varnode::isAddrForce` or
/// `PcodeOp::isReturnCopy` flags.  The representable address-forced shape is
/// therefore identified by address-tied, descendant-free machine locations;
/// the return-copy-only extra source copy is not a graph form.
fn copy_force_form_apply(
    input_split: &SplitVarnode,
    workop: OpId,
    workishi: bool,
    data: &mut Funcdata,
) -> bool {
    if !workishi || !input_split.has_both_pieces() || data.opcode_of(workop) != Some(op::COPY) {
        return false;
    }
    let (Some(hi), Some(lo), Some(whole)) = (input_split.hi, input_split.lo, input_split.whole)
    else {
        return false;
    };
    if input(data, workop, 0) != Some(hi) {
        return false;
    }
    let Some(reshi) = output(data, workop) else {
        return false;
    };
    if !data.is_addr_tied(reshi) || !data.varnode(reshi).descendants.is_empty() {
        return false;
    }
    let parent = operation_parent(data, workop);
    let low_descendants: Vec<OpId> = data.varnode(lo).descendants.iter().copied().collect();
    for copylo in low_descendants {
        if data.opcode_of(copylo) != Some(op::COPY) || operation_parent(data, copylo) != parent {
            continue;
        }
        let Some(reslo) = output(data, copylo) else {
            continue;
        };
        if !data.is_addr_tied(reslo) || !data.varnode(reslo).descendants.is_empty() {
            continue;
        }
        let Some((space, address, size)) = contiguous_piece_storage(data, reslo, reshi) else {
            continue;
        };
        let seq = data.op(workop).seq;
        let whole_copy = data.new_op(op::COPY, seq, vec![whole]);
        let out = data.new_varnode(space, address, size);
        data.op_set_output(whole_copy, Some(out));
        data.op_insert_before(whole_copy, workop);
        data.op_destroy(workop);
        data.op_destroy(copylo);
        return true;
    }
    false
}

/// Match Ghidra's `PhiForm::applyRule` (`double.cc:3026-3078`).
fn phi_form_apply(
    input_split: &SplitVarnode,
    workop: OpId,
    workishi: bool,
    data: &mut Funcdata,
) -> bool {
    if !workishi || !input_split.has_both_pieces() || data.opcode_of(workop) != Some(op::MULTIEQUAL)
    {
        return false;
    }
    let (Some(hi), Some(lo), Some(hiphi_out)) =
        (input_split.hi, input_split.lo, output(data, workop))
    else {
        return false;
    };
    if data.varnode(hiphi_out).descendants.is_empty() {
        return false;
    }
    let Some(parent) = operation_parent(data, workop) else {
        return false;
    };
    let Some(hi_slot) = slot_of(data, workop, hi) else {
        return false;
    };
    let low_descendants: Vec<OpId> = data.varnode(lo).descendants.iter().copied().collect();
    let Some(lophi) = low_descendants.into_iter().find(|id| {
        data.opcode_of(*id) == Some(op::MULTIEQUAL)
            && operation_parent(data, *id) == Some(parent)
            && input(data, *id, hi_slot) == Some(lo)
    }) else {
        return false;
    };
    let (Some(lophi_out), Some(num_inputs)) =
        (output(data, lophi), Some(data.op(workop).inputs.len()))
    else {
        return false;
    };
    let mut input_list = Vec::with_capacity(num_inputs);
    for index in 0..num_inputs {
        let (Some(vhi), Some(vlo)) = (input(data, workop, index), input(data, lophi, index)) else {
            return false;
        };
        input_list.push(SplitVarnode::from_parts_with_size(
            data,
            input_split.wholesize,
            vlo,
            Some(vhi),
        ));
    }
    let mut output_split =
        SplitVarnode::from_parts_with_size(data, input_split.wholesize, lophi_out, Some(hiphi_out));
    let Some(exist) = prepare_phi(data, &mut output_split, &mut input_list) else {
        return false;
    };
    let Some(whole) = output_split.find_create_output_whole(data) else {
        return false;
    };
    let mut whole_inputs = Vec::with_capacity(input_list.len());
    for input_split in &mut input_list {
        let Some(whole_input) = input_split.find_create_whole(data, Some(exist)) else {
            return false;
        };
        whole_inputs.push(whole_input);
    }
    let seq = data.op(exist).seq;
    let newphi = data.new_op(op::MULTIEQUAL, seq, whole_inputs);
    data.op_set_output(newphi, Some(whole));
    data.op_insert_before(newphi, exist);
    let high_size = data.varnode(lo).size;
    rebuild_piece_from_whole(data, lophi_out, whole, 0)
        && rebuild_piece_from_whole(data, hiphi_out, whole, high_size)
}

/// Match Ghidra's `IndirectForm::applyRule` (`double.cc:3080-3129`).
fn indirect_form_apply(
    input_split: &SplitVarnode,
    workop: OpId,
    workishi: bool,
    data: &mut Funcdata,
) -> bool {
    if !workishi || !input_split.has_both_pieces() || data.opcode_of(workop) != Some(op::INDIRECT) {
        return false;
    }
    let (Some(_hi), Some(lo), Some(iop)) = (input_split.hi, input_split.lo, input(data, workop, 1))
    else {
        return false;
    };
    let Some(affector) = data.iop_target(iop) else {
        return false;
    };
    let Some(reshi) = output(data, workop) else {
        return false;
    };
    if data.varnode(reshi).flags.unique {
        return false;
    }
    let low_descendants: Vec<OpId> = data.varnode(lo).descendants.iter().copied().collect();
    let Some(indlo) = low_descendants.into_iter().find(|id| {
        data.opcode_of(*id) == Some(op::INDIRECT)
            && input(data, *id, 1).is_some_and(|value| data.iop_target(value) == Some(affector))
    }) else {
        return false;
    };
    let Some(reslo) = output(data, indlo) else {
        return false;
    };
    if data.varnode(reslo).flags.unique {
        return false;
    }
    let Some((_, _, size)) = contiguous_piece_storage(data, reslo, reshi) else {
        return false;
    };
    let mut known_input = input_split.clone();
    if !known_input.is_whole_feasible(data, affector) {
        return false;
    }
    let Some(input_whole) = known_input.find_create_whole(data, Some(affector)) else {
        return false;
    };
    let mark_creation = data.is_indirect_creation(workop) || data.is_indirect_creation(indlo);
    let mut output_split = SplitVarnode::from_parts_with_size(data, size, reslo, Some(reshi));
    let Some(whole) = create_joined_output_whole(data, &mut output_split) else {
        return false;
    };
    let affector_seq = data.op(affector).seq;
    let affector_iop = data.new_iop(affector);
    let newop = data.new_op(op::INDIRECT, affector_seq, vec![input_whole, affector_iop]);
    data.op_set_output(newop, Some(whole));
    if mark_creation {
        data.mark_indirect_creation(newop);
    }
    data.op_insert_before(newop, affector);
    let high_size = data.varnode(lo).size;
    rebuild_piece_from_whole(data, reslo, whole, 0)
        && rebuild_piece_from_whole(data, reshi, whole, high_size)
}

/// Match Ghidra's `Equal1Form::applyRule` (`double.cc:1827-1916`).
fn equal1_form_apply(
    input_split: &SplitVarnode,
    workop: OpId,
    workishi: bool,
    data: &mut Funcdata,
) -> bool {
    if !workishi
        || !input_split.has_both_pieces()
        || !matches!(
            data.opcode_of(workop),
            Some(op::INT_EQUAL | op::INT_NOTEQUAL)
        )
    {
        return false;
    }
    let (Some(hi1), Some(lo1), Some(hi_output)) =
        (input_split.hi, input_split.lo, output(data, workop))
    else {
        return false;
    };
    let Some(hi2) = other_input(data, workop, hi1) else {
        return false;
    };
    let hi_notequal = data.opcode_of(workop) == Some(op::INT_NOTEQUAL);
    let low_descendants: Vec<OpId> = data.varnode(lo1).descendants.iter().copied().collect();
    let hi_bool_descendants: Vec<OpId> = data
        .varnode(hi_output)
        .descendants
        .iter()
        .copied()
        .collect();
    for loopop in low_descendants {
        let Some(low_opcode) = data.opcode_of(loopop) else {
            continue;
        };
        if !matches!(low_opcode, op::INT_EQUAL | op::INT_NOTEQUAL) {
            continue;
        }
        let Some(lo2) = other_input(data, loopop, lo1) else {
            continue;
        };
        let lo_notequal = low_opcode == op::INT_NOTEQUAL;
        let mut in2 =
            SplitVarnode::from_parts_with_size(data, input_split.wholesize, lo2, Some(hi2));
        if in2.exceeds_const_precision() {
            continue;
        }
        let Some(lo_output) = output(data, loopop) else {
            continue;
        };
        let lo_bool_descendants: Vec<OpId> = data
            .varnode(lo_output)
            .descendants
            .iter()
            .copied()
            .collect();
        for hibool in hi_bool_descendants.iter().copied() {
            if data.opcode_of(hibool) != Some(op::CBRANCH) {
                continue;
            }
            for lobool in lo_bool_descendants.iter().copied() {
                if data.opcode_of(lobool) != Some(op::CBRANCH) {
                    continue;
                }
                let Some((hi_true, hi_false)) = branch_true_false(data, hibool, hi_notequal) else {
                    continue;
                };
                let Some((lo_true, lo_false)) = branch_true_false(data, lobool, lo_notequal) else {
                    continue;
                };
                let hi_parent = operation_parent(data, hibool);
                let lo_parent = operation_parent(data, lobool);
                let (continue_branch, compare_branch, other_branch) = if Some(hi_true) == lo_parent
                    && hi_false == lo_false
                    && otherwise_empty(data, lobool)
                {
                    (true, hibool, lobool)
                } else if Some(lo_true) == hi_parent
                    && hi_false == lo_false
                    && otherwise_empty(data, hibool)
                {
                    (false, lobool, hibool)
                } else {
                    continue;
                };
                let mut in1 = input_split.clone();
                if !in1.is_whole_feasible(data, compare_branch)
                    || !in2.is_whole_feasible(data, compare_branch)
                {
                    continue;
                }
                let compare_opcode = if continue_branch {
                    if hi_notequal {
                        op::INT_NOTEQUAL
                    } else {
                        op::INT_EQUAL
                    }
                } else if lo_notequal {
                    op::INT_NOTEQUAL
                } else {
                    op::INT_EQUAL
                };
                if !create_bool_op(data, compare_branch, &mut in1, &mut in2, compare_opcode) {
                    continue;
                }
                let value = if continue_branch {
                    if lo_notequal { 0 } else { 1 }
                } else if hi_notequal {
                    0
                } else {
                    1
                };
                let condition = data.new_constant(value, 1);
                data.op_set_input(other_branch, condition, 1);
                return true;
            }
        }
    }
    false
}

/// Match Ghidra's `Equal2Form::applyRule` (`double.cc:1936-1982`).
fn equal2_form_apply(
    input_split: &SplitVarnode,
    workop: OpId,
    workishi: bool,
    data: &mut Funcdata,
) -> bool {
    if !workishi
        || !input_split.has_both_pieces()
        || !matches!(
            data.opcode_of(workop),
            Some(op::INT_EQUAL | op::INT_NOTEQUAL)
        )
    {
        return false;
    }
    let (Some(hi1), Some(lo1), Some(hi_output)) =
        (input_split.hi, input_split.lo, output(data, workop))
    else {
        return false;
    };
    let Some(hi2) = other_input(data, workop, hi1) else {
        return false;
    };
    let eq_opcode = data.opcode_of(workop).expect("checked compare opcode");
    let bool_descendants: Vec<OpId> = data
        .varnode(hi_output)
        .descendants
        .iter()
        .copied()
        .collect();
    for boolop in bool_descendants {
        let expected = if eq_opcode == op::INT_EQUAL {
            op::BOOL_AND
        } else {
            op::BOOL_OR
        };
        if data.opcode_of(boolop) != Some(expected) {
            continue;
        }
        let Some(other_bool_input) = other_input(data, boolop, hi_output) else {
            continue;
        };
        let Some(equal_lo) = definition(data, other_bool_input) else {
            continue;
        };
        if data.opcode_of(equal_lo) != Some(eq_opcode) {
            continue;
        }
        let Some(lo2) = (if input(data, equal_lo, 0) == Some(lo1) {
            input(data, equal_lo, 1)
        } else if input(data, equal_lo, 1) == Some(lo1) {
            input(data, equal_lo, 0)
        } else {
            None
        }) else {
            continue;
        };
        if constant(data, hi2).is_some() != constant(data, lo2).is_some() {
            continue;
        }
        let mut first = input_split.clone();
        let mut second =
            SplitVarnode::from_parts_with_size(data, input_split.wholesize, lo2, Some(hi2));
        if second.exceeds_const_precision()
            || !first.is_whole_feasible(data, boolop)
            || !second.is_whole_feasible(data, boolop)
        {
            continue;
        }
        if replace_bool(data, boolop, &mut first, &mut second, eq_opcode) {
            return true;
        }
    }
    false
}

/// Match Ghidra's `LessConstForm::applyRule` (`double.cc:2498-2548`).
fn less_const_form_apply(
    input_split: &SplitVarnode,
    workop: OpId,
    workishi: bool,
    data: &mut Funcdata,
) -> bool {
    if !workishi
        || input_split.hi.is_none()
        || !matches!(
            data.opcode_of(workop),
            Some(op::INT_LESS | op::INT_LESSEQUAL | op::INT_SLESS | op::INT_SLESSEQUAL)
        )
    {
        return false;
    }
    let hi = input_split.hi.expect("checked high piece");
    let Some(inslot) = slot_of(data, workop, hi) else {
        return false;
    };
    let Some(constant_input) = input(data, workop, 1usize.saturating_sub(inslot)) else {
        return false;
    };
    let Some(constant_value) = constant(data, constant_input) else {
        return false;
    };
    let opcode = data.opcode_of(workop).expect("checked compare opcode");
    let high_lessequal = matches!(opcode, op::INT_LESSEQUAL | op::INT_SLESSEQUAL);
    let low_size = input_split.size().saturating_sub(data.varnode(hi).size);
    let shift = low_size.saturating_mul(8);
    let mut value = if shift >= 64 {
        0
    } else {
        constant_value.wrapping_shl(shift)
    };
    if high_lessequal != (inslot == 1) {
        value |= mask_for_size(low_size);
    }
    let Some(descendant) =
        output(data, workop).and_then(|_| data.lone_descend(output(data, workop)?))
    else {
        return false;
    };
    if data.opcode_of(descendant) != Some(op::CBRANCH) {
        return false;
    }
    let mut constant_split = SplitVarnode::new_constant(input_split.size(), value);
    if constant_split.exceeds_const_precision() {
        return false;
    }
    let mut known_input = input_split.clone();
    if inslot == 0 {
        replace_bool(data, workop, &mut known_input, &mut constant_split, opcode)
    } else {
        replace_bool(data, workop, &mut constant_split, &mut known_input, opcode)
    }
}

/// State used while matching Ghidra's three-branch less-than expansion.
#[derive(Default)]
struct LessThreeWay {
    input: SplitVarnode,
    in2: SplitVarnode,
    hilessbl: Option<GraphBlockId>,
    lolessbl: Option<GraphBlockId>,
    hieqbl: Option<GraphBlockId>,
    hilessbool: Option<OpId>,
    lolessbool: Option<OpId>,
    hieqbool: Option<OpId>,
    hiless: Option<OpId>,
    loless: Option<OpId>,
    hiequal: Option<OpId>,
    hiflip: bool,
    equalflip: bool,
    loflip: bool,
    midlessform: bool,
    lolessiszerocomp: bool,
    midlessequal: bool,
    midsigncompare: bool,
    lolessequalform: bool,
    hilessequalform: bool,
    signcompare: bool,
    hiconstform: bool,
    midconstform: bool,
    loconstform: bool,
    hival: u64,
    midval: u64,
    loval: u64,
    vnhil1: Option<VarnodeId>,
    vnhil2: Option<VarnodeId>,
    vnhie1: Option<VarnodeId>,
    vnhie2: Option<VarnodeId>,
    vnlo1: Option<VarnodeId>,
    vnlo2: Option<VarnodeId>,
    lo: Option<VarnodeId>,
    hi: Option<VarnodeId>,
    lo2: Option<VarnodeId>,
    hi2: Option<VarnodeId>,
    hislot: usize,
    final_opcode: i32,
}

impl LessThreeWay {
    /// Map the low branch's predecessor chain to the three comparison blocks.
    ///
    /// This is `LessThreeWay::mapBlocksFromLow` (`double.cc:2026-2039`).
    fn map_blocks_from_low(&mut self, data: &Funcdata, low_branch: OpId) -> bool {
        let Some(low_block) = operation_parent(data, low_branch) else {
            return false;
        };
        let low_predecessors = &data.block(low_block).predecessors;
        if low_predecessors.len() != 1 || data.block(low_block).successors.len() != 2 {
            return false;
        }
        let middle_block = low_predecessors[0];
        let middle_predecessors = &data.block(middle_block).predecessors;
        if middle_predecessors.len() != 1 || data.block(middle_block).successors.len() != 2 {
            return false;
        }
        let high_block = middle_predecessors[0];
        if data.block(high_block).successors.len() != 2 {
            return false;
        }
        self.lolessbl = Some(low_block);
        self.hieqbl = Some(middle_block);
        self.hilessbl = Some(high_block);
        true
    }

    /// Map each comparison block's terminator and comparison producer.
    ///
    /// This is `LessThreeWay::mapOpsFromBlocks` (`double.cc:2041-2146`).
    fn map_ops_from_blocks(&mut self, data: &Funcdata) -> bool {
        let (Some(hilessbl), Some(lolessbl), Some(hieqbl)) =
            (self.hilessbl, self.lolessbl, self.hieqbl)
        else {
            return false;
        };
        let Some(hilessbool) = last_live_op(data, hilessbl) else {
            return false;
        };
        let Some(lolessbool) = last_live_op(data, lolessbl) else {
            return false;
        };
        let Some(hieqbool) = last_live_op(data, hieqbl) else {
            return false;
        };
        if data.opcode_of(hilessbool) != Some(op::CBRANCH)
            || data.opcode_of(lolessbool) != Some(op::CBRANCH)
            || data.opcode_of(hieqbool) != Some(op::CBRANCH)
        {
            return false;
        }
        let Some(hiequal) = input(data, hieqbool, 1)
            .filter(|value| is_written(data, *value))
            .and_then(|value| definition(data, value))
        else {
            return false;
        };
        let Some(loless) = input(data, lolessbool, 1)
            .filter(|value| is_written(data, *value))
            .and_then(|value| definition(data, value))
        else {
            return false;
        };
        let Some(hiless) = input(data, hilessbool, 1)
            .filter(|value| is_written(data, *value))
            .and_then(|value| definition(data, value))
        else {
            return false;
        };
        self.hilessbool = Some(hilessbool);
        self.lolessbool = Some(lolessbool);
        self.hieqbool = Some(hieqbool);
        self.hiequal = Some(hiequal);
        self.loless = Some(loless);
        self.hiless = Some(hiless);
        self.hiflip = false;
        self.equalflip = false;
        self.loflip = false;
        self.midlessform = false;
        self.lolessiszerocomp = false;
        match data.opcode_of(hiequal) {
            Some(op::INT_EQUAL) | Some(op::INT_NOTEQUAL) => {}
            Some(op::INT_LESS) => {
                self.midlessequal = false;
                self.midsigncompare = false;
                self.midlessform = true;
            }
            Some(op::INT_LESSEQUAL) => {
                self.midlessequal = true;
                self.midsigncompare = false;
                self.midlessform = true;
            }
            Some(op::INT_SLESS) => {
                self.midlessequal = false;
                self.midsigncompare = true;
                self.midlessform = true;
            }
            Some(op::INT_SLESSEQUAL) => {
                self.midlessequal = true;
                self.midsigncompare = true;
                self.midlessform = true;
            }
            _ => return false,
        }
        match data.opcode_of(loless) {
            Some(op::INT_LESS) => self.lolessequalform = false,
            Some(op::INT_LESSEQUAL) => self.lolessequalform = true,
            Some(op::INT_EQUAL) => {
                let Some(right) = input(data, loless, 1) else {
                    return false;
                };
                if constant(data, right) != Some(0) {
                    return false;
                }
                self.lolessiszerocomp = true;
                self.lolessequalform = true;
            }
            Some(op::INT_NOTEQUAL) => {
                let Some(right) = input(data, loless, 1) else {
                    return false;
                };
                if constant(data, right) != Some(0) {
                    return false;
                }
                self.lolessiszerocomp = true;
                self.lolessequalform = false;
            }
            _ => return false,
        }
        match data.opcode_of(hiless) {
            Some(op::INT_LESS) => {
                self.hilessequalform = false;
                self.signcompare = false;
            }
            Some(op::INT_LESSEQUAL) => {
                self.hilessequalform = true;
                self.signcompare = false;
            }
            Some(op::INT_SLESS) => {
                self.hilessequalform = false;
                self.signcompare = true;
            }
            Some(op::INT_SLESSEQUAL) => {
                self.hilessequalform = true;
                self.signcompare = true;
            }
            _ => return false,
        }
        true
    }

    /// Ensure high and middle comparisons use the same signedness.
    ///
    /// This is `LessThreeWay::checkSignedness` (`double.cc:2148-2155`).
    fn check_signedness(&self) -> bool {
        !self.midlessform || self.midsigncompare == self.signcompare
    }

    /// Normalize the high comparison to a strict less-than form.
    ///
    /// This is `LessThreeWay::normalizeHi` (`double.cc:2157-2202`).
    fn normalize_hi(&mut self, data: &Funcdata) -> bool {
        let Some(hiless) = self.hiless else {
            return false;
        };
        let (Some(mut first), Some(mut second)) = (input(data, hiless, 0), input(data, hiless, 1))
        else {
            return false;
        };
        if constant(data, first).is_some() {
            self.hiflip = !self.hiflip;
            self.hilessequalform = !self.hilessequalform;
            std::mem::swap(&mut first, &mut second);
        }
        self.vnhil1 = Some(first);
        self.vnhil2 = Some(second);
        self.hiconstform = false;
        if constant(data, second).is_some() {
            if self.input.size() > 8 {
                return false;
            }
            self.hiconstform = true;
            self.hival = constant(data, second).expect("constant checked");
            let Some(hilessbool) = self.hilessbool else {
                return false;
            };
            let Some((_, hilessfalse)) = branch_true_false(data, hilessbool, self.hiflip) else {
                return false;
            };
            let mut increment = 1i8;
            if Some(hilessfalse) != self.hieqbl {
                self.hiflip = !self.hiflip;
                self.hilessequalform = !self.hilessequalform;
                std::mem::swap(&mut first, &mut second);
                self.vnhil1 = Some(first);
                self.vnhil2 = Some(second);
                increment = -1;
            }
            if self.hilessequalform {
                self.hival = if increment < 0 {
                    self.hival.wrapping_sub(1)
                } else {
                    self.hival.wrapping_add(1)
                };
                self.hival &= mask_for_size(self.input.size());
                self.hilessequalform = false;
            }
            let shift = self
                .input
                .lo
                .map(|value| data.varnode(value).size)
                .unwrap_or(0)
                * 8;
            if shift >= 64 {
                self.hival = 0;
            } else {
                self.hival >>= shift;
            }
        } else if self.hilessequalform {
            self.hilessequalform = false;
            self.hiflip = !self.hiflip;
            std::mem::swap(&mut first, &mut second);
            self.vnhil1 = Some(first);
            self.vnhil2 = Some(second);
        }
        true
    }

    /// Normalize the middle comparison against equality of high pieces.
    ///
    /// This is `LessThreeWay::normalizeMid` (`double.cc:2204-2259`).
    fn normalize_mid(&mut self, data: &Funcdata) -> bool {
        let Some(hiequal) = self.hiequal else {
            return false;
        };
        let (Some(mut first), Some(mut second)) =
            (input(data, hiequal, 0), input(data, hiequal, 1))
        else {
            return false;
        };
        if constant(data, first).is_some() {
            std::mem::swap(&mut first, &mut second);
            if self.midlessform {
                self.equalflip = !self.equalflip;
                self.midlessequal = !self.midlessequal;
            }
        }
        self.vnhie1 = Some(first);
        self.vnhie2 = Some(second);
        self.midconstform = false;
        if constant(data, second).is_some() {
            if !self.hiconstform {
                return false;
            }
            self.midconstform = true;
            self.midval = constant(data, second).expect("constant checked");
            if data.varnode(second).size == self.input.size() {
                let low_bits = self
                    .input
                    .lo
                    .map(|value| data.varnode(value).size)
                    .unwrap_or(0)
                    * 8;
                let low_mask = self
                    .input
                    .lo
                    .map(|value| mask_for_size(data.varnode(value).size))
                    .unwrap_or(0);
                let low_part = self.midval & low_mask;
                if low_bits >= 64 {
                    self.midval = 0;
                } else {
                    self.midval >>= low_bits;
                }
                if self.midlessform {
                    if self.midlessequal {
                        if low_part != low_mask {
                            return false;
                        }
                    } else if low_part != 0 {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            if self.midval != self.hival {
                if !self.midlessform {
                    return false;
                }
                self.midval = if self.midlessequal {
                    self.midval.wrapping_add(1)
                } else {
                    self.midval.wrapping_sub(1)
                };
                self.midval &= mask_for_size(
                    self.input
                        .lo
                        .map(|value| data.varnode(value).size)
                        .unwrap_or(0),
                );
                self.midlessequal = !self.midlessequal;
                if self.midval != self.hival {
                    return false;
                }
            }
        }
        if self.midlessform {
            if !self.midlessequal {
                self.equalflip = !self.equalflip;
            }
        } else if data.opcode_of(hiequal) == Some(op::INT_NOTEQUAL) {
            self.equalflip = !self.equalflip;
        }
        true
    }

    /// Normalize the low comparison to a strict less-than form.
    ///
    /// This is `LessThreeWay::normalizeLo` (`double.cc:2261-2306`).
    fn normalize_lo(&mut self, data: &Funcdata) -> bool {
        let Some(loless) = self.loless else {
            return false;
        };
        let (Some(mut first), Some(mut second)) = (input(data, loless, 0), input(data, loless, 1))
        else {
            return false;
        };
        self.vnlo1 = Some(first);
        self.vnlo2 = Some(second);
        if self.lolessiszerocomp {
            self.loconstform = true;
            if self.lolessequalform {
                self.loval = 1;
                self.lolessequalform = false;
            } else {
                self.loflip = !self.loflip;
                self.loval = 1;
            }
            return true;
        }
        if constant(data, first).is_some() {
            self.loflip = !self.loflip;
            self.lolessequalform = !self.lolessequalform;
            std::mem::swap(&mut first, &mut second);
            self.vnlo1 = Some(first);
            self.vnlo2 = Some(second);
        }
        self.loconstform = false;
        if constant(data, second).is_some() {
            self.loconstform = true;
            self.loval = constant(data, second).expect("constant checked");
            if self.lolessequalform {
                self.loval = self.loval.wrapping_add(1);
                self.loval &= mask_for_size(data.varnode(second).size);
                self.lolessequalform = false;
            }
        } else if self.lolessequalform {
            self.lolessequalform = false;
            self.loflip = !self.loflip;
            std::mem::swap(&mut first, &mut second);
            self.vnlo1 = Some(first);
            self.vnlo2 = Some(second);
        }
        true
    }

    /// Check that normalized comparison operands have the split shape.
    ///
    /// This is `LessThreeWay::checkOpForm` (`double.cc:2331-2400`).
    fn check_op_form(&mut self, data: &Funcdata) -> bool {
        let (Some(vnhil1), Some(vnhil2), Some(vnhie1), Some(vnhie2), Some(vnlo1), Some(vnlo2)) = (
            self.vnhil1,
            self.vnhil2,
            self.vnhie1,
            self.vnhie2,
            self.vnlo1,
            self.vnlo2,
        ) else {
            return false;
        };
        self.lo = self.input.lo;
        self.hi = self.input.hi;
        if self.midconstform {
            if !self.hiconstform {
                return false;
            }
            let Some(vnhie2) = self.vnhie2 else {
                return false;
            };
            if data.varnode(vnhie2).size == self.input.size() {
                if vnhie1 != vnhil1 && vnhie1 != vnhil2 {
                    return false;
                }
            } else if Some(vnhie1) != self.hi {
                return false;
            }
        } else if (vnhil1 != vnhie1 && vnhil1 != vnhie2) || (vnhil2 != vnhie1 && vnhil2 != vnhie2) {
            return false;
        }
        let Some(lo) = self.lo else {
            return false;
        };
        if self.hi == Some(vnhil1) {
            if self.hiconstform {
                return false;
            }
            self.hislot = 0;
            self.hi2 = Some(vnhil2);
            if vnlo1 != lo {
                self.vnlo1 = Some(vnlo2);
                self.vnlo2 = Some(vnlo1);
                if self.vnlo1 != Some(lo) {
                    return false;
                }
                self.loflip = !self.loflip;
                self.lolessequalform = !self.lolessequalform;
            }
            self.lo2 = self.vnlo2;
        } else if self.hi == Some(vnhil2) {
            if self.hiconstform {
                return false;
            }
            self.hislot = 1;
            self.hi2 = Some(vnhil1);
            if vnlo2 != lo {
                self.vnlo1 = Some(vnlo2);
                self.vnlo2 = Some(vnlo1);
                if self.vnlo2 != Some(lo) {
                    return false;
                }
                self.loflip = !self.loflip;
                self.lolessequalform = !self.lolessequalform;
            }
            self.lo2 = self.vnlo1;
        } else if self.input.whole == Some(vnhil1) {
            if !self.hiconstform || !self.loconstform || vnlo1 != lo {
                return false;
            }
            self.hislot = 0;
        } else if self.input.whole == Some(vnhil2) {
            if !self.hiconstform || !self.loconstform {
                return false;
            }
            if vnlo2 != lo {
                self.loflip = !self.loflip;
                self.loval = self.loval.wrapping_sub(1);
                self.loval &= mask_for_size(data.varnode(lo).size);
                if vnlo1 != lo {
                    return false;
                }
            }
            self.hislot = 1;
        } else {
            return false;
        }
        true
    }

    /// Check the branch topology of the three-way expansion.
    ///
    /// This is `LessThreeWay::checkBlockForm` (`double.cc:2308-2329`).
    fn check_block_form(&self, data: &Funcdata) -> bool {
        let (Some(hilessbool), Some(lolessbool), Some(hieqbool)) =
            (self.hilessbool, self.lolessbool, self.hieqbool)
        else {
            return false;
        };
        let Some((hilesstrue, hilessfalse)) = branch_true_false(data, hilessbool, self.hiflip)
        else {
            return false;
        };
        let Some((lolesstrue, lolessfalse)) = branch_true_false(data, lolessbool, self.loflip)
        else {
            return false;
        };
        let Some((hieqtrue, hieqfalse)) = branch_true_false(data, hieqbool, self.equalflip) else {
            return false;
        };
        hilesstrue == lolesstrue
            && hieqfalse == lolessfalse
            && Some(hilessfalse) == self.hieqbl
            && Some(hieqtrue) == self.lolessbl
            && otherwise_empty(data, hieqbool)
            && otherwise_empty(data, lolessbool)
    }

    /// Select the final wide comparison opcode and operand order.
    ///
    /// This is `LessThreeWay::setOpCode` (`double.cc:2403-2414`).
    fn set_opcode(&mut self) {
        self.final_opcode = if self.lolessequalform != self.hiflip {
            if self.signcompare {
                op::INT_SLESSEQUAL
            } else {
                op::INT_LESSEQUAL
            }
        } else if self.signcompare {
            op::INT_SLESS
        } else {
            op::INT_LESS
        };
        if self.hiflip {
            self.hislot = 1usize.saturating_sub(self.hislot);
            self.hiflip = false;
        }
    }

    /// Check whether the selected branch can carry the wide comparison.
    ///
    /// This is `LessThreeWay::setBoolOp` (`double.cc:2416-2428`).
    fn set_bool_op(&self, data: &Funcdata) -> bool {
        let Some(hilessbool) = self.hilessbool else {
            return false;
        };
        let mut first = self.input.clone();
        let mut second = self.in2.clone();
        if self.hislot == 0 {
            first.is_whole_feasible(data, hilessbool) && second.is_whole_feasible(data, hilessbool)
        } else {
            second.is_whole_feasible(data, hilessbool) && first.is_whole_feasible(data, hilessbool)
        }
    }
    fn map_from_low(&mut self, data: &Funcdata, low_compare: OpId) -> bool {
        let Some(low_output) = output(data, low_compare) else {
            return false;
        };
        let Some(low_branch) = data.lone_descend(low_output) else {
            return false;
        };
        self.map_blocks_from_low(data, low_branch)
            && self.map_ops_from_blocks(data)
            && self.check_signedness()
            && self.normalize_hi(data)
            && self.normalize_mid(data)
            && self.normalize_lo(data)
            && self.check_op_form(data)
            && self.check_block_form(data)
    }

    /// Build the replacement operand and validate whole-value feasibility.
    fn test_replace(&mut self, data: &mut Funcdata) -> bool {
        self.set_opcode();
        if self.hiconstform {
            let low_size = self
                .input
                .lo
                .map(|value| data.varnode(value).size)
                .unwrap_or(0);
            let shift = low_size.saturating_mul(8);
            let value = if shift >= 64 {
                self.loval
            } else {
                self.hival.wrapping_shl(shift) | self.loval
            };
            self.in2 = SplitVarnode::new_constant(self.input.size(), value);
        } else {
            let (Some(lo2), Some(hi2)) = (self.lo2, self.hi2) else {
                return false;
            };
            self.in2 = SplitVarnode::from_parts_with_size(data, self.input.size(), lo2, Some(hi2));
        }
        self.set_bool_op(data)
    }
}

/// Match Ghidra's `LessThreeWay::applyRule` (`double.cc:2462-2495`).
fn less_three_way_apply(
    input_split: &SplitVarnode,
    workop: OpId,
    workishi: bool,
    data: &mut Funcdata,
) -> bool {
    if workishi || input_split.lo.is_none() {
        return false;
    }
    let mut form = LessThreeWay {
        input: input_split.clone(),
        ..LessThreeWay::default()
    };
    if !form.map_from_low(data, workop) || !form.test_replace(data) {
        return false;
    }
    if form.in2.exceeds_const_precision() {
        return false;
    }
    let (Some(hilessbool), Some(hieqbool)) = (form.hilessbool, form.hieqbool) else {
        return false;
    };
    let mut first = form.input.clone();
    let mut second = form.in2.clone();
    let created = if form.hislot == 0 {
        create_bool_op(data, hilessbool, &mut first, &mut second, form.final_opcode)
    } else {
        create_bool_op(data, hilessbool, &mut second, &mut first, form.final_opcode)
    };
    if !created {
        return false;
    }
    let equalflip_value = if form.equalflip { 1 } else { 0 };
    let constant = data.new_constant(equalflip_value, 1);
    data.op_set_input(hieqbool, constant, 1);
    true
}

/// Match Ghidra's `AddForm::applyRule` (`double.cc:1503-1606`).
fn add_form_apply(
    input_split: &SplitVarnode,
    workop: OpId,
    workishi: bool,
    data: &mut Funcdata,
) -> bool {
    if !workishi || !input_split.has_both_pieces() {
        return false;
    }
    let (Some(hi1), Some(lo1), Some(work_out)) =
        (input_split.hi, input_split.lo, output(data, workop))
    else {
        return false;
    };
    if data.opcode_of(workop) != Some(op::INT_ADD) {
        return false;
    }
    let mut matched = None;
    for variant in 0..3 {
        let (reshi, hizext1, hizext2) = match variant {
            0 => {
                let Some(add2) = data.lone_descend(work_out) else {
                    continue;
                };
                if data.opcode_of(add2) != Some(op::INT_ADD) {
                    continue;
                }
                let Some(reshi) = output(data, add2) else {
                    continue;
                };
                let Some(hizext1) = other_input(data, workop, hi1) else {
                    continue;
                };
                let Some(hizext2) = other_input(data, add2, work_out) else {
                    continue;
                };
                (reshi, hizext1, Some(hizext2))
            }
            1 => {
                let Some(tmp) = other_input(data, workop, hi1) else {
                    continue;
                };
                let Some(add2) = definition(data, tmp) else {
                    continue;
                };
                if data.opcode_of(add2) != Some(op::INT_ADD) {
                    continue;
                }
                let Some(reshi) = output(data, workop) else {
                    continue;
                };
                let (Some(hizext1), Some(hizext2)) = (input(data, add2, 0), input(data, add2, 1))
                else {
                    continue;
                };
                (reshi, hizext1, Some(hizext2))
            }
            _ => {
                let Some(reshi) = output(data, workop) else {
                    continue;
                };
                let Some(hizext1) = other_input(data, workop, hi1) else {
                    continue;
                };
                (reshi, hizext1, None)
            }
        };

        for high_slot in 0..2 {
            let (candidate, hi2) = if high_slot == 0 {
                (hizext1, hizext2)
            } else {
                let Some(hizext2) = hizext2 else {
                    continue;
                };
                (hizext2, Some(hizext1))
            };
            let Some(zextop) = definition(data, candidate) else {
                continue;
            };
            let Some((mut lo2, negconst)) = check_add_carry(data, zextop, lo1) else {
                continue;
            };
            let descendants: Vec<OpId> = data.varnode(lo1).descendants.iter().copied().collect();
            for loadd in descendants {
                if data.opcode_of(loadd) != Some(op::INT_ADD) {
                    continue;
                }
                let Some(tmp) = other_input(data, loadd, lo1) else {
                    continue;
                };
                if lo2.is_none() {
                    if constant(data, tmp) != Some(negconst) {
                        continue;
                    }
                    lo2 = Some(tmp);
                } else if let Some(lo2_value) = lo2 {
                    if constant(data, lo2_value).is_some() {
                        if constant(data, tmp) != constant(data, lo2_value) {
                            continue;
                        }
                    } else if tmp != lo2_value {
                        continue;
                    }
                }
                let Some(reslo) = output(data, loadd) else {
                    continue;
                };
                let Some(lo2) = lo2 else {
                    continue;
                };
                matched = Some((reslo, reshi, lo2, hi2));
                break;
            }
            if matched.is_some() {
                break;
            }
        }
        if matched.is_some() {
            break;
        }
    }

    let Some((reslo, reshi, lo2, hi2)) = matched else {
        return false;
    };
    let mut other = SplitVarnode::from_parts_with_size(data, input_split.size(), lo2, hi2);
    if other.exceeds_const_precision() {
        return false;
    }
    let mut out = SplitVarnode::from_parts_with_size(data, input_split.size(), reslo, Some(reshi));
    let mut known_input = input_split.clone();
    let Some(exist) = prepare_binary(data, &mut out, &mut known_input, &mut other) else {
        return false;
    };
    create_binary(
        data,
        &mut out,
        &mut known_input,
        &mut other,
        exist,
        op::INT_ADD,
    )
}
fn verify_mult_neg_one(data: &Funcdata, id: OpId) -> bool {
    if data.opcode_of(id) != Some(op::INT_MULT) {
        return false;
    }
    let Some(value) = input(data, id, 1) else {
        return false;
    };
    constant(data, value) == Some(mask_for_size(data.varnode(value).size))
}

/// Match Ghidra's `SubForm::applyRule` (`double.cc:1609-1701`).
fn sub_form_apply(
    input_split: &SplitVarnode,
    workop: OpId,
    workishi: bool,
    data: &mut Funcdata,
) -> bool {
    if !workishi || !input_split.has_both_pieces() {
        return false;
    }
    let (Some(hi1), Some(lo1), Some(work_out)) =
        (input_split.hi, input_split.lo, output(data, workop))
    else {
        return false;
    };
    if data.opcode_of(workop) != Some(op::INT_ADD) {
        return false;
    }

    let mut matched = None;
    for variant in 0..2 {
        let (reshi, hineg1, hineg2) = if variant == 0 {
            let Some(add2) = data.lone_descend(work_out) else {
                continue;
            };
            if data.opcode_of(add2) != Some(op::INT_ADD) {
                continue;
            }
            let (Some(reshi), Some(hineg1), Some(hineg2)) = (
                output(data, add2),
                other_input(data, workop, hi1),
                other_input(data, add2, work_out),
            ) else {
                continue;
            };
            (reshi, hineg1, hineg2)
        } else {
            let Some(tmp) = other_input(data, workop, hi1) else {
                continue;
            };
            let Some(add2) = definition(data, tmp) else {
                continue;
            };
            if data.opcode_of(add2) != Some(op::INT_ADD) {
                continue;
            }
            let (Some(reshi), Some(hineg1), Some(hineg2)) = (
                output(data, workop),
                input(data, add2, 0),
                input(data, add2, 1),
            ) else {
                continue;
            };
            (reshi, hineg1, hineg2)
        };
        if !is_written(data, hineg1)
            || !is_written(data, hineg2)
            || !definition(data, hineg1).is_some_and(|id| verify_mult_neg_one(data, id))
            || !definition(data, hineg2).is_some_and(|id| verify_mult_neg_one(data, id))
        {
            continue;
        }
        let (Some(neg1), Some(neg2)) = (definition(data, hineg1), definition(data, hineg2)) else {
            continue;
        };
        let (Some(hizext1), Some(hizext2)) = (input(data, neg1, 0), input(data, neg2, 0)) else {
            continue;
        };
        for swapped in [false, true] {
            let (candidate, other_hi) = if swapped {
                (hizext2, hizext1)
            } else {
                (hizext1, hizext2)
            };
            let Some(zextop) = definition(data, candidate) else {
                continue;
            };
            if data.opcode_of(zextop) != Some(op::INT_ZEXT) {
                continue;
            }
            let Some(less_value) = input(data, zextop, 0) else {
                continue;
            };
            let Some(lessop) = definition(data, less_value) else {
                continue;
            };
            if data.opcode_of(lessop) != Some(op::INT_LESS) || input(data, lessop, 0) != Some(lo1) {
                continue;
            }
            let Some(lo2) = input(data, lessop, 1) else {
                continue;
            };
            let descendants: Vec<OpId> = data.varnode(lo1).descendants.iter().copied().collect();
            for loadd in descendants {
                if data.opcode_of(loadd) != Some(op::INT_ADD) {
                    continue;
                }
                let Some(negated) = other_input(data, loadd, lo1) else {
                    continue;
                };
                let Some(negop) = definition(data, negated) else {
                    continue;
                };
                if !verify_mult_neg_one(data, negop) || input(data, negop, 0) != Some(lo2) {
                    continue;
                }
                let Some(reslo) = output(data, loadd) else {
                    continue;
                };
                matched = Some((reslo, reshi, lo2, other_hi));
                break;
            }
            if matched.is_some() {
                break;
            }
        }
        if matched.is_some() {
            break;
        }
    }
    let Some((reslo, reshi, lo2, hi2)) = matched else {
        return false;
    };
    let mut other = SplitVarnode::from_parts_with_size(data, input_split.size(), lo2, Some(hi2));
    if other.exceeds_const_precision() {
        return false;
    }
    let mut output_split =
        SplitVarnode::from_parts_with_size(data, input_split.size(), reslo, Some(reshi));
    let mut known_input = input_split.clone();
    let Some(exist) = prepare_binary(data, &mut output_split, &mut known_input, &mut other) else {
        return false;
    };
    create_binary(
        data,
        &mut output_split,
        &mut known_input,
        &mut other,
        exist,
        op::INT_SUB,
    )
}
fn companion_high(data: &Funcdata, low: VarnodeId) -> Option<VarnodeId> {
    let (whole, offset) = subpiece_source(data, low)?;
    if offset != 0 {
        return None;
    }
    let whole_size = data.varnode(whole).size;
    let descendants: Vec<OpId> = data.varnode(whole).descendants.iter().copied().collect();
    descendants.into_iter().find_map(|id| {
        if data.opcode_of(id) != Some(op::SUBPIECE) || input(data, id, 0) != Some(whole) {
            return None;
        }
        let high = output(data, id)?;
        let high_offset = constant(data, input(data, id, 1)?)?;
        (high_offset == u64::from(whole_size.saturating_sub(data.varnode(high).size))
            && data.varnode(high).size == data.varnode(low).size)
            .then_some(high)
    })
}

fn high_op_for_low_result(
    data: &Funcdata,
    low_result: VarnodeId,
    hi1: VarnodeId,
    low_other: VarnodeId,
    opcode: i32,
) -> Option<(OpId, VarnodeId)> {
    let descendants: Vec<OpId> = data
        .varnode(low_result)
        .descendants
        .iter()
        .copied()
        .collect();
    descendants.into_iter().find_map(|piece| {
        if data.opcode_of(piece) != Some(op::PIECE) || input(data, piece, 1) != Some(low_result) {
            return None;
        }
        let hi_result = input(data, piece, 0)?;
        let hiop = definition(data, hi_result)?;
        if data.opcode_of(hiop) != Some(opcode) || slot_of(data, hiop, hi1).is_none() {
            return None;
        }
        let hi_other = other_input(data, hiop, hi1)?;
        (data.varnode(hi_other).flags.constant == data.varnode(low_other).flags.constant)
            .then_some((hiop, hi_result))
    })
}

/// Match Ghidra's `LogicalForm::applyRule` (`double.cc:1704-1824`).
fn logical_form_apply(
    input_split: &SplitVarnode,
    low_op: OpId,
    workishi: bool,
    data: &mut Funcdata,
) -> bool {
    if workishi || !input_split.has_both_pieces() {
        return false;
    }
    let (Some(hi1), Some(lo1), Some(lo_result)) =
        (input_split.hi, input_split.lo, output(data, low_op))
    else {
        return false;
    };
    let Some(opcode) = data.opcode_of(low_op) else {
        return false;
    };
    if !matches!(opcode, op::INT_AND | op::INT_OR | op::INT_XOR) {
        return false;
    }
    let Some(low_other) = other_input(data, low_op, lo1) else {
        return false;
    };

    let (_hiop, hi_result, hi2, lo2) = if let Some((hiop, hi_result)) =
        high_op_for_low_result(data, lo_result, hi1, low_other, opcode)
    {
        let Some(hi2) = other_input(data, hiop, hi1) else {
            return false;
        };
        (hiop, hi_result, hi2, low_other)
    } else if !data.varnode(low_other).flags.constant {
        let Some(hi2) = companion_high(data, low_other) else {
            return false;
        };
        let descendants: Vec<OpId> = data.varnode(hi2).descendants.iter().copied().collect();
        let Some((hiop, hi_result)) = descendants.into_iter().find_map(|candidate| {
            if data.opcode_of(candidate) != Some(opcode) || slot_of(data, candidate, hi1).is_none()
            {
                return None;
            }
            Some((candidate, output(data, candidate)?))
        }) else {
            return false;
        };
        (hiop, hi_result, hi2, low_other)
    } else {
        let descendants: Vec<OpId> = data.varnode(hi1).descendants.iter().copied().collect();
        let mut candidate = None;
        for hiop in descendants {
            if data.opcode_of(hiop) != Some(opcode)
                || !input(data, hiop, 1).is_some_and(|other| data.varnode(other).flags.constant)
            {
                continue;
            }
            let Some(hi_result) = output(data, hiop) else {
                continue;
            };
            if candidate.is_some() {
                return false;
            }
            candidate = Some((hiop, hi_result));
        }
        let Some((hiop, hi_result)) = candidate else {
            return false;
        };
        let Some(hi2) = other_input(data, hiop, hi1) else {
            return false;
        };
        (hiop, hi_result, hi2, low_other)
    };

    if lo2 == lo1 || lo2 == hi1 || hi2 == hi1 || hi2 == lo1 || lo2 == hi2 {
        return false;
    }
    let mut other = SplitVarnode::from_parts_with_size(data, input_split.size(), lo2, Some(hi2));
    if other.exceeds_const_precision() {
        return false;
    }
    let mut output_split =
        SplitVarnode::from_parts_with_size(data, input_split.size(), lo_result, Some(hi_result));
    let mut known_input = input_split.clone();
    let Some(exist) = prepare_binary(data, &mut output_split, &mut known_input, &mut other) else {
        return false;
    };
    create_binary(
        data,
        &mut output_split,
        &mut known_input,
        &mut other,
        exist,
        opcode,
    )
}

/// Match Ghidra's `Equal3Form::applyRule` (`double.cc:1984-2023`).
fn equal3_form_apply(
    input_split: &SplitVarnode,
    andop: OpId,
    workishi: bool,
    data: &mut Funcdata,
) -> bool {
    if !workishi || !input_split.has_both_pieces() || data.opcode_of(andop) != Some(op::INT_AND) {
        return false;
    }
    let (Some(hi), Some(lo), Some(and_output)) =
        (input_split.hi, input_split.lo, output(data, andop))
    else {
        return false;
    };
    if !((input(data, andop, 0) == Some(hi) && input(data, andop, 1) == Some(lo))
        || (input(data, andop, 0) == Some(lo) && input(data, andop, 1) == Some(hi)))
    {
        return false;
    }
    let Some(compare) = data.lone_descend(and_output) else {
        return false;
    };
    if !matches!(
        data.opcode_of(compare),
        Some(op::INT_EQUAL | op::INT_NOTEQUAL)
    ) {
        return false;
    }
    let Some(small_constant) = input(data, compare, 1) else {
        return false;
    };
    if constant(data, small_constant) != Some(mask_for_size(data.varnode(lo).size)) {
        return false;
    }
    let mut all_ones =
        SplitVarnode::new_constant(input_split.size(), mask_for_size(input_split.size()));
    if all_ones.exceeds_const_precision() {
        return false;
    }
    let mut known_input = input_split.clone();
    replace_bool(
        data,
        compare,
        &mut known_input,
        &mut all_ones,
        data.op(compare).opcode,
    )
}
fn prepare_shift(
    data: &mut Funcdata,
    output_split: &mut SplitVarnode,
    input_split: &mut SplitVarnode,
) -> Option<OpId> {
    let exist = output_exist(data, output_split)?;
    input_split.is_whole_feasible(data, exist).then_some(exist)
}
fn verify_shift_amount(
    data: &Funcdata,
    lo: VarnodeId,
    low_amount: VarnodeId,
    high_amount: VarnodeId,
    middle_amount: VarnodeId,
) -> bool {
    let (Some(low), Some(high), Some(middle)) = (
        constant(data, low_amount),
        constant(data, high_amount),
        constant(data, middle_amount),
    ) else {
        return false;
    };
    let bits = u64::from(data.varnode(lo).size).saturating_mul(8);
    low == high && low < bits && middle == bits.saturating_sub(low)
}

fn shift_left_match(
    data: &Funcdata,
    hi: VarnodeId,
    lo: VarnodeId,
    low_shift: OpId,
) -> Option<(VarnodeId, VarnodeId, VarnodeId)> {
    if data.opcode_of(low_shift) != Some(op::INT_LEFT) {
        return None;
    }
    let low_result = output(data, low_shift)?;
    let descendants: Vec<OpId> = data.varnode(hi).descendants.iter().copied().collect();
    for high_shift in descendants {
        if data.opcode_of(high_shift) != Some(op::INT_LEFT) {
            continue;
        }
        let high_shift_output = output(data, high_shift)?;
        let middle_descendants: Vec<OpId> = data
            .varnode(high_shift_output)
            .descendants
            .iter()
            .copied()
            .collect();
        for middle in middle_descendants {
            let Some(high_result) = output(data, middle) else {
                continue;
            };
            let Some(orop) = definition(data, high_result) else {
                continue;
            };
            if !matches!(
                data.opcode_of(orop),
                Some(op::INT_OR | op::INT_XOR | op::INT_ADD)
            ) {
                continue;
            }
            let (Some(mut middle_low), Some(mut middle_high)) =
                (input(data, orop, 0), input(data, orop, 1))
            else {
                continue;
            };
            if definition(data, middle_high).and_then(|id| data.opcode_of(id)) != Some(op::INT_LEFT)
            {
                std::mem::swap(&mut middle_low, &mut middle_high);
            }
            let Some(middle_shift) = definition(data, middle_low) else {
                continue;
            };
            let Some(high_shift_again) = definition(data, middle_high) else {
                continue;
            };
            if data.opcode_of(middle_shift) != Some(op::INT_RIGHT)
                || data.opcode_of(high_shift_again) != Some(op::INT_LEFT)
                || input(data, high_shift_again, 0) != Some(hi)
                || input(data, middle_shift, 0) != Some(lo)
                || input(data, low_shift, 0) != Some(lo)
            {
                continue;
            }
            let (Some(low_amount), Some(high_amount), Some(middle_amount)) = (
                input(data, low_shift, 1),
                input(data, high_shift_again, 1),
                input(data, middle_shift, 1),
            ) else {
                continue;
            };
            if !verify_shift_amount(data, lo, low_amount, high_amount, middle_amount) {
                continue;
            }
            return Some((low_result, high_result, low_amount));
        }
    }
    None
}

fn shift_right_match(
    data: &Funcdata,
    hi: VarnodeId,
    lo: VarnodeId,
    high_shift: OpId,
) -> Option<(VarnodeId, VarnodeId, VarnodeId, i32)> {
    let high_opcode = data.opcode_of(high_shift)?;
    if !matches!(high_opcode, op::INT_RIGHT | op::INT_SRIGHT) {
        return None;
    }
    let high_result = output(data, high_shift)?;
    let descendants: Vec<OpId> = data.varnode(lo).descendants.iter().copied().collect();
    for low_shift in descendants {
        if data.opcode_of(low_shift) != Some(op::INT_RIGHT) {
            continue;
        }
        let low_shift_output = output(data, low_shift)?;
        let middle_descendants: Vec<OpId> = data
            .varnode(low_shift_output)
            .descendants
            .iter()
            .copied()
            .collect();
        for middle in middle_descendants {
            let Some(low_result) = output(data, middle) else {
                continue;
            };
            let Some(orop) = definition(data, low_result) else {
                continue;
            };
            if !matches!(
                data.opcode_of(orop),
                Some(op::INT_OR | op::INT_XOR | op::INT_ADD)
            ) {
                continue;
            }
            let (Some(mut middle_low), Some(mut middle_high)) =
                (input(data, orop, 0), input(data, orop, 1))
            else {
                continue;
            };
            if definition(data, middle_low).and_then(|id| data.opcode_of(id)) != Some(op::INT_RIGHT)
            {
                std::mem::swap(&mut middle_low, &mut middle_high);
            }
            let Some(middle_shift) = definition(data, middle_high) else {
                continue;
            };
            let Some(low_shift_again) = definition(data, middle_low) else {
                continue;
            };
            if data.opcode_of(middle_shift) != Some(op::INT_LEFT)
                || data.opcode_of(low_shift_again) != Some(op::INT_RIGHT)
                || input(data, low_shift_again, 0) != Some(lo)
                || input(data, middle_shift, 0) != Some(hi)
                || input(data, high_shift, 0) != Some(hi)
            {
                continue;
            }
            let (Some(low_amount), Some(high_amount), Some(middle_amount)) = (
                input(data, low_shift_again, 1),
                input(data, high_shift, 1),
                input(data, middle_shift, 1),
            ) else {
                continue;
            };
            if !verify_shift_amount(data, lo, low_amount, high_amount, middle_amount) {
                continue;
            }
            return Some((low_result, high_result, low_amount, high_opcode));
        }
    }
    None
}

/// Match Ghidra's `ShiftForm::applyRuleLeft/Right` (`double.cc:2550-2733`).
fn shift_form_apply(
    input_split: &SplitVarnode,
    workop: OpId,
    workishi: bool,
    left: bool,
    data: &mut Funcdata,
) -> bool {
    if !input_split.has_both_pieces() || (left == workishi) {
        return false;
    }
    let (Some(hi), Some(lo)) = (input_split.hi, input_split.lo) else {
        return false;
    };
    let (reslo, reshi, shift, opcode) = if left {
        let Some((reslo, reshi, shift)) = shift_left_match(data, hi, lo, workop) else {
            return false;
        };
        (reslo, reshi, shift, op::INT_LEFT)
    } else {
        let Some((reslo, reshi, shift, opcode)) = shift_right_match(data, hi, lo, workop) else {
            return false;
        };
        (reslo, reshi, shift, opcode)
    };
    let mut output_split =
        SplitVarnode::from_parts_with_size(data, input_split.size(), reslo, Some(reshi));
    let mut known_input = input_split.clone();
    let Some(exist) = prepare_shift(data, &mut output_split, &mut known_input) else {
        return false;
    };
    create_shift(
        data,
        &mut output_split,
        &mut known_input,
        shift,
        exist,
        opcode,
    )
}

/// Collapse `PIECE(load(high), load(low))` into one wider LOAD.
pub struct RuleDoubleLoad;
#[derive(Copy, Clone)]
struct MultShape {
    reshi: VarnodeId,
    subhi: OpId,
    multhi1: OpId,
    multhi2: Option<OpId>,
    midtmp: VarnodeId,
    lo1zext: VarnodeId,
    lo2zext: VarnodeId,
}

fn map_res_hi_small_const(data: &Funcdata, rhi: VarnodeId) -> Option<MultShape> {
    let add1 = definition(data, rhi)?;
    if data.opcode_of(add1) != Some(op::INT_ADD) {
        return None;
    }
    let (ad1, ad2) = (input(data, add1, 0)?, input(data, add1, 1)?);
    if !is_written(data, ad1) || !is_written(data, ad2) {
        return None;
    }
    let ad1_def = definition(data, ad1)?;
    let ad2_def = definition(data, ad2)?;
    let (multhi1, subhi) = if data.opcode_of(ad1_def) == Some(op::INT_MULT)
        && data.opcode_of(ad2_def) == Some(op::SUBPIECE)
    {
        (ad1_def, ad2_def)
    } else if data.opcode_of(ad2_def) == Some(op::INT_MULT)
        && data.opcode_of(ad1_def) == Some(op::SUBPIECE)
    {
        (ad2_def, ad1_def)
    } else {
        return None;
    };
    let midtmp = input(data, subhi, 0)?;
    let multlo = definition(data, midtmp)?;
    if data.opcode_of(multlo) != Some(op::INT_MULT) {
        return None;
    }
    Some(MultShape {
        reshi: rhi,
        subhi,
        multhi1,
        multhi2: None,
        midtmp,
        lo1zext: input(data, multlo, 0)?,
        lo2zext: input(data, multlo, 1)?,
    })
}

fn map_res_hi(data: &Funcdata, rhi: VarnodeId) -> Option<MultShape> {
    let add1 = definition(data, rhi)?;
    if data.opcode_of(add1) != Some(op::INT_ADD) {
        return None;
    }
    let (first, second) = (input(data, add1, 0)?, input(data, add1, 1)?);
    let first_def = definition(data, first)?;
    let second_def = definition(data, second)?;
    let (add2, ad1, ad2) = if data.opcode_of(first_def) == Some(op::INT_ADD) {
        (
            first_def,
            input(data, first_def, 0)?,
            input(data, first_def, 1)?,
        )
    } else {
        let add2 = second_def;
        if data.opcode_of(add2) != Some(op::INT_ADD) {
            return None;
        }
        (add2, input(data, add2, 0)?, input(data, add2, 1)?)
    };
    let ad3 = if add2 == first_def { second } else { first };
    if ![ad1, ad2, ad3].iter().all(|value| is_written(data, *value)) {
        return None;
    }
    let defs = [
        (ad1, definition(data, ad1)?),
        (ad2, definition(data, ad2)?),
        (ad3, definition(data, ad3)?),
    ];
    let Some((subhi_index, (_, subhi))) = defs
        .iter()
        .enumerate()
        .find(|(_, (_, id))| data.opcode_of(*id) == Some(op::SUBPIECE))
    else {
        return None;
    };
    let subhi = *subhi;
    let mut multiplies = defs
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != subhi_index)
        .map(|(_, (_, id))| *id);
    let multhi1 = multiplies.next()?;
    let multhi2 = multiplies.next()?;
    if data.opcode_of(multhi1) != Some(op::INT_MULT)
        || data.opcode_of(multhi2) != Some(op::INT_MULT)
    {
        return None;
    }
    let midtmp = input(data, subhi, 0)?;
    let multlo = definition(data, midtmp)?;
    if data.opcode_of(multlo) != Some(op::INT_MULT) {
        return None;
    }
    Some(MultShape {
        reshi: rhi,
        subhi,
        multhi1,
        multhi2: Some(multhi2),
        midtmp,
        lo1zext: input(data, multlo, 0)?,
        lo2zext: input(data, multlo, 1)?,
    })
}

fn find_lo_from_in(
    data: &Funcdata,
    shape: &mut MultShape,
    hi1: VarnodeId,
    lo1: VarnodeId,
) -> Option<(VarnodeId, Option<VarnodeId>)> {
    let mut first = input(data, shape.multhi1, 0)?;
    let mut second = input(data, shape.multhi1, 1)?;
    if first != lo1 && second != lo1 {
        let old_first = shape.multhi1;
        let old_second = shape.multhi2.replace(old_first)?;
        shape.multhi1 = old_second;
        first = input(data, shape.multhi1, 0)?;
        second = input(data, shape.multhi1, 1)?;
    }
    let hi2 = if first == lo1 {
        second
    } else if second == lo1 {
        first
    } else {
        return None;
    };
    let multhi2 = shape.multhi2?;
    let first = input(data, multhi2, 0)?;
    let second = input(data, multhi2, 1)?;
    let lo2 = if first == hi1 {
        second
    } else if second == hi1 {
        first
    } else {
        return None;
    };
    Some((lo2, Some(hi2)))
}

fn find_lo_from_small_const(
    data: &Funcdata,
    shape: &MultShape,
    hi1: VarnodeId,
) -> Option<(VarnodeId, Option<VarnodeId>)> {
    let first = input(data, shape.multhi1, 0)?;
    let second = input(data, shape.multhi1, 1)?;
    let lo2 = if first == hi1 {
        second
    } else if second == hi1 {
        first
    } else {
        return None;
    };
    constant(data, lo2).map(|_| (lo2, None))
}

fn zext_of(data: &Funcdata, big: VarnodeId, small: VarnodeId) -> bool {
    if let Some(small_value) = constant(data, small) {
        return constant(data, big) == Some(small_value);
    }
    let Some(def) = definition(data, big) else {
        return false;
    };
    if data.opcode_of(def) == Some(op::INT_ZEXT) {
        return input(data, def, 0) == Some(small);
    }
    if data.opcode_of(def) != Some(op::INT_AND) {
        return false;
    }
    let Some(mask) = input(data, def, 1).and_then(|value| constant(data, value)) else {
        return false;
    };
    if mask != mask_for_size(data.varnode(small).size) {
        return false;
    }
    let Some(small_def) = definition(data, small) else {
        return false;
    };
    data.opcode_of(small_def) == Some(op::SUBPIECE)
        && input(data, small_def, 0).is_some_and(|whole| input(data, def, 0) == Some(whole))
}

fn verify_mult_lo(data: &Funcdata, shape: &MultShape, lo1: VarnodeId, lo2: VarnodeId) -> bool {
    let Some(offset) = input(data, shape.subhi, 1).and_then(|value| constant(data, value)) else {
        return false;
    };
    if offset != u64::from(data.varnode(lo1).size) {
        return false;
    }
    (zext_of(data, shape.lo1zext, lo1) && zext_of(data, shape.lo2zext, lo2))
        || (zext_of(data, shape.lo1zext, lo2) && zext_of(data, shape.lo2zext, lo1))
}

fn find_res_lo(
    data: &Funcdata,
    shape: &MultShape,
    lo1: VarnodeId,
    lo2: VarnodeId,
) -> Option<VarnodeId> {
    let descendants: Vec<OpId> = data
        .varnode(shape.midtmp)
        .descendants
        .iter()
        .copied()
        .collect();
    for id in descendants {
        if data.opcode_of(id) != Some(op::SUBPIECE)
            || constant(data, input(data, id, 1)?) != Some(0)
        {
            continue;
        }
        let result = output(data, id)?;
        if data.varnode(result).size == data.varnode(lo1).size {
            return Some(result);
        }
    }
    let descendants: Vec<OpId> = data.varnode(lo1).descendants.iter().copied().collect();
    for id in descendants {
        if data.opcode_of(id) != Some(op::INT_MULT) {
            continue;
        }
        let first = input(data, id, 0)?;
        let second = input(data, id, 1)?;
        let matches = if let Some(value) = constant(data, lo2) {
            constant(data, first) == Some(value) || constant(data, second) == Some(value)
        } else {
            first == lo2 || second == lo2
        };
        if matches {
            return output(data, id);
        }
    }
    None
}

fn map_mult_from_in(
    data: &Funcdata,
    rhi: VarnodeId,
    hi1: VarnodeId,
    lo1: VarnodeId,
) -> Option<(VarnodeId, VarnodeId, VarnodeId, Option<VarnodeId>)> {
    let mut shape = map_res_hi(data, rhi)?;
    let (lo2, hi2) = find_lo_from_in(data, &mut shape, hi1, lo1)?;
    if !verify_mult_lo(data, &shape, lo1, lo2) {
        return None;
    }
    let reslo = find_res_lo(data, &shape, lo1, lo2)?;
    Some((reslo, shape.reshi, lo2, hi2))
}

fn map_mult_from_small_const(
    data: &Funcdata,
    rhi: VarnodeId,
    hi1: VarnodeId,
    lo1: VarnodeId,
) -> Option<(VarnodeId, VarnodeId, VarnodeId, Option<VarnodeId>)> {
    let shape = map_res_hi_small_const(data, rhi)?;
    let (lo2, hi2) = find_lo_from_small_const(data, &shape, hi1)?;
    if !verify_mult_lo(data, &shape, lo1, lo2) {
        return None;
    }
    let reslo = find_res_lo(data, &shape, lo1, lo2)?;
    Some((reslo, shape.reshi, lo2, hi2))
}

/// Match Ghidra's `MultForm::applyRule` (`double.cc:2735-3023`).
fn mult_form_apply(
    input_split: &SplitVarnode,
    workop: OpId,
    workishi: bool,
    data: &mut Funcdata,
) -> bool {
    if !workishi || !input_split.has_both_pieces() {
        return false;
    }
    let (Some(hi1), Some(lo1), Some(work_output)) =
        (input_split.hi, input_split.lo, output(data, workop))
    else {
        return false;
    };
    let descendants: Vec<OpId> = data
        .varnode(work_output)
        .descendants
        .iter()
        .copied()
        .collect();
    let mut matched = None;
    for add1 in descendants {
        if data.opcode_of(add1) != Some(op::INT_ADD) {
            continue;
        }
        let nested: Vec<OpId> = output(data, add1)
            .into_iter()
            .flat_map(|value| data.varnode(value).descendants.iter().copied())
            .collect();
        for add2 in nested {
            if data.opcode_of(add2) != Some(op::INT_ADD) {
                continue;
            }
            if let Some(candidate) =
                output(data, add2).and_then(|rhi| map_mult_from_in(data, rhi, hi1, lo1))
            {
                matched = Some(candidate);
                break;
            }
        }
        if matched.is_some() {
            break;
        }
        if let Some(rhi) = output(data, add1) {
            matched = map_mult_from_in(data, rhi, hi1, lo1)
                .or_else(|| map_mult_from_small_const(data, rhi, hi1, lo1));
        }
        if matched.is_some() {
            break;
        }
    }
    let Some((reslo, reshi, lo2, hi2)) = matched else {
        return false;
    };
    let mut other = SplitVarnode::from_parts_with_size(data, input_split.size(), lo2, hi2);
    if other.exceeds_const_precision() {
        return false;
    }
    let mut output_split =
        SplitVarnode::from_parts_with_size(data, input_split.size(), reslo, Some(reshi));
    let mut known_input = input_split.clone();
    let Some(exist) = prepare_binary(data, &mut output_split, &mut known_input, &mut other) else {
        return false;
    };
    create_binary(
        data,
        &mut output_split,
        &mut known_input,
        &mut other,
        exist,
        op::INT_MULT,
    )
}
/// Mark and collapse the two-piece input form registered by Ghidra as
/// `RuleDoubleIn` (`double.cc:3198-3278`).
pub struct RuleDoubleIn;

impl RuleDoubleIn {
    fn attempt_marking(&self, data: &mut Funcdata, piece: VarnodeId, subpiece: OpId) -> usize {
        let Some(whole) = input(data, subpiece, 0) else {
            return 0;
        };
        let Some(offset) = input(data, subpiece, 1).and_then(|value| constant(data, value)) else {
            return 0;
        };
        let piece_size = data.varnode(piece).size;
        if offset != u64::from(piece_size)
            || piece_size.saturating_mul(2) != data.varnode(whole).size
        {
            return 0;
        }
        if data.varnode(whole).flags.input {
            // `Varnode::isTypeLock` is not represented; an entry value is
            // the only whole-value seed the graph can provide.
        } else {
            let Some(def) = definition(data, whole) else {
                return 0;
            };
            if !is_arithmetic_or_float_opcode(data.op(def).opcode) {
                return 0;
            }
        }
        let descendants: Vec<OpId> = data.varnode(whole).descendants.iter().copied().collect();
        let Some(low) = descendants.into_iter().find_map(|id| {
            if data.opcode_of(id) != Some(op::SUBPIECE)
                || constant(data, input(data, id, 1)?) != Some(0)
            {
                return None;
            }
            let low = output(data, id)?;
            (data.varnode(low).size == piece_size).then_some(low)
        }) else {
            return 0;
        };
        set_precision(data, low, Precision::Lo);
        set_precision(data, piece, Precision::Hi);
        1
    }
}

impl Rule for RuleDoubleIn {
    fn name(&self) -> &'static str {
        "doublein"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::SUBPIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        if data.opcode_of(id) != Some(op::SUBPIECE) {
            return 0;
        }
        let Some(piece) = output(data, id) else {
            return 0;
        };
        if !precision_marked(data, piece, Precision::Lo) {
            if precision_marked(data, piece, Precision::Hi) {
                return 0;
            }
            return self.attempt_marking(data, piece, id);
        }
        // `if (data.hasUnreachableBlocks()) return 0;` - an unreachable block's
        // data flow is not trustworthy evidence about how a value is pieced
        // together, so the rewrite waits until such a block is gone.
        if data.has_unreachable_blocks() {
            return 0;
        }
        let Some(whole) = input(data, id, 0) else {
            return 0;
        };
        let mut candidates = SplitVarnode::whole_list(data, whole);
        for candidate in &mut candidates {
            if candidate.apply_rule_in(data) != 0 {
                return 1;
            }
        }
        0
    }
}

/// Mark and combine contiguous input pieces registered by Ghidra as
/// `RuleDoubleOut` (`double.cc:3281-3355`).
pub struct RuleDoubleOut;

impl RuleDoubleOut {
    fn attempt_marking(
        &self,
        data: &mut Funcdata,
        high: VarnodeId,
        low: VarnodeId,
        piece_op: OpId,
    ) -> usize {
        let Some(whole) = output(data, piece_op) else {
            return 0;
        };
        if data.varnode(high).size != data.varnode(low).size {
            return 0;
        }
        let descendants: Vec<OpId> = data.varnode(whole).descendants.iter().copied().collect();
        if !descendants.into_iter().any(|id| {
            data.opcode_of(id)
                .is_some_and(is_arithmetic_or_float_opcode)
        }) {
            return 0;
        }
        set_precision(data, high, Precision::Hi);
        set_precision(data, low, Precision::Lo);
        1
    }
}

/// Combine contiguous persistent input pieces into one input Varnode.
///
/// This ports `Funcdata::combineInputVarnodes` (`funcdata_varnode.cc:387-466`).
/// The graph has no Varnode-destruction operation, so the old records remain
/// as unreachable identities after every reader is redirected; replacement
/// SUBPIECEs retain each old machine location while the operation and
/// descendant links follow the C++ rewrite.
fn combine_input_pieces(
    data: &mut Funcdata,
    high: VarnodeId,
    low: VarnodeId,
    _piece_op: OpId,
) -> bool {
    if !data.is_addr_tied(high) || !data.is_addr_tied(low) {
        return false;
    }
    let (high_space, high_offset, high_size) = {
        let value = data.varnode(high);
        (value.space, value.offset, value.size)
    };
    let (low_space, low_offset, low_size) = {
        let value = data.varnode(low);
        (value.space, value.offset, value.size)
    };
    if high_space != low_space {
        return false;
    }
    let base = if data.big_endian {
        if high_offset.checked_add(u64::from(high_size)) != Some(low_offset) {
            return false;
        }
        high_offset
    } else {
        if low_offset.checked_add(u64::from(low_size)) != Some(high_offset) {
            return false;
        }
        low_offset
    };
    let wide = data.set_input_varnode(high_space, base, high_size.saturating_add(low_size));

    let high_users: Vec<OpId> = data.varnode(high).descendants.iter().copied().collect();
    let low_users: Vec<OpId> = data.varnode(low).descendants.iter().copied().collect();
    for user in high_users.into_iter().chain(low_users) {
        if data.opcode_of(user) == Some(op::PIECE)
            && input(data, user, 0) == Some(high)
            && input(data, user, 1) == Some(low)
        {
            data.op_set_opcode(user, op::COPY);
            data.op_set_inputs(user, vec![wide]);
        }
    }

    let first_block = data.blocks().next().map(|(id, _)| id);
    let first_seq = first_block
        .and_then(|block| data.block(block).ops.first().copied())
        .map(|id| data.op(id).seq)
        .unwrap_or(SeqNum {
            address: data.entry,
            order: 0,
        });
    for (old, offset) in [(high, low_size), (low, 0)] {
        if data.varnode(old).descendants.is_empty() {
            continue;
        }
        let has_other_user = data.varnode(old).descendants.iter().copied().any(|user| {
            !(data.opcode_of(user) == Some(op::PIECE)
                && input(data, user, 0) == Some(high)
                && input(data, user, 1) == Some(low))
        });
        if !has_other_user {
            continue;
        }
        let Some(block) = first_block else {
            return false;
        };
        let offset_value = data.new_constant(u64::from(offset), 4);
        let subpiece = data.new_op(op::SUBPIECE, first_seq, vec![wide, offset_value]);
        let old_value = data.varnode(old);
        let replacement = data.new_varnode(old_value.space, old_value.offset, old_value.size);
        data.op_set_output(subpiece, Some(replacement));
        data.op_insert_front(subpiece, block);
        data.total_replace(old, replacement);
    }
    true
}

impl Rule for RuleDoubleOut {
    fn name(&self) -> &'static str {
        "doubleout"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::PIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        if data.opcode_of(id) != Some(op::PIECE) {
            return 0;
        }
        let (Some(high), Some(low)) = (input(data, id, 0), input(data, id, 1)) else {
            return 0;
        };
        // The graph has no separate `Varnode::isPersist` bit.  Input values
        // are the persistent locations represented by this port.
        if !data.varnode(high).flags.input || !data.varnode(low).flags.input {
            return 0;
        }
        if !precision_marked(data, high, Precision::Hi)
            || !precision_marked(data, low, Precision::Lo)
        {
            return self.attempt_marking(data, high, low, id);
        }
        combine_input_pieces(data, high, low, id)
            .then_some(1)
            .unwrap_or(0)
    }
}

impl Rule for RuleDoubleLoad {
    fn name(&self) -> &'static str {
        "doubleload"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::PIECE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        if data.opcode_of(id) != Some(op::PIECE) {
            return 0;
        }
        let (Some(hi), Some(lo)) = (input(data, id, 0), input(data, id, 1)) else {
            return 0;
        };
        let Some(piece_out) = output(data, id) else {
            return 0;
        };
        if data.varnode(piece_out).size
            != data.varnode(lo).size.saturating_add(data.varnode(hi).size)
        {
            return 0;
        }
        let Some(load_hi) = direct_load(data, hi) else {
            return 0;
        };
        let Some(load_lo) = direct_load(data, lo) else {
            return 0;
        };
        if load_hi == load_lo {
            return 0;
        }
        let (Some(space_hi), Some(space_lo), Some(ptr_hi), Some(ptr_lo)) = (
            memory_space(data, load_hi),
            memory_space(data, load_lo),
            input(data, load_hi, 1),
            input(data, load_lo, 1),
        ) else {
            return 0;
        };
        if space_hi != space_lo || !adjacent_pointers(data, ptr_lo, ptr_hi, data.varnode(lo).size) {
            return 0;
        }
        let mut split = SplitVarnode::from_parts(data, lo, Some(hi));
        if !split.find_definition_point(data) {
            return 0;
        }
        let mut indirects = Vec::new();
        let Some(latest) = no_write_conflict(data, load_lo, load_hi, space_lo, &mut indirects)
        else {
            return 0;
        };
        let size = split.size();
        let seq = data.op(latest).seq;
        let new_load = data.new_op(op::LOAD, seq, vec![data.op(load_lo).inputs[0], ptr_lo]);
        let whole = data.new_unique(size);
        data.op_set_output(new_load, Some(whole));
        data.op_insert_after(new_load, latest);

        data.op_set_opcode(id, op::COPY);
        data.op_set_inputs(id, vec![whole]);
        1
    }
}

/// Collapse `STORE(ptr, SUBPIECE(whole,0))` and the adjacent high STORE.
pub struct RuleDoubleStore;

impl Rule for RuleDoubleStore {
    fn name(&self) -> &'static str {
        "doublestore"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::STORE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        if data.opcode_of(id) != Some(op::STORE) {
            return 0;
        }
        let (Some(low_value), Some(low_ptr), Some(low_space)) = (
            input(data, id, 2),
            input(data, id, 1),
            memory_space(data, id),
        ) else {
            return 0;
        };
        // `if (!vnlo->isPrecisLo()) return 0;`. The marks exist now, set by
        // `RuleDoubleIn`/`RuleDoubleOut`'s `attemptMarking`, so the discovery no
        // longer has to be purely structural: a pair Ghidra has not recognised
        // as a double-precision whole is not one here either.
        if !precision_marked(data, low_value, Precision::Lo) {
            return 0;
        }
        let Some(low_def) = definition(data, low_value) else {
            return 0;
        };
        let Some(low_offset) = input(data, low_def, 1).and_then(|value| constant(data, value))
        else {
            return 0;
        };
        if data.opcode_of(low_def) != Some(op::SUBPIECE) || low_offset != 0 {
            return 0;
        }
        let Some(whole) = input(data, low_def, 0) else {
            return 0;
        };
        if !data.varnode(whole).flags.input && !is_written(data, whole) {
            return 0;
        }
        let low_size = data.varnode(low_value).size;
        let descendants: Vec<OpId> = data.varnode(whole).descendants.iter().copied().collect();
        for high_def in descendants {
            if data.opcode_of(high_def) != Some(op::SUBPIECE) || high_def == low_def {
                continue;
            }
            let Some(high_offset) =
                input(data, high_def, 1).and_then(|value| constant(data, value))
            else {
                continue;
            };
            if input(data, high_def, 0) != Some(whole) || high_offset != u64::from(low_size) {
                continue;
            }
            let Some(high_value) = output(data, high_def) else {
                continue;
            };
            // `if (!vnhi->isPrecisHi()) continue;`
            if !precision_marked(data, high_value, Precision::Hi) {
                continue;
            }
            if data.varnode(high_value).size + low_size != data.varnode(whole).size {
                continue;
            }
            let mut split = SplitVarnode::from_parts_with_size(
                data,
                low_size + data.varnode(high_value).size,
                low_value,
                Some(high_value),
            );
            if !split.find_whole(data) || split.whole() != Some(whole) {
                continue;
            }
            let high_stores: Vec<OpId> = data
                .varnode(high_value)
                .descendants
                .iter()
                .copied()
                .collect();
            for high_store in high_stores {
                if data.opcode_of(high_store) != Some(op::STORE)
                    || input(data, high_store, 2) != Some(high_value)
                {
                    continue;
                }
                let Some(high_space) = memory_space(data, high_store) else {
                    continue;
                };
                let Some(high_ptr) = input(data, high_store, 1) else {
                    continue;
                };
                if high_space != low_space || !adjacent_pointers(data, low_ptr, high_ptr, low_size)
                {
                    continue;
                }
                let mut indirects = Vec::new();
                let Some(latest) =
                    no_write_conflict(data, id, high_store, low_space, &mut indirects)
                else {
                    continue;
                };
                // `testIndirectUse`: a guard whose output something between the
                // two stores still reads cannot be relocated.
                if !test_indirect_use(data, id, high_store, &indirects) {
                    continue;
                }
                let seq = data.op(latest).seq;
                let new_store =
                    data.new_op(op::STORE, seq, vec![data.op(id).inputs[0], low_ptr, whole]);
                data.op_insert_after(new_store, latest);
                data.op_destroy(id);
                data.op_destroy(high_store);
                // The guards annotated the two stores that are now gone; they
                // belong to the combined store.
                reassign_indirects(data, new_store, &indirects);
                return 1;
            }
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{RAM_SPACE, REGISTER_SPACE};

    #[test]
    fn all_registers_only_rules_with_graph_rewrites() {
        let rules = all();
        assert!(rules.iter().any(|rule| rule.name() == "doubleload"));
        assert!(rules.iter().any(|rule| rule.name() == "doublestore"));
        assert!(rules.iter().any(|rule| rule.name() == "doublein"));
        assert!(rules.iter().any(|rule| rule.name() == "doubleout"));
        assert!(rules.iter().all(|rule| !rule.op_list().is_empty()));
    }

    #[test]
    fn double_out_combines_contiguous_input_pieces() {
        let (mut data, block) = graph();
        let low = input_value(&mut data, 0x1000, 4);
        let high = input_value(&mut data, 0x1004, 4);
        let (piece, whole) = add_op(&mut data, block, 0, op::PIECE, vec![high, low], Some(8));
        let piece_output = whole.expect("piece output");
        let one = data.new_constant(1, 8);
        let (consumer, _) = add_op(
            &mut data,
            block,
            1,
            op::INT_ADD,
            vec![piece_output, one],
            Some(8),
        );

        let rule = RuleDoubleOut;
        assert_eq!(rule.apply_op(piece, &mut data), 1);
        assert_eq!(rule.apply_op(piece, &mut data), 1);
        assert_eq!(data.opcode_of(piece), Some(op::COPY));
        let combined = data.op(piece).inputs[0];
        assert_eq!(data.varnode(combined).size, 8);
        assert_eq!(data.varnode(combined).offset, 0x1000);
        assert_eq!(
            data.op(consumer).inputs[0],
            data.op(piece).output.expect("piece output")
        );
    }

    fn graph() -> (Funcdata, GraphBlockId) {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        (data, block)
    }

    fn seq(order: u32) -> SeqNum {
        SeqNum {
            address: 0x1000 + u64::from(order),
            order,
        }
    }

    fn add_op(
        data: &mut Funcdata,
        block: GraphBlockId,
        order: u32,
        opcode: i32,
        inputs: Vec<VarnodeId>,
        output_size: Option<u32>,
    ) -> (OpId, Option<VarnodeId>) {
        let id = data.new_op(opcode, seq(order), inputs);
        let output = output_size.map(|size| data.new_unique(size));
        data.op_set_output(id, output);
        data.op_insert_end(id, block);
        (id, output)
    }

    fn memory_space(data: &mut Funcdata) -> VarnodeId {
        data.new_constant(u64::from(RAM_SPACE), 4)
    }

    fn input_pointer(data: &mut Funcdata, offset: u64) -> VarnodeId {
        let ptr = data.new_varnode(REGISTER_SPACE, offset, 8);
        data.mark_input(ptr);
        ptr
    }

    fn input_value(data: &mut Funcdata, offset: u64, size: u32) -> VarnodeId {
        let value = data.new_varnode(REGISTER_SPACE, offset, size);
        data.mark_input(value);
        value
    }

    fn add_pointer(
        data: &mut Funcdata,
        block: GraphBlockId,
        order: u32,
        base: VarnodeId,
        offset: u64,
    ) -> VarnodeId {
        let amount = data.new_constant(offset, 8);
        let (_, output) = add_op(data, block, order, op::INT_ADD, vec![base, amount], Some(8));
        output.expect("pointer add has an output")
    }

    fn load(
        data: &mut Funcdata,
        block: GraphBlockId,
        order: u32,
        space: VarnodeId,
        ptr: VarnodeId,
    ) -> (OpId, VarnodeId) {
        let (id, output) = add_op(data, block, order, op::LOAD, vec![space, ptr], Some(4));
        (id, output.expect("load has an output"))
    }

    #[test]
    fn split_varnode_finds_pair_whole_and_bit_width() {
        let (mut data, block) = graph();
        let whole = input_pointer(&mut data, 0x20);
        let zero = data.new_constant(0, 4);
        let four = data.new_constant(4, 4);
        let (_, lo) = add_op(
            &mut data,
            block,
            0,
            op::SUBPIECE,
            vec![whole, zero],
            Some(4),
        );
        let (_, hi) = add_op(
            &mut data,
            block,
            1,
            op::SUBPIECE,
            vec![whole, four],
            Some(4),
        );
        let lo = lo.expect("low piece");
        let hi = hi.expect("high piece");
        let mut split = SplitVarnode::from_parts(&data, lo, Some(hi));
        assert!(split.find_whole(&data));
        assert_eq!(split.whole(), Some(whole));

        assert_eq!(split.lo(), Some(lo));
        assert_eq!(split.hi(), Some(hi));
        assert_eq!(split.bit_width(), 64);
        let (piece, _) = add_op(&mut data, block, 2, op::PIECE, vec![hi, lo], Some(8));
        assert!(split.is_whole_feasible(&data, piece));
    }

    #[test]
    fn double_in_add_form_collapses_two_pieces() {
        let (mut data, block) = graph();
        let whole = input_pointer(&mut data, 0x400);
        let zero = data.new_constant(0, 4);
        let four = data.new_constant(4, 4);
        let (low_op, low) = add_op(
            &mut data,
            block,
            0,
            op::SUBPIECE,
            vec![whole, zero],
            Some(4),
        );
        let (high_op, high) = add_op(
            &mut data,
            block,
            1,
            op::SUBPIECE,
            vec![whole, four],
            Some(4),
        );
        let low = low.expect("low piece");
        let high = high.expect("high piece");
        let other = input_value(&mut data, 0x500, 4);
        let (_, low_result) = add_op(&mut data, block, 2, op::INT_ADD, vec![low, other], Some(4));
        let (carry_op, carry) = add_op(
            &mut data,
            block,
            3,
            op::INT_CARRY,
            vec![low, other],
            Some(1),
        );
        let (_, carry_wide) = add_op(
            &mut data,
            block,
            4,
            op::INT_ZEXT,
            vec![carry.expect("carry")],
            Some(4),
        );
        let (_, high_result) = add_op(
            &mut data,
            block,
            5,
            op::INT_ADD,
            vec![high, carry_wide.expect("wide carry")],
            Some(4),
        );
        let (piece, _) = add_op(
            &mut data,
            block,
            6,
            op::PIECE,
            vec![
                high_result.expect("high result"),
                low_result.expect("low result"),
            ],
            Some(8),
        );

        let rule = RuleDoubleIn;
        assert_eq!(rule.apply_op(high_op, &mut data), 1);
        assert_eq!(rule.apply_op(low_op, &mut data), 1);
        assert_eq!(data.opcode_of(piece), Some(op::INT_ADD));
        assert_eq!(data.op(piece).inputs[0], whole);
        assert_eq!(data.opcode_of(carry_op), Some(op::INT_CARRY));
    }

    #[test]
    fn double_in_logical_form_collapses_and_pieces() {
        let (mut data, block) = graph();
        let first_whole = input_pointer(&mut data, 0x600);
        let second_whole = input_pointer(&mut data, 0x700);
        let zero = data.new_constant(0, 4);
        let four = data.new_constant(4, 4);
        let (low1_op, low1) = add_op(
            &mut data,
            block,
            0,
            op::SUBPIECE,
            vec![first_whole, zero],
            Some(4),
        );
        let (high1_op, high1) = add_op(
            &mut data,
            block,
            1,
            op::SUBPIECE,
            vec![first_whole, four],
            Some(4),
        );
        let (_, low2) = add_op(
            &mut data,
            block,
            2,
            op::SUBPIECE,
            vec![second_whole, zero],
            Some(4),
        );
        let (_, high2) = add_op(
            &mut data,
            block,
            3,
            op::SUBPIECE,
            vec![second_whole, four],
            Some(4),
        );
        let low1 = low1.expect("first low piece");
        let high1 = high1.expect("first high piece");
        let low2 = low2.expect("second low piece");
        let high2 = high2.expect("second high piece");
        let (_, low_result) = add_op(&mut data, block, 4, op::INT_AND, vec![low1, low2], Some(4));
        let (_, high_result) = add_op(
            &mut data,
            block,
            5,
            op::INT_AND,
            vec![high1, high2],
            Some(4),
        );
        let (piece, _) = add_op(
            &mut data,
            block,
            6,
            op::PIECE,
            vec![
                high_result.expect("high logical result"),
                low_result.expect("low logical result"),
            ],
            Some(8),
        );

        let rule = RuleDoubleIn;
        assert_eq!(rule.apply_op(high1_op, &mut data), 1);
        assert_eq!(rule.apply_op(low1_op, &mut data), 1);
        assert_eq!(data.opcode_of(piece), Some(op::INT_AND));
        assert_eq!(data.op(piece).inputs[0], first_whole);
    }

    #[test]
    fn double_in_logical_or_form_collapses_two_pieces() {
        let (mut data, block) = graph();
        let first_whole = input_pointer(&mut data, 0x680);
        let second_whole = input_pointer(&mut data, 0x780);
        let zero = data.new_constant(0, 4);
        let four = data.new_constant(4, 4);
        let (low1_op, low1) = add_op(
            &mut data,
            block,
            0,
            op::SUBPIECE,
            vec![first_whole, zero],
            Some(4),
        );
        let (high1_op, high1) = add_op(
            &mut data,
            block,
            1,
            op::SUBPIECE,
            vec![first_whole, four],
            Some(4),
        );
        let (_, low2) = add_op(
            &mut data,
            block,
            2,
            op::SUBPIECE,
            vec![second_whole, zero],
            Some(4),
        );
        let (_, high2) = add_op(
            &mut data,
            block,
            3,
            op::SUBPIECE,
            vec![second_whole, four],
            Some(4),
        );
        let low1 = low1.expect("first low piece");
        let high1 = high1.expect("first high piece");
        let low2 = low2.expect("second low piece");
        let high2 = high2.expect("second high piece");
        let (_, low_result) = add_op(&mut data, block, 4, op::INT_OR, vec![low1, low2], Some(4));
        let (_, high_result) = add_op(&mut data, block, 5, op::INT_OR, vec![high1, high2], Some(4));
        let (piece, _) = add_op(
            &mut data,
            block,
            6,
            op::PIECE,
            vec![
                high_result.expect("high logical result"),
                low_result.expect("low logical result"),
            ],
            Some(8),
        );

        let rule = RuleDoubleIn;
        assert_eq!(rule.apply_op(high1_op, &mut data), 1);
        assert_eq!(rule.apply_op(low1_op, &mut data), 1);
        assert_eq!(data.opcode_of(piece), Some(op::INT_OR));
        assert_eq!(data.op(piece).inputs[0], first_whole);
    }

    #[test]
    fn double_in_equal3_form_rewrites_wide_compare() {
        let (mut data, block) = graph();
        let whole = input_pointer(&mut data, 0x800);
        let zero = data.new_constant(0, 4);
        let four = data.new_constant(4, 4);
        let (_, low) = add_op(
            &mut data,
            block,
            0,
            op::SUBPIECE,
            vec![whole, zero],
            Some(4),
        );
        let (_, high) = add_op(
            &mut data,
            block,
            1,
            op::SUBPIECE,
            vec![whole, four],
            Some(4),
        );
        let low = low.expect("low piece");
        let high = high.expect("high piece");
        let (and_op, and_output) =
            add_op(&mut data, block, 2, op::INT_AND, vec![high, low], Some(4));
        let all_low = data.new_constant(mask_for_size(data.varnode(low).size), 4);
        let (compare, _) = add_op(
            &mut data,
            block,
            3,
            op::INT_EQUAL,
            vec![and_output.expect("and output"), all_low],
            Some(1),
        );

        let high_op = data.varnode(high).def.expect("high piece definition");
        let low_op = data.varnode(low).def.expect("low piece definition");
        let rule = RuleDoubleIn;
        assert_eq!(rule.apply_op(high_op, &mut data), 1);
        assert_eq!(rule.apply_op(low_op, &mut data), 1);
        assert_eq!(data.opcode_of(and_op), Some(op::INT_AND));
        assert_eq!(data.op(compare).inputs[0], whole);
        assert_eq!(data.varnode(data.op(compare).inputs[1]).size, 8);
    }

    #[test]
    fn double_in_sub_form_collapses_two_pieces() {
        let (mut data, block) = graph();
        let first_whole = input_pointer(&mut data, 0xa00);
        let second_whole = input_pointer(&mut data, 0xb00);
        let zero = data.new_constant(0, 4);
        let four = data.new_constant(4, 4);
        let all_ones = data.new_constant(mask_for_size(4), 4);
        let (_, low1) = add_op(
            &mut data,
            block,
            0,
            op::SUBPIECE,
            vec![first_whole, zero],
            Some(4),
        );
        let (_, high1) = add_op(
            &mut data,
            block,
            1,
            op::SUBPIECE,
            vec![first_whole, four],
            Some(4),
        );
        let (_, low2) = add_op(
            &mut data,
            block,
            2,
            op::SUBPIECE,
            vec![second_whole, zero],
            Some(4),
        );
        let (_, high2) = add_op(
            &mut data,
            block,
            3,
            op::SUBPIECE,
            vec![second_whole, four],
            Some(4),
        );
        let low1 = low1.expect("first low piece");
        let high1 = high1.expect("first high piece");
        let low2 = low2.expect("second low piece");
        let high2 = high2.expect("second high piece");
        let (_, neg_low2) = add_op(
            &mut data,
            block,
            4,
            op::INT_MULT,
            vec![low2, all_ones],
            Some(4),
        );
        let (_, low_result) = add_op(
            &mut data,
            block,
            5,
            op::INT_ADD,
            vec![low1, neg_low2.expect("negative low")],
            Some(4),
        );
        let (_, less) = add_op(&mut data, block, 6, op::INT_LESS, vec![low1, low2], Some(1));
        let (_, extended_less) = add_op(
            &mut data,
            block,
            7,
            op::INT_ZEXT,
            vec![less.expect("borrow")],
            Some(4),
        );
        let (_, neg_extended_less) = add_op(
            &mut data,
            block,
            8,
            op::INT_MULT,
            vec![extended_less.expect("extended borrow"), all_ones],
            Some(4),
        );
        let (_, neg_high2) = add_op(
            &mut data,
            block,
            9,
            op::INT_MULT,
            vec![high2, all_ones],
            Some(4),
        );
        let (_, inner_high_result) = add_op(
            &mut data,
            block,
            10,
            op::INT_ADD,
            vec![
                neg_extended_less.expect("negative borrow"),
                neg_high2.expect("negative high"),
            ],
            Some(4),
        );
        let (_, high_result) = add_op(
            &mut data,
            block,
            11,
            op::INT_ADD,
            vec![high1, inner_high_result.expect("negative high sum")],
            Some(4),
        );
        let (piece, _) = add_op(
            &mut data,
            block,
            12,
            op::PIECE,
            vec![
                high_result.expect("high subtraction result"),
                low_result.expect("low subtraction result"),
            ],
            Some(8),
        );
        let high_op = data.varnode(high1).def.expect("high piece definition");
        let low_op = data.varnode(low1).def.expect("low piece definition");
        let rule = RuleDoubleIn;
        assert_eq!(rule.apply_op(high_op, &mut data), 1);
        assert_eq!(rule.apply_op(low_op, &mut data), 1);
        assert_eq!(data.opcode_of(piece), Some(op::INT_SUB));
    }

    #[test]
    fn double_in_mult_form_collapses_two_pieces() {
        let (mut data, block) = graph();
        let first_whole = input_pointer(&mut data, 0xc00);
        let second_whole = input_pointer(&mut data, 0xd00);
        let zero = data.new_constant(0, 4);
        let four = data.new_constant(4, 4);
        let (_, low1) = add_op(
            &mut data,
            block,
            0,
            op::SUBPIECE,
            vec![first_whole, zero],
            Some(4),
        );
        let (_, high1) = add_op(
            &mut data,
            block,
            1,
            op::SUBPIECE,
            vec![first_whole, four],
            Some(4),
        );
        let (_, low2) = add_op(
            &mut data,
            block,
            2,
            op::SUBPIECE,
            vec![second_whole, zero],
            Some(4),
        );
        let (_, high2) = add_op(
            &mut data,
            block,
            3,
            op::SUBPIECE,
            vec![second_whole, four],
            Some(4),
        );
        let low1 = low1.expect("first low piece");
        let high1 = high1.expect("first high piece");
        let low2 = low2.expect("second low piece");
        let high2 = high2.expect("second high piece");
        let (_, low1zext) = add_op(&mut data, block, 4, op::INT_ZEXT, vec![low1], Some(8));
        let (_, low2zext) = add_op(&mut data, block, 5, op::INT_ZEXT, vec![low2], Some(8));
        let (_, low_product) = add_op(
            &mut data,
            block,
            6,
            op::INT_MULT,
            vec![
                low1zext.expect("first zero extension"),
                low2zext.expect("second zero extension"),
            ],
            Some(8),
        );
        let (_, middle) = add_op(
            &mut data,
            block,
            7,
            op::SUBPIECE,
            vec![low_product.expect("low product"), four],
            Some(4),
        );
        let (_, high_product_one) = add_op(
            &mut data,
            block,
            8,
            op::INT_MULT,
            vec![high1, low2],
            Some(4),
        );
        let (_, high_product_two) = add_op(
            &mut data,
            block,
            9,
            op::INT_MULT,
            vec![high2, low1],
            Some(4),
        );
        let (_, high_sum) = add_op(
            &mut data,
            block,
            10,
            op::INT_ADD,
            vec![
                high_product_one.expect("first high product"),
                high_product_two.expect("second high product"),
            ],
            Some(4),
        );
        let (_, high_result) = add_op(
            &mut data,
            block,
            11,
            op::INT_ADD,
            vec![
                high_sum.expect("high product sum"),
                middle.expect("middle product"),
            ],
            Some(4),
        );
        let (_, low_result) = add_op(
            &mut data,
            block,
            12,
            op::SUBPIECE,
            vec![low_product.expect("low product"), zero],
            Some(4),
        );
        let (piece, _) = add_op(
            &mut data,
            block,
            13,
            op::PIECE,
            vec![
                high_result.expect("high multiplication result"),
                low_result.expect("low multiplication result"),
            ],
            Some(8),
        );
        let high_op = data.varnode(high1).def.expect("high piece definition");
        let low_op = data.varnode(low1).def.expect("low piece definition");
        let rule = RuleDoubleIn;
        assert_eq!(rule.apply_op(high_op, &mut data), 1);
        assert_eq!(rule.apply_op(low_op, &mut data), 1);
        assert_eq!(data.opcode_of(piece), Some(op::INT_MULT));
        assert_eq!(data.op(piece).inputs[0], first_whole);
    }

    #[test]
    fn double_in_shift_form_collapses_left_shift() {
        let (mut data, block) = graph();
        let whole = input_pointer(&mut data, 0xe00);
        let zero = data.new_constant(0, 4);
        let four = data.new_constant(4, 4);
        let shift_amount = data.new_constant(8, 4);
        let middle_amount = data.new_constant(24, 4);
        let (_, low) = add_op(
            &mut data,
            block,
            0,
            op::SUBPIECE,
            vec![whole, zero],
            Some(4),
        );
        let (_, high) = add_op(
            &mut data,
            block,
            1,
            op::SUBPIECE,
            vec![whole, four],
            Some(4),
        );
        let low = low.expect("low piece");
        let high = high.expect("high piece");
        let (_, low_shift) = add_op(
            &mut data,
            block,
            2,
            op::INT_LEFT,
            vec![low, shift_amount],
            Some(4),
        );
        let (_, high_shift) = add_op(
            &mut data,
            block,
            3,
            op::INT_LEFT,
            vec![high, shift_amount],
            Some(4),
        );
        let (_, middle_right) = add_op(
            &mut data,
            block,
            4,
            op::INT_RIGHT,
            vec![low, middle_amount],
            Some(4),
        );
        let (_, high_result) = add_op(
            &mut data,
            block,
            5,
            op::INT_OR,
            vec![
                high_shift.expect("high shift"),
                middle_right.expect("middle shift"),
            ],
            Some(4),
        );
        let (piece, _) = add_op(
            &mut data,
            block,
            6,
            op::PIECE,
            vec![
                high_result.expect("high result"),
                low_shift.expect("low shift"),
            ],
            Some(8),
        );
        let high_op = data.varnode(high).def.expect("high piece definition");
        let low_op = data.varnode(low).def.expect("low piece definition");
        let rule = RuleDoubleIn;
        assert_eq!(rule.apply_op(high_op, &mut data), 1);
        assert_eq!(rule.apply_op(low_op, &mut data), 1);
        assert_eq!(data.opcode_of(piece), Some(op::INT_LEFT));
        assert_eq!(data.op(piece).inputs[0], whole);
    }
    #[test]
    fn double_load_fires_converges_and_reconstructs_sum_width() {
        let (mut data, block) = graph();
        let space = memory_space(&mut data);
        let base = input_pointer(&mut data, 0x100);
        let (_, low) = load(&mut data, block, 0, space, base);
        let high_ptr = add_pointer(&mut data, block, 1, base, 4);
        let (_, high) = load(&mut data, block, 2, space, high_ptr);
        let (piece, _) = add_op(&mut data, block, 3, op::PIECE, vec![high, low], Some(8));
        let split = SplitVarnode::from_parts(&data, low, Some(high));
        assert_eq!(
            split.bit_width(),
            data.varnode(low)
                .size
                .saturating_add(data.varnode(high).size)
                * 8
        );

        let rule = RuleDoubleLoad;
        assert_eq!(rule.apply_op(piece, &mut data), 1);
        assert_eq!(data.op(piece).opcode, op::COPY);
        assert_eq!(rule.apply_op(piece, &mut data), 0);
        let combined = data
            .live_ops()
            .filter_map(|(id, operation)| {
                (operation.opcode == op::LOAD)
                    .then(|| operation.output)
                    .flatten()
                    .filter(|output| data.varnode(*output).size == 8)
                    .map(|output| (id, output))
            })
            .next()
            .expect("one combined load");
        assert_eq!(data.varnode(combined.1).size * 8, split.bit_width());
    }

    #[test]
    fn double_load_declines_noncontiguous_pointers() {
        let (mut data, block) = graph();
        let space = memory_space(&mut data);
        let base = input_pointer(&mut data, 0x100);
        let (_, low) = load(&mut data, block, 0, space, base);
        let high_ptr = add_pointer(&mut data, block, 1, base, 8);
        let (_, high) = load(&mut data, block, 2, space, high_ptr);
        let (piece, _) = add_op(&mut data, block, 3, op::PIECE, vec![high, low], Some(8));
        assert_eq!(RuleDoubleLoad.apply_op(piece, &mut data), 0);
        assert_eq!(data.op(piece).opcode, op::PIECE);
    }

    fn store_fixture(
        high_offset: u64,
    ) -> (Funcdata, GraphBlockId, OpId, VarnodeId, VarnodeId, OpId) {
        let (mut data, block) = graph();
        let space = memory_space(&mut data);
        let base = input_pointer(&mut data, 0x200);
        let high_ptr = add_pointer(&mut data, block, 0, base, high_offset);
        let whole = input_pointer(&mut data, 0x300);
        let zero = data.new_constant(0, 4);
        let four = data.new_constant(4, 4);
        let (_, low) = add_op(
            &mut data,
            block,
            1,
            op::SUBPIECE,
            vec![whole, zero],
            Some(4),
        );
        let (_, high) = add_op(
            &mut data,
            block,
            2,
            op::SUBPIECE,
            vec![whole, four],
            Some(4),
        );
        let low = low.expect("low piece");
        let high = high.expect("high piece");
        // `RuleDoubleIn::attemptMarking` sets these from the shape of the graph
        // before `RuleDoubleStore` ever looks, and the rule requires them:
        // `if (!vnlo->isPrecisLo()) return 0;`.
        set_precision(&mut data, low, Precision::Lo);
        set_precision(&mut data, high, Precision::Hi);
        let (low_store, _) = add_op(&mut data, block, 3, op::STORE, vec![space, base, low], None);
        let (high_store, _) = add_op(
            &mut data,
            block,
            4,
            op::STORE,
            vec![space, high_ptr, high],
            None,
        );
        (data, block, low_store, whole, low, high_store)
    }

    #[test]
    fn double_store_fires_converges_and_keeps_sum_width() {
        let (mut data, _block, low_store, whole, low, high_store) = store_fixture(4);
        let high = data.op(high_store).inputs[2];
        let split = SplitVarnode::from_parts(&data, low, Some(high));
        assert_eq!(split.bit_width(), 64);
        let rule = RuleDoubleStore;
        assert_eq!(rule.apply_op(low_store, &mut data), 1);
        assert_eq!(rule.apply_op(low_store, &mut data), 0);
        assert_eq!(data.opcode_of(low_store), None);
        assert_eq!(data.opcode_of(high_store), None);
        let combined = data
            .live_ops()
            .find(|(_, operation)| operation.opcode == op::STORE)
            .map(|(_, operation)| operation.inputs[2])
            .expect("one combined store");
        assert_eq!(combined, whole);
        assert_eq!(data.varnode(combined).size * 8, split.bit_width());
    }

    #[test]
    fn double_store_declines_noncontiguous_pointers() {
        let (mut data, _block, low_store, _whole, _low, _high_store) = store_fixture(8);
        assert_eq!(RuleDoubleStore.apply_op(low_store, &mut data), 0);
        assert_eq!(data.opcode_of(low_store), Some(op::STORE));
    }

    /// Builds the store pair with an `INDIRECT` guarding each store, laid out
    /// the way `Heritage` leaves them: each guard immediately precedes the store
    /// it annotates, and the second reads the first's output.
    fn guarded_store_fixture() -> (Funcdata, OpId, OpId, OpId, OpId) {
        let (mut data, block) = graph();
        let space = memory_space(&mut data);
        let base = input_pointer(&mut data, 0x200);
        let whole = input_pointer(&mut data, 0x300);
        let zero = data.new_constant(0, 4);
        let four = data.new_constant(4, 4);
        let (_, low) = add_op(
            &mut data,
            block,
            0,
            op::SUBPIECE,
            vec![whole, zero],
            Some(4),
        );
        let (_, high) = add_op(
            &mut data,
            block,
            1,
            op::SUBPIECE,
            vec![whole, four],
            Some(4),
        );
        let low = low.expect("low piece");
        let high = high.expect("high piece");
        set_precision(&mut data, low, Precision::Lo);
        set_precision(&mut data, high, Precision::Hi);
        let high_ptr = add_pointer(&mut data, block, 2, base, 4);
        let guarded = data.new_varnode(RAM_SPACE, 0x40, 4);

        // `guard_lo` then `low_store`, `guard_hi` then `high_store`.
        let guard_lo = data.new_op(op::INDIRECT, seq(3), vec![guarded]);
        let guard_lo_out = data.new_varnode(RAM_SPACE, 0x40, 4);
        data.op_set_output(guard_lo, Some(guard_lo_out));
        data.op_insert_end(guard_lo, block);
        let (low_store, _) = add_op(&mut data, block, 4, op::STORE, vec![space, base, low], None);
        let annotation_lo = data.new_iop(low_store);
        data.op_set_input(guard_lo, annotation_lo, 1);

        let guard_hi = data.new_op(op::INDIRECT, seq(5), vec![guard_lo_out]);
        let guard_hi_out = data.new_varnode(RAM_SPACE, 0x40, 4);
        data.op_set_output(guard_hi, Some(guard_hi_out));
        data.op_insert_end(guard_hi, block);
        let (high_store, _) = add_op(
            &mut data,
            block,
            6,
            op::STORE,
            vec![space, high_ptr, high],
            None,
        );
        let annotation_hi = data.new_iop(high_store);
        data.op_set_input(guard_hi, annotation_hi, 1);

        (data, low_store, high_store, guard_lo, guard_hi)
    }

    /// `noWriteConflict` starts its scan *before* the first `STORE`, walking
    /// back over the `INDIRECT`s that annotate it, and an `INDIRECT` caused by
    /// either store of the pair is collected rather than treated as an aliasing
    /// conflict. We were doing neither, so any store carrying a guard - which is
    /// most of them - was refused on its own annotation.
    #[test]
    fn double_store_collects_the_guards_of_both_stores() {
        let (data, low_store, high_store, guard_lo, guard_hi) = guarded_store_fixture();
        let mut indirects = Vec::new();
        let latest = no_write_conflict(
            &data,
            low_store,
            high_store,
            u64::from(RAM_SPACE),
            &mut indirects,
        );
        assert_eq!(latest, Some(high_store), "the later store is the anchor");
        assert_eq!(
            indirects,
            vec![guard_lo, guard_hi],
            "both guards belong to the pair, and the first is before the first store"
        );
    }

    /// `reassignIndirects`: the pair of guards collapses to the later one, which
    /// inherits the earlier's input, and the survivor moves in front of the
    /// combined store and annotates it. Leaving the guards behind would point
    /// them at destroyed operations.
    #[test]
    fn double_store_moves_its_guards_onto_the_combined_store() {
        let (mut data, low_store, high_store, guard_lo, guard_hi) = guarded_store_fixture();
        let guarded = data.op(guard_lo).inputs[0];
        assert_eq!(RuleDoubleStore.apply_op(low_store, &mut data), 1);
        assert_eq!(data.opcode_of(low_store), None);
        assert_eq!(data.opcode_of(high_store), None);
        let combined = data
            .live_ops()
            .find(|(_, operation)| operation.opcode == op::STORE)
            .map(|(id, _)| id)
            .expect("one combined store");

        // The earlier guard fed the later one, so only the later survives.
        assert_eq!(data.opcode_of(guard_lo), None, "the pair collapsed");
        assert_eq!(data.opcode_of(guard_hi), Some(op::INDIRECT));
        assert_eq!(
            data.op(guard_hi).inputs[0],
            guarded,
            "the survivor took over the earlier guard's input"
        );
        assert_eq!(
            data.iop_target(data.op(guard_hi).inputs[1]),
            Some(combined),
            "and now annotates the combined store"
        );
        let ops = &data.block(data.op(guard_hi).parent.expect("a block")).ops;
        let guard_position = ops.iter().position(|id| *id == guard_hi);
        let store_position = ops.iter().position(|id| *id == combined);
        assert!(
            guard_position < store_position,
            "and sits in front of it, as opInsertBefore leaves it"
        );
    }

    /// `testIndirectUse`: a guard whose output is read between the two stores by
    /// something that is not a later guard of the second store cannot be moved -
    /// that reader wants the value the first store left behind.
    #[test]
    fn double_store_declines_when_a_guard_is_read_in_between() {
        let (mut data, low_store, high_store, guard_lo, _guard_hi) = guarded_store_fixture();
        let guard_lo_out = data.op(guard_lo).output.expect("a guarded value");
        let block = data.op(low_store).parent.expect("a block");
        // An ordinary read of the first guard's output, before the second store.
        let (_, _) = add_op(
            &mut data,
            block,
            5,
            op::INT_ADD,
            vec![guard_lo_out, guard_lo_out],
            Some(4),
        );
        let mut indirects = Vec::new();
        assert!(
            no_write_conflict(
                &data,
                low_store,
                high_store,
                u64::from(RAM_SPACE),
                &mut indirects
            )
            .is_some(),
            "the read is not an aliasing conflict on its own"
        );
        assert!(
            !test_indirect_use(&data, low_store, high_store, &indirects),
            "but the guard cannot be relocated past its reader"
        );
        assert_eq!(RuleDoubleStore.apply_op(low_store, &mut data), 0);
        assert_eq!(data.opcode_of(low_store), Some(op::STORE));
    }
    fn split_input(
        data: &mut Funcdata,
        block: GraphBlockId,
        offset: u64,
    ) -> (VarnodeId, VarnodeId, VarnodeId) {
        let whole = input_pointer(data, offset);
        let zero = data.new_constant(0, 4);
        let four = data.new_constant(4, 4);
        let (_, low) = add_op(data, block, 0, op::SUBPIECE, vec![whole, zero], Some(4));
        let (_, high) = add_op(data, block, 1, op::SUBPIECE, vec![whole, four], Some(4));
        (
            whole,
            low.expect("split low output"),
            high.expect("split high output"),
        )
    }

    fn machine_op(
        data: &mut Funcdata,
        block: GraphBlockId,
        order: u32,
        opcode: i32,
        inputs: Vec<VarnodeId>,
        space: u32,
        offset: u64,
        size: u32,
    ) -> (OpId, VarnodeId) {
        let id = data.new_op(opcode, seq(order), inputs);
        let output = data.new_varnode(space, offset, size);
        data.op_set_output(id, Some(output));
        data.op_insert_end(id, block);
        (id, output)
    }

    fn branch_to(
        data: &mut Funcdata,
        block: GraphBlockId,
        order: u32,
        target: GraphBlockId,
        condition: VarnodeId,
    ) -> OpId {
        let destination = data.new_varnode(RAM_SPACE, data.block(target).start, 4);
        let branch = data.new_op(op::CBRANCH, seq(order), vec![destination, condition]);
        data.op_insert_end(branch, block);
        branch
    }

    fn input_pair(
        data: &mut Funcdata,
        low_offset: u64,
        high_offset: u64,
    ) -> (VarnodeId, VarnodeId) {
        (
            input_value(data, low_offset, 4),
            input_value(data, high_offset, 4),
        )
    }

    #[test]
    fn double_in_copy_force_form_collapses_two_address_forced_copies() {
        let (mut data, block) = graph();
        let (whole, low, high) = split_input(&mut data, block, 0x100);
        let low_output = data.new_varnode(REGISTER_SPACE, 0x500, 4);
        let high_output = data.new_varnode(REGISTER_SPACE, 0x504, 4);
        let copy_low = data.new_op(op::COPY, seq(2), vec![low]);
        data.op_set_output(copy_low, Some(low_output));
        data.op_insert_end(copy_low, block);
        let copy_high = data.new_op(op::COPY, seq(3), vec![high]);
        data.op_set_output(copy_high, Some(high_output));
        data.op_insert_end(copy_high, block);

        let mut split = SplitVarnode::with_whole(&data, whole, low, Some(high));
        assert_eq!(split.apply_rule_in(&mut data), 1);
        assert_eq!(data.opcode_of(copy_low), None);
        assert_eq!(data.opcode_of(copy_high), None);
        let copies: Vec<_> = data
            .live_ops()
            .filter(|(_, operation)| operation.opcode == op::COPY)
            .collect();
        assert_eq!(copies.len(), 1);
        let (_, operation) = copies[0];
        let output = operation.output.expect("wide copy output");
        assert_eq!(data.varnode(output).size, 8);
        assert_eq!(data.varnode(output).offset, 0x500);
        assert_eq!(operation.inputs, vec![whole]);
    }

    #[test]
    fn double_in_phi_form_creates_one_wide_phi() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        let first = data.new_block(0x1100);
        let second = data.new_block(0x1200);
        let join = data.new_block(0x1300);
        data.add_edge(entry, first);
        data.add_edge(entry, second);
        data.add_edge(first, join);
        data.add_edge(second, join);
        let (whole, low, high) = split_input(&mut data, entry, 0x100);
        let (low_second, high_second) = input_pair(&mut data, 0x300, 0x304);
        let (high_phi, high_output) = machine_op(
            &mut data,
            join,
            2,
            op::MULTIEQUAL,
            vec![high, high_second],
            ventris_lifter::UNIQUE_SPACE,
            0,
            4,
        );
        let (low_phi, _low_output) = machine_op(
            &mut data,
            join,
            3,
            op::MULTIEQUAL,
            vec![low, low_second],
            ventris_lifter::UNIQUE_SPACE,
            4,
            4,
        );
        let one = data.new_constant(1, 4);
        let _ = machine_op(
            &mut data,
            join,
            4,
            op::INT_ADD,
            vec![high_output, one],
            ventris_lifter::UNIQUE_SPACE,
            8,
            4,
        );

        let mut split = SplitVarnode::with_whole(&data, whole, low, Some(high));
        assert_eq!(split.apply_rule_in(&mut data), 1);
        assert_eq!(data.opcode_of(high_phi), Some(op::SUBPIECE));
        assert_eq!(data.opcode_of(low_phi), Some(op::SUBPIECE));
        let wide_phis: Vec<_> = data
            .live_ops()
            .filter(|(_, operation)| {
                operation.opcode == op::MULTIEQUAL
                    && operation
                        .output
                        .is_some_and(|value| data.varnode(value).size == 8)
            })
            .collect();
        assert_eq!(wide_phis.len(), 1);
        let output = wide_phis[0].1.output.expect("wide phi output");
        assert_eq!(data.varnode(output).size, 8);
        assert_eq!(data.op(wide_phis[0].0).inputs.len(), 2);
    }

    #[test]
    fn double_in_indirect_form_creates_one_wide_indirect() {
        let (mut data, block) = graph();
        let (whole, low, high) = split_input(&mut data, block, 0x100);
        let (affector, _) = add_op(&mut data, block, 10, op::CALL, vec![], None);
        let high_iop = data.new_iop(affector);
        let low_iop = data.new_iop(affector);
        let high_indirect = data.new_op(op::INDIRECT, seq(2), vec![high, high_iop]);
        let high_output = data.new_varnode(REGISTER_SPACE, 0x604, 4);
        data.op_set_output(high_indirect, Some(high_output));
        data.op_insert_before(high_indirect, affector);
        let low_indirect = data.new_op(op::INDIRECT, seq(3), vec![low, low_iop]);
        let low_output = data.new_varnode(REGISTER_SPACE, 0x600, 4);
        data.op_set_output(low_indirect, Some(low_output));
        data.op_insert_before(low_indirect, affector);

        let mut split = SplitVarnode::with_whole(&data, whole, low, Some(high));
        assert_eq!(split.apply_rule_in(&mut data), 1);
        assert_eq!(data.opcode_of(high_indirect), Some(op::SUBPIECE));
        assert_eq!(data.opcode_of(low_indirect), Some(op::SUBPIECE));
        let wide_indirects: Vec<_> = data
            .live_ops()
            .filter(|(_, operation)| {
                operation.opcode == op::INDIRECT
                    && operation
                        .output
                        .is_some_and(|value| data.varnode(value).size == 8)
            })
            .collect();
        assert_eq!(wide_indirects.len(), 1);
        let output = wide_indirects[0].1.output.expect("wide indirect output");
        assert_eq!(data.varnode(output).offset, 0x600);
        assert_eq!(data.op(wide_indirects[0].0).inputs[0], whole);
    }

    #[test]
    fn double_in_equal1_form_collapses_branching_piece_compares() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let high_block = data.new_block(0x1000);
        let low_block = data.new_block(0x1100);
        let true_block = data.new_block(0x1200);
        let false_block = data.new_block(0x1300);
        data.add_edge(high_block, low_block);
        data.add_edge(high_block, false_block);
        data.add_edge(low_block, true_block);
        data.add_edge(low_block, false_block);
        let (whole, low, high) = split_input(&mut data, high_block, 0x100);
        let (low_other, high_other) = input_pair(&mut data, 0x200, 0x204);
        let (high_compare, high_bool) = add_op(
            &mut data,
            high_block,
            2,
            op::INT_EQUAL,
            vec![high, high_other],
            Some(1),
        );
        let high_bool = high_bool.expect("high comparison output");
        let high_branch = branch_to(&mut data, high_block, 3, low_block, high_bool);
        let (low_compare, low_bool) = add_op(
            &mut data,
            low_block,
            4,
            op::INT_EQUAL,
            vec![low, low_other],
            Some(1),
        );
        let low_bool = low_bool.expect("low comparison output");
        let low_branch = branch_to(&mut data, low_block, 5, true_block, low_bool);
        let mut split = SplitVarnode::with_whole(&data, whole, low, Some(high));

        assert_eq!(split.apply_rule_in(&mut data), 1);
        let wide = data
            .live_ops()
            .find(|(_, operation)| {
                operation.opcode == op::INT_EQUAL
                    && operation
                        .output
                        .is_some_and(|value| data.varnode(value).size == 1)
                    && operation
                        .inputs
                        .iter()
                        .all(|value| data.varnode(*value).size == 8)
            })
            .map(|(id, _)| id)
            .expect("wide branch comparison");
        assert_eq!(
            data.op(high_branch).inputs[1],
            data.op(wide).output.expect("wide output")
        );
        assert_eq!(constant(&data, data.op(low_branch).inputs[1]), Some(1));
        assert_eq!(data.opcode_of(high_compare), Some(op::INT_EQUAL));
        assert_eq!(data.opcode_of(low_compare), Some(op::INT_EQUAL));
    }

    #[test]
    fn double_in_equal2_form_collapses_boolean_piece_compares() {
        let (mut data, block) = graph();
        let (whole, low, high) = split_input(&mut data, block, 0x100);
        let (low_other, high_other) = input_pair(&mut data, 0x200, 0x204);
        let (_, high_bool) = add_op(
            &mut data,
            block,
            2,
            op::INT_EQUAL,
            vec![high, high_other],
            Some(1),
        );
        let high_bool = high_bool.expect("high comparison output");
        let (_, low_bool) = add_op(
            &mut data,
            block,
            3,
            op::INT_EQUAL,
            vec![low, low_other],
            Some(1),
        );
        let low_bool = low_bool.expect("low comparison output");
        let (and, _) = add_op(
            &mut data,
            block,
            4,
            op::BOOL_AND,
            vec![high_bool, low_bool],
            Some(1),
        );
        let mut split = SplitVarnode::with_whole(&data, whole, low, Some(high));

        assert_eq!(split.apply_rule_in(&mut data), 1);
        assert_eq!(data.opcode_of(and), Some(op::INT_EQUAL));
        assert!(
            data.op(and)
                .inputs
                .iter()
                .all(|value| data.varnode(*value).size == 8)
        );
    }

    #[test]
    fn double_in_less_const_form_extends_high_constant_compare() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);
        let true_block = data.new_block(0x1100);
        let false_block = data.new_block(0x1200);
        data.add_edge(block, true_block);
        data.add_edge(block, false_block);
        let (whole, low, high) = split_input(&mut data, block, 0x100);
        let zero = data.new_constant(0, 4);
        let (compare, compare_output) =
            add_op(&mut data, block, 2, op::INT_LESS, vec![high, zero], Some(1));
        let compare_output = compare_output.expect("high comparison output");
        let _branch = branch_to(&mut data, block, 3, true_block, compare_output);
        let mut split = SplitVarnode::with_whole(&data, whole, low, Some(high));

        assert_eq!(split.apply_rule_in(&mut data), 1);
        assert_eq!(data.opcode_of(compare), Some(op::INT_LESS));
        assert_eq!(data.op(compare).inputs[0], whole);
        let extended = data.op(compare).inputs[1];
        assert_eq!(data.varnode(extended).size, 8);
        assert_eq!(constant(&data, extended), Some(0));
    }

    #[test]
    fn double_in_less_three_way_form_collapses_three_branch_compare() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let high_block = data.new_block(0x1000);
        let middle_block = data.new_block(0x1100);
        let low_block = data.new_block(0x1200);
        let true_block = data.new_block(0x1300);
        let false_block = data.new_block(0x1400);
        data.add_edge(high_block, true_block);
        data.add_edge(high_block, middle_block);
        data.add_edge(middle_block, low_block);
        data.add_edge(middle_block, false_block);
        data.add_edge(low_block, true_block);
        data.add_edge(low_block, false_block);
        let (whole, low, high) = split_input(&mut data, high_block, 0x100);
        let (low_other, high_other) = input_pair(&mut data, 0x200, 0x204);
        let (_, high_less_output) = add_op(
            &mut data,
            high_block,
            2,
            op::INT_LESS,
            vec![high, high_other],
            Some(1),
        );
        let high_less_output = high_less_output.expect("high less output");
        let high_branch = branch_to(&mut data, high_block, 3, true_block, high_less_output);
        let (_, high_equal_output) = add_op(
            &mut data,
            middle_block,
            4,
            op::INT_EQUAL,
            vec![high, high_other],
            Some(1),
        );
        let high_equal_output = high_equal_output.expect("high equality output");
        let equal_branch = branch_to(&mut data, middle_block, 5, low_block, high_equal_output);
        let (low_less, low_less_output) = add_op(
            &mut data,
            low_block,
            6,
            op::INT_LESS,
            vec![low, low_other],
            Some(1),
        );
        let low_less_output = low_less_output.expect("low less output");
        let low_branch = branch_to(&mut data, low_block, 7, true_block, low_less_output);
        let mut split = SplitVarnode::with_whole(&data, whole, low, Some(high));

        assert_eq!(split.apply_rule_in(&mut data), 1);
        let wide = data
            .live_ops()
            .find(|(_, operation)| {
                operation.opcode == op::INT_LESS
                    && operation
                        .output
                        .is_some_and(|value| data.varnode(value).size == 1)
                    && operation
                        .inputs
                        .iter()
                        .all(|value| data.varnode(*value).size == 8)
            })
            .map(|(id, _)| id)
            .expect("wide three-way comparison");
        assert_eq!(
            data.op(high_branch).inputs[1],
            data.op(wide).output.expect("wide output")
        );
        assert_eq!(constant(&data, data.op(equal_branch).inputs[1]), Some(0));
        assert_eq!(data.opcode_of(low_less), Some(op::INT_LESS));
        assert_eq!(data.opcode_of(low_branch), Some(op::CBRANCH));
    }
}
/// Return the registered double-precision graph rewrite rules.
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(RuleDoubleLoad),
        Box::new(RuleDoubleStore),
        Box::new(RuleDoubleIn),
        Box::new(RuleDoubleOut),
    ]
}
