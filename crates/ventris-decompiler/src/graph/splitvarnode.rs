//! Split-value recovery from Ghidra 12.1.3's `double.cc`.
//!
//! `SplitVarnode` models one logical value whose little-endian storage is held
//! in a low and a high piece.  The graph does not carry Ghidra's precision
//! marks, type locks, address-tied symbols, or dominance cache, so discovery is
//! deliberately structural: SUBPIECEs at offsets zero and `whole - hi.size`,
//! or a PIECE whose inputs are the pair.
//!
//! The two rules below are the portions of the double-precision cleanup that
//! this graph can express without inventing metadata.  `RuleDoubleLoad`
//! collapses two adjacent LOADs under a PIECE; `RuleDoubleStore` collapses two
//! adjacent SUBPIECE/STORE pairs back into one STORE.  Both rules only accept
//! direct, same-block operations and reject anything that could make memory
//! ordering ambiguous.  The store rule deliberately omits Ghidra's
//! `RuleDoubleStore::testIndirectUse` and `RuleDoubleStore::reassignIndirects`
//! path because this graph has no IOP-affector identity or operation-uninsert
//! primitive.
//!
//! The following requested rules remain intentionally unregistered:
//!
//! * `RuleDoubleIn` needs `Varnode::isPrecisLo`, `Varnode::isPrecisHi`,
//!   `Varnode::isTypeLock`, `Varnode::getType`, `TypeOp::isArithmeticOp`,
//!   `TypeOp::isFloatingPointOp`, `Funcdata::hasUnreachableBlocks`, and
//!   `SplitVarnode::wholeList`/`SplitVarnode::applyRuleIn`.
//!   `RuleDoubleOut` additionally needs `Varnode::isPersist`,
//!   `Varnode::isAddrTied`, `Varnode::getSymbolEntry`,
//!   `SplitVarnode::isAddrTiedContiguous`, and
//!   `Funcdata::combineInputVarnodes`.
//! * `RuleSplitCopy`, `RuleSplitLoad`, and `RuleSplitStore` need
//!   `SplitDatatype::splitCopy`, `SplitDatatype::splitLoad`,
//!   `SplitDatatype::splitStore`, `SplitDatatype::getValueDatatype`, and
//!   the full `Datatype` aggregate layout (`getMetatype`, field offsets, and
//!   pointer-relative types).
//! * `RuleStringCopy` needs `StringSequence::isValid`,
//!   `StringSequence::transform`, `Datatype::isCharPrint`,
//!   `Datatype::isOpaqueString`, `Varnode::isAddrTied`, and
//!   `ScopeLocal::queryContainer`.  `RuleStringStore` needs
//!   `HeapSequence::isValid`, `HeapSequence::transform`,
//!   `Datatype::getMetatype`, `TypePointer::getPtrTo`, and the same
//!   character-type/user-op construction machinery.
//!
//! Source authority: the pinned Ghidra `double.hh`, `double.cc`,
//! `subflow.cc`, and `constseq.cc`.

use ventris_pcode::op;

use super::action::Rule;
use super::{Funcdata, GraphBlockId, OpId, SeqNum, VarnodeId};

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

    pub fn is_constant(&self) -> bool {
        self.val.is_some()
    }

    pub fn has_both_pieces(&self) -> bool {
        self.lo.is_some() && self.hi.is_some()
    }

    pub fn size(&self) -> u32 {
        self.wholesize
    }

    pub fn bit_width(&self) -> u32 {
        self.wholesize.saturating_mul(8)
    }

    pub fn lo(&self) -> Option<VarnodeId> {
        self.lo
    }

    pub fn hi(&self) -> Option<VarnodeId> {
        self.hi
    }

    pub fn whole(&self) -> Option<VarnodeId> {
        self.whole
    }

    pub fn definition_point(&self) -> Option<OpId> {
        self.defpoint
    }

    pub fn definition_block(&self) -> Option<GraphBlockId> {
        self.defblock
    }

    pub fn value(&self) -> Option<u64> {
        self.val
    }

    /// Find the whole from matching SUBPIECEs of one source Varnode.
    ///
    /// This is the useful graph equivalent of Ghidra's private
    /// `findWholeSplitToPieces`.  One transparent COPY around a SUBPIECE is
    /// accepted because address-forced pieces commonly carry that copy.
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
            if let Some(parent) = parent
                && operation.parent != Some(parent)
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
    /// The operation is a PIECE for a two-piece value and an INT_ZEXT for an
    /// implied-zero high piece.  The method returns the whole Varnode.
    pub fn find_create_whole(
        &mut self,
        data: &mut Funcdata,
        exist_op: Option<OpId>,
    ) -> Option<VarnodeId> {
        if let Some(whole) = self.whole {
            return Some(whole);
        }
        if let Some(value) = self.val {
            let whole = data.new_constant(value, self.wholesize);
            self.whole = Some(whole);
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
    pub fn find_create_output_whole(&mut self, data: &mut Funcdata) -> Option<VarnodeId> {
        if self.is_constant() {
            return self.find_create_whole(data, None);
        }
        if self.whole.is_none() {
            self.whole = Some(data.new_unique(self.wholesize));
        }
        self.whole
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

/// Reject a pair if a same-space write, call, or control transfer intervenes.
fn no_write_conflict(data: &Funcdata, first: OpId, second: OpId, space: u64) -> Option<OpId> {
    let (block_first, pos_first) = op_position(data, first)?;
    let (block_second, pos_second) = op_position(data, second)?;
    if block_first != block_second {
        return None;
    }
    let (start, end) = if pos_first <= pos_second {
        (pos_first, pos_second)
    } else {
        (pos_second, pos_first)
    };
    let block = data.block(block_first);
    for candidate in block
        .ops
        .iter()
        .copied()
        .skip(start + 1)
        .take(end - start - 1)
    {
        let operation = data.op(candidate);
        if operation.dead {
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
                if output(data, candidate)
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
    Some(
        if sequence_order(data, first) >= sequence_order(data, second) {
            first
        } else {
            second
        },
    )
}

fn direct_load(data: &Funcdata, piece: VarnodeId) -> Option<OpId> {
    let def = definition(data, piece)?;
    if data.opcode_of(def) != Some(op::LOAD) {
        return None;
    }
    (output(data, def) == Some(piece)).then_some(def)
}

/// Collapse `PIECE(load(high), load(low))` into one wider LOAD.
pub struct RuleDoubleLoad;

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
        let Some(latest) = no_write_conflict(data, load_lo, load_hi, space_lo) else {
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
                let Some(latest) = no_write_conflict(data, id, high_store, low_space) else {
                    continue;
                };
                let seq = data.op(latest).seq;
                let new_store =
                    data.new_op(op::STORE, seq, vec![data.op(id).inputs[0], low_ptr, whole]);
                data.op_insert_after(new_store, latest);
                data.op_destroy(id);
                data.op_destroy(high_store);
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
        assert!(rules.iter().all(|rule| !rule.op_list().is_empty()));
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
}
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![Box::new(RuleDoubleLoad), Box::new(RuleDoubleStore)]
}
