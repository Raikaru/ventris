//! Lifecycle actions from Ghidra 12.1.3's `coreaction.hh` and
//! `coreaction.cc`.
//!
//! `ActionStart` is the first action in `ActionDatabase::universalAction`,
//! before `ActionConstbase` and every analysis group. `ActionStartTypes` sits
//! near the end of the repeated `actfullloop`, after `ActionUnjustifiedParams`
//! and before `ActionActiveReturn`; its start flag therefore remains one-shot
//! across full-loop iterations, while its reset hook enables type recovery.
//! `ActionStartCleanUp` follows the full loop and `ActionMappedLocalSync`, just
//! before the cleanup rule pool. `ActionAssignHigh` follows cleanup,
//! `ActionPreferComplement`, `ActionStructureTransform`, and
//! `ActionNormalizeBranches`, and begins the merge sequence.
//! `ActionMergeMultiEntry` follows `ActionMergeRequired`, `ActionMarkExplicit`,
//! and `ActionMarkImplied`, before `ActionMergeCopy`. `ActionMarkIndirectOnly`
//! follows `ActionDynamicSymbols` and comes before speculative
//! `ActionMergeAdjacent`, as required by the source comment. `ActionStop` is
//! the final action, after `ActionPrototypeWarnings`.
//!
//! The graph carries lifecycle markers and the per-varnode indirect-only bit,
//! but it has no symbol scope, symbol entries, high-variable arena, or cover
//! conflict machinery. The seven wrappers therefore preserve every state
//! transition that the graph can represent. `merge_multi_entry` is deliberately
//! unsupported rather than a guessed merge: Ghidra's implementation needs
//! symbol-entry lookup and mutable `HighVariable` unions that this graph cannot
//! express.

use super::Funcdata;
use super::action::Action;

/// Ports Ghidra's `ActionStart`, which starts function processing by setting
/// `Funcdata::processing_started`.
///
/// The graph is already lifted by `Funcdata::from_lifted`, so this action only
/// records the lifecycle transition instead of repeating flow tracing.
pub struct ActionStart;

impl Action for ActionStart {
    fn name(&self) -> &'static str {
        "start"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        data.start_processing();
        0
    }
}

/// Ports Ghidra's `ActionStop`, which completes function processing by setting
/// `Funcdata::processing_complete`.
///
/// Dead-operation reclamation and warning emission belong to Ghidra services
/// absent from this graph, so the action keeps only the observable lifecycle
/// marker.
pub struct ActionStop;

impl Action for ActionStop {
    fn name(&self) -> &'static str {
        "stop"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        data.stop_processing();
        0
    }
}

/// Ports Ghidra's `ActionStartTypes`, which enables and starts the type
/// recovery lifecycle states.
///
/// `apply` records `typerecovery_start`; the separate `reset` hook records
/// `typerecovery_on`, matching Ghidra's distinction between opting into type
/// analysis and reaching its first propagation pass.
pub struct ActionStartTypes;

impl ActionStartTypes {
    /// Enables type recovery during action-pool reset.
    ///
    /// This ports `ActionStartTypes::reset`, which calls
    /// `Funcdata::setTypeRecovery(true)` before the full loop begins.
    pub fn reset(&self, data: &mut Funcdata) {
        data.set_type_recovery(true);
    }
}

impl Action for ActionStartTypes {
    fn name(&self) -> &'static str {
        "starttypes"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let _ = data.start_type_recovery();
        0
    }
}

/// Ports Ghidra's `ActionStartCleanUp` by recording the varnode creation
/// boundary at which cleanup starts.
///
/// Cleanup rules use the saved `Funcdata::clean_up_index` to distinguish
/// pre-existing values from values introduced during cleanup.
pub struct ActionStartCleanUp;

impl Action for ActionStartCleanUp {
    fn name(&self) -> &'static str {
        "startcleanup"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        data.start_clean_up();
        0
    }
}

/// Ports Ghidra's `ActionAssignHigh` by enabling the high-level variable phase
/// at the current varnode boundary.
///
/// This records both its `Funcdata::high_level_on` state and
/// `Funcdata::high_level_index`. The graph has no `HighVariable` objects to
/// allocate, so it does not fabricate them.
pub struct ActionAssignHigh;

impl Action for ActionAssignHigh {
    fn name(&self) -> &'static str {
        "assignhigh"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        data.set_high_level();
        0
    }
}

/// Ports Ghidra's `ActionMarkIndirectOnly`, which marks abnormal inputs whose
/// complete graph use reaches an `INDIRECT`.
///
/// The graph stores the resulting `Varnode::indirectonly` equivalent on
/// `VarnodeFlags`, while its conservative graph model treats every `INDIRECT`
/// as the terminal form.
pub struct ActionMarkIndirectOnly;

impl Action for ActionMarkIndirectOnly {
    fn name(&self) -> &'static str {
        "markindirectonly"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let _ = data.mark_indirect_only();
        0
    }
}

/// Attempts Ghidra's symbol-entry merge for a multiple-entry function.
///
/// `Merge::mergeMultiEntry` collects every `Varnode` linked to each complete
/// `SymbolEntry`, then unions their `HighVariable` objects unless cover
/// conflicts forbid the merge. `Funcdata` has one entry address but no symbol
/// scope, symbol-entry links, high-variable arena, or mutable cover-aware merge
/// operation, so there is no faithful graph transformation to perform.
pub fn merge_multi_entry(_data: &mut Funcdata) -> usize {
    0
}

/// Exposes Ghidra's `ActionMergeMultiEntry` at its merge-phase slot.
///
/// The action remains visible to the pipeline, while `merge_multi_entry`
/// intentionally reports no change until the graph grows the symbol and
/// high-variable structures required by Ghidra.
pub struct ActionMergeMultiEntry;

impl Action for ActionMergeMultiEntry {
    fn name(&self) -> &'static str {
        "mergemultientry"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        merge_multi_entry(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SeqNum;
    use ventris_lifter::REGISTER_SPACE;
    use ventris_pcode::op;

    fn seq(address: u64, order: u32) -> SeqNum {
        SeqNum { address, order }
    }

    #[test]
    fn start_marks_processing_started() {
        let mut data = Funcdata::default();
        assert!(!data.is_proc_started());
        assert_eq!(ActionStart.apply(&mut data), 0);
        assert!(data.processing_started);
        assert!(data.is_proc_started());
    }

    #[test]
    fn stop_marks_processing_complete() {
        let mut data = Funcdata::default();
        ActionStart.apply(&mut data);
        assert!(!data.is_proc_complete());
        assert_eq!(ActionStop.apply(&mut data), 0);
        assert!(data.processing_complete);
        assert!(data.is_proc_complete());
    }

    #[test]
    fn start_types_reset_enables_and_apply_starts_recovery() {
        let mut data = Funcdata::default();
        let action = ActionStartTypes;
        action.reset(&mut data);
        assert!(data.type_recovery_on);
        assert!(data.is_type_recovery_on());
        assert!(!data.type_recovery_started);
        assert_eq!(action.apply(&mut data), 0);
        assert!(data.type_recovery_started);
        assert!(data.has_type_recovery_started());
        assert!(!data.start_type_recovery());
    }

    #[test]
    fn start_cleanup_records_the_current_creation_boundary() {
        let mut data = Funcdata::default();
        data.new_varnode(REGISTER_SPACE, 0, 4);
        data.new_varnode(REGISTER_SPACE, 4, 4);
        assert_eq!(ActionStartCleanUp.apply(&mut data), 0);
        assert_eq!(data.clean_up_index, 2);
        data.new_varnode(REGISTER_SPACE, 8, 4);
        assert_eq!(data.clean_up_index, 2);
    }

    #[test]
    fn assign_high_records_the_high_level_boundary_once() {
        let mut data = Funcdata::default();
        data.new_varnode(REGISTER_SPACE, 0, 4);
        assert_eq!(ActionAssignHigh.apply(&mut data), 0);
        assert!(data.high_level_on);
        assert!(data.is_high_on());
        assert_eq!(data.high_level_index, 1);
        data.new_varnode(REGISTER_SPACE, 4, 4);
        ActionAssignHigh.apply(&mut data);
        assert_eq!(data.high_level_index, 1);
    }

    #[test]
    fn mark_indirect_only_marks_only_abnormal_inputs_with_indirect_uses() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);

        let indirect_input = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(indirect_input);
        let indirect = data.new_op(op::INDIRECT, seq(0x1000, 0), vec![indirect_input]);
        let indirect_output = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.op_set_output(indirect, Some(indirect_output));
        data.op_insert_end(indirect, block);

        let ordinary_input = data.new_varnode(REGISTER_SPACE, 4, 4);
        data.mark_input(ordinary_input);
        let copy = data.new_op(op::COPY, seq(0x1004, 0), vec![ordinary_input]);
        let copy_output = data.new_varnode(REGISTER_SPACE, 4, 4);
        data.op_set_output(copy, Some(copy_output));
        data.op_insert_end(copy, block);

        assert_eq!(ActionMarkIndirectOnly.apply(&mut data), 0);
        assert!(data.varnode(indirect_input).flags.indirect_only);
        assert!(!data.varnode(ordinary_input).flags.indirect_only);
    }

    #[test]
    fn merge_multi_entry_is_explicitly_unavailable_without_symbol_links() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x2000);
        let input = data.new_constant(1, 4);
        let operation = data.new_op(op::COPY, seq(0x2000, 0), vec![input]);
        data.op_insert_end(operation, block);
        let before = data.clone();
        assert_eq!(ActionMergeMultiEntry.apply(&mut data), 0);
        assert_eq!(data, before);
        assert_eq!(merge_multi_entry(&mut data), 0);
        assert_eq!(data.block(block).ops, vec![operation]);
    }
}
