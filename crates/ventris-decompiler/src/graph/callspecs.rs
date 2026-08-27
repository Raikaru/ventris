//! Per-call prototype state and the call-site actions that consume it.
//!
//! This is the graph-side equivalent of Ghidra's `FuncCallSpecs` in
//! `fspec.hh`/`fspec.cc`.  A call spec deliberately has two prototype slots:
//!
//! * [`FuncCallSpecs::prototype`] is the working prototype at this call site;
//! * [`FuncCallSpecs::callee_prototype`] is the recovered prototype of the
//!   called function, corresponding to `FuncCallSpecs::getFuncdata()` followed
//!   by `Funcdata::getFuncProto()`.
//!
//! The second link is not redundant.  `ActionDefaultParams` copies a known
//! callee's recovered prototype into an unmaterialized call-site prototype
//! before considering the evaluation model.  `guard::CallEffects` only models
//! effects and cannot stand in for that link.
//!
//! The graph does not yet own a call-spec arena, so actions take their call
//! specs explicitly.  This keeps the mutation honest: no global registry or
//! guessed relationship between a graph `CALL` and a native type is created.
//!
//! `NativeCallPrototype` cannot currently populate [`FuncCallSpecs::callee_prototype`].
//! It carries only recovered [`crate::native::Type`] values; it carries neither
//! an [`ventris_target::Abi`] nor the storage locations selected by callee
//! prototype recovery.  A caller that has a genuine [`FuncProto`] can attach it
//! with [`FuncCallSpecs::set_callee_prototype`].

use std::cell::{Ref, RefCell};

use ventris_pcode::op;

use super::action::Action;
use super::callproto::{ParamActive, call_arguments};
use super::funcproto::{EXTRAPOP_UNKNOWN, FuncProto};
use super::guard::Location;
use super::proto::recover_call_arguments;
use super::protoconstraints::{ExtraPopCall, apply_extra_pop_calls};
use super::protorecovery::{ActionDefaultParams as DefaultParamsHelper, DefaultParamsCall};
use super::{Funcdata, OpId, VarnodeId};

/// Ghidra's `FuncCallSpecs::offset_unknown` value.
pub const STACK_OFFSET_UNKNOWN: u64 = 0x0BAD_BEEF;

/// One evolving prototype attached to a CALL or CALLIND operation.
///
/// The fields mirror the call-site state that the already ported trial and
/// prototype passes can represent.  The operation id is stable for the graph
/// arena even when the operation is later destroyed, so callers can safely
/// retain a spec while an action checks `Funcdata::opcode_of`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuncCallSpecs {
    op: OpId,
    prototype: Option<FuncProto>,
    callee_prototype: Option<FuncProto>,
    effective_extra_pop: i32,
    stack_offset: u64,
    stack_placeholder_slot: Option<usize>,
    paramshift: i32,
    match_call_count: usize,
    active_input: ParamActive,
    active_output: ParamActive,
    input_consume: Vec<i32>,
    input_active: bool,
    output_active: bool,
    bad_jump_table: bool,
    stack_output_lock: bool,
}

impl FuncCallSpecs {
    /// Construct a call spec with no materialized prototype.
    ///
    /// A missing prototype is meaningful: it is the state consumed by
    /// `ActionDefaultParams` when it decides whether to copy the known callee
    /// or install the evaluation model internally.
    pub fn new(op: OpId) -> Self {
        Self {
            op,
            prototype: None,
            callee_prototype: None,
            effective_extra_pop: EXTRAPOP_UNKNOWN,
            stack_offset: STACK_OFFSET_UNKNOWN,
            stack_placeholder_slot: None,
            paramshift: 0,
            match_call_count: 0,
            active_input: ParamActive::new(),
            active_output: ParamActive::new(),
            input_consume: Vec::new(),
            input_active: false,
            output_active: false,
            bad_jump_table: false,
            stack_output_lock: false,
        }
    }

    /// Construct a call spec whose working prototype is already materialized.
    pub fn with_prototype(op: OpId, prototype: FuncProto) -> Self {
        let mut result = Self::new(op);
        result.prototype = Some(prototype);
        result
    }

    /// The graph operation represented by this spec.
    pub const fn op(&self) -> OpId {
        self.op
    }

    /// Ghidra spelling of [`Self::op`].
    pub const fn get_op(&self) -> OpId {
        self.op()
    }

    /// The working call-site prototype, if one has been materialized.
    pub const fn prototype(&self) -> Option<&FuncProto> {
        self.prototype.as_ref()
    }

    /// Mutable access to the working call-site prototype.
    pub fn prototype_mut(&mut self) -> Option<&mut FuncProto> {
        self.prototype.as_mut()
    }

    /// Replace the working call-site prototype.
    pub fn set_prototype(&mut self, prototype: FuncProto) {
        self.prototype = Some(prototype);
    }

    /// Remove the working call-site prototype, returning it to the
    /// unmaterialized state consumed by `ActionDefaultParams`.
    pub fn take_prototype(&mut self) -> Option<FuncProto> {
        self.prototype.take()
    }

    /// The recovered prototype of the known callee, if available.
    pub const fn callee_prototype(&self) -> Option<&FuncProto> {
        self.callee_prototype.as_ref()
    }

    /// Mutable access to the recovered callee prototype.
    pub fn callee_prototype_mut(&mut self) -> Option<&mut FuncProto> {
        self.callee_prototype.as_mut()
    }

    /// Attach the callee's own recovered prototype to this call spec.
    pub fn set_callee_prototype(&mut self, prototype: FuncProto) {
        self.callee_prototype = Some(prototype);
    }

    /// Remove the callee link.
    pub fn take_callee_prototype(&mut self) -> Option<FuncProto> {
        self.callee_prototype.take()
    }

    /// Whether a recovered callee prototype is attached.
    pub const fn has_callee_prototype(&self) -> bool {
        self.callee_prototype.is_some()
    }

    pub fn get_extra_pop(&self) -> i32 {
        match self.prototype.as_ref() {
            Some(prototype) => prototype.get_extra_pop(),
            None => EXTRAPOP_UNKNOWN,
        }
    }
    /// The working extra-pop selected for this call, after model resolution.
    pub const fn effective_extra_pop(&self) -> i32 {
        self.effective_extra_pop
    }

    /// Ghidra spelling of [`Self::effective_extra_pop`].
    pub const fn get_effective_extra_pop(&self) -> i32 {
        self.effective_extra_pop()
    }

    /// Set the call-specific effective extra-pop.
    pub const fn set_effective_extra_pop(&mut self, value: i32) {
        self.effective_extra_pop = value;
    }

    /// Relative stack-pointer offset at this call site.
    pub const fn stack_offset(&self) -> u64 {
        self.stack_offset
    }

    /// Ghidra spelling of [`Self::stack_offset`].
    pub const fn get_spacebase_offset(&self) -> u64 {
        self.stack_offset()
    }

    /// Set the relative stack-pointer offset.
    pub const fn set_stack_offset(&mut self, value: u64) {
        self.stack_offset = value;
    }

    /// The temporary CALL input slot used as a stack placeholder.
    pub const fn stack_placeholder_slot(&self) -> Option<usize> {
        self.stack_placeholder_slot
    }

    /// Ghidra spelling of [`Self::stack_placeholder_slot`].
    pub const fn get_stack_placeholder_slot(&self) -> Option<usize> {
        self.stack_placeholder_slot()
    }

    /// Set the stack-placeholder input slot.
    pub const fn set_stack_placeholder_slot(&mut self, slot: usize) {
        self.stack_placeholder_slot = Some(slot);
    }

    /// Release the stack-placeholder input slot.
    pub const fn clear_stack_placeholder_slot(&mut self) {
        self.stack_placeholder_slot = None;
    }

    /// Number of leading parameters ignored before the prototype's inputs.
    pub const fn paramshift(&self) -> i32 {
        self.paramshift
    }

    /// Ghidra spelling of [`Self::paramshift`].
    pub const fn get_paramshift(&self) -> i32 {
        self.paramshift()
    }

    /// Set the call-site parameter shift.
    pub const fn set_paramshift(&mut self, value: i32) {
        self.paramshift = value;
    }

    /// Number of matching calls to the same callee in this function.
    pub const fn match_call_count(&self) -> usize {
        self.match_call_count
    }

    /// Ghidra spelling of [`Self::match_call_count`].
    pub const fn get_match_call_count(&self) -> usize {
        self.match_call_count()
    }

    /// Set the matching-call count.
    pub const fn set_match_call_count(&mut self, value: usize) {
        self.match_call_count = value;
    }

    /// Parameter trials in ABI order for the call's inputs.
    pub const fn active_input(&self) -> &ParamActive {
        &self.active_input
    }

    /// Mutable parameter trials in ABI order for the call's inputs.
    pub const fn active_input_mut(&mut self) -> &mut ParamActive {
        &mut self.active_input
    }

    /// Parameter trials in ABI order for the call's outputs.
    pub const fn active_output(&self) -> &ParamActive {
        &self.active_output
    }

    /// Mutable parameter trials in ABI order for the call's outputs.
    pub const fn active_output_mut(&mut self) -> &mut ParamActive {
        &mut self.active_output
    }

    /// Turn input-trial recovery on or off.
    pub const fn set_input_active(&mut self, value: bool) {
        self.input_active = value;
    }

    /// Whether input-trial recovery is active.
    pub const fn is_input_active(&self) -> bool {
        self.input_active
    }

    /// Turn output-trial recovery on or off.
    pub const fn set_output_active(&mut self, value: bool) {
        self.output_active = value;
    }

    /// Whether output-trial recovery is active.
    pub const fn is_output_active(&self) -> bool {
        self.output_active
    }

    /// Mark this call as an unresolved jump-table edge.
    pub const fn set_bad_jump_table(&mut self, value: bool) {
        self.bad_jump_table = value;
    }

    /// Whether this call originated from an unresolved jump table.
    pub const fn is_bad_jump_table(&self) -> bool {
        self.bad_jump_table
    }

    /// Mark the return value as locked in stack storage.
    pub const fn set_stack_output_lock(&mut self, value: bool) {
        self.stack_output_lock = value;
    }

    /// Whether the return value is locked in stack storage.
    pub const fn is_stack_output_lock(&self) -> bool {
        self.stack_output_lock
    }

    /// Return the bytes consumed by one input slot, if known.
    pub fn input_bytes_consumed(&self, slot: usize) -> i32 {
        self.input_consume.get(slot).copied().unwrap_or(0)
    }

    /// Set one input's consumed-byte estimate.
    ///
    /// Ghidra treats zero as "all bytes" and only permits a non-zero estimate
    /// to become smaller once one has already been recorded.
    pub fn set_input_bytes_consumed(&mut self, slot: usize, value: i32) -> bool {
        if value < 0 {
            return false;
        }
        self.input_consume.resize(slot.saturating_add(1), 0);
        let old = self.input_consume[slot];
        if old == 0 || value < old {
            self.input_consume[slot] = value;
            return true;
        }
        false
    }

    /// Read the arguments recovered for this call by the shared trial engine.
    ///
    /// This delegates to [`call_arguments`] rather than maintaining a second
    /// argument-recovery implementation in the call-spec object.
    pub fn argument_values(
        &self,
        data: &Funcdata,
        argument_locations: &[Location],
    ) -> Vec<VarnodeId> {
        call_arguments(data, argument_locations)
            .remove(&self.op)
            .unwrap_or_default()
    }

    /// Recover call operands through the existing graph trial engine.
    ///
    /// The helper intentionally operates on every call in `data`, matching the
    /// graph pipeline's existing action.  The returned count is the number of
    /// calls whose operand list was rebuilt; this method is a convenience entry
    /// point for callers that already have a call-spec object to anchor the
    /// operation.
    pub fn recover_arguments(
        &self,
        data: &mut Funcdata,
        argument_sections: &[Vec<Location>],
        arity_of: &dyn Fn(u64) -> Option<usize>,
    ) -> usize {
        recover_call_arguments(data, argument_sections, arity_of)
    }
}

/// `ActionDefaultParams` from Ghidra's `base` group at position
/// `defaultparams` (registered at `coreaction.cc:5531`, body at `2352-2377`).
///
/// **Not registered in the pipeline, and the reason is architectural rather
/// than a missing accessor.** The action needs a per-call-site
/// `FuncCallSpecs` arena - Ghidra's `Funcdata::qlst` - to write a default
/// prototype into. This pipeline never grew one: per-call parameter recovery
/// took the trial route instead (`graph::callproto`'s `register_trials` and
/// `recover_call_arguments`, driven by `ActionActiveParam`), and the
/// convention's storage reaches a call through the `FuncProto` on `Funcdata`.
/// Adding an arena purely to host this action would put two independent
/// prototypes on every call site, and the trial machinery is the one that is
/// measured. The static [`Self::apply_with`] form stays available for a caller
/// that does own its records.
pub struct ActionDefaultParams {
    calls: RefCell<Vec<FuncCallSpecs>>,
    eval_model: FuncProto,
}

impl ActionDefaultParams {
    /// Construct a configured default-parameter action.
    pub fn new(calls: Vec<FuncCallSpecs>, eval_model: FuncProto) -> Self {
        Self {
            calls: RefCell::new(calls),
            eval_model,
        }
    }

    /// Borrow the configured call specs after applying the action.
    pub fn calls(&self) -> Ref<'_, Vec<FuncCallSpecs>> {
        self.calls.borrow()
    }

    /// Apply default-model selection to explicit call specs.
    ///
    /// Records are matched by operation id, not by slice position.  This keeps
    /// a stale/dead spec from changing a different live call while preserving
    /// the live-call order expected by the existing helper.
    pub fn apply_with(
        data: &Funcdata,
        calls: &mut [FuncCallSpecs],
        eval_model: &FuncProto,
    ) -> usize {
        let live_calls: Vec<OpId> = data
            .live_ops()
            .filter(|(_, operation)| {
                matches!(operation.opcode, op::CALL | op::CALLIND | op::CALLOTHER)
            })
            .map(|(id, _)| id)
            .collect();
        if live_calls.is_empty() || calls.is_empty() {
            return 0;
        }

        let mut records: Vec<DefaultParamsCall> = live_calls
            .iter()
            .map(|op| {
                calls.iter().find(|call| call.op() == *op).map_or(
                    DefaultParamsCall {
                        prototype: None,
                        known_function: None,
                    },
                    |call| DefaultParamsCall {
                        prototype: call.prototype().cloned(),
                        known_function: call.callee_prototype().cloned(),
                    },
                )
            })
            .collect();

        // The helper intentionally owns the exact Ghidra decision tree.  A
        // placeholder record is included for an unregistered live call because
        // the helper consumes one record per live call; its result is ignored
        // below and cannot mutate the caller's specs.
        let _ = DefaultParamsHelper::apply_to_call_records(data, &mut records, eval_model);

        let mut changed = 0;
        for (op, record) in live_calls.into_iter().zip(records) {
            let Some(call) = calls.iter_mut().find(|call| call.op() == op) else {
                continue;
            };
            if call.prototype != record.prototype {
                call.prototype = record.prototype;
                changed += 1;
            }
        }
        changed
    }
}

impl Action for ActionDefaultParams {
    fn name(&self) -> &'static str {
        "defaultparams"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        Self::apply_with(data, &mut self.calls.borrow_mut(), &self.eval_model)
    }
}

/// `ActionExtraPopSetup` from Ghidra's `base` group at position
/// `extrapopsetup` (`coreaction.cc`, line 5533; body around lines 1443-1464).
///
/// **Not registered, and provably inert for every supported target.** The whole
/// action is a stack adjustment of `extrapop` bytes after a call, and the
/// shipped cspecs for the architectures this pipeline decompiles declare
/// `extrapop="0"`: `Ghidra/Processors/MIPS/data/languages/*.cspec` and
/// `.../PowerPC/...` both do, and Ghidra's own default is `extrapop=0`
/// (`fspec.cc:2346`). A zero adjustment inserts nothing, so registering it -
/// which would also need the per-call-site arena `ActionDefaultParams` above
/// describes - could not change any output here.
///
/// Only the known-extra-pop branch is representable in any case. An unknown
/// value needs Ghidra's IOP-space varnode and an `INDIRECT` creation marker;
/// both facilities now exist (`Funcdata::new_iop`, `mark_indirect_creation`),
/// so that half is no longer the blocker - the arena is.
pub struct ActionExtraPopSetup {
    stack: Location,
    calls: RefCell<Vec<FuncCallSpecs>>,
}

impl ActionExtraPopSetup {
    /// Construct a configured stack-adjustment action.
    pub fn new(stack: Location, calls: Vec<FuncCallSpecs>) -> Self {
        Self {
            stack,
            calls: RefCell::new(calls),
        }
    }

    /// Borrow the configured call specs.
    pub fn calls(&self) -> Ref<'_, Vec<FuncCallSpecs>> {
        self.calls.borrow()
    }

    /// Apply known extra-pop adjustments to explicit call specs.
    pub fn apply_with(data: &mut Funcdata, stack: Location, calls: &[FuncCallSpecs]) -> usize {
        let records: Vec<ExtraPopCall> = calls
            .iter()
            .filter_map(|call| {
                call.prototype().cloned().map(|proto| ExtraPopCall {
                    op: call.op(),
                    proto,
                })
            })
            .collect();
        apply_extra_pop_calls(data, stack, &records)
    }

    /// Apply known extra-pop adjustments and record each call's effective
    /// value, matching `FuncCallSpecs::setEffectiveExtraPop` in Ghidra.
    pub fn apply_with_mut(
        data: &mut Funcdata,
        stack: Location,
        calls: &mut [FuncCallSpecs],
    ) -> usize {
        let changed = Self::apply_with(data, stack, calls);
        for call in calls {
            let extra_pop = call.get_extra_pop();
            if extra_pop != EXTRAPOP_UNKNOWN {
                call.set_effective_extra_pop(extra_pop);
            }
        }
        changed
    }
}

impl Action for ActionExtraPopSetup {
    fn name(&self) -> &'static str {
        "extrapopsetup"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        Self::apply_with_mut(data, self.stack, &mut self.calls.borrow_mut())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{RAM_SPACE, REGISTER_SPACE};
    use ventris_target::TargetProfile;

    fn location(space: u32, offset: u64, size: u32) -> Location {
        Location {
            space,
            offset,
            size,
        }
    }

    fn prototype(parameter_offset: u64, output_offset: u64, extra_pop: i32) -> FuncProto {
        let mut proto = FuncProto::with_storage(
            TargetProfile::Ps2.spec().abi,
            vec![location(REGISTER_SPACE, parameter_offset, 4)],
            vec![location(REGISTER_SPACE, output_offset, 4)],
        );
        proto.add_model_param("argument", crate::native::Type::Unsigned(32));
        proto.set_extra_pop(extra_pop);
        proto
    }

    fn call_data() -> (Funcdata, super::super::GraphBlockId, OpId) {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(data.entry);
        let target = data.new_constant(0x2000, 4);
        let call = data.new_op(
            op::CALL,
            super::super::SeqNum {
                address: 0x1010,
                order: 0,
            },
            vec![target],
        );
        data.op_insert_end(call, block);
        (data, block, call)
    }

    #[test]
    fn default_params_copy_known_callee_prototype_and_storage() {
        let (mut data, _, call) = call_data();
        let callee = prototype(0x20, 0x40, EXTRAPOP_UNKNOWN);
        let eval = prototype(0x80, 0x90, EXTRAPOP_UNKNOWN);
        let mut spec = FuncCallSpecs::new(call);
        spec.set_callee_prototype(callee.clone());

        assert_eq!(
            ActionDefaultParams::apply_with(&data, std::slice::from_mut(&mut spec), &eval),
            1
        );
        let selected = spec.prototype().expect("default params materialized");
        assert_eq!(selected, &callee);
        assert_eq!(selected.model_input_storage(), callee.model_input_storage());
        assert_eq!(
            selected.get_param(0).unwrap().get_address(),
            callee.get_param(0).unwrap().get_address()
        );

        let action = ActionDefaultParams::new(vec![spec.clone()], eval.clone());
        assert_eq!(Action::apply(&action, &mut data), 0);
        assert_eq!(action.calls()[0].prototype(), spec.prototype());
    }

    #[test]
    fn default_params_declines_already_materialized_matching_model() {
        let (data, _, call) = call_data();
        let eval = prototype(0x80, 0x90, EXTRAPOP_UNKNOWN);
        let mut spec = FuncCallSpecs::with_prototype(call, eval.clone());
        spec.set_callee_prototype(prototype(0x20, 0x40, EXTRAPOP_UNKNOWN));
        let before = spec.clone();
        assert_eq!(
            ActionDefaultParams::apply_with(&data, std::slice::from_mut(&mut spec), &eval),
            0
        );
        assert_eq!(spec, before);
    }

    #[test]
    fn extra_pop_setup_inserts_stack_adjustment_for_known_call() {
        let (mut data, _, call) = call_data();
        let mut call_proto = prototype(0x20, 0x40, 8);
        call_proto.set_extra_pop(8);
        let spec = FuncCallSpecs::with_prototype(call, call_proto);
        let stack = location(RAM_SPACE, 0x80, 4);

        let action = ActionExtraPopSetup::new(stack, vec![spec]);
        assert_eq!(Action::apply(&action, &mut data), 1);
        assert_eq!(action.calls()[0].get_effective_extra_pop(), 8);
        assert!(data.live_ops().any(|(_, operation)| {
            operation.opcode == op::INT_ADD
                && operation.output.is_some_and(|output| {
                    let value = data.varnode(output);
                    value.space == stack.space
                        && value.offset == stack.offset
                        && value.size == stack.size
                })
        }));
    }

    #[test]
    fn extra_pop_setup_declines_unknown_call_pop() {
        let (mut data, _, call) = call_data();
        let spec = FuncCallSpecs::with_prototype(call, prototype(0x20, 0x40, EXTRAPOP_UNKNOWN));
        let stack = location(RAM_SPACE, 0x80, 4);

        assert_eq!(
            ActionExtraPopSetup::apply_with(&mut data, stack, &[spec]),
            0
        );
        assert!(
            !data
                .live_ops()
                .any(|(_, operation)| operation.opcode == op::INT_ADD)
        );
    }
}
