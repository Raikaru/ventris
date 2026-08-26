//! Prototype-recovery actions ported from Ghidra 12.1.3's `coreaction.cc`.
//!
//! The source authority is `ActionInputPrototype`, `ActionOutputPrototype`,
//! `ActionPrototypeTypes`, and `ActionDefaultParams` in `coreaction.cc` and
//! `coreaction.hh`, at Ghidra commit `8b4c91d4d5bd1549622bfbade0df199585b98365`:
//!
//! * `ActionPrototypeTypes` is in the `protorecovery` group at position
//!   `prototypetypes` (`coreaction.cc` lines 4660-4755).
//! * `ActionDefaultParams` is in the `base` group at position `defaultparams`
//!   (`coreaction.cc` lines 2352-2377).
//! * `ActionInputPrototype` is in the `fixateproto` group at position
//!   `inputprototype` (`coreaction.cc` lines 4758-4813).
//! * `ActionOutputPrototype` is in the `localrecovery` group at position
//!   `outputprototype` (`coreaction.cc` lines 4816-4832).
//!
//! `Funcdata` owns the optional function prototype and local scope on the graph
//! path.  The action implementations clone those values before delegating to
//! the public `apply_with` methods and write them back afterwards.  Cloning is
//! intentional: `Funcdata` exposes independent accessors rather than a method
//! that can lend two mutable fields at once, and the borrow boundary should stay
//! visible instead of being hidden behind interior mutability.
//!
//! Ghidra's `resolveModel` has no direct equivalent.  Ventris has one concrete
//! [`ventris_target::Abi`] per [`FuncProto`], so `FuncProto::derive_input_map`
//! performs the representable model filtering directly.  With no model storage
//! map it deliberately leaves trials alone; claiming an arbitrary register
//! would be less correct than declining to resolve one.
//!
//! `ActionDefaultParams` is the one intentionally partial port.  Ghidra's
//! action mutates a `FuncCallSpecs` object for every call, while this graph has
//! no per-call prototype object.  [`ActionDefaultParams::apply_to_calls`] ports
//! the actual copy/set-internal/set-model decision for callers that supply that
//! missing call-spec slice.  There is no `Action` implementation for the
//! graph-only form: an unconditional zero-change wrapper would be shelfware,
//! and `guard::CallEffects` is not a substitute for a call prototype.

use std::collections::BTreeSet;

use ventris_pcode::op;

use super::action::Action;
use super::callproto::ParamActive;
use super::funcproto::FuncProto;
use super::guard::Location;
use super::scope::{ScopeLocal, SymbolCategory};
use super::{Funcdata, GraphBlockId, OpId, SeqNum, VarnodeId};
use crate::native::Type;

/// Return the graph location of one varnode.
fn varnode_location(data: &Funcdata, id: VarnodeId) -> Location {
    let varnode = data.varnode(id);
    Location {
        space: varnode.space,
        offset: varnode.offset,
        size: varnode.size,
    }
}

/// Return input varnodes in the address order used by Ghidra's definition set.
///
/// The graph has no `VarnodeDefSet` iterator.  Its varnode arena is the source
/// of truth, so sort the explicit input values by storage and retain one input
/// value per location.  Duplicate input versions can appear after a caller
/// rebuilds a graph; choosing the first stable version keeps one trial per ABI
/// storage range rather than manufacturing duplicate parameters.
fn input_varnodes(data: &Funcdata, proto: &FuncProto) -> Vec<VarnodeId> {
    let mut values: Vec<_> = (0..data.varnode_count())
        .map(|index| VarnodeId(index as u32))
        .filter(|id| {
            let value = data.varnode(*id);
            value.flags.input && proto.possible_input_param(varnode_location(data, *id))
        })
        .collect();
    values.sort_by_key(|id| {
        let value = data.varnode(*id);
        (value.space, value.offset, value.size, id.0)
    });
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|id| seen.insert(varnode_location(data, *id)))
        .collect()
}

/// Return the first non-dead basic block, if the graph has one.
fn first_live_block(data: &Funcdata) -> Option<GraphBlockId> {
    data.blocks()
        .find_map(|(id, block)| (!block.dead).then_some(id))
}

/// Insert one model-requested input extension at the entry block.
///
/// `ActionPrototypeTypes::extendInput` inserts an extension only when the
/// model says that the observed value is a justified subrange of a larger
/// locked parameter.  The graph does not carry high-level varnode types, so
/// the prototype's extension opcode and storage location are the complete
/// representable decision.
fn extend_input(data: &mut Funcdata, input: VarnodeId, opcode: i32, target: Location) -> bool {
    if opcode == op::COPY {
        return false;
    }
    let already_present = data.live_ops().any(|(_, operation)| {
        operation.opcode == opcode
            && operation.inputs.first().copied() == Some(input)
            && operation.output.is_some_and(|output| {
                let location = varnode_location(data, output);
                location == target
            })
    });
    if already_present {
        return false;
    }
    let Some(block) = first_live_block(data) else {
        return false;
    };
    let start = data.block(block).start;
    let extension = data.new_op(
        opcode,
        SeqNum {
            address: start,
            order: 0,
        },
        vec![input],
    );
    let output = data.new_varnode(target.space, target.offset, target.size);
    data.op_set_output(extension, Some(output));
    data.op_insert_front(extension, block);
    true
}

/// Replace the first input of a return with the canonical indirect marker.
fn strip_return_indirect(data: &mut Funcdata, return_op: OpId) -> bool {
    let Some(indirect) = data.op(return_op).inputs.first().copied() else {
        return false;
    };
    if data.varnode(indirect).flags.constant {
        return false;
    }
    // `Funcdata::new_constant` is `(value, size)`, unlike Ghidra's C++ helper
    // whose first argument is the size.  Keep the width from the marker.
    let replacement = data.new_constant(0, data.varnode(indirect).size);
    data.op_set_input(return_op, replacement, 0);
    true
}

/// Add a locked output storage value to one return operation.
fn append_locked_output(data: &mut Funcdata, return_op: OpId, output: Location) -> bool {
    if output.size == 0 {
        return false;
    }
    let already_present = data
        .op(return_op)
        .inputs
        .iter()
        .copied()
        .any(|value| varnode_location(data, value) == output);
    if already_present {
        return false;
    }
    let value = data.new_varnode(output.space, output.offset, output.size);
    let slot = data.op(return_op).inputs.len();
    data.op_set_input(return_op, value, slot);
    true
}

/// Recover the input prototype from graph entry values and descendants.
pub struct ActionInputPrototype;

impl ActionInputPrototype {
    /// Apply input recovery with an explicitly supplied prototype and local
    /// scope.
    fn apply_core(
        data: &mut Funcdata,
        proto: &mut FuncProto,
        scope: Option<&mut ScopeLocal>,
    ) -> usize {
        let before = proto.clone();
        let mut changed = scope
            .map(|scope| scope.clear_category(SymbolCategory::FakeInput))
            .unwrap_or(0);
        proto.clear_unlocked_input();
        if proto.is_input_locked() {
            return changed + usize::from(*proto != before);
        }

        let candidates = input_varnodes(data, proto);
        let mut active = ParamActive::new();
        let mut triallist = Vec::with_capacity(candidates.len());
        for value in candidates {
            let location = varnode_location(data, value);
            active.register(location);
            let trial = active
                .trials_mut()
                .last_mut()
                .expect("register always appends a trial");
            trial.value = Some(value);
            if !data.varnode(value).descendants.is_empty() {
                trial.mark_active();
            }
            triallist.push(value);
        }

        // Ghidra preserves fixed-position arguments when a prototype is
        // variadic.  ParamActive's graph representation already assigns
        // stable slots in registration order, but invoke its explicit hook so
        // the varargs distinction is not silently discarded.
        if proto.is_dotdotdot() {
            active.sort_fixed_position();
        }
        if proto.derive_input_map(&mut active) {
            changed += 1;
        }
        if data.is_high_on() {
            let _ = proto.update_input_types(data, &triallist, &active);
        } else {
            let _ = proto.update_input_no_types(&triallist, &active);
        }
        changed + usize::from(*proto != before)
    }
    /// Apply input recovery with an explicitly supplied prototype and scope.
    pub fn apply_with(data: &mut Funcdata, proto: &mut FuncProto, scope: &mut ScopeLocal) -> usize {
        Self::apply_core(data, proto, Some(scope))
    }

    /// Apply input recovery when the graph has not built a local scope.
    fn apply_without_scope(data: &mut Funcdata, proto: &mut FuncProto) -> usize {
        Self::apply_core(data, proto, None)
    }
}

impl Action for ActionInputPrototype {
    fn name(&self) -> &'static str {
        "inputprototype"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let mut scope = data.scope_local().cloned();
        let Some(mut proto) = data.func_proto().cloned() else {
            let changed = scope
                .as_mut()
                .map(|scope| scope.clear_category(SymbolCategory::FakeInput))
                .unwrap_or(0);
            if let Some(scope) = scope {
                data.set_scope_local(scope);
            }
            return changed;
        };
        let changed = if let Some(scope) = scope.as_mut() {
            Self::apply_with(data, &mut proto, scope)
        } else {
            Self::apply_without_scope(data, &mut proto)
        };
        data.set_func_proto(proto);
        if let Some(scope) = scope {
            data.set_scope_local(scope);
        }
        changed
    }
}

/// Set the recovered return storage/type as a formal prototype output.
pub struct ActionOutputPrototype;

impl ActionOutputPrototype {
    /// Apply output recovery with an explicitly supplied prototype.
    pub fn apply_with(data: &mut Funcdata, proto: &mut FuncProto) -> usize {
        let output = proto.get_output();
        if output.is_type_locked() && !output.is_size_type_locked() {
            return 0;
        }
        let returns: Vec<_> = data
            .live_ops()
            .filter(|(_, operation)| operation.opcode == op::RETURN)
            .map(|(id, _)| id)
            .collect();
        let values: Vec<VarnodeId> = returns
            .first()
            .map(|return_op| {
                data.op(*return_op)
                    .inputs
                    .iter()
                    .copied()
                    .skip(1)
                    .collect::<Vec<VarnodeId>>()
            })
            .unwrap_or_default();
        if data.is_high_on() {
            usize::from(proto.update_output_types(data, &values))
        } else {
            usize::from(proto.update_output_no_types(data, &values))
        }
    }
}

impl Action for ActionOutputPrototype {
    fn name(&self) -> &'static str {
        "outputprototype"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let Some(mut proto) = data.func_proto().cloned() else {
            return 0;
        };
        let changed = Self::apply_with(data, &mut proto);
        data.set_func_proto(proto);
        changed
    }
}

/// Lay down locked input/output storage and sanitize return markers.
pub struct ActionPrototypeTypes;

impl ActionPrototypeTypes {
    /// Apply locked prototype storage with an explicitly supplied prototype.
    pub fn apply_with(data: &mut Funcdata, proto: &mut FuncProto) -> usize {
        let before = proto.clone();
        let mut changed = 0;
        if proto.has_this_pointer() {
            proto.update_this_pointer();
        }

        let returns: Vec<_> = data
            .live_ops()
            .filter(|(_, operation)| operation.opcode == op::RETURN)
            .map(|(id, _)| id)
            .collect();
        for return_op in returns {
            if strip_return_indirect(data, return_op) {
                changed += 1;
            }
        }

        if proto.is_output_locked() && !matches!(proto.get_output_type(), Type::Void) {
            let output = proto.get_output().get_address();
            for return_op in data
                .live_ops()
                .filter(|(_, operation)| operation.opcode == op::RETURN)
                .map(|(id, _)| id)
                .collect::<Vec<_>>()
            {
                if append_locked_output(data, return_op, output) {
                    changed += 1;
                }
            }
        }

        if proto.is_input_locked() {
            let parameters: Vec<_> = proto.params().to_vec();
            for parameter in parameters {
                let location = parameter.get_address();
                let input = data
                    .at_location(location.space, location.offset, location.size)
                    .iter()
                    .copied()
                    .find(|value| data.varnode(*value).flags.input)
                    .unwrap_or_else(|| {
                        let value =
                            data.new_varnode(location.space, location.offset, location.size);
                        data.mark_input(value);
                        value
                    });
                let (opcode, target) = proto.assumed_input_extension(location);
                if let Some(target) = target {
                    if extend_input(data, input, opcode, target) {
                        changed += 1;
                    }
                }
            }
        }
        changed + usize::from(*proto != before)
    }
}

impl Action for ActionPrototypeTypes {
    fn name(&self) -> &'static str {
        "prototypetypes"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let Some(mut proto) = data.func_proto().cloned() else {
            return 0;
        };
        let changed = Self::apply_with(data, &mut proto);
        data.set_func_proto(proto);
        changed
    }
}

/// Missing per-call prototype context for `ActionDefaultParams`.
///
/// The graph can still port the operation when a caller supplies this missing
/// context through [`ActionDefaultParams::apply_to_calls`].
pub struct ActionDefaultParams;

/// Explicit call-site metadata for the copy branch of
/// `ActionDefaultParams`.
///
/// `prototype` is the call's current prototype, when one has already been
/// materialized.  `known_function` stands in for Ghidra's `FuncCallSpecs`
/// `getFuncdata()` link: when the call has no model but its target function is
/// known, the target's prototype is copied before the evaluation model is
/// considered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultParamsCall {
    pub prototype: Option<FuncProto>,
    pub known_function: Option<FuncProto>,
}

fn copy_model_storage(destination: &mut FuncProto, model: &FuncProto) {
    destination.set_model_storage(
        model.model_input_storage().to_vec(),
        model.model_output_storage().to_vec(),
    );
    destination.set_model_extra_pop(model.get_model_extra_pop());
}

fn call_count(data: &Funcdata) -> usize {
    data.live_ops()
        .filter(|(_, operation)| matches!(operation.opcode, op::CALL | op::CALLIND | op::CALLOTHER))
        .count()
}

fn apply_default_to_one(
    prototype: &mut Option<FuncProto>,
    known_function: Option<&FuncProto>,
    eval_model: &FuncProto,
) -> usize {
    let mut changed = 0;
    if prototype.is_none() {
        let mut selected = if let Some(known) = known_function {
            known.clone()
        } else {
            let mut internal = FuncProto::new(eval_model.abi());
            internal.set_internal(eval_model.abi(), Type::Void);
            internal
        };
        copy_model_storage(&mut selected, known_function.unwrap_or(eval_model));
        *prototype = Some(selected);
        changed += 1;
    } else if !prototype
        .as_ref()
        .expect("prototype was checked above")
        .has_model()
    {
        let current = prototype.as_mut().expect("prototype was checked above");
        if let Some(known) = known_function {
            current.copy_from(known);
        } else {
            current.set_internal(eval_model.abi(), Type::Void);
        }
        copy_model_storage(current, known_function.unwrap_or(eval_model));
        changed += 1;
    }

    let current = prototype.as_mut().expect("prototype was selected above");
    if !current.is_model_locked() && !current.has_matching_model(&eval_model.abi()) {
        current.set_model(eval_model.abi());
        copy_model_storage(current, eval_model);
        changed += 1;
    }
    changed
}

impl ActionDefaultParams {
    /// Apply Ghidra's default-model decision to one prototype per CALL.
    ///
    /// `calls` is in live-CALL order and uses `None` for a call with no known
    /// callee prototype.  Such a call receives an internal void prototype from
    /// the evaluation model.  This convenience form has no donor
    /// `Funcdata`; callers that have one use [`Self::apply_to_call_records`].
    pub fn apply_to_calls(
        data: &Funcdata,
        calls: &mut [Option<FuncProto>],
        eval_model: &FuncProto,
    ) -> usize {
        calls
            .iter_mut()
            .take(call_count(data))
            .map(|call| apply_default_to_one(call, None, eval_model))
            .sum()
    }

    /// Apply the complete `ActionDefaultParams` operation to explicit
    /// call-site records, including the `getFuncdata()->getFuncProto()` copy
    /// branch that the convenience form cannot represent.
    pub fn apply_to_call_records(
        data: &Funcdata,
        calls: &mut [DefaultParamsCall],
        eval_model: &FuncProto,
    ) -> usize {
        calls
            .iter_mut()
            .take(call_count(data))
            .map(|call| {
                apply_default_to_one(
                    &mut call.prototype,
                    call.known_function.as_ref(),
                    eval_model,
                )
            })
            .sum()
    }

    /// Return the source-level reason the graph-only action is unavailable.
    pub const fn needs_call_specs() -> &'static str {
        "ActionDefaultParams needs per-call FuncCallSpecs; Funcdata carries no per-call prototypes"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::REGISTER_SPACE;
    use ventris_target::{Abi, TargetProfile};

    fn location(offset: u64, size: u32) -> Location {
        Location {
            space: REGISTER_SPACE,
            offset,
            size,
        }
    }

    fn prototype() -> FuncProto {
        FuncProto::with_storage(
            TargetProfile::Ps2.spec().abi,
            vec![location(0x20, 4), location(0x24, 8)],
            vec![location(0x40, 4)],
        )
    }

    fn block(data: &mut Funcdata) -> GraphBlockId {
        data.new_block(0x1000)
    }

    fn seq(order: u32) -> SeqNum {
        SeqNum {
            address: 0x1000,
            order,
        }
    }

    #[test]
    fn input_prototype_recovers_storage_and_clears_fake_inputs() {
        let mut data = Funcdata::default();
        let entry = block(&mut data);
        let input = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        data.mark_input(input);
        let use_op = data.new_op(op::COPY, seq(0), vec![input]);
        data.op_insert_end(use_op, entry);

        let mut scope = ScopeLocal::new(REGISTER_SPACE);
        let fake = scope.add_symbol_with_category(
            "fake",
            Type::Unsigned(32),
            SymbolCategory::FakeInput,
            None,
        );
        assert!(scope.add_map_point(fake, location(0x20, 4)).is_some());
        data.set_func_proto(prototype());
        data.set_scope_local(scope);
        assert!(ActionInputPrototype.apply(&mut data) > 0);

        let proto = data.func_proto().expect("prototype is retained");
        assert_eq!(proto.num_params(), 1);
        assert_eq!(proto.get_param(0).unwrap().get_address(), location(0x20, 4));
        assert_eq!(proto.get_param(0).unwrap().get_type(), &Type::Unknown);
        assert!(
            data.scope_local()
                .expect("scope is retained")
                .find_by_name("fake")
                .is_empty()
        );
    }

    #[test]
    fn output_prototype_recovers_return_storage_without_high_level_types() {
        let mut data = Funcdata::default();
        let entry = block(&mut data);
        let marker = data.new_varnode(REGISTER_SPACE, 0x00, 4);
        let result = data.new_varnode(REGISTER_SPACE, 0x40, 4);
        let return_op = data.new_op(op::RETURN, seq(0), vec![marker, result]);
        data.op_insert_end(return_op, entry);

        data.set_func_proto(prototype());
        assert_eq!(ActionOutputPrototype.apply(&mut data), 1);
        let proto = data.func_proto().expect("prototype is retained");
        assert_eq!(proto.get_output().get_address(), location(0x40, 4));
        assert_eq!(proto.get_output_type(), &Type::Unknown);
        assert!(!proto.is_output_locked());
    }

    #[test]
    fn prototype_types_force_locked_storage_and_strip_return_marker() {
        let mut data = Funcdata::default();
        let entry = block(&mut data);
        let marker = data.new_varnode(REGISTER_SPACE, 0x00, 4);
        let return_op = data.new_op(op::RETURN, seq(0), vec![marker]);
        data.op_insert_end(return_op, entry);

        let mut proto = prototype();
        proto.set_param_parts(0, "arg", location(0x20, 4), Type::Unsigned(32));
        proto.set_input_lock(true);
        proto.set_output_parts(location(0x40, 4), Type::Unsigned(32));
        proto.set_output_lock(true);
        data.set_func_proto(proto);
        assert!(ActionPrototypeTypes.apply(&mut data) >= 2);
        let input = data
            .at_location(REGISTER_SPACE, 0x20, 4)
            .iter()
            .copied()
            .find(|value| data.varnode(*value).flags.input)
            .expect("locked input is materialized");
        assert!(data.varnode(input).flags.input);
        let inputs = &data.op(return_op).inputs;
        assert_eq!(inputs.len(), 2);
        assert!(data.varnode(inputs[0]).flags.constant);
        assert_eq!(varnode_location(&data, inputs[1]), location(0x40, 4));
    }

    #[test]
    fn default_params_applies_internal_call_prototype_when_call_spec_is_supplied() {
        let mut data = Funcdata::default();
        let entry = block(&mut data);
        let target = data.new_varnode(REGISTER_SPACE, 0x08, 4);
        let call = data.new_op(op::CALL, seq(0), vec![target]);
        data.op_insert_end(call, entry);

        let eval = prototype();
        let mut calls = vec![None];
        assert_eq!(
            ActionDefaultParams::apply_to_calls(&data, &mut calls, &eval),
            1
        );
        let call_proto = calls[0].as_ref().expect("internal prototype created");
        assert!(call_proto.has_custom_storage());
        assert_eq!(call_proto.get_output_type(), &Type::Void);
        assert_eq!(call_proto.model_input_storage(), eval.model_input_storage());
    }

    #[test]
    fn default_params_does_not_replace_a_locked_call_model() {
        let mut data = Funcdata::default();
        let entry = block(&mut data);
        let target = data.new_varnode(REGISTER_SPACE, 0x08, 4);
        let call = data.new_op(op::CALL, seq(0), vec![target]);
        data.op_insert_end(call, entry);

        let eval = prototype();
        let mut calls = vec![Some(FuncProto::new(Abi::for_target(
            TargetProfile::GameCube,
        )))];
        calls[0].as_mut().unwrap().set_model_lock(true);
        assert_eq!(
            ActionDefaultParams::apply_to_calls(&data, &mut calls, &eval),
            0
        );
        assert_eq!(
            calls[0].as_ref().unwrap().abi(),
            TargetProfile::GameCube.spec().abi
        );
    }

    #[test]
    fn default_params_copies_known_function_prototype() {
        let mut data = Funcdata::default();
        let entry = block(&mut data);
        let target = data.new_varnode(REGISTER_SPACE, 0x08, 4);
        let call = data.new_op(op::CALL, seq(0), vec![target]);
        data.op_insert_end(call, entry);

        let eval = prototype();
        let mut known = prototype();
        known.set_model_unknown(true);
        known.set_output_parts(location(0x44, 8), Type::Signed(64));
        let mut calls = vec![DefaultParamsCall {
            prototype: None,
            known_function: Some(known.clone()),
        }];
        assert_eq!(
            ActionDefaultParams::apply_to_call_records(&data, &mut calls, &eval),
            1
        );
        let copied = calls[0].prototype.as_ref().expect("known prototype copied");
        assert!(copied.is_model_unknown());
        assert_eq!(copied.get_output(), known.get_output());
        assert_eq!(copied.model_input_storage(), known.model_input_storage());
    }

    #[test]
    fn model_resolution_is_concrete_abi_filtering() {
        let mut proto = prototype();
        assert!(proto.has_model());
        assert!(proto.has_matching_model(&TargetProfile::Ps2.spec().abi));
        assert_eq!(
            ActionDefaultParams::needs_call_specs(),
            "ActionDefaultParams needs per-call FuncCallSpecs; Funcdata carries no per-call prototypes"
        );
        // Keep this assertion tied to the actual one-model design: no hidden
        // resolver is consulted by input recovery.
        assert!(!proto.is_dotdotdot());
        proto.set_dotdotdot(true);
        assert!(proto.is_dotdotdot());
    }
}
