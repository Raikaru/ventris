//! Promotion of recovered parameter trials into a function prototype.
//!
//! This is the graph-facing part of Ghidra 12.1.3's
//! `FuncProto::updateInputTypes` and `FuncProto::updateOutputTypes`
//! (`fspec.cc:4052-4087`, `fspec.cc:4136-4162`), driven by the trial
//! decisions made by `ActionInputPrototype` and `ActionOutputPrototype`
//! (`coreaction.cc:4758-4813`, `coreaction.cc:4816-4832`).
//!
//! [`ParamActive`] already owns the recovered trial order and the active/
//! inactive decision.  This module deliberately does not recover trials a
//! second time: it consumes only the contiguous prefix returned by
//! [`ParamActive::used`], resolves each trial's graph type, and replaces the
//! unlocked prototype description with the survivors.

use super::callproto::{ParamActive, Trial};
use super::funcproto::{FuncProto, ProtoParameter};
use super::guard::Location;
use super::{Funcdata, VarnodeId};
use crate::native::Type;

/// Return the concrete graph storage of a varnode.
fn varnode_location(data: &Funcdata, value: VarnodeId) -> Location {
    let varnode = data.varnode(value);
    Location {
        space: varnode.space,
        offset: varnode.offset,
        size: varnode.size,
    }
}

/// Return the type recovered for a varnode, or `Type::Unknown` when the graph
/// has no type entry for it.
///
/// `FuncProto::updateInputTypes` and `updateOutputTypes` read the high-level
/// type attached to the trial Varnode.  The graph stores that result in its
/// cached rich type table instead, so lowering it here is the equivalent
/// boundary operation.  A missing entry is possible for an isolated value;
/// Ghidra's undefined high-level type is represented by `Type::Unknown`.
fn recovered_type(data: &Funcdata, value: VarnodeId) -> Type {
    data.recovered_types()
        .1
        .get(value)
        .map(super::typefactory::to_native)
        .unwrap_or(Type::Unknown)
}

/// Build one input parameter from one surviving trial.
/// One parameter for one surviving trial.
///
/// A trial can survive without a value. `ParamListStandard::buildTrialMap`
/// keeps an unreferenced trial that sits before a referenced one, because the
/// convention still passes something in that slot even when the function
/// ignores it - so the parameter exists and only its type is unknown. Its
/// storage comes from the trial either way, which is why `updateInputTypes`
/// reads the trial's address rather than a value's.
fn input_parameter(data: &Funcdata, trial: &Trial) -> ProtoParameter {
    let ty = match trial.value {
        Some(value) => recovered_type(data, value),
        None => Type::Unsigned(trial.location.size.saturating_mul(8)),
    };
    ProtoParameter::new("", trial.location, ty)
}

/// Promote the surviving input trials into `proto`.
///
/// This follows `FuncProto::updateInputTypes`: an input-locked prototype is
/// untouched; otherwise all old inputs are discarded and one unnamed
/// [`ProtoParameter`] is installed for each used trial in trial order.  The
/// graph's `ParamActive::used` prefix is important: an active trial after the
/// first inactive/no-use trial is not a formal parameter.
///
/// The return value is one when the prototype changed and zero otherwise,
/// matching the graph action convention.
pub fn promote_input_trials(data: &Funcdata, proto: &mut FuncProto, active: &ParamActive) -> usize {
    if proto.is_input_locked() {
        return 0;
    }

    let promoted: Vec<ProtoParameter> = active
        .used()
        .into_iter()
        .map(|trial| input_parameter(data, trial))
        .collect();

    let changed = proto.params() != promoted;
    if changed {
        // `clearAllInputs` in Ghidra removes the unlocked input descriptions
        // while retaining prototype lock state.  `clear_unlocked_input` is
        // the graph equivalent; `clear_input` would also release the lock.
        proto.clear_unlocked_input();
        for parameter in promoted {
            proto.add_param(parameter);
        }
    }
    // Ghidra calls updateThisPointer after rebuilding the input store even if
    // no parameter was added.  Keep the same invariant for an existing list.
    proto.update_this_pointer();
    usize::from(changed)
}

/// Promote the first surviving output trial into `proto`.
///
/// Ghidra's output action supplies at most one Varnode to
/// `FuncProto::updateOutputTypes`.  The graph's active output container uses
/// the same convention: only the first member of `active.used()` is a formal
/// output.  An ordinary unlocked output is cleared when there is no survivor;
/// a type-locked output is never changed, while a size-locked unknown may be
/// refined only when the trial has exactly the locked storage.
///
/// The return value is one when the prototype changed and zero otherwise.
pub fn promote_output_trials(
    data: &Funcdata,
    proto: &mut FuncProto,
    active: &ParamActive,
) -> usize {
    let output = proto.get_output();
    if output.is_type_locked() && !output.is_size_type_locked() {
        return 0;
    }

    let first = active.used().into_iter().next();
    let value = first.and_then(|trial| trial.value);

    if output.is_type_locked() {
        // The only remaining locked case is a size lock.  Ghidra refuses to
        // replace its storage, and only overrides the type for an exact
        // matching trial.
        let Some(value) = value else {
            return 0;
        };
        let location = varnode_location(data, value);
        if location != output.get_address() {
            return 0;
        }
        let Some(ty) = data
            .recovered_types()
            .1
            .get(value)
            .map(super::typefactory::to_native)
        else {
            return 0;
        };
        return usize::from(proto.get_output_mut().override_size_lock_type(ty));
    }

    let Some(value) = value else {
        let replacement = ProtoParameter::void();
        let changed = proto.get_output() != &replacement;
        if changed {
            // `store->clearOutput()` in Ghidra removes the output
            // description; it does not alter other prototype hints.
            proto.set_output(replacement);
        }
        return usize::from(changed);
    };

    // Unlike input promotion, updateOutputTypes takes the address from the
    // Varnode itself (fspec.cc:4157), not from a ParamTrial address.
    let location = varnode_location(data, value);
    let replacement = ProtoParameter::new("", location, recovered_type(data, value));
    let changed = proto.get_output() != &replacement;
    if changed {
        proto.set_output(replacement);
    }
    usize::from(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SeqNum;
    use ventris_lifter::REGISTER_SPACE;
    use ventris_target::TargetProfile;

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
            vec![location(0x20, 4), location(0x24, 8), location(0x2c, 4)],
            vec![location(0x40, 4)],
        )
    }

    fn input_graph() -> (Funcdata, [VarnodeId; 3]) {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let mut values = [VarnodeId(0); 3];
        for (index, (offset, size)) in [(0x20, 4), (0x24, 8), (0x2c, 4)].into_iter().enumerate() {
            let value = data.new_varnode(REGISTER_SPACE, offset, size);
            data.mark_input(value);
            let use_value = data.new_unique(size);
            let copy = data.new_op(
                ventris_pcode::op::COPY,
                SeqNum {
                    address: 0x1000 + index as u64,
                    order: 0,
                },
                vec![value],
            );
            data.op_set_output(copy, Some(use_value));
            data.op_insert_end(copy, block);
            values[index] = value;
        }
        (data, values)
    }

    fn active_with_values(values: [VarnodeId; 3]) -> ParamActive {
        let mut active = ParamActive::new();
        for (index, value) in values.into_iter().enumerate() {
            active.register(location(
                [0x20_u64, 0x24, 0x2c][index],
                [4_u32, 8, 4][index],
            ));
            let trial = active
                .trials_mut()
                .last_mut()
                .expect("register appends a trial");
            trial.value = Some(value);
            trial.mark_active();
        }
        active
    }

    #[test]
    fn input_promotion_keeps_only_used_prefix_with_storage_and_types() {
        let (data, values) = input_graph();
        let mut active = active_with_values(values);
        active
            .trials_mut()
            .get_mut(1)
            .expect("second trial")
            .mark_no_use();

        let mut proto = prototype();
        assert_eq!(promote_input_trials(&data, &mut proto, &active), 1);
        assert_eq!(proto.num_params(), 1);
        assert_eq!(proto.get_param(0).unwrap().get_address(), location(0x20, 4));
        assert_eq!(proto.get_param(0).unwrap().get_type(), &Type::Unsigned(32));
    }

    #[test]
    fn output_promotion_uses_surviving_trial_storage_and_type() {
        let (mut data, values) = input_graph();
        let block = data.blocks().next().expect("input block").0;
        let marker = data.new_constant(0, 4);
        let ret = data.new_op(
            ventris_pcode::op::RETURN,
            SeqNum {
                address: 0x1010,
                order: 0,
            },
            vec![marker, values[1]],
        );
        data.op_insert_end(ret, block);

        let mut active = ParamActive::new();
        active.register(location(0x99, 1));
        let trial = active.trials_mut().last_mut().expect("output trial");
        trial.value = Some(values[1]);
        trial.mark_active();

        let mut proto = prototype();
        assert_eq!(promote_output_trials(&data, &mut proto, &active), 1);
        assert_eq!(proto.get_output().get_address(), location(0x24, 8));
        assert_eq!(proto.get_output_type(), &Type::Unsigned(64));
    }

    #[test]
    fn locked_prototype_is_left_untouched() {
        let (data, values) = input_graph();
        let active = active_with_values(values);

        let mut input_proto = prototype();
        input_proto.add_param_parts("old", location(0x70, 4), Type::Signed(32));
        input_proto.set_input_lock(true);
        let before_input = input_proto.clone();
        assert_eq!(promote_input_trials(&data, &mut input_proto, &active), 0);
        assert_eq!(input_proto, before_input);

        let mut output_proto = prototype();
        output_proto.set_output_parts(location(0x80, 4), Type::Signed(32));
        output_proto.set_output_lock(true);
        let before_output = output_proto.clone();
        assert_eq!(promote_output_trials(&data, &mut output_proto, &active), 0);
        assert_eq!(output_proto, before_output);
    }
}
