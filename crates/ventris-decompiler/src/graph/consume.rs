//! Convention-aware consumed-bit analysis, ported from Ghidra 12.1.3's
//! `ActionDeadCode` in `coreaction.cc`.
//!
//! [`super::deadcode::propagate`] reconstructs `Varnode::getConsume` by
//! walking backwards from observable p-code sinks.  Ghidra has one additional
//! source of liveness that is not an operation sink: storage which the current
//! function prototype says may carry an input.  `ActionDeadCode::apply` seeds
//! such storage before propagating, so an input that has no surviving reader is
//! not mistaken for an impossible parameter by the next prototype-recovery
//! pass.
//!
//! The graph does not carry Ghidra's address-space heritage delays or
//! `Varnode::addrforce`/`autoLive` state.  Its explicit prototype model is the
//! representable convention boundary, so this module uses
//! [`FuncProto::possible_input_param`] for each graph value.  That accessor
//! reads the model's input storage while the input is unlocked and the locked
//! `FuncProto` parameter storage when a prototype has fixed parameters.  The
//! `flags.input` bit is intentionally not a guard: Ghidra's pre-live storage
//! seed is not conditional on that bit, and adding the guard would hide the
//! missing convention seed rather than reproduce it.
//!
//! Source authority: `ActionDeadCode::apply` (especially
//! `coreaction.cc:3989-4069`), `ActionDeadCode::markConsumedParameters`
//! (`coreaction.cc:3885-3913`), and `FuncProto::possibleInputParam`
//! (`fspec.cc:4358-4388`) at Ghidra commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use std::collections::BTreeMap;

use super::deadcode;
use super::guard::Location;
use super::{Funcdata, VarnodeId};

/// Every bit represented by a graph varnode in the 64-bit consume domain.
///
/// Ghidra calls `pushConsumed(~((uintb)0), vn, ...)`, and its helper masks the
/// result to the varnode width.  The Rust graph stores consumed bits in a
/// `u64`, so widths beyond eight bytes are represented by all 64 bits, just as
/// the existing propagation does.
fn all_consumed(size: u32) -> u64 {
    match size {
        0 => 0,
        1..=7 => (1_u64 << (size * 8)) - 1,
        _ => u64::MAX,
    }
}

fn location(data: &Funcdata, value: VarnodeId) -> Location {
    let value = data.varnode(value);
    Location {
        space: value.space,
        offset: value.offset,
        size: value.size,
    }
}

/// Compute consumed bits from ordinary sinks and convention-claimed input
/// storage.
///
/// The ordinary backward propagation remains the source of all operation-flow
/// consumption.  The prototype seed is ORed into it rather than replacing it,
/// preserving partial masks already established by a STORE, RETURN, branch, or
/// call.  Values outside the convention's possible input storage are left at
/// the ordinary result (usually no entry, which means a zero mask to callers).
///
/// This deliberately does not require `VarnodeFlags::input`.  Ghidra's
/// pre-live storage seed in `ActionDeadCode::apply` walks every varnode in a
/// storage space before dead-code removal is allowed; the graph's prototype
/// storage is the narrower state it can express.  Over-seeding is conservative
/// (the zeroing arm fires less often), while under-seeding can delete a value
/// that prototype recovery still needs.
pub fn consume_masks(data: &Funcdata) -> BTreeMap<VarnodeId, u64> {
    let mut consumed = deadcode::propagate(data);
    let Some(proto) = data.func_proto() else {
        return consumed;
    };

    for index in 0..data.varnode_count() {
        let value = VarnodeId(index as u32);
        let varnode = data.varnode(value);
        let mask = all_consumed(varnode.size);
        if mask == 0 || !proto.possible_input_param(location(data, value)) {
            continue;
        }
        consumed
            .entry(value)
            .and_modify(|existing| *existing |= mask)
            .or_insert(mask);
    }
    consumed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::funcproto::FuncProto;
    use crate::native::Type;
    use ventris_lifter::REGISTER_SPACE;
    use ventris_target::{Abi, TargetProfile};

    fn location(offset: u64, size: u32) -> Location {
        Location {
            space: REGISTER_SPACE,
            offset,
            size,
        }
    }

    fn prototype(input: &[Location]) -> FuncProto {
        FuncProto::with_storage(
            Abi::for_target(TargetProfile::Ps2),
            input.to_vec(),
            Vec::new(),
        )
    }

    #[test]
    fn convention_claimed_input_is_consumed_without_a_reader() {
        let mut data = Funcdata::default();
        let claimed = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        data.mark_input(claimed);
        // The storage seed is deliberately not an `input`-flag filter.  A
        // second version at the claimed location must receive the same seed.
        let claimed_version = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        let unclaimed = data.new_varnode(REGISTER_SPACE, 0x30, 4);
        data.mark_input(unclaimed);

        data.set_func_proto(prototype(&[location(0x20, 4)]));

        let consumed = consume_masks(&data);
        assert_eq!(consumed.get(&claimed), Some(&0xffff_ffff));
        assert_eq!(consumed.get(&claimed_version), Some(&0xffff_ffff));
        assert_eq!(consumed.get(&unclaimed).copied().unwrap_or(0), 0);
    }

    #[test]
    fn locked_parameter_storage_is_a_convention_sink() {
        let mut data = Funcdata::default();
        let parameter = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        // The seed must be about claimed storage, not a reader in the graph.
        data.mark_input(parameter);

        let mut proto = prototype(&[location(0x20, 4)]);
        proto.add_param_parts("value", location(0x20, 4), Type::Unsigned(32));
        proto.set_input_lock(true);
        data.set_func_proto(proto);

        let consumed = consume_masks(&data);
        assert_eq!(consumed.get(&parameter), Some(&0xffff_ffff));
    }

    #[test]
    fn ordinary_propagation_is_preserved_alongside_the_seed() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let claimed = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        data.mark_input(claimed);
        let constant = data.new_constant(1, 4);
        let add = data.new_op(
            ventris_pcode::op::INT_ADD,
            crate::graph::SeqNum {
                address: 0x1000,
                order: 0,
            },
            vec![claimed, constant],
        );
        let sum = data.new_unique(4);
        data.op_set_output(add, Some(sum));
        data.op_insert_end(add, block);
        let ret = data.new_op(
            ventris_pcode::op::RETURN,
            crate::graph::SeqNum {
                address: 0x1004,
                order: 0,
            },
            vec![sum, sum],
        );
        data.op_insert_end(ret, block);
        data.set_func_proto(prototype(&[location(0x20, 4)]));

        let consumed = consume_masks(&data);
        assert_eq!(consumed.get(&claimed), Some(&0xffff_ffff));
        assert_eq!(consumed.get(&sum), Some(&0xffff_ffff));
    }
}
