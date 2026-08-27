//! Expression marking and C cast decisions, ported from Ghidra 12.1.3.
//!
//! Source authority (commit `8b4c91d4d5bd1549622bfbade0df199585b98365`):
//! `ActionMarkExplicit::apply`, `ActionMarkExplicit::baseExplicit`,
//! `ActionMarkExplicit::multipleInteraction` (the pinned source's name for
//! the requested `ActionMarkExplicit::multiExplicit` pass),
//! `ActionMarkImplied::apply`, and
//! `ActionMarkImplied::checkImpliedCover` in `coreaction.cc`; the pinned
//! source has no literal `ActionMarkImplied::checkCycle` symbol, so this port's
//! `check_cycle` is the traversal guard that supplies that requested invariant;
//! `ActionHideShadow::apply`, `ActionCopyMarker::apply`,
//! `ActionLikelyTrash::apply`, and `ActionLikelyTrash::traceTrash` in
//! `coreaction.cc`; `CastStrategyC::castStandard`,
//! `CastStrategyC::isZextCast`, `CastStrategyC::isSextCast`,
//! `CastStrategyC::checkIntPromotionForCompare`,
//! `CastStrategyC::checkIntPromotionForExtension`,
//! `CastStrategyC::markExplicitUnsigned`, and
//! `CastStrategyC::markExplicitLongSize` in `cast.cc`; and
//! `ActionSetCasts::castInput`, `ActionSetCasts::castOutput`,
//! `ActionSetCasts::testStructOffset0`, and
//! `ActionSetCasts::tryResolutionAdjustment` in `coreaction.cc`.
//!
//! The graph intentionally does not carry Ghidra's HighVariable marks,
//! datatypes, union resolutions, shadow flags, non-printing op flags, or
//! unsigned/long constant-token flags, and Funcdata has no prototype
//! trash-register list.  This module therefore computes explicitness as an
//! immutable side result and leaves the metadata-only action wrappers as
//! analysis actions; it never abuses `volatile` or another unrelated graph
//! bit as a hidden mark.  The trash pass takes its register list explicitly;
//! the graph also lacks Ghidra's indirect-store/persistent distinction, so
//! this port treats every reachable `INDIRECT` as a terminal (stronger than
//! Ghidra on that boundary).  Struct/array offset-zero resolution and union
//! resolution are unavailable: retaining a cast where Ghidra can prove a
//! field-compatible pointer is stronger, while an unknown type's no-claim
//! result can decline a cast Ghidra would prove from a concrete size (weaker).

use std::collections::{BTreeMap, BTreeSet};

use ventris_pcode::op;

use crate::native::Type;

use super::action::Action;
use super::{Funcdata, OpId, VarnodeId};

const INT_BITS: u32 = 32;
const MAX_EXPRESSION_DEPTH: usize = 32;
const MAX_DUPLICATED_TERMS: usize = 2;

/// Which values are printed as their own expression rather than folded into a reader.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Explicit {
    values: BTreeSet<VarnodeId>,
}

impl Explicit {
    /// Compute Ghidra's explicit/implied split over the graph that this port can represent.
    pub fn of(data: &Funcdata) -> Self {
        let mut result = Self::default();
        for index in 0..data.varnode_count() {
            let value = VarnodeId(index as u32);
            let varnode = data.varnode(value);
            if varnode.flags.constant {
                continue;
            }

            // A free input with several readers still needs a source-level
            // name, even though Ghidra's first pass normally sees it through
            // its HighVariable rather than through baseExplicit.
            if varnode.def.is_none() {
                if varnode.descendants.len() > 1 {
                    result.values.insert(value);
                }
                continue;
            }

            let def = varnode.def.expect("checked above");
            let opcode = data.op(def).opcode;
            let mut force = varnode.descendants.len() != 1;

            // Calls and loads cannot be copied into each reader: doing so
            // duplicates an observable operation.  MULTIEQUAL/INDIRECT are
            // SSA markers with no ordinary expression spelling.
            force |= cannot_duplicate(opcode);
            force |= varnode.flags.volatile;

            // An address-tied result can be observed through an alias.  The
            // reduced graph has no `isAddrTied`; a non-unique, non-constant
            // storage location is the available stronger approximation.
            force |= !varnode.flags.unique;

            // Ghidra's `processMultiplier` limits duplicated terms.  The
            // graph has no architecture knob, so use the pinned default of 2
            // and also cap pathological expression depth for cycle-safe code.
            if varnode.descendants.len() > 1 {
                force |= expression_terms(data, value, &mut BTreeSet::new())
                    .is_some_and(|terms| terms > MAX_DUPLICATED_TERMS);
            }
            force |= expression_depth(data, value, &mut BTreeSet::new())
                .is_some_and(|depth| depth > MAX_EXPRESSION_DEPTH);
            force |= check_cycle(data, value);

            if force {
                result.values.insert(value);
            }
        }
        result
    }

    /// Whether `v` must be printed as a named/stand-alone expression.
    pub fn is_explicit(&self, v: VarnodeId) -> bool {
        self.values.contains(&v)
    }

    /// Number of values selected by the pass.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether no value was selected.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

fn cannot_duplicate(opcode: i32) -> bool {
    matches!(
        opcode,
        op::LOAD | op::CALL | op::CALLIND | op::CALLOTHER | op::MULTIEQUAL | op::INDIRECT
    )
}

fn expression_terms(
    data: &Funcdata,
    value: VarnodeId,
    active: &mut BTreeSet<VarnodeId>,
) -> Option<usize> {
    if !active.insert(value) {
        return Some(MAX_DUPLICATED_TERMS + 1);
    }
    let Some(def) = data.varnode(value).def else {
        active.remove(&value);
        return Some(1);
    };
    let operation = data.op(def);
    let terms = if operation.inputs.is_empty() || cannot_duplicate(operation.opcode) {
        1
    } else {
        operation
            .inputs
            .iter()
            .copied()
            .map(|input| expression_terms(data, input, active).unwrap_or(MAX_DUPLICATED_TERMS + 1))
            .fold(0usize, |total, part| total.saturating_add(part))
            .min(MAX_DUPLICATED_TERMS + 1)
    };
    active.remove(&value);
    Some(terms)
}

fn expression_depth(
    data: &Funcdata,
    value: VarnodeId,
    active: &mut BTreeSet<VarnodeId>,
) -> Option<usize> {
    if !active.insert(value) {
        return Some(MAX_EXPRESSION_DEPTH + 1);
    }
    let depth = data
        .varnode(value)
        .def
        .map(|def| {
            data.op(def)
                .inputs
                .iter()
                .copied()
                .map(|input| {
                    expression_depth(data, input, active).unwrap_or(MAX_EXPRESSION_DEPTH + 1)
                })
                .max()
                .unwrap_or(0)
                .saturating_add(1)
        })
        .unwrap_or(0);
    active.remove(&value);
    Some(depth)
}

/// Return true when following readers from `value` can reach `value` again.
///
/// This is the graph equivalent of the cycle guard needed before marking a
/// value implied.  A self-fed `MULTIEQUAL` is not a special case: its output
/// is reachable from its own reader edge and must remain explicit.
pub fn check_cycle(data: &Funcdata, value: VarnodeId) -> bool {
    let mut seen = BTreeSet::from([value]);
    let mut pending = vec![value];
    while let Some(current) = pending.pop() {
        let descendants: Vec<OpId> = data.varnode(current).descendants.iter().copied().collect();
        for reader in descendants {
            let Some(output) = data.op(reader).output else {
                continue;
            };
            if output == value {
                return true;
            }
            if seen.insert(output) {
                pending.push(output);
            }
        }
    }
    false
}
/// Preliminary explicit-value marking.

/// Converse implied-value marking, with cycle protection.

/// Hide duplicate shadow definitions when the graph can identify them.

/// Mark internal copies as non-printing when variable metadata is available.

/// A register location that the ABI says is trash after the function call.
pub type TrashRegister = (u32, u64, u32);

/// Identify likely-trash flows from an explicit set of ABI trash registers.
///
/// Ghidra registers this on the full loop (`coreaction.cc:5730`) and it reads
/// `ProtoModel::likelytrash`, filled from a cspec's `<likelytrash>` element.
///
/// **Not registered, because no data source for it exists here or in Ghidra for
/// these targets.** `<likelytrash>` appears in the shipped 12.1.3 cspecs only
/// under `Ghidra/Processors/x86` - x86gcc, x86win, x86borland, x86delphi and
/// x86-32-golang - and in none of MIPS, PowerPC or ARM, which are the
/// architectures this pipeline decompiles. `ventris-target` has no trash-register
/// field either, so there is nothing to construct the set from.
///
/// This is a stricter bar than the one `RuleFuncPtrEncoding` clears: that rule
/// reads `Funcdata::funcptr_align`, a field that exists and is zero, so
/// registering it is faithful and inert. Here the reader itself is absent, and
/// registering with a hardcoded empty set would assert an ABI fact no spec in
/// the tree states.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActionLikelyTrash {
    trash: BTreeSet<TrashRegister>,
}

impl ActionLikelyTrash {
    /// Construct the action with the caller's ABI trash-register list.
    pub fn new<I>(trash: I) -> Self
    where
        I: IntoIterator<Item = TrashRegister>,
    {
        Self {
            trash: trash.into_iter().collect(),
        }
    }

    /// Expose the supplied ABI boundary without fabricating architecture data.
    pub fn trash_registers(&self) -> &BTreeSet<TrashRegister> {
        &self.trash
    }

    /// Test one starting value and collect terminal INDIRECT/AND operations.
    pub fn trace_trash(&self, data: &Funcdata, value: VarnodeId) -> Option<BTreeSet<OpId>> {
        trace_trash(data, value)
    }
    /// Source-oriented spelling of [`Self::trace_trash`].
    #[allow(non_snake_case)]
    pub fn traceTrash(&self, data: &Funcdata, value: VarnodeId) -> Option<BTreeSet<OpId>> {
        self.trace_trash(data, value)
    }
}

impl Action for ActionLikelyTrash {
    fn name(&self) -> &'static str {
        "likelytrash"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let roots: Vec<VarnodeId> = self
            .trash
            .iter()
            .flat_map(|(space, offset, size)| {
                data.at_location(*space, *offset, *size).iter().copied()
            })
            .collect();
        let mut terminals = BTreeMap::<OpId, i32>::new();
        for root in roots {
            let Some(found) = trace_trash(data, root) else {
                continue;
            };
            for terminal in found {
                terminals
                    .entry(terminal)
                    .or_insert(data.op(terminal).opcode);
            }
        }

        let mut changed = 0;
        for (id, opcode) in terminals {
            match opcode {
                op::INDIRECT => {
                    let Some(input) = data.op(id).inputs.first().copied() else {
                        continue;
                    };
                    let size = data
                        .op(id)
                        .output
                        .map(|output| data.varnode(output).size)
                        .unwrap_or_else(|| data.varnode(input).size);
                    if !data.varnode(input).flags.constant || data.varnode(input).offset != 0 {
                        let zero = data.new_constant(0, size);
                        data.op_set_input(id, zero, 0);
                        changed += 1;
                    }
                }
                op::INT_AND => {
                    let Some(mask) = data.op(id).inputs.get(1).copied() else {
                        continue;
                    };
                    let size = data.varnode(mask).size;
                    if !data.varnode(mask).flags.constant || data.varnode(mask).offset != 0 {
                        let zero = data.new_constant(0, size);
                        data.op_set_input(id, zero, 1);
                        changed += 1;
                    }
                }
                _ => {}
            }
        }
        changed
    }
}

/// Trace a value through only the operations Ghidra treats as likely trash.
///
/// `None` means a non-trash operation was reached or a merge/PIECE route did
/// not have every input on the traced set.  `Some` lists the terminal
/// operations that the caller may rewrite.
pub fn trace_trash(data: &Funcdata, root: VarnodeId) -> Option<BTreeSet<OpId>> {
    let mut marked = BTreeSet::from([root]);
    let mut pending = vec![root];
    let mut routes = BTreeSet::<OpId>::new();
    let mut terminal = BTreeSet::<OpId>::new();
    let mut route_outputs = BTreeMap::<OpId, VarnodeId>::new();
    let mut failed = false;

    while let Some(value) = pending.pop() {
        let descendants: Vec<OpId> = data.varnode(value).descendants.iter().copied().collect();
        for id in descendants {
            let operation = data.op(id);
            let Some(output) = operation.output else {
                failed = true;
                continue;
            };
            match operation.opcode {
                op::INDIRECT => {
                    terminal.insert(id);
                }
                op::SUBPIECE => {
                    if marked.insert(output) {
                        pending.push(output);
                    }
                }
                op::MULTIEQUAL | op::PIECE => {
                    routes.insert(id);
                    route_outputs.insert(id, output);
                }
                op::INT_AND if top_byte_mask(data, operation) => {
                    terminal.insert(id);
                }
                _ => failed = true,
            }
        }

        // A MULTIEQUAL/PIECE can be followed only after every incoming route
        // has been marked.  This mirrors countMarks() without hidden Varnode
        // marks and lets a later route make progress in the same traversal.
        let route_ids: Vec<OpId> = routes.iter().copied().collect();
        for id in route_ids {
            if marked.contains(&route_outputs[&id]) {
                continue;
            }
            let operation = data.op(id);
            if operation.inputs.iter().all(|input| marked.contains(input)) {
                let output = route_outputs[&id];
                if marked.insert(output) {
                    pending.push(output);
                }
            }
        }
    }

    if failed {
        return None;
    }
    for id in routes {
        if !data
            .op(id)
            .inputs
            .iter()
            .all(|input| marked.contains(input))
        {
            return None;
        }
    }
    Some(terminal)
}

fn top_byte_mask(data: &Funcdata, operation: &super::GraphOp) -> bool {
    let Some(mask) = operation.inputs.get(1).copied() else {
        return false;
    };
    let mask_vn = data.varnode(mask);
    if !mask_vn.flags.constant {
        return false;
    }
    let full = full_mask(mask_vn.size);
    let value = mask_vn.offset & full;
    [8u32, 16, 32].iter().any(|shift| {
        let shifted = if *shift >= 64 {
            0
        } else {
            (full << shift) & full
        };
        value == shifted
    })
}

fn full_mask(size: u32) -> u64 {
    match size {
        0 => 0,
        1..=7 => (1u64 << (size * 8)) - 1,
        _ => u64::MAX,
    }
}

/// Ghidra's C cast strategy. `from` is the current type and `to` is the
/// operation's required type; `Some(to.clone())` means a cast must be shown.
pub fn cast_standard(
    from: &Type,
    to: &Type,
    mut care_uint_int: bool,
    care_ptr_uint: bool,
) -> Option<Type> {
    if from == to {
        return None;
    }
    if matches!(from, Type::Void) {
        return Some(to.clone());
    }

    let mut required = to;
    let mut current = from;
    let mut through_pointer = false;
    while let (Type::Pointer(required_to), Type::Pointer(current_from)) = (required, current) {
        required = required_to;
        current = current_from;
        care_uint_int = true;
        through_pointer = true;
    }

    if matches!(required, Type::Void) || matches!(current, Type::Void) {
        return None;
    }
    if matches!(required, Type::Unknown) || matches!(current, Type::Unknown) {
        return None;
    }

    if let (Some(required_bits), Some(current_bits)) =
        (storage_bits(required), storage_bits(current))
        && required_bits != current_bits
    {
        return Some(to.clone());
    }

    match required {
        Type::Unsigned(_) => {
            if !care_uint_int && integerish(current) {
                return None;
            }
            if care_uint_int && matches!(current, Type::Unsigned(_) | Type::Bool) {
                return None;
            }
            if !care_ptr_uint && matches!(current, Type::Pointer(_)) {
                return None;
            }
        }
        Type::Signed(_) => {
            if !care_uint_int && integerish(current) {
                return None;
            }
            if care_uint_int && matches!(current, Type::Signed(_) | Type::Bool) {
                return None;
            }
        }
        Type::Bool => {
            if integerish(current) || matches!(current, Type::Pointer(_)) {
                return None;
            }
        }
        Type::Pointer(_) => {
            // A pointer and an integer have the same storage width on the
            // target, but C still requires the conversion to be spelled.
            return Some(to.clone());
        }
        Type::Float(_) | Type::Void | Type::Unknown => {}
    }

    if through_pointer && (matches!(required, Type::Unknown) || matches!(current, Type::Unknown)) {
        return None;
    }
    Some(to.clone())
}

fn integerish(ty: &Type) -> bool {
    matches!(ty, Type::Unsigned(_) | Type::Signed(_) | Type::Bool)
}

fn storage_bits(ty: &Type) -> Option<u32> {
    match ty {
        Type::Unsigned(bits) | Type::Signed(bits) | Type::Float(bits) => Some(*bits),
        Type::Bool => Some(8),
        Type::Pointer(_) => Some(64),
        Type::Unknown | Type::Void => None,
    }
}

fn extension_for_type(ty: &Type) -> u8 {
    match ty {
        Type::Unsigned(_) | Type::Bool => EXT_UNSIGNED,
        Type::Signed(_) => EXT_SIGNED,
        _ => EXT_UNKNOWN,
    }
}

const EXT_UNSIGNED: u8 = 1;
const EXT_SIGNED: u8 = 2;
const EXT_EITHER: u8 = EXT_UNSIGNED | EXT_SIGNED;
const EXT_UNKNOWN: u8 = 0;
const EXT_NONE: u8 = 4;

fn local_extension(data: &Funcdata, value: VarnodeId, ty: &Type) -> u8 {
    let natural = extension_for_type(ty);
    if data.varnode(value).flags.constant {
        let bits = data.varnode(value).size.saturating_mul(8);
        if bits == 0 || bits >= 64 || data.varnode(value).offset & (1u64 << (bits - 1)) == 0 {
            return EXT_EITHER;
        }
    }
    natural
}

fn promotion_extension(data: &Funcdata, value: VarnodeId, ty: &Type) -> u8 {
    let varnode = data.varnode(value);
    if varnode.size.saturating_mul(8) >= INT_BITS {
        return EXT_NONE;
    }
    if varnode.flags.constant {
        return local_extension(data, value, ty);
    }
    let Some(def) = varnode.def else {
        // This is precisely UNKNOWN_PROMOTION in CastStrategyC: a free
        // input's signedness is not recoverable from p-code alone.
        return EXT_UNKNOWN;
    };
    let opcode = data.op(def).opcode;
    match opcode {
        // A BOOL operation is already a source-level boolean result; the
        // C++ intPromotionType switch therefore reports NO_PROMOTION here.
        op::BOOL_NEGATE | op::BOOL_XOR | op::BOOL_AND | op::BOOL_OR => EXT_NONE,
        // These operations introduce a value whose source-level integer
        // promotion is not represented by this p-code edge.
        op::COPY
        | op::MULTIEQUAL
        | op::INDIRECT
        | op::CAST
        | op::LOAD
        | op::CALL
        | op::CALLIND
        | op::CALLOTHER => EXT_NONE,
        op::INT_AND => {
            let operation = data.op(def);
            let mut result = EXT_UNKNOWN;
            for input in operation.inputs.iter().rev().copied() {
                let ext = local_extension_context(data, input);
                if ext & EXT_UNSIGNED != 0 {
                    result = EXT_UNSIGNED;
                    break;
                }
            }
            result
        }
        op::INT_RIGHT => data
            .op(def)
            .inputs
            .first()
            .copied()
            .map_or(EXT_UNKNOWN, |input| {
                let ext = local_extension_context(data, input);
                if ext & EXT_UNSIGNED != 0 {
                    ext
                } else {
                    EXT_UNKNOWN
                }
            }),
        op::INT_SRIGHT => data
            .op(def)
            .inputs
            .first()
            .copied()
            .map_or(EXT_UNKNOWN, |input| {
                let ext = local_extension_context(data, input);
                if ext & EXT_SIGNED != 0 {
                    ext
                } else {
                    EXT_UNKNOWN
                }
            }),
        op::INT_XOR | op::INT_OR | op::INT_DIV | op::INT_REM => {
            let inputs = data.op(def).inputs.iter().copied();
            if inputs.clone().count() >= 2
                && inputs
                    .map(|input| local_extension_context(data, input))
                    .all(|ext| ext & EXT_UNSIGNED != 0)
            {
                EXT_UNSIGNED
            } else {
                EXT_UNKNOWN
            }
        }
        op::INT_SDIV | op::INT_SREM => {
            let inputs = data.op(def).inputs.iter().copied();
            if inputs.clone().count() >= 2
                && inputs
                    .map(|input| local_extension_context(data, input))
                    .all(|ext| ext & EXT_SIGNED != 0)
            {
                EXT_SIGNED
            } else {
                EXT_UNKNOWN
            }
        }
        op::INT_NEGATE | op::INT_2COMP => {
            data.op(def)
                .inputs
                .first()
                .copied()
                .map_or(EXT_UNKNOWN, |input| {
                    let ext = local_extension_context(data, input);
                    if ext & EXT_SIGNED != 0 {
                        EXT_SIGNED
                    } else {
                        EXT_UNKNOWN
                    }
                })
        }
        // Addition, subtraction, multiplication, and left shift do not let
        // CastStrategyC prove an extension direction from one edge.
        op::INT_ADD | op::INT_SUB | op::INT_MULT | op::INT_LEFT | op::PTRADD | op::PTRSUB => {
            EXT_UNKNOWN
        }
        _ => EXT_NONE,
    }
}

fn local_extension_context(data: &Funcdata, value: VarnodeId) -> u8 {
    let ty = inferred_type(data, value);
    let varnode = data.varnode(value);
    if varnode.flags.constant {
        return local_extension(data, value, &ty);
    }
    if Explicit::of(data).is_explicit(value) {
        return extension_for_type(&ty);
    }
    let Some(def) = varnode.def else {
        return EXT_UNKNOWN;
    };
    match data.op(def).opcode {
        op::BOOL_NEGATE | op::BOOL_XOR | op::BOOL_AND | op::BOOL_OR => EXT_EITHER,
        op::CAST | op::LOAD | op::CALL | op::CALLIND | op::CALLOTHER => extension_for_type(&ty),
        op::INT_AND => data
            .op(def)
            .inputs
            .iter()
            .rev()
            .copied()
            .find_map(|input| {
                data.varnode(input)
                    .flags
                    .constant
                    .then(|| local_extension(data, input, &inferred_type(data, input)))
            })
            .unwrap_or(EXT_UNKNOWN),
        _ => EXT_UNKNOWN,
    }
}

fn inferred_type(data: &Funcdata, value: VarnodeId) -> Type {
    super::types::infer_types(data, &BTreeMap::new())
        .get(value)
        .cloned()
        .unwrap_or_else(|| Type::Unsigned(data.varnode(value).size.saturating_mul(8)))
}

/// Return true when C's comparison promotion does not satisfy `ty`, so the
/// required input type must be written as a cast.  This mirrors
/// `CastStrategyC::checkIntPromotionForCompare`'s true = cast-required result.
pub fn int_promotion_for_compare(data: &Funcdata, value: VarnodeId, ty: &Type) -> bool {
    let source = inferred_type(data, value);
    let extension = promotion_extension(data, value, &source);
    if extension == EXT_NONE {
        return false;
    }
    if extension == EXT_UNKNOWN || extension_for_type(ty) == EXT_UNKNOWN {
        return true;
    }
    (extension & extension_for_type(ty)) == 0
}

/// Return true when C's promotion extension disagrees with the explicit ZEXT
/// or SEXT input type `ty`, requiring a cast before that extension.
pub fn int_promotion_for_extension(data: &Funcdata, value: VarnodeId, ty: &Type) -> bool {
    let source = inferred_type(data, value);
    let extension = promotion_extension(data, value, &source);
    if extension == EXT_NONE {
        return false;
    }
    if extension == EXT_UNKNOWN {
        return true;
    }
    let required = extension_for_type(ty);
    required == EXT_UNKNOWN || (extension & required) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{CONST_SPACE, REGISTER_SPACE};

    fn seq(address: u64, order: u32) -> super::super::SeqNum {
        super::super::SeqNum { address, order }
    }

    #[test]
    fn two_readers_are_explicit_but_one_reader_is_foldable() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let constant = data.new_constant(7, 4);
        let definition = data.new_op(op::COPY, seq(0x1000, 0), vec![constant]);
        let value = data.new_unique(4);
        data.op_set_output(definition, Some(value));
        data.op_insert_end(definition, block);
        let one = data.new_op(op::RETURN, seq(0x1004, 0), vec![value]);
        data.op_insert_end(one, block);
        assert!(!Explicit::of(&data).is_explicit(value));
        let two = data.new_op(op::RETURN, seq(0x1008, 0), vec![value]);
        data.op_insert_end(two, block);
        assert!(Explicit::of(&data).is_explicit(value));
    }

    #[test]
    fn load_is_explicit_even_with_one_reader() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let space = data.new_constant(u64::from(CONST_SPACE), 4);
        let address = data.new_constant(0x2000, 4);
        let load = data.new_op(op::LOAD, seq(0x1000, 0), vec![space, address]);
        let value = data.new_unique(4);
        data.op_set_output(load, Some(value));
        data.op_insert_end(load, block);
        let ret = data.new_op(op::RETURN, seq(0x1004, 0), vec![value]);
        data.op_insert_end(ret, block);
        assert!(Explicit::of(&data).is_explicit(value));
    }

    #[test]
    fn cast_standard_leaves_c_integer_conversion_and_marks_real_conversion() {
        assert_eq!(
            cast_standard(&Type::Unsigned(32), &Type::Signed(32), false, false),
            None
        );
        assert_eq!(
            cast_standard(
                &Type::Unsigned(32),
                &Type::Pointer(Box::new(Type::Unsigned(8))),
                false,
                true
            ),
            Some(Type::Pointer(Box::new(Type::Unsigned(8))))
        );
    }

    #[test]
    fn comparison_and_extension_promotions_have_different_rules() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_constant(0xff, 1);
        let right = data.new_constant(0xff, 1);
        let mask = data.new_op(op::INT_AND, seq(0x1000, 0), vec![left, right]);
        let narrow = data.new_unique(1);
        data.op_set_output(mask, Some(narrow));
        data.op_insert_end(mask, block);
        // An AND with a high-bit mask has a known unsigned extension;
        // comparing it with signed int requires a cast, while an explicit
        // zero extension agrees with it.
        assert!(int_promotion_for_compare(&data, narrow, &Type::Signed(32)));
        assert!(!int_promotion_for_extension(
            &data,
            narrow,
            &Type::Unsigned(8)
        ));
    }

    #[test]
    fn cycle_guard_rejects_a_value_reaching_itself() {
        let mut data = Funcdata::default();
        let plain = data.new_unique(4);
        assert!(!check_cycle(&data, plain));
        let block = data.new_block(0x1000);
        let value = data.new_unique(4);
        let copy = data.new_op(op::COPY, seq(0x1000, 0), vec![value]);
        data.op_set_output(copy, Some(value));
        data.op_insert_end(copy, block);
        assert!(check_cycle(&data, value));
        assert!(Explicit::of(&data).is_explicit(value));
    }

    #[test]
    fn trash_trace_requires_the_supplied_register_list() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let trash = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.mark_input(trash);
        let indirect = data.new_op(op::INDIRECT, seq(0x1000, 0), vec![trash]);
        let after = data.new_unique(4);
        data.op_set_output(indirect, Some(after));
        data.op_insert_end(indirect, block);
        let none = ActionLikelyTrash::new([]).apply(&mut data);
        assert_eq!(none, 0);
        let action = ActionLikelyTrash::new([(REGISTER_SPACE, 8, 4)]);
        assert_eq!(action.apply(&mut data), 1);
        assert_eq!(data.varnode(data.op(indirect).inputs[0]).offset, 0);
    }
}
