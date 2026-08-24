//! Variable naming for merged graph values, ported from Ghidra 12.1.3.
//!
//! Ghidra first links explicit symbols, then recovers names recommended by
//! callers, then assigns a stack/register/default name.  The graph API has no
//! symbol table, prototype parameters, or architecture object, so this pass
//! implements the evidence that survives in [`Funcdata`]: frame-relative
//! data-flow, unwritten register locations, and deterministic type-class
//! fallbacks.  The missing symbol/prototype layer is deliberately not guessed.
//!
//! Source authority: `ActionNameVars::apply`, `ActionNameVars::makeRec`,
//! `ActionNameVars::linkSpacebaseSymbol`, and `ActionNameVars::lookForFuncParamNames`
//! in `coreaction.cc`; `Funcdata::buildDynamicSymbol` in
//! `funcdata_varnode.cc` (the pinned source has no `nameRecommendation` or
//! `lookupUnmapped` symbol); stack naming in `ScopeLocal::buildVariableName`,
//! `ScopeLocal::collectNameRecs`, and
//! `ScopeLocal::recoverNameRecommendationsForSymbols` in `varmap.cc`; and
//! fallback naming in `ScopeInternal::buildVariableName` in `database.cc`,
//! plus `PrintLanguage::pushVnExplicit`/`PrintC::pushUnnamedLocation` in
//! `printlanguage.cc`/`printc.cc`, all at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use std::collections::{BTreeMap, BTreeSet};

use ventris_lifter::REGISTER_SPACE;
use ventris_pcode::op;

use crate::native::Type;

use super::action::Action;
use super::guard::Location;
use super::mergeaction::merge_all;
use super::types::{Types, infer_types};
use super::{Funcdata, VarnodeId};

/// Names assigned to merged variable groups.
///
/// Ghidra stores these on `HighVariable`/`Symbol`.  Ventris keeps naming as a
/// side result because [`Funcdata`] intentionally models only p-code data-flow.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Names {
    names: BTreeMap<u32, String>,
}

impl Names {
    /// Build one deterministic name for every non-constant variable group.
    ///
    /// `groups` is the same partition that Ghidra calls a `HighVariable`
    /// partition.  The closure is used for every varnode, including values
    /// that have no operation definition, so callers may pass a previously
    /// computed [`super::mergeaction::Variables::high_of`].
    pub fn of(
        data: &Funcdata,
        group_of: &dyn Fn(VarnodeId) -> u32,
        types: &Types,
        stack_pointer: Option<Location>,
    ) -> Self {
        let mut groups: BTreeMap<u32, Vec<VarnodeId>> = BTreeMap::new();
        for index in 0..data.varnode_count() {
            let value = VarnodeId(index as u32);
            groups.entry(group_of(value)).or_default().push(value);
        }

        let mut ordered: Vec<GroupInfo> = groups
            .into_iter()
            .filter_map(|(group, values)| {
                // Constants are equates/literals, not C variables.  Ghidra's
                // ActionNameVars can give an equate a symbol, but that symbol
                // table is outside the graph API and must not be fabricated.
                if values
                    .iter()
                    .all(|value| data.varnode(*value).flags.constant)
                {
                    return None;
                }
                let first_position = first_position(data, &values);
                Some(GroupInfo {
                    group,
                    values,
                    first_position,
                })
            })
            .collect();
        ordered.sort_by_key(|info| (info.first_position, info.group));

        let mut names = BTreeMap::new();
        let mut used = BTreeSet::new();
        let mut next_default = 1u32;

        for info in ordered {
            // This is the same priority as ActionNameVars after symbol
            // recovery: a location-specific stack name outranks a register
            // and both outrank the generic datatype name.
            let candidate = stack_pointer
                .and_then(|pointer| frame_name(data, &info.values, pointer))
                .or_else(|| register_name_for_group(data, &info.values))
                .unwrap_or_else(|| {
                    let prefix = type_prefix(types, &info.values);
                    let name = format!("{prefix}Var{next_default}");
                    next_default = next_default.saturating_add(1);
                    name
                });
            let name = make_unique(candidate, &mut used);
            used.insert(name.clone());
            names.insert(info.group, name);
        }

        Self { names }
    }

    /// Return the name assigned to a variable group.
    pub fn name_of_group(&self, group: u32) -> Option<&str> {
        self.names.get(&group).map(String::as_str)
    }
}

/// The final Ghidra variable-name action.
///
/// Naming itself is a side computation in this graph port: the action computes
/// the same merge partition and reports how many groups received a name.  The
/// renderer can retain a [`Names`] value built with an ABI-provided stack
/// pointer when it has that information.
pub struct ActionNameVars;

impl Action for ActionNameVars {
    fn name(&self) -> &'static str {
        "namevars"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        if data.varnode_count() == 0 || data.blocks().next().is_none() {
            return 0;
        }
        let variables = merge_all(data);
        let types = infer_types(data, &BTreeMap::new());
        let names = Names::of(data, &|value| variables.high_of(value), &types, None);
        names.names.len()
    }
}

struct GroupInfo {
    group: u32,
    values: Vec<VarnodeId>,
    first_position: (u64, u32, u32),
}

/// Return the first operation position contributing to a group.
///
/// Ghidra's naming order is address order, not varnode arena order.  An
/// input-only value has no definition, so its first read is the stable fall
/// back; the final varnode id tie-breaker keeps synthetic graphs reproducible.
fn first_position(data: &Funcdata, values: &[VarnodeId]) -> (u64, u32, u32) {
    let mut first_definition = (u64::MAX, u32::MAX, u32::MAX);
    let mut first_use = (u64::MAX, u32::MAX, u32::MAX);
    let mut has_definition = false;
    for value in values {
        if let Some(def) = data.varnode(*value).def {
            let operation = data.op(def);
            first_definition =
                first_definition.min((operation.seq.address, operation.seq.order, value.0));
            has_definition = true;
        }
        for descendant in &data.varnode(*value).descendants {
            let operation = data.op(*descendant);
            first_use = first_use.min((operation.seq.address, operation.seq.order, value.0));
        }
    }
    if has_definition {
        first_definition
    } else {
        first_use
    }
}

fn type_prefix(types: &Types, values: &[VarnodeId]) -> &'static str {
    // Type inference stores the strongest fact for each value.  Prefer the
    // first known fact in varnode order, which is deterministic for a merged
    // group and avoids letting hash/map iteration affect a name.
    let ty = values
        .iter()
        .filter_map(|value| types.get(*value))
        .find(|ty| !matches!(ty, Type::Unknown));
    match ty {
        Some(Type::Bool) => "b",
        Some(Type::Signed(_)) => "i",
        Some(Type::Unsigned(_)) | Some(Type::Unknown) | None => "u",
        Some(Type::Float(_)) => "f",
        Some(Type::Pointer(_)) => "p",
        Some(Type::Void) => {
            // Void cannot normally be attached to a Varnode.  Treating it as
            // unknown is safer than emitting a keyword-like pseudo-type.
            "u"
        }
    }
}

fn register_name_for_group(data: &Funcdata, values: &[VarnodeId]) -> Option<String> {
    values.iter().copied().find_map(|value| {
        let varnode = data.varnode(value);
        if varnode.space != REGISTER_SPACE
            || varnode.flags.constant
            || varnode.flags.written
            || varnode.def.is_some()
        {
            return None;
        }

        // `flags.written` is per SSA instance.  Register offsets identify
        // architectural locations rather than arbitrary byte ranges, so a
        // sub-register at another base offset does not write this register.
        let location_written = (0..data.varnode_count()).any(|index| {
            let other = data.varnode(VarnodeId(index as u32));
            other.space == varnode.space
                && other.offset == varnode.offset
                && (other.flags.written || other.def.is_some())
        });
        if location_written {
            return None;
        }

        // Funcdata carries p-code offsets, not the selected SLEIGH
        // Architecture.  The graph renderer's architectural callback uses the
        // same canonical spelling (`r<offset>`), so preserve it here rather
        // than guessing an ABI-specific register table.
        Some(format!("r{}", varnode.offset))
    })
}

fn frame_name(data: &Funcdata, values: &[VarnodeId], stack_pointer: Location) -> Option<String> {
    let mut best: Option<((u64, u32, u32), i64)> = None;
    for value in values {
        let Some(offset) = frame_offset(data, *value, stack_pointer) else {
            continue;
        };
        let position = value_position(data, *value);
        if best.is_none_or(|(old_position, _)| position < old_position) {
            best = Some((position, offset));
        }
    }
    best.map(|(_, offset)| {
        if offset < 0 {
            format!("local_{:x}", offset.unsigned_abs())
        } else if offset > 0 {
            format!("local_res{:x}", offset as u64)
        } else {
            "local_0".to_string()
        }
    })
}

fn value_position(data: &Funcdata, value: VarnodeId) -> (u64, u32, u32) {
    let mut best = (u64::MAX, u32::MAX, value.0);
    if let Some(def) = data.varnode(value).def {
        let operation = data.op(def);
        best = (operation.seq.address, operation.seq.order, value.0);
    }
    for descendant in &data.varnode(value).descendants {
        let operation = data.op(*descendant);
        best = best.min((operation.seq.address, operation.seq.order, value.0));
    }
    best
}

/// Trace an address (or a load result) back to the configured stack pointer.
///
/// This is intentionally a local copy of `deadcode.rs`'s frame trace.  The
/// naming pass cannot depend on dead-store elimination: a frame address can be
/// live solely because it is printed, and adding a cross-pass mutable helper
/// would change the ordering invariant of the action pipeline.
fn frame_offset(data: &Funcdata, value: VarnodeId, stack_pointer: Location) -> Option<i64> {
    let mut seen = BTreeSet::new();
    frame_offset_inner(data, value, stack_pointer, 0, false, &mut seen)
}

fn frame_offset_inner(
    data: &Funcdata,
    value: VarnodeId,
    stack_pointer: Location,
    depth: u32,
    derived: bool,
    seen: &mut BTreeSet<VarnodeId>,
) -> Option<i64> {
    if depth > 16 || !seen.insert(value) {
        return None;
    }
    let varnode = data.varnode(value);
    if varnode.space == stack_pointer.space && varnode.offset == stack_pointer.offset {
        // A bare stack-pointer input is a register, not local_0.  Once an
        // arithmetic edge has been crossed it denotes frame offset zero.
        if varnode.def.is_none() {
            return derived.then_some(0);
        }
    }

    let def = varnode.def?;
    let operation = data.op(def);
    match operation.opcode {
        op::COPY | op::CAST | op::INDIRECT => frame_offset_inner(
            data,
            operation.inputs.first().copied()?,
            stack_pointer,
            depth + 1,
            derived,
            seen,
        ),
        op::LOAD => frame_offset_inner(
            data,
            operation.inputs.get(1).copied()?,
            stack_pointer,
            depth + 1,
            derived,
            seen,
        ),
        op::MULTIEQUAL => {
            let mut common = None;
            for input in operation.inputs.iter().copied() {
                // Distinct phi inputs may share a predecessor path.  Each
                // branch gets its own cycle guard; sharing `seen` would make
                // the second path look recursive and lose a valid frame slot.
                let mut branch_seen = seen.clone();
                let offset = frame_offset_inner(
                    data,
                    input,
                    stack_pointer,
                    depth + 1,
                    derived,
                    &mut branch_seen,
                )?;
                if let Some(previous) = common {
                    if previous != offset {
                        return None;
                    }
                } else {
                    common = Some(offset);
                }
            }
            common
        }
        op::INT_ADD | op::PTRSUB => {
            let left = operation.inputs.first().copied()?;
            let right = operation.inputs.get(1).copied()?;
            let (base, constant) = if data.varnode(right).flags.constant {
                (left, right)
            } else if operation.opcode == op::INT_ADD && data.varnode(left).flags.constant {
                (right, left)
            } else {
                return None;
            };
            let base_offset = frame_offset_inner(data, base, stack_pointer, depth + 1, true, seen)?;
            base_offset.checked_add(sign_extend(
                data.varnode(constant).offset,
                data.varnode(constant).size,
            ))
        }
        op::PTRADD => {
            let base = operation.inputs.first().copied()?;
            let index = operation.inputs.get(1).copied()?;
            let scale = operation.inputs.get(2).copied()?;
            if !data.varnode(index).flags.constant || !data.varnode(scale).flags.constant {
                return None;
            }
            let index = sign_extend(data.varnode(index).offset, data.varnode(index).size);
            let scale = sign_extend(data.varnode(scale).offset, data.varnode(scale).size);
            let delta = index.checked_mul(scale)?;
            let base_offset = frame_offset_inner(data, base, stack_pointer, depth + 1, true, seen)?;
            base_offset.checked_add(delta)
        }
        op::INT_SUB => {
            let base = operation.inputs.first().copied()?;
            let constant = operation.inputs.get(1).copied()?;
            if !data.varnode(constant).flags.constant {
                return None;
            }
            let base_offset = frame_offset_inner(data, base, stack_pointer, depth + 1, true, seen)?;
            base_offset.checked_sub(sign_extend(
                data.varnode(constant).offset,
                data.varnode(constant).size,
            ))
        }
        _ => None,
    }
}

fn sign_extend(value: u64, size: u32) -> i64 {
    let bits = size.saturating_mul(8);
    if bits == 0 || bits >= 64 {
        return value as i64;
    }
    let sign = 1u64 << (bits - 1);
    let mask = (1u64 << bits) - 1;
    if value & sign != 0 {
        (value | !mask) as i64
    } else {
        value as i64
    }
}

const C_KEYWORDS: &[&str] = &[
    "alignas",
    "alignof",
    "and",
    "and_eq",
    "asm",
    "auto",
    "bitand",
    "bitor",
    "bool",
    "break",
    "case",
    "catch",
    "char",
    "class",
    "compl",
    "const",
    "consteval",
    "constexpr",
    "constinit",
    "const_cast",
    "continue",
    "co_await",
    "co_return",
    "co_yield",
    "decltype",
    "default",
    "delete",
    "do",
    "double",
    "dynamic_cast",
    "else",
    "enum",
    "explicit",
    "export",
    "extern",
    "false",
    "float",
    "for",
    "friend",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "mutable",
    "namespace",
    "new",
    "noexcept",
    "not",
    "not_eq",
    "nullptr",
    "operator",
    "or",
    "or_eq",
    "private",
    "protected",
    "public",
    "register",
    "reinterpret_cast",
    "requires",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "static_assert",
    "static_cast",
    "struct",
    "switch",
    "template",
    "this",
    "thread_local",
    "throw",
    "true",
    "try",
    "typedef",
    "typeid",
    "typename",
    "union",
    "unsigned",
    "using",
    "virtual",
    "void",
    "volatile",
    "wchar_t",
    "while",
    "xor",
    "xor_eq",
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_Bool",
    "_Complex",
    "_Generic",
    "_Imaginary",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
];

fn forbidden_name(name: &str) -> bool {
    C_KEYWORDS.contains(&name)
        || name.starts_with("arg")
        || name.starts_with("farg")
        || name.starts_with("varg")
}

fn make_unique(candidate: String, used: &mut BTreeSet<String>) -> String {
    let base = if forbidden_name(&candidate) {
        format!("var_{candidate}")
    } else {
        candidate
    };
    if !used.contains(&base) && !forbidden_name(&base) {
        return base;
    }
    for index in 0..=u32::MAX {
        let suffix = if index < 100 {
            format!("_{index:02}")
        } else {
            format!("_{index}")
        };
        let candidate = format!("{base}{suffix}");
        if !used.contains(&candidate) && !forbidden_name(&candidate) {
            return candidate;
        }
    }
    // The loop can only exhaust after allocating every possible String-sized
    // suffix, which is impossible for a finite graph.  Keep the branch for a
    // total function rather than panic in a renderer.
    format!("{base}_value")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SeqNum;
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    fn stack_pointer() -> Location {
        Location {
            space: REGISTER_SPACE,
            offset: 0x1d0,
            size: 4,
        }
    }

    fn names(data: &Funcdata, stack_pointer: Option<Location>) -> Names {
        let types = Types::default();
        Names::of(data, &|value| value.0, &types, stack_pointer)
    }

    fn frame_address(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        at: u64,
        offset: u64,
    ) -> VarnodeId {
        let sp = data.new_varnode(REGISTER_SPACE, 0x1d0, 4);
        let delta = data.new_constant(offset, 4);
        let add = data.new_op(op::INT_ADD, seq(at), vec![sp, delta]);
        let address = data.new_unique(4);
        data.op_set_output(add, Some(address));
        data.op_insert_end(add, block);
        address
    }

    #[test]
    fn frame_relative_values_use_local_and_reserved_argument_spellings() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let local = frame_address(&mut data, block, 0x1000, 0xffff_fff0);
        let incoming = frame_address(&mut data, block, 0x1004, 8);
        let unrelated_base = data.new_varnode(REGISTER_SPACE, 3, 4);
        let unrelated_delta = data.new_constant(4, 4);
        let unrelated_op = data.new_op(
            op::INT_ADD,
            seq(0x1008),
            vec![unrelated_base, unrelated_delta],
        );
        let unrelated = data.new_unique(4);
        data.op_set_output(unrelated_op, Some(unrelated));
        data.op_insert_end(unrelated_op, block);

        let named = names(&data, Some(stack_pointer()));
        assert_eq!(named.name_of_group(local.0), Some("local_10"));
        assert_eq!(named.name_of_group(incoming.0), Some("local_res8"));
        assert_ne!(named.name_of_group(unrelated.0), Some("local_4"));
    }

    #[test]
    fn an_unwritten_register_keeps_its_register_name_but_a_written_one_does_not() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let input = data.new_varnode(REGISTER_SPACE, 3, 4);
        data.mark_input(input);
        let constant = data.new_constant(7, 4);
        let write = data.new_op(op::COPY, seq(0x1000), vec![constant]);
        let written = data.new_varnode(REGISTER_SPACE, 4, 4);
        data.op_set_output(write, Some(written));
        data.op_insert_end(write, block);

        let named = names(&data, None);
        assert_eq!(named.name_of_group(input.0), Some("r3"));
        assert_ne!(named.name_of_group(written.0), Some("r4"));
    }

    #[test]
    fn names_are_unique_and_follow_definition_address_order() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left_constant = data.new_constant(1, 4);
        let left_op = data.new_op(op::COPY, seq(0x1010), vec![left_constant]);
        let left = data.new_unique(4);
        data.op_set_output(left_op, Some(left));
        data.op_insert_end(left_op, block);
        let right_constant = data.new_constant(2, 4);
        let right_op = data.new_op(op::COPY, seq(0x1008), vec![right_constant]);
        let right = data.new_unique(4);
        data.op_set_output(right_op, Some(right));
        data.op_insert_end(right_op, block);
        let literal = data.new_constant(3, 4);

        let first = names(&data, None);
        let second = names(&data, None);
        assert_eq!(first, second, "same graph must receive stable names");
        assert_ne!(first.name_of_group(left.0), first.name_of_group(right.0));
        assert_eq!(first.name_of_group(right.0), Some("uVar1"));
        assert_eq!(first.name_of_group(left.0), Some("uVar2"));
        assert_eq!(
            first.name_of_group(literal.0),
            None,
            "constants are not variables"
        );
    }

    #[test]
    fn generated_names_do_not_use_parameter_or_c_keyword_spellings() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let one = data.new_constant(1, 4);
        let copy = data.new_op(op::COPY, seq(0x1000), vec![one]);
        let value = data.new_unique(4);
        data.op_set_output(copy, Some(value));
        data.op_insert_end(copy, block);

        let named = names(&data, None);
        let name = named.name_of_group(value.0).expect("fallback name");
        assert_ne!(name, "arg0");
        assert_ne!(name, "return");
        assert!(!forbidden_name(name));
    }

    #[test]
    fn action_reports_named_groups_and_declines_an_empty_graph() {
        let action = ActionNameVars;
        let mut empty = Funcdata::default();
        assert_eq!(action.apply(&mut empty), 0);

        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let constant = data.new_constant(1, 4);
        let copy = data.new_op(op::COPY, seq(0x1000), vec![constant]);
        let value = data.new_unique(4);
        data.op_set_output(copy, Some(value));
        data.op_insert_end(copy, block);
        assert!(action.apply(&mut data) >= 1);
    }
}
