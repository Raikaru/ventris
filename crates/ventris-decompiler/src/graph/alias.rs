//! Stack-pointer alias analysis, ported from Ghidra 12.1.3's `AliasChecker`.
//!
//! `AliasChecker::gather` follows the incoming frame-base value through the
//! additive p-code operators.  When an additive chain reaches a non-additive
//! use, that chain result is an [`AddBase`] and its constant displacement is an
//! alias start.  `has_local_alias` then applies Ghidra's conservative stack
//! boundary rule to a location in the analyzed stack space.
//!
//! The graph stores the frame-base register as [`Funcdata::spacebase`], but it
//! does not have Ghidra's `AddrSpace` or `FuncProto` objects.  The caller names
//! the stack space explicitly.  [`AliasChecker::gather`] uses Ghidra's default
//! downward-stack boundary when no prototype ranges are available;
//! [`AliasChecker::gather_with_layout`] lets a later prototype consumer provide
//! the missing stack direction and local/parameter boundary.
//!
//! Source authority: `AliasChecker::gatherInternal`, `gather`,
//! `hasLocalAlias`, `sortAlias`, `gatherAdditiveBase`, and `gatherOffset` in
//! `varmap.cc`, plus `AliasChecker::AddBase` in `varmap.hh`, at Ghidra commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use std::collections::BTreeSet;

use ventris_pcode::op;

use super::guard::Location;
use super::stackframe::is_frame_derived;
use super::{Funcdata, OpId, VarnodeId};

/// A pointer result reached through an additive expression rooted at the
/// incoming spacebase, together with a possible non-constant index.
///
/// This is Ghidra's `AliasChecker::AddBase`.  `base` is the final Varnode of
/// the additive chain.  `index` is the most recent non-constant additive term,
/// or `None` when the chain contains constants only.  The records and
/// [`AliasChecker::get_alias`] are kept in parallel, just as Ghidra's
/// `addBase` and `alias` vectors are.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AddBase {
    /// Final Varnode of the additive pointer chain.
    pub base: VarnodeId,
    /// Non-constant index carried by the additive chain, when there is one.
    pub index: Option<VarnodeId>,
}

/// A lightweight analysis of pointer references into one address space.
///
/// The checker deliberately owns only analysis state, not a reference to the
/// graph.  That keeps it a local pass object like Ghidra's checker and avoids a
/// stale cached verdict when earlier rules rewrite pointer computations; a
/// deferred query supplies the graph to
/// [`has_local_alias`](Self::has_local_alias) when the calculation is needed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AliasChecker {
    /// Address-space identifier being checked (`AliasChecker::space`).
    stack_space: Option<u32>,
    /// Whether that space grows toward lower offsets.  Ghidra's `direction`
    /// is `1` for this case and `-1` otherwise.
    stack_grows_down: bool,
    /// Boundary between parameter references and local references
    /// (`AliasChecker::localBoundary`).
    local_boundary: u64,
    /// Initial shallowest-alias sentinel (`AliasChecker::localExtreme`).
    local_extreme: u64,
    /// Shallowest local alias found (`AliasChecker::aliasBoundary`).
    alias_boundary: u64,
    /// Whether `gather_internal` has populated the two result vectors.
    calculated: bool,
    /// Additive pointer-chain endpoints (`AliasChecker::addBase`).
    add_base: Vec<AddBase>,
    /// Alias starting offsets (`AliasChecker::alias`).
    alias: Vec<u64>,
}

impl Default for AliasChecker {
    fn default() -> Self {
        Self {
            stack_space: None,
            stack_grows_down: true,
            local_boundary: DEFAULT_LOCAL_BOUNDARY,
            local_extreme: u64::MAX,
            alias_boundary: u64::MAX,
            calculated: false,
            add_base: Vec::new(),
            alias: Vec::new(),
        }
    }
}

/// Ghidra's no-prototype default for the local/parameter split on a
/// downward-growing stack (`deriveBoundaries`).  Stack offsets below this
/// value are treated as parameter references; normal negative frame offsets
/// are represented as large unsigned values and therefore remain local.
const DEFAULT_LOCAL_BOUNDARY: u64 = 0x0100_0000;

impl AliasChecker {
    /// Gather pointer references into `stack_space`.
    ///
    /// `stack_space` is explicit because [`Funcdata::spacebase`] identifies the
    /// register holding the frame base, not the memory space that register
    /// addresses.  `defer` preserves Ghidra's lazy `gather` behavior: with it
    /// set, the additive walk occurs on the first `has_local_alias` query.
    /// Without a prototype model, this uses Ghidra's default downward-stack
    /// layout (`localBoundary = 0x1000000`, `localExtreme = UINT_MAX`).
    pub fn gather(&mut self, data: &Funcdata, stack_space: u32, defer: bool) {
        self.gather_with_layout(
            data,
            stack_space,
            true,
            DEFAULT_LOCAL_BOUNDARY,
            u64::MAX,
            defer,
        );
    }

    /// Gather with explicit stack layout boundaries.
    ///
    /// This is the representable portion of `AliasChecker::deriveBoundaries`.
    /// Ghidra obtains these values from `FuncProto` and `AddrSpace`; the graph
    /// has neither object, so callers that have the prototype/target facts may
    /// provide them here.  `local_boundary` separates parameter references from
    /// locals in the address-space offset ordering.  `local_extreme` is the
    /// initial shallowest alias sentinel.  For a downward-growing stack the
    /// usual sentinel is `u64::MAX`; for an upward-growing stack it is normally
    /// the local boundary.
    pub fn gather_with_layout(
        &mut self,
        data: &Funcdata,
        stack_space: u32,
        stack_grows_down: bool,
        local_boundary: u64,
        local_extreme: u64,
        defer: bool,
    ) {
        self.stack_space = Some(stack_space);
        self.stack_grows_down = stack_grows_down;
        self.local_boundary = local_boundary;
        self.local_extreme = local_extreme;
        self.alias_boundary = local_extreme;
        self.calculated = false;
        self.add_base.clear();
        self.alias.clear();
        if !defer {
            self.gather_internal(data);
        }
    }

    /// Return whether `location` may be aliased by a pointer reference.
    ///
    /// This is Ghidra's `AliasChecker::hasLocalAlias`.  The graph argument is
    /// needed only because a Rust checker cannot retain a reference to a
    /// mutable-owner's `Funcdata` field; it is used for a deferred gather and
    /// ignored after the result is calculated.  A location in another space is
    /// not a local of this checker.  On an upward-growing stack Ghidra declines
    /// this heuristic and returns false, preserving that behavior.
    pub fn has_local_alias(&mut self, data: &Funcdata, location: Location) -> bool {
        let Some(stack_space) = self.stack_space else {
            return false;
        };
        if !self.calculated {
            self.gather_internal(data);
        }
        if location.space != stack_space || !self.stack_grows_down {
            return false;
        }
        location.offset >= self.alias_boundary
    }

    /// Sort alias starting offsets (`AliasChecker::sortAlias`).
    ///
    /// Ghidra intentionally sorts only the alias vector; `AddBase` and alias
    /// entries are a parallel pair only until this method is called.  Consumers
    /// that need both vectors paired should inspect them before sorting.
    pub fn sort_alias(&mut self) {
        self.alias.sort_unstable();
    }

    /// Return additive-chain endpoints collected by `gather`.
    pub fn get_add_base(&self) -> &[AddBase] {
        &self.add_base
    }

    /// Return alias starting offsets collected by `gather`.
    pub fn get_alias(&self) -> &[u64] {
        &self.alias
    }

    /// Walk forward through the additive uses of `start` and collect terminal
    /// pointer references.  This is Ghidra's `gatherAdditiveBase`.
    fn gather_additive_base(data: &Funcdata, start: VarnodeId, add_base: &mut Vec<AddBase>) {
        let mut queue = vec![(start, None)];
        let mut seen = BTreeSet::from([start]);
        let mut cursor = 0;

        while let Some(&(vn, carried_index)) = queue.get(cursor) {
            cursor += 1;
            let mut index = carried_index;
            let mut non_additive_use = false;
            let descendants: Vec<OpId> = data.varnode(vn).descendants.iter().copied().collect();

            for operation_id in descendants {
                let operation = data.op(operation_id);
                if operation.dead {
                    continue;
                }
                match operation.opcode {
                    op::COPY => {
                        // COPY is both a terminal observation and part of the
                        // additive expression in Ghidra's traversal.
                        non_additive_use = true;
                        if let Some(output) = operation.output
                            && seen.insert(output)
                        {
                            queue.push((output, index));
                        }
                    }
                    op::INT_SUB => {
                        let Some(right) = operation.inputs.get(1).copied() else {
                            non_additive_use = true;
                            continue;
                        };
                        // Subtracting the pointer is not an additive pointer
                        // chain.  Keep the current value as a terminal base.
                        if right == vn {
                            non_additive_use = true;
                            continue;
                        }
                        if !is_constant(data, right) {
                            index = Some(right);
                        }
                        if let Some(output) = operation.output
                            && seen.insert(output)
                        {
                            queue.push((output, index));
                        }
                    }
                    op::INT_ADD | op::PTRADD => {
                        let (Some(left), Some(right)) = (
                            operation.inputs.first().copied(),
                            operation.inputs.get(1).copied(),
                        ) else {
                            non_additive_use = true;
                            continue;
                        };
                        let other = if right == vn { left } else { right };
                        if !is_constant(data, other) {
                            index = Some(other);
                        }
                        if let Some(output) = operation.output
                            && seen.insert(output)
                        {
                            queue.push((output, index));
                        }
                    }
                    op::PTRSUB | op::SEGMENTOP => {
                        if let Some(output) = operation.output
                            && seen.insert(output)
                        {
                            queue.push((output, index));
                        }
                    }
                    _ => {
                        non_additive_use = true;
                    }
                }
            }

            if non_additive_use {
                add_base.push(AddBase { base: vn, index });
            }
        }
    }

    /// Sum the constant portion of an additive expression (`gatherOffset`).
    fn gather_offset(data: &Funcdata, value: VarnodeId, active: &mut BTreeSet<VarnodeId>) -> u64 {
        if !active.insert(value) {
            // A malformed/cyclic graph has no finite constant sum.  Zero is
            // Ghidra's fallback for an unknown definition and is conservative
            // for the alias-boundary test below.
            return 0;
        }

        let varnode = data.varnode(value);
        let raw = if varnode.flags.constant {
            varnode.offset
        } else {
            let Some(definition) = varnode.def else {
                active.remove(&value);
                return 0;
            };
            let operation = data.op(definition);
            match operation.opcode {
                op::COPY => operation
                    .inputs
                    .first()
                    .copied()
                    .map_or(0, |input| Self::gather_offset(data, input, active)),
                op::PTRSUB | op::INT_ADD => {
                    let left = operation
                        .inputs
                        .first()
                        .copied()
                        .map_or(0, |input| Self::gather_offset(data, input, active));
                    let right = operation
                        .inputs
                        .get(1)
                        .copied()
                        .map_or(0, |input| Self::gather_offset(data, input, active));
                    left.wrapping_add(right)
                }
                op::INT_SUB => {
                    let left = operation
                        .inputs
                        .first()
                        .copied()
                        .map_or(0, |input| Self::gather_offset(data, input, active));
                    let right = operation
                        .inputs
                        .get(1)
                        .copied()
                        .map_or(0, |input| Self::gather_offset(data, input, active));
                    left.wrapping_sub(right)
                }
                op::PTRADD => {
                    let base = operation
                        .inputs
                        .first()
                        .copied()
                        .map_or(0, |input| Self::gather_offset(data, input, active));
                    match (
                        operation.inputs.get(1).copied(),
                        operation.inputs.get(2).copied(),
                    ) {
                        (Some(index), Some(scale)) => {
                            let scale_value = data.varnode(scale).offset;
                            if data.varnode(index).flags.constant {
                                base.wrapping_add(
                                    data.varnode(index).offset.wrapping_mul(scale_value),
                                )
                            } else if scale_value == 1 {
                                base.wrapping_add(Self::gather_offset(data, index, active))
                            } else {
                                base
                            }
                        }
                        _ => base,
                    }
                }
                op::SEGMENTOP => operation
                    .inputs
                    .get(2)
                    .copied()
                    .map_or(0, |input| Self::gather_offset(data, input, active)),
                _ => 0,
            }
        };
        active.remove(&value);
        raw & mask_for_size(varnode.size)
    }

    /// Run the deferred calculation (`AliasChecker::gatherInternal`).
    fn gather_internal(&mut self, data: &Funcdata) {
        if self.calculated {
            return;
        }
        self.calculated = true;
        self.alias_boundary = self.local_extreme;
        self.add_base.clear();
        self.alias.clear();

        let Some(root_location) = data.spacebase else {
            return;
        };
        let Some(spacebase) = find_spacebase_input(data, root_location) else {
            return;
        };

        Self::gather_additive_base(data, spacebase, &mut self.add_base);
        for record in &self.add_base {
            let offset = Self::gather_offset(data, record.base, &mut BTreeSet::new());
            self.alias.push(offset);
            if self.stack_grows_down {
                // `direction == 1`: only references in the local half of the
                // stack affect the shallowest local alias.
                if offset < self.local_boundary {
                    continue;
                }
                if offset < self.alias_boundary {
                    self.alias_boundary = offset;
                }
            }
            // `direction == -1` has no useful local-alias heuristic; Ghidra
            // still records offsets but leaves `hasLocalAlias` returning false.
        }
    }
}

/// Return whether a value is a constant Varnode.
fn is_constant(data: &Funcdata, value: VarnodeId) -> bool {
    data.varnode(value).flags.constant
}

/// Find the incoming Varnode corresponding to `Funcdata::spacebase`.
///
/// Ghidra calls `findSpacebaseInput`.  The graph has no `spacebase` flag, so an
/// input-marked, undefined value at the exact storage location is preferred;
/// tests and hand-built graphs may omit `input`, in which case an undefined
/// value at that location is still the only representable root.  The ancestry
/// check delegates to the existing `stackframe::is_frame_derived` predicate
/// rather than reimplementing frame-root recognition here.
fn find_spacebase_input(data: &Funcdata, location: Location) -> Option<VarnodeId> {
    let mut fallback = None;
    for index in 0..data.varnode_count() {
        let value = VarnodeId(index as u32);
        let varnode = data.varnode(value);
        if varnode.space != location.space
            || varnode.offset != location.offset
            || varnode.size != location.size
            || varnode.def.is_some()
        {
            continue;
        }
        if !is_frame_derived(data, value, location) {
            continue;
        }
        if varnode.flags.input {
            return Some(value);
        }
        fallback.get_or_insert(value);
    }
    fallback
}

fn mask_for_size(size: u32) -> u64 {
    match size {
        0 => 0,
        1..=7 => (1u64 << (size * 8)) - 1,
        _ => u64::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{RAM_SPACE, REGISTER_SPACE};

    fn seq(address: u64, order: u32) -> super::super::SeqNum {
        super::super::SeqNum { address, order }
    }

    fn frame_pointer(data: &mut Funcdata) -> VarnodeId {
        let pointer = data.new_varnode(REGISTER_SPACE, 0x1d0, 4);
        data.spacebase = Some(Location {
            space: REGISTER_SPACE,
            offset: 0x1d0,
            size: 4,
        });
        pointer
    }

    fn add_constant(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        base: VarnodeId,
        offset: u64,
    ) -> VarnodeId {
        let constant = data.new_constant(offset, 4);
        let operation = data.new_op(
            op::INT_ADD,
            seq(0x1000 + data.op_count() as u64 * 4, 0),
            vec![base, constant],
        );
        let output = data.new_unique(4);
        data.op_set_output(operation, Some(output));
        data.op_insert_end(operation, block);
        output
    }

    #[test]
    fn indirect_store_escape_marks_stack_location_aliased() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let stackbase = frame_pointer(&mut data);
        let address = add_constant(&mut data, block, stackbase, 0xffff_fff0);

        let external_target = data.new_varnode(RAM_SPACE, 0x5000, 4);
        let store_space = data.new_constant(RAM_SPACE as u64, 4);
        // The frame address is the value of an indirect store, so the address
        // escapes the frame rather than merely naming a known local access.
        let store = data.new_op(
            op::STORE,
            seq(0x1010, 0),
            vec![store_space, external_target, address],
        );
        data.op_insert_end(store, block);

        let mut checker = AliasChecker::default();
        checker.gather(&data, RAM_SPACE, false);
        assert_eq!(
            checker.get_add_base(),
            &[AddBase {
                base: address,
                index: None,
            }]
        );
        assert_eq!(checker.get_alias(), &[0xffff_fff0]);
        assert!(checker.has_local_alias(
            &data,
            Location {
                space: RAM_SPACE,
                offset: 0xffff_fff0,
                size: 4,
            }
        ));
    }

    #[test]
    fn dead_frame_pointer_has_no_alias() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x2000);
        let stackbase = frame_pointer(&mut data);
        let _private_address = add_constant(&mut data, block, stackbase, 0xffff_ffc0);

        let mut checker = AliasChecker::default();
        checker.gather(&data, RAM_SPACE, false);
        assert!(checker.get_add_base().is_empty());
        assert!(checker.get_alias().is_empty());
        assert!(!checker.has_local_alias(
            &data,
            Location {
                space: RAM_SPACE,
                offset: 0xffff_ffc0,
                size: 4,
            }
        ));
    }

    #[test]
    fn additive_chain_preserves_index_and_sort_alias_offsets() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x3000);
        let stackbase = frame_pointer(&mut data);
        let first = add_constant(&mut data, block, stackbase, 0xffff_ff00);
        let index = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        data.mark_input(index);
        let operation = data.new_op(op::INT_ADD, seq(0x3010, 0), vec![first, index]);
        let indexed = data.new_unique(4);
        data.op_set_output(operation, Some(indexed));
        data.op_insert_end(operation, block);

        let store_space = data.new_constant(RAM_SPACE as u64, 4);
        let target = data.new_varnode(RAM_SPACE, 0x6000, 4);
        let store = data.new_op(
            op::STORE,
            seq(0x3020, 0),
            vec![store_space, target, indexed],
        );
        data.op_insert_end(store, block);

        let mut checker = AliasChecker::default();
        checker.gather(&data, RAM_SPACE, false);
        assert_eq!(checker.get_add_base()[0].index, Some(index));
        assert_eq!(checker.get_alias(), &[0xffff_ff00]);

        // Add another terminal use at a shallower offset and verify the exact
        // Ghidra sorting operation, independently of alias-boundary selection.
        let second = add_constant(&mut data, block, stackbase, 0xffff_ff80);
        let store = data.new_op(op::STORE, seq(0x3030, 0), vec![store_space, target, second]);
        data.op_insert_end(store, block);
        checker.gather(&data, RAM_SPACE, false);
        checker.sort_alias();
        assert_eq!(checker.get_alias(), &[0xffff_ff00, 0xffff_ff80]);
    }

    #[test]
    fn deferred_gather_calculates_on_first_query() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x4000);
        let stackbase = frame_pointer(&mut data);
        let address = add_constant(&mut data, block, stackbase, 0xffff_ffd0);
        let store_space = data.new_constant(RAM_SPACE as u64, 4);
        let target = data.new_varnode(RAM_SPACE, 0x7000, 4);
        let store = data.new_op(
            op::STORE,
            seq(0x4010, 0),
            vec![store_space, target, address],
        );
        data.op_insert_end(store, block);

        let mut checker = AliasChecker::default();
        checker.gather(&data, RAM_SPACE, true);
        assert!(checker.get_alias().is_empty());
        assert!(checker.has_local_alias(
            &data,
            Location {
                space: RAM_SPACE,
                offset: 0xffff_ffd0,
                size: 4,
            }
        ));
        assert_eq!(checker.get_alias(), &[0xffff_ffd0]);
    }
}
