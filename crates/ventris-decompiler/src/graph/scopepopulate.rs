//! Local-scope population and stack range reconstruction.
//!
//! This is the graph-facing part of Ghidra 12.1.3's `MapState` and
//! `ScopeLocal::restructureVarnode`/`restructure` in `varmap.cc`.  Ghidra
//! collects fixed ranges from stack-space Varnodes, adds open ranges for
//! frame-relative pointers, reconciles overlaps, and then enters symbols in
//! the function's local scope.  The graph has no `HighVariable` arena or
//! architecture `RangeList`, so the equivalent input is the graph Varnode
//! arena plus the frame slots recovered by [`super::stackframe::Frame`].
//!
//! Source authority:
//!
//! * `MapState::{MapState,gatherVarnodes,gatherOpen,initialize}` and
//!   `ScopeLocal::{restructureVarnode,restructure}` in
//!   `Ghidra/Features/Decompiler/src/decompile/cpp/varmap.cc`, lines
//!   864-879, 1063-1081, 1124-1249, and 1251-1325;
//! * `ScopeLocal::buildVariableName` in the same file, lines 548-580;
//! * `ActionRestructureVarnode::apply` and `ActionMapGlobals::apply` in
//!   `coreaction.cc`, lines 2315-2350 and 5787-5789.
//!
//! The local-scope population entry point is [`build_local_scope`].  It is
//! intentionally pure with respect to the graph: callers install the returned
//! scope with `Funcdata::set_scope_local` at the action boundary.  Each local
//! mapping carries a real code liveness range.  This matters for stack-slot
//! reuse: two SSA values at the same storage location but at disjoint points
//! become two symbols rather than one symbol whose lifetime incorrectly spans
//! both values.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use ventris_pcode::op;

use super::alias::AliasChecker;
use super::guard::Location;
use super::scope::{Liveness, ScopeLocal, SymbolCategory, UsePoint, UseRange};
use super::stackframe::{Frame, frame_offset};
use super::typefactory::DataType;
use super::{Funcdata, VarnodeId};

/// One fixed range hint collected by [`MapState`].
///
/// Ghidra's `RangeHint` also carries open-array and type-lock state.  The graph
/// has no `LoadGuard`, forced type lock, or high-variable metadata, so this
/// record contains the complete set of facts that can be established without
/// inventing any of them: storage, recovered type, and code liveness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapRange {
    location: Location,
    ty: DataType,
    liveness: Liveness,
}

impl MapRange {
    pub fn new(location: Location, ty: DataType, liveness: Liveness) -> Option<Self> {
        (location.size != 0).then_some(Self {
            location,
            ty,
            liveness,
        })
    }

    pub fn location(&self) -> Location {
        self.location
    }

    pub fn ty(&self) -> &DataType {
        &self.ty
    }

    pub fn liveness(&self) -> &Liveness {
        &self.liveness
    }
}

/// Collected stack storage hints, corresponding to Ghidra's `MapState`.
///
/// `MapState` deliberately owns no graph reference.  A caller can collect
/// from one graph, let it be dropped, and collect again after a rewrite just
/// as Ghidra constructs a fresh state for each restructuring pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapState {
    stack_space: u32,
    ranges: Vec<MapRange>,
}

impl MapState {
    pub fn new(stack_space: u32) -> Self {
        Self {
            stack_space,
            ranges: Vec::new(),
        }
    }

    pub fn stack_space(&self) -> u32 {
        self.stack_space
    }

    /// Gather fixed ranges from stack-space Varnodes.
    ///
    /// A free, unread Varnode is not evidence of a storage object.  Every
    /// other non-constant Varnode in the requested space contributes its
    /// recovered type and the interval from its definition through its live
    /// descendants.  This mirrors `MapState::gatherVarnodes`'s
    /// `isReadActive` guard without fabricating a symbol for an unused arena
    /// value.
    pub fn gather_vnodes(&mut self, data: &Funcdata) {
        let recovered = data.recovered_types();
        for index in 0..data.varnode_count() {
            let id = VarnodeId(index as u32);
            let value = data.varnode(id);
            if value.space != self.stack_space
                || value.size == 0
                || value.flags.constant
                || value.flags.unique
            {
                continue;
            }
            let Some(liveness) = varnode_liveness(data, id) else {
                continue;
            };
            let ty = recovered
                .1
                .get(id)
                .cloned()
                .unwrap_or_else(|| DataType::Unknown(value.size.saturating_mul(8)));
            self.ranges.push(MapRange {
                location: Location {
                    space: self.stack_space,
                    offset: value.offset,
                    size: value.size,
                },
                ty,
                liveness,
            });
        }
    }

    /// Gather ranges from accesses whose address is derived from the frame
    /// base.  `Frame::of` owns the storage-discovery rule and records each
    /// observed access width; this pass only associates those slots with their
    /// operation sequence points and recovered value types.
    pub fn gather_open(&mut self, data: &Funcdata) {
        let Some(stack_pointer) = data.spacebase else {
            return;
        };

        let frame = Frame::of(data, stack_pointer);
        let frame_slots: BTreeSet<(i64, u32)> =
            frame.slots().map(|slot| (slot.offset, slot.size)).collect();
        if frame_slots.is_empty() {
            return;
        }

        let mut grouped: BTreeMap<(i64, u32), AccessHint> = BTreeMap::new();
        for (_, operation) in data.live_ops() {
            let (address, value) = match operation.opcode {
                op::LOAD => {
                    let Some(address) = operation.inputs.get(1).copied() else {
                        continue;
                    };
                    let Some(output) = operation.output else {
                        continue;
                    };
                    (address, output)
                }
                op::STORE => {
                    let Some(address) = operation.inputs.get(1).copied() else {
                        continue;
                    };
                    let Some(value) = operation.inputs.get(2).copied() else {
                        continue;
                    };
                    (address, value)
                }
                _ => continue,
            };

            let Some(offset) = frame_offset(data, address, stack_pointer) else {
                // A dynamic frame-derived pointer is still meaningful for
                // alias analysis, but there is no fixed storage address at
                // which a SymbolEntry could be entered.  Do not guess one.
                continue;
            };
            let size = data.varnode(value).size;
            if size == 0 || !frame_slots.contains(&(offset, size)) {
                continue;
            }
            let key = (offset, size);
            let point = UsePoint::from(operation.seq);
            let ty = recovered_type(data, value);
            grouped
                .entry(key)
                .and_modify(|hint| {
                    hint.points.insert(point);
                    hint.ty = reconcile_type(&hint.ty, &ty, size);
                })
                .or_insert_with(|| AccessHint {
                    ty,
                    points: BTreeSet::from([point]),
                });
        }

        for ((offset, size), hint) in grouped {
            // A memory access does not carry SSA identity in this graph.  Keep
            // nearby accesses together as one slot lifetime, but split a
            // clearly separated run so a recycled frame slot does not become
            // one declaration spanning unrelated code.  Direct stack-space
            // SSA Varnodes retain their exact def/use lifetimes below.
            for liveness in point_runs(hint.points) {
                self.ranges.push(MapRange {
                    location: Location {
                        space: self.stack_space,
                        offset: offset as u64,
                        size,
                    },
                    ty: hint.ty.clone(),
                    liveness,
                });
            }
        }
    }

    /// Gather all graph-observable fixed and frame-relative ranges.
    pub fn gather(&mut self, data: &Funcdata) {
        self.ranges.clear();
        self.gather_vnodes(data);
        self.gather_open(data);
    }

    /// Reconcile intersecting ranges in the same live interval.
    ///
    /// This is the representable part of `RangeHint::merge` followed by
    /// `ScopeLocal::restructure`: fixed ranges are merged only when their
    /// storage and liveness overlap.  Adjacent ranges remain separate because
    /// Ghidra only joins an open range to a following hint; treating adjacency
    /// as identity would merge two independent stack objects.
    pub fn initialize(&mut self) -> bool {
        self.ranges.sort_by(range_order);
        let mut merged = Vec::with_capacity(self.ranges.len());
        for range in self.ranges.drain(..) {
            let mut pending = range;
            let mut index = 0;
            while index < merged.len() {
                let Some(joined) = merge_ranges(&merged[index], &pending) else {
                    index += 1;
                    continue;
                };
                pending = joined;
                merged.remove(index);
                index = 0;
            }
            merged.push(pending);
        }
        merged.sort_by(range_order);
        self.ranges = merged;
        !self.ranges.is_empty()
    }

    /// Ranges after collection/reconciliation.
    pub fn ranges(&self) -> impl Iterator<Item = &MapRange> {
        self.ranges.iter()
    }

    pub fn into_ranges(self) -> Vec<MapRange> {
        self.ranges
    }
}

#[derive(Clone, Debug)]
struct AccessHint {
    ty: DataType,
    points: BTreeSet<UsePoint>,
}

/// Build a populated local scope for `stack_space`.
///
/// Explicit prototype parameters are entered first, with their exact storage
/// and `Liveness::All`, so a printer looking up a parameter at an invalid/zero
/// use point still finds the backing `SymbolEntry`.  Local ranges then come
/// from fixed stack Varnodes and frame-relative accesses.  Parameter-overlap
/// ranges are discarded rather than silently claiming bytes owned by a locked
/// input parameter.  Every emitted local gets a real liveness range.
///
/// Alias analysis is intentionally local to this invocation.  The checker is
/// gathered and queried once the final storage ranges are known, and its
/// verdict is copied into `ScopeLocal`; no checker is cached across graph
/// rewrites.  As in Ghidra, an aliased slot still receives a symbol: the
/// verdict only says that the symbol cannot be treated as an unaliased private
/// local.
pub fn build_local_scope(data: &Funcdata, stack_space: u32) -> ScopeLocal {
    let mut scope = ScopeLocal::with_name("local", stack_space);
    let stack_grows_negative = data
        .func_proto()
        .map_or(true, |proto| proto.abi().stack_grows_down);
    scope.set_stack_grows_negative(stack_grows_negative);

    let mut parameter_locations = Vec::new();
    if let Some(proto) = data.func_proto() {
        for (index, parameter) in proto.params().iter().enumerate() {
            let location = parameter.get_address();
            if location.size == 0 {
                continue;
            }
            let requested = if parameter.is_name_undefined() {
                format!("param_{}", index + 1)
            } else {
                parameter.get_name().to_owned()
            };
            let name = scope.make_name_unique(&requested);
            let ty: DataType = parameter.get_type().clone().into();
            // Stack parameters reserve their storage before local ranges are
            // reconciled.  Keeping the reservation in ScopeLocal makes
            // `is_parameter_location` and `parameter_bounds` agree with the
            // entries emitted below; `is_mapped` intentionally remains false
            // for this caller-visible storage.  Register-space parameters are
            // still entered in the same scope so exact declaration lookup can
            // resolve every prototype parameter.
            if location.space == stack_space {
                scope.mark_not_mapped(location.space, location.offset, location.size, true);
                parameter_locations.push(location);
            }
            let symbol = scope.scope_mut().add_symbol_with_category(
                name,
                ty,
                SymbolCategory::FunctionParameter,
                u16::try_from(index).ok(),
            );
            let _ = scope.scope_mut().add_map(symbol, location, Liveness::All);
            let _ = scope.mark_mapped(location.space, location.offset, location.size);
        }
    }

    let mut state = MapState::new(stack_space);
    state.gather(data);
    state.initialize();

    let mut checker = AliasChecker::default();
    let (local_boundary, local_extreme) = if stack_grows_negative {
        (
            scope
                .parameter_bounds()
                .map_or(0x0100_0000, |(_, last)| last),
            u64::MAX,
        )
    } else {
        (0x0100_0000, 0x0100_0000)
    };
    checker.gather_with_layout(
        data,
        stack_space,
        stack_grows_negative,
        local_boundary,
        local_extreme,
        false,
    );
    for range in state.ranges() {
        let location = range.location();
        if parameter_locations
            .iter()
            .copied()
            .any(|parameter| locations_overlap(parameter, location))
        {
            continue;
        }

        let base_name = stack_variable_name(&scope, location, range.ty());
        let name = scope.make_name_unique(&base_name);
        let symbol = scope.scope_mut().add_symbol(name, range.ty().clone());
        let _ = scope
            .scope_mut()
            .add_map(symbol, location, range.liveness().clone());
        let _ = scope.mark_mapped(location.space, location.offset, location.size);

        // This is the sole escape decision.  AliasChecker owns the pointer
        // walk and boundary policy; the scope merely retains its verdict for
        // consumers that ask whether an unmapped range is safe to treat as
        // private.
        let aliased = checker.has_local_alias(data, location);
        scope.set_alias_verdict(location, aliased);
    }

    // The graph's public ScopeLocal restructuring method performs the final
    // structural overlap census.  We have already reconciled the ranges, but
    // invoking it keeps the same invariant as the registered Ghidra action.
    let _ = scope.restructure_varnode(false);
    scope
}

fn recovered_type(data: &Funcdata, value: VarnodeId) -> DataType {
    let size = data.varnode(value).size;
    data.recovered_types()
        .1
        .get(value)
        .cloned()
        .unwrap_or_else(|| DataType::Unknown(size.saturating_mul(8)))
}

fn varnode_liveness(data: &Funcdata, value: VarnodeId) -> Option<Liveness> {
    let node = data.varnode(value);
    let mut points = BTreeSet::new();
    if let Some(definition) = node.def
        && let Some(operation) = data.opcode_of(definition)
    {
        let _ = operation;
        points.insert(UsePoint::from(data.op(definition).seq));
    }
    for descendant in node.descendants.iter().copied() {
        if data.opcode_of(descendant).is_some() {
            points.insert(UsePoint::from(data.op(descendant).seq));
        }
    }
    let first = points.first().copied()?;
    let last = points.last().copied().unwrap_or(first);
    Some(Liveness::Ranges(vec![UseRange::new(first, last)]))
}

fn point_runs(points: BTreeSet<UsePoint>) -> Vec<Liveness> {
    let mut iter = points.into_iter();
    let Some(mut start) = iter.next() else {
        return Vec::new();
    };
    let mut end = start;
    let mut ranges = Vec::new();
    for point in iter {
        if point.address.saturating_sub(end.address) <= 4 {
            end = point;
        } else {
            ranges.push(UseRange::new(start, end));
            start = point;
            end = point;
        }
    }
    ranges.push(UseRange::new(start, end));
    ranges
        .into_iter()
        .map(|range| Liveness::Ranges(vec![range]))
        .collect()
}

fn range_order(left: &MapRange, right: &MapRange) -> Ordering {
    left.location
        .space
        .cmp(&right.location.space)
        .then_with(|| left.location.offset.cmp(&right.location.offset))
        .then_with(|| left.location.size.cmp(&right.location.size))
        .then_with(|| liveness_first(&left.liveness).cmp(&liveness_first(&right.liveness)))
}

fn liveness_first(liveness: &Liveness) -> UsePoint {
    liveness.first().unwrap_or_default()
}

fn locations_overlap(left: Location, right: Location) -> bool {
    left.space == right.space
        && left.offset
            <= right
                .offset
                .saturating_add(u64::from(right.size).saturating_sub(1))
        && right.offset
            <= left
                .offset
                .saturating_add(u64::from(left.size).saturating_sub(1))
}

fn liveness_overlap(left: &Liveness, right: &Liveness) -> bool {
    match (left, right) {
        (Liveness::All, _) | (_, Liveness::All) => true,
        (Liveness::Ranges(left), Liveness::Ranges(right)) => left
            .iter()
            .any(|a| right.iter().any(|b| a.start <= b.end && b.start <= a.end)),
    }
}

fn merge_liveness(left: &Liveness, right: &Liveness) -> Liveness {
    match (left, right) {
        (Liveness::All, _) | (_, Liveness::All) => Liveness::All,
        (Liveness::Ranges(left), Liveness::Ranges(right)) => {
            let mut ranges = left.clone();
            ranges.extend(right.iter().copied());
            ranges.sort_unstable();
            let mut merged: Vec<UseRange> = Vec::with_capacity(ranges.len());
            for range in ranges {
                if let Some(last) = merged.last_mut()
                    && last.end >= range.start
                {
                    if range.end > last.end {
                        last.end = range.end;
                    }
                } else {
                    merged.push(range);
                }
            }
            Liveness::Ranges(merged)
        }
    }
}

fn merge_ranges(left: &MapRange, right: &MapRange) -> Option<MapRange> {
    if !locations_overlap(left.location, right.location)
        || !liveness_overlap(&left.liveness, &right.liveness)
    {
        return None;
    }
    let first = left.location.offset.min(right.location.offset);
    let last = left
        .location
        .offset
        .saturating_add(u64::from(left.location.size).saturating_sub(1))
        .max(
            right
                .location
                .offset
                .saturating_add(u64::from(right.location.size).saturating_sub(1)),
        );
    let size = last
        .saturating_sub(first)
        .saturating_add(1)
        .min(u64::from(u32::MAX)) as u32;
    Some(MapRange {
        location: Location {
            space: left.location.space,
            offset: first,
            size,
        },
        ty: reconcile_type(&left.ty, &right.ty, size),
        liveness: merge_liveness(&left.liveness, &right.liveness),
    })
}

fn type_width(ty: &DataType) -> u32 {
    match ty {
        DataType::Unknown(bits) | DataType::Float(bits) => bits.saturating_add(7) / 8,
        DataType::Bool => 1,
        DataType::Int { bits, .. } => bits.saturating_add(7) / 8,
        DataType::Void => 0,
        DataType::Pointer { bits, .. } | DataType::PointerRel { bits, .. } => {
            bits.saturating_add(7) / 8
        }
        DataType::Array { element, count } => type_width(element).saturating_mul(*count as u32),
        DataType::Struct { fields, .. } => fields
            .iter()
            .map(|field| field.offset.saturating_add(type_width(&field.ty)))
            .max()
            .unwrap_or(0),
        DataType::Spacebase => 0,
    }
}

fn is_unknown(ty: &DataType) -> bool {
    matches!(ty, DataType::Unknown(_))
}

fn same_type_family(left: &DataType, right: &DataType) -> bool {
    matches!(
        (left, right),
        (DataType::Bool, DataType::Bool)
            | (DataType::Float(_), DataType::Float(_))
            | (DataType::Int { .. }, DataType::Int { .. })
            | (DataType::Pointer { .. }, DataType::Pointer { .. })
            | (DataType::PointerRel { .. }, DataType::PointerRel { .. })
            | (DataType::Array { .. }, DataType::Array { .. })
            | (DataType::Struct { .. }, DataType::Struct { .. })
            | (DataType::Spacebase, DataType::Spacebase)
    )
}

fn reconcile_type(left: &DataType, right: &DataType, storage_size: u32) -> DataType {
    if left == right {
        return left.clone();
    }
    if is_unknown(left) {
        return right.clone();
    }
    if is_unknown(right) {
        return left.clone();
    }
    let left_width = type_width(left);
    let right_width = type_width(right);
    if same_type_family(left, right) && left_width == right_width {
        return left.clone();
    }
    if left_width > 0 && left_width == storage_size && right_width != storage_size {
        return left.clone();
    }
    if right_width > 0 && right_width == storage_size && left_width != storage_size {
        return right.clone();
    }
    DataType::Unknown(storage_size.saturating_mul(8))
}

fn signed_stack_offset(offset: u64) -> i64 {
    if offset <= u64::from(u32::MAX) {
        (offset as u32 as i32) as i64
    } else {
        offset as i64
    }
}

fn type_name_base(ty: &DataType) -> String {
    match ty {
        DataType::Unknown(_) => "u".to_owned(),
        DataType::Bool => "b".to_owned(),
        DataType::Int { signed: true, .. } => "i".to_owned(),
        DataType::Int { signed: false, .. } => "u".to_owned(),
        DataType::Float(_) => "f".to_owned(),
        DataType::Void => "v".to_owned(),
        DataType::Pointer { to, .. } | DataType::PointerRel { to, .. } => {
            format!("p{}", type_name_base(to))
        }
        DataType::Array { element, .. } => format!("a{}", type_name_base(element)),
        DataType::Struct { name, .. } => name
            .chars()
            .next()
            .map_or_else(|| "s".to_owned(), |ch| ch.to_string()),
        DataType::Spacebase => "p".to_owned(),
    }
}

/// Ghidra's `ScopeLocal::buildVariableName` for a stack-backed default name.
///
/// The graph has no translated address-space name, so the architecture's
/// canonical `Stack` spelling is used.  `X` marks an offset on the allocated
/// side of a downward-growing stack, exactly as the C++ implementation's
/// sign/marker branch does.
fn stack_variable_name(scope: &ScopeLocal, location: Location, ty: &DataType) -> String {
    let signed = signed_stack_offset(location.offset);
    let oriented = if scope.stack_grows_negative() {
        signed.saturating_neg()
    } else {
        signed
    };
    let marker = if oriented <= 0 {
        "X"
    } else if let Some((min_param, max_param)) = scope.parameter_bounds() {
        let outside_parameter_region = if scope.stack_grows_negative() {
            location.offset < min_param
        } else {
            location.offset > max_param
        };
        if outside_parameter_region { "Y" } else { "" }
    } else {
        ""
    };
    let magnitude = if oriented <= 0 {
        oriented.saturating_neg() as u64
    } else {
        oriented as u64
    };
    format!("{}Stack{marker}_{magnitude:x}", type_name_base(ty))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{RAM_SPACE, REGISTER_SPACE};

    fn seq(address: u64, order: u32) -> super::super::SeqNum {
        super::super::SeqNum { address, order }
    }

    fn copy_to_stack(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        stack_space: u32,
        offset: u64,
        address: u64,
        value: u64,
    ) -> VarnodeId {
        let constant = data.new_constant(value, 4);
        let output = data.new_varnode(stack_space, offset, 4);
        let copy = data.new_op(op::COPY, seq(address, 0), vec![constant]);
        data.op_set_output(copy, Some(output));
        data.op_insert_end(copy, block);
        output
    }

    #[test]
    fn distinct_stack_ranges_get_exact_storage_and_liveness() {
        let stack_space = RAM_SPACE;
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(data.entry);
        copy_to_stack(&mut data, block, stack_space, 0x10, 0x1000, 1);
        copy_to_stack(&mut data, block, stack_space, 0x20, 0x1010, 2);

        let scope = build_local_scope(&data, stack_space);
        let entries: Vec<_> = scope.entries().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].location(),
            Some(Location {
                space: stack_space,
                offset: 0x10,
                size: 4
            })
        );
        assert_eq!(
            entries[1].location(),
            Some(Location {
                space: stack_space,
                offset: 0x20,
                size: 4
            })
        );
        assert_eq!(
            entries[0].use_range(),
            &Liveness::range(0x1000_u64, 0x1000_u64)
        );
        assert_eq!(
            entries[1].use_range(),
            &Liveness::range(0x1010_u64, 0x1010_u64)
        );
        assert_eq!(
            scope.entry_symbol(entries[0].id()).unwrap().name(),
            "uStackX_10"
        );
        assert_eq!(
            scope.entry_symbol(entries[1].id()).unwrap().name(),
            "uStackX_20"
        );
    }

    #[test]
    fn reused_stack_slot_gets_distinct_symbols_at_disjoint_points() {
        let stack_space = RAM_SPACE;
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(data.entry);
        copy_to_stack(&mut data, block, stack_space, 0x10, 0x1000, 1);
        copy_to_stack(&mut data, block, stack_space, 0x10, 0x2000, 2);

        let scope = build_local_scope(&data, stack_space);
        let entries: Vec<_> = scope
            .entries()
            .filter(|entry| entry.location().is_some())
            .collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].location(),
            Some(Location {
                space: stack_space,
                offset: 0x10,
                size: 4
            })
        );
        assert_eq!(
            entries[1].location(),
            Some(Location {
                space: stack_space,
                offset: 0x10,
                size: 4
            })
        );
        assert_eq!(
            entries[0].use_range(),
            &Liveness::range(0x1000_u64, 0x1000_u64)
        );
        assert_eq!(
            entries[1].use_range(),
            &Liveness::range(0x2000_u64, 0x2000_u64)
        );
        assert_ne!(entries[0].symbol_id(), entries[1].symbol_id());
    }

    #[test]
    fn escaping_frame_slot_remains_mapped_but_is_not_unaliased() {
        let stack_space = RAM_SPACE;
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(data.entry);
        let stack_pointer = data.new_varnode(REGISTER_SPACE, 0x1d0, 4);
        data.mark_input(stack_pointer);
        data.spacebase = Some(Location {
            space: REGISTER_SPACE,
            offset: 0x1d0,
            size: 4,
        });
        let delta = data.new_constant((-0x10_i32) as u32 as u64, 4);
        let address = data.new_unique(4);
        let add = data.new_op(op::INT_ADD, seq(0x1000, 0), vec![stack_pointer, delta]);
        data.op_set_output(add, Some(address));
        data.op_insert_end(add, block);
        let value = data.new_varnode(REGISTER_SPACE, 0x200, 4);
        let space = data.new_constant(stack_space as u64, 4);
        let store = data.new_op(op::STORE, seq(0x1010, 0), vec![space, address, value]);
        data.op_insert_end(store, block);
        let target = data.new_varnode(REGISTER_SPACE, 0x300, 4);
        let call = data.new_op(op::CALL, seq(0x1020, 0), vec![target, address]);
        data.op_insert_end(call, block);

        let scope = build_local_scope(&data, stack_space);
        let location = Location {
            space: stack_space,
            offset: (-0x10_i64) as u64,
            size: 4,
        };
        assert!(scope.find_addr(location, 0x1010_u64).is_some());
        let mut checker = AliasChecker::default();
        checker.gather(&data, stack_space, false);
        assert!(checker.has_local_alias(&data, location));
        assert!(!scope.is_unmapped_unaliased_with_alias(&data, location, &mut checker));
    }

    #[test]
    fn parameter_entry_uses_exact_location_and_all_liveness() {
        let stack_space = RAM_SPACE;
        let mut data = Funcdata::default();
        let mut proto = super::super::funcproto::FuncProto::new(ventris_target::Abi::for_target(
            ventris_target::TargetProfile::Ps2,
        ));
        proto.add_param_parts(
            "input",
            Location {
                space: stack_space,
                offset: 0x20,
                size: 4,
            },
            crate::native::Type::Unsigned(32),
        );
        data.set_func_proto(proto);

        let scope = build_local_scope(&data, stack_space);
        let location = Location {
            space: stack_space,
            offset: 0x20,
            size: 4,
        };
        let entry = scope.find_addr(location, 0_u64).expect("parameter map");
        assert_eq!(entry.location(), Some(location));
        assert!(entry.use_range().is_all());
        let symbol = scope.entry_symbol(entry.id()).expect("parameter symbol");
        assert_eq!(symbol.name(), "input");
        assert_eq!(symbol.category(), SymbolCategory::FunctionParameter);
    }
}
