//! Rich data-type recovery, ported from Ghidra 12.1.3's type model.
//!
//! Source authority: `TypeFactory::getTypeStruct`, `TypeFactory::getTypePointer`,
//! `TypeFactory::getTypeArray`, `Datatype::typeOrder`, `TypeStruct::getSubType`,
//! `TypeArray::getSubEntry`, `TypePointer::downChain`, and
//! `Datatype::resolveInFlow` in `type.cc`/`type.hh`; the edge semantics are from
//! `TypeOpBinary::getInputCast`, `TypeOpBinary::propagateType`,
//! `TypeOpPtradd::propagateType`, `TypeOpPtrsub::propagateType`,
//! `TypeOpLoad::propagateType`, `TypeOpStore::propagateType`,
//! `TypeOpCopy::propagateType`, `TypeOpMulti::propagateType` in `typeop.cc`,
//! and `ActionInferTypes::propagateTypeEdge` plus `ActionPrototypeTypes::apply`
//! in `coreaction.cc`, all at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.
//!
//! The graph contract has no `ProtoModel`, type-lock, annotation, or
//! architecture-space metadata.  `seed` is therefore the explicit equivalent
//! of Ghidra's locked prototype types; `ActionPrototypeTypes::apply` cannot
//! synthesize missing ABI varnodes here without inventing graph state.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use ventris_lifter::CONST_SPACE;
use ventris_pcode::op;

use super::action::Action;
use super::{Funcdata, OpId, VarnodeId};

/// One byte-aligned component of a recovered structure.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Field {
    pub offset: u32,
    pub ty: DataType,
    pub name: String,
}

/// The part of Ghidra's `Datatype` hierarchy needed by graph recovery.
///
/// `Unknown(bits)` records the storage width even when no semantic type is
/// known.  An `Array` with `count == 0` is an open-ended array: the graph has
/// proved an element stride but has no bound for the index.  This is the only
/// deliberate approximation of `TypeArray`, whose C++ representation requires
/// a finite count; it is weaker than Ghidra for bounds, but does not invent a
/// bound that the graph never observed.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum DataType {
    Unknown(u32),
    Bool,
    Int {
        bits: u32,
        signed: bool,
    },
    Float(u32),
    Void,
    Pointer {
        to: Box<DataType>,
        bits: u32,
    },
    Array {
        element: Box<DataType>,
        count: usize,
    },
    Struct {
        name: String,
        fields: Vec<Field>,
    },
    /// Ghidra's `TypePointerRel`: a pointer into the middle of a larger object.
    ///
    /// `to` is what lies at the offset, exactly as a plain pointer's `to` is,
    /// and `parent`/`offset` record which object it points into and where. That
    /// provenance is what stops a rule from re-deriving a pointer it already
    /// derived: `RuleStructOffset0` matches a pointer *to* a structure, and the
    /// pointer it produces points *into* one, so its own output no longer
    /// matches and the rewrite terminates.
    PointerRel {
        to: Box<DataType>,
        bits: u32,
        parent: Box<DataType>,
        offset: u32,
    },
}

/// A small interning factory mirroring the identity-sharing role of Ghidra's
/// `TypeFactory`.  Values are returned by value because the graph API has no
/// lifetime tied to a factory; interning still ensures repeated constructors
/// produce one canonical structural value inside this factory.
#[derive(Debug)]
pub struct TypeFactory {
    pointer_bits: u32,
    interned: RefCell<BTreeSet<DataType>>,
}

impl TypeFactory {
    pub fn new(pointer_bits: u32) -> Self {
        Self {
            pointer_bits: pointer_bits.max(1),
            interned: RefCell::new(BTreeSet::new()),
        }
    }

    /// Construct or retrieve an empty structure, corresponding to
    /// `TypeFactory::getTypeStruct` before fields are assigned.
    pub fn get_type_struct<N: Into<String>>(&self, name: N) -> DataType {
        self.get_type_struct_fields(name, Vec::new())
    }

    /// Construct or retrieve a structure with sorted, byte-offset fields.
    pub fn get_type_struct_fields<N: Into<String>>(
        &self,
        name: N,
        mut fields: Vec<Field>,
    ) -> DataType {
        fields.sort_by_key(|field| field.offset);
        self.intern(DataType::Struct {
            name: name.into(),
            fields,
        })
    }

    /// Construct or retrieve a pointer using this factory's architecture
    /// pointer width, corresponding to `TypeFactory::getTypePointer`.
    pub fn get_type_pointer(&self, to: DataType) -> DataType {
        self.get_type_pointer_with_bits(to, self.pointer_bits)
    }

    pub fn get_type_pointer_with_bits(&self, to: DataType, bits: u32) -> DataType {
        self.intern(DataType::Pointer {
            to: Box::new(to),
            bits: bits.max(1),
        })
    }

    /// Construct or retrieve an array, corresponding to
    /// `TypeFactory::getTypeArray`.
    pub fn get_type_array(&self, element: DataType, count: usize) -> DataType {
        self.intern(DataType::Array {
            element: Box::new(element),
            count,
        })
    }

    /// Ghidra's `Datatype::typeOrder`: negative means the left type is more
    /// specific, positive means the right type is more specific.
    pub fn order(left: &DataType, right: &DataType) -> i32 {
        order_inner(left, right, 10)
    }

    /// Recover one component, preserving the offset relative to that
    /// component.  This is `TypeStruct::getSubType` and the one-level element
    /// part of `TypeArray::getSubEntry`; gaps intentionally return `None`.
    ///
    /// For an array, including an open-ended one, an interior byte offset is
    /// valid too: `TypeArray::getSubEntry` returns the element and its `newoff`
    /// remainder rather than requiring alignment to the first byte.
    pub fn sub_type(&self, ty: &DataType, offset: u32) -> Option<(DataType, u32)> {
        match ty {
            DataType::Struct { fields, .. } => fields
                .iter()
                .filter_map(|field| {
                    let size = byte_width(&field.ty);
                    let rel = offset.checked_sub(field.offset)?;
                    (rel < size && size != 0).then(|| (field.ty.clone(), rel))
                })
                .max_by_key(|(_, rel)| offset.saturating_sub(*rel)),
            DataType::Array { element, count } => {
                let stride = byte_width(element).max(1);
                if *count != 0
                    && u64::from(offset) >= u64::from(stride).saturating_mul(*count as u64)
                {
                    return None;
                }
                Some((element.as_ref().clone(), offset % stride))
            }
            _ => None,
        }
    }

    /// `TypePointer::downChain`, simplified to the graph's byte-offset API:
    /// add an offset to a pointer and return a pointer to the containing
    /// component.  The pointer width is preserved.
    pub fn down_chain(&self, ty: &DataType, offset: u32) -> Option<DataType> {
        let DataType::Pointer { to, bits } = ty else {
            return None;
        };
        let (component, _) = self.sub_type(to, offset)?;
        // Ghidra's `downChain` yields a `TypePointerRel` when it steps into a
        // container, carrying the container and the offset. Returning a plain
        // pointer instead lost that provenance, and a rule whose guard tests
        // "pointer to a structure" then matched its own output forever.
        if matches!(
            to.as_ref(),
            DataType::Struct { .. } | DataType::Array { .. }
        ) {
            return Some(self.intern(DataType::PointerRel {
                to: Box::new(component),
                bits: *bits,
                parent: to.clone(),
                offset,
            }));
        }
        Some(self.get_type_pointer_with_bits(component, *bits))
    }

    /// The pointer a relative pointer behaves as when its provenance is not
    /// wanted, matching `TypePointerRel::getStripped`.
    pub fn strip_relative(&self, ty: &DataType) -> DataType {
        match ty {
            DataType::PointerRel { to, bits, .. } => {
                self.get_type_pointer_with_bits(to.as_ref().clone(), *bits)
            }
            other => other.clone(),
        }
    }

    fn intern(&self, ty: DataType) -> DataType {
        let mut interned = self.interned.borrow_mut();
        if let Some(existing) = interned.get(&ty) {
            return existing.clone();
        }
        interned.insert(ty.clone());
        ty
    }
}

/// Recovered types keyed by graph varnode.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct RecoveredTypes {
    types: BTreeMap<VarnodeId, DataType>,
    /// True when the seven-pass cap was reached while a pass still changed a
    /// type.  This follows `ActionInferTypes::apply`'s bounded localcount.
    pub unsettled: bool,
}

impl RecoveredTypes {
    pub fn get(&self, v: VarnodeId) -> Option<&DataType> {
        self.types.get(&v)
    }

    pub fn len(&self) -> usize {
        self.types.len()
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (VarnodeId, &DataType)> {
        self.types.iter().map(|(id, ty)| (*id, ty))
    }
}

const PASS_CAP: usize = 7;

/// Infer rich types with the same bounded-pass shape as Ghidra's
/// `ActionInferTypes`: local types are established first, each operation gets
/// a chance to propagate, and type recovery is accepted after seven passes.
pub fn infer(
    data: &Funcdata,
    factory: &TypeFactory,
    seed: &BTreeMap<VarnodeId, DataType>,
) -> RecoveredTypes {
    let mut types = BTreeMap::new();
    for index in 0..data.varnode_count() {
        let id = VarnodeId(index as u32);
        let value = data.varnode(id);
        if value.def.is_none() && value.descendants.is_empty() {
            continue;
        }
        types.insert(
            id,
            DataType::Int {
                bits: value.size.saturating_mul(8),
                signed: false,
            },
        );
    }
    let locks = seed.clone();
    for (id, ty) in seed {
        types.insert(*id, ty.clone());
    }

    let mut unsettled = false;
    for _ in 0..PASS_CAP {
        let mut changed = false;
        let operations: Vec<OpId> = data.live_ops().map(|(id, _)| id).collect();
        for id in operations {
            changed |= propagate_op(data, id, factory, &mut types, &locks);
        }
        // Access recovery is deliberately after ordinary edges: a FLOAT or
        // signed operation can then supply the semantic type of a recovered
        // field instead of forcing every field to an unsigned storage type.
        changed |= recover_access_types(data, factory, &mut types, &locks);
        if !changed {
            unsettled = false;
            break;
        }
        unsettled = true;
    }

    RecoveredTypes { types, unsettled }
}

/// Port of the graph-facing part of `ActionInferTypes`.  The graph contract
/// has no persistent high-level type slot, so the public `infer` function is
/// the write-back surface; this action still executes the bounded pass and
/// returns Ghidra's action count convention (zero).
pub struct ActionInferTypes;

impl Action for ActionInferTypes {
    fn name(&self) -> &'static str {
        "infer-types-rich"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let factory = TypeFactory::new(32);
        let _ = infer(data, &factory, &BTreeMap::new());
        0
    }
}

/// Lower a rich type at the renderer boundary.  The shared native type has no
/// structure or array variant, so those details intentionally disappear.
pub fn to_native(ty: &DataType) -> crate::native::Type {
    match ty {
        DataType::Unknown(_) => crate::native::Type::Unknown,
        DataType::Bool => crate::native::Type::Bool,
        DataType::Int { bits, signed } => {
            if *signed {
                crate::native::Type::Signed(*bits)
            } else {
                crate::native::Type::Unsigned(*bits)
            }
        }
        DataType::Float(bits) => crate::native::Type::Float(*bits),
        DataType::Void => crate::native::Type::Void,
        DataType::Pointer { to, .. } | DataType::PointerRel { to, .. } => {
            // A relative pointer renders as an ordinary pointer: its provenance
            // guides rewriting, not printing.
            crate::native::Type::Pointer(Box::new(to_native(to)))
        }
        DataType::Array { element, .. } => to_native(element),
        DataType::Struct { .. } => crate::native::Type::Unknown,
    }
}

fn byte_width(ty: &DataType) -> u32 {
    match ty {
        DataType::Unknown(bits)
        | DataType::Int { bits, .. }
        | DataType::Float(bits)
        | DataType::Pointer { bits, .. }
        | DataType::PointerRel { bits, .. } => bits.saturating_add(7) / 8,
        DataType::Bool => 1,
        DataType::Void => 0,
        DataType::Array { element, count } => {
            if *count == 0 {
                0
            } else {
                byte_width(element).saturating_mul((*count).min(u32::MAX as usize) as u32)
            }
        }
        DataType::Struct { fields, .. } => fields.iter().fold(0, |end, field| {
            end.max(field.offset.saturating_add(byte_width(&field.ty)))
        }),
    }
}

fn bit_width(ty: &DataType) -> u32 {
    byte_width(ty).saturating_mul(8)
}

fn rank(ty: &DataType) -> u8 {
    match ty {
        // A relative pointer is at least as specific as a plain one: it says
        // the same thing and names the container as well.
        DataType::PointerRel { .. } => 0,
        DataType::Pointer { .. } => 0,
        DataType::Struct { .. } => 1,
        DataType::Array { .. } => 2,
        DataType::Bool | DataType::Float(_) => 3,
        DataType::Int { .. } => 4,
        DataType::Unknown(_) => 6,
        DataType::Void => 7,
    }
}

fn cmp_width(left: u32, right: u32) -> i32 {
    if left == right {
        0
    } else if left > right {
        -1
    } else {
        1
    }
}

fn order_inner(left: &DataType, right: &DataType, depth: usize) -> i32 {
    if left == right {
        return 0;
    }
    let left_rank = rank(left);
    let right_rank = rank(right);
    if left_rank != right_rank {
        return if left_rank < right_rank { -1 } else { 1 };
    }
    match (left, right) {
        (DataType::Unknown(left_bits), DataType::Unknown(right_bits)) => {
            cmp_width(*left_bits, *right_bits)
        }
        (
            DataType::Int {
                bits: left_bits,
                signed: left_signed,
            },
            DataType::Int {
                bits: right_bits,
                signed: right_signed,
            },
        ) => {
            if left_signed != right_signed {
                if *left_signed { -1 } else { 1 }
            } else {
                cmp_width(*left_bits, *right_bits)
            }
        }
        (DataType::Float(left_bits), DataType::Float(right_bits)) => {
            cmp_width(*left_bits, *right_bits)
        }
        (
            DataType::Pointer {
                to: left_to,
                bits: left_bits,
            },
            DataType::Pointer {
                to: right_to,
                bits: right_bits,
            },
        ) => {
            let pointee = if depth == 0 {
                0
            } else {
                order_inner(left_to, right_to, depth - 1)
            };
            if pointee != 0 {
                pointee
            } else {
                cmp_width(*left_bits, *right_bits)
            }
        }
        (
            DataType::Array {
                element: left_element,
                count: left_count,
            },
            DataType::Array {
                element: right_element,
                count: right_count,
            },
        ) => {
            let element = if depth == 0 {
                0
            } else {
                order_inner(left_element, right_element, depth - 1)
            };
            if element != 0 {
                element
            } else if left_count == right_count {
                0
            } else if *left_count == 0 {
                1
            } else if *right_count == 0 {
                -1
            } else if left_count > right_count {
                -1
            } else {
                1
            }
        }
        (
            DataType::Struct {
                fields: left_fields,
                ..
            },
            DataType::Struct {
                fields: right_fields,
                ..
            },
        ) => struct_order(left_fields, right_fields, depth),
        (DataType::Bool, DataType::Bool) => 0,
        (DataType::Void, DataType::Void) => 0,
        _ => 0,
    }
}

fn struct_order(left: &[Field], right: &[Field], depth: usize) -> i32 {
    let mut left_is_more = false;
    for right_field in right {
        let Some(left_field) = left.iter().find(|field| field.offset == right_field.offset) else {
            return 1;
        };
        if depth != 0 {
            match order_inner(&left_field.ty, &right_field.ty, depth - 1) {
                -1 => left_is_more = true,
                1 => return 1,
                _ => {}
            }
        }
    }
    if left
        .iter()
        .any(|field| !right.iter().any(|other| other.offset == field.offset))
    {
        left_is_more = true;
    }
    if left_is_more {
        -1
    } else if right
        .iter()
        .any(|field| !left.iter().any(|other| other.offset == field.offset))
    {
        1
    } else {
        0
    }
}

fn merge_types(candidate: &DataType, current: &DataType) -> DataType {
    if candidate == current {
        return current.clone();
    }
    let ordering = TypeFactory::order(candidate, current);
    if ordering < 0 {
        return match (candidate, current) {
            (
                DataType::Pointer {
                    to: candidate_to,
                    bits: candidate_bits,
                },
                DataType::Pointer {
                    to: current_to,
                    bits: current_bits,
                },
            ) => DataType::Pointer {
                to: Box::new(merge_types(candidate_to, current_to)),
                bits: (*candidate_bits).max(*current_bits),
            },
            (
                DataType::Array {
                    element: candidate_element,
                    count: candidate_count,
                },
                DataType::Array {
                    element: current_element,
                    count: current_count,
                },
            ) => DataType::Array {
                element: Box::new(merge_types(candidate_element, current_element)),
                count: if *candidate_count == 0 {
                    *current_count
                } else if *current_count == 0 {
                    *candidate_count
                } else {
                    (*candidate_count).max(*current_count)
                },
            },
            _ => candidate.clone(),
        };
    }
    if ordering > 0 {
        return current.clone();
    }
    match (candidate, current) {
        (
            DataType::Struct {
                name: candidate_name,
                fields: candidate_fields,
            },
            DataType::Struct {
                name: current_name,
                fields: current_fields,
            },
        ) => DataType::Struct {
            name: if !candidate_name.is_empty() {
                candidate_name.clone()
            } else {
                current_name.clone()
            },
            fields: merge_fields(candidate_fields, current_fields),
        },
        (
            DataType::Pointer {
                to: candidate_to,
                bits: candidate_bits,
            },
            DataType::Pointer {
                to: current_to,
                bits: current_bits,
            },
        ) => DataType::Pointer {
            to: Box::new(merge_types(candidate_to, current_to)),
            bits: (*candidate_bits).max(*current_bits),
        },
        _ => current.clone(),
    }
}

fn merge_fields(left: &[Field], right: &[Field]) -> Vec<Field> {
    let mut fields = BTreeMap::new();
    for field in left.iter().chain(right) {
        fields
            .entry(field.offset)
            .and_modify(|existing: &mut Field| {
                existing.ty = merge_types(&field.ty, &existing.ty);
                if existing.name.is_empty() {
                    existing.name = field.name.clone();
                }
            })
            .or_insert_with(|| field.clone());
    }
    fields.into_values().collect()
}

fn set_type(
    types: &mut BTreeMap<VarnodeId, DataType>,
    locks: &BTreeMap<VarnodeId, DataType>,
    value: VarnodeId,
    candidate: DataType,
) -> bool {
    if locks.contains_key(&value) {
        return false;
    }
    let Some(current) = types.get(&value).cloned() else {
        types.insert(value, candidate);
        return true;
    };
    let merged = merge_types(&candidate, &current);
    if merged == current || TypeFactory::order(&merged, &current) >= 0 {
        return false;
    }
    types.insert(value, merged);
    true
}

fn propagate_op(
    data: &Funcdata,
    id: OpId,
    factory: &TypeFactory,
    types: &mut BTreeMap<VarnodeId, DataType>,
    locks: &BTreeMap<VarnodeId, DataType>,
) -> bool {
    let operation = data.op(id).clone();
    let mut changed = false;
    macro_rules! set_here {
        ($value:expr, $ty:expr) => {
            changed |= set_type(types, locks, $value, $ty);
        };
    }
    match operation.opcode {
        op::COPY | op::CAST | op::MULTIEQUAL | op::INDIRECT => {
            let limit = if operation.opcode == op::INDIRECT {
                1
            } else {
                operation.inputs.len()
            };
            let mut values = Vec::with_capacity(limit + 1);
            if let Some(output) = operation.output {
                values.push(output);
            }
            values.extend(operation.inputs.iter().take(limit).copied());
            let mut best = None;
            for value in &values {
                if let Some(ty) = types.get(value) {
                    best = Some(match best {
                        None => ty.clone(),
                        Some(existing) => merge_types(ty, &existing),
                    });
                }
            }
            if let Some(best) = best {
                for value in values {
                    set_here!(value, best.clone());
                }
            }
        }
        op::LOAD => {
            let (Some(output), Some(address)) =
                (operation.output, operation.inputs.get(1).copied())
            else {
                return false;
            };
            let width = data.varnode(output).size;
            if let Some(address_type) = types.get(&address).cloned() {
                if let DataType::Pointer { to, .. } = address_type {
                    if byte_width(&to) == width {
                        set_here!(output, *to);
                    }
                }
            }
            if let Some(output_type) = types.get(&output).cloned() {
                let pointer =
                    pointer_to_value(factory, output_type, pointer_bits(factory, types, address));
                set_here!(address, pointer);
            }
        }
        op::STORE => {
            let (Some(address), Some(value)) = (
                operation.inputs.get(1).copied(),
                operation.inputs.get(2).copied(),
            ) else {
                return false;
            };
            let width = data.varnode(value).size;
            if let Some(address_type) = types.get(&address).cloned() {
                if let DataType::Pointer { to, .. } = address_type {
                    if byte_width(&to) == width {
                        set_here!(value, *to);
                    }
                }
            }
            if let Some(value_type) = types.get(&value).cloned() {
                let pointer =
                    pointer_to_value(factory, value_type, pointer_bits(factory, types, address));
                set_here!(address, pointer);
            }
        }
        op::PTRADD | op::PTRSUB | op::INT_ADD => {
            let output = operation.output;
            if let Some(output) = output {
                for (slot, input) in operation.inputs.iter().copied().enumerate() {
                    let Some(input_type) = types.get(&input).cloned() else {
                        continue;
                    };
                    if !matches!(input_type, DataType::Pointer { .. }) {
                        continue;
                    }
                    if let Some(new_type) =
                        pointer_after_arithmetic(data, &operation, slot, factory, &input_type)
                    {
                        set_here!(output, new_type);
                    }
                }
            }
        }
        op::INT_EQUAL
        | op::INT_NOTEQUAL
        | op::INT_LESS
        | op::INT_LESSEQUAL
        | op::INT_SLESS
        | op::INT_SLESSEQUAL
        | op::FLOAT_EQUAL
        | op::FLOAT_NOTEQUAL
        | op::FLOAT_LESS
        | op::FLOAT_LESSEQUAL
        | op::BOOL_NEGATE
        | op::BOOL_AND
        | op::BOOL_OR
        | op::BOOL_XOR => {
            if let Some(output) = operation.output {
                set_here!(output, DataType::Bool);
            }
            if matches!(
                operation.opcode,
                op::BOOL_NEGATE | op::BOOL_AND | op::BOOL_OR | op::BOOL_XOR
            ) {
                for input in operation.inputs.iter().copied() {
                    set_here!(input, DataType::Bool);
                }
            } else if operation.inputs.len() >= 2 {
                // Comparisons are the type-equality edge in Ghidra: the
                // result is bool, while operands may share a richer type.
                let left = operation.inputs[0];
                let right = operation.inputs[1];
                if let (Some(left_ty), Some(right_ty)) =
                    (types.get(&left).cloned(), types.get(&right).cloned())
                {
                    let best = merge_types(&left_ty, &right_ty);
                    set_here!(left, best.clone());
                    set_here!(right, best);
                }
            }
        }
        op::INT_SDIV
        | op::INT_SREM
        | op::INT_SRIGHT
        | op::INT_SEXT
        | op::INT_2COMP
        | op::INT_NEGATE => {
            if let Some(output) = operation.output {
                set_here!(
                    output,
                    DataType::Int {
                        bits: data.varnode(output).size.saturating_mul(8),
                        signed: true,
                    }
                );
            }
            if let Some(input) = operation.inputs.first().copied() {
                set_here!(
                    input,
                    DataType::Int {
                        bits: data.varnode(input).size.saturating_mul(8),
                        signed: true,
                    }
                );
            }
        }
        op::FLOAT_ADD
        | op::FLOAT_SUB
        | op::FLOAT_MULT
        | op::FLOAT_DIV
        | op::FLOAT_NEG
        | op::FLOAT_ABS
        | op::FLOAT_SQRT
        | op::FLOAT_FLOAT2FLOAT
        | op::FLOAT_TRUNC
        | op::FLOAT_CEIL
        | op::FLOAT_FLOOR
        | op::FLOAT_ROUND => {
            if let Some(output) = operation.output {
                set_here!(
                    output,
                    DataType::Float(data.varnode(output).size.saturating_mul(8))
                );
            }
            for input in operation.inputs {
                set_here!(
                    input,
                    DataType::Float(data.varnode(input).size.saturating_mul(8))
                );
            }
        }
        op::FLOAT_INT2FLOAT => {
            if let Some(output) = operation.output {
                set_here!(
                    output,
                    DataType::Float(data.varnode(output).size.saturating_mul(8))
                );
            }
        }
        op::CBRANCH => {
            if let Some(condition) = operation.inputs.get(1).copied() {
                set_here!(condition, DataType::Bool);
            }
        }
        _ => {}
    }
    changed
}

fn pointer_bits(
    factory: &TypeFactory,
    types: &BTreeMap<VarnodeId, DataType>,
    value: VarnodeId,
) -> u32 {
    types
        .get(&value)
        .and_then(|ty| match ty {
            DataType::Pointer { bits, .. } => Some(*bits),
            _ => None,
        })
        .unwrap_or(factory.pointer_bits)
}

fn pointer_to_value(factory: &TypeFactory, ty: DataType, bits: u32) -> DataType {
    let pointee = if matches!(ty, DataType::Pointer { .. }) {
        DataType::Unknown(bit_width(&ty))
    } else {
        ty
    };
    factory.get_type_pointer_with_bits(pointee, bits)
}

fn pointer_after_arithmetic(
    data: &Funcdata,
    operation: &super::GraphOp,
    slot: usize,
    factory: &TypeFactory,
    pointer: &DataType,
) -> Option<DataType> {
    if slot != 0 {
        return None;
    }
    match operation.opcode {
        op::PTRSUB => {
            let offset = operation
                .inputs
                .get(1)
                .and_then(|id| constant_value(data, *id))?;
            // Offset zero is not the identity here. `PTRSUB(p, 0)` on a
            // pointer to a container is Ghidra's way of saying "the first
            // component of that container", and its result is a
            // `TypePointerRel`. Returning the operand's own type instead is
            // what let `RuleStructOffset0` match its own output forever.
            factory
                .down_chain(pointer, offset.min(u64::from(u32::MAX)) as u32)
                .or_else(|| (offset == 0).then(|| pointer.clone()))
        }
        op::PTRADD => {
            let index = operation
                .inputs
                .get(1)
                .and_then(|id| constant_value(data, *id));
            let stride = operation
                .inputs
                .get(2)
                .and_then(|id| constant_value(data, *id));
            match (index, stride) {
                (Some(index), Some(stride)) => factory
                    .down_chain(
                        pointer,
                        index.saturating_mul(stride).min(u64::from(u32::MAX)) as u32,
                    )
                    .or_else(|| (index.saturating_mul(stride) == 0).then(|| pointer.clone())),
                (None, Some(_)) => match pointer {
                    DataType::Pointer { to, bits } => {
                        if let DataType::Array { element, .. } = to.as_ref() {
                            Some(
                                factory.get_type_pointer_with_bits(element.as_ref().clone(), *bits),
                            )
                        } else {
                            Some(pointer.clone())
                        }
                    }
                    _ => None,
                },
                _ => None,
            }
        }
        op::INT_ADD => {
            let other = operation
                .inputs
                .get(1)
                .and_then(|id| constant_value(data, *id));
            if let Some(offset) = other {
                if offset == 0 {
                    return Some(pointer.clone());
                }
                return factory.down_chain(pointer, offset.min(u64::from(u32::MAX)) as u32);
            }
            if operation
                .inputs
                .get(1)
                .is_some_and(|id| scaled_index(data, *id).is_some())
            {
                return Some(pointer.clone());
            }
            None
        }
        _ => None,
    }
}

#[derive(Copy, Clone, Debug)]
struct AddressShape {
    root: VarnodeId,
    offset: u32,
    indexed: bool,
    stride: u32,
}

#[derive(Clone, Debug)]
struct Access {
    address: VarnodeId,
    shape: AddressShape,
    width: u32,
    ty: DataType,
}

#[derive(Default, Debug)]
struct AccessSet {
    fields: BTreeMap<u32, (u32, DataType)>,
    indexed: Vec<(u32, DataType)>,
}

fn recover_access_types(
    data: &Funcdata,
    factory: &TypeFactory,
    types: &mut BTreeMap<VarnodeId, DataType>,
    locks: &BTreeMap<VarnodeId, DataType>,
) -> bool {
    let accesses = collect_accesses(data, types);
    let mut grouped: BTreeMap<VarnodeId, AccessSet> = BTreeMap::new();
    for access in &accesses {
        let set = grouped.entry(access.shape.root).or_default();
        if access.shape.indexed {
            set.indexed.push((access.shape.stride, access.ty.clone()));
        } else {
            set.fields
                .entry(access.shape.offset)
                .and_modify(|(width, ty)| {
                    if access.width > *width {
                        *width = access.width;
                    }
                    *ty = merge_types(&access.ty, ty);
                })
                .or_insert((access.width, access.ty.clone()));
        }
    }

    let mut changed = false;
    for (root, set) in &grouped {
        let pointee = if !set.indexed.is_empty() && set.fields.is_empty() {
            let mut element = None;
            for (_, ty) in &set.indexed {
                element = Some(match element {
                    None => ty.clone(),
                    Some(existing) => merge_types(ty, &existing),
                });
            }
            // An unknown index has no finite bound in the graph.  `count == 0`
            // records that fact without fabricating a maximum index.
            factory.get_type_array(element.unwrap_or(DataType::Unknown(0)), 0)
        } else {
            let fields = set
                .fields
                .iter()
                .map(|(offset, (_, ty))| Field {
                    offset: *offset,
                    ty: ty.clone(),
                    name: format!("field_{offset:x}"),
                })
                .collect();
            factory.get_type_struct_fields(format!("struct_{:x}", root.0), fields)
        };
        let pointer = factory.get_type_pointer(pointee.clone());
        changed |= set_type(types, locks, *root, pointer);

        for access in accesses.iter().filter(|access| access.shape.root == *root) {
            if access.address == *root {
                continue;
            }
            let component = if access.shape.indexed {
                match &pointee {
                    DataType::Array { element, .. } => Some(element.as_ref().clone()),
                    _ => None,
                }
            } else {
                factory
                    .sub_type(&pointee, access.shape.offset)
                    .map(|(ty, _)| ty)
            };
            if let Some(component) = component {
                changed |= set_type(
                    types,
                    locks,
                    access.address,
                    factory.get_type_pointer_with_bits(component, factory.pointer_bits),
                );
            }
        }
    }
    changed
}

fn collect_accesses(data: &Funcdata, types: &BTreeMap<VarnodeId, DataType>) -> Vec<Access> {
    let mut accesses = Vec::new();
    for (_, operation) in data.live_ops() {
        let (address, value) = match operation.opcode {
            op::LOAD => (operation.inputs.get(1).copied(), operation.output),
            op::STORE => (
                operation.inputs.get(1).copied(),
                operation.inputs.get(2).copied(),
            ),
            _ => (None, None),
        };
        let (Some(address), Some(value)) = (address, value) else {
            continue;
        };
        let width = data.varnode(value).size.max(1);
        let ty = types
            .get(&value)
            .filter(|ty| bit_width(ty) == width.saturating_mul(8) || matches!(ty, DataType::Bool))
            .cloned()
            .unwrap_or(DataType::Int {
                bits: width.saturating_mul(8),
                signed: false,
            });
        accesses.push(Access {
            address,
            shape: trace_address(data, address, &mut BTreeSet::new()),
            width,
            ty,
        });
    }
    accesses
}

fn trace_address(
    data: &Funcdata,
    value: VarnodeId,
    seen: &mut BTreeSet<VarnodeId>,
) -> AddressShape {
    if !seen.insert(value) {
        return AddressShape {
            root: value,
            offset: 0,
            indexed: false,
            stride: 0,
        };
    }
    let Some(definition) = data.varnode(value).def else {
        return AddressShape {
            root: value,
            offset: 0,
            indexed: false,
            stride: 0,
        };
    };
    let operation = data.op(definition);
    match operation.opcode {
        op::COPY | op::CAST | op::INDIRECT => operation
            .inputs
            .first()
            .copied()
            .map(|input| trace_address(data, input, seen))
            .unwrap_or(AddressShape {
                root: value,
                offset: 0,
                indexed: false,
                stride: 0,
            }),
        op::PTRSUB => {
            let Some(base) = operation.inputs.first().copied() else {
                return direct_shape(value);
            };
            let Some(offset) = operation
                .inputs
                .get(1)
                .and_then(|id| constant_value(data, *id))
            else {
                return direct_shape(value);
            };
            add_shape(&mut trace_address(data, base, seen), offset)
        }
        op::PTRADD => {
            let Some(base) = operation.inputs.first().copied() else {
                return direct_shape(value);
            };
            let mut shape = trace_address(data, base, seen);
            let index = operation
                .inputs
                .get(1)
                .and_then(|id| constant_value(data, *id));
            let stride = operation
                .inputs
                .get(2)
                .and_then(|id| constant_value(data, *id));
            match (index, stride) {
                (Some(index), Some(stride)) => {
                    add_shape(&mut shape, index.saturating_mul(stride));
                }
                (None, Some(stride)) => {
                    shape.indexed = true;
                    shape.stride = stride.min(u64::from(u32::MAX)) as u32;
                }
                _ => {}
            }
            shape
        }
        op::INT_ADD => {
            let left = operation.inputs.first().copied();
            let right = operation.inputs.get(1).copied();
            if let (Some(left), Some(right)) = (left, right) {
                if let Some(offset) = constant_value(data, right) {
                    return add_shape(&mut trace_address(data, left, seen), offset);
                }
                if let Some(offset) = constant_value(data, left) {
                    return add_shape(&mut trace_address(data, right, seen), offset);
                }
                if let Some((_, stride)) = scaled_index(data, right) {
                    let mut shape = trace_address(data, left, seen);
                    shape.indexed = true;
                    shape.stride = stride;
                    return shape;
                }
                if let Some((_, stride)) = scaled_index(data, left) {
                    let mut shape = trace_address(data, right, seen);
                    shape.indexed = true;
                    shape.stride = stride;
                    return shape;
                }
            }
            direct_shape(value)
        }
        _ => direct_shape(value),
    }
}

fn direct_shape(value: VarnodeId) -> AddressShape {
    AddressShape {
        root: value,
        offset: 0,
        indexed: false,
        stride: 0,
    }
}

fn add_shape(shape: &mut AddressShape, offset: u64) -> AddressShape {
    shape.offset = shape
        .offset
        .saturating_add(offset.min(u64::from(u32::MAX)) as u32);
    *shape
}

fn constant_value(data: &Funcdata, value: VarnodeId) -> Option<u64> {
    let varnode = data.varnode(value);
    (varnode.flags.constant || varnode.space == CONST_SPACE).then_some(varnode.offset)
}

fn scaled_index(data: &Funcdata, value: VarnodeId) -> Option<(VarnodeId, u32)> {
    let definition = data.varnode(value).def?;
    let operation = data.op(definition);
    if operation.opcode != op::INT_MULT || operation.inputs.len() < 2 {
        return None;
    }
    if let Some(multiplier) = constant_value(data, operation.inputs[0]) {
        return Some((
            operation.inputs[1],
            multiplier.min(u64::from(u32::MAX)) as u32,
        ));
    }
    if let Some(multiplier) = constant_value(data, operation.inputs[1]) {
        return Some((
            operation.inputs[0],
            multiplier.min(u64::from(u32::MAX)) as u32,
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64, order: u32) -> super::super::SeqNum {
        super::super::SeqNum { address, order }
    }

    fn add_ptrsub_load(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        base: VarnodeId,
        offset: u64,
        order: u32,
    ) -> (VarnodeId, VarnodeId) {
        let displacement = data.new_constant(offset, 4);
        let ptr = data.new_unique(4);
        let ptrsub = data.new_op(
            op::PTRSUB,
            seq(0x1000 + u64::from(order) * 8, order),
            vec![base, displacement],
        );
        data.op_set_output(ptrsub, Some(ptr));
        data.op_insert_end(ptrsub, block);
        let space = data.new_constant(0, 4);
        let value = data.new_unique(4);
        let load = data.new_op(
            op::LOAD,
            seq(0x1004 + u64::from(order) * 8, order),
            vec![space, ptr],
        );
        data.op_set_output(load, Some(value));
        data.op_insert_end(load, block);
        (ptr, value)
    }

    #[test]
    fn constant_field_accesses_recover_only_observed_struct_fields() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let base = data.new_varnode(REGISTER_SPACE, 0, 4);
        data.mark_input(base);
        add_ptrsub_load(&mut data, block, base, 0, 0);
        add_ptrsub_load(&mut data, block, base, 4, 1);
        add_ptrsub_load(&mut data, block, base, 8, 2);

        let factory = TypeFactory::new(32);
        let recovered = infer(&data, &factory, &BTreeMap::new());
        let Some(DataType::Pointer { to, .. }) = recovered.get(base) else {
            panic!(
                "base was not recovered as a pointer: {:?}",
                recovered.get(base)
            );
        };
        let DataType::Struct { fields, .. } = to.as_ref() else {
            panic!("constant accesses must recover a struct, got {to:?}");
        };
        assert_eq!(fields.len(), 3);
        assert_eq!(
            fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            vec!["field_0", "field_4", "field_8"]
        );
        assert!(fields.iter().all(|field| matches!(
            field.ty,
            DataType::Int {
                bits: 32,
                signed: false
            }
        )));
        assert!(factory.sub_type(to, 12).is_none());
        assert!(
            factory
                .down_chain(recovered.get(base).unwrap(), 4)
                .is_some()
        );
    }

    #[test]
    fn specific_pointer_wins_over_same_width_integer_and_reverse_order_declines() {
        let factory = TypeFactory::new(32);
        let structure = DataType::Struct {
            name: "Recovered".to_owned(),
            fields: vec![Field {
                offset: 0,
                ty: DataType::Int {
                    bits: 32,
                    signed: false,
                },
                name: "field_0".to_owned(),
            }],
        };
        let pointer = DataType::Pointer {
            to: Box::new(structure.clone()),
            bits: 32,
        };
        let integer = DataType::Int {
            bits: 32,
            signed: false,
        };
        assert!(TypeFactory::order(&pointer, &integer) < 0);
        assert!(TypeFactory::order(&integer, &pointer) > 0);

        let mut data = Funcdata::default();
        let block = data.new_block(0x2000);
        let input = data.new_varnode(REGISTER_SPACE, 0, 4);
        let output = data.new_unique(4);
        let copy = data.new_op(op::COPY, seq(0x2000, 0), vec![input]);
        data.op_set_output(copy, Some(output));
        data.op_insert_end(copy, block);
        let seed = BTreeMap::from([(input, pointer.clone())]);
        let recovered = infer(&data, &factory, &seed);
        assert_eq!(recovered.get(input), Some(&pointer));
        assert_eq!(recovered.get(output), Some(&pointer));
    }

    #[test]
    fn scaled_index_recovers_open_array_and_constant_ptrsub_declines_array_shape() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x3000);
        let base = data.new_varnode(REGISTER_SPACE, 0, 4);
        let index = data.new_varnode(REGISTER_SPACE, 4, 4);
        data.mark_input(base);
        data.mark_input(index);
        let stride = data.new_constant(4, 4);
        let address = data.new_unique(4);
        let ptradd = data.new_op(op::PTRADD, seq(0x3000, 0), vec![base, index, stride]);
        data.op_set_output(ptradd, Some(address));
        data.op_insert_end(ptradd, block);
        let space = data.new_constant(0, 4);
        let loaded = data.new_unique(4);
        let load = data.new_op(op::LOAD, seq(0x3004, 0), vec![space, address]);
        data.op_set_output(load, Some(loaded));
        data.op_insert_end(load, block);

        let factory = TypeFactory::new(32);
        let recovered = infer(&data, &factory, &BTreeMap::new());
        let Some(DataType::Pointer { to, .. }) = recovered.get(base) else {
            panic!("indexed base was not a pointer: {:?}", recovered.get(base));
        };
        assert!(matches!(to.as_ref(), DataType::Array { count: 0, .. }));
        assert!(!matches!(to.as_ref(), DataType::Struct { .. }));
        assert_eq!(factory.sub_type(to, 4).map(|(_, offset)| offset), Some(0));

        let direct = DataType::Pointer {
            to: Box::new(DataType::Int {
                bits: 32,
                signed: false,
            }),
            bits: 32,
        };
        assert!(factory.down_chain(&direct, 0).is_none());
    }

    #[test]
    fn native_lowering_handles_every_rich_variant_and_keeps_pointer_boundary() {
        let structure = DataType::Struct {
            name: "S".to_owned(),
            fields: Vec::new(),
        };
        let values = vec![
            DataType::Unknown(32),
            DataType::Bool,
            DataType::Int {
                bits: 32,
                signed: false,
            },
            DataType::Int {
                bits: 32,
                signed: true,
            },
            DataType::Float(32),
            DataType::Void,
            DataType::Pointer {
                to: Box::new(structure.clone()),
                bits: 32,
            },
            DataType::Array {
                element: Box::new(DataType::Float(32)),
                count: 0,
            },
            structure,
        ];
        for value in &values {
            let _ = to_native(value);
        }
        assert!(matches!(
            to_native(&values[6]),
            crate::native::Type::Pointer(inner)
                if matches!(*inner, crate::native::Type::Unknown)
        ));
    }

    #[test]
    fn stepping_into_a_container_yields_a_relative_pointer() {
        // Ghidra's `downChain` returns a `TypePointerRel` here, and that
        // provenance is load-bearing: a rule whose guard reads "pointer to a
        // structure" must not match the pointer it just produced, or it rewrites
        // the same access forever. `RuleStructOffset0` did exactly that until
        // this variant existed.
        let factory = TypeFactory::new(32);
        let field = DataType::Int {
            bits: 32,
            signed: false,
        };
        let structure = factory.get_type_struct_fields(
            "container".to_owned(),
            vec![Field {
                offset: 0,
                ty: field.clone(),
                name: "field_0".to_owned(),
            }],
        );
        let pointer = factory.get_type_pointer(structure.clone());

        let stepped = factory
            .down_chain(&pointer, 0)
            .expect("offset zero steps into the first component");
        match &stepped {
            DataType::PointerRel {
                to, parent, offset, ..
            } => {
                assert_eq!(to.as_ref(), &field);
                assert_eq!(parent.as_ref(), &structure);
                assert_eq!(*offset, 0);
            }
            other => panic!("expected a relative pointer, got {other:?}"),
        }
        assert!(
            !matches!(stepped, DataType::Pointer { .. }),
            "a relative pointer must not read as a plain pointer to the container"
        );
    }

    #[test]
    fn a_relative_pointer_strips_to_a_plain_one() {
        // `TypePointerRel::getStripped`: the same pointer without provenance,
        // for the places that only want to know what is pointed at.
        let factory = TypeFactory::new(32);
        let field = DataType::Int {
            bits: 32,
            signed: true,
        };
        let relative = DataType::PointerRel {
            to: Box::new(field.clone()),
            bits: 32,
            parent: Box::new(DataType::Void),
            offset: 8,
        };
        assert_eq!(
            factory.strip_relative(&relative),
            factory.get_type_pointer(field)
        );
    }
}
