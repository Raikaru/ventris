//! Splitting aggregate COPY, LOAD, and STORE operations into their components.
//!
//! Port of Ghidra 12.1.3's `SplitDatatype` and the three rules that drive it —
//! `RuleSplitCopy`, `RuleSplitLoad`, `RuleSplitStore` — from `subflow.cc`.
//!
//! One machine instruction can move a whole structure. Printed as a single
//! assignment it says nothing about what was moved; split into one operation per
//! field it reads as the field assignments the source wrote. The whole algorithm
//! is a matching problem: find components of the incoming and outgoing types with
//! equal size at equal offsets, and refuse the split unless every byte is
//! accounted for.
//!
//! Two facets of the source are absent here and neither is reachable:
//!
//! - Ghidra's `TypePartialStruct` metatype. `TypeFactory::get_exact_piece`
//!   returns a structure of exactly the windowed fields instead, which is what a
//!   partial struct describes, so the paths that test for the metatype are
//!   expressed as tests on that window.
//! - The proto-partial marking in `buildOutConcats`
//!   (`setProtoPartial`/`setPartialRoot`/`registerProtoPartialRoot`). Those mark
//!   a CONCAT stack for the merge pass; the concatenation itself is built
//!   identically without them. This graph has no proto-partial registry.
//!
//! `Varnode::isAddrTied` becomes "not unique and not constant": a value in a
//! machine space has shared storage that a later STORE can reach, which is the
//! property every use of the flag here depends on.

use ventris_pcode::op;

use super::typefactory::{DataType, TypeFactory};
use super::{Funcdata, OpId, VarnodeId, action::Rule};

/// A matched pair of component types at one offset within the whole.
///
/// Ghidra's `SplitDatatype::Component`.
#[derive(Clone, Debug)]
struct Component {
    /// Type coming into the logical COPY.
    in_type: DataType,
    /// Type coming out of the logical COPY.
    out_type: DataType,
    /// Byte offset of this piece within the whole.
    offset: u32,
}

/// The pointer a LOAD or STORE addresses, and the root it is offset from.
///
/// Ghidra's `SplitDatatype::RootPointer`. The distinction between the immediate
/// pointer and the root matters because the split emits one pointer per
/// component, and those are built from the root plus a component offset. Backing
/// up to the root is what lets `s->field` and `s->other` share `s`.
#[derive(Clone, Debug)]
struct RootPointer {
    /// The pointer type of the root.
    ptr_type: DataType,
    /// The direct pointer input of the LOAD or STORE.
    first_pointer: VarnodeId,
    /// The root pointer.
    pointer: VarnodeId,
    /// Byte offset of the access relative to the root.
    base_offset: i64,
}

impl RootPointer {
    /// Follow the pointer back through one INT_ADD, PTRSUB, PTRADD, or COPY.
    ///
    /// `RootPointer::backUpPointer`.
    fn back_up_pointer(
        &mut self,
        data: &Funcdata,
        rich: &super::typefactory::RecoveredTypes,
        implied_base: Option<&DataType>,
    ) -> bool {
        let Some(def) = data.varnode(self.pointer).def else {
            return false;
        };
        let add_op = data.op(def);
        let offset = match add_op.opcode {
            op::PTRSUB | op::INT_ADD | op::PTRADD => {
                let Some(constant) = add_op
                    .inputs
                    .get(1)
                    .copied()
                    .filter(|value| data.varnode(*value).flags.constant)
                else {
                    return false;
                };
                data.varnode(constant).offset as i64
            }
            op::COPY => 0,
            _ => return false,
        };
        let Some(tmp_pointer) = add_op.inputs.first().copied() else {
            return false;
        };
        let Some(ty) = rich.get(tmp_pointer) else {
            return false;
        };
        let Some(parent) = pointee(ty) else {
            return false;
        };
        if !matches!(parent, DataType::Struct { .. } | DataType::Array { .. }) {
            // Only an array step or a plain copy may land on the element type
            // the caller allowed: any other operation reaching a non-aggregate
            // means the root is not an aggregate pointer and there is nothing to
            // split against.
            let allowed = matches!(add_op.opcode, op::PTRADD | op::COPY)
                && implied_base.is_some_and(|base| *base == parent);
            if !allowed {
                return false;
            }
        }
        let offset = if add_op.opcode == op::PTRADD {
            let stride = add_op
                .inputs
                .get(2)
                .copied()
                .filter(|value| data.varnode(*value).flags.constant)
                .map_or(1, |value| data.varnode(value).offset as i64);
            offset.saturating_mul(stride)
        } else {
            offset
        };
        self.ptr_type = ty.clone();
        self.base_offset = self.base_offset.saturating_add(offset);
        self.pointer = tmp_pointer;
        true
    }

    /// Locate the root pointer for a LOAD or STORE addressing `value_type`.
    ///
    /// `RootPointer::find`. One hop is allowed to reach a pointer to the value
    /// type; from there up to three further hops climb out of nested aggregates.
    fn find(
        data: &Funcdata,
        rich: &super::typefactory::RecoveredTypes,
        load_store: OpId,
        value_type: &DataType,
    ) -> Option<Self> {
        let mut value_type = value_type.clone();
        let mut implied_base = None;
        if let DataType::Array { element, .. } = &value_type {
            // A pointer to the first element is an accepted match for a pointer
            // to the array: they address the same byte.
            value_type = element.as_ref().clone();
            implied_base = Some(value_type.clone());
        }
        let pointer = data.op(load_store).inputs.get(1).copied()?;
        let ty = rich.get(pointer)?;
        pointee(ty)?;
        let mut root = Self {
            ptr_type: ty.clone(),
            first_pointer: pointer,
            pointer,
            base_offset: 0,
        };
        if pointee(&root.ptr_type) != Some(value_type.clone()) {
            if implied_base.is_some() {
                return None;
            }
            if !root.back_up_pointer(data, rich, implied_base.as_ref()) {
                return None;
            }
            if pointee(&root.ptr_type) != Some(value_type.clone()) {
                return None;
            }
        }
        for _ in 0..3 {
            if is_addr_tied(data, root.pointer) || data.lone_descend(root.pointer).is_none() {
                break;
            }
            if !root.back_up_pointer(data, rich, implied_base.as_ref()) {
                break;
            }
        }
        Some(root)
    }

    /// COPY the root into a temporary and make that the root.
    ///
    /// `RootPointer::duplicateToTemp`. A root in shared storage can be written
    /// by one of the STOREs the split is about to emit, which would change what
    /// the later pointers mean.
    fn duplicate_to_temp(&mut self, data: &mut Funcdata, follow_op: OpId) {
        let size = data.varnode(self.pointer).size;
        let seq = data.op(follow_op).seq;
        let copy = data.new_op(op::COPY, seq, vec![self.pointer]);
        let temp = data.new_unique(size);
        data.op_set_output(copy, Some(temp));
        data.op_insert_before(copy, follow_op);
        self.pointer = temp;
    }

    /// Remove the pointer arithmetic the split made dead.
    ///
    /// `RootPointer::freePointerChain`.
    fn free_pointer_chain(&mut self, data: &mut Funcdata) {
        while self.first_pointer != self.pointer
            && !is_addr_tied(data, self.first_pointer)
            && data.varnode(self.first_pointer).descendants.is_empty()
        {
            let Some(def) = data.varnode(self.first_pointer).def else {
                break;
            };
            let Some(next) = data.op(def).inputs.first().copied() else {
                break;
            };
            self.first_pointer = next;
            data.op_destroy(def);
        }
    }
}

/// What a pointer points at, for both plain and relative pointers.
fn pointee(ty: &DataType) -> Option<DataType> {
    match ty {
        DataType::Pointer { to, .. } => Some(to.as_ref().clone()),
        DataType::PointerRel { to, .. } => Some(to.as_ref().clone()),
        _ => None,
    }
}

/// Whether a value's storage is shared, standing in for `Varnode::isAddrTied`.
fn is_addr_tied(data: &Funcdata, id: VarnodeId) -> bool {
    let flags = data.varnode(id).flags;
    !flags.unique && !flags.constant
}

/// How a type may be split.
///
/// `SplitDatatype::categorizeDatatype`'s return, named rather than numbered.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Category {
    /// Structure-based, needs splitting.
    Structure,
    /// Array-based, needs splitting.
    Array,
    /// Primitive, splittable many ways: it takes its shape from the other side.
    Primitive,
}

/// The splitting engine.
struct SplitDatatype<'a> {
    factory: &'a TypeFactory,
    pieces: Vec<Component>,
    split_structures: bool,
    split_arrays: bool,
    is_load_store: bool,
}

impl<'a> SplitDatatype<'a> {
    fn new(factory: &'a TypeFactory) -> Self {
        Self {
            factory,
            pieces: Vec::new(),
            // Ghidra reads these from `split_datatype_config`; both halves of
            // the option are on in its default configuration.
            split_structures: true,
            split_arrays: true,
            is_load_store: false,
        }
    }

    /// The component of `ty` starting exactly at `offset`, descending as far as
    /// needed, or an undefined type covering a hole.
    ///
    /// `SplitDatatype::getComponent`.
    fn get_component(&self, ty: &DataType, offset: u32) -> Option<(DataType, bool)> {
        let mut current = ty.clone();
        let mut current_offset = offset;
        loop {
            match self.factory.sub_type(&current, current_offset) {
                Some((component, remainder)) => {
                    current = component;
                    current_offset = remainder;
                }
                None => {
                    let hole = self.factory.hole_size(ty, offset);
                    if hole > 0 {
                        return Some((DataType::Unknown(hole.min(8) * 8), true));
                    }
                    return None;
                }
            }
            if current_offset == 0 && !matches!(current, DataType::Array { .. }) {
                return Some((current, false));
            }
        }
    }

    /// `SplitDatatype::categorizeDatatype`.
    fn categorize(&self, ty: &DataType) -> Option<Category> {
        match ty {
            DataType::Array { element, .. } => {
                if !self.split_arrays {
                    return None;
                }
                // An array of unknown bytes has no interior structure to
                // recover, so it behaves as one large primitive.
                if matches!(element.as_ref(), DataType::Unknown(8)) {
                    Some(Category::Primitive)
                } else {
                    Some(Category::Array)
                }
            }
            DataType::Struct { .. } => {
                if !self.split_structures {
                    return None;
                }
                (TypeFactory::num_depend(ty) > 1).then_some(Category::Structure)
            }
            DataType::Int { .. } | DataType::Unknown(_) => Some(Category::Primitive),
            _ => None,
        }
    }

    /// Whether the two types split into matching components, recording them.
    ///
    /// `SplitDatatype::testDatatypeCompatibility`.
    fn test_datatype_compatibility(
        &mut self,
        in_base: &DataType,
        out_base: &DataType,
        in_constant: bool,
    ) -> bool {
        let Some(in_category) = self.categorize(in_base) else {
            return false;
        };
        let Some(out_category) = self.categorize(out_base) else {
            return false;
        };
        if in_category == Category::Primitive && out_category == Category::Primitive {
            return false;
        }
        if !in_constant && in_base == out_base && matches!(in_base, DataType::Struct { .. }) {
            // Splitting a structure into itself says nothing. Initialising one
            // from a constant does, which is the exception Ghidra carves out.
            return false;
        }
        if self.is_load_store {
            if out_category == Category::Primitive && in_category == Category::Array {
                return false;
            }
            if in_category == Category::Primitive && !in_constant && out_category == Category::Array
            {
                return false;
            }
            if in_category == Category::Array && out_category == Category::Array && !in_constant {
                return false;
            }
        }

        let mut offset = 0_u32;
        let mut size_left = TypeFactory::align_size(in_base) as i64;
        if in_category == Category::Primitive {
            while size_left > 0 {
                let Some((out_component, out_hole)) = self.get_component(out_base, offset) else {
                    return false;
                };
                let width = TypeFactory::align_size(&out_component);
                if width == 0 {
                    return false;
                }
                // A constant carries its own value into each piece, so the
                // incoming type is the outgoing one. Anything else is storage of
                // the right width and nothing more.
                let in_component = if in_constant {
                    out_component.clone()
                } else {
                    DataType::Unknown(width * 8)
                };
                self.pieces.push(Component {
                    in_type: in_component,
                    out_type: out_component,
                    offset,
                });
                size_left -= i64::from(width);
                offset += width;
                if out_hole && self.hole_refuses(size_left) {
                    return false;
                }
            }
        } else if out_category == Category::Primitive {
            while size_left > 0 {
                let Some((in_component, in_hole)) = self.get_component(in_base, offset) else {
                    return false;
                };
                let width = TypeFactory::align_size(&in_component);
                if width == 0 {
                    return false;
                }
                self.pieces.push(Component {
                    in_type: in_component,
                    out_type: DataType::Unknown(width * 8),
                    offset,
                });
                size_left -= i64::from(width);
                offset += width;
                if in_hole && self.hole_refuses(size_left) {
                    return false;
                }
            }
        } else {
            while size_left > 0 {
                let Some((mut in_component, mut in_hole)) = self.get_component(in_base, offset)
                else {
                    return false;
                };
                let Some((mut out_component, mut out_hole)) = self.get_component(out_base, offset)
                else {
                    return false;
                };
                // Descend whichever side is wider until the two agree. A hole
                // has no interior, so it is cut to the other side's width
                // instead.
                while TypeFactory::align_size(&in_component)
                    != TypeFactory::align_size(&out_component)
                {
                    if TypeFactory::align_size(&in_component)
                        > TypeFactory::align_size(&out_component)
                    {
                        let width = TypeFactory::align_size(&out_component);
                        if in_hole {
                            in_component = DataType::Unknown(width * 8);
                        } else {
                            let Some((next, hole)) = self.get_component(&in_component, 0) else {
                                return false;
                            };
                            if TypeFactory::align_size(&next)
                                >= TypeFactory::align_size(&in_component)
                            {
                                return false;
                            }
                            in_component = next;
                            in_hole = hole;
                        }
                    } else {
                        let width = TypeFactory::align_size(&in_component);
                        if out_hole {
                            out_component = DataType::Unknown(width * 8);
                        } else {
                            let Some((next, hole)) = self.get_component(&out_component, 0) else {
                                return false;
                            };
                            if TypeFactory::align_size(&next)
                                >= TypeFactory::align_size(&out_component)
                            {
                                return false;
                            }
                            out_component = next;
                            out_hole = hole;
                        }
                    }
                }
                let width = TypeFactory::align_size(&in_component);
                if width == 0 {
                    return false;
                }
                self.pieces.push(Component {
                    in_type: in_component,
                    out_type: out_component,
                    offset,
                });
                size_left -= i64::from(width);
                offset += width;
            }
        }
        self.pieces.len() > 1
    }

    /// Whether a hole at the current position makes the split not worth doing.
    ///
    /// A hole as the very first piece means the access starts in padding, and a
    /// two-piece split where one is a hole is padding rather than structure.
    fn hole_refuses(&self, size_left: i64) -> bool {
        self.pieces.len() == 1 || (size_left == 0 && self.pieces.len() == 2)
    }

    /// `SplitDatatype::testCopyConstraints`.
    fn test_copy_constraints(&self, data: &Funcdata, copy_op: OpId) -> bool {
        let Some(in_vn) = data.op(copy_op).inputs.first().copied() else {
            return false;
        };
        if data.varnode(in_vn).flags.input {
            return false;
        }
        if is_addr_tied(data, in_vn) {
            if let Some(out_vn) = data.op(copy_op).output
                && is_addr_tied(data, out_vn)
                && data.varnode(out_vn).location() == data.varnode(in_vn).location()
            {
                return false;
            }
        } else if let Some(def) = data.varnode(in_vn).def
            && data.op(def).opcode == op::LOAD
            && data.lone_descend(in_vn) == Some(copy_op)
        {
            // A LOAD feeding one COPY is the LOAD split's business, and doing it
            // here would emit the pieces twice.
            return false;
        }
        true
    }

    /// Build the incoming pieces of a constant by cutting up its value.
    ///
    /// `SplitDatatype::buildInConstants`.
    fn build_in_constants(
        &self,
        data: &mut Funcdata,
        root: VarnodeId,
        big_endian: bool,
    ) -> Vec<VarnodeId> {
        let base_value = data.varnode(root).offset;
        let root_size = data.varnode(root).size;
        self.pieces
            .iter()
            .map(|piece| {
                let width = TypeFactory::align_size(&piece.in_type);
                let offset = if big_endian {
                    root_size.saturating_sub(piece.offset).saturating_sub(width)
                } else {
                    piece.offset
                };
                let value = base_value
                    .checked_shr(8u32.saturating_mul(offset))
                    .unwrap_or(0)
                    & mask(width);
                data.new_constant(value, width)
            })
            .collect()
    }

    /// Build the incoming pieces by taking SUBPIECEs of the root.
    ///
    /// `SplitDatatype::buildInSubpieces`.
    fn build_in_subpieces(
        &self,
        data: &mut Funcdata,
        root: VarnodeId,
        follow_op: OpId,
        big_endian: bool,
    ) -> Vec<VarnodeId> {
        if let Some(constants) = self.generate_constants(data, root, big_endian) {
            return constants;
        }
        let root_size = data.varnode(root).size;
        let seq = data.op(follow_op).seq;
        let mut built = Vec::with_capacity(self.pieces.len());
        for piece in &self.pieces {
            let width = TypeFactory::align_size(&piece.in_type);
            let offset = if big_endian {
                root_size.saturating_sub(piece.offset).saturating_sub(width)
            } else {
                piece.offset
            };
            let shift = data.new_constant(u64::from(offset), 4);
            let subpiece = data.new_op(op::SUBPIECE, seq, vec![root, shift]);
            let out = data.new_unique(width);
            data.op_set_output(subpiece, Some(out));
            data.op_insert_before(subpiece, follow_op);
            built.push(out);
        }
        built
    }

    /// Split an extended-precision constant into per-piece constants.
    ///
    /// `SplitDatatype::generateConstants`, for the `ZEXT(c)` and `PIECE(c1, c2)`
    /// forms. Returning the pieces directly beats taking SUBPIECEs of a value
    /// that is already known.
    fn generate_constants(
        &self,
        data: &mut Funcdata,
        vn: VarnodeId,
        big_endian: bool,
    ) -> Option<Vec<VarnodeId>> {
        data.lone_descend(vn)?;
        let def = data.varnode(vn).def?;
        let operation = data.op(def);
        let full_size = data.varnode(vn).size;
        let (high, low, low_size) = match operation.opcode {
            op::INT_ZEXT => {
                let source = operation.inputs.first().copied()?;
                if !data.varnode(source).flags.constant {
                    return None;
                }
                (0, data.varnode(source).offset, data.varnode(source).size)
            }
            op::PIECE => {
                let high = operation.inputs.first().copied()?;
                let low = operation.inputs.get(1).copied()?;
                if !data.varnode(high).flags.constant || !data.varnode(low).flags.constant {
                    return None;
                }
                (
                    data.varnode(high).offset,
                    data.varnode(low).offset,
                    data.varnode(low).size,
                )
            }
            _ => return None,
        };
        let mut built = Vec::with_capacity(self.pieces.len());
        for piece in &self.pieces {
            let width = TypeFactory::align_size(&piece.in_type);
            if width > 8 {
                return None;
            }
            let shift = if big_endian {
                full_size.saturating_sub(piece.offset).saturating_sub(width)
            } else {
                piece.offset
            };
            let mut value = if shift >= low_size {
                high.checked_shr(shift - low_size).unwrap_or(0)
            } else {
                let mut value = low.checked_shr(shift.saturating_mul(8)).unwrap_or(0);
                if shift + width > low_size {
                    value |= high
                        .checked_shl(low_size.saturating_sub(shift).saturating_mul(8))
                        .unwrap_or(0);
                }
                value
            };
            value &= mask(width);
            built.push(data.new_constant(value, width));
        }
        data.op_destroy(def);
        Some(built)
    }

    /// Build the outgoing pieces as storage at offsets from the root.
    ///
    /// `SplitDatatype::buildOutVarnodes`.
    fn build_out_varnodes(&self, data: &mut Funcdata, root: VarnodeId) -> Vec<VarnodeId> {
        let base = data.varnode(root).location();
        self.pieces
            .iter()
            .map(|piece| {
                let width = TypeFactory::align_size(&piece.out_type);
                data.new_varnode(base.space, base.offset + u64::from(piece.offset), width)
            })
            .collect()
    }

    /// Concatenate the outgoing pieces back into the root.
    ///
    /// `SplitDatatype::buildOutConcats`. Readers of the whole still need the
    /// whole, and the PIECE stack is how the graph says the pieces are it.
    fn build_out_concats(
        &self,
        data: &mut Funcdata,
        root: VarnodeId,
        previous_op: OpId,
        out_varnodes: &[VarnodeId],
        big_endian: bool,
    ) {
        if data.varnode(root).descendants.is_empty() || out_varnodes.len() < 2 {
            return;
        }
        let seq = data.op(previous_op).seq;
        let mut previous = previous_op;
        // Most significant first, which is index order on a big-endian layout
        // and its reverse on a little-endian one.
        let order: Vec<VarnodeId> = if big_endian {
            out_varnodes.to_vec()
        } else {
            out_varnodes.iter().rev().copied().collect()
        };
        let mut accumulated = order[0];
        let mut concat = None;
        for (index, piece) in order.iter().enumerate().skip(1) {
            let op_id = data.new_op(op::PIECE, seq, vec![accumulated, *piece]);
            data.op_insert_after(op_id, previous);
            concat = Some(op_id);
            if index + 1 >= order.len() {
                break;
            }
            previous = op_id;
            let size = data
                .varnode(accumulated)
                .size
                .saturating_add(data.varnode(*piece).size);
            let out = data.new_unique(size);
            data.op_set_output(op_id, Some(out));
            accumulated = out;
        }
        if let Some(concat) = concat {
            data.op_set_output(concat, Some(root));
        }
    }

    /// Build one pointer per component from a root pointer.
    ///
    /// `SplitDatatype::buildPointers`. An offset inside the pointed-at type is a
    /// PTRSUB to a field; an offset beyond it is a PTRADD by whole elements,
    /// which is how a pointer walks an array.
    fn build_pointers(
        &self,
        data: &mut Funcdata,
        root: VarnodeId,
        ptr_type: &DataType,
        base_offset: i64,
        follow_op: OpId,
        is_input: bool,
    ) -> Option<Vec<VarnodeId>> {
        let base_type = pointee(ptr_type)?;
        // Ghidra retypes each intermediate pointer with
        // `getTypePointerStripArray`. Types here live in a recovered-type
        // snapshot rather than on the varnode, so the intermediate pointers take
        // their types from the next inference pass instead of being stamped now.
        let seq = data.op(follow_op).seq;
        let pointer_size = data.varnode(root).size;
        let mut built = Vec::with_capacity(self.pieces.len());
        for piece in &self.pieces {
            let match_type = if is_input {
                &piece.in_type
            } else {
                &piece.out_type
            };
            let match_width = TypeFactory::align_size(match_type);
            let mut current_offset = base_offset.saturating_add(i64::from(piece.offset));
            let mut current_type = base_type.clone();
            let mut in_pointer = root;
            loop {
                let current_width = i64::from(TypeFactory::align_size(&current_type));
                let (new_type, new_offset) = if current_width <= 0
                    || current_offset < 0
                    || current_offset >= current_width
                {
                    // Outside the type means an array walk: the type repeats and
                    // the offset wraps into one element.
                    if current_width <= 0 {
                        return None;
                    }
                    let wrapped = current_offset.rem_euclid(current_width);
                    (current_type.clone(), wrapped)
                } else {
                    match self
                        .factory
                        .sub_type(&current_type, u32::try_from(current_offset).ok()?)
                    {
                        Some((component, remainder)) => (component, i64::from(remainder)),
                        // Null here is a hole, and the precomputed component
                        // type is what fills it.
                        None => (match_type.clone(), 0),
                    }
                };
                let step_is_element =
                    current_type == new_type || matches!(current_type, DataType::Array { .. });
                let new_op = if step_is_element {
                    let element_size = i64::from(TypeFactory::align_size(&new_type));
                    if element_size <= 0 {
                        return None;
                    }
                    let index = current_offset.saturating_sub(new_offset) / element_size;
                    let index_vn = data.new_constant(index as u64, pointer_size);
                    let stride_vn = data.new_constant(element_size as u64, pointer_size);
                    data.new_op(op::PTRADD, seq, vec![in_pointer, index_vn, stride_vn])
                } else {
                    let displacement = current_offset.saturating_sub(new_offset);
                    let displacement_vn = data.new_constant(displacement as u64, pointer_size);
                    data.new_op(op::PTRSUB, seq, vec![in_pointer, displacement_vn])
                };
                let out = data.new_unique(pointer_size);
                data.op_set_output(new_op, Some(out));
                data.op_insert_before(new_op, follow_op);
                in_pointer = out;
                current_type = new_type;
                current_offset = new_offset;
                if TypeFactory::align_size(&current_type) <= match_width {
                    break;
                }
            }
            built.push(in_pointer);
        }
        Some(built)
    }

    /// Whether any reader of the value performs arithmetic on it.
    ///
    /// `SplitDatatype::isArithmeticInput`. Arithmetic on the whole means the
    /// whole is a number to its readers, whatever its recovered type says.
    fn is_arithmetic_input(data: &Funcdata, vn: VarnodeId) -> bool {
        data.varnode(vn)
            .descendants
            .iter()
            .any(|op_id| is_arithmetic(data.op(*op_id).opcode))
    }

    /// `SplitDatatype::isArithmeticOutput`.
    fn is_arithmetic_output(data: &Funcdata, vn: VarnodeId) -> bool {
        data.varnode(vn)
            .def
            .is_some_and(|def| is_arithmetic(data.op(def).opcode))
    }

    /// `SplitDatatype::splitCopy`.
    fn split_copy(
        &mut self,
        data: &mut Funcdata,
        copy_op: OpId,
        in_type: &DataType,
        out_type: &DataType,
        big_endian: bool,
    ) -> bool {
        if !self.test_copy_constraints(data, copy_op) {
            return false;
        }
        let Some(in_vn) = data.op(copy_op).inputs.first().copied() else {
            return false;
        };
        let in_constant = data.varnode(in_vn).flags.constant;
        if !self.test_datatype_compatibility(in_type, out_type, in_constant) {
            return false;
        }
        if Self::is_arithmetic_output(data, in_vn) {
            return false;
        }
        let Some(out_vn) = data.op(copy_op).output else {
            return false;
        };
        if Self::is_arithmetic_input(data, out_vn) {
            return false;
        }
        let in_varnodes = if in_constant {
            self.build_in_constants(data, in_vn, big_endian)
        } else {
            self.build_in_subpieces(data, in_vn, copy_op, big_endian)
        };
        if in_varnodes.len() != self.pieces.len() {
            return false;
        }
        let out_varnodes = self.build_out_varnodes(data, out_vn);
        self.build_out_concats(data, out_vn, copy_op, &out_varnodes, big_endian);
        let seq = data.op(copy_op).seq;
        for (source, destination) in in_varnodes.iter().zip(&out_varnodes) {
            let copy = data.new_op(op::COPY, seq, vec![*source]);
            data.op_set_output(copy, Some(*destination));
            data.op_insert_before(copy, copy_op);
        }
        data.op_destroy(copy_op);
        true
    }

    /// `SplitDatatype::splitLoad`.
    fn split_load(
        &mut self,
        data: &mut Funcdata,
        rich: &super::typefactory::RecoveredTypes,
        load_op: OpId,
        in_type: &DataType,
        big_endian: bool,
    ) -> bool {
        self.is_load_store = true;
        let Some(load_out) = data.op(load_op).output else {
            return false;
        };
        let mut out_vn = load_out;
        let mut copy_op = None;
        if !is_addr_tied(data, out_vn) {
            copy_op = data.lone_descend(out_vn);
        }
        if let Some(candidate) = copy_op {
            match data.op(candidate).opcode {
                // A LOAD feeding a STORE is the STORE split's business.
                op::STORE => return false,
                op::COPY => {}
                _ => copy_op = None,
            }
        }
        if let Some(candidate) = copy_op
            && let Some(output) = data.op(candidate).output
        {
            out_vn = output;
        }
        let Some(out_type) = rich.get(out_vn).cloned() else {
            return false;
        };
        if !self.test_datatype_compatibility(in_type, &out_type, false) {
            return false;
        }
        if Self::is_arithmetic_input(data, out_vn) {
            return false;
        }
        let _factory = self.factory;
        let Some(mut root) = RootPointer::find(data, rich, load_op, in_type) else {
            return false;
        };
        let insert_point = copy_op.unwrap_or(load_op);
        let ptr_type = root.ptr_type.clone();
        let Some(ptr_varnodes) = self.build_pointers(
            data,
            root.pointer,
            &ptr_type,
            root.base_offset,
            load_op,
            true,
        ) else {
            return false;
        };
        let out_varnodes = self.build_out_varnodes(data, out_vn);
        self.build_out_concats(data, out_vn, insert_point, &out_varnodes, big_endian);
        let Some(space) = data.op(load_op).inputs.first().copied() else {
            return false;
        };
        let seq = data.op(insert_point).seq;
        for (pointer, destination) in ptr_varnodes.iter().zip(&out_varnodes) {
            let load = data.new_op(op::LOAD, seq, vec![space, *pointer]);
            data.op_set_output(load, Some(*destination));
            data.op_insert_before(load, insert_point);
        }
        if let Some(candidate) = copy_op {
            data.op_destroy(candidate);
        }
        data.op_destroy(load_op);
        root.free_pointer_chain(data);
        true
    }

    /// `SplitDatatype::splitStore`.
    fn split_store(
        &mut self,
        data: &mut Funcdata,
        rich: &super::typefactory::RecoveredTypes,
        store_op: OpId,
        out_type: &DataType,
        big_endian: bool,
    ) -> bool {
        self.is_load_store = true;
        let Some(in_vn) = data.op(store_op).inputs.get(2).copied() else {
            return false;
        };
        let mut load_op = None;
        let mut in_type = None;
        if let Some(def) = data.varnode(in_vn).def
            && data.op(def).opcode == op::LOAD
            && data.lone_descend(in_vn) == Some(store_op)
        {
            let size = data.varnode(in_vn).size;
            if let Some(ty) = value_datatype(data, rich, self.factory, def, size) {
                load_op = Some(def);
                in_type = Some(ty);
            }
        }
        let in_constant = data.varnode(in_vn).flags.constant;
        if in_type.is_none() {
            in_type = rich.get(in_vn).cloned();
        }
        let Some(mut resolved_in) = in_type else {
            return false;
        };
        if !self.test_datatype_compatibility(&resolved_in, out_type, in_constant) {
            // The LOAD may be what makes the types disagree; the store is still
            // splittable against the stored value's own type.
            if load_op.is_none() {
                return false;
            }
            load_op = None;
            let Some(plain) = rich.get(in_vn).cloned() else {
                return false;
            };
            resolved_in = plain;
            self.pieces.clear();
            if !self.test_datatype_compatibility(&resolved_in, out_type, in_constant) {
                return false;
            }
        }
        if Self::is_arithmetic_output(data, in_vn) {
            return false;
        }
        let _factory = self.factory;
        let Some(mut store_root) = RootPointer::find(data, rich, store_op, out_type) else {
            return false;
        };
        let mut load_root = None;
        if let Some(load) = load_op {
            let Some(root) = RootPointer::find(data, rich, load, &resolved_in) else {
                return false;
            };
            load_root = Some(root);
        }
        let Some(store_space) = data.op(store_op).inputs.first().copied() else {
            return false;
        };

        let in_varnodes = if in_constant {
            self.build_in_constants(data, in_vn, big_endian)
        } else if let (Some(load), Some(mut root)) = (load_op, load_root.clone()) {
            let ptr_type = root.ptr_type.clone();
            let Some(load_pointers) =
                self.build_pointers(data, root.pointer, &ptr_type, root.base_offset, load, true)
            else {
                return false;
            };
            let Some(load_space) = data.op(load).inputs.first().copied() else {
                return false;
            };
            let seq = data.op(load).seq;
            let mut built = Vec::with_capacity(load_pointers.len());
            for (pointer, piece) in load_pointers.iter().zip(&self.pieces) {
                let width = TypeFactory::align_size(&piece.in_type);
                let new_load = data.new_op(op::LOAD, seq, vec![load_space, *pointer]);
                let out = data.new_unique(width);
                data.op_set_output(new_load, Some(out));
                data.op_insert_before(new_load, load);
                built.push(out);
            }
            root.free_pointer_chain(data);
            load_root = Some(root);
            built
        } else {
            self.build_in_subpieces(data, in_vn, store_op, big_endian)
        };
        if in_varnodes.len() != self.pieces.len() {
            return false;
        }

        if is_addr_tied(data, store_root.pointer) {
            store_root.duplicate_to_temp(data, store_op);
        }
        let ptr_type = store_root.ptr_type.clone();
        let Some(store_pointers) = self.build_pointers(
            data,
            store_root.pointer,
            &ptr_type,
            store_root.base_offset,
            store_op,
            false,
        ) else {
            return false;
        };
        if store_pointers.len() != in_varnodes.len() {
            return false;
        }
        // The original STORE becomes the first of the pieces so that anything
        // referring to it, an INDIRECT above all, still refers to a real store.
        data.op_set_input(store_op, store_pointers[0], 1);
        data.op_set_input(store_op, in_varnodes[0], 2);
        let seq = data.op(store_op).seq;
        let mut last_store = store_op;
        for (pointer, value) in store_pointers.iter().zip(&in_varnodes).skip(1) {
            let new_store = data.new_op(op::STORE, seq, vec![store_space, *pointer, *value]);
            data.op_insert_after(new_store, last_store);
            last_store = new_store;
        }

        if let Some(load) = load_op {
            data.op_destroy(load);
            if let Some(mut root) = load_root {
                root.free_pointer_chain(data);
            }
        }
        store_root.free_pointer_chain(data);
        true
    }
}

/// The type of the value a LOAD or STORE addresses, sized to the access.
///
/// `SplitDatatype::getValueDatatype`. A relative pointer contributes its
/// container and offset, which is exactly what makes a field access recognisable
/// as a window on the enclosing structure.
fn value_datatype(
    data: &Funcdata,
    rich: &super::typefactory::RecoveredTypes,
    factory: &TypeFactory,
    load_store: OpId,
    size: u32,
) -> Option<DataType> {
    let pointer = data.op(load_store).inputs.get(1).copied()?;
    let ptr_type = rich.get(pointer)?;
    let (result, base_offset) = match ptr_type {
        DataType::PointerRel { parent, offset, .. } => (parent.as_ref().clone(), *offset),
        DataType::Pointer { to, .. } => (to.as_ref().clone(), 0),
        _ => return None,
    };
    if matches!(result, DataType::Spacebase) {
        return None;
    }
    let align = TypeFactory::align_size(&result);
    if align < size {
        if matches!(
            result,
            DataType::Int { .. } | DataType::Bool | DataType::Float(_) | DataType::Pointer { .. }
        ) && align != 0
            && size % align == 0
        {
            return Some(factory.get_type_array(result, (size / align) as usize));
        }
        return None;
    }
    if matches!(result, DataType::Struct { .. } | DataType::Array { .. }) {
        return factory.get_exact_piece(&result, base_offset, size);
    }
    None
}

/// Whether an opcode is arithmetic, matching `TypeOp::isArithmeticOp`.
fn is_arithmetic(opcode: i32) -> bool {
    matches!(
        opcode,
        op::INT_ADD
            | op::INT_SUB
            | op::INT_MULT
            | op::INT_DIV
            | op::INT_SDIV
            | op::INT_REM
            | op::INT_SREM
            | op::INT_LEFT
            | op::INT_RIGHT
            | op::INT_SRIGHT
            | op::INT_2COMP
            | op::FLOAT_ADD
            | op::FLOAT_SUB
            | op::FLOAT_MULT
            | op::FLOAT_DIV
            | op::FLOAT_NEG
    )
}

/// The low `width` bytes as a mask.
fn mask(width: u32) -> u64 {
    if width >= 8 {
        u64::MAX
    } else {
        (1_u64 << (width * 8)) - 1
    }
}

/// The recovered types and factory a split needs, or nothing.
fn recovered(data: &Funcdata) -> std::rc::Rc<(TypeFactory, super::typefactory::RecoveredTypes)> {
    data.recovered_types()
}

/// `RuleSplitCopy`: split a COPY of an aggregate into one COPY per component.
pub struct RuleSplitCopy;

impl Rule for RuleSplitCopy {
    fn name(&self) -> &'static str {
        "splitcopy"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::COPY]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(in_vn) = data.op(id).inputs.first().copied() else {
            return 0;
        };
        let Some(out_vn) = data.op(id).output else {
            return 0;
        };
        let big_endian = data.big_endian;
        let types = recovered(data);
        let (factory, rich) = &*types;
        let (Some(in_type), Some(out_type)) = (rich.get(in_vn).cloned(), rich.get(out_vn).cloned())
        else {
            return 0;
        };
        if !is_aggregate(&in_type) && !is_aggregate(&out_type) {
            return 0;
        }
        let mut splitter = SplitDatatype::new(factory);
        usize::from(splitter.split_copy(data, id, &in_type, &out_type, big_endian))
    }
}

/// `RuleSplitLoad`: split a LOAD of an aggregate into one LOAD per component.
pub struct RuleSplitLoad;

impl Rule for RuleSplitLoad {
    fn name(&self) -> &'static str {
        "splitload"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::LOAD]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(out_vn) = data.op(id).output else {
            return 0;
        };
        let size = data.varnode(out_vn).size;
        let big_endian = data.big_endian;
        let types = recovered(data);
        let (factory, rich) = &*types;
        let Some(in_type) = value_datatype(data, rich, factory, id, size) else {
            return 0;
        };
        if !is_aggregate(&in_type) {
            return 0;
        }
        let mut splitter = SplitDatatype::new(factory);
        usize::from(splitter.split_load(data, rich, id, &in_type, big_endian))
    }
}

/// `RuleSplitStore`: split a STORE of an aggregate into one STORE per component.
pub struct RuleSplitStore;

impl Rule for RuleSplitStore {
    fn name(&self) -> &'static str {
        "splitstore"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::STORE]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(in_vn) = data.op(id).inputs.get(2).copied() else {
            return 0;
        };
        let size = data.varnode(in_vn).size;
        let big_endian = data.big_endian;
        let types = recovered(data);
        let (factory, rich) = &*types;
        let Some(out_type) = value_datatype(data, rich, factory, id, size) else {
            return 0;
        };
        if !is_aggregate(&out_type) {
            return 0;
        }
        let mut splitter = SplitDatatype::new(factory);
        usize::from(splitter.split_store(data, rich, id, &out_type, big_endian))
    }
}

/// Whether a type has components to split into.
fn is_aggregate(ty: &DataType) -> bool {
    matches!(ty, DataType::Struct { .. } | DataType::Array { .. })
}

/// Every rule in this module, for the pipeline's batch registration.
pub fn all() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(RuleSplitCopy),
        Box::new(RuleSplitLoad),
        Box::new(RuleSplitStore),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ventris_lifter::{RAM_SPACE, REGISTER_SPACE};

    use super::super::SeqNum;
    use super::super::typefactory::{Field, RecoveredTypes, infer};
    use super::*;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    /// A structure of two 32-bit fields, the smallest thing worth splitting.
    fn pair(factory: &TypeFactory) -> DataType {
        let word = DataType::Int {
            bits: 32,
            signed: false,
        };
        factory.get_type_struct_fields(
            "pair".to_owned(),
            vec![
                Field {
                    offset: 0,
                    ty: word.clone(),
                    name: "field_0".to_owned(),
                },
                Field {
                    offset: 4,
                    ty: word,
                    name: "field_4".to_owned(),
                },
            ],
        )
    }

    fn types_for(
        data: &Funcdata,
        factory: &TypeFactory,
        seed: BTreeMap<VarnodeId, DataType>,
    ) -> RecoveredTypes {
        infer(data, factory, &seed)
    }

    #[test]
    fn a_structure_store_becomes_one_store_per_field() {
        // One instruction can move a whole structure. Split, it reads as the
        // field assignments the source wrote.
        let factory = TypeFactory::new(32);
        let structure = pair(&factory);
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let space = data.new_constant(u64::from(RAM_SPACE), 4);
        let pointer = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        data.mark_input(pointer);
        let value = data.new_constant(0x1111_1111_2222_2222, 8);
        let store = data.new_op(op::STORE, seq(0x1000), vec![space, pointer, value]);
        data.op_insert_end(store, block);

        let mut seed = BTreeMap::new();
        seed.insert(pointer, factory.get_type_pointer(structure.clone()));
        let rich = types_for(&data, &factory, seed);

        let out_type = value_datatype(&data, &rich, &factory, store, 8)
            .expect("a pointer to the pair describes the stored value");
        assert_eq!(out_type, structure);

        let mut splitter = SplitDatatype::new(&factory);
        assert!(
            splitter.split_store(&mut data, &rich, store, &out_type, false),
            "a two-field structure store must split"
        );

        let stores: Vec<OpId> = data
            .live_ops()
            .filter(|(_, op)| op.opcode == op::STORE)
            .map(|(id, _)| id)
            .collect();
        assert_eq!(stores.len(), 2, "one store per field");
        // Each store addresses the structure through its own field pointer, and
        // the values are the halves of the original constant.
        // The offset a value lands at is the whole point, so the pair is what
        // gets asserted: sorting the two lists apart would pass either way.
        let mut pairs: Vec<(u64, u64)> = stores
            .iter()
            .map(|id| {
                let address = data.op(*id).inputs[1];
                let def = data.varnode(address).def.expect("a field pointer");
                assert_eq!(data.op(def).opcode, op::PTRSUB);
                let displacement = data.varnode(data.op(def).inputs[1]).offset;
                let value = data.op(*id).inputs[2];
                assert!(data.varnode(value).flags.constant, "a split constant");
                (displacement, data.varnode(value).offset)
            })
            .collect();
        pairs.sort_unstable();
        assert_eq!(
            pairs,
            vec![(0, 0x2222_2222), (4, 0x1111_1111)],
            "little endian puts the low half of the value in the first field"
        );
    }

    #[test]
    fn a_big_endian_store_takes_the_fields_the_other_way() {
        // Which end a piece comes from is the whole meaning of the split, so the
        // same constant lands in the opposite fields.
        let factory = TypeFactory::new(32);
        let structure = pair(&factory);
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let space = data.new_constant(u64::from(RAM_SPACE), 4);
        let pointer = data.new_varnode(REGISTER_SPACE, 0x20, 4);
        data.mark_input(pointer);
        let value = data.new_constant(0x1111_1111_2222_2222, 8);
        let store = data.new_op(op::STORE, seq(0x1000), vec![space, pointer, value]);
        data.op_insert_end(store, block);

        let mut seed = BTreeMap::new();
        seed.insert(pointer, factory.get_type_pointer(structure.clone()));
        let rich = types_for(&data, &factory, seed);

        let mut splitter = SplitDatatype::new(&factory);
        assert!(splitter.split_store(&mut data, &rich, store, &structure, true));

        let mut pairs: Vec<(u64, u64)> = data
            .live_ops()
            .filter(|(_, op)| op.opcode == op::STORE)
            .map(|(id, _)| {
                let address = data.op(id).inputs[1];
                let def = data.varnode(address).def.expect("a field pointer");
                let displacement = data.varnode(data.op(def).inputs[1]).offset;
                let value = data.varnode(data.op(id).inputs[2]).offset;
                (displacement, value)
            })
            .collect();
        pairs.sort_unstable();
        assert_eq!(
            pairs,
            vec![(0, 0x1111_1111), (4, 0x2222_2222)],
            "big endian takes the high field first"
        );
    }

    #[test]
    fn a_structure_copied_to_itself_is_not_split() {
        // Splitting a structure into the same structure says nothing that the
        // single assignment did not, so Ghidra refuses it unless the source is a
        // constant initialiser.
        let factory = TypeFactory::new(32);
        let structure = pair(&factory);
        let mut splitter = SplitDatatype::new(&factory);
        assert!(
            !splitter.test_datatype_compatibility(&structure, &structure, false),
            "a whole-structure copy must not split"
        );
        let mut initialiser = SplitDatatype::new(&factory);
        assert!(
            initialiser.test_datatype_compatibility(&structure, &structure, true),
            "the same copy from a constant is an initialisation and does split"
        );
    }

    #[test]
    fn padding_is_not_a_component() {
        // A two-piece split where one piece is a gap is padding, not structure,
        // and naming the gap a field would invent storage.
        let factory = TypeFactory::new(32);
        let structure = factory.get_type_struct_fields(
            "padded".to_owned(),
            vec![Field {
                offset: 0,
                ty: DataType::Int {
                    bits: 32,
                    signed: false,
                },
                name: "field_0".to_owned(),
            }],
        );
        let mut splitter = SplitDatatype::new(&factory);
        assert!(
            !splitter.test_datatype_compatibility(&DataType::Unknown(64), &structure, false),
            "one field and one hole is padding"
        );
    }

    #[test]
    fn an_array_of_unknown_bytes_acts_as_one_value() {
        // `unknown1[n]` has no interior to recover, so Ghidra treats it as a
        // large primitive rather than splitting it byte by byte.
        let factory = TypeFactory::new(32);
        let bytes = factory.get_type_array(DataType::Unknown(8), 8);
        let splitter = SplitDatatype::new(&factory);
        assert_eq!(splitter.categorize(&bytes), Some(Category::Primitive));
        let words = factory.get_type_array(
            DataType::Int {
                bits: 32,
                signed: false,
            },
            2,
        );
        assert_eq!(splitter.categorize(&words), Some(Category::Array));
    }

    #[test]
    fn a_hole_between_fields_is_typed_by_its_width() {
        // `getComponent` gives a gap an undefined type of exactly the gap's
        // width, which is what lets a split step across padding.
        let factory = TypeFactory::new(32);
        let structure = factory.get_type_struct_fields(
            "gapped".to_owned(),
            vec![
                Field {
                    offset: 0,
                    ty: DataType::Int {
                        bits: 32,
                        signed: false,
                    },
                    name: "field_0".to_owned(),
                },
                Field {
                    offset: 8,
                    ty: DataType::Int {
                        bits: 32,
                        signed: false,
                    },
                    name: "field_8".to_owned(),
                },
            ],
        );
        let splitter = SplitDatatype::new(&factory);
        let (hole, is_hole) = splitter
            .get_component(&structure, 4)
            .expect("the gap is reported");
        assert!(is_hole);
        assert_eq!(TypeFactory::align_size(&hole), 4);
    }
}
