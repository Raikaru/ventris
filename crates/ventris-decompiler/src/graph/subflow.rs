//! Sub-variable flow and packed-condition reduction, ported from Ghidra 12.1.3.
//!
//! The graph rewrites mirror `SubvariableFlow::doTrace`, `traceForward`,
//! `traceBackward`, `createLink`, and `doReplacement` in `subflow.cc`.  The
//! opcode rules follow `RuleSubvarAnd`, `RuleSubvarSubpiece`,
//! `RuleSubvarShift`, `RuleSubvarCompZero`, `RuleSubvarZext`, and
//! `RuleSubvarSext` in `subflow.cc`, plus `RuleBoolZext` and `RuleLogic2Bool`
//! in `ruleaction.cc`, at commit `8b4c91d4d5bd1549622bfbade0df199585b98365`.
//!
//! PowerPC condition-register fields are packed bit lanes, not ordinary
//! integers.  Keeping a lane as an opaque word hides the comparison that a
//! later `CBRANCH` tests, so this module only rewrites lanes whose origin is
//! mechanically derivable.  A `MULTIEQUAL` is deliberately a hard boundary:
//! choosing one of its paths would change control flow.

use std::collections::BTreeSet;

use ventris_pcode::op;

use super::action::Rule;
use super::{Funcdata, OpId, VarnodeId};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum BitValue {
    Unknown,
    Known {
        value: bool,
        constant: Option<VarnodeId>,
    },
    Value(VarnodeId),
}

fn full_mask(size: u32) -> u64 {
    let bits = u64::from(size).saturating_mul(8);
    if bits == 0 {
        0
    } else if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn width_bits(size: u32) -> u32 {
    size.saturating_mul(8).min(64)
}

fn comparison(opcode: i32) -> bool {
    matches!(
        opcode,
        op::INT_EQUAL
            | op::INT_NOTEQUAL
            | op::INT_SLESS
            | op::INT_SLESSEQUAL
            | op::INT_LESS
            | op::INT_LESSEQUAL
            | op::INT_CARRY
            | op::INT_SCARRY
            | op::INT_SBORROW
            | op::FLOAT_EQUAL
            | op::FLOAT_NOTEQUAL
            | op::FLOAT_LESS
            | op::FLOAT_LESSEQUAL
            | op::FLOAT_NAN
    )
}

fn boolean_opcode(opcode: i32) -> bool {
    matches!(
        opcode,
        op::BOOL_NEGATE | op::BOOL_XOR | op::BOOL_AND | op::BOOL_OR
    )
}

fn constant_id(data: &Funcdata, value: bool) -> Option<VarnodeId> {
    let wanted = u64::from(value);
    (0..data.varnode_count())
        .map(|index| VarnodeId(index as u32))
        .find(|id| {
            let vn = data.varnode(*id);
            vn.flags.constant && vn.offset == wanted
        })
}
fn known(value: bool, preferred: Option<VarnodeId>) -> BitValue {
    BitValue::Known {
        value,
        constant: preferred,
    }
}

fn known_zero(value: BitValue) -> bool {
    matches!(value, BitValue::Known { value: false, .. })
}

fn known_one(value: BitValue) -> bool {
    matches!(value, BitValue::Known { value: true, .. })
}

fn combine_and(left: BitValue, right: BitValue) -> BitValue {
    if known_zero(left) || known_zero(right) {
        return known(false, None);
    }
    if known_one(left) {
        return right;
    }
    if known_one(right) {
        return left;
    }
    if let (BitValue::Value(a), BitValue::Value(b)) = (left, right)
        && a == b
    {
        return BitValue::Value(a);
    }
    BitValue::Unknown
}

fn combine_or(left: BitValue, right: BitValue) -> BitValue {
    if known_one(left) || known_one(right) {
        return known(true, None);
    }
    if known_zero(left) {
        return right;
    }
    if known_zero(right) {
        return left;
    }
    if let (BitValue::Value(a), BitValue::Value(b)) = (left, right)
        && a == b
    {
        return BitValue::Value(a);
    }
    BitValue::Unknown
}

fn combine_xor(left: BitValue, right: BitValue) -> BitValue {
    if known_zero(left) {
        return right;
    }
    if known_zero(right) {
        return left;
    }
    if let (BitValue::Known { value: a, .. }, BitValue::Known { value: b, .. }) = (left, right) {
        return known(a ^ b, None);
    }
    if let (BitValue::Value(a), BitValue::Value(b)) = (left, right)
        && a == b
    {
        return known(false, None);
    }
    BitValue::Unknown
}

fn is_boolean_value(data: &Funcdata, value: VarnodeId, seen: &mut BTreeSet<VarnodeId>) -> bool {
    if !seen.insert(value) {
        return false;
    }
    let vn = data.varnode(value);
    if vn.flags.constant {
        seen.remove(&value);
        return vn.offset <= 1;
    }
    if vn.flags.input && vn.size == 1 {
        seen.remove(&value);
        return true;
    }
    let result = match vn.def.and_then(|def| data.opcode_of(def)) {
        Some(code) if comparison(code) || boolean_opcode(code) => true,
        Some(op::COPY | op::CAST | op::INT_ZEXT | op::INT_SEXT) => data
            .op(vn.def.expect("definition exists"))
            .inputs
            .first()
            .is_some_and(|input| is_boolean_value(data, *input, seen)),
        Some(op::INT_AND) => {
            let operation = data.op(vn.def.expect("definition exists"));
            (operation
                .inputs
                .first()
                .is_some_and(|input| is_boolean_value(data, *input, seen))
                && operation.inputs.get(1).is_some_and(|input| {
                    let mask = data.varnode(*input);
                    mask.flags.constant && mask.offset == 1
                }))
                || (operation
                    .inputs
                    .get(1)
                    .is_some_and(|input| is_boolean_value(data, *input, seen))
                    && operation.inputs.first().is_some_and(|input| {
                        let mask = data.varnode(*input);
                        mask.flags.constant && mask.offset == 1
                    }))
        }
        _ => false,
    };
    seen.remove(&value);
    result
}

fn bit_expr(
    data: &Funcdata,
    value: VarnodeId,
    bit: u32,
    path: &mut BTreeSet<VarnodeId>,
) -> BitValue {
    if !path.insert(value) {
        return BitValue::Unknown;
    }
    let vn = data.varnode(value);
    let width = width_bits(vn.size);
    let result = if bit >= width {
        known(false, None)
    } else if vn.flags.constant {
        let bit_value = bit < 64 && ((vn.offset >> bit) & 1) != 0;
        let constant = (vn.offset == u64::from(bit_value)).then_some(value);
        known(bit_value, constant)
    } else {
        let definition = vn.def.and_then(|def| data.opcode_of(def));
        match definition {
            Some(code) if comparison(code) || boolean_opcode(code) => {
                if bit == 0 {
                    BitValue::Value(value)
                } else {
                    known(false, None)
                }
            }
            Some(op::MULTIEQUAL) => BitValue::Unknown,
            Some(op::COPY | op::CAST) => data
                .op(vn.def.expect("definition exists"))
                .inputs
                .first()
                .map_or(BitValue::Unknown, |input| bit_expr(data, *input, bit, path)),
            Some(op::INT_ZEXT) => {
                let operation = data.op(vn.def.expect("definition exists"));
                let Some(input) = operation.inputs.first().copied() else {
                    path.remove(&value);
                    return BitValue::Unknown;
                };
                if bit >= width_bits(data.varnode(input).size) {
                    known(false, None)
                } else {
                    bit_expr(data, input, bit, path)
                }
            }
            Some(op::INT_SEXT) => {
                let operation = data.op(vn.def.expect("definition exists"));
                let Some(input) = operation.inputs.first().copied() else {
                    path.remove(&value);
                    return BitValue::Unknown;
                };
                let input_width = width_bits(data.varnode(input).size);
                if bit < input_width {
                    bit_expr(data, input, bit, path)
                } else if input_width == 0 {
                    known(false, None)
                } else {
                    match bit_expr(data, input, input_width - 1, path) {
                        BitValue::Known { value, constant } => known(value, constant),
                        _ => BitValue::Unknown,
                    }
                }
            }
            Some(op::INT_AND) => {
                let operation = data.op(vn.def.expect("definition exists"));
                let left = operation.inputs.first().copied();
                let right = operation.inputs.get(1).copied();
                let (Some(left), Some(right)) = (left, right) else {
                    path.remove(&value);
                    return BitValue::Unknown;
                };
                if data.varnode(left).flags.constant {
                    if ((data.varnode(left).offset >> bit) & 1) == 0 {
                        known(false, None)
                    } else {
                        bit_expr(data, right, bit, path)
                    }
                } else if data.varnode(right).flags.constant {
                    if ((data.varnode(right).offset >> bit) & 1) == 0 {
                        known(false, None)
                    } else {
                        bit_expr(data, left, bit, path)
                    }
                } else {
                    combine_and(
                        bit_expr(data, left, bit, path),
                        bit_expr(data, right, bit, path),
                    )
                }
            }
            Some(op::INT_OR) | Some(op::INT_XOR) => {
                let operation = data.op(vn.def.expect("definition exists"));
                let Some(left) = operation.inputs.first().copied() else {
                    path.remove(&value);
                    return BitValue::Unknown;
                };
                let Some(right) = operation.inputs.get(1).copied() else {
                    path.remove(&value);
                    return BitValue::Unknown;
                };
                let left_value = bit_expr(data, left, bit, path);
                let right_value = bit_expr(data, right, bit, path);
                if definition == Some(op::INT_OR) {
                    combine_or(left_value, right_value)
                } else {
                    combine_xor(left_value, right_value)
                }
            }
            Some(op::INT_LEFT) => {
                let operation = data.op(vn.def.expect("definition exists"));
                let Some(input) = operation.inputs.first().copied() else {
                    path.remove(&value);
                    return BitValue::Unknown;
                };
                let Some(shift) = operation
                    .inputs
                    .get(1)
                    .filter(|shift| data.varnode(**shift).flags.constant)
                    .map(|shift| data.varnode(*shift).offset)
                else {
                    path.remove(&value);
                    return BitValue::Unknown;
                };
                if u64::from(bit) < shift {
                    known(false, None)
                } else {
                    let source_bit = u64::from(bit) - shift;
                    if source_bit >= 64 {
                        known(false, None)
                    } else {
                        bit_expr(data, input, source_bit as u32, path)
                    }
                }
            }
            Some(op::INT_RIGHT) => {
                let operation = data.op(vn.def.expect("definition exists"));
                let Some(input) = operation.inputs.first().copied() else {
                    path.remove(&value);
                    return BitValue::Unknown;
                };
                let Some(shift) = operation
                    .inputs
                    .get(1)
                    .filter(|shift| data.varnode(**shift).flags.constant)
                    .map(|shift| data.varnode(*shift).offset)
                else {
                    path.remove(&value);
                    return BitValue::Unknown;
                };
                let source_bit = shift.saturating_add(u64::from(bit));
                if source_bit >= u64::from(width_bits(data.varnode(input).size)) {
                    known(false, None)
                } else if source_bit >= 64 {
                    known(false, None)
                } else {
                    bit_expr(data, input, source_bit as u32, path)
                }
            }
            Some(op::INT_SRIGHT) => {
                let operation = data.op(vn.def.expect("definition exists"));
                let Some(input) = operation.inputs.first().copied() else {
                    path.remove(&value);
                    return BitValue::Unknown;
                };
                let Some(shift) = operation
                    .inputs
                    .get(1)
                    .filter(|shift| data.varnode(**shift).flags.constant)
                    .map(|shift| data.varnode(*shift).offset)
                else {
                    path.remove(&value);
                    return BitValue::Unknown;
                };
                let input_width = width_bits(data.varnode(input).size);
                let source_bit = shift.saturating_add(u64::from(bit));
                if source_bit < u64::from(input_width) && source_bit < 64 {
                    bit_expr(data, input, source_bit as u32, path)
                } else if input_width == 0 {
                    known(false, None)
                } else {
                    match bit_expr(data, input, input_width - 1, path) {
                        BitValue::Known { value, constant } => known(value, constant),
                        _ => BitValue::Unknown,
                    }
                }
            }
            Some(op::SUBPIECE) => {
                let operation = data.op(vn.def.expect("definition exists"));
                let Some(input) = operation.inputs.first().copied() else {
                    path.remove(&value);
                    return BitValue::Unknown;
                };
                let Some(offset) = operation
                    .inputs
                    .get(1)
                    .filter(|offset| data.varnode(**offset).flags.constant)
                    .map(|offset| data.varnode(*offset).offset)
                else {
                    path.remove(&value);
                    return BitValue::Unknown;
                };
                let source_bit = offset.saturating_mul(8).saturating_add(u64::from(bit));
                if source_bit >= 64 {
                    known(false, None)
                } else {
                    bit_expr(data, input, source_bit as u32, path)
                }
            }
            Some(op::PIECE) => {
                let operation = data.op(vn.def.expect("definition exists"));
                let Some(high) = operation.inputs.first().copied() else {
                    path.remove(&value);
                    return BitValue::Unknown;
                };
                let Some(low) = operation.inputs.get(1).copied() else {
                    path.remove(&value);
                    return BitValue::Unknown;
                };
                let low_width = width_bits(data.varnode(low).size);
                if bit < low_width {
                    bit_expr(data, low, bit, path)
                } else if bit - low_width < width_bits(data.varnode(high).size) {
                    bit_expr(data, high, bit - low_width, path)
                } else {
                    known(false, None)
                }
            }
            Some(op::INDIRECT) => data
                .op(vn.def.expect("definition exists"))
                .inputs
                .first()
                .map_or(BitValue::Unknown, |input| bit_expr(data, *input, bit, path)),
            _ => {
                // A free one-byte input is the graph's representation of a
                // machine boolean when no type lock is available.  Wider free
                // values remain opaque, as required for status/flag words.
                if bit > 0 && vn.size == 1 && vn.flags.input && vn.def.is_none() {
                    known(false, None)
                } else {
                    BitValue::Unknown
                }
            }
        }
    };
    path.remove(&value);
    result
}

/// Resolve one bit of a packed value to its existing source value.
///
/// The returned value is an existing comparison/boolean varnode whenever the
/// lane can be proven to be that value.  A constant is returned only when the
/// graph already contains a suitable `0` or `1` constant; `Funcdata` is
/// intentionally immutable here, so inventing a detached constant would not
/// preserve graph identity.  Any path-dependent merge or opaque input returns
/// `None` rather than guessing.
pub fn condition_bit(data: &Funcdata, value: VarnodeId, bit: u32) -> Option<VarnodeId> {
    let mut path = BTreeSet::new();
    match bit_expr(data, value, bit, &mut path) {
        BitValue::Value(value) => Some(value),
        BitValue::Known { value, constant } => constant.or_else(|| constant_id(data, value)),
        BitValue::Unknown => None,
    }
}

fn rewrite_copy(data: &mut Funcdata, operation: OpId, input: VarnodeId) -> usize {
    let current = data.op(operation).clone();
    if current.opcode == op::COPY && current.inputs == vec![input] {
        return 0;
    }
    data.op_set_opcode(operation, op::COPY);
    data.op_set_inputs(operation, vec![input]);
    1
}

fn existing_constant(data: &Funcdata, value: u64, size: u32) -> Option<VarnodeId> {
    (0..data.varnode_count())
        .map(|index| VarnodeId(index as u32))
        .find(|id| {
            let vn = data.varnode(*id);
            vn.flags.constant && vn.offset == value && vn.size == size
        })
}

fn rewrite_lane(
    data: &mut Funcdata,
    operation: OpId,
    input: VarnodeId,
    bit: u32,
    shift_size: u32,
) -> usize {
    if bit == 0 {
        return rewrite_copy(data, operation, input);
    }
    let shift = existing_constant(data, u64::from(bit), shift_size.max(1))
        .unwrap_or_else(|| data.new_constant(u64::from(bit), shift_size.max(1)));
    let current = data.op(operation).clone();
    if current.opcode == op::INT_LEFT && current.inputs == vec![input, shift] {
        return 0;
    }
    data.op_set_opcode(operation, op::INT_LEFT);
    data.op_set_inputs(operation, vec![input, shift]);
    1
}

fn rewrite_negate(data: &mut Funcdata, operation: OpId, input: VarnodeId) -> usize {
    let current = data.op(operation).clone();
    if current.opcode == op::BOOL_NEGATE && current.inputs == vec![input] {
        return 0;
    }
    data.op_set_opcode(operation, op::BOOL_NEGATE);
    data.op_set_inputs(operation, vec![input]);
    1
}

fn constant_operand(data: &Funcdata, operation: &super::GraphOp) -> Option<(usize, VarnodeId)> {
    operation
        .inputs
        .iter()
        .enumerate()
        .find_map(|(slot, value)| {
            data.varnode(*value)
                .flags
                .constant
                .then_some((slot, *value))
        })
}

/// A compact graph form of Ghidra's `SubvariableFlow` transform.
///
/// The full C++ transform creates parallel operations for every traversed
/// container.  Ventris' graph has no consume/type metadata, so this adapter
/// records the one-bit link that can be proved from the graph and applies the
/// same terminal extraction rewrites.  It never rewrites an operation unless
/// `condition_bit` found an existing source value.
pub struct SubvariableFlow {
    root: VarnodeId,
    mask: u64,
    source: Option<VarnodeId>,
}

impl SubvariableFlow {
    pub fn new(root: VarnodeId, mask: u64) -> Self {
        Self {
            root,
            mask,
            source: None,
        }
    }

    /// Trace a one-bit logical value through the graph.
    pub fn do_trace(&mut self, data: &Funcdata) -> bool {
        if self.mask == 0 || self.mask.count_ones() != 1 {
            self.source = None;
            return false;
        }
        let bit = self.mask.trailing_zeros();
        self.source = condition_bit(data, self.root, bit);
        self.source.is_some()
    }
    /// Return the linked source, if tracing succeeded.
    pub fn source(&self) -> Option<VarnodeId> {
        self.source
    }

    /// Apply terminal extraction rewrites discovered by [`Self::do_trace`].
    pub fn do_replacement(&self, data: &mut Funcdata) -> usize {
        let Some(source) = self.source else {
            return 0;
        };
        let bit = self.mask.trailing_zeros();
        let readers: Vec<OpId> = data
            .varnode(self.root)
            .descendants
            .iter()
            .copied()
            .collect();
        let mut changes = 0;
        for reader in readers {
            let operation = data.op(reader).clone();
            match operation.opcode {
                op::INT_AND => {
                    if let Some((_, constant)) = constant_operand(data, &operation)
                        && data.varnode(constant).offset == self.mask
                    {
                        changes +=
                            rewrite_lane(data, reader, source, bit, data.varnode(constant).size);
                    }
                }
                op::INT_RIGHT | op::INT_SRIGHT => {
                    if operation.inputs.get(1).is_some_and(|shift| {
                        data.varnode(*shift).flags.constant
                            && data.varnode(*shift).offset == u64::from(bit)
                    }) {
                        changes += rewrite_copy(data, reader, source);
                    }
                }
                op::INT_EQUAL | op::INT_NOTEQUAL => {
                    if let Some((_, constant)) = constant_operand(data, &operation) {
                        let value = data.varnode(constant).offset;
                        if value == 0 || value == self.mask {
                            let equal = operation.opcode == op::INT_EQUAL;
                            let invert = if value == 0 { equal } else { !equal };
                            if invert {
                                changes += rewrite_negate(data, reader, source);
                            } else {
                                changes += rewrite_copy(data, reader, source);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        changes
    }
}

/// Reduce `AND(value, single_lane_mask)` to the comparison/boolean that owns
/// the lane.  This is the terminal `SubvariableFlow` case for flag fields.
pub struct RuleSubvarAnd;

impl Rule for RuleSubvarAnd {
    fn name(&self) -> &'static str {
        "subvar_and"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_AND]
    }

    fn apply_op(&self, operation: OpId, data: &mut Funcdata) -> usize {
        let current = data.op(operation).clone();
        let Some((constant_slot, constant)) = constant_operand(data, &current) else {
            return 0;
        };
        let Some(value) = current.inputs.get(1 - constant_slot).copied() else {
            return 0;
        };
        let mask = data.varnode(constant).offset & full_mask(data.varnode(value).size);
        if mask == 0 || mask.count_ones() != 1 {
            return 0;
        }
        let mut flow = SubvariableFlow::new(value, mask);
        if !flow.do_trace(data) {
            return 0;
        }
        let Some(source) = flow.source() else {
            return 0;
        };
        rewrite_lane(
            data,
            operation,
            source,
            mask.trailing_zeros(),
            data.varnode(constant).size,
        )
    }
}

/// Reduce a byte/word `SUBPIECE` whose low output bit is a single logical lane.
pub struct RuleSubvarSubpiece;

impl Rule for RuleSubvarSubpiece {
    fn name(&self) -> &'static str {
        "subvar_subpiece"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::SUBPIECE]
    }

    fn apply_op(&self, operation: OpId, data: &mut Funcdata) -> usize {
        let current = data.op(operation).clone();
        let Some(value) = current.inputs.first().copied() else {
            return 0;
        };
        let Some(offset) = current.inputs.get(1).copied() else {
            return 0;
        };
        if !data.varnode(offset).flags.constant {
            return 0;
        }
        let Some(output) = current.output else {
            return 0;
        };
        let output_bits = width_bits(data.varnode(output).size);
        if output_bits == 0 || output_bits > 64 {
            return 0;
        }
        let base = data.varnode(offset).offset.saturating_mul(8);
        if base >= 64 {
            return 0;
        }
        let Some(source) = condition_bit(data, value, base as u32) else {
            return 0;
        };
        let mut path = BTreeSet::new();
        for bit in 1..output_bits {
            let source_bit = base.saturating_add(u64::from(bit));
            if source_bit >= 64 || !known_zero(bit_expr(data, value, source_bit as u32, &mut path))
            {
                return 0;
            }
        }
        rewrite_copy(data, operation, source)
    }
}

/// Reduce a constant right shift which moves exactly one known lane to bit 0.
pub struct RuleSubvarShift;

impl Rule for RuleSubvarShift {
    fn name(&self) -> &'static str {
        "subvar_shift"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_RIGHT, op::INT_SRIGHT]
    }

    fn apply_op(&self, operation: OpId, data: &mut Funcdata) -> usize {
        let current = data.op(operation).clone();
        let Some(value) = current.inputs.first().copied() else {
            return 0;
        };
        let Some(shift) = current.inputs.get(1).copied() else {
            return 0;
        };
        if !data.varnode(shift).flags.constant {
            return 0;
        }
        let shift = data.varnode(shift).offset;
        if shift >= 64 {
            return 0;
        }
        let masks = data.nonzero_masks();
        let mask = masks[value.0 as usize];
        if ((mask >> shift) != 1) || (mask & (1u64 << shift)) == 0 {
            return 0;
        }
        let Some(source) = condition_bit(data, value, shift as u32) else {
            return 0;
        };
        rewrite_copy(data, operation, source)
    }
}

/// Reduce a comparison of a single masked lane against zero or the lane mask.
pub struct RuleSubvarCompZero;

impl Rule for RuleSubvarCompZero {
    fn name(&self) -> &'static str {
        "subvar_compzero"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_EQUAL, op::INT_NOTEQUAL]
    }

    fn apply_op(&self, operation: OpId, data: &mut Funcdata) -> usize {
        let current = data.op(operation).clone();
        let Some((constant_slot, constant)) = constant_operand(data, &current) else {
            return 0;
        };
        let Some(value) = current.inputs.get(1 - constant_slot).copied() else {
            return 0;
        };
        let masks = data.nonzero_masks();
        let mask = masks[value.0 as usize];
        if mask == 0 || mask.count_ones() != 1 {
            return 0;
        }
        let tested = data.varnode(constant).offset;
        if tested != 0 && tested != mask {
            return 0;
        }
        let Some(source) = condition_bit(data, value, mask.trailing_zeros()) else {
            return 0;
        };
        let equal = current.opcode == op::INT_EQUAL;
        let invert = if tested == 0 { equal } else { !equal };
        if invert {
            rewrite_negate(data, operation, source)
        } else {
            rewrite_copy(data, operation, source)
        }
    }
}

/// Simplify a zero-extension of a boolean when a direct comparison consumes it.
pub struct RuleBoolZext;

impl Rule for RuleBoolZext {
    fn name(&self) -> &'static str {
        "bool_zext"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_ZEXT]
    }

    fn apply_op(&self, operation: OpId, data: &mut Funcdata) -> usize {
        let current = data.op(operation).clone();
        let Some(boolean) = current.inputs.first().copied() else {
            return 0;
        };
        if !is_boolean_value(data, boolean, &mut BTreeSet::new()) {
            return 0;
        }
        let Some(output) = current.output else {
            return 0;
        };
        let readers: Vec<OpId> = data.varnode(output).descendants.iter().copied().collect();
        let mut changes = 0;
        for reader in readers {
            let consumer = data.op(reader).clone();
            if !matches!(consumer.opcode, op::INT_EQUAL | op::INT_NOTEQUAL) {
                continue;
            }
            let Some((slot, constant)) = constant_operand(data, &consumer) else {
                continue;
            };
            if consumer.inputs.get(1 - slot).copied() != Some(output) {
                continue;
            }
            let compared = data.varnode(constant).offset;
            if compared > 1 {
                continue;
            }
            let invert = if compared == 0 {
                consumer.opcode == op::INT_EQUAL
            } else {
                consumer.opcode == op::INT_NOTEQUAL
            };
            if invert {
                changes += rewrite_negate(data, reader, boolean);
            } else {
                changes += rewrite_copy(data, reader, boolean);
            }
        }
        changes
    }
}

/// Apply the same boolean comparison reduction to a zero-extension trigger.
pub struct RuleSubvarZext;

impl Rule for RuleSubvarZext {
    fn name(&self) -> &'static str {
        "subvar_zext"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_ZEXT]
    }

    fn apply_op(&self, operation: OpId, data: &mut Funcdata) -> usize {
        RuleBoolZext.apply_op(operation, data)
    }
}

/// Reduce comparisons consuming a sign-extension of a boolean.
pub struct RuleSubvarSext;

impl Rule for RuleSubvarSext {
    fn name(&self) -> &'static str {
        "subvar_sext"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_SEXT]
    }

    fn apply_op(&self, operation: OpId, data: &mut Funcdata) -> usize {
        let current = data.op(operation).clone();
        let Some(boolean) = current.inputs.first().copied() else {
            return 0;
        };
        if !is_boolean_value(data, boolean, &mut BTreeSet::new()) {
            return 0;
        }
        let Some(output) = current.output else {
            return 0;
        };
        let all_ones = full_mask(data.varnode(output).size);
        let readers: Vec<OpId> = data.varnode(output).descendants.iter().copied().collect();
        let mut changes = 0;
        for reader in readers {
            let consumer = data.op(reader).clone();
            if !matches!(consumer.opcode, op::INT_EQUAL | op::INT_NOTEQUAL) {
                continue;
            }
            let Some((slot, constant)) = constant_operand(data, &consumer) else {
                continue;
            };
            if consumer.inputs.get(1 - slot).copied() != Some(output) {
                continue;
            }
            let compared = data.varnode(constant).offset;
            if compared != 0 && compared != all_ones {
                continue;
            }
            let equal = consumer.opcode == op::INT_EQUAL;
            let invert = if compared == 0 { equal } else { !equal };
            if invert {
                changes += rewrite_negate(data, reader, boolean);
            } else {
                changes += rewrite_copy(data, reader, boolean);
            }
        }
        changes
    }
}

/// Convert integer AND/OR/XOR to their boolean p-code forms when both inputs
/// are known boolean values.
pub struct RuleLogic2Bool;

impl Rule for RuleLogic2Bool {
    fn name(&self) -> &'static str {
        "logic2bool"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INT_AND, op::INT_OR, op::INT_XOR]
    }

    fn apply_op(&self, operation: OpId, data: &mut Funcdata) -> usize {
        let current = data.op(operation).clone();
        let Some(left) = current.inputs.first().copied() else {
            return 0;
        };
        let Some(right) = current.inputs.get(1).copied() else {
            return 0;
        };
        if !is_boolean_value(data, left, &mut BTreeSet::new())
            || !is_boolean_value(data, right, &mut BTreeSet::new())
        {
            return 0;
        }
        let bool_opcode = match current.opcode {
            op::INT_AND => op::BOOL_AND,
            op::INT_OR => op::BOOL_OR,
            op::INT_XOR => op::BOOL_XOR,
            _ => return 0,
        };
        data.op_set_opcode(operation, bool_opcode);
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::SeqNum;
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    fn comparison_value(
        data: &mut Funcdata,
        block: super::super::GraphBlockId,
        opcode: i32,
        address: u64,
    ) -> VarnodeId {
        let left = data.new_varnode(REGISTER_SPACE, address, 4);
        let right = data.new_varnode(REGISTER_SPACE, address + 0x100, 4);
        let compare = data.new_op(opcode, seq(address), vec![left, right]);
        let result = data.new_unique(1);
        data.op_set_output(compare, Some(result));
        data.op_insert_end(compare, block);
        result
    }

    #[test]
    fn ppc_condition_field_resolves_comparison_lanes() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let less = comparison_value(&mut data, block, op::INT_LESS, 0x1000);
        let greater = comparison_value(&mut data, block, op::INT_LESS, 0x1010);
        let equal = comparison_value(&mut data, block, op::INT_EQUAL, 0x1020);

        let shift3 = data.new_constant(3, 1);
        let shift2 = data.new_constant(2, 1);
        let shift1 = data.new_constant(1, 1);
        let left3 = data.new_op(op::INT_LEFT, seq(0x1030), vec![less, shift3]);
        let lane3 = data.new_unique(4);
        data.op_set_output(left3, Some(lane3));
        data.op_insert_end(left3, block);
        let left2 = data.new_op(op::INT_LEFT, seq(0x1034), vec![greater, shift2]);
        let lane2 = data.new_unique(4);
        data.op_set_output(left2, Some(lane2));
        data.op_insert_end(left2, block);
        let left1 = data.new_op(op::INT_LEFT, seq(0x1038), vec![equal, shift1]);
        let lane1 = data.new_unique(4);
        data.op_set_output(left1, Some(lane1));
        data.op_insert_end(left1, block);
        let summary = data.new_varnode(REGISTER_SPACE, 0x200, 1);
        data.mark_input(summary);
        let first_or = data.new_op(op::INT_OR, seq(0x103c), vec![lane3, lane2]);
        let first = data.new_unique(4);
        data.op_set_output(first_or, Some(first));
        data.op_insert_end(first_or, block);
        let second_or = data.new_op(op::INT_OR, seq(0x1040), vec![first, lane1]);
        let second = data.new_unique(4);
        data.op_set_output(second_or, Some(second));
        data.op_insert_end(second_or, block);
        let final_or = data.new_op(op::INT_OR, seq(0x1044), vec![second, summary]);
        let packed = data.new_unique(4);
        data.op_set_output(final_or, Some(packed));
        data.op_insert_end(final_or, block);

        assert_eq!(condition_bit(&data, packed, 1), Some(equal));
        assert_eq!(condition_bit(&data, packed, 2), Some(greater));
        assert_eq!(condition_bit(&data, packed, 3), Some(less));

        let lane_mask = data.new_constant(2, 4);
        let and = data.new_op(op::INT_AND, seq(0x1048), vec![packed, lane_mask]);
        let masked = data.new_unique(4);
        data.op_set_output(and, Some(masked));
        data.op_insert_end(and, block);
        assert_eq!(RuleSubvarAnd.apply_op(and, &mut data), 1);
        assert_eq!(data.op(and).opcode, op::INT_LEFT);
        assert_eq!(data.op(and).inputs[0], equal);
    }

    #[test]
    fn opaque_merge_lane_is_not_guessed() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x2000);
        let incoming = data.new_varnode(REGISTER_SPACE, 0x300, 4);
        data.mark_input(incoming);
        let phi = data.new_op(op::MULTIEQUAL, seq(0x2000), vec![incoming]);
        let merged = data.new_unique(4);
        data.op_set_output(phi, Some(merged));
        data.op_set_input(phi, merged, 1);
        data.op_insert_end(phi, block);
        let lane_mask = data.new_constant(2, 4);
        let and = data.new_op(op::INT_AND, seq(0x2004), vec![merged, lane_mask]);
        let masked = data.new_unique(4);
        data.op_set_output(and, Some(masked));
        data.op_insert_end(and, block);
        let zero = data.new_constant(0, 4);
        let compare = data.new_op(op::INT_EQUAL, seq(0x2008), vec![masked, zero]);
        let result = data.new_unique(1);
        data.op_set_output(compare, Some(result));
        data.op_insert_end(compare, block);

        assert_eq!(condition_bit(&data, masked, 1), None);
        assert_eq!(RuleSubvarAnd.apply_op(and, &mut data), 0);
        assert_eq!(RuleSubvarCompZero.apply_op(compare, &mut data), 0);
        assert_eq!(data.op(and).opcode, op::INT_AND);
        assert_eq!(data.op(compare).opcode, op::INT_EQUAL);
    }

    #[test]
    fn compzero_and_single_bit_rules_reduce_known_lanes() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x3000);
        let comparison = comparison_value(&mut data, block, op::INT_EQUAL, 0x3000);
        let mask = data.new_constant(1, 4);
        let and = data.new_op(op::INT_AND, seq(0x3010), vec![comparison, mask]);
        let masked = data.new_unique(4);
        data.op_set_output(and, Some(masked));
        data.op_insert_end(and, block);
        let zero = data.new_constant(0, 4);
        let test = data.new_op(op::INT_NOTEQUAL, seq(0x3014), vec![masked, zero]);
        let result = data.new_unique(1);
        data.op_set_output(test, Some(result));
        data.op_insert_end(test, block);

        assert_eq!(RuleSubvarAnd.apply_op(and, &mut data), 1);
        assert_eq!(data.op(and).opcode, op::COPY);
        assert_eq!(data.op(and).inputs, vec![comparison]);
        assert_eq!(RuleSubvarCompZero.apply_op(test, &mut data), 1);
        assert_eq!(data.op(test).opcode, op::COPY);
        assert_eq!(data.op(test).inputs, vec![comparison]);

        let three = data.new_constant(3, 1);
        let left = data.new_op(op::INT_LEFT, seq(0x3020), vec![comparison, three]);
        let shifted = data.new_unique(1);
        data.op_set_output(left, Some(shifted));
        data.op_insert_end(left, block);
        let right = data.new_op(op::INT_RIGHT, seq(0x3024), vec![shifted, three]);
        let unshifted = data.new_unique(1);
        data.op_set_output(right, Some(unshifted));
        data.op_insert_end(right, block);
        assert_eq!(RuleSubvarShift.apply_op(right, &mut data), 1);
        assert_eq!(data.op(right).inputs, vec![comparison]);

        let offset = data.new_constant(0, 1);
        let subpiece = data.new_op(op::SUBPIECE, seq(0x3028), vec![comparison, offset]);
        let byte = data.new_unique(1);
        data.op_set_output(subpiece, Some(byte));
        data.op_insert_end(subpiece, block);
        assert_eq!(RuleSubvarSubpiece.apply_op(subpiece, &mut data), 1);
        assert_eq!(data.op(subpiece).inputs, vec![comparison]);
    }

    #[test]
    fn absent_shift_and_nonconstant_subpiece_do_not_fire() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x4000);
        let value = data.new_varnode(REGISTER_SPACE, 0x500, 1);
        data.mark_input(value);
        let dynamic = data.new_varnode(REGISTER_SPACE, 0x504, 1);
        data.mark_input(dynamic);
        let shift = data.new_op(op::INT_RIGHT, seq(0x4000), vec![value, dynamic]);
        let shifted = data.new_unique(1);
        data.op_set_output(shift, Some(shifted));
        data.op_insert_end(shift, block);
        assert_eq!(RuleSubvarShift.apply_op(shift, &mut data), 0);

        let offset = data.new_varnode(REGISTER_SPACE, 0x508, 1);
        data.mark_input(offset);
        let subpiece = data.new_op(op::SUBPIECE, seq(0x4004), vec![value, offset]);
        let output = data.new_unique(1);
        data.op_set_output(subpiece, Some(output));
        data.op_insert_end(subpiece, block);
        assert_eq!(RuleSubvarSubpiece.apply_op(subpiece, &mut data), 0);
    }

    #[test]
    fn bool_extensions_and_logic_are_reduced_only_for_booleans() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x5000);
        let boolean = comparison_value(&mut data, block, op::INT_EQUAL, 0x5000);
        let zext = data.new_op(op::INT_ZEXT, seq(0x5010), vec![boolean]);
        let extended = data.new_unique(4);
        data.op_set_output(zext, Some(extended));
        data.op_insert_end(zext, block);
        let zero = data.new_constant(0, 4);
        let test = data.new_op(op::INT_EQUAL, seq(0x5014), vec![extended, zero]);
        let result = data.new_unique(1);
        data.op_set_output(test, Some(result));
        data.op_insert_end(test, block);
        assert_eq!(RuleBoolZext.apply_op(zext, &mut data), 1);
        assert_eq!(data.op(test).opcode, op::BOOL_NEGATE);
        assert_eq!(data.op(test).inputs, vec![boolean]);

        let other = comparison_value(&mut data, block, op::INT_LESS, 0x5020);
        let logic = data.new_op(op::INT_AND, seq(0x5030), vec![boolean, other]);
        let logic_out = data.new_unique(1);
        data.op_set_output(logic, Some(logic_out));
        data.op_insert_end(logic, block);
        assert_eq!(RuleLogic2Bool.apply_op(logic, &mut data), 1);
        assert_eq!(data.op(logic).opcode, op::BOOL_AND);

        let opaque = data.new_varnode(REGISTER_SPACE, 0x610, 4);
        data.mark_input(opaque);
        let bad_logic = data.new_op(op::INT_OR, seq(0x5040), vec![boolean, opaque]);
        let bad_out = data.new_unique(4);
        data.op_set_output(bad_logic, Some(bad_out));
        data.op_insert_end(bad_logic, block);
        assert_eq!(RuleLogic2Bool.apply_op(bad_logic, &mut data), 0);
    }

    #[test]
    fn sign_extension_rule_and_flow_reject_unproven_inputs() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x6000);
        let boolean = comparison_value(&mut data, block, op::INT_EQUAL, 0x6000);
        let sext = data.new_op(op::INT_SEXT, seq(0x6010), vec![boolean]);
        let extended = data.new_unique(4);
        data.op_set_output(sext, Some(extended));
        data.op_insert_end(sext, block);
        let ones = data.new_constant(0xffff_ffff, 4);
        let test = data.new_op(op::INT_EQUAL, seq(0x6014), vec![extended, ones]);
        let result = data.new_unique(1);
        data.op_set_output(test, Some(result));
        data.op_insert_end(test, block);
        assert_eq!(RuleSubvarSext.apply_op(sext, &mut data), 1);
        assert_eq!(data.op(test).opcode, op::COPY);
        assert_eq!(data.op(test).inputs, vec![boolean]);

        let opaque = data.new_varnode(REGISTER_SPACE, 0x700, 4);
        data.mark_input(opaque);
        let mut flow = SubvariableFlow::new(opaque, 2);
        assert!(!flow.do_trace(&data));
        assert_eq!(flow.do_replacement(&mut data), 0);
    }
}
