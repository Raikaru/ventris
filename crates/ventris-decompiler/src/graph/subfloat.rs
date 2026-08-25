//! Floating-point sub-variable flow from Ghidra 12.1.3's `subflow.cc`.
//!
//! `RuleSubfloatConvert` below keeps the part of `SubfloatFlow` that can be
//! represented by this graph: a precision slice is traced through the
//! copy/unary/binary floating operations that Ghidra permits, and a successful
//! trace rewrites those existing operations to the smaller logical varnodes.
//! The graph has no `TransformManager` placeholders, floating-format encoder,
//! address-force/type-lock/auto-live flags, or recursive-op destruction helper.
//! Consequently constants of a different size, wide input varnodes, and
//! transformations requiring those pieces are conservatively declined.
//!
//! `RuleDumptyHumpLate` is intentionally omitted.  The late rule is not a
//! different operand shape: it recursively backtracks through `PIECE` while
//! the live `RuleDumptyHump` performs one such step.  Ghidra makes them
//! disjoint by running the latter in the `analysis` action group and the
//! former in the later `cleanup` group.  This graph's `Rule` contract carries
//! no action-group/phase state, so registering both would offer both rules the
//! same `SUBPIECE(PIECE(...), offset)` operands.

use std::collections::{BTreeMap, BTreeSet};

use super::action::Rule;
use super::{Funcdata, OpId, VarnodeId};
use ventris_pcode::op;

fn input(data: &Funcdata, id: OpId, slot: usize) -> Option<VarnodeId> {
    data.op(id).inputs.get(slot).copied()
}

fn output(data: &Funcdata, id: OpId) -> Option<VarnodeId> {
    data.op(id).output
}

fn live_def(data: &Funcdata, value: VarnodeId) -> Option<OpId> {
    data.varnode(value)
        .def
        .filter(|candidate| data.opcode_of(*candidate).is_some())
}

fn is_constant(data: &Funcdata, value: VarnodeId) -> bool {
    data.varnode(value).flags.constant
}

fn is_free(data: &Funcdata, value: VarnodeId) -> bool {
    let node = data.varnode(value);
    !node.flags.written && !node.flags.input
}

fn is_binary_float(opcode: i32) -> bool {
    matches!(
        opcode,
        op::FLOAT_ADD | op::FLOAT_SUB | op::FLOAT_MULT | op::FLOAT_DIV
    )
}

fn is_unary_float(opcode: i32) -> bool {
    matches!(
        opcode,
        op::FLOAT_NEG
            | op::FLOAT_ABS
            | op::FLOAT_SQRT
            | op::FLOAT_CEIL
            | op::FLOAT_FLOOR
            | op::FLOAT_ROUND
    )
}

fn is_comparison(opcode: i32) -> bool {
    matches!(
        opcode,
        op::FLOAT_EQUAL | op::FLOAT_NOTEQUAL | op::FLOAT_LESS | op::FLOAT_LESSEQUAL
    )
}

fn max_precision_inner(
    data: &Funcdata,
    value: VarnodeId,
    memo: &mut BTreeMap<VarnodeId, u32>,
    active: &mut BTreeSet<VarnodeId>,
) -> u32 {
    if let Some(precision) = memo.get(&value).copied() {
        return precision;
    }
    if !active.insert(value) {
        return data.varnode(value).size;
    }

    let node = data.varnode(value);
    let precision = match live_def(data, value) {
        None => node.size,
        Some(definition) => {
            let operation = data.op(definition);
            match operation.opcode {
                op::MULTIEQUAL | op::COPY if !operation.inputs.is_empty() => operation
                    .inputs
                    .iter()
                    .map(|input| max_precision_inner(data, *input, memo, active))
                    .max()
                    .unwrap_or(node.size),
                code if is_unary_float(code) && !operation.inputs.is_empty() => operation
                    .inputs
                    .iter()
                    .map(|input| max_precision_inner(data, *input, memo, active))
                    .max()
                    .unwrap_or(node.size),
                code if is_binary_float(code) => 0,
                op::FLOAT_FLOAT2FLOAT | op::FLOAT_INT2FLOAT => {
                    match operation.inputs.first().copied() {
                        None => node.size,
                        Some(input) => {
                            let input_size = data.varnode(input).size;
                            if input_size > node.size {
                                node.size
                            } else {
                                input_size
                            }
                        }
                    }
                }
                _ => node.size,
            }
        }
    };

    active.remove(&value);
    memo.insert(value, precision);
    precision
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FlowValue {
    Existing(VarnodeId),
    Produced(OpId),
}

#[derive(Default)]
struct PlannedOp {
    inputs: BTreeMap<usize, FlowValue>,
    narrow_output: bool,
    copy_output: bool,
}

/// The graph-local portion of Ghidra's `SubfloatFlow`.
///
/// The analysis is deliberately transactional: it records symbolic output
/// values first and mutates `Funcdata` only after the complete trace reaches a
/// terminator.  A failed trace therefore cannot leave half of a precision
/// rewrite behind.
struct SubfloatFlow<'a> {
    data: &'a Funcdata,
    precision: u32,
    root: VarnodeId,
    values: BTreeMap<VarnodeId, FlowValue>,
    active: BTreeSet<VarnodeId>,
    processed: BTreeSet<OpId>,
    queued: BTreeSet<VarnodeId>,
    plans: BTreeMap<OpId, PlannedOp>,
    terminals: usize,
}

impl<'a> SubfloatFlow<'a> {
    fn new(data: &'a Funcdata, root: VarnodeId, precision: u32) -> Self {
        Self {
            data,
            precision,
            root,
            values: BTreeMap::new(),
            active: BTreeSet::new(),
            processed: BTreeSet::new(),
            queued: BTreeSet::new(),
            plans: BTreeMap::new(),
            terminals: 0,
        }
    }

    fn plan_input(&mut self, id: OpId, slot: usize, value: FlowValue) -> bool {
        let plan = self.plans.entry(id).or_default();
        match plan.inputs.get(&slot).copied() {
            Some(previous) => previous == value,
            None => {
                plan.inputs.insert(slot, value);
                true
            }
        }
    }

    fn plan_narrow_output(&mut self, id: OpId) {
        self.plans.entry(id).or_default().narrow_output = true;
    }

    fn plan_copy_output(&mut self, id: OpId) {
        self.plans.entry(id).or_default().copy_output = true;
    }

    fn output_value(&mut self, id: OpId, value: VarnodeId) -> Option<FlowValue> {
        let size = self.data.varnode(value).size;
        if size < self.precision {
            return None;
        }
        if size == self.precision {
            Some(FlowValue::Existing(value))
        } else {
            self.plan_narrow_output(id);
            Some(FlowValue::Produced(id))
        }
    }

    fn exceeds_precision(&self, id: OpId) -> bool {
        let Some(left) = input(self.data, id, 0) else {
            return true;
        };
        let Some(right) = input(self.data, id, 1) else {
            return true;
        };
        let mut memo = BTreeMap::new();
        let mut active = BTreeSet::new();
        let left = max_precision_inner(self.data, left, &mut memo, &mut active);
        let right = max_precision_inner(self.data, right, &mut memo, &mut active);
        left > self.precision && right > self.precision
    }

    /// Trace a value backwards through the defining operation.
    fn ensure_flow(&mut self, value: VarnodeId) -> Option<FlowValue> {
        if let Some(flow) = self.values.get(&value).copied() {
            return Some(flow);
        }
        if !self.active.insert(value) {
            return None;
        }
        let node_size = self.data.varnode(value).size;
        let node_input = self.data.varnode(value).flags.input;
        let result = if is_constant(self.data, value) {
            // The graph does not carry FloatFormat, so only an already
            // correctly-sized constant can be kept verbatim.
            (node_size == self.precision).then_some(FlowValue::Existing(value))
        } else if node_input {
            // This is the `SubfloatFlow::setReplacement` input guard.
            (node_size == self.precision).then_some(FlowValue::Existing(value))
        } else if is_free(self.data, value) || node_size < self.precision {
            None
        } else {
            let Some(definition) = live_def(self.data, value) else {
                self.active.remove(&value);
                return None;
            };
            let operation = self.data.op(definition);
            let code = operation.opcode;
            if code == op::FLOAT_FLOAT2FLOAT {
                let Some(source) = operation.inputs.first().copied() else {
                    self.active.remove(&value);
                    return None;
                };
                if self.data.varnode(source).size != self.precision {
                    None
                } else {
                    let source_flow = self.ensure_flow(source);
                    if let Some(source_flow) = source_flow {
                        if self.plan_input(definition, 0, source_flow) {
                            self.plan_copy_output(definition);
                            self.output_value(definition, value)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            } else if code == op::FLOAT_INT2FLOAT {
                let Some(source) = operation.inputs.first().copied() else {
                    self.active.remove(&value);
                    return None;
                };
                if self.data.varnode(source).size != self.precision
                    || (!is_constant(self.data, source) && is_free(self.data, source))
                {
                    None
                } else {
                    let source_flow = self.ensure_flow(source);
                    if let Some(source_flow) = source_flow {
                        if self.plan_input(definition, 0, source_flow) {
                            self.output_value(definition, value)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            } else if code == op::MULTIEQUAL
                || code == op::COPY
                || is_unary_float(code)
                || is_binary_float(code)
            {
                let required_inputs = if is_binary_float(code) { 2 } else { 1 };
                if is_binary_float(code) && self.exceeds_precision(definition) {
                    None
                } else if operation.inputs.len() < required_inputs
                    || (code == op::MULTIEQUAL && operation.inputs.is_empty())
                {
                    None
                } else {
                    let mut input_flows = Vec::with_capacity(operation.inputs.len());
                    let mut valid = true;
                    for source in operation.inputs.iter().copied() {
                        let Some(source_flow) = self.ensure_flow(source) else {
                            valid = false;
                            break;
                        };
                        input_flows.push(source_flow);
                    }
                    if !valid {
                        None
                    } else {
                        let mut valid = true;
                        for (slot, source_flow) in input_flows.into_iter().enumerate() {
                            valid &= self.plan_input(definition, slot, source_flow);
                        }
                        valid
                            .then(|| self.output_value(definition, value))
                            .flatten()
                    }
                }
            } else {
                None
            }
        };

        self.active.remove(&value);
        if let Some(flow) = result {
            self.values.insert(value, flow);
        }
        result
    }

    /// Trace a logical value through all of its descendants.
    fn trace_forward(&mut self) -> bool {
        let mut worklist = vec![self.root];
        while let Some(value) = worklist.pop() {
            if !self.queued.insert(value) {
                continue;
            }
            let Some(flow) = self.values.get(&value).copied() else {
                return false;
            };
            let readers: Vec<OpId> = self
                .data
                .varnode(value)
                .descendants
                .iter()
                .copied()
                .collect();
            for reader in readers {
                if !self.processed.insert(reader) {
                    continue;
                }
                let Some(code) = self.data.opcode_of(reader) else {
                    continue;
                };
                match code {
                    op::FLOAT_FLOAT2FLOAT => {
                        let Some(result) = output(self.data, reader) else {
                            return false;
                        };
                        if self.data.varnode(result).size < self.precision
                            || !self.plan_input(reader, 0, flow)
                        {
                            return false;
                        }
                        if self.data.varnode(result).size == self.precision {
                            self.plan_copy_output(reader);
                        }
                        self.terminals += 1;
                    }
                    op::FLOAT_TRUNC | op::FLOAT_NAN => {
                        if output(self.data, reader).is_none() || !self.plan_input(reader, 0, flow)
                        {
                            return false;
                        }
                        self.terminals += 1;
                    }
                    code if is_comparison(code) => {
                        if self.data.op(reader).inputs.len() != 2 || self.exceeds_precision(reader)
                        {
                            return false;
                        }
                        let mut input_flows = Vec::with_capacity(self.data.op(reader).inputs.len());
                        for source in self.data.op(reader).inputs.iter().copied() {
                            let source_flow = if source == value {
                                Some(flow)
                            } else {
                                self.ensure_flow(source)
                            };
                            let Some(source_flow) = source_flow else {
                                return false;
                            };
                            input_flows.push(source_flow);
                        }
                        for (slot, source_flow) in input_flows.into_iter().enumerate() {
                            if !self.plan_input(reader, slot, source_flow) {
                                return false;
                            }
                        }
                        self.terminals += 1;
                    }
                    op::MULTIEQUAL
                    | op::COPY
                    | op::FLOAT_NEG
                    | op::FLOAT_ABS
                    | op::FLOAT_SQRT
                    | op::FLOAT_CEIL
                    | op::FLOAT_FLOOR
                    | op::FLOAT_ROUND
                    | op::FLOAT_ADD
                    | op::FLOAT_SUB
                    | op::FLOAT_MULT
                    | op::FLOAT_DIV => {
                        let Some(result) = output(self.data, reader) else {
                            return false;
                        };
                        if self.data.varnode(result).size < self.precision {
                            return false;
                        }
                        if is_binary_float(code) && self.exceeds_precision(reader) {
                            return false;
                        }
                        let mut input_flows = Vec::with_capacity(self.data.op(reader).inputs.len());
                        for source in self.data.op(reader).inputs.iter().copied() {
                            let Some(source_flow) = self.ensure_flow(source) else {
                                return false;
                            };
                            input_flows.push(source_flow);
                        }
                        for (slot, source_flow) in input_flows.into_iter().enumerate() {
                            if !self.plan_input(reader, slot, source_flow) {
                                return false;
                            }
                        }
                        let Some(result_flow) = self.ensure_flow(result) else {
                            return false;
                        };
                        if self.data.varnode(result).size > self.precision {
                            worklist.push(result);
                        }
                        let _ = result_flow;
                    }
                    _ => return false,
                }
            }
        }
        self.terminals != 0
    }

    fn trace(mut self) -> Option<SubfloatPlan> {
        // `setReplacement` creates work only for a value larger than the
        // requested precision.  Equal-sized conversions are intentionally not
        // treated as a sub-float flow.
        if self.precision == 0 || self.data.varnode(self.root).size <= self.precision {
            return None;
        }
        self.ensure_flow(self.root)?;
        if !self.trace_forward() {
            return None;
        }
        Some(SubfloatPlan {
            precision: self.precision,
            plans: self.plans,
        })
    }
}

struct SubfloatPlan {
    precision: u32,
    plans: BTreeMap<OpId, PlannedOp>,
}

impl SubfloatPlan {
    fn apply(self, data: &mut Funcdata) -> usize {
        let mut produced = BTreeMap::new();
        for (id, plan) in &self.plans {
            if !plan.narrow_output {
                continue;
            }
            let Some(output) = data.op(*id).output else {
                return 0;
            };
            if data.varnode(output).size <= self.precision {
                continue;
            }
            produced.insert(*id, data.new_unique(self.precision));
        }

        for (id, plan) in &self.plans {
            if !plan.narrow_output {
                continue;
            }
            let Some(old_output) = data.op(*id).output else {
                return 0;
            };
            let Some(new_output) = produced.get(id).copied() else {
                return 0;
            };
            data.op_set_output(*id, Some(new_output));
            data.total_replace(old_output, new_output);
        }

        for (id, plan) in &self.plans {
            if plan.copy_output && data.opcode_of(*id) == Some(op::FLOAT_FLOAT2FLOAT) {
                data.op_set_opcode(*id, op::COPY);
            }
            for (slot, flow) in &plan.inputs {
                let value = match flow {
                    FlowValue::Existing(value) => *value,
                    FlowValue::Produced(producer) => {
                        let Some(value) = produced.get(producer).copied() else {
                            return 0;
                        };
                        value
                    }
                };
                if data.op(*id).inputs.get(*slot).copied() != Some(value) {
                    data.op_set_input(*id, value, *slot);
                }
            }
        }
        1
    }
}

/// Perform the precision-flow rewrite triggered by a `FLOAT_FLOAT2FLOAT`.
pub struct RuleSubfloatConvert;

impl Rule for RuleSubfloatConvert {
    fn name(&self) -> &'static str {
        "subfloat_convert"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::FLOAT_FLOAT2FLOAT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        if data.opcode_of(id) != Some(op::FLOAT_FLOAT2FLOAT) {
            return 0;
        }
        let (Some(input), Some(output)) = (input(data, id, 0), output(data, id)) else {
            return 0;
        };
        let input_size = data.varnode(input).size;
        let output_size = data.varnode(output).size;
        let (root, precision) = if output_size > input_size {
            (output, input_size)
        } else {
            (input, output_size)
        };
        let Some(plan) = SubfloatFlow::new(data, root, precision).trace() else {
            return 0;
        };
        plan.apply(data)
    }
}

pub fn all() -> Vec<Box<dyn Rule>> {
    vec![Box::new(RuleSubfloatConvert)]
}

#[cfg(test)]
mod tests {
    use super::super::GraphBlockId;
    use super::super::SeqNum;
    use super::*;
    use ventris_lifter::REGISTER_SPACE;

    fn block(data: &mut Funcdata) -> GraphBlockId {
        data.new_block(0x1000)
    }

    fn input_value(data: &mut Funcdata, size: u32) -> VarnodeId {
        let value = data.new_varnode(REGISTER_SPACE, data.varnode_count() as u64 * 8, size);
        data.mark_input(value);
        value
    }

    fn op_with_output(
        data: &mut Funcdata,
        block: GraphBlockId,
        opcode: i32,
        inputs: Vec<VarnodeId>,
        size: u32,
    ) -> (OpId, VarnodeId) {
        let id = data.new_op(
            opcode,
            SeqNum {
                address: 0x1000 + data.op_count() as u64 * 4,
                order: 0,
            },
            inputs,
        );
        let output = data.new_unique(size);
        data.op_set_output(id, Some(output));
        data.op_insert_end(id, block);
        (id, output)
    }

    #[test]
    fn subfloat_convert_fires_and_second_apply_declines() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let source = input_value(&mut data, 4);
        let (convert, widened) =
            op_with_output(&mut data, b, op::FLOAT_FLOAT2FLOAT, vec![source], 8);
        let (_, negated) = op_with_output(&mut data, b, op::FLOAT_NEG, vec![widened], 8);
        let (terminal, _) = op_with_output(&mut data, b, op::FLOAT_FLOAT2FLOAT, vec![negated], 4);

        assert_eq!(RuleSubfloatConvert.apply_op(convert, &mut data), 1);
        assert_eq!(data.op(convert).opcode, op::COPY);
        assert_eq!(data.varnode(data.op(convert).output.unwrap()).size, 4);
        assert_eq!(data.varnode(data.op(terminal).inputs[0]).size, 4);
        assert_eq!(RuleSubfloatConvert.apply_op(convert, &mut data), 0);
    }

    #[test]
    fn subfloat_convert_declines_without_a_terminator() {
        let mut data = Funcdata::default();
        let b = block(&mut data);
        let source = input_value(&mut data, 4);
        let (convert, _) = op_with_output(&mut data, b, op::FLOAT_FLOAT2FLOAT, vec![source], 8);

        assert_eq!(RuleSubfloatConvert.apply_op(convert, &mut data), 0);
        assert_eq!(data.op(convert).opcode, op::FLOAT_FLOAT2FLOAT);
    }
}
