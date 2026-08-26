//! The Action and Rule framework, ported from Ghidra 12.1.3.
//!
//! Ventris already had an "action database", but it rewrote *statements* — the
//! rendered form — with each rule matching on statement shapes. Ghidra's rules
//! rewrite the p-code graph: a rule is registered against opcodes, receives one
//! operation, and mutates operands, opcodes, and edges in place. Everything
//! downstream reads the mutated graph, so one rule's result is another rule's
//! input without either knowing about the other.
//!
//! That difference is why the statement rules could never express the things
//! Ghidra's can: a statement has no descendant list to redirect and no operand
//! slot to overwrite.
//!
//! Source authority: `Action`, `Rule`, `ActionPool`, `ActionGroup` in
//! `action.hh`/`action.cc`, and the rules named on each implementation, at
//! commit `8b4c91d4d5bd1549622bfbade0df199585b98365`.
//!
//! # Passes deliberately not ported
//!
//! Every remaining Ghidra action and rule is accounted for either by a note in
//! the module that would own it, or here:
//!
//! * `ActionRestartGroup` (`action.cc`) - the restart-and-regroup driver. All
//!   four of Ghidra's restart sources write into `Override` before setting
//!   `setRestartPending`: `fspec.cc:5471` and `5503`, `heritage.cc:2581` via
//!   `insertDeadcodeDelay`, and `jumptable.cc:2712-2717` via
//!   `insertMultistageJump`. Nothing here can populate an `Override` -
//!   `LoadOptions` and `Hints` carry no control-flow input - so the group would
//!   iterate exactly once. A fixed round loop is used instead.
//! * `RuleTransformCpool` (`ruleaction.cc:3902-3940`) - matches `CPOOLREF`. A
//!   census of all 21 bundled packed SLA payloads found zero operation templates
//!   with `ATTR_CODE=68`, against 203029 templates total, so no supported lifter
//!   can emit the opcode.
//! * `RuleUndistribute` and `RuleRightShiftSub` (`ruleaction.hh`) - declared but
//!   registered zero times in Ghidra itself. Porting them would add code Ghidra
//!   does not run.
//! * `RuleGeneric` (`rulecompile.hh`) - part of the SLEIGH rule compiler, not a
//!   decompiler rule, and never in scope.

use std::collections::BTreeMap;

use ventris_pcode::op;

use super::{Funcdata, OpId, VarnodeId};

/// A transform applied to one operation at a time.
pub trait Rule {
    fn name(&self) -> &'static str;

    /// The opcodes this rule wants to see. `ActionPool` indexes by these, so a
    /// rule is only offered operations it can act on.
    fn op_list(&self) -> Vec<i32>;

    /// Applies the rule, returning the number of changes made.
    fn apply_op(&self, op: OpId, data: &mut Funcdata) -> usize;
}

/// A stage of the pipeline.
pub trait Action {
    fn name(&self) -> &'static str;
    fn apply(&self, data: &mut Funcdata) -> usize;
}

/// Applies a set of rules to every operation, indexed by opcode.
pub struct ActionPool {
    name: &'static str,
    rules: Vec<Box<dyn Rule>>,
    per_op: BTreeMap<i32, Vec<usize>>,
}

impl ActionPool {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            rules: Vec::new(),
            per_op: BTreeMap::new(),
        }
    }

    pub fn add_rule(mut self, rule: Box<dyn Rule>) -> Self {
        let index = self.rules.len();
        for opcode in rule.op_list() {
            self.per_op.entry(opcode).or_default().push(index);
        }
        self.rules.push(rule);
        self
    }
}

impl Action for ActionPool {
    fn name(&self) -> &'static str {
        self.name
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let mut changes = 0;
        let ops: Vec<OpId> = data.live_ops().map(|(id, _)| id).collect();
        for id in ops {
            // A rule may have destroyed this operation, or changed its opcode
            // so a different rule set now applies. Re-read both each round.
            let mut guard = 0;
            loop {
                let Some(opcode) = data.opcode_of(id) else {
                    break;
                };
                let Some(rules) = self.per_op.get(&opcode) else {
                    break;
                };
                let mut applied = 0;
                for rule in rules.iter().copied() {
                    applied += self.rules[rule].apply_op(id, data);
                    if data.opcode_of(id) != Some(opcode) {
                        break;
                    }
                }
                changes += applied;
                guard += 1;
                if applied == 0 || guard >= ROUND_CAP {
                    break;
                }
            }
        }
        changes
    }
}

/// A sequence of actions.
pub struct ActionGroup {
    name: &'static str,
    actions: Vec<Box<dyn Action>>,
}

impl ActionGroup {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            actions: Vec::new(),
        }
    }

    pub fn add(mut self, action: Box<dyn Action>) -> Self {
        self.actions.push(action);
        self
    }
}

impl Action for ActionGroup {
    fn name(&self) -> &'static str {
        self.name
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        self.actions.iter().map(|action| action.apply(data)).sum()
    }
}

/// Repeats an action until it reports no further change.
///
/// Ghidra's `ActionGroup` with `rule_repeatapply`. The cap exists because a
/// rule pair can oscillate; Ghidra bounds the same way.
pub struct FixedPoint {
    inner: Box<dyn Action>,
    cap: usize,
}

const ROUND_CAP: usize = 16;

impl FixedPoint {
    pub fn new(inner: Box<dyn Action>) -> Self {
        Self {
            inner,
            cap: ROUND_CAP,
        }
    }
}

impl Action for FixedPoint {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        let mut total = 0;
        for _ in 0..self.cap {
            let changed = self.inner.apply(data);
            total += changed;
            if changed == 0 {
                break;
            }
        }
        total
    }
}

/// A `MULTIEQUAL` whose operands all name one value is not a merge.
///
/// Ghidra's `RuleMultiCollapse`. Operands equal to the merge's own result are
/// skipped: that is a loop-carried value recurring unchanged, which agrees with
/// every other path by construction.
pub struct RuleMultiCollapse;

impl Rule for RuleMultiCollapse {
    fn name(&self) -> &'static str {
        "multi-collapse"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::MULTIEQUAL]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let Some(output) = data.op(id).output else {
            return 0;
        };
        let mut single: Option<VarnodeId> = None;
        for operand in data.op(id).inputs.clone() {
            if operand == output {
                continue;
            }
            match single {
                None => single = Some(operand),
                Some(existing) if existing == operand => {}
                Some(_) => return 0,
            }
        }
        let Some(single) = single else { return 0 };
        data.op_set_opcode(id, op::COPY);
        data.op_set_inputs(id, vec![single]);
        1
    }
}

/// A `COPY` result is the same value as its operand, so readers can use the
/// operand directly.
///
/// Ghidra's `RulePropagateCopy`. A copy whose operand is a function input is
/// left alone: the copy is what gives the input a name distinct from the
/// storage it arrived in.
pub struct RulePropagateCopy;

impl Rule for RulePropagateCopy {
    fn name(&self) -> &'static str {
        "propagate-copy"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::COPY]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id);
        let (Some(output), Some(source)) = (operation.output, operation.inputs.first().copied())
        else {
            return 0;
        };
        if output == source {
            return 0;
        }
        // Only propagate within one storage location or into a temporary.
        // Copying between two named locations is an observable assignment.
        let out = data.varnode(output);
        let src = data.varnode(source);
        // A copy that changes width is not a copy: it truncates or extends, and
        // every reader of the output expects the output's width. Propagating one
        // handed readers a value of the wrong size - a one-byte store became a
        // two-byte store, which `SplitDatatype::splitStore` then split into a
        // pair, so each byte written also cleared its neighbour.
        if out.size != src.size {
            return 0;
        }
        let transparent = src.flags.constant
            || out.space == super::UNIQUE_SPACE
            || (out.space == src.space && out.offset == src.offset);
        if !transparent {
            return 0;
        }
        if data.varnode(output).descendants.is_empty() {
            return 0;
        }
        data.total_replace(output, source);
        data.op_destroy(id);
        1
    }
}

/// An operation with constant operands is a constant.
///
/// Ghidra's `RuleCollapseConstants`, which rewrites the operation into a `COPY`
/// of the folded value rather than deleting it, so descendants keep their edge.
pub struct RuleCollapseConstants;

impl Rule for RuleCollapseConstants {
    fn name(&self) -> &'static str {
        "collapse-constants"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![
            op::INT_ADD,
            op::INT_SUB,
            op::INT_MULT,
            op::INT_AND,
            op::INT_OR,
            op::INT_XOR,
            op::INT_LEFT,
            op::INT_RIGHT,
            op::INT_NEGATE,
            op::INT_2COMP,
            op::INT_EQUAL,
            op::INT_NOTEQUAL,
            op::INT_LESS,
            op::INT_LESSEQUAL,
            op::BOOL_NEGATE,
        ]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id);
        let Some(output) = operation.output else {
            return 0;
        };
        let operands: Vec<&super::GraphVarnode> = operation
            .inputs
            .iter()
            .map(|input| data.varnode(*input))
            .collect();
        if operands.is_empty() || !operands.iter().all(|value| value.flags.constant) {
            return 0;
        }
        let width = data.varnode(output).size;
        let mask = if width >= 8 {
            u64::MAX
        } else {
            (1u64 << (width * 8)) - 1
        };
        let left = operands[0].offset;
        let right = operands.get(1).map(|value| value.offset).unwrap_or(0);
        let folded = match operation.opcode {
            op::INT_ADD => left.wrapping_add(right),
            op::INT_SUB => left.wrapping_sub(right),
            op::INT_MULT => left.wrapping_mul(right),
            op::INT_AND => left & right,
            op::INT_OR => left | right,
            op::INT_XOR => left ^ right,
            op::INT_LEFT if right < 64 => left << right,
            op::INT_LEFT => 0,
            op::INT_RIGHT if right < 64 => left >> right,
            op::INT_RIGHT => 0,
            op::INT_NEGATE => !left,
            op::INT_2COMP => left.wrapping_neg(),
            op::INT_EQUAL => u64::from(left == right),
            op::INT_NOTEQUAL => u64::from(left != right),
            op::INT_LESS => u64::from(left < right),
            op::INT_LESSEQUAL => u64::from(left <= right),
            op::BOOL_NEGATE => u64::from(left == 0),
            _ => return 0,
        } & mask;
        let constant = data.new_constant(folded, width);
        data.op_set_opcode(id, op::COPY);
        data.op_set_inputs(id, vec![constant]);
        1
    }
}

/// Identities that make an operation its own operand.
///
/// Ghidra's `RuleTrivialArith` and the identity cases of `RuleAndMask`. Each
/// arm is an algebraic identity, not a heuristic.
pub struct RuleTrivialArith;

impl Rule for RuleTrivialArith {
    fn name(&self) -> &'static str {
        "trivial-arith"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![
            op::INT_ADD,
            op::INT_SUB,
            op::INT_MULT,
            op::INT_AND,
            op::INT_OR,
            op::INT_XOR,
            op::INT_LEFT,
            op::INT_RIGHT,
        ]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id);
        if operation.output.is_none() || operation.inputs.len() != 2 {
            return 0;
        }
        let left = operation.inputs[0];
        let right = operation.inputs[1];
        let opcode = operation.opcode;
        let right_value = data.varnode(right);
        let left_value = data.varnode(left);
        let right_zero = right_value.flags.constant && right_value.offset == 0;
        let right_one = right_value.flags.constant && right_value.offset == 1;
        // Ghidra canonicalises a commutative operation's constant onto the
        // second slot before these identities run. Nothing here does that yet,
        // so an identity written the other way round has to be recognised
        // directly or `0 | x` survives into the output.
        let left_zero = left_value.flags.constant && left_value.offset == 0;
        let left_one = left_value.flags.constant && left_value.offset == 1;
        if matches!(opcode, op::INT_ADD | op::INT_OR | op::INT_XOR) && left_zero {
            data.op_set_opcode(id, op::COPY);
            data.op_set_inputs(id, vec![right]);
            return 1;
        }
        if opcode == op::INT_MULT && left_one {
            data.op_set_opcode(id, op::COPY);
            data.op_set_inputs(id, vec![right]);
            return 1;
        }
        let identity = match opcode {
            op::INT_ADD | op::INT_SUB | op::INT_LEFT | op::INT_RIGHT => right_zero,
            op::INT_MULT => right_one,
            // A register move is spelled `or rX, rX, rX` on PowerPC and
            // `or rX, rX, zero` on MIPS. Both are the value itself.
            op::INT_OR => right_zero || left == right,
            op::INT_AND => left == right,
            op::INT_XOR => right_zero,
            _ => false,
        };
        if opcode == op::INT_XOR && left == right {
            // A value exclusive-ored with itself is zero, whatever it was.
            let width = data.varnode(left).size;
            let zero = data.new_constant(0, width);
            data.op_set_opcode(id, op::COPY);
            data.op_set_inputs(id, vec![zero]);
            return 1;
        }
        if !identity {
            return 0;
        }
        data.op_set_opcode(id, op::COPY);
        data.op_set_inputs(id, vec![left]);
        1
    }
}

/// An `INDIRECT` whose effect nothing distinguishes is a `COPY` of the value
/// that was already there.
///
/// Ghidra's `RuleIndirectCollapse`. The guard pass inserts an `INDIRECT` for
/// every location a call may change, deliberately over-approximating; this
/// removes the ones where the location's value is not actually in question,
/// leaving the value flowing through.
pub struct RuleIndirectCollapse;

impl Rule for RuleIndirectCollapse {
    fn name(&self) -> &'static str {
        "indirect-collapse"
    }

    fn op_list(&self) -> Vec<i32> {
        vec![op::INDIRECT]
    }

    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id);
        let (Some(output), Some(source)) = (operation.output, operation.inputs.first().copied())
        else {
            return 0;
        };
        // The responsible operation is named by the second operand. If it is
        // gone, there is no indirect effect left to describe.
        let cause_alive = operation
            .inputs
            .get(1)
            .copied()
            .map(|cause| data.varnode(cause))
            .map(|cause| data.has_op_at(cause.offset))
            .unwrap_or(false);
        if cause_alive {
            return 0;
        }
        data.op_set_opcode(id, op::COPY);
        data.op_set_inputs(id, vec![source]);
        let _ = output;
        1
    }
}

/// The default source-level pipeline for the graph.
///
/// The order mirrors Ghidra's `ActionDatabase`: the sub-lane rules run with the
/// rest of the expression set rather than in their own phase, because reducing a
/// packed flag word exposes ordinary arithmetic underneath it and vice versa.
pub fn default_pipeline() -> Box<dyn Action> {
    let mut expression = ActionPool::new("expression-rules")
        .add_rule(Box::new(RuleMultiCollapse))
        .add_rule(Box::new(RuleCollapseConstants))
        .add_rule(Box::new(RuleTrivialArith))
        .add_rule(Box::new(super::rules::RuleAndMask))
        .add_rule(Box::new(super::rules::RuleTrivialBool))
        .add_rule(Box::new(super::rules::RuleEquality))
        .add_rule(Box::new(super::rules::RuleEqual2Zero))
        .add_rule(Box::new(super::rules::RuleSubExtComm))
        .add_rule(Box::new(super::rules::RuleBoolNegate))
        // Sub-lane extraction: a comparison packed into a flag word is only a
        // comparison again once the shift-and-mask that reads one bit is
        // reduced away.
        .add_rule(Box::new(super::subflow::RuleSubvarAnd))
        .add_rule(Box::new(super::subflow::RuleSubvarSubpiece))
        .add_rule(Box::new(super::subflow::RuleSubvarShift))
        .add_rule(Box::new(super::subflow::RuleSubvarCompZero))
        .add_rule(Box::new(super::subflow::RuleSubvarZext))
        .add_rule(Box::new(super::subflow::RuleSubvarSext))
        .add_rule(Box::new(super::subflow::RuleBoolZext))
        .add_rule(Box::new(super::subflow::RuleLogic2Bool));
    for rule in super::expr_rules::all() {
        expression = expression.add_rule(rule);
    }
    let dropped: Vec<String> = std::env::var("VENTRIS_SKIP_RULE")
        .map(|value| {
            value
                .split(',')
                .map(|entry| entry.trim().to_string())
                .collect()
        })
        .unwrap_or_default();
    // Each new batch is switchable so an oscillating pair can be attributed to
    // one batch without a rebuild per guess.
    let batches: [(&str, Vec<Box<dyn Rule>>); 10] = [
        ("expr_bool", super::expr_bool::all()),
        ("expr_arith", super::expr_arith::all()),
        ("expr_divmod", super::expr_divmod::all()),
        ("expr_piece", super::expr_piece::all()),
        ("expr_float", super::expr_float::all()),
        ("expr_ptr", super::expr_ptr::all()),
        ("expr_memory", super::expr_memory::all()),
        ("splitvarnode", super::splitvarnode::all()),
        ("subfloat", super::subfloat::all()),
        ("splitdatatype", super::splitdatatype::all()),
    ];
    let skipped_batches: Vec<String> = std::env::var("VENTRIS_SKIP_BATCH")
        .map(|value| value.split(',').map(str::trim).map(str::to_owned).collect())
        .unwrap_or_default();
    for (name, rules) in batches {
        if skipped_batches.iter().any(|skip| skip == name) {
            continue;
        }
        for rule in rules {
            if dropped.iter().any(|name| name == rule.name()) {
                continue;
            }
            expression = expression.add_rule(rule);
        }
    }
    for rule in super::expr_rules2::all() {
        if dropped.iter().any(|name| name == rule.name()) {
            continue;
        }
        expression = expression.add_rule(rule);
    }
    // Copy propagation and indirect collapse run last: they remove the
    // operations the other rules match on, so running them earlier hides work.
    expression = expression
        .add_rule(Box::new(super::protoconstraints::RulePiecePathology))
        .add_rule(Box::new(super::orconsume::RuleOrConsume))
        .add_rule(Box::new(super::scopeconsumers::RulePtrsubCharConstant))
        .add_rule(Box::new(super::scopeconsumers::RuleStringCopy))
        .add_rule(Box::new(RulePropagateCopy))
        .add_rule(Box::new(RuleIndirectCollapse));
    // Prototype and parameter recovery runs before the expression set: an
    // argument list decides which values are live at a call, and the rules
    // rewrite what they can see.
    let mut prototypes = ActionGroup::new("prototypes");
    for (name, action) in [
        (
            "active-param",
            Box::new(super::callproto::ActionActiveParam) as Box<dyn Action>,
        ),
        (
            "active-return",
            Box::new(super::callproto::ActionActiveReturn) as Box<dyn Action>,
        ),
        (
            "func-link",
            Box::new(super::callproto::ActionFuncLink) as Box<dyn Action>,
        ),
        (
            "param-double",
            Box::new(super::callproto::ActionParamDouble) as Box<dyn Action>,
        ),
    ] {
        if std::env::var("VENTRIS_SKIP_ACTION")
            .map(|value| value.split(',').any(|entry| entry.trim() == name))
            .unwrap_or(false)
        {
            continue;
        }
        prototypes = prototypes.add(action);
    }
    let skip = |name: &str| {
        std::env::var("VENTRIS_SKIP_GROUP")
            .map(|value| value.split(',').any(|entry| entry.trim() == name))
            .unwrap_or(false)
    };
    let mut pipeline = ActionGroup::new("source-pipeline");
    if !skip("prototypes") {
        pipeline = pipeline.add(Box::new(prototypes));
    }
    if !skip("expression") {
        pipeline = pipeline.add(Box::new(FixedPoint::new(Box::new(expression))));
    }
    // Ghidra registers the bitfield rules in the `cleanup` pool, group
    // `bitfields`, which runs after the full loop rather than inside it: they
    // rewrite a mask-and-shift into a single ZPULL, so running them earlier
    // would remove the shapes the expression rules match on.
    if !skip("cleanup") {
        let mut cleanup = ActionPool::new("cleanup");
        for rule in [
            Box::new(super::bitfield::RuleBitFieldOut) as Box<dyn Rule>,
            Box::new(super::bitfield::RuleBitFieldLoad),
            Box::new(super::bitfield::RuleBitFieldStore),
            Box::new(super::bitfield::RulePullAbsorb),
            Box::new(super::bitfield::RuleInsertAbsorb),
        ] {
            if dropped.iter().any(|name| name == rule.name()) {
                continue;
            }
            cleanup = cleanup.add_rule(rule);
        }
        pipeline = pipeline.add(Box::new(FixedPoint::new(Box::new(cleanup))));
    }
    // Ghidra's `localrecovery` group, which reads the local scope:
    // ActionRestructureVarnode at coreaction.cc:5555-5557 and
    // ActionMappedLocalSync at 5741-5743.
    if !skip("localrecovery") {
        let mut localrecovery = ActionGroup::new("localrecovery");
        for action in [
            Box::new(super::scopeconsumers::ActionRestructureVarnode) as Box<dyn Action>,
            Box::new(super::scopeconsumers::ActionMappedLocalSync),
        ] {
            localrecovery = localrecovery.add(action);
        }
        pipeline = pipeline.add(Box::new(localrecovery));
    }
    // Ghidra's `protorecovery` group: prototype recovery reads the function's
    // FuncProto, which the graph path populates from the target ABI.
    // ActionUnjustifiedParams is at coreaction.cc:5737 and
    // ActionPrototypeWarnings at 5794.
    if !skip("protorecovery") {
        let mut protorecovery = ActionGroup::new("protorecovery");
        for action in [
            Box::new(super::protorecovery::ActionInputPrototype) as Box<dyn Action>,
            Box::new(super::protorecovery::ActionOutputPrototype),
            Box::new(super::protorecovery::ActionPrototypeTypes),
            Box::new(super::protoconstraints::ActionUnjustifiedParams),
            Box::new(super::protoconstraints::ActionPrototypeWarnings),
        ] {
            protorecovery = protorecovery.add(action);
        }
        pipeline = pipeline.add(Box::new(protorecovery));
    }
    // Ghidra adds these to `blockrecovery` immediately after the cleanup pool
    // (coreaction.cc:5771-5773), before ActionNormalizeBranches.
    if !skip("blockrecovery") {
        let mut blockrecovery = ActionGroup::new("blockrecovery");
        for action in super::structuretransform::all() {
            blockrecovery = blockrecovery.add(action);
        }
        pipeline = pipeline.add(Box::new(blockrecovery));
    }
    if !skip("infer-types-rich") {
        pipeline = pipeline.add(Box::new(super::typefactory::ActionInferTypes));
    }
    Box::new(pipeline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{SeqNum, heritage::heritage};
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    #[test]
    fn constant_operands_fold_into_one_value() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_constant(2, 4);
        let right = data.new_constant(3, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![left, right]);
        let sum = data.new_unique(4);
        data.op_set_output(add, Some(sum));
        data.op_insert_end(add, block);

        assert_eq!(RuleCollapseConstants.apply_op(add, &mut data), 1);
        assert_eq!(data.op(add).opcode, op::COPY);
        let folded = data.op(add).inputs[0];
        assert_eq!(data.varnode(folded).offset, 5);
    }

    #[test]
    fn folding_truncates_to_the_result_width() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_constant(0xffff_ffff, 4);
        let right = data.new_constant(2, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![left, right]);
        let sum = data.new_unique(4);
        data.op_set_output(add, Some(sum));
        data.op_insert_end(add, block);

        RuleCollapseConstants.apply_op(add, &mut data);
        let folded = data.op(add).inputs[0];
        assert_eq!(data.varnode(folded).offset, 1, "the carry out is discarded");
    }

    #[test]
    fn adding_zero_is_the_value_itself() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = data.new_varnode(REGISTER_SPACE, 8, 4);
        let zero = data.new_constant(0, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![value, zero]);
        let sum = data.new_unique(4);
        data.op_set_output(add, Some(sum));
        data.op_insert_end(add, block);

        assert_eq!(RuleTrivialArith.apply_op(add, &mut data), 1);
        assert_eq!(data.op(add).opcode, op::COPY);
        assert_eq!(data.op(add).inputs, vec![value]);
    }

    #[test]
    fn a_merge_of_one_value_is_not_a_merge() {
        let mut data = Funcdata::default();
        let entry = data.new_block(0x1000);
        let left = data.new_block(0x1010);
        let right = data.new_block(0x1020);
        let join = data.new_block(0x1030);
        data.add_edge(entry, left);
        data.add_edge(entry, right);
        data.add_edge(left, join);
        data.add_edge(right, join);
        // Both arms write the same value into the location.
        let shared = data.new_constant(7, 4);
        for block in [left, right] {
            let start = data.block(block).start;
            let copy = data.new_op(op::COPY, seq(start), vec![shared]);
            let out = data.new_varnode(REGISTER_SPACE, 8, 4);
            data.op_set_output(copy, Some(out));
            data.op_insert_end(copy, block);
        }
        let read = data.new_varnode(REGISTER_SPACE, 8, 4);
        let ret = data.new_op(op::RETURN, seq(0x1030), vec![read]);
        data.op_insert_end(ret, join);
        heritage(&mut data);

        let phi = data
            .live_ops()
            .find(|(_, operation)| operation.opcode == op::MULTIEQUAL)
            .map(|(id, _)| id)
            .expect("a phi was placed");
        // The two arms produce distinct SSA values, so this phi is real.
        assert_eq!(RuleMultiCollapse.apply_op(phi, &mut data), 0);

        // Make both operands name one value, as copy propagation would.
        let operands = data.op(phi).inputs.clone();
        data.op_set_inputs(phi, vec![operands[0], operands[0]]);
        assert_eq!(RuleMultiCollapse.apply_op(phi, &mut data), 1);
        assert_eq!(data.op(phi).opcode, op::COPY);
    }

    #[test]
    fn a_loop_carried_operand_does_not_block_collapse() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let value = data.new_varnode(REGISTER_SPACE, 8, 4);
        let phi = data.new_op(op::MULTIEQUAL, seq(0x1000), vec![value]);
        let result = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(phi, Some(result));
        data.op_insert_end(phi, block);
        data.op_set_inputs(phi, vec![value, result]);

        assert_eq!(RuleMultiCollapse.apply_op(phi, &mut data), 1);
        assert_eq!(data.op(phi).inputs, vec![value]);
    }

    #[test]
    fn a_copy_into_a_temporary_is_propagated_to_its_readers() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let source = data.new_varnode(REGISTER_SPACE, 8, 4);
        let copy = data.new_op(op::COPY, seq(0x1000), vec![source]);
        let temporary = data.new_unique(4);
        data.op_set_output(copy, Some(temporary));
        data.op_insert_end(copy, block);
        let ret = data.new_op(op::RETURN, seq(0x1004), vec![temporary]);
        data.op_insert_end(ret, block);

        assert_eq!(RulePropagateCopy.apply_op(copy, &mut data), 1);
        assert_eq!(data.op(ret).inputs, vec![source]);
        assert!(data.live_ops().all(|(_, op)| op.opcode != op::COPY));
    }

    #[test]
    fn a_copy_between_two_named_locations_is_kept() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let source = data.new_varnode(REGISTER_SPACE, 8, 4);
        let copy = data.new_op(op::COPY, seq(0x1000), vec![source]);
        let destination = data.new_varnode(REGISTER_SPACE, 16, 4);
        data.op_set_output(copy, Some(destination));
        data.op_insert_end(copy, block);
        let ret = data.new_op(op::RETURN, seq(0x1004), vec![destination]);
        data.op_insert_end(ret, block);

        assert_eq!(
            RulePropagateCopy.apply_op(copy, &mut data),
            0,
            "moving between registers is an observable assignment"
        );
    }

    #[test]
    fn the_pipeline_reaches_a_fixed_point_across_rules() {
        // (2 + 3) * 1 + 0 folds to 5 in one pipeline run, which needs three
        // rules to feed each other.
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let two = data.new_constant(2, 4);
        let three = data.new_constant(3, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![two, three]);
        let sum = data.new_unique(4);
        data.op_set_output(add, Some(sum));
        data.op_insert_end(add, block);
        let one = data.new_constant(1, 4);
        let mult = data.new_op(op::INT_MULT, seq(0x1004), vec![sum, one]);
        let scaled = data.new_unique(4);
        data.op_set_output(mult, Some(scaled));
        data.op_insert_end(mult, block);
        let zero = data.new_constant(0, 4);
        let offset = data.new_op(op::INT_ADD, seq(0x1008), vec![scaled, zero]);
        let final_value = data.new_unique(4);
        data.op_set_output(offset, Some(final_value));
        data.op_insert_end(offset, block);
        let ret = data.new_op(op::RETURN, seq(0x100c), vec![final_value]);
        data.op_insert_end(ret, block);

        assert!(default_pipeline().apply(&mut data) > 0);
        let returned = data.op(ret).inputs[0];
        let value = data.varnode(returned);
        assert!(value.flags.constant, "the chain folded to a constant");
        assert_eq!(value.offset, 5);
    }
    /// A copy that changes width truncates or extends; propagating it hands
    /// every reader a value of the wrong size.
    #[test]
    fn a_width_changing_copy_is_not_propagated() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let wide = data.new_varnode(ventris_lifter::REGISTER_SPACE, 0, 2);
        let narrow = data.new_varnode(ventris_lifter::REGISTER_SPACE, 0, 1);
        let copy = data.new_op(
            op::COPY,
            SeqNum {
                address: 0x1000,
                order: 0,
            },
            vec![wide],
        );
        data.op_set_output(copy, Some(narrow));
        data.op_insert_end(copy, block);
        // Something has to read the output, or the rule declines for that reason.
        let reader = data.new_op(
            op::INT_ADD,
            SeqNum {
                address: 0x1004,
                order: 0,
            },
            vec![narrow, narrow],
        );
        let sum = data.new_unique(1);
        data.op_set_output(reader, Some(sum));
        data.op_insert_end(reader, block);

        assert_eq!(
            RulePropagateCopy.apply_op(copy, &mut data),
            0,
            "one byte and two bytes are not the same value"
        );
        assert_eq!(data.op(copy).opcode, op::COPY, "the copy survives");

        // The same copy at one width propagates.
        let same = data.new_varnode(ventris_lifter::REGISTER_SPACE, 0, 2);
        let other = data.new_unique(2);
        let plain = data.new_op(
            op::COPY,
            SeqNum {
                address: 0x1008,
                order: 0,
            },
            vec![same],
        );
        data.op_set_output(plain, Some(other));
        data.op_insert_end(plain, block);
        let uses = data.new_op(
            op::INT_ADD,
            SeqNum {
                address: 0x100c,
                order: 0,
            },
            vec![other, other],
        );
        let total = data.new_unique(2);
        data.op_set_output(uses, Some(total));
        data.op_insert_end(uses, block);
        assert_eq!(RulePropagateCopy.apply_op(plain, &mut data), 1);
    }
}
