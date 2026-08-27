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
                    let fired = self.rules[rule].apply_op(id, data);
                    applied += fired;
                    if fired > 0 && std::env::var("VENTRIS_TRACE_RULES").is_ok() {
                        eprintln!("rule {} fired {fired} on {id:?}", self.rules[rule].name());
                    }
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
        // Ghidra gives a non-matching branch "one last chance" when it is itself
        // a `MULTIEQUAL`: it marks that phi, adds it to the collapse list, and
        // appends *its* inputs to the things still to match. A value already
        // marked "indicates a loop construct, where the value is recurring in the
        // loop without change, so we treat this as equal to all other branches".
        // Without that expansion a phi whose loop-carried input is another phi
        // never collapses, and the definition left in the loop's tail is a marker
        // - which is why `queryMapAddress_single`'s second `for` was rejected for
        // having "no iteration in tail".
        let is_phi = |data: &Funcdata, value: VarnodeId| {
            data.varnode(value)
                .def
                .is_some_and(|def| data.op(def).opcode == op::MULTIEQUAL)
        };
        let mut matchlist: Vec<VarnodeId> = data.op(id).inputs.clone();
        // The base branch every other must match: the first that is not itself a
        // phi, so the comparison is against a real value where one exists.
        let mut base = matchlist
            .iter()
            .copied()
            .find(|value| !is_phi(data, *value));
        // `nofunc`: a `MULTIEQUAL` or an unwritten value cannot match by
        // functional equality, only by being the very same value.
        let mut no_func =
            base.is_some_and(|value| is_phi(data, value) || data.varnode(value).def.is_none());
        let mut func_eq = false;
        let mut marked: std::collections::BTreeSet<VarnodeId> =
            std::collections::BTreeSet::from([output]);
        let mut collapse: Vec<VarnodeId> = vec![output];
        let mut index = 0;
        while index < matchlist.len() {
            let candidate = matchlist[index];
            index += 1;
            if marked.contains(&candidate) {
                continue;
            }
            match base {
                None => {
                    no_func = is_phi(data, candidate) || data.varnode(candidate).def.is_none();
                    base = Some(candidate);
                }
                Some(chosen) if chosen == candidate => {}
                // Functional equality: two *different* values computed alike.
                // Ghidra allows it unless the base is a marker or unwritten.
                Some(chosen)
                    if !no_func
                        && super::equality::functional_equality(data, chosen, candidate)
                            == super::equality::Equality::Same =>
                {
                    func_eq = true;
                }
                Some(_) if is_phi(data, candidate) => {
                    marked.insert(candidate);
                    collapse.push(candidate);
                    let definition = data.varnode(candidate).def.expect("a phi has a definition");
                    matchlist.extend(data.op(definition).inputs.clone());
                }
                Some(_) => return 0,
            }
        }
        let Some(base) = base else { return 0 };
        let mut changed = 0;
        for value in collapse {
            let Some(definition) = data.varnode(value).def else {
                continue;
            };
            if value == base {
                continue;
            }
            if !func_eq {
                // Absolute equality: every branch is the same value, so the
                // merge is a copy of it.
                data.op_set_opcode(definition, op::COPY);
                data.op_set_inputs(definition, vec![base]);
                changed += 1;
                continue;
            }
            // Functional equality: the branches compute the same thing from
            // different values, so the merge becomes that computation. If this
            // block already computes it, use that result instead of a second
            // copy - `cseFindInBlock` bounded by the merge's earliest use, so
            // the substitute is available where the value is read.
            let Some(source) = data.varnode(base).def else {
                continue;
            };
            let Some(block) = data.op(definition).parent else {
                continue;
            };
            let earliest = data.earliest_use(block, value);
            let substitute = data
                .op(source)
                .inputs
                .clone()
                .into_iter()
                .find(|operand| !data.varnode(*operand).flags.constant)
                .and_then(|operand| data.cse_find_in_block(source, operand, block, earliest));
            if let Some(substitute) = substitute {
                let Some(replacement) = data.op(substitute).output else {
                    continue;
                };
                data.total_replace(value, replacement);
                data.op_destroy(definition);
                changed += 1;
                continue;
            }
            // Otherwise copy the computation onto the merge. A merge that is no
            // longer a merge has to move below any that remain, which is what
            // `opInsertBegin` after `opUninsert` achieves.
            let operands = data.op(source).inputs.clone();
            let opcode = data.op(source).opcode;
            let was_marker = data.op(definition).opcode == op::MULTIEQUAL;
            data.op_set_inputs(definition, operands);
            data.op_set_opcode(definition, opcode);
            if was_marker {
                data.op_uninsert(definition);
                data.op_insert_begin(definition, block);
            }
            changed += 1;
        }
        changed
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
        // An `INDIRECT` that indirectly *creates* its output must never collapse:
        // `RuleIndirectCollapse` returns 0 for `op->isIndirectCreation()`, and
        // collapsing would replace a location a call destroyed with the
        // placeholder constant standing in for "no previous value".
        if data.is_indirect_creation(id) {
            return 0;
        }
        // The responsible operation is named by the second operand. If it is
        // gone, there is no indirect effect left to describe.
        let cause_alive = operation
            .inputs
            .get(1)
            .copied()
            .and_then(|cause| data.iop_target(cause))
            .is_some_and(|cause| data.opcode_of(cause).is_some());
        if cause_alive {
            return 0;
        }
        // `totalReplace` then `opDestroy`: the value flows on directly, and the
        // marker itself is gone rather than left as an assignment to print.
        data.total_replace(output, source);
        data.op_destroy(id);
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
    // `splitdatatype` is deliberately absent: Ghidra registers `RuleSplitCopy`,
    // `RuleSplitLoad` and `RuleSplitStore` in the *cleanup* pool
    // (`coreaction.cc:5754-5756`), not here, and the pool decides when they run.
    let batches: [(&str, Vec<Box<dyn Rule>>); 9] = [
        ("expr_bool", super::expr_bool::all()),
        ("expr_arith", super::expr_arith::all()),
        ("expr_divmod", super::expr_divmod::all()),
        ("expr_piece", super::expr_piece::all()),
        ("expr_float", super::expr_float::all()),
        ("expr_ptr", super::expr_ptr::all()),
        ("expr_memory", super::expr_memory::all()),
        ("splitvarnode", super::splitvarnode::all()),
        ("subfloat", super::subfloat::all()),
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
    //
    // `RulePtrsubCharConstant` and `RuleStringCopy` used to sit here, but Ghidra
    // registers both in the *cleanup* pool (`coreaction.cc:5755`, `5760`). A
    // cleanup rule running inside the main loop rewrites shapes the expression
    // rules still need, which is the whole reason the pool boundary exists.
    expression = expression
        .add_rule(Box::new(super::protoconstraints::RulePiecePathology))
        .add_rule(Box::new(super::orconsume::RuleOrConsume))
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
    if !skip("varnodeprops") {
        pipeline = pipeline.add(Box::new(super::varnodeprops::ActionVarnodeProps));
    }
    if !skip("prototypes") {
        pipeline = pipeline.add(Box::new(prototypes));
    }
    if !skip("expression") {
        pipeline = pipeline.add(Box::new(FixedPoint::new(Box::new(expression))));
    }
    // Ghidra's second rule pool, `oppool2` (`coreaction.cc:5713-5721`). It sits
    // in the main loop *after* `ActionBlockStructure` and `ActionConstantPtr` and
    // before the determined-branch and unreachable passes, and it holds exactly
    // five rules: `RulePushPtr`, `RuleStructOffset0`, `RulePtrArith`,
    // `RuleLoadVarnode` and `RuleStoreVarnode`.
    //
    // All five were in the single expression pool, which runs earlier. The pool
    // boundary is the point: these rewrite pointer arithmetic and stack-variable
    // accesses, and Ghidra runs them only once the block structure and the
    // constant-pointer marks exist, so that a pointer they synthesise is not
    // then re-derived by the arithmetic rules that ran before them.
    if !skip("expression2") {
        let mut second = ActionPool::new("oppool2");
        for rule in [
            Box::new(super::expr_ptr::RulePushPtr) as Box<dyn Rule>,
            Box::new(super::expr_ptr::RuleStructOffset0),
            Box::new(super::expr_ptr::RulePtrArith),
            Box::new(super::expr_memory::RuleLoadVarnode),
            Box::new(super::expr_memory::RuleStoreVarnode),
        ] {
            if dropped.iter().any(|name| name == rule.name()) {
                continue;
            }
            second = second.add_rule(rule);
        }
        pipeline = pipeline.add(Box::new(FixedPoint::new(Box::new(second))));
    }
    // Ghidra's `localrecovery` group, plus `ActionRestrictLocal` which precedes
    // it in the main loop (`coreaction.cc:5553`, before `ActionDeadCode` at
    // `5554` - its own comment says "Do before dead code removed"). It marks the
    // frame slots that hold saved registers not-mapped, so they never become
    // locals; leaving it a no-op is what let prologue spills print.
    if !skip("localrecovery") {
        let mut localrecovery = ActionGroup::new("localrecovery");
        for action in [
            Box::new(super::stackframe::ActionRestrictLocal) as Box<dyn Action>,
            Box::new(super::scopeconsumers::ActionRestructureVarnode),
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
    // `ActionPreferComplement` (`coreaction.cc:5770`), `ActionStructureTransform`
    // (`5772`) and `ActionNormalizeBranches` (`5773`) are at Ghidra's top level,
    // after the loop. They stay per-round here for the same reason the cleanup
    // pool does, which `cleanup_pipeline` records in full: this graph has no
    // spacebase varnodes, so the frame handling Ghidra does once cannot be done
    // once here.
    if !skip("blockrecovery") {
        let mut blockrecovery = ActionGroup::new("blockrecovery");
        for action in super::structuretransform::all() {
            blockrecovery = blockrecovery.add(action);
        }
        blockrecovery = blockrecovery.add(Box::new(super::branchaction::ActionNormalizeBranches));
        pipeline = pipeline.add(Box::new(blockrecovery));
    }
    if !skip("infer-types-rich") {
        pipeline = pipeline.add(Box::new(super::typefactory::ActionInferTypes));
    }
    // Called from here rather than once after the loop: see `cleanup_pipeline`
    // for the measurement and the blocking prerequisite.
    pipeline = pipeline.add(cleanup_pipeline());
    Box::new(pipeline)
}

/// Everything Ghidra runs **once, after** the full loop has settled.
///
/// `actcleanup` is added to the universal group rather than to `actfullloop`
/// (`coreaction.cc:5769`), and the merge and block-recovery actions follow it at
/// the same level (`5770-5795`). That is a phase boundary, not a naming detail:
/// the cleanup pool holds rules that are the exact inverses of rules in the
/// expression pool, and they are safe together only because they never run in
/// the same loop.
///
/// Having this inside the per-round group is what made the pipeline oscillate.
/// `RuleMultNegOne` (cleanup, `5747`) rewrites `a * -1` to `-a`, and
/// `Rule2Comp2Mult` (expression) rewrites `-a` back to `a * -1`; `RuleSubRight`
/// and `Rule2Comp2Sub` pair with `RuleSub2Add` the same way. Measured on
/// `animal_crossing_gafe01`'s largest function the pool alternated between 45 and
/// 33 firings for every one of its twenty-four iterations and never reported
/// zero, so the emitted C was decided by the iteration cap.
///
/// # Why it is called from inside the loop anyway
///
/// Moving it out was implemented, measured, and reverted. `agrees` went 31 -> 29:
/// `osContGetReadData` and `GameWorld::drawMainMenuOpt` began printing their
/// prologue register spills, which is what the `excess-casts` family reports when
/// a `*(uint32_t *)(r1 - 4) = r31;` survives into the output.
///
/// The cause is a missing facility, not the placement. Ghidra never has to
/// remove those stores, because `ActionRestrictLocal` (`coreaction.cc:2036`)
/// marks the frame slot that parks a preserved register as not-mapped, so it is
/// never a local. That algorithm looks for a **`COPY` whose output lands in the
/// stack space** - `isUnaffectedStorage` is `vn->getSpace() == space`
/// (`varmap.hh:244`). Ghidra has such varnodes because `IPTR_SPACEBASE` spaces
/// and `ActionSpacebase` give every frame slot its own varnode. This graph keeps
/// a stack save as a `STORE` to a RAM address computed from the stack-pointer
/// register, so there is no COPY and no stack-space varnode to mark: the ported
/// `graph::stackframe::ActionRestrictLocal` runs and marks **zero** slots, which
/// was measured rather than assumed.
///
/// With the pool inside the loop, its rules keep rewriting the spill shapes until
/// the statement-level pass that removes matched save/restore pairs can recognise
/// them. That is compensation, and it costs the fixed point: the pool alternates
/// 25/33 forever. The honest state of the port is that **the phase boundary is
/// blocked on spacebase varnodes**, and the exchange rate is currently two
/// agreeing functions against a cap-determined answer on one.
///
/// The prerequisite is therefore `IPTR_SPACEBASE`-style address spaces plus
/// `ActionSpacebase`, after which this should be called once from
/// `native.rs` after the full loop and the compensation removed.
pub fn cleanup_pipeline() -> Box<dyn Action> {
    let dropped: Vec<String> = std::env::var("VENTRIS_SKIP_RULE")
        .map(|value| value.split(',').map(str::trim).map(str::to_owned).collect())
        .unwrap_or_default();
    let skip = |name: &str| {
        std::env::var("VENTRIS_SKIP_GROUP")
            .map(|value| value.split(',').any(|entry| entry.trim() == name))
            .unwrap_or(false)
    };
    let mut pipeline = ActionGroup::new("cleanup-pipeline");
    // Ghidra's `cleanup` pool. The bitfield rules rewrite a mask-and-shift into a
    // single ZPULL, so running them earlier would remove the shapes the
    // expression rules match on; the same ordering argument is why
    // `RuleMultNegOne` and `RuleAddUnsigned` belong here - they rewrite an
    // addition of a large constant into a subtraction, a presentation choice the
    // arithmetic rules must not see.
    //
    // Registration order follows `coreaction.cc:5745-5767`.
    if !skip("cleanup") {
        let mut cleanup = ActionPool::new("cleanup");
        for rule in [
            Box::new(super::expr_arith::RuleMultNegOne) as Box<dyn Rule>,
            Box::new(super::expr_arith::RuleAddUnsigned),
            Box::new(super::expr_arith::Rule2Comp2Sub),
            Box::new(super::subfloat::RuleDumptyHumpLate),
            Box::new(super::expr_rules::RuleSubRight),
            Box::new(super::expr_float::RuleFloatSignCleanup),
            Box::new(super::expr_memory::RuleExpandLoad),
            Box::new(super::scopeconsumers::RulePtrsubCharConstant),
            Box::new(super::expr_piece::RuleExtensionPush),
            Box::new(super::expr_ptr::RulePieceStructure),
            Box::new(super::splitdatatype::RuleSplitCopy),
            Box::new(super::splitdatatype::RuleSplitLoad),
            Box::new(super::splitdatatype::RuleSplitStore),
            Box::new(super::scopeconsumers::RuleStringCopy),
            Box::new(super::bitfield::RuleBitFieldStore),
            Box::new(super::bitfield::RuleBitFieldOut),
            Box::new(super::bitfield::RuleBitFieldLoad),
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

    /// Two arms computing the same thing from the same operands are
    /// *functionally* equal, and `RuleMultiCollapse` collapses that: the merge
    /// becomes the computation. Ghidra only refuses when the base branch is
    /// itself a marker or unwritten - `nofunc` - because neither can be matched
    /// except by being the very same value.
    #[test]
    fn a_merge_of_two_values_computed_alike_becomes_that_computation() {
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
        assert_eq!(RuleMultiCollapse.apply_op(phi, &mut data), 1);
        assert_eq!(
            data.op(phi).opcode,
            op::COPY,
            "the merge is the computation both arms performed"
        );
        assert_eq!(data.op(phi).inputs, vec![shared]);
    }

    /// A merge whose base branch is unwritten cannot match by functional
    /// equality, so a differently computed branch keeps the merge.
    #[test]
    fn a_merge_against_an_unwritten_branch_refuses_functional_equality() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let unwritten = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.mark_input(unwritten);
        let constant = data.new_constant(7, 4);
        let copy = data.new_op(op::COPY, seq(0x1000), vec![constant]);
        let computed = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(copy, Some(computed));
        data.op_insert_end(copy, block);
        let phi = data.new_op(op::MULTIEQUAL, seq(0x1000), vec![unwritten, computed]);
        let result = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(phi, Some(result));
        data.op_insert_end(phi, block);

        assert_eq!(RuleMultiCollapse.apply_op(phi, &mut data), 0);
        assert_eq!(data.op(phi).opcode, op::MULTIEQUAL);
    }

    /// Two operands naming one value collapse by absolute equality.
    #[test]
    fn a_merge_of_one_value_is_not_a_merge() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let constant = data.new_constant(7, 4);
        let copy = data.new_op(op::COPY, seq(0x1000), vec![constant]);
        let computed = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(copy, Some(computed));
        data.op_insert_end(copy, block);
        let phi = data.new_op(op::MULTIEQUAL, seq(0x1000), vec![computed, computed]);
        let result = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(phi, Some(result));
        data.op_insert_end(phi, block);

        assert_eq!(RuleMultiCollapse.apply_op(phi, &mut data), 1);
        assert_eq!(data.op(phi).opcode, op::COPY);
        assert_eq!(data.op(phi).inputs, vec![computed]);
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

    /// Ghidra gives a non-matching branch "one last chance" when it is itself a
    /// `MULTIEQUAL`: it marks that phi, adds it to the collapse list, and appends
    /// its inputs to the things still to match. Two phis carrying one value round
    /// a loop therefore both collapse. Without the expansion the phi in the tail
    /// survives, and a loop whose carried value is defined by a marker is refused
    /// a `for` - "no iteration in tail".
    #[test]
    fn two_phis_carrying_one_value_round_a_loop_both_collapse() {
        let mut data = Funcdata::default();
        let head = data.new_block(0x1000);
        let tail = data.new_block(0x1010);
        let value = data.new_varnode(REGISTER_SPACE, 8, 4);

        let head_phi = data.new_op(op::MULTIEQUAL, seq(0x1000), vec![value]);
        let head_out = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(head_phi, Some(head_out));
        data.op_insert_end(head_phi, head);

        let tail_phi = data.new_op(op::MULTIEQUAL, seq(0x1010), vec![value]);
        let tail_out = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(tail_phi, Some(tail_out));
        data.op_insert_end(tail_phi, tail);

        // The head merges the entry value with the tail's, and the tail merges the
        // same entry value with the head's: one value, going round unchanged.
        data.op_set_inputs(head_phi, vec![value, tail_out]);
        data.op_set_inputs(tail_phi, vec![value, head_out]);

        assert_eq!(RuleMultiCollapse.apply_op(head_phi, &mut data), 2);
        assert_eq!(data.op(head_phi).opcode, op::COPY);
        assert_eq!(data.op(head_phi).inputs, vec![value]);
        assert_eq!(
            data.op(tail_phi).opcode,
            op::COPY,
            "the tail's phi is no longer a marker, so a loop can iterate through it"
        );
        assert_eq!(data.op(tail_phi).inputs, vec![value]);
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
        // A `RETURN`'s first operand is the return address, which consume
        // propagation skips; a one-operand `RETURN` therefore consumes nothing
        // and the chain reads as dead. Real returns carry both.
        let ret = data.new_op(op::RETURN, seq(0x100c), vec![final_value, final_value]);
        data.op_insert_end(ret, block);

        assert!(default_pipeline().apply(&mut data) > 0);
        let returned = data.op(ret).inputs[1];
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
