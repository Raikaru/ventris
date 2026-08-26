//! Control-flow structuring, ported from Ghidra 12.1.3's `CollapseStructure`.
//!
//! Structuring is a graph rewrite, not a statement rewrite. Ghidra repeatedly
//! finds a subgraph matching a source construct and replaces it with one
//! composite node, until a single node remains. Each rule states exactly which
//! edges the shape requires, so a construct is only recovered when the control
//! flow really has that shape — anything left over stays a `goto`, which is
//! honest rather than wrong.
//!
//! Ventris' own structuring worked on a flat statement list, pattern-matching
//! label and goto sequences. That cannot express the edge conditions these
//! rules test: "nothing else reaches this clause", "both clauses leave to the
//! same place", "the clause loops back to the header".
//!
//! Source authority: `CollapseStructure::ruleBlockCat`, `ruleBlockIfElse`,
//! `ruleBlockIfNoExit`, `ruleBlockWhileDo`, `ruleBlockDoWhile`, and
//! `ruleBlockGoto` in `blockaction.cc` at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use std::collections::{BTreeMap, BTreeSet};

use ventris_pcode::op;

use super::heritage::compute_dominance;
use super::tracedag;
use super::{Funcdata, GraphBlockId};

/// The test a construct evaluates.
///
/// A single branch is one block's condition. Short-circuit operators combine
/// two, which is what `CollapseStructure::ruleBlockOr` recovers: machine code
/// spells `a || b` as two consecutive conditional branches to the same target,
/// and without recognising that shape the second branch stays a separate block
/// and the whole region falls back to `goto`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Condition {
    /// The condition under which `block`'s branch transfers to its taken
    /// target, negated when `taken` is false.
    Branch {
        block: GraphBlockId,
        taken: bool,
    },
    Or(Box<Condition>, Box<Condition>),
    And(Box<Condition>, Box<Condition>),
}

/// A recovered source construct.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Structured {
    /// One basic block's statements.
    Basic(GraphBlockId),
    /// Straight-line concatenation.
    List(Vec<Structured>),
    /// A two-way branch whose clauses rejoin.
    ///
    /// `header` is everything that runs before the test, which may be several
    /// blocks once concatenation has collapsed them. `test` names the block
    /// holding the branch itself, so the condition can be read from it.
    IfElse {
        header: Box<Structured>,
        test: Condition,
        /// True when the recovered clauses are in the branch's taken order.
        taken_first: bool,
        then_body: Box<Structured>,
        else_body: Option<Box<Structured>>,
    },
    /// A loop testing before its body.
    WhileDo {
        header: Box<Structured>,
        test: Condition,
        /// True when the body is the taken side of the test.
        body_taken: bool,
        body: Box<Structured>,
    },
    /// A loop testing after its body.
    DoWhile {
        body: Box<Structured>,
        test: Condition,
        body_taken: bool,
    },
    /// A loop with no exit.
    InfLoop { body: Box<Structured> },
    /// An edge no construct claimed.
    Goto {
        from: GraphBlockId,
        target: GraphBlockId,
    },
    /// A jump to the enclosing loop's exit, which C spells `break`.
    Break,
    /// A conditional jump to the enclosing loop's exit.
    IfBreak { test: Condition, taken: bool },
    /// A multi-way branch and its cases.
    ///
    /// `header` is everything up to and including the indirect branch. Each case
    /// is one recovered body; `has_exit` records whether the cases converge on a
    /// block after the switch, which is what lets the emitter spell `break`.
    Switch {
        header: Box<Structured>,
        /// The value the branch selects on.
        selector: super::VarnodeId,
        /// Each case's label and body. A case with no label is the default: the
        /// table named no value for it.
        cases: Vec<(Option<u64>, Structured)>,
        has_exit: bool,
    },
    /// One edge of a two-way branch that no construct claimed. The other edge
    /// remains the fallthrough, so the branch keeps its condition instead of
    /// becoming an unconditional jump that orphans it.
    IfGoto {
        test: Condition,
        taken: bool,
        target: GraphBlockId,
    },
}

/// One node of the collapsing graph.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Node {
    body: Structured,
    /// Entry block, so incoming edges can be redirected.
    entry: GraphBlockId,
    /// Block holding this node's outgoing branch, which is where a construct
    /// reads its condition from.
    exit: GraphBlockId,
    /// The condition under which `successors[0]` is taken, once a rule has
    /// combined several branches into one test. `None` means the condition is
    /// still just this node's own exit branch.
    test: Option<Condition>,
    successors: Vec<NodeId>,
    predecessors: Vec<NodeId>,
    collapsed: bool,
    /// Set once `ruleBlockSwitch` has claimed this node's multi-way branch.
    /// Ghidra's `f_switch_out` lives on the block, and the composite the switch
    /// rule builds does not carry it, so the other rules stop deferring once the
    /// switch is resolved.
    switch_resolved: bool,
}

type NodeId = usize;

/// Collapses a function's control flow into a construct tree.
///
/// The result is a single construct when the flow is fully structured, and a
/// list containing `Goto` where it is not.
pub fn structure(data: &Funcdata, tables: &[super::jumptable::JumpTable]) -> Structured {
    let mut graph = Graph::of(data, tables);
    graph.collapse();
    let mut tree = graph.finish();
    // `ActionFinalStructure` calls `BlockGraph::scopeBreak` once the tree is
    // built, which is what turns a jump to a loop's exit into `break`.
    scope_break(&mut tree, None, None);
    tree
}

/// The first basic block a construct enters.
///
/// Ghidra's `FlowBlock::getFrontLeaf`. `scopeBreak` needs it to tell one member
/// of a list what the next member is, which is that member's exit.
pub(super) fn front_block(node: &Structured) -> Option<GraphBlockId> {
    match node {
        Structured::Basic(block) => Some(*block),
        Structured::List(members) => members.iter().find_map(front_block),
        Structured::IfElse { header, .. }
        | Structured::WhileDo { header, .. }
        | Structured::Switch { header, .. } => front_block(header),
        Structured::DoWhile { body, .. } | Structured::InfLoop { body } => front_block(body),
        Structured::Goto { from, .. } => Some(*from),
        Structured::IfGoto { .. } | Structured::Break | Structured::IfBreak { .. } => None,
    }
}

/// Turn a jump to the enclosing loop's exit into `break`.
///
/// Port of `BlockGraph::scopeBreak` and the overrides on the loop and goto
/// blocks. `exit` is the block control reaches when this construct falls through;
/// `loop_exit` is the block that leaves the innermost enclosing loop. A loop
/// introduces a new scope, so its own body sees the loop's exit as `loop_exit`
/// — which is this construct's `exit`.
fn scope_break(node: &mut Structured, exit: Option<GraphBlockId>, loop_exit: Option<GraphBlockId>) {
    match node {
        Structured::List(members) => {
            for index in 0..members.len() {
                // Each member's exit is the next member's entry; the last
                // inherits the list's own.
                let next = members.get(index + 1).and_then(front_block).or(exit);
                scope_break(&mut members[index], next, loop_exit);
            }
        }
        Structured::IfElse {
            header,
            then_body,
            else_body,
            ..
        } => {
            scope_break(header, None, loop_exit);
            scope_break(then_body, exit, loop_exit);
            if let Some(body) = else_body {
                scope_break(body, exit, loop_exit);
            }
        }
        Structured::WhileDo { header, body, .. } => {
            // The loop's exit is whatever follows it, and its body is a new
            // scope in which a jump there is a `break`.
            scope_break(header, None, exit);
            scope_break(body, front_block(header), exit);
        }
        Structured::DoWhile { body, .. } => scope_break(body, None, exit),
        Structured::InfLoop { body } => scope_break(body, None, exit),
        Structured::Switch { header, cases, .. } => {
            scope_break(header, None, loop_exit);
            for (_, case) in cases.iter_mut() {
                scope_break(case, exit, loop_exit);
            }
        }
        Structured::Goto { target, .. } => {
            if loop_exit == Some(*target) {
                *node = Structured::Break;
            }
        }
        Structured::IfGoto {
            test,
            taken,
            target,
        } => {
            if loop_exit == Some(*target) {
                *node = Structured::IfBreak {
                    test: test.clone(),
                    taken: *taken,
                };
            }
        }
        Structured::Basic(_) | Structured::Break | Structured::IfBreak { .. } => {}
    }
}

/// The collapsing graph: nodes that rules merge until one construct remains.
struct Graph<'a> {
    data: &'a Funcdata,
    nodes: Vec<Node>,
    of_block: BTreeMap<GraphBlockId, NodeId>,
    entry: Option<NodeId>,
    /// Count of edges given up as gotos, so a stalled collapse can tell whether
    /// re-marking loop exits made progress.
    surrendered: usize,
    /// Recovered switch tables, so a multi-way branch can name its cases.
    tables: &'a [super::jumptable::JumpTable],
}

impl<'a> Graph<'a> {
    fn of(data: &'a Funcdata, tables: &'a [super::jumptable::JumpTable]) -> Self {
        let mut nodes = Vec::new();
        let mut of_block = BTreeMap::new();
        for (id, _) in data.blocks() {
            of_block.insert(id, nodes.len());
            nodes.push(Node {
                body: Structured::Basic(id),
                entry: id,
                exit: id,
                test: None,
                successors: Vec::new(),
                predecessors: Vec::new(),
                collapsed: false,
                switch_resolved: false,
            });
        }
        for (id, block) in data.blocks() {
            let node = of_block[&id];
            // Successor order is the branch's own: taken first, then
            // fallthrough, so a rule can ask which side a clause is on.
            let mut successors: Vec<GraphBlockId> = block.successors.clone();
            if let Some(taken) = taken_successor(data, id) {
                successors.sort_by_key(|candidate| u8::from(*candidate != taken));
            }
            nodes[node].successors = successors
                .iter()
                .filter_map(|successor| of_block.get(successor).copied())
                .collect();
        }
        for node in 0..nodes.len() {
            for successor in nodes[node].successors.clone() {
                nodes[successor].predecessors.push(node);
            }
        }
        let entry = data
            .blocks()
            .find(|(_, block)| block.start == data.entry && block.start_order == 0)
            .map(|(id, _)| id)
            .or_else(|| data.blocks().next().map(|(id, _)| id))
            .and_then(|id| of_block.get(&id).copied());
        Self {
            data,
            nodes,
            of_block,
            entry,
            surrendered: 0,
            tables,
        }
    }

    fn collapse(&mut self) {
        // Conditions collapse in their own pass first. Ghidra runs
        // `collapseConditions` ahead of the main loop because a short-circuit
        // operator spans two blocks that every other rule would otherwise
        // treat as separate regions.
        self.collapse_conditions();
        // Loop exits are *not* surrendered up front. Ghidra's `collapseInternal`
        // runs every rule to a fixpoint and only then lets `ruleBlockGoto` reach
        // `selectGoto`, so an edge is given up only once nothing else applies.
        // Surrendering before any rule has run hands away an edge the rules
        // would have structured, and with `labelExitEdges` priority that first
        // edge is an interior one — the worst choice available.

        let cap = self.nodes.len() * 4 + 16;
        let mut guard = 0;
        loop {
            let mut inner_changed = true;
            while inner_changed {
                guard += 1;
                if guard > cap {
                    return;
                }
                inner_changed = false;
                let live: Vec<NodeId> = (0..self.nodes.len())
                    .filter(|node| !self.nodes[*node].collapsed)
                    .collect();
                if live.len() <= 1 {
                    return;
                }
                for node in live.iter().copied() {
                    if self.nodes[node].collapsed {
                        continue;
                    }
                    // `collapseInternal`'s rule chain, in its order. Ghidra's
                    // `ruleBlockProperIf` — a single-sided `if`, the commonest
                    // C construct — is the third rule tried, not a last
                    // resort, and `ruleBlockSwitch` is the last, because a
                    // switch absorbs its cases and running it early takes
                    // blocks a loop or an `if` would have claimed.
                    if self.rule_cat(node)
                        || self.rule_if_no_exit(node)
                        || self.rule_if_else(node)
                        || self.rule_while_do(node)
                        || self.rule_do_while(node)
                        || self.rule_inf_loop(node)
                        || self.rule_block_switch(node)
                    {
                        inner_changed = true;
                        break;
                    }
                }
            }

            // Only when nothing preferable applies: Ghidra's comment is that
            // applying `ruleBlockIfNoExit` too early makes preferable rules
            // miss, and `ruleCaseFallthru` shares the phase.
            let live: Vec<NodeId> = (0..self.nodes.len())
                .filter(|node| !self.nodes[*node].collapsed)
                .collect();
            if live.len() <= 1 {
                return;
            }
            let mut outer_changed = false;
            for node in live.iter().copied() {
                if self.nodes[node].collapsed {
                    continue;
                }
                if self.rule_block_if_return(node) || self.rule_case_fallthru(node) {
                    outer_changed = true;
                    break;
                }
            }
            if outer_changed {
                continue;
            }
            // Concatenation can expose a loop that was not visible as one
            // before, so exits are re-marked whenever the rules stall.
            let before = self.surrendered;
            self.mark_loop_exits();
            if self.surrendered != before {
                continue;
            }
            // Nothing matched at all: give up one edge as a goto and retry.
            // This is `ruleBlockGoto`, the last resort that guarantees the
            // collapse terminates.
            if !self.rule_goto(&live) {
                return;
            }
        }
    }

    /// Surrenders every edge that leaves a natural loop, except its one exit.
    ///
    /// Ported from `CollapseStructure::labelLoops`, `LoopBody::findBase`,
    /// `LoopBody::findExit`, and `CollapseStructure::markExitsAsGotos`.
    fn mark_loop_exits(&mut self) {
        let dominance = compute_dominance(self.data);
        for (head, tails) in self.natural_loops(&dominance) {
            let mut tails = tails;
            let (mut body, unique_count) = self.loop_body(head, &tails);
            let exit = self.loop_exit(&body, &tails);
            self.extend_loop_body(&mut body, exit);
            // The exit may only be recomputed after extension, because a block
            // taken into the body is no longer a candidate exit.
            let exit = self.loop_exit(&body, &tails);
            self.order_tails(&mut tails, exit);

            // `LoopBody::labelExitEdges`: the priority for removal is the middle
            // of the body first, then the head, then the tails in reverse so the
            // preferred tail's edges go last, and every edge to the official exit
            // block after all of those.
            let inside: BTreeSet<NodeId> = body.iter().copied().collect();
            let exits_of = |node: NodeId| -> Vec<(NodeId, NodeId)> {
                self.nodes[node]
                    .successors
                    .iter()
                    .copied()
                    .filter(|successor| !inside.contains(successor))
                    .map(|successor| (node, successor))
                    .collect()
            };
            let mut leaving: Vec<(NodeId, NodeId)> = Vec::new();
            let mut to_exit: Vec<(NodeId, NodeId)> = Vec::new();
            let classify = |edges: Vec<(NodeId, NodeId)>,
                            leaving: &mut Vec<(NodeId, NodeId)>,
                            to_exit: &mut Vec<(NodeId, NodeId)>| {
                for edge in edges {
                    if Some(edge.1) == exit {
                        to_exit.push(edge);
                    } else {
                        leaving.push(edge);
                    }
                }
            };
            for node in body.iter().copied().skip(unique_count) {
                classify(exits_of(node), &mut leaving, &mut to_exit);
            }
            classify(exits_of(head), &mut leaving, &mut to_exit);
            for tail in tails.iter().rev().copied() {
                if tail == head {
                    continue;
                }
                classify(exits_of(tail), &mut leaving, &mut to_exit);
            }
            leaving.extend(to_exit);
            if leaving.is_empty() {
                continue;
            }
            // One edge per pass, so the collapse rules get a chance between
            // each: `selectGoto` advances through this list rather than
            // surrendering all of it at once.
            let chosen = self
                .traced_loop_edge(&inside, head, &tails)
                .filter(|edge| leaving.contains(edge))
                .or_else(|| leaving.first().copied());
            if let Some((node, successor)) = chosen {
                self.surrender_edge(node, successor);
                return;
            }
        }
    }

    /// Back edges, grouped by the loop head they return to.
    ///
    /// An edge is a back edge when its target dominates its source, which is
    /// exactly Ghidra's `isBackEdgeIn` for a reducible graph.
    fn natural_loops(&self, dominance: &super::heritage::Dominance) -> Vec<(NodeId, Vec<NodeId>)> {
        let mut loops: BTreeMap<NodeId, Vec<NodeId>> = BTreeMap::new();
        for node in 0..self.nodes.len() {
            if self.nodes[node].collapsed {
                continue;
            }
            for successor in self.nodes[node].successors.clone() {
                if dominates(
                    dominance,
                    self.nodes[successor].entry,
                    self.nodes[node].entry,
                ) {
                    loops.entry(successor).or_default().push(node);
                }
            }
        }
        loops.into_iter().collect()
    }

    /// The edge inside a loop body that `TraceDAG` judges least structurable.
    ///
    /// The trace is bounded exactly as Ghidra bounds it: rooted at the loop head,
    /// finishing at a tail, and with the edges leaving the body excluded from the
    /// DAG so the trace does not wander out of the loop. That is
    /// `setExitMarks` plus `setFinishBlock`.
    fn traced_loop_edge(
        &self,
        body: &BTreeSet<NodeId>,
        head: NodeId,
        tails: &[NodeId],
    ) -> Option<(NodeId, usize)> {
        let successors: Vec<Vec<NodeId>> = (0..self.nodes.len())
            .map(|node| {
                if body.contains(&node) {
                    self.nodes[node].successors.clone()
                } else {
                    Vec::new()
                }
            })
            .collect();
        // An edge leaving the body, or returning to the head, is not a DAG edge.
        let inside = |node: NodeId, index: usize| -> bool {
            self.nodes[node]
                .successors
                .get(index)
                .is_some_and(|successor| body.contains(successor) && *successor != head)
        };
        let dag_out = |node: NodeId, index: usize| inside(node, index);
        let dag_in_count = |node: NodeId| {
            body.iter()
                .copied()
                .flat_map(|from| {
                    self.nodes[from]
                        .successors
                        .iter()
                        .copied()
                        .enumerate()
                        .map(move |(index, to)| (from, index, to))
                })
                .filter(|(from, index, to)| *to == node && inside(*from, *index))
                .count()
        };
        let roots = [head];
        let edges = tracedag::TraceDag::new(tracedag::Dag {
            successors: &successors,
            dag_out: &dag_out,
            dag_in_count: &dag_in_count,
            roots: &roots,
            finish: tails.first().copied(),
        })
        .run();
        edges.into_iter().find_map(|edge| {
            let index = self.nodes[edge.bottom]
                .successors
                .iter()
                .position(|successor| *successor == edge.dest)?;
            Some((edge.bottom, index))
        })
    }

    /// The loop body in `LoopBody::findBase` order.
    ///
    /// The order is load-bearing, not incidental: the head and the tails come
    /// first and `unique_count` records how many that is, so
    /// `LoopBody::labelExitEdges` can address the non-head/tail nodes as the
    /// tail of the list. The rest follow in the order the predecessor walk
    /// discovers them. Returning a set instead — as this did — sorts the interior
    /// by block number and loses the discovery order the exit-edge priority is
    /// expressed in.
    fn loop_body(&self, head: NodeId, tails: &[NodeId]) -> (Vec<NodeId>, usize) {
        let mut body: Vec<NodeId> = vec![head];
        let mut seen: BTreeSet<NodeId> = BTreeSet::from([head]);
        for tail in tails.iter().copied() {
            if seen.insert(tail) {
                body.push(tail);
            }
        }
        let unique_count = body.len();
        // Walk predecessors from index one, so the head is never traversed back
        // through: what reaches the head from outside is not in the loop.
        let mut index = 1;
        while index < body.len() {
            let node = body[index];
            index += 1;
            for predecessor in self.nodes[node].predecessors.clone() {
                if self.nodes[predecessor].collapsed {
                    continue;
                }
                if seen.insert(predecessor) {
                    body.push(predecessor);
                }
            }
        }
        (body, unique_count)
    }

    /// `LoopBody::extend`: take in every block reachable only from the body
    /// without passing the exit.
    ///
    /// A block every one of whose predecessors is already inside cannot be
    /// reached from anywhere else, so it belongs to the loop even though no back
    /// edge passes through it. Without this a tail-call-shaped region after the
    /// last test counts as outside, and the edge into it is surrendered.
    fn extend_loop_body(&self, body: &mut Vec<NodeId>, exit: Option<NodeId>) {
        let mut seen: BTreeSet<NodeId> = body.iter().copied().collect();
        let mut visits: BTreeMap<NodeId, usize> = BTreeMap::new();
        let mut index = 0;
        while index < body.len() {
            let node = body[index];
            index += 1;
            for successor in self.nodes[node].successors.clone() {
                if seen.contains(&successor) || Some(successor) == exit {
                    continue;
                }
                let count = visits.entry(successor).or_insert(0);
                *count += 1;
                let incoming = self.nodes[successor]
                    .predecessors
                    .iter()
                    .filter(|predecessor| !self.nodes[**predecessor].collapsed)
                    .count();
                if *count == incoming {
                    seen.insert(successor);
                    body.push(successor);
                }
            }
        }
    }

    /// `LoopBody::orderTails`: put the tail that leaves to the exit first.
    ///
    /// `labelExitEdges` walks the tails in reverse, so the first tail's exit
    /// edges are the last to be surrendered. The tail carrying the loop's own
    /// exit is the one whose edges are worth keeping longest.
    fn order_tails(&self, tails: &mut [NodeId], exit: Option<NodeId>) {
        let Some(exit) = exit else { return };
        if tails.len() <= 1 {
            return;
        }
        let Some(preferred) = tails
            .iter()
            .position(|tail| self.nodes[*tail].successors.contains(&exit))
        else {
            return;
        };
        tails.swap(0, preferred);
    }

    /// The one block a structured loop may exit to.
    ///
    /// `LoopBody::findExit` prefers an exit taken from a tail, because that is
    /// the loop's own test; an exit from the middle is a `break`, which has to
    /// become a goto.
    fn loop_exit(&self, body: &[NodeId], tails: &[NodeId]) -> Option<NodeId> {
        for tail in tails.iter().copied() {
            if let Some(exit) = self.nodes[tail]
                .successors
                .iter()
                .copied()
                .find(|successor| !body.contains(successor))
            {
                return Some(exit);
            }
        }
        body.iter()
            .copied()
            .flat_map(|node| self.nodes[node].successors.clone())
            .find(|successor| !body.contains(successor))
    }

    /// Turns one edge into a `goto`, leaving the rest of the node intact.
    fn surrender_edge(&mut self, node: NodeId, successor: NodeId) {
        let Some(index) = self.nodes[node]
            .successors
            .iter()
            .position(|candidate| *candidate == successor)
        else {
            return;
        };
        // `collapse` compares this count before and after `mark_loop_exits` to
        // tell whether re-marking made progress. It was never incremented, so
        // the comparison always said no and the collapse fell straight through
        // to `rule_goto` - surrendering an edge as a `goto` instead of retrying
        // with the exits that had just been marked.
        self.surrendered += 1;
        let branching = self.nodes[node].successors.len() == 2;
        self.nodes[node].successors.remove(index);
        self.nodes[successor]
            .predecessors
            .retain(|predecessor| *predecessor != node);
        let jump = if branching {
            Structured::IfGoto {
                test: self.condition_for(node),
                taken: index == 0,
                target: self.nodes[successor].entry,
            }
        } else {
            Structured::Goto {
                from: self.nodes[node].exit,
                target: self.nodes[successor].entry,
            }
        };
        self.nodes[node].body = Structured::List(vec![self.nodes[node].body.clone(), jump]);
    }

    /// Collapses short-circuit conditions to a fixed point.
    fn collapse_conditions(&mut self) {
        let cap = self.nodes.len() * 2 + 8;
        for _ in 0..cap {
            let live: Vec<NodeId> = (0..self.nodes.len())
                .filter(|node| !self.nodes[*node].collapsed)
                .collect();
            let mut changed = false;
            for node in live {
                if !self.nodes[node].collapsed && self.rule_block_or(node) {
                    changed = true;
                    break;
                }
            }
            if !changed {
                return;
            }
        }
    }

    /// A block whose only successor is itself never leaves.
    ///
    /// Ghidra's `ruleBlockInfLoop`. Without this the block keeps a self edge
    /// that no other rule can claim, and the collapse surrenders it as a goto.
    fn rule_inf_loop(&mut self, node: NodeId) -> bool {
        if self.nodes[node].successors.len() != 1 || self.nodes[node].successors[0] != node {
            return false;
        }
        // A jump to this node's own entry is what the loop already says. Left in
        // the body it contradicts the construct, and every statement after it
        // reads as dead code.
        let head = self.nodes[node].entry;
        let mut inner = self.nodes[node].body.clone();
        drop_jumps_to(&mut inner, head);
        let body = Structured::InfLoop {
            body: Box::new(inner),
        };
        self.nodes[node].successors.clear();
        self.nodes[node]
            .predecessors
            .retain(|predecessor| *predecessor != node);
        self.nodes[node].body = body;
        true
    }

    /// Two blocks in a chain become one.
    fn rule_cat(&mut self, node: NodeId) -> bool {
        // "Switch must be resolved first": every rule ahead of `ruleBlockSwitch`
        // refuses a multi-way branch, which is what lets the switch rule run
        // last without the others taking its cases.
        if self.is_switch_out(node) {
            return false;
        }
        if self.nodes[node].successors.len() != 1 {
            return false;
        }
        // A construct that always jumps has no fallthrough to concatenate onto.
        if ends_in_transfer(&self.nodes[node].body) {
            return false;
        }
        let next = self.nodes[node].successors[0];
        if next == node {
            return false;
        }
        if self.nodes[next].predecessors.len() != 1 {
            return false;
        }
        // Must start a chain, so concatenation happens once per chain.
        if self.nodes[node].predecessors.len() == 1 {
            let previous = self.nodes[node].predecessors[0];
            if self.nodes[previous].successors.len() == 1 {
                return false;
            }
        }
        let body = Structured::List(vec![
            self.nodes[node].body.clone(),
            self.nodes[next].body.clone(),
        ]);
        let exit = self.nodes[next].exit;
        self.absorb(node, &[next], body);
        self.nodes[node].exit = exit;
        true
    }

    /// A two-way branch whose clauses each rejoin at one place.
    fn rule_if_else(&mut self, node: NodeId) -> bool {
        if self.is_switch_out(node) {
            return false;
        }
        if self.nodes[node].successors.len() != 2 {
            return false;
        }
        // A header that always jumps never reaches its own test.
        if ends_in_transfer(&self.nodes[node].body) {
            return false;
        }
        let (taken, fallthrough) = (
            self.nodes[node].successors[0],
            self.nodes[node].successors[1],
        );
        if taken == node || fallthrough == node {
            return false;
        }
        // Ghidra's `if (!bl->isDecisionOut(0)) return false;` and the same for
        // edge one. A decision edge is one that is neither a back edge, a goto
        // edge nor irreducible; surrendered edges are already gone from
        // `successors` here, so the test that remains is the back edge. An `if`
        // built across one would claim a branch where the flow is a loop.
        if self.nodes[taken].entry <= self.nodes[node].entry
            || self.nodes[fallthrough].entry <= self.nodes[node].entry
        {
            return false;
        }
        for clause in [taken, fallthrough] {
            if self.nodes[clause].predecessors.len() != 1 {
                return false;
            }
            if self.nodes[clause].successors.len() != 1 {
                return false;
            }
        }
        let join = self.nodes[taken].successors[0];
        if join != self.nodes[fallthrough].successors[0] || join == node {
            return false;
        }
        let body = Structured::IfElse {
            header: Box::new(self.nodes[node].body.clone()),
            test: self.condition_for(node),
            taken_first: true,
            then_body: Box::new(self.nodes[taken].body.clone()),
            else_body: Some(Box::new(self.nodes[fallthrough].body.clone())),
        };
        self.absorb(node, &[taken, fallthrough], body);
        true
    }

    /// A two-way branch where one side is a clause that rejoins the other.
    fn rule_if_no_exit(&mut self, node: NodeId) -> bool {
        if self.is_switch_out(node) {
            return false;
        }
        if self.nodes[node].successors.len() != 2 {
            return false;
        }
        // A header that always jumps never reaches its own test.
        if ends_in_transfer(&self.nodes[node].body) {
            return false;
        }
        let (taken, fallthrough) = (
            self.nodes[node].successors[0],
            self.nodes[node].successors[1],
        );
        for (clause, other, taken_first) in
            [(taken, fallthrough, true), (fallthrough, taken, false)]
        {
            if clause == node || other == node {
                continue;
            }
            // Ghidra's `if (!bl->isDecisionOut(i)) continue;` - the edge into the
            // clause must be a decision edge, so not a back edge here. An `if`
            // built across one claims a branch where the flow is a loop.
            if self.nodes[clause].entry <= self.nodes[node].entry {
                continue;
            }
            if self.nodes[clause].predecessors.len() != 1 {
                continue;
            }
            if self.nodes[clause].successors.len() != 1 {
                continue;
            }
            // Ghidra's `if (clauseblock->isSwitchOut()) continue;` - "Don't use
            // switch (possibly with goto edges)". Only the head was checked
            // here, so a clause that itself ends in a computed jump could be
            // absorbed into an `if` body, hiding the multi-way branch.

            // Ghidra's `if (clauseblock->isSwitchOut()) continue;` - "Don't use
            // switch (possibly with goto edges)". Only the head was checked
            // here, so a clause that itself ends in a computed jump could be
            // absorbed into an `if` body, hiding the multi-way branch.
            if self.is_switch_out(clause) {
                continue;
            }
            if self.nodes[clause].successors[0] != other {
                continue;
            }
            let body = Structured::IfElse {
                header: Box::new(self.nodes[node].body.clone()),
                test: self.condition_for(node),
                taken_first,
                then_body: Box::new(self.nodes[clause].body.clone()),
                else_body: None,
            };
            let exit = self.nodes[other].exit;
            self.absorb(node, &[clause], body);
            let _ = exit;
            return true;
        }
        false
    }

    /// A test at the top of a body that loops back to it.
    fn rule_while_do(&mut self, node: NodeId) -> bool {
        if self.is_switch_out(node) {
            return false;
        }
        if self.nodes[node].successors.len() != 2 {
            return false;
        }
        let successors = self.nodes[node].successors.clone();
        for (index, body) in successors.iter().copied().enumerate() {
            if body == node {
                continue;
            }
            if self.nodes[body].predecessors.len() != 1 {
                continue;
            }
            if self.nodes[body].successors.len() != 1 {
                continue;
            }
            if self.nodes[body].successors[0] != node {
                continue;
            }
            let head = self.nodes[node].entry;
            let mut inner = self.nodes[body].body.clone();
            drop_jumps_to(&mut inner, head);
            let structured = Structured::WhileDo {
                header: Box::new(self.nodes[node].body.clone()),
                test: self.condition_for(node),
                body_taken: index == 0,
                body: Box::new(inner),
            };
            self.absorb(node, &[body], structured);
            // The body's only successor is this node, so `absorb` derives a
            // self-edge from it and loses the real exit. The construct has
            // consumed the back edge - `newBlockWhileDo` closes the loop inside
            // the composite - so the composite leaves through the other branch
            // and nowhere else. Without this the composite still loops onto
            // itself and `ruleBlockInfLoop` wraps the whole `while` in a
            // `while (true)`.
            let exit = successors[1 - index];
            self.nodes[node].successors = vec![exit];
            self.nodes[node].predecessors.retain(|held| *held != node);
            let entry = &mut self.nodes[exit].predecessors;
            entry.retain(|held| *held != node);
            entry.push(node);
            return true;
        }
        false
    }

    /// A body whose own terminator tests whether to repeat it.
    fn rule_do_while(&mut self, node: NodeId) -> bool {
        if self.is_switch_out(node) {
            return false;
        }
        if self.nodes[node].successors.len() != 2 {
            return false;
        }
        let Some(self_index) = self.self_edge(node) else {
            return false;
        };
        let head = self.nodes[node].entry;
        let mut inner = self.nodes[node].body.clone();
        drop_jumps_to(&mut inner, head);
        let body = Structured::DoWhile {
            body: Box::new(inner),
            test: self.condition_for(node),
            body_taken: self_index == 0,
        };
        // The self edge is consumed; the other edge leaves the loop.
        self.nodes[node]
            .successors
            .retain(|successor| *successor != node);
        self.nodes[node]
            .predecessors
            .retain(|predecessor| *predecessor != node);
        self.nodes[node].body = body;
        true
    }

    /// The condition under which this node transfers to its first successor.
    ///
    /// A node that has not been combined with another still tests its own exit
    /// branch; one that has carries the combined tree instead.
    fn condition_for(&self, node: NodeId) -> Condition {
        self.nodes[node].test.clone().unwrap_or(Condition::Branch {
            block: self.nodes[node].exit,
            taken: true,
        })
    }

    /// Whether a block is too complicated to become one arm of a short-circuit
    /// condition, porting Ghidra's `BlockBasic::isComplex`.
    ///
    /// A short-circuit operator only evaluates its second arm when the first
    /// did not decide the branch, but the collapse concatenates both bodies and
    /// so runs the second unconditionally. Ghidra allows a complex *first*
    /// block, because only its branch is printed, and refuses a complex second
    /// one for exactly this reason.
    ///
    /// Without the guard `decompSZS_subroutine` collapsed blocks that compute a
    /// value into an `||`, which both ran their statements unconditionally and
    /// left two distinct values sharing one variable name - rendering as
    /// `b || b` and `b || !b` where the source tests two different things.
    ///
    /// Statement counting follows Ghidra: the branch counts as one, so does a
    /// call or an operation with no output, and so does a calculation whose
    /// result is explicit rather than inlined into its reader. More than two
    /// and the block is complex.
    fn is_complex(&self, block: GraphBlockId, successors: usize) -> bool {
        const MAX_IMPLIED_REF: usize = 2;
        let mut statements = usize::from(successors >= 2);
        for operation in self.data.block(block).ops.iter().copied() {
            let op = self.data.op(operation);
            if is_marker_opcode(op.opcode) {
                continue;
            }
            if is_call_opcode(op.opcode) {
                statements += 1;
            } else if let Some(output) = op.output {
                let descendants = &self.data.varnode(output).descendants;
                let explicit = descendants.is_empty()
                    || descendants.len() > MAX_IMPLIED_REF
                    || descendants.iter().any(|reader| {
                        is_marker_opcode(self.data.op(*reader).opcode)
                            || self.data.op(*reader).parent != Some(block)
                    });
                if explicit {
                    statements += 1;
                }
            } else if !is_flow_break_opcode(op.opcode) {
                statements += 1;
            }
            if statements > 2 {
                return true;
            }
        }
        false
    }

    /// The condition under which this node transfers to the given successor.
    fn condition_toward(&self, node: NodeId, successor: NodeId) -> Option<Condition> {
        let index = self.nodes[node]
            .successors
            .iter()
            .position(|candidate| *candidate == successor)?;
        let base = self.condition_for(node);
        Some(if index == 0 { base } else { negate(base) })
    }

    /// Two consecutive tests reaching one target are a short-circuit operator.
    ///
    /// Ghidra's `ruleBlockOr`. Control reaches the shared clause when the first
    /// test takes its edge there, or else when the second does; because the
    /// second is only evaluated when the first did not, the disjunction is
    /// exactly C's `||` including its evaluation order.
    /// Whether an unstructured jump already targets this node's entry.
    ///
    /// Ghidra's `FlowBlock::isInteriorGotoTarget`, checked by `ruleBlockOr` as
    /// `if (orblock->isInteriorGotoTarget()) continue;`. A block a `goto` enters
    /// is not the tail of one condition: control can arrive there without
    /// evaluating the first test, so folding the two into `||` would claim an
    /// order of evaluation that does not hold. Ghidra keeps the surrendered edge
    /// and marks it; this graph removes it, so the jump is found in the bodies
    /// that were already built.
    fn is_interior_goto_target(&self, node: NodeId) -> bool {
        let entry = self.nodes[node].entry;
        self.nodes
            .iter()
            .filter(|candidate| !candidate.collapsed)
            .any(|candidate| body_jumps_to(&candidate.body, entry))
    }

    fn rule_block_or(&mut self, node: NodeId) -> bool {
        if self.nodes[node].successors.len() != 2 {
            return false;
        }
        let successors = self.nodes[node].successors.clone();
        for index in 0..2 {
            let second = successors[index];
            let clause = successors[1 - index];
            if second == node || clause == node || clause == second {
                continue;
            }
            // Ghidra's `if (bl->isBackEdgeOut(i)) continue;` - "Don't use loop
            // branch to get to orblock". A short-circuit condition is evaluated
            // in one pass through the code, so reaching the second test by
            // looping back is not that shape at all.

            // Ghidra's `if (bl->isBackEdgeOut(i)) continue;` - "Don't use loop
            // branch to get to orblock". A short-circuit condition is evaluated
            // in one pass through the code, so reaching the second test by
            // looping back is not that shape at all.
            if self.nodes[second].entry <= self.nodes[node].entry {
                continue;
            }
            // Ghidra's `if (orblock->isInteriorGotoTarget()) continue;`.

            // Ghidra's `if (orblock->isInteriorGotoTarget()) continue;`.
            if self.is_interior_goto_target(second) {
                continue;
            }
            // Nothing else may reach the second test, or it is a join rather
            // than the tail of one condition.
            if self.nodes[second].predecessors.len() != 1 {
                continue;
            }
            if self.nodes[second].successors.len() != 2 {
                continue;
            }
            // Ghidra's `if (orblock->isComplex()) continue;`. The second arm's
            // body would run unconditionally once the two are concatenated.
            if self.is_complex(self.nodes[second].exit, 2) {
                continue;
            }
            if !self.nodes[second].successors.contains(&clause) {
                continue;
            }
            let other = self.nodes[second]
                .successors
                .iter()
                .copied()
                .find(|candidate| *candidate != clause);
            let Some(other) = other else { continue };
            if other == node {
                continue;
            }
            let Some(first_to_clause) = self.condition_toward(node, clause) else {
                continue;
            };
            let Some(second_to_clause) = self.condition_toward(second, clause) else {
                continue;
            };
            let combined = Condition::Or(Box::new(first_to_clause), Box::new(second_to_clause));
            self.nodes[second].collapsed = true;
            let body = Structured::List(vec![
                self.nodes[node].body.clone(),
                self.nodes[second].body.clone(),
            ]);
            // The composite tests both blocks, and reaches the clause first.
            self.nodes[node].body = body;
            self.nodes[node].test = Some(combined);
            self.nodes[node].exit = self.nodes[second].exit;
            self.nodes[node].successors = vec![clause, other];
            for successor in [clause, other] {
                let predecessors = &mut self.nodes[successor].predecessors;
                predecessors.retain(|predecessor| *predecessor != node && *predecessor != second);
                predecessors.push(node);
            }
            return true;
        }
        false
    }

    /// A clause that leaves the function needs no join to be an `if`.
    ///
    /// Ghidra's `ruleBlockIfNoExit`. A guard clause that returns has no
    /// successor at all, so the rule that requires both arms to rejoin cannot
    /// see it, and the region stays a `goto`.
    fn rule_block_if_return(&mut self, node: NodeId) -> bool {
        if self.nodes[node].successors.len() != 2 {
            return false;
        }
        let successors = self.nodes[node].successors.clone();
        for index in 0..2 {
            let clause = successors[index];
            if clause == node {
                continue;
            }
            if self.nodes[clause].predecessors.len() != 1 {
                continue;
            }
            if !self.nodes[clause].successors.is_empty() {
                continue;
            }
            let body = Structured::IfElse {
                header: Box::new(self.nodes[node].body.clone()),
                test: self.condition_for(node),
                taken_first: index == 0,
                then_body: Box::new(self.nodes[clause].body.clone()),
                else_body: None,
            };
            self.absorb_keeping_exits(node, &[clause], body);
            return true;
        }
        false
    }

    /// The edge `TraceDAG` judges least structurable, if it finds one.
    ///
    /// Ghidra generates its likely-unstructured edges by tracing every path out
    /// of every branch point and scoring the traces that get stuck against each
    /// other, rather than by scoring one edge at a time. The local heuristic
    /// below cannot see that a join reached by three structured paths is fine
    /// while a cross edge between two arms is not, because from one edge's point
    /// of view they look the same.
    fn traced_goto_edge(&self, live: &[NodeId]) -> Option<(NodeId, usize)> {
        // A back edge is not part of the DAG, and neither is an edge whose
        // target has already been collapsed away.
        let back_edge = |node: NodeId, index: usize| -> bool {
            self.nodes[node]
                .successors
                .get(index)
                .is_some_and(|successor| self.nodes[*successor].entry <= self.nodes[node].entry)
        };
        let successors: Vec<Vec<NodeId>> = (0..self.nodes.len())
            .map(|node| {
                if self.nodes[node].collapsed {
                    Vec::new()
                } else {
                    self.nodes[node].successors.clone()
                }
            })
            .collect();
        let dag_out = |node: NodeId, index: usize| !back_edge(node, index);
        let dag_in_count = |node: NodeId| {
            (0..self.nodes.len())
                .filter(|from| !self.nodes[*from].collapsed)
                .flat_map(|from| {
                    self.nodes[from]
                        .successors
                        .iter()
                        .copied()
                        .enumerate()
                        .map(move |(index, to)| (from, index, to))
                })
                .filter(|(from, index, to)| *to == node && !back_edge(*from, *index))
                .count()
        };
        let roots: Vec<NodeId> = self
            .entry
            .filter(|entry| !self.nodes[*entry].collapsed)
            .map(|entry| vec![entry])
            .unwrap_or_else(|| live.first().copied().into_iter().collect());
        let edges = tracedag::TraceDag::new(tracedag::Dag {
            successors: &successors,
            dag_out: &dag_out,
            dag_in_count: &dag_in_count,
            roots: &roots,
            finish: None,
        })
        .run();
        // The first edge the trace gave up is the one it scored worst.
        edges.into_iter().find_map(|edge| {
            let index = self.nodes[edge.bottom]
                .successors
                .iter()
                .position(|successor| *successor == edge.dest)?;
            (!self.nodes[edge.bottom].collapsed).then_some((edge.bottom, index))
        })
    }

    /// Whether this node's outgoing branch is an indirect multi-way one.
    ///
    /// Ghidra's `FlowBlock::isSwitchOut`, which is set when jump-table recovery
    /// claimed the block's `BRANCHIND`.
    fn is_switch_out(&self, node: NodeId) -> bool {
        if self.nodes[node].switch_resolved {
            return false;
        }
        let block = self.nodes[node].exit;
        self.data
            .block(block)
            .ops
            .last()
            .copied()
            .is_some_and(|last| self.data.op(last).opcode == op::BRANCHIND)
    }

    /// A multi-way branch whose cases each fall to one block after the switch.
    ///
    /// Ghidra's `ruleBlockSwitch`. Every other rule here requires a two-way
    /// branch, so without this an indirect branch is a node no construct can
    /// claim and each of its edges becomes a `goto`.
    fn rule_block_switch(&mut self, node: NodeId) -> bool {
        if !self.is_switch_out(node) {
            return false;
        }
        let successors = self.nodes[node].successors.clone();
        if successors.len() < 2 {
            return false;
        }
        // The "obvious" exit: a case target that loops back to the switch, or
        // that several paths reach, or that itself branches.
        let mut exit = None;
        for successor in successors.iter().copied() {
            if successor == node
                || self.nodes[successor].successors.len() > 1
                || self.nodes[successor].predecessors.len() > 1
            {
                exit = Some(successor);
                break;
            }
        }
        match exit {
            None => {
                // Every case target has one predecessor and at most one
                // successor, so the first successor any of them has is the exit.
                for successor in successors.iter().copied() {
                    if self.is_switch_out(successor) {
                        return false; // A nested switch resolves first.
                    }
                    if self.nodes[successor].successors.len() == 1 {
                        let candidate = self.nodes[successor].successors[0];
                        match exit {
                            Some(known) if known != candidate => return false,
                            _ => exit = Some(candidate),
                        }
                    }
                }
            }
            Some(exit) => {
                for successor in successors.iter().copied() {
                    if successor == exit {
                        continue; // The switch may go straight to the exit.
                    }
                    // A case can only be entered by falling into it from the
                    // switch, and may leave only to the exit.
                    if self.nodes[successor].predecessors.len() > 1
                        || self.nodes[successor].successors.len() > 1
                        || self.is_switch_out(successor)
                    {
                        return false;
                    }
                    if self.nodes[successor].successors.len() == 1
                        && self.nodes[successor].successors[0] != exit
                    {
                        return false;
                    }
                }
            }
        }
        let cases: Vec<NodeId> = successors
            .iter()
            .copied()
            .filter(|successor| Some(*successor) != exit)
            .collect();
        if cases.is_empty() {
            return false;
        }
        // Only a recovered table can name the cases. Without one the branch
        // keeps its edges and each becomes a `goto`, because printing
        // alternatives as an unlabelled sequence would say they run in turn.
        let block = self.nodes[node].exit;
        let Some(table) = self.tables.iter().find(|table| {
            self.data
                .block(block)
                .ops
                .iter()
                .any(|candidate| *candidate == table.branch)
        }) else {
            return false;
        };
        let labelled: Vec<(Option<u64>, Structured)> = cases
            .iter()
            .copied()
            .map(|case| {
                let start = self.data.block(self.nodes[case].entry).start;
                let label = table
                    .cases
                    .iter()
                    .find(|(_, target)| *target == start)
                    .map(|(label, _)| *label);
                (label, self.nodes[case].body.clone())
            })
            .collect();
        // Every case but the default must carry a label, or the construct would
        // claim a case the table does not describe.
        if labelled.iter().filter(|(label, _)| label.is_none()).count() > 1 {
            return false;
        }
        let body = Structured::Switch {
            header: Box::new(self.nodes[node].body.clone()),
            selector: table.switch_value,
            cases: labelled,
            has_exit: exit.is_some(),
        };
        self.absorb(node, &cases, body);
        // The composite is no longer a multi-way branch, so the rules that
        // defer to `ruleBlockSwitch` may claim it now.
        self.nodes[node].switch_resolved = true;
        true
    }

    /// A switch case that falls through into another case.
    ///
    /// Ghidra's `ruleCaseFallthru`. C reaches a fallthrough case by omitting the
    /// `break`, but this construct tree has no way to say "continue into the next
    /// case", so the edge is surrendered as a `goto` and `ruleBlockSwitch` can
    /// then claim the rest. A case qualifies when its single successor is reached
    /// by exactly two edges — its own and the switch's — which is what makes the
    /// successor another case rather than the exit.
    fn rule_case_fallthru(&mut self, node: NodeId) -> bool {
        if !self.is_switch_out(node) {
            return false;
        }
        let successors = self.nodes[node].successors.clone();
        let mut nonfallthru = 0usize;
        let mut fallthru: Vec<NodeId> = Vec::new();
        for successor in successors.iter().copied() {
            if successor == node {
                return false; // A switch cannot fall through to itself.
            }
            if self.nodes[successor].predecessors.len() > 2
                || self.nodes[successor].successors.len() > 1
            {
                nonfallthru += 1;
            } else if self.nodes[successor].successors.len() == 1 {
                let target = self.nodes[successor].successors[0];
                if self.nodes[target].predecessors.len() == 2
                    && self.nodes[target].successors.len() <= 1
                    && self.nodes[target]
                        .predecessors
                        .iter()
                        .any(|predecessor| *predecessor == node)
                {
                    fallthru.push(successor);
                }
            }
            if nonfallthru > 1 {
                return false; // At most one exit that is not a fallthrough.
            }
        }
        let Some(case) = fallthru.first().copied() else {
            return false;
        };
        let target = self.nodes[case].successors[0];
        self.surrender_edge(case, target);
        true
    }

    /// Surrenders one edge as a `goto` so collapsing can continue.
    ///
    /// The edge chosen is a back edge if there is one, because a loop that no
    /// loop rule matched is what blocks progress most often.
    fn rule_goto(&mut self, live: &[NodeId]) -> bool {
        // Prefer the edge whose removal unblocks the other rules while
        // destroying the least structure. Every rule requires its clause to
        // have exactly one predecessor, so an edge into a block several paths
        // reach is what stalls the collapse.
        //
        // A back edge is the last thing to give up. Ghidra never surrenders
        // one: `markExitsAsGotos` marks the edges *leaving* a loop, because the
        // back edge is the loop. Scoring it highest — as this did — hands the
        // loop to a goto and no later rule can recover it.
        // Ask the trace first. It only answers when it found an edge it can
        // justify; the scoring heuristic below remains the fallback.
        let mut choice: Option<(NodeId, usize, u32)> = None;
        if let Some((node, index)) = self.traced_goto_edge(live) {
            choice = Some((node, index, u32::MAX));
        }
        for node in live.iter().copied() {
            if choice.is_some_and(|(_, _, best)| best == u32::MAX) {
                break;
            }
            for (index, successor) in self.nodes[node].successors.iter().copied().enumerate() {
                if self.nodes[node].successors.len() == 1 && successor == node {
                    continue;
                }
                let joins = self.nodes[successor].predecessors.len() > 1;
                let back = self.nodes[successor].entry <= self.nodes[node].entry;
                let score = u32::from(!back) * 4 + u32::from(joins) * 2;
                if choice.is_none_or(|(_, _, best)| score > best) {
                    choice = Some((node, index, score));
                }
            }
        }
        let choice = choice.map(|(node, index, _)| (node, index));
        let Some((node, index)) = choice else {
            return false;
        };
        let branching = self.nodes[node].successors.len() == 2;
        let successor = self.nodes[node].successors.remove(index);
        self.nodes[successor]
            .predecessors
            .retain(|predecessor| *predecessor != node);
        let jump = if branching {
            Structured::IfGoto {
                test: self.condition_for(node),
                taken: index == 0,
                target: self.nodes[successor].entry,
            }
        } else {
            Structured::Goto {
                from: self.nodes[node].exit,
                target: self.nodes[successor].entry,
            }
        };
        self.nodes[node].body = Structured::List(vec![self.nodes[node].body.clone(), jump]);
        true
    }

    /// Replaces `node` and `absorbed` with one node carrying `body`.
    fn absorb(&mut self, node: NodeId, absorbed: &[NodeId], body: Structured) {
        // An absorbed member's edge back to the composite is the loop's back
        // edge. `newBlockList` keeps it, and it must be kept here: dropping it
        // turns the loop into straight-line code that no loop rule can
        // recognise afterwards.
        let mut successors: Vec<NodeId> = Vec::new();
        for member in absorbed.iter().copied() {
            for successor in self.nodes[member].successors.clone() {
                if absorbed.contains(&successor) || successors.contains(&successor) {
                    continue;
                }
                successors.push(successor);
            }
        }
        for member in absorbed.iter().copied() {
            self.nodes[member].collapsed = true;
        }
        for successor in successors.clone() {
            let entry = &mut self.nodes[successor].predecessors;
            entry.retain(|predecessor| *predecessor != node && !absorbed.contains(predecessor));
            entry.push(node);
        }
        // A predecessor of an absorbed member now reaches the composite, so its
        // outgoing edge has to name the composite instead of the collapsed node.
        for member in absorbed.iter().copied() {
            for predecessor in self.nodes[member].predecessors.clone() {
                if predecessor == node || absorbed.contains(&predecessor) {
                    continue;
                }
                for entry in self.nodes[predecessor].successors.iter_mut() {
                    if *entry == member {
                        *entry = node;
                    }
                }
                if !self.nodes[node].predecessors.contains(&predecessor) {
                    self.nodes[node].predecessors.push(predecessor);
                }
            }
        }
        self.nodes[node].successors = successors;
        self.nodes[node].body = body;
    }

    /// As [`Self::absorb`], keeping the composite's own edges out.
    ///
    /// `rule_block_if_return` absorbs a clause that returns, so that clause
    /// contributes no external successor and the union of the members' exits is
    /// empty. Replacing the composite's successors with it dropped the head's
    /// other path, turning a live edge into a dead end that no later loop rule
    /// could recognise.
    fn absorb_keeping_exits(&mut self, node: NodeId, absorbed: &[NodeId], body: Structured) {
        let own: Vec<NodeId> = self.nodes[node].successors.clone();
        self.absorb(node, absorbed, body);
        for successor in own {
            if successor == node
                || absorbed.contains(&successor)
                || self.nodes[node].successors.contains(&successor)
            {
                continue;
            }
            self.nodes[node].successors.push(successor);
            let entry = &mut self.nodes[successor].predecessors;
            if !entry.contains(&node) {
                entry.push(node);
            }
        }
    }

    fn finish(self) -> Structured {
        let live: Vec<&Node> = self.nodes.iter().filter(|node| !node.collapsed).collect();
        let mut members: Vec<Structured> = if live.len() == 1 {
            // Fully structured, but still not necessarily complete: a rule that
            // absorbs a node whose body another composite already owns drops
            // blocks out of the tree, and the completeness guard below is the
            // only thing that notices. `__FrameCallback__Fl` lost the block
            // holding its `return`, so the function read as void and three
            // surviving jumps named labels that were never emitted.
            vec![live[0].body.clone()]
        } else {
            // Not fully structured: emit the remaining nodes in address order,
            // with whatever gotos the collapse left in them.
            let mut remaining: Vec<(GraphBlockId, Structured)> = self
                .nodes
                .iter()
                .enumerate()
                .filter(|(_, node)| !node.collapsed)
                .map(|(index, node)| {
                    let first = if Some(index) == self.entry {
                        GraphBlockId(0)
                    } else {
                        node.entry
                    };
                    (first, node.body.clone())
                })
                .collect();
            remaining.sort_by_key(|(entry, _)| self.data.block(*entry).start);
            remaining.into_iter().map(|(_, body)| body).collect()
        };

        // Every live block must appear exactly once. A rule that absorbs a node
        // whose body another composite already owns, or that leaves a stale
        // edge, can otherwise drop a block from the tree entirely — which reads
        // as a function that simply stops, with the rest of its body silently
        // missing. Recovering the block as its own region keeps the output
        // honest: unstructured, but complete.
        let mut present: BTreeSet<GraphBlockId> = BTreeSet::new();
        for member in &members {
            collect_blocks(member, &mut present);
        }
        let mut missing: Vec<GraphBlockId> = self
            .data
            .blocks()
            .map(|(id, _)| id)
            .filter(|id| !present.contains(id))
            .collect();
        missing.sort_by_key(|id| self.data.block(*id).start);
        if missing.is_empty() && members.len() == 1 {
            return members.remove(0);
        }
        members.extend(missing.into_iter().map(Structured::Basic));
        let _ = &self.of_block;
        Structured::List(members)
    }
}

/// Removes jumps to `head` from inside a loop body.
///
/// A surrendered back edge and a recovered loop say the same thing. Keeping both
/// leaves a jump in the middle of the body that contradicts the construct
/// wrapped around it.
/// Whether a recovered construct contains a jump to the given block.
fn body_jumps_to(node: &Structured, target: GraphBlockId) -> bool {
    match node {
        Structured::Goto { target: named, .. } | Structured::IfGoto { target: named, .. } => {
            *named == target
        }
        Structured::List(members) => members.iter().any(|member| body_jumps_to(member, target)),
        Structured::IfElse {
            header,
            then_body,
            else_body,
            ..
        } => {
            body_jumps_to(header, target)
                || body_jumps_to(then_body, target)
                || else_body
                    .as_ref()
                    .is_some_and(|body| body_jumps_to(body, target))
        }
        Structured::WhileDo { header, body, .. } => {
            body_jumps_to(header, target) || body_jumps_to(body, target)
        }
        Structured::DoWhile { body, .. } | Structured::InfLoop { body } => {
            body_jumps_to(body, target)
        }
        Structured::Switch { header, cases, .. } => {
            body_jumps_to(header, target)
                || cases.iter().any(|(_, case)| body_jumps_to(case, target))
        }
        Structured::Basic(_) | Structured::Break | Structured::IfBreak { .. } => false,
    }
}

fn drop_jumps_to(node: &mut Structured, head: GraphBlockId) {
    match node {
        Structured::List(members) => {
            members.retain(|member| {
                !matches!(
                    member,
                    Structured::Goto { target, .. } | Structured::IfGoto { target, .. }
                        if *target == head
                )
            });
            for member in members.iter_mut() {
                drop_jumps_to(member, head);
            }
        }
        Structured::IfElse {
            header,
            then_body,
            else_body,
            ..
        } => {
            drop_jumps_to(header, head);
            drop_jumps_to(then_body, head);
            if let Some(body) = else_body {
                drop_jumps_to(body, head);
            }
        }
        Structured::WhileDo { header, body, .. } => {
            drop_jumps_to(header, head);
            drop_jumps_to(body, head);
        }
        Structured::DoWhile { body, .. } | Structured::InfLoop { body } => {
            drop_jumps_to(body, head)
        }
        Structured::Switch { header, cases, .. } => {
            drop_jumps_to(header, head);
            for (_, case) in cases.iter_mut() {
                drop_jumps_to(case, head);
            }
        }
        Structured::Basic(_)
        | Structured::Goto { .. }
        | Structured::IfGoto { .. }
        | Structured::Break
        | Structured::IfBreak { .. } => {}
    }
}

/// Every basic block a construct tree mentions.
pub(super) fn collect_blocks(node: &Structured, into: &mut BTreeSet<GraphBlockId>) {
    match node {
        Structured::Basic(block) => {
            into.insert(*block);
        }
        Structured::List(members) => {
            for member in members {
                collect_blocks(member, into);
            }
        }
        Structured::IfElse {
            header,
            then_body,
            else_body,
            ..
        } => {
            collect_blocks(header, into);
            collect_blocks(then_body, into);
            if let Some(body) = else_body {
                collect_blocks(body, into);
            }
        }
        Structured::WhileDo { header, body, .. } => {
            collect_blocks(header, into);
            collect_blocks(body, into);
        }
        Structured::DoWhile { body, .. } | Structured::InfLoop { body } => {
            collect_blocks(body, into)
        }
        Structured::Switch { header, cases, .. } => {
            collect_blocks(header, into);
            for (_, case) in cases {
                collect_blocks(case, into);
            }
        }
        Structured::Break | Structured::IfBreak { .. } => {}
        Structured::Goto { .. } | Structured::IfGoto { .. } => {}
    }
}

/// Whether one block dominates another, by walking the dominator tree upward.
fn dominates(
    dominance: &super::heritage::Dominance,
    ancestor: GraphBlockId,
    mut candidate: GraphBlockId,
) -> bool {
    loop {
        if candidate == ancestor {
            return true;
        }
        match dominance.immediate.get(&candidate).copied().flatten() {
            Some(parent) if parent != candidate => candidate = parent,
            _ => return false,
        }
    }
}

/// The condition that holds exactly when the given one does not.
///
/// Negation is pushed into the leaf so a combined test stays a tree of `&&` and
/// `||` over branch conditions, which is what De Morgan's laws give and what C
/// can spell without a temporary.
/// Ghidra's `PcodeOp::isMarker`: a phi or an indirect effect, neither of which
/// is a printed statement.
fn is_marker_opcode(opcode: i32) -> bool {
    matches!(opcode, op::MULTIEQUAL | op::INDIRECT)
}

fn is_call_opcode(opcode: i32) -> bool {
    matches!(opcode, op::CALL | op::CALLIND | op::CALLOTHER)
}

/// Ghidra's `PcodeOp::isFlowBreak`: a transfer, which is not counted as a
/// statement on top of the branch already counted.
fn is_flow_break_opcode(opcode: i32) -> bool {
    matches!(
        opcode,
        op::BRANCH | op::CBRANCH | op::BRANCHIND | op::RETURN
    )
}

fn negate(condition: Condition) -> Condition {
    match condition {
        Condition::Branch { block, taken } => Condition::Branch {
            block,
            taken: !taken,
        },
        Condition::Or(left, right) => {
            Condition::And(Box::new(negate(*left)), Box::new(negate(*right)))
        }
        Condition::And(left, right) => {
            Condition::Or(Box::new(negate(*left)), Box::new(negate(*right)))
        }
    }
}

/// The block a conditional branch jumps to when its condition holds.
fn taken_successor(data: &Funcdata, block: GraphBlockId) -> Option<GraphBlockId> {
    let terminator = data.block(block).ops.last().copied()?;
    let operation = data.op(terminator);
    if operation.opcode != op::CBRANCH {
        return None;
    }
    let target = operation.inputs.first().copied()?;
    if data.varnode(target).space == ventris_lifter::CONST_SPACE {
        // A branch within one instruction: the destination is a p-code index
        // relative to the branching operation, so the taken block is the one
        // starting at that operation of the same instruction.
        let seq = data.op(terminator).seq;
        let relative = data.varnode(target).offset as i64;
        let order = u32::try_from(i64::from(seq.order).checked_add(relative)?).ok()?;
        return data
            .blocks()
            .find(|(_, candidate)| candidate.start == seq.address && candidate.start_order == order)
            .map(|(id, _)| id);
    }
    let address = data.varnode(target).offset;
    data.blocks()
        // An instruction split into several blocks has one at order zero; a
        // machine branch always arrives there.
        .find(|(_, candidate)| candidate.start == address && candidate.start_order == 0)
        .map(|(id, _)| id)
}

impl Graph<'_> {
    /// Position of a self edge, if the node loops directly to itself.
    fn self_edge(&self, node: NodeId) -> Option<usize> {
        self.nodes[node]
            .successors
            .iter()
            .position(|successor| *successor == node)
    }
}

#[cfg(test)]
mod tests {
    use ventris_lifter::REGISTER_SPACE;

    use super::*;
    use crate::graph::SeqNum;

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    /// A block ending in a conditional branch to `target`.
    fn conditional(data: &mut Funcdata, block: GraphBlockId, target: u64) {
        let start = data.block(block).start;
        let address = data.new_varnode(ventris_lifter::RAM_SPACE, target, 4);
        let condition = data.new_unique(1);
        let branch = data.new_op(op::CBRANCH, seq(start), vec![address, condition]);
        data.op_insert_end(branch, block);
    }

    #[test]
    fn a_chain_of_blocks_becomes_a_list() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let first = data.new_block(0x1000);
        let second = data.new_block(0x1010);
        let third = data.new_block(0x1020);
        data.add_edge(first, second);
        data.add_edge(second, third);

        let structured = structure(&data, &[]);
        let Structured::List(members) = &structured else {
            panic!("expected a list, got {structured:?}");
        };
        assert!(
            members.len() >= 2,
            "the chain collapsed into one construct: {structured:?}"
        );
    }

    #[test]
    fn a_diamond_becomes_an_if_else() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let head = data.new_block(0x1000);
        let taken = data.new_block(0x1010);
        let fallthrough = data.new_block(0x1020);
        let join = data.new_block(0x1030);
        conditional(&mut data, head, 0x1010);
        data.add_edge(head, taken);
        data.add_edge(head, fallthrough);
        data.add_edge(taken, join);
        data.add_edge(fallthrough, join);

        let structured = structure(&data, &[]);
        assert!(
            contains_if_else(&structured, true),
            "expected an if/else with both clauses: {structured:?}"
        );
    }

    #[test]
    fn a_branch_over_one_clause_becomes_an_if_without_else() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let head = data.new_block(0x1000);
        let clause = data.new_block(0x1010);
        let after = data.new_block(0x1020);
        conditional(&mut data, head, 0x1020);
        data.add_edge(head, after);
        data.add_edge(head, clause);
        data.add_edge(clause, after);

        let structured = structure(&data, &[]);
        assert!(
            contains_if_else(&structured, false),
            "expected an if with no else: {structured:?}"
        );
    }

    #[test]
    fn a_test_before_a_body_becomes_a_while() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let head = data.new_block(0x1000);
        let body = data.new_block(0x1010);
        let after = data.new_block(0x1020);
        conditional(&mut data, head, 0x1010);
        data.add_edge(head, body);
        data.add_edge(head, after);
        data.add_edge(body, head);

        let structured = structure(&data, &[]);
        assert!(
            contains(&structured, &|node| matches!(
                node,
                Structured::WhileDo { .. }
            )),
            "expected a while loop: {structured:?}"
        );
    }

    #[test]
    fn a_self_looping_block_becomes_a_do_while() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let head = data.new_block(0x1000);
        let after = data.new_block(0x1010);
        conditional(&mut data, head, 0x1000);
        data.add_edge(head, head);
        data.add_edge(head, after);

        let structured = structure(&data, &[]);
        assert!(
            contains(&structured, &|node| matches!(
                node,
                Structured::DoWhile { .. }
            )),
            "expected a do/while loop: {structured:?}"
        );
    }

    #[test]
    fn irreducible_flow_keeps_a_goto_rather_than_inventing_a_construct() {
        // Two entries into one loop body cannot be expressed with structured
        // control flow, so at least one edge must remain a goto.
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let head = data.new_block(0x1000);
        let left = data.new_block(0x1010);
        let right = data.new_block(0x1020);
        conditional(&mut data, head, 0x1010);
        data.add_edge(head, left);
        data.add_edge(head, right);
        data.add_edge(left, right);
        data.add_edge(right, left);

        let structured = structure(&data, &[]);
        // The surrendered edge may be conditional or unconditional depending on
        // which one the collapse gives up; either is an unstructured transfer.
        assert!(
            contains(&structured, &|node| matches!(
                node,
                Structured::Goto { .. } | Structured::IfGoto { .. }
            )),
            "expected an unstructured transfer for the irreducible edge: {structured:?}"
        );
    }

    #[test]
    fn two_tests_reaching_one_clause_become_a_short_circuit_condition() {
        // `if (a || b) clause;` compiles to two conditional branches to the
        // same target. Without recognising that, the second test stays its own
        // region and the whole thing degenerates to goto.
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let first = data.new_block(0x1000);
        let second = data.new_block(0x1010);
        let clause = data.new_block(0x1020);
        let after = data.new_block(0x1030);
        conditional(&mut data, first, 0x1020);
        data.add_edge(first, clause);
        data.add_edge(first, second);
        conditional(&mut data, second, 0x1020);
        data.add_edge(second, clause);
        data.add_edge(second, after);
        data.add_edge(clause, after);

        let structured = structure(&data, &[]);
        assert!(
            contains(&structured, &|node| matches!(
                node,
                Structured::IfElse {
                    test: Condition::Or(..),
                    ..
                }
            )),
            "expected a short-circuit condition: {structured:?}"
        );
    }

    #[test]
    fn a_single_test_keeps_a_plain_condition() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let head = data.new_block(0x1000);
        let clause = data.new_block(0x1010);
        let after = data.new_block(0x1020);
        conditional(&mut data, head, 0x1010);
        data.add_edge(head, clause);
        data.add_edge(head, after);
        data.add_edge(clause, after);

        let structured = structure(&data, &[]);
        assert!(
            !contains(&structured, &|node| matches!(
                node,
                Structured::IfElse {
                    test: Condition::Or(..) | Condition::And(..),
                    ..
                }
            )),
            "one test is not a short circuit: {structured:?}"
        );
    }

    #[test]
    fn a_block_looping_only_to_itself_is_an_infinite_loop() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let entry = data.new_block(0x1000);
        let spin = data.new_block(0x1010);
        data.add_edge(entry, spin);
        data.add_edge(spin, spin);

        let structured = structure(&data, &[]);
        assert!(
            contains(&structured, &|node| matches!(
                node,
                Structured::InfLoop { .. }
            )),
            "expected an infinite loop: {structured:?}"
        );
    }

    #[test]
    fn a_guard_clause_that_returns_becomes_an_if_without_else() {
        // The clause has no successor at all, so the rule requiring both arms
        // to rejoin cannot see it.
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let head = data.new_block(0x1000);
        let bail = data.new_block(0x1010);
        let rest = data.new_block(0x1020);
        conditional(&mut data, head, 0x1010);
        data.add_edge(head, bail);
        data.add_edge(head, rest);
        let link = data.new_varnode(ventris_lifter::REGISTER_SPACE, 0x1f0, 8);
        let ret = data.new_op(op::RETURN, seq(0x1010), vec![link]);
        data.op_insert_end(ret, bail);

        let structured = structure(&data, &[]);
        assert!(
            contains(&structured, &|node| matches!(
                node,
                Structured::IfElse {
                    else_body: None,
                    ..
                }
            )),
            "expected an if with no else: {structured:?}"
        );
    }

    #[test]
    fn negating_a_short_circuit_applies_de_morgan() {
        let base = Condition::Or(
            Box::new(Condition::Branch {
                block: GraphBlockId(0),
                taken: true,
            }),
            Box::new(Condition::Branch {
                block: GraphBlockId(1),
                taken: false,
            }),
        );
        assert_eq!(
            negate(base),
            Condition::And(
                Box::new(Condition::Branch {
                    block: GraphBlockId(0),
                    taken: false
                }),
                Box::new(Condition::Branch {
                    block: GraphBlockId(1),
                    taken: true
                }),
            )
        );
    }

    fn contains(node: &Structured, predicate: &dyn Fn(&Structured) -> bool) -> bool {
        if predicate(node) {
            return true;
        }
        match node {
            Structured::List(members) => members.iter().any(|member| contains(member, predicate)),
            Structured::IfElse {
                header,
                then_body,
                else_body,
                ..
            } => {
                contains(header, predicate)
                    || contains(then_body, predicate)
                    || else_body
                        .as_ref()
                        .is_some_and(|body| contains(body, predicate))
            }
            Structured::WhileDo { header, body, .. } => {
                contains(header, predicate) || contains(body, predicate)
            }
            Structured::DoWhile { body, .. } | Structured::InfLoop { body } => {
                contains(body, predicate)
            }
            Structured::Switch { header, cases, .. } => {
                contains(header, predicate)
                    || cases.iter().any(|(_, case)| contains(case, predicate))
            }
            Structured::Basic(_)
            | Structured::Goto { .. }
            | Structured::IfGoto { .. }
            | Structured::Break
            | Structured::IfBreak { .. } => false,
        }
    }

    fn contains_if_else(node: &Structured, with_else: bool) -> bool {
        contains(node, &|candidate| {
            matches!(
                candidate,
                Structured::IfElse { else_body, .. } if else_body.is_some() == with_else
            )
        })
    }
    #[test]
    fn a_multi_way_branch_with_a_table_becomes_a_switch() {
        // Every other rule here requires a two-way branch, so without
        // `ruleBlockSwitch` an indirect branch is a node no construct claims and
        // each of its edges leaves as a `goto`.
        let mut data = Funcdata::default();
        let head = data.new_block(0x1000);
        let case_a = data.new_block(0x1010);
        let case_b = data.new_block(0x1020);
        let join = data.new_block(0x1030);
        for (from, to) in [
            (head, case_a),
            (head, case_b),
            (case_a, join),
            (case_b, join),
        ] {
            data.add_edge(from, to);
        }
        let selector = data.new_varnode(REGISTER_SPACE, 0x10, 4);
        data.mark_input(selector);
        let branch = data.new_op(op::BRANCHIND, seq(0x1000), vec![selector]);
        data.op_insert_end(branch, head);

        let table = super::super::jumptable::JumpTable {
            branch,
            switch_value: selector,
            cases: vec![(0, 0x1010), (1, 0x1020)],
            default_target: None,
        };
        let structured = structure(&data, std::slice::from_ref(&table));
        assert!(
            contains(&structured, &|node| matches!(
                node,
                Structured::Switch { .. }
            )),
            "expected a switch construct, got {structured:?}"
        );
        assert!(
            !contains(&structured, &|node| matches!(
                node,
                Structured::Goto { .. } | Structured::IfGoto { .. }
            )),
            "a fully structured switch needs no goto: {structured:?}"
        );
    }

    #[test]
    fn a_case_falling_into_another_case_surrenders_that_edge() {
        // `case_a` runs on and into `case_b` rather than leaving to the exit.
        // `case_b` therefore has two predecessors, which makes it the switch's
        // exit block, and the whole shape structures with no `goto` at all: the
        // one labelled case breaks out to `case_b`, and a selector reaching
        // `case_b` directly arrives at the same place. `ruleCaseFallthru` is
        // offered after `ruleBlockSwitch` for exactly this reason — it only has
        // to surrender an edge when the switch rule cannot claim the shape.
        let mut data = Funcdata::default();
        let head = data.new_block(0x1000);
        let case_a = data.new_block(0x1010);
        let case_b = data.new_block(0x1020);
        let join = data.new_block(0x1030);
        for (from, to) in [
            (head, case_a),
            (head, case_b),
            (case_a, case_b),
            (case_b, join),
        ] {
            data.add_edge(from, to);
        }
        let selector = data.new_varnode(REGISTER_SPACE, 0x10, 4);
        data.mark_input(selector);
        let branch = data.new_op(op::BRANCHIND, seq(0x1000), vec![selector]);
        data.op_insert_end(branch, head);

        let table = super::super::jumptable::JumpTable {
            branch,
            switch_value: selector,
            cases: vec![(0, 0x1010), (1, 0x1020)],
            default_target: None,
        };
        let structured = structure(&data, std::slice::from_ref(&table));
        assert!(
            contains(&structured, &|node| matches!(
                node,
                Structured::Switch { .. }
            )),
            "the switch should still be recovered: {structured:?}"
        );
        assert!(
            !contains(&structured, &|node| matches!(
                node,
                Structured::Goto { .. } | Structured::IfGoto { .. }
            )),
            "this shape structures without surrendering an edge: {structured:?}"
        );
        // The fallthrough target is the exit, so only the one case is labelled.
        let cases = collect_switch_cases(&structured);
        assert_eq!(cases, vec![Some(0)], "unexpected cases: {structured:?}");
    }

    /// Every label a recovered switch claims.
    fn collect_switch_cases(node: &Structured) -> Vec<Option<u64>> {
        let mut found = Vec::new();
        let mut pending = vec![node];
        while let Some(current) = pending.pop() {
            match current {
                Structured::Switch { header, cases, .. } => {
                    found.extend(cases.iter().map(|(label, _)| *label));
                    pending.push(header);
                    pending.extend(cases.iter().map(|(_, case)| case));
                }
                Structured::List(members) => pending.extend(members.iter()),
                Structured::IfElse {
                    header,
                    then_body,
                    else_body,
                    ..
                } => {
                    pending.push(header);
                    pending.push(then_body);
                    if let Some(body) = else_body {
                        pending.push(body);
                    }
                }
                Structured::WhileDo { header, body, .. } => {
                    pending.push(header);
                    pending.push(body);
                }
                Structured::DoWhile { body, .. } | Structured::InfLoop { body } => {
                    pending.push(body)
                }
                _ => {}
            }
        }
        found
    }

    #[test]
    fn a_multi_way_branch_without_a_table_is_not_claimed() {
        // The case labels live in the image. With no table the cases cannot be
        // named, and printing alternatives as an unlabelled sequence would say
        // they run in turn, so the branch must keep its edges.
        let mut data = Funcdata::default();
        let head = data.new_block(0x1000);
        let case_a = data.new_block(0x1010);
        let case_b = data.new_block(0x1020);
        let join = data.new_block(0x1030);
        for (from, to) in [
            (head, case_a),
            (head, case_b),
            (case_a, join),
            (case_b, join),
        ] {
            data.add_edge(from, to);
        }
        let selector = data.new_varnode(REGISTER_SPACE, 0x10, 4);
        data.mark_input(selector);
        let branch = data.new_op(op::BRANCHIND, seq(0x1000), vec![selector]);
        data.op_insert_end(branch, head);

        let structured = structure(&data, &[]);
        assert!(
            !contains(&structured, &|node| matches!(
                node,
                Structured::Switch { .. }
            )),
            "no table means no switch: {structured:?}"
        );
    }

    #[test]
    fn a_jump_to_a_loops_exit_becomes_a_break() {
        // while (..) { if (..) goto after; .. }  after: ..
        let mut tree = Structured::List(vec![
            Structured::WhileDo {
                header: Box::new(Structured::Basic(GraphBlockId(0))),
                test: Condition::Branch {
                    block: GraphBlockId(0),
                    taken: true,
                },
                body: Box::new(Structured::List(vec![
                    Structured::IfGoto {
                        test: Condition::Branch {
                            block: GraphBlockId(1),
                            taken: true,
                        },
                        taken: true,
                        target: GraphBlockId(9),
                    },
                    Structured::Basic(GraphBlockId(1)),
                ])),
                body_taken: true,
            },
            Structured::Basic(GraphBlockId(9)),
        ]);
        scope_break(&mut tree, None, None);
        let Structured::List(members) = &tree else {
            panic!("expected a list");
        };
        let Structured::WhileDo { body, .. } = &members[0] else {
            panic!("expected the loop");
        };
        let Structured::List(body) = body.as_ref() else {
            panic!("expected a body list");
        };
        assert!(
            matches!(body[0], Structured::IfBreak { .. }),
            "a jump to the block after the loop is a break, got {:?}",
            body[0]
        );

        // The same jump outside any loop stays a goto: `loop_exit` is unset.
        let mut plain = Structured::List(vec![
            Structured::IfGoto {
                test: Condition::Branch {
                    block: GraphBlockId(1),
                    taken: true,
                },
                taken: true,
                target: GraphBlockId(9),
            },
            Structured::Basic(GraphBlockId(9)),
        ]);
        scope_break(&mut plain, None, None);
        let Structured::List(members) = &plain else {
            panic!("expected a list");
        };
        assert!(
            matches!(members[0], Structured::IfGoto { .. }),
            "outside a loop the jump has no break to become"
        );
    }

    /// Ghidra refuses a short-circuit collapse when the second arm is complex,
    /// because the collapse concatenates both bodies and would otherwise run
    /// the second arm's statements unconditionally.
    #[test]
    fn a_complex_second_arm_is_not_collapsed_into_a_short_circuit() {
        let mut data = Funcdata::default();
        let busy = data.new_block(0x1000);
        for order in 0..3 {
            let call = data.new_op(
                op::CALL,
                crate::graph::SeqNum {
                    address: 0x1000,
                    order,
                },
                Vec::new(),
            );
            data.op_insert_end(call, busy);
        }
        let simple = data.new_block(0x2000);
        let left = data.new_constant(1, 4);
        let right = data.new_constant(2, 4);
        let compare = data.new_op(op::INT_LESS, seq(0x2000), vec![left, right]);
        data.op_insert_end(compare, simple);

        let graph = Graph::of(&data, &[]);
        assert!(
            graph.is_complex(busy, 2),
            "three calls are past Ghidra's two-statement ceiling"
        );
        assert!(
            !graph.is_complex(simple, 2),
            "one comparison plus the branch is exactly the ceiling"
        );
    }

    /// Ghidra requires the edges an `if` is built from to be *decision* edges -
    /// neither back edges, goto edges nor irreducible. Surrendered edges are
    /// already gone from `successors` here, so the test that remains is the back
    /// edge: an `if` built across one claims a branch where the flow is a loop.
    #[test]
    fn an_if_refuses_a_clause_reached_by_a_back_edge() {
        // Blocks in address order, as `from_lifted` creates them, because a back
        // edge is recognised by the target's identifier preceding the source's.
        let mut data = Funcdata::default();
        data.entry = 0x1010;
        let earlier = data.new_block(0x1000);
        let head = data.new_block(0x1010);
        let join = data.new_block(0x1020);
        conditional(&mut data, head, 0x1000);
        data.add_edge(head, earlier);
        data.add_edge(head, join);
        data.add_edge(earlier, join);

        let mut graph = Graph::of(&data, &[]);
        let node = graph
            .nodes
            .iter()
            .position(|candidate| candidate.entry == head)
            .expect("the head is a node");
        assert!(
            !graph.rule_if_no_exit(node),
            "the clause is reached by a back edge, so no `if` is built"
        );
    }

    /// Ghidra's `if (clauseblock->isSwitchOut()) continue;` - "Don't use switch
    /// (possibly with goto edges)". Only the head was checked here, so a clause
    /// that itself ends in a computed jump could be absorbed into an `if` body,
    /// hiding the multi-way branch.
    #[test]
    fn an_if_refuses_a_clause_that_ends_in_a_computed_jump() {
        let build = |computed: bool| {
            let mut data = Funcdata::default();
            data.entry = 0x1000;
            let head = data.new_block(0x1000);
            let clause = data.new_block(0x1010);
            let join = data.new_block(0x1020);
            conditional(&mut data, head, 0x1010);
            data.add_edge(head, clause);
            data.add_edge(head, join);
            data.add_edge(clause, join);
            if computed {
                let target = data.new_varnode(ventris_lifter::REGISTER_SPACE, 12, 4);
                let branch = data.new_op(op::BRANCHIND, seq(0x1010), vec![target]);
                data.op_insert_end(branch, clause);
            }
            data
        };

        let plain = build(false);
        let mut graph = Graph::of(&plain, &[]);
        let node = graph
            .nodes
            .iter()
            .position(|candidate| candidate.entry == GraphBlockId(0))
            .expect("the head is a node");
        assert!(
            graph.rule_if_no_exit(node),
            "an ordinary clause is absorbed as an if body"
        );

        let switched = build(true);
        let mut graph = Graph::of(&switched, &[]);
        let node = graph
            .nodes
            .iter()
            .position(|candidate| candidate.entry == GraphBlockId(0))
            .expect("the head is a node");
        assert!(
            !graph.rule_if_no_exit(node),
            "a clause ending in a computed jump is left for the switch rule"
        );
    }

    /// A block an unstructured jump enters is not the tail of one condition:
    /// control can arrive there without evaluating the first test, so folding the
    /// two into `||` would claim an evaluation order that does not hold. This is
    /// Ghidra's `if (orblock->isInteriorGotoTarget()) continue;`.
    #[test]
    fn a_short_circuit_refuses_a_second_test_a_goto_enters() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let head = data.new_block(0x1000);
        let second = data.new_block(0x1010);
        let clause = data.new_block(0x1020);
        let other = data.new_block(0x1030);
        let elsewhere = data.new_block(0x1040);
        conditional(&mut data, head, 0x1010);
        data.add_edge(head, second);
        data.add_edge(head, clause);
        conditional(&mut data, second, 0x1020);
        data.add_edge(second, clause);
        data.add_edge(second, other);

        let mut graph = Graph::of(&data, &[]);
        let node = |entry: GraphBlockId| {
            graph
                .nodes
                .iter()
                .position(|candidate| candidate.entry == entry)
                .expect("the block is a node")
        };
        let head_node = node(head);
        let second_node = node(second);
        // Without a jump into it the merge is available.
        let mut permissive = Graph::of(&data, &[]);
        assert!(
            permissive.rule_block_or(head_node),
            "the shape itself is mergeable"
        );

        // Now a live body jumps straight into the second test.
        let jumped = node(elsewhere);
        graph.nodes[jumped].body = Structured::Goto {
            from: graph.nodes[jumped].entry,
            target: graph.nodes[second_node].entry,
        };
        assert!(
            !graph.rule_block_or(head_node),
            "a jump enters the second test, so no condition is built"
        );
    }

    /// Ghidra's `ruleBlockOr` refuses to reach the second test through a back
    /// edge - "Don't use loop branch to get to orblock". A short-circuit
    /// condition is evaluated in one pass, so a second test reached by looping
    /// back is not that shape, however well the clause targets line up.
    #[test]
    fn a_short_circuit_does_not_reach_its_second_test_by_looping_back() {
        let mut data = Funcdata::default();
        data.entry = 0x1010;
        // Blocks are created in address order, as `from_lifted` does, because a
        // back edge is recognised by the target's block identifier preceding the
        // source's.
        let earlier = data.new_block(0x1000);
        let head = data.new_block(0x1010);
        let clause = data.new_block(0x1020);
        let other = data.new_block(0x1030);
        // The head tests, and one edge goes *backwards* to another test that
        // shares the head's clause - the shape the rule would otherwise merge.
        conditional(&mut data, head, 0x1000);
        data.add_edge(head, earlier);
        data.add_edge(head, clause);
        conditional(&mut data, earlier, 0x1020);
        data.add_edge(earlier, clause);
        data.add_edge(earlier, other);

        let mut graph = Graph::of(&data, &[]);
        let node = graph
            .nodes
            .iter()
            .position(|candidate| candidate.entry == head)
            .expect("the head is a node");
        assert!(
            !graph.rule_block_or(node),
            "the second test is reached by a back edge, so no condition is built"
        );
    }

    /// Absorbing a clause that returns must not drop the head's other path.
    ///
    /// The clause contributes no external successor, so replacing the
    /// composite's successors with the members' exits left a dead end and the
    /// loop around it became unrecognisable.
    #[test]
    fn absorbing_a_returning_clause_keeps_the_other_path() {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let head = data.new_block(0x1000);
        let returns = data.new_block(0x1010);
        let after = data.new_block(0x1020);
        conditional(&mut data, head, 0x1010);
        data.add_edge(head, returns);
        data.add_edge(head, after);

        let mut graph = Graph::of(&data, &[]);
        let node = graph
            .nodes
            .iter()
            .position(|candidate| candidate.entry == head)
            .expect("the head is a node");
        let reached = graph.nodes[node]
            .successors
            .iter()
            .find(|successor| graph.nodes[**successor].entry == after)
            .copied()
            .expect("the head reaches the block past the clause");

        assert!(graph.rule_block_if_return(node), "the clause is absorbed");

        assert!(
            graph.nodes[node].successors.contains(&reached),
            "the path past the absorbed clause survives: {:?}",
            graph.nodes[node].successors
        );
        assert!(
            graph.nodes[reached].predecessors.contains(&node),
            "and the composite is named as its predecessor"
        );
    }
}

/// Whether a recovered construct's flow always leaves through a jump.
///
/// A construct that ends in an unconditional transfer has no fallthrough, so
/// nothing may be concatenated after it and it cannot serve as the header of a
/// construct that then evaluates a test. Ignoring this produced an `if` printed
/// directly after a `goto`, which claims flow that does not exist.
fn ends_in_transfer(node: &Structured) -> bool {
    match node {
        Structured::Goto { .. } => true,
        Structured::List(members) => members.last().is_some_and(ends_in_transfer),
        Structured::IfElse {
            then_body,
            else_body,
            ..
        } => else_body
            .as_ref()
            .is_some_and(|other| ends_in_transfer(then_body) && ends_in_transfer(other)),
        // A switch whose every case transfers has no fallthrough either, but
        // only when it has no exit block for control to converge on.
        Structured::Switch {
            cases, has_exit, ..
        } => !has_exit && cases.iter().all(|(_, case)| ends_in_transfer(case)),
        // A `break` leaves the construct it is in, exactly as a `goto` does.
        Structured::Break => true,
        Structured::Basic(_)
        | Structured::IfGoto { .. }
        | Structured::IfBreak { .. }
        | Structured::WhileDo { .. }
        | Structured::DoWhile { .. }
        | Structured::InfLoop { .. } => false,
    }
}
