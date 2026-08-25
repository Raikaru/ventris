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
}

type NodeId = usize;

/// Collapses a function's control flow into a construct tree.
///
/// The result is a single construct when the flow is fully structured, and a
/// list containing `Goto` where it is not.
pub fn structure(data: &Funcdata) -> Structured {
    let mut graph = Graph::of(data);
    graph.collapse();
    graph.finish()
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
}

impl<'a> Graph<'a> {
    fn of(data: &'a Funcdata) -> Self {
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
            .find(|(_, block)| block.start == data.entry)
            .map(|(id, _)| id)
            .or_else(|| data.blocks().next().map(|(id, _)| id))
            .and_then(|id| of_block.get(&id).copied());
        Self {
            data,
            nodes,
            of_block,
            entry,
            surrendered: 0,
        }
    }

    fn collapse(&mut self) {
        // Conditions collapse in their own pass first. Ghidra runs
        // `collapseConditions` ahead of the main loop because a short-circuit
        // operator spans two blocks that every other rule would otherwise
        // treat as separate regions.
        self.collapse_conditions();
        // Then loops are identified and their exits surrendered. Every
        // structuring rule demands that a clause have exactly one predecessor,
        // and a loop with a `break` violates that at the block after the loop.
        // Marking the exits first is how Ghidra makes the loop itself visible;
        // a greedy rule set without this step recovers the loop only when the
        // body happens to be a single-entry chain.
        self.mark_loop_exits();

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
                    if self.rule_cat(node)
                        || self.rule_if_else(node)
                        || self.rule_while_do(node)
                        || self.rule_do_while(node)
                        || self.rule_inf_loop(node)
                    {
                        inner_changed = true;
                        break;
                    }
                }
            }

            // Only when nothing preferable applies. An `if` with no join
            // matches shapes that a loop or an if/else would have claimed, so
            // running it early loses those constructs.
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
                if self.rule_if_no_exit(node) || self.rule_block_if_return(node) {
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
            let body = self.loop_body(head, &tails);
            let exit = self.loop_exit(&body, &tails);
            // Every edge out of the body other than the chosen exit is a
            // candidate for being unstructured, but only one is surrendered per
            // pass.
            //
            // Ghidra builds the same candidate list in `emitLikelyEdges` and
            // then `selectGoto` pops it one edge at a time, returning to the
            // collapse rules after each. Surrendering the whole list at once —
            // as this did — gives up edges the rules would have structured once
            // the first one was gone, and each surrendered edge is a `goto` in
            // the output that cannot be recovered later.
            let leaving: Vec<(NodeId, NodeId)> = body
                .iter()
                .copied()
                .flat_map(|node| {
                    self.nodes[node]
                        .successors
                        .clone()
                        .into_iter()
                        .map(move |successor| (node, successor))
                })
                .filter(|(_, successor)| !body.contains(successor))
                .filter(|(_, successor)| Some(*successor) != exit)
                .collect();
            if leaving.is_empty() {
                continue;
            }
            // Which of the candidates to give up is the trace's decision, not a
            // positional one. Ghidra runs `TraceDAG` from the loop head with the
            // loop bottom as the finish block and the exit edges marked, so the
            // trace stays inside the body and scores the edges that stall it
            // against each other.
            let chosen = self
                .traced_loop_edge(&body, head, &tails)
                .filter(|edge| leaving.contains(edge))
                .or_else(|| leaving.first().copied());
            if let Some((node, successor)) = chosen {
                self.surrender_edge(node, successor);
                return;
            }
        }
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

    /// The natural loop body: the head, its tails, and everything that reaches a
    /// tail without leaving through the head.
    ///
    /// `LoopBody::findBase` walks predecessors rather than successors, because
    /// the body is what can reach the back edge, not what the head can reach.
    fn loop_body(&self, head: NodeId, tails: &[NodeId]) -> BTreeSet<NodeId> {
        let mut body: BTreeSet<NodeId> = BTreeSet::from([head]);
        let mut pending: Vec<NodeId> = Vec::new();
        for tail in tails.iter().copied() {
            if body.insert(tail) {
                pending.push(tail);
            }
        }
        while let Some(node) = pending.pop() {
            for predecessor in self.nodes[node].predecessors.clone() {
                if predecessor == head || self.nodes[predecessor].collapsed {
                    continue;
                }
                if body.insert(predecessor) {
                    pending.push(predecessor);
                }
            }
        }
        body
    }

    /// The one block a structured loop may exit to.
    ///
    /// `LoopBody::findExit` prefers an exit taken from a tail, because that is
    /// the loop's own test; an exit from the middle is a `break`, which has to
    /// become a goto.
    fn loop_exit(&self, body: &BTreeSet<NodeId>, tails: &[NodeId]) -> Option<NodeId> {
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
            if self.nodes[clause].predecessors.len() != 1 {
                continue;
            }
            if self.nodes[clause].successors.len() != 1 {
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
            return true;
        }
        false
    }

    /// A body whose own terminator tests whether to repeat it.
    fn rule_do_while(&mut self, node: NodeId) -> bool {
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
            // Nothing else may reach the second test, or it is a join rather
            // than the tail of one condition.
            if self.nodes[second].predecessors.len() != 1 {
                continue;
            }
            if self.nodes[second].successors.len() != 2 {
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
            self.absorb(node, &[clause], body);
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

    fn finish(self) -> Structured {
        let live: Vec<&Node> = self.nodes.iter().filter(|node| !node.collapsed).collect();
        if live.len() == 1 {
            return live[0].body.clone();
        }
        // Not fully structured: emit the remaining nodes in address order, with
        // whatever gotos the collapse left in them.
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
        let mut members: Vec<Structured> = remaining.into_iter().map(|(_, body)| body).collect();

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
        Structured::Basic(_) | Structured::Goto { .. } | Structured::IfGoto { .. } => {}
    }
}

/// Every basic block a construct tree mentions.
fn collect_blocks(node: &Structured, into: &mut BTreeSet<GraphBlockId>) {
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
    let address = data.varnode(target).offset;
    data.blocks()
        .find(|(_, candidate)| candidate.start == address)
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

        let structured = structure(&data);
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

        let structured = structure(&data);
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

        let structured = structure(&data);
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

        let structured = structure(&data);
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

        let structured = structure(&data);
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

        let structured = structure(&data);
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

        let structured = structure(&data);
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

        let structured = structure(&data);
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

        let structured = structure(&data);
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

        let structured = structure(&data);
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
            Structured::Basic(_) | Structured::Goto { .. } | Structured::IfGoto { .. } => false,
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
        Structured::Basic(_)
        | Structured::IfGoto { .. }
        | Structured::WhileDo { .. }
        | Structured::DoWhile { .. }
        | Structured::InfLoop { .. } => false,
    }
}
