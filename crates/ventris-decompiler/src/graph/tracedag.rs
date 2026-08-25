//! Choosing which edges become `goto`, by tracing paths through the DAG.
//!
//! Port of Ghidra 12.1.3's `TraceDAG` from `blockaction.cc`, with its
//! `BranchPoint`, `BlockTrace` and `BadEdgeScore` helpers.
//!
//! Every structuring rule requires its clause to have exactly one predecessor,
//! so a region several paths reach stalls the collapse and one of its incoming
//! edges has to be surrendered as unstructured. *Which* edge decides how much
//! structure survives: give up the wrong one and an `if`/`else` that would have
//! collapsed becomes two `goto`s.
//!
//! Ghidra does not choose locally. It pushes a trace along every path out of
//! each branch point simultaneously; while a path can advance it does, and when
//! no path can advance any further the traces that are stuck are scored against
//! each other and the worst one's edge is declared unstructured. The score
//! prefers, in order: fewer sibling traces leaving the same branch point to the
//! same place, then a non-terminal destination, then a greater distance between
//! branch points, then greater depth.
//!
//! A node may only be *opened* once every one of its incoming DAG edges has been
//! traced into it, which is what makes the algorithm find the join points rather
//! than guess at them.

use std::collections::BTreeMap;

/// A node in the caller's collapsing graph.
pub type NodeId = usize;

/// The graph shape this trace needs: successors per node, and which of those
/// edges take part in the loop DAG.
///
/// Ghidra reads `isLoopDAGOut`/`isLoopDAGIn` off the `FlowBlock`. Here the
/// caller supplies the same fact, because it is the caller that knows which
/// edges it has already surrendered and which are loop back edges.
pub struct Dag<'a> {
    /// Successors of each live node, in branch order.
    pub successors: &'a [Vec<NodeId>],
    /// Whether the edge from `node` at `index` is part of the loop DAG.
    pub dag_out: &'a dyn Fn(NodeId, usize) -> bool,
    /// Number of incoming loop-DAG edges of a node.
    pub dag_in_count: &'a dyn Fn(NodeId) -> usize,
    /// Nodes to trace from.
    pub roots: &'a [NodeId],
    /// A node not to trace beyond, when the caller designates one.
    pub finish: Option<NodeId>,
}

/// One edge the trace judged unstructured: from `bottom` along to `dest`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct FloatingEdge {
    pub bottom: NodeId,
    pub dest: NodeId,
}

/// The branch point a set of traces leaves from.
struct BranchPoint {
    parent: Option<usize>,
    /// Index of the parent's path along which this lies.
    pathout: usize,
    /// The node that branches, or `None` for the virtual root.
    top: Option<NodeId>,
    /// Index into `traces` for each path out of this point.
    paths: Vec<usize>,
    depth: usize,
    ismark: bool,
}

/// One path out of a branch point.
struct BlockTrace {
    active: bool,
    terminal: bool,
    /// Owning branch point.
    top: usize,
    /// Index of this path within the branch point.
    pathout: usize,
    /// Node the trace has reached, or `None` for a root trace.
    bottom: Option<NodeId>,
    /// Node the trace will try to push into.
    dest: Option<NodeId>,
    /// Above one when the edge to `dest` stands for several edges merged.
    edgelump: usize,
    /// Branch point this trace opened, while it is open.
    derived: Option<usize>,
    /// Set when the trace has been retired out of the structure.
    dead: bool,
}

/// Scoring record for one candidate unstructured edge.
struct BadEdgeScore {
    exit: NodeId,
    trace: usize,
    /// Least distance between this trace's branch point and any other sharing
    /// the same exit. `None` until a conflict is processed.
    distance: Option<usize>,
    terminal: bool,
    siblings: usize,
    /// Branch point index and path, for the grouping order.
    top: Option<NodeId>,
    pathout: usize,
}

/// The trace state.
pub struct TraceDag<'a> {
    graph: Dag<'a>,
    branches: Vec<BranchPoint>,
    traces: Vec<BlockTrace>,
    /// Traces currently active, in push order.
    active: Vec<usize>,
    /// Edges declared unstructured, in the order they were chosen.
    likely: Vec<FloatingEdge>,
    /// Per-node count of incoming edges already surrendered, so a node whose
    /// remaining edges have all been traced can still be opened.
    visit: BTreeMap<NodeId, usize>,
}

impl<'a> TraceDag<'a> {
    pub fn new(graph: Dag<'a>) -> Self {
        Self {
            graph,
            branches: Vec::new(),
            traces: Vec::new(),
            active: Vec::new(),
            likely: Vec::new(),
            visit: BTreeMap::new(),
        }
    }

    /// `TraceDAG::initialize`: one virtual branch point over every root.
    fn initialize(&mut self) {
        self.branches.push(BranchPoint {
            parent: None,
            pathout: usize::MAX,
            top: None,
            paths: Vec::new(),
            depth: 0,
            ismark: false,
        });
        for root in self.graph.roots.iter().copied() {
            let pathout = self.branches[0].paths.len();
            let trace = self.traces.len();
            self.traces.push(BlockTrace {
                active: false,
                terminal: false,
                top: 0,
                pathout,
                bottom: None,
                dest: Some(root),
                edgelump: 1,
                derived: None,
                dead: false,
            });
            self.branches[0].paths.push(trace);
            self.insert_active(trace);
        }
    }

    /// `TraceDAG::pushBranches`, and the entry point: run the trace and return
    /// the edges it judged unstructured.
    pub fn run(mut self) -> Vec<FloatingEdge> {
        self.initialize();
        let mut cursor = 0usize;
        let mut missed = 0usize;
        // Ghidra loops while any trace is active. The bound is a guard against a
        // malformed graph rather than part of the algorithm: every iteration
        // either advances a trace, retires a branch point, or surrenders an
        // edge, and each is finite.
        let bound = self
            .graph
            .successors
            .len()
            .saturating_mul(8)
            .saturating_add(64);
        let mut guard = 0usize;
        while !self.active.is_empty() {
            guard += 1;
            if guard > bound {
                break;
            }
            if cursor >= self.active.len() {
                cursor = 0;
            }
            let trace = self.active[cursor];
            if missed >= self.active.len() {
                // No trace can advance, so one of them is crossing an edge that
                // cannot be structured.
                let bad = self.select_bad_edge();
                match bad {
                    Some(bad) => self.remove_trace(bad),
                    None => break,
                }
                cursor = 0;
                missed = 0;
            } else if let Some(exit) = self.check_retirement(trace) {
                cursor = self.retire_branch(self.traces[trace].top, exit);
                missed = 0;
            } else if self.check_open(trace) {
                cursor = self.open_branch(trace);
                missed = 0;
            } else {
                missed += 1;
                cursor += 1;
            }
        }
        self.likely
    }

    fn insert_active(&mut self, trace: usize) {
        self.traces[trace].active = true;
        self.active.push(trace);
    }

    fn remove_active(&mut self, trace: usize) {
        self.traces[trace].active = false;
        self.active.retain(|candidate| *candidate != trace);
    }

    /// `TraceDAG::checkOpen`: a node may only be opened once every incoming
    /// loop-DAG edge has been traced into it.
    fn check_open(&self, trace: usize) -> bool {
        let current = &self.traces[trace];
        if current.terminal {
            return false;
        }
        let mut is_root = false;
        if self.branches[current.top].depth == 0 {
            if current.bottom.is_none() {
                // The virtual root's first level is not a real edge.
                return true;
            }
            is_root = true;
        }
        let Some(dest) = current.dest else {
            return false;
        };
        if Some(dest) == self.graph.finish && !is_root {
            return false;
        }
        let ignore = current.edgelump + self.visit.get(&dest).copied().unwrap_or(0);
        (self.graph.dag_in_count)(dest) <= ignore
    }

    /// `TraceDAG::openBranch`: split a trace at the node it reached.
    fn open_branch(&mut self, parent: usize) -> usize {
        let Some(top) = self.traces[parent].dest else {
            return 0;
        };
        let depth = self.branches[self.traces[parent].top].depth + 1;
        let branch = self.branches.len();
        self.branches.push(BranchPoint {
            parent: Some(self.traces[parent].top),
            pathout: self.traces[parent].pathout,
            top: Some(top),
            paths: Vec::new(),
            depth,
            ismark: false,
        });
        self.traces[parent].derived = Some(branch);
        // `BranchPoint::createTraces`: one path per outgoing loop-DAG edge.
        let outgoing: Vec<NodeId> = self.graph.successors.get(top).cloned().unwrap_or_default();
        for (index, successor) in outgoing.iter().copied().enumerate() {
            if !(self.graph.dag_out)(top, index) {
                continue;
            }
            let pathout = self.branches[branch].paths.len();
            let trace = self.traces.len();
            self.traces.push(BlockTrace {
                active: false,
                terminal: false,
                top: branch,
                pathout,
                bottom: Some(top),
                dest: Some(successor),
                edgelump: 1,
                derived: None,
                dead: false,
            });
            self.branches[branch].paths.push(trace);
        }
        if self.branches[branch].paths.is_empty() {
            // Nowhere to go: the parent trace is terminal.
            self.branches.pop();
            self.traces[parent].derived = None;
            self.mark_terminal(parent);
            return self
                .active
                .iter()
                .position(|candidate| *candidate == parent)
                .unwrap_or(0);
        }
        self.remove_active(parent);
        let paths = self.branches[branch].paths.clone();
        for trace in paths.iter().copied() {
            self.insert_active(trace);
        }
        self.active
            .iter()
            .position(|candidate| Some(*candidate) == paths.first().copied())
            .unwrap_or(0)
    }

    fn mark_terminal(&mut self, trace: usize) {
        let current = &mut self.traces[trace];
        current.terminal = true;
        current.bottom = None;
        current.dest = None;
        current.edgelump = 0;
    }

    /// `TraceDAG::checkRetirement`: every sibling path must terminate or reach
    /// the same node.
    fn check_retirement(&self, trace: usize) -> Option<NodeId> {
        if self.traces[trace].pathout != 0 {
            return None;
        }
        let branch = self.traces[trace].top;
        if self.branches[branch].depth == 0 {
            // The root retires only when every path has terminated, and it
            // yields no exit node.
            for path in self.branches[branch].paths.iter().copied() {
                if !self.traces[path].active || !self.traces[path].terminal {
                    return None;
                }
            }
            return Some(usize::MAX);
        }
        let mut out = None;
        for path in self.branches[branch].paths.iter().copied() {
            if !self.traces[path].active {
                return None;
            }
            if self.traces[path].terminal {
                continue;
            }
            if out == self.traces[path].dest {
                continue;
            }
            if out.is_some() {
                return None;
            }
            out = self.traces[path].dest;
        }
        Some(out.unwrap_or(usize::MAX))
    }

    /// `TraceDAG::retireBranch`: fold a finished branch point into its parent.
    fn retire_branch(&mut self, branch: usize, exit: NodeId) -> usize {
        let mut edgeout: Option<NodeId> = None;
        let mut edgelump_sum = 0usize;
        for path in self.branches[branch].paths.clone() {
            if !self.traces[path].terminal {
                edgelump_sum += self.traces[path].edgelump;
                if edgeout.is_none() {
                    edgeout = self.traces[path].bottom;
                }
            }
            self.remove_active(path);
        }
        if self.branches[branch].depth == 0 {
            return 0;
        }
        let Some(parent) = self.branches[branch].parent else {
            return 0;
        };
        let pathout = self.branches[branch].pathout;
        let Some(parent_trace) = self.branches[parent].paths.get(pathout).copied() else {
            return 0;
        };
        self.traces[parent_trace].derived = None;
        match edgeout {
            None => self.mark_terminal(parent_trace),
            Some(bottom) => {
                self.traces[parent_trace].bottom = Some(bottom);
                self.traces[parent_trace].dest = (exit != usize::MAX).then_some(exit);
                self.traces[parent_trace].edgelump = edgelump_sum;
                if self.traces[parent_trace].dest.is_none() {
                    self.mark_terminal(parent_trace);
                }
            }
        }
        self.insert_active(parent_trace);
        self.active
            .iter()
            .position(|candidate| *candidate == parent_trace)
            .unwrap_or(0)
    }

    /// `BranchPoint::markPath`: flip the mark along the path to the root.
    fn mark_path(&mut self, branch: usize) {
        let mut cursor = Some(branch);
        while let Some(current) = cursor {
            self.branches[current].ismark = !self.branches[current].ismark;
            cursor = self.branches[current].parent;
        }
    }

    /// `BranchPoint::distance`: edges up to the common ancestor plus edges back
    /// down, assuming `from`'s path to the root is marked.
    fn distance(&self, from: usize, to: usize) -> usize {
        let mut cursor = Some(to);
        while let Some(current) = cursor {
            if self.branches[current].ismark {
                return (self.branches[from].depth - self.branches[current].depth)
                    + (self.branches[to].depth - self.branches[current].depth);
            }
            cursor = self.branches[current].parent;
        }
        self.branches[from].depth + self.branches[to].depth + 1
    }

    /// `TraceDAG::selectBadEdge`: score every stuck trace and pick the worst.
    fn select_bad_edge(&mut self) -> Option<usize> {
        let mut scores: Vec<BadEdgeScore> = Vec::new();
        for trace in self.active.clone() {
            if self.traces[trace].terminal {
                continue;
            }
            let branch = self.traces[trace].top;
            // A virtual edge out of the root is not a real edge and can never be
            // the unstructured one.
            if self.branches[branch].top.is_none() && self.traces[trace].bottom.is_none() {
                continue;
            }
            let Some(dest) = self.traces[trace].dest else {
                continue;
            };
            scores.push(BadEdgeScore {
                exit: dest,
                trace,
                distance: None,
                terminal: self
                    .graph
                    .successors
                    .get(dest)
                    .is_none_or(|successors| successors.is_empty()),
                siblings: 0,
                top: self.branches[branch].top,
                pathout: self.traces[trace].pathout,
            });
        }
        if scores.is_empty() {
            return None;
        }
        // `BadEdgeScore::operator<`: group by exit, then by branch point, then
        // by the branch taken.
        scores.sort_by_key(|score| {
            (
                score.exit,
                score.top.map_or(usize::MAX, |top| top),
                score.pathout,
            )
        });

        // Traces sharing an exit conflict, and the conflict is what supplies the
        // sibling counts and distances.
        let mut start = 0usize;
        while start < scores.len() {
            let mut end = start + 1;
            while end < scores.len() && scores[end].exit == scores[start].exit {
                end += 1;
            }
            if end - start > 1 {
                self.process_exit_conflict(&mut scores[start..end]);
            }
            start = end;
        }

        // `compareFinal`: the trace that is most likely to be the bad edge.
        let mut best = 0usize;
        for index in 1..scores.len() {
            if self.less_likely_bad(&scores[best], &scores[index]) {
                best = index;
            }
        }
        Some(scores[best].trace)
    }

    /// `TraceDAG::processExitConflict`: least distance and sibling counts among
    /// traces reaching one exit.
    fn process_exit_conflict(&mut self, group: &mut [BadEdgeScore]) {
        for first in 0..group.len() {
            if first + 1 >= group.len() {
                break;
            }
            let start_branch = self.traces[group[first].trace].top;
            self.mark_path(start_branch);
            for second in (first + 1)..group.len() {
                let other_branch = self.traces[group[second].trace].top;
                if start_branch == other_branch {
                    group[first].siblings += 1;
                    group[second].siblings += 1;
                }
                let distance = self.distance(start_branch, other_branch);
                for index in [first, second] {
                    if group[index].distance.is_none_or(|best| best > distance) {
                        group[index].distance = Some(distance);
                    }
                }
            }
            self.mark_path(start_branch);
        }
    }

    /// `BadEdgeScore::compareFinal`: true when `left` is *less* likely to be the
    /// bad edge than `right`.
    fn less_likely_bad(&self, left: &BadEdgeScore, right: &BadEdgeScore) -> bool {
        if left.siblings != right.siblings {
            // More siblings leaving the same point to the same place means the
            // edge is part of a real multi-way structure, so less likely bad.
            return right.siblings < left.siblings;
        }
        // A sibling edge counts for more than a terminal one: terminal edges
        // matter most to joined returns, which a switch edge rarely is, whereas
        // switches often exit to a terminal node.
        if left.terminal != right.terminal {
            return !left.terminal && right.terminal;
        }
        let left_distance = left.distance.unwrap_or(0);
        let right_distance = right.distance.unwrap_or(0);
        if left_distance != right_distance {
            return left_distance < right_distance;
        }
        self.branches[self.traces[left.trace].top].depth
            < self.branches[self.traces[right.trace].top].depth
    }

    /// `TraceDAG::removeTrace`: record the edge as unstructured and repair the
    /// branch point it came from.
    fn remove_trace(&mut self, trace: usize) {
        let (Some(bottom), Some(dest)) = (self.traces[trace].bottom, self.traces[trace].dest)
        else {
            // Nothing to record; drop it so the loop can make progress.
            self.remove_active(trace);
            self.traces[trace].dead = true;
            return;
        };
        self.likely.push(FloatingEdge { bottom, dest });
        *self.visit.entry(dest).or_insert(0) += self.traces[trace].edgelump;

        let branch = self.traces[trace].top;
        if self.branches[branch].top != Some(bottom) {
            // The trace has moved past its branch point, so from here it simply
            // terminates rather than vacating a path.
            self.mark_terminal(trace);
            return;
        }
        self.remove_active(trace);
        let pathout = self.traces[trace].pathout;
        let paths = self.branches[branch].paths.clone();
        for index in (pathout + 1)..paths.len() {
            let moved = paths[index];
            self.traces[moved].pathout -= 1;
            if let Some(derived) = self.traces[moved].derived {
                self.branches[derived].pathout -= 1;
            }
            self.branches[branch].paths[index - 1] = moved;
        }
        self.branches[branch].paths.pop();
        self.traces[trace].dead = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a trace over a graph where every edge is a DAG edge.
    fn trace(successors: &[Vec<NodeId>], roots: &[NodeId]) -> Vec<FloatingEdge> {
        let counts: Vec<usize> = (0..successors.len())
            .map(|node| successors.iter().filter(|out| out.contains(&node)).count())
            .collect();
        let dag_out = |_: NodeId, _: usize| true;
        let dag_in_count = move |node: NodeId| counts.get(node).copied().unwrap_or(0);
        TraceDag::new(Dag {
            successors,
            dag_out: &dag_out,
            dag_in_count: &dag_in_count,
            roots,
            finish: None,
        })
        .run()
    }

    #[test]
    fn a_diamond_needs_no_unstructured_edge() {
        // 0 branches to 1 and 2, both reach 3. Every path merges, so the trace
        // retires the branch point and surrenders nothing.
        let successors = vec![vec![1, 2], vec![3], vec![3], vec![]];
        assert_eq!(trace(&successors, &[0]), Vec::new());
    }

    #[test]
    fn a_straight_line_needs_no_unstructured_edge() {
        let successors = vec![vec![1], vec![2], vec![]];
        assert_eq!(trace(&successors, &[0]), Vec::new());
    }

    #[test]
    fn a_nested_diamond_needs_no_unstructured_edge() {
        // The shape that stalls the local heuristic: two nested branches whose
        // clauses converge on one join, which therefore has three predecessors.
        //   0 -> 1, 4      1 -> 2, 4      2 -> 3      3 -> 4
        let successors = vec![vec![1, 4], vec![2, 4], vec![3], vec![4], vec![]];
        assert_eq!(
            trace(&successors, &[0]),
            Vec::new(),
            "a join reached by three structured paths is not unstructured"
        );
    }

    #[test]
    fn a_cross_edge_is_surrendered_once() {
        // 1 and 2 are the arms of a branch, and 1 also jumps into 2. One edge
        // has to go; exactly one should.
        let successors = vec![vec![1, 2], vec![2, 3], vec![3], vec![]];
        let edges = trace(&successors, &[0]);
        assert_eq!(
            edges.len(),
            1,
            "expected one surrendered edge, got {edges:?}"
        );
    }

    #[test]
    fn the_chosen_edge_is_the_one_into_the_shared_join() {
        // Two branch points both reach node 3 directly, and 3 is also reached
        // through 2. The edge scored worst must be one of the direct ones, never
        // the structured path through 2.
        let successors = vec![vec![1, 3], vec![2, 3], vec![3], vec![]];
        let edges = trace(&successors, &[0]);
        assert!(
            edges.iter().all(|edge| edge.dest == 3),
            "every surrendered edge should target the shared join, got {edges:?}"
        );
        assert!(
            edges.iter().all(|edge| edge.bottom != 2),
            "the structured path through 2 must not be the one given up: {edges:?}"
        );
    }
}
