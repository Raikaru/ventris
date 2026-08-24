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

use std::collections::BTreeMap;

use ventris_pcode::op;

use super::{Funcdata, GraphBlockId};

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
        test: GraphBlockId,
        /// True when the recovered clauses are in the branch's taken order.
        taken_first: bool,
        then_body: Box<Structured>,
        else_body: Option<Box<Structured>>,
    },
    /// A loop testing before its body.
    WhileDo {
        header: Box<Structured>,
        test: GraphBlockId,
        /// True when the body is the taken side of the test.
        body_taken: bool,
        body: Box<Structured>,
    },
    /// A loop testing after its body.
    DoWhile {
        body: Box<Structured>,
        test: GraphBlockId,
        body_taken: bool,
    },
    /// An edge no construct claimed.
    Goto {
        from: GraphBlockId,
        target: GraphBlockId,
    },
    /// One edge of a two-way branch that no construct claimed. The other edge
    /// remains the fallthrough, so the branch keeps its condition instead of
    /// becoming an unconditional jump that orphans it.
    IfGoto {
        test: GraphBlockId,
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

struct Graph<'a> {
    data: &'a Funcdata,
    nodes: Vec<Node>,
    of_block: BTreeMap<GraphBlockId, NodeId>,
    entry: Option<NodeId>,
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
        }
    }

    fn collapse(&mut self) {
        let mut guard = 0;
        let cap = self.nodes.len() * 4 + 16;
        loop {
            guard += 1;
            if guard > cap {
                break;
            }
            let live: Vec<NodeId> = (0..self.nodes.len())
                .filter(|node| !self.nodes[*node].collapsed)
                .collect();
            if live.len() <= 1 {
                break;
            }
            let mut progressed = false;
            for node in live.iter().copied() {
                if self.nodes[node].collapsed {
                    continue;
                }
                if self.rule_cat(node)
                    || self.rule_if_else(node)
                    || self.rule_if_no_exit(node)
                    || self.rule_while_do(node)
                    || self.rule_do_while(node)
                {
                    progressed = true;
                    break;
                }
            }
            if progressed {
                continue;
            }
            // Nothing matched: give up one edge as a goto and try again. This
            // is Ghidra's `ruleBlockGoto`, the last resort that guarantees
            // termination.
            if !self.rule_goto(&live) {
                break;
            }
        }
    }

    /// Two blocks in a chain become one.
    fn rule_cat(&mut self, node: NodeId) -> bool {
        if self.nodes[node].successors.len() != 1 {
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
            test: self.nodes[node].exit,
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
                test: self.nodes[node].exit,
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
            let structured = Structured::WhileDo {
                header: Box::new(self.nodes[node].body.clone()),
                test: self.nodes[node].exit,
                body_taken: index == 0,
                body: Box::new(self.nodes[body].body.clone()),
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
        let body = Structured::DoWhile {
            body: Box::new(self.nodes[node].body.clone()),
            test: self.nodes[node].exit,
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

    /// Surrenders one edge as a `goto` so collapsing can continue.
    ///
    /// The edge chosen is a back edge if there is one, because a loop that no
    /// loop rule matched is what blocks progress most often.
    fn rule_goto(&mut self, live: &[NodeId]) -> bool {
        let mut choice = None;
        for node in live.iter().copied() {
            for (index, successor) in self.nodes[node].successors.iter().copied().enumerate() {
                let back = self.nodes[successor].entry <= self.nodes[node].entry;
                if back {
                    choice = Some((node, index));
                    break;
                }
                if choice.is_none() {
                    choice = Some((node, index));
                }
            }
            if matches!(choice, Some((chosen, _)) if chosen == node) {
                break;
            }
        }
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
                test: self.nodes[node].exit,
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
        // The composite's successors are whatever the absorbed nodes left to.
        let mut successors: Vec<NodeId> = Vec::new();
        for member in absorbed.iter().copied() {
            for successor in self.nodes[member].successors.clone() {
                if successor != node
                    && !absorbed.contains(&successor)
                    && !successors.contains(&successor)
                {
                    successors.push(successor);
                }
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
        let _ = &self.of_block;
        Structured::List(remaining.into_iter().map(|(_, body)| body).collect())
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
        assert!(
            contains(&structured, &|node| matches!(node, Structured::Goto { .. })),
            "expected a goto for the irreducible edge: {structured:?}"
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
            Structured::DoWhile { body, .. } => contains(body, predicate),
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
