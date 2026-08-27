use super::*;

/// The terminal operation of a basic block.  The block keeps the original
/// statements as well: retaining the source form is what lets an unsafe
/// reduction fall back to an exact label/goto representation.
#[derive(Clone)]
enum BlockTerminator {
    None,
    IfGoto { condition: Expr, target: u64 },
    Goto(u64),
    IfReturn,
    Return,
    IndirectGoto,
}

#[derive(Clone)]
struct BasicBlock {
    statements: Vec<NativeStatement>,
    terminator: BlockTerminator,
    successors: Vec<usize>,
}

/// A compact CFG model corresponding to the block/edge facts used by
/// Ghidra's `BlockBasic` and `BlockGraph` passes.  Sets are ordered on
/// purpose: output must not depend on hash iteration order.
struct ControlFlowGraph {
    blocks: Vec<BasicBlock>,
    labels: BTreeMap<u64, usize>,
    predecessors: Vec<BTreeSet<usize>>,
    reachable: BTreeSet<usize>,
    postdominators: Vec<BTreeSet<usize>>,
    back_edges: BTreeSet<(usize, usize)>,
    natural_loops: BTreeMap<usize, BTreeSet<usize>>,
    has_indirect_goto: bool,
}

#[derive(Clone)]
enum LoopPlan {
    While {
        header: usize,
        body_entry: usize,
        exit: usize,
        body_nodes: BTreeSet<usize>,
        condition: Expr,
        invert_condition: bool,
        target: u64,
    },
    DoWhile {
        header: usize,
        tail: usize,
        exit: usize,
        body_nodes: BTreeSet<usize>,
        condition: Expr,
        invert_condition: bool,
        target: u64,
    },
}

impl BasicBlock {
    fn prefix_len(&self) -> usize {
        match &self.terminator {
            BlockTerminator::IfGoto { .. }
            | BlockTerminator::Goto(_)
            | BlockTerminator::IfReturn
            | BlockTerminator::Return
            | BlockTerminator::IndirectGoto => self.statements.len().saturating_sub(1),
            BlockTerminator::None => self.statements.len(),
        }
    }
}

fn statement_contains_indirect_goto(statement: &NativeStatement) -> bool {
    match statement {
        NativeStatement::IndirectGoto(_) => true,
        NativeStatement::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body.iter().any(statement_contains_indirect_goto)
                || else_body.iter().any(statement_contains_indirect_goto)
        }
        NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
            body.iter().any(statement_contains_indirect_goto)
        }
        NativeStatement::For {
            initializer,
            step,
            body,
            ..
        } => {
            initializer
                .as_deref()
                .is_some_and(statement_contains_indirect_goto)
                || step
                    .as_deref()
                    .is_some_and(statement_contains_indirect_goto)
                || body.iter().any(statement_contains_indirect_goto)
        }
        NativeStatement::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|(_, body)| body.iter().any(statement_contains_indirect_goto))
                || default.iter().any(statement_contains_indirect_goto)
        }
        _ => false,
    }
}

fn successors_for(
    block_id: usize,
    blocks: &[BasicBlock],
    labels: &BTreeMap<u64, usize>,
) -> Vec<usize> {
    let block = &blocks[block_id];
    let next = (block_id + 1 < blocks.len()).then_some(block_id + 1);
    let mut successors = BTreeSet::new();
    match &block.terminator {
        BlockTerminator::IfGoto { target, .. } => {
            if let Some(target) = labels.get(target).copied() {
                successors.insert(target);
            }
            if let Some(next) = next {
                successors.insert(next);
            }
        }
        BlockTerminator::Goto(target) => {
            if let Some(target) = labels.get(target).copied() {
                successors.insert(target);
            }
        }
        BlockTerminator::IfReturn | BlockTerminator::None => {
            if let Some(next) = next {
                successors.insert(next);
            }
        }
        BlockTerminator::Return | BlockTerminator::IndirectGoto => {}
    }
    successors.into_iter().collect()
}
fn statement_is_terminator(statement: &NativeStatement) -> bool {
    matches!(
        statement,
        NativeStatement::IfGoto { .. }
            | NativeStatement::IfReturn { .. }
            | NativeStatement::Goto(_)
            | NativeStatement::Return(_)
            | NativeStatement::IndirectGoto(_)
    )
}

fn block_terminator(statements: &[NativeStatement]) -> BlockTerminator {
    match statements.last() {
        Some(NativeStatement::IfGoto { condition, target }) => BlockTerminator::IfGoto {
            condition: condition.clone(),
            target: *target,
        },
        Some(NativeStatement::IfReturn { .. }) => BlockTerminator::IfReturn,
        Some(NativeStatement::Goto(target)) => BlockTerminator::Goto(*target),
        Some(NativeStatement::Return(_)) => BlockTerminator::Return,
        Some(NativeStatement::IndirectGoto(_)) => BlockTerminator::IndirectGoto,
        _ => BlockTerminator::None,
    }
}

fn build_cfg(statements: &[NativeStatement]) -> ControlFlowGraph {
    if statements.is_empty() {
        return ControlFlowGraph {
            blocks: Vec::new(),
            labels: BTreeMap::new(),
            predecessors: Vec::new(),
            reachable: BTreeSet::new(),
            postdominators: Vec::new(),
            back_edges: BTreeSet::new(),
            natural_loops: BTreeMap::new(),
            has_indirect_goto: false,
        };
    }

    let mut leaders = BTreeSet::from([0usize]);
    for (index, statement) in statements.iter().enumerate() {
        if matches!(statement, NativeStatement::Label(_)) {
            leaders.insert(index);
        }
        if statement_is_terminator(statement) && index + 1 < statements.len() {
            leaders.insert(index + 1);
        }
    }
    let leaders = leaders.into_iter().collect::<Vec<_>>();
    let mut blocks = Vec::with_capacity(leaders.len());
    for (block_index, start) in leaders.iter().copied().enumerate() {
        let end = leaders
            .get(block_index + 1)
            .copied()
            .unwrap_or(statements.len());
        let block_statements = statements[start..end].to_vec();
        blocks.push(BasicBlock {
            terminator: block_terminator(&block_statements),
            statements: block_statements,
            successors: Vec::new(),
        });
    }

    let mut labels = BTreeMap::new();
    for (block_id, block) in blocks.iter().enumerate() {
        for statement in &block.statements {
            if let NativeStatement::Label(address) = statement {
                // Duplicate labels are malformed input, but choosing the first
                // block is deterministic and keeps every original statement.
                labels.entry(*address).or_insert(block_id);
            }
        }
    }
    for block_id in 0..blocks.len() {
        blocks[block_id].successors = successors_for(block_id, &blocks, &labels);
    }

    let mut predecessors = vec![BTreeSet::new(); blocks.len()];
    for (block_id, block) in blocks.iter().enumerate() {
        for successor in &block.successors {
            predecessors[*successor].insert(block_id);
        }
    }

    let mut reachable = BTreeSet::new();
    if !blocks.is_empty() {
        let mut pending = vec![0usize];
        while let Some(block_id) = pending.pop() {
            if !reachable.insert(block_id) {
                continue;
            }
            // `successors` is already sorted; reverse here so the stack visits
            // the lowest order first without depending on recursion.
            for successor in blocks[block_id].successors.iter().rev() {
                pending.push(*successor);
            }
        }
    }

    let dominators = compute_dominators(&blocks, &predecessors, &reachable);
    let postdominators = compute_postdominators(&blocks, &reachable);
    let (back_edges, natural_loops) =
        compute_natural_loops(&blocks, &predecessors, &reachable, &dominators);
    let has_indirect_goto = statements.iter().any(statement_contains_indirect_goto);

    ControlFlowGraph {
        blocks,
        labels,
        predecessors,
        reachable,
        postdominators,
        back_edges,
        natural_loops,
        has_indirect_goto,
    }
}

fn compute_dominators(
    blocks: &[BasicBlock],
    predecessors: &[BTreeSet<usize>],
    reachable: &BTreeSet<usize>,
) -> Vec<BTreeSet<usize>> {
    let mut dominators = vec![BTreeSet::new(); blocks.len()];
    for block_id in reachable {
        if *block_id == 0 {
            dominators[*block_id].insert(0);
        } else {
            dominators[*block_id] = reachable.clone();
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for block_id in reachable.iter().copied().filter(|id| *id != 0) {
            let reachable_predecessors = predecessors[block_id]
                .iter()
                .filter(|predecessor| reachable.contains(predecessor));
            let Some(first) = reachable_predecessors.clone().next() else {
                let singleton = BTreeSet::from([block_id]);
                if dominators[block_id] != singleton {
                    dominators[block_id] = singleton;
                    changed = true;
                }
                continue;
            };
            let mut intersection = dominators[*first].clone();
            for predecessor in reachable_predecessors {
                intersection.retain(|candidate| dominators[*predecessor].contains(candidate));
            }
            intersection.insert(block_id);
            if dominators[block_id] != intersection {
                dominators[block_id] = intersection;
                changed = true;
            }
        }
    }
    dominators
}

fn compute_postdominators(
    blocks: &[BasicBlock],
    reachable: &BTreeSet<usize>,
) -> Vec<BTreeSet<usize>> {
    let mut postdominators = vec![BTreeSet::new(); blocks.len()];
    let exits = reachable
        .iter()
        .copied()
        .filter(|block_id| {
            !blocks[*block_id]
                .successors
                .iter()
                .any(|successor| reachable.contains(successor))
        })
        .collect::<BTreeSet<_>>();
    // A function with no reachable exit is an unfinished/cyclic graph.  There
    // is no sound common postdominator in that case, so leave all sets empty.
    if exits.is_empty() {
        return postdominators;
    }

    for block_id in reachable {
        if exits.contains(block_id) {
            postdominators[*block_id].insert(*block_id);
        } else {
            postdominators[*block_id] = reachable.clone();
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for block_id in reachable.iter().copied() {
            if exits.contains(&block_id) {
                continue;
            }
            let successors = blocks[block_id]
                .successors
                .iter()
                .filter(|successor| reachable.contains(successor));
            let Some(first) = successors.clone().next() else {
                continue;
            };
            let mut intersection = postdominators[*first].clone();
            for successor in successors {
                intersection.retain(|candidate| postdominators[*successor].contains(candidate));
            }
            intersection.insert(block_id);
            if postdominators[block_id] != intersection {
                postdominators[block_id] = intersection;
                changed = true;
            }
        }
    }
    postdominators
}

fn compute_natural_loops(
    blocks: &[BasicBlock],
    predecessors: &[BTreeSet<usize>],
    reachable: &BTreeSet<usize>,
    dominators: &[BTreeSet<usize>],
) -> (BTreeSet<(usize, usize)>, BTreeMap<usize, BTreeSet<usize>>) {
    let mut back_edges = BTreeSet::new();
    let mut natural_loops = BTreeMap::<usize, BTreeSet<usize>>::new();
    for tail in reachable {
        for head in &blocks[*tail].successors {
            if !reachable.contains(head) || !dominators[*tail].contains(head) {
                continue;
            }
            back_edges.insert((*tail, *head));
            let mut loop_nodes = BTreeSet::from([*head, *tail]);
            let mut pending = vec![*tail];
            while let Some(node) = pending.pop() {
                for predecessor in predecessors[node].iter().copied() {
                    if !reachable.contains(&predecessor)
                        || predecessor == *head
                        || !loop_nodes.insert(predecessor)
                    {
                        continue;
                    }
                    pending.push(predecessor);
                }
            }
            natural_loops.entry(*head).or_default().extend(loop_nodes);
        }
    }
    (back_edges, natural_loops)
}

fn nearest_common_postdominator(
    graph: &ControlFlowGraph,
    left: usize,
    right: usize,
    source: usize,
) -> Option<usize> {
    if !graph.reachable.contains(&left) || !graph.reachable.contains(&right) {
        return None;
    }
    let mut common = graph.postdominators[left]
        .intersection(&graph.postdominators[right])
        .copied()
        .filter(|candidate| *candidate != source)
        .collect::<Vec<_>>();
    // The closest postdominator has the smallest postdominator set.  The
    // block id breaks equal-size ties and therefore makes reductions stable.
    common.sort_by_key(|candidate| (graph.postdominators[*candidate].len(), *candidate));
    common.into_iter().next()
}

fn collect_until_stops(
    graph: &ControlFlowGraph,
    start: usize,
    stops: &BTreeSet<usize>,
) -> BTreeSet<usize> {
    let mut result = BTreeSet::new();
    let mut pending = vec![start];
    while let Some(block_id) = pending.pop() {
        if stops.contains(&block_id) || !result.insert(block_id) {
            continue;
        }
        for successor in graph.blocks[block_id].successors.iter().rev() {
            if !stops.contains(successor) {
                pending.push(*successor);
            }
        }
    }
    result
}

fn region_is_closed(
    graph: &ControlFlowGraph,
    region: &BTreeSet<usize>,
    stops: &BTreeSet<usize>,
) -> bool {
    region.iter().all(|block_id| {
        graph.blocks[*block_id]
            .successors
            .iter()
            .all(|successor| stops.contains(successor) || region.contains(successor))
    })
}

fn region_has_external_predecessor(
    graph: &ControlFlowGraph,
    region: &BTreeSet<usize>,
    source: usize,
) -> bool {
    region.iter().any(|block_id| {
        graph.predecessors[*block_id]
            .iter()
            .any(|predecessor| *predecessor != source && !region.contains(predecessor))
    })
}

fn region_is_acyclic(
    graph: &ControlFlowGraph,
    region: &BTreeSet<usize>,
    stops: &BTreeSet<usize>,
) -> bool {
    if region.is_empty() {
        return true;
    }
    let mut indegree = BTreeMap::<usize, usize>::new();
    for block_id in region {
        indegree.insert(*block_id, 0);
    }
    for block_id in region {
        for successor in &graph.blocks[*block_id].successors {
            if region.contains(successor) {
                // A recognized natural-loop back edge is left for the nested
                // loop reducer. Other cycles are irreducible here.
                if !graph.back_edges.contains(&(*block_id, *successor)) {
                    *indegree.entry(*successor).or_default() += 1;
                }
            } else if !stops.contains(successor)
                && !graph.back_edges.contains(&(*block_id, *successor))
            {
                return false;
            }
        }
    }

    let mut pending = indegree
        .iter()
        .filter_map(|(block_id, degree)| (*degree == 0).then_some(*block_id))
        .collect::<BTreeSet<_>>();
    let mut visited = 0usize;
    while let Some(block_id) = pending.iter().next().copied() {
        pending.remove(&block_id);
        visited += 1;
        for successor in &graph.blocks[block_id].successors {
            if !region.contains(successor) || graph.back_edges.contains(&(block_id, *successor)) {
                continue;
            }
            let degree = indegree
                .get_mut(successor)
                .expect("region successor has an indegree entry");
            *degree -= 1;
            if *degree == 0 {
                pending.insert(*successor);
            }
        }
    }
    visited == region.len()
}

fn region_has_back_edge(
    graph: &ControlFlowGraph,
    source: usize,
    left: &BTreeSet<usize>,
    right: &BTreeSet<usize>,
    stop: Option<usize>,
) -> bool {
    graph.back_edges.iter().any(|(tail, head)| {
        if *tail == source {
            return Some(*head) != stop;
        }
        let side = if left.contains(tail) && left.contains(head) {
            Some(left)
        } else if right.contains(tail) && right.contains(head) {
            Some(right)
        } else {
            None
        };
        if let Some(nodes) = side {
            return graph
                .natural_loops
                .get(head)
                .map_or(true, |loop_nodes| !loop_nodes.is_subset(nodes));
        }
        if left.contains(tail) || right.contains(tail) {
            return Some(*head) != stop;
        }
        false
    })
}

fn invert_condition(value: Expr) -> Expr {
    match value {
        Expr::Not(inner) => *inner,
        value => Expr::Not(Box::new(value)),
    }
}

fn prune_labels(
    statements: &mut Vec<NativeStatement>,
    remaining_targets: &BTreeSet<u64>,
    keep_all: bool,
) {
    let mut retained = Vec::with_capacity(statements.len());
    for statement in statements.drain(..) {
        if let Some(statement) = prune_label_statement(statement, remaining_targets, keep_all) {
            retained.push(statement);
        }
    }
    *statements = retained;
}

fn prune_label_statement(
    mut statement: NativeStatement,
    remaining_targets: &BTreeSet<u64>,
    keep_all: bool,
) -> Option<NativeStatement> {
    match &mut statement {
        NativeStatement::IfElse {
            then_body,
            else_body,
            ..
        } => {
            prune_labels(then_body, remaining_targets, keep_all);
            prune_labels(else_body, remaining_targets, keep_all);
        }
        NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
            prune_labels(body, remaining_targets, keep_all);
        }
        NativeStatement::For {
            initializer,
            step,
            body,
            ..
        } => {
            if let Some(value) = initializer.take() {
                *initializer =
                    prune_label_statement(*value, remaining_targets, keep_all).map(Box::new);
            }
            if let Some(value) = step.take() {
                *step = prune_label_statement(*value, remaining_targets, keep_all).map(Box::new);
            }
            prune_labels(body, remaining_targets, keep_all);
        }
        NativeStatement::Switch { cases, default, .. } => {
            for (_, body) in cases {
                prune_labels(body, remaining_targets, keep_all);
            }
            prune_labels(default, remaining_targets, keep_all);
        }
        _ => {}
    }
    if let NativeStatement::Label(address) = statement {
        if !keep_all && !remaining_targets.contains(&address) {
            return None;
        }
    }
    Some(statement)
}

struct GraphStructurer<'a> {
    graph: &'a ControlFlowGraph,
    emitted: BTreeSet<usize>,
    consumed_edges: BTreeSet<(usize, u64)>,
    output: Vec<NativeStatement>,
}

impl<'a> GraphStructurer<'a> {
    fn new(graph: &'a ControlFlowGraph, capacity: usize) -> Self {
        Self {
            graph,
            emitted: BTreeSet::new(),
            consumed_edges: BTreeSet::new(),
            output: Vec::with_capacity(capacity),
        }
    }

    fn append_raw_block(&mut self, block_id: usize, output: &mut Vec<NativeStatement>) {
        if !self.emitted.insert(block_id) {
            return;
        }
        output.extend(self.graph.blocks[block_id].statements.iter().cloned());
    }

    fn append_prefix(&mut self, block_id: usize, output: &mut Vec<NativeStatement>) {
        if !self.emitted.insert(block_id) {
            return;
        }
        let block = &self.graph.blocks[block_id];
        output.extend(block.statements[..block.prefix_len()].iter().cloned());
    }

    fn block_target(&self, target: u64) -> Option<usize> {
        self.graph.labels.get(&target).copied()
    }

    fn if_goto_parts(&self, block_id: usize) -> Option<(Expr, u64, usize, usize)> {
        let BlockTerminator::IfGoto { condition, target } = &self.graph.blocks[block_id].terminator
        else {
            return None;
        };
        let target_id = self.block_target(*target)?;
        let fallthrough = self.graph.blocks[block_id]
            .successors
            .iter()
            .copied()
            .find(|successor| *successor != target_id)?;
        Some((condition.clone(), *target, target_id, fallthrough))
    }

    fn candidate_regions(
        &self,
        block_id: usize,
        allowed: &BTreeSet<usize>,
        stop: Option<usize>,
    ) -> Option<(usize, BTreeSet<usize>, BTreeSet<usize>, Expr, u64)> {
        if self.graph.has_indirect_goto {
            return None;
        }
        let (condition, target, target_id, fallthrough) = self.if_goto_parts(block_id)?;
        if target_id == fallthrough
            || !allowed.contains(&target_id)
            || !allowed.contains(&fallthrough)
            || self.graph.back_edges.contains(&(block_id, target_id))
        {
            return None;
        }
        let join = nearest_common_postdominator(self.graph, target_id, fallthrough, block_id)?;
        if join == block_id {
            return None;
        }
        if stop != Some(join) && !allowed.contains(&join) {
            return None;
        }

        let then_nodes = collect_until_stops(self.graph, target_id, &BTreeSet::from([join]));
        let else_nodes = collect_until_stops(self.graph, fallthrough, &BTreeSet::from([join]));
        let join_stops = BTreeSet::from([join]);
        let mut permitted_join_predecessors = then_nodes.clone();
        permitted_join_predecessors.extend(else_nodes.iter().copied());
        permitted_join_predecessors.insert(block_id);
        if self.graph.predecessors[join]
            .iter()
            .any(|predecessor| !permitted_join_predecessors.contains(predecessor))
        {
            return None;
        }
        if then_nodes.contains(&block_id)
            || else_nodes.contains(&block_id)
            || then_nodes.intersection(&else_nodes).next().is_some()
            || !then_nodes.is_subset(allowed)
            || !else_nodes.is_subset(allowed)
            || !region_is_closed(self.graph, &then_nodes, &join_stops)
            || !region_is_closed(self.graph, &else_nodes, &join_stops)
            || !region_is_acyclic(self.graph, &then_nodes, &join_stops)
            || !region_is_acyclic(self.graph, &else_nodes, &join_stops)
            || region_has_external_predecessor(self.graph, &then_nodes, block_id)
            || region_has_external_predecessor(self.graph, &else_nodes, block_id)
            || region_has_back_edge(self.graph, block_id, &then_nodes, &else_nodes, stop)
        {
            return None;
        }
        Some((join, then_nodes, else_nodes, condition, target))
    }

    fn direct_return_block(&self, block_id: usize) -> Option<Option<Expr>> {
        let block = &self.graph.blocks[block_id];
        if !matches!(&block.terminator, BlockTerminator::Return) {
            return None;
        }
        // IfReturn can carry only the return expression, not preceding side
        // effects.  Such a region remains a normal label/goto region.
        if block
            .statements
            .iter()
            .take(block.prefix_len())
            .any(|statement| !matches!(statement, NativeStatement::Label(_)))
        {
            return None;
        }
        match block.statements.last() {
            Some(NativeStatement::Return(value)) => Some(value.clone()),
            _ => None,
        }
    }

    fn direct_return_is_safe(&self, block_id: usize, source: usize) -> bool {
        let region = BTreeSet::from([block_id]);
        !region_has_external_predecessor(self.graph, &region, source)
    }

    fn direct_return_after_fallthrough_is_safe(
        &self,
        return_block: usize,
        source: usize,
        fallthrough: usize,
    ) -> bool {
        let stops = BTreeSet::from([return_block]);
        let path = collect_until_stops(self.graph, fallthrough, &stops);
        if !path
            .iter()
            .any(|block| self.graph.blocks[*block].successors.contains(&return_block))
        {
            return false;
        }
        if path.contains(&source)
            || !region_is_closed(self.graph, &path, &stops)
            || !region_is_acyclic(self.graph, &path, &stops)
        {
            return false;
        }
        let mut permitted_predecessors = path;
        permitted_predecessors.insert(source);
        self.graph.predecessors[return_block]
            .iter()
            .all(|predecessor| permitted_predecessors.contains(predecessor))
    }

    fn try_early_return(
        &mut self,
        block_id: usize,
        allowed: &BTreeSet<usize>,
        stop: Option<usize>,
        output: &mut Vec<NativeStatement>,
    ) -> Option<usize> {
        if self.graph.has_indirect_goto {
            return None;
        }
        let (condition, target, target_id, fallthrough) = self.if_goto_parts(block_id)?;
        if !allowed.contains(&target_id)
            || !allowed.contains(&fallthrough)
            || target_id == fallthrough
            || stop == Some(target_id)
            || stop == Some(fallthrough)
            || self.graph.back_edges.contains(&(block_id, target_id))
        {
            return None;
        }

        if let Some(value) = self.direct_return_block(target_id) {
            if self.direct_return_after_fallthrough_is_safe(target_id, block_id, fallthrough)
                && !self.emitted.contains(&target_id)
            {
                self.append_prefix(block_id, output);
                // The false path reaches the same return block lexically. Keep
                // that block available; only the true edge becomes IfReturn.
                output.push(NativeStatement::IfReturn { condition, value });
                self.consumed_edges.insert((block_id, target));
                return Some(fallthrough);
            }
        }

        if let Some(value) = self.direct_return_block(fallthrough) {
            if !self.direct_return_is_safe(fallthrough, block_id)
                || self.emitted.contains(&fallthrough)
                || !self.direct_return_is_safe(target_id, block_id)
            {
                return None;
            }
            self.append_prefix(block_id, output);
            output.push(NativeStatement::IfReturn {
                condition: invert_condition(condition),
                value,
            });
            self.emitted.insert(fallthrough);
            self.consumed_edges.insert((block_id, target));
            return Some(target_id);
        }
        None
    }

    fn loop_plan(
        &self,
        header: usize,
        allowed: &BTreeSet<usize>,
        stop: Option<usize>,
    ) -> Option<LoopPlan> {
        if self.graph.has_indirect_goto
            || !allowed.contains(&header)
            || self.emitted.contains(&header)
        {
            return None;
        }
        let loop_nodes = self.graph.natural_loops.get(&header)?.clone();
        if loop_nodes.is_empty() {
            return None;
        }
        if !loop_nodes.is_subset(allowed) {
            return None;
        }
        let exits = loop_nodes
            .iter()
            .flat_map(|block_id| self.graph.blocks[*block_id].successors.iter().copied())
            .filter(|successor| !loop_nodes.contains(successor))
            .collect::<BTreeSet<_>>();
        if exits.len() != 1 {
            return None;
        }
        let exit = *exits.iter().next()?;
        if stop != Some(exit) && !allowed.contains(&exit) {
            return None;
        }
        let back_tails = self
            .graph
            .back_edges
            .iter()
            .filter_map(|(tail, head)| (*head == header).then_some(*tail))
            .collect::<Vec<_>>();
        if back_tails.len() != 1 {
            return None;
        }
        let tail = back_tails[0];
        if !loop_nodes.contains(&tail) {
            return None;
        }
        let body_without_header = loop_nodes
            .iter()
            .copied()
            .filter(|block_id| *block_id != header)
            .collect::<BTreeSet<_>>();
        if body_without_header
            .iter()
            .any(|block_id| self.emitted.contains(block_id))
            || region_has_external_predecessor(self.graph, &body_without_header, header)
        {
            return None;
        }

        let stops = BTreeSet::from([header, exit]);
        if !region_is_closed(self.graph, &body_without_header, &stops)
            || !region_is_acyclic(self.graph, &body_without_header, &stops)
        {
            return None;
        }

        if let Some((condition, target, target_id, fallthrough)) = self.if_goto_parts(header) {
            if target_id == exit || fallthrough == exit {
                let body_entry = if target_id == exit {
                    fallthrough
                } else {
                    target_id
                };
                let tail_is_back_goto = matches!(
                    &self.graph.blocks[tail].terminator,
                    BlockTerminator::Goto(_)
                ) && matches!(
                    &self.graph.blocks[tail].terminator,
                    BlockTerminator::Goto(back_target)
                        if self.block_target(*back_target) == Some(header)
                );
                if body_without_header.contains(&body_entry)
                    && body_without_header.contains(&tail)
                    && tail_is_back_goto
                {
                    let reachable_body = collect_until_stops(self.graph, body_entry, &stops);
                    if reachable_body == body_without_header {
                        return Some(LoopPlan::While {
                            header,
                            body_entry,
                            exit,
                            body_nodes: body_without_header,
                            condition,
                            invert_condition: target_id == exit,
                            target,
                        });
                    }
                }
            }
        }

        let pre_tail = loop_nodes
            .iter()
            .copied()
            .filter(|block_id| *block_id != tail)
            .collect::<BTreeSet<_>>();
        let Some((condition, target, target_id, fallthrough)) = self.if_goto_parts(tail) else {
            return None;
        };
        if (tail != header && !pre_tail.contains(&header))
            || target_id != header && fallthrough != header
            || target_id == fallthrough
        {
            return None;
        }
        let do_exit = if target_id == header {
            fallthrough
        } else {
            target_id
        };
        if do_exit != exit
            || pre_tail.iter().any(|block_id| {
                self.graph.blocks[*block_id]
                    .successors
                    .iter()
                    .any(|successor| *successor == header)
            })
        {
            return None;
        }
        let pre_tail_stops = BTreeSet::from([tail, exit]);
        let reachable_body = collect_until_stops(self.graph, header, &pre_tail_stops);
        if reachable_body != pre_tail
            || !region_is_closed(self.graph, &pre_tail, &pre_tail_stops)
            || !region_is_acyclic(self.graph, &pre_tail, &pre_tail_stops)
        {
            return None;
        }
        Some(LoopPlan::DoWhile {
            header,
            tail,
            exit,
            body_nodes: pre_tail,
            condition,
            invert_condition: target_id != header,
            target,
        })
    }

    fn try_loop(
        &mut self,
        header: usize,
        allowed: &BTreeSet<usize>,
        stop: Option<usize>,
        output: &mut Vec<NativeStatement>,
    ) -> Option<usize> {
        let plan = self.loop_plan(header, allowed, stop)?;
        let emitted_before = self.emitted.clone();
        let consumed_before = self.consumed_edges.clone();
        let mut body = Vec::new();
        let (exit, condition, invert) = match &plan {
            LoopPlan::While {
                exit,
                condition,
                invert_condition,
                ..
            }
            | LoopPlan::DoWhile {
                exit,
                condition,
                invert_condition,
                ..
            } => (*exit, condition.clone(), *invert_condition),
        };

        match &plan {
            LoopPlan::While {
                header,
                body_entry,
                body_nodes,
                ..
            } => {
                self.emitted.insert(*header);
                self.emit_path(*body_entry, Some(*header), body_nodes, true, &mut body);
                if !body_nodes.iter().all(|node| self.emitted.contains(node)) {
                    self.emitted = emitted_before;
                    self.consumed_edges = consumed_before;
                    return None;
                }
                let prefix = self.graph.blocks[*header].prefix_len();
                output.extend(
                    self.graph.blocks[*header].statements[..prefix]
                        .iter()
                        .cloned(),
                );
                output.push(NativeStatement::While {
                    condition: if invert {
                        invert_condition(condition)
                    } else {
                        condition
                    },
                    body,
                });
            }
            LoopPlan::DoWhile {
                header,
                tail,
                body_nodes,
                ..
            } => {
                self.emit_path(*header, Some(*tail), body_nodes, true, &mut body);
                if !body_nodes.iter().all(|node| self.emitted.contains(node))
                    || self.emitted.contains(tail)
                {
                    self.emitted = emitted_before;
                    self.consumed_edges = consumed_before;
                    return None;
                }
                self.emitted.insert(*tail);
                let prefix = self.graph.blocks[*tail].prefix_len();
                body.extend(
                    self.graph.blocks[*tail].statements[..prefix]
                        .iter()
                        .cloned(),
                );
                output.push(NativeStatement::DoWhile {
                    body,
                    condition: if invert {
                        invert_condition(condition)
                    } else {
                        condition
                    },
                });
            }
        }
        self.consumed_edges.insert(match &plan {
            LoopPlan::While { header, target, .. } => (*header, *target),
            LoopPlan::DoWhile { tail, target, .. } => (*tail, *target),
        });
        Some(exit)
    }

    fn try_conditional(
        &mut self,
        block_id: usize,
        allowed: &BTreeSet<usize>,
        stop: Option<usize>,
        output: &mut Vec<NativeStatement>,
    ) -> Option<usize> {
        let (join, then_nodes, else_nodes, condition, target) =
            self.candidate_regions(block_id, allowed, stop)?;
        if self.emitted.contains(&block_id)
            || then_nodes.iter().any(|node| self.emitted.contains(node))
            || else_nodes.iter().any(|node| self.emitted.contains(node))
        {
            return None;
        }

        let emitted_before = self.emitted.clone();
        let consumed_before = self.consumed_edges.clone();
        let mut then_body = Vec::new();
        let mut else_body = Vec::new();
        let (_, _, target_id, fallthrough) = self.if_goto_parts(block_id)?;

        self.emitted.insert(block_id);
        self.emit_path(target_id, Some(join), &then_nodes, true, &mut then_body);
        self.emit_path(fallthrough, Some(join), &else_nodes, true, &mut else_body);
        let then_complete = then_nodes.iter().all(|node| self.emitted.contains(node));
        let else_complete = else_nodes.iter().all(|node| self.emitted.contains(node));
        if !then_complete || !else_complete {
            self.emitted = emitted_before;
            self.consumed_edges = consumed_before;
            return None;
        }

        output.extend(
            self.graph.blocks[block_id].statements[..self.graph.blocks[block_id].prefix_len()]
                .iter()
                .cloned(),
        );
        let (condition, then_body, else_body) = if then_body.is_empty() && !else_body.is_empty() {
            (invert_condition(condition), else_body, then_body)
        } else {
            (condition, then_body, else_body)
        };
        output.push(NativeStatement::IfElse {
            condition,
            then_body,
            else_body,
        });
        self.consumed_edges.insert((block_id, target));
        Some(join)
    }

    fn emit_path(
        &mut self,
        start: usize,
        stop: Option<usize>,
        allowed: &BTreeSet<usize>,
        omit_goto_to_stop: bool,
        output: &mut Vec<NativeStatement>,
    ) {
        let mut current = start;
        loop {
            if stop == Some(current)
                || self.emitted.contains(&current)
                || !allowed.contains(&current)
            {
                break;
            }

            if let Some(next) = self.try_loop(current, allowed, stop, output) {
                current = next;
                continue;
            }
            if matches!(
                &self.graph.blocks[current].terminator,
                BlockTerminator::IfGoto { .. }
            ) {
                if let Some(next) = self.try_early_return(current, allowed, stop, output) {
                    current = next;
                    continue;
                }
                if let Some(next) = self.try_conditional(current, allowed, stop, output) {
                    current = next;
                    continue;
                }
            }

            let terminator = self.graph.blocks[current].terminator.clone();
            let successors = self.graph.blocks[current].successors.clone();
            self.append_raw_block(current, output);
            match terminator {
                BlockTerminator::Goto(target) => {
                    let target_id = self.block_target(target);
                    if omit_goto_to_stop && target_id == stop {
                        let _ = output.pop();
                        self.consumed_edges.insert((current, target));
                    }
                    break;
                }
                BlockTerminator::IfGoto { target, .. } => {
                    // An unstructured conditional retains its branch edge.  We
                    // continue along only the lexical fallthrough; the target
                    // remains labelled and is emitted by the outer pass.
                    let target_id = self.block_target(target);
                    let next = successors
                        .into_iter()
                        .find(|successor| Some(*successor) != target_id);
                    match next {
                        Some(next) if Some(next) != stop && allowed.contains(&next) => {
                            current = next;
                        }
                        _ => break,
                    }
                }
                BlockTerminator::IfReturn | BlockTerminator::None => {
                    let Some(next) = successors.first().copied() else {
                        break;
                    };
                    current = next;
                }
                BlockTerminator::Return | BlockTerminator::IndirectGoto => break,
            }
        }
    }

    fn finish(mut self) -> Vec<NativeStatement> {
        let mut remaining_targets = BTreeSet::new();
        if !self.graph.has_indirect_goto {
            for (block_id, block) in self.graph.blocks.iter().enumerate() {
                match &block.terminator {
                    BlockTerminator::IfGoto { target, .. } | BlockTerminator::Goto(target) => {
                        if !self.consumed_edges.contains(&(block_id, *target)) {
                            remaining_targets.insert(*target);
                        }
                    }
                    _ => {}
                }
            }
        }
        prune_labels(
            &mut self.output,
            &remaining_targets,
            self.graph.has_indirect_goto,
        );
        self.output
    }
}

fn refine_structured_statements(statements: &mut Vec<NativeStatement>) {
    for statement in statements.iter_mut() {
        match statement {
            NativeStatement::IfElse {
                then_body,
                else_body,
                ..
            } => {
                refine_structured_statements(then_body);
                refine_structured_statements(else_body);
            }
            NativeStatement::While { body, .. } | NativeStatement::DoWhile { body, .. } => {
                refine_structured_statements(body);
            }
            NativeStatement::For {
                initializer,
                step,
                body,
                ..
            } => {
                if let Some(initializer) = initializer {
                    refine_nested_statement(initializer);
                }
                if let Some(step) = step {
                    refine_nested_statement(step);
                }
                refine_structured_statements(body);
            }
            NativeStatement::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    refine_structured_statements(body);
                }
                refine_structured_statements(default);
            }
            _ => {}
        }
    }

    for statement in statements.iter_mut() {
        if let Some(replacement) = switch_from_if_chain(statement) {
            *statement = replacement;
        }
    }

    let mut index = 0usize;
    while index + 1 < statements.len() {
        let Some(replacement) =
            for_from_initializer_and_while(&statements[index], &statements[index + 1])
        else {
            index += 1;
            continue;
        };
        statements[index] = replacement;
        statements.remove(index + 1);
        index += 1;
    }
}

fn refine_nested_statement(statement: &mut NativeStatement) {
    let mut wrapper = vec![statement.clone()];
    refine_structured_statements(&mut wrapper);
    *statement = wrapper
        .pop()
        .expect("a one-statement refinement remains one statement");
}

fn switch_from_if_chain(statement: &NativeStatement) -> Option<NativeStatement> {
    let mut current = statement;
    let mut expression = None::<Expr>;
    let mut values = BTreeSet::new();
    let mut cases = Vec::new();
    let default;
    loop {
        let NativeStatement::IfElse {
            condition,
            then_body,
            else_body,
        } = current
        else {
            return None;
        };
        let (candidate, value) = equality_case(condition)?;
        if !is_pure_expression(candidate) || !values.insert(value) {
            return None;
        }
        match &expression {
            Some(expression) if expression != candidate => return None,
            None => expression = Some(candidate.clone()),
            _ => {}
        }
        let mut case_body = then_body.clone();
        terminate_switch_case(&mut case_body);
        cases.push((value, case_body));
        if else_body.len() == 1 && matches!(else_body[0], NativeStatement::IfElse { .. }) {
            current = &else_body[0];
        } else if let [
            NativeStatement::Switch {
                expression: nested_expression,
                cases: nested_cases,
                default: nested_default,
            },
        ] = else_body.as_slice()
        {
            if expression.as_ref() != Some(nested_expression) {
                return None;
            }
            for (nested_value, nested_body) in nested_cases {
                if !values.insert(*nested_value) {
                    return None;
                }
                let mut nested_body = nested_body.clone();
                terminate_switch_case(&mut nested_body);
                cases.push((*nested_value, nested_body));
            }
            default = nested_default.clone();
            break;
        } else {
            default = else_body.clone();
            break;
        }
    }
    (cases.len() >= 2).then(|| NativeStatement::Switch {
        expression: expression.expect("a switch chain has at least one expression"),
        cases,
        default,
    })
}

fn terminate_switch_case(body: &mut Vec<NativeStatement>) {
    if !body.last().is_some_and(statement_terminates_switch_case) {
        body.push(NativeStatement::Break);
    }
}

fn statement_terminates_switch_case(statement: &NativeStatement) -> bool {
    match statement {
        NativeStatement::Break
        | NativeStatement::Continue
        | NativeStatement::Goto(_)
        | NativeStatement::IndirectGoto(_)
        | NativeStatement::Return(_) => true,
        NativeStatement::IfElse {
            then_body,
            else_body,
            ..
        } => {
            !then_body.is_empty()
                && !else_body.is_empty()
                && then_body
                    .last()
                    .is_some_and(statement_terminates_switch_case)
                && else_body
                    .last()
                    .is_some_and(statement_terminates_switch_case)
        }
        _ => false,
    }
}

fn equality_case(condition: &Expr) -> Option<(&Expr, u64)> {
    let Expr::Binary {
        op: BinaryOp::Equal,
        left,
        right,
    } = condition
    else {
        return None;
    };
    match (left.as_ref(), right.as_ref()) {
        (expression, Expr::Constant { value, .. }) => Some((expression, *value)),
        (Expr::Constant { value, .. }, expression) => Some((expression, *value)),
        _ => None,
    }
}

fn is_pure_expression(expression: &Expr) -> bool {
    match expression {
        Expr::Constant { .. }
        | Expr::Parameter { .. }
        | Expr::Register { .. }
        | Expr::Temporary { .. }
        | Expr::Global { .. } => true,
        // A field read touches memory, so it is not pure.
        Expr::Field { .. } => false,
        // An assignment is an effect, and a comma expression carries one.
        Expr::Assign { .. } | Expr::Comma(_) => false,
        Expr::Binary { left, right, .. } => is_pure_expression(left) && is_pure_expression(right),
        Expr::Not(value)
        | Expr::Neg(value)
        | Expr::BitNot(value)
        | Expr::Cast { value, .. }
        | Expr::Typed { value, .. } => is_pure_expression(value),
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => {
            is_pure_expression(condition)
                && is_pure_expression(when_true)
                && is_pure_expression(when_false)
        }
        Expr::Load { .. } | Expr::Call { .. } | Expr::Builtin { .. } => false,
    }
}

fn for_from_initializer_and_while(
    initializer: &NativeStatement,
    loop_statement: &NativeStatement,
) -> Option<NativeStatement> {
    let destination = assignment_destination(initializer)?;
    let NativeStatement::While { condition, body } = loop_statement else {
        return None;
    };
    let step = body.last()?;
    if assignment_destination(step)? != destination
        || !is_induction_step(step, destination)
        || !expression_contains(condition, destination)
        || body[..body.len() - 1]
            .iter()
            .any(statement_contains_continue)
    {
        return None;
    }
    Some(NativeStatement::For {
        initializer: Some(Box::new(initializer.clone())),
        condition: Some(condition.clone()),
        step: Some(Box::new(step.clone())),
        body: body[..body.len() - 1].to_vec(),
    })
}

fn assignment_destination(statement: &NativeStatement) -> Option<&Expr> {
    match statement {
        NativeStatement::Copy {
            destination,
            volatile: false,
            ..
        } if matches!(destination, Expr::Temporary { .. } | Expr::Register { .. }) => {
            Some(destination)
        }
        _ => None,
    }
}

fn is_induction_step(statement: &NativeStatement, destination: &Expr) -> bool {
    let NativeStatement::Copy { source, .. } = statement else {
        return false;
    };
    match source {
        Expr::Binary {
            op: BinaryOp::Add | BinaryOp::Sub,
            left,
            right,
        } => {
            (left.as_ref() == destination && matches!(right.as_ref(), Expr::Constant { .. }))
                || (matches!(
                    source,
                    Expr::Binary {
                        op: BinaryOp::Add,
                        ..
                    }
                ) && right.as_ref() == destination
                    && matches!(left.as_ref(), Expr::Constant { .. }))
        }
        _ => false,
    }
}

fn expression_contains(expression: &Expr, needle: &Expr) -> bool {
    if expression == needle {
        return true;
    }
    match expression {
        Expr::Binary { left, right, .. } => {
            expression_contains(left, needle) || expression_contains(right, needle)
        }
        Expr::Assign {
            destination,
            source,
        } => expression_contains(destination, needle) || expression_contains(source, needle),
        Expr::Comma(members) => members
            .iter()
            .any(|member| expression_contains(member, needle)),
        Expr::Not(value)
        | Expr::Neg(value)
        | Expr::BitNot(value)
        | Expr::Cast { value, .. }
        | Expr::Typed { value, .. }
        | Expr::Load { address: value, .. }
        | Expr::Field { base: value, .. } => expression_contains(value, needle),
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => {
            expression_contains(condition, needle)
                || expression_contains(when_true, needle)
                || expression_contains(when_false, needle)
        }
        Expr::Call { callee, args, .. } => {
            callee
                .as_deref()
                .is_some_and(|callee| expression_contains(callee, needle))
                || args
                    .iter()
                    .any(|argument| expression_contains(argument, needle))
        }
        Expr::Builtin { args, .. } => args
            .iter()
            .any(|argument| expression_contains(argument, needle)),
        Expr::Constant { .. }
        | Expr::Parameter { .. }
        | Expr::Register { .. }
        | Expr::Temporary { .. }
        | Expr::Global { .. } => false,
    }
}

fn statement_contains_continue(statement: &NativeStatement) -> bool {
    match statement {
        NativeStatement::Continue => true,
        NativeStatement::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body.iter().any(statement_contains_continue)
                || else_body.iter().any(statement_contains_continue)
        }
        NativeStatement::While { .. }
        | NativeStatement::DoWhile { .. }
        | NativeStatement::For { .. } => false,
        NativeStatement::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|(_, body)| body.iter().any(statement_contains_continue))
                || default.iter().any(statement_contains_continue)
        }
        _ => false,
    }
}

/// Structure a flat native statement stream using CFG facts rather than
/// source-text pattern matching.
///
/// Natural loops are reduced to `While`/`DoWhile` only when the natural-loop
/// boundary is canonical and single-entry/single-exit.  Irreducible and
/// cross-entered regions deliberately stay in explicit label/goto form.
pub(super) fn structure_graph(statements: Vec<NativeStatement>) -> Vec<NativeStatement> {
    if statements.is_empty() {
        return statements;
    }
    let graph = build_cfg(&statements);
    let mut structurer = GraphStructurer::new(&graph, statements.len());
    let reachable = graph.reachable.clone();
    for block_id in 0..graph.blocks.len() {
        if structurer.emitted.contains(&block_id) {
            continue;
        }
        if reachable.contains(&block_id) {
            let mut path = Vec::new();
            structurer.emit_path(block_id, None, &reachable, false, &mut path);
            structurer.output.extend(path);
        } else {
            let mut path = Vec::new();
            structurer.append_raw_block(block_id, &mut path);
            structurer.output.extend(path);
        }
    }
    let mut structured = structurer.finish();
    refine_structured_statements(&mut structured);
    structured
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary(name: &str) -> Expr {
        Expr::Temporary {
            name: name.to_owned(),
            width: 4,
        }
    }

    fn copy(destination: Expr, source: Expr) -> NativeStatement {
        NativeStatement::Copy {
            destination,
            source,
            width: 4,
            volatile: false,
        }
    }

    #[test]
    fn canonical_natural_loop_reduces_to_while() {
        let statements = vec![
            NativeStatement::Label(0x1000),
            NativeStatement::IfGoto {
                condition: temporary("flag"),
                target: 0x1003,
            },
            NativeStatement::Label(0x1001),
            NativeStatement::Expression(Expr::Builtin {
                name: "tick",
                args: Vec::new(),
            }),
            NativeStatement::Goto(0x1000),
            NativeStatement::Label(0x1003),
            NativeStatement::Return(None),
        ];

        let structured = structure_graph(statements);
        assert!(
            structured
                .iter()
                .any(|statement| matches!(statement, NativeStatement::While { .. })),
            "{structured:?}"
        );
        assert!(
            !structured
                .iter()
                .any(|statement| matches!(statement, NativeStatement::Goto(_))),
            "{structured:?}"
        );
    }

    #[test]
    fn equality_if_chain_refines_to_switch() {
        let selector = temporary("selector");
        let equals = |value| Expr::Binary {
            op: BinaryOp::Equal,
            left: Box::new(selector.clone()),
            right: Box::new(Expr::constant(value, 4)),
        };
        let mut statements = vec![NativeStatement::IfElse {
            condition: equals(1),
            then_body: vec![NativeStatement::Return(Some(Expr::constant(10, 4)))],
            else_body: vec![NativeStatement::IfElse {
                condition: equals(2),
                then_body: vec![NativeStatement::Return(Some(Expr::constant(20, 4)))],
                else_body: vec![NativeStatement::Return(Some(Expr::constant(30, 4)))],
            }],
        }];

        refine_structured_statements(&mut statements);
        let NativeStatement::Switch {
            expression,
            cases,
            default,
        } = &statements[0]
        else {
            panic!("not a switch: {statements:?}");
        };
        assert_eq!(expression, &selector);
        assert_eq!(
            cases.iter().map(|(value, _)| *value).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(default.len(), 1);
    }

    #[test]
    fn canonical_induction_loop_refines_to_for_but_continue_blocks_it() {
        let induction = temporary("i");
        let initializer = copy(induction.clone(), Expr::constant(0, 4));
        let condition = Expr::Binary {
            op: BinaryOp::Less,
            left: Box::new(induction.clone()),
            right: Box::new(Expr::constant(10, 4)),
        };
        let step = copy(
            induction.clone(),
            Expr::Binary {
                op: BinaryOp::Add,
                left: Box::new(induction.clone()),
                right: Box::new(Expr::constant(1, 4)),
            },
        );
        let work = NativeStatement::Expression(Expr::Builtin {
            name: "work",
            args: Vec::new(),
        });
        let mut statements = vec![
            initializer.clone(),
            NativeStatement::While {
                condition: condition.clone(),
                body: vec![work.clone(), step.clone()],
            },
        ];
        refine_structured_statements(&mut statements);
        assert!(matches!(
            statements.as_slice(),
            [NativeStatement::For { .. }]
        ));

        let mut with_continue = vec![
            initializer,
            NativeStatement::While {
                condition,
                body: vec![NativeStatement::Continue, step],
            },
        ];
        refine_structured_statements(&mut with_continue);
        assert!(matches!(
            with_continue.as_slice(),
            [NativeStatement::Copy { .. }, NativeStatement::While { .. }]
        ));
    }
}
