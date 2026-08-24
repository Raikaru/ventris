use super::*;

use ventris_lifter::Flow;

/// Stable identifier for a basic block in a [`Heritage`] result.
///
/// IDs are assigned in ascending block-start address order.  Keeping the
/// identifier independent from an address lets callers use compact maps while
/// still retaining the original address on [`HeritageBlock`].
pub(super) type BlockId = u32;

/// Version zero denotes a value entering the function without a local
/// definition.  Locally-created values and phi results start at version one.
pub(super) type Version = u32;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub(super) struct OperationId {
    pub(super) address: u64,
    pub(super) index: u32,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub(super) struct VersionedValue {
    pub(super) location: ValueKey,
    pub(super) version: Version,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct PhiInput {
    pub(super) predecessor: BlockId,
    pub(super) value: VersionedValue,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct PhiNode {
    pub(super) location: ValueKey,
    pub(super) output: VersionedValue,
    pub(super) inputs: Vec<PhiInput>,
    /// `Some` when this result corresponds to an explicit MULTIEQUAL p-code
    /// operation; `None` identifies a phi inserted by Cytron placement.
    pub(super) operation: Option<OperationId>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct MemoryPhi {
    pub(super) output: Version,
    pub(super) inputs: Vec<MemoryInput>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct MemoryInput {
    pub(super) predecessor: BlockId,
    pub(super) version: Version,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct HeritageOperation {
    pub(super) id: OperationId,
    pub(super) opcode: i32,
    pub(super) defs: Vec<VersionedValue>,
    pub(super) uses: Vec<VersionedValue>,
    /// Memory state observed before this operation.
    pub(super) memory_in: Version,
    /// Memory state after this operation.  STORE and calls advance it;
    /// ordinary operations and LOAD preserve it.
    pub(super) memory_out: Version,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct HeritageBlock {
    pub(super) id: BlockId,
    pub(super) start: u64,
    pub(super) instructions: Vec<u64>,
    pub(super) operations: Vec<HeritageOperation>,
    pub(super) phis: Vec<PhiNode>,
    pub(super) unreachable: bool,
    /// An indirect branch has no sound concrete successor without a value-set
    /// analysis.  We retain this fact instead of inventing a target edge.
    pub(super) indirect_flow: bool,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) struct Heritage {
    pub(super) entry: Option<BlockId>,
    pub(super) blocks: Vec<HeritageBlock>,
    pub(super) predecessors: BTreeMap<BlockId, BTreeSet<BlockId>>,
    pub(super) successors: BTreeMap<BlockId, BTreeSet<BlockId>>,
    pub(super) reverse_postorder: Vec<BlockId>,
    pub(super) dominators: BTreeMap<BlockId, BTreeSet<BlockId>>,
    pub(super) immediate_dominators: BTreeMap<BlockId, Option<BlockId>>,
    pub(super) dominance_frontiers: BTreeMap<BlockId, BTreeSet<BlockId>>,
    /// A single conservative memory state is used for all address spaces.  A
    /// join receives a memory phi even when no alias information is available.
    pub(super) memory_phis: BTreeMap<BlockId, MemoryPhi>,
}

#[derive(Clone)]
struct WorkOperation {
    id: OperationId,
    opcode: i32,
    output: Option<Varnode>,
    inputs: Vec<Varnode>,
    record: HeritageOperation,
}

#[derive(Clone)]
struct WorkPhi {
    location: ValueKey,
    operation: Option<OperationId>,
    output: Option<VersionedValue>,
}

#[derive(Clone)]
struct WorkMemoryPhi {
    output: Option<Version>,
}

#[derive(Clone)]
struct WorkBlock {
    id: BlockId,
    start: u64,
    instructions: Vec<u64>,
    operations: Vec<WorkOperation>,
    phis: BTreeMap<ValueKey, WorkPhi>,
    memory_phi: Option<WorkMemoryPhi>,
    indirect_flow: bool,
}

#[derive(Default)]
struct Graph {
    blocks: Vec<WorkBlock>,
    predecessors: BTreeMap<BlockId, BTreeSet<BlockId>>,
    successors: BTreeMap<BlockId, BTreeSet<BlockId>>,
    entry: Option<BlockId>,
    actual_reachable: BTreeSet<BlockId>,
}

/// Build the CFG, dominance data, Cytron phi placement, and deterministic SSA
/// versions for one lifted function.
///
/// The pass intentionally keeps exact `(space, offset, width)` locations as
/// distinct keys.  In particular, a byte view of a register never aliases a
/// full-register definition here; later type/alias passes can add that fact
/// explicitly without invalidating these SSA identities.
pub(super) fn build_heritage(function: &NativeFunction) -> Heritage {
    let mut graph = discover_graph(function);
    if graph.blocks.is_empty() {
        return Heritage {
            entry: None,
            blocks: Vec::new(),
            predecessors: BTreeMap::new(),
            successors: BTreeMap::new(),
            reverse_postorder: Vec::new(),
            dominators: BTreeMap::new(),
            immediate_dominators: BTreeMap::new(),
            dominance_frontiers: BTreeMap::new(),
            memory_phis: BTreeMap::new(),
        };
    }

    let starts = traversal_starts(graph.entry, &graph.predecessors, &graph.successors);
    let reverse_postorder = make_reverse_postorder(&starts, &graph.successors);
    let roots = starts.clone();
    let effective_predecessors = effective_predecessors(&roots, &graph.predecessors);
    let dominators = compute_dominators(&reverse_postorder, &roots, &effective_predecessors);
    let immediate_dominators = compute_immediate_dominators(&dominators);
    let rename_roots = rename_roots(graph.entry, &immediate_dominators);
    let dominance_frontiers = compute_dominance_frontiers(
        &graph.blocks,
        &effective_predecessors,
        &immediate_dominators,
    );
    let dominator_children = build_dominator_children(&immediate_dominators);

    let definition_sites = collect_definition_sites(&graph.blocks);
    seed_explicit_phis(&mut graph.blocks);
    place_phis(&mut graph.blocks, &definition_sites, &dominance_frontiers);
    place_memory_phis(&mut graph.blocks, &effective_predecessors);

    let mut rename_state = RenameState {
        blocks: &mut graph.blocks,
        successors: &graph.successors,
        children: &dominator_children,
        value_stacks: BTreeMap::new(),
        next_values: BTreeMap::new(),
        memory_stack: Vec::new(),
        next_memory: 1,
        edge_values: BTreeMap::new(),
        edge_memory: BTreeMap::new(),
    };
    for root in rename_roots.iter().copied() {
        rename_block(&mut rename_state, root);
    }

    let edge_values = rename_state.edge_values.clone();
    let edge_memory = rename_state.edge_memory.clone();
    drop(rename_state);
    finalize_multiequal_uses(&mut graph.blocks, &graph.predecessors, &edge_values);

    let blocks: Vec<HeritageBlock> = graph
        .blocks
        .iter()
        .map(|block| HeritageBlock {
            id: block.id,
            start: block.start,
            instructions: block.instructions.clone(),
            operations: block
                .operations
                .iter()
                .map(|operation| operation.record.clone())
                .collect(),
            phis: block
                .phis
                .values()
                .map(|phi| PhiNode {
                    location: phi.location,
                    output: phi
                        .output
                        .expect("every heritage phi is visited by a rename root"),
                    inputs: finalized_phi_inputs(
                        block.id,
                        phi,
                        &block.operations,
                        &graph.predecessors,
                        &edge_values,
                    ),
                    operation: phi.operation,
                })
                .collect(),
            unreachable: !graph.actual_reachable.contains(&block.id),
            indirect_flow: block.indirect_flow,
        })
        .collect();

    let memory_phis = graph
        .blocks
        .iter()
        .filter_map(|block| {
            let phi = block.memory_phi.as_ref()?;
            let output = phi
                .output
                .expect("every memory phi is visited by a rename root");
            let inputs = effective_predecessors
                .get(&block.id)
                .into_iter()
                .flat_map(|preds| preds.iter())
                .map(|predecessor| MemoryInput {
                    predecessor: *predecessor,
                    version: edge_memory
                        .get(&(*predecessor, block.id))
                        .copied()
                        .unwrap_or(0),
                })
                .collect();
            Some((block.id, MemoryPhi { output, inputs }))
        })
        .collect();

    Heritage {
        entry: graph.entry,
        blocks,
        predecessors: graph.predecessors,
        successors: graph.successors,
        reverse_postorder,
        dominators,
        immediate_dominators,
        dominance_frontiers,
        memory_phis,
    }
}

fn discover_graph(function: &NativeFunction) -> Graph {
    let addresses: Vec<u64> = function.instructions.keys().copied().collect();
    if addresses.is_empty() {
        return Graph::default();
    }

    let address_set: BTreeSet<u64> = addresses.iter().copied().collect();
    let mut raw_successors: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for address in addresses.iter().copied() {
        raw_successors.entry(address).or_default();
    }
    for &(source, target) in &function.edges {
        if address_set.contains(&source) && address_set.contains(&target) {
            raw_successors.entry(source).or_default().insert(target);
        }
    }

    let mut leaders = BTreeSet::new();
    if address_set.contains(&function.entry) {
        leaders.insert(function.entry);
    }
    let mut indirect_addresses = BTreeSet::new();
    let mut terminating_addresses = BTreeSet::new();

    for (position, address) in addresses.iter().copied().enumerate() {
        let instruction = function
            .instructions
            .get(&address)
            .expect("instruction address came from the function map");
        match &instruction.flow {
            Flow::FallThrough(target) => {
                add_direct_successor(&mut raw_successors, &address_set, address, *target);
            }
            Flow::Conditional {
                target,
                fallthrough,
            } => {
                add_direct_successor(&mut raw_successors, &address_set, address, *target);
                add_direct_successor(&mut raw_successors, &address_set, address, *fallthrough);
                terminating_addresses.insert(address);
            }
            Flow::Jump(target) => {
                add_direct_successor(&mut raw_successors, &address_set, address, *target);
                terminating_addresses.insert(address);
            }
            Flow::Call { fallthrough, .. } => {
                // A returning call is not a CFG terminator.  Its p-code call
                // operation still receives a memory barrier during renaming.
                add_direct_successor(&mut raw_successors, &address_set, address, *fallthrough);
            }
            Flow::Return => {
                terminating_addresses.insert(address);
            }
        }

        for operation in &instruction.pcode.ops {
            match operation.opcode {
                op::BRANCH => {
                    terminating_addresses.insert(address);
                    if let Some(target) = operation
                        .inputs
                        .first()
                        .and_then(|value| branch_target(value, &address_set))
                    {
                        add_direct_successor(&mut raw_successors, &address_set, address, target);
                    } else if !flow_has_direct_branch(&instruction.flow) {
                        indirect_addresses.insert(address);
                    }
                }
                op::CBRANCH => {
                    terminating_addresses.insert(address);
                    if let Some(target) = operation
                        .inputs
                        .first()
                        .and_then(|value| branch_target(value, &address_set))
                    {
                        add_direct_successor(&mut raw_successors, &address_set, address, target);
                    } else if !flow_has_direct_branch(&instruction.flow) {
                        indirect_addresses.insert(address);
                    }
                    if instruction.flow.fallthrough().is_none() {
                        if let Some(next) = addresses.get(position + 1).copied() {
                            add_direct_successor(&mut raw_successors, &address_set, address, next);
                        }
                    }
                }
                op::BRANCHIND => {
                    terminating_addresses.insert(address);
                    indirect_addresses.insert(address);
                }
                op::RETURN => {
                    terminating_addresses.insert(address);
                }
                _ => {}
            }
        }
    }

    let predecessor_counts =
        raw_successors
            .values()
            .fold(BTreeMap::<u64, usize>::new(), |mut counts, successors| {
                for target in successors {
                    *counts.entry(*target).or_default() += 1;
                }
                counts
            });
    for (position, source) in addresses.iter().copied().enumerate() {
        let natural_next = addresses.get(position + 1).copied();
        for target in raw_successors
            .get(&source)
            .into_iter()
            .flat_map(|successors| successors.iter().copied())
        {
            if Some(target) != natural_next
                || terminating_addresses.contains(&source)
                || predecessor_counts.get(&target).copied().unwrap_or(0) > 1
            {
                leaders.insert(target);
            }
        }
        if let Some(next) = natural_next {
            if terminating_addresses.contains(&source)
                || !raw_successors
                    .get(&source)
                    .is_some_and(|successors| successors.contains(&next))
            {
                leaders.insert(next);
            }
        }
    }
    // A malformed or externally-created NativeFunction may omit its entry from
    // the instruction map.  It still receives a deterministic block partition.
    if leaders.is_empty() {
        leaders.insert(addresses[0]);
    }

    let mut drafts: Vec<(u64, Vec<u64>, bool)> = Vec::new();
    for address in addresses.iter().copied() {
        if drafts.is_empty() || leaders.contains(&address) {
            drafts.push((address, Vec::new(), false));
        }
        let draft = drafts
            .last_mut()
            .expect("a block draft is created before its first instruction");
        draft.1.push(address);
        if indirect_addresses.contains(&address) {
            draft.2 = true;
        }
    }

    let mut block_for_address = BTreeMap::new();
    let mut blocks = Vec::with_capacity(drafts.len());
    for (id, (start, instructions, indirect_flow)) in drafts.into_iter().enumerate() {
        let id = id as BlockId;
        for address in instructions.iter().copied() {
            block_for_address.insert(address, id);
        }
        let mut operations = Vec::new();
        for address in instructions.iter().copied() {
            let instruction = function
                .instructions
                .get(&address)
                .expect("block instruction came from the function map");
            for (index, operation) in instruction.pcode.ops.iter().enumerate() {
                let id = OperationId {
                    address,
                    index: index as u32,
                };
                operations.push(WorkOperation {
                    id,
                    opcode: operation.opcode,
                    output: operation.output,
                    inputs: operation.inputs.clone(),
                    record: HeritageOperation {
                        id,
                        opcode: operation.opcode,
                        defs: Vec::new(),
                        uses: Vec::new(),
                        memory_in: 0,
                        memory_out: 0,
                    },
                });
            }
        }
        blocks.push(WorkBlock {
            id,
            start,
            instructions,
            operations,
            phis: BTreeMap::new(),
            memory_phi: None,
            indirect_flow,
        });
    }

    let mut predecessors: BTreeMap<BlockId, BTreeSet<BlockId>> = blocks
        .iter()
        .map(|block| (block.id, BTreeSet::new()))
        .collect();
    let mut successors: BTreeMap<BlockId, BTreeSet<BlockId>> = blocks
        .iter()
        .map(|block| (block.id, BTreeSet::new()))
        .collect();
    for (source, targets) in &raw_successors {
        let Some(&source_block) = block_for_address.get(source) else {
            continue;
        };
        for target in targets {
            let Some(&target_block) = block_for_address.get(target) else {
                continue;
            };
            successors
                .get_mut(&source_block)
                .expect("every block has a successor set")
                .insert(target_block);
            predecessors
                .get_mut(&target_block)
                .expect("every block has a predecessor set")
                .insert(source_block);
        }
    }

    let entry = block_for_address.get(&function.entry).copied();
    let actual_reachable = entry
        .map(|start| reachable_blocks(start, &successors))
        .unwrap_or_default();
    Graph {
        blocks,
        predecessors,
        successors,
        entry,
        actual_reachable,
    }
}

fn add_direct_successor(
    successors: &mut BTreeMap<u64, BTreeSet<u64>>,
    addresses: &BTreeSet<u64>,
    source: u64,
    target: u64,
) {
    if addresses.contains(&target) {
        successors.entry(source).or_default().insert(target);
    }
}

fn branch_target(value: &Varnode, addresses: &BTreeSet<u64>) -> Option<u64> {
    if value.space == ventris_lifter::CONST_SPACE || addresses.contains(&value.offset) {
        Some(value.offset)
    } else {
        None
    }
}

fn flow_has_direct_branch(flow: &Flow) -> bool {
    matches!(flow, Flow::Conditional { .. } | Flow::Jump(_))
}

fn reachable_blocks(
    start: BlockId,
    successors: &BTreeMap<BlockId, BTreeSet<BlockId>>,
) -> BTreeSet<BlockId> {
    let mut reached = BTreeSet::new();
    let mut pending = vec![start];
    while let Some(block) = pending.pop() {
        if !reached.insert(block) {
            continue;
        }
        if let Some(next) = successors.get(&block) {
            pending.extend(next.iter().rev().copied());
        }
    }
    reached
}

fn traversal_starts(
    entry: Option<BlockId>,
    predecessors: &BTreeMap<BlockId, BTreeSet<BlockId>>,
    successors: &BTreeMap<BlockId, BTreeSet<BlockId>>,
) -> Vec<BlockId> {
    let mut starts = Vec::new();
    if let Some(entry) = entry {
        starts.push(entry);
    }
    for block in predecessors.keys().copied() {
        if Some(block) != entry && predecessors.get(&block).is_some_and(BTreeSet::is_empty) {
            starts.push(block);
        }
    }

    let mut covered = BTreeSet::new();
    for start in starts.iter().copied() {
        covered.extend(reachable_blocks(start, successors));
    }
    for block in predecessors.keys().copied() {
        if !covered.contains(&block) {
            starts.push(block);
            covered.extend(reachable_blocks(block, successors));
        }
    }
    starts
}

fn make_reverse_postorder(
    starts: &[BlockId],
    successors: &BTreeMap<BlockId, BTreeSet<BlockId>>,
) -> Vec<BlockId> {
    let mut visited = BTreeSet::new();
    let mut postorder = Vec::new();
    for start in starts.iter().copied() {
        let mut pending = vec![(start, false)];
        while let Some((block, expanded)) = pending.pop() {
            if expanded {
                postorder.push(block);
                continue;
            }
            if !visited.insert(block) {
                continue;
            }
            pending.push((block, true));
            if let Some(next) = successors.get(&block) {
                for successor in next.iter().rev().copied() {
                    if !visited.contains(&successor) {
                        pending.push((successor, false));
                    }
                }
            }
        }
    }
    postorder.into_iter().rev().collect()
}

fn effective_predecessors(
    roots: &[BlockId],
    predecessors: &BTreeMap<BlockId, BTreeSet<BlockId>>,
) -> BTreeMap<BlockId, BTreeSet<BlockId>> {
    let root_set: BTreeSet<BlockId> = roots.iter().copied().collect();
    predecessors
        .iter()
        .map(|(block, preds)| {
            let effective = if root_set.contains(block) {
                BTreeSet::new()
            } else {
                preds.clone()
            };
            (*block, effective)
        })
        .collect()
}

fn compute_dominators(
    reverse_postorder: &[BlockId],
    roots: &[BlockId],
    predecessors: &BTreeMap<BlockId, BTreeSet<BlockId>>,
) -> BTreeMap<BlockId, BTreeSet<BlockId>> {
    let all: BTreeSet<BlockId> = predecessors.keys().copied().collect();
    let root_set: BTreeSet<BlockId> = roots.iter().copied().collect();
    let mut dominators = BTreeMap::new();
    for block in all.iter().copied() {
        if root_set.contains(&block) {
            dominators.insert(block, BTreeSet::from([block]));
        } else {
            dominators.insert(block, all.clone());
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for block in reverse_postorder.iter().copied() {
            if root_set.contains(&block) {
                continue;
            }
            let Some(preds) = predecessors.get(&block) else {
                continue;
            };
            let mut next: Option<BTreeSet<BlockId>> = None;
            for predecessor in preds.iter().copied() {
                let Some(pred_dominators) = dominators.get(&predecessor) else {
                    continue;
                };
                next = Some(match next {
                    None => pred_dominators.clone(),
                    Some(current) => current.intersection(pred_dominators).copied().collect(),
                });
            }
            let mut candidate = next.unwrap_or_default();
            candidate.insert(block);
            if dominators.get(&block) != Some(&candidate) {
                dominators.insert(block, candidate);
                changed = true;
            }
        }
    }
    dominators
}

fn compute_immediate_dominators(
    dominators: &BTreeMap<BlockId, BTreeSet<BlockId>>,
) -> BTreeMap<BlockId, Option<BlockId>> {
    let mut immediate = BTreeMap::new();
    for block in dominators.keys().copied() {
        let Some(dom_set) = dominators.get(&block) else {
            continue;
        };
        let strict: BTreeSet<BlockId> = dom_set
            .iter()
            .copied()
            .filter(|candidate| *candidate != block)
            .collect();
        let idom = strict.iter().copied().find(|candidate| {
            strict
                .iter()
                .all(|other| *other == *candidate || dominators[candidate].contains(other))
        });
        immediate.insert(block, idom);
    }
    immediate
}

fn rename_roots(
    entry: Option<BlockId>,
    immediate_dominators: &BTreeMap<BlockId, Option<BlockId>>,
) -> Vec<BlockId> {
    let mut roots: Vec<BlockId> = immediate_dominators
        .iter()
        .filter_map(|(block, parent)| parent.is_none().then_some(*block))
        .collect();
    if let Some(entry) = entry {
        if let Some(position) = roots.iter().position(|block| *block == entry) {
            roots.remove(position);
        }
        roots.insert(0, entry);
    }
    roots
}

fn compute_dominance_frontiers(
    blocks: &[WorkBlock],
    predecessors: &BTreeMap<BlockId, BTreeSet<BlockId>>,
    immediate_dominators: &BTreeMap<BlockId, Option<BlockId>>,
) -> BTreeMap<BlockId, BTreeSet<BlockId>> {
    let mut frontiers: BTreeMap<BlockId, BTreeSet<BlockId>> = blocks
        .iter()
        .map(|block| (block.id, BTreeSet::new()))
        .collect();
    for block in blocks.iter().map(|block| block.id) {
        let Some(preds) = predecessors.get(&block) else {
            continue;
        };
        if preds.len() < 2 {
            continue;
        }
        let stop = immediate_dominators.get(&block).copied().flatten();
        for predecessor in preds.iter().copied() {
            let mut runner = predecessor;
            while Some(runner) != stop {
                frontiers
                    .get_mut(&runner)
                    .expect("every block has a frontier")
                    .insert(block);
                let Some(next) = immediate_dominators.get(&runner).copied().flatten() else {
                    break;
                };
                runner = next;
            }
        }
    }
    frontiers
}

fn build_dominator_children(
    immediate_dominators: &BTreeMap<BlockId, Option<BlockId>>,
) -> BTreeMap<BlockId, BTreeSet<BlockId>> {
    let mut children: BTreeMap<BlockId, BTreeSet<BlockId>> = immediate_dominators
        .keys()
        .copied()
        .map(|block| (block, BTreeSet::new()))
        .collect();
    for (block, parent) in immediate_dominators {
        if let Some(parent) = parent {
            children
                .get_mut(parent)
                .expect("an immediate dominator is a known block")
                .insert(*block);
        }
    }
    children
}

fn collect_definition_sites(blocks: &[WorkBlock]) -> BTreeMap<ValueKey, BTreeSet<BlockId>> {
    let mut sites: BTreeMap<ValueKey, BTreeSet<BlockId>> = BTreeMap::new();
    for block in blocks {
        for operation in &block.operations {
            let Some(output) = operation.output else {
                continue;
            };
            if let Some(key) = location_key(output) {
                sites.entry(key).or_default().insert(block.id);
            }
        }
    }
    sites
}

fn seed_explicit_phis(blocks: &mut [WorkBlock]) {
    for block in blocks {
        for operation in &block.operations {
            if operation.opcode != op::MULTIEQUAL {
                continue;
            }
            let Some(output) = operation.output.and_then(location_key) else {
                continue;
            };
            let entry = block.phis.entry(output).or_insert_with(|| WorkPhi {
                location: output,
                operation: None,
                output: None,
            });
            entry.operation = Some(operation.id);
        }
    }
}

fn place_phis(
    blocks: &mut [WorkBlock],
    definition_sites: &BTreeMap<ValueKey, BTreeSet<BlockId>>,
    frontiers: &BTreeMap<BlockId, BTreeSet<BlockId>>,
) {
    for (location, sites) in definition_sites {
        let mut work: Vec<BlockId> = sites.iter().copied().collect();
        let mut queued: BTreeSet<BlockId> = sites.clone();
        let mut placed: BTreeSet<BlockId> = blocks
            .iter()
            .filter(|block| block.phis.contains_key(location))
            .map(|block| block.id)
            .collect();
        while let Some(block) = work.pop() {
            let Some(frontier) = frontiers.get(&block) else {
                continue;
            };
            for merge in frontier.iter().copied() {
                if !placed.insert(merge) {
                    continue;
                }
                let target = blocks
                    .get_mut(merge as usize)
                    .expect("block IDs index the block vector");
                target.phis.entry(*location).or_insert_with(|| WorkPhi {
                    location: *location,
                    operation: None,
                    output: None,
                });
                if queued.insert(merge) {
                    work.push(merge);
                }
            }
        }
    }
}

fn place_memory_phis(
    blocks: &mut [WorkBlock],
    predecessors: &BTreeMap<BlockId, BTreeSet<BlockId>>,
) {
    for block in blocks {
        if predecessors
            .get(&block.id)
            .is_some_and(|preds| preds.len() > 1)
        {
            block.memory_phi = Some(WorkMemoryPhi { output: None });
        }
    }
}

struct RenameState<'a> {
    blocks: &'a mut [WorkBlock],
    successors: &'a BTreeMap<BlockId, BTreeSet<BlockId>>,
    children: &'a BTreeMap<BlockId, BTreeSet<BlockId>>,
    value_stacks: BTreeMap<ValueKey, Vec<Version>>,
    next_values: BTreeMap<ValueKey, Version>,
    memory_stack: Vec<Version>,
    next_memory: Version,
    edge_values: BTreeMap<(BlockId, BlockId, ValueKey), Version>,
    edge_memory: BTreeMap<(BlockId, BlockId), Version>,
}

fn rename_block(state: &mut RenameState<'_>, block_id: BlockId) {
    let phi_locations: Vec<ValueKey> = state.blocks[block_id as usize]
        .phis
        .keys()
        .copied()
        .collect();
    for location in phi_locations.iter().copied() {
        let version = allocate_value_version(state, location);
        state
            .value_stacks
            .entry(location)
            .or_default()
            .push(version);
        state.blocks[block_id as usize]
            .phis
            .get_mut(&location)
            .expect("phi location came from this block")
            .output = Some(VersionedValue { location, version });
    }

    let memory_phi = state.blocks[block_id as usize]
        .memory_phi
        .as_ref()
        .is_some();
    let mut memory = state.memory_stack.last().copied().unwrap_or(0);
    if memory_phi {
        memory = allocate_memory_version(state);
        state.blocks[block_id as usize]
            .memory_phi
            .as_mut()
            .expect("memory phi was checked above")
            .output = Some(memory);
    }
    // Keep the block's post-store/call state visible to all dominator
    // children.  A memory phi is only the entry value; the frame itself must
    // remain live until those children have supplied their edge snapshots.
    state.memory_stack.push(memory);
    let mut pushed_values = Vec::new();

    let operation_count = state.blocks[block_id as usize].operations.len();
    for index in 0..operation_count {
        let (opcode, operation_id, inputs, output) = {
            let operation = &state.blocks[block_id as usize].operations[index];
            (
                operation.opcode,
                operation.id,
                operation.inputs.clone(),
                operation.output,
            )
        };
        let is_multiequal = opcode == op::MULTIEQUAL;
        let uses = if is_multiequal {
            inputs
                .iter()
                .filter_map(|input| {
                    location_key(*input).map(|location| VersionedValue {
                        location,
                        version: 0,
                    })
                })
                .collect()
        } else {
            inputs
                .iter()
                .filter_map(|input| {
                    let location = location_key(*input)?;
                    Some(VersionedValue {
                        location,
                        version: current_value_version(&state.value_stacks, location),
                    })
                })
                .collect()
        };
        let mut defs = Vec::new();
        if let Some(output) = output.and_then(location_key) {
            let version = if is_multiequal {
                state.blocks[block_id as usize]
                    .phis
                    .get(&output)
                    .and_then(|phi| phi.output)
                    .expect("MULTIEQUAL output has a seeded heritage phi")
                    .version
            } else {
                let version = allocate_value_version(state, output);
                state.value_stacks.entry(output).or_default().push(version);
                pushed_values.push(output);
                version
            };
            defs.push(VersionedValue {
                location: output,
                version,
            });
        }
        let memory_in = memory;
        let memory_out = if matches!(opcode, op::STORE | op::CALL | op::CALLIND | op::CALLOTHER) {
            memory = allocate_memory_version(state);
            memory
        } else {
            memory
        };
        *state
            .memory_stack
            .last_mut()
            .expect("every renamed block owns a memory frame") = memory;
        let record = &mut state.blocks[block_id as usize].operations[index].record;
        record.defs = defs;
        record.uses = uses;
        record.memory_in = memory_in;
        record.memory_out = memory_out;

        // Keep the operation identity live in the record even though the
        // p-code operation itself is owned by the lifting result.
        debug_assert_eq!(record.id, operation_id);
    }

    let successors: Vec<BlockId> = state
        .successors
        .get(&block_id)
        .into_iter()
        .flat_map(|successors| successors.iter().copied())
        .collect();
    for successor in successors {
        let phi_locations: Vec<ValueKey> = state.blocks[successor as usize]
            .phis
            .keys()
            .copied()
            .collect();
        for location in phi_locations {
            state.edge_values.insert(
                (block_id, successor, location),
                current_value_version(&state.value_stacks, location),
            );
        }
        if state.blocks[successor as usize].memory_phi.is_some() {
            state.edge_memory.insert((block_id, successor), memory);
        }
    }

    let children: Vec<BlockId> = state
        .children
        .get(&block_id)
        .into_iter()
        .flat_map(|children| children.iter().copied())
        .collect();
    for child in children {
        rename_block(state, child);
    }

    for location in pushed_values.into_iter().rev() {
        state
            .value_stacks
            .get_mut(&location)
            .expect("a pushed value has a value stack")
            .pop();
    }
    for location in phi_locations.into_iter().rev() {
        state
            .value_stacks
            .get_mut(&location)
            .expect("a pushed phi has a value stack")
            .pop();
    }
    state
        .memory_stack
        .pop()
        .expect("every renamed block owns a memory frame");
}

fn allocate_value_version(state: &mut RenameState<'_>, location: ValueKey) -> Version {
    let next = state.next_values.entry(location).or_insert(1);
    let version = *next;
    *next = next.saturating_add(1);
    version
}

fn current_value_version(stacks: &BTreeMap<ValueKey, Vec<Version>>, location: ValueKey) -> Version {
    stacks
        .get(&location)
        .and_then(|versions| versions.last().copied())
        .unwrap_or(0)
}

fn allocate_memory_version(state: &mut RenameState<'_>) -> Version {
    let version = state.next_memory;
    state.next_memory = state.next_memory.saturating_add(1);
    version
}

fn finalize_multiequal_uses(
    blocks: &mut [WorkBlock],
    predecessors: &BTreeMap<BlockId, BTreeSet<BlockId>>,
    edge_values: &BTreeMap<(BlockId, BlockId, ValueKey), Version>,
) {
    for block in blocks {
        let pred_list: Vec<BlockId> = predecessors
            .get(&block.id)
            .into_iter()
            .flat_map(|preds| preds.iter().copied())
            .collect();
        for operation in &mut block.operations {
            if operation.opcode != op::MULTIEQUAL {
                continue;
            }
            operation.record.uses = operation
                .inputs
                .iter()
                .enumerate()
                .filter_map(|(index, input)| {
                    let location = location_key(*input)?;
                    let version = pred_list
                        .get(index)
                        .and_then(|predecessor| {
                            edge_values.get(&(*predecessor, block.id, location))
                        })
                        .copied()
                        .unwrap_or(0);
                    Some(VersionedValue { location, version })
                })
                .collect();
        }
    }
}

fn finalized_phi_inputs(
    block_id: BlockId,
    phi: &WorkPhi,
    operations: &[WorkOperation],
    predecessors: &BTreeMap<BlockId, BTreeSet<BlockId>>,
    edge_values: &BTreeMap<(BlockId, BlockId, ValueKey), Version>,
) -> Vec<PhiInput> {
    let explicit_inputs = phi.operation.and_then(|operation_id| {
        operations
            .iter()
            .find(|operation| operation.id == operation_id)
            .map(|operation| operation.inputs.clone())
    });
    predecessors
        .get(&block_id)
        .into_iter()
        .flat_map(|preds| preds.iter())
        .enumerate()
        .map(|(index, predecessor)| {
            let location = explicit_inputs
                .as_ref()
                .and_then(|inputs| inputs.get(index).copied())
                .and_then(location_key)
                .unwrap_or(phi.location);
            PhiInput {
                predecessor: *predecessor,
                value: VersionedValue {
                    location,
                    version: edge_values
                        .get(&(*predecessor, block_id, location))
                        .copied()
                        .unwrap_or(0),
                },
            }
        })
        .collect()
}

fn location_key(value: Varnode) -> Option<ValueKey> {
    (value.space != ventris_lifter::CONST_SPACE).then(|| ValueKey::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{Flow, LiftedInstruction};
    use ventris_pcode::{InstPcode, PcodeOp};

    fn instruction(address: u64, flow: Flow, ops: Vec<PcodeOp>) -> LiftedInstruction {
        LiftedInstruction {
            address,
            bytes: vec![0],
            pcode: InstPcode {
                len: 1,
                space: ventris_lifter::RAM_SPACE,
                offset: address,
                ops,
            },
            flow,
            embedded_delay_slot_bytes: 0,
        }
    }

    fn function(
        entry: u64,
        instructions: impl IntoIterator<Item = LiftedInstruction>,
    ) -> NativeFunction {
        NativeFunction {
            entry,
            instructions: instructions
                .into_iter()
                .map(|instruction| (instruction.address, instruction))
                .collect(),
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        }
    }

    #[test]
    fn straight_line_fallthroughs_remain_one_basic_block() {
        let value = Varnode::new(ventris_lifter::REGISTER_SPACE, 0, 4);
        let function = function(
            0x1000,
            [
                instruction(
                    0x1000,
                    Flow::FallThrough(0x1001),
                    vec![PcodeOp::new(
                        op::COPY,
                        Some(value),
                        vec![Varnode::new(ventris_lifter::CONST_SPACE, 1, 4)],
                    )],
                ),
                instruction(
                    0x1001,
                    Flow::FallThrough(0x1002),
                    vec![PcodeOp::new(op::INT_ADD, Some(value), vec![value, value])],
                ),
                instruction(
                    0x1002,
                    Flow::Return,
                    vec![PcodeOp::new(op::RETURN, None, vec![value])],
                ),
            ],
        );

        let heritage = build_heritage(&function);
        assert_eq!(heritage.blocks.len(), 1);
        assert_eq!(
            heritage.blocks[0].instructions,
            vec![0x1000, 0x1001, 0x1002]
        );
    }

    #[test]
    fn diamond_places_phi_with_predecessor_versions() {
        let value = Varnode::new(ventris_lifter::REGISTER_SPACE, 0, 4);
        let condition = Varnode::new(ventris_lifter::REGISTER_SPACE, 4, 1);
        let one = Varnode::new(ventris_lifter::CONST_SPACE, 1, 4);
        let two = Varnode::new(ventris_lifter::CONST_SPACE, 2, 4);
        let target = Varnode::new(ventris_lifter::CONST_SPACE, 0x1002, 8);
        let function = function(
            0x1000,
            [
                instruction(
                    0x1000,
                    Flow::Conditional {
                        target: 0x1002,
                        fallthrough: 0x1001,
                    },
                    vec![PcodeOp::new(op::CBRANCH, None, vec![target, condition])],
                ),
                instruction(
                    0x1001,
                    Flow::Jump(0x1003),
                    vec![PcodeOp::new(op::COPY, Some(value), vec![one])],
                ),
                instruction(
                    0x1002,
                    Flow::Jump(0x1003),
                    vec![PcodeOp::new(op::COPY, Some(value), vec![two])],
                ),
                instruction(
                    0x1003,
                    Flow::Return,
                    vec![PcodeOp::new(op::RETURN, None, vec![value])],
                ),
            ],
        );

        let heritage = build_heritage(&function);
        let join = heritage
            .blocks
            .iter()
            .find(|block| block.start == 0x1003)
            .unwrap();
        let phi = join
            .phis
            .iter()
            .find(|phi| phi.location == ValueKey::from(value))
            .unwrap();
        assert_eq!(phi.inputs.len(), 2);
        assert!(phi.inputs.iter().all(|input| input.value.version != 0));
        assert_ne!(phi.inputs[0].value.version, phi.inputs[1].value.version);
        assert_ne!(phi.output.version, phi.inputs[0].value.version);
        assert_ne!(phi.output.version, phi.inputs[1].value.version);
    }

    #[test]
    fn loop_header_receives_value_and_memory_phis() {
        let value = Varnode::new(ventris_lifter::REGISTER_SPACE, 0, 4);
        let condition = Varnode::new(ventris_lifter::REGISTER_SPACE, 4, 1);
        let address = Varnode::new(ventris_lifter::CONST_SPACE, 0x2000, 8);
        let ram = Varnode::new(
            ventris_lifter::CONST_SPACE,
            ventris_lifter::RAM_SPACE as u64,
            4,
        );
        let target = Varnode::new(ventris_lifter::CONST_SPACE, 0x1003, 8);
        let function = function(
            0x1000,
            [
                instruction(
                    0x1000,
                    Flow::FallThrough(0x1001),
                    vec![PcodeOp::new(
                        op::COPY,
                        Some(value),
                        vec![Varnode::new(ventris_lifter::CONST_SPACE, 0, 4)],
                    )],
                ),
                instruction(
                    0x1001,
                    Flow::Conditional {
                        target: 0x1003,
                        fallthrough: 0x1002,
                    },
                    vec![PcodeOp::new(op::CBRANCH, None, vec![target, condition])],
                ),
                instruction(
                    0x1002,
                    Flow::Jump(0x1001),
                    vec![
                        PcodeOp::new(
                            op::INT_ADD,
                            Some(value),
                            vec![value, Varnode::new(ventris_lifter::CONST_SPACE, 1, 4)],
                        ),
                        PcodeOp::new(op::STORE, None, vec![ram, address, value]),
                    ],
                ),
                instruction(
                    0x1003,
                    Flow::Return,
                    vec![PcodeOp::new(op::RETURN, None, vec![value])],
                ),
            ],
        );

        let heritage = build_heritage(&function);
        let header = heritage
            .blocks
            .iter()
            .find(|block| block.start == 0x1001)
            .unwrap();
        let phi = header
            .phis
            .iter()
            .find(|phi| phi.location == ValueKey::from(value))
            .unwrap();
        assert_eq!(phi.inputs.len(), 2);
        let memory_phi = heritage.memory_phis.get(&header.id).unwrap();
        assert_eq!(memory_phi.inputs.len(), 2);
        assert!(memory_phi.inputs.iter().any(|input| input.version == 0));
        assert!(memory_phi.inputs.iter().any(|input| input.version != 0));
    }

    #[test]
    fn calls_advance_memory_without_defining_constant_inputs() {
        let target = Varnode::new(ventris_lifter::CONST_SPACE, 0x2000, 8);
        let function = function(
            0x1000,
            [instruction(
                0x1000,
                Flow::Return,
                vec![
                    PcodeOp::new(op::CALL, None, vec![target]),
                    PcodeOp::new(op::RETURN, None, vec![]),
                ],
            )],
        );

        let heritage = build_heritage(&function);
        let operations = &heritage.blocks[0].operations;
        assert!(operations[0].uses.is_empty());
        assert_ne!(operations[0].memory_in, operations[0].memory_out);
        assert_eq!(operations[1].memory_in, operations[0].memory_out);
    }
}
