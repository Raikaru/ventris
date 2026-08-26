//! SSA construction on the mutable graph, ported from Ghidra 12.1.3.
//!
//! The existing `native::heritage` module computes SSA facts as a side table
//! and nothing consumes them for value resolution. This port does what Ghidra
//! does instead: it inserts real `MULTIEQUAL` operations into the graph and
//! rewrites every read to point at the definition that dominates it. After it
//! runs, following a use to its definition is a graph edge, so later passes
//! need no reaching-definition heuristic of their own.
//!
//! Source authority: `Heritage::calcMultiequals`, `renameRecurse`,
//! `Funcdata::opSetInput`, and the augmented dominance tree in `heritage.cc`
//! and `block.cc` at commit `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use std::collections::{BTreeMap, BTreeSet};

use ventris_pcode::op;

use super::{Funcdata, GraphBlockId, OpId, SeqNum, VarnodeId};

/// Dominance data for one function's block graph.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Dominance {
    pub reverse_postorder: Vec<GraphBlockId>,
    pub immediate: BTreeMap<GraphBlockId, Option<GraphBlockId>>,
    pub children: BTreeMap<GraphBlockId, Vec<GraphBlockId>>,
    pub frontiers: BTreeMap<GraphBlockId, BTreeSet<GraphBlockId>>,
}

/// Computes reverse postorder, immediate dominators, the dominator tree, and
/// dominance frontiers.
///
/// Immediate dominators use the Cooper-Harvey-Kennedy iteration and frontiers
/// use Cytron's rule: for every join, walk each predecessor up the dominator
/// tree until the block's immediate dominator is reached.
pub fn compute_dominance(data: &Funcdata) -> Dominance {
    // Prefer the block at the recorded entry address, but fall back to the
    // first block so a graph assembled without an address still analyses.
    let entry = data
        .blocks()
        .find(|(id, _)| data.is_entry_block(*id))
        .map(|(id, _)| id)
        .or_else(|| data.blocks().next().map(|(id, _)| id));
    let Some(entry) = entry else {
        return Dominance::default();
    };
    let reverse_postorder = reverse_postorder(data, entry);
    let position: BTreeMap<GraphBlockId, usize> = reverse_postorder
        .iter()
        .enumerate()
        .map(|(index, id)| (*id, index))
        .collect();

    let mut immediate: BTreeMap<GraphBlockId, Option<GraphBlockId>> =
        reverse_postorder.iter().map(|id| (*id, None)).collect();
    immediate.insert(entry, Some(entry));
    let mut changed = true;
    while changed {
        changed = false;
        for id in reverse_postorder.iter().copied().filter(|id| *id != entry) {
            let mut candidate: Option<GraphBlockId> = None;
            for predecessor in data.block(id).predecessors.iter().copied() {
                if immediate.get(&predecessor).copied().flatten().is_none() {
                    continue;
                }
                candidate = Some(match candidate {
                    None => predecessor,
                    Some(current) => intersect(&immediate, &position, predecessor, current),
                });
            }
            if candidate.is_some() && immediate.get(&id).copied().flatten() != candidate {
                immediate.insert(id, candidate);
                changed = true;
            }
        }
    }

    let mut children: BTreeMap<GraphBlockId, Vec<GraphBlockId>> = BTreeMap::new();
    for (id, parent) in &immediate {
        if let Some(parent) = parent
            && *parent != *id
        {
            children.entry(*parent).or_default().push(*id);
        }
    }

    let mut frontiers: BTreeMap<GraphBlockId, BTreeSet<GraphBlockId>> = BTreeMap::new();
    for (id, block) in data.blocks() {
        if block.predecessors.len() < 2 {
            continue;
        }
        let stop = immediate.get(&id).copied().flatten();
        for predecessor in block.predecessors.iter().copied() {
            let mut runner = Some(predecessor);
            while let Some(current) = runner {
                if Some(current) == stop {
                    break;
                }
                frontiers.entry(current).or_default().insert(id);
                let next = immediate.get(&current).copied().flatten();
                runner = if next == Some(current) { None } else { next };
            }
        }
    }

    Dominance {
        reverse_postorder,
        immediate,
        children,
        frontiers,
    }
}

fn intersect(
    immediate: &BTreeMap<GraphBlockId, Option<GraphBlockId>>,
    position: &BTreeMap<GraphBlockId, usize>,
    mut left: GraphBlockId,
    mut right: GraphBlockId,
) -> GraphBlockId {
    while left != right {
        let left_position = position.get(&left).copied().unwrap_or(usize::MAX);
        let right_position = position.get(&right).copied().unwrap_or(usize::MAX);
        if left_position > right_position {
            match immediate.get(&left).copied().flatten() {
                Some(next) if next != left => left = next,
                _ => return right,
            }
        } else {
            match immediate.get(&right).copied().flatten() {
                Some(next) if next != right => right = next,
                _ => return left,
            }
        }
    }
    left
}

fn reverse_postorder(data: &Funcdata, entry: GraphBlockId) -> Vec<GraphBlockId> {
    let mut order = Vec::new();
    let mut seen = BTreeSet::new();
    let mut stack = vec![(entry, 0usize)];
    seen.insert(entry);
    while let Some((id, index)) = stack.pop() {
        let successors = &data.block(id).successors;
        if index < successors.len() {
            stack.push((id, index + 1));
            let next = successors[index];
            if seen.insert(next) {
                stack.push((next, 0));
            }
        } else {
            order.push(id);
        }
    }
    order.reverse();
    order
}

/// Inserts `MULTIEQUAL` operations and rewrites reads to dominating definitions.
///
/// Returns the number of phi operations inserted.
pub fn heritage(data: &mut Funcdata) -> usize {
    heritage_with_endianness(data, true)
}

/// As [`heritage`], told which end of a wide value holds its least significant
/// byte, which decides how a narrow read of part of one is truncated.
pub fn heritage_with_endianness(data: &mut Funcdata, little_endian: bool) -> usize {
    let dominance = compute_dominance(data);
    if dominance.reverse_postorder.is_empty() {
        return 0;
    }
    let phis = place_phis(data, &dominance);
    let entry = dominance.reverse_postorder[0];
    let mut stacks: BTreeMap<(u32, u64, u32), Vec<VarnodeId>> = BTreeMap::new();
    rename(data, &dominance, entry, &mut stacks, little_endian);
    phis
}

/// Cytron placement: a location written in one block needs a phi at every block
/// in that block's iterated dominance frontier.
fn place_phis(data: &mut Funcdata, dominance: &Dominance) -> usize {
    let mut definitions: BTreeMap<(u32, u64, u32), BTreeSet<GraphBlockId>> = BTreeMap::new();
    for (id, block) in data.blocks() {
        for op in block.ops.iter().copied() {
            if let Some(output) = data.op(op).output {
                let varnode = data.varnode(output);
                if varnode.flags.constant {
                    continue;
                }
                definitions
                    .entry((varnode.space, varnode.offset, varnode.size))
                    .or_default()
                    .insert(id);
            }
        }
    }

    let mut inserted = 0;
    for (location, sites) in definitions {
        let mut placed: BTreeSet<GraphBlockId> = BTreeSet::new();
        let mut pending: Vec<GraphBlockId> = sites.iter().copied().collect();
        while let Some(block) = pending.pop() {
            let Some(frontier) = dominance.frontiers.get(&block) else {
                continue;
            };
            for join in frontier.iter().copied() {
                if !placed.insert(join) {
                    continue;
                }
                insert_phi(data, join, location);
                inserted += 1;
                if !sites.contains(&join) {
                    pending.push(join);
                }
            }
        }
    }
    inserted
}

/// Creates a `MULTIEQUAL` at the head of a block, one operand per predecessor.
fn insert_phi(data: &mut Funcdata, block: GraphBlockId, location: (u32, u64, u32)) -> OpId {
    let (space, offset, size) = location;
    let arity = data.block(block).predecessors.len();
    let seq = SeqNum {
        address: data.block(block).start,
        order: 0,
    };
    let inputs: Vec<VarnodeId> = (0..arity)
        .map(|_| data.new_varnode(space, offset, size))
        .collect();
    let phi = data.new_op(op::MULTIEQUAL, seq, inputs);
    let output = data.new_varnode(space, offset, size);
    data.op_set_output(phi, Some(output));
    data.op_insert_front(phi, block);
    phi
}

/// Walks the dominator tree, replacing each read with the definition on top of
/// its location's stack. This is `renameRecurse`.
/// The narrowest definition whose bytes contain a location, if any.
///
/// A sub-view need not share the containing register's offset. Big-endian
/// MIPS64 writes the whole 64-bit register at its base and reads the low half
/// four bytes further in, so `lui` defining `(64, 8)` is the definition a later
/// `addiu` reading `(68, 4)` must see. Searching only for a wider definition at
/// the same offset missed that and minted an entry value, which is why every
/// `lui`/`addiu` address on N64 became an invented parameter.
///
/// The stack top is used, so the definition found is the one that dominates
/// here. Returns the definition with the byte offset and size of its location,
/// which together decide how the read is truncated out of it.
fn tightest_containing(
    stacks: &BTreeMap<(u32, u64, u32), Vec<VarnodeId>>,
    key: (u32, u64, u32),
) -> Option<(VarnodeId, u64, u32)> {
    // Registers only. A temporary that happens to share an offset with a wider
    // temporary is not a view of it, and truncating one to the other discarded
    // real computation: a multiply's result was replaced by an undefined value.
    if key.0 != ventris_lifter::REGISTER_SPACE {
        return None;
    }
    let end = key.1.checked_add(u64::from(key.2))?;
    stacks
        .range((key.0, 0, 0)..=(key.0, key.1, u32::MAX))
        .filter(|((_, offset, size), _)| {
            // Strictly wider than the read, and covering all of its bytes.
            (*offset, *size) != (key.1, key.2) && offset.saturating_add(u64::from(*size)) >= end
        })
        // The tightest is the latest-starting, then the smallest.
        .min_by_key(|((_, offset, size), _)| (key.1 - *offset, *size))
        .and_then(|((_, offset, size), stack)| {
            stack.last().copied().map(|value| (value, *offset, *size))
        })
}

/// Inserts a truncation of `wide` to the `size` bytes at `offset` ahead of
/// `before`.
///
/// `SUBPIECE`'s second operand counts least-significant bytes to discard, so it
/// is the distance from the read to the wide value's least significant end -
/// which is the far end of the register on a big-endian bank.
fn truncate_before(
    data: &mut Funcdata,
    before: OpId,
    wide: VarnodeId,
    wide_at: (u64, u32),
    location: (u64, u32),
    little_endian: bool,
) -> VarnodeId {
    let (wide_offset, wide_size) = wide_at;
    let (offset, size) = location;
    let skip = if little_endian {
        offset.saturating_sub(wide_offset)
    } else {
        (wide_offset.saturating_add(u64::from(wide_size)))
            .saturating_sub(offset.saturating_add(u64::from(size)))
    };
    let seq = data.op(before).seq;
    let shift = data.new_constant(skip, 4);
    let truncate = data.new_op(op::SUBPIECE, seq, vec![wide, shift]);
    // A unique output, so the truncation is not itself a definition of the
    // register and does not change what the rest of this walk sees.
    let narrow = data.new_unique(size);
    data.op_set_output(truncate, Some(narrow));
    data.op_insert_before(truncate, before);
    narrow
}

fn rename(
    data: &mut Funcdata,
    dominance: &Dominance,
    block: GraphBlockId,
    stacks: &mut BTreeMap<(u32, u64, u32), Vec<VarnodeId>>,
    little_endian: bool,
) {
    let mut pushed: Vec<(u32, u64, u32)> = Vec::new();
    let ops: Vec<OpId> = data.block(block).ops.clone();
    for op in ops.iter().copied() {
        if data.op(op).opcode != op::MULTIEQUAL {
            let inputs = data.op(op).inputs.clone();
            for (slot, input) in inputs.into_iter().enumerate() {
                let varnode = data.varnode(input);
                if varnode.flags.constant || varnode.flags.written {
                    continue;
                }
                let key = (varnode.space, varnode.offset, varnode.size);
                let current = match stacks.get(&key).and_then(|stack| stack.last().copied()) {
                    Some(current) => current,
                    // A narrow read of a register nothing defined at that width
                    // is a view of the wider register that was defined. Minting
                    // an entry value instead claimed the function was handed an
                    // undefined register: `sb v1` after `addiu v1,zero,1`
                    // printed the bare register name and lost the constant.
                    None => match tightest_containing(stacks, key) {
                        Some((wide, wide_offset, wide_size)) => truncate_before(
                            data,
                            op,
                            wide,
                            (wide_offset, wide_size),
                            (key.1, key.2),
                            little_endian,
                        ),
                        None => {
                            let entry_value = data.new_varnode(key.0, key.1, key.2);
                            data.mark_input(entry_value);
                            stacks.entry(key).or_default().push(entry_value);
                            entry_value
                        }
                    },
                };
                if current != input {
                    data.op_set_input(op, current, slot);
                }
            }
        }
        if let Some(output) = data.op(op).output {
            let varnode = data.varnode(output);
            if !varnode.flags.constant {
                let key = (varnode.space, varnode.offset, varnode.size);
                stacks.entry(key).or_default().push(output);
                pushed.push(key);
            }
        }
    }

    let successors = data.block(block).successors.clone();
    for successor in successors {
        let slot = data
            .block(successor)
            .predecessors
            .iter()
            .position(|predecessor| *predecessor == block);
        let Some(slot) = slot else { continue };
        let phis: Vec<OpId> = data
            .block(successor)
            .ops
            .iter()
            .copied()
            .take_while(|op| data.op(*op).opcode == op::MULTIEQUAL)
            .collect();
        for phi in phis {
            let Some(operand) = data.op(phi).inputs.get(slot).copied() else {
                continue;
            };
            let varnode = data.varnode(operand);
            if varnode.flags.written {
                continue;
            }
            let key = (varnode.space, varnode.offset, varnode.size);
            let current = match stacks.get(&key).and_then(|stack| stack.last().copied()) {
                Some(current) => current,
                None => {
                    let entry_value = data.new_varnode(key.0, key.1, key.2);
                    data.mark_input(entry_value);
                    stacks.entry(key).or_default().push(entry_value);
                    entry_value
                }
            };
            if current != operand {
                data.op_set_input(phi, current, slot);
            }
        }
    }

    for child in dominance.children.get(&block).cloned().unwrap_or_default() {
        rename(data, dominance, child, stacks, little_endian);
    }

    for key in pushed {
        if let Some(stack) = stacks.get_mut(&key) {
            stack.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::REGISTER_SPACE;

    /// entry -> then/else -> join, with the location written on both arms.
    fn diamond() -> (Funcdata, GraphBlockId) {
        let mut data = Funcdata::default();
        let entry = data.new_block(0x1000);
        let left = data.new_block(0x1010);
        let right = data.new_block(0x1020);
        let join = data.new_block(0x1030);
        data.add_edge(entry, left);
        data.add_edge(entry, right);
        data.add_edge(left, join);
        data.add_edge(right, join);
        for (block, value) in [(left, 1u64), (right, 2u64)] {
            let seq = SeqNum {
                address: data.block(block).start,
                order: 0,
            };
            let constant = data.new_constant(value, 4);
            let op = data.new_op(op::COPY, seq, vec![constant]);
            let out = data.new_varnode(REGISTER_SPACE, 8, 4);
            data.op_set_output(op, Some(out));
            data.op_insert_end(op, block);
        }
        let seq = SeqNum {
            address: 0x1030,
            order: 0,
        };
        let read = data.new_varnode(REGISTER_SPACE, 8, 4);
        let ret = data.new_op(op::RETURN, seq, vec![read]);
        data.op_insert_end(ret, join);
        (data, join)
    }

    #[test]
    fn a_join_receives_one_phi_per_merged_location() {
        let (mut data, join) = diamond();
        assert_eq!(heritage(&mut data), 1);
        let phis: Vec<OpId> = data
            .block(join)
            .ops
            .iter()
            .copied()
            .filter(|op| data.op(*op).opcode == op::MULTIEQUAL)
            .collect();
        assert_eq!(phis.len(), 1);
        assert_eq!(
            data.op(phis[0]).inputs.len(),
            2,
            "one operand per predecessor"
        );
    }

    #[test]
    fn a_phi_operand_names_the_definition_from_that_predecessor() {
        let (mut data, join) = diamond();
        heritage(&mut data);
        let phi = *data
            .block(join)
            .ops
            .iter()
            .find(|op| data.op(**op).opcode == op::MULTIEQUAL)
            .expect("phi present");
        let sources: Vec<u64> = data
            .op(phi)
            .inputs
            .iter()
            .map(|input| {
                let definition = data
                    .varnode(*input)
                    .def
                    .expect("each operand is defined on its arm");
                let constant = data.op(definition).inputs[0];
                data.varnode(constant).offset
            })
            .collect();
        assert_eq!(sources, vec![1, 2], "operands follow predecessor order");
    }

    #[test]
    fn the_read_after_the_join_uses_the_phi_result() {
        let (mut data, join) = diamond();
        heritage(&mut data);
        let phi = *data
            .block(join)
            .ops
            .iter()
            .find(|op| data.op(**op).opcode == op::MULTIEQUAL)
            .expect("phi present");
        let result = data.op(phi).output.expect("phi defines a value");
        let ret = *data
            .block(join)
            .ops
            .iter()
            .find(|op| data.op(**op).opcode == op::RETURN)
            .expect("return present");
        assert_eq!(data.op(ret).inputs[0], result);
    }

    #[test]
    fn straight_line_code_needs_no_phi() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let seq = SeqNum {
            address: 0x1000,
            order: 0,
        };
        let constant = data.new_constant(1, 4);
        let op = data.new_op(op::COPY, seq, vec![constant]);
        let out = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(op, Some(out));
        data.op_insert_end(op, block);
        let read = data.new_varnode(REGISTER_SPACE, 8, 4);
        let ret = data.new_op(op::RETURN, seq, vec![read]);
        data.op_insert_end(ret, block);
        assert_eq!(heritage(&mut data), 0);
        assert_eq!(data.op(ret).inputs[0], out, "the read sees the local write");
    }

    #[test]
    fn a_loop_header_receives_a_phi() {
        let mut data = Funcdata::default();
        let entry = data.new_block(0x1000);
        let header = data.new_block(0x1010);
        let body = data.new_block(0x1020);
        data.add_edge(entry, header);
        data.add_edge(header, body);
        data.add_edge(body, header);
        let seq = SeqNum {
            address: 0x1020,
            order: 0,
        };
        let read = data.new_varnode(REGISTER_SPACE, 8, 4);
        let one = data.new_constant(1, 4);
        let add = data.new_op(op::INT_ADD, seq, vec![read, one]);
        let out = data.new_varnode(REGISTER_SPACE, 8, 4);
        data.op_set_output(add, Some(out));
        data.op_insert_end(add, body);
        assert_eq!(heritage(&mut data), 1);
        let phi = data
            .block(header)
            .ops
            .iter()
            .find(|op| data.op(**op).opcode == op::MULTIEQUAL)
            .copied()
            .expect("the header receives a phi");
        assert_eq!(data.op(phi).inputs.len(), 2);
    }

    #[test]
    fn an_undefined_read_becomes_a_function_input() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let seq = SeqNum {
            address: 0x1000,
            order: 0,
        };
        let read = data.new_varnode(REGISTER_SPACE, 8, 4);
        let ret = data.new_op(op::RETURN, seq, vec![read]);
        data.op_insert_end(ret, block);
        heritage(&mut data);
        let operand = data.op(ret).inputs[0];
        assert!(data.varnode(operand).flags.input);
        assert!(data.varnode(operand).def.is_none());
    }

    /// A big-endian bank writes the whole register at its base and reads the low
    /// half four bytes in: MIPS64 `lui` defines `(64, 8)` and the following
    /// `addiu` reads `(68, 4)`. That read is a view of the definition, not an
    /// undefined register handed to the function.
    #[test]
    fn a_big_endian_low_half_read_truncates_the_wide_definition() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let seq = SeqNum {
            address: 0x1000,
            order: 0,
        };
        let constant = data.new_constant(0x8009_0000, 8);
        let wide = data.new_varnode(REGISTER_SPACE, 64, 8);
        let define = data.new_op(op::COPY, seq, vec![constant]);
        data.op_set_output(define, Some(wide));
        data.op_insert_end(define, block);
        let low = data.new_varnode(REGISTER_SPACE, 68, 4);
        let ret = data.new_op(op::RETURN, seq, vec![low]);
        data.op_insert_end(ret, block);

        heritage_with_endianness(&mut data, false);

        let operand = data.op(ret).inputs[0];
        assert!(
            !data.varnode(operand).flags.input,
            "the low half is not a function input"
        );
        let truncation = data
            .varnode(operand)
            .def
            .expect("the low half is defined by a truncation");
        assert_eq!(data.op(truncation).opcode, op::SUBPIECE);
        assert_eq!(data.op(truncation).inputs[0], wide);
        // The low half of a big-endian register discards no less significant
        // bytes, so the truncation starts at zero.
        let skip = data.op(truncation).inputs[1];
        assert_eq!(data.varnode(skip).offset, 0);
    }
}
