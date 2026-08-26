//! The second Ghidra jump-table model.
//!
//! `JumpBasic2` is the model described by `jumptable.hh:429-453` and
//! implemented by `jumptable.cc:1651-1784`.  It starts with the path meld
//! produced by `JumpBasic`, then handles the case where a guard selects a
//! default constant on one path and a table calculation on the other path.
//! The two values meet in a two-input `MULTIEQUAL` before the indirect branch.
//!
//! The graph module deliberately keeps the first model's parser private to
//! its implementation, so this module uses the small shared `pub(crate)`
//! parser surface from [`super::jumptable`] and adds only the join-aware
//! substitution needed by the second model.  No model is claimed unless both
//! the split data-flow shape and a bounded, readable table are present.

use std::collections::BTreeSet;

use super::jumptable::{
    self, AddressModel, DestinationModel, GuardModel, JumpTable, MAX_TABLE_ENTRIES,
};
use super::{Funcdata, GraphBlockId, OpId, VarnodeId};
use ventris_pcode::op;

/// A backwards data-flow edge, equivalent to Ghidra's `PcodeOpNode`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct PathNode {
    op: OpId,
    slot: usize,
}

/// An operation and the common-path value at which its path split.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct RootedOp {
    op: OpId,
    root_vn: usize,
}

/// The part of Ghidra's `PathMeld` needed by `JumpBasic2`.
///
/// `common_vn` is ordered from the indirect branch backwards.  `op_meld`
/// records the operations on the paths and their split point in that common
/// list.  The graph has no mutable mark bit on varnodes, so `meld` uses value
/// identity and an explicit old-to-new index map instead of temporary marks.
#[derive(Clone, Debug, Default)]
struct PathMeld {
    common_vn: Vec<VarnodeId>,
    op_meld: Vec<RootedOp>,
}

impl PathMeld {
    fn clear(&mut self) {
        self.common_vn.clear();
        self.op_meld.clear();
    }

    fn empty(&self) -> bool {
        self.common_vn.is_empty()
    }

    fn last_common(&self) -> Option<VarnodeId> {
        self.common_vn.last().copied()
    }

    /// Port of `PathMeld::set(const vector<PcodeOpNode>&)`
    /// (`jumptable.cc:920-931`).
    fn set(&mut self, data: &Funcdata, path: &[PathNode]) {
        self.clear();
        for (index, node) in path.iter().copied().enumerate() {
            let Some(value) = data.op(node.op).inputs.get(node.slot).copied() else {
                self.clear();
                return;
            };
            self.op_meld.push(RootedOp {
                op: node.op,
                root_vn: index,
            });
            self.common_vn.push(value);
        }
    }

    /// Port of the one-node `PathMeld::set` overload
    /// (`jumptable.cc:933-940`).
    fn set_single(&mut self, op_id: OpId, value: VarnodeId) {
        self.clear();
        self.common_vn.push(value);
        self.op_meld.push(RootedOp {
            op: op_id,
            root_vn: 0,
        });
    }

    /// Port of `PathMeld::append` (`jumptable.cc:942-955`).
    ///
    /// The path passed in is executed before the current path when both are
    /// represented in backwards order, so its values and operations are put
    /// at the front and the old roots are shifted by its value count.
    fn append(&mut self, earlier: &PathMeld) {
        let offset = earlier.common_vn.len();
        let mut common = earlier.common_vn.clone();
        common.extend(self.common_vn.iter().copied());

        let mut operations = earlier.op_meld.clone();
        operations.extend(self.op_meld.iter().copied().map(|mut rooted| {
            rooted.root_vn += offset;
            rooted
        }));

        self.common_vn = common;
        self.op_meld = operations;
    }

    /// Port of the intersection and path-meld part of
    /// `PathMeld::meld` (`jumptable.cc:787-819`, `964-994`).
    ///
    /// The original uses a temporary mark on every varnode in the new path.
    /// This implementation computes the same ordered intersection and
    /// explicit old-to-new root map, then uses the block/sequence merge from
    /// `PathMeld::meldOps` (`jumptable.cc:821-894`).
    fn meld(&mut self, data: &Funcdata, path: &mut Vec<PathNode>) {
        let path_values: Vec<VarnodeId> = path
            .iter()
            .filter_map(|node| data.op(node.op).inputs.get(node.slot).copied())
            .collect();
        if path_values.is_empty() || self.common_vn.is_empty() {
            path.clear();
            self.clear();
            return;
        }

        let old_common = self.common_vn.clone();
        let mut used = vec![false; path_values.len()];
        let mut parent_map: Vec<Option<usize>> = vec![None; old_common.len()];
        let mut new_common = Vec::new();

        // `internalIntersect` walks the old list in order and keeps the same
        // values in the new path, preserving backwards execution order.
        for (old_index, old_value) in old_common.iter().copied().enumerate() {
            let Some(path_index) = path_values
                .iter()
                .enumerate()
                .find(|(index, value)| !used[*index] && **value == old_value)
                .map(|(index, _)| index)
            else {
                continue;
            };
            used[path_index] = true;
            parent_map[old_index] = Some(new_common.len());
            new_common.push(old_value);
        }

        // Ghidra's backwards fill maps a removed common value to the next
        // earliest value that survives the intersection.  Values after the
        // last intersection remain unmapped and their operations are dropped.
        let mut next = None;
        for index in (0..parent_map.len()).rev() {
            if parent_map[index].is_none() {
                parent_map[index] = next;
            } else {
                next = parent_map[index];
            }
        }

        let cutoff = path_values
            .iter()
            .rposition(|value| new_common.contains(value))
            .map_or(0, |index| index + 1);

        let old_operations = self.op_meld.clone();
        let mut remapped = Vec::with_capacity(old_operations.len());
        for mut rooted in old_operations {
            let Some(mapped) = parent_map.get(rooted.root_vn).and_then(|value| *value) else {
                continue;
            };
            rooted.root_vn = mapped;
            remapped.push(rooted);
        }

        self.common_vn = new_common;
        self.op_meld = remapped;
        self.meld_ops(data, path, &path_values, cutoff);
        path.truncate(cutoff);
    }

    /// Port `PathMeld::meldOps` (`jumptable.cc:821-894`), adapted to graph
    /// block IDs and `SeqNum.order`.
    fn meld_ops(
        &mut self,
        data: &Funcdata,
        path: &[PathNode],
        path_values: &[VarnodeId],
        cutoff: usize,
    ) {
        let old_operations = std::mem::take(&mut self.op_meld);
        let mut new_meld = Vec::new();
        let mut meld_pos = 0;
        let mut cur_root = None;
        let mut last_block = None;

        for (path_index, node) in path.iter().copied().take(cutoff).enumerate() {
            let Some(operation) = data.op(node.op).parent else {
                continue;
            };
            let mut matching = None;

            while meld_pos < old_operations.len() {
                let trial = old_operations[meld_pos];
                let trial_block = data.op(trial.op).parent;
                if trial_block != Some(operation) {
                    if Some(operation) == last_block {
                        break;
                    }
                    if trial_block != last_block {
                        // The paths cannot be ordered in one common block
                        // sequence.  Ghidra cuts the path at this root.
                        self.op_meld = new_meld;
                        self.truncate_paths(trial.root_vn);
                        return;
                    }
                } else if data.op(trial.op).seq.order <= data.op(node.op).seq.order {
                    matching = Some(trial);
                    break;
                }

                last_block = trial_block;
                new_meld.push(trial);
                meld_pos += 1;
            }

            if let Some(trial) = matching {
                new_meld.push(trial);
                cur_root = Some(trial.root_vn);
                meld_pos += 1;
            } else {
                let root_vn = path_values
                    .get(path_index)
                    .and_then(|value| self.common_vn.iter().position(|common| common == value))
                    .or(cur_root)
                    .unwrap_or(0);
                new_meld.push(RootedOp {
                    op: node.op,
                    root_vn,
                });
            }
            last_block = Some(operation);
        }
        self.op_meld = new_meld;
    }

    fn truncate_paths(&mut self, cutoff: usize) {
        while self.op_meld.len() > 1 {
            if self
                .op_meld
                .last()
                .is_some_and(|rooted| rooted.root_vn < cutoff)
            {
                break;
            }
            self.op_meld.pop();
        }
        self.common_vn.truncate(cutoff);
    }
}

/// `JumpBasic::isprune`, with graph-native marker recognition.
///
/// Ghidra marks `MULTIEQUAL` and `INDIRECT` as SSA markers, so the first model
/// stops at their output.  That stop is the key invariant that lets
/// `JumpBasic2` receive the phi output as its extra/default value.
fn is_prune(data: &Funcdata, value: VarnodeId) -> bool {
    let Some(def) = data.varnode(value).def else {
        return true;
    };
    let operation = data.op(def);
    operation.inputs.is_empty()
        || matches!(
            operation.opcode,
            op::CALL | op::CALLIND | op::CALLOTHER | op::MULTIEQUAL | op::INDIRECT
        )
}

fn is_point(data: &Funcdata, value: VarnodeId) -> bool {
    !data.varnode(value).flags.constant
}

/// Port `JumpBasic::findDeterminingVarnodes` (`jumptable.cc:548-591`).
fn find_determining(data: &Funcdata, operation: OpId, slot: usize) -> PathMeld {
    let mut meld = PathMeld::default();
    let Some(_) = data.op(operation).inputs.get(slot) else {
        return meld;
    };

    let mut path = vec![PathNode {
        op: operation,
        slot,
    }];
    let mut first_point = false;

    while !path.is_empty() {
        let last = path.len() - 1;
        let node = path[last];
        let Some(value) = data.op(node.op).inputs.get(node.slot).copied() else {
            path.pop();
            if let Some(parent) = path.last_mut() {
                parent.slot += 1;
            }
            continue;
        };

        if is_prune(data, value) {
            if is_point(data, value) {
                if !first_point {
                    meld.set(data, &path);
                    first_point = true;
                } else {
                    let mut candidate = path.clone();
                    meld.meld(data, &mut candidate);
                }
            }
            path[last].slot += 1;
            while let Some(current) = path.last() {
                if current.slot < data.op(current.op).inputs.len() {
                    break;
                }
                path.pop();
                if let Some(parent) = path.last_mut() {
                    parent.slot += 1;
                }
            }
        } else if let Some(def) = data.varnode(value).def {
            path.push(PathNode { op: def, slot: 0 });
        } else {
            // A malformed graph should decline rather than spin or invent a
            // path.  This is the equivalent of an untraversable leaf.
            path[last].slot += 1;
        }
    }

    if meld.empty() {
        let value = data.op(operation).inputs[slot];
        meld.set_single(operation, value);
    }
    meld
}

fn default_phi_path(data: &Funcdata, join: OpId) -> Option<(usize, usize, VarnodeId, u64)> {
    let operation = data.op(join);
    if operation.opcode != op::MULTIEQUAL || operation.inputs.len() != 2 {
        return None;
    }

    let mut default_path = None;
    for slot in 0..2 {
        let input = operation.inputs[slot];
        let Some(def) = data.varnode(input).def else {
            continue;
        };
        let copy = data.op(def);
        if copy.opcode != op::COPY || copy.inputs.len() != 1 {
            continue;
        }
        let Some(value) = jumptable::constant_value(data, copy.inputs[0]) else {
            continue;
        };
        if default_path.is_some() {
            // Two constant paths are not the two-stage model; there is no
            // unique table-producing side to recover.
            return None;
        }
        default_path = Some((slot, value, input));
    }

    let (default_slot, default_value, _) = default_path?;
    let dynamic_slot = 1 - default_slot;
    let dynamic_input = operation.inputs[dynamic_slot];
    if data.varnode(dynamic_input).flags.constant {
        return None;
    }
    Some((default_slot, dynamic_slot, dynamic_input, default_value))
}

/// Recover a scaled index while treating the phi output as a symbolic value
/// supplied by `dynamic_input`.  This is the data-flow composition performed
/// by `JumpBasic2` when its `origPathMeld` is appended to the second path.
fn parse_scaled_through_join(
    data: &Funcdata,
    value: VarnodeId,
    join: VarnodeId,
    dynamic_input: VarnodeId,
) -> Option<(VarnodeId, u64)> {
    let value = jumptable::strip_alias(data, value);
    if value == join {
        let scale = jumptable::parse_scaled(data, dynamic_input)?;
        return Some((scale.value, scale.stride));
    }
    if data.varnode(value).flags.constant {
        return None;
    }
    let def = data.varnode(value).def?;
    let operation = data.op(def);
    match operation.opcode {
        op::INT_MULT if operation.inputs.len() >= 2 => {
            let (index, scale) =
                if let Some(scale) = jumptable::constant_value(data, operation.inputs[1]) {
                    (operation.inputs[0], scale)
                } else if let Some(scale) = jumptable::constant_value(data, operation.inputs[0]) {
                    (operation.inputs[1], scale)
                } else {
                    return None;
                };
            if scale == 0 {
                return None;
            }
            let (value, stride) = parse_scaled_through_join(data, index, join, dynamic_input)?;
            Some((value, stride.checked_mul(scale)?))
        }
        op::INT_LEFT if operation.inputs.len() >= 2 => {
            let shift = jumptable::constant_value(data, operation.inputs[1])?;
            if shift >= u64::from(u64::BITS) {
                return None;
            }
            let (value, stride) =
                parse_scaled_through_join(data, operation.inputs[0], join, dynamic_input)?;
            Some((value, stride.checked_shl(shift as u32)?))
        }
        _ => None,
    }
}

/// Recover `constant base + scaled(phi)` from a LOAD address, then substitute
/// the non-default phi input into the scaled expression.
fn parse_address_through_join(
    data: &Funcdata,
    value: VarnodeId,
    join: VarnodeId,
    dynamic_input: VarnodeId,
) -> Option<AddressModel> {
    let value = jumptable::strip_alias(data, value);
    let def = data.varnode(value).def?;
    let operation = data.op(def);
    if operation.opcode != op::INT_ADD || operation.inputs.len() < 2 {
        return None;
    }

    if let Some(base) = jumptable::constant_value(data, operation.inputs[0]) {
        if let Some((index, stride)) =
            parse_scaled_through_join(data, operation.inputs[1], join, dynamic_input)
        {
            return Some(AddressModel {
                base,
                index,
                stride,
            });
        }
        if let Some(mut nested) =
            parse_address_through_join(data, operation.inputs[1], join, dynamic_input)
        {
            nested.base = nested.base.wrapping_add(base);
            return Some(nested);
        }
    }
    if let Some(base) = jumptable::constant_value(data, operation.inputs[1]) {
        if let Some((index, stride)) =
            parse_scaled_through_join(data, operation.inputs[0], join, dynamic_input)
        {
            return Some(AddressModel {
                base,
                index,
                stride,
            });
        }
        if let Some(mut nested) =
            parse_address_through_join(data, operation.inputs[0], join, dynamic_input)
        {
            nested.base = nested.base.wrapping_add(base);
            return Some(nested);
        }
    }
    None
}

fn parse_destination_through_join(
    data: &Funcdata,
    value: VarnodeId,
    join: VarnodeId,
    dynamic_input: VarnodeId,
) -> Option<DestinationModel> {
    let value = jumptable::strip_alias(data, value);
    if value == join {
        return jumptable::parse_destination(data, dynamic_input);
    }
    let def = data.varnode(value).def?;
    let operation = data.op(def);
    match operation.opcode {
        op::LOAD => {
            let address =
                parse_address_through_join(data, *operation.inputs.get(1)?, join, dynamic_input)?;
            let output = operation.output?;
            let entry_size = data.varnode(output).size;
            (entry_size != 0).then_some(DestinationModel {
                address,
                entry_size,
                target_bias: 0,
            })
        }
        op::INT_ADD if operation.inputs.len() >= 2 => {
            if let Some(bias) = jumptable::constant_value(data, operation.inputs[0]) {
                let mut nested =
                    parse_destination_through_join(data, operation.inputs[1], join, dynamic_input)?;
                nested.target_bias = nested.target_bias.wrapping_add(bias);
                return Some(nested);
            }
            if let Some(bias) = jumptable::constant_value(data, operation.inputs[1]) {
                let mut nested =
                    parse_destination_through_join(data, operation.inputs[0], join, dynamic_input)?;
                nested.target_bias = nested.target_bias.wrapping_add(bias);
                return Some(nested);
            }
            None
        }
        _ => None,
    }
}

fn mask_for_size(size: u32) -> u64 {
    let bits = size.saturating_mul(8);
    if bits == 0 {
        0
    } else if bits >= u64::BITS {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn evaluate_default_inner(
    data: &Funcdata,
    value: VarnodeId,
    join: VarnodeId,
    replacement: u64,
    read_memory: &dyn Fn(u64, u32) -> Option<u64>,
    seen: &mut BTreeSet<VarnodeId>,
) -> Option<u64> {
    let value = jumptable::strip_alias(data, value);
    if value == join {
        return Some(replacement);
    }
    if !seen.insert(value) {
        return None;
    }
    let result = if let Some(value) = jumptable::constant_value(data, value) {
        Some(value)
    } else {
        let def = data.varnode(value).def?;
        let operation = data.op(def);
        match operation.opcode {
            op::INT_ADD | op::INT_SUB | op::INT_MULT | op::INT_AND | op::INT_OR | op::INT_XOR
                if operation.inputs.len() >= 2 =>
            {
                let left = evaluate_default_inner(
                    data,
                    operation.inputs[0],
                    join,
                    replacement,
                    read_memory,
                    seen,
                )?;
                let right = evaluate_default_inner(
                    data,
                    operation.inputs[1],
                    join,
                    replacement,
                    read_memory,
                    seen,
                )?;
                Some(match operation.opcode {
                    op::INT_ADD => left.wrapping_add(right),
                    op::INT_SUB => left.wrapping_sub(right),
                    op::INT_MULT => left.wrapping_mul(right),
                    op::INT_AND => left & right,
                    op::INT_OR => left | right,
                    op::INT_XOR => left ^ right,
                    _ => unreachable!("matched binary operation"),
                })
            }
            op::INT_LEFT | op::INT_RIGHT | op::INT_SRIGHT if operation.inputs.len() >= 2 => {
                let input = evaluate_default_inner(
                    data,
                    operation.inputs[0],
                    join,
                    replacement,
                    read_memory,
                    seen,
                )?;
                let shift = evaluate_default_inner(
                    data,
                    operation.inputs[1],
                    join,
                    replacement,
                    read_memory,
                    seen,
                )?;
                let shift = u32::try_from(shift).ok()?;
                Some(match operation.opcode {
                    op::INT_LEFT => input.checked_shl(shift).unwrap_or(0),
                    op::INT_RIGHT => input.checked_shr(shift).unwrap_or(0),
                    op::INT_SRIGHT => {
                        let size = data.varnode(value).size;
                        let bits = size.saturating_mul(8);
                        if bits == 0 || bits >= u64::BITS {
                            input.wrapping_shr(shift)
                        } else {
                            let mask = mask_for_size(size);
                            let signed = ((input & (1u64 << (bits - 1))) != 0)
                                .then_some(input | !mask)
                                .unwrap_or(input);
                            signed.wrapping_shr(shift)
                        }
                    }
                    _ => unreachable!("matched shift operation"),
                })
            }
            op::LOAD => {
                let address = evaluate_default_inner(
                    data,
                    *operation.inputs.get(1)?,
                    join,
                    replacement,
                    read_memory,
                    seen,
                )?;
                let output = operation.output?;
                let size = data.varnode(output).size;
                read_memory(address, size)
            }
            op::SUBPIECE if operation.inputs.len() >= 2 => {
                let input = evaluate_default_inner(
                    data,
                    operation.inputs[0],
                    join,
                    replacement,
                    read_memory,
                    seen,
                )?;
                let offset = evaluate_default_inner(
                    data,
                    operation.inputs[1],
                    join,
                    replacement,
                    read_memory,
                    seen,
                )?;
                input.checked_shr(offset.checked_mul(8).and_then(|v| u32::try_from(v).ok())?)
            }
            op::PIECE if operation.inputs.len() >= 2 => {
                let high = evaluate_default_inner(
                    data,
                    operation.inputs[0],
                    join,
                    replacement,
                    read_memory,
                    seen,
                )?;
                let low = evaluate_default_inner(
                    data,
                    operation.inputs[1],
                    join,
                    replacement,
                    read_memory,
                    seen,
                )?;
                let low_size = data.varnode(operation.inputs[1]).size;
                Some(
                    high.checked_shl(low_size.saturating_mul(8))
                        .unwrap_or(0)
                        .wrapping_add(low),
                )
            }
            _ => None,
        }
    };
    seen.remove(&value);
    result
}

fn evaluate_default(
    data: &Funcdata,
    value: VarnodeId,
    join: VarnodeId,
    replacement: u64,
    read_memory: &dyn Fn(u64, u32) -> Option<u64>,
) -> Option<u64> {
    evaluate_default_inner(
        data,
        value,
        join,
        replacement,
        read_memory,
        &mut BTreeSet::new(),
    )
}

fn guard_bound(data: &Funcdata, compare: OpId, switch_value: VarnodeId) -> Option<u64> {
    let operation = data.op(compare);
    let left = *operation.inputs.first()?;
    let right = *operation.inputs.get(1)?;
    if !jumptable::same_value(data, left, switch_value) {
        return None;
    }
    let limit = jumptable::constant_value(data, right)?;
    match operation.opcode {
        op::INT_LESS => Some(limit),
        op::INT_LESSEQUAL => limit.checked_add(1),
        _ => None,
    }
}

/// Find the guard protecting the table-producing predecessor of the phi.
/// This is `JumpBasic::analyzeGuards`/`findSmallestNormal` restricted to the
/// second-stage path (`jumptable.cc:1050-1127`, `1173-1210`).
fn find_stage_guard(
    data: &Funcdata,
    dynamic_block: GraphBlockId,
    switch_value: VarnodeId,
) -> Option<GuardModel> {
    let mut best = None;
    for (cbranch, operation) in data.live_ops() {
        if operation.opcode != op::CBRANCH || operation.inputs.len() < 2 {
            continue;
        }
        let condition = jumptable::strip_alias(data, operation.inputs[1]);
        let Some(compare) = data.varnode(condition).def else {
            continue;
        };
        if !matches!(data.op(compare).opcode, op::INT_LESS | op::INT_LESSEQUAL) {
            continue;
        }
        let Some(bound) = guard_bound(data, compare, switch_value) else {
            continue;
        };
        if bound == 0 || bound > MAX_TABLE_ENTRIES {
            continue;
        }
        let Some(guard_block) = operation.parent else {
            continue;
        };
        let successors = &data.block(guard_block).successors;
        let relation = if successors.len() == 2 {
            let first = jumptable::block_reaches(data, successors[0], dynamic_block);
            let second = jumptable::block_reaches(data, successors[1], dynamic_block);
            if !first && !second {
                continue;
            }
            if first == second {
                None
            } else if first {
                Some(data.block(successors[1]).start)
            } else {
                Some(data.block(successors[0]).start)
            }
        } else if jumptable::block_reaches(data, guard_block, dynamic_block) {
            None
        } else {
            continue;
        };
        let candidate = GuardModel {
            bound,
            default_target: relation,
        };
        if best.is_none_or(|current: GuardModel| candidate.bound < current.bound) {
            best = Some(candidate);
        }
        let _ = cbranch;
    }
    best
}

/// Recover a two-stage jump table.
///
/// This is the public entry point Main can place after the ordinary basic
/// model.  It returns the same table representation as
/// [`super::jumptable::recover_jump_tables`].
///
/// The returned cases are the normalized range values (`0..bound`), matching
/// the existing local basic model.  The default path is evaluated through the
/// post-phi calculation, so a default constant that feeds a LOAD is read from
/// the same image accessor rather than guessed from a graph edge.
pub fn recover_jump_basic2(
    data: &Funcdata,
    branch: OpId,
    read_memory: &dyn Fn(u64, u32) -> Option<u64>,
) -> Option<JumpTable> {
    if data.op(branch).opcode != op::BRANCHIND {
        return None;
    }
    let branch_input = *data.op(branch).inputs.first()?;

    // `JumpBasic`'s path meld stops at marker outputs.  For this model the
    // final common value must therefore be the two-input phi that carries the
    // default and table paths.
    let initial_path = find_determining(data, branch, 0);
    let join = initial_path.last_common()?;
    let join_def = data.varnode(join).def?;
    if data.op(join_def).opcode != op::MULTIEQUAL {
        return None;
    }
    let (default_slot, dynamic_slot, dynamic_input, default_value) =
        default_phi_path(data, join_def)?;

    // Re-run the path search from the non-default phi input.  Appending the
    // original path is the operation performed by JumpBasic2::recoverModel
    // at `jumptable.cc:1726-1729`; it also gives us the normalized leaf while
    // retaining the split path rather than treating the phi as a plain copy.
    let dynamic_path = find_determining(data, join_def, dynamic_slot);
    let mut complete_path = dynamic_path.clone();
    complete_path.append(&initial_path);
    let normalized = complete_path.last_common()?;

    let destination = parse_destination_through_join(data, branch_input, join, dynamic_input)?;
    if !jumptable::same_value(data, normalized, destination.address.index) {
        return None;
    }

    let join_parent = data.op(join_def).parent?;
    let predecessors = &data.block(join_parent).predecessors;
    let dynamic_block = *predecessors.get(dynamic_slot)?;
    // Keep the default slot tied to a real predecessor as Ghidra does when it
    // calls `getIn(1-path)`; an unconnected phi is not a two-stage CFG.
    let _default_block = *predecessors.get(default_slot)?;
    let guard = find_stage_guard(data, dynamic_block, destination.address.index)?;

    let count = usize::try_from(guard.bound).ok()?;
    let mut cases = Vec::with_capacity(count);
    for label in 0..guard.bound {
        let offset = label.checked_mul(destination.address.stride)?;
        let address = destination.address.base.checked_add(offset)?;
        let target = read_memory(address, destination.entry_size)?;
        cases.push((label, target.wrapping_add(destination.target_bias)));
    }

    // `JumpValuesRangeDefault` iterates this extra value last and starts the
    // emulator at the phi output.  Evaluating the branch expression with the
    // default value substituted is the graph-native equivalent.
    let default_target = evaluate_default(data, branch_input, join, default_value, read_memory)?;

    Some(JumpTable {
        branch,
        switch_value: destination.address.index,
        cases,
        default_target: Some(default_target),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{RAM_SPACE, REGISTER_SPACE};

    fn seq(order: u32) -> super::super::SeqNum {
        super::super::SeqNum {
            address: 0x1000 + u64::from(order),
            order,
        }
    }

    struct Fixture {
        data: Funcdata,
        branch: OpId,
        index: VarnodeId,
        table_base: u64,
        entries: Vec<u64>,
        default_target: u64,
    }

    fn two_stage_fixture() -> Fixture {
        let mut data = Funcdata {
            entry: 0x1000,
            ..Funcdata::default()
        };
        let entry = data.new_block(0x1000);
        let guard_block = data.new_block(0x1010);
        let default_block = data.new_block(0x2000);
        let dynamic_block = data.new_block(0x1020);
        let join_block = data.new_block(0x1030);
        data.add_edge(entry, guard_block);
        data.add_edge(guard_block, default_block);
        data.add_edge(guard_block, dynamic_block);
        data.add_edge(default_block, join_block);
        data.add_edge(dynamic_block, join_block);

        let index = data.new_varnode(REGISTER_SPACE, 0, 1);
        data.mark_input(index);
        let bound = data.new_constant(3, 4);
        let compare = data.new_op(op::INT_LESS, seq(0), vec![index, bound]);
        let comparison = data.new_unique(1);
        data.op_set_output(compare, Some(comparison));
        data.op_insert_end(compare, guard_block);
        let guard_target = data.new_constant(data.block(dynamic_block).start, 8);
        let cbranch = data.new_op(op::CBRANCH, seq(1), vec![guard_target, comparison]);
        data.op_insert_end(cbranch, guard_block);

        let table_base = 0x8000;
        let default_target = 0x5000;
        // The phi carries a table *offset*, not a final target.  This is the
        // `JumpBasic2` shape where the original path is appended after the
        // split and the common LOAD is performed afterwards.
        let default_value = data.new_constant(3 * 8, 8);
        let default_copy_out = data.new_unique(8);
        let default_copy = data.new_op(op::COPY, seq(2), vec![default_value]);
        data.op_set_output(default_copy, Some(default_copy_out));
        data.op_insert_end(default_copy, default_block);

        let stride = data.new_constant(8, 4);
        let scaled = data.new_unique(8);
        let scale = data.new_op(op::INT_MULT, seq(3), vec![index, stride]);
        data.op_set_output(scale, Some(scaled));
        data.op_insert_end(scale, dynamic_block);

        // The predecessor insertion order is the MULTIEQUAL input order.
        let joined = data.new_unique(8);
        let phi = data.new_op(op::MULTIEQUAL, seq(4), vec![default_copy_out, scaled]);
        data.op_set_output(phi, Some(joined));
        data.op_insert_end(phi, join_block);

        let base = data.new_constant(table_base, 8);
        let address = data.new_unique(8);
        let add = data.new_op(op::INT_ADD, seq(5), vec![base, joined]);
        data.op_set_output(add, Some(address));
        data.op_insert_end(add, join_block);
        let space = data.new_constant(RAM_SPACE as u64, 4);
        let loaded = data.new_unique(8);
        let load = data.new_op(op::LOAD, seq(6), vec![space, address]);
        data.op_set_output(load, Some(loaded));
        data.op_insert_end(load, join_block);
        let branch = data.new_op(op::BRANCHIND, seq(7), vec![loaded]);
        data.op_insert_end(branch, join_block);

        Fixture {
            data,
            branch,
            index,
            table_base,
            entries: vec![0x3000, 0x3010, 0x3020, default_target],
            default_target,
        }
    }

    #[test]
    fn two_stage_table_recovers_cases_and_default() {
        let fixture = two_stage_fixture();
        let entries = fixture.entries.clone();
        let base = fixture.table_base;
        let recovered =
            recover_jump_basic2(&fixture.data, fixture.branch, &move |address, width| {
                assert_eq!(width, 8);
                let index = usize::try_from((address - base) / 8).ok()?;
                entries.get(index).copied()
            })
            .expect("two-stage model");

        assert_eq!(recovered.branch, fixture.branch);
        assert_eq!(recovered.switch_value, fixture.index);
        assert_eq!(recovered.cases, vec![(0, 0x3000), (1, 0x3010), (2, 0x3020)]);
        assert_eq!(recovered.default_target, Some(fixture.default_target));
    }

    #[test]
    fn model_declines_without_a_default_copy_path() {
        let mut fixture = two_stage_fixture();
        let phi = fixture
            .data
            .live_ops()
            .find(|(_, operation)| operation.opcode == op::MULTIEQUAL)
            .map(|(id, _)| id)
            .expect("phi");
        let dynamic = fixture.data.op(phi).inputs[1];
        let replacement = fixture.data.new_unique(8);
        let copy = fixture.data.new_op(op::COPY, seq(8), vec![dynamic]);
        fixture.data.op_set_output(copy, Some(replacement));
        fixture.data.op_set_input(phi, replacement, 0);
        assert!(recover_jump_basic2(&fixture.data, fixture.branch, &|_, _| None).is_none());
    }
}
