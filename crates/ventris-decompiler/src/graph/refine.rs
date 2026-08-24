//! Location refinement, ported from Ghidra 12.1.3's `Heritage`.
//!
//! A function may write a register as a word and read one byte of it, or write
//! two halves and read the whole. SSA keyed on exact `(space, offset, size)`
//! cannot relate those accesses, so a naive renaming loses the flow. Ghidra
//! resolves it before renaming: it cuts every overlapping address range at the
//! union of all access boundaries, then rewrites each access that spans several
//! cells. A read becomes a `PIECE` expression over the cells; a write becomes a
//! `SUBPIECE` per cell.
//!
//! Source authority: `Heritage::buildRefinement`, `splitByRefinement`,
//! `refineRead`, `refineWrite`, `concatPieces`, `splitPieces` in `heritage.cc`
//! at commit `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use std::collections::{BTreeMap, BTreeSet};

use ventris_pcode::op;

use super::{Funcdata, OpId, SeqNum, VarnodeId};

/// One maximal run of overlapping accesses, cut at every access boundary.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Refinement {
    pub space: u32,
    pub start: u64,
    /// Cut points relative to `start`, ascending, including `0` and the length.
    pub boundaries: Vec<u64>,
}

impl Refinement {
    /// The cells this refinement divides its range into, as `(offset, size)`.
    pub fn cells(&self) -> Vec<(u64, u32)> {
        self.boundaries
            .windows(2)
            .filter_map(|pair| {
                let size = u32::try_from(pair[1] - pair[0]).ok()?;
                (size > 0).then_some((self.start + pair[0], size))
            })
            .collect()
    }

    /// The cells covering one access, or `None` when the access is not covered
    /// exactly by cell boundaries.
    fn cover(&self, offset: u64, size: u32) -> Option<Vec<(u64, u32)>> {
        let end = offset.checked_add(u64::from(size))?;
        let covered: Vec<(u64, u32)> = self
            .cells()
            .into_iter()
            .filter(|(cell, cell_size)| {
                *cell >= offset && cell.saturating_add(u64::from(*cell_size)) <= end
            })
            .collect();
        let total: u64 = covered.iter().map(|(_, size)| u64::from(*size)).sum();
        (total == u64::from(size) && !covered.is_empty()).then_some(covered)
    }
}

/// Groups every accessed location into overlapping ranges cut at all boundaries.
///
/// This is `buildRefinement`: each access contributes a cut at its start and at
/// the byte after its end, so the resulting cells never straddle an access.
pub fn build_refinements(data: &Funcdata) -> Vec<Refinement> {
    let mut accesses: BTreeMap<u32, BTreeSet<(u64, u32)>> = BTreeMap::new();
    for index in 0..data.varnode_count() {
        let varnode = data.varnode(VarnodeId(index as u32));
        if varnode.flags.constant || varnode.size == 0 {
            continue;
        }
        accesses
            .entry(varnode.space)
            .or_default()
            .insert((varnode.offset, varnode.size));
    }

    let mut refinements = Vec::new();
    for (space, locations) in accesses {
        let mut run: Option<(u64, u64, BTreeSet<u64>)> = None;
        for (offset, size) in locations {
            let end = offset.saturating_add(u64::from(size));
            match run.as_mut() {
                Some((start, run_end, cuts)) if offset < *run_end => {
                    *run_end = (*run_end).max(end);
                    cuts.insert(offset - *start);
                    cuts.insert(end - *start);
                }
                _ => {
                    if let Some((start, run_end, cuts)) = run.take() {
                        refinements.push(finish_run(space, start, run_end, cuts));
                    }
                    run = Some((offset, end, BTreeSet::from([0, end - offset])));
                }
            }
        }
        if let Some((start, run_end, cuts)) = run.take() {
            refinements.push(finish_run(space, start, run_end, cuts));
        }
    }
    refinements
        .into_iter()
        .filter(|refinement| refinement.boundaries.len() > 2)
        .collect()
}

fn finish_run(space: u32, start: u64, end: u64, mut cuts: BTreeSet<u64>) -> Refinement {
    cuts.insert(0);
    cuts.insert(end - start);
    Refinement {
        space,
        start,
        boundaries: cuts.into_iter().collect(),
    }
}

/// Rewrites every access that spans more than one refinement cell.
///
/// Returns the number of accesses rewritten. Reads become `PIECE` chains and
/// writes become `SUBPIECE` extractions, which is what lets SSA renaming key on
/// cells while the program keeps its original values.
pub fn refine_accesses(data: &mut Funcdata, big_endian: bool) -> usize {
    let refinements = build_refinements(data);
    if refinements.is_empty() {
        return 0;
    }
    let mut rewritten = 0;
    for index in 0..data.varnode_count() {
        let id = VarnodeId(index as u32);
        let varnode = data.varnode(id);
        if varnode.flags.constant || varnode.size == 0 {
            continue;
        }
        let (space, offset, size) = (varnode.space, varnode.offset, varnode.size);
        let Some(refinement) = refinements
            .iter()
            .find(|refinement| refinement.space == space && refinement.covers(offset, size))
        else {
            continue;
        };
        let Some(cells) = refinement.cover(offset, size) else {
            continue;
        };
        if cells.len() < 2 {
            continue;
        }
        if data.varnode(id).flags.written {
            if refine_write(data, id, &cells, big_endian) {
                rewritten += 1;
            }
        } else if refine_read(data, id, &cells, big_endian) {
            rewritten += 1;
        }
    }
    rewritten
}

impl Refinement {
    fn covers(&self, offset: u64, size: u32) -> bool {
        let end = self.start + self.boundaries.last().copied().unwrap_or_default();
        offset >= self.start && offset.saturating_add(u64::from(size)) <= end
    }
}

/// Replaces a spanning read with a concatenation of its cells.
fn refine_read(data: &mut Funcdata, id: VarnodeId, cells: &[(u64, u32)], big_endian: bool) -> bool {
    let Some(reader) = data.lone_descend(id) else {
        return false;
    };
    let slot = data
        .op(reader)
        .inputs
        .iter()
        .position(|input| *input == id)
        .expect("the reader reads this value");
    let space = data.varnode(id).space;
    let size = data.varnode(id).size;
    let seq = data.op(reader).seq;
    let pieces: Vec<VarnodeId> = ordered_cells(cells, big_endian)
        .into_iter()
        .map(|(offset, cell_size)| data.new_varnode(space, offset, cell_size))
        .collect();
    let combined = concat_pieces(data, &pieces, reader, seq, size);
    data.op_set_input(reader, combined, slot);
    true
}

/// Replaces a spanning write with per-cell extractions of the written value.
fn refine_write(
    data: &mut Funcdata,
    id: VarnodeId,
    cells: &[(u64, u32)],
    big_endian: bool,
) -> bool {
    let Some(definition) = data.varnode(id).def else {
        return false;
    };
    let space = data.varnode(id).space;
    let base = data.varnode(id).offset;
    let size = data.varnode(id).size;
    let seq = data.op(definition).seq;
    let whole = data.new_unique(size);
    data.op_set_output(definition, Some(whole));
    let mut previous = definition;
    for (offset, cell_size) in cells.iter().copied() {
        let shift = if big_endian {
            base + u64::from(size) - (offset + u64::from(cell_size))
        } else {
            offset - base
        };
        let cell = data.new_varnode(space, offset, cell_size);
        let amount = data.new_constant(shift, 4);
        let extract = data.new_op(op::SUBPIECE, seq, vec![whole, amount]);
        data.op_set_output(extract, Some(cell));
        data.op_insert_after(extract, previous);
        previous = extract;
    }
    true
}

/// Orders cells most-significant first, matching `concatPieces`.
fn ordered_cells(cells: &[(u64, u32)], big_endian: bool) -> Vec<(u64, u32)> {
    let mut ordered = cells.to_vec();
    if big_endian {
        ordered.sort_by_key(|(offset, _)| *offset);
    } else {
        ordered.sort_by_key(|(offset, _)| std::cmp::Reverse(*offset));
    }
    ordered
}

/// Builds a `PIECE` chain over `pieces`, most significant first.
fn concat_pieces(
    data: &mut Funcdata,
    pieces: &[VarnodeId],
    before: OpId,
    seq: SeqNum,
    total: u32,
) -> VarnodeId {
    let mut accumulated = pieces[0];
    for piece in &pieces[1..] {
        let width = data.varnode(accumulated).size + data.varnode(*piece).size;
        let op = data.new_op(op::PIECE, seq, vec![accumulated, *piece]);
        let output = if width == total {
            data.new_unique(total)
        } else {
            data.new_unique(width)
        };
        data.op_set_output(op, Some(output));
        data.op_insert_before(op, before);
        accumulated = output;
    }
    accumulated
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::REGISTER_SPACE;

    fn graph_with(accesses: &[(u64, u32, bool)]) -> Funcdata {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let seq = SeqNum {
            address: 0x1000,
            order: 0,
        };
        let anchor = data.new_op(op::RETURN, seq, vec![]);
        data.op_insert_end(anchor, block);
        for (offset, size, written) in accesses.iter().copied() {
            let value = data.new_varnode(REGISTER_SPACE, offset, size);
            if written {
                let op = data.new_op(op::COPY, seq, vec![]);
                data.op_set_output(op, Some(value));
                data.op_insert_before(op, anchor);
            } else {
                let op = data.new_op(op::COPY, seq, vec![value]);
                data.op_insert_before(op, anchor);
            }
        }
        data
    }

    #[test]
    fn a_word_and_its_byte_produce_cut_points_at_every_boundary() {
        let data = graph_with(&[(8, 4, true), (9, 1, false)]);
        let refinements = build_refinements(&data);
        assert_eq!(refinements.len(), 1);
        assert_eq!(
            refinements[0].cells(),
            vec![(8, 1), (9, 1), (10, 2)],
            "cells must not straddle either access"
        );
    }

    #[test]
    fn disjoint_locations_need_no_refinement() {
        let data = graph_with(&[(8, 4, true), (16, 4, false)]);
        assert!(build_refinements(&data).is_empty());
    }

    #[test]
    fn a_spanning_read_becomes_a_concatenation() {
        let mut data = graph_with(&[(8, 4, false), (9, 1, true)]);
        assert_eq!(refine_accesses(&mut data, false), 1);
        let pieces = data
            .live_ops()
            .filter(|(_, candidate)| candidate.opcode == op::PIECE)
            .count();
        assert_eq!(pieces, 2, "three cells concatenate with two PIECE ops");
    }

    #[test]
    fn a_spanning_write_becomes_per_cell_extractions() {
        let mut data = graph_with(&[(8, 4, true), (9, 1, false)]);
        assert_eq!(refine_accesses(&mut data, false), 1);
        let extracts: Vec<_> = data
            .live_ops()
            .filter(|(_, candidate)| candidate.opcode == op::SUBPIECE)
            .collect();
        assert_eq!(extracts.len(), 3, "one extraction per cell");
        for (_, extract) in extracts {
            let amount = data.varnode(extract.inputs[1]);
            assert!(amount.flags.constant, "the shift is a constant");
        }
    }

    #[test]
    fn big_endian_extractions_shift_from_the_other_end() {
        let mut data = graph_with(&[(8, 4, true), (9, 1, false)]);
        refine_accesses(&mut data, true);
        let shifts: BTreeSet<u64> = data
            .live_ops()
            .filter(|(_, candidate)| candidate.opcode == op::SUBPIECE)
            .map(|(_, candidate)| data.varnode(candidate.inputs[1]).offset)
            .collect();
        assert_eq!(shifts, BTreeSet::from([0, 2, 3]));
    }
}
