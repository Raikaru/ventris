//! Function basic-block graph + layered layout (Phase 2.1).
//!
//! `basic_blocks` walks a function from its entry with the in-Rust decoder
//! (flow kinds give exact edge targets) and splits basic blocks on control
//! transfers. `layered_layout` assigns ranks (longest-path layering),
//! orders nodes within ranks (barycenter passes), and emits coordinates —
//! the same layout for every frontend, computed in core rather than C++.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

/// One basic block: [address, address + size).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BbNode {
    pub address: u64,
    pub size: u64,
}

/// Edge kind mirrors the roadmap typing: true / false / unconditional / call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BbEdgeKind {
    True,
    False,
    Unconditional,
    Call,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BbEdge {
    pub from: u64,
    pub to: u64,
    pub kind: BbEdgeKind,
}

#[derive(Clone, Debug, Default)]
pub struct BbGraph {
    pub nodes: Vec<BbNode>,
    pub edges: Vec<BbEdge>,
}

/// Byte reader: returns up to `size` bytes at `offset` from the mapped image.
pub type ImageReader<'a> = dyn Fn(u64, usize) -> Option<Vec<u8>> + 'a;

/// Walks the function at `entry` and splits basic blocks. Bounded by
/// `max_instructions` so pathological functions cannot loop forever.
pub fn basic_blocks(
    read: &ImageReader<'_>,
    entry: u64,
    max_instructions: usize,
) -> BbGraph {
    let mut graph = BbGraph::default();
    let mut block_starts: BTreeSet<u64> = BTreeSet::new();
    let mut block_end_flow: HashMap<u64, u64> = HashMap::new();
    let mut queue = VecDeque::new();
    let mut visited: BTreeSet<u64> = BTreeSet::new();
    queue.push_back(entry);
    block_starts.insert(entry);
    let mut instructions = 0usize;

    while let Some(block_start) = queue.pop_front() {
        let mut current = block_start;
        loop {
            if instructions >= max_instructions || visited.contains(&current) {
                break;
            }
            let Some(bytes) = read(current, 16) else {
                break;
            };
            let info = crate::disasm::decode(&bytes, current);
            instructions += 1;
            visited.insert(current);
            match info.flow {
                crate::disasm::Flow::Next => {
                    current += info.len as u64;
                }
                crate::disasm::Flow::Jump(target) => {
                    block_end_flow.insert(block_start, current + info.len as u64);
                    graph.edges.push(BbEdge {
                        from: block_start,
                        to: target,
                        kind: BbEdgeKind::Unconditional,
                    });
                    if !visited.contains(&target) && instructions < max_instructions {
                        block_starts.insert(target);
                        queue.push_back(target);
                    }
                    break;
                }
                crate::disasm::Flow::JumpCond(target) => {
                    block_end_flow.insert(block_start, current + info.len as u64);
                    let fallthrough = current + info.len as u64;
                    graph.edges.push(BbEdge {
                        from: block_start,
                        to: target,
                        kind: BbEdgeKind::True,
                    });
                    graph.edges.push(BbEdge {
                        from: block_start,
                        to: fallthrough,
                        kind: BbEdgeKind::False,
                    });
                    if !visited.contains(&target) && instructions < max_instructions {
                        block_starts.insert(target);
                        queue.push_back(target);
                    }
                    if !visited.contains(&fallthrough) && instructions < max_instructions {
                        block_starts.insert(fallthrough);
                        queue.push_back(fallthrough);
                    }
                    break;
                }
                crate::disasm::Flow::Call(target) => {
                    graph.edges.push(BbEdge {
                        from: block_start,
                        to: target,
                        kind: BbEdgeKind::Call,
                    });
                    current += info.len as u64;
                    // Calls fall through: the block continues.
                }
                crate::disasm::Flow::Indirect
                | crate::disasm::Flow::IndirectCall
                | crate::disasm::Flow::Stop => {
                    block_end_flow.insert(block_start, current + info.len as u64);
                    break;
                }
                crate::disasm::Flow::Bad => {
                    block_end_flow.insert(block_start, current + 1);
                    break;
                }
            }
        }
    }

    // Materialize blocks: [start, next_start or flow-end + len).
    let starts: Vec<u64> = block_starts.iter().copied().collect();
    for (i, &start) in starts.iter().enumerate() {
        let end = block_end_flow.get(&start).copied().unwrap_or_else(|| {
            if i + 1 < starts.len() {
                starts[i + 1]
            } else {
                start + 1
            }
        });
        graph.nodes.push(BbNode {
            address: start,
            size: (end - start).max(1),
        });
    }
    // Drop edges leaving blocks the walk never reached (cap cuts). Call
    // targets outside the function stay: they are cross-function edges.
    let reached: BTreeSet<u64> = graph.nodes.iter().map(|n| n.address).collect();
    graph.edges.retain(|e| reached.contains(&e.from));
    graph
}

/// Layered (Sugiyama-style) layout: rank by longest-path layering from the
/// entry, order within ranks by barycenter passes, position on a grid.
/// Node boxes are fixed-size; the view scales and pans.
pub struct LayoutNode {
    pub address: u64,
    pub rank: usize,
    pub order: usize,
    pub x: i64,
    pub y: i64,
}

pub const LAYOUT_NODE_WIDTH: i64 = 180;
pub const LAYOUT_NODE_HEIGHT: i64 = 60;
pub const LAYOUT_COL_GAP: i64 = 60;
pub const LAYOUT_ROW_GAP: i64 = 90;

pub fn layered_layout(graph: &BbGraph) -> Vec<LayoutNode> {
    if graph.nodes.is_empty() {
        return Vec::new();
    }
    let entry = graph.nodes.iter().map(|n| n.address).min().unwrap_or(0);
    let mut successors: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut predecessors: HashMap<u64, Vec<u64>> = HashMap::new();
    for edge in &graph.edges {
        if edge.kind == BbEdgeKind::Call {
            continue; // call edges do not shape the function's shape
        }
        successors.entry(edge.from).or_default().push(edge.to);
        predecessors.entry(edge.to).or_default().push(edge.from);
    }

    // 1. Rank: BFS layering from the entry (longest-path approximation:
    // a node's rank = max(rank of non-call predecessors) + 1).
    let mut rank: HashMap<u64, usize> = HashMap::new();
    let mut queue = VecDeque::new();
    rank.insert(entry, 0);
    queue.push_back(entry);
    while let Some(addr) = queue.pop_front() {
        let r = rank[&addr];
        for &next in successors.get(&addr).into_iter().flatten() {
            let candidate = r + 1;
            if rank.get(&next).copied().unwrap_or(usize::MAX) > candidate {
                rank.insert(next, candidate);
                queue.push_back(next);
            }
        }
    }

    // 2. Order within ranks: barycenter of predecessor orders, a few passes.
    let mut ranks: BTreeMap<usize, Vec<u64>> = BTreeMap::new();
    for (&addr, &r) in &rank {
        ranks.entry(r).or_default().push(addr);
    }
    for level in ranks.values_mut() {
        level.sort_unstable();
    }
    let mut order: HashMap<u64, usize> = HashMap::new();
    for level in ranks.values() {
        for (i, &addr) in level.iter().enumerate() {
            order.insert(addr, i);
        }
    }
    for _ in 0..4 {
        let ranks_snapshot: Vec<Vec<u64>> = ranks.values().cloned().collect();
        for down in [true, false] {
            let levels: &Vec<Vec<u64>> = if down {
                &ranks_snapshot
            } else {
                &ranks_snapshot
            };
            let iter: Vec<&Vec<u64>> = if down {
                levels.iter().collect()
            } else {
                levels.iter().rev().collect()
            };
            for level in iter {
                let mut scored: Vec<(f64, u64)> = level
                    .iter()
                    .map(|&addr| {
                        let neighbors = if down {
                            predecessors.get(&addr)
                        } else {
                            successors.get(&addr)
                        };
                        let barycenter = neighbors
                            .map(|ns| {
                                if ns.is_empty() {
                                    order[&addr] as f64
                                } else {
                                    ns.iter()
                                        .map(|n| order.get(n).copied().unwrap_or(0) as f64)
                                        .sum::<f64>()
                                        / ns.len() as f64
                                }
                            })
                            .unwrap_or(order[&addr] as f64);
                        (barycenter, addr)
                    })
                    .collect();
                scored.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
                for (i, &(_, addr)) in scored.iter().enumerate() {
                    order.insert(addr, i);
                }
            }
        }
        // Rebuild ranks in the new order.
        for level in ranks.values_mut() {
            level.sort_unstable_by_key(|&addr| order[&addr]);
            for (i, &addr) in level.iter().enumerate() {
                order.insert(addr, i);
            }
        }
    }

    // 3. Coordinates.
    let mut nodes = Vec::new();
    for (&r, level) in &ranks {
        for &addr in level {
            nodes.push(LayoutNode {
                address: addr,
                rank: r,
                order: order[&addr],
                x: order[&addr] as i64 * (LAYOUT_NODE_WIDTH + LAYOUT_COL_GAP),
                y: r as i64 * (LAYOUT_NODE_HEIGHT + LAYOUT_ROW_GAP),
            });
        }
    }
    nodes
}

/// Wire shape for the bridge: nodes + typed edges with layout coordinates.
pub fn graph_wire(graph: &BbGraph, layout: &[LayoutNode]) -> serde_json::Value {
    let nodes: Vec<serde_json::Value> = layout
        .iter()
        .map(|n| {
            serde_json::json!({
                "address": format!("{:x}", n.address),
                "size": graph
                    .nodes
                    .iter()
                    .find(|b| b.address == n.address)
                    .map(|b| b.size)
                    .unwrap_or(0),
                "x": n.x,
                "y": n.y,
            })
        })
        .collect();
    let edges: Vec<serde_json::Value> = graph
        .edges
        .iter()
        .map(|e| {
            serde_json::json!({
                "from": format!("{:x}", e.from),
                "to": format!("{:x}", e.to),
                "kind": match e.kind {
                    BbEdgeKind::True => "true",
                    BbEdgeKind::False => "false",
                    BbEdgeKind::Unconditional => "unconditional",
                    BbEdgeKind::Call => "call",
                },
            })
        })
        .collect();
    serde_json::json!({ "nodes": nodes, "edges": edges })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic function: entry; jcc target; target: ret. Bytes:
    /// 0x40: test eax,eax (85 c0); 0x42: jz +2 (74 02); 0x44: ret (c3);
    /// 0x45: ret (c3) at target 0x46? Keep it simple and hand-computed.
    fn reader_for(bytes: &[(u64, u8)]) -> impl Fn(u64, usize) -> Option<Vec<u8>> + '_ {
        move |offset, size| {
            let mut out = Vec::new();
            for i in 0..size {
                let addr = offset + i as u64;
                if let Some(&(_, b)) = bytes.iter().find(|(a, _)| *a == addr) {
                    out.push(b);
                } else {
                    break;
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(out)
            }
        }
    }

    #[test]
    fn splits_conditional_branch_into_three_blocks() {
        // 0x1000: 85 C0       test eax, eax      (Next)
        // 0x1002: 74 05       jz 0x1009          (JumpCond -> 0x1009)
        // 0x1004: C3          ret                (Stop)
        // 0x1009: C3          ret                (Stop)
        let bytes = [(0x1000u64, 0x85u8), (0x1001, 0xC0), (0x1002, 0x74), (0x1003, 0x05), (0x1004, 0xC3), (0x1009, 0xC3)];
        let read = reader_for(&bytes);
        let graph = basic_blocks(&read, 0x1000, 64);
        let mut addrs: Vec<u64> = graph.nodes.iter().map(|n| n.address).collect();
        addrs.sort_unstable();
        assert_eq!(addrs, vec![0x1000, 0x1004, 0x1009]);
        // true edge to 0x1009, false edge to 0x1004 (fallthrough)
        // Edges reference block addresses: the jcc ends the block at 0x1000.
        assert!(graph
            .edges
            .iter()
            .any(|e| e.from == 0x1000 && e.to == 0x1009 && e.kind == BbEdgeKind::True));
        assert!(graph
            .edges
            .iter()
            .any(|e| e.from == 0x1000 && e.to == 0x1004 && e.kind == BbEdgeKind::False));
    }

    #[test]
    fn call_edges_typed_and_walk_continues() {
        // 0x2000: E8 05 00 00 00   call 0x200a   (Call, falls through)
        // 0x2005: C3               ret
        // 0x200a: C3               ret
        let bytes = [
            (0x2000u64, 0xE8u8),
            (0x2001, 0x05),
            (0x2002, 0x00),
            (0x2003, 0x00),
            (0x2004, 0x00),
            (0x2005, 0xC3),
            (0x200a, 0xC3),
        ];
        let read = reader_for(&bytes);
        let graph = basic_blocks(&read, 0x2000, 64);
        assert!(graph
            .edges
            .iter()
            .any(|e| e.kind == BbEdgeKind::Call && e.from == 0x2000 && e.to == 0x200a));
        // Calls fall through within the same block: one block covering
        // call (5 bytes) + ret (1 byte).
        let block = graph.nodes.iter().find(|n| n.address == 0x2000).unwrap();
        assert_eq!(block.size, 6);
    }

    #[test]
    fn layout_assigns_ranks_and_orders() {
        // entry -> a (true/false), entry -> b; b deeper than a.
        let graph = BbGraph {
            nodes: vec![
                BbNode { address: 0x1000, size: 4 },
                BbNode { address: 0x1004, size: 4 },
                BbNode { address: 0x1009, size: 4 },
            ],
            edges: vec![
                BbEdge { from: 0x1000, to: 0x1009, kind: BbEdgeKind::True },
                BbEdge { from: 0x1000, to: 0x1004, kind: BbEdgeKind::False },
            ],
        };
        let layout = layered_layout(&graph);
        assert_eq!(layout.len(), 3);
        let entry = layout.iter().find(|n| n.address == 0x1000).unwrap();
        let a = layout.iter().find(|n| n.address == 0x1004).unwrap();
        let b = layout.iter().find(|n| n.address == 0x1009).unwrap();
        assert_eq!(entry.rank, 0);
        assert_eq!(a.rank, 1);
        assert_eq!(b.rank, 1);
        assert_eq!(entry.y, 0);
        assert!(a.y > entry.y && b.y > entry.y);
    }
}
