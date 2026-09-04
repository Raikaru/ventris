//! Mapped-image discovery: SLEIGH supplies instruction lengths and call targets;
//! the existing worklist supplies control-flow closure. No ISA-specific decoder.
use super::{close_call_targets, code_ranges, extern_name, filter_candidate, CandidateFilterContext, ImportError, NativeFunction, NativeImport, NativeXref, Result};
use crate::native_runtime::{ConsoleSession, FlowKind};
use std::collections::{HashMap, HashSet};

pub(super) fn discover_mapped(import: &mut NativeImport) -> Result<()> {
    let mut session = ConsoleSession::new(&import.cfg)
        .map_err(|e| ImportError::Bad(e.to_string()))?;
    session.load_mapped(import).map_err(|e| ImportError::Bad(e.to_string()))?;
    let ranges = code_ranges(import);
    let in_code = |address| ranges.iter().any(|&(start, end)| start <= address && address < end);
    let mut cursors: Vec<_> = ranges.iter().map(|&(start, end)| (start, end, true)).collect();
    let mut candidates = Vec::new();
    let mut addresses = Vec::with_capacity(cursors.len());
    let mut decoded = HashMap::new();
    // Stripped images retain calls in code that is not reachable from startup.
    // Walk section bytes by the decoder's lengths, including after terminators.
    while !cursors.is_empty() {
        addresses.clear();
        addresses.extend(cursors.iter().map(|&(address, _, _)| address));
        let flows = session.try_flow_batch(&addresses);
        if flows.len() != addresses.len() {
            return super::err("incomplete SLEIGH seed scan");
        }
        for ((address, end, boundary), flow) in cursors.iter_mut().zip(flows) {
            if flow.address != *address || flow.length == 0 {
                return super::err("invalid SLEIGH seed-scan response");
            }
            if !matches!(flow.kind, FlowKind::Bad | FlowKind::Unimpl) {
                if *boundary {
                    candidates.push(*address);
                }
                *boundary = flow.kind == FlowKind::Return;
            }
            if flow.kind == FlowKind::Call {
                for &target in &flow.targets {
                    if in_code(target) {
                        import.xrefs.push(NativeXref::new(*address, target, "UNCONDITIONAL_CALL"));
                    }
                }
            }
            let next = address.saturating_add(flow.length as u64).min(*end);
            decoded.insert(*address, flow);
            *address = next;
        }
        cursors.retain(|&(address, end, _)| address < end);
    }
    close_call_targets(import);
    let mut failure = None;
    flow_discover_with_candidates(import, &candidates, |chunk| {
        let mut results = Vec::with_capacity(chunk.len());
        for address in chunk {
            if !decoded.contains_key(address) {
                match session.flow(*address) {
                    Ok(flow) => { decoded.insert(*address, flow); }
                    Err(error) => { failure = Some(error); return Vec::new(); }
                }
            }
            results.push(decoded[address].clone());
        }
        results
    });
    if let Some(error) = failure {
        return Err(ImportError::Bad(error.to_string()));
    }
    Ok(())
}
fn get_canonical_origin(mut addr: u64, addr_origin: &std::collections::HashMap<u64, u64>) -> u64 {
    let mut hops = 0;
    while let Some(&parent) = addr_origin.get(&addr) {
        if parent == addr || hops >= 64 {
            break;
        }
        addr = parent;
        hops += 1;
    }
    addr
}

fn merge_reached_candidate(
    target: u64,
    origin: u64,
    reloc_set: &HashSet<u64>,
    addr_origin: &mut std::collections::HashMap<u64, u64>,
    proven_bodies: &mut std::collections::HashMap<u64, u64>,
) {
    if !reloc_set.contains(&target) {
        return;
    }
    let canon_origin = get_canonical_origin(origin, addr_origin);
    let canon_target = get_canonical_origin(target, addr_origin);
    if canon_target != canon_origin {
        addr_origin.insert(target, canon_origin);
        addr_origin.insert(canon_target, canon_origin);
        for v in addr_origin.values_mut() {
            if *v == target || *v == canon_target {
                *v = canon_origin;
            }
        }
        if let Some(t_span) = proven_bodies.remove(&target) {
            proven_bodies
                .entry(canon_origin)
                .and_modify(|e| *e = (*e).max(t_span))
                .or_insert(t_span);
        }
        if let Some(t_span) = proven_bodies.remove(&canon_target) {
            proven_bodies
                .entry(canon_origin)
                .and_modify(|e| *e = (*e).max(t_span))
                .or_insert(t_span);
        }
    }
}

/// Core flow-based discovery over a provided control-flow resolver.
pub fn flow_discover_with_provider<F: FnMut(&[u64]) -> Vec<crate::native_runtime::FlowResult>>(
    imp: &mut NativeImport,
    flow_provider: F,
) {
    flow_discover_with_candidates(imp, &[], flow_provider);
}

fn flow_discover_with_candidates<F: FnMut(&[u64]) -> Vec<crate::native_runtime::FlowResult>>(
    imp: &mut NativeImport,
    candidates: &[u64],
    mut flow_provider: F,
) {
    use crate::native_runtime::FlowKind;
    let code = code_ranges(imp);
    let in_code = |a: u64| code.iter().any(|(v, e)| a >= *v && a < *e);
    // Initial discovery from trusted seeds first:
    let mut entries: Vec<u64> = imp
        .functions
        .iter()
        .map(|f| f.entry)
        .chain(imp.externals.iter().map(|(a, _)| *a))
        .filter(|a| *a != 0 && in_code(*a))
        .collect();
    entries.sort_unstable();
    entries.dedup();

    let mut calls: Vec<(u64, u64)> = Vec::new();
    let mut instruction_extents = Vec::new();
    let mut proven_bodies: std::collections::HashMap<u64, u64> = std::collections::HashMap::with_capacity(4096);
    let mut addr_origin: std::collections::HashMap<u64, u64> = std::collections::HashMap::with_capacity(32768);
    for &s in &entries {
        addr_origin.insert(s, s);
    }
    let mut visited: HashSet<u64> = HashSet::with_capacity(32768);
    let mut active: Vec<u64> = entries.clone();
    while !active.is_empty() {
        active.sort_unstable();
        active.dedup();
        let to_query: Vec<u64> = active
            .drain(..)
            .filter(|a| *a != 0 && in_code(*a) && visited.insert(*a))
            .collect();
        if to_query.is_empty() {
            break;
        }

        let mut next_active: Vec<u64> = Vec::new();
        for chunk in to_query.chunks(1024) {
            let flows = flow_provider(chunk);
            for (addr, info) in chunk.iter().copied().zip(flows) {
                let origin = get_canonical_origin(addr, &addr_origin);
                let span = addr + info.length as u64;
                if !matches!(info.kind, FlowKind::Bad | FlowKind::Unimpl) {
                    instruction_extents.push((addr, info.length as u64));
                }
                proven_bodies
                    .entry(origin)
                    .and_modify(|e| *e = (*e).max(span))
                    .or_insert(span);

                match info.kind {
                    FlowKind::Call => {
                        for t in &info.targets {
                            if in_code(*t) && !entries.contains(t) {
                                entries.push(*t);
                                addr_origin.insert(*t, *t);
                                next_active.push(*t);
                            }
                            if *t != 0 {
                                calls.push((addr, *t));
                            }
                        }
                        let fall = info.fallthrough.unwrap_or(addr + info.length as u64);
                        if in_code(fall) && !visited.contains(&fall) {
                            addr_origin.insert(fall, origin);
                            next_active.push(fall);
                        }
                    }
                    FlowKind::Branch => {
                        if let Some(&t) = info.targets.first() {
                            if in_code(t) && !visited.contains(&t) {
                                addr_origin.insert(t, origin);
                                next_active.push(t);
                            }
                        }
                    }
                    FlowKind::CBranch => {
                        if let Some(&t) = info.targets.first() {
                            if in_code(t) && !visited.contains(&t) {
                                addr_origin.insert(t, origin);
                                next_active.push(t);
                            }
                        }
                        let fall = info.fallthrough.unwrap_or(addr + info.length as u64);
                        if in_code(fall) && !visited.contains(&fall) {
                            addr_origin.insert(fall, origin);
                            next_active.push(fall);
                        }
                    }
                    FlowKind::CallInd => {
                        let fall = info.fallthrough.unwrap_or(addr + info.length as u64);
                        if in_code(fall) && !visited.contains(&fall) {
                            addr_origin.insert(fall, origin);
                            next_active.push(fall);
                        }
                    }
                    FlowKind::Fallthrough => {
                        let fall = info.fallthrough.unwrap_or(addr + info.length as u64);
                        if in_code(fall) && !visited.contains(&fall) {
                            addr_origin.insert(fall, origin);
                            next_active.push(fall);
                        }
                    }
                    FlowKind::BranchInd | FlowKind::Return | FlowKind::Bad | FlowKind::Unimpl => {}
                }
            }
        }
        active = next_active;
    }

    // Only decoded bytes prove containment. A branch over a gap does not.
    let mut extents: Vec<(u64, u64)> = imp
        .functions
        .iter()
        .filter(|f| f.size > 1)
        .map(|f| (f.entry, f.size))
        .collect();
    extents.extend(instruction_extents);

    let filter_ctx = CandidateFilterContext {
        mappings: &imp.mappings,
        known_extents: &extents,
        initial_seeds: &entries.iter().copied().collect(),
    };

    // Relocation candidates: reject candidates already visited inside trusted bodies
    let unvisited_relocs: Vec<u64> = imp
        .reloc_candidates
        .iter()
        .chain(imp.pointer_candidates.iter())
        .chain(imp.initializer_candidates.iter())
        .chain(candidates.iter())
        .copied()
        .filter(|&cand| in_code(cand) && !visited.contains(&cand) && !entries.contains(&cand))
        .collect();

    if !unvisited_relocs.is_empty() {
        let flows = flow_provider(&unvisited_relocs);
        let confirmed_relocs: Vec<u64> = unvisited_relocs
            .into_iter()
            .zip(flows)
            .filter(|&(c, ref info)| filter_candidate(c, &filter_ctx, |_| info.clone()))
            .map(|(c, _)| c)
            .collect();

        if !confirmed_relocs.is_empty() {
            for &r in &confirmed_relocs {
                if !entries.contains(&r) {
                    entries.push(r);
                    addr_origin.insert(r, r);
                }
            }
            let reloc_set: HashSet<u64> = confirmed_relocs.iter().copied().collect();
            let mut reloc_active = confirmed_relocs;
            while !reloc_active.is_empty() {
                reloc_active.sort_unstable();
                reloc_active.dedup();
                let to_query: Vec<u64> = reloc_active
                    .drain(..)
                    .filter(|a| *a != 0 && in_code(*a) && visited.insert(*a))
                    .collect();
                if to_query.is_empty() {
                    break;
                }
                let mut next_active: Vec<u64> = Vec::new();
                for chunk in to_query.chunks(1024) {
                    let flows = flow_provider(chunk);
                    for (addr, info) in chunk.iter().copied().zip(flows) {
                        let origin = get_canonical_origin(addr, &addr_origin);
                        let span = addr + info.length as u64;
                        proven_bodies
                            .entry(origin)
                            .and_modify(|e| *e = (*e).max(span))
                            .or_insert(span);

                        match info.kind {
                            FlowKind::Call => {
                                for t in &info.targets {
                                    if in_code(*t) && !entries.contains(t) {
                                        entries.push(*t);
                                        addr_origin.insert(*t, *t);
                                        next_active.push(*t);
                                    }
                                    if *t != 0 {
                                        calls.push((addr, *t));
                                    }
                                }
                                let fall = info.fallthrough.unwrap_or(addr + info.length as u64);
                                merge_reached_candidate(fall, origin, &reloc_set, &mut addr_origin, &mut proven_bodies);
                                if in_code(fall) && !visited.contains(&fall) {
                                    addr_origin.insert(fall, origin);
                                    next_active.push(fall);
                                }
                            }
                            FlowKind::Branch => {
                                if let Some(&t) = info.targets.first() {
                                    merge_reached_candidate(t, origin, &reloc_set, &mut addr_origin, &mut proven_bodies);
                                    if in_code(t) && !visited.contains(&t) {
                                        addr_origin.insert(t, origin);
                                        next_active.push(t);
                                    }
                                }
                            }
                            FlowKind::CBranch => {
                                if let Some(&t) = info.targets.first() {
                                    merge_reached_candidate(t, origin, &reloc_set, &mut addr_origin, &mut proven_bodies);
                                    if in_code(t) && !visited.contains(&t) {
                                        addr_origin.insert(t, origin);
                                        next_active.push(t);
                                    }
                                }
                                let fall = info.fallthrough.unwrap_or(addr + info.length as u64);
                                merge_reached_candidate(fall, origin, &reloc_set, &mut addr_origin, &mut proven_bodies);
                                if in_code(fall) && !visited.contains(&fall) {
                                    addr_origin.insert(fall, origin);
                                    next_active.push(fall);
                                }
                            }
                            FlowKind::Fallthrough | FlowKind::CallInd => {
                                let fall = info.fallthrough.unwrap_or(addr + info.length as u64);
                                merge_reached_candidate(fall, origin, &reloc_set, &mut addr_origin, &mut proven_bodies);
                                if in_code(fall) && !visited.contains(&fall) {
                                    addr_origin.insert(fall, origin);
                                    next_active.push(fall);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                reloc_active = next_active;
            }
        }
    }
    // Canonicalize proven_bodies so descendant spans are merged into their root origins:
    let mut canon_bodies: std::collections::HashMap<u64, u64> = std::collections::HashMap::with_capacity(proven_bodies.len());
    for (root, span_end) in proven_bodies.drain() {
        let canon = get_canonical_origin(root, &addr_origin);
        canon_bodies
            .entry(canon)
            .and_modify(|e| *e = (*e).max(span_end))
            .or_insert(span_end);
    }
    proven_bodies = canon_bodies;

    // Reconcile batched relocation candidates after discovering their bodies:
    // an entry plus an internal relocation target cannot both become functions.
    entries.retain(|&e| get_canonical_origin(e, &addr_origin) == e);

    entries.sort_unstable();
    entries.dedup();

    let mut merged = imp.functions.clone();
    for e in entries {
        if !merged.iter().any(|f| f.entry == e) {
            let name = extern_name(imp, e).unwrap_or_else(|| format!("FUN_{e:08x}"));
            merged.push(NativeFunction {
                entry: e,
                name,
                size: 1,
            });
        }
    }
    merged.sort_by_key(|f| f.entry);
    merged.dedup_by_key(|f| f.entry);

    for f in merged.iter_mut() {
        if let Some(span_end) = proven_bodies.get(&f.entry) {
            f.size = span_end.saturating_sub(f.entry).max(1);
        }
    }
    imp.functions = merged;

    let mut xrefs = imp.xrefs.clone();
    let mut seen_xrefs: HashSet<(u64, u64)> = xrefs.iter().map(|x| (x.from, x.to)).collect();
    for (from, to) in calls {
        if seen_xrefs.insert((from, to)) {
            xrefs.push(NativeXref::new(from, to, "UNCONDITIONAL_CALL"));
        }
    }
    imp.xrefs = xrefs;
    close_call_targets(imp);
}
