//! Mapped-image discovery: SLEIGH supplies instruction lengths and call targets;
//! the existing worklist supplies control-flow closure. No ISA-specific decoder.
use super::{
    close_call_targets, code_ranges, extern_name, filter_candidate, CandidateFilterContext,
    ImportError, NativeFunction, NativeImport, NativeXref, Result,
};
use crate::native_runtime::{
    ConsoleSession, FlowKind, FlowResult, LinkageResult, NativeRuntimeError,
};
use std::collections::{HashMap, HashSet};

#[cfg(test)]
mod tests;

trait FlowProvider {
    fn flow(&mut self, addresses: &[u64]) -> Vec<FlowResult>;
    fn linkages(&mut self, addresses: &[u64]) -> Vec<LinkageResult>;
    fn plt_linkages(&mut self, addresses: &[u64]) -> Vec<LinkageResult>;
}

struct ConsoleProvider {
    session: ConsoleSession,
    decoded: Option<HashMap<u64, FlowResult>>,
    failure: Option<NativeRuntimeError>,
}

impl FlowProvider for ConsoleProvider {
    fn flow(&mut self, addresses: &[u64]) -> Vec<FlowResult> {
        // Seeded walking already visits each instruction once. Only the
        // section sweep has decoded results worth retaining and reusing.
        let Some(decoded) = self.decoded.as_mut() else {
            return self.session.flow_batch(addresses).unwrap_or_else(|error| {
                self.failure = Some(error);
                Vec::new()
            });
        };
        let missing: Vec<_> = addresses
            .iter()
            .copied()
            .filter(|address| !decoded.contains_key(address))
            .collect();
        if !missing.is_empty() {
            match self.session.flow_batch(&missing) {
                Ok(flows) => {
                    decoded.extend(flows.into_iter().map(|flow| (flow.address, flow)));
                }
                Err(error) => {
                    self.failure = Some(error);
                    return Vec::new();
                }
            }
        }
        addresses
            .iter()
            .filter_map(|address| decoded.get(address).cloned())
            .collect()
    }

    fn linkages(&mut self, addresses: &[u64]) -> Vec<LinkageResult> {
        match self.session.linkage_batch(addresses) {
            Ok(results) => results,
            Err(error) => {
                self.failure = Some(error);
                Vec::new()
            }
        }
    }

    fn plt_linkages(&mut self, addresses: &[u64]) -> Vec<LinkageResult> {
        match self.session.plt_linkage_batch(addresses) {
            Ok(results) => results,
            Err(error) => {
                self.failure = Some(error);
                Vec::new()
            }
        }
    }
}

/// ELF/PE retain structural facts when the optional console is unavailable.
/// All supported languages use the same mapped addresses and flow worklist.
pub(super) fn discover_seeded(import: &mut NativeImport) {
    if import.mappings.is_empty()
        || import
            .cfg
            .console_path
            .as_ref()
            .map_or(true, |path| !path.is_file())
    {
        return;
    }
    let Ok(mut session) = ConsoleSession::new(&import.cfg) else {
        return;
    };
    if session.load_mapped(import).is_err() {
        return;
    }
    let mut provider = ConsoleProvider {
        session,
        decoded: None,
        failure: None,
    };
    flow_discover_with_candidates(import, &[], &mut provider);
}

pub(super) fn discover_mapped(import: &mut NativeImport) -> Result<()> {
    let mut session =
        ConsoleSession::new(&import.cfg).map_err(|e| ImportError::Bad(e.to_string()))?;
    session
        .load_mapped(import)
        .map_err(|e| ImportError::Bad(e.to_string()))?;
    let ranges = code_ranges(import);
    let in_code = |address| {
        ranges
            .iter()
            .any(|&(start, end)| start <= address && address < end)
    };
    let mut cursors: Vec<_> = ranges
        .iter()
        .map(|&(start, end)| (start, end, true))
        .collect();
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
                        import
                            .xrefs
                            .push(NativeXref::new(*address, target, "UNCONDITIONAL_CALL"));
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
    let mut provider = ConsoleProvider {
        session,
        decoded: Some(decoded),
        failure: None,
    };
    flow_discover_with_candidates(import, &candidates, &mut provider);
    if let Some(error) = provider.failure {
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
#[cfg(test)]
pub fn flow_discover_with_provider<F: FnMut(&[u64]) -> Vec<crate::native_runtime::FlowResult>>(
    imp: &mut NativeImport,
    flow_provider: F,
) {
    struct TestProvider<F>(F);
    impl<F: FnMut(&[u64]) -> Vec<FlowResult>> FlowProvider for TestProvider<F> {
        fn flow(&mut self, addresses: &[u64]) -> Vec<FlowResult> {
            (self.0)(addresses)
        }
        fn linkages(&mut self, _: &[u64]) -> Vec<LinkageResult> {
            Vec::new()
        }
        fn plt_linkages(&mut self, _: &[u64]) -> Vec<LinkageResult> {
            Vec::new()
        }
    }
    flow_discover_with_candidates(imp, &[], &mut TestProvider(flow_provider));
}

fn flow_discover_with_candidates<P: FlowProvider>(
    imp: &mut NativeImport,
    candidates: &[u64],
    flow_provider: &mut P,
) {
    use crate::native_runtime::FlowKind;
    let code = code_ranges(imp);
    let in_code = |a: u64| code.iter().any(|(v, e)| a >= *v && a < *e);
    let has_linkage_slots = imp.externals.iter().any(|(address, _)| *address != 0);
    let mut examined_linkages = HashSet::new();
    // Table metadata supplies boundaries, not functions. Each entry still needs
    // bounded p-code evidence ending in an indirect transfer through a known slot.
    if has_linkage_slots {
        for chunk in imp.plt_candidates.chunks(1024) {
            let addresses: Vec<_> = chunk.iter().map(|&(address, _)| address).collect();
            for (&(address, width), linkage) in
                chunk.iter().zip(flow_provider.plt_linkages(&addresses))
            {
                if linkage.address != address
                    || linkage.length == 0
                    || linkage.length as u64 > width
                    || imp
                        .functions
                        .iter()
                        .any(|function| function.entry == address)
                    || !code.iter().any(|&(start, end)| {
                        start <= address && address < end && linkage.length as u64 <= end - address
                    })
                {
                    continue;
                }
                let Some(slot) = linkage.slot else {
                    continue;
                };
                let Some((_, name)) = imp
                    .externals
                    .iter()
                    .find(|(slot_address, _)| *slot_address == slot && slot != 0)
                else {
                    continue;
                };
                imp.functions.push(NativeFunction {
                    entry: address,
                    name: name.clone(),
                    size: linkage.length as u64,
                });
            }
        }
    }
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
    let mut thunk_candidates = HashSet::new();
    let mut thunk_jumps = Vec::new();
    let mut thunk_roots = HashMap::new();
    let mut thunk_continuations = HashMap::new();
    let mut landing_entries = HashMap::new();
    let mut proven_bodies: std::collections::HashMap<u64, u64> =
        std::collections::HashMap::with_capacity(4096);
    let mut addr_origin: std::collections::HashMap<u64, u64> =
        std::collections::HashMap::with_capacity(32768);
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
            let flows = flow_provider.flow(chunk);
            // Only an unconditional branch to a proven imported-slot stub
            // establishes an independent linkage entry; ordinary labels do not.
            if has_linkage_slots {
                let mut targets: Vec<_> = chunk
                    .iter()
                    .zip(&flows)
                    .filter(|(address, flow)| {
                        flow.address == **address
                            && flow.length != 0
                            && flow.kind == FlowKind::Branch
                            && flow.targets.len() == 1
                    })
                    .map(|(_, flow)| flow.targets[0])
                    .filter(|target| {
                        in_code(*target)
                            && !entries.contains(target)
                            && !visited.contains(target)
                            && !instruction_extents
                                .iter()
                                .any(|&(start, size)| *target > start && *target - start < size)
                            && !flows.iter().any(|flow| {
                                *target > flow.address
                                    && *target - flow.address < flow.length as u64
                            })
                            && examined_linkages.insert(*target)
                    })
                    .collect();
                targets.sort_unstable();
                for linkage in flow_provider.linkages(&targets) {
                    let Some(slot) = linkage.slot else {
                        continue;
                    };
                    if linkage.length == 0
                        || targets.binary_search(&linkage.address).is_err()
                        || !code.iter().any(|&(start, end)| {
                            start <= linkage.address
                                && linkage.address < end
                                && linkage.length as u64 <= end - linkage.address
                        })
                    {
                        continue;
                    }
                    let Some((_, name)) = imp
                        .externals
                        .iter()
                        .find(|(address, _)| *address == slot && slot != 0)
                    else {
                        continue;
                    };
                    entries.push(linkage.address);
                    addr_origin.insert(linkage.address, linkage.address);
                    imp.functions.push(NativeFunction {
                        entry: linkage.address,
                        name: name.clone(),
                        size: linkage.length as u64,
                    });
                }
            }
            let thunks = confirmed_thunks(
                imp,
                &entries,
                &landing_entries,
                &visited,
                &instruction_extents,
                chunk,
                &flows,
                flow_provider,
            );
            for (addr, info) in chunk.iter().copied().zip(flows) {
                if info.address == addr
                    && info.no_op
                    && info.length != 0
                    && info.kind == FlowKind::Fallthrough
                    && info.targets.is_empty()
                    && info.fallthrough == addr.checked_add(info.length as u64)
                    && entries.contains(&addr)
                    && imp.mappings.iter().any(|m| {
                        m.flags & 4 != 0
                            && addr >= m.vaddr
                            && addr - m.vaddr < m.size
                            && info.length as u64 <= m.size - (addr - m.vaddr)
                    })
                {
                    // Only the first instruction may be skipped, never a no-op chain.
                    if let Some(fall) = info.fallthrough {
                        landing_entries.insert(fall, addr);
                    }
                }
                // A jump chain reaching its source's continuation is an internal
                // branch-over-body sequence, not a set of separate functions.
                if let Some(&root) = thunk_continuations.get(&addr) {
                    if thunk_roots.get(&get_canonical_origin(addr, &addr_origin)) == Some(&root) {
                        for (&target, &owner) in &thunk_roots {
                            if owner == root {
                                merge_reached_candidate(
                                    target,
                                    root,
                                    &thunk_candidates,
                                    &mut addr_origin,
                                    &mut proven_bodies,
                                );
                            }
                        }
                    }
                }
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
                        merge_reached_candidate(
                            fall,
                            origin,
                            &thunk_candidates,
                            &mut addr_origin,
                            &mut proven_bodies,
                        );
                        if in_code(fall) && !visited.contains(&fall) {
                            addr_origin.insert(fall, origin);
                            next_active.push(fall);
                        }
                    }
                    FlowKind::Branch => {
                        if let Some(&t) = info.targets.first() {
                            if thunks.get(&addr) == Some(&t) {
                                if !entries.contains(&t) {
                                    entries.push(t);
                                    thunk_candidates.insert(t);
                                    let root = thunk_roots.get(&origin).copied().unwrap_or(origin);
                                    thunk_roots.insert(t, root);
                                    thunk_continuations.insert(addr + info.length as u64, root);
                                }
                                thunk_jumps.push((addr, t));
                                addr_origin.insert(t, t);
                                if !visited.contains(&t) {
                                    next_active.push(t);
                                }
                                continue;
                            }
                            merge_reached_candidate(
                                t,
                                origin,
                                &thunk_candidates,
                                &mut addr_origin,
                                &mut proven_bodies,
                            );
                            if in_code(t) && !visited.contains(&t) {
                                addr_origin.insert(t, origin);
                                next_active.push(t);
                            }
                        }
                    }
                    FlowKind::CBranch => {
                        if let Some(&t) = info.targets.first() {
                            merge_reached_candidate(
                                t,
                                origin,
                                &thunk_candidates,
                                &mut addr_origin,
                                &mut proven_bodies,
                            );
                            if in_code(t) && !visited.contains(&t) {
                                addr_origin.insert(t, origin);
                                next_active.push(t);
                            }
                        }
                        let fall = info.fallthrough.unwrap_or(addr + info.length as u64);
                        merge_reached_candidate(
                            fall,
                            origin,
                            &thunk_candidates,
                            &mut addr_origin,
                            &mut proven_bodies,
                        );
                        if in_code(fall) && !visited.contains(&fall) {
                            addr_origin.insert(fall, origin);
                            next_active.push(fall);
                        }
                    }
                    FlowKind::CallInd => {
                        let fall = info.fallthrough.unwrap_or(addr + info.length as u64);
                        merge_reached_candidate(
                            fall,
                            origin,
                            &thunk_candidates,
                            &mut addr_origin,
                            &mut proven_bodies,
                        );
                        if in_code(fall) && !visited.contains(&fall) {
                            addr_origin.insert(fall, origin);
                            next_active.push(fall);
                        }
                    }
                    FlowKind::Fallthrough => {
                        let fall = info.fallthrough.unwrap_or(addr + info.length as u64);
                        merge_reached_candidate(
                            fall,
                            origin,
                            &thunk_candidates,
                            &mut addr_origin,
                            &mut proven_bodies,
                        );
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
        let flows = flow_provider.flow(&unvisited_relocs);
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
            let reloc_set: HashSet<u64> = confirmed_relocs
                .iter()
                .chain(thunk_candidates.iter())
                .copied()
                .collect();
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
                    let flows = flow_provider.flow(chunk);
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
                                merge_reached_candidate(
                                    fall,
                                    origin,
                                    &reloc_set,
                                    &mut addr_origin,
                                    &mut proven_bodies,
                                );
                                if in_code(fall) && !visited.contains(&fall) {
                                    addr_origin.insert(fall, origin);
                                    next_active.push(fall);
                                }
                            }
                            FlowKind::Branch => {
                                if let Some(&t) = info.targets.first() {
                                    merge_reached_candidate(
                                        t,
                                        origin,
                                        &reloc_set,
                                        &mut addr_origin,
                                        &mut proven_bodies,
                                    );
                                    if in_code(t) && !visited.contains(&t) {
                                        addr_origin.insert(t, origin);
                                        next_active.push(t);
                                    }
                                }
                            }
                            FlowKind::CBranch => {
                                if let Some(&t) = info.targets.first() {
                                    merge_reached_candidate(
                                        t,
                                        origin,
                                        &reloc_set,
                                        &mut addr_origin,
                                        &mut proven_bodies,
                                    );
                                    if in_code(t) && !visited.contains(&t) {
                                        addr_origin.insert(t, origin);
                                        next_active.push(t);
                                    }
                                }
                                let fall = info.fallthrough.unwrap_or(addr + info.length as u64);
                                merge_reached_candidate(
                                    fall,
                                    origin,
                                    &reloc_set,
                                    &mut addr_origin,
                                    &mut proven_bodies,
                                );
                                if in_code(fall) && !visited.contains(&fall) {
                                    addr_origin.insert(fall, origin);
                                    next_active.push(fall);
                                }
                            }
                            FlowKind::Fallthrough | FlowKind::CallInd => {
                                let fall = info.fallthrough.unwrap_or(addr + info.length as u64);
                                merge_reached_candidate(
                                    fall,
                                    origin,
                                    &reloc_set,
                                    &mut addr_origin,
                                    &mut proven_bodies,
                                );
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
    let mut canon_bodies: std::collections::HashMap<u64, u64> =
        std::collections::HashMap::with_capacity(proven_bodies.len());
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
    for (from, to) in thunk_jumps {
        if !imp
            .xrefs
            .iter()
            .any(|x| x.from == from && x.to == to && x.kind == "UNCONDITIONAL_JUMP")
        {
            let provenance = if entries.contains(&to) {
                "native-import:thunk"
            } else {
                "native-import"
            };
            imp.xrefs.push(NativeXref::with_provenance(
                from,
                to,
                "UNCONDITIONAL_JUMP",
                provenance,
            ));
        }
    }

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

/// Conservative subset of Ghidra CreateThunkFunctionCmd.getSimpleFlow:
/// an established entry's pure branch, optionally after one proven no-op.
/// Unlike arbitrary branch closure, the destination must independently decode.
fn confirmed_thunks<P: FlowProvider>(
    imp: &NativeImport,
    entries: &[u64],
    landing_entries: &HashMap<u64, u64>,
    visited: &HashSet<u64>,
    extents: &[(u64, u64)],
    addresses: &[u64],
    flows: &[crate::native_runtime::FlowResult],
    provider: &mut P,
) -> HashMap<u64, u64> {
    let mut candidates = HashMap::new();
    for (&address, flow) in addresses.iter().zip(flows) {
        if flow.address != address
            || flow.length == 0
            || !flow.pure_jump
            || flow.kind != FlowKind::Branch
            || flow.fallthrough.is_some()
            || flow.targets.len() != 1
            || !imp.mappings.iter().any(|m| {
                m.flags & 4 != 0
                    && address >= m.vaddr
                    && address - m.vaddr < m.size
                    && flow.length as u64 <= m.size - (address - m.vaddr)
            })
        {
            continue;
        }
        let entry = if entries.contains(&address) {
            address
        } else if let Some(&entry) = landing_entries.get(&address) {
            entry
        } else {
            continue;
        };
        let target = flow.targets[0];
        if target == address
            || target == entry
            || (visited.contains(&target) && !entries.contains(&target))
            || !imp
                .mappings
                .iter()
                .any(|m| m.flags & 4 != 0 && target >= m.vaddr && target - m.vaddr < m.size)
            || imp
                .functions
                .iter()
                .any(|f| target > f.entry && target - f.entry < f.size)
            || extents
                .iter()
                .any(|&(start, size)| target > start && target - start < size)
        {
            continue;
        }
        candidates.insert(address, target);
    }
    if candidates.is_empty() {
        return candidates;
    }
    let mut targets: Vec<_> = candidates.values().copied().collect();
    targets.sort_unstable();
    targets.dedup();
    let valid: Vec<_> = targets
        .iter()
        .copied()
        .zip(provider.flow(&targets))
        .filter(|&(target, ref flow)| {
            flow.address == target
                && flow.length != 0
                && !matches!(flow.kind, FlowKind::Bad | FlowKind::Unimpl)
                && imp.mappings.iter().any(|m| {
                    m.flags & 4 != 0
                        && target >= m.vaddr
                        && target - m.vaddr < m.size
                        && flow.length as u64 <= m.size - (target - m.vaddr)
                })
        })
        .map(|(target, _)| target)
        .collect();
    candidates.retain(|_, target| valid.binary_search(target).is_ok());
    candidates
}
