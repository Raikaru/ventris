//! Mapped-image discovery: SLEIGH supplies instruction lengths and call targets;
//! the existing worklist supplies control-flow closure. No ISA-specific decoder.
use super::{close_call_targets, code_ranges, flow_discover_with_candidates, ImportError, NativeImport, NativeXref, Result};
use crate::native_runtime::{ConsoleSession, FlowKind};
use std::collections::HashMap;

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
