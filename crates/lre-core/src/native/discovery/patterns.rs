//! Ghidra FunctionStartAnalyzer/PseudoDisassembler prerequisites (Apache-2.0).
//! A byte-pattern match is evidence to check, never an instruction or function.
use super::{FlowKind, FlowProvider, NativeImport};
use std::collections::HashSet;

pub(super) struct CodeRequirement {
    pub minimum: usize,
    pub maximum: usize,
    pub must_terminate: bool,
    pub contiguous: bool,
}

fn loaded_byte(import: &NativeImport, address: u64) -> Option<u8> {
    let mapping = import
        .mappings
        .iter()
        .find(|mapping| address >= mapping.vaddr && address - mapping.vaddr < mapping.size)?;
    if !mapping.bytes.is_empty() {
        return mapping
            .bytes
            .get((address - mapping.vaddr) as usize)
            .copied();
    }
    // Initialized bytes already contain loader fixups; only zero-fill mappings
    // need the separately retained relocation overlay.
    for relocation in &import.relocations {
        if let Some(offset) = address.checked_sub(relocation.address) {
            if offset < relocation.width as u64 {
                return Some(relocation.bytes[offset as usize]);
            }
        }
    }
    Some(0)
}

fn contains(extents: &[(u64, u64)], address: u64) -> bool {
    extents
        .iter()
        .any(|&(start, end)| start <= address && address < end)
}

/// Follows the source validator's bounded control-flow walk. Delay slots belong
/// to the body but do not contribute to its contiguous instruction count.
pub(super) fn valid_code<P: FlowProvider>(
    import: &NativeImport,
    entry: u64,
    requirement: &CodeRequirement,
    functions: &[u64],
    instructions: &[(u64, u64)],
    data: &[(u64, u64)],
    provider: &mut P,
) -> bool {
    let mut nonzero = false;
    for offset in 0..8 {
        let Some(byte) = entry
            .checked_add(offset)
            .and_then(|address| loaded_byte(import, address))
        else {
            return false;
        };
        nonzero |= byte != 0;
    }
    if !nonzero {
        return false;
    }
    let mut body = Vec::new();
    let mut starts = HashSet::new();
    let mut pending = Vec::new();
    let mut targets = Vec::new();
    let mut target = Some(entry);
    let mut contiguous_end = None;
    let mut count = 0;
    let mut terminated = false;
    let mut valid_call = false;
    let mut repeat_byte = None;
    let mut repeat_count = 0;
    for _ in 0..requirement.maximum {
        let Some(address) = target else { break };
        let mut flows = provider.flow(&[address]);
        let Some(flow) = flows.pop() else {
            return false;
        };
        if !flows.is_empty()
            || flow.address != address
            || flow.length == 0
            || matches!(flow.kind, FlowKind::Bad | FlowKind::Unimpl)
        {
            return false;
        }
        let Some(end) = address.checked_add(flow.length as u64) else {
            return false;
        };
        let slots: u64 = flow
            .delay_slots
            .iter()
            .map(|&length| u64::from(length))
            .sum();
        if slots >= u64::from(flow.length) {
            return false;
        }
        let instruction_end = end - slots;
        // Existing starts are allowed; offcut decoding and overlapping pseudo
        // instructions are not. Extent inputs use (address, length).
        if instructions.iter().any(|&(start, length)| {
            let end = start.saturating_add(length);
            start < instruction_end && address < end && start != address
        }) || body
            .iter()
            .any(|&(start, end)| start < instruction_end && address < end)
        {
            return false;
        }
        if contiguous_end.is_none() || !requirement.contiguous || contiguous_end == Some(address) {
            count += 1;
            contiguous_end = Some(instruction_end);
        }
        let mut repeated = loaded_byte(import, address);
        for byte_address in address..instruction_end {
            let Some(byte) = loaded_byte(import, byte_address) else {
                return false;
            };
            if Some(byte) != repeated {
                repeated = None;
            }
        }
        if repeated.is_some() && repeated == repeat_byte {
            repeat_count += 1;
            if repeat_count > 4 {
                return false;
            }
        } else {
            repeat_byte = repeated;
            repeat_count = usize::from(repeated.is_some());
        }
        body.push((address, instruction_end));
        starts.insert(address);
        let mut slot_address = instruction_end;
        for &length in &flow.delay_slots {
            let mut slots = provider.flow(&[slot_address]);
            let Some(slot) = slots.pop() else {
                return false;
            };
            if length == 0
                || !slots.is_empty()
                || slot.address != slot_address
                || slot.length != length
                || !slot.delay_slots.is_empty()
                || matches!(slot.kind, FlowKind::Bad | FlowKind::Unimpl)
            {
                return false;
            }
            let slot_end = slot_address + u64::from(length);
            if instructions.iter().any(|&(start, length)| {
                start != address
                    && start < slot_end
                    && slot_address < start.saturating_add(length)
                    && start != slot_address
            }) || body
                .iter()
                .any(|&(start, end)| start < slot_end && slot_address < end)
            {
                return false;
            }
            body.push((slot_address, slot_end));
            starts.insert(slot_address);
            slot_address = slot_end;
        }
        terminated |= flow.terminal && flow.return_op;
        let jump = matches!(
            flow.kind,
            FlowKind::Branch | FlowKind::CBranch | FlowKind::BranchInd
        );
        let call = matches!(flow.kind, FlowKind::Call | FlowKind::CallInd);
        target = flow.fallthrough.or_else(|| {
            if targets.contains(&end) {
                Some(end)
            } else if jump {
                flow.targets
                    .iter()
                    .copied()
                    .find(|&to| !contains(&body, to))
            } else {
                None
            }
        });
        if jump {
            for &to in &flow.targets {
                if flow.fallthrough == Some(to) && flow.delay_slots.is_empty() {
                    return false;
                }
                if functions.contains(&to) {
                    valid_call = true;
                    target = None;
                } else {
                    targets.push(to);
                    pending.push(to);
                }
            }
            if flow.kind == FlowKind::BranchInd && flow.targets.is_empty() {
                terminated = true;
            }
        }
        if call || flow.kind == FlowKind::BranchInd {
            valid_call |= flow.targets.iter().any(|to| functions.contains(to));
        }
        if target.is_none() {
            while let Some(next) = pending.pop() {
                if !contains(&body, next) {
                    target = Some(next);
                    break;
                }
            }
        }
    }
    count >= requirement.minimum
        && (!requirement.must_terminate || terminated || valid_call)
        && targets
            .iter()
            .all(|&to| !contains(&body, to) || starts.contains(&to))
        && import
            .xrefs
            .iter()
            .all(|xref| !contains(&body, xref.to) || starts.contains(&xref.to))
        && body.iter().all(|&(start, end)| {
            !data
                .iter()
                .any(|&(data_start, data_end)| start < data_end && data_start < end)
        })
}

#[derive(Clone, Copy)]
pub(super) struct Candidate {
    pub address: u64,
    pub possible: bool,
}

pub(super) fn collect<P: FlowProvider>(
    import: &NativeImport,
    patterns: &crate::native_runtime::FunctionPatterns,
    functions: &[u64],
    instructions: &[(u64, u64)],
    conditional_targets: &HashSet<u64>,
    provider: &mut P,
) -> super::Result<Vec<Candidate>> {
    let data_references: HashSet<_> = import
        .xrefs
        .iter()
        .filter(|xref| xref.kind == "DATA")
        .map(|xref| xref.from)
        .collect();
    let data: Vec<_> = import
        .relocations
        .iter()
        .filter(|relocation| data_references.contains(&relocation.address))
        .filter_map(|relocation| {
            relocation
                .address
                .checked_add(relocation.width as u64)
                .map(|end| (relocation.address, end))
        })
        .collect();
    let mut candidates = Vec::new();
    for hit in &patterns.matches {
        let address = hit.address;
        if contains(&data, address) {
            continue;
        }
        if address % patterns.alignment != 0
            || functions.contains(&address)
            || instructions
                .iter()
                .any(|&(start, length)| start <= address && address - start < length)
            || import.functions.iter().any(|function| {
                function.entry < address && address - function.entry < function.size
            })
        {
            continue;
        }
        let rule = &patterns.rules[hit.rule];
        for action in &rule.actions {
            match action.kind.as_str() {
                "codeboundary" => continue,
                "setcontext" => {
                    return Err(super::ImportError::Bad(format!(
                        "function-pattern context prerequisite is unavailable: {}",
                        rule.file
                    )))
                }
                "funcstart" | "possiblefuncstart" => {}
                kind => {
                    return Err(super::ImportError::Bad(format!(
                        "unknown pattern action: {kind}"
                    )))
                }
            }
            if action.kind == "possiblefuncstart" && conditional_targets.contains(&address) {
                continue;
            }
            let attribute = |name| action.attributes.get(name).map(String::as_str);
            if attribute("section").is_some() {
                return Err(super::ImportError::Bad(format!(
                    "function-pattern section prerequisite is unavailable: {}",
                    rule.file
                )));
            }
            let valid = attribute("validcode").unwrap_or(if attribute("validcodemax").is_some() {
                "subroutine"
            } else {
                "0"
            });
            if valid.eq_ignore_ascii_case("function") {
                // This action annotates an existing function, never creates one.
                continue;
            }
            if let Some(after) = attribute("after") {
                let block_start = import
                    .mappings
                    .iter()
                    .any(|mapping| mapping.vaddr == address)
                    || address.checked_sub(1).is_none_or(|previous| {
                        !import.mappings.iter().any(|mapping| {
                            previous >= mapping.vaddr && previous - mapping.vaddr < mapping.size
                        })
                    });
                let instruction_before = instructions
                    .iter()
                    .any(|&(start, length)| start < address && address - start <= length);
                let data_before = address
                    .checked_sub(1)
                    .is_some_and(|previous| contains(&data, previous));
                let mut references = import
                    .xrefs
                    .iter()
                    .filter(|xref| xref.to == address)
                    .peekable();
                let pure_data =
                    references.peek().is_some() && references.all(|xref| xref.kind == "DATA");
                let satisfied = if after.starts_with("func") || after.starts_with("inst") {
                    // Input instructions have already been reached from functions.
                    instruction_before
                } else if after.starts_with("data") {
                    data_before
                } else if after.starts_with("ptr") {
                    pure_data
                } else if after.starts_with("def") {
                    instruction_before || data_before || pure_data
                } else {
                    return Err(super::ImportError::Bad(format!(
                        "invalid pattern after prerequisite: {after}"
                    )));
                };
                if !block_start && !satisfied {
                    continue;
                }
            }
            let minimum =
                if valid.eq_ignore_ascii_case("true") || valid.eq_ignore_ascii_case("subroutine") {
                    -1
                } else if valid == "false" {
                    0
                } else {
                    valid.parse::<i32>().map_err(|error| {
                        super::ImportError::Bad(format!("invalid validcode: {error}"))
                    })?
                };
            if minimum != 0 {
                let maximum = attribute("validcodemax")
                    .map(str::parse::<i32>)
                    .transpose()
                    .map_err(|error| {
                        super::ImportError::Bad(format!("invalid validcodemax: {error}"))
                    })?
                    .unwrap_or(minimum);
                let requirement = CodeRequirement {
                    minimum: minimum.max(0) as usize,
                    maximum: if maximum > 0 { maximum as usize } else { 4000 },
                    must_terminate: minimum < 0,
                    contiguous: !attribute("contiguous")
                        .is_some_and(|value| value.eq_ignore_ascii_case("false")),
                };
                if !valid_code(
                    import,
                    address,
                    &requirement,
                    functions,
                    instructions,
                    &data,
                    provider,
                ) {
                    continue;
                }
            } else {
                let flows = provider.flow(&[address]);
                if flows.len() != 1
                    || flows[0].address != address
                    || flows[0].length == 0
                    || matches!(flows[0].kind, FlowKind::Bad | FlowKind::Unimpl)
                {
                    continue;
                }
            }
            candidates.push(Candidate {
                address,
                possible: action.kind == "possiblefuncstart",
            });
        }
    }
    // A definite action wins over a possible action at the same address.
    candidates.sort_unstable_by_key(|candidate| (candidate.address, candidate.possible));
    candidates.dedup_by_key(|candidate| candidate.address);
    Ok(candidates)
}
