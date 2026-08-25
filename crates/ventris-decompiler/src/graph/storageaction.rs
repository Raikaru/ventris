//! Storage-oriented actions from Ghidra 12.1.3's `coreaction.cc`.
//!
//! The graph deliberately exposes only SSA data-flow.  The following actions
//! therefore remain omitted because their real `apply` methods require state
//! which cannot be represented here:
//!
//! * `ActionLaneDivide` needs `Architecture`'s `LanedRegister`/lane-access
//!   registry and `LaneDivide::apply`; `graph::subflow` handles explicit
//!   subvariable forms but does not provide that architecture registry.
//! * `ActionSegmentize` needs the architecture user-op `SegmentOp` registry,
//!   segmented address-space metadata, and `SegmentOp::unify`.
//! * `ActionNormalizeSetup` needs `FuncProto` input/model/output lock state.
//! * `ActionInternalStorage` needs `FuncProto` internal-storage ranges,
//!   `Varnode::isEventualConstant`, and the `PcodeOp::storeUnmapped` flag.
//! * `ActionRestructureVarnode` needs `ScopeLocal::restructureVarnode`,
//!   `Funcdata::syncVarnodesWithSymbols`, and the no-indirect-collapse
//!   operation flag used to protect switch paths.  `graph::stackframe`
//!   already recovers frame-relative arithmetic, access widths, and
//!   conservative frame slots; that is the observable overlap, not a local
//!   symbol-layout implementation.
//! * `ActionMappedLocalSync` needs `ScopeLocal`, the symbol table/type links,
//!   overlap diagnostics, and `syncVarnodesWithSymbols`.
//!
//! `ActionShadowVar` is different: its complete `apply` is a graph-local
//! rewrite.  It turns a second `MULTIEQUAL` with the same incoming values as a
//! preceding merge into a `COPY` of the preceding merge's result.

use std::collections::BTreeSet;

use ventris_pcode::op;

use super::action::Action;
use super::{Funcdata, OpId, VarnodeId};

/// Collapse a shadow `MULTIEQUAL` into a copy of the first equivalent merge.
///
/// Ghidra only considers merges at the beginning address of a basic block and
/// first identifies a shadow by a repeated first input.  The full input list
/// must then agree with an earlier `MULTIEQUAL`; this prevents an unrelated
/// merge from being rewritten merely because one incoming path happens to
/// share a value.
pub struct ActionShadowVar;

impl Action for ActionShadowVar {
    fn name(&self) -> &'static str {
        "shadowvar"
    }

    fn apply(&self, data: &mut Funcdata) -> usize {
        // Collect before mutating.  Besides avoiding aliasing the graph while
        // it is borrowed, this preserves the original MULTIEQUAL lists for
        // all candidates in a block.
        let mut rewrites: Vec<(OpId, VarnodeId)> = Vec::new();

        for (_, block) in data.blocks() {
            let op_ids = block.ops.clone();
            let start = block.start;
            let mut seen_first_inputs = BTreeSet::new();
            let mut candidates = Vec::new();

            // The C++ action scans only the initial run of operations whose
            // address is the block start.  Non-MULTIEQUAL operations are
            // allowed in that run, because multi-collapse can leave them
            // interspersed with later merges.
            for (index, id) in op_ids.iter().copied().enumerate() {
                let operation = data.op(id);
                if operation.dead || operation.seq.address != start {
                    break;
                }
                if operation.opcode != op::MULTIEQUAL {
                    continue;
                }
                let Some(first) = operation.inputs.first().copied() else {
                    continue;
                };
                if !seen_first_inputs.insert(first) {
                    candidates.push((index, id, operation.inputs.clone()));
                }
            }

            for (candidate_index, candidate, candidate_inputs) in candidates {
                let Some(candidate_output) = data.op(candidate).output else {
                    continue;
                };
                let Some(source) = op_ids[..candidate_index].iter().rev().copied().find(|id| {
                    let operation = data.op(*id);
                    operation.opcode == op::MULTIEQUAL
                        && !operation.dead
                        && operation.inputs == candidate_inputs
                        && operation.output.is_some()
                        && data.varnode(operation.output.expect("checked above")).size
                            == data.varnode(candidate_output).size
                }) else {
                    continue;
                };
                let source_output = data.op(source).output.expect("checked above");
                rewrites.push((candidate, source_output));
            }
        }

        let mut changes = 0;
        for (candidate, source_output) in rewrites {
            // A candidate can only be rewritten once.  This guard also keeps
            // repeated application convergent if a malformed graph contains
            // duplicate operation identifiers in a block.
            if data.opcode_of(candidate) != Some(op::MULTIEQUAL) {
                continue;
            }
            data.op_set_opcode(candidate, op::COPY);
            data.op_set_inputs(candidate, vec![source_output]);
            changes += 1;
        }
        changes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::REGISTER_SPACE;

    fn seq(address: u64, order: u32) -> super::super::SeqNum {
        super::super::SeqNum { address, order }
    }

    fn phi_pair(same_inputs: bool) -> (Funcdata, OpId, VarnodeId) {
        let mut data = Funcdata::default();
        data.entry = 0x1000;
        let block = data.new_block(0x1000);

        let left = data.new_varnode(REGISTER_SPACE, 0, 4);
        let right = data.new_varnode(REGISTER_SPACE, 4, 4);
        data.mark_input(left);
        data.mark_input(right);

        let first = data.new_op(op::MULTIEQUAL, seq(0x1000, 0), vec![left, right]);
        let first_output = data.new_unique(4);
        data.op_set_output(first, Some(first_output));
        data.op_insert_end(first, block);

        let second_right = if same_inputs {
            right
        } else {
            data.new_varnode(REGISTER_SPACE, 8, 4)
        };
        let second = data.new_op(op::MULTIEQUAL, seq(0x1000, 1), vec![left, second_right]);
        let second_output = data.new_unique(4);
        data.op_set_output(second, Some(second_output));
        data.op_insert_end(second, block);
        (data, second, first_output)
    }

    #[test]
    fn shadowvar_collapses_an_equivalent_merge_and_preserves_width() {
        let (mut data, shadow, source_output) = phi_pair(true);
        let original_output = data.op(shadow).output.expect("shadow output");
        let original_bits = data.varnode(original_output).size * 8;

        assert_eq!(ActionShadowVar.apply(&mut data), 1);
        assert_eq!(data.op(shadow).opcode, op::COPY);
        assert_eq!(data.op(shadow).inputs, vec![source_output]);
        let result = data.op(shadow).output.expect("copy output");
        assert_eq!(data.varnode(result).size * 8, original_bits);
        assert_eq!(ActionShadowVar.apply(&mut data), 0);
    }

    #[test]
    fn shadowvar_declines_when_the_full_merge_inputs_differ() {
        let (mut data, shadow, _) = phi_pair(false);
        let before = data.op(shadow).inputs.clone();

        assert_eq!(ActionShadowVar.apply(&mut data), 0);
        assert_eq!(data.op(shadow).opcode, op::MULTIEQUAL);
        assert_eq!(data.op(shadow).inputs, before);
    }
}

pub fn all() -> Vec<Box<dyn Action>> {
    vec![Box::new(ActionShadowVar)]
}
