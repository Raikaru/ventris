//! Ghidra 12.1.3 expression rules from `ruleaction.cc`.
//!
//! Source authority is the pinned Ghidra C++ `applyOp`/`getOpList` methods at
//! commit `8b4c91d4d5bd1549622bfbade0df199585b98365`. The complete module is
//! filled in below as the graph-compatible arithmetic, comparison, and
//! extension rewrites are ported. `RuleRangeMeld` is intentionally omitted
//! because `CircleRange` is not represented by the graph API. `RuleShiftCast`
//! and `RuleSextSext` are absent from this pinned Ghidra source.

use ventris_pcode::op;

use super::action::Rule;
use super::{Funcdata, OpId};

pub struct RuleIdentityEl;

impl Rule for RuleIdentityEl {
    fn name(&self) -> &'static str {
        "identityel"
    }
    fn op_list(&self) -> Vec<i32> {
        vec![
            op::INT_ADD,
            op::INT_XOR,
            op::INT_OR,
            op::BOOL_XOR,
            op::BOOL_OR,
            op::INT_MULT,
        ]
    }
    fn apply_op(&self, id: OpId, data: &mut Funcdata) -> usize {
        let operation = data.op(id);
        let Some(&left) = operation.inputs.first() else {
            return 0;
        };
        let Some(&right) = operation.inputs.get(1) else {
            return 0;
        };
        if !data.varnode(right).flags.constant {
            return 0;
        }
        let value = data.varnode(right).offset;
        if operation.opcode != op::INT_MULT && value == 0 {
            data.op_set_opcode(id, op::COPY);
            data.op_set_inputs(id, vec![left]);
            return 1;
        }
        if operation.opcode == op::INT_MULT && (value == 0 || value == 1) {
            data.op_set_opcode(id, op::COPY);
            data.op_set_inputs(id, vec![if value == 0 { right } else { left }]);
            return 1;
        }
        0
    }
}

pub fn all() -> Vec<Box<dyn Rule>> {
    vec![Box::new(RuleIdentityEl)]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_el_is_registered() {
        assert_eq!(all().len(), 1);
    }
}
