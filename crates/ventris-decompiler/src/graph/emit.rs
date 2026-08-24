//! Statement emission from the SSA graph.
//!
//! Ghidra's printer walks the structured block tree and asks each varnode for
//! its expression, which the graph already answers. Ventris' old emitter did
//! the opposite: it walked instructions in address order while maintaining a
//! map of what each location currently held, and every control-flow join needed
//! bespoke repair — intersecting predecessor states, proving path invariance,
//! and dropping any value it could not prove. Those repairs are unnecessary
//! here, because [`super::heritage`] already placed a `MULTIEQUAL` wherever
//! paths disagree and [`super::value`] already named it.
//!
//! The output is the label-and-goto form the existing structuring pass
//! consumes, so control-flow recovery is unchanged by this stage.
//!
//! Source authority: `PrintC::emitBlockBasic` and `Funcdata::opCode` handling in
//! `printc.cc` at commit `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use std::collections::{BTreeMap, BTreeSet};

use ventris_pcode::op;

use super::value::{Naming, Resolver, mark_explicit};
use super::{Funcdata, GraphBlockId, OpId};
use crate::native::{Expr, NativeStatement};

/// Emits statements for a heritage'd graph.
pub fn emit(
    data: &Funcdata,
    register_name: &dyn Fn(u32, u64, u32) -> Option<String>,
) -> Vec<NativeStatement> {
    let naming = mark_explicit(data);
    let resolver = Resolver::new(data, &naming, register_name);
    Emitter {
        data,
        naming: &naming,
        resolver,
    }
    .run()
}

struct Emitter<'a> {
    data: &'a Funcdata,
    naming: &'a Naming,
    resolver: Resolver<'a>,
}

impl Emitter<'_> {
    fn run(&self) -> Vec<NativeStatement> {
        let labels = self.labels();
        let mut phi_copies: BTreeMap<GraphBlockId, Vec<NativeStatement>> = BTreeMap::new();
        for (block, copy) in self.resolver.phi_copies() {
            phi_copies.entry(block).or_default().push(copy);
        }

        // Blocks are emitted in address order so that a fallthrough stays
        // adjacent to its predecessor and needs no goto.
        let mut blocks: Vec<(GraphBlockId, u64)> = self
            .data
            .blocks()
            .map(|(id, block)| (id, block.start))
            .collect();
        blocks.sort_by_key(|(_, start)| *start);

        let mut statements = Vec::new();
        for (index, (block, start)) in blocks.iter().copied().enumerate() {
            if labels.contains(&start) {
                statements.push(NativeStatement::Label(start));
            }
            let terminator = self.emit_body(block, &mut statements);
            // Phi assignments belong after the block's computation but before
            // control leaves it, so the join sees this path's value.
            if let Some(copies) = phi_copies.get(&block) {
                let insert_at = statements.len() - terminator.len();
                for (offset, copy) in copies.iter().cloned().enumerate() {
                    statements.insert(insert_at + offset, copy);
                }
            }
            statements.extend(terminator);
            let next = blocks.get(index + 1).map(|(_, start)| *start);
            if let Some(target) = self.explicit_fallthrough(block, next) {
                statements.push(NativeStatement::Goto(target));
            }
        }
        statements
    }

    /// Addresses that need a label: every block reached other than by falling
    /// through from the textually preceding block.
    fn labels(&self) -> BTreeSet<u64> {
        let mut labels = BTreeSet::new();
        for (id, block) in self.data.blocks() {
            for predecessor in block.predecessors.iter().copied() {
                let sequential = self
                    .data
                    .block(predecessor)
                    .ops
                    .last()
                    .map(|op| self.data.op(*op).seq.address);
                if predecessor == id || sequential.is_none_or(|address| address >= block.start) {
                    labels.insert(block.start);
                }
            }
            if block.predecessors.len() > 1 {
                labels.insert(block.start);
            }
        }
        labels
    }

    /// Emits the block's non-terminator statements, returning the terminator so
    /// the caller can place phi assignments before it.
    fn emit_body(
        &self,
        block: GraphBlockId,
        statements: &mut Vec<NativeStatement>,
    ) -> Vec<NativeStatement> {
        let mut terminator = Vec::new();
        for op in self.data.block(block).ops.iter().copied() {
            match self.classify(op) {
                Emission::Skip => {}
                Emission::Body(statement) => statements.push(statement),
                Emission::Terminator(statement) => terminator.push(statement),
            }
        }
        terminator
    }

    fn classify(&self, op: OpId) -> Emission {
        let operation = self.data.op(op);
        match operation.opcode {
            // A named result is declared where it is defined; an unnamed one
            // inlines into its reader and produces no statement here.
            op::MULTIEQUAL | op::INDIRECT => Emission::Skip,
            op::STORE => {
                let (Some(address), Some(value)) = (
                    operation.inputs.get(1).copied(),
                    operation.inputs.get(2).copied(),
                ) else {
                    return Emission::Skip;
                };
                Emission::Body(NativeStatement::Store {
                    address: self.resolver.resolve(address),
                    value: self.resolver.resolve(value),
                    width: self.data.varnode(value).size,
                    volatile: false,
                })
            }
            op::CALL | op::CALLIND => {
                let call = self.call_expression(op);
                match operation.output {
                    Some(output) => match self.naming.name_of(output) {
                        Some(name) => Emission::Body(NativeStatement::Copy {
                            destination: Expr::Temporary {
                                name: name.to_string(),
                                width: self.data.varnode(output).size,
                            },
                            source: call,
                            width: self.data.varnode(output).size,
                            volatile: false,
                        }),
                        None => Emission::Body(NativeStatement::Call(call)),
                    },
                    None => Emission::Body(NativeStatement::Call(call)),
                }
            }
            op::RETURN => {
                let value = operation
                    .inputs
                    .first()
                    .copied()
                    .map(|value| self.resolver.resolve(value));
                Emission::Terminator(NativeStatement::Return(value))
            }
            op::BRANCH => match self.branch_target(op, 0) {
                Some(target) => Emission::Terminator(NativeStatement::Goto(target)),
                None => Emission::Skip,
            },
            op::CBRANCH => {
                let (Some(target), Some(condition)) =
                    (self.branch_target(op, 0), operation.inputs.get(1).copied())
                else {
                    return Emission::Skip;
                };
                Emission::Terminator(NativeStatement::IfGoto {
                    condition: self.resolver.resolve(condition),
                    target,
                })
            }
            op::BRANCHIND => match operation.inputs.first().copied() {
                Some(destination) => Emission::Terminator(NativeStatement::IndirectGoto(
                    self.resolver.resolve(destination),
                )),
                None => Emission::Skip,
            },
            _ => match operation.output {
                Some(output) => match self.naming.name_of(output) {
                    Some(_) => Emission::Body(self.declaration_of(op, output)),
                    None => Emission::Skip,
                },
                None => Emission::Skip,
            },
        }
    }

    fn declaration_of(&self, _op: OpId, output: super::VarnodeId) -> NativeStatement {
        let name = self
            .naming
            .name_of(output)
            .expect("caller checked the value is named")
            .to_string();
        let width = self.data.varnode(output).size;
        NativeStatement::Copy {
            destination: Expr::Temporary { name, width },
            source: self.resolver.resolve_definition(output),
            width,
            volatile: false,
        }
    }

    fn call_expression(&self, op: OpId) -> Expr {
        let operation = self.data.op(op);
        let mut inputs = operation.inputs.iter().copied();
        let destination = inputs.next();
        let args: Vec<Expr> = inputs.map(|value| self.resolver.resolve(value)).collect();
        match destination {
            Some(destination) if self.data.varnode(destination).flags.constant => Expr::Call {
                target: Some(self.data.varnode(destination).offset),
                callee: None,
                args,
            },
            Some(destination) => Expr::Call {
                target: None,
                callee: Some(Box::new(self.resolver.resolve(destination))),
                args,
            },
            None => Expr::Call {
                target: None,
                callee: None,
                args,
            },
        }
    }

    fn branch_target(&self, op: OpId, slot: usize) -> Option<u64> {
        let value = self.data.op(op).inputs.get(slot).copied()?;
        let varnode = self.data.varnode(value);
        varnode.flags.constant.then_some(varnode.offset)
    }

    /// A block whose successor is not the next block in address order needs an
    /// explicit jump, unless it already ends in one.
    fn explicit_fallthrough(&self, block: GraphBlockId, next: Option<u64>) -> Option<u64> {
        let terminates = self
            .data
            .block(block)
            .ops
            .last()
            .map(|op| self.data.op(*op).opcode)
            .is_some_and(|opcode| matches!(opcode, op::BRANCH | op::BRANCHIND | op::RETURN));
        if terminates {
            return None;
        }
        let successors = &self.data.block(block).successors;
        let fallthrough = successors
            .iter()
            .copied()
            .map(|successor| self.data.block(successor).start)
            .find(|start| Some(*start) != next)?;
        (successors.len() == 1 || Some(fallthrough) != next).then_some(fallthrough)
    }
}

enum Emission {
    Skip,
    Body(NativeStatement),
    Terminator(NativeStatement),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{SeqNum, heritage::heritage};
    use ventris_lifter::REGISTER_SPACE;

    fn names(space: u32, offset: u64, _size: u32) -> Option<String> {
        (space == REGISTER_SPACE).then(|| format!("r{offset}"))
    }

    fn seq(address: u64) -> SeqNum {
        SeqNum { address, order: 0 }
    }

    #[test]
    fn a_store_renders_its_address_and_value() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let space = data.new_constant(0, 4);
        let address = data.new_constant(0x2000, 4);
        let value = data.new_constant(7, 4);
        let store = data.new_op(op::STORE, seq(0x1000), vec![space, address, value]);
        data.op_insert_end(store, block);

        let statements = emit(&data, &names);
        assert_eq!(
            statements,
            vec![NativeStatement::Store {
                address: Expr::Constant {
                    value: 0x2000,
                    width: 4
                },
                value: Expr::Constant { value: 7, width: 4 },
                width: 4,
                volatile: false,
            }]
        );
    }

    #[test]
    fn a_direct_call_names_its_target_and_arguments() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let target = data.new_constant(0x3000, 4);
        let argument = data.new_constant(1, 4);
        let call = data.new_op(op::CALL, seq(0x1000), vec![target, argument]);
        data.op_insert_end(call, block);

        let statements = emit(&data, &names);
        assert_eq!(
            statements,
            vec![NativeStatement::Call(Expr::Call {
                target: Some(0x3000),
                callee: None,
                args: vec![Expr::Constant { value: 1, width: 4 }],
            })]
        );
    }

    #[test]
    fn a_return_carries_the_resolved_result() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_constant(2, 4);
        let right = data.new_constant(3, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![left, right]);
        let sum = data.new_unique(4);
        data.op_set_output(add, Some(sum));
        data.op_insert_end(add, block);
        let ret = data.new_op(op::RETURN, seq(0x1004), vec![sum]);
        data.op_insert_end(ret, block);

        let statements = emit(&data, &names);
        assert_eq!(
            statements,
            vec![NativeStatement::Return(Some(Expr::Binary {
                op: crate::native::BinaryOp::Add,
                left: Box::new(Expr::Constant { value: 2, width: 4 }),
                right: Box::new(Expr::Constant { value: 3, width: 4 }),
            }))]
        );
    }

    #[test]
    fn a_merged_return_value_is_assigned_on_each_path_and_then_returned() {
        let mut data = Funcdata::default();
        let entry = data.new_block(0x1000);
        let left = data.new_block(0x1010);
        let right = data.new_block(0x1020);
        let join = data.new_block(0x1030);
        data.add_edge(entry, left);
        data.add_edge(entry, right);
        data.add_edge(left, join);
        data.add_edge(right, join);
        let condition = data.new_constant(1, 1);
        let target = data.new_constant(0x1020, 4);
        let branch = data.new_op(op::CBRANCH, seq(0x1000), vec![target, condition]);
        data.op_insert_end(branch, entry);
        for (block, value) in [(left, 7u64), (right, 9u64)] {
            let start = data.block(block).start;
            let constant = data.new_constant(value, 4);
            let copy = data.new_op(op::COPY, seq(start), vec![constant]);
            let out = data.new_varnode(REGISTER_SPACE, 8, 4);
            data.op_set_output(copy, Some(out));
            data.op_insert_end(copy, block);
        }
        let read = data.new_varnode(REGISTER_SPACE, 8, 4);
        let ret = data.new_op(op::RETURN, seq(0x1030), vec![read]);
        data.op_insert_end(ret, join);

        heritage(&mut data);
        let statements = emit(&data, &names);

        let assignments: Vec<&NativeStatement> = statements
            .iter()
            .filter(|statement| matches!(statement, NativeStatement::Copy { .. }))
            .collect();
        assert_eq!(assignments.len(), 2, "each path assigns the merged value");
        let NativeStatement::Return(Some(Expr::Temporary { name, .. })) = statements
            .iter()
            .rev()
            .find(|statement| matches!(statement, NativeStatement::Return(_)))
            .expect("a return is emitted")
        else {
            panic!("the merged value must be returned by name, not dropped");
        };
        for assignment in assignments {
            let NativeStatement::Copy { destination, .. } = assignment else {
                unreachable!()
            };
            assert_eq!(
                destination,
                &Expr::Temporary {
                    name: name.clone(),
                    width: 4
                }
            );
        }
    }

    #[test]
    fn a_join_block_receives_a_label() {
        let mut data = Funcdata::default();
        let entry = data.new_block(0x1000);
        let left = data.new_block(0x1010);
        let join = data.new_block(0x1020);
        data.add_edge(entry, left);
        data.add_edge(entry, join);
        data.add_edge(left, join);
        let condition = data.new_constant(1, 1);
        let target = data.new_constant(0x1020, 4);
        let branch = data.new_op(op::CBRANCH, seq(0x1000), vec![target, condition]);
        data.op_insert_end(branch, entry);
        let ret = data.new_op(op::RETURN, seq(0x1020), vec![]);
        data.op_insert_end(ret, join);

        let statements = emit(&data, &names);
        assert!(statements.contains(&NativeStatement::Label(0x1020)));
        assert!(statements.contains(&NativeStatement::IfGoto {
            condition: Expr::Constant { value: 1, width: 1 },
            target: 0x1020
        }));
    }

    #[test]
    fn a_shared_computation_is_assigned_once_and_reused() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_constant(2, 4);
        let right = data.new_constant(3, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![left, right]);
        let sum = data.new_unique(4);
        data.op_set_output(add, Some(sum));
        data.op_insert_end(add, block);
        let space = data.new_constant(0, 4);
        for address in [0x1004u64, 0x1008] {
            let store = data.new_op(op::STORE, seq(address), vec![space, sum, sum]);
            data.op_insert_end(store, block);
        }

        let statements = emit(&data, &names);
        let assignments = statements
            .iter()
            .filter(|statement| matches!(statement, NativeStatement::Copy { .. }))
            .count();
        assert_eq!(assignments, 1, "the computation is spelled once");
        for statement in &statements {
            if let NativeStatement::Store { address, value, .. } = statement {
                assert!(matches!(address, Expr::Temporary { .. }));
                assert!(matches!(value, Expr::Temporary { .. }));
            }
        }
    }
}
