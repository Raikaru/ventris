//! Value resolution through the SSA graph.
//!
//! This is the load-bearing consumer the previous SSA work lacked. Ventris
//! resolved a read by looking its location up in a `BTreeMap<ValueKey, Expr>`
//! walked in address order, which cannot answer "what value arrives here when
//! two paths disagree" and cannot see a definition that dominates a use from a
//! lower address. Both limitations were visible in output: a merged return
//! value was dropped rather than named, and a stack spill could not forward to
//! the parameter that produced it.
//!
//! Here a read resolves by following its varnode's definition edge. A value
//! that several readers share, or that a `MULTIEQUAL` produces, becomes a named
//! variable declared at its definition; everything else inlines into its single
//! reader. That is Ghidra's explicit/implicit split, applied to the graph
//! instead of to an address map.
//!
//! Source authority: `Varnode::isExplicit`, `ActionMarkExplicit`, and
//! `PrintC::pushVn` in `varnode.hh`, `coreaction.cc`, and `printc.cc` at commit
//! `8b4c91d4d5bd1549622bfbade0df199585b98365`.

use std::collections::{BTreeMap, BTreeSet};

use ventris_pcode::op;

use super::{Funcdata, OpId, VarnodeId};
use crate::native::{BinaryOp, Expr, NativeStatement, Type};

/// Names assigned to values that must be spelled once and referred to by name.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Naming {
    names: BTreeMap<VarnodeId, String>,
}

impl Naming {
    pub fn name_of(&self, value: VarnodeId) -> Option<&str> {
        self.names.get(&value).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// Decides which values are explicit, i.e. get a name and a declaration.
///
/// Ghidra's `ActionMarkExplicit` marks a varnode explicit when it has more than
/// one descendant, when its definition cannot be duplicated, or when it is a
/// phi result. Duplicating a call or a load would duplicate an observable
/// effect, and a phi has no expression spelling at all, so both must be named.
pub fn mark_explicit(data: &Funcdata) -> Naming {
    let mut names = BTreeMap::new();
    for (id, op) in data.live_ops() {
        let Some(output) = op.output else { continue };
        let varnode = data.varnode(output);
        if varnode.flags.constant {
            continue;
        }
        let effectful = matches!(
            op.opcode,
            op::MULTIEQUAL | op::INDIRECT | op::CALL | op::CALLIND | op::LOAD
        );
        let shared = varnode.descendants.len() > 1;
        if !effectful && !shared {
            continue;
        }
        names.insert(output, value_name(data, id, output));
    }
    Naming { names }
}

fn value_name(data: &Funcdata, def: OpId, value: VarnodeId) -> String {
    let seq = data.op(def).seq;
    let varnode = data.varnode(value);
    match data.op(def).opcode {
        op::MULTIEQUAL => format!("phi_{:x}_{:x}", seq.address, varnode.offset),
        _ => format!("v_{:x}_{:x}", seq.address, varnode.offset),
    }
}

/// Resolves values to expressions by following definition edges.
pub struct Resolver<'a> {
    data: &'a Funcdata,
    naming: &'a Naming,
    register_name: &'a dyn Fn(u32, u64, u32) -> Option<String>,
}

impl<'a> Resolver<'a> {
    pub fn new(
        data: &'a Funcdata,
        naming: &'a Naming,
        register_name: &'a dyn Fn(u32, u64, u32) -> Option<String>,
    ) -> Self {
        Self {
            data,
            naming,
            register_name,
        }
    }

    /// The expression for a value at a use site.
    pub fn resolve(&self, value: VarnodeId) -> Expr {
        self.resolve_guarded(value, &mut BTreeSet::new())
    }

    /// The expression a named value's definition computes.
    ///
    /// [`Self::resolve`] returns the name, which is what a use site wants. The
    /// definition site wants the computation itself, so it can be assigned to
    /// that name exactly once.
    pub fn resolve_definition(&self, value: VarnodeId) -> Expr {
        let Some(def) = self.data.varnode(value).def else {
            return self.storage(value);
        };
        let mut active = BTreeSet::from([value]);
        self.translate(def, &mut active)
            .unwrap_or_else(|| self.storage(value))
    }

    fn resolve_guarded(&self, value: VarnodeId, active: &mut BTreeSet<VarnodeId>) -> Expr {
        let varnode = self.data.varnode(value);
        if varnode.flags.constant {
            return Expr::Constant {
                value: varnode.offset,
                width: varnode.size,
            };
        }
        if let Some(name) = self.naming.name_of(value) {
            return Expr::Temporary {
                name: name.to_string(),
                width: varnode.size,
            };
        }
        let Some(def) = varnode.def else {
            return self.storage(value);
        };
        // A definition reachable from its own operands cannot be inlined. The
        // explicit marking above already names every phi, so this only guards
        // against a malformed graph rather than against ordinary loops.
        if !active.insert(value) {
            return self.storage(value);
        }
        let expression = self.translate(def, active);
        active.remove(&value);
        expression.unwrap_or_else(|| self.storage(value))
    }

    /// The spelling of a value that has no inlinable definition: a register, a
    /// function input, or a stack slot.
    fn storage(&self, value: VarnodeId) -> Expr {
        let varnode = self.data.varnode(value);
        match (self.register_name)(varnode.space, varnode.offset, varnode.size) {
            Some(name) => Expr::Register {
                name,
                width: varnode.size,
            },
            None => Expr::Temporary {
                name: format!("loc_{:x}_{:x}", varnode.space, varnode.offset),
                width: varnode.size,
            },
        }
    }

    fn translate(&self, def: OpId, active: &mut BTreeSet<VarnodeId>) -> Option<Expr> {
        let op = self.data.op(def);
        let mut input = |slot: usize| -> Option<Expr> {
            op.inputs
                .get(slot)
                .copied()
                .map(|value| self.resolve_guarded(value, active))
        };
        let binary = |op_kind: BinaryOp, left: Expr, right: Expr| Expr::Binary {
            op: op_kind,
            left: Box::new(left),
            right: Box::new(right),
        };
        match op.opcode {
            op::COPY | op::CAST => input(0),
            op::INT_ADD | op::PTRADD | op::PTRSUB => {
                Some(binary(BinaryOp::Add, input(0)?, input(1)?))
            }
            op::INT_SUB => Some(binary(BinaryOp::Sub, input(0)?, input(1)?)),
            op::INT_MULT => Some(binary(BinaryOp::Mul, input(0)?, input(1)?)),
            op::INT_DIV => Some(binary(BinaryOp::Div, input(0)?, input(1)?)),
            op::INT_REM => Some(binary(BinaryOp::Rem, input(0)?, input(1)?)),
            op::INT_SDIV => Some(binary(BinaryOp::SignedDiv, input(0)?, input(1)?)),
            op::INT_SREM => Some(binary(BinaryOp::SignedRem, input(0)?, input(1)?)),
            op::INT_AND => Some(binary(BinaryOp::And, input(0)?, input(1)?)),
            op::INT_OR => Some(binary(BinaryOp::Or, input(0)?, input(1)?)),
            op::INT_XOR => Some(binary(BinaryOp::Xor, input(0)?, input(1)?)),
            op::INT_LEFT => Some(binary(BinaryOp::Left, input(0)?, input(1)?)),
            op::INT_RIGHT => Some(binary(BinaryOp::Right, input(0)?, input(1)?)),
            op::INT_SRIGHT => Some(binary(BinaryOp::SignedRight, input(0)?, input(1)?)),
            op::INT_EQUAL => Some(binary(BinaryOp::Equal, input(0)?, input(1)?)),
            op::INT_NOTEQUAL => Some(binary(BinaryOp::NotEqual, input(0)?, input(1)?)),
            op::INT_LESS => Some(binary(BinaryOp::Less, input(0)?, input(1)?)),
            op::INT_LESSEQUAL => Some(binary(BinaryOp::LessEqual, input(0)?, input(1)?)),
            op::INT_SLESS => Some(binary(BinaryOp::SignedLess, input(0)?, input(1)?)),
            op::INT_SLESSEQUAL => Some(binary(BinaryOp::SignedLessEqual, input(0)?, input(1)?)),
            op::INT_NEGATE => Some(Expr::BitNot(Box::new(input(0)?))),
            op::INT_2COMP => Some(Expr::Neg(Box::new(input(0)?))),
            op::BOOL_NEGATE => Some(Expr::Not(Box::new(input(0)?))),
            op::BOOL_AND => Some(binary(BinaryOp::LogicalAnd, input(0)?, input(1)?)),
            op::BOOL_OR => Some(binary(BinaryOp::LogicalOr, input(0)?, input(1)?)),
            op::INT_ZEXT | op::INT_SEXT => {
                let width = self.data.varnode(op.output?).size;
                let ty = if op.opcode == op::INT_SEXT {
                    Type::Signed(width.saturating_mul(8))
                } else {
                    Type::Unsigned(width.saturating_mul(8))
                };
                Some(Expr::Cast {
                    ty,
                    value: Box::new(input(0)?),
                })
            }
            op::LOAD => Some(Expr::Load {
                address: Box::new(input(1)?),
                width: self.data.varnode(op.output?).size,
            }),
            _ => None,
        }
    }

    /// Declarations for every explicit value, in graph order.
    ///
    /// A phi result is declared without an initializer expression, because its
    /// value depends on the path taken; the copies that give it a value are
    /// emitted at the end of each predecessor by [`phi_copies`].
    pub fn declarations(&self) -> Vec<NativeStatement> {
        let mut statements = Vec::new();
        for (def, op) in self.data.live_ops() {
            let Some(output) = op.output else { continue };
            let Some(name) = self.naming.name_of(output) else {
                continue;
            };
            let width = self.data.varnode(output).size;
            let ty = Type::Unsigned(width.saturating_mul(8));
            let value = if op.opcode == op::MULTIEQUAL {
                Expr::Temporary {
                    name: name.to_string(),
                    width,
                }
            } else {
                self.translate(def, &mut BTreeSet::new())
                    .unwrap_or_else(|| self.storage(output))
            };
            statements.push(NativeStatement::Declare {
                name: name.to_string(),
                ty,
                value,
            });
        }
        statements
    }

    /// The assignments that give each phi its value, per predecessor block.
    ///
    /// This is how a phi is spelled in C: the merge disappears and each
    /// incoming path assigns the shared name before control reaches the join.
    pub fn phi_copies(&self) -> Vec<(super::GraphBlockId, NativeStatement)> {
        let mut copies = Vec::new();
        for (_, op) in self.data.live_ops() {
            if op.opcode != op::MULTIEQUAL {
                continue;
            }
            let Some(output) = op.output else { continue };
            let Some(name) = self.naming.name_of(output) else {
                continue;
            };
            let Some(block) = op.parent else { continue };
            let width = self.data.varnode(output).size;
            for (slot, operand) in op.inputs.iter().copied().enumerate() {
                let Some(predecessor) = self.data.block(block).predecessors.get(slot).copied()
                else {
                    continue;
                };
                copies.push((
                    predecessor,
                    NativeStatement::Assign {
                        destination: Expr::Temporary {
                            name: name.to_string(),
                            width,
                        },
                        source: self.resolve(operand),
                    },
                ));
            }
        }
        copies
    }
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
    fn a_single_reader_definition_inlines_into_its_use() {
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

        let naming = mark_explicit(&data);
        assert!(naming.is_empty(), "one reader needs no name");
        let resolver = Resolver::new(&data, &naming, &names);
        assert_eq!(
            resolver.resolve(sum),
            Expr::Binary {
                op: BinaryOp::Add,
                left: Box::new(Expr::Constant { value: 2, width: 4 }),
                right: Box::new(Expr::Constant { value: 3, width: 4 }),
            }
        );
    }

    #[test]
    fn a_shared_definition_is_named_once_and_referenced_by_name() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let left = data.new_constant(2, 4);
        let right = data.new_constant(3, 4);
        let add = data.new_op(op::INT_ADD, seq(0x1000), vec![left, right]);
        let sum = data.new_unique(4);
        data.op_set_output(add, Some(sum));
        data.op_insert_end(add, block);
        for address in [0x1004, 0x1008] {
            let use_op = data.new_op(op::RETURN, seq(address), vec![sum]);
            data.op_insert_end(use_op, block);
        }

        let naming = mark_explicit(&data);
        assert_eq!(naming.len(), 1, "two readers force a name");
        let resolver = Resolver::new(&data, &naming, &names);
        assert!(matches!(resolver.resolve(sum), Expr::Temporary { .. }));
        let declarations = resolver.declarations();
        assert_eq!(declarations.len(), 1);
        let NativeStatement::Declare { value, .. } = &declarations[0] else {
            panic!("expected a declaration");
        };
        assert!(
            matches!(value, Expr::Binary { .. }),
            "the declaration carries the computation"
        );
    }

    #[test]
    fn a_load_is_named_so_the_memory_read_happens_once() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let space = data.new_constant(0, 4);
        let address = data.new_constant(0x2000, 4);
        let load = data.new_op(op::LOAD, seq(0x1000), vec![space, address]);
        let loaded = data.new_unique(4);
        data.op_set_output(load, Some(loaded));
        data.op_insert_end(load, block);
        let ret = data.new_op(op::RETURN, seq(0x1004), vec![loaded]);
        data.op_insert_end(ret, block);

        let naming = mark_explicit(&data);
        assert_eq!(naming.len(), 1, "a load is not duplicated into its readers");
    }

    #[test]
    fn a_merged_value_is_named_and_assigned_on_each_path() {
        let mut data = Funcdata::default();
        let entry = data.new_block(0x1000);
        let left = data.new_block(0x1010);
        let right = data.new_block(0x1020);
        let join = data.new_block(0x1030);
        data.add_edge(entry, left);
        data.add_edge(entry, right);
        data.add_edge(left, join);
        data.add_edge(right, join);
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

        assert_eq!(heritage(&mut data), 1);
        let naming = mark_explicit(&data);
        let resolver = Resolver::new(&data, &naming, &names);

        let returned = resolver.resolve(data.op(ret).inputs[0]);
        let Expr::Temporary { name, .. } = &returned else {
            panic!("a merged value must be named, not dropped: {returned:?}");
        };

        let copies = resolver.phi_copies();
        assert_eq!(copies.len(), 2, "one assignment per incoming path");
        let mut sources: Vec<u64> = Vec::new();
        for (block, statement) in &copies {
            assert!(*block == left || *block == right);
            let NativeStatement::Assign {
                destination,
                source,
            } = statement
            else {
                panic!("expected an assignment");
            };
            assert_eq!(
                destination,
                &Expr::Temporary {
                    name: name.clone(),
                    width: 4
                }
            );
            let Expr::Constant { value, .. } = source else {
                panic!("expected the path's constant");
            };
            sources.push(*value);
        }
        sources.sort_unstable();
        assert_eq!(sources, vec![7, 9]);
    }

    #[test]
    fn an_entry_register_resolves_to_its_architectural_name() {
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let read = data.new_varnode(REGISTER_SPACE, 16, 4);
        let ret = data.new_op(op::RETURN, seq(0x1000), vec![read]);
        data.op_insert_end(ret, block);
        let naming = mark_explicit(&data);
        let resolver = Resolver::new(&data, &naming, &names);
        assert_eq!(
            resolver.resolve(read),
            Expr::Register {
                name: "r16".to_string(),
                width: 4
            }
        );
    }

    #[test]
    fn a_definition_below_its_use_still_resolves() {
        // The old address-ordered map could only see definitions at lower
        // addresses. Following the graph edge is order-independent.
        let mut data = Funcdata::default();
        let block = data.new_block(0x1000);
        let constant = data.new_constant(5, 4);
        let define = data.new_op(op::COPY, seq(0x2000), vec![constant]);
        let defined = data.new_unique(4);
        data.op_set_output(define, Some(defined));
        data.op_insert_end(define, block);
        let ret = data.new_op(op::RETURN, seq(0x1000), vec![defined]);
        data.op_insert_end(ret, block);

        let naming = mark_explicit(&data);
        let resolver = Resolver::new(&data, &naming, &names);
        assert_eq!(
            resolver.resolve(defined),
            Expr::Constant { value: 5, width: 4 }
        );
    }
}
