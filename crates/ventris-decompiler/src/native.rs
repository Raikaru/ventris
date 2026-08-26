//! A dependency-free native decompiler for the p-code produced by
//! `ventris-lifter`.
//!
//! This module owns the complete native pipeline: versioned values,
//! width-driven type facts, CFG labels, and deterministic C rendering.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::LazyLock;
use ventris_lifter::{Architecture, NativeFunction, REGISTER_SPACE};
use ventris_pcode::{PcodeOp, Varnode, op};
use ventris_target::{Abi, AbiRegisterClass, ArgumentRegisterMode};

mod actions;
mod c_score;
mod control_flow;
mod declaration;
mod frame;
mod heritage;
mod printer;
mod ssa;
mod structure;

use crate::graph;
use actions::{expression_width, type_width};
pub use c_score::{CScore, score_c};
use control_flow::simplify;
#[cfg(test)]
use control_flow::structure_control_flow;
use frame::promote_frame_slots;
pub use ssa::{SsaFunction, SsaValue, TypeConstraint, TypeSolver, build_ssa};
use ssa::{ValueKey, merge_types};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Type {
    Unknown,
    Bool,
    Unsigned(u32),
    Signed(u32),
    Float(u32),
    Pointer(Box<Type>),
    Void,
}

impl Type {
    pub fn c_name(&self) -> &'static str {
        match self {
            Self::Unknown => "uint64_t",
            Self::Bool => "bool",
            Self::Unsigned(8) => "uint8_t",
            Self::Unsigned(16) => "uint16_t",
            Self::Unsigned(32) => "uint32_t",
            Self::Unsigned(64) => "uint64_t",
            Self::Unsigned(_) => "uint64_t",
            Self::Float(32) => "float",
            Self::Float(64) => "double",
            Self::Float(_) => "double",
            Self::Signed(8) => "int8_t",
            Self::Signed(16) => "int16_t",
            Self::Signed(32) => "int32_t",
            Self::Signed(64) => "int64_t",
            Self::Signed(_) => "int64_t",
            Self::Pointer(_) => "uintptr_t",
            Self::Void => "void",
        }
    }

    fn from_width(width: u32) -> Self {
        Self::Unsigned(width.saturating_mul(8))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    SignedDiv,
    SignedRem,
    And,
    Or,
    Xor,
    LogicalAnd,
    LogicalOr,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    SignedLess,
    SignedLessEqual,
    Left,
    Right,
    SignedRight,
}

impl BinaryOp {
    fn text(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div | Self::SignedDiv => "/",
            Self::Rem | Self::SignedRem => "%",
            Self::And => "&",
            Self::Or => "|",
            Self::Xor => "^",
            Self::LogicalAnd => "&&",
            Self::LogicalOr => "||",
            Self::Equal => "==",
            Self::NotEqual => "!=",
            Self::Less | Self::SignedLess => "<",
            Self::LessEqual | Self::SignedLessEqual => "<=",
            Self::Left => "<<",
            Self::Right | Self::SignedRight => ">>",
        }
    }

    fn precedence(self) -> u8 {
        match self {
            Self::LogicalOr => 2,
            Self::LogicalAnd => 3,
            Self::Or => 4,
            Self::Xor => 5,
            Self::And => 6,
            Self::Equal
            | Self::NotEqual
            | Self::Less
            | Self::LessEqual
            | Self::SignedLess
            | Self::SignedLessEqual => 7,
            Self::Left | Self::Right | Self::SignedRight => 8,
            Self::Add | Self::Sub => 9,
            Self::Mul | Self::Div | Self::Rem | Self::SignedDiv | Self::SignedRem => 10,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Expr {
    Constant {
        value: u64,
        width: u32,
    },
    Parameter {
        name: String,
        ty: Type,
    },
    Register {
        name: String,
        width: u32,
    },
    Temporary {
        name: String,
        width: u32,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Not(Box<Expr>),
    Neg(Box<Expr>),
    BitNot(Box<Expr>),
    Cast {
        ty: Type,
        value: Box<Expr>,
    },
    /// An analysis-only type assertion. Rendering is transparent: the wrapped
    /// expression already has the desired source spelling, while this node
    /// preserves p-code result semantics for later return/type recovery.
    Typed {
        ty: Type,
        value: Box<Expr>,
    },
    Select {
        condition: Box<Expr>,
        when_true: Box<Expr>,
        when_false: Box<Expr>,
    },
    Global {
        name: String,
        address: u64,
        width: u32,
    },
    Load {
        address: Box<Expr>,
        width: u32,
    },
    /// A field read through a recovered structure pointer.
    ///
    /// `*(uint32_t *)(p + 0x40)` and `p->field_40` describe the same access, but
    /// only the second says the offset is a field of a known type. Ghidra emits
    /// the second whenever type recovery gives it a structure, which is why its
    /// output carries no cast where ours carries two.
    Field {
        base: Box<Expr>,
        name: String,
        width: u32,
    },
    Call {
        target: Option<u64>,
        callee: Option<Box<Expr>>,
        args: Vec<Expr>,
    },
    Builtin {
        name: &'static str,
        args: Vec<Expr>,
    },
}

impl Expr {
    fn constant(value: u64, width: u32) -> Self {
        Self::Constant { value, width }
    }

    fn is_zero(&self) -> bool {
        matches!(self, Self::Constant { value: 0, .. })
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NativeStatement {
    Label(u64),
    Store {
        address: Expr,
        value: Expr,
        width: u32,
        volatile: bool,
    },
    Copy {
        destination: Expr,
        source: Expr,
        width: u32,
        volatile: bool,
    },
    Call(Expr),
    Declare {
        name: String,
        ty: Type,
        value: Expr,
    },
    /// A local whose value depends on the path taken, so it is declared where
    /// every assignment to it is dominated and assigned on each path. This is
    /// how a `MULTIEQUAL` is spelled in C.
    DeclareLocal {
        name: String,
        ty: Type,
    },
    /// An assignment to an already-declared location. Distinct from `Copy`,
    /// which is a block memory copy, and from `Declare`, which introduces a
    /// name at its single definition site.
    Assign {
        destination: Expr,
        source: Expr,
    },
    IfGoto {
        condition: Expr,
        target: u64,
    },
    IfReturn {
        condition: Expr,
        value: Option<Expr>,
    },
    IfElse {
        condition: Expr,
        then_body: Vec<NativeStatement>,
        else_body: Vec<NativeStatement>,
    },
    While {
        condition: Expr,
        body: Vec<NativeStatement>,
    },
    DoWhile {
        body: Vec<NativeStatement>,
        condition: Expr,
    },
    For {
        initializer: Option<Box<NativeStatement>>,
        condition: Option<Expr>,
        step: Option<Box<NativeStatement>>,
        body: Vec<NativeStatement>,
    },
    Switch {
        expression: Expr,
        cases: Vec<(u64, Vec<NativeStatement>)>,
        default: Vec<NativeStatement>,
    },
    Break,
    Continue,
    Goto(u64),
    /// A computed control-flow transfer. GNU C's computed-goto spelling keeps
    /// the operation distinct from an indirect call without inventing a target.
    IndirectGoto(Expr),
    Return(Option<Expr>),
    Expression(Expr),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NativeParameter {
    pub name: String,
    pub ty: Type,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NativeDocument {
    pub name: String,
    pub return_type: Type,
    pub parameters: Vec<NativeParameter>,
    pub statements: Vec<NativeStatement>,
    pub ssa: SsaFunction,
    pub types: Vec<TypeConstraint>,
    pub warnings: Vec<String>,
    /// The recovered prototype, when a calling convention was known.
    ///
    /// Ghidra's `PrintC::emitFunctionDeclaration` reads the prototype and the
    /// local scope rather than re-deriving the signature from the body, so both
    /// travel with the document for the printer to read.
    pub prototype: Option<graph::funcproto::FuncProto>,
    pub scope: Option<graph::scope::ScopeLocal>,
}

impl Default for NativeDocument {
    fn default() -> Self {
        Self {
            name: String::new(),
            return_type: Type::Void,
            parameters: Vec::new(),
            statements: Vec::new(),
            ssa: SsaFunction::default(),
            types: Vec::new(),
            warnings: Vec::new(),
            prototype: None,
            scope: None,
        }
    }
}

impl NativeDocument {
    pub fn render(&self) -> String {
        printer::render_document(self)
    }
}

/// Stack offsets a callee-saved register is restored from.
///
/// A save whose value is read back before the function returns is bookkeeping,
/// not computation.
fn graph_restored_slots(
    architecture: Architecture,
    abi: &Abi,
    statements: &[NativeStatement],
) -> BTreeSet<(String, i64)> {
    let mut restored = BTreeSet::new();
    for statement in statements {
        let value = match statement {
            NativeStatement::Declare { value, .. }
            | NativeStatement::Assign { source: value, .. } => value,
            _ => continue,
        };
        if let Expr::Load { address, .. } = value
            && let Some(slot) = prologue_stack_slot(architecture, abi, address)
        {
            restored.insert(slot);
        }
    }
    restored
}

/// The return type a graph-pipeline function reports.
///
/// A function whose returns carry no value is `void`. Reporting a value type
/// unconditionally claims a result the function never produces, which is what
/// made every graph-pipeline function differ from the oracle on return
/// presence.
fn graph_return_type(
    data: &graph::Funcdata,
    types: &graph::types::Types,
    architecture: Architecture,
) -> Type {
    let returned: Vec<graph::VarnodeId> = data
        .live_ops()
        .filter(|(_, operation)| operation.opcode == op::RETURN)
        .filter_map(|(_, operation)| operation.inputs.get(1).copied())
        .collect();
    if returned.is_empty() {
        return Type::Void;
    }
    // A returned pointer is pointer-width, whatever register held it. On a
    // 64-bit register file the value's storage says 64 bits, so the shared
    // `Type` table reports `int64_t` and the caller has to cast the address
    // computation twice. Ghidra reports `GameWorld *` for the same function.
    // The rich table is consulted only for this: a genuine 64-bit integer
    // return recovers as an integer, not a pointer, so it is left alone.
    let rich = data.recovered_types();
    if let Some(pointee) = returned
        .iter()
        .filter_map(|value| rich.1.get(*value))
        .find_map(|recovered| match recovered {
            graph::typefactory::DataType::Pointer { to, .. } => {
                Some(graph::typefactory::to_native(to))
            }
            _ => None,
        })
    {
        return Type::Pointer(Box::new(pointee));
    }
    returned
        .iter()
        .filter_map(|value| types.get(*value).cloned())
        .find(|recovered| !matches!(recovered, Type::Unknown))
        .unwrap_or_else(|| default_return_type(architecture))
}

/// Bounded source normal forms for compiler-sensitive candidate probing.
///
/// These are semantic-preserving spellings, not arbitrary optimization knobs.
/// Keep this list small: every added form multiplies external compiler work.
/// How many times simplification, unreachable-block removal, and dead code
/// may feed each other before the pipeline stops. Each pass is monotone, so a
/// small bound suffices; the cap exists so a rule pair that oscillates cannot
/// spin.
const GRAPH_PIPELINE_ROUNDS: usize = 8;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum CompilerNormalForm {
    Canonical,
    ExplicitResultCasts,
}

impl CompilerNormalForm {
    pub const ALL: [Self; 2] = [Self::Canonical, Self::ExplicitResultCasts];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::ExplicitResultCasts => "explicit-result-casts",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CompilerCandidate {
    pub normal_form: CompilerNormalForm,
    pub source: String,
    pub score: CScore,
}

impl NativeDocument {
    pub fn render_normal_form(&self, normal_form: CompilerNormalForm) -> String {
        match normal_form {
            CompilerNormalForm::Canonical => self.render(),
            CompilerNormalForm::ExplicitResultCasts => {
                let mut document = self.clone();
                document.statements = document
                    .statements
                    .into_iter()
                    .map(materialize_result_casts_statement)
                    .collect();
                document.render()
            }
        }
    }

    /// Generate the complete bounded candidate set and rank it against an
    /// external C oracle. Exact candidates sort first, then token similarity,
    /// with the stable normal-form order as the final tie-breaker.
    pub fn compiler_candidates(&self, oracle: &str) -> Vec<CompilerCandidate> {
        let mut candidates = CompilerNormalForm::ALL
            .into_iter()
            .map(|normal_form| {
                let source = self.render_normal_form(normal_form);
                let score = score_c(oracle, &source);
                CompilerCandidate {
                    normal_form,
                    source,
                    score,
                }
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            right
                .score
                .exact
                .cmp(&left.score.exact)
                .then_with(|| right.score.ratio_milli().cmp(&left.score.ratio_milli()))
                .then_with(|| right.score.matched_tokens.cmp(&left.score.matched_tokens))
                .then_with(|| left.normal_form.cmp(&right.normal_form))
        });
        candidates
    }
}

fn materialize_result_casts_expr(expression: Expr) -> Expr {
    match expression {
        Expr::Typed { ty, value } => Expr::Cast {
            ty,
            value: Box::new(materialize_result_casts_expr(*value)),
        },
        Expr::Binary { op, left, right } => Expr::Binary {
            op,
            left: Box::new(materialize_result_casts_expr(*left)),
            right: Box::new(materialize_result_casts_expr(*right)),
        },
        Expr::Not(value) => Expr::Not(Box::new(materialize_result_casts_expr(*value))),
        Expr::Neg(value) => Expr::Neg(Box::new(materialize_result_casts_expr(*value))),
        Expr::BitNot(value) => Expr::BitNot(Box::new(materialize_result_casts_expr(*value))),
        Expr::Cast { ty, value } => Expr::Cast {
            ty,
            value: Box::new(materialize_result_casts_expr(*value)),
        },
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => Expr::Select {
            condition: Box::new(materialize_result_casts_expr(*condition)),
            when_true: Box::new(materialize_result_casts_expr(*when_true)),
            when_false: Box::new(materialize_result_casts_expr(*when_false)),
        },
        Expr::Field { base, name, width } => Expr::Field {
            base: Box::new(materialize_result_casts_expr(*base)),
            name,
            width,
        },
        Expr::Load { address, width } => Expr::Load {
            address: Box::new(materialize_result_casts_expr(*address)),
            width,
        },
        Expr::Call {
            target,
            callee,
            args,
        } => Expr::Call {
            target,
            callee: callee.map(|value| Box::new(materialize_result_casts_expr(*value))),
            args: args
                .into_iter()
                .map(materialize_result_casts_expr)
                .collect(),
        },
        Expr::Builtin { name, args } => Expr::Builtin {
            name,
            args: args
                .into_iter()
                .map(materialize_result_casts_expr)
                .collect(),
        },
        value @ (Expr::Constant { .. }
        | Expr::Parameter { .. }
        | Expr::Register { .. }
        | Expr::Temporary { .. }
        | Expr::Global { .. }) => value,
    }
}

fn materialize_result_casts_statement(statement: NativeStatement) -> NativeStatement {
    match statement {
        NativeStatement::Store {
            address,
            value,
            width,
            volatile,
        } => NativeStatement::Store {
            address: materialize_result_casts_expr(address),
            value: materialize_result_casts_expr(value),
            width,
            volatile,
        },
        NativeStatement::DeclareLocal { name, ty } => NativeStatement::DeclareLocal { name, ty },
        NativeStatement::Assign {
            destination,
            source,
        } => NativeStatement::Assign {
            destination: materialize_result_casts_expr(destination),
            source: materialize_result_casts_expr(source),
        },
        NativeStatement::Copy {
            destination,
            source,
            width,
            volatile,
        } => NativeStatement::Copy {
            destination: materialize_result_casts_expr(destination),
            source: materialize_result_casts_expr(source),
            width,
            volatile,
        },
        NativeStatement::Call(value) => NativeStatement::Call(materialize_result_casts_expr(value)),
        NativeStatement::Declare { name, ty, value } => NativeStatement::Declare {
            name,
            ty,
            value: materialize_result_casts_expr(value),
        },
        NativeStatement::IfGoto { condition, target } => NativeStatement::IfGoto {
            condition: materialize_result_casts_expr(condition),
            target,
        },
        NativeStatement::IfReturn { condition, value } => NativeStatement::IfReturn {
            condition: materialize_result_casts_expr(condition),
            value: value.map(materialize_result_casts_expr),
        },
        NativeStatement::IfElse {
            condition,
            then_body,
            else_body,
        } => NativeStatement::IfElse {
            condition: materialize_result_casts_expr(condition),
            then_body: then_body
                .into_iter()
                .map(materialize_result_casts_statement)
                .collect(),
            else_body: else_body
                .into_iter()
                .map(materialize_result_casts_statement)
                .collect(),
        },
        NativeStatement::While { condition, body } => NativeStatement::While {
            condition: materialize_result_casts_expr(condition),
            body: body
                .into_iter()
                .map(materialize_result_casts_statement)
                .collect(),
        },
        NativeStatement::DoWhile { body, condition } => NativeStatement::DoWhile {
            body: body
                .into_iter()
                .map(materialize_result_casts_statement)
                .collect(),
            condition: materialize_result_casts_expr(condition),
        },
        NativeStatement::For {
            initializer,
            condition,
            step,
            body,
        } => NativeStatement::For {
            initializer: initializer
                .map(|statement| Box::new(materialize_result_casts_statement(*statement))),
            condition: condition.map(materialize_result_casts_expr),
            step: step.map(|statement| Box::new(materialize_result_casts_statement(*statement))),
            body: body
                .into_iter()
                .map(materialize_result_casts_statement)
                .collect(),
        },
        NativeStatement::Switch {
            expression,
            cases,
            default,
        } => NativeStatement::Switch {
            expression: materialize_result_casts_expr(expression),
            cases: cases
                .into_iter()
                .map(|(value, body)| {
                    (
                        value,
                        body.into_iter()
                            .map(materialize_result_casts_statement)
                            .collect(),
                    )
                })
                .collect(),
            default: default
                .into_iter()
                .map(materialize_result_casts_statement)
                .collect(),
        },
        NativeStatement::IndirectGoto(value) => {
            NativeStatement::IndirectGoto(materialize_result_casts_expr(value))
        }
        NativeStatement::Return(value) => {
            NativeStatement::Return(value.map(materialize_result_casts_expr))
        }
        NativeStatement::Expression(value) => {
            NativeStatement::Expression(materialize_result_casts_expr(value))
        }
        value @ (NativeStatement::Label(_)
        | NativeStatement::Goto(_)
        | NativeStatement::Break
        | NativeStatement::Continue) => value,
    }
}
fn default_return_type(architecture: Architecture) -> Type {
    match architecture {
        Architecture::M6502 | Architecture::Z80 => Type::Unsigned(8),
        Architecture::Arm32
        | Architecture::X86_32
        | Architecture::Thumb
        | Architecture::Mips32
        | Architecture::Mips32Be
        | Architecture::Ps2
        | Architecture::Ps1
        | Architecture::Rv32
        | Architecture::Ppc32
        | Architecture::GameCube
        | Architecture::M68k
        | Architecture::Sh2
        | Architecture::Sh4
        | Architecture::Spu => Type::Unsigned(32),
        Architecture::N64
        | Architecture::X86_64
        | Architecture::AArch64
        | Architecture::Rv64
        | Architecture::Ppc64 => Type::Unsigned(64),
    }
}

fn expression_type(value: &Expr, architecture: Architecture) -> Type {
    match value {
        Expr::Parameter { ty, .. } => ty.clone(),
        Expr::Constant { width, .. } => Type::from_width(*width),
        Expr::Call { .. } => default_return_type(architecture),
        Expr::Global { width, .. } | Expr::Load { width, .. } | Expr::Field { width, .. } => {
            Type::from_width(*width)
        }
        Expr::Builtin { .. } => Type::Unsigned(32),
        Expr::Typed { ty, .. } => ty.clone(),
        Expr::Register { width, .. } | Expr::Temporary { width, .. } => Type::from_width(*width),
        Expr::Binary { op, left, right } => {
            if matches!(
                op,
                BinaryOp::Equal
                    | BinaryOp::NotEqual
                    | BinaryOp::Less
                    | BinaryOp::LessEqual
                    | BinaryOp::SignedLess
                    | BinaryOp::SignedLessEqual
                    | BinaryOp::LogicalAnd
                    | BinaryOp::LogicalOr
            ) {
                Type::Bool
            } else {
                let merged = merge_types(
                    &expression_type(left, architecture),
                    &expression_type(right, architecture),
                );
                if matches!(
                    op,
                    BinaryOp::SignedDiv | BinaryOp::SignedRem | BinaryOp::SignedRight
                ) {
                    match merged {
                        Type::Unsigned(width) | Type::Signed(width) => Type::Signed(width),
                        _ => merged,
                    }
                } else {
                    merged
                }
            }
        }
        Expr::Not(_) => Type::Bool,
        Expr::Neg(value) | Expr::BitNot(value) => expression_type(value, architecture),
        Expr::Cast { ty, .. } => ty.clone(),
        Expr::Select {
            when_true,
            when_false,
            ..
        } => merge_types(
            &expression_type(when_true, architecture),
            &expression_type(when_false, architecture),
        ),
    }
}

/// Whether the architecture's memory is big endian.
///
/// Ghidra reads this from the address space the value lives in. Every target
/// here has one byte order for memory, so the architecture answers it. SuperH is
/// switchable in hardware; both profiles are the big-endian configurations the
/// pinned languages describe.
fn architecture_is_big_endian(architecture: Architecture) -> bool {
    match architecture {
        Architecture::Mips32Be
        | Architecture::N64
        | Architecture::Ppc32
        | Architecture::Ppc64
        | Architecture::GameCube
        | Architecture::M68k
        | Architecture::Sh2
        | Architecture::Sh4
        | Architecture::Spu => true,
        Architecture::X86_64
        | Architecture::X86_32
        | Architecture::AArch64
        | Architecture::Arm32
        | Architecture::Thumb
        | Architecture::Mips32
        | Architecture::Ps2
        | Architecture::Ps1
        | Architecture::Rv64
        | Architecture::Rv32
        | Architecture::M6502
        | Architecture::Z80 => false,
    }
}

fn abi_register_vnode(
    architecture: Architecture,
    register: &str,
    pointer_bits: u8,
) -> Option<Varnode> {
    let register = register.strip_prefix('$').unwrap_or(register);
    let width = u32::from(pointer_bits.div_ceil(8)).max(1);
    match architecture {
        Architecture::Mips32 | Architecture::Mips32Be | Architecture::Ps1 => {
            const GPR: &[&str] = &[
                "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4",
                "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0",
                "k1", "gp", "sp", "fp", "ra",
            ];
            if let Some(index) = GPR.iter().position(|candidate| *candidate == register) {
                return Some(Varnode::new(REGISTER_SPACE, index as u64 * 4, 4));
            }
            register.strip_prefix('f').and_then(|index| {
                index
                    .parse::<u64>()
                    .ok()
                    .filter(|index| *index < 32)
                    .map(|index| Varnode::new(REGISTER_SPACE, 0x200 + index * 4, 4))
            })
        }
        Architecture::Ps2 => {
            // The R5900 uses O32 register names over a 128-bit register file,
            // so neither the MIPS32 nor the MIPS64 stride applies. Ask the
            // language for the offset instead of assuming one.
            const GPR: &[&str] = &[
                "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4",
                "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0",
                "k1", "gp", "sp", "fp", "ra",
            ];
            let named = GPR.iter().any(|candidate| *candidate == register)
                || register
                    .strip_prefix('f')
                    .is_some_and(|index| index.parse::<u64>().is_ok_and(|index| index < 32));
            if !named {
                return None;
            }
            ventris_lifter::sleigh_register_varnode(architecture, register)
                .map(|(space, offset, size)| Varnode::new(space, offset, size))
        }
        Architecture::N64 => {
            const GPR: &[&str] = &[
                "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "t0",
                "t1", "t2", "t3", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0",
                "k1", "gp", "sp", "fp", "ra",
            ];
            if let Some(index) = GPR.iter().position(|candidate| *candidate == register) {
                return Some(Varnode::new(REGISTER_SPACE, index as u64 * 8, 8));
            }
            register.strip_prefix('f').and_then(|index| {
                index
                    .parse::<u64>()
                    .ok()
                    .filter(|index| *index < 32)
                    .map(|index| Varnode::new(REGISTER_SPACE, 0x200 + index * 8, 8))
            })
        }
        Architecture::Arm32 | Architecture::Thumb => {
            let index = match register {
                "sp" => Some(13),
                "lr" => Some(14),
                "pc" => Some(15),
                _ => register
                    .strip_prefix('r')
                    .and_then(|index| index.parse::<u64>().ok())
                    .filter(|index| *index < 16),
            };
            if let Some(index) = index {
                return Some(Varnode::new(REGISTER_SPACE, 32 + index * 4, 4));
            }
            register.strip_prefix('s').and_then(|index| {
                index
                    .parse::<u64>()
                    .ok()
                    .filter(|index| *index < 32)
                    .map(|index| Varnode::new(REGISTER_SPACE, 0x200 + index * 4, 4))
            })
        }
        Architecture::Ppc32 | Architecture::GameCube | Architecture::Ppc64 => {
            if register == "lr" {
                return Some(Varnode::new(REGISTER_SPACE, 0x1020, width));
            }
            if register == "ctr" {
                return Some(Varnode::new(REGISTER_SPACE, 0x1024, width));
            }
            if let Some(index) = register
                .strip_prefix('f')
                .and_then(|index| index.parse::<u64>().ok().filter(|index| *index < 32))
            {
                return Some(Varnode::new(
                    REGISTER_SPACE,
                    0x200 + index * u64::from(width),
                    width,
                ));
            }
            register
                .strip_prefix('r')
                .and_then(|index| index.parse::<u64>().ok())
                .filter(|index| *index < 32)
                .map(|index| Varnode::new(REGISTER_SPACE, index * u64::from(width), width))
        }
        _ => None,
    }
}

fn abi_register_name(architecture: Architecture, abi: &Abi, register: &str) -> Option<String> {
    abi_register_vnode(architecture, register, abi.pointer_bits)
        .map(|vnode| register_name(architecture, vnode.offset))
}

fn register_vnode_matches(value: Varnode, register: Varnode) -> bool {
    value.space == register.space && value.offset == register.offset && value.size <= register.size
}

fn definition_available(value: Varnode, definitions: &BTreeMap<ValueKey, Expr>) -> bool {
    definitions.keys().any(|key| {
        key.space == value.space && key.offset == value.offset && key.width <= value.size
    })
}

fn abi_argument_vnodes(architecture: Architecture, abi: &Abi) -> Vec<Varnode> {
    let groups = [
        AbiRegisterClass::Integer,
        AbiRegisterClass::Floating,
        AbiRegisterClass::Vector,
    ];
    let mut registers = Vec::new();
    for class in groups {
        let group = abi.arguments.group(class);
        let Some(count) = group.count() else {
            continue;
        };
        for index in 0..count {
            if let Some(register) = group
                .at(index)
                .and_then(|name| abi_register_vnode(architecture, name, abi.pointer_bits))
            {
                registers.push(register);
            }
        }
    }
    registers
}

fn abi_return_vnodes(architecture: Architecture, abi: &Abi) -> Vec<Varnode> {
    let groups = [
        AbiRegisterClass::Integer,
        AbiRegisterClass::Floating,
        AbiRegisterClass::Vector,
    ];
    let mut registers = Vec::new();
    for class in groups {
        let group = abi.returns.group(class);
        let Some(count) = group.count() else {
            continue;
        };
        for index in 0..count {
            if let Some(register) = group
                .at(index)
                .and_then(|name| abi_register_vnode(architecture, name, abi.pointer_bits))
            {
                registers.push(register);
            }
        }
    }
    if registers.is_empty() {
        if let Some(register) =
            abi_register_vnode(architecture, abi.return_register, abi.pointer_bits)
        {
            registers.push(register);
        }
    }
    registers
}

fn abi_primary_return_vnodes(architecture: Architecture, abi: &Abi) -> Vec<Varnode> {
    [
        AbiRegisterClass::Integer,
        AbiRegisterClass::Floating,
        AbiRegisterClass::Vector,
    ]
    .into_iter()
    .filter_map(|class| {
        abi.returns
            .group(class)
            .at(0)
            .and_then(|name| abi_register_vnode(architecture, name, abi.pointer_bits))
    })
    .collect()
}

fn abi_register_group_vnodes(
    architecture: Architecture,
    abi: &Abi,
    group: ventris_target::RegisterGroup,
) -> Vec<Varnode> {
    let Some(count) = group.count() else {
        return Vec::new();
    };
    (0..count)
        .filter_map(|index| {
            group
                .at(index)
                .and_then(|name| abi_register_vnode(architecture, name, abi.pointer_bits))
        })
        .collect()
}

fn invalidate_abi_call_clobbers(
    architecture: Architecture,
    abi: &Abi,
    definitions: &mut BTreeMap<ValueKey, Expr>,
) {
    let registers = abi_register_group_vnodes(architecture, abi, abi.caller_saved);
    if registers.is_empty() {
        return;
    }
    definitions.retain(|key, _| {
        !registers.iter().any(|register| {
            key.space == register.space
                && key.offset == register.offset
                && key.width <= register.size
        })
    });
}

fn signed_constant(value: &Expr) -> Option<i64> {
    let Expr::Constant { value, width } = value else {
        return None;
    };
    let bits = width.saturating_mul(8).min(64);
    if bits == 0 {
        return Some(0);
    }
    if bits == 64 {
        Some(*value as i64)
    } else {
        let mask = (1u64 << bits) - 1;
        let value = *value & mask;
        let sign = 1u64 << (bits - 1);
        Some(if value & sign != 0 {
            (value | !mask) as i64
        } else {
            value as i64
        })
    }
}

fn affine_register_offset(value: &Expr, roots: &[&str]) -> Option<(String, i64)> {
    match value {
        Expr::Register { name, .. } if roots.iter().any(|root| *root == name) => {
            Some((name.clone(), 0))
        }
        Expr::Cast { value, .. } => affine_register_offset(value, roots),
        Expr::Typed { value, .. } => affine_register_offset(value, roots),
        Expr::Binary {
            op: BinaryOp::Add,
            left,
            right,
        } => {
            if let Some((root, offset)) = affine_register_offset(left, roots) {
                return signed_constant(right)
                    .map(|constant| (root, offset.saturating_add(constant)));
            }
            if let Some((root, offset)) = affine_register_offset(right, roots) {
                return signed_constant(left)
                    .map(|constant| (root, offset.saturating_add(constant)));
            }
            None
        }
        Expr::Binary {
            op: BinaryOp::Sub,
            left,
            right,
        } => affine_register_offset(left, roots).and_then(|(root, offset)| {
            signed_constant(right).map(|constant| (root, offset.saturating_sub(constant)))
        }),
        _ => None,
    }
}

fn entry_stack_offset(architecture: Architecture, abi: &Abi, address: &Expr) -> Option<i64> {
    let stack_name = abi_register_name(architecture, abi, abi.stack_pointer)?;
    affine_register_offset(address, &[stack_name.as_str()]).map(|(_, offset)| offset)
}

fn prologue_stack_slot(
    architecture: Architecture,
    abi: &Abi,
    address: &Expr,
) -> Option<(String, i64)> {
    let stack_name = abi_register_name(architecture, abi, abi.stack_pointer)?;
    let frame_name = abi
        .frame_pointer
        .and_then(|register| abi_register_name(architecture, abi, register));
    let mut roots = vec![stack_name.as_str()];
    if let Some(frame_name) = frame_name.as_deref() {
        if frame_name != stack_name {
            roots.push(frame_name);
        }
    }
    affine_register_offset(address, &roots)
}

fn abi_special_register_names(architecture: Architecture, abi: &Abi) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for register in [
        Some(abi.stack_pointer),
        abi.frame_pointer,
        abi.return_address,
    ]
    .into_iter()
    .flatten()
    {
        if let Some(name) = abi_register_name(architecture, abi, register) {
            names.insert(name);
        }
    }
    if let Some(count) = abi.callee_saved.count() {
        for index in 0..count {
            if let Some(register) = abi
                .callee_saved
                .at(index)
                .and_then(|name| abi_register_name(architecture, abi, name))
            {
                names.insert(register);
            }
        }
    }
    names
}

fn expression_is_named_register(value: &Expr, names: &BTreeSet<String>) -> bool {
    match value {
        Expr::Register { name, .. } => names.contains(name),
        Expr::Cast { value, .. } => expression_is_named_register(value, names),
        _ => false,
    }
}

fn is_abi_stack_backchain_save(
    architecture: Architecture,
    abi: &Abi,
    address: &Expr,
    value: &Expr,
) -> bool {
    if !matches!(
        architecture,
        Architecture::Ppc32 | Architecture::GameCube | Architecture::Ppc64
    ) {
        return false;
    }
    let Some(stack_name) = abi_register_name(architecture, abi, abi.stack_pointer) else {
        return false;
    };
    matches!(value, Expr::Register { name, .. } if name == &stack_name)
        && affine_register_offset(address, &[stack_name.as_str()])
            .is_some_and(|(_, offset)| offset < 0)
}

fn is_abi_restore_load(
    architecture: Architecture,
    abi: &Abi,
    _output: Varnode,
    address: &Expr,
    state: &mut PrologueState,
) -> bool {
    let Some(slot) = prologue_stack_slot(architecture, abi, address) else {
        return false;
    };
    if !state.saved_stack_slots.contains(&slot) {
        return false;
    }
    state.restored_stack_slots.insert(slot);
    true
}

fn stack_argument_parameter(
    architecture: Architecture,
    abi: &Abi,
    address: &Expr,
    width: u32,
) -> Option<Expr> {
    let stack = abi.stack_arguments?;
    let offset = entry_stack_offset(architecture, abi, address)?;
    let first_offset = i64::from(stack.first_offset);
    let slot_size = i64::from(stack.slot_size);
    if slot_size <= 0 || offset < first_offset {
        return None;
    }
    let relative = offset - first_offset;
    if relative % slot_size != 0 {
        return None;
    }
    let index = usize::from(stack.register_slots)
        .saturating_add(usize::try_from(relative / slot_size).ok()?);
    Some(Expr::Parameter {
        name: format!("arg{index}"),
        ty: Type::from_width(width),
    })
}

fn type_call_arguments(arguments: Vec<Expr>, prototype: Option<&NativeCallPrototype>) -> Vec<Expr> {
    arguments
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let ty = prototype
                .and_then(|prototype| prototype.parameters.get(index))
                .filter(|ty| !matches!(ty, Type::Unknown | Type::Void));
            match ty {
                Some(ty) => Expr::Typed {
                    ty: ty.clone(),
                    value: Box::new(value),
                },
                None => value,
            }
        })
        .collect()
}

fn materialize_abi_call_arguments(
    architecture: Architecture,
    abi: &Abi,
    definitions: &BTreeMap<ValueKey, Expr>,
    prototype: Option<&NativeCallPrototype>,
) -> Vec<Expr> {
    let omit_untouched = prototype.is_none()
        && matches!(
            architecture,
            Architecture::Ppc32 | Architecture::GameCube | Architecture::Ppc64 | Architecture::Ps2
        );
    let arity = prototype.map(|prototype| prototype.parameters.len());
    let arguments = abi_argument_vnodes(architecture, abi)
        .into_iter()
        .enumerate()
        .filter(|(index, value)| {
            arity.is_none_or(|arity| *index < arity) && definition_available(*value, definitions)
        })
        .map(|(_, value)| simplify(eval(value, architecture, definitions)))
        .filter(|value| !omit_untouched || !matches!(value, Expr::Parameter { .. }))
        .collect();
    type_call_arguments(arguments, prototype)
}

fn materialize_indirect_abi_call_arguments(
    architecture: Architecture,
    abi: &Abi,
    definitions: &BTreeMap<ValueKey, Expr>,
    callee: Option<&Expr>,
) -> Vec<Expr> {
    let parameter_index = match callee {
        Some(Expr::Parameter { name, .. }) => name
            .strip_prefix("arg")
            .and_then(|index| index.parse::<usize>().ok()),
        Some(Expr::Typed { value, .. }) | Some(Expr::Cast { value, .. }) => {
            if let Expr::Parameter { name, .. } = value.as_ref() {
                name.strip_prefix("arg")
                    .and_then(|index| index.parse::<usize>().ok())
            } else {
                None
            }
        }
        _ => None,
    };
    if let Some(parameter_index) = parameter_index {
        return (0..parameter_index)
            .filter_map(|index| {
                abi.arguments
                    .integer
                    .at(index)
                    .and_then(|register| {
                        abi_register_vnode(architecture, register, abi.pointer_bits)
                    })
                    .map(|value| simplify(eval(value, architecture, definitions)))
            })
            .collect();
    }
    materialize_abi_call_arguments(architecture, abi, definitions, None)
}

fn seed_abi_parameters(
    definitions: &mut BTreeMap<ValueKey, Expr>,
    architecture: Architecture,
    abi: &Abi,
) {
    let groups = [
        (AbiRegisterClass::Integer, abi.arguments.integer),
        (AbiRegisterClass::Floating, abi.arguments.floating),
        (AbiRegisterClass::Vector, abi.arguments.vector),
    ];
    for (class, group) in groups {
        let Some(count) = group.count() else {
            continue;
        };
        for index in 0..count {
            let Some(vnode) = group
                .at(index)
                .and_then(|register| abi_register_vnode(architecture, register, abi.pointer_bits))
            else {
                continue;
            };
            let name = match (abi.argument_mode, class) {
                (ArgumentRegisterMode::Coupled, AbiRegisterClass::Floating)
                | (_, AbiRegisterClass::Integer) => format!("arg{index}"),
                (_, AbiRegisterClass::Floating) => format!("farg{index}"),
                (_, AbiRegisterClass::Vector) => format!("varg{index}"),
            };
            let ty = match class {
                AbiRegisterClass::Integer => Type::Unsigned(u32::from(abi.pointer_bits)),
                AbiRegisterClass::Floating => Type::Float(vnode.size.saturating_mul(8)),
                AbiRegisterClass::Vector => Type::Unsigned(vnode.size.saturating_mul(8)),
            };
            definitions.insert(ValueKey::from(vnode), Expr::Parameter { name, ty });
        }
    }
}

fn collect_expr_parameters(value: &Expr, used: &mut BTreeMap<String, Type>) {
    collect_expr_parameters_with_type(value, None, used);
}

fn collect_expr_parameters_with_type(
    value: &Expr,
    expected: Option<&Type>,
    used: &mut BTreeMap<String, Type>,
) {
    match value {
        Expr::Parameter { name, ty } => {
            let ty = expected.unwrap_or(ty);
            used.entry(name.clone())
                .and_modify(|previous| *previous = merge_types(previous, ty))
                .or_insert_with(|| ty.clone());
        }
        Expr::Typed { value, ty } => collect_expr_parameters_with_type(value, Some(ty), used),
        Expr::Binary { left, right, .. } => {
            collect_expr_parameters(left, used);
            collect_expr_parameters(right, used);
        }
        Expr::Not(value) | Expr::Neg(value) | Expr::BitNot(value) | Expr::Cast { value, .. } => {
            collect_expr_parameters(value, used)
        }
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => {
            collect_expr_parameters(condition, used);
            collect_expr_parameters(when_true, used);
            collect_expr_parameters(when_false, used);
        }
        Expr::Load { address, .. } => collect_expr_parameters(address, used),
        Expr::Field { base, .. } => collect_expr_parameters(base, used),
        Expr::Call { callee, args, .. } => {
            if let Some(callee) = callee {
                collect_expr_parameters(callee, used);
            }
            for argument in args {
                collect_expr_parameters(argument, used);
            }
        }
        Expr::Builtin { args, .. } => {
            for argument in args {
                collect_expr_parameters(argument, used);
            }
        }
        Expr::Constant { .. }
        | Expr::Register { .. }
        | Expr::Temporary { .. }
        | Expr::Global { .. } => {}
    }
}

fn collect_statement_parameters(statement: &NativeStatement, used: &mut BTreeMap<String, Type>) {
    match statement {
        NativeStatement::Store { address, value, .. } => {
            collect_expr_parameters(address, used);
            collect_expr_parameters(value, used);
        }
        NativeStatement::Copy {
            destination,
            source,
            ..
        }
        | NativeStatement::Assign {
            destination,
            source,
        } => {
            collect_expr_parameters(destination, used);
            collect_expr_parameters(source, used);
        }
        NativeStatement::DeclareLocal { .. } => {}
        NativeStatement::Call(value)
        | NativeStatement::IndirectGoto(value)
        | NativeStatement::Expression(value) => collect_expr_parameters(value, used),
        NativeStatement::Declare { value, .. } => collect_expr_parameters(value, used),
        NativeStatement::IfGoto { condition, .. } => collect_expr_parameters(condition, used),
        NativeStatement::IfReturn { condition, value } => {
            collect_expr_parameters(condition, used);
            if let Some(value) = value {
                collect_expr_parameters(value, used);
            }
        }
        NativeStatement::IfElse {
            condition,
            then_body,
            else_body,
        } => {
            collect_expr_parameters(condition, used);
            for nested in then_body.iter().chain(else_body) {
                collect_statement_parameters(nested, used);
            }
        }
        NativeStatement::While { condition, body }
        | NativeStatement::DoWhile { condition, body } => {
            collect_expr_parameters(condition, used);
            for nested in body {
                collect_statement_parameters(nested, used);
            }
        }
        NativeStatement::For {
            initializer,
            condition,
            step,
            body,
        } => {
            if let Some(initializer) = initializer {
                collect_statement_parameters(initializer, used);
            }
            if let Some(condition) = condition {
                collect_expr_parameters(condition, used);
            }
            if let Some(step) = step {
                collect_statement_parameters(step, used);
            }
            for nested in body {
                collect_statement_parameters(nested, used);
            }
        }
        NativeStatement::Switch {
            expression,
            cases,
            default,
        } => {
            collect_expr_parameters(expression, used);
            for nested in cases
                .iter()
                .flat_map(|(_, body)| body)
                .chain(default.iter())
            {
                collect_statement_parameters(nested, used);
            }
        }
        NativeStatement::Return(value) => {
            if let Some(value) = value {
                collect_expr_parameters(value, used);
            }
        }
        NativeStatement::Label(_)
        | NativeStatement::Goto(_)
        | NativeStatement::Break
        | NativeStatement::Continue => {}
    }
}

fn parameter_prefix(
    prefix: &str,
    used: &BTreeMap<String, Type>,
    default_type: Type,
) -> Vec<NativeParameter> {
    let highest = used
        .keys()
        .filter_map(|name| name.strip_prefix(prefix)?.parse::<usize>().ok())
        .max();
    highest
        .map(|highest| {
            (0..=highest)
                .map(|index| {
                    let name = format!("{prefix}{index}");
                    NativeParameter {
                        ty: used
                            .get(&name)
                            .cloned()
                            .unwrap_or_else(|| default_type.clone()),
                        name,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn recover_parameters(abi: Option<&Abi>, statements: &[NativeStatement]) -> Vec<NativeParameter> {
    let Some(abi) = abi else {
        return Vec::new();
    };
    let mut used = BTreeMap::new();
    for statement in statements {
        collect_statement_parameters(statement, &mut used);
    }
    let default_integer = Type::Unsigned(u32::from(abi.pointer_bits));
    let mut parameters = parameter_prefix("arg", &used, default_integer);
    if abi.argument_mode == ArgumentRegisterMode::Independent {
        parameters.extend(parameter_prefix("farg", &used, Type::Float(32)));
        parameters.extend(parameter_prefix(
            "varg",
            &used,
            Type::Unsigned(u32::from(abi.pointer_bits)),
        ));
    }
    parameters
}

#[derive(Default)]
pub struct NativeDecompiler;

/// Optional file-backed memory facts used by the native renderer.
///
/// The caller decides which addresses are safe to fold and which stores are
/// volatile. The decompiler does not infer mutability from an address alone.
pub struct NativeMemory<'a> {
    pub read: &'a dyn Fn(u64, u32) -> Option<u64>,
    pub is_volatile: &'a dyn Fn(u64, u32) -> bool,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NativeCallPrototype {
    pub return_type: Type,
    pub parameters: Vec<Type>,
}

#[derive(Default)]
struct PrologueState {
    saved_stack_slots: BTreeSet<(String, i64)>,
    restored_stack_slots: BTreeSet<(String, i64)>,
}

struct PendingDefinitionJoin {
    branch_target: u64,
    condition: Expr,
    base: BTreeMap<ValueKey, Expr>,
    fallthrough: Option<BTreeMap<ValueKey, Expr>>,
    join: Option<u64>,
}

fn merge_branch_definitions(
    condition: &Expr,
    base: &BTreeMap<ValueKey, Expr>,
    when_true: &BTreeMap<ValueKey, Expr>,
    when_false: &BTreeMap<ValueKey, Expr>,
) -> BTreeMap<ValueKey, Expr> {
    let keys = base
        .keys()
        .chain(when_true.keys())
        .chain(when_false.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    keys.into_iter()
        .filter_map(|key| {
            let true_value = when_true.get(&key).or_else(|| base.get(&key));
            let false_value = when_false.get(&key).or_else(|| base.get(&key));
            match (true_value, false_value) {
                (Some(left), Some(right)) if left == right => Some((key, left.clone())),
                (Some(when_true), Some(when_false)) => Some((
                    key,
                    simplify(Expr::Select {
                        condition: Box::new(condition.clone()),
                        when_true: Box::new(when_true.clone()),
                        when_false: Box::new(when_false.clone()),
                    }),
                )),
                (Some(value), None) | (None, Some(value)) => Some((key, value.clone())),
                (None, None) => None,
            }
        })
        .collect()
}

fn is_matched_abi_stack_save(
    architecture: Architecture,
    abi: &Abi,
    restored_slots: &BTreeSet<(String, i64)>,
    statement: &NativeStatement,
) -> bool {
    let NativeStatement::Store { address, value, .. } = statement else {
        return false;
    };
    prologue_stack_slot(architecture, abi, address).is_some_and(|slot| {
        restored_slots.contains(&slot)
            && expression_is_named_register(value, &abi_special_register_names(architecture, abi))
    })
}

impl NativeDecompiler {
    pub fn decompile(
        &mut self,
        architecture: Architecture,
        function: &NativeFunction,
    ) -> NativeDocument {
        self.decompile_with_memory_and_symbols(architecture, function, None, None)
    }

    pub fn decompile_with_memory(
        &mut self,
        architecture: Architecture,
        function: &NativeFunction,
        memory: Option<&NativeMemory<'_>>,
    ) -> NativeDocument {
        self.decompile_with_memory_and_symbols(architecture, function, memory, None)
    }

    /// Decompile with optional memory facts and a symbol resolver for absolute
    /// addresses. Named globals remain source-level identifiers instead of
    /// being rendered as synthetic `DAT_...` names.
    pub fn decompile_with_memory_and_symbols(
        &mut self,
        architecture: Architecture,
        function: &NativeFunction,
        memory: Option<&NativeMemory<'_>>,
        symbols: Option<&dyn Fn(u64) -> Option<String>>,
    ) -> NativeDocument {
        self.decompile_with_abi_memory_and_symbols(architecture, function, None, memory, symbols)
    }

    /// Decompile through a target-owned ABI. Entry register values become
    /// structured parameters; architecture-only callers retain the legacy
    /// register-shaped output.
    pub fn decompile_with_abi_memory_and_symbols(
        &mut self,
        architecture: Architecture,
        function: &NativeFunction,
        abi: Option<&Abi>,
        memory: Option<&NativeMemory<'_>>,
        symbols: Option<&dyn Fn(u64) -> Option<String>>,
    ) -> NativeDocument {
        self.decompile_with_call_prototypes(architecture, function, abi, memory, symbols, None)
    }

    /// Decompile with ABI facts plus prototypes recovered for direct callees.
    ///
    /// A known prototype makes untouched entry-register values observable at a
    /// call site. Without it, the caller alone cannot distinguish an argument
    /// from an unrelated live-in register.
    pub fn decompile_with_call_prototypes(
        &mut self,
        architecture: Architecture,
        function: &NativeFunction,
        abi: Option<&Abi>,
        memory: Option<&NativeMemory<'_>>,
        symbols: Option<&dyn Fn(u64) -> Option<String>>,
        call_prototypes: Option<&BTreeMap<u64, NativeCallPrototype>>,
    ) -> NativeDocument {
        let ssa = build_ssa(function);
        let mut solver = TypeSolver::default();
        for constraint in &ssa.constraints {
            solver.constrain(constraint.value, constraint.ty.clone());
        }
        let types = solver.solve();
        // A likely-branch reports a non-sequential fallthrough: the block it
        // skips to needs a label because the emitted `if` jumps there, even
        // though it is the next address.
        let labels: BTreeSet<u64> = function
            .instructions
            .iter()
            .flat_map(|(address, instruction)| {
                let sequential = address.wrapping_add(u64::from(instruction.pcode.len));
                match instruction.flow {
                    ventris_lifter::Flow::Jump(target) => vec![target],
                    ventris_lifter::Flow::Conditional {
                        target,
                        fallthrough,
                    } => {
                        if fallthrough == sequential && !instruction.skips_delay_slot() {
                            vec![target]
                        } else {
                            vec![target, fallthrough]
                        }
                    }
                    ventris_lifter::Flow::FallThrough(_)
                    | ventris_lifter::Flow::Return
                    | ventris_lifter::Flow::Call { .. } => Vec::new(),
                }
            })
            .collect();
        let mut definitions: BTreeMap<ValueKey, Expr> = BTreeMap::new();
        if let Some(abi) = abi {
            seed_abi_parameters(&mut definitions, architecture, abi);
        }
        let live_reads = LiveReads::of(function);
        let mut statements = Vec::new();
        let mut warnings = Vec::new();
        let mut prologue_state = PrologueState::default();
        let mut consumed_delay_slots = BTreeSet::new();
        let mut pending_definition_joins = Vec::<PendingDefinitionJoin>::new();
        let mut returned = false;
        let mut value_returned = false;
        let mut inferred_return_type = None;
        // A label reached from several blocks may see a different value in the
        // same register on each path. Intersecting the incoming states keeps
        // only the definitions every predecessor agrees on; anything else must
        // fall back to the register, because inlining one path's value silently
        // rewrites what the other paths compute.
        let mut predecessors: BTreeMap<u64, usize> = BTreeMap::new();
        for (_, target) in &function.edges {
            *predecessors.entry(*target).or_default() += 1;
        }
        // Each contribution records where the predecessor's block ended, so a
        // value that differs per path can be assigned there and merged into one
        // named variable at the label.
        let mut join_states: BTreeMap<u64, Vec<(usize, BTreeMap<ValueKey, Expr>)>> =
            BTreeMap::new();
        // Registers whose value cannot depend on which path reached a label:
        // the frame registers, which every path must agree on, and any register
        // the function never writes.
        let mut stable_registers: BTreeSet<String> =
            live_reads.unwritten_register_names(architecture);
        if let Some(abi) = abi {
            for name in [Some(abi.stack_pointer), abi.frame_pointer]
                .into_iter()
                .flatten()
            {
                stable_registers.insert(name.strip_prefix('$').unwrap_or(name).to_owned());
            }
        }
        for (address, instruction) in &function.instructions {
            if consumed_delay_slots.contains(address) {
                continue;
            }
            if labels.contains(address) {
                let mut handled_by_branch_join = false;
                if let Some(index) = pending_definition_joins
                    .iter()
                    .rposition(|pending| pending.join == Some(*address))
                {
                    let pending = pending_definition_joins.remove(index);
                    if let Some(fallthrough) = pending.fallthrough {
                        definitions = merge_branch_definitions(
                            &pending.condition,
                            &pending.base,
                            &definitions,
                            &fallthrough,
                        );
                        handled_by_branch_join = true;
                    }
                }
                if !handled_by_branch_join && predecessors.get(address).copied().unwrap_or(0) > 1 {
                    definitions = merge_join_contributions(
                        architecture,
                        predecessors[address],
                        join_states.get(address).map(Vec::as_slice).unwrap_or(&[]),
                        &definitions,
                        &stable_registers,
                    );
                }
                if let Some(pending) = pending_definition_joins.iter_mut().rfind(|pending| {
                    pending.branch_target == *address && pending.fallthrough.is_none()
                }) {
                    if let Some(NativeStatement::Goto(join)) = statements.last() {
                        pending.join = Some(*join);
                        pending.fallthrough = Some(definitions.clone());
                        definitions = pending.base.clone();
                    }
                }
                statements.push(NativeStatement::Label(*address));
            }
            if matches!(
                architecture,
                Architecture::Mips32
                    | Architecture::Mips32Be
                    | Architecture::Ps1
                    | Architecture::Ps2
                    | Architecture::N64
                    | Architecture::Sh2
                    | Architecture::Sh4
            ) && !matches!(instruction.flow, ventris_lifter::Flow::FallThrough(_))
            {
                if let Some(delay_address) = address.checked_add(u64::from(instruction.pcode.len)) {
                    if !labels.contains(&delay_address) {
                        if let Some(delay) = function.instructions.get(&delay_address) {
                            if matches!(delay.flow, ventris_lifter::Flow::FallThrough(_)) {
                                if instruction.embedded_delay_slot_bytes == 0 {
                                    for operation in &delay.pcode.ops {
                                        self.translate_operation(
                                            architecture,
                                            memory,
                                            symbols,
                                            abi,
                                            call_prototypes,
                                            &mut prologue_state,
                                            &live_reads,
                                            delay_address,
                                            operation,
                                            &mut definitions,
                                            &mut statements,
                                            &mut warnings,
                                        );
                                    }
                                }
                                consumed_delay_slots.insert(delay_address);
                            }
                        }
                    }
                }
            }
            for operation in &instruction.pcode.ops {
                if Self::synthetic_call_frame_store(architecture, &instruction.flow, operation) {
                    continue;
                }
                self.translate_operation(
                    architecture,
                    memory,
                    symbols,
                    abi,
                    call_prototypes,
                    &mut prologue_state,
                    &live_reads,
                    *address,
                    operation,
                    &mut definitions,
                    &mut statements,
                    &mut warnings,
                );
                if operation.opcode == op::CBRANCH {
                    if let Some(NativeStatement::IfGoto { condition, target }) = statements.last() {
                        pending_definition_joins.push(PendingDefinitionJoin {
                            branch_target: *target,
                            condition: condition.clone(),
                            base: definitions.clone(),
                            fallthrough: None,
                            join: None,
                        });
                    }
                }
                if operation.opcode == op::RETURN {
                    let mut value = return_value(
                        architecture,
                        abi,
                        &definitions,
                        operation.inputs.first().copied(),
                        &live_reads,
                    );
                    if let Some(returned_value) = value.as_ref() {
                        let repeats_store = statements
                            .iter()
                            .rev()
                            .find_map(|statement| match statement {
                                NativeStatement::Store { value, .. } => Some(value),
                                _ => None,
                            })
                            .is_some_and(|stored| is_same_value(stored, returned_value));
                        if repeats_store {
                            value = None;
                        } else {
                            let ty = expression_type(returned_value, architecture);
                            inferred_return_type = Some(match inferred_return_type.take() {
                                Some(previous) => merge_types(&previous, &ty),
                                None => ty,
                            });
                        }
                    }
                    value_returned |= value.is_some();
                    statements.push(NativeStatement::Return(value));
                    returned = true;
                }
            }
            for (source, target) in &function.edges {
                if source != address || predecessors.get(target).copied().unwrap_or(0) <= 1 {
                    continue;
                }
                join_states
                    .entry(*target)
                    .or_default()
                    .push((statements.len(), definitions.clone()));
            }
        }
        if let Some(abi) = abi {
            statements.retain(|statement| {
                !is_matched_abi_stack_save(
                    architecture,
                    abi,
                    &prologue_state.restored_stack_slots,
                    statement,
                )
            });
        }
        let mut return_type = default_return_type(architecture);
        if returned && value_returned {
            if let Some(inferred) = inferred_return_type {
                return_type = inferred;
            }
        } else if returned {
            return_type = Type::Void;
        }
        if !returned {
            let width = match &return_type {
                Type::Unsigned(width) => *width / 8,
                _ => 8,
            };
            statements.push(NativeStatement::Return(Some(Expr::constant(0, width))));
        }
        drop_unread_memory_snapshots(&mut statements);
        statements = structure::structure_graph(statements);
        statements = actions::run_action_database(statements);
        promote_frame_slots(&mut statements, &stable_registers);
        let parameters = recover_parameters(abi, &statements);
        NativeDocument {
            name: format!("sub_{:x}", function.entry),
            return_type,
            parameters,
            statements,
            ssa,
            types,
            warnings,
            prototype: None,
            scope: None,
        }
    }

    ///
    /// This is the ported pipeline: build the graph, refine overlapping
    /// locations, guard indirect effects, construct SSA with real `MULTIEQUAL`
    /// ops, then resolve and emit. Structuring and the action database are
    /// shared with the address-ordered path so the comparison isolates value
    /// resolution.
    /// Decompiles through the SSA graph rather than the address-ordered pass.
    ///
    /// This is the ported pipeline: build the graph, guard indirect effects,
    /// construct SSA with real `MULTIEQUAL` ops, simplify to a fixed point,
    /// then resolve and emit.
    pub fn decompile_via_graph(
        &mut self,
        architecture: Architecture,
        function: &NativeFunction,
        abi: Option<&Abi>,
        call_prototypes: Option<&BTreeMap<u64, NativeCallPrototype>>,
        memory: Option<&NativeMemory>,
    ) -> NativeDocument {
        // The address-ordered SSA and its type solver are not built here. This
        // path recovers types with `graph::types::infer_types`, the ported
        // inference, and that is what emission reads; running the linear pass as
        // well only filled two document fields that nothing on this path reads.
        // Leaving them empty is the honest statement that the types in this
        // document came from somewhere else.
        let mut data = graph::Funcdata::from_lifted(function);
        // Only registers are guarded here. Memory locations are named by their
        // loads and stores, and guarding them without alias analysis invents a
        // merge for every address the function mentions.
        let mut locations = graph::guard::heritaged_locations(&data);
        locations.retain(|location| location.space == REGISTER_SPACE);
        // A convention's parameter locations get a trial whether or not this
        // function mentions them. A forwarding function passes arguments it
        // never touches, so waiting for one to appear as a varnode loses them.
        if let Some(abi) = abi {
            for vnode in abi_argument_vnodes(architecture, abi) {
                locations.insert(graph::guard::Location {
                    space: vnode.space,
                    offset: vnode.offset,
                    size: vnode.size,
                });
            }
        }
        let mut effects = graph::guard::CallEffects::default();
        if let Some(abi) = abi {
            for name in [Some(abi.stack_pointer), abi.frame_pointer]
                .into_iter()
                .flatten()
            {
                if let Some(vnode) = abi_register_vnode(architecture, name, abi.pointer_bits) {
                    effects.preserved.insert((vnode.space, vnode.offset));
                }
            }
        }
        // A hardwired-zero register reads as the constant zero. The lifter
        // emits it as an ordinary register, so without this `addiu v1,zero,1`
        // stays an addition of an undefined register and the constant is never
        // folded: every store of it rendered as the bare register name.
        replace_hardwired_zero_reads(&mut data, architecture);
        // A call reads only the storage its convention passes arguments in.
        // Guarding every heritaged register instead made an argument out of
        // whatever the call instruction itself happened to read - PowerPC's `bl`
        // touches `r2`, so a forwarding function called `f(r2)` and lost its own
        // parameter. Ghidra's trials come from the prototype model for the same
        // reason. With no convention there is no model, so every location stands.
        let call_locations = match abi {
            Some(abi) => abi_argument_vnodes(architecture, abi)
                .into_iter()
                .map(|vnode| graph::guard::Location {
                    space: vnode.space,
                    offset: vnode.offset,
                    size: vnode.size,
                })
                .filter(|location| locations.contains(location))
                .collect(),
            None => locations.clone(),
        };
        graph::guard::guard_calls(&mut data, &call_locations, &effects);
        // A return reads the convention's result storage. Without this the
        // returned value has no reader, dead code removes the computation, and
        // the function reports `void`. With no convention the architecture's
        // own result register stands in, which is what the address-ordered path
        // has always done: `--arch ps1` with no target still returns a value.
        if let Some(abi) = abi {
            let result: Vec<graph::guard::Location> = abi_primary_return_vnodes(architecture, abi)
                .into_iter()
                .map(|vnode| graph::guard::Location {
                    space: vnode.space,
                    offset: vnode.offset,
                    size: vnode.size,
                })
                .collect();
            graph::guard::guard_returns(&mut data, &result);
        }
        if abi.is_none() {
            let vnode = return_vnode(architecture);
            graph::guard::guard_returns(
                &mut data,
                &[graph::guard::Location {
                    space: vnode.space,
                    offset: vnode.offset,
                    size: vnode.size,
                }],
            );
        }
        graph::heritage::heritage_with_endianness(&mut data, is_little_endian(architecture));
        // Arguments must be recovered while the guards that name each
        // location's value at the call still exist: simplification collapses
        // them once nothing distinguishes their effect.
        if let Some(abi) = abi {
            let argument_locations: Vec<graph::guard::Location> =
                abi_argument_vnodes(architecture, abi)
                    .into_iter()
                    .map(|vnode| graph::guard::Location {
                        space: vnode.space,
                        offset: vnode.offset,
                        size: vnode.size,
                    })
                    .collect();
            let arity_of = |target: u64| {
                call_prototypes
                    .and_then(|prototypes| prototypes.get(&target))
                    .map(|prototype| prototype.parameters.len())
            };
            graph::proto::recover_call_arguments(&mut data, &argument_locations, &arity_of);
        }
        // Simplification, unreachable-block removal, and dead code each expose
        // work for the others: folding a condition orphans a block, removing a
        // block leaves a merge with one operand, and collapsing that merge
        // leaves a copy nothing reads. Ghidra runs them in one fixed point.
        // Whether the function returns a value is `ActionReturnRecovery`'s
        // decision, and whether a callee's result is used is
        // `ActionActiveReturn`'s. Both read the graph rather than the emitted
        // statements, so they run before simplification consumes the guards.
        graph::action::Action::apply(&graph::protoaction::ActionReturnRecovery, &mut data);
        graph::action::Action::apply(&graph::protoaction::ActionActiveReturn, &mut data);
        // A comma-separated `VENTRIS_SKIP_PASS` disables named passes, so a
        // defect can be attributed to one pass without rebuilding per guess.
        let skipped_passes: Vec<String> = std::env::var("VENTRIS_SKIP_PASS")
            .map(|value| value.split(',').map(str::trim).map(str::to_owned).collect())
            .unwrap_or_default();
        // Newly ported actions, switchable by name so one can be attributed
        // without a rebuild.
        for action in graph::blockaction::all()
            .into_iter()
            .chain(graph::coreaction::all())
            .chain(graph::storageaction::all())
        {
            if skipped_passes.iter().any(|skip| skip == action.name()) {
                continue;
            }
        }
        let pipeline = graph::action::default_pipeline();
        let control_flow: [&dyn graph::action::Action; 12] = [
            &graph::branchaction::ActionDeterminedBranch,
            &graph::branchaction::ActionRedundBranch,
            &graph::branchaction::ActionDoNothing,
            &graph::branchaction::ActionUnreachable,
            &graph::branchaction::ActionCse,
            &graph::branchaction::ActionMultiCse,
            // Resolving a loaded function pointer to a constant turns an
            // indirect call into a named callee, which then gets a prototype.
            &graph::condprop::ActionDeindirect,
            &graph::branchaction::ActionCbranchFlip,
            // Ghidra runs `ActionNodeJoin` here, after the unreachable and
            // determined-branch passes and before the conditional ones. Merging
            // two blocks that test the same value removes an edge, which is what
            // lets a guarded bottom-tested loop structure as one `while`.
            &graph::nodejoin::ActionNodeJoin,
            &graph::condprop::ActionConditionalConst,
            &graph::condprop::ActionConditionalExe,
            &graph::stackframe::ActionStackPtrFlow,
        ];
        // Which end a piece of a value comes from decides what every split of
        // an aggregate means, so the graph is told before any rule runs.
        data.big_endian = architecture_is_big_endian(architecture);
        // `ActionSpacebase`, and it must happen before anything reads a type:
        // types are re-derived at a round boundary, not per edit, so naming the
        // frame base after the first round leaves that round's view of the stack
        // behind.
        if let Some(abi) = abi
            && let Some(vnode) =
                abi_register_vnode(architecture, abi.stack_pointer, abi.pointer_bits)
        {
            data.spacebase = Some(graph::guard::Location {
                space: vnode.space,
                offset: vnode.offset,
                size: vnode.size,
            });
        }
        for _ in 0..GRAPH_PIPELINE_ROUNDS {
            // `ActionInferTypes` is a pass in Ghidra's pool, not a query the
            // rules make: types are re-derived once per round, and the rules in
            // that round read what it produced. Re-deriving after every rewrite
            // instead cost fifty seconds on one corpus function.
            data.invalidate_types();
            let mut changed = graph::action::Action::apply(pipeline.as_ref(), &mut data);
            for pass in control_flow {
                if skipped_passes.iter().any(|name| name == pass.name()) {
                    continue;
                }
                changed += pass.apply(&mut data);
            }
            changed += graph::deadcode::eliminate_dead_code(&mut data);
            if let Some(abi) = abi
                && let Some(vnode) =
                    abi_register_vnode(architecture, abi.stack_pointer, abi.pointer_bits)
            {
                changed += graph::deadcode::eliminate_dead_frame_stores(
                    &mut data,
                    graph::guard::Location {
                        space: vnode.space,
                        offset: vnode.offset,
                        size: vnode.size,
                    },
                );
            }
            if changed == 0 {
                break;
            }
        }
        // The last round's rewrites are not in the types the round started with,
        // and emission reads types to spell a field access. Ghidra recovers types
        // once more before it prints for the same reason.
        data.invalidate_types();
        // `ActionDominantCopy` belongs to Ghidra's merge phase, which runs after
        // simplification. Running it before the rounds meant computing the whole
        // variable merge over the largest version of the graph — 11,500 varnodes
        // against the 10,000 that survive dead-code elimination — to find five
        // groups of COPYs, at ten and a half seconds for six rewrites.
        for action in graph::dominantcopy::all() {
            if skipped_passes.iter().any(|skip| skip == action.name()) {
                continue;
            }
            graph::action::Action::apply(action.as_ref(), &mut data);
        }

        let naming = |space: u32, offset: u64, _size: u32| -> Option<String> {
            (space == REGISTER_SPACE).then(|| register_name(architecture, offset))
        };
        // The statement-level action database exists to repair the
        // address-ordered emitter's output. Its rules assume that shape, and
        // running them over graph-emitted statements loses conditionals. The
        // graph's own rules already ran, on the graph.
        // A switch's case labels live in the image, not the graph, so the
        // structurer can only recover a multi-way construct when the table can
        // be read. Without memory the branch keeps its edges and each becomes a
        // `goto`, exactly as before: inventing labels would print alternatives
        // as though they were a sequence.
        let tables = memory
            .map(|memory| {
                graph::jumptable::recover_jump_tables(&data, &|address, width| {
                    (memory.read)(address, width)
                })
            })
            .unwrap_or_default();
        // An indirect jump whose table could not be read is a call, not a
        // branch to nowhere. Ghidra converts it before anything structures the
        // graph, so the constructs are built over the call.
        graph::jumptable::truncate_indirect_jumps(&mut data, &tables);
        let recovered = graph::types::infer_types(&data, &BTreeMap::new());
        // The rich table keeps the structures and arrays that `Type` cannot
        // represent, which is what lets a field read render as `p->field_40`
        // instead of a cast through a computed address.
        let factory = graph::typefactory::TypeFactory::new(
            abi.map(|abi| u32::from(abi.pointer_bits)).unwrap_or(32),
        );
        let rich = if std::env::var("VENTRIS_NO_RICH").is_ok() {
            Default::default()
        } else {
            graph::typefactory::infer(&data, &factory, &BTreeMap::new())
        };
        // Argument locations name themselves as parameters, which is how the
        // recovered prototype gets its arguments.
        let mut parameter_names: BTreeMap<(u32, u64), (String, Type)> = BTreeMap::new();
        if let Some(abi) = abi {
            // Names follow the convention the prototype recovery reads back:
            // integer arguments are `arg`, floating `farg`, vector `varg`, each
            // numbered within its class.
            let classes = [
                (
                    AbiRegisterClass::Integer,
                    "arg",
                    Type::Unsigned(u32::from(abi.pointer_bits)),
                ),
                (AbiRegisterClass::Floating, "farg", Type::Float(32)),
                (
                    AbiRegisterClass::Vector,
                    "varg",
                    Type::Unsigned(u32::from(abi.pointer_bits)),
                ),
            ];
            let independent = abi.argument_mode == ArgumentRegisterMode::Independent;
            for (class, prefix, declared) in classes {
                if prefix != "arg" && !independent {
                    continue;
                }
                let group = abi.arguments.group(class);
                let vnodes = abi_register_group_vnodes(architecture, abi, group);
                for (index, vnode) in vnodes.into_iter().enumerate() {
                    parameter_names
                        .entry((vnode.space, vnode.offset))
                        .or_insert_with(|| (format!("{prefix}{index}"), declared.clone()));
                }
            }
        }
        // Structuring happens on the graph, where the edge conditions each
        // construct requires are visible. The statement-level structurer
        // inferred them back from labels.
        let stack_slot = abi.and_then(|abi| {
            abi_register_vnode(architecture, abi.stack_pointer, abi.pointer_bits).map(|vnode| {
                graph::guard::Location {
                    space: vnode.space,
                    offset: vnode.offset,
                    size: vnode.size,
                }
            })
        });
        // A recovered prototype is what the prototype passes read. Attaching it
        // where the convention is already in hand keeps the passes working on
        // real storage instead of a permanent `None`.
        if let Some(abi) = abi {
            let mut proto = graph::funcproto::FuncProto::new(*abi);
            // Ghidra's `ProtoModel` carries the convention's storage lists, and
            // `FuncProto::deriveInputMap` filters trials against them. Without
            // them every derive call is a no-op, so the prototype passes could
            // not decide anything. The lists come from the same ABI helpers the
            // address-ordered path already uses.
            let to_location = |vnode: &Varnode| graph::guard::Location {
                space: vnode.space,
                offset: vnode.offset,
                size: vnode.size,
            };
            proto.set_model_storage(
                abi_argument_vnodes(architecture, abi)
                    .iter()
                    .map(to_location)
                    .collect(),
                abi_primary_return_vnodes(architecture, abi)
                    .iter()
                    .map(to_location)
                    .collect(),
            );
            // `ActionActiveParam` registers a trial per model location and
            // decides it; `ActionInputPrototype` promotes the survivors into
            // parameters. Without the promotion the prototype held no
            // parameters whatever the prototype passes decided.
            let mut inputs = graph::callproto::ParamActive::new();
            for location in proto.model_input_storage() {
                inputs.register(*location);
            }
            // `ActionInputPrototype` sees an entry input as active when it has
            // a descendant, but only after `ActionActiveParam` has removed
            // call-only pass-through operands from each call. The graph action
            // deliberately refuses to shorten an existing call, so those
            // operands can still be visible here through transparent
            // `INDIRECT`/`COPY`/`SUBPIECE`/`PIECE`/`MULTIEQUAL` nodes.
            // In particular, an `INDIRECT` guard whose output feeds a later
            // CALL is still this pass-through chain; treating the guard as a
            // terminal use would incorrectly retain that call-only input.
            //
            // Reconstruct that distinction by treating a chain whose only
            // terminal use is a CALL argument as inactive. Do not call
            // `ancestor_realistic` directly: its `ancestor_verdict` maps an
            // undefined input (`def = None`) to `UntouchedInput`, and the
            // public boolean collapses that to false. Ghidra records the same
            // case as inactive (`fspec.cc:5645-5646`), not definitely absent;
            // rejecting every undefined input loses the PS1 `a2` parameter.
            for trial in inputs.trials_mut() {
                let held = (0..data.varnode_count())
                    .map(|index| graph::VarnodeId(index as u32))
                    .find(|value| {
                        let varnode = data.varnode(*value);
                        varnode.flags.input
                            && varnode.space == trial.location.space
                            && varnode.offset == trial.location.offset
                            && varnode.size == trial.location.size
                    });
                match held {
                    Some(value) if !data.varnode(value).descendants.is_empty() => {
                        trial.value = Some(value);
                        if !data.varnode(value).descendants.is_empty() {
                            trial.mark_active();
                        } else {
                            trial.mark_inactive();
                        }
                    }
                    _ => trial.mark_no_use(),
                }
            }
            // Ghidra's `ParamListStandard::buildTrialMap` keeps an unreferenced
            // trial that sits *before* a referenced one: the parameter exists,
            // the function just ignores it. Only the trailing unused run is
            // dropped. Without this a hole truncates the list, because
            // `ParamActive::used` is a leading run of active trials.
            let last_used = inputs
                .trials()
                .iter()
                .rposition(|trial| trial.is_active())
                .map(|index| index + 1)
                .unwrap_or(0);
            for trial in inputs.trials_mut().iter_mut().take(last_used) {
                if !trial.is_active() {
                    trial.mark_active();
                }
            }
            graph::parampromote::promote_input_trials(&data, &mut proto, &inputs);
            // Ghidra names a parameter through the symbol its scope holds, and
            // `emitPrototypeInputs` prints the type alone when there is no
            // symbol. Until scope population lands, name them the way the body
            // already refers to them - a signature whose names disagree with the
            // body's is not valid C.
            for index in 0..proto.params().len() {
                if proto
                    .get_param(index)
                    .is_some_and(|parameter| parameter.get_name().is_empty())
                {
                    let (location, ty) = {
                        let parameter = proto.get_param(index).expect("checked above");
                        (parameter.get_address(), parameter.get_type().clone())
                    };
                    proto.set_param_parts(index, format!("arg{index}"), location, ty);
                }
            }
            let mut returns = graph::callproto::ParamActive::new();
            for location in proto.model_output_storage() {
                returns.register(*location);
            }
            let returned = data.live_ops().find_map(|(_, operation)| {
                (operation.opcode == ventris_pcode::op::RETURN)
                    .then(|| operation.inputs.get(1).copied())
                    .flatten()
            });
            for trial in returns.trials_mut() {
                match returned {
                    Some(value)
                        if data.varnode(value).space == trial.location.space
                            && data.varnode(value).offset == trial.location.offset =>
                    {
                        trial.value = Some(value);
                        trial.mark_active();
                    }
                    _ => trial.mark_no_use(),
                }
            }
            graph::parampromote::promote_output_trials(&data, &mut proto, &returns);
            data.set_func_proto(proto);
            // `ScopeLocal::restructure` gathers the stack's varnodes into ranges
            // and enters a symbol for each. It runs after the prototype so the
            // parameter entries exist, and before anything that reads the scope.
            let scope = graph::scopepopulate::build_local_scope(&data, ventris_lifter::RAM_SPACE);
            data.set_scope_local(scope);
        }
        let statements = graph::emit::emit_structured(
            &tables,
            &data,
            &naming,
            &recovered,
            &parameter_names,
            stack_slot,
            architecture,
            &rich,
            &factory,
        );
        // A matched save and restore of a callee-saved register says nothing
        // about what the function computes, and naming provably private stack
        // slots turns spills into locals. Both stages read statements, so they
        // are shared with the address-ordered path rather than reimplemented.
        let mut statements = statements;
        let mut stable_registers = LiveReads::of(function).unwritten_register_names(architecture);
        if let Some(abi) = abi {
            for name in [Some(abi.stack_pointer), abi.frame_pointer]
                .into_iter()
                .flatten()
            {
                stable_registers.insert(name.strip_prefix('$').unwrap_or(name).to_owned());
            }
            let restored = graph_restored_slots(architecture, abi, &statements);
            statements.retain(|statement| {
                !is_matched_abi_stack_save(architecture, abi, &restored, statement)
            });
        }
        promote_frame_slots(&mut statements, &stable_registers);
        // Ghidra's signature comes from the prototype, so the document's
        // parameter list does too. `SourceReconstruction::from_signature` also
        // reads this list, so deriving it from statements here was enough to
        // keep the whole prototype layer out of the rendered output.
        let recovered_parameters = data.func_proto().map(|proto| {
            proto
                .params()
                .iter()
                .enumerate()
                .map(|(index, parameter)| NativeParameter {
                    name: if parameter.get_name().is_empty() {
                        format!("arg{index}")
                    } else {
                        parameter.get_name().to_owned()
                    },
                    ty: parameter.get_type().clone(),
                })
                .collect::<Vec<_>>()
        });
        let parameters = match recovered_parameters {
            Some(recovered) if !recovered.is_empty() => recovered,
            _ => recover_parameters(abi, &statements),
        };
        let return_type = graph_return_type(&data, &recovered, architecture);
        NativeDocument {
            name: format!("sub_{:x}", function.entry),
            return_type,
            parameters,
            statements,
            ssa: SsaFunction::default(),
            types: Vec::new(),
            warnings: data.warnings().to_vec(),
            prototype: data.func_proto().cloned(),
            scope: data.scope_local().cloned(),
        }
    }

    fn synthetic_call_frame_store(
        architecture: Architecture,
        flow: &ventris_lifter::Flow,
        operation: &PcodeOp,
    ) -> bool {
        let ventris_lifter::Flow::Call { fallthrough, .. } = flow else {
            return false;
        };
        matches!(architecture, Architecture::X86_64 | Architecture::X86_32)
            && operation.opcode == op::STORE
            && operation.inputs.get(2).and_then(constant_value) == Some(*fallthrough)
    }

    fn translate_operation(
        &self,
        architecture: Architecture,
        memory: Option<&NativeMemory<'_>>,
        symbols: Option<&dyn Fn(u64) -> Option<String>>,
        abi: Option<&Abi>,
        call_prototypes: Option<&BTreeMap<u64, NativeCallPrototype>>,
        prologue_state: &mut PrologueState,
        live_reads: &LiveReads,
        address: u64,
        operation: &PcodeOp,
        definitions: &mut BTreeMap<ValueKey, Expr>,
        statements: &mut Vec<NativeStatement>,
        warnings: &mut Vec<String>,
    ) {
        let input = |index: usize| {
            operation
                .inputs
                .get(index)
                .copied()
                .map(|v| eval_input(v, architecture, definitions, memory))
        };
        match operation.opcode {
            op::COPY => {
                if let (Some(output), Some(value)) = (operation.output, input(0)) {
                    if output.space == ventris_lifter::RAM_SPACE {
                        let width = output.size;
                        let raw_address = Expr::constant(output.offset, width);
                        let volatile =
                            memory.is_some_and(|memory| (memory.is_volatile)(output.offset, width));
                        let address =
                            named_global(symbols, &raw_address, width).unwrap_or(raw_address);
                        statements.push(NativeStatement::Store {
                            address,
                            value: simplify(value),
                            width,
                            volatile,
                        });
                    } else {
                        definitions.insert(ValueKey::from(output), value);
                    }
                }
            }
            op::CMOV => {
                if let (Some(output), Some(condition), Some(when_true), Some(when_false)) =
                    (operation.output, input(0), input(1), input(2))
                {
                    definitions.insert(
                        ValueKey::from(output),
                        Expr::Select {
                            condition: Box::new(condition),
                            when_true: Box::new(when_true),
                            when_false: Box::new(when_false),
                        },
                    );
                }
            }
            op::INT_ADD
            | op::INT_SUB
            | op::INT_MULT
            | op::INT_DIV
            | op::INT_SDIV
            | op::INT_REM
            | op::INT_SREM
            | op::INT_AND
            | op::INT_OR
            | op::INT_XOR
            | op::INT_EQUAL
            | op::INT_NOTEQUAL
            | op::INT_LESS
            | op::INT_LESSEQUAL
            | op::INT_SLESS
            | op::INT_SLESSEQUAL
            | op::INT_LEFT
            | op::INT_RIGHT
            | op::INT_SRIGHT
            | op::BOOL_XOR
            | op::BOOL_AND
            | op::BOOL_OR => {
                if let (Some(output), Some(left), Some(right)) =
                    (operation.output, input(0), input(1))
                {
                    let binary = match operation.opcode {
                        op::INT_ADD => BinaryOp::Add,
                        op::INT_SUB => BinaryOp::Sub,
                        op::INT_MULT => BinaryOp::Mul,
                        op::INT_DIV => BinaryOp::Div,
                        op::INT_SDIV => BinaryOp::SignedDiv,
                        op::INT_REM => BinaryOp::Rem,
                        op::INT_SREM => BinaryOp::SignedRem,
                        op::INT_AND => BinaryOp::And,
                        op::INT_OR => BinaryOp::Or,
                        op::INT_XOR => BinaryOp::Xor,
                        op::INT_EQUAL => BinaryOp::Equal,
                        op::INT_NOTEQUAL => BinaryOp::NotEqual,
                        op::INT_LESS => BinaryOp::Less,
                        op::INT_LESSEQUAL => BinaryOp::LessEqual,
                        op::INT_SLESS => BinaryOp::SignedLess,
                        op::INT_SLESSEQUAL => BinaryOp::SignedLessEqual,
                        op::INT_LEFT => BinaryOp::Left,
                        op::INT_RIGHT => BinaryOp::Right,
                        op::INT_SRIGHT => BinaryOp::SignedRight,
                        op::BOOL_XOR => BinaryOp::Xor,
                        op::BOOL_AND => BinaryOp::LogicalAnd,
                        op::BOOL_OR => BinaryOp::LogicalOr,
                        _ => unreachable!(),
                    };
                    let signed = |value: Expr| Expr::Cast {
                        ty: Type::Signed(operation.inputs[0].size.saturating_mul(8)),
                        value: Box::new(value),
                    };
                    let (left, right) = match operation.opcode {
                        op::INT_SDIV | op::INT_SREM | op::INT_SLESS | op::INT_SLESSEQUAL => {
                            (signed(left), signed(right))
                        }
                        op::INT_SRIGHT => (signed(left), right),
                        _ => (left, right),
                    };
                    let value = simplify(BinaryOp::build(binary, left, right));
                    definitions.insert(ValueKey::from(output), value);
                }
            }

            op::FLOAT_EQUAL | op::FLOAT_NOTEQUAL | op::FLOAT_LESS | op::FLOAT_LESSEQUAL => {
                if let (Some(output), Some(left), Some(right)) =
                    (operation.output, input(0), input(1))
                {
                    let binary = match operation.opcode {
                        op::FLOAT_EQUAL => BinaryOp::Equal,
                        op::FLOAT_NOTEQUAL => BinaryOp::NotEqual,
                        op::FLOAT_LESS => BinaryOp::Less,
                        op::FLOAT_LESSEQUAL => BinaryOp::LessEqual,
                        _ => unreachable!(),
                    };
                    definitions
                        .insert(ValueKey::from(output), BinaryOp::build(binary, left, right));
                }
            }
            op::FLOAT_ADD | op::FLOAT_SUB | op::FLOAT_MULT | op::FLOAT_DIV => {
                if let (Some(output), Some(left), Some(right)) =
                    (operation.output, input(0), input(1))
                {
                    let binary = match operation.opcode {
                        op::FLOAT_ADD => BinaryOp::Add,
                        op::FLOAT_SUB => BinaryOp::Sub,
                        op::FLOAT_MULT => BinaryOp::Mul,
                        op::FLOAT_DIV => BinaryOp::Div,
                        _ => unreachable!(),
                    };
                    definitions.insert(
                        ValueKey::from(output),
                        Expr::Typed {
                            ty: Type::Float(output.size.saturating_mul(8)),
                            value: Box::new(BinaryOp::build(binary, left, right)),
                        },
                    );
                }
            }
            op::FLOAT_NEG => {
                if let (Some(output), Some(value)) = (operation.output, input(0)) {
                    definitions.insert(
                        ValueKey::from(output),
                        Expr::Typed {
                            ty: Type::Float(output.size.saturating_mul(8)),
                            value: Box::new(Expr::Neg(Box::new(value))),
                        },
                    );
                }
            }
            op::FLOAT_ABS | op::FLOAT_SQRT | op::FLOAT_CEIL | op::FLOAT_FLOOR | op::FLOAT_ROUND => {
                if let (Some(output), Some(value)) = (operation.output, input(0)) {
                    let is_float = output.size <= 4;
                    let name = match (operation.opcode, is_float) {
                        (op::FLOAT_ABS, true) => "__builtin_fabsf",
                        (op::FLOAT_ABS, false) => "__builtin_fabs",
                        (op::FLOAT_SQRT, true) => "__builtin_sqrtf",
                        (op::FLOAT_SQRT, false) => "__builtin_sqrt",
                        (op::FLOAT_CEIL, true) => "__builtin_ceilf",
                        (op::FLOAT_CEIL, false) => "__builtin_ceil",
                        (op::FLOAT_FLOOR, true) => "__builtin_floorf",
                        (op::FLOAT_FLOOR, false) => "__builtin_floor",
                        (op::FLOAT_ROUND, true) => "__builtin_roundf",
                        (op::FLOAT_ROUND, false) => "__builtin_round",
                        _ => unreachable!(),
                    };
                    definitions.insert(
                        ValueKey::from(output),
                        Expr::Typed {
                            ty: Type::Float(output.size.saturating_mul(8)),
                            value: Box::new(Expr::Builtin {
                                name,
                                args: vec![value],
                            }),
                        },
                    );
                }
            }
            op::FLOAT_NAN => {
                if let (Some(output), Some(value)) = (operation.output, input(0)) {
                    definitions.insert(
                        ValueKey::from(output),
                        Expr::Typed {
                            ty: Type::Bool,
                            value: Box::new(Expr::Builtin {
                                name: "__builtin_isnan",
                                args: vec![value],
                            }),
                        },
                    );
                }
            }
            op::FLOAT_INT2FLOAT | op::FLOAT_FLOAT2FLOAT | op::FLOAT_TRUNC => {
                if let (Some(output), Some(value)) = (operation.output, input(0)) {
                    let value = if operation.opcode == op::FLOAT_INT2FLOAT {
                        let input_width = operation.inputs[0].size.saturating_mul(8);
                        Expr::Cast {
                            ty: Type::Signed(input_width),
                            value: Box::new(value),
                        }
                    } else {
                        value
                    };
                    let ty = if operation.opcode == op::FLOAT_TRUNC {
                        Type::Signed(output.size.saturating_mul(8))
                    } else {
                        Type::Float(output.size.saturating_mul(8))
                    };
                    definitions.insert(
                        ValueKey::from(output),
                        Expr::Cast {
                            ty,
                            value: Box::new(value),
                        },
                    );
                }
            }

            op::INT_CARRY => {
                if let (Some(output), Some(left), Some(right)) =
                    (operation.output, input(0), input(1))
                {
                    let sum = BinaryOp::build(BinaryOp::Add, left.clone(), right);
                    definitions.insert(
                        ValueKey::from(output),
                        BinaryOp::build(BinaryOp::Less, sum, left),
                    );
                }
            }
            op::INT_SCARRY | op::INT_SBORROW => {
                if let (Some(output), Some(left), Some(right)) =
                    (operation.output, input(0), input(1))
                {
                    let signed_width = operation
                        .inputs
                        .first()
                        .map_or(output.size, |value| value.size);
                    let signed_type = Type::Signed(signed_width.saturating_mul(8));
                    let left = Expr::Cast {
                        ty: signed_type.clone(),
                        value: Box::new(left),
                    };
                    let right = Expr::Cast {
                        ty: signed_type.clone(),
                        value: Box::new(right),
                    };
                    let left_negative = BinaryOp::build(
                        BinaryOp::SignedLess,
                        left.clone(),
                        Expr::constant(0, signed_width),
                    );
                    let right_negative = BinaryOp::build(
                        BinaryOp::SignedLess,
                        right.clone(),
                        Expr::constant(0, signed_width),
                    );
                    let arithmetic = if operation.opcode == op::INT_SCARRY {
                        BinaryOp::build(BinaryOp::Add, left.clone(), right.clone())
                    } else {
                        BinaryOp::build(BinaryOp::Sub, left.clone(), right.clone())
                    };
                    let result_negative = BinaryOp::build(
                        BinaryOp::SignedLess,
                        Expr::Cast {
                            ty: signed_type,
                            value: Box::new(arithmetic),
                        },
                        Expr::constant(0, signed_width),
                    );
                    let same_sign =
                        BinaryOp::build(BinaryOp::Equal, left_negative.clone(), right_negative);
                    let changed_sign =
                        BinaryOp::build(BinaryOp::NotEqual, left_negative, result_negative);
                    definitions.insert(
                        ValueKey::from(output),
                        BinaryOp::build(BinaryOp::And, same_sign, changed_sign),
                    );
                }
            }

            op::POPCOUNT | op::LZCOUNT => {
                if let (Some(output), Some(value)) = (operation.output, input(0)) {
                    let name = if operation.opcode == op::POPCOUNT {
                        "__builtin_popcount"
                    } else {
                        "__builtin_clz"
                    };
                    definitions.insert(
                        ValueKey::from(output),
                        Expr::Builtin {
                            name,
                            args: vec![value],
                        },
                    );
                }
            }
            op::INT_2COMP => {
                if let (Some(output), Some(value)) = (operation.output, input(0)) {
                    definitions
                        .insert(ValueKey::from(output), simplify(Expr::Neg(Box::new(value))));
                }
            }
            op::INT_NEGATE => {
                if let (Some(output), Some(value)) = (operation.output, input(0)) {
                    definitions.insert(
                        ValueKey::from(output),
                        simplify(Expr::BitNot(Box::new(value))),
                    );
                }
            }
            op::BOOL_NEGATE => {
                if let (Some(output), Some(value)) = (operation.output, input(0)) {
                    definitions
                        .insert(ValueKey::from(output), simplify(Expr::Not(Box::new(value))));
                }
            }
            op::INT_ZEXT | op::INT_SEXT | op::CAST => {
                if let (Some(output), Some(value)) = (operation.output, input(0)) {
                    let ty = if operation.opcode == op::INT_SEXT {
                        Type::Signed(output.size.saturating_mul(8))
                    } else {
                        Type::from_width(output.size)
                    };
                    definitions.insert(
                        ValueKey::from(output),
                        Expr::Cast {
                            ty,
                            value: Box::new(value),
                        },
                    );
                }
            }
            op::SUBPIECE => {
                if let (Some(output), Some(value)) = (operation.output, input(0)) {
                    definitions.insert(
                        ValueKey::from(output),
                        Expr::Cast {
                            ty: Type::from_width(output.size),
                            value: Box::new(value),
                        },
                    );
                }
            }
            op::LOAD => {
                if let (Some(output), Some(address)) = (operation.output, input(1)) {
                    let is_restore = abi.is_some_and(|abi| {
                        is_abi_restore_load(architecture, abi, output, &address, prologue_state)
                    });
                    let value = (!is_restore)
                        .then(|| {
                            abi.and_then(|abi| {
                                stack_argument_parameter(architecture, abi, &address, output.size)
                            })
                        })
                        .flatten()
                        .or_else(|| named_global(symbols, &address, output.size))
                        .or_else(|| match (&address, memory) {
                            (
                                Expr::Constant {
                                    value: address_value,
                                    ..
                                },
                                Some(memory),
                            ) => (memory.read)(*address_value, output.size)
                                .map(|value| Expr::constant(value, output.size)),
                            _ => None,
                        })
                        .unwrap_or_else(|| Expr::Load {
                            address: Box::new(address),
                            width: output.size,
                        });
                    definitions.insert(ValueKey::from(output), simplify(value));
                }
            }
            op::STORE => {
                let instruction_address = address;
                if let (Some(address), Some(value)) = (input(1), input(2)) {
                    let stack_backchain = abi.is_some_and(|abi| {
                        is_abi_stack_backchain_save(architecture, abi, &address, &value)
                    });
                    if let Some(abi) = abi {
                        if expression_is_named_register(
                            &value,
                            &abi_special_register_names(architecture, abi),
                        ) {
                            if let Some(slot) = prologue_stack_slot(architecture, abi, &address) {
                                prologue_state.saved_stack_slots.insert(slot);
                            }
                        }
                    }
                    if stack_backchain {
                        return;
                    }
                    let width = operation.inputs.get(2).map_or(8, |v| v.size);
                    let volatile = match (&address, memory) {
                        (
                            Expr::Constant {
                                value: address_value,
                                ..
                            },
                            Some(memory),
                        ) => (memory.is_volatile)(*address_value, width),
                        _ => false,
                    };
                    // A pending definition that still reads memory must be
                    // read before this store overwrites it. Re-materializing
                    // the load after the store would silently return the new
                    // value: the whole point of `iVar1 = *p; *p = iVar1 + 1;`
                    // is that the two uses differ.
                    materialize_loads_before_store(
                        &address,
                        width,
                        architecture,
                        instruction_address,
                        live_reads,
                        definitions,
                        statements,
                    );
                    let address = named_global(symbols, &address, width).unwrap_or(address);
                    let value = simplify(value);
                    if width > 8 {
                        statements.push(NativeStatement::Copy {
                            destination: address,
                            source: value,
                            width,
                            volatile,
                        });
                    } else {
                        statements.push(NativeStatement::Store {
                            address,
                            value,
                            width,
                            volatile,
                        });
                    }
                }
            }
            op::CALLOTHER => {
                let userop = operation.inputs.first().and_then(constant_value);
                let internal_branch_state_userop = operation.output.is_none()
                    && (userop.is_some_and(|index| {
                        ventris_lifter::sleigh_userop_name(architecture, index)
                            == Some("setISAMode")
                    }) || match architecture {
                        Architecture::Arm32 | Architecture::Thumb => userop == Some(62),
                        Architecture::Mips32
                        | Architecture::Mips32Be
                        | Architecture::Ps1
                        | Architecture::Ps2
                        | Architecture::N64 => userop == Some(0),
                        _ => false,
                    });
                if internal_branch_state_userop {
                    // The MIPS/N64 return and Arm32 BX lifters use these
                    // userops for branch-state bookkeeping. They have no
                    // source-level effect.
                    return;
                }

                let resolved_name = userop
                    .and_then(|index| ventris_lifter::sleigh_userop_name(architecture, index));
                let call = Expr::Builtin {
                    name: resolved_name.unwrap_or("__ventris_callother"),
                    args: operation
                        .inputs
                        .iter()
                        .skip(usize::from(resolved_name.is_some()))
                        .copied()
                        .map(|value| eval(value, architecture, definitions))
                        .collect(),
                };
                if let Some(output) = operation.output {
                    definitions.insert(ValueKey::from(output), call);
                } else {
                    statements.push(NativeStatement::Expression(call));
                }
            }
            op::CALL => {
                let target = operation.inputs.first().and_then(direct_target_value);
                let callee = target
                    .and_then(|target| named_symbol(symbols, target, 0))
                    .or_else(|| target.is_none().then(|| input(0)).flatten())
                    .map(Box::new);
                let prototype = target.and_then(|target| {
                    call_prototypes.and_then(|prototypes| prototypes.get(&target))
                });
                let args = if operation.inputs.len() > 1 {
                    let arguments = operation
                        .inputs
                        .iter()
                        .skip(1)
                        .filter(|value| {
                            abi.is_some()
                                || call_argument_available(architecture, **value, definitions)
                        })
                        .map(|value| eval(*value, architecture, definitions))
                        .collect();
                    type_call_arguments(arguments, prototype)
                } else {
                    abi.map(|abi| {
                        materialize_abi_call_arguments(architecture, abi, definitions, prototype)
                    })
                    .unwrap_or_default()
                };
                let call = Expr::Call {
                    target,
                    callee,
                    args,
                };
                if let Some(abi) = abi {
                    invalidate_abi_call_clobbers(architecture, abi, definitions);
                } else {
                    invalidate_mips_o32_call_arguments(architecture, definitions);
                }
                let return_type = prototype
                    .map(|prototype| prototype.return_type.clone())
                    .unwrap_or_else(|| default_return_type(architecture));
                if return_type == Type::Void {
                    statements.push(NativeStatement::Call(call));
                } else {
                    let return_register = abi
                        .and_then(|abi| abi_return_vnodes(architecture, abi).into_iter().next())
                        .unwrap_or_else(|| return_vnode(architecture));
                    let name = format!("call_{address:x}");
                    statements.push(NativeStatement::Declare {
                        name: name.clone(),
                        ty: return_type,
                        value: call,
                    });
                    definitions.insert(
                        ValueKey::from(return_register),
                        Expr::Temporary {
                            name,
                            width: return_register.size,
                        },
                    );
                }
            }
            op::CALLIND => {
                let callee = input(0)
                    .map(|value| match value {
                        Expr::Constant { value, width } => named_symbol(symbols, value, width)
                            .unwrap_or(Expr::Constant { value, width }),
                        value => value,
                    })
                    .map(Box::new);
                let args = if operation.inputs.len() > 1 {
                    operation
                        .inputs
                        .iter()
                        .skip(1)
                        .filter(|value| {
                            abi.is_some()
                                || call_argument_available(architecture, **value, definitions)
                        })
                        .map(|value| eval(*value, architecture, definitions))
                        .collect()
                } else {
                    abi.map(|abi| {
                        materialize_indirect_abi_call_arguments(
                            architecture,
                            abi,
                            definitions,
                            callee.as_deref(),
                        )
                    })
                    .unwrap_or_default()
                };
                let call = Expr::Call {
                    target: None,
                    callee,
                    args,
                };
                if let Some(abi) = abi {
                    invalidate_abi_call_clobbers(architecture, abi, definitions);
                } else {
                    invalidate_mips_o32_call_arguments(architecture, definitions);
                }
                let return_register = abi
                    .and_then(|abi| abi_return_vnodes(architecture, abi).into_iter().next())
                    .unwrap_or_else(|| return_vnode(architecture));
                let name = format!("call_{address:x}");
                statements.push(NativeStatement::Declare {
                    name: name.clone(),
                    ty: default_return_type(architecture),
                    value: call,
                });
                definitions.insert(
                    ValueKey::from(return_register),
                    Expr::Temporary {
                        name,
                        width: return_register.size,
                    },
                );
            }
            op::CBRANCH => {
                if let (Some(target), Some(condition)) = (
                    operation.inputs.first().and_then(direct_target_value),
                    input(1),
                ) {
                    statements.push(NativeStatement::IfGoto { condition, target });
                }
            }
            op::BRANCH => {
                if let Some(target) = operation.inputs.first().and_then(direct_target_value) {
                    statements.push(NativeStatement::Goto(target));
                }
            }
            op::BRANCHIND => {
                if let Some(value) = input(0) {
                    statements.push(NativeStatement::IndirectGoto(value));
                } else {
                    warnings.push(format!(
                        "indirect branch at {address:#x} has no target expression"
                    ));
                }
            }
            op::RETURN => {}
            op::MULTIEQUAL => {
                if let (Some(output), Some(value)) = (operation.output, input(0)) {
                    definitions.insert(ValueKey::from(output), value);
                }
            }
            _ => warnings.push(format!(
                "p-code opcode {} at {address:#x} was not rendered",
                operation.opcode
            )),
        }
    }
}

fn direct_target_value(v: &Varnode) -> Option<u64> {
    matches!(
        v.space,
        ventris_lifter::CONST_SPACE | ventris_lifter::RAM_SPACE
    )
    .then_some(v.offset)
}

fn constant_value(v: &Varnode) -> Option<u64> {
    (v.space == ventris_lifter::CONST_SPACE).then_some(v.offset)
}

/// Offsets of the O32 argument registers in one architecture's own language.
fn mips_o32_call_argument_offsets(architecture: Architecture) -> &'static BTreeSet<u64> {
    static OFFSETS: LazyLock<BTreeMap<Architecture, BTreeSet<u64>>> = LazyLock::new(|| {
        const ARGUMENTS: [&str; 6] = ["a0", "a1", "a2", "a3", "f12", "f14"];
        [
            Architecture::Mips32,
            Architecture::Mips32Be,
            Architecture::Ps1,
            Architecture::Ps2,
        ]
        .into_iter()
        .map(|architecture| {
            let offsets = ARGUMENTS
                .into_iter()
                .filter_map(|name| {
                    ventris_lifter::sleigh_register_varnode(architecture, name)
                        .filter(|(space, _, _)| *space == REGISTER_SPACE)
                        .map(|(_, offset, _)| offset)
                })
                .collect();
            (architecture, offsets)
        })
        .collect()
    });
    static EMPTY: LazyLock<BTreeSet<u64>> = LazyLock::new(BTreeSet::new);
    OFFSETS.get(&architecture).unwrap_or(&EMPTY)
}

fn is_mips_o32_call_argument(architecture: Architecture, value: Varnode) -> bool {
    value.space == ventris_lifter::REGISTER_SPACE
        && mips_o32_call_argument_offsets(architecture).contains(&value.offset)
}

fn call_argument_available(
    architecture: Architecture,
    value: Varnode,
    definitions: &BTreeMap<ValueKey, Expr>,
) -> bool {
    if !matches!(
        architecture,
        Architecture::Mips32 | Architecture::Mips32Be | Architecture::Ps1 | Architecture::Ps2
    ) || !is_mips_o32_call_argument(architecture, value)
    {
        return true;
    }
    definitions.keys().any(|key| {
        key.space == value.space && key.offset == value.offset && key.width == value.size
    })
}
fn invalidate_mips_o32_call_arguments(
    architecture: Architecture,
    definitions: &mut BTreeMap<ValueKey, Expr>,
) {
    if matches!(
        architecture,
        Architecture::Mips32 | Architecture::Mips32Be | Architecture::Ps1 | Architecture::Ps2
    ) {
        definitions.retain(|key, _| {
            !is_mips_o32_call_argument(architecture, Varnode::new(key.space, key.offset, key.width))
        });
    }
}

/// Whether a value is the same no matter which path reached it.
///
/// Constants, parameters, and globals do not depend on the path. A register
/// does only if the function never writes it, or if it is a frame register,
/// whose value every path must agree on for the function to return. Memory is
/// excluded: any path may have stored to it.
fn is_path_invariant(value: &Expr, stable_registers: &BTreeSet<String>) -> bool {
    match value {
        Expr::Constant { .. } | Expr::Parameter { .. } | Expr::Global { .. } => true,
        Expr::Register { name, .. } => stable_registers.contains(name),
        Expr::Temporary { .. } => false,
        Expr::Binary { left, right, .. } => {
            is_path_invariant(left, stable_registers) && is_path_invariant(right, stable_registers)
        }
        Expr::Not(inner) | Expr::Neg(inner) | Expr::BitNot(inner) => {
            is_path_invariant(inner, stable_registers)
        }
        Expr::Cast { value, .. } | Expr::Typed { value, .. } => {
            is_path_invariant(value, stable_registers)
        }
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => {
            is_path_invariant(condition, stable_registers)
                && is_path_invariant(when_true, stable_registers)
                && is_path_invariant(when_false, stable_registers)
        }
        Expr::Load { .. } | Expr::Field { .. } | Expr::Call { .. } | Expr::Builtin { .. } => false,
    }
}

/// Merges the states flowing into one label, naming values that disagree.
///
/// Only a key every predecessor agrees on keeps its inlined value. A key whose
/// value depends on the path is dropped, so a later use reads the register
/// rather than one path's value.
fn merge_join_contributions(
    architecture: Architecture,
    predecessor_count: usize,
    contributions: &[(usize, BTreeMap<ValueKey, Expr>)],
    incoming: &BTreeMap<ValueKey, Expr>,
    stable_registers: &BTreeSet<String>,
) -> BTreeMap<ValueKey, Expr> {
    if contributions.len() != predecessor_count || contributions.is_empty() {
        // Not every path has been translated yet. A definition survives only if
        // no path could have written a different value into its register *and*
        // the value itself does not depend on the path. Keeping a per-path
        // constant because constants look stable is what makes a merge adopt
        // one branch's value.
        return incoming
            .iter()
            .filter(|(key, value)| {
                stable_registers.contains(&register_name(architecture, key.offset))
                    && is_path_invariant(value, stable_registers)
            })
            .map(|(key, value)| (*key, value.clone()))
            .collect();
    }
    let (_, first) = &contributions[0];
    first
        .iter()
        .filter(|(key, value)| {
            contributions
                .iter()
                .all(|(_, state)| state.get(key) == Some(*value))
        })
        .map(|(key, value)| (*key, value.clone()))
        .collect()
}
/// Prefix of the temporaries introduced to hold a value read before a store.
const MEMORY_SNAPSHOT_PREFIX: &str = "mem_";

/// Removes memory snapshots that nothing ended up reading.
///
/// A snapshot is only created because a store might overwrite the value. When
/// the value turns out to be unread, the snapshot is pure bookkeeping: the load
/// it holds is a plain read of the same address the neighbouring store already
/// names, so dropping it removes a line without removing an observable effect.
fn drop_unread_memory_snapshots(statements: &mut Vec<NativeStatement>) {
    let mut referenced = BTreeSet::new();
    for statement in statements.iter() {
        let declared = match statement {
            NativeStatement::Declare { name, .. } => Some(name.clone()),
            _ => None,
        };
        let mut used = actions::statement_temporary_uses(statement);
        if let Some(declared) = declared {
            used.remove(&declared);
        }
        referenced.extend(used);
    }
    statements.retain(|statement| match statement {
        NativeStatement::Declare { name, .. } => {
            !name.starts_with(MEMORY_SNAPSHOT_PREFIX) || referenced.contains(name)
        }
        _ => true,
    });
}

/// Where each varnode is still read, so a value is only named when it is used.
///
/// Materializing every memory-valued definition before a store would be
/// correct but unreadable: most definitions are intermediates that nothing
/// reads again. This records the highest address that reads each varnode, and
/// whether the function can branch backwards, which makes any read reachable
/// again.
struct LiveReads {
    last_read: BTreeMap<(u32, u64), u64>,
    written: BTreeSet<(u32, u64)>,
    has_back_edge: bool,
}

impl LiveReads {
    fn of(function: &NativeFunction) -> Self {
        let mut last_read = BTreeMap::new();
        let mut written = BTreeSet::new();
        for (address, instruction) in &function.instructions {
            for operation in &instruction.pcode.ops {
                for input in &operation.inputs {
                    if input.space != REGISTER_SPACE {
                        continue;
                    }
                    last_read
                        .entry((input.space, input.offset))
                        .and_modify(|previous: &mut u64| *previous = (*previous).max(*address))
                        .or_insert(*address);
                }
                if let Some(output) = operation.output.filter(|o| o.space == REGISTER_SPACE) {
                    written.insert((output.space, output.offset));
                }
            }
        }
        Self {
            last_read,
            written,
            has_back_edge: function
                .edges
                .iter()
                .any(|(source, target)| target <= source),
        }
    }

    fn read_after(&self, key: &ValueKey, address: u64) -> bool {
        self.last_read
            .get(&(key.space, key.offset))
            .is_some_and(|last| self.has_back_edge || *last > address)
    }

    /// Whether the function writes this varnode at all.
    fn is_written(&self, value: &Varnode) -> bool {
        self.written.contains(&(value.space, value.offset))
    }

    /// Names of registers the function never writes. Their value at any point
    /// is the value on entry, so no path can disagree about them.
    fn unwritten_register_names(&self, architecture: Architecture) -> BTreeSet<String> {
        self.last_read
            .keys()
            .filter(|key| !self.written.contains(key))
            .map(|(_, offset)| register_name(architecture, *offset))
            .collect()
    }
}
/// Interprets a constant of the given byte width as signed.
fn signed_constant_value(value: u64, width: u32) -> i64 {
    let bits = width.saturating_mul(8).min(64);
    if bits == 0 {
        return 0;
    }
    if bits == 64 {
        return value as i64;
    }
    let mask = (1_u64 << bits) - 1;
    let masked = value & mask;
    if masked & (1_u64 << (bits - 1)) == 0 {
        masked as i64
    } else {
        (masked as i64) - (1_i64 << bits)
    }
}

/// Splits `base + constant` so two addresses can be compared symbolically.
fn address_base_and_offset(value: &Expr) -> (&Expr, u64) {
    match value {
        Expr::Binary {
            op: BinaryOp::Add,
            left,
            right,
        } => match right.as_ref() {
            Expr::Constant { value, .. } => (left.as_ref(), *value),
            _ => (value, 0),
        },
        value => (value, 0),
    }
}

/// Whether a load at `load` could read bytes a store at `store` overwrites.
///
/// Only provable disjointness returns false. Two accesses off the same base at
/// non-overlapping constant offsets are distinct fields; two different
/// constant addresses are distinct globals. Everything else may alias.
fn accesses_may_alias(load: &Expr, load_width: u32, store: &Expr, store_width: u32) -> bool {
    let disjoint = |left: u64, left_width: u32, right: u64, right_width: u32| {
        left.saturating_add(u64::from(left_width)) <= right
            || right.saturating_add(u64::from(right_width)) <= left
    };
    if let (Expr::Constant { value: load, .. }, Expr::Constant { value: store, .. }) = (load, store)
    {
        return !disjoint(*load, load_width, *store, store_width);
    }
    let (load_base, load_offset) = address_base_and_offset(load);
    let (store_base, store_offset) = address_base_and_offset(store);
    if load_base == store_base {
        return !disjoint(load_offset, load_width, store_offset, store_width);
    }
    true
}

fn expression_reads_memory(value: &Expr) -> bool {
    match value {
        Expr::Load { .. } | Expr::Field { .. } => true,
        Expr::Binary { left, right, .. } => {
            expression_reads_memory(left) || expression_reads_memory(right)
        }
        Expr::Not(inner) | Expr::Neg(inner) | Expr::BitNot(inner) => expression_reads_memory(inner),
        Expr::Cast { value, .. } | Expr::Typed { value, .. } => expression_reads_memory(value),
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => {
            expression_reads_memory(condition)
                || expression_reads_memory(when_true)
                || expression_reads_memory(when_false)
        }
        Expr::Call { args, .. } | Expr::Builtin { args, .. } => {
            args.iter().any(expression_reads_memory)
        }
        _ => false,
    }
}

/// Collects the loads inside `value` that `store` may overwrite.
fn aliasing_loads(value: &Expr, store: &Expr, store_width: u32, found: &mut bool) {
    match value {
        Expr::Load { address, width } => {
            if accesses_may_alias(address, *width, store, store_width) {
                *found = true;
            }
            aliasing_loads(address, store, store_width, found);
        }
        Expr::Binary { left, right, .. } => {
            aliasing_loads(left, store, store_width, found);
            aliasing_loads(right, store, store_width, found);
        }
        Expr::Not(inner) | Expr::Neg(inner) | Expr::BitNot(inner) => {
            aliasing_loads(inner, store, store_width, found);
        }
        Expr::Cast { value, .. } | Expr::Typed { value, .. } => {
            aliasing_loads(value, store, store_width, found);
        }
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => {
            aliasing_loads(condition, store, store_width, found);
            aliasing_loads(when_true, store, store_width, found);
            aliasing_loads(when_false, store, store_width, found);
        }
        Expr::Call { args, .. } | Expr::Builtin { args, .. } => {
            for arg in args {
                aliasing_loads(arg, store, store_width, found);
            }
        }
        _ => {}
    }
}

/// Reads pending memory-valued definitions into temporaries before a store.
///
/// A definition holding `*p` is inlined at its use sites. If a store to `p`
/// intervenes, the inlined load reads the stored value instead of the value the
/// program computed, which changes what the function returns.
fn materialize_loads_before_store(
    store_address: &Expr,
    store_width: u32,
    architecture: Architecture,
    instruction_address: u64,
    live_reads: &LiveReads,
    definitions: &mut BTreeMap<ValueKey, Expr>,
    statements: &mut Vec<NativeStatement>,
) {
    let mut pending = Vec::new();
    let mut stale = Vec::new();
    for (key, value) in definitions.iter() {
        if !expression_reads_memory(value) {
            continue;
        }
        let mut aliases = false;
        aliasing_loads(value, store_address, store_width, &mut aliases);
        if !aliases {
            continue;
        }
        if live_reads.read_after(key, instruction_address) {
            pending.push((*key, value.clone()));
        } else {
            stale.push(*key);
        }
    }
    // A definition nothing reads again would only add an unused name, but it
    // must not survive: a later re-materialization would read the stored value.
    for key in stale {
        definitions.remove(&key);
    }
    for (index, (key, value)) in pending.into_iter().enumerate() {
        let name = format!("mem_{instruction_address:x}_{index}");
        let ty = expression_type(&value, architecture);
        statements.push(NativeStatement::Declare {
            name: name.clone(),
            ty,
            value,
        });
        definitions.insert(
            key,
            Expr::Temporary {
                name,
                width: key.width,
            },
        );
    }
}

fn named_global(
    symbols: Option<&dyn Fn(u64) -> Option<String>>,
    address: &Expr,
    width: u32,
) -> Option<Expr> {
    let Expr::Constant { value, .. } = address else {
        return None;
    };
    named_symbol(symbols, *value, width)
}

fn named_symbol(
    symbols: Option<&dyn Fn(u64) -> Option<String>>,
    address: u64,
    width: u32,
) -> Option<Expr> {
    let name = symbols
        .and_then(|resolve| resolve(address))
        .map(|name| global_identifier(&name, address))?;
    Some(Expr::Global {
        name,
        address,
        width,
    })
}

fn global_identifier(name: &str, address: u64) -> String {
    let mut identifier = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if identifier.is_empty() {
        identifier = format!("DAT_{address:x}");
    } else if identifier.starts_with(|character: char| character.is_ascii_digit()) {
        identifier.insert(0, '_');
    }
    identifier
}

/// Rewrites every read of the architecture's hardwired-zero register to the
/// constant zero.
fn replace_hardwired_zero_reads(data: &mut graph::Funcdata, architecture: Architecture) {
    let zero_offset = match architecture {
        Architecture::AArch64 => 0x4000 + 31 * 8,
        Architecture::Mips32
        | Architecture::Mips32Be
        | Architecture::Ps1
        | Architecture::Ps2
        | Architecture::N64 => 0,
        Architecture::Rv64 | Architecture::Rv32 => 0x2000,
        _ => return,
    };
    let operations: Vec<graph::OpId> = data.live_ops().map(|(id, _)| id).collect();
    for id in operations {
        let inputs = data.op(id).inputs.clone();
        for (slot, value) in inputs.into_iter().enumerate() {
            let varnode = data.varnode(value);
            if varnode.flags.constant
                || varnode.space != REGISTER_SPACE
                || varnode.offset != zero_offset
            {
                continue;
            }
            let size = varnode.size;
            let zero = data.new_constant(0, size);
            data.op_set_input(id, zero, slot);
        }
    }
}

fn is_zero_register(architecture: Architecture, v: Varnode) -> bool {
    v.space == REGISTER_SPACE
        && match architecture {
            Architecture::AArch64 => v.offset == 0x4000 + 31 * 8,
            Architecture::Mips32
            | Architecture::Mips32Be
            | Architecture::Ps1
            | Architecture::Ps2
            | Architecture::N64 => v.offset == 0,
            Architecture::Rv64 | Architecture::Rv32 => v.offset == 0x2000,
            _ => false,
        }
}

/// Low-byte and halfword register views may share a Varnode offset on
/// little-endian register banks. Big-endian views require byte-position
/// adjustment, so a wider definition at the same offset is not an alias.
fn is_little_endian(architecture: Architecture) -> bool {
    matches!(
        architecture,
        Architecture::X86_64
            | Architecture::X86_32
            | Architecture::AArch64
            | Architecture::Arm32
            | Architecture::Thumb
            | Architecture::Mips32
            | Architecture::Ps1
            | Architecture::Ps2
            | Architecture::Rv64
            | Architecture::Rv32
            | Architecture::Sh4
            | Architecture::M6502
            | Architecture::Z80
    )
}

fn eval_input(
    v: Varnode,
    architecture: Architecture,
    definitions: &BTreeMap<ValueKey, Expr>,
    memory: Option<&NativeMemory<'_>>,
) -> Expr {
    if v.space == ventris_lifter::RAM_SPACE {
        if let Some(value) = memory.and_then(|memory| (memory.read)(v.offset, v.size)) {
            return Expr::constant(value, v.size);
        }
        return Expr::Load {
            address: Box::new(Expr::constant(v.offset, v.size)),
            width: v.size,
        };
    }
    eval(v, architecture, definitions)
}

fn eval(v: Varnode, architecture: Architecture, definitions: &BTreeMap<ValueKey, Expr>) -> Expr {
    if let Some(value) = constant_value(&v) {
        return Expr::constant(value, v.size);
    }
    if is_zero_register(architecture, v) {
        return Expr::constant(0, v.size);
    }
    let key = ValueKey::from(v);
    if let Some(value) = definitions.get(&key) {
        return value.clone();
    }
    if v.space == REGISTER_SPACE {
        if is_little_endian(architecture) {
            if let Some((_, value)) = definitions
                .iter()
                .filter(|(candidate, _)| {
                    candidate.space == v.space
                        && candidate.offset == v.offset
                        && candidate.width > v.size
                })
                .min_by_key(|(candidate, _)| candidate.width)
            {
                return simplify(Expr::Cast {
                    ty: Type::from_width(v.size),
                    value: Box::new(value.clone()),
                });
            }
        }
        if let Some((_, value)) = definitions
            .iter()
            .filter(|(candidate, _)| {
                candidate.space == v.space
                    && candidate.offset == v.offset
                    && candidate.width < v.size
            })
            .max_by_key(|(candidate, _)| candidate.width)
        {
            return simplify(Expr::Cast {
                ty: Type::from_width(v.size),
                value: Box::new(value.clone()),
            });
        }
        return Expr::Register {
            name: register_name(architecture, v.offset),
            width: v.size,
        };
    }
    Expr::Temporary {
        name: format!("u_{:x}", v.offset),
        width: v.size,
    }
}

fn return_vnode(architecture: Architecture) -> Varnode {
    match architecture {
        Architecture::X86_64 => Varnode::new(REGISTER_SPACE, 0, 8),
        Architecture::X86_32 => Varnode::new(REGISTER_SPACE, 0, 4),
        Architecture::AArch64 => Varnode::new(REGISTER_SPACE, 0x4000 + 8 * 0, 8),
        Architecture::Arm32 | Architecture::Thumb => Varnode::new(REGISTER_SPACE, 32, 4),
        Architecture::Mips32 | Architecture::Mips32Be | Architecture::Ps1 => {
            Varnode::new(REGISTER_SPACE, 8, 4)
        }
        Architecture::Ps2 => Varnode::new(REGISTER_SPACE, 32, 8),
        Architecture::N64 => Varnode::new(REGISTER_SPACE, 16, 8),
        Architecture::Rv64 => Varnode::new(REGISTER_SPACE, 0x2000 + 8 * 10, 8),
        Architecture::Rv32 => Varnode::new(REGISTER_SPACE, 0x2000 + 4 * 10, 4),
        Architecture::Ppc32 | Architecture::GameCube => Varnode::new(REGISTER_SPACE, 3 * 4, 4),
        Architecture::Ppc64 => Varnode::new(REGISTER_SPACE, 3 * 8, 8),
        Architecture::M68k => Varnode::new(REGISTER_SPACE, 0, 4),
        Architecture::Sh2 | Architecture::Sh4 => Varnode::new(REGISTER_SPACE, 0, 4),
        Architecture::Spu => Varnode::new(REGISTER_SPACE, 3 * 16, 16),
        Architecture::M6502 => Varnode::new(REGISTER_SPACE, 0, 1),
        Architecture::Z80 => Varnode::new(REGISTER_SPACE, 1, 1),
    }
}

/// Presents a value at the width its own type declares.
///
/// A definition's expression can be narrower than the value it defines: the
/// R5900 materializes a 32-bit result from a 16-bit immediate, so the recorded
/// expression is two bytes wide while the defined value is four. Returning the
/// raw expression would infer a 16-bit return type for a 32-bit result.
fn narrow_to_declared_width(value: Expr, architecture: Architecture) -> Expr {
    let ty = expression_type(&value, architecture);
    let declared = type_width(&ty);
    if declared == 0 || expression_width(&value) == declared {
        return value;
    }
    simplify(Expr::Cast {
        ty,
        value: Box::new(value),
    })
}
/// Compares two expressions as values, ignoring the declared width of an
/// integer constant.
///
/// A stored constant carries the store's width while the same constant left in
/// a register carries the register's width. They are the same value, and a
/// width-sensitive comparison would treat a returned byproduct as a genuine
/// return value.
fn is_same_value(left: &Expr, right: &Expr) -> bool {
    match (left, right) {
        (Expr::Constant { value: left, .. }, Expr::Constant { value: right, .. }) => left == right,
        (left, right) => left == right,
    }
}

fn return_value(
    architecture: Architecture,
    abi: Option<&Abi>,
    definitions: &BTreeMap<ValueKey, Expr>,
    explicit: Option<Varnode>,
    live_reads: &LiveReads,
) -> Option<Expr> {
    // A return register the function never writes still holds the incoming
    // argument. Treating that as the return value invents a result out of an
    // untouched register, which is how a `void` function grows a return type.
    let all_candidates = abi
        .map(|abi| abi_return_vnodes(architecture, abi))
        .map(|candidates| {
            let written = candidates
                .iter()
                .copied()
                .filter(|candidate| live_reads.is_written(candidate))
                .collect::<Vec<_>>();
            if written.is_empty() {
                candidates
            } else {
                written
            }
        })
        .filter(|candidates| !candidates.is_empty())
        .unwrap_or_else(|| vec![return_vnode(architecture)]);
    let explicit_candidate = explicit.and_then(|explicit| {
        all_candidates
            .iter()
            .copied()
            .find(|candidate| register_vnode_matches(explicit, *candidate))
    });
    let candidates = explicit_candidate.map_or_else(
        || {
            abi.map(|abi| abi_primary_return_vnodes(architecture, abi))
                .map(|candidates| {
                    let written = candidates
                        .iter()
                        .copied()
                        .filter(|candidate| live_reads.is_written(candidate))
                        .collect::<Vec<_>>();
                    if written.is_empty() {
                        candidates
                    } else {
                        written
                    }
                })
                .filter(|candidates| !candidates.is_empty())
                .unwrap_or_else(|| vec![return_vnode(architecture)])
        },
        |candidate| vec![candidate],
    );
    let value = candidates
        .iter()
        .find_map(|return_register| {
            definitions
                .iter()
                .filter(|(key, _)| {
                    key.space == return_register.space
                        && key.offset == return_register.offset
                        && key.width <= return_register.size
                })
                .max_by_key(|(key, _)| key.width)
                .map(|(_, value)| simplify(value.clone()))
        })
        .or_else(|| {
            candidates
                .first()
                .map(|register| simplify(eval(*register, architecture, definitions)))
        });
    let value = value?;
    let value = match (architecture, value) {
        (
            Architecture::X86_64,
            Expr::Cast {
                ty: Type::Unsigned(64),
                value,
            },
        ) if expression_type(&value, architecture) == Type::Unsigned(32) => {
            narrow_to_declared_width(*value, architecture)
        }
        (
            Architecture::Ps2,
            Expr::Cast {
                ty: Type::Signed(64) | Type::Unsigned(64),
                value,
            },
        ) if matches!(
            expression_type(&value, architecture),
            Type::Signed(32) | Type::Unsigned(32)
        ) =>
        {
            narrow_to_declared_width(*value, architecture)
        }
        (_, value) => value,
    };
    match value {
        Expr::Register { .. } | Expr::Call { .. } => None,
        Expr::Temporary { ref name, .. } if name.starts_with("call_") => None,
        value => Some(value),
    }
}

/// The R5900's register offsets are not derivable by arithmetic: general
/// registers are quadword-spaced and COP1 registers are stored in swapped
/// little-endian pairs. Invert the language's own forward mapping instead of
/// guessing a stride.
fn ps2_register_names() -> &'static BTreeMap<u64, &'static str> {
    static NAMES: LazyLock<BTreeMap<u64, &'static str>> = LazyLock::new(|| {
        const GPR: [&str; 32] = [
            "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5",
            "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1",
            "gp", "sp", "fp", "ra",
        ];
        const FPR: [&str; 32] = [
            "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10", "f11", "f12", "f13",
            "f14", "f15", "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23", "f24", "f25",
            "f26", "f27", "f28", "f29", "f30", "f31",
        ];
        let mut names = BTreeMap::new();
        for name in GPR.into_iter().chain(FPR) {
            if let Some((space, offset, _)) =
                ventris_lifter::sleigh_register_varnode(Architecture::Ps2, name)
                && space == REGISTER_SPACE
            {
                names.insert(offset, name);
            }
        }
        names
    });
    &NAMES
}

/// The R4300 coprocessor-0 register file, as SLEIGH names it.
///
/// Verified against `vm_boot`: the offsets observed there are `0x2000 + n * 8`
/// for n = 0, 2, 3, 5 and 10, which are `Index`, `EntryLo0`, `EntryLo1`,
/// `PageMask` and `EntryHi` — exactly what the oracle prints for the same five
/// `setCopReg` calls. Only N64 is claimed here because only N64 is verified.
const R4300_COP0_REGISTERS: [&str; 32] = [
    "Index",
    "Random",
    "EntryLo0",
    "EntryLo1",
    "Context",
    "PageMask",
    "Wired",
    "Reserved07",
    "BadVAddr",
    "Count",
    "EntryHi",
    "Compare",
    "Status",
    "Cause",
    "EPC",
    "PRId",
    "Config",
    "LLAddr",
    "WatchLo",
    "WatchHi",
    "XContext",
    "Reserved21",
    "Reserved22",
    "Reserved23",
    "Reserved24",
    "Reserved25",
    "ParityError",
    "CacheError",
    "TagLo",
    "TagHi",
    "ErrorEPC",
    "Reserved31",
];

/// The coprocessor-0 register at a register-space offset, if this is one.
fn cop0_register_name(architecture: Architecture, offset: u64) -> Option<&'static str> {
    if architecture != Architecture::N64 {
        return None;
    }
    let index = offset.checked_sub(0x2000)?;
    if index % 8 != 0 {
        return None;
    }
    R4300_COP0_REGISTERS.get((index / 8) as usize).copied()
}

/// The spelling for a register this architecture's table does not name.
///
/// Every unknown offset used to render as `reg`, so two different registers
/// became the same identifier and the output said they were one value. The
/// offset is what is actually known, so that is what is spelled: the COP0
/// registers in `vm_boot` are a different bank from the general-purpose file and
/// all six arguments of its `setCopReg` calls collapsed into one name.
fn unknown_register_name(offset: u64) -> String {
    format!("reg_{offset:x}")
}

/// A register's name, preferring a coprocessor name where one applies.
fn named_register(architecture: Architecture, offset: u64) -> String {
    cop0_register_name(architecture, offset)
        .map(str::to_owned)
        .unwrap_or_else(|| unknown_register_name(offset))
}

fn register_name(architecture: Architecture, offset: u64) -> String {
    match architecture {
        Architecture::X86_64 => [
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15",
        ]
        .get((offset / 8) as usize)
        .map(|name| (*name).to_owned())
        .unwrap_or_else(|| named_register(architecture, offset)),
        Architecture::X86_32 => [
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
            "r12d", "r13d", "r14d", "r15d",
        ]
        .get((offset / 8) as usize)
        .map(|name| (*name).to_owned())
        .unwrap_or_else(|| named_register(architecture, offset)),
        Architecture::AArch64 => format!("x{}", offset.saturating_sub(0x4000) / 8),
        Architecture::Rv64 => format!("x{}", offset.saturating_sub(0x2000) / 8),
        Architecture::Rv32 => format!("x{}", offset.saturating_sub(0x2000) / 4),
        Architecture::Arm32 | Architecture::Thumb => {
            let fpu_offset = offset.saturating_sub(0x200);
            if offset >= 0x200 && fpu_offset < 32 * 4 && fpu_offset % 4 == 0 {
                format!("s{}", fpu_offset / 4)
            } else {
                [
                    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "sp",
                    "lr", "pc",
                ]
                .get(offset.saturating_sub(32).checked_div(4).unwrap_or_default() as usize)
                .map(|name| (*name).to_owned())
                .unwrap_or_else(|| named_register(architecture, offset))
            }
        }
        Architecture::Mips32 | Architecture::Mips32Be | Architecture::Ps1 => {
            let fpu_offset = offset.saturating_sub(0x200);
            if offset >= 0x200 && fpu_offset < 32 * 4 && fpu_offset % 4 == 0 {
                format!("f{}", fpu_offset / 4)
            } else {
                [
                    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4",
                    "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9",
                    "k0", "k1", "gp", "sp", "fp", "ra",
                ]
                .get((offset / 4) as usize)
                .map(|name| (*name).to_owned())
                .unwrap_or_else(|| named_register(architecture, offset))
            }
        }
        Architecture::Ps2 => ps2_register_names()
            .get(&offset)
            .copied()
            .map(str::to_owned)
            .unwrap_or_else(|| named_register(architecture, offset)),
        Architecture::N64 => {
            let fpu_offset = offset.saturating_sub(0x200);
            if offset >= 0x200 && fpu_offset < 32 * 8 && fpu_offset % 8 == 0 {
                format!("f{}", fpu_offset / 8)
            } else {
                [
                    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4",
                    "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9",
                    "k0", "k1", "gp", "sp", "fp", "ra",
                ]
                .get((offset / 8) as usize)
                .map(|name| (*name).to_owned())
                .unwrap_or_else(|| named_register(architecture, offset))
            }
        }
        Architecture::Ppc32 | Architecture::GameCube => {
            let fpu_offset = offset.saturating_sub(0x200);
            if offset >= 0x200 && fpu_offset < 32 * 4 && fpu_offset % 4 == 0 {
                format!("f{}", fpu_offset / 4)
            } else if offset == 0x1020 {
                "lr".to_string()
            } else if offset == 0x1024 {
                "ctr".to_string()
            } else {
                format!("r{}", offset / 4)
            }
        }
        Architecture::Ppc64 => {
            let fpu_offset = offset.saturating_sub(0x200);
            if offset >= 0x200 && fpu_offset < 32 * 8 && fpu_offset % 8 == 0 {
                format!("f{}", fpu_offset / 8)
            } else if offset == 0x1020 {
                "lr".to_string()
            } else if offset == 0x1024 {
                "ctr".to_string()
            } else {
                format!("r{}", offset / 8)
            }
        }
        Architecture::M68k => [
            "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "a0", "a1", "a2", "a3", "a4", "a5",
            "a6", "a7", "pc",
        ]
        .get((offset / 4) as usize)
        .map(|name| (*name).to_owned())
        .unwrap_or_else(|| named_register(architecture, offset)),
        Architecture::Sh2 | Architecture::Sh4 => {
            if offset / 4 < 16 {
                format!("r{}", offset / 4)
            } else if offset == 16 * 4 {
                "pr".to_string()
            } else {
                "pc".to_string()
            }
        }
        Architecture::Spu => format!("r{}", offset / 16),
        Architecture::M6502 => ["a", "x", "y", "sp", "p", "pc"]
            .get(offset as usize)
            .map(|name| (*name).to_owned())
            .unwrap_or_else(|| named_register(architecture, offset)),
        Architecture::Z80 => ["a", "f", "b", "c", "d", "e", "h", "l", "sp", "pc"]
            .get(offset as usize)
            .map(|name| (*name).to_owned())
            .unwrap_or_else(|| named_register(architecture, offset)),
    }
}

impl fmt::Display for NativeDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ventris_lifter::{
        AArch64, Arm32, CONST_SPACE, Flow, GameCube, LiftedInstruction, Lifter, M68k, M6502,
        Mips32, Mips32Be, N64, Ppc32, Ps1, Ps2, RAM_SPACE, Rv32, Rv64, Sh2, Sh4, Thumb,
        UNIQUE_SPACE, X86_32, X86_64, Z80,
    };
    use ventris_pcode::InstPcode;
    use ventris_target::TargetProfile;

    fn simple_function() -> NativeFunction {
        let x = X86_64;
        let xor = x.lift_instruction(0x1000, &[0x31, 0xc0]).unwrap();
        let ret = x.lift_instruction(0x1002, &[0xc3]).unwrap();
        NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([(0x1000, xor), (0x1002, ret)]),
            edges: BTreeSet::from([(0x1000, 0x1002)]),
            calls: BTreeSet::new(),
        }
    }

    fn unary_and_division_function() -> NativeFunction {
        let value = Varnode::new(REGISTER_SPACE, 0, 4);
        let instruction = LiftedInstruction {
            address: 0x1000,
            bytes: vec![0],
            pcode: InstPcode {
                len: 1,
                space: RAM_SPACE,
                offset: 0x1000,
                ops: vec![
                    PcodeOp::new(op::COPY, Some(value), vec![Varnode::new(CONST_SPACE, 7, 4)]),
                    PcodeOp::new(op::INT_2COMP, Some(value), vec![value]),
                    PcodeOp::new(op::INT_NEGATE, Some(value), vec![value]),
                    PcodeOp::new(
                        op::INT_DIV,
                        Some(value),
                        vec![value, Varnode::new(CONST_SPACE, 2, 4)],
                    ),
                    PcodeOp::new(op::RETURN, None, vec![value]),
                ],
            },
            flow: Flow::Return,
            embedded_delay_slot_bytes: 0,
        };
        NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([(0x1000, instruction)]),
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        }
    }
    fn ppc_float_function(ops: Vec<PcodeOp>) -> NativeFunction {
        let instruction = LiftedInstruction {
            address: 0x1000,
            bytes: vec![0; 4],
            pcode: InstPcode {
                len: 4,
                space: RAM_SPACE,
                offset: 0x1000,
                ops,
            },
            flow: Flow::Return,
            embedded_delay_slot_bytes: 0,
        };
        NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([(0x1000, instruction)]),
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        }
    }

    #[test]
    fn native_ps2_does_not_treat_secondary_integer_return_register_as_scalar_return() {
        let v1 = Varnode::new(REGISTER_SPACE, 3 * 4, 4);
        let ra = Varnode::new(REGISTER_SPACE, 31 * 4, 4);
        let function = ppc_float_function(vec![
            PcodeOp::new(op::COPY, Some(v1), vec![Varnode::new(CONST_SPACE, 1, 4)]),
            PcodeOp::new(op::RETURN, None, vec![ra]),
        ]);
        let abi = TargetProfile::Ps2.spec().abi;
        let document = NativeDecompiler.decompile_with_abi_memory_and_symbols(
            Architecture::Mips32,
            &function,
            Some(&abi),
            None,
            None,
        );

        assert_eq!(document.return_type, Type::Void);
        assert_eq!(document.render().matches("return").count(), 1);
    }

    #[test]
    fn native_gamecube_float_arithmetic_recovers_float_signature() {
        let f1 = Varnode::new(REGISTER_SPACE, 0x204, 4);
        let f2 = Varnode::new(REGISTER_SPACE, 0x208, 4);
        let product = Varnode::new(UNIQUE_SPACE, 0, 4);
        let function = ppc_float_function(vec![
            PcodeOp::new(op::FLOAT_MULT, Some(product), vec![f1, f2]),
            PcodeOp::new(op::COPY, Some(f1), vec![product]),
            PcodeOp::new(op::RETURN, None, vec![f1]),
        ]);
        let abi = TargetProfile::GameCube.spec().abi;
        let document = NativeDecompiler.decompile_with_abi_memory_and_symbols(
            Architecture::GameCube,
            &function,
            Some(&abi),
            None,
            None,
        );

        assert_eq!(document.return_type, Type::Float(32));
        assert_eq!(
            document.parameters,
            vec![
                NativeParameter {
                    name: "farg0".into(),
                    ty: Type::Float(32),
                },
                NativeParameter {
                    name: "farg1".into(),
                    ty: Type::Float(32),
                },
            ]
        );
        assert!(document.render().contains("return farg0 * farg1;"));
        let explicit = document.render_normal_form(CompilerNormalForm::ExplicitResultCasts);
        assert!(
            explicit.contains("return (float)(farg0 * farg1);"),
            "{explicit}"
        );
        let candidates = document.compiler_candidates(&explicit);
        assert_eq!(
            candidates[0].normal_form,
            CompilerNormalForm::ExplicitResultCasts
        );
        assert!(candidates[0].score.exact);
    }

    #[test]
    fn known_gamecube_callee_prototype_materializes_untouched_arguments() {
        let target = 0x800a_67d8;
        let function = ppc_float_function(vec![
            PcodeOp::new(op::CALL, None, vec![Varnode::new(CONST_SPACE, target, 4)]),
            PcodeOp::new(
                op::RETURN,
                None,
                vec![Varnode::new(REGISTER_SPACE, 0x244, 4)],
            ),
        ]);
        let abi = TargetProfile::GameCube.spec().abi;
        let prototypes = BTreeMap::from([(
            target,
            NativeCallPrototype {
                return_type: Type::Void,
                parameters: vec![
                    Type::Pointer(Box::new(Type::Unknown)),
                    Type::Unsigned(8),
                    Type::Unsigned(32),
                ],
            },
        )]);
        let symbol = |address| (address == target).then(|| "TRK_fill_mem".to_string());
        let document = NativeDecompiler.decompile_with_call_prototypes(
            Architecture::GameCube,
            &function,
            Some(&abi),
            None,
            Some(&symbol),
            Some(&prototypes),
        );
        let source = document.render();

        assert!(
            source.contains("TRK_fill_mem(arg0, arg1, arg2);"),
            "{source}"
        );
        assert_eq!(
            document.parameters,
            vec![
                NativeParameter {
                    name: "arg0".into(),
                    ty: Type::Pointer(Box::new(Type::Unknown)),
                },
                NativeParameter {
                    name: "arg1".into(),
                    ty: Type::Unsigned(8),
                },
                NativeParameter {
                    name: "arg2".into(),
                    ty: Type::Unsigned(32),
                },
            ]
        );
    }

    #[test]
    fn native_gamecube_int_to_float_preserves_signed_conversion() {
        let r3 = Varnode::new(REGISTER_SPACE, 3 * 4, 4);
        let converted = Varnode::new(UNIQUE_SPACE, 0, 4);
        let f1 = Varnode::new(REGISTER_SPACE, 0x204, 4);
        let function = ppc_float_function(vec![
            PcodeOp::new(op::FLOAT_INT2FLOAT, Some(converted), vec![r3]),
            PcodeOp::new(op::COPY, Some(f1), vec![converted]),
            PcodeOp::new(op::RETURN, None, vec![f1]),
        ]);
        let abi = TargetProfile::GameCube.spec().abi;
        let document = NativeDecompiler.decompile_with_abi_memory_and_symbols(
            Architecture::GameCube,
            &function,
            Some(&abi),
            None,
            None,
        );
        let source = document.render();

        assert_eq!(document.return_type, Type::Float(32));
        assert!(
            source.contains("return (float)((int32_t)(arg0));"),
            "{source}"
        );
    }

    fn parse_public_hex(text: &str) -> Vec<u8> {
        text.split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect()
    }

    fn public_x86_function(hex: &str) -> NativeFunction {
        let bytes = parse_public_hex(hex);
        let lifter = X86_64;
        let mut instructions = BTreeMap::new();
        let mut edges = BTreeSet::new();
        let mut calls = BTreeSet::new();
        let mut offset = 0usize;
        let mut address = 0x1000;
        while offset < bytes.len() {
            let instruction = lifter
                .lift_instruction(address, &bytes[offset..])
                .unwrap_or_else(|error| {
                    panic!("x86 fixture offset {offset:#x}, address {address:#x}: {error}")
                });
            let next = address + instruction.bytes.len() as u64;
            if let Some(fallthrough) = instruction.flow.fallthrough() {
                edges.insert((address, fallthrough));
            }
            if let Some(target) = instruction.flow.branch_target() {
                if matches!(instruction.flow, ventris_lifter::Flow::Call { .. }) {
                    calls.insert(target);
                }
            }
            instructions.insert(address, instruction);
            offset += (next - address) as usize;
            address = next;
        }
        NativeFunction {
            entry: 0x1000,
            instructions,
            edges,
            calls,
        }
    }
    fn public_mips_function(hex: &str) -> NativeFunction {
        let bytes = parse_public_hex(hex);
        let lifter = Ps2;
        let mut instructions = BTreeMap::new();
        let mut edges = BTreeSet::new();
        let mut calls = BTreeSet::new();
        let mut offset = 0usize;
        let mut address = 0x1000;
        while offset < bytes.len() {
            let instruction = lifter.lift_instruction(address, &bytes[offset..]).unwrap();
            let next = address + instruction.bytes.len() as u64;
            if let Some(fallthrough) = instruction.flow.fallthrough() {
                edges.insert((address, fallthrough));
            }
            if let Some(target) = instruction.flow.branch_target() {
                if matches!(instruction.flow, ventris_lifter::Flow::Call { .. }) {
                    calls.insert(target);
                }
            }
            instructions.insert(address, instruction);
            offset += (next - address) as usize;
            address = next;
        }
        NativeFunction {
            entry: 0x1000,
            instructions,
            edges,
            calls,
        }
    }
    fn public_function(hex: &str, lifter: &dyn Lifter) -> NativeFunction {
        public_function_at(hex, lifter, 0x1000)
    }

    fn public_function_at(hex: &str, lifter: &dyn Lifter, entry: u64) -> NativeFunction {
        let bytes = parse_public_hex(hex);
        let mut instructions = BTreeMap::new();
        let mut edges = BTreeSet::new();
        let mut calls = BTreeSet::new();
        let mut offset = 0usize;
        let mut address = entry;
        while offset < bytes.len() {
            let instruction = lifter.lift_instruction(address, &bytes[offset..]).unwrap();
            let next = address + instruction.bytes.len() as u64;
            if let Some(fallthrough) = instruction.flow.fallthrough() {
                edges.insert((address, fallthrough));
            }
            if let Some(target) = instruction.flow.branch_target() {
                if matches!(instruction.flow, ventris_lifter::Flow::Call { .. }) {
                    calls.insert(target);
                }
            }
            instructions.insert(address, instruction);
            offset += (next - address) as usize;
            address = next;
        }
        NativeFunction {
            entry,
            instructions,
            edges,
            calls,
        }
    }

    fn decompile_for_target(
        hex: &str,
        lifter: &dyn Lifter,
        architecture: Architecture,
        target: TargetProfile,
    ) -> NativeDocument {
        NativeDecompiler.decompile_with_abi_memory_and_symbols(
            architecture,
            &public_function(hex, lifter),
            Some(&target.spec().abi),
            None,
            None,
        )
    }

    #[test]
    fn abi_parameters_fill_register_gaps_for_console_targets() {
        let ps1 = decompile_for_target(
            "01 00 c2 24 08 00 e0 03 00 00 00 00",
            &Ps1,
            Architecture::Ps1,
            TargetProfile::Ps1,
        )
        .render();
        assert!(
            ps1.contains("uint32_t sub_1000(uint32_t arg0, uint32_t arg1, uint32_t arg2)"),
            "{ps1}"
        );
        assert!(ps1.contains("return arg2 + 1;"), "{ps1}");

        let gamecube = decompile_for_target(
            "7c 63 2a 14 4e 80 00 20",
            &GameCube,
            Architecture::GameCube,
            TargetProfile::GameCube,
        )
        .render();
        assert!(
            gamecube.contains("uint32_t sub_1000(uint32_t arg0, uint32_t arg1, uint32_t arg2)"),
            "{gamecube}"
        );
        assert!(gamecube.contains("return arg0 + arg2;"), "{gamecube}");

        let gba = decompile_for_target(
            "80 18 70 47",
            &Thumb,
            Architecture::Thumb,
            TargetProfile::Gba,
        )
        .render();
        assert!(
            gba.contains("uint32_t sub_1000(uint32_t arg0, uint32_t arg1, uint32_t arg2)"),
            "{gba}"
        );
        assert!(gba.contains("return arg0 + arg2;"), "{gba}");
    }

    #[test]
    fn abi_stack_arguments_and_core_registers_are_exact() {
        let ps1 = decompile_for_target(
            "18 00 a2 8f 08 00 e0 03 00 00 00 00",
            &Ps1,
            Architecture::Ps1,
            TargetProfile::Ps1,
        )
        .render();
        assert!(
            ps1.contains(
                "uint32_t sub_1000(uint32_t arg0, uint32_t arg1, uint32_t arg2, \
                 uint32_t arg3, uint32_t arg4, uint32_t arg5, uint32_t arg6)"
            ),
            "{ps1}"
        );
        assert!(ps1.contains("return arg6;"), "{ps1}");

        let gamecube = decompile_for_target(
            "80 81 00 08 7c 64 1a 14 4e 80 00 20",
            &GameCube,
            Architecture::GameCube,
            TargetProfile::GameCube,
        )
        .render();
        assert!(
            gamecube.contains(
                "uint32_t sub_1000(uint32_t arg0, uint32_t arg1, uint32_t arg2, \
                 uint32_t arg3, uint32_t arg4, uint32_t arg5, uint32_t arg6, uint32_t arg7, \
                 uint32_t arg8)"
            ),
            "{gamecube}"
        );
        assert!(gamecube.contains("return arg8 + arg0;"), "{gamecube}");

        let r0 = Varnode::new(REGISTER_SPACE, 32, 4);
        let r2 = Varnode::new(REGISTER_SPACE, 40, 4);
        let function = NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([(
                0x1000,
                LiftedInstruction {
                    address: 0x1000,
                    bytes: vec![0; 2],
                    pcode: InstPcode {
                        len: 2,
                        space: RAM_SPACE,
                        offset: 0x1000,
                        ops: vec![
                            PcodeOp::new(op::INT_ADD, Some(r0), vec![r0, r2]),
                            PcodeOp::new(op::RETURN, None, vec![r0]),
                        ],
                    },
                    flow: Flow::Return,
                    embedded_delay_slot_bytes: 0,
                },
            )]),
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        };
        let gba = NativeDecompiler
            .decompile_with_abi_memory_and_symbols(
                Architecture::Thumb,
                &function,
                Some(&TargetProfile::Gba.spec().abi),
                None,
                None,
            )
            .render();
        assert!(
            gba.contains("uint32_t sub_1000(uint32_t arg0, uint32_t arg1, uint32_t arg2)"),
            "{gba}"
        );
        assert!(!gba.contains("farg"), "{gba}");
        assert!(gba.contains("return arg0 + arg2;"), "{gba}");
    }

    #[test]
    fn abi_prologue_saves_are_suppressed_but_real_stores_remain() {
        let sp = Varnode::new(REGISTER_SPACE, 29 * 4, 4);
        let fp = Varnode::new(REGISTER_SPACE, 30 * 4, 4);
        let ra = Varnode::new(REGISTER_SPACE, 31 * 4, 4);
        let s0 = Varnode::new(REGISTER_SPACE, 16 * 4, 4);
        let a0 = Varnode::new(REGISTER_SPACE, 4 * 4, 4);
        let pc = Varnode::new(REGISTER_SPACE, 128, 4);
        let save_ra = Varnode::new(UNIQUE_SPACE, 0, 4);
        let save_fp = Varnode::new(UNIQUE_SPACE, 4, 4);
        let save_s0 = Varnode::new(UNIQUE_SPACE, 8, 4);
        let local = Varnode::new(UNIQUE_SPACE, 12, 4);
        let unmatched_s0 = Varnode::new(UNIQUE_SPACE, 28, 4);
        let restore_ra = Varnode::new(UNIQUE_SPACE, 16, 4);
        let restore_fp = Varnode::new(UNIQUE_SPACE, 20, 4);
        let restore_s0 = Varnode::new(UNIQUE_SPACE, 24, 4);
        let ram = Varnode::new(CONST_SPACE, 417, 4);
        let frame = Varnode::new(CONST_SPACE, 0xffff_fff0, 4);
        let sixteen = Varnode::new(CONST_SPACE, 16, 4);
        let twelve = Varnode::new(CONST_SPACE, 12, 4);
        let eight = Varnode::new(CONST_SPACE, 8, 4);
        let twenty_four = Varnode::new(CONST_SPACE, 24, 4);
        let function = NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([(
                0x1000,
                LiftedInstruction {
                    address: 0x1000,
                    bytes: vec![0; 4],
                    pcode: InstPcode {
                        len: 4,
                        space: RAM_SPACE,
                        offset: 0x1000,
                        ops: vec![
                            PcodeOp::new(op::INT_ADD, Some(sp), vec![sp, frame]),
                            PcodeOp::new(op::INT_ADD, Some(save_ra), vec![sp, twelve]),
                            PcodeOp::new(op::STORE, None, vec![ram, save_ra, ra]),
                            PcodeOp::new(op::INT_ADD, Some(save_fp), vec![sp, eight]),
                            PcodeOp::new(op::STORE, None, vec![ram, save_fp, fp]),
                            PcodeOp::new(op::INT_ADD, Some(save_s0), vec![sp, sixteen]),
                            PcodeOp::new(op::STORE, None, vec![ram, save_s0, s0]),
                            PcodeOp::new(op::COPY, Some(fp), vec![sp]),
                            PcodeOp::new(
                                op::INT_ADD,
                                Some(local),
                                vec![sp, Varnode::new(CONST_SPACE, 20, 4)],
                            ),
                            PcodeOp::new(op::STORE, None, vec![ram, local, a0]),
                            PcodeOp::new(
                                op::STORE,
                                None,
                                vec![ram, Varnode::new(CONST_SPACE, 0x8000, 4), a0],
                            ),
                            PcodeOp::new(op::INT_ADD, Some(unmatched_s0), vec![sp, twenty_four]),
                            PcodeOp::new(op::STORE, None, vec![ram, unmatched_s0, s0]),
                            PcodeOp::new(op::INT_ADD, Some(restore_ra), vec![sp, twelve]),
                            PcodeOp::new(op::LOAD, Some(ra), vec![ram, restore_ra]),
                            PcodeOp::new(op::INT_ADD, Some(restore_fp), vec![sp, eight]),
                            PcodeOp::new(op::LOAD, Some(fp), vec![ram, restore_fp]),
                            PcodeOp::new(op::INT_ADD, Some(restore_s0), vec![sp, sixteen]),
                            PcodeOp::new(op::LOAD, Some(s0), vec![ram, restore_s0]),
                            PcodeOp::new(op::INT_ADD, Some(sp), vec![sp, sixteen]),
                            PcodeOp::new(op::RETURN, None, vec![pc]),
                        ],
                    },
                    flow: Flow::Return,
                    embedded_delay_slot_bytes: 0,
                },
            )]),
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        };
        let document = NativeDecompiler.decompile_with_abi_memory_and_symbols(
            Architecture::Ps1,
            &function,
            Some(&TargetProfile::Ps1.spec().abi),
            None,
            None,
        );
        let prologue_register_store = |statement: &NativeStatement| match statement {
            NativeStatement::Store {
                value: Expr::Register { name, .. },
                ..
            }
            | NativeStatement::Copy {
                source: Expr::Register { name, .. },
                ..
            } => matches!(name.as_str(), "sp" | "fp" | "ra" | "s0"),
            _ => false,
        };
        assert_eq!(
            document
                .statements
                .iter()
                .filter(|statement| prologue_register_store(statement))
                .count(),
            1,
            "{}",
            document.render()
        );
        let real_stores = document
            .statements
            .iter()
            .filter(|statement| {
                matches!(
                    statement,
                    NativeStatement::Store {
                        value: Expr::Parameter { name, .. },
                        ..
                    } if name == "arg0"
                )
            })
            .count();
        assert!(real_stores >= 2, "{}", document.render());
    }
    #[test]
    fn ssa_versions_reused_registers() {
        let register = Varnode::new(REGISTER_SPACE, 0, 4);
        let instruction = LiftedInstruction {
            address: 0x1000,
            bytes: vec![0],
            pcode: InstPcode {
                len: 1,
                space: RAM_SPACE,
                offset: 0x1000,
                ops: vec![
                    PcodeOp::new(
                        op::COPY,
                        Some(register),
                        vec![Varnode::new(CONST_SPACE, 1, 4)],
                    ),
                    PcodeOp::new(
                        op::COPY,
                        Some(register),
                        vec![Varnode::new(CONST_SPACE, 2, 4)],
                    ),
                ],
            },
            flow: Flow::Return,
            embedded_delay_slot_bytes: 0,
        };
        let function = NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([(0x1000, instruction)]),
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        };
        let versions = build_ssa(&function)
            .values
            .into_iter()
            .map(|value| value.version)
            .collect::<Vec<_>>();
        assert_eq!(versions.len(), 2);
        assert_ne!(versions[0], versions[1]);
    }

    #[test]
    fn native_decompiler_folds_zeroing_xor() {
        let mut decompiler = NativeDecompiler;
        let document = decompiler.decompile(Architecture::X86_64, &simple_function());
        let c = document.render();
        assert!(c.contains("return 0;"), "{c}");
        assert!(c.contains("sub_1000"), "{c}");
    }

    #[test]
    fn native_action_pipeline_folds_constant_unary_and_division_ops() {
        let mut decompiler = NativeDecompiler;
        let document = decompiler.decompile(Architecture::X86_64, &unary_and_division_function());
        let c = document.render();
        assert!(c.contains("return 3;"), "{c}");
        assert!(document.warnings.is_empty(), "{:?}", document.warnings);
    }

    #[test]
    fn native_renderer_preserves_opaque_callother() {
        let value = Varnode::new(REGISTER_SPACE, 0, 8);
        let instruction = LiftedInstruction {
            address: 0x1000,
            bytes: vec![0],
            pcode: InstPcode {
                len: 1,
                space: RAM_SPACE,
                offset: 0x1000,
                ops: vec![
                    PcodeOp::new(
                        op::CALLOTHER,
                        None,
                        vec![Varnode::new(CONST_SPACE, 3, 4), value],
                    ),
                    PcodeOp::new(op::RETURN, None, vec![Varnode::new(CONST_SPACE, 0, 8)]),
                ],
            },
            flow: Flow::Return,
            embedded_delay_slot_bytes: 0,
        };
        let function = NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([(0x1000, instruction)]),
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        };

        let document = NativeDecompiler.decompile(Architecture::X86_64, &function);
        let c = document.render();
        assert!(c.contains("sysenter(rax)"), "{c}");
        assert!(document.warnings.is_empty(), "{:?}", document.warnings);
    }

    #[test]
    fn native_renderer_preserves_computed_branch() {
        let target = Varnode::new(REGISTER_SPACE, 8, 8);
        let instruction = LiftedInstruction {
            address: 0x1000,
            bytes: vec![0],
            pcode: InstPcode {
                len: 1,
                space: RAM_SPACE,
                offset: 0x1000,
                ops: vec![PcodeOp::new(op::BRANCHIND, None, vec![target])],
            },
            flow: Flow::Return,
            embedded_delay_slot_bytes: 0,
        };
        let function = NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([(0x1000, instruction)]),
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        };

        let document = NativeDecompiler.decompile(Architecture::X86_64, &function);
        let c = document.render();
        assert!(c.contains("goto *(rcx);"), "{c}");
        assert!(!c.contains("indirect_call"), "{c}");
        assert!(document.warnings.is_empty(), "{:?}", document.warnings);
    }

    #[test]
    fn native_mips_calls_render_defined_o32_arguments_and_return_use() {
        let arguments = [
            Varnode::new(REGISTER_SPACE, 16, 4),
            Varnode::new(REGISTER_SPACE, 20, 4),
            Varnode::new(REGISTER_SPACE, 24, 4),
            Varnode::new(REGISTER_SPACE, 28, 4),
            Varnode::new(REGISTER_SPACE, 0x230, 4),
            Varnode::new(REGISTER_SPACE, 0x238, 4),
        ];
        let return_register = Varnode::new(REGISTER_SPACE, 8, 4);
        let make_function = |opcode, target| {
            let mut ops = arguments
                .iter()
                .copied()
                .map(|value| PcodeOp::new(op::COPY, Some(value), vec![value]))
                .collect::<Vec<_>>();
            let mut inputs = vec![target];
            inputs.extend(arguments);
            ops.push(PcodeOp::new(opcode, Some(return_register), inputs));
            ops.push(PcodeOp::new(
                op::STORE,
                None,
                vec![
                    Varnode::new(CONST_SPACE, 417, 4),
                    Varnode::new(CONST_SPACE, 0x8000, 4),
                    return_register,
                ],
            ));
            ops.push(PcodeOp::new(op::RETURN, None, vec![return_register]));
            NativeFunction {
                entry: 0x1000,
                instructions: BTreeMap::from([(
                    0x1000,
                    LiftedInstruction {
                        address: 0x1000,
                        bytes: vec![0; 4],
                        pcode: InstPcode {
                            len: 4,
                            space: RAM_SPACE,
                            offset: 0x1000,
                            ops,
                        },
                        flow: Flow::Return,
                        embedded_delay_slot_bytes: 0,
                    },
                )]),
                edges: BTreeSet::new(),
                calls: BTreeSet::new(),
            }
        };

        let direct = make_function(op::CALL, Varnode::new(CONST_SPACE, 0x2000, 4));
        let direct_document = NativeDecompiler.decompile(Architecture::Mips32, &direct);
        let direct_c = direct_document.render();
        assert!(
            direct_c.contains("uint32_t call_1000 = sub_2000(a0, a1, a2, a3, f12, f14)"),
            "{direct_c}"
        );
        assert!(direct_c.contains("DAT_8000 = call_1000"), "{direct_c}");
        assert!(
            direct_document
                .ssa
                .values
                .iter()
                .any(|value| value.origin == return_register)
        );

        let indirect = make_function(op::CALLIND, Varnode::new(REGISTER_SPACE, 25 * 4, 4));
        let indirect_c = NativeDecompiler
            .decompile(Architecture::Mips32, &indirect)
            .render();
        assert!(
            indirect_c.contains("t9(a0, a1, a2, a3, f12, f14);"),
            "{indirect_c}"
        );
    }

    #[test]
    fn native_mips_call_arguments_are_invalidated_after_each_call() {
        let a0 = Varnode::new(REGISTER_SPACE, 16, 4);
        let v0 = Varnode::new(REGISTER_SPACE, 8, 4);
        let function = NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([(
                0x1000,
                LiftedInstruction {
                    address: 0x1000,
                    bytes: vec![0; 4],
                    pcode: InstPcode {
                        len: 4,
                        space: RAM_SPACE,
                        offset: 0x1000,
                        ops: vec![
                            PcodeOp::new(op::COPY, Some(a0), vec![a0]),
                            PcodeOp::new(
                                op::CALL,
                                Some(v0),
                                vec![Varnode::new(CONST_SPACE, 0x2000, 4), a0],
                            ),
                            PcodeOp::new(
                                op::CALL,
                                Some(v0),
                                vec![Varnode::new(CONST_SPACE, 0x3000, 4), a0],
                            ),
                            PcodeOp::new(op::RETURN, None, vec![v0]),
                        ],
                    },
                    flow: Flow::Return,
                    embedded_delay_slot_bytes: 0,
                },
            )]),
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        };

        let candidate = NativeDecompiler
            .decompile(Architecture::Mips32, &function)
            .render();
        assert!(candidate.contains("sub_2000(a0);"), "{candidate}");
        assert!(candidate.contains("sub_3000();"), "{candidate}");
        assert!(!candidate.contains("sub_3000(a0);"), "{candidate}");
    }

    #[test]
    fn native_mips_call_observes_argument_defined_in_delay_slot() {
        let a0 = Varnode::new(REGISTER_SPACE, 16, 4);
        let v0 = Varnode::new(REGISTER_SPACE, 8, 4);
        let function = NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([
                (
                    0x1000,
                    LiftedInstruction {
                        address: 0x1000,
                        bytes: vec![0; 4],
                        pcode: InstPcode {
                            len: 4,
                            space: RAM_SPACE,
                            offset: 0x1000,
                            ops: vec![PcodeOp::new(
                                op::CALL,
                                Some(v0),
                                vec![Varnode::new(CONST_SPACE, 0x2000, 4), a0],
                            )],
                        },
                        flow: Flow::Call {
                            target: 0x2000,
                            fallthrough: 0x1004,
                        },
                        embedded_delay_slot_bytes: 0,
                    },
                ),
                (
                    0x1004,
                    LiftedInstruction {
                        address: 0x1004,
                        bytes: vec![0; 4],
                        pcode: InstPcode {
                            len: 4,
                            space: RAM_SPACE,
                            offset: 0x1004,
                            ops: vec![PcodeOp::new(
                                op::COPY,
                                Some(a0),
                                vec![Varnode::new(CONST_SPACE, 42, 4)],
                            )],
                        },
                        flow: Flow::FallThrough(0x1008),
                        embedded_delay_slot_bytes: 0,
                    },
                ),
                (
                    0x1008,
                    LiftedInstruction {
                        address: 0x1008,
                        bytes: vec![0; 4],
                        pcode: InstPcode {
                            len: 4,
                            space: RAM_SPACE,
                            offset: 0x1008,
                            ops: vec![PcodeOp::new(op::RETURN, None, vec![v0])],
                        },
                        flow: Flow::Return,
                        embedded_delay_slot_bytes: 0,
                    },
                ),
            ]),
            edges: BTreeSet::new(),
            calls: BTreeSet::from([0x2000]),
        };

        let candidate = NativeDecompiler
            .decompile(Architecture::Mips32, &function)
            .render();
        assert!(candidate.contains("sub_2000(0x2a);"), "{candidate}");
        assert!(!candidate.contains("sub_2000();"), "{candidate}");
    }
    #[test]
    fn native_mips_return_executes_delay_slot_before_return() {
        let function = NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([
                (
                    0x1000,
                    LiftedInstruction {
                        address: 0x1000,
                        bytes: vec![0; 4],
                        pcode: InstPcode {
                            len: 4,
                            space: RAM_SPACE,
                            offset: 0x1000,
                            ops: vec![PcodeOp::new(op::RETURN, None, vec![])],
                        },
                        flow: Flow::Return,
                        embedded_delay_slot_bytes: 0,
                    },
                ),
                (
                    0x1004,
                    LiftedInstruction {
                        address: 0x1004,
                        bytes: vec![0; 4],
                        pcode: InstPcode {
                            len: 4,
                            space: RAM_SPACE,
                            offset: 0x1004,
                            ops: vec![PcodeOp::new(
                                op::STORE,
                                None,
                                vec![
                                    Varnode::new(CONST_SPACE, 417, 4),
                                    Varnode::new(CONST_SPACE, 0x8000, 4),
                                    Varnode::new(CONST_SPACE, 0, 1),
                                ],
                            )],
                        },
                        flow: Flow::FallThrough(0x1008),
                        embedded_delay_slot_bytes: 0,
                    },
                ),
            ]),
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        };

        let candidate = NativeDecompiler
            .decompile(Architecture::Mips32, &function)
            .render();
        let store = candidate
            .find("= 0;")
            .unwrap_or_else(|| panic!("{candidate}"));
        let return_statement = candidate.find("return;").expect("return statement");
        assert!(store < return_statement, "{candidate}");
    }

    #[test]
    fn native_n64_executes_call_and_return_delay_slots_in_order() {
        let store = |address, value| {
            PcodeOp::new(
                op::STORE,
                None,
                vec![
                    Varnode::new(CONST_SPACE, 417, 8),
                    Varnode::new(CONST_SPACE, address, 8),
                    Varnode::new(CONST_SPACE, value, 1),
                ],
            )
        };
        let instruction = |address, ops, flow| LiftedInstruction {
            address,
            bytes: vec![0; 4],
            pcode: InstPcode {
                len: 4,
                space: RAM_SPACE,
                offset: address,
                ops,
            },
            flow,
            embedded_delay_slot_bytes: 0,
        };
        let function = NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([
                (
                    0x1000,
                    instruction(
                        0x1000,
                        vec![PcodeOp::new(
                            op::CALL,
                            None,
                            vec![Varnode::new(CONST_SPACE, 0x2000, 8)],
                        )],
                        Flow::Call {
                            target: 0x2000,
                            fallthrough: 0x1004,
                        },
                    ),
                ),
                (
                    0x1004,
                    instruction(0x1004, vec![store(0x8000, 1)], Flow::FallThrough(0x1008)),
                ),
                (
                    0x1008,
                    instruction(
                        0x1008,
                        vec![PcodeOp::new(op::RETURN, None, vec![])],
                        Flow::Return,
                    ),
                ),
                (
                    0x100c,
                    instruction(0x100c, vec![store(0x8001, 0)], Flow::FallThrough(0x1010)),
                ),
            ]),
            edges: BTreeSet::new(),
            calls: BTreeSet::from([0x2000]),
        };

        let candidate = NativeDecompiler
            .decompile(Architecture::N64, &function)
            .render();
        let call_delay = candidate
            .find("= 1;")
            .unwrap_or_else(|| panic!("{candidate}"));
        let call = candidate
            .find("sub_2000();")
            .unwrap_or_else(|| panic!("{candidate}"));
        let return_delay = candidate
            .find("= 0;")
            .unwrap_or_else(|| panic!("{candidate}"));
        let return_statement = candidate
            .find("return;")
            .unwrap_or_else(|| panic!("{candidate}"));
        assert!(
            call_delay < call && call < return_delay && return_delay < return_statement,
            "{candidate}"
        );
    }

    #[test]
    fn thumb_start_timer_folds_literal_and_preserves_mmio_store() {
        let function = public_function_at(
            include_str!("../testdata/public/thumb_start_timer.hex"),
            &Thumb,
            0x0800_0554,
        );
        let read_memory =
            |address, width| (address == 0x0800_055c && width == 4).then_some(0x0400_0106);
        let is_volatile = |address, _width| (0x0400_0000..0x0400_0400).contains(&address);
        let memory = NativeMemory {
            read: &read_memory,
            is_volatile: &is_volatile,
        };
        let candidate = NativeDecompiler
            .decompile_with_memory(Architecture::Thumb, &function, Some(&memory))
            .render();
        let oracle = include_str!("../testdata/oracle/thumb_start_timer.c");
        let score = score_c(oracle, &candidate);
        assert!(score.exact, "score={score:?}\n{candidate}");
    }

    #[test]
    fn console_subregister_narrowing_respects_endianness() {
        let little_endian_cases = [
            (
                Architecture::Mips32,
                &Mips32 as &dyn Lifter,
                include_str!("../testdata/public/mips_le_subregister_store.hex"),
            ),
            (
                Architecture::Ps1,
                &Ps1 as &dyn Lifter,
                include_str!("../testdata/public/mips_le_subregister_store.hex"),
            ),
        ];
        for (architecture, lifter, hex) in little_endian_cases {
            let function = public_function_at(hex, lifter, 0x1000);
            let candidate = NativeDecompiler.decompile(architecture, &function).render();
            // `sb` stores the low byte of 0x1234; Ghidra renders `= 0x34`.
            assert!(
                candidate.contains("= 0x34;"),
                "{architecture:?}\n{candidate}"
            );
            assert!(
                !candidate.contains("= 0x1234;"),
                "{architecture:?}\n{candidate}"
            );
            assert!(
                !candidate.contains("= v0;"),
                "{architecture:?}\n{candidate}"
            );
        }

        let big_endian_cases = [
            (
                Architecture::Mips32Be,
                &Mips32Be as &dyn Lifter,
                include_str!("../testdata/public/mips_be_subregister_store.hex"),
            ),
            (
                Architecture::N64,
                &N64 as &dyn Lifter,
                include_str!("../testdata/public/mips_be_subregister_store.hex"),
            ),
        ];
        for (architecture, lifter, hex) in big_endian_cases {
            let function = public_function_at(hex, lifter, 0x1000);
            let candidate = NativeDecompiler.decompile(architecture, &function).render();
            assert!(candidate.contains("= v0;"), "{architecture:?}\n{candidate}");
            assert!(
                !candidate.contains("= 0x1234;"),
                "{architecture:?}\n{candidate}"
            );
        }
    }

    #[test]
    fn native_infers_return_width_from_pcode_value() {
        let mut decompiler = NativeDecompiler;
        let document = decompiler.decompile(
            Architecture::X86_64,
            &public_x86_function(include_str!("../testdata/public/x86_add.hex")),
        );
        assert_eq!(document.return_type, Type::Unsigned(32));
        assert!(
            document.render().contains("uint32_t sub_1000"),
            "{}",
            document.render()
        );
        assert!(document.warnings.is_empty(), "{:?}", document.warnings);
    }

    #[test]
    fn native_rendering_keeps_branch_labels_and_direct_calls() {
        let x = X86_64;
        let branch = x.lift_instruction(0x1000, &[0x75, 0x02]).unwrap();
        let call = x
            .lift_instruction(0x1002, &[0xe8, 0xfb, 0x0f, 0, 0])
            .unwrap();
        let ret = x.lift_instruction(0x1007, &[0xc3]).unwrap();
        let function = NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([(0x1000, branch), (0x1002, call), (0x1007, ret)]),
            edges: BTreeSet::from([(0x1000, 0x1002), (0x1000, 0x1004), (0x1002, 0x1007)]),
            calls: BTreeSet::from([0x2002]),
        };
        let mut decompiler = NativeDecompiler;
        let c = decompiler
            .decompile(Architecture::X86_64, &function)
            .render();
        assert!(c.contains("if ("));
        assert!(c.contains("goto loc_1004"));
        assert!(c.contains("sub_2002();"));
    }

    #[test]
    fn native_structures_conditional_join_into_if_else() {
        let call = |target| {
            NativeStatement::Call(Expr::Call {
                target: Some(target),
                callee: None,
                args: Vec::new(),
            })
        };
        let statements = structure_control_flow(vec![
            NativeStatement::IfGoto {
                condition: Expr::Register {
                    name: "flag".into(),
                    width: 1,
                },
                target: 0x1020,
            },
            call(0x2000),
            NativeStatement::Goto(0x1030),
            NativeStatement::Label(0x1020),
            call(0x2010),
            NativeStatement::Label(0x1030),
            NativeStatement::Return(None),
        ]);
        assert!(matches!(
            &statements[0],
            NativeStatement::IfElse {
                then_body,
                else_body,
                ..
            } if then_body.len() == 1 && else_body.len() == 1
        ));
        let document = NativeDocument {
            name: "sub_1000".into(),
            return_type: Type::Void,
            parameters: Vec::new(),
            statements,
            ssa: SsaFunction::default(),
            types: Vec::new(),
            warnings: Vec::new(),
            prototype: None,
            scope: None,
        };
        let c = document.render();
        assert!(c.contains("if (flag) {"), "{c}");
        assert!(c.contains("sub_2010();"), "{c}");
        assert!(c.contains("} else {"), "{c}");
        assert!(c.contains("sub_2000();"), "{c}");
    }

    #[test]
    fn native_if_else_fold_keeps_externally_referenced_labels() {
        for (external_target, external_branch) in [
            (0x1020, NativeStatement::Goto(0x1020)),
            (
                0x1030,
                NativeStatement::IfGoto {
                    condition: Expr::Register {
                        name: "again".into(),
                        width: 1,
                    },
                    target: 0x1030,
                },
            ),
        ] {
            let call = |target| {
                NativeStatement::Call(Expr::Call {
                    target: Some(target),
                    callee: None,
                    args: Vec::new(),
                })
            };
            let statements = structure_control_flow(vec![
                NativeStatement::IfGoto {
                    condition: Expr::Register {
                        name: "flag".into(),
                        width: 1,
                    },
                    target: 0x1020,
                },
                call(0x2000),
                NativeStatement::Goto(0x1030),
                NativeStatement::Label(0x1020),
                call(0x2010),
                NativeStatement::Label(0x1030),
                external_branch,
                NativeStatement::Return(None),
            ]);
            assert!(
                statements
                    .iter()
                    .any(|statement| matches!(statement, NativeStatement::Label(label) if *label == external_target)),
                "missing externally referenced label {external_target:#x}: {statements:?}"
            );
            assert!(
                !statements
                    .iter()
                    .any(|statement| matches!(statement, NativeStatement::IfElse { .. })),
                "unsafe fold retained for {external_target:#x}: {statements:?}"
            );
            let document = NativeDocument {
                name: "sub_1000".into(),
                return_type: Type::Void,
                parameters: Vec::new(),
                statements,
                ssa: SsaFunction::default(),
                types: Vec::new(),
                warnings: Vec::new(),
                prototype: None,
                scope: None,
            };
            let c = document.render();
            assert!(c.contains(&format!("goto loc_{external_target:x};")), "{c}");
            assert!(c.contains(&format!("loc_{external_target:x}:")), "{c}");
        }
    }
    #[test]
    fn native_structures_branch_to_terminal_return_as_early_return() {
        let condition = Expr::Register {
            name: "flag".into(),
            width: 1,
        };
        let body = NativeStatement::Expression(Expr::Call {
            target: Some(0x2000),
            callee: None,
            args: Vec::new(),
        });
        let statements = structure_control_flow(vec![
            NativeStatement::IfGoto {
                condition: condition.clone(),
                target: 0x1020,
            },
            body,
            NativeStatement::Label(0x1020),
            NativeStatement::Return(None),
        ]);
        assert!(matches!(
            statements.as_slice(),
            [
                NativeStatement::IfReturn {
                    condition: observed,
                    value: None,
                },
                NativeStatement::Expression(_),
                NativeStatement::Return(None),
            ] if observed == &condition
        ));
        let document = NativeDocument {
            name: "sub_1000".into(),
            return_type: Type::Void,
            parameters: Vec::new(),
            statements,
            ssa: SsaFunction::default(),
            types: Vec::new(),
            warnings: Vec::new(),
            prototype: None,
            scope: None,
        };
        let c = document.render();
        assert!(c.contains("if (flag) {"), "{c}");
        assert!(c.contains("return;"), "{c}");
        assert!(!c.contains("goto"), "{c}");
        assert!(!c.contains("loc_1020"), "{c}");
    }
    #[test]
    fn native_indirect_goto_blocks_label_eliminating_folds() {
        let computed = || {
            NativeStatement::IndirectGoto(Expr::Register {
                name: "switch_target".into(),
                width: 4,
            })
        };
        let early_return = vec![
            NativeStatement::IfGoto {
                condition: Expr::Register {
                    name: "flag".into(),
                    width: 1,
                },
                target: 0x1020,
            },
            NativeStatement::Return(Some(Expr::Constant { value: 1, width: 4 })),
            NativeStatement::Label(0x1020),
            NativeStatement::Return(Some(Expr::Constant { value: 0, width: 4 })),
            computed(),
        ];
        let if_else = vec![
            NativeStatement::IfGoto {
                condition: Expr::Register {
                    name: "flag".into(),
                    width: 1,
                },
                target: 0x2020,
            },
            NativeStatement::Call(Expr::Call {
                target: Some(0x3000),
                callee: None,
                args: Vec::new(),
            }),
            NativeStatement::Goto(0x2030),
            NativeStatement::Label(0x2020),
            NativeStatement::Call(Expr::Call {
                target: Some(0x3010),
                callee: None,
                args: Vec::new(),
            }),
            NativeStatement::Label(0x2030),
            computed(),
            NativeStatement::Return(None),
        ];
        for (input, required_labels) in [
            (early_return, vec![0x1020]),
            (if_else, vec![0x2020, 0x2030]),
        ] {
            let statements = structure_control_flow(input);
            assert!(
                !statements.iter().any(|statement| matches!(
                    statement,
                    NativeStatement::IfReturn { .. } | NativeStatement::IfElse { .. }
                )),
                "label-eliminating fold survived indirect branch: {statements:?}"
            );
            for label in required_labels {
                assert!(
                    statements.iter().any(
                        |statement| matches!(statement, NativeStatement::Label(address) if *address == label)
                    ),
                    "missing label {label:#x}: {statements:?}"
                );
            }
            let document = NativeDocument {
                name: "sub_1000".into(),
                return_type: Type::Void,
                parameters: Vec::new(),
                statements,
                ssa: SsaFunction::default(),
                types: Vec::new(),
                warnings: Vec::new(),
                prototype: None,
                scope: None,
            };
            let c = document.render();
            assert!(c.contains("goto *(switch_target);"), "{c}");
        }
    }
    #[test]
    fn native_keeps_return_label_referenced_by_an_external_branch() {
        let statements = structure_control_flow(vec![
            NativeStatement::Goto(0x1020),
            NativeStatement::IfGoto {
                condition: Expr::Register {
                    name: "flag".into(),
                    width: 1,
                },
                target: 0x1020,
            },
            NativeStatement::Expression(Expr::Call {
                target: Some(0x2000),
                callee: None,
                args: Vec::new(),
            }),
            NativeStatement::Label(0x1020),
            NativeStatement::Return(None),
        ]);
        assert!(
            statements
                .iter()
                .any(|statement| matches!(statement, NativeStatement::Label(0x1020)))
        );
        let document = NativeDocument {
            name: "sub_1000".into(),
            return_type: Type::Void,
            parameters: Vec::new(),
            statements,
            ssa: SsaFunction::default(),
            types: Vec::new(),
            warnings: Vec::new(),
            prototype: None,
            scope: None,
        };
        let c = document.render();
        assert_eq!(c.matches("goto loc_1020;").count(), 2, "{c}");
        assert!(c.contains("loc_1020:"), "{c}");
    }

    #[test]
    fn native_renders_resolved_symbols() {
        let resolve = |address| match address {
            0x2000 => Some("g-score".to_string()),
            0x3000 => Some("update_score".to_string()),
            _ => None,
        };
        let global = named_symbol(Some(&resolve), 0x2000, 4).unwrap();
        let call_target = named_symbol(Some(&resolve), 0x3000, 0).unwrap();
        let document = NativeDocument {
            name: "update".into(),
            return_type: Type::Void,
            parameters: Vec::new(),
            statements: vec![
                NativeStatement::Store {
                    address: global,
                    value: Expr::Register {
                        name: "eax".into(),
                        width: 4,
                    },
                    width: 4,
                    volatile: false,
                },
                NativeStatement::Call(Expr::Call {
                    target: Some(0x3000),
                    callee: Some(Box::new(call_target)),
                    args: Vec::new(),
                }),
                NativeStatement::Return(None),
            ],
            ssa: SsaFunction::default(),
            types: Vec::new(),
            warnings: Vec::new(),
            prototype: None,
            scope: None,
        };
        let c = document.render();
        assert!(c.contains("g_score = eax;"), "{c}");
        assert!(c.contains("update_score();"), "{c}");
    }

    #[test]
    fn native_renders_aggregate_copy_without_scalarizing() {
        let document = NativeDocument {
            name: "copy".into(),
            return_type: Type::Void,
            parameters: Vec::new(),
            statements: vec![
                NativeStatement::Copy {
                    destination: Expr::Global {
                        name: "dst".into(),
                        address: 0x2000,
                        width: 16,
                    },
                    source: Expr::Load {
                        address: Box::new(Expr::Constant {
                            value: 0x3000,
                            width: 8,
                        }),
                        width: 16,
                    },
                    width: 16,
                    volatile: false,
                },
                NativeStatement::Return(None),
            ],
            ssa: SsaFunction::default(),
            types: Vec::new(),
            warnings: Vec::new(),
            prototype: None,
            scope: None,
        };
        let c = document.render();
        assert!(
            c.contains("__builtin_memcpy(&dst, (const void *)(uintptr_t)(0x3000), 16);"),
            "{c}"
        );
        assert!(!c.contains("uint64_t *)(uintptr_t)(0x3000)"), "{c}");
    }

    #[test]
    fn type_solver_keeps_width_facts() {
        let mut solver = TypeSolver::default();
        solver.constrain(Varnode::new(REGISTER_SPACE, 0, 4), Type::Unsigned(32));
        assert_eq!(solver.solve()[0].ty, Type::Unsigned(32));
    }
    #[test]
    fn ssa_propagates_widths_across_uses() {
        let ssa = build_ssa(&public_x86_function(include_str!(
            "../testdata/public/x86_add.hex"
        )));
        assert!(ssa.constraints.iter().any(|constraint| {
            constraint.value == Varnode::new(REGISTER_SPACE, 48, 4)
                && constraint.ty == Type::Unsigned(32)
        }));
        assert!(ssa.constraints.iter().any(|constraint| {
            constraint.value == Varnode::new(REGISTER_SPACE, 56, 4)
                && constraint.ty == Type::Unsigned(32)
        }));
        let mut solver = TypeSolver::default();
        for constraint in &ssa.constraints {
            solver.constrain(constraint.value, constraint.ty.clone());
        }
        assert_eq!(
            solver
                .solve()
                .into_iter()
                .find(|constraint| constraint.value == Varnode::new(REGISTER_SPACE, 48, 4))
                .map(|constraint| constraint.ty),
            Some(Type::Unsigned(32))
        );
    }

    #[test]
    fn type_solver_merges_unknown_and_pointer_facts() {
        let value = Varnode::new(REGISTER_SPACE, 0, 8);
        let mut solver = TypeSolver::default();
        solver.constrain(value, Type::Unknown);
        solver.constrain(value, Type::Pointer(Box::new(Type::Unsigned(8))));
        assert_eq!(
            solver.solve()[0].ty,
            Type::Pointer(Box::new(Type::Unsigned(8)))
        );
    }

    #[test]
    fn oracle_body_score_ignores_generated_names_but_checks_semantics() {
        let mut decompiler = NativeDecompiler;
        let document = decompiler.decompile(Architecture::X86_64, &simple_function());
        let oracle = include_str!("../testdata/oracle/zero_return.c");
        let score = score_c(oracle, &document.render());
        assert!(score.exact, "{score:?}\n{}", document.render());
        assert_eq!(score.ratio_milli(), 1000);
    }

    #[test]
    fn oracle_body_score_preserves_literal_values_and_identifier_bindings() {
        assert!(!score_c("void f(void) { return 0; }", "void g(void) { return 1; }").exact);
        assert!(
            !score_c(
                "void f(void) { return left - left; }",
                "void g(void) { return left - right; }"
            )
            .exact
        );
        assert!(
            score_c(
                "void f(void) { return left - left; }",
                "void g(void) { return first - first; }"
            )
            .exact
        );
        assert!(
            score_c(
                "void f(void) { int unused; return left; }",
                "void g(void) { uint32_t generated; return first; }"
            )
            .exact
        );
        assert!(
            !score_c(
                "void f(void) { return left + right; }",
                "void g(void) { return left - right; }"
            )
            .exact
        );
        assert!(
            !score_c(
                "void f(void) { if (left) { return 1; } else { return 0; } }",
                "void g(void) { if (left) { return 1; } return 0; }"
            )
            .exact
        );
        assert!(
            !score_c(
                "void f(void) { return left + right; }",
                "void g(void) { return left + right; return 0; }"
            )
            .exact
        );
        assert!(
            score_c(
                "void f(void) { return 0x2a; }",
                "void g(void) { return 42; }"
            )
            .exact
        );
    }
    #[test]
    fn oracle_corpus_covers_branch_and_return_architectures() {
        let x = X86_64;
        let branch = x.lift_instruction(0x1000, &[0x75, 0x02]).unwrap();
        let call = x
            .lift_instruction(0x1002, &[0xe8, 0xfb, 0x0f, 0, 0])
            .unwrap();
        let ret = x.lift_instruction(0x1007, &[0xc3]).unwrap();
        let branch_function = NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([(0x1000, branch), (0x1002, call), (0x1007, ret)]),
            edges: BTreeSet::from([(0x1000, 0x1002), (0x1000, 0x1004), (0x1002, 0x1007)]),
            calls: BTreeSet::from([0x2002]),
        };
        let branch_candidate = NativeDecompiler
            .decompile(Architecture::X86_64, &branch_function)
            .render();
        let branch_score = score_c(
            include_str!("../testdata/oracle/branch_call.c"),
            &branch_candidate,
        );
        assert!(branch_score.exact, "{branch_score:?}\n{branch_candidate}");
        let cases = [
            (
                Architecture::AArch64,
                AArch64
                    .lift_instruction(0x2000, &0xaa1f_03e0u32.to_le_bytes())
                    .unwrap(),
                AArch64
                    .lift_instruction(0x2004, &0xd65f_03c0u32.to_le_bytes())
                    .unwrap(),
                include_str!("../testdata/public/aarch64_zero.c"),
            ),
            (
                Architecture::Arm32,
                Arm32
                    .lift_instruction(0x3000, &0xe3a0_0000u32.to_le_bytes())
                    .unwrap(),
                Arm32
                    .lift_instruction(0x3004, &0xe12f_ff1eu32.to_le_bytes())
                    .unwrap(),
                include_str!("../testdata/oracle/zero_return_arm32.c"),
            ),
            (
                Architecture::Rv64,
                Rv64.lift_instruction(0x4000, &0x0000_0513u32.to_le_bytes())
                    .unwrap(),
                Rv64.lift_instruction(0x4004, &0x0000_8067u32.to_le_bytes())
                    .unwrap(),
                include_str!("../testdata/oracle/zero_return_rv64.c"),
            ),
            (
                Architecture::Ppc32,
                Ppc32
                    .lift_instruction(0x5000, &0x3860_0000u32.to_be_bytes())
                    .unwrap(),
                Ppc32
                    .lift_instruction(0x5004, &0x4e80_0020u32.to_be_bytes())
                    .unwrap(),
                include_str!("../testdata/oracle/zero_return_ppc32.c"),
            ),
            (
                Architecture::Mips32,
                Mips32
                    .lift_instruction(0x6000, &0x2402_0000u32.to_le_bytes())
                    .unwrap(),
                Mips32
                    .lift_instruction(0x6004, &0x03e0_0008u32.to_le_bytes())
                    .unwrap(),
                include_str!("../testdata/oracle/zero_return_mips32.c"),
            ),
        ];
        for (architecture, first, second, oracle) in cases {
            let first_address = first.address;
            let second_address = second.address;
            let function = NativeFunction {
                entry: first_address,
                instructions: BTreeMap::from([(first_address, first), (second_address, second)]),
                edges: BTreeSet::from([(first_address, second_address)]),
                calls: BTreeSet::new(),
            };
            let score = score_c(
                oracle,
                &NativeDecompiler.decompile(architecture, &function).render(),
            );
            assert!(score.exact, "{architecture:?}: {score:?}");
        }
    }

    #[test]
    fn native_decompiler_tracks_32_and_64_bit_return_conventions() {
        let cases = [
            (
                Architecture::Arm32,
                Arm32
                    .lift_instruction(0x3000, &0xe3a0_0000u32.to_le_bytes())
                    .unwrap(),
                Arm32
                    .lift_instruction(0x3004, &0xe12f_ff1eu32.to_le_bytes())
                    .unwrap(),
            ),
            (
                Architecture::Rv64,
                Rv64.lift_instruction(0x4000, &0x0000_0513u32.to_le_bytes())
                    .unwrap(),
                Rv64.lift_instruction(0x4004, &0x0000_8067u32.to_le_bytes())
                    .unwrap(),
            ),
            (
                Architecture::Ppc32,
                Ppc32
                    .lift_instruction(0x5000, &0x3860_0000u32.to_be_bytes())
                    .unwrap(),
                Ppc32
                    .lift_instruction(0x5004, &0x4e80_0020u32.to_be_bytes())
                    .unwrap(),
            ),
        ];
        for (architecture, first, second) in cases {
            let first_address = first.address;
            let second_address = second.address;
            let function = NativeFunction {
                entry: first_address,
                instructions: BTreeMap::from([(first_address, first), (second_address, second)]),
                edges: BTreeSet::from([(first_address, second_address)]),
                calls: BTreeSet::new(),
            };
            let mut decompiler = NativeDecompiler;
            let document = decompiler.decompile(architecture, &function);
            assert!(
                document.render().contains("return 0;"),
                "{}",
                document.render()
            );
            assert_eq!(
                document.return_type,
                Type::Unsigned(if architecture == Architecture::Rv64 {
                    64
                } else {
                    32
                })
            );
        }
    }
    #[test]
    fn public_native_corpus_matches_ghidra_oracles() {
        let cases = [
            (
                include_str!("../testdata/public/x86_zero.hex"),
                include_str!("../testdata/public/x86_zero.c"),
            ),
            (
                include_str!("../testdata/public/x86_add.hex"),
                include_str!("../testdata/public/x86_add.c"),
            ),
            (
                include_str!("../testdata/public/x86_call.hex"),
                include_str!("../testdata/public/x86_call.c"),
            ),
            (
                include_str!("../testdata/public/x86_store.hex"),
                include_str!("../testdata/public/x86_store.c"),
            ),
            (
                include_str!("../testdata/public/x86_branch.hex"),
                include_str!("../testdata/public/x86_branch.c"),
            ),
            (
                include_str!("../testdata/public/x86_logic.hex"),
                include_str!("../testdata/public/x86_logic.c"),
            ),
            (
                include_str!("../testdata/public/x86_global_load.hex"),
                include_str!("../testdata/public/x86_global_load.c"),
            ),
            (
                include_str!("../testdata/public/x86_mingw_add.hex"),
                include_str!("../testdata/public/x86_mingw_add.c"),
            ),
            (
                include_str!("../testdata/public/x86_mingw_branch.hex"),
                include_str!("../testdata/public/x86_mingw_branch.c"),
            ),
        ];
        for (hex, oracle) in cases {
            let function = public_x86_function(hex);
            let candidate = NativeDecompiler.decompile(Architecture::X86_64, &function);
            let score = score_c(oracle, &candidate.render());
            assert!(score.exact, "{hex}: {score:?}\n{}", candidate.render());
        }

        let mips_cases = [
            (
                include_str!("../testdata/public/mips_ps2_fade_start.hex"),
                include_str!("../testdata/public/mips_ps2_fade_start.c"),
                false,
            ),
            (
                include_str!("../testdata/public/mips_ps2_process_exists.hex"),
                include_str!("../testdata/public/mips_ps2_process_exists.c"),
                true,
            ),
        ];
        for (hex, oracle, with_abi) in mips_cases {
            let function = public_mips_function(hex);
            let abi = TargetProfile::Ps2.spec().abi;
            let candidate = if with_abi {
                NativeDecompiler.decompile_with_abi_memory_and_symbols(
                    Architecture::Ps2,
                    &function,
                    Some(&abi),
                    None,
                    None,
                )
            } else {
                NativeDecompiler.decompile(Architecture::Ps2, &function)
            };
            let score = score_c(oracle, &candidate.render());
            assert!(score.exact, "{hex}: {score:?}\n{}", candidate.render());
        }

        let processor_cases = [
            (
                Architecture::Ps1,
                &Ps1 as &dyn Lifter,
                include_str!("../testdata/public/ps1_return.hex"),
                include_str!("../testdata/public/ps1_return.c"),
            ),
            (
                Architecture::N64,
                &N64 as &dyn Lifter,
                include_str!("../testdata/public/n64_return.hex"),
                include_str!("../testdata/public/n64_return.c"),
            ),
            (
                Architecture::GameCube,
                &GameCube as &dyn Lifter,
                include_str!("../testdata/public/gamecube_return.hex"),
                include_str!("../testdata/public/gamecube_return.c"),
            ),
            (
                Architecture::X86_32,
                &X86_32 as &dyn Lifter,
                include_str!("../testdata/public/x86_32_return.hex"),
                include_str!("../testdata/public/x86_32_return.c"),
            ),
            (
                Architecture::Thumb,
                &Thumb as &dyn Lifter,
                include_str!("../testdata/public/thumb_return.hex"),
                include_str!("../testdata/public/thumb_return.c"),
            ),
            (
                Architecture::Mips32Be,
                &Mips32Be as &dyn Lifter,
                include_str!("../testdata/public/mips32be_return.hex"),
                include_str!("../testdata/public/mips32be_return.c"),
            ),
            (
                Architecture::Rv32,
                &Rv32 as &dyn Lifter,
                include_str!("../testdata/public/rv32_return.hex"),
                include_str!("../testdata/public/rv32_return.c"),
            ),
            (
                Architecture::M68k,
                &M68k as &dyn Lifter,
                include_str!("../testdata/public/m68k_return.hex"),
                include_str!("../testdata/public/m68k_return.c"),
            ),
            (
                Architecture::Sh2,
                &Sh2 as &dyn Lifter,
                include_str!("../testdata/public/sh2_return.hex"),
                include_str!("../testdata/public/sh2_return.c"),
            ),
            (
                Architecture::Sh4,
                &Sh4 as &dyn Lifter,
                include_str!("../testdata/public/sh4_return.hex"),
                include_str!("../testdata/public/sh4_return.c"),
            ),
            (
                Architecture::M6502,
                &M6502 as &dyn Lifter,
                include_str!("../testdata/public/m6502_return.hex"),
                include_str!("../testdata/public/m6502_return.c"),
            ),
            (
                Architecture::Z80,
                &Z80 as &dyn Lifter,
                include_str!("../testdata/public/z80_return.hex"),
                include_str!("../testdata/public/z80_return.c"),
            ),
        ];
        for (architecture, lifter, hex, oracle) in processor_cases {
            let function = public_function(hex, lifter);
            let candidate = NativeDecompiler.decompile(architecture, &function);
            let score = score_c(oracle, &candidate.render());
            assert!(score.exact, "{hex}: {score:?}\n{}", candidate.render());
        }

        let first = AArch64
            .lift_instruction(0x2000, &0xaa1f_03e0u32.to_le_bytes())
            .unwrap();
        let second = AArch64
            .lift_instruction(0x2004, &0xd65f_03c0u32.to_le_bytes())
            .unwrap();
        let function = NativeFunction {
            entry: 0x2000,
            instructions: BTreeMap::from([(0x2000, first), (0x2004, second)]),
            edges: BTreeSet::from([(0x2000, 0x2004)]),
            calls: BTreeSet::new(),
        };
        let candidate = NativeDecompiler.decompile(Architecture::AArch64, &function);
        let oracle = include_str!("../testdata/public/aarch64_zero.c");
        let score = score_c(oracle, &candidate.render());
        assert!(score.exact, "aarch64: {score:?}\n{}", candidate.render());
    }

    #[test]
    fn real_binary_opcode_gap_fixture_lifts_all_instructions() {
        for (line, text) in include_str!("../testdata/public/x86_real_gap.hex")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .enumerate()
        {
            let bytes = parse_public_hex(text);
            let instruction = X86_64
                .lift_instruction(0x4000 + (line as u64) * 0x100, &bytes)
                .unwrap_or_else(|error| panic!("fixture line {line}: {error}"));
            assert_eq!(
                instruction.bytes,
                bytes[..instruction.bytes.len()],
                "fixture line {line}"
            );
        }
    }
}
