//! A dependency-free native decompiler for the p-code produced by
//! `ventris-lifter`.
//!
//! This module owns the complete native pipeline: versioned values,
//! width-driven type facts, CFG labels, and deterministic C rendering.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as FmtWrite;
use ventris_lifter::{Architecture, NativeFunction, REGISTER_SPACE};
use ventris_pcode::{op, PcodeOp, Varnode};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Type {
    Unknown,
    Bool,
    Unsigned(u32),
    Signed(u32),
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
        match width {
            1 => Self::Bool,
            n => Self::Unsigned(n.saturating_mul(8)),
        }
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
            Self::Equal
            | Self::NotEqual
            | Self::Less
            | Self::LessEqual
            | Self::SignedLess
            | Self::SignedLessEqual => 5,
            Self::Left | Self::Right | Self::SignedRight => 7,
            Self::Add | Self::Sub => 8,
            Self::Mul | Self::Div | Self::Rem | Self::SignedDiv | Self::SignedRem => 9,
            Self::And => 4,
            Self::Xor => 3,
            Self::Or => 2,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Expr {
    Constant {
        value: u64,
        width: u32,
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

    fn render(&self) -> String {
        self.render_prec(0)
    }

    fn render_prec(&self, parent_precedence: u8) -> String {
        match self {
            Self::Constant { value, .. } => {
                if *value == 0 {
                    "0".into()
                } else if *value <= 9 {
                    value.to_string()
                } else {
                    format!("0x{value:x}")
                }
            }
            Self::Register { name, .. } | Self::Temporary { name, .. } => name.clone(),
            Self::Select {
                condition,
                when_true,
                when_false,
            } => {
                let value = format!(
                    "{} ? {} : {}",
                    condition.render_prec(1),
                    when_true.render_prec(1),
                    when_false.render_prec(1)
                );
                format!("({value})")
            }
            Self::Binary { op, left, right } => {
                let precedence = op.precedence();
                let value = format!(
                    "{} {} {}",
                    left.render_prec(precedence),
                    op.text(),
                    right.render_prec(precedence.saturating_add(1))
                );
                if precedence < parent_precedence {
                    format!("({value})")
                } else {
                    value
                }
            }
            Self::Not(value) => {
                let value = format!("!{}", value.render_prec(10));
                if 10 < parent_precedence {
                    format!("({value})")
                } else {
                    value
                }
            }
            Self::Neg(value) => {
                let value = format!("-{}", value.render_prec(10));
                if 10 < parent_precedence {
                    format!("({value})")
                } else {
                    value
                }
            }
            Self::BitNot(value) => {
                let value = format!("~{}", value.render_prec(10));
                if 10 < parent_precedence {
                    format!("({value})")
                } else {
                    value
                }
            }
            Self::Cast { ty, value } => format!("({})({})", ty.c_name(), value.render()),
            Self::Global { name, .. } => name.clone(),
            Self::Load { address, width } => {
                if let Expr::Constant { value, .. } = address.as_ref() {
                    format!("DAT_{value:x}")
                } else {
                    format!(
                        "*({} *)(uintptr_t)({})",
                        Type::from_width(*width).c_name(),
                        address.render()
                    )
                }
            }
            Self::Call {
                target,
                callee,
                args,
            } => {
                let name = callee
                    .as_ref()
                    .map(|value| value.render())
                    .or_else(|| target.map(|a| format!("sub_{a:x}")))
                    .unwrap_or_else(|| "indirect_call".into());
                let args = args.iter().map(Expr::render).collect::<Vec<_>>().join(", ");
                format!("{name}({args})")
            }
            Self::Builtin { name, args } => {
                let args = args.iter().map(Expr::render).collect::<Vec<_>>().join(", ");
                format!("{name}({args})")
            }
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
struct ValueKey {
    space: u32,
    offset: u64,
    width: u32,
}

impl From<Varnode> for ValueKey {
    fn from(v: Varnode) -> Self {
        Self {
            space: v.space,
            offset: v.offset,
            width: v.size,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TypeConstraint {
    pub value: Varnode,
    pub ty: Type,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SsaValue {
    pub id: u32,
    pub origin: Varnode,
    pub ty: Type,
    pub version: u32,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SsaFunction {
    pub values: Vec<SsaValue>,
    pub constraints: Vec<TypeConstraint>,
}

/// Build versioned definitions from p-code outputs. A definition gets a new
/// version even when the machine register is reused; this is the invariant that
/// prevents a later assignment from rewriting an earlier expression.
///
/// Constraints are emitted for both definitions and their typed uses. This
/// keeps width facts attached to the value that crosses an instruction
/// boundary instead of treating every input register as an untyped name.
pub fn build_ssa(function: &NativeFunction) -> SsaFunction {
    let mut out = SsaFunction::default();
    let mut versions: BTreeMap<ValueKey, u32> = BTreeMap::new();
    for instruction in function.instructions.values() {
        for operation in &instruction.pcode.ops {
            let output_ty = operation
                .output
                .map(|output| operation_type(operation.opcode, output.size));
            if let Some(output) = operation.output {
                let key = ValueKey::from(output);
                let version = versions.entry(key).or_insert(0);
                let current = *version;
                *version = version.saturating_add(1);
                let ty = output_ty.clone().unwrap_or(Type::Unknown);
                out.constraints.push(TypeConstraint {
                    value: output,
                    ty: ty.clone(),
                });
                out.values.push(SsaValue {
                    id: out.values.len() as u32,
                    origin: output,
                    ty,
                    version: current,
                });
            }
            for (index, input) in operation.inputs.iter().copied().enumerate() {
                let Some(ty) = input_type(operation.opcode, index, input, output_ty.as_ref())
                else {
                    continue;
                };
                if input.space != ventris_lifter::CONST_SPACE
                    && input.space != ventris_lifter::UNIQUE_SPACE
                {
                    out.constraints.push(TypeConstraint { value: input, ty });
                }
            }
        }
    }
    out
}

fn operation_type(opcode: i32, width: u32) -> Type {
    match opcode {
        op::BOOL_NEGATE
        | op::BOOL_XOR
        | op::BOOL_AND
        | op::BOOL_OR
        | op::INT_EQUAL
        | op::INT_NOTEQUAL
        | op::INT_LESS
        | op::INT_LESSEQUAL
        | op::INT_SLESS
        | op::INT_SLESSEQUAL
        | op::INT_CARRY
        | op::INT_SCARRY
        | op::INT_SBORROW => Type::Bool,
        op::INT_SDIV | op::INT_SREM | op::INT_SRIGHT => Type::Signed(width.saturating_mul(8)),
        op::INT_SEXT => Type::Signed(width.saturating_mul(8)),
        _ => Type::from_width(width),
    }
}

fn input_type(opcode: i32, index: usize, input: Varnode, output_ty: Option<&Type>) -> Option<Type> {
    match opcode {
        op::BOOL_NEGATE | op::BOOL_XOR | op::BOOL_AND | op::BOOL_OR => Some(Type::Bool),
        op::INT_EQUAL
        | op::INT_NOTEQUAL
        | op::INT_LESS
        | op::INT_LESSEQUAL
        | op::INT_SLESS
        | op::INT_SLESSEQUAL => Some(Type::from_width(input.size)),
        op::CMOV if index == 0 => Some(Type::Bool),
        op::COPY | op::MULTIEQUAL | op::CMOV => output_ty.cloned(),
        op::INT_2COMP | op::INT_NEGATE | op::INT_ZEXT | op::SUBPIECE | op::CAST => {
            Some(Type::from_width(input.size))
        }
        op::INT_SEXT => Some(Type::Signed(input.size.saturating_mul(8))),
        op::LOAD if index == 1 => Some(Type::Pointer(Box::new(Type::Unknown))),
        op::STORE if index == 1 => Some(Type::Pointer(Box::new(Type::Unknown))),
        op::STORE if index == 2 => Some(Type::from_width(input.size)),
        op::INT_SDIV | op::INT_SREM | op::INT_SRIGHT => {
            Some(Type::Signed(input.size.saturating_mul(8)))
        }
        op::INT_ADD
        | op::INT_SUB
        | op::INT_MULT
        | op::INT_DIV
        | op::INT_REM
        | op::INT_AND
        | op::INT_OR
        | op::INT_XOR
        | op::INT_LEFT
        | op::INT_RIGHT
        | op::INT_CARRY
        | op::INT_SCARRY
        | op::INT_SBORROW => Some(Type::from_width(input.size)),
        _ => None,
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct TypeSolver {
    constraints: BTreeMap<ValueKey, Type>,
}

impl TypeSolver {
    pub fn constrain(&mut self, value: Varnode, ty: Type) {
        let key = ValueKey::from(value);
        self.constraints
            .entry(key)
            .and_modify(|old| *old = merge_types(old, &ty))
            .or_insert(ty);
    }

    pub fn solve(&self) -> Vec<TypeConstraint> {
        self.constraints
            .iter()
            .map(|(key, ty)| TypeConstraint {
                value: Varnode::new(key.space, key.offset, key.width),
                ty: ty.clone(),
            })
            .collect()
    }
}

fn merge_types(old: &Type, new: &Type) -> Type {
    match (old, new) {
        (Type::Unknown, ty) | (ty, Type::Unknown) => ty.clone(),
        (Type::Unsigned(left), Type::Unsigned(right)) => Type::Unsigned((*left).max(*right)),
        (Type::Signed(left), Type::Signed(right)) => Type::Signed((*left).max(*right)),
        (Type::Pointer(left), Type::Pointer(right)) => {
            Type::Pointer(Box::new(merge_types(left, right)))
        }
        (left, _) => left.clone(),
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
    Goto(u64),
    /// A computed control-flow transfer. GNU C's computed-goto spelling keeps
    /// the operation distinct from an indirect call without inventing a target.
    IndirectGoto(Expr),
    Return(Option<Expr>),
    Expression(Expr),
}

impl NativeStatement {
    fn render(&self, out: &mut String) {
        self.render_at(out, 0);
    }

    fn render_at(&self, out: &mut String, depth: usize) {
        match self {
            Self::Label(address) => {
                write_indent(out, depth);
                let _ = writeln!(out, "loc_{address:x}:");
            }
            Self::Store {
                address,
                value,
                width,
                volatile,
            } => {
                write_indent(out, depth + 1);
                if let Expr::Global { name, .. } = address {
                    let _ = writeln!(out, "{name} = {};", value.render());
                } else if !volatile && matches!(address, Expr::Constant { .. }) {
                    if let Expr::Constant {
                        value: address_value,
                        ..
                    } = address
                    {
                        let _ = writeln!(out, "DAT_{address_value:x} = {};", value.render());
                    }
                } else {
                    let ty = Type::from_width(*width).c_name();
                    let qualifier = if *volatile { "volatile " } else { "" };
                    let _ = writeln!(
                        out,
                        "*({qualifier}{ty} *)(uintptr_t)({}) = {};",
                        address.render(),
                        value.render()
                    );
                }
            }
            Self::Copy {
                destination,
                source,
                width,
                volatile,
            } => {
                write_indent(out, depth + 1);
                let destination = pointer_expression(destination, false);
                let source = pointer_expression(source, true);
                let qualifier = if *volatile { " /* volatile */" } else { "" };
                let _ = writeln!(
                    out,
                    "__builtin_memcpy({destination}, {source}, {width}){qualifier};"
                );
            }
            Self::Call(call) | Self::Expression(call) => {
                write_indent(out, depth + 1);
                let _ = writeln!(out, "{};", call.render());
            }
            Self::IfGoto { condition, target } => {
                write_indent(out, depth + 1);
                let _ = writeln!(out, "if ({}) goto loc_{target:x};", condition.render());
            }
            Self::IfReturn { condition, value } => {
                write_indent(out, depth + 1);
                let _ = writeln!(out, "if ({}) {{", condition.render());
                match value {
                    Some(value) => {
                        write_indent(out, depth + 2);
                        let _ = writeln!(out, "return {};", value.render());
                    }
                    None => {
                        write_indent(out, depth + 2);
                        let _ = writeln!(out, "return;");
                    }
                }
                write_indent(out, depth + 1);
                let _ = writeln!(out, "}}");
            }
            Self::IfElse {
                condition,
                then_body,
                else_body,
            } => {
                write_indent(out, depth + 1);
                let _ = writeln!(out, "if ({}) {{", condition.render());
                for statement in then_body {
                    statement.render_at(out, depth + 1);
                }
                write_indent(out, depth + 1);
                let _ = writeln!(out, "}} else {{");
                for statement in else_body {
                    statement.render_at(out, depth + 1);
                }
                write_indent(out, depth + 1);
                let _ = writeln!(out, "}}");
            }
            Self::Goto(target) => {
                write_indent(out, depth + 1);
                let _ = writeln!(out, "goto loc_{target:x};");
            }
            Self::IndirectGoto(target) => {
                write_indent(out, depth + 1);
                let _ = writeln!(out, "goto *({});", target.render());
            }
            Self::Return(value) => {
                write_indent(out, depth + 1);
                let _ = match value {
                    Some(value) => writeln!(out, "return {};", value.render()),
                    None => writeln!(out, "return;"),
                };
            }
        }
    }
}

fn write_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("    ");
    }
}
fn pointer_expression(value: &Expr, constant: bool) -> String {
    let qualifier = if constant { "const " } else { "" };
    match value {
        Expr::Global { name, .. } => format!("&{name}"),
        Expr::Load { address, .. } => {
            format!("({qualifier}void *)(uintptr_t)({})", address.render())
        }
        _ => format!("({qualifier}void *)(uintptr_t)({})", value.render()),
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NativeDocument {
    pub name: String,
    pub return_type: Type,
    pub statements: Vec<NativeStatement>,
    pub ssa: SsaFunction,
    pub types: Vec<TypeConstraint>,
    pub warnings: Vec<String>,
}

impl NativeDocument {
    pub fn render(&self) -> String {
        let mut out = String::from("#include <stdint.h>\n#include <stdbool.h>\n\n");
        let _ = writeln!(out, "{} {}(void)", self.return_type.c_name(), self.name);
        out.push_str("{\n");
        for statement in &self.statements {
            statement.render(&mut out);
        }
        out.push_str("}\n");
        out
    }
}
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CScore {
    pub oracle_tokens: usize,
    pub candidate_tokens: usize,
    pub matched_tokens: usize,
    pub exact: bool,
}

impl CScore {
    pub fn ratio_milli(&self) -> usize {
        if self.oracle_tokens == 0 {
            return usize::from(self.candidate_tokens == 0) * 1000;
        }
        self.matched_tokens.saturating_mul(1000) / self.oracle_tokens
    }
}
fn c_body(text: &str) -> &str {
    text.find('{')
        .and_then(|start| text.rfind('}').map(|end| &text[start..=end]))
        .unwrap_or(text)
}

/// Compare the semantic body of two C renderings.
///
/// Function names, type names, and generated temporary names are intentionally
/// canonicalized: the native pipeline has no symbol database. Identifier
/// bindings remain consistent within each body, and numeric literals are
/// normalized by value. Keywords, operators, punctuation, and literal-vs-
/// identifier shape remain significant.
pub fn score_c(oracle: &str, candidate: &str) -> CScore {
    let oracle_tokens = canonical_c_tokens(c_body(oracle));
    let candidate_tokens = canonical_c_tokens(c_body(candidate));
    let mut row = vec![0usize; candidate_tokens.len() + 1];
    for left in &oracle_tokens {
        let mut diagonal = 0;
        for (index, right) in candidate_tokens.iter().enumerate() {
            let saved = row[index + 1];
            row[index + 1] = if left == right {
                diagonal + 1
            } else {
                row[index + 1].max(row[index])
            };
            diagonal = saved;
        }
    }
    let matched_tokens = *row.last().unwrap_or(&0);
    CScore {
        oracle_tokens: oracle_tokens.len(),
        candidate_tokens: candidate_tokens.len(),
        matched_tokens,
        exact: oracle_tokens == candidate_tokens,
    }
}

fn is_local_declaration(line: &str) -> bool {
    let line = line.trim();
    if !line.ends_with(';') || line.contains('(') || line.contains('=') {
        return false;
    }
    [
        "bool ",
        "char ",
        "double ",
        "float ",
        "int ",
        "long ",
        "short ",
        "uint",
        "int",
        "undefined",
        "size_t ",
        "uintptr_t ",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
}
fn canonical_number(value: &str) -> String {
    let trimmed = value.trim_end_matches(['u', 'U', 'l', 'L']);
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u128::from_str_radix(hex, 16).ok()
    } else if let Some(binary) = trimmed
        .strip_prefix("0b")
        .or_else(|| trimmed.strip_prefix("0B"))
    {
        u128::from_str_radix(binary, 2).ok()
    } else if let Some(octal) = trimmed
        .strip_prefix("0o")
        .or_else(|| trimmed.strip_prefix("0O"))
    {
        u128::from_str_radix(octal, 8).ok()
    } else {
        trimmed.parse::<u128>().ok()
    };
    parsed.map_or_else(
        || format!("$number:{trimmed}"),
        |number| format!("$number:{number}"),
    )
}

fn canonical_c_tokens(text: &str) -> Vec<String> {
    const KEYWORDS: &[&str] = &[
        "if", "else", "for", "while", "switch", "case", "break", "continue", "return", "goto",
        "do", "sizeof", "true", "false",
    ];
    let normalized = text
        .lines()
        .filter(|line| !is_local_declaration(line))
        .collect::<Vec<_>>()
        .join("\n");
    let mut tokens = Vec::new();
    let mut identifiers = BTreeMap::<String, String>::new();
    let mut chars = normalized.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        if ch.is_ascii_alphabetic() || ch == '_' {
            let mut word = String::from(ch);
            while let Some(next) = chars.peek().copied() {
                if next.is_ascii_alphanumeric() || next == '_' {
                    word.push(next);
                    chars.next();
                } else {
                    break;
                }
            }
            if KEYWORDS.contains(&word.as_str()) {
                tokens.push(word);
            } else if let Some(canonical) = identifiers.get(&word) {
                tokens.push(canonical.clone());
            } else {
                let canonical = format!("$id{}", identifiers.len());
                identifiers.insert(word, canonical.clone());
                tokens.push(canonical);
            }
            continue;
        }
        if ch.is_ascii_digit() {
            let mut number = String::from(ch);
            while let Some(next) = chars.peek().copied() {
                if next.is_ascii_alphanumeric() || next == '_' {
                    number.push(next);
                    chars.next();
                } else {
                    break;
                }
            }
            tokens.push(canonical_number(&number));
            continue;
        }
        let mut operator = String::from(ch);
        if let Some(next) = chars.peek().copied() {
            if matches!(
                (ch, next),
                ('=', '=')
                    | ('!', '=')
                    | ('<', '=')
                    | ('>', '=')
                    | ('&', '&')
                    | ('|', '|')
                    | ('+', '+')
                    | ('-', '-')
                    | ('-', '>')
                    | ('<', '<')
                    | ('>', '>')
            ) {
                operator.push(next);
                chars.next();
            }
        }
        tokens.push(operator);
    }
    tokens
}

fn default_return_type(architecture: Architecture) -> Type {
    match architecture {
        Architecture::M6502 | Architecture::Z80 => Type::Unsigned(8),
        Architecture::Arm32
        | Architecture::X86_32
        | Architecture::Thumb
        | Architecture::Mips32
        | Architecture::Mips32Be
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
        Expr::Constant { .. } | Expr::Call { .. } => default_return_type(architecture),
        Expr::Global { width, .. } | Expr::Load { width, .. } => Type::from_width(*width),
        Expr::Builtin { .. } => Type::Unsigned(32),
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
        let ssa = build_ssa(function);
        let mut solver = TypeSolver::default();
        for constraint in &ssa.constraints {
            solver.constrain(constraint.value, constraint.ty.clone());
        }
        let types = solver.solve();
        let labels: BTreeSet<u64> = function
            .instructions
            .values()
            .filter_map(|instruction| match instruction.flow {
                ventris_lifter::Flow::Jump(target)
                | ventris_lifter::Flow::Conditional { target, .. } => Some(target),
                ventris_lifter::Flow::FallThrough(_)
                | ventris_lifter::Flow::Return
                | ventris_lifter::Flow::Call { .. } => None,
            })
            .collect();
        let mut definitions: BTreeMap<ValueKey, Expr> = BTreeMap::new();
        let mut statements = Vec::new();
        let mut warnings = Vec::new();
        let mut consumed_delay_slots = BTreeSet::new();
        let mut returned = false;
        let mut value_returned = false;
        let mut inferred_return_type = None;
        for (address, instruction) in &function.instructions {
            if consumed_delay_slots.contains(address) {
                continue;
            }
            if labels.contains(address) {
                statements.push(NativeStatement::Label(*address));
            }
            if matches!(
                architecture,
                Architecture::Mips32
                    | Architecture::Mips32Be
                    | Architecture::Ps1
                    | Architecture::N64
            ) {
                let delay_address = match instruction.flow {
                    ventris_lifter::Flow::Call { fallthrough, .. } => Some(fallthrough),
                    ventris_lifter::Flow::Return => address.checked_add(4),
                    _ => None,
                };
                if let Some(delay_address) = delay_address {
                    if !labels.contains(&delay_address) {
                        if let Some(delay) = function.instructions.get(&delay_address) {
                            if matches!(delay.flow, ventris_lifter::Flow::FallThrough(_)) {
                                for operation in &delay.pcode.ops {
                                    self.translate_operation(
                                        architecture,
                                        memory,
                                        symbols,
                                        delay_address,
                                        operation,
                                        &mut definitions,
                                        &mut statements,
                                        &mut warnings,
                                    );
                                }
                                consumed_delay_slots.insert(delay_address);
                            }
                        }
                    }
                }
            }
            for operation in &instruction.pcode.ops {
                self.translate_operation(
                    architecture,
                    memory,
                    symbols,
                    *address,
                    operation,
                    &mut definitions,
                    &mut statements,
                    &mut warnings,
                );
                if operation.opcode == op::RETURN {
                    let mut value = return_value(architecture, &definitions);
                    if let Some(returned_value) = value.as_ref() {
                        let repeats_store = statements.iter().rev().find_map(|statement| {
                            if let NativeStatement::Store { value, .. } = statement {
                                Some(value)
                            } else {
                                None
                            }
                        }) == Some(returned_value);
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
        statements = structure_control_flow(statements);
        NativeDocument {
            name: format!("sub_{:x}", function.entry),
            return_type,
            statements,
            ssa,
            types,
            warnings,
        }
    }

    fn translate_operation(
        &self,
        architecture: Architecture,
        memory: Option<&NativeMemory<'_>>,
        symbols: Option<&dyn Fn(u64) -> Option<String>>,
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
                .map(|v| eval(v, architecture, definitions))
        };
        match operation.opcode {
            op::COPY => {
                if let (Some(output), Some(value)) = (operation.output, input(0)) {
                    definitions.insert(ValueKey::from(output), value);
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
                        op::BOOL_AND => BinaryOp::And,
                        op::BOOL_OR => BinaryOp::Or,
                        _ => unreachable!(),
                    };
                    let value = simplify(BinaryOp::build(binary, left, right));
                    definitions.insert(ValueKey::from(output), value);
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
                    let value = named_global(symbols, &address, output.size)
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
                if let (Some(address), Some(value)) = (input(1), input(2)) {
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
                let internal_branch_state_userop = if operation.output.is_some() {
                    false
                } else {
                    let userop = operation.inputs.first().and_then(constant_value);
                    match architecture {
                        Architecture::Arm32 => userop == Some(62),
                        Architecture::Mips32
                        | Architecture::Mips32Be
                        | Architecture::Ps1
                        | Architecture::N64 => userop == Some(0),
                        _ => false,
                    }
                };
                if internal_branch_state_userop {
                    // The MIPS/N64 return and Arm32 BX lifters use these
                    // userops for branch-state bookkeeping. They have no
                    // source-level effect.
                    return;
                }

                // Other userops are target/language-specific. Preserve the
                // userop index and operands as an opaque builtin rather than
                // dropping the operation or guessing an intrinsic.
                let call = Expr::Builtin {
                    name: "__ventris_callother",
                    args: operation
                        .inputs
                        .iter()
                        .copied()
                        .map(|v| eval(v, architecture, definitions))
                        .collect(),
                };
                if let Some(output) = operation.output {
                    definitions.insert(ValueKey::from(output), call);
                } else {
                    statements.push(NativeStatement::Expression(call));
                }
            }
            op::CALL => {
                let target = operation.inputs.first().and_then(constant_value);
                let callee = target
                    .and_then(|target| named_symbol(symbols, target, 0))
                    .or_else(|| target.is_none().then(|| input(0)).flatten())
                    .map(Box::new);
                let call = Expr::Call {
                    target,
                    callee,
                    args: operation
                        .inputs
                        .iter()
                        .skip(1)
                        .filter(|value| call_argument_available(architecture, **value, definitions))
                        .map(|v| eval(*v, architecture, definitions))
                        .collect(),
                };
                statements.push(NativeStatement::Call(call.clone()));
                invalidate_mips_o32_call_arguments(architecture, definitions);
                definitions.insert(ValueKey::from(return_vnode(architecture)), call);
            }
            op::CALLIND => {
                let callee = input(0)
                    .map(|value| match value {
                        Expr::Constant { value, width } => named_symbol(symbols, value, width)
                            .unwrap_or(Expr::Constant { value, width }),
                        value => value,
                    })
                    .map(Box::new);
                let call = Expr::Call {
                    target: None,
                    callee,
                    args: operation
                        .inputs
                        .iter()
                        .skip(1)
                        .filter(|value| call_argument_available(architecture, **value, definitions))
                        .map(|v| eval(*v, architecture, definitions))
                        .collect(),
                };
                statements.push(NativeStatement::Call(call.clone()));
                invalidate_mips_o32_call_arguments(architecture, definitions);
                definitions.insert(ValueKey::from(return_vnode(architecture)), call);
            }
            op::CBRANCH => {
                if let (Some(target), Some(condition)) =
                    (operation.inputs.first().and_then(constant_value), input(1))
                {
                    statements.push(NativeStatement::IfGoto { condition, target });
                }
            }
            op::BRANCH => {
                if let Some(target) = operation.inputs.first().and_then(constant_value) {
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

impl BinaryOp {
    fn build(op: Self, left: Expr, right: Expr) -> Expr {
        Expr::Binary {
            op,
            left: Box::new(left),
            right: Box::new(right),
        }
    }
}

fn simplify(value: Expr) -> Expr {
    match value {
        Expr::Binary {
            op: binary,
            left,
            right,
        } => {
            let left = simplify(*left);
            let right = simplify(*right);
            if matches!(binary, BinaryOp::Xor | BinaryOp::Sub) && left == right {
                return Expr::constant(0, 8);
            }
            if matches!(binary, BinaryOp::And) && left == right {
                return left;
            }
            if matches!(binary, BinaryOp::Add | BinaryOp::Or | BinaryOp::Xor) && right.is_zero() {
                return left;
            }
            if matches!(binary, BinaryOp::Add | BinaryOp::Or | BinaryOp::Xor) && left.is_zero() {
                return right;
            }
            Expr::Binary {
                op: binary,
                left: Box::new(left),
                right: Box::new(right),
            }
        }
        Expr::Not(value) => Expr::Not(Box::new(simplify(*value))),
        Expr::Neg(value) => Expr::Neg(Box::new(simplify(*value))),
        Expr::BitNot(value) => Expr::BitNot(Box::new(simplify(*value))),
        Expr::Builtin { name, args } => Expr::Builtin {
            name,
            args: args.into_iter().map(simplify).collect(),
        },
        Expr::Cast { ty, value } => {
            let value = simplify(*value);
            if let Expr::Constant { value, width } = value {
                Expr::Constant { value, width }
            } else {
                Expr::Cast {
                    ty,
                    value: Box::new(value),
                }
            }
        }
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => Expr::Select {
            condition: Box::new(simplify(*condition)),
            when_true: Box::new(simplify(*when_true)),
            when_false: Box::new(simplify(*when_false)),
        },
        value => value,
    }
}
fn invert_condition(value: Expr) -> Expr {
    match value {
        Expr::Not(inner) => *inner,
        value => Expr::Not(Box::new(value)),
    }
}
fn has_other_branch_to(statements: &[NativeStatement], current_index: usize, target: u64) -> bool {
    statements.iter().enumerate().any(|(index, statement)| {
        index != current_index
            && match statement {
                NativeStatement::Goto(branch_target)
                | NativeStatement::IfGoto {
                    target: branch_target,
                    ..
                } => *branch_target == target,
                _ => false,
            }
    })
}

fn structure_control_flow(statements: Vec<NativeStatement>) -> Vec<NativeStatement> {
    let mut structured = Vec::with_capacity(statements.len());
    let mut index = 0usize;
    while index < statements.len() {
        if index + 3 < statements.len() {
            if let (
                NativeStatement::IfGoto { condition, target },
                NativeStatement::Return(value),
                NativeStatement::Label(label),
                NativeStatement::Return(joined),
            ) = (
                &statements[index],
                &statements[index + 1],
                &statements[index + 2],
                &statements[index + 3],
            ) {
                if target == label && !has_other_branch_to(&statements, index, *target) {
                    structured.push(NativeStatement::IfReturn {
                        condition: invert_condition(condition.clone()),
                        value: value.clone(),
                    });
                    structured.push(NativeStatement::Return(joined.clone()));
                    index += 4;
                    continue;
                }
            }
        }

        if let NativeStatement::IfGoto { condition, target } = &statements[index] {
            let target_index = statements[index + 1..]
                .iter()
                .position(|statement| {
                    matches!(statement, NativeStatement::Label(label) if label == target)
                })
                .map(|relative| index + 1 + relative);
            if let Some(target_index) =
                target_index.filter(|target_index| *target_index > index + 1)
            {
                if !has_other_branch_to(&statements, index, *target) {
                    if let Some(NativeStatement::Return(value)) = statements.get(target_index + 1) {
                        structured.push(NativeStatement::IfReturn {
                            condition: condition.clone(),
                            value: value.clone(),
                        });
                        structured.extend(statements[index + 1..target_index].iter().cloned());
                        structured.push(NativeStatement::Return(value.clone()));
                        index = target_index + 2;
                        continue;
                    }
                }
            }
        }

        if let NativeStatement::IfGoto { condition, target } = &statements[index] {
            let target_index = statements[index + 1..]
                .iter()
                .position(|statement| {
                    matches!(statement, NativeStatement::Label(label) if label == target)
                })
                .map(|relative| index + 1 + relative);
            if let Some(target_index) =
                target_index.filter(|target_index| *target_index > index + 1)
            {
                if let Some(NativeStatement::Goto(join)) = statements.get(target_index - 1) {
                    let join_index = statements[target_index + 1..]
                        .iter()
                        .position(|statement| {
                            matches!(statement, NativeStatement::Label(label) if label == join)
                        })
                        .map(|relative| target_index + 1 + relative);
                    if let Some(join_index) = join_index {
                        let then_body = statements[target_index + 1..join_index].to_vec();
                        let else_body = statements[index + 1..target_index - 1].to_vec();
                        if !then_body.is_empty() || !else_body.is_empty() {
                            structured.push(NativeStatement::IfElse {
                                condition: condition.clone(),
                                then_body,
                                else_body,
                            });
                            index = join_index + 1;
                            continue;
                        }
                    }
                }
            }
        }

        structured.push(statements[index].clone());
        index += 1;
    }
    structured
}
fn constant_value(v: &Varnode) -> Option<u64> {
    (v.space == ventris_lifter::CONST_SPACE).then_some(v.offset)
}

fn is_mips_o32_call_argument(value: Varnode) -> bool {
    value.space == ventris_lifter::REGISTER_SPACE
        && value.size == 4
        && ((16..=28).contains(&value.offset) && value.offset % 4 == 0
            || matches!(value.offset, 0x230 | 0x238))
}

fn call_argument_available(
    architecture: Architecture,
    value: Varnode,
    definitions: &BTreeMap<ValueKey, Expr>,
) -> bool {
    if !matches!(
        architecture,
        Architecture::Mips32 | Architecture::Mips32Be | Architecture::Ps1
    ) || !is_mips_o32_call_argument(value)
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
        Architecture::Mips32 | Architecture::Mips32Be | Architecture::Ps1
    ) {
        definitions.retain(|key, _| {
            !is_mips_o32_call_argument(Varnode::new(key.space, key.offset, key.width))
        });
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

fn is_zero_register(architecture: Architecture, v: Varnode) -> bool {
    v.space == REGISTER_SPACE
        && match architecture {
            Architecture::AArch64 => v.offset == 0x4000 + 31 * 8,
            Architecture::Mips32
            | Architecture::Mips32Be
            | Architecture::Ps1
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
            | Architecture::Rv64
            | Architecture::Rv32
            | Architecture::Sh4
            | Architecture::M6502
            | Architecture::Z80
    )
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
        Architecture::N64 => Varnode::new(REGISTER_SPACE, 16, 8),
        Architecture::Rv64 => Varnode::new(REGISTER_SPACE, 0x2000 + 8 * 10, 8),
        Architecture::Rv32 => Varnode::new(REGISTER_SPACE, 0x2000 + 8 * 10, 4),
        Architecture::Ppc32 | Architecture::GameCube => Varnode::new(REGISTER_SPACE, 3 * 4, 4),
        Architecture::Ppc64 => Varnode::new(REGISTER_SPACE, 3 * 8, 8),
        Architecture::M68k => Varnode::new(REGISTER_SPACE, 0, 4),
        Architecture::Sh2 | Architecture::Sh4 => Varnode::new(REGISTER_SPACE, 0, 4),
        Architecture::Spu => Varnode::new(REGISTER_SPACE, 3 * 16, 16),
        Architecture::M6502 | Architecture::Z80 => Varnode::new(REGISTER_SPACE, 0, 1),
    }
}

fn return_value(
    architecture: Architecture,
    definitions: &BTreeMap<ValueKey, Expr>,
) -> Option<Expr> {
    let return_register = return_vnode(architecture);
    let value = definitions
        .iter()
        .filter(|(key, _)| {
            key.space == return_register.space
                && key.offset == return_register.offset
                && key.width <= return_register.size
        })
        .max_by_key(|(key, _)| key.width)
        .map(|(_, value)| simplify(value.clone()))
        .unwrap_or_else(|| simplify(eval(return_register, architecture, definitions)));
    match value {
        Expr::Register { .. } | Expr::Call { .. } => None,
        value => Some(value),
    }
}

fn register_name(architecture: Architecture, offset: u64) -> String {
    match architecture {
        Architecture::X86_64 => [
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15",
        ]
        .get((offset / 8) as usize)
        .unwrap_or(&"reg")
        .to_string(),
        Architecture::X86_32 => [
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d",
            "r12d", "r13d", "r14d", "r15d",
        ]
        .get((offset / 8) as usize)
        .unwrap_or(&"reg")
        .to_string(),
        Architecture::AArch64 => format!("x{}", offset.saturating_sub(0x4000) / 8),
        Architecture::Rv64 | Architecture::Rv32 => {
            format!("x{}", offset.saturating_sub(0x2000) / 8)
        }
        Architecture::Arm32 | Architecture::Thumb => [
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "sp", "lr",
            "pc",
        ]
        .get(offset.saturating_sub(32).checked_div(4).unwrap_or_default() as usize)
        .unwrap_or(&"reg")
        .to_string(),
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
                .unwrap_or(&"reg")
                .to_string()
            }
        }
        Architecture::N64 => [
            "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5",
            "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1",
            "gp", "sp", "fp", "ra",
        ]
        .get((offset / 8) as usize)
        .unwrap_or(&"reg")
        .to_string(),
        Architecture::Ppc32 | Architecture::GameCube => {
            if offset == 32 * 4 {
                "lr".to_string()
            } else {
                format!("r{}", offset / 4)
            }
        }
        Architecture::Ppc64 => {
            if offset == 32 * 8 {
                "lr".to_string()
            } else {
                format!("r{}", offset / 8)
            }
        }
        Architecture::M68k => [
            "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "a0", "a1", "a2", "a3", "a4", "a5",
            "a6", "a7", "pc",
        ]
        .get((offset / 4) as usize)
        .unwrap_or(&"reg")
        .to_string(),
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
            .unwrap_or(&"reg")
            .to_string(),
        Architecture::Z80 => ["a", "f", "b", "c", "d", "e", "h", "l", "sp", "pc"]
            .get(offset as usize)
            .unwrap_or(&"reg")
            .to_string(),
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
        AArch64, Arm32, Flow, GameCube, LiftedInstruction, Lifter, M68k, Mips32, Mips32Be, Ppc32,
        Ps1, Rv32, Rv64, Sh2, Sh4, Thumb, M6502, N64, RAM_SPACE, X86_32, X86_64, Z80,
    };
    use ventris_pcode::{op, InstPcode, PcodeOp, Varnode, CONST_SPACE};

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
        };
        NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([(0x1000, instruction)]),
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        }
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
    fn public_mips_function(hex: &str) -> NativeFunction {
        let bytes = parse_public_hex(hex);
        let lifter = Mips32;
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

    #[test]
    fn ssa_versions_reused_registers() {
        let ssa = build_ssa(&simple_function());
        assert_eq!(ssa.values.len(), 4);
        assert_eq!(ssa.values[0].version, 0);
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
    fn native_renderer_covers_integer_unary_and_division_ops() {
        let mut decompiler = NativeDecompiler;
        let document = decompiler.decompile(Architecture::X86_64, &unary_and_division_function());
        let c = document.render();
        assert!(c.contains("~"), "{c}");
        assert!(c.contains("-7"), "{c}");
        assert!(c.contains("/ 2"), "{c}");
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
        };
        let function = NativeFunction {
            entry: 0x1000,
            instructions: BTreeMap::from([(0x1000, instruction)]),
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        };

        let document = NativeDecompiler.decompile(Architecture::X86_64, &function);
        let c = document.render();
        assert!(c.contains("__ventris_callother(3, rax);"), "{c}");
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
            direct_c.contains("sub_2000(a0, a1, a2, a3, f12, f14);"),
            "{direct_c}"
        );
        assert!(
            direct_c.contains("DAT_8000 = sub_2000(a0, a1, a2, a3, f12, f14);"),
            "{direct_c}"
        );
        assert!(direct_document
            .ssa
            .values
            .iter()
            .any(|value| value.origin == return_register));

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
            assert!(
                candidate.contains("= 0x1234;"),
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
            statements,
            ssa: SsaFunction::default(),
            types: Vec::new(),
            warnings: Vec::new(),
        };
        let c = document.render();
        assert!(c.contains("if (flag) {"), "{c}");
        assert!(c.contains("sub_2010();"), "{c}");
        assert!(c.contains("} else {"), "{c}");
        assert!(c.contains("sub_2000();"), "{c}");
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
            statements,
            ssa: SsaFunction::default(),
            types: Vec::new(),
            warnings: Vec::new(),
        };
        let c = document.render();
        assert!(c.contains("if (flag) {"), "{c}");
        assert!(c.contains("return;"), "{c}");
        assert!(!c.contains("goto"), "{c}");
        assert!(!c.contains("loc_1020"), "{c}");
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
        assert!(statements
            .iter()
            .any(|statement| matches!(statement, NativeStatement::Label(0x1020))));
        let document = NativeDocument {
            name: "sub_1000".into(),
            return_type: Type::Void,
            statements,
            ssa: SsaFunction::default(),
            types: Vec::new(),
            warnings: Vec::new(),
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
        let branch_score = score_c(
            include_str!("../testdata/oracle/branch_call.c"),
            &NativeDecompiler
                .decompile(Architecture::X86_64, &branch_function)
                .render(),
        );
        assert!(branch_score.exact, "{branch_score:?}");
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
            ),
            (
                include_str!("../testdata/public/mips_ps2_process_exists.hex"),
                include_str!("../testdata/public/mips_ps2_process_exists.c"),
            ),
        ];
        for (hex, oracle) in mips_cases {
            let function = public_mips_function(hex);
            let candidate = NativeDecompiler.decompile(Architecture::Mips32, &function);
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
