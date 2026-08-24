use super::*;

/// C's precedence levels, ordered from the weakest binding expression to the
/// strongest. The AST currently has no comma or assignment node, but keeping
/// those slots implicit makes the conditional level's relationship explicit.
const PREC_CONDITIONAL: u8 = 1;
const PREC_UNARY: u8 = 11;
const PREC_POSTFIX: u8 = 12;
const PREC_PRIMARY: u8 = 13;

/// Render a complete native document without going through the legacy
/// `Display` implementations. Keeping traversal here AST-based is important:
/// a source spelling is not a stable intermediate representation, especially
/// once nested casts and operators need different parenthesization rules.
pub(super) fn render_document(document: &NativeDocument) -> String {
    let mut out = String::from("#include <stdint.h>\n#include <stdbool.h>\n\n");

    let parameters = if document.parameters.is_empty() {
        "void".to_owned()
    } else {
        document
            .parameters
            .iter()
            .map(|parameter| {
                format!(
                    "{} {}",
                    render_type(&parameter.ty),
                    escape_identifier(&parameter.name)
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    out.push_str(&format!(
        "{} {}({parameters})\n",
        render_type(&document.return_type),
        escape_identifier(&document.name)
    ));
    out.push_str("{\n");
    for statement in &document.statements {
        render_statement(statement, &mut out, 0);
    }
    out.push_str("}\n");
    out
}

fn render_type(ty: &Type) -> String {
    // Type::c_name intentionally uses uintptr_t for pointer facts. That is the
    // established native output policy: address arithmetic remains an integer
    // operation while memory accesses carry their pointed-to width.
    ty.c_name().to_owned()
}

fn render_statement(statement: &NativeStatement, out: &mut String, depth: usize) {
    match statement {
        NativeStatement::Label(address) => {
            write_line(out, depth, &format!("loc_{address:x}:"));
        }
        NativeStatement::Store {
            address,
            value,
            width,
            volatile,
        } => {
            if let Expr::Global { name, address, .. } = address {
                write_line(
                    out,
                    depth + 1,
                    &format!(
                        "{} = {};",
                        render_global_name(name, *address),
                        render_expr(value, 0)
                    ),
                );
            } else if !volatile {
                if let Expr::Constant { value: address, .. } = address {
                    write_line(
                        out,
                        depth + 1,
                        &format!(
                            "{} = {};",
                            render_global_name("", *address),
                            render_expr(value, 0)
                        ),
                    );
                } else {
                    render_memory_store(out, depth, address, value, *width, *volatile);
                }
            } else {
                render_memory_store(out, depth, address, value, *width, *volatile);
            }
        }
        NativeStatement::Copy {
            destination,
            source,
            width,
            volatile,
        } => {
            let destination = render_pointer_expression(destination, false);
            let source = render_pointer_expression(source, true);
            let qualifier = if *volatile { " /* volatile */" } else { "" };
            write_line(
                out,
                depth + 1,
                &format!("__builtin_memcpy({destination}, {source}, {width}){qualifier};"),
            );
        }
        NativeStatement::Call(call) | NativeStatement::Expression(call) => {
            write_line(out, depth + 1, &format!("{};", render_expr(call, 0)));
        }
        NativeStatement::DeclareLocal { name, ty } => {
            write_line(out, depth + 1, &format!("{} {};", ty.c_name(), name));
        }
        NativeStatement::Assign {
            destination,
            source,
        } => {
            write_line(
                out,
                depth + 1,
                &format!(
                    "{} = {};",
                    render_expr(destination, 0),
                    render_expr(source, 0)
                ),
            );
        }
        NativeStatement::Declare { name, ty, value } => {
            write_line(
                out,
                depth + 1,
                &format!("{} {} = {};", ty.c_name(), name, render_expr(value, 0)),
            );
        }
        NativeStatement::IfGoto { condition, target } => {
            write_line(
                out,
                depth + 1,
                &format!("if ({}) goto loc_{target:x};", render_expr(condition, 0)),
            );
        }
        NativeStatement::IfReturn { condition, value } => {
            write_line(
                out,
                depth + 1,
                &format!("if ({}) {{", render_expr(condition, 0)),
            );
            match value {
                Some(value) => write_line(
                    out,
                    depth + 2,
                    &format!("return {};", render_expr(value, 0)),
                ),
                None => write_line(out, depth + 2, "return;"),
            }
            write_line(out, depth + 1, "}");
        }
        NativeStatement::IfElse {
            condition,
            then_body,
            else_body,
        } => {
            write_line(
                out,
                depth + 1,
                &format!("if ({}) {{", render_expr(condition, 0)),
            );
            for nested in then_body {
                render_statement(nested, out, depth + 1);
            }
            if else_body.is_empty() {
                write_line(out, depth + 1, "}");
            } else {
                write_line(out, depth + 1, "} else {");
                for nested in else_body {
                    render_statement(nested, out, depth + 1);
                }
                write_line(out, depth + 1, "}");
            }
        }
        NativeStatement::While { condition, body } => {
            write_line(
                out,
                depth + 1,
                &format!("while ({}) {{", render_expr(condition, 0)),
            );
            for nested in body {
                render_statement(nested, out, depth + 1);
            }
            write_line(out, depth + 1, "}");
        }
        NativeStatement::DoWhile { body, condition } => {
            write_line(out, depth + 1, "do {");
            for nested in body {
                render_statement(nested, out, depth + 1);
            }
            write_line(
                out,
                depth + 1,
                &format!("}} while ({});", render_expr(condition, 0)),
            );
        }
        NativeStatement::For {
            initializer,
            condition,
            step,
            body,
        } => {
            let initializer = initializer
                .as_deref()
                .map(render_for_clause)
                .unwrap_or_default();
            let condition = condition
                .as_ref()
                .map(|condition| render_expr(condition, 0))
                .unwrap_or_default();
            let step = step.as_deref().map(render_for_clause).unwrap_or_default();
            write_line(
                out,
                depth + 1,
                &format!("for ({initializer}; {condition}; {step}) {{"),
            );
            for nested in body {
                render_statement(nested, out, depth + 1);
            }
            write_line(out, depth + 1, "}");
        }
        NativeStatement::Switch {
            expression,
            cases,
            default,
        } => {
            write_line(
                out,
                depth + 1,
                &format!("switch ({}) {{", render_expr(expression, 0)),
            );
            for (value, body) in cases {
                write_line(out, depth + 2, &format!("case {value}:"));
                for nested in body {
                    render_statement(nested, out, depth + 2);
                }
            }
            if !default.is_empty() {
                write_line(out, depth + 2, "default:");
                for nested in default {
                    render_statement(nested, out, depth + 2);
                }
            }
            write_line(out, depth + 1, "}");
        }
        NativeStatement::Break => write_line(out, depth + 1, "break;"),
        NativeStatement::Continue => write_line(out, depth + 1, "continue;"),
        NativeStatement::Goto(target) => {
            write_line(out, depth + 1, &format!("goto loc_{target:x};"));
        }
        NativeStatement::IndirectGoto(target) => {
            // GNU C's computed-goto form is the least lossy spelling for an
            // irreducible transfer whose destination is not a known label.
            write_line(
                out,
                depth + 1,
                &format!("goto *({});", render_expr(target, 0)),
            );
        }
        NativeStatement::Return(value) => {
            let line = match value {
                Some(value) => format!("return {};", render_expr(value, 0)),
                None => "return;".to_owned(),
            };
            write_line(out, depth + 1, &line);
        }
    }
}

fn render_for_clause(statement: &NativeStatement) -> String {
    match statement {
        NativeStatement::Store {
            address,
            value,
            width,
            volatile,
        } => render_store_clause(address, value, *width, *volatile),
        NativeStatement::Copy {
            destination,
            source,
            width,
            volatile,
        } => {
            let destination = render_pointer_expression(destination, false);
            let source = render_pointer_expression(source, true);
            let qualifier = if *volatile { " /* volatile */" } else { "" };
            format!("__builtin_memcpy({destination}, {source}, {width}){qualifier}")
        }
        NativeStatement::Call(call) | NativeStatement::Expression(call) => render_expr(call, 0),
        NativeStatement::DeclareLocal { name, ty } => format!("{} {}", ty.c_name(), name),
        NativeStatement::Assign {
            destination,
            source,
        } => {
            format!(
                "{} = {}",
                render_expr(destination, 0),
                render_expr(source, 0)
            )
        }
        NativeStatement::Declare { name, ty, value } => {
            format!("{} {} = {}", ty.c_name(), name, render_expr(value, 0))
        }
        // A control-transfer statement cannot be put in a for-header. The
        // no-op expression keeps malformed/incomplete input valid C while the
        // original statement remains represented by the surrounding AST body.
        NativeStatement::Label(_)
        | NativeStatement::IfGoto { .. }
        | NativeStatement::IfReturn { .. }
        | NativeStatement::IfElse { .. }
        | NativeStatement::While { .. }
        | NativeStatement::DoWhile { .. }
        | NativeStatement::For { .. }
        | NativeStatement::Switch { .. }
        | NativeStatement::Goto(_)
        | NativeStatement::IndirectGoto(_)
        | NativeStatement::Return(_)
        | NativeStatement::Break
        | NativeStatement::Continue => "(void)0".to_owned(),
    }
}

fn render_store_clause(address: &Expr, value: &Expr, width: u32, volatile: bool) -> String {
    let left = if let Expr::Global { name, address, .. } = address {
        render_global_name(name, *address)
    } else if !volatile {
        if let Expr::Constant { value: address, .. } = address {
            render_global_name("", *address)
        } else {
            render_memory_lvalue(address, width, volatile)
        }
    } else {
        render_memory_lvalue(address, width, volatile)
    };
    format!("{left} = {}", render_expr(value, 0))
}

fn render_memory_lvalue(address: &Expr, width: u32, volatile: bool) -> String {
    let ty = render_type(&Type::from_width(width));
    let qualifier = if volatile { "volatile " } else { "" };
    format!(
        "*({qualifier}{ty} *)(uintptr_t)({})",
        render_expr(address, 0)
    )
}

fn render_memory_store(
    out: &mut String,
    depth: usize,
    address: &Expr,
    value: &Expr,
    width: u32,
    volatile: bool,
) {
    write_line(
        out,
        depth + 1,
        &format!(
            "{} = {};",
            render_memory_lvalue(address, width, volatile),
            render_expr(value, 0)
        ),
    );
}

fn render_pointer_expression(value: &Expr, constant: bool) -> String {
    let qualifier = if constant { "const " } else { "" };
    match value {
        Expr::Global { name, address, .. } => {
            format!("&{}", render_global_name(name, *address))
        }
        Expr::Load { address, .. } => format!(
            "({qualifier}void *)(uintptr_t)({})",
            render_expr(address, 0)
        ),
        _ => format!("({qualifier}void *)(uintptr_t)({})", render_expr(value, 0)),
    }
}

fn write_line(out: &mut String, depth: usize, line: &str) {
    write_indent(out, depth);
    out.push_str(line);
    out.push('\n');
}

fn write_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("    ");
    }
}

/// Magnitude of a constant that is more readable as a subtraction.
///
/// Only clearly-negative small offsets qualify: a value near the top of its
/// width is an offset, while an arbitrary large constant is a mask or a bit
/// pattern and must keep its written form.
fn negative_offset(value: u64, width: u32) -> Option<u64> {
    let bits = width.saturating_mul(8);
    if bits == 0 || bits > 64 {
        return None;
    }
    let span = if bits == 64 {
        u64::MAX
    } else {
        (1_u64 << bits) - 1
    };
    let magnitude = span.wrapping_sub(value).wrapping_add(1);
    (value > span / 2 && magnitude <= 0xffff).then_some(magnitude)
}

fn render_expr(value: &Expr, parent_precedence: u8) -> String {
    // Select is deliberately emitted with one pair of parentheses at every
    // occurrence. Besides matching the existing source style, this prevents
    // a nested conditional from ever stealing the surrounding `:` delimiter.
    if let Expr::Select {
        condition,
        when_true,
        when_false,
    } = value
    {
        return format!(
            "({} ? {} : {})",
            render_expr(condition, PREC_CONDITIONAL + 1),
            render_expr(when_true, PREC_CONDITIONAL + 1),
            render_expr(when_false, PREC_CONDITIONAL + 1)
        );
    }

    let precedence = expr_precedence(value);
    let rendered = match value {
        Expr::Constant { value, .. } => render_constant(*value),
        Expr::Parameter { name, .. }
        | Expr::Register { name, .. }
        | Expr::Temporary { name, .. } => escape_identifier(name),
        Expr::Binary { op, left, right } => {
            let precedence = op.precedence();
            // A folded negative offset reads as a subtraction. Printing
            // `rsp + 0xfffffffffffffff0` for `rsp - 0x10` is technically the
            // same value and useless to a reader.
            if let (BinaryOp::Add, Expr::Constant { value, width }) = (op, right.as_ref())
                && let Some(magnitude) = negative_offset(*value, *width)
            {
                return format!(
                    "{} - {:#x}",
                    render_expr(left, BinaryOp::Sub.precedence()),
                    magnitude
                );
            }
            // C binary operators are left associative. The right child must
            // therefore bind more strongly than the operator to retain an
            // equal-precedence AST grouping (`a - (b - c)`).
            format!(
                "{} {} {}",
                render_expr(left, precedence),
                op.text(),
                render_expr(right, precedence.saturating_add(1))
            )
        }
        Expr::Not(value) => format!("!{}", render_unary_operand(value)),
        Expr::Neg(value) => format!("-{}", render_unary_operand(value)),
        Expr::BitNot(value) => format!("~{}", render_unary_operand(value)),
        Expr::Cast { ty, value } => {
            format!("({})({})", render_type(ty), render_expr(value, 0))
        }
        Expr::Typed { value, .. } => return render_expr(value, parent_precedence),
        Expr::Global { name, address, .. } => render_global_name(name, *address),
        Expr::Load { address, width } => {
            if let Expr::Constant { value, .. } = address.as_ref() {
                render_global_name("", *value)
            } else {
                format!(
                    "*({} *)(uintptr_t)({})",
                    render_type(&Type::from_width(*width)),
                    render_expr(address, 0)
                )
            }
        }
        Expr::Call {
            target,
            callee,
            args,
        } => {
            let function = callee
                .as_deref()
                .map(|callee| render_expr(callee, PREC_POSTFIX))
                .or_else(|| target.map(|address| format!("sub_{address:x}")))
                .unwrap_or_else(|| "indirect_call".to_owned());
            let args = args
                .iter()
                .map(|argument| render_expr(argument, 0))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{function}({args})")
        }
        Expr::Builtin { name, args } => {
            let args = args
                .iter()
                .map(|argument| render_expr(argument, 0))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{}({args})", escape_identifier(name))
        }
        Expr::Select { .. } => unreachable!("select expressions are handled above"),
    };

    if precedence < parent_precedence {
        format!("({rendered})")
    } else {
        rendered
    }
}

fn expr_precedence(value: &Expr) -> u8 {
    match value {
        Expr::Typed { value, .. } => expr_precedence(value),
        Expr::Select { .. } => PREC_CONDITIONAL,
        Expr::Binary { op, .. } => op.precedence(),
        Expr::Not(_) | Expr::Neg(_) | Expr::BitNot(_) | Expr::Cast { .. } | Expr::Load { .. } => {
            PREC_UNARY
        }
        Expr::Call { .. } | Expr::Builtin { .. } => PREC_POSTFIX,
        Expr::Constant { .. }
        | Expr::Parameter { .. }
        | Expr::Register { .. }
        | Expr::Temporary { .. }
        | Expr::Global { .. } => PREC_PRIMARY,
    }
}

fn render_unary_operand(value: &Expr) -> String {
    let rendered = render_expr(value, PREC_UNARY);
    // `--x` and `++x` are tokenized as decrement/increment rather than two
    // unary operators. Parenthesizing every prefix-unary child is cheap and
    // also keeps future unary additions from creating a lexical ambiguity.
    if is_prefix_unary(value) {
        format!("({rendered})")
    } else {
        rendered
    }
}

fn is_prefix_unary(value: &Expr) -> bool {
    match value {
        Expr::Not(_) | Expr::Neg(_) | Expr::BitNot(_) => true,
        Expr::Typed { value, .. } => is_prefix_unary(value),
        _ => false,
    }
}

fn render_constant(value: u64) -> String {
    if value <= 9 {
        value.to_string()
    } else {
        format!("0x{value:x}")
    }
}

fn render_global_name(name: &str, address: u64) -> String {
    if name.is_empty() {
        format!("DAT_{address:x}")
    } else {
        escape_identifier(name)
    }
}

fn escape_identifier(name: &str) -> String {
    let mut escaped = String::new();
    for (index, character) in name.chars().enumerate() {
        if (index == 0 && character.is_ascii_digit()) || !is_identifier_character(index, character)
        {
            escaped.push_str(&format!("_u{:x}_", u32::from(character)));
        } else {
            escaped.push(character);
        }
    }

    if escaped.is_empty() {
        escaped.push_str("_unnamed");
    }
    if is_c_keyword(&escaped) {
        escaped.insert(0, '_');
    }
    escaped
}

fn is_identifier_character(index: usize, character: char) -> bool {
    if index == 0 {
        character == '_' || character.is_ascii_alphabetic()
    } else {
        character == '_' || character.is_ascii_alphanumeric()
    }
}

fn is_c_keyword(identifier: &str) -> bool {
    matches!(
        identifier,
        "auto"
            | "break"
            | "case"
            | "char"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extern"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "inline"
            | "int"
            | "long"
            | "register"
            | "restrict"
            | "return"
            | "short"
            | "signed"
            | "sizeof"
            | "static"
            | "struct"
            | "switch"
            | "typedef"
            | "union"
            | "unsigned"
            | "void"
            | "volatile"
            | "while"
            | "_Alignas"
            | "_Alignof"
            | "_Atomic"
            | "_Bool"
            | "_Complex"
            | "_Generic"
            | "_Imaginary"
            | "_Noreturn"
            | "_Static_assert"
            | "_Thread_local"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn variable(name: &str) -> Expr {
        Expr::Temporary {
            name: name.to_owned(),
            width: 4,
        }
    }

    fn document(statements: Vec<NativeStatement>) -> NativeDocument {
        NativeDocument {
            name: "render_test".to_owned(),
            return_type: Type::Unsigned(32),
            parameters: Vec::new(),
            statements,
            ssa: SsaFunction::default(),
            types: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn logical_and_bitwise_precedence_matches_c() {
        let expression = Expr::Binary {
            op: BinaryOp::LogicalOr,
            left: Box::new(variable("flag")),
            right: Box::new(Expr::Binary {
                op: BinaryOp::LogicalAnd,
                left: Box::new(variable("ready")),
                right: Box::new(Expr::Binary {
                    op: BinaryOp::Or,
                    left: Box::new(variable("mask")),
                    right: Box::new(Expr::constant(1, 4)),
                }),
            }),
        };
        assert_eq!(render_expr(&expression, 0), "flag || ready && mask | 1");
    }

    #[test]
    fn right_associative_source_parentheses_preserve_binary_ast() {
        let expression = Expr::Binary {
            op: BinaryOp::Sub,
            left: Box::new(variable("a")),
            right: Box::new(Expr::Binary {
                op: BinaryOp::Sub,
                left: Box::new(variable("b")),
                right: Box::new(variable("c")),
            }),
        };
        assert_eq!(render_expr(&expression, 0), "a - (b - c)");
    }

    #[test]
    fn identifiers_are_valid_and_keywords_are_escaped() {
        assert_eq!(escape_identifier("switch"), "_switch");
        assert_eq!(escape_identifier("9 bad-name"), "_u39__u20_bad_u2d_name");
        assert_eq!(escape_identifier(""), "_unnamed");
    }

    #[test]
    fn empty_else_is_not_printed() {
        let source = document(vec![NativeStatement::IfElse {
            condition: variable("flag"),
            then_body: vec![NativeStatement::Return(Some(Expr::constant(1, 4)))],
            else_body: Vec::new(),
        }])
        .render();
        assert!(source.contains("if (flag) {"));
        assert!(!source.contains("else"));
    }

    #[test]
    fn structured_switch_and_for_render_as_c_ast() {
        let induction = variable("i");
        let source = document(vec![
            NativeStatement::For {
                initializer: None,
                condition: Some(Expr::Binary {
                    op: BinaryOp::Less,
                    left: Box::new(induction.clone()),
                    right: Box::new(Expr::constant(3, 4)),
                }),
                step: None,
                body: vec![NativeStatement::Switch {
                    expression: induction,
                    cases: vec![(
                        1,
                        vec![
                            NativeStatement::Expression(Expr::Builtin {
                                name: "work",
                                args: Vec::new(),
                            }),
                            NativeStatement::Break,
                        ],
                    )],
                    default: vec![NativeStatement::Break],
                }],
            },
            NativeStatement::Return(Some(Expr::constant(0, 4))),
        ])
        .render();
        assert!(source.contains("for (; i < 3; ) {"), "{source}");
        assert!(source.contains("switch (i) {"), "{source}");
        assert!(source.contains("case 1:"), "{source}");
        assert!(source.contains("default:"), "{source}");
    }
}
