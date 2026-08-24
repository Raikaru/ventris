//! Promotion of frame-relative memory accesses to named locals.
//!
//! A compiler spills to the stack constantly, and rendering every spill as
//! `*(uint32_t *)(uintptr_t)(sp - 0x30)` buries the program in address
//! arithmetic and casts. Naming the slot recovers what the source wrote: a
//! local variable.
//!
//! Promotion is refused unless the slot is provably a private scalar. A slot
//! whose address escapes, or whose bytes are read at more than one width, or
//! that overlaps another accessed slot, keeps its memory form: those are the
//! cases where a name would assert something the program does not.

use std::collections::{BTreeMap, BTreeSet};

use super::{Expr, NativeStatement, Type};

/// One frame slot's accessed byte range and width.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Slot {
    offset: i64,
    width: u32,
}

#[derive(Default)]
struct Survey {
    slots: BTreeMap<i64, BTreeSet<u32>>,
    escaped: bool,
}

/// Splits a frame-relative address into its signed constant offset.
fn frame_offset(address: &Expr, frame_registers: &BTreeSet<String>) -> Option<i64> {
    match address {
        Expr::Register { name, .. } if frame_registers.contains(name) => Some(0),
        Expr::Binary {
            op: super::BinaryOp::Add,
            left,
            right,
        } => {
            let base = match left.as_ref() {
                Expr::Register { name, .. } if frame_registers.contains(name) => 0,
                _ => return None,
            };
            match right.as_ref() {
                Expr::Constant { value, width } => {
                    Some(base + super::signed_constant_value(*value, *width))
                }
                _ => None,
            }
        }
        Expr::Cast { value, .. } | Expr::Typed { value, .. } => {
            frame_offset(value, frame_registers)
        }
        _ => None,
    }
}

fn survey_expr(value: &Expr, frame_registers: &BTreeSet<String>, survey: &mut Survey) {
    match value {
        Expr::Load { address, width } => match frame_offset(address, frame_registers) {
            Some(offset) => {
                survey.slots.entry(offset).or_default().insert(*width);
            }
            None => survey_expr(address, frame_registers, survey),
        },
        Expr::Field { base, .. } => survey_expr(base, frame_registers, survey),
        Expr::Register { name, .. } if frame_registers.contains(name) => {
            // The frame register reached a position that is not an access
            // address, so a slot's address can leave the function.
            survey.escaped = true;
        }
        Expr::Binary { left, right, .. } => {
            survey_expr(left, frame_registers, survey);
            survey_expr(right, frame_registers, survey);
        }
        Expr::Not(inner) | Expr::Neg(inner) | Expr::BitNot(inner) => {
            survey_expr(inner, frame_registers, survey);
        }
        Expr::Cast { value, .. } | Expr::Typed { value, .. } => {
            survey_expr(value, frame_registers, survey);
        }
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => {
            survey_expr(condition, frame_registers, survey);
            survey_expr(when_true, frame_registers, survey);
            survey_expr(when_false, frame_registers, survey);
        }
        Expr::Call { callee, args, .. } => {
            if let Some(callee) = callee {
                survey_expr(callee, frame_registers, survey);
            }
            for arg in args {
                survey_expr(arg, frame_registers, survey);
            }
        }
        Expr::Builtin { args, .. } => {
            for arg in args {
                survey_expr(arg, frame_registers, survey);
            }
        }
        Expr::Constant { .. }
        | Expr::Parameter { .. }
        | Expr::Register { .. }
        | Expr::Temporary { .. }
        | Expr::Global { .. } => {}
    }
}

fn survey_statement(
    statement: &NativeStatement,
    frame_registers: &BTreeSet<String>,
    survey: &mut Survey,
) {
    match statement {
        NativeStatement::Store {
            address,
            value,
            width,
            volatile,
        } => {
            match frame_offset(address, frame_registers) {
                Some(offset) if !*volatile => {
                    survey.slots.entry(offset).or_default().insert(*width);
                }
                _ => survey_expr(address, frame_registers, survey),
            }
            survey_expr(value, frame_registers, survey);
        }
        NativeStatement::DeclareLocal { .. } => {}
        NativeStatement::Assign {
            destination,
            source,
        } => {
            survey_expr(destination, frame_registers, survey);
            survey_expr(source, frame_registers, survey);
        }
        NativeStatement::Copy {
            destination,
            source,
            ..
        } => {
            // An aggregate copy names a range, not a scalar slot.
            survey_expr(destination, frame_registers, survey);
            survey_expr(source, frame_registers, survey);
            if frame_offset(destination, frame_registers).is_some()
                || frame_offset(source, frame_registers).is_some()
            {
                survey.escaped = true;
            }
        }
        NativeStatement::Call(value)
        | NativeStatement::IndirectGoto(value)
        | NativeStatement::Expression(value)
        | NativeStatement::Declare { value, .. } => {
            survey_expr(value, frame_registers, survey);
        }
        NativeStatement::IfGoto { condition, .. } => {
            survey_expr(condition, frame_registers, survey);
        }
        NativeStatement::IfReturn { condition, value } => {
            survey_expr(condition, frame_registers, survey);
            if let Some(value) = value {
                survey_expr(value, frame_registers, survey);
            }
        }
        NativeStatement::IfElse {
            condition,
            then_body,
            else_body,
        } => {
            survey_expr(condition, frame_registers, survey);
            for nested in then_body.iter().chain(else_body) {
                survey_statement(nested, frame_registers, survey);
            }
        }
        NativeStatement::While { condition, body } => {
            survey_expr(condition, frame_registers, survey);
            for nested in body {
                survey_statement(nested, frame_registers, survey);
            }
        }
        NativeStatement::DoWhile { body, condition } => {
            for nested in body {
                survey_statement(nested, frame_registers, survey);
            }
            survey_expr(condition, frame_registers, survey);
        }
        NativeStatement::For {
            initializer,
            condition,
            step,
            body,
        } => {
            for nested in initializer.iter().chain(step) {
                survey_statement(nested, frame_registers, survey);
            }
            if let Some(condition) = condition {
                survey_expr(condition, frame_registers, survey);
            }
            for nested in body {
                survey_statement(nested, frame_registers, survey);
            }
        }
        NativeStatement::Switch {
            expression,
            cases,
            default,
        } => {
            survey_expr(expression, frame_registers, survey);
            for (_, body) in cases {
                for nested in body {
                    survey_statement(nested, frame_registers, survey);
                }
            }
            for nested in default {
                survey_statement(nested, frame_registers, survey);
            }
        }
        NativeStatement::Return(value) => {
            if let Some(value) = value {
                survey_expr(value, frame_registers, survey);
            }
        }
        NativeStatement::Label(_)
        | NativeStatement::Goto(_)
        | NativeStatement::Break
        | NativeStatement::Continue => {}
    }
}

/// Selects the slots that a single name can describe without losing meaning.
fn promotable(survey: &Survey) -> BTreeMap<i64, Slot> {
    if survey.escaped {
        return BTreeMap::new();
    }
    let single_width = survey
        .slots
        .iter()
        .filter_map(|(offset, widths)| {
            let mut widths = widths.iter();
            let width = *widths.next()?;
            widths.next().is_none().then_some(Slot {
                offset: *offset,
                width,
            })
        })
        .collect::<Vec<_>>();
    single_width
        .iter()
        .filter(|slot| {
            single_width.iter().all(|other| {
                other.offset == slot.offset
                    || other.offset + i64::from(other.width) <= slot.offset
                    || slot.offset + i64::from(slot.width) <= other.offset
            })
        })
        .map(|slot| (slot.offset, *slot))
        .collect()
}

fn slot_name(offset: i64) -> String {
    if offset < 0 {
        format!("local_{:x}", offset.unsigned_abs())
    } else {
        format!("stack_{offset:x}")
    }
}

/// The synthetic address that distinguishes one named slot from another.
fn slot_address(offset: i64) -> u64 {
    offset as u64
}

fn slot_expr(slot: &Slot) -> Expr {
    Expr::Global {
        name: slot_name(slot.offset),
        address: slot_address(slot.offset),
        width: slot.width,
    }
}

fn rewrite_expr(value: &mut Expr, frame_registers: &BTreeSet<String>, slots: &BTreeMap<i64, Slot>) {
    if let Expr::Load { address, width } = value
        && let Some(offset) = frame_offset(address, frame_registers)
        && let Some(slot) = slots.get(&offset)
        && slot.width == *width
    {
        *value = slot_expr(slot);
        return;
    }
    match value {
        Expr::Load { address, .. } => rewrite_expr(address, frame_registers, slots),
        Expr::Field { base, .. } => rewrite_expr(base, frame_registers, slots),
        Expr::Binary { left, right, .. } => {
            rewrite_expr(left, frame_registers, slots);
            rewrite_expr(right, frame_registers, slots);
        }
        Expr::Not(inner) | Expr::Neg(inner) | Expr::BitNot(inner) => {
            rewrite_expr(inner, frame_registers, slots);
        }
        Expr::Cast { value, .. } | Expr::Typed { value, .. } => {
            rewrite_expr(value, frame_registers, slots);
        }
        Expr::Select {
            condition,
            when_true,
            when_false,
        } => {
            rewrite_expr(condition, frame_registers, slots);
            rewrite_expr(when_true, frame_registers, slots);
            rewrite_expr(when_false, frame_registers, slots);
        }
        Expr::Call { callee, args, .. } => {
            if let Some(callee) = callee {
                rewrite_expr(callee, frame_registers, slots);
            }
            for arg in args {
                rewrite_expr(arg, frame_registers, slots);
            }
        }
        Expr::Builtin { args, .. } => {
            for arg in args {
                rewrite_expr(arg, frame_registers, slots);
            }
        }
        Expr::Constant { .. }
        | Expr::Parameter { .. }
        | Expr::Register { .. }
        | Expr::Temporary { .. }
        | Expr::Global { .. } => {}
    }
}

fn rewrite_statement(
    statement: &mut NativeStatement,
    frame_registers: &BTreeSet<String>,
    slots: &BTreeMap<i64, Slot>,
) {
    if let NativeStatement::Store {
        address,
        value,
        width,
        ..
    } = statement
        && let Some(offset) = frame_offset(address, frame_registers)
        && let Some(slot) = slots.get(&offset)
        && slot.width == *width
    {
        *address = slot_expr(slot);
        rewrite_expr(value, frame_registers, slots);
        return;
    }
    match statement {
        NativeStatement::Store { address, value, .. } => {
            rewrite_expr(address, frame_registers, slots);
            rewrite_expr(value, frame_registers, slots);
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
            rewrite_expr(destination, frame_registers, slots);
            rewrite_expr(source, frame_registers, slots);
        }
        NativeStatement::DeclareLocal { .. } => {}
        NativeStatement::Call(value)
        | NativeStatement::IndirectGoto(value)
        | NativeStatement::Expression(value)
        | NativeStatement::Declare { value, .. } => {
            rewrite_expr(value, frame_registers, slots);
        }
        NativeStatement::IfGoto { condition, .. } => {
            rewrite_expr(condition, frame_registers, slots);
        }
        NativeStatement::IfReturn { condition, value } => {
            rewrite_expr(condition, frame_registers, slots);
            if let Some(value) = value {
                rewrite_expr(value, frame_registers, slots);
            }
        }
        NativeStatement::IfElse {
            condition,
            then_body,
            else_body,
        } => {
            rewrite_expr(condition, frame_registers, slots);
            for nested in then_body.iter_mut().chain(else_body) {
                rewrite_statement(nested, frame_registers, slots);
            }
        }
        NativeStatement::While { condition, body } => {
            rewrite_expr(condition, frame_registers, slots);
            for nested in body {
                rewrite_statement(nested, frame_registers, slots);
            }
        }
        NativeStatement::DoWhile { body, condition } => {
            for nested in body {
                rewrite_statement(nested, frame_registers, slots);
            }
            rewrite_expr(condition, frame_registers, slots);
        }
        NativeStatement::For {
            initializer,
            condition,
            step,
            body,
        } => {
            for nested in initializer.iter_mut().chain(step) {
                rewrite_statement(nested, frame_registers, slots);
            }
            if let Some(condition) = condition {
                rewrite_expr(condition, frame_registers, slots);
            }
            for nested in body {
                rewrite_statement(nested, frame_registers, slots);
            }
        }
        NativeStatement::Switch {
            expression,
            cases,
            default,
        } => {
            rewrite_expr(expression, frame_registers, slots);
            for (_, body) in cases {
                for nested in body {
                    rewrite_statement(nested, frame_registers, slots);
                }
            }
            for nested in default {
                rewrite_statement(nested, frame_registers, slots);
            }
        }
        NativeStatement::Return(value) => {
            if let Some(value) = value {
                rewrite_expr(value, frame_registers, slots);
            }
        }
        NativeStatement::Label(_)
        | NativeStatement::Goto(_)
        | NativeStatement::Break
        | NativeStatement::Continue => {}
    }
}

/// Names every frame slot that one variable can stand for, and declares it.
pub(super) fn promote_frame_slots(
    statements: &mut Vec<NativeStatement>,
    frame_registers: &BTreeSet<String>,
) {
    if frame_registers.is_empty() {
        return;
    }
    let mut survey = Survey::default();
    for statement in statements.iter() {
        survey_statement(statement, frame_registers, &mut survey);
    }
    let slots = promotable(&survey);
    if slots.is_empty() {
        return;
    }
    for statement in statements.iter_mut() {
        rewrite_statement(statement, frame_registers, &slots);
    }
    for slot in slots.values().rev() {
        statements.insert(
            0,
            NativeStatement::Declare {
                name: slot_name(slot.offset),
                ty: Type::from_width(slot.width),
                value: Expr::constant(0, slot.width),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_registers() -> BTreeSet<String> {
        BTreeSet::from(["sp".to_owned()])
    }

    fn frame_address(offset: i64) -> Expr {
        Expr::Binary {
            op: super::super::BinaryOp::Add,
            left: Box::new(Expr::Register {
                name: "sp".into(),
                width: 4,
            }),
            right: Box::new(Expr::Constant {
                value: offset as u64,
                width: 4,
            }),
        }
    }

    fn store(offset: i64, width: u32, value: u64) -> NativeStatement {
        NativeStatement::Store {
            address: frame_address(offset),
            value: Expr::constant(value, width),
            width,
            volatile: false,
        }
    }

    #[test]
    fn a_private_scalar_slot_becomes_a_declared_local() {
        let mut statements = vec![
            store(-0x30, 4, 7),
            NativeStatement::Return(Some(Expr::Load {
                address: Box::new(frame_address(-0x30)),
                width: 4,
            })),
        ];
        promote_frame_slots(&mut statements, &frame_registers());
        assert_eq!(
            statements[0],
            NativeStatement::Declare {
                name: "local_30".into(),
                ty: Type::Unsigned(32),
                value: Expr::constant(0, 4),
            }
        );
        let rendered = format!("{statements:?}");
        assert!(rendered.contains("local_30"), "{rendered}");
        assert!(rendered.contains("Load") == false, "{rendered}");
    }

    #[test]
    fn a_slot_read_at_two_widths_keeps_its_memory_form() {
        let mut statements = vec![
            store(-0x30, 1, 0x6e),
            NativeStatement::Return(Some(Expr::Load {
                address: Box::new(frame_address(-0x30)),
                width: 4,
            })),
        ];
        let before = statements.clone();
        promote_frame_slots(&mut statements, &frame_registers());
        assert_eq!(statements, before);
    }

    #[test]
    fn a_slot_whose_address_escapes_keeps_its_memory_form() {
        let mut statements = vec![
            store(-0x30, 4, 7),
            NativeStatement::Call(Expr::Call {
                target: Some(0x1000),
                callee: None,
                args: vec![frame_address(-0x30)],
            }),
        ];
        let before = statements.clone();
        promote_frame_slots(&mut statements, &frame_registers());
        assert_eq!(statements, before);
    }

    #[test]
    fn overlapping_slots_keep_their_memory_form() {
        let mut statements = vec![store(-0x30, 4, 7), store(-0x2e, 2, 1)];
        let before = statements.clone();
        promote_frame_slots(&mut statements, &frame_registers());
        assert_eq!(statements, before);
    }
}
