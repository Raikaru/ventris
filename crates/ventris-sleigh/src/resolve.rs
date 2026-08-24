use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use ventris_pcode::{CONST_SPACE, PcodeOp, op};

use crate::emit::{
    dynamic_handle, fix_space, fix_value, fix_varnode, materialize_dynamic_pointer,
    space_id_varnode,
};
use crate::{
    AttributeValue, ConstTemplate, ConstructTemplate, Constructor, Element, EmitError, FixedHandle,
    HandleSelector, HandleTemplate, SleighSpec, TemplateContext,
};

const ATTR_VAL: u16 = 2;
const ATTR_ID: u16 = 3;
const ATTR_SPACE: u16 = 4;
const ATTR_OFF: u16 = 6;
const ATTR_INDEX: u16 = 9;
const ATTR_STARTBIT: u16 = 14;
const ATTR_SIZE: u16 = 15;
const ATTR_MINLEN: u16 = 18;
const ATTR_BASE: u16 = 19;
const ATTR_SUBSYM: u16 = 23;
const ATTR_SHIFT: u16 = 29;
const ATTR_ENDBIT: u16 = 30;
const ATTR_SIGNBIT: u16 = 31;
const ATTR_ENDBYTE: u16 = 32;
const ATTR_STARTBYTE: u16 = 33;
const ATTR_BIGENDIAN: u16 = 35;

const ELEM_OPERAND_EXP: u16 = 12;
const ELEM_OPERAND_SYM: u16 = 13;
const ELEM_VARNODE_SYM: u16 = 23;
const ELEM_TOKENFIELD: u16 = 27;
const ELEM_VAR: u16 = 28;
const ELEM_CONTEXTFIELD: u16 = 29;
const ELEM_VALUE_SYM: u16 = 39;
const ELEM_END_SYM: u16 = 43;
const ELEM_AND_EXP: u16 = 47;
const ELEM_DIV_EXP: u16 = 48;
const ELEM_LSHIFT_EXP: u16 = 49;
const ELEM_MINUS_EXP: u16 = 50;
const ELEM_MULT_EXP: u16 = 51;
const ELEM_NOT_EXP: u16 = 52;
const ELEM_OR_EXP: u16 = 53;
const ELEM_PLUS_EXP: u16 = 54;
const ELEM_RSHIFT_EXP: u16 = 55;
const ELEM_SUB_EXP: u16 = 56;
const ELEM_XOR_EXP: u16 = 57;
const ELEM_INTB: u16 = 58;
const ELEM_END_EXP: u16 = 59;
const ELEM_NEXT2_EXP: u16 = 60;
const ELEM_START_EXP: u16 = 61;
const ELEM_NAME_SYM: u16 = 64;
const ELEM_NEXT2_SYM: u16 = 67;
const ELEM_START_SYM: u16 = 69;
const ELEM_VALUEMAP_SYM: u16 = 73;
const ELEM_VALUETAB: u16 = 75;
const ELEM_VARLIST_SYM: u16 = 76;
const ELEM_SUBTABLE_SYM: u16 = 71;

pub fn resolve_operand_handles(
    spec: &SleighSpec,
    constructor: &Constructor,
    bytes: &[u8],
    context: &[u32],
    template_context: &TemplateContext,
) -> Result<Vec<FixedHandle>, HandleError> {
    let mut instruction_context = context.to_vec();
    Ok(resolve_node(
        spec,
        constructor,
        bytes,
        &mut instruction_context,
        template_context,
        0,
    )?
    .handles)
}

pub fn emit_constructor(
    spec: &SleighSpec,
    constructor: &Constructor,
    bytes: &[u8],
    context: &[u32],
    template_context: &TemplateContext,
) -> Result<Vec<PcodeOp>, ConstructorEmitError> {
    let mut resolved_context = template_context.clone();
    resolved_context.unique_space = Some(spec.unique_space);
    resolved_context.unique_offset =
        (resolved_context.address & spec.unique_allocation_mask).wrapping_shl(8);
    resolved_context.space_ids = Some(spec.space_ids.clone());
    let mut instruction_context = context.to_vec();
    let node = resolve_node(
        spec,
        constructor,
        bytes,
        &mut instruction_context,
        &resolved_context,
        0,
    )?;
    let mut builder = Builder::default();
    build_node(&node, None, &resolved_context, &[], false, &mut builder)?;
    let mut operations = builder.finish().map_err(ConstructorEmitError::Emit)?;
    normalize_operations(spec, &mut operations);
    Ok(operations)
}

/// Resolves an instruction's complete constructor tree before emitting p-code.
///
/// Variable-length languages encode byte consumption in nested subtable
/// constructors. The root constructor's minimum length is therefore not the
/// instruction length. Resolution runs twice so `inst_next` expressions in
/// the final p-code observe the complete recursively measured length.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EmittedInstruction {
    pub length: u32,
    pub operations: Vec<PcodeOp>,
    pub delay_slot_bytes: u32,
}

pub fn emit_instruction(
    spec: &SleighSpec,
    constructor: &Constructor,
    bytes: &[u8],
    context: &[u32],
    address: u64,
    current_space: u32,
    current_space_size: u32,
) -> Result<(u32, Vec<PcodeOp>), ConstructorEmitError> {
    let emitted = emit_instruction_details(
        spec,
        constructor,
        bytes,
        context,
        address,
        current_space,
        current_space_size,
    )?;
    Ok((emitted.length, emitted.operations))
}

pub fn emit_instruction_details(
    spec: &SleighSpec,
    constructor: &Constructor,
    bytes: &[u8],
    context: &[u32],
    address: u64,
    current_space: u32,
    current_space_size: u32,
) -> Result<EmittedInstruction, ConstructorEmitError> {
    let mut emitted = emit_instruction_details_raw(
        spec,
        constructor,
        bytes,
        context,
        address,
        current_space,
        current_space_size,
    )?;
    normalize_operations(spec, &mut emitted.operations);
    Ok(emitted)
}

fn emit_instruction_details_raw(
    spec: &SleighSpec,
    constructor: &Constructor,
    bytes: &[u8],
    context: &[u32],
    address: u64,
    current_space: u32,
    current_space_size: u32,
) -> Result<EmittedInstruction, ConstructorEmitError> {
    let provisional = TemplateContext::at(address, 0, current_space, current_space_size);
    let mut measuring_context = context.to_vec();
    let measured = resolve_node(
        spec,
        constructor,
        bytes,
        &mut measuring_context,
        &provisional,
        0,
    )?;
    let length =
        u32::try_from(measured.end_offset).map_err(|_| HandleError::InvalidOperandOffset)?;
    if length == 0 || usize::try_from(length).unwrap_or(usize::MAX) > bytes.len() {
        return Err(HandleError::InvalidOperandOffset.into());
    }

    let mut delay_operations = Vec::new();
    let delay_bytes = main_template(measured.constructor)?.delay_slot_bytes;
    if delay_bytes > 0 {
        let threshold =
            usize::try_from(delay_bytes).map_err(|_| HandleError::InvalidOperandOffset)?;
        let mut consumed = 0_usize;
        while consumed < threshold {
            let offset = usize::try_from(length)
                .unwrap_or(usize::MAX)
                .checked_add(consumed)
                .ok_or(HandleError::InvalidOperandOffset)?;
            let delay_bytes = bytes
                .get(offset..)
                .ok_or(HandleError::InvalidOperandOffset)?;
            let delay_constructor = spec
                .resolve_instruction(delay_bytes, &measuring_context)
                .map_err(|error| HandleError::NestedResolution(error.to_string()))?;
            let emitted = emit_instruction_details_raw(
                spec,
                delay_constructor,
                delay_bytes,
                &measuring_context,
                address.wrapping_add(u64::try_from(offset).unwrap_or(u64::MAX)),
                current_space,
                current_space_size,
            )?;
            let delay_length = emitted.length;
            delay_operations.extend(emitted.operations);
            consumed = consumed
                .checked_add(usize::try_from(delay_length).unwrap_or(usize::MAX))
                .ok_or(HandleError::InvalidOperandOffset)?;
            // Delay-slot operations remain in raw language-local spaces until
            // the complete instruction is normalized once at the API boundary.
        }
    }

    let mut template_context =
        TemplateContext::at(address, length, current_space, current_space_size);
    template_context.unique_space = Some(spec.unique_space);
    template_context.unique_offset =
        (template_context.address & spec.unique_allocation_mask).wrapping_shl(8);
    template_context.space_ids = Some(spec.space_ids.clone());
    let mut instruction_context = context.to_vec();
    let node = resolve_node(
        spec,
        constructor,
        bytes,
        &mut instruction_context,
        &template_context,
        0,
    )?;
    let mut builder = Builder::default();
    build_node(
        &node,
        None,
        &template_context,
        &delay_operations,
        delay_bytes > 0,
        &mut builder,
    )?;
    let operations = builder.finish().map_err(ConstructorEmitError::Emit)?;
    Ok(EmittedInstruction {
        length,
        operations,
        delay_slot_bytes: u32::try_from(delay_bytes)
            .map_err(|_| HandleError::InvalidOperandOffset)?,
    })
}

fn normalize_operations(spec: &SleighSpec, operations: &mut [PcodeOp]) {
    for operation in operations {
        if let Some(output) = &mut operation.output {
            output.space = spec.normalize_space(output.space);
        }
        for input in &mut operation.inputs {
            input.space = spec.normalize_space(input.space);
        }
    }
}

struct ResolvedNode<'a> {
    constructor: &'a Constructor,
    handles: Vec<FixedHandle>,
    children: Vec<Option<Box<ResolvedNode<'a>>>>,
    end_offset: usize,
}

fn resolve_node<'a>(
    spec: &'a SleighSpec,
    constructor: &'a Constructor,
    bytes: &[u8],
    context: &mut [u32],
    template_context: &TemplateContext,
    node_offset: usize,
) -> Result<ResolvedNode<'a>, HandleError> {
    for operation in &constructor.context_operations {
        let state = EvalState {
            bytes,
            context,
            byte_offset: node_offset,
            template_context,
            spec: Some(spec),
            constructor: Some(constructor),
            handles: &[],
        };
        let value = eval(&operation.expression, &state)? as u32;
        let word = context
            .get_mut(operation.word)
            .ok_or(HandleError::InvalidContextWord(operation.word))?;
        *word = (*word & !operation.mask) | (value.wrapping_shl(operation.shift) & operation.mask);
    }
    let mut handles = Vec::with_capacity(constructor.operand_symbols.len());
    let mut children = Vec::with_capacity(constructor.operand_symbols.len());
    let mut operand_offsets = Vec::with_capacity(constructor.operand_symbols.len());
    let mut operand_ends = Vec::with_capacity(constructor.operand_symbols.len());
    let mut consumed_end = node_offset.saturating_add(constructor.minimum_length);
    for (position, symbol_id) in constructor.operand_symbols.iter().copied().enumerate() {
        let operand = spec
            .symbol_bodies
            .get(&symbol_id)
            .ok_or(HandleError::MissingSymbol(symbol_id))?;
        expect_element(operand, ELEM_OPERAND_SYM)?;
        let base = optional_signed(operand, ATTR_BASE)?.unwrap_or(-1);
        let base_offset = if base < 0 {
            node_offset
        } else {
            let base = usize::try_from(base).map_err(|_| HandleError::InvalidOperandBase(base))?;
            *operand_ends
                .get(base)
                .ok_or(HandleError::InvalidOperandBase(base as i64))?
        };
        let relative_offset = signed(operand, ATTR_OFF)?;
        let byte_offset = if relative_offset < 0 {
            base_offset
                .checked_sub(relative_offset.unsigned_abs() as usize)
                .ok_or(HandleError::NegativeOperandOffset(relative_offset))?
        } else {
            base_offset
                .checked_add(relative_offset as usize)
                .ok_or(HandleError::InvalidOperandOffset)?
        };
        if byte_offset > bytes.len() {
            return Err(HandleError::InvalidOperandOffset);
        }
        operand_offsets.push(byte_offset);
        let state = EvalState {
            bytes,
            context,
            byte_offset,
            template_context,
            handles: &handles,
            spec: Some(spec),
            constructor: Some(constructor),
        };
        let subsymbol = optional_unsigned(operand, ATTR_SUBSYM)?;
        let (handle, child) = if let Some(subsymbol) = subsymbol {
            let symbol = spec
                .symbol_bodies
                .get(&subsymbol)
                .ok_or(HandleError::MissingSymbol(subsymbol))?;
            if symbol.id == ELEM_SUBTABLE_SYM {
                let table = spec
                    .subtables
                    .get(&subsymbol)
                    .ok_or(HandleError::MissingSubtable(subsymbol))?;
                let mut window = [0_u8; 16];
                let available = bytes.len().saturating_sub(byte_offset).min(window.len());
                window[..available].copy_from_slice(&bytes[byte_offset..byte_offset + available]);
                let candidates = table
                    .resolve_candidates(&window, context)
                    .map_err(|error| HandleError::NestedResolution(error.to_string()))?;
                let mut last_error = None;
                let mut resolved = None;
                for nested_constructor in candidates {
                    let mut candidate_context = context.to_vec();
                    match resolve_node(
                        spec,
                        nested_constructor,
                        bytes,
                        &mut candidate_context,
                        template_context,
                        byte_offset,
                    ) {
                        Ok(child) => match resolve_result_handle(&child, template_context) {
                            Ok(handle) => {
                                context.copy_from_slice(&candidate_context);
                                resolved = Some((handle, Some(Box::new(child))));
                                break;
                            }
                            Err(error) => last_error = Some(error),
                        },
                        Err(error) => last_error = Some(error),
                    }
                }
                resolved.ok_or_else(|| {
                    last_error.unwrap_or_else(|| {
                        HandleError::NestedResolution(
                            "no viable nested SLEIGH constructor".to_owned(),
                        )
                    })
                })?
            } else {
                (resolve_symbol(spec, subsymbol, &state)?, None)
            }
        } else {
            let expression = operand
                .children
                .get(1)
                .ok_or(HandleError::MissingDefinition(symbol_id))?;
            (
                FixedHandle::direct(CONST_SPACE, eval(expression, &state)? as u64, 0),
                None,
            )
        };
        let operand_end = if let Some(child) = child.as_deref() {
            child.end_offset
        } else if let Some(subsymbol) = subsymbol {
            symbol_instruction_end(spec, constructor, &operand_offsets, subsymbol, byte_offset)?
        } else {
            operand
                .children
                .get(1)
                .map(|expression| {
                    expression_instruction_end(
                        expression,
                        byte_offset,
                        spec,
                        constructor,
                        &operand_offsets,
                    )
                })
                .transpose()?
                .unwrap_or(byte_offset)
        };
        let structural_end = if let Some(child) = child.as_deref() {
            child.end_offset
        } else {
            let minimum_length = optional_signed(operand, ATTR_MINLEN)?.unwrap_or(0);
            byte_offset
                .checked_add(
                    usize::try_from(minimum_length)
                        .map_err(|_| HandleError::InvalidOperandOffset)?,
                )
                .ok_or(HandleError::InvalidOperandOffset)?
        };
        consumed_end = consumed_end.max(operand_end);
        operand_ends.push(structural_end);
        handles.push(handle);
        children.push(child);
        let _ = position;
    }
    let end_offset = children
        .iter()
        .flatten()
        .map(|child| child.end_offset)
        .fold(consumed_end, usize::max);
    Ok(ResolvedNode {
        constructor,
        handles,
        children,
        end_offset,
    })
}

fn symbol_instruction_end(
    spec: &SleighSpec,
    constructor: &Constructor,
    operand_offsets: &[usize],
    symbol_id: u64,
    byte_offset: usize,
) -> Result<usize, HandleError> {
    let symbol = spec
        .symbol_bodies
        .get(&symbol_id)
        .ok_or(HandleError::MissingSymbol(symbol_id))?;
    match symbol.id {
        ELEM_VALUE_SYM | ELEM_NAME_SYM | ELEM_VALUEMAP_SYM | ELEM_VARLIST_SYM => {
            expression_instruction_end(
                first_child(symbol)?,
                byte_offset,
                spec,
                constructor,
                operand_offsets,
            )
        }
        _ => Ok(byte_offset),
    }
}

fn expression_instruction_end(
    expression: &Element,
    byte_offset: usize,
    spec: &SleighSpec,
    constructor: &Constructor,
    operand_offsets: &[usize],
) -> Result<usize, HandleError> {
    if expression.id == ELEM_TOKENFIELD {
        return byte_offset
            .checked_add(nonnegative_usize(signed(expression, ATTR_ENDBYTE)?)?)
            .and_then(|end| end.checked_add(1))
            .ok_or(HandleError::InvalidField);
    }
    if expression.id == ELEM_OPERAND_EXP {
        let index = usize::try_from(signed(expression, ATTR_INDEX)?)
            .map_err(|_| HandleError::InvalidOperandIndex)?;
        let operand_offset = *operand_offsets
            .get(index)
            .ok_or(HandleError::InvalidOperandIndex)?;
        let symbol_id = *constructor
            .operand_symbols
            .get(index)
            .ok_or(HandleError::InvalidOperandIndex)?;
        let operand = spec
            .symbol_bodies
            .get(&symbol_id)
            .ok_or(HandleError::MissingSymbol(symbol_id))?;
        if let Some(definition) = operand.children.get(1) {
            return expression_instruction_end(
                definition,
                operand_offset,
                spec,
                constructor,
                operand_offsets,
            );
        }
        if let Some(subsymbol) = optional_unsigned(operand, ATTR_SUBSYM)? {
            return symbol_instruction_end(
                spec,
                constructor,
                operand_offsets,
                subsymbol,
                operand_offset,
            );
        }
        return Ok(operand_offset);
    }
    let mut end = byte_offset;
    for child in &expression.children {
        end = end.max(expression_instruction_end(
            child,
            byte_offset,
            spec,
            constructor,
            operand_offsets,
        )?);
    }
    Ok(end)
}

fn resolve_result_handle(
    node: &ResolvedNode<'_>,
    template_context: &TemplateContext,
) -> Result<FixedHandle, HandleError> {
    let template = main_template(node.constructor)?;
    let Some(result) = template.result.as_ref() else {
        return Ok(FixedHandle::invalid());
    };
    let mut context = template_context.clone();
    context.handles.clone_from(&node.handles);
    fix_handle_template(result, &context)
}

fn fix_handle_template(
    template: &HandleTemplate,
    context: &TemplateContext,
) -> Result<FixedHandle, HandleError> {
    let space = fix_export_space(&template.space, context)?;
    let size = u32::try_from(fix_value(&template.size, context)?)
        .map_err(|_| HandleError::InvalidSize(-1))?;
    if matches!(template.pointer_space, ConstTemplate::Real(_)) {
        if let ConstTemplate::Handle { index, .. } = template.pointer_offset {
            let mut handle = *context
                .handles
                .get(index)
                .ok_or(HandleError::InvalidOperandIndex)?;
            handle.space = space;
            handle.size = size;
            Ok(handle)
        } else {
            Ok(FixedHandle::direct(
                space,
                fix_value(&template.pointer_offset, context)?,
                size,
            ))
        }
    } else {
        let offset_space = fix_space(&template.pointer_space, context)?;
        let offset = fix_value(&template.pointer_offset, context)?;
        if offset_space == CONST_SPACE {
            Ok(FixedHandle::direct(space, offset, size))
        } else {
            Ok(FixedHandle {
                valid: true,
                space,
                offset_space: Some(offset_space),
                offset,
                offset_size: u32::try_from(fix_value(&template.pointer_size, context)?)
                    .map_err(|_| HandleError::InvalidSize(-1))?,
                size,
                temporary_space: Some(fix_space(&template.temporary_space, context)?),
                temporary_offset: fix_value(&template.temporary_offset, context)?,
            })
        }
    }
}

fn fix_export_space(
    template: &ConstTemplate,
    context: &TemplateContext,
) -> Result<u32, HandleError> {
    if let ConstTemplate::Handle {
        index,
        selector: HandleSelector::Space,
        ..
    } = template
    {
        let handle = context
            .handles
            .get(*index)
            .ok_or(HandleError::InvalidOperandIndex)?;
        if !handle.valid {
            return Err(HandleError::InvalidOperandIndex);
        }
        Ok(handle.space)
    } else {
        fix_space(template, context).map_err(HandleError::TemplateFix)
    }
}

fn main_template(constructor: &Constructor) -> Result<&ConstructTemplate, HandleError> {
    constructor
        .templates
        .iter()
        .find(|template| template.section.is_none())
        .ok_or(HandleError::MissingMainTemplate)
}

fn build_node(
    node: &ResolvedNode<'_>,
    section: Option<usize>,
    template_context: &TemplateContext,
    delay_operations: &[PcodeOp],
    delay_resolved: bool,
    builder: &mut Builder,
) -> Result<(), ConstructorEmitError> {
    let template = node
        .constructor
        .templates
        .iter()
        .find(|template| template.section == section);
    let Some(template) = template else {
        if section.is_some() {
            for child in node.children.iter().flatten() {
                build_node(
                    child,
                    section,
                    template_context,
                    delay_operations,
                    delay_resolved,
                    builder,
                )?;
            }
            return Ok(());
        }
        return Err(ConstructorEmitError::MissingMainTemplate);
    };
    if template.delay_slot_bytes != 0 && !delay_resolved {
        return Err(ConstructorEmitError::Emit(EmitError::DelaySlot(
            template.delay_slot_bytes,
        )));
    }
    let label_base = builder.next_label_base;
    builder.next_label_base = builder
        .next_label_base
        .checked_add(template.label_count as u64)
        .ok_or(ConstructorEmitError::Emit(EmitError::LabelOverflow))?;
    let mut context = template_context.clone();
    context.handles.clone_from(&node.handles);
    for operation in &template.operations {
        let opcode = operation.opcode;
        if opcode == i64::from(op::MULTIEQUAL) {
            let input = operation
                .inputs
                .first()
                .ok_or(ConstructorEmitError::Emit(EmitError::MalformedBuild))?;
            let index = usize::try_from(real_template_offset(input)?)
                .map_err(|_| ConstructorEmitError::Emit(EmitError::MalformedBuild))?;
            if let Some(child) = node.children.get(index).and_then(Option::as_deref) {
                build_node(
                    child,
                    section,
                    template_context,
                    delay_operations,
                    delay_resolved,
                    builder,
                )?;
            }
        } else if opcode == i64::from(op::INDIRECT) {
            if builder.delay_slot_inserted {
                return Err(ConstructorEmitError::Emit(EmitError::DelaySlotOperation));
            }
            builder.operations.extend_from_slice(delay_operations);
            builder.delay_slot_inserted = true;
        } else if opcode == i64::from(op::PTRSUB) {
            return Err(ConstructorEmitError::Emit(EmitError::CrossBuild));
        } else if opcode == i64::from(op::PTRADD) {
            let input = operation
                .inputs
                .first()
                .ok_or(ConstructorEmitError::Emit(EmitError::MalformedLabel))?;
            let label = real_template_offset(input)?
                .checked_add(label_base)
                .ok_or(ConstructorEmitError::Emit(EmitError::LabelOverflow))?;
            builder.labels.insert(label, builder.operations.len());
        } else {
            let opcode = i32::try_from(opcode)
                .map_err(|_| ConstructorEmitError::Emit(EmitError::InvalidOpcode(opcode)))?;
            if !(0..op::MAX).contains(&opcode) {
                return Err(ConstructorEmitError::Emit(EmitError::InvalidOpcode(
                    operation.opcode,
                )));
            }
            let dynamic_output = operation
                .output
                .as_ref()
                .map(|template| dynamic_handle(template, &context))
                .transpose()?
                .flatten();
            let output = operation
                .output
                .as_ref()
                .map(|template| fix_varnode(template, &context))
                .transpose()?;
            let mut inputs = Vec::with_capacity(operation.inputs.len());
            for input in &operation.inputs {
                let varnode = fix_varnode(input, &context)?;
                if let Some((handle, plus)) = dynamic_handle(input, &context)? {
                    let pointer = materialize_dynamic_pointer(
                        handle,
                        plus,
                        &context,
                        &mut builder.runtime_unique_offset,
                        &mut builder.operations,
                    )?;
                    builder.operations.push(PcodeOp::new(
                        op::LOAD,
                        Some(varnode),
                        vec![space_id_varnode(handle.space, &context), pointer],
                    ));
                }
                inputs.push(varnode);
            }
            let operation_index = builder.operations.len();
            for (input_index, input) in operation.inputs.iter().enumerate() {
                if let ConstTemplate::Relative(label) = input.offset {
                    let label = label
                        .checked_add(label_base)
                        .ok_or(ConstructorEmitError::Emit(EmitError::LabelOverflow))?;
                    builder
                        .relatives
                        .push((operation_index, input_index, label));
                }
            }
            builder
                .operations
                .push(PcodeOp::new(opcode, output, inputs));
            if let (Some((handle, plus)), Some(value)) = (dynamic_output, output) {
                let pointer = materialize_dynamic_pointer(
                    handle,
                    plus,
                    &context,
                    &mut builder.runtime_unique_offset,
                    &mut builder.operations,
                )?;
                builder.operations.push(PcodeOp::new(
                    op::STORE,
                    None,
                    vec![space_id_varnode(handle.space, &context), pointer, value],
                ));
            }
        }
    }
    Ok(())
}

fn real_template_offset(template: &crate::VarnodeTemplate) -> Result<u64, ConstructorEmitError> {
    match template.offset {
        ConstTemplate::Real(value) => Ok(value),
        _ => Err(ConstructorEmitError::Emit(EmitError::MalformedBuild)),
    }
}

struct Builder {
    operations: Vec<PcodeOp>,
    labels: BTreeMap<u64, usize>,
    relatives: Vec<(usize, usize, u64)>,
    next_label_base: u64,
    delay_slot_inserted: bool,
    runtime_unique_offset: u64,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            operations: Vec::new(),
            labels: BTreeMap::new(),
            relatives: Vec::new(),
            next_label_base: 0,
            delay_slot_inserted: false,
            runtime_unique_offset: 0xffff_ff00,
        }
    }
}

impl Builder {
    fn finish(mut self) -> Result<Vec<PcodeOp>, EmitError> {
        for (operation_index, input_index, label) in self.relatives {
            let target = self
                .labels
                .get(&label)
                .copied()
                .ok_or(EmitError::MissingLabel(label))?;
            let input = &mut self.operations[operation_index].inputs[input_index];
            input.offset = u64::try_from(target)
                .unwrap()
                .wrapping_sub(u64::try_from(operation_index).unwrap())
                & varnode_size_mask(input.size);
        }
        Ok(self.operations)
    }
}

fn varnode_size_mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else if size == 0 {
        0
    } else {
        (1_u64 << (size * 8)) - 1
    }
}

fn resolve_symbol(
    spec: &SleighSpec,
    symbol_id: u64,
    state: &EvalState<'_>,
) -> Result<FixedHandle, HandleError> {
    let symbol = spec
        .symbol_bodies
        .get(&symbol_id)
        .ok_or(HandleError::MissingSymbol(symbol_id))?;
    match symbol.id {
        ELEM_VARNODE_SYM => Ok(FixedHandle::direct(
            match attribute(symbol, ATTR_SPACE)? {
                AttributeValue::AddressSpace(space) => {
                    u32::try_from(*space).map_err(|_| HandleError::InvalidSpace(*space))?
                }
                _ => return Err(HandleError::AttributeType(ATTR_SPACE)),
            },
            unsigned(symbol, ATTR_OFF)?,
            u32::try_from(signed(symbol, ATTR_SIZE)?)
                .map_err(|_| HandleError::InvalidSize(signed(symbol, ATTR_SIZE).unwrap_or(-1)))?,
        )),
        ELEM_VALUE_SYM | ELEM_NAME_SYM => Ok(FixedHandle::direct(
            CONST_SPACE,
            eval(first_child(symbol)?, state)? as u64,
            0,
        )),
        ELEM_VALUEMAP_SYM => {
            let index = table_index(eval(first_child(symbol)?, state)?)?;
            let entries = symbol
                .children
                .iter()
                .filter(|child| child.id == ELEM_VALUETAB)
                .collect::<Vec<_>>();
            let entry = entries.get(index).copied().ok_or(HandleError::TableIndex {
                index,
                symbol: symbol_id,
                entries: entries.len(),
            })?;
            Ok(FixedHandle::direct(
                CONST_SPACE,
                signed(entry, ATTR_VAL)? as u64,
                0,
            ))
        }
        ELEM_VARLIST_SYM => {
            let index = table_index(eval(first_child(symbol)?, state)?)?;
            let entries = symbol.children.get(1..).unwrap_or_default();
            let entry = entries.get(index).ok_or(HandleError::TableIndex {
                index,
                symbol: symbol_id,
                entries: entries.len(),
            })?;
            if entry.id != ELEM_VAR {
                return Err(HandleError::InvalidOperandIndex);
            }
            resolve_symbol(spec, unsigned(entry, ATTR_ID)?, state)
        }
        ELEM_START_SYM => Ok(FixedHandle::direct(
            state.template_context.current_space,
            state.template_context.address,
            state.template_context.current_space_size,
        )),
        ELEM_END_SYM => Ok(FixedHandle::direct(
            state.template_context.current_space,
            state.template_context.next_address,
            state.template_context.current_space_size,
        )),
        ELEM_NEXT2_SYM => Ok(FixedHandle::direct(
            state.template_context.current_space,
            state
                .template_context
                .next2_address
                .ok_or(HandleError::MissingNext2)?,
            state.template_context.current_space_size,
        )),
        element => Err(HandleError::UnsupportedSymbol { symbol_id, element }),
    }
}

struct EvalState<'a> {
    bytes: &'a [u8],
    context: &'a [u32],
    byte_offset: usize,
    template_context: &'a TemplateContext,
    handles: &'a [FixedHandle],
    spec: Option<&'a SleighSpec>,
    constructor: Option<&'a Constructor>,
}

fn eval(expression: &Element, state: &EvalState<'_>) -> Result<i64, HandleError> {
    match expression.id {
        ELEM_TOKENFIELD => eval_token_field(expression, state),
        ELEM_CONTEXTFIELD => eval_context_field(expression, state),
        ELEM_INTB => signed(expression, ATTR_VAL),
        ELEM_OPERAND_EXP => eval_operand(
            usize::try_from(signed(expression, ATTR_INDEX)?)
                .map_err(|_| HandleError::InvalidOperandIndex)?,
            state,
        ),
        ELEM_START_EXP => Ok(state.template_context.address as i64),
        ELEM_END_EXP => Ok(state.template_context.next_address as i64),
        ELEM_NEXT2_EXP => Ok(state
            .template_context
            .next2_address
            .ok_or(HandleError::MissingNext2)? as i64),
        ELEM_NOT_EXP => Ok(!eval(unary(expression)?, state)?),
        ELEM_PLUS_EXP | ELEM_SUB_EXP | ELEM_MULT_EXP | ELEM_DIV_EXP | ELEM_AND_EXP
        | ELEM_OR_EXP | ELEM_XOR_EXP | ELEM_LSHIFT_EXP | ELEM_RSHIFT_EXP => {
            let (left, right) = binary(expression)?;
            let left = eval(left, state)?;
            let right = eval(right, state)?;
            match expression.id {
                ELEM_PLUS_EXP => Ok(left.wrapping_add(right)),
                ELEM_SUB_EXP => Ok(left.wrapping_sub(right)),
                ELEM_MULT_EXP => Ok(left.wrapping_mul(right)),
                ELEM_DIV_EXP => left
                    .checked_div(right)
                    .ok_or(HandleError::InvalidArithmetic),
                ELEM_AND_EXP => Ok(left & right),
                ELEM_OR_EXP => Ok(left | right),
                ELEM_XOR_EXP => Ok(left ^ right),
                ELEM_LSHIFT_EXP => Ok(left.wrapping_shl(right as u32)),
                ELEM_RSHIFT_EXP => Ok(((left as u64).wrapping_shr(right as u32)) as i64),
                _ => unreachable!(),
            }
        }
        ELEM_MINUS_EXP => Ok(eval(unary(expression)?, state)?.wrapping_neg()),
        element => Err(HandleError::UnsupportedExpression(element)),
    }
}
fn eval_operand(index: usize, state: &EvalState<'_>) -> Result<i64, HandleError> {
    if let Some(handle) = state.handles.get(index) {
        return Ok(handle.offset as i64);
    }
    let spec = state.spec.ok_or(HandleError::InvalidOperandIndex)?;
    let constructor = state.constructor.ok_or(HandleError::InvalidOperandIndex)?;
    let symbol_id = *constructor
        .operand_symbols
        .get(index)
        .ok_or(HandleError::InvalidOperandIndex)?;
    let operand = spec
        .symbol_bodies
        .get(&symbol_id)
        .ok_or(HandleError::MissingSymbol(symbol_id))?;
    expect_element(operand, ELEM_OPERAND_SYM)?;
    let base = optional_signed(operand, ATTR_BASE)?.unwrap_or(-1);
    if base >= 0 {
        return Err(HandleError::ChainedOperandBase {
            operand: index,
            base,
        });
    }
    let relative_offset = signed(operand, ATTR_OFF)?;
    let byte_offset = if relative_offset < 0 {
        state
            .byte_offset
            .checked_sub(relative_offset.unsigned_abs() as usize)
            .ok_or(HandleError::NegativeOperandOffset(relative_offset))?
    } else {
        state
            .byte_offset
            .checked_add(relative_offset as usize)
            .ok_or(HandleError::InvalidOperandOffset)?
    };
    let nested_state = EvalState {
        bytes: state.bytes,
        context: state.context,
        byte_offset,
        template_context: state.template_context,
        handles: state.handles,
        spec: state.spec,
        constructor: state.constructor,
    };
    if let Some(expression) = operand.children.get(1) {
        eval(expression, &nested_state)
    } else if let Some(subsymbol) = optional_unsigned(operand, ATTR_SUBSYM)? {
        resolve_symbol(spec, subsymbol, &nested_state).map(|handle| handle.offset as i64)
    } else {
        Err(HandleError::MissingDefinition(symbol_id))
    }
}

fn eval_token_field(expression: &Element, state: &EvalState<'_>) -> Result<i64, HandleError> {
    let start = state
        .byte_offset
        .checked_add(nonnegative_usize(signed(expression, ATTR_STARTBYTE)?)?)
        .ok_or(HandleError::InvalidField)?;
    let end = state
        .byte_offset
        .checked_add(nonnegative_usize(signed(expression, ATTR_ENDBYTE)?)?)
        .ok_or(HandleError::InvalidField)?;
    if end < start || end >= state.bytes.len() || end - start >= 8 {
        return Err(HandleError::InvalidField);
    }
    let mut value = 0_u64;
    for byte in &state.bytes[start..=end] {
        value = (value << 8) | u64::from(*byte);
    }
    if !boolean(expression, ATTR_BIGENDIAN)? {
        value = byte_swap(value, end - start + 1);
    }
    finish_field(expression, value)
}

fn eval_context_field(expression: &Element, state: &EvalState<'_>) -> Result<i64, HandleError> {
    let mut bytes = Vec::with_capacity(state.context.len() * 4);
    for word in state.context {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    let start = nonnegative_usize(signed(expression, ATTR_STARTBYTE)?)?;
    let end = nonnegative_usize(signed(expression, ATTR_ENDBYTE)?)?;
    if end < start || end >= bytes.len() || end - start >= 8 {
        return Err(HandleError::InvalidField);
    }
    let mut value = 0_u64;
    for byte in &bytes[start..=end] {
        value = (value << 8) | u64::from(*byte);
    }
    finish_field(expression, value)
}

fn finish_field(expression: &Element, value: u64) -> Result<i64, HandleError> {
    let shift =
        u32::try_from(signed(expression, ATTR_SHIFT)?).map_err(|_| HandleError::InvalidField)?;
    let start_bit = signed(expression, ATTR_STARTBIT)?;
    let end_bit = signed(expression, ATTR_ENDBIT)?;
    if end_bit < start_bit || end_bit - start_bit >= 64 {
        return Err(HandleError::InvalidField);
    }
    let width = u32::try_from(end_bit - start_bit + 1).unwrap();
    let value = value.wrapping_shr(shift) & width_mask(width);
    if boolean(expression, ATTR_SIGNBIT)? && width < 64 && value & (1_u64 << (width - 1)) != 0 {
        Ok((value | !width_mask(width)) as i64)
    } else {
        Ok(value as i64)
    }
}

fn width_mask(width: u32) -> u64 {
    if width == 64 {
        u64::MAX
    } else {
        (1_u64 << width) - 1
    }
}

fn byte_swap(mut value: u64, size: usize) -> u64 {
    let mut result = 0_u64;
    for _ in 0..size {
        result = (result << 8) | (value & 0xff);
        value >>= 8;
    }
    result
}

fn table_index(value: i64) -> Result<usize, HandleError> {
    usize::try_from(value).map_err(|_| HandleError::NegativeTableIndex(value))
}

fn first_child(element: &Element) -> Result<&Element, HandleError> {
    element
        .children
        .first()
        .ok_or(HandleError::MissingExpression)
}

fn unary(element: &Element) -> Result<&Element, HandleError> {
    if element.children.len() != 1 {
        return Err(HandleError::MissingExpression);
    }
    Ok(&element.children[0])
}

fn binary(element: &Element) -> Result<(&Element, &Element), HandleError> {
    if element.children.len() != 2 {
        return Err(HandleError::MissingExpression);
    }
    Ok((&element.children[0], &element.children[1]))
}

fn expect_element(element: &Element, expected: u16) -> Result<(), HandleError> {
    if element.id == expected {
        Ok(())
    } else {
        Err(HandleError::UnexpectedElement {
            expected,
            actual: element.id,
        })
    }
}

fn attribute(element: &Element, id: u16) -> Result<&AttributeValue, HandleError> {
    element
        .attributes
        .iter()
        .find(|attribute| attribute.id == id)
        .map(|attribute| &attribute.value)
        .ok_or(HandleError::MissingAttribute(id))
}

fn optional_attribute(element: &Element, id: u16) -> Option<&AttributeValue> {
    element
        .attributes
        .iter()
        .find(|attribute| attribute.id == id)
        .map(|attribute| &attribute.value)
}

fn signed(element: &Element, id: u16) -> Result<i64, HandleError> {
    match attribute(element, id)? {
        AttributeValue::Signed(value) => Ok(*value),
        _ => Err(HandleError::AttributeType(id)),
    }
}

fn optional_signed(element: &Element, id: u16) -> Result<Option<i64>, HandleError> {
    match optional_attribute(element, id) {
        Some(AttributeValue::Signed(value)) => Ok(Some(*value)),
        Some(_) => Err(HandleError::AttributeType(id)),
        None => Ok(None),
    }
}

fn unsigned(element: &Element, id: u16) -> Result<u64, HandleError> {
    match attribute(element, id)? {
        AttributeValue::Unsigned(value) => Ok(*value),
        _ => Err(HandleError::AttributeType(id)),
    }
}

fn optional_unsigned(element: &Element, id: u16) -> Result<Option<u64>, HandleError> {
    match optional_attribute(element, id) {
        Some(AttributeValue::Unsigned(value)) => Ok(Some(*value)),
        Some(_) => Err(HandleError::AttributeType(id)),
        None => Ok(None),
    }
}

fn boolean(element: &Element, id: u16) -> Result<bool, HandleError> {
    match attribute(element, id)? {
        AttributeValue::Boolean(value) => Ok(*value),
        _ => Err(HandleError::AttributeType(id)),
    }
}

fn nonnegative_usize(value: i64) -> Result<usize, HandleError> {
    usize::try_from(value).map_err(|_| HandleError::InvalidField)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandleError {
    MissingSymbol(u64),
    UnsupportedSymbol {
        symbol_id: u64,
        element: u16,
    },
    UnexpectedElement {
        expected: u16,
        actual: u16,
    },
    MissingAttribute(u16),
    AttributeType(u16),
    ChainedOperandBase {
        operand: usize,
        base: i64,
    },
    InvalidOperandBase(i64),
    InvalidOperandOffset,
    NegativeOperandOffset(i64),
    MissingDefinition(u64),
    MissingSubtable(u64),
    NestedResolution(String),
    MissingMainTemplate,
    MissingResult,
    MissingExpression,
    UnsupportedExpression(u16),
    InvalidOperandIndex,
    InvalidArithmetic,
    InvalidField,
    InvalidContextWord(usize),
    NegativeTableIndex(i64),
    TableIndex {
        index: usize,
        symbol: u64,
        entries: usize,
    },
    InvalidSize(i64),
    InvalidSpace(u64),
    MissingNext2,
    TemplateFix(EmitError),
}

impl fmt::Display for HandleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for HandleError {}

impl From<EmitError> for HandleError {
    fn from(error: EmitError) -> Self {
        Self::TemplateFix(error)
    }
}

#[derive(Debug)]
pub enum ConstructorEmitError {
    MissingMainTemplate,
    Handle(HandleError),
    Emit(EmitError),
}

impl fmt::Display for ConstructorEmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMainTemplate => formatter.write_str("constructor has no main template"),
            Self::Handle(error) => write!(formatter, "operand resolution failed: {error}"),
            Self::Emit(error) => write!(formatter, "template emission failed: {error}"),
        }
    }
}

impl Error for ConstructorEmitError {}

impl From<HandleError> for ConstructorEmitError {
    fn from(error: HandleError) -> Self {
        Self::Handle(error)
    }
}

impl From<EmitError> for ConstructorEmitError {
    fn from(error: EmitError) -> Self {
        Self::Emit(error)
    }
}
