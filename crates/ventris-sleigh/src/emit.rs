use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use ventris_pcode::{PcodeOp, Varnode, op};

#[cfg(test)]
use crate::OperationTemplate;
use crate::{ConstTemplate, ConstructTemplate, HandleSelector, VarnodeTemplate};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedHandle {
    pub valid: bool,
    pub space: u32,
    pub offset_space: Option<u32>,
    pub offset: u64,
    pub offset_size: u32,
    pub size: u32,
    pub temporary_space: Option<u32>,
    pub temporary_offset: u64,
}

impl FixedHandle {
    pub const fn direct(space: u32, offset: u64, size: u32) -> Self {
        Self {
            space,
            valid: true,
            offset_space: None,
            offset,
            offset_size: 0,
            size,
            temporary_space: None,
            temporary_offset: 0,
        }
    }

    pub const fn invalid() -> Self {
        Self {
            valid: false,
            space: 0,
            offset_space: None,
            offset: 0,
            offset_size: 0,
            size: 0,
            temporary_space: None,
            temporary_offset: 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemplateContext {
    pub address: u64,
    pub next_address: u64,
    pub next2_address: Option<u64>,
    pub current_space: u32,
    pub current_space_size: u32,
    pub unique_space: Option<u32>,
    pub unique_offset: u64,
    pub space_ids: Option<Arc<[u64]>>,
    pub flow_reference: Option<FixedHandle>,
    pub flow_destination: Option<FixedHandle>,
    pub handles: Vec<FixedHandle>,
}

impl TemplateContext {
    pub fn at(
        address: u64,
        instruction_length: u32,
        current_space: u32,
        current_space_size: u32,
    ) -> Self {
        Self {
            address,
            next_address: address.wrapping_add(u64::from(instruction_length)),
            next2_address: None,
            current_space,
            current_space_size,
            flow_reference: None,
            flow_destination: None,
            unique_space: None,
            unique_offset: 0,
            space_ids: None,
            handles: Vec::new(),
        }
    }
}

pub fn emit_template(
    template: &ConstructTemplate,
    context: &TemplateContext,
) -> Result<Vec<PcodeOp>, EmitError> {
    if template.delay_slot_bytes != 0 {
        return Err(EmitError::DelaySlot(template.delay_slot_bytes));
    }

    let mut emitted = Vec::new();
    let mut labels = BTreeMap::<u64, usize>::new();
    let mut relatives = Vec::<(usize, usize, u64)>::new();
    let mut runtime_unique_offset = 0xffff_ff00_u64;
    for operation in &template.operations {
        match operation.opcode {
            opcode if opcode == i64::from(op::MULTIEQUAL) => return Err(EmitError::Build),
            opcode if opcode == i64::from(op::INDIRECT) => {
                return Err(EmitError::DelaySlotOperation);
            }
            opcode if opcode == i64::from(op::PTRSUB) => return Err(EmitError::CrossBuild),
            opcode if opcode == i64::from(op::PTRADD) => {
                let label = operation.inputs.first().ok_or(EmitError::MalformedLabel)?;
                labels.insert(real_offset(label)?, emitted.len());
            }
            opcode => {
                if !(0..op::MAX).contains(&i32::try_from(opcode).unwrap_or(i32::MAX)) {
                    return Err(EmitError::InvalidOpcode(opcode));
                }
                let dynamic_output = operation
                    .output
                    .as_ref()
                    .map(|template| dynamic_handle(template, context))
                    .transpose()?
                    .flatten();
                let output = operation
                    .output
                    .as_ref()
                    .map(|template| fix_varnode(template, context))
                    .transpose()?;
                let mut inputs = Vec::with_capacity(operation.inputs.len());
                for input in &operation.inputs {
                    let varnode = fix_varnode(input, context)?;
                    if let Some((handle, plus)) = dynamic_handle(input, context)? {
                        let pointer = materialize_dynamic_pointer(
                            handle,
                            plus,
                            context,
                            &mut runtime_unique_offset,
                            &mut emitted,
                        )?;
                        emitted.push(PcodeOp::new(
                            op::LOAD,
                            Some(varnode),
                            vec![space_id_varnode(handle.space, context), pointer],
                        ));
                    }
                    inputs.push(varnode);
                }
                let operation_index = emitted.len();
                for (input_index, input) in operation.inputs.iter().enumerate() {
                    if matches!(input.offset, ConstTemplate::Relative(_)) {
                        relatives.push((operation_index, input_index, inputs[input_index].offset));
                    }
                }
                emitted.push(PcodeOp::new(opcode as i32, output, inputs));
                if let (Some((handle, plus)), Some(value)) = (dynamic_output, output) {
                    let pointer = materialize_dynamic_pointer(
                        handle,
                        plus,
                        context,
                        &mut runtime_unique_offset,
                        &mut emitted,
                    )?;
                    emitted.push(PcodeOp::new(
                        op::STORE,
                        None,
                        vec![space_id_varnode(handle.space, context), pointer, value],
                    ));
                }
            }
        }
    }

    for (operation_index, input_index, label) in relatives {
        let target = labels
            .get(&label)
            .copied()
            .ok_or(EmitError::MissingLabel(label))?;
        let input = &mut emitted[operation_index].inputs[input_index];
        input.offset = u64::try_from(target)
            .unwrap()
            .wrapping_sub(u64::try_from(operation_index).unwrap())
            & size_mask(input.size);
    }
    Ok(emitted)
}

pub(crate) fn dynamic_handle(
    template: &VarnodeTemplate,
    context: &TemplateContext,
) -> Result<Option<(FixedHandle, u64)>, EmitError> {
    let ConstTemplate::Handle {
        index,
        selector,
        plus,
    } = template.offset
    else {
        return Ok(None);
    };
    let handle = *context
        .handles
        .get(index)
        .ok_or(EmitError::MissingHandle(index))?;
    if !handle.valid {
        return Err(EmitError::InvalidHandle(index));
    }
    Ok(handle.offset_space.is_some().then_some((
        handle,
        if selector == HandleSelector::OffsetPlus {
            plus & 0xffff
        } else {
            0
        },
    )))
}

pub(crate) fn space_id_varnode(space: u32, context: &TemplateContext) -> Varnode {
    let offset = context
        .space_ids
        .as_deref()
        .and_then(|spaces| spaces.get(space as usize))
        .copied()
        .unwrap_or(u64::from(space));
    Varnode::new(ventris_pcode::CONST_SPACE, offset, 8)
}

pub(crate) fn materialize_dynamic_pointer(
    handle: FixedHandle,
    plus: u64,
    context: &TemplateContext,
    runtime_unique_offset: &mut u64,
    emitted: &mut Vec<PcodeOp>,
) -> Result<Varnode, EmitError> {
    let pointer_space = handle.offset_space.ok_or(EmitError::ExpectedSpace)?;
    let mut pointer_offset = handle.offset;
    if context.unique_space == Some(pointer_space) {
        pointer_offset |= context.unique_offset;
    }
    let pointer = Varnode::new(pointer_space, pointer_offset, handle.offset_size);
    if plus == 0 {
        return Ok(pointer);
    }
    let unique_space = context.unique_space.ok_or(EmitError::ExpectedSpace)?;
    let adjusted = Varnode::new(
        unique_space,
        *runtime_unique_offset | context.unique_offset,
        handle.offset_size,
    );
    *runtime_unique_offset =
        runtime_unique_offset.wrapping_add(u64::from(handle.offset_size.max(1)));
    emitted.push(PcodeOp::new(
        op::INT_ADD,
        Some(adjusted),
        vec![
            pointer,
            Varnode::new(ventris_pcode::CONST_SPACE, plus, handle.offset_size),
        ],
    ));
    Ok(adjusted)
}

pub(crate) fn fix_varnode(
    template: &VarnodeTemplate,
    context: &TemplateContext,
) -> Result<Varnode, EmitError> {
    let space = fix_space(&template.space, context)?;
    let size_value = fix_value(&template.size, context)?;
    let size = u32::try_from(size_value).map_err(|_| EmitError::InvalidSize(size_value))?;
    let mut offset = fix_value(&template.offset, context)?;
    if space == ventris_pcode::CONST_SPACE {
        offset &= size_mask(size);
    } else if context.unique_space == Some(space) {
        offset |= context.unique_offset;
    }
    Ok(Varnode::new(space, offset, size))
}

pub(crate) fn fix_space(
    template: &ConstTemplate,
    context: &TemplateContext,
) -> Result<u32, EmitError> {
    match template {
        ConstTemplate::SpaceId(space) => {
            u32::try_from(*space).map_err(|_| EmitError::InvalidSpace(*space))
        }
        ConstTemplate::CurrentSpace => Ok(context.current_space),
        ConstTemplate::Handle {
            index,
            selector: HandleSelector::Space,
            ..
        } => {
            let handle = context
                .handles
                .get(*index)
                .ok_or(EmitError::MissingHandle(*index))?;
            if !handle.valid {
                return Err(EmitError::InvalidHandle(*index));
            }
            if handle.offset_space.is_none() {
                Ok(handle.space)
            } else {
                handle
                    .temporary_space
                    .ok_or(EmitError::MissingTemporary(*index))
            }
        }
        _ => Err(EmitError::ExpectedSpace),
    }
}

pub(crate) fn fix_value(
    template: &ConstTemplate,
    context: &TemplateContext,
) -> Result<u64, EmitError> {
    match template {
        ConstTemplate::Real(value) | ConstTemplate::Relative(value) => Ok(*value),
        ConstTemplate::Start => Ok(context.address),
        ConstTemplate::Next => Ok(context.next_address),
        ConstTemplate::Next2 => context.next2_address.ok_or(EmitError::MissingNext2),
        ConstTemplate::CurrentSpace => Ok(u64::from(context.current_space)),
        ConstTemplate::CurrentSpaceSize => Ok(u64::from(context.current_space_size)),
        ConstTemplate::SpaceId(space) => context
            .space_ids
            .as_deref()
            .and_then(|space_ids| space_ids.get(*space as usize))
            .copied()
            .ok_or(EmitError::InvalidSpace(*space)),
        ConstTemplate::FlowRef => context
            .flow_reference
            .map(|handle| handle.offset)
            .ok_or(EmitError::MissingFlowReference),
        ConstTemplate::FlowRefSize => context
            .flow_reference
            .map(|handle| u64::from(handle.size))
            .ok_or(EmitError::MissingFlowReference),
        ConstTemplate::FlowDest => context
            .flow_destination
            .map(|handle| handle.offset)
            .ok_or(EmitError::MissingFlowDestination),
        ConstTemplate::FlowDestSize => context
            .flow_destination
            .map(|handle| u64::from(handle.size))
            .ok_or(EmitError::MissingFlowDestination),
        ConstTemplate::Handle {
            index,
            selector,
            plus,
        } => {
            let handle = context
                .handles
                .get(*index)
                .ok_or(EmitError::MissingHandle(*index))?;
            if !handle.valid {
                return Err(EmitError::InvalidHandle(*index));
            }
            let dynamic_offset = || {
                if handle.offset_space.is_none() {
                    Ok(handle.offset)
                } else {
                    Ok(handle.temporary_offset)
                }
            };
            match selector {
                HandleSelector::Space => Ok(u64::from(if handle.offset_space.is_none() {
                    handle.space
                } else {
                    handle
                        .temporary_space
                        .ok_or(EmitError::MissingTemporary(*index))?
                })),
                HandleSelector::Offset => dynamic_offset(),
                HandleSelector::Size => Ok(u64::from(handle.size)),
                HandleSelector::OffsetPlus => {
                    let offset = dynamic_offset()?;
                    if handle.space == ventris_pcode::CONST_SPACE {
                        Ok(offset >> (8 * (plus >> 16)))
                    } else {
                        Ok(offset.wrapping_add(plus & 0xffff))
                    }
                }
            }
        }
    }
}

fn real_offset(template: &VarnodeTemplate) -> Result<u64, EmitError> {
    match template.offset {
        ConstTemplate::Real(value) => Ok(value),
        _ => Err(EmitError::MalformedLabel),
    }
}

fn size_mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else if size == 0 {
        0
    } else {
        (1_u64 << (size * 8)) - 1
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EmitError {
    Build,
    CrossBuild,
    DelaySlot(i64),
    DelaySlotOperation,
    InvalidOpcode(i64),
    InvalidSize(u64),
    InvalidSpace(u64),
    MissingHandle(usize),
    InvalidHandle(usize),
    MissingTemporary(usize),
    MissingNext2,
    MissingFlowReference,
    MissingFlowDestination,
    ExpectedSpace,
    MalformedLabel,
    MissingLabel(u64),
    MalformedBuild,
    LabelOverflow,
}

impl fmt::Display for EmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build => formatter.write_str("template requires an operand BUILD"),
            Self::CrossBuild => formatter.write_str("template requires a CROSSBUILD"),
            Self::DelaySlot(bytes) => {
                write!(formatter, "template requires {bytes} delay-slot bytes")
            }
            Self::DelaySlotOperation => {
                formatter.write_str("template contains a DELAY_SLOT operation")
            }
            Self::InvalidOpcode(opcode) => write!(formatter, "invalid p-code opcode {opcode}"),
            Self::InvalidSize(size) => write!(formatter, "varnode size {size} exceeds u32"),
            Self::InvalidSpace(space) => {
                write!(formatter, "address-space index {space} exceeds u32")
            }
            Self::MissingHandle(index) => write!(formatter, "missing operand handle {index}"),
            Self::InvalidHandle(index) => write!(formatter, "operand handle {index} is invalid"),
            Self::MissingTemporary(index) => {
                write!(formatter, "dynamic handle {index} has no temporary storage")
            }
            Self::MissingNext2 => formatter.write_str("inst_next2 is unavailable"),
            Self::MissingFlowReference => formatter.write_str("flow reference is unavailable"),
            Self::MissingFlowDestination => formatter.write_str("flow destination is unavailable"),
            Self::ExpectedSpace => {
                formatter.write_str("constant template does not resolve to a space")
            }
            Self::MalformedLabel => formatter.write_str("malformed LABELBUILD operation"),
            Self::MissingLabel(label) => {
                write!(formatter, "relative p-code label {label} is undefined")
            }
            Self::MalformedBuild => formatter.write_str("malformed BUILD operation"),
            Self::LabelOverflow => formatter.write_str("p-code label id overflow"),
        }
    }
}

impl Error for EmitError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_fixed_copy() {
        let template = ConstructTemplate {
            delay_slot_bytes: 0,
            label_count: 0,
            section: None,
            result: None,
            operations: vec![OperationTemplate {
                opcode: i64::from(op::COPY),
                output: Some(VarnodeTemplate {
                    space: ConstTemplate::SpaceId(4),
                    offset: ConstTemplate::Real(8),
                    size: ConstTemplate::Real(4),
                }),
                inputs: vec![VarnodeTemplate {
                    space: ConstTemplate::SpaceId(0),
                    offset: ConstTemplate::Real(7),
                    size: ConstTemplate::Real(4),
                }],
            }],
        };
        assert_eq!(
            emit_template(&template, &TemplateContext::at(0x1000, 4, 3, 4)).unwrap(),
            vec![PcodeOp::new(
                op::COPY,
                Some(Varnode::new(4, 8, 4)),
                vec![Varnode::new(0, 7, 4)]
            )]
        );
    }
}
