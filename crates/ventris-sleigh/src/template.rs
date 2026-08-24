use crate::{AttributeValue, Element};

use super::decision::SpecError;

const ATTR_VAL: u16 = 2;
const ATTR_SPACE: u16 = 4;
const ATTR_SELECTOR: u16 = 5;
const ATTR_CODE: u16 = 7;
const ATTR_PLUS: u16 = 28;
const ATTR_DELAY: u16 = 42;
const ATTR_SECTION: u16 = 54;
const ATTR_LABELS: u16 = 55;

const ELEM_CONST_REAL: u16 = 1;
const ELEM_VARNODE_TEMPLATE: u16 = 2;
const ELEM_CONST_SPACE_ID: u16 = 3;
const ELEM_CONST_HANDLE: u16 = 4;
const ELEM_OP_TEMPLATE: u16 = 5;
const ELEM_NULL: u16 = 11;
const ELEM_CONSTRUCT_TEMPLATE: u16 = 21;
const ELEM_HANDLE_TEMPLATE: u16 = 30;
const ELEM_CONST_RELATIVE: u16 = 31;
const ELEM_CONST_START: u16 = 80;
const ELEM_CONST_NEXT: u16 = 81;
const ELEM_CONST_NEXT2: u16 = 82;
const ELEM_CONST_CURRENT_SPACE: u16 = 83;
const ELEM_CONST_CURRENT_SPACE_SIZE: u16 = 84;
const ELEM_CONST_FLOW_REF: u16 = 85;
const ELEM_CONST_FLOW_REF_SIZE: u16 = 86;
const ELEM_CONST_FLOW_DEST: u16 = 87;
const ELEM_CONST_FLOW_DEST_SIZE: u16 = 88;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConstTemplate {
    Real(u64),
    Handle {
        index: usize,
        selector: HandleSelector,
        plus: u64,
    },
    Start,
    Next,
    Next2,
    CurrentSpace,
    CurrentSpaceSize,
    SpaceId(u64),
    Relative(u64),
    FlowRef,
    FlowRefSize,
    FlowDest,
    FlowDestSize,
}

impl ConstTemplate {
    fn decode(element: &Element) -> Result<Self, SpecError> {
        Ok(match element.id {
            ELEM_CONST_REAL => Self::Real(unsigned(element, ATTR_VAL)?),
            ELEM_CONST_HANDLE => {
                let index = nonnegative_usize(signed(element, ATTR_VAL)?, "handle index")?;
                let selector = match signed(element, ATTR_SELECTOR)? {
                    0 => HandleSelector::Space,
                    1 => HandleSelector::Offset,
                    2 => HandleSelector::Size,
                    3 => HandleSelector::OffsetPlus,
                    value => return Err(model(format!("invalid handle selector {value}"))),
                };
                let plus = if selector == HandleSelector::OffsetPlus {
                    unsigned(element, ATTR_PLUS)?
                } else {
                    0
                };
                Self::Handle {
                    index,
                    selector,
                    plus,
                }
            }
            ELEM_CONST_START => Self::Start,
            ELEM_CONST_NEXT => Self::Next,
            ELEM_CONST_NEXT2 => Self::Next2,
            ELEM_CONST_CURRENT_SPACE => Self::CurrentSpace,
            ELEM_CONST_CURRENT_SPACE_SIZE => Self::CurrentSpaceSize,
            ELEM_CONST_SPACE_ID => Self::SpaceId(address_space(element, ATTR_SPACE)?),
            ELEM_CONST_RELATIVE => Self::Relative(unsigned(element, ATTR_VAL)?),
            ELEM_CONST_FLOW_REF => Self::FlowRef,
            ELEM_CONST_FLOW_REF_SIZE => Self::FlowRefSize,
            ELEM_CONST_FLOW_DEST => Self::FlowDest,
            ELEM_CONST_FLOW_DEST_SIZE => Self::FlowDestSize,
            id => return Err(model(format!("unknown constant template element {id}"))),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandleSelector {
    Space,
    Offset,
    Size,
    OffsetPlus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VarnodeTemplate {
    pub space: ConstTemplate,
    pub offset: ConstTemplate,
    pub size: ConstTemplate,
}

impl VarnodeTemplate {
    fn decode(element: &Element) -> Result<Self, SpecError> {
        expect_id(element, ELEM_VARNODE_TEMPLATE)?;
        expect_child_count(element, 3)?;
        Ok(Self {
            space: ConstTemplate::decode(&element.children[0])?,
            offset: ConstTemplate::decode(&element.children[1])?,
            size: ConstTemplate::decode(&element.children[2])?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandleTemplate {
    pub space: ConstTemplate,
    pub size: ConstTemplate,
    pub pointer_space: ConstTemplate,
    pub pointer_offset: ConstTemplate,
    pub pointer_size: ConstTemplate,
    pub temporary_space: ConstTemplate,
    pub temporary_offset: ConstTemplate,
}

impl HandleTemplate {
    fn decode(element: &Element) -> Result<Self, SpecError> {
        expect_id(element, ELEM_HANDLE_TEMPLATE)?;
        expect_child_count(element, 7)?;
        Ok(Self {
            space: ConstTemplate::decode(&element.children[0])?,
            size: ConstTemplate::decode(&element.children[1])?,
            pointer_space: ConstTemplate::decode(&element.children[2])?,
            pointer_offset: ConstTemplate::decode(&element.children[3])?,
            pointer_size: ConstTemplate::decode(&element.children[4])?,
            temporary_space: ConstTemplate::decode(&element.children[5])?,
            temporary_offset: ConstTemplate::decode(&element.children[6])?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationTemplate {
    pub opcode: i64,
    pub output: Option<VarnodeTemplate>,
    pub inputs: Vec<VarnodeTemplate>,
}

impl OperationTemplate {
    fn decode(element: &Element) -> Result<Self, SpecError> {
        expect_id(element, ELEM_OP_TEMPLATE)?;
        let output_element = element
            .children
            .first()
            .ok_or_else(|| model("operation template has no output marker"))?;
        let output = if output_element.id == ELEM_NULL {
            None
        } else {
            Some(VarnodeTemplate::decode(output_element)?)
        };
        let inputs = element.children[1..]
            .iter()
            .map(VarnodeTemplate::decode)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            opcode: signed(element, ATTR_CODE)?,
            output,
            inputs,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConstructTemplate {
    pub delay_slot_bytes: i64,
    pub label_count: i64,
    pub section: Option<usize>,
    pub result: Option<HandleTemplate>,
    pub operations: Vec<OperationTemplate>,
}

impl ConstructTemplate {
    pub(crate) fn decode(element: &Element) -> Result<Self, SpecError> {
        expect_id(element, ELEM_CONSTRUCT_TEMPLATE)?;
        let result_element = element
            .children
            .first()
            .ok_or_else(|| model("construct template has no result marker"))?;
        let result = if result_element.id == ELEM_NULL {
            None
        } else {
            Some(HandleTemplate::decode(result_element)?)
        };
        let operations = element.children[1..]
            .iter()
            .map(OperationTemplate::decode)
            .collect::<Result<Vec<_>, _>>()?;
        let section = match element.attribute(ATTR_SECTION) {
            None => None,
            Some(AttributeValue::Signed(value)) => Some(nonnegative_usize(*value, "section id")?),
            Some(value) => {
                return Err(model(format!(
                    "construct template section is {value:?}, expected signed integer"
                )));
            }
        };
        Ok(Self {
            delay_slot_bytes: optional_signed(element, ATTR_DELAY)?.unwrap_or(0),
            label_count: optional_signed(element, ATTR_LABELS)?.unwrap_or(0),
            section,
            result,
            operations,
        })
    }
}

fn expect_id(element: &Element, expected: u16) -> Result<(), SpecError> {
    if element.id == expected {
        Ok(())
    } else {
        Err(model(format!(
            "expected element {expected}, found {}",
            element.id
        )))
    }
}

fn expect_child_count(element: &Element, expected: usize) -> Result<(), SpecError> {
    if element.children.len() == expected {
        Ok(())
    } else {
        Err(model(format!(
            "element {} has {} children, expected {expected}",
            element.id,
            element.children.len()
        )))
    }
}

fn attribute(element: &Element, id: u16) -> Result<&AttributeValue, SpecError> {
    element
        .attribute(id)
        .ok_or_else(|| model(format!("element {} has no attribute {id}", element.id)))
}

fn signed(element: &Element, id: u16) -> Result<i64, SpecError> {
    match attribute(element, id)? {
        AttributeValue::Signed(value) => Ok(*value),
        value => Err(model(format!(
            "element {} attribute {id} is {value:?}, expected signed integer",
            element.id
        ))),
    }
}

fn optional_signed(element: &Element, id: u16) -> Result<Option<i64>, SpecError> {
    match element.attribute(id) {
        None => Ok(None),
        Some(AttributeValue::Signed(value)) => Ok(Some(*value)),
        Some(value) => Err(model(format!(
            "element {} attribute {id} is {value:?}, expected signed integer",
            element.id
        ))),
    }
}

fn unsigned(element: &Element, id: u16) -> Result<u64, SpecError> {
    match attribute(element, id)? {
        AttributeValue::Unsigned(value) => Ok(*value),
        value => Err(model(format!(
            "element {} attribute {id} is {value:?}, expected unsigned integer",
            element.id
        ))),
    }
}

fn address_space(element: &Element, id: u16) -> Result<u64, SpecError> {
    match attribute(element, id)? {
        AttributeValue::AddressSpace(value) => Ok(*value),
        value => Err(model(format!(
            "element {} attribute {id} is {value:?}, expected address-space index",
            element.id
        ))),
    }
}

fn nonnegative_usize(value: i64, what: &str) -> Result<usize, SpecError> {
    usize::try_from(value).map_err(|_| model(format!("{what} is negative or too large: {value}")))
}

fn model(message: impl Into<String>) -> SpecError {
    SpecError::Model(message.into())
}
