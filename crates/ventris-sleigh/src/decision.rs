use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use crate::{AttributeValue, ConstructTemplate, Element, SlaArtifact, SlaError};
use ventris_pcode::{CONST_SPACE, OTHER_SPACE, RAM_SPACE, REGISTER_SPACE, UNIQUE_SPACE};

const ATTR_VAL: u16 = 2;
const ATTR_ID: u16 = 3;
const ATTR_SPACE: u16 = 4;
const ATTR_OFF: u16 = 6;
const ATTR_INDEX: u16 = 9;
const ATTR_MASK: u16 = 8;
const ATTR_NONZERO: u16 = 10;
const ATTR_PIECE: u16 = 11;
const ATTR_NAME: u16 = 12;
const ATTR_STARTBIT: u16 = 14;
const ATTR_SIZE: u16 = 15;
const ATTR_NUMBER: u16 = 20;
const ATTR_CONTEXT: u16 = 21;
const ATTR_PARENT: u16 = 22;
const ATTR_SOURCE: u16 = 25;
const ATTR_LENGTH: u16 = 26;
const ATTR_FIRST: u16 = 27;
const ATTR_LOW: u16 = 48;
const ATTR_HIGH: u16 = 49;
const ATTR_SHIFT: u16 = 29;
const ATTR_VERSION: u16 = 34;
const ATTR_BIG_ENDIAN: u16 = 35;
const ATTR_ALIGNMENT: u16 = 36;
const ATTR_UNIQUE_BASE: u16 = 37;
const ATTR_MAX_DELAY: u16 = 38;
const ATTR_UNIQUE_MASK: u16 = 39;
const ATTR_NUM_SECTIONS: u16 = 40;
const ATTR_DEFAULT_SPACE: u16 = 41;
const ATTR_SCOPE_SIZE: u16 = 45;
const ATTR_SYMBOL_SIZE: u16 = 46;
const ATTR_I: u16 = 52;
const ATTR_NUM_CONSTRUCTORS: u16 = 53;

const ELEM_PATTERN_BLOCK: u16 = 7;
const ELEM_PRINT: u16 = 8;
const ELEM_PAIR: u16 = 9;
const ELEM_CONTEXT_PATTERN: u16 = 10;
const ELEM_DECISION: u16 = 16;
const ELEM_INSTRUCTION_PATTERN: u16 = 18;
const ELEM_COMBINE_PATTERN: u16 = 19;
const ELEM_CONSTRUCTOR: u16 = 20;
const ELEM_CONSTRUCT_TEMPLATE: u16 = 21;
const ELEM_USEROP: u16 = 25;
const ELEM_USEROP_HEADER: u16 = 26;
const ELEM_CONTEXT_OP: u16 = 32;
const ELEM_SPACES: u16 = 34;
const ELEM_SPACE_UNIQUE: u16 = 46;
const ELEM_VARNODE_SYM: u16 = 23;
const ELEM_SPACE: u16 = 37;
const ELEM_SPACE_OTHER: u16 = 45;
const ELEM_SYMBOL_TABLE: u16 = 38;
const ELEM_OPER: u16 = 15;
const ELEM_CONTEXT_SYMBOL: u16 = 41;
const ELEM_SUBTABLE_SYMBOL: u16 = 71;
const ELEM_SUBTABLE_SYMBOL_HEADER: u16 = 72;

/// Semantic subset of a compiled SLEIGH specification needed to select constructors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SleighSpec {
    pub big_endian: bool,
    pub alignment: i64,
    pub unique_base: u64,
    pub max_delay_slot_bytes: u64,
    pub unique_allocation_mask: u64,
    pub unique_space: u32,
    pub space_ids: Arc<[u64]>,
    /// Maps language-local compiled space indices to stable p-code space IDs.
    pub space_map: Arc<[u32]>,
    pub num_sections: u64,
    pub symbols: Vec<SymbolHeader>,
    pub symbol_bodies: BTreeMap<u64, Element>,
    pub subtables: BTreeMap<u64, Subtable>,
    instruction_table_id: u64,
}

impl SleighSpec {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, SpecError> {
        let artifact = SlaArtifact::from_path(path).map_err(SpecError::Artifact)?;
        Self::from_artifact(&artifact)
    }

    pub fn from_artifact(artifact: &SlaArtifact) -> Result<Self, SpecError> {
        let root = &artifact.root;
        let version = signed(root, ATTR_VERSION)?;
        if version != i64::from(crate::FORMAT_VERSION) {
            return Err(model(format!(
                "ELEM_SLEIGH version {version} does not match {}",
                crate::FORMAT_VERSION
            )));
        }

        let symbol_table = child(root, ELEM_SYMBOL_TABLE)?;
        let scope_count = nonnegative_usize(signed(symbol_table, ATTR_SCOPE_SIZE)?, "scope count")?;
        let symbol_count =
            nonnegative_usize(signed(symbol_table, ATTR_SYMBOL_SIZE)?, "symbol count")?;
        let header_start = scope_count;
        let header_end = header_start
            .checked_add(symbol_count)
            .ok_or_else(|| model("symbol-table size overflow"))?;
        if symbol_table.children.len() < header_end {
            return Err(model(format!(
                "symbol table declares {scope_count} scopes and {symbol_count} symbols but has only {} children",
                symbol_table.children.len()
            )));
        }

        let mut symbols = Vec::with_capacity(symbol_count);
        let mut instruction_table_id = None;
        for header in &symbol_table.children[header_start..header_end] {
            let symbol = SymbolHeader {
                element_id: header.id,
                id: unsigned(header, ATTR_ID)?,
                name: string(header, ATTR_NAME)?.to_owned(),
            };
            if header.id == ELEM_SUBTABLE_SYMBOL_HEADER && symbol.name == "instruction" {
                instruction_table_id = Some(symbol.id);
            }
            symbols.push(symbol);
        }
        let instruction_table_id = instruction_table_id
            .ok_or_else(|| model("symbol table has no instruction subtable"))?;

        let mut symbol_bodies = BTreeMap::new();
        for body in &symbol_table.children[header_end..] {
            let id = unsigned(body, ATTR_ID)?;
            if symbol_bodies.insert(id, body.clone()).is_some() {
                return Err(model(format!("duplicate symbol body id {id}")));
            }
        }
        if symbol_bodies.len() != symbol_count {
            return Err(model(format!(
                "symbol table declares {symbol_count} symbols but contains {} bodies",
                symbol_bodies.len()
            )));
        }

        let mut subtables = BTreeMap::new();
        for body in &symbol_table.children[header_end..] {
            if body.id != ELEM_SUBTABLE_SYMBOL {
                continue;
            }
            let table = Subtable::decode(body)?;
            if subtables.insert(table.id, table).is_some() {
                return Err(model(format!(
                    "duplicate subtable body id {}",
                    unsigned(body, ATTR_ID)?
                )));
            }
        }
        if !subtables.contains_key(&instruction_table_id) {
            return Err(model(format!(
                "instruction subtable {instruction_table_id} has no body"
            )));
        }

        let spaces = child(root, ELEM_SPACES)?;
        let default_space = string(spaces, ATTR_DEFAULT_SPACE)?;
        let unique_space_element = child(spaces, ELEM_SPACE_UNIQUE)?;
        let unique_space = u32::try_from(signed(unique_space_element, ATTR_INDEX)?)
            .map_err(|_| model("unique-space index is negative or exceeds u32"))?;
        let mut space_ids = Vec::new();
        let mut space_map = Vec::new();
        let mut next_custom_space = REGISTER_SPACE + 1;
        for space in &spaces.children {
            let space_type = match space.id {
                ELEM_SPACE => 1_u64,
                ELEM_SPACE_UNIQUE => 3,
                ELEM_SPACE_OTHER => 7,
                _ => continue,
            };
            let index = nonnegative_usize(signed(space, ATTR_INDEX)?, "address-space index")?;
            let size = u64::try_from(signed(space, ATTR_SIZE)?)
                .map_err(|_| model("address-space size is negative"))?;
            if size == 0 || !size.is_power_of_two() {
                return Err(model(format!(
                    "address-space size {size} is not a power of two"
                )));
            }
            let normalized = match space.id {
                ELEM_SPACE_UNIQUE => UNIQUE_SPACE,
                ELEM_SPACE_OTHER => OTHER_SPACE,
                ELEM_SPACE => {
                    let name = string(space, ATTR_NAME)?;
                    if name == default_space || name == "ram" {
                        RAM_SPACE
                    } else if name == "register" {
                        REGISTER_SPACE
                    } else {
                        let id = next_custom_space;
                        next_custom_space = next_custom_space
                            .checked_add(1)
                            .ok_or_else(|| model("too many address spaces"))?;
                        id
                    }
                }
                _ => unreachable!(),
            };
            space_ids.resize(space_ids.len().max(index + 1), 0);
            space_ids[index] =
                (u64::from(normalized) << 7) | (u64::from(size.trailing_zeros()) << 4) | space_type;
            space_map.resize(space_map.len().max(index + 1), CONST_SPACE);
            space_map[index] = normalized;
        }
        let space_ids: Arc<[u64]> = space_ids.into();
        let space_map: Arc<[u32]> = space_map.into();

        Ok(Self {
            big_endian: boolean(root, ATTR_BIG_ENDIAN)?,
            alignment: signed(root, ATTR_ALIGNMENT)?,
            unique_base: unsigned(root, ATTR_UNIQUE_BASE)?,
            max_delay_slot_bytes: optional_unsigned(root, ATTR_MAX_DELAY)?.unwrap_or(0),
            unique_allocation_mask: optional_unsigned(root, ATTR_UNIQUE_MASK)?.unwrap_or(0),
            num_sections: optional_unsigned(root, ATTR_NUM_SECTIONS)?.unwrap_or(0),
            symbols,
            unique_space,
            space_ids,
            space_map,
            symbol_bodies,
            subtables,
            instruction_table_id,
        })
    }

    pub fn instruction_table(&self) -> &Subtable {
        &self.subtables[&self.instruction_table_id]
    }

    /// Converts a compiled language's table index to Ventris's stable p-code
    /// space numbering. Index zero remains the synthetic constant space.
    pub fn normalize_space(&self, space: u32) -> u32 {
        self.space_map.get(space as usize).copied().unwrap_or(space)
    }

    /// Selects the top-level instruction constructor using Ghidra's decision-tree rules.
    pub fn resolve_instruction<'a>(
        &'a self,
        bytes: &[u8],
        context: &[u32],
    ) -> Result<&'a Constructor, ResolveError> {
        self.instruction_table().resolve(bytes, context)
    }

    /// Returns the compiled name for a CALLOTHER operation index.
    pub fn userop_name(&self, index: u64) -> Option<&str> {
        self.symbols.iter().find_map(|header| {
            if header.element_id != ELEM_USEROP_HEADER {
                return None;
            }
            let body = self.symbol_bodies.get(&header.id)?;
            if body.id != ELEM_USEROP
                || u64::try_from(signed(body, ATTR_INDEX).ok()?).ok()? != index
            {
                return None;
            }
            Some(header.name.as_str())
        })
    }

    /// Returns the address space, offset, and size compiled for a named
    /// register.
    ///
    /// Register offsets are language facts, not architecture folklore: the
    /// R5900 spaces its 128-bit general registers 16 bytes apart while generic
    /// MIPS64 spaces its 64-bit registers 8 bytes apart. Callers that hardcode
    /// one layout silently misidentify ABI registers under the other.
    pub fn register_varnode(&self, name: &str) -> Option<(u32, u64, u32)> {
        let header = self.symbols.iter().find(|symbol| symbol.name == name)?;
        let body = self.symbol_bodies.get(&header.id)?;
        if body.id != ELEM_VARNODE_SYM {
            return None;
        }
        let space = match attribute(body, ATTR_SPACE).ok()? {
            AttributeValue::AddressSpace(space) => u32::try_from(*space).ok()?,
            _ => return None,
        };
        Some((
            self.normalize_space(space),
            unsigned(body, ATTR_OFF).ok()?,
            u32::try_from(signed(body, ATTR_SIZE).ok()?).ok()?,
        ))
    }

    /// Sets a named stored-context field using the bit range encoded in the
    /// compiled SLEIGH symbol table. Context bit zero is the most-significant
    /// bit of the first 32-bit word, matching Ghidra's parser context.
    pub fn set_context_variable(
        &self,
        context: &mut [u32],
        name: &str,
        value: u32,
    ) -> Result<(), SpecError> {
        let header = self
            .symbols
            .iter()
            .find(|symbol| symbol.name == name)
            .ok_or_else(|| model(format!("compiled SLEIGH has no context symbol {name:?}")))?;
        let body = self
            .symbol_bodies
            .get(&header.id)
            .ok_or_else(|| model(format!("context symbol {name:?} has no body")))?;
        if body.id != ELEM_CONTEXT_SYMBOL {
            return Err(model(format!(
                "symbol {name:?} is element {}, not a context symbol",
                body.id
            )));
        }
        let low = nonnegative_usize(signed(body, ATTR_LOW)?, "context low bit")?;
        let high = nonnegative_usize(signed(body, ATTR_HIGH)?, "context high bit")?;
        if high < low || high - low >= u32::BITS as usize {
            return Err(model(format!(
                "context symbol {name:?} has invalid bit range {low}..={high}"
            )));
        }
        let width = high - low + 1;
        if width < u32::BITS as usize && value >= (1_u32 << width) {
            return Err(model(format!(
                "value {value} does not fit {width}-bit context symbol {name:?}"
            )));
        }
        if high / 32 >= context.len() {
            return Err(model(format!(
                "context symbol {name:?} requires word {}, but only {} supplied",
                high / 32,
                context.len()
            )));
        }
        for field_bit in 0..width {
            let bit = low + field_bit;
            let word = bit / 32;
            let mask = 1_u32 << (31 - bit % 32);
            if value & (1_u32 << (width - field_bit - 1)) != 0 {
                context[word] |= mask;
            } else {
                context[word] &= !mask;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SymbolHeader {
    pub element_id: u16,
    pub id: u64,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Subtable {
    pub id: u64,
    pub constructors: Vec<Constructor>,
    pub decision: DecisionNode,
}

impl Subtable {
    fn decode(element: &Element) -> Result<Self, SpecError> {
        let id = unsigned(element, ATTR_ID)?;
        let declared =
            nonnegative_usize(signed(element, ATTR_NUM_CONSTRUCTORS)?, "constructor count")?;
        let constructors = element
            .children
            .iter()
            .filter(|child| child.id == ELEM_CONSTRUCTOR)
            .enumerate()
            .map(|(id, child)| Constructor::decode(id, child))
            .collect::<Result<Vec<_>, _>>()?;
        if constructors.len() != declared {
            return Err(model(format!(
                "subtable {id} declares {declared} constructors but contains {}",
                constructors.len()
            )));
        }
        let decision = DecisionNode::decode(child(element, ELEM_DECISION)?, declared)?;
        Ok(Self {
            id,
            constructors,
            decision,
        })
    }

    pub fn resolve(&self, bytes: &[u8], context: &[u32]) -> Result<&Constructor, ResolveError> {
        let id = self.decision.resolve(bytes, context)?;
        self.constructors
            .get(id)
            .ok_or(ResolveError::InvalidConstructor(id))
    }

    /// Returns every pattern-compatible constructor in source order.
    ///
    /// Some SLEIGH tables intentionally overlap patterns and use an operand
    /// table's invalid entry to reject an early candidate. Full resolution
    /// must therefore be able to try the remaining leaf candidates.
    pub fn resolve_candidates(
        &self,
        bytes: &[u8],
        context: &[u32],
    ) -> Result<Vec<&Constructor>, ResolveError> {
        self.decision
            .resolve_candidates(bytes, context)?
            .into_iter()
            .map(|id| {
                self.constructors
                    .get(id)
                    .ok_or(ResolveError::InvalidConstructor(id))
            })
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Constructor {
    pub id: usize,
    pub parent_symbol: u64,
    pub minimum_length: usize,
    pub first_whitespace: i64,
    pub source_index: i64,
    pub print_pieces: Vec<String>,
    pub operand_symbols: Vec<u64>,
    pub context_operations: Vec<ContextOperation>,
    pub templates: Vec<ConstructTemplate>,
}

impl Constructor {
    fn decode(id: usize, element: &Element) -> Result<Self, SpecError> {
        let length = signed(element, ATTR_LENGTH)?;
        let minimum_length = nonnegative_usize(length, "constructor minimum length")?;
        let print_pieces = element
            .children
            .iter()
            .filter(|child| child.id == ELEM_PRINT)
            .map(|child| string(child, ATTR_PIECE).map(ToOwned::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        let operand_symbols = element
            .children
            .iter()
            .filter(|child| child.id == ELEM_OPER)
            .map(|child| unsigned(child, ATTR_ID))
            .collect::<Result<Vec<_>, _>>()?;
        let context_operations = element
            .children
            .iter()
            .filter(|child| child.id == ELEM_CONTEXT_OP)
            .map(ContextOperation::decode)
            .collect::<Result<Vec<_>, _>>()?;
        let templates = element
            .children
            .iter()
            .filter(|child| child.id == ELEM_CONSTRUCT_TEMPLATE)
            .map(ConstructTemplate::decode)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            id,
            parent_symbol: unsigned(element, ATTR_PARENT)?,
            minimum_length,
            first_whitespace: signed(element, ATTR_FIRST)?,
            source_index: signed(element, ATTR_SOURCE)?,
            print_pieces,
            operand_symbols,
            context_operations,
            templates,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextOperation {
    pub word: usize,
    pub shift: u32,
    pub mask: u32,
    pub expression: Element,
}

impl ContextOperation {
    fn decode(element: &Element) -> Result<Self, SpecError> {
        Ok(Self {
            word: nonnegative_usize(signed(element, ATTR_I)?, "context word index")?,
            shift: u32::try_from(signed(element, ATTR_SHIFT)?)
                .map_err(|_| model("context shift is negative or exceeds u32"))?,
            mask: u32::try_from(unsigned(element, ATTR_MASK)?)
                .map_err(|_| model("context mask exceeds u32"))?,
            expression: element
                .children
                .first()
                .cloned()
                .ok_or_else(|| model("context operation has no expression"))?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionNode {
    pub number: i64,
    pub context_decision: bool,
    pub start_bit: usize,
    pub bit_size: usize,
    pub pairs: Vec<DecisionPair>,
    pub children: Vec<DecisionNode>,
}

impl DecisionNode {
    fn decode(element: &Element, constructor_count: usize) -> Result<Self, SpecError> {
        if element.id != ELEM_DECISION {
            return Err(model(format!(
                "expected decision element {ELEM_DECISION}, found {}",
                element.id
            )));
        }
        let start_bit = nonnegative_usize(signed(element, ATTR_STARTBIT)?, "decision start bit")?;
        let bit_size = nonnegative_usize(signed(element, ATTR_SIZE)?, "decision bit size")?;
        if bit_size > 31 {
            return Err(model(format!("decision bit size {bit_size} exceeds uintm")));
        }
        let mut pairs = Vec::new();
        let mut children = Vec::new();
        for child in &element.children {
            match child.id {
                ELEM_PAIR => {
                    let constructor_id =
                        nonnegative_usize(signed(child, ATTR_ID)?, "constructor id")?;
                    if constructor_id >= constructor_count {
                        return Err(model(format!(
                            "decision references constructor {constructor_id} of {constructor_count}"
                        )));
                    }
                    let pattern_element = child
                        .children
                        .first()
                        .ok_or_else(|| model("decision pair has no pattern"))?;
                    pairs.push(DecisionPair {
                        constructor_id,
                        pattern: Pattern::decode(pattern_element)?,
                    });
                }
                ELEM_DECISION => children.push(Self::decode(child, constructor_count)?),
                id => return Err(model(format!("unexpected decision child element {id}"))),
            }
        }
        if bit_size == 0 {
            if !children.is_empty() {
                return Err(model("terminal decision has child decisions"));
            }
        } else {
            let expected = 1_usize << bit_size;
            if children.len() != expected {
                return Err(model(format!(
                    "{bit_size}-bit decision has {} children instead of {expected}",
                    children.len()
                )));
            }
        }
        Ok(Self {
            number: signed(element, ATTR_NUMBER)?,
            context_decision: boolean(element, ATTR_CONTEXT)?,
            start_bit,
            bit_size,
            pairs,
            children,
        })
    }

    fn resolve(&self, bytes: &[u8], context: &[u32]) -> Result<usize, ResolveError> {
        if self.bit_size == 0 {
            for pair in &self.pairs {
                if pair.pattern.matches(bytes, context)? {
                    return Ok(pair.constructor_id);
                }
            }
            return Err(ResolveError::NoConstructor);
        }
        let value = if self.context_decision {
            context_bits(context, self.start_bit, self.bit_size)?
        } else {
            instruction_bits(bytes, self.start_bit, self.bit_size)?
        };
        self.children
            .get(value as usize)
            .ok_or(ResolveError::InvalidDecisionIndex(value))?
            .resolve(bytes, context)
    }

    fn resolve_candidates(
        &self,
        bytes: &[u8],
        context: &[u32],
    ) -> Result<Vec<usize>, ResolveError> {
        if self.bit_size == 0 {
            let mut candidates = Vec::new();
            for pair in &self.pairs {
                if pair.pattern.matches(bytes, context)? {
                    candidates.push(pair.constructor_id);
                }
            }
            return if candidates.is_empty() {
                Err(ResolveError::NoConstructor)
            } else {
                Ok(candidates)
            };
        }
        let value = if self.context_decision {
            context_bits(context, self.start_bit, self.bit_size)?
        } else {
            instruction_bits(bytes, self.start_bit, self.bit_size)?
        };
        self.children
            .get(value as usize)
            .ok_or(ResolveError::InvalidDecisionIndex(value))?
            .resolve_candidates(bytes, context)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionPair {
    pub constructor_id: usize,
    pub pattern: Pattern,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Pattern {
    Instruction(PatternBlock),
    Context(PatternBlock),
    Combine {
        context: PatternBlock,
        instruction: PatternBlock,
    },
}

impl Pattern {
    fn decode(element: &Element) -> Result<Self, SpecError> {
        match element.id {
            ELEM_INSTRUCTION_PATTERN => Ok(Self::Instruction(PatternBlock::decode(child(
                element,
                ELEM_PATTERN_BLOCK,
            )?)?)),
            ELEM_CONTEXT_PATTERN => Ok(Self::Context(PatternBlock::decode(child(
                element,
                ELEM_PATTERN_BLOCK,
            )?)?)),
            ELEM_COMBINE_PATTERN => {
                let context_element = child(element, ELEM_CONTEXT_PATTERN)?;
                let instruction_element = child(element, ELEM_INSTRUCTION_PATTERN)?;
                Ok(Self::Combine {
                    context: PatternBlock::decode(child(context_element, ELEM_PATTERN_BLOCK)?)?,
                    instruction: PatternBlock::decode(child(
                        instruction_element,
                        ELEM_PATTERN_BLOCK,
                    )?)?,
                })
            }
            id => Err(model(format!("unknown disjoint pattern element {id}"))),
        }
    }

    fn matches(&self, bytes: &[u8], context: &[u32]) -> Result<bool, ResolveError> {
        match self {
            Self::Instruction(pattern) => pattern.matches_instruction(bytes),
            Self::Context(pattern) => pattern.matches_context(context),
            Self::Combine {
                context: context_pattern,
                instruction,
            } => Ok(instruction.matches_instruction(bytes)?
                && context_pattern.matches_context(context)?),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PatternBlock {
    pub offset: i64,
    pub nonzero_size: i64,
    pub words: Vec<(u32, u32)>,
}

impl PatternBlock {
    fn decode(element: &Element) -> Result<Self, SpecError> {
        let mut words = Vec::new();
        for word in &element.children {
            let mask = u32::try_from(unsigned(word, ATTR_MASK)?)
                .map_err(|_| model("pattern mask exceeds Ghidra uintm"))?;
            let value = u32::try_from(unsigned(word, ATTR_VAL)?)
                .map_err(|_| model("pattern value exceeds Ghidra uintm"))?;
            words.push((mask, value));
        }
        Ok(Self {
            offset: signed(element, ATTR_OFF)?,
            nonzero_size: signed(element, ATTR_NONZERO)?,
            words,
        })
    }

    fn matches_instruction(&self, bytes: &[u8]) -> Result<bool, ResolveError> {
        self.matches_bytes(bytes)
    }

    fn matches_context(&self, context: &[u32]) -> Result<bool, ResolveError> {
        let mut bytes = Vec::with_capacity(context.len() * 4);
        for word in context {
            bytes.extend_from_slice(&word.to_be_bytes());
        }
        self.matches_bytes(&bytes)
    }

    fn matches_bytes(&self, bytes: &[u8]) -> Result<bool, ResolveError> {
        if self.nonzero_size <= 0 {
            return Ok(self.nonzero_size == 0);
        }
        let mut offset = usize::try_from(self.offset)
            .map_err(|_| ResolveError::NegativePatternOffset(self.offset))?;
        for &(mask, value) in &self.words {
            let end = offset
                .checked_add(4)
                .ok_or(ResolveError::InputTooShort { offset, needed: 4 })?;
            let word = bytes
                .get(offset..end)
                .ok_or(ResolveError::InputTooShort { offset, needed: 4 })?;
            let data = u32::from_be_bytes(word.try_into().expect("four-byte slice"));
            if mask & data != value {
                return Ok(false);
            }
            offset = end;
        }
        Ok(true)
    }
}

#[derive(Debug)]
pub enum SpecError {
    Artifact(SlaError),
    Model(String),
}

impl fmt::Display for SpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Artifact(error) => error.fmt(formatter),
            Self::Model(message) => write!(formatter, "invalid SLEIGH model: {message}"),
        }
    }
}

impl Error for SpecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Artifact(error) => Some(error),
            Self::Model(_) => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveError {
    InputTooShort { offset: usize, needed: usize },
    ContextTooShort { word: usize },
    InvalidDecisionIndex(u32),
    InvalidConstructor(usize),
    NegativePatternOffset(i64),
    NoConstructor,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooShort { offset, needed } => write!(
                formatter,
                "instruction input is too short at byte {offset}; need {needed} byte(s)"
            ),
            Self::ContextTooShort { word } => {
                write!(formatter, "context input is missing word {word}")
            }
            Self::InvalidDecisionIndex(index) => {
                write!(formatter, "decision tree has no child {index}")
            }
            Self::InvalidConstructor(id) => write!(formatter, "invalid constructor id {id}"),
            Self::NegativePatternOffset(offset) => {
                write!(formatter, "cannot match negative pattern offset {offset}")
            }
            Self::NoConstructor => formatter.write_str("no constructor pattern matched"),
        }
    }
}

impl Error for ResolveError {}

fn instruction_bits(bytes: &[u8], start_bit: usize, size: usize) -> Result<u32, ResolveError> {
    bit_slice(bytes, start_bit, size, false)
}

fn context_bits(context: &[u32], start_bit: usize, size: usize) -> Result<u32, ResolveError> {
    let mut bytes = Vec::with_capacity(context.len() * 4);
    for word in context {
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    bit_slice(&bytes, start_bit, size, true)
}

fn bit_slice(
    bytes: &[u8],
    start_bit: usize,
    size: usize,
    is_context: bool,
) -> Result<u32, ResolveError> {
    debug_assert!(size <= 31);
    let mut value = 0_u32;
    for bit in start_bit..start_bit + size {
        let byte_index = bit / 8;
        let byte = match bytes.get(byte_index) {
            Some(byte) => *byte,
            None if is_context => {
                return Err(ResolveError::ContextTooShort {
                    word: byte_index / 4,
                });
            }
            None => {
                return Err(ResolveError::InputTooShort {
                    offset: byte_index,
                    needed: 1,
                });
            }
        };
        value = (value << 1) | u32::from((byte >> (7 - bit % 8)) & 1);
    }
    Ok(value)
}

fn child(element: &Element, id: u16) -> Result<&Element, SpecError> {
    element
        .children
        .iter()
        .find(|child| child.id == id)
        .ok_or_else(|| model(format!("element {} has no child {id}", element.id)))
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

fn unsigned(element: &Element, id: u16) -> Result<u64, SpecError> {
    match attribute(element, id)? {
        AttributeValue::Unsigned(value) => Ok(*value),
        value => Err(model(format!(
            "element {} attribute {id} is {value:?}, expected unsigned integer",
            element.id
        ))),
    }
}

fn optional_unsigned(element: &Element, id: u16) -> Result<Option<u64>, SpecError> {
    match element.attribute(id) {
        None => Ok(None),
        Some(AttributeValue::Unsigned(value)) => Ok(Some(*value)),
        Some(value) => Err(model(format!(
            "element {} attribute {id} is {value:?}, expected unsigned integer",
            element.id
        ))),
    }
}

fn boolean(element: &Element, id: u16) -> Result<bool, SpecError> {
    match attribute(element, id)? {
        AttributeValue::Boolean(value) => Ok(*value),
        value => Err(model(format!(
            "element {} attribute {id} is {value:?}, expected boolean",
            element.id
        ))),
    }
}

fn string(element: &Element, id: u16) -> Result<&str, SpecError> {
    match attribute(element, id)? {
        AttributeValue::String(value) => Ok(value),
        value => Err(model(format!(
            "element {} attribute {id} is {value:?}, expected string",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_msb_first_instruction_bits() {
        assert_eq!(instruction_bits(&[0b1011_0010], 0, 3).unwrap(), 0b101);
        assert_eq!(instruction_bits(&[0b1011_0010], 3, 4).unwrap(), 0b1001);
    }

    #[test]
    fn pattern_words_are_big_endian() {
        let pattern = PatternBlock {
            offset: 0,
            nonzero_size: 4,
            words: vec![(0xffff_0000, 0x1234_0000)],
        };
        assert!(
            pattern
                .matches_instruction(&[0x12, 0x34, 0x56, 0x78])
                .unwrap()
        );
        assert!(
            !pattern
                .matches_instruction(&[0x12, 0x35, 0x56, 0x78])
                .unwrap()
        );
    }

    #[test]
    fn named_context_fields_use_compiled_symbol_ranges() {
        let artifact = SlaArtifact::from_bytes(crate::X86_64_SLA).unwrap();
        let spec = SleighSpec::from_artifact(&artifact).unwrap();
        let mut context = [0_u32; 4];
        spec.set_context_variable(&mut context, "addrsize", 2)
            .unwrap();
        spec.set_context_variable(&mut context, "opsize", 1)
            .unwrap();
        spec.set_context_variable(&mut context, "longMode", 1)
            .unwrap();
        assert_eq!(context[0], 0x8900_0000);
    }

    #[test]
    fn language_local_spaces_do_not_displace_canonical_registers() {
        let artifact = SlaArtifact::from_bytes(crate::Z80_SLA).unwrap();
        let spec = SleighSpec::from_artifact(&artifact).unwrap();
        assert_eq!(
            spec.normalize_space(4),
            5,
            "Z80 I/O is the first custom space"
        );
        assert_eq!(spec.normalize_space(5), REGISTER_SPACE);
        assert_eq!(spec.space_ids[5] >> 7, u64::from(REGISTER_SPACE));
    }
}
