//! The debug information a decompiler can act on, independent of the format it
//! was written in.
//!
//! Two formats populate this: DWARF 2 in `.debug_info`, and MIPS symbolic debug
//! in `.mdebug`. They are unrelated on the wire and describe overlapping
//! subsets of an image — `dungeon_game.elf` carries both, with DWARF covering
//! only the linked-in runtime and `.mdebug` covering the program's own
//! translation units. A reader per format writing into one model is what lets a
//! caller ask "what does this function return" without knowing which toolchain
//! emitted the answer.

use std::collections::BTreeMap;

/// Everything the readers recover from an image's debug sections.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DebugInfo {
    /// Function prototypes, keyed by entry address.
    pub functions: BTreeMap<u64, DebugFunction>,
}

impl DebugInfo {
    /// Fold another reader's findings in, keeping what is already present.
    ///
    /// Order of preference is the caller's: whichever source is merged first
    /// keeps its entry. The two formats describe disjoint sets in practice, and
    /// where they overlap the richer record should be merged first.
    pub fn merge(&mut self, other: DebugInfo) {
        for (entry, function) in other.functions {
            self.functions.entry(entry).or_insert(function);
        }
    }
}

/// One function's prototype as the compiler recorded it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DebugFunction {
    pub entry: u64,
    /// The name as recorded. DWARF stores the source name; MIPS symbolic stores
    /// the linkage name, so a C++ member function arrives decorated.
    pub name: String,
    /// The declared return type. `None` is a function returning nothing, which
    /// both formats spell as an absent type rather than a void type.
    pub return_type: Option<DebugType>,
    pub parameters: Vec<DebugParameter>,
    /// Source file, when the unit named one.
    pub source: Option<String>,
}

/// One declared parameter.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DebugParameter {
    pub name: Option<String>,
    pub ty: DebugType,
}

/// A declared type, reduced to what a decompiler can act on.
///
/// Qualifiers (`const`, `volatile`) and typedefs are resolved through rather
/// than represented: they do not change storage, and the pipeline's own type
/// model has nowhere to put them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DebugType {
    Bool,
    Int {
        bits: u32,
        signed: bool,
    },
    Float {
        bits: u32,
    },
    Pointer {
        bits: u32,
        to: Box<DebugType>,
    },
    /// A named aggregate and its size in bytes, when the format recorded one.
    Aggregate {
        name: Option<String>,
        bytes: u32,
    },
    Array {
        element: Box<DebugType>,
        count: Option<u64>,
    },
    /// A type whose shape was understood but not its contents, carrying
    /// whatever width was declared.
    Opaque {
        bytes: Option<u32>,
    },
    /// `void`, reachable as a pointer's target or a typedef of nothing.
    Void,
}

impl DebugType {
    /// The storage width in bytes, when the declaration fixed one.
    pub fn byte_size(&self) -> Option<u32> {
        match self {
            Self::Bool => Some(1),
            Self::Int { bits, .. } | Self::Float { bits } => Some(bits.div_ceil(8)),
            Self::Pointer { bits, .. } => Some(bits.div_ceil(8)),
            Self::Aggregate { bytes, .. } => Some(*bytes),
            Self::Array { element, count } => {
                let stride = element.byte_size()?;
                let count = u32::try_from((*count)?).ok()?;
                stride.checked_mul(count)
            }
            Self::Opaque { bytes } => *bytes,
            Self::Void => None,
        }
    }

    /// Whether this type addresses memory, which is the fact a return type most
    /// needs to carry.
    pub fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer { .. })
    }
}
