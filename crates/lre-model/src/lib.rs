//! Core data model.
//!
//! Addresses are address-space identity plus offset (spec 8.3): a plain `u64`
//! cannot name overlays, registers, or split spaces, and Ghidra's own model
//! does not pretend they can. Entities use compact stable IDs (spec 8.2).

/// Stable ID for a program inside a project.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct ProgramId(pub u64);

/// Stable ID for a function inside a program.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct FunctionId(pub u32);

/// Stable ID for a symbol inside a program.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct SymbolId(pub u32);

/// Which address space an offset lives in. Stage 1 only ever materializes
/// `ram`, but the enum exists so callers cannot silently assume flat memory.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
pub enum AddressSpace {
    /// Main loaded memory.
    #[default]
    Ram,
    /// External (linked library) space.
    External,
    /// Other spaces Ghidra knows: registers, uniques, constants, overlays.
    Other(String),
}

impl AddressSpace {
    /// Parses the space portion of a Ghidra address string (`"00400466"` or
    /// `"ram:00400466"`). Ghidra prints bare hex offsets for the default space.
    pub fn from_ghidra_str(s: &str) -> Self {
        match s.split_once(':') {
            Some((space, _)) if space.eq_ignore_ascii_case("ram") => Self::Ram,
            Some((space, _)) if space.eq_ignore_ascii_case("ext") => Self::External,
            Some((space, _)) => Self::Other(space.to_string()),
            None => Self::Ram,
        }
    }
}

/// A resolved address: space identity plus offset.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct Address {
    /// Address space the offset is relative to.
    pub space: AddressSpace,
    /// Offset into the space.
    pub offset: u64,
}

impl Address {
    /// Builds a RAM address, the overwhelmingly common case.
    pub fn ram(offset: u64) -> Self {
        Self { space: AddressSpace::Ram, offset }
    }
}

/// One function row as the Core API returns it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FunctionRow {
    /// Entry address as a canonical hex string (`"00400466"`).
    pub entry: String,
    /// Display name, primary symbol.
    pub name: String,
    /// Number of bytes in the function body footprint.
    pub size: u64,
    /// Recovered prototype string, when analysis produced one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Calling convention name, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calling_convention: Option<String>,
}

/// One cross-reference record.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct XrefRow {
    /// Source (incoming) address, canonical hex.
    pub from: String,
    /// Destination address, canonical hex.
    pub to: String,
    /// Ghidra reference type name (`UNCONDITIONAL_CALL`, `DATA`, ...).
    pub kind: String,
}

/// One symbol row.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SymbolRow {
    /// Symbol name.
    pub name: String,
    /// Address it anchors, canonical hex.
    pub address: String,
    /// True for symbols naming external/library functions.
    pub external: bool,
    /// Ghidra source type: USER_DEFINED, ANALYSIS, IMPORTED, DEFAULT, ...
    pub source: String,
}

/// Disassembly line: address plus rendered text.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DisasmRow {
    /// Instruction address, canonical hex.
    pub address: String,
    /// Rendered mnemonic + operands, Ghidra style.
    pub text: String,
}

/// Program summary returned by import/open.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProgramSummary {
    /// Program name in the project.
    pub program: String,
    /// Function count discovered by analysis.
    pub functions: u64,
    /// Ghidra language ID, e.g. `x86:LE:64:default`.
    pub language: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Provenance {
    /// Producing component: always `ghidra-bridge` in Stage 1.
    pub producer: String,
    /// Pinned upstream version.
    pub upstream_version: String,
}

/// A stored comment (from the bridge export).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CommentRow {
    /// Code unit address (hex string as Ghidra reports it).
    pub address: String,
    /// Owning function entry (hex string).
    pub function: String,
    /// Comment kind: "eol" | "pre" | "plate" (bridge reports its kind).
    pub kind: String,
    /// Comment text.
    pub text: String,
}

/// A stored data type (from the bridge export; name + free text definition).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DataTypeRow {
    pub name: String,
    pub definition: String,
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ghidra_address_strings() {
        assert_eq!(AddressSpace::from_ghidra_str("00400466"), AddressSpace::Ram);
        assert_eq!(AddressSpace::from_ghidra_str("ram:1000"), AddressSpace::Ram);
        assert_eq!(AddressSpace::from_ghidra_str("ext:1000"), AddressSpace::External);
        assert!(matches!(
            AddressSpace::from_ghidra_str("ov1:1000"),
            AddressSpace::Other(s) if s == "ov1"
        ));
    }

    #[test]
    fn ram_address_defaults() {
        let a = Address::ram(0x404000);
        assert_eq!(a.space, AddressSpace::Ram);
        assert_eq!(a.offset, 0x404000);
    }
}
