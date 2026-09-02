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
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default, serde::Serialize, serde::Deserialize)]
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
#[derive(Clone, PartialEq, Eq, Hash, Debug, Default, serde::Serialize)]
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

    /// Parses a canonical hex string (`"00400466"`, `"0x400466"`) as a RAM
    /// address, the storage convention of every row in the project store.
    pub fn parse_ram_hex(s: &str) -> Option<Self> {
        let hex = s.trim().trim_start_matches("0x");
        if hex.is_empty() {
            return None;
        }
        u64::from_str_radix(hex, 16).ok().map(Self::ram)
    }

    /// The canonical hex form the store writes (`"00400466"`).
    pub fn hex(&self) -> String {
        format!("{:08x}", self.offset)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

// The wire/storage serialization edge: Ghidra-style hex strings
// ("00400466", "ram:00400466") and the structured form both deserialize.
// Serde's derive accepts only the structured form; the JSON-RPC bridge and
// older consumers talk in strings, so this visitor keeps them compatible.
impl<'de> serde::Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct AddrVisitor;
        impl<'de> serde::de::Visitor<'de> for AddrVisitor {
            type Value = Address;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a hex address string or {space, offset} object")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Address, E> {
                // LAST colon: Ghidra overlay/space names can contain
                // colons (".annobin.notes::00000000").
                let (space, offset_part) = match v.rsplit_once(':') {
                    Some((sp, off)) => (AddressSpace::from_ghidra_str(sp), off),
                    None => (AddressSpace::Ram, v),
                };
                let hex = offset_part.trim_start_matches("0x");
                let offset = u64::from_str_radix(hex, 16)
                    .map_err(|_| E::custom(format!("bad hex address: {v}")))?;
                Ok(Address { space, offset })
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Address, A::Error> {
                let mut space = AddressSpace::Ram;
                let mut offset = 0u64;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "space" => space = map.next_value::<AddressSpace>()?,
                        "offset" => offset = map.next_value::<u64>()?,
                        _ => {
                            map.next_value::<serde_json::Value>()?;
                        }
                    }
                }
                Ok(Address { space, offset })
            }
        }
        deserializer.deserialize_any(AddrVisitor)
    }
}

/// One function row as the Core API returns it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FunctionRow {
    /// Entry address (typed; formatted only at serialization edges).
    pub entry: Address,
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
    /// Source (incoming) address (typed).
    pub from: Address,
    /// Destination address (typed).
    pub to: Address,
    /// Ghidra reference type name (`UNCONDITIONAL_CALL`, `DATA`, ...).
    pub kind: String,
}

/// One symbol row.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SymbolRow {
    /// Symbol name.
    pub name: String,
    /// Address it anchors (typed).
    pub address: Address,
    /// True for symbols naming external/library functions.
    pub external: bool,
    /// Ghidra source type: USER_DEFINED, ANALYSIS, IMPORTED, DEFAULT, ...
    pub source: String,
}

/// Disassembly line: address plus rendered text.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DisasmRow {
    /// Instruction address (typed).
    pub address: Address,
    /// Rendered mnemonic + operands, Ghidra style.
    pub text: String,
}

/// Decompiler token kinds (from the packed document's element ids — pinned
/// from ElementId.java; WORKER-004).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TokenKind {
    Value,
    Variable,
    Op,
    Syntax,
    FuncName,
    Type,
    Comment,
    Label,
    Field,
    Bitfield,
    Break,
    Other,
}

/// The p-code object reference carried by a specialized Clang token.
///
/// `id` is the decompiler's per-response PcodeFactory index. It is not a
/// durable database id or an address; consumers must treat it as scoped to
/// this decompiler document.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DecompReference {
    pub kind: DecompReferenceKind,
    pub id: u64,
}

/// Which p-code object a decompiler token references.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DecompReferenceKind {
    Varnode,
    Operation,
}

/// One structured decompiler token: text + kind + any entity mapping the
/// packed document carried (WORKER-004).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DecompToken {
    pub text: String,
    pub kind: TokenKind,
    /// Ghidra syntax color class (0..7; ATTRIB_COLOR).
    pub color: u8,
    /// Entity name when the token carried ATTRIB_NAME.
    pub symbol: Option<String>,
    /// Entity address when the token carried space+off attributes.
    pub address: Option<Address>,
    /// Per-response p-code reference from ATTRIB_VARREF/ATTRIB_OPREF.
    pub reference: Option<DecompReference>,
    /// Data-type id carried by ClangTypeToken/ClangFieldToken.
    pub datatype_id: Option<u64>,
    /// Number of characters of indentation carried by ClangBreak.
    pub indent: Option<i64>,
}

/// The structured decompiler document for one function (WORKER-004): a
/// token stream the UI renders without re-parsing C text.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DecompDoc {
    pub tokens: Vec<DecompToken>,
    pub address: Address,
    pub revision: u64,
}

/// One listing row (CORE-007): stable id (= instruction address),
/// typed address, and the rendered text a virtualized view shows.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ListingRow {
    /// Stable row identity: the instruction address offset.
    pub stable_id: u64,
    pub address: Address,
    /// Rendered mnemonic + operands.
    pub text: String,
    /// Raw instruction bytes as hex; empty when the source cannot read
    /// the image.
    pub bytes: String,
}

/// One listing window (CORE-007): bounded rows + overscan for a
/// virtualized view.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ListingWindow {
    pub rows: Vec<ListingRow>,
    pub start: Address,
    pub count: u32,
    /// Rows fetched beyond the window (above+below the visible set).
    pub overscan: u64,
}

/// One recorded command (CORE-006): the undoable mutation journal entry.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct JournalEntry {
    /// Monotonic sequence within the program.
    pub seq: u64,
    /// Command kind: "rename" (the CORE-006 first command).
    pub kind: String,
    /// Command payload (JSON; kind-specific).
    pub payload: String,
    /// Undo payload (JSON; applied by the undo dispatcher).
    pub undo_payload: String,
    /// 1 once undone.
    pub done: bool,
}

/// One durable change record: the mutation stream consumers watch
/// (review CORE-005: every change carries a revision, and revisions are
/// observable).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RevisionEvent {
    /// Revision the program reached with this change.
    pub revision: u64,
    /// Machine kind: "rename", "replace-functions", ... 
    pub kind: String,
    /// Human/detail payload (new name, replaced row count, ...).
    pub detail: String,
}

/// A paged query result: a bounded window plus cursor info and the
/// revision the window was read at (review CORE-004: views never preload).
#[derive(Clone, Debug, serde::Serialize)]
pub struct Page<T> {
    /// The window of rows (at most `limit`).
    pub rows: Vec<T>,
    /// Offset of the first row in the full result.
    pub offset: u64,
    /// Total row count when known cheaply (COUNT), else `None`.
    pub total: Option<u64>,
    /// Store revision the window was read at (CORE-005 precursor).
    pub revision: u64,
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
    /// Code unit address (typed).
    pub address: Address,
    /// Owning function entry (typed).
    pub function: Address,
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

/// A string discovered in loaded memory or a string table.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct StringRow {
    pub address: Address,
    pub value: String,
    pub kind: String,
}

/// One mapped binary region used by the memory map and hex view.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct MemoryRegion {
    pub name: String,
    pub start: Address,
    pub size: u64,
    pub permissions: String,
    pub source: String,
}

/// A full-text search result across durable analysis facts.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SearchHit {
    pub address: Option<Address>,
    pub kind: String,
    pub name: String,
    pub context: String,
}

/// A function graph vertex.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct GraphNode {
    pub address: Address,
    pub name: String,
}

/// A function graph edge.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct GraphEdge {
    pub from: Address,
    pub to: Address,
    pub kind: String,
}

/// User bookmark attached to an address.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BookmarkRow {
    pub address: Address,
    pub label: String,
    pub comment: String,
}

/// One byte patch with both source and active values retained.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PatchRow {
    pub address: Address,
    pub original: Vec<u8>,
    pub patched: Vec<u8>,
    pub enabled: bool,
}



/// A named data type with its composite metadata.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TypeDefRow {
    pub name: String,
    pub kind: String,
    pub definition: String,
    pub size: Option<u64>,
    pub alignment: Option<u64>,
    pub base_type: Option<String>,
    pub provenance: String,
}

/// One field in a composite type.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TypeFieldRow {
    pub type_name: String,
    pub ordinal: u32,
    pub field_name: String,
    pub offset: u64,
    pub size: Option<u64>,
    pub type_ref: Option<String>,
}

/// Function prototype and calling convention.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PrototypeRow {
    pub function: Address,
    pub signature: String,
    pub calling_convention: Option<String>,
    pub return_type: Option<String>,
}

/// One recovered stack variable.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct StackVariableRow {
    pub function: Address,
    pub ordinal: u32,
    pub name: String,
    pub storage: String,
    pub type_name: Option<String>,
    pub offset: Option<i64>,
    pub size: Option<u64>,
}

/// A typed dependency edge retained with provenance.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TypeLinkRow {
    pub source: String,
    pub target: String,
    pub kind: String,
    pub provenance: String,
}

/// Type graph node used by the type manager.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TypeGraphNode {
    pub name: String,
    pub kind: String,
    pub size: Option<u64>,
}

/// One installed SLEIGH processor/language variant.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ArchitectureSpec {
    pub id: String,
    pub processor: String,
    pub endian: String,
    pub bits: Option<u32>,
    pub language_dir: String,
    pub sla_count: u32,
}

/// One execution/analysis event in a durable timeline.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TraceEvent {
    /// Monotonic sequence within a program.
    pub sequence: u64,
    /// Source timestamp supplied by the recorder.
    pub at: String,
    /// Thread or execution context label.
    pub thread: String,
    /// Optional RAM address associated with the event.
    pub address: Option<Address>,
    /// Event kind, for example `breakpoint` or `instruction`.
    pub kind: String,
    /// Structured payload retained at the serialization edge.
    pub payload: String,
    /// Producer/provenance label.
    pub provenance: String,
}

/// One deterministic, idempotent collaboration operation.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CollaborationOp {
    /// Client-generated idempotency key.
    pub op_id: String,
    /// Stable actor identity used for deterministic ordering.
    pub actor: String,
    /// Lamport clock supplied by the actor.
    pub lamport: u64,
    /// Operation kind, interpreted by the collaboration client.
    pub kind: String,
    /// Operation payload.
    pub payload: String,
    /// Whether this operation has been applied locally.
    pub applied: bool,
    /// Producer/provenance label.
    pub provenance: String,
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
