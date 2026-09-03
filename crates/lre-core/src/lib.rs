//! lre-core: the CoreService facade.
//!
//! The core owns durable state (lre-db) and orchestrates the bridge. Every
//! imported fact is exported into the project database with provenance, so
//! reopening and browsing never needs the JVM (spec 14.4, Phase 3 exit).

pub mod bridge;
pub mod architecture;
pub mod disasm;
pub mod listing;
pub mod native;
pub mod native_runtime;
pub mod session;

use lre_db::ProjectDb;
use lre_model::{
    Address, AddressSpace, ArchitectureSpec, BookmarkRow, CollaborationOp, CommentRow, DataTypeRow,
    DecompDoc, DisasmRow, FunctionRow, GraphEdge, GraphNode, MemoryRegion, PatchRow, ProgramId,
    ProgramSummary, PrototypeRow, SearchHit, StackVariableRow, StringRow, SymbolRow, TraceEvent,
    TypeDefRow, TypeFieldRow, TypeGraphNode, TypeLinkRow, XrefRow,
};
use std::path::{Path, PathBuf};

#[derive(Debug, serde::Deserialize)]
struct CollaborationRename {
    address: Address,
    name: String,
}

#[derive(Debug, serde::Deserialize)]
struct CollaborationComment {
    address: Address,
    #[serde(default)]
    function: Option<Address>,
    kind: String,
    text: String,
}

fn decode_collaboration<T: serde::de::DeserializeOwned>(
    op_id: &str,
    payload: &str,
) -> Result<T> {
    serde_json::from_str(payload).map_err(|error| {
        CoreError::Collaboration(format!("operation {op_id} has invalid payload: {error}"))
    })
}

/// Core facade failure: wraps the layer that actually failed.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Database layer failure.
    #[error("db: {0}")]
    Db(#[from] lre_db::DbError),
    /// Bridge layer failure.
    #[error("bridge: {0}")]
    Bridge(#[from] bridge::BridgeError),
    /// Filesystem or environment problem outside db/bridge.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Native runtime (console, worker) or setup failure.
    #[error("native runtime: {0}")]
    NativeRuntime(#[from] native_runtime::NativeRuntimeError),
    /// Native import/parse failure.
    #[error("native: {0}")]
    Native(#[from] native::ImportError),
    /// Collaboration payload or operation application failure.
    #[error("collaboration: {0}")]
    Collaboration(String),
    /// Installed-architecture catalog failure.
    #[error("architecture: {0}")]
    Architecture(#[from] architecture::ArchitectureError),
    /// Function sort key was not one of entry|name|size[:asc|:desc].
    #[error("invalid sort key: {0}")]
    InvalidSortKey(String),
}

/// Convenience alias with the error defaulted per project convention.
pub type Result<T, E = CoreError> = std::result::Result<T, E>;

/// The Core API: one authoritative semantic surface (spec 8.1).
///
/// A GUI would call this in-process; the CLI does exactly that; the bridge is
/// an implementation detail behind `import_program`/`refresh_from_bridge`.
pub struct Core {
    db: ProjectDb,
    db_path: PathBuf,
    /// Last mapped image for a binary path, so repeated `mem_native`
    /// reads don't re-open/re-parse the file per call. One-entry cache:
    /// the CLI's scroll pattern is single-binary; `ProgramSession` (the
    /// sessionful image layer) supersedes it for interactive consumers.
    native_cache: std::cell::RefCell<Option<(PathBuf, std::sync::Arc<session::ProgramImage>)>>,
    /// Immutable runtime configuration (env-derived by default).
    config: session::RuntimeConfig,
}

impl Core {
    /// Opens (or creates) a project at `project_dir` holding `project.sqlite`.
    pub fn open(project_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(project_dir)?;
        let db = ProjectDb::open(&project_dir.join("project.sqlite"))?;
        Ok(Self {
            db,
            db_path: project_dir.to_path_buf(),
            native_cache: std::cell::RefCell::new(None),
            config: session::RuntimeConfig::from_env(),
        })
    }

    /// Opens (or creates) a project with an explicit runtime configuration.
    pub fn open_with_config(project_dir: &Path, config: session::RuntimeConfig) -> Result<Self> {
        std::fs::create_dir_all(project_dir)?;
        let db = ProjectDb::open(&project_dir.join("project.sqlite"))?;
        Ok(Self {
            db,
            db_path: project_dir.to_path_buf(),
            native_cache: std::cell::RefCell::new(None),
            config,
        })
    }

    /// Path of the backing database (diagnostics).
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
    /// Lists language variants available in the configured Ghidra install.
    pub fn architectures(&self) -> Result<Vec<ArchitectureSpec>> {
        Ok(architecture::discover(&self.config.ghidra_install)?)
    }

    /// Imports a binary through the bridge, exports facts into the project
    /// store, and returns the normalized summary.
    pub fn import_program(
        &self,
        bridge: &mut bridge::Bridge,
        session: &str,
        binary: &Path,
    ) -> Result<ProgramSummary> {
        let summary = bridge.import(session, binary)?;
        let id = self.db.upsert_program(
            &summary.program,
            &summary.language,
            &bridge.provenance,
        )?;
        let functions = bridge.functions(session)?;
        let symbols = bridge.symbols(session)?;
        self.db.replace_symbols(id, &symbols)?;
        self.export(bridge, session, id, &functions)?;
        Ok(summary)
    }

    /// Reopens an already-imported program. Reads come from the project store;
    /// the bridge starts only if the caller explicitly asks for a refresh.
    pub fn open_program(&self, program: &str) -> Result<ProgramSummary> {
        let id = self.db.program_id(program)?;
        let functions = self.db.functions(id)?;
        Ok(ProgramSummary {
            program: program.to_string(),
            functions: functions.len() as u64,
            language: self.db.program_language(id)?,
        })
    }

    /// Borrows the project store (native-import persistence path).
    pub fn store_handle(&self) -> Result<&ProjectDb> {
        Ok(&self.db)
    }

    /// Lists functions from the project store (no JVM).
    pub fn functions(&self, program: &str) -> Result<Vec<FunctionRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.functions(id)?)
    }
    /// One listing window (CORE-007): SLEIGH console rows when configured,
    /// bounded + overscan, stable ids. Errors honestly when the console is
    /// not available (needs binutils-devel to build; see RuntimeConfig).
    pub fn listing_window(
        &self,
        binary: &std::path::Path,
        start: &lre_model::Address,
        count: u32,
        overscan_fraction: f32,
    ) -> Result<lre_model::ListingWindow> {
        let source = listing::ConsoleListingSource::new(self.config.clone(), binary);
        let mut window = listing::window(&source, start, count, overscan_fraction)?;
        // Enrich rows with raw instruction bytes: the decoder gives the
        // length, the mapped image gives the bytes. Rows whose bytes cannot
        // be read stay empty rather than failing the window.
        for row in &mut window.rows {
            let bytes = self
                .mem_native(binary, row.address.offset, 16)
                .unwrap_or_default();
            if bytes.is_empty() {
                continue;
            }
            let info = crate::disasm::decode(&bytes, row.address.offset);
            let len = (info.len as usize).clamp(1, bytes.len());
            row.bytes = bytes[..len].iter().map(|b| format!("{b:02x}")).collect();
        }
        Ok(window)
    }

    /// Revision events after `since` for the program (CORE-005).
    pub fn events_since(&self, program: &str, since: u64) -> Result<Vec<lre_model::RevisionEvent>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.events_since(id, since)?)
    }

    /// Reads a bounded execution/analysis timeline window.
    pub fn trace_events(
        &self,
        program: &str,
        since: u64,
        limit: u64,
    ) -> Result<Vec<TraceEvent>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.trace_events(id, since, limit)?)
    }

    /// Appends a timeline event and returns its assigned sequence.
    pub fn append_trace_event(&self, program: &str, row: &TraceEvent) -> Result<TraceEvent> {
        let id = self.db.program_id(program)?;
        Ok(self.db.append_trace_event(id, row)?)
    }

    /// Lists collaboration operations in deterministic merge order.
    pub fn collaboration_ops(&self, program: &str) -> Result<Vec<CollaborationOp>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.collaboration_ops(id)?)
    }

    /// Adds one idempotent collaboration operation.
    pub fn append_collaboration_op(
        &self,
        program: &str,
        row: &CollaborationOp,
    ) -> Result<bool> {
        let id = self.db.program_id(program)?;
        Ok(self.db.append_collaboration_op(id, row)?)
    }

    /// Applies a collaboration operation once. Known fact mutations are
    /// decoded and routed through the same Core command/type APIs; note
    /// operations remain durable log entries without changing facts.
    pub fn apply_collaboration_op(&self, program: &str, op_id: &str) -> Result<bool> {
        let id = self.db.program_id(program)?;
        let operation = self
            .db
            .collaboration_ops(id)?
            .into_iter()
            .find(|operation| operation.op_id == op_id)
            .ok_or_else(|| lre_db::DbError::OperationNotFound(op_id.into()))?;
        if operation.applied {
            return Ok(false);
        }
        match operation.kind.as_str() {
            "rename" => {
                let payload: CollaborationRename =
                    decode_collaboration(op_id, &operation.payload)?;
                self.rename_command(program, &payload.address, &payload.name)?;
            }
            "comment" => {
                let payload: CollaborationComment =
                    decode_collaboration(op_id, &operation.payload)?;
                let function = payload.function.unwrap_or_else(|| payload.address.clone());
                self.comment_command(
                    program,
                    &payload.address,
                    &function,
                    &payload.kind,
                    &payload.text,
                )?;
            }
            "bookmark" => {
                let payload: BookmarkRow = decode_collaboration(op_id, &operation.payload)?;
                self.set_bookmark(program, &payload)?;
            }
            "patch" => {
                let payload: PatchRow = decode_collaboration(op_id, &operation.payload)?;
                self.set_patch(program, &payload)?;
            }
            "set_type_def" => {
                let payload: TypeDefRow = decode_collaboration(op_id, &operation.payload)?;
                self.set_type_def(program, &payload)?;
            }
            "set_type_field" => {
                let payload: TypeFieldRow = decode_collaboration(op_id, &operation.payload)?;
                self.set_type_field(program, &payload)?;
            }
            "set_prototype" => {
                let payload: PrototypeRow = decode_collaboration(op_id, &operation.payload)?;
                self.set_prototype(program, &payload)?;
            }
            "set_stack_variable" => {
                let payload: StackVariableRow = decode_collaboration(op_id, &operation.payload)?;
                self.set_stack_variable(program, &payload)?;
            }
            "set_type_link" => {
                let payload: TypeLinkRow = decode_collaboration(op_id, &operation.payload)?;
                self.set_type_link(program, &payload)?;
            }
            "note" | "trace" => {}
            other => {
                return Err(CoreError::Collaboration(format!(
                    "operation {op_id} has unsupported kind {other:?}"
                )));
            }
        }
        Ok(self.db.apply_collaboration_op(id, op_id)?)
    }

    /// Paged functions (review CORE-004): bounded window + total + revision.
    /// `filter` is a case-insensitive name substring, or a regex when it
    /// carries a `re:` prefix. `sort` is "entry" | "name" | "size" with an
    /// optional ":asc"/":desc" suffix; defaults to entry ascending.
    pub fn functions_page(
        &self,
        program: &str,
        offset: u64,
        limit: u64,
        filter: Option<&str>,
        sort: Option<&str>,
    ) -> Result<lre_model::Page<FunctionRow>> {
        let id = self.db.program_id(program)?;
        let filter = lre_db::FunctionsFilter::parse(filter.unwrap_or(""))?;
        let sort = sort.map(parse_function_sort).transpose()?;
        let (rows, total, revision) =
            self.db
                .functions_page(id, offset, limit, filter.as_ref(), sort)?;
        Ok(lre_model::Page { rows, offset, total, revision })
    }

    /// Paged symbols (review CORE-004).
    pub fn symbols_page(
        &self,
        program: &str,
        offset: u64,
        limit: u64,
    ) -> Result<lre_model::Page<SymbolRow>> {
        let id = self.db.program_id(program)?;
        let (rows, total, revision) = self.db.symbols_page(id, offset, limit)?;
        Ok(lre_model::Page { rows, offset, total, revision })
    }

    /// Paged xrefs in one direction (review CORE-004).
    pub fn xrefs_page(
        &self,
        program: &str,
        address: &lre_model::Address,
        incoming: bool,
        offset: u64,
        limit: u64,
    ) -> Result<lre_model::Page<XrefRow>> {
        let id = self.db.program_id(program)?;
        let (rows, total, revision) = self.db.xrefs_page(id, address, incoming, offset, limit)?;
        Ok(lre_model::Page { rows, offset, total, revision })
    }

    /// Lists comments from the project store (no JVM).
    pub fn comments(&self, program: &str) -> Result<Vec<CommentRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.comments(id)?)
    }

    /// Lists datatypes from the project store (no JVM).
    pub fn datatypes(&self, program: &str) -> Result<Vec<DataTypeRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.datatypes(id)?)
    }

    /// Lists symbols from the project store (no JVM).
    pub fn symbols(&self, program: &str) -> Result<Vec<SymbolRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.symbols(id)?)
    }

    /// Lists discovered strings from the durable project store.
    /// Paged strings (Phase 2.3).
    pub fn strings_page(
        &self,
        program: &str,
        offset: u64,
        limit: u64,
    ) -> Result<lre_model::Page<StringRow>> {
        let id = self.db.program_id(program)?;
        let (rows, total, revision) = self.db.strings_page(id, offset, limit)?;
        Ok(lre_model::Page { rows, offset, total, revision })
    }

    pub fn strings(&self, program: &str) -> Result<Vec<StringRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.strings(id)?)
    }

    /// Searches durable analysis facts without loading the native image.
    pub fn search(&self, program: &str, term: &str, limit: u64) -> Result<Vec<SearchHit>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.search(id, term, limit)?)
    }

    /// Returns function vertices and reference edges for graph rendering.
    pub fn function_graph(&self, program: &str) -> Result<(Vec<GraphNode>, Vec<GraphEdge>)> {
        let id = self.db.program_id(program)?;
        Ok(self.db.function_graph(id)?)
    }

    /// Lists persisted memory mappings (no JVM, no worker).
    pub fn memory_regions(&self, program: &str) -> Result<Vec<MemoryRegion>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.memory_regions(id)?)
    }

    /// Lists analyst bookmarks.
    pub fn bookmarks(&self, program: &str) -> Result<Vec<BookmarkRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.bookmarks(id)?)
    }

    /// Sets one analyst bookmark.
    pub fn set_bookmark(&self, program: &str, row: &BookmarkRow) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.set_bookmark(id, row)?;
        Ok(())
    }

    /// Removes one analyst bookmark.
    pub fn delete_bookmark(&self, program: &str, address: &Address) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.delete_bookmark(id, address)?;
        Ok(())
    }

    /// Lists analyst byte patches.
    pub fn patches(&self, program: &str) -> Result<Vec<PatchRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.patches(id)?)
    }

    /// Stores one analyst byte patch.
    pub fn set_patch(&self, program: &str, row: &PatchRow) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.set_patch(id, row)?;
        Ok(())
    }

    /// Removes one analyst byte patch.
    pub fn delete_patch(&self, program: &str, address: &Address) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.delete_patch(id, address)?;
        Ok(())
    }
    /// Lists rich named types and their composite metadata.
    pub fn type_defs(&self, program: &str) -> Result<Vec<TypeDefRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.type_defs(id)?)
    }
    /// Replaces the project's rich type definitions.
    pub fn replace_type_defs(&self, program: &str, rows: &[TypeDefRow]) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.replace_type_defs(id, rows)?;
        Ok(())
    }
    /// Upserts one type definition.
    pub fn set_type_def(&self, program: &str, row: &TypeDefRow) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.set_type_def(id, row)?;
        Ok(())
    }


    /// Replaces the project's composite type fields.
    pub fn replace_type_fields(&self, program: &str, rows: &[TypeFieldRow]) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.replace_type_fields(id, rows)?;
        Ok(())
    }
    /// Upserts one composite field.
    pub fn set_type_field(&self, program: &str, row: &TypeFieldRow) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.set_type_field(id, row)?;
        Ok(())
    }


    /// Lists fields, optionally restricted to one type.
    pub fn type_fields(
        &self,
        program: &str,
        type_name: Option<&str>,
    ) -> Result<Vec<TypeFieldRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.type_fields(id, type_name)?)
    }

    /// Lists function prototypes.
    pub fn prototypes(&self, program: &str) -> Result<Vec<PrototypeRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.prototypes(id)?)
    }
    /// Replaces function prototypes.
    pub fn replace_prototypes(&self, program: &str, rows: &[PrototypeRow]) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.replace_prototypes(id, rows)?;
        Ok(())
    }
    /// Upserts one function prototype.
    pub fn set_prototype(&self, program: &str, row: &PrototypeRow) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.set_prototype(id, row)?;
        Ok(())
    }


    /// Replaces recovered stack variables.
    pub fn replace_stack_variables(
        &self,
        program: &str,
        rows: &[StackVariableRow],
    ) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.replace_stack_variables(id, rows)?;
        Ok(())
    }
    /// Upserts one stack variable.
    pub fn set_stack_variable(&self, program: &str, row: &StackVariableRow) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.set_stack_variable(id, row)?;
        Ok(())
    }


    /// Replaces type dependency links.
    pub fn replace_type_links(&self, program: &str, rows: &[TypeLinkRow]) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.replace_type_links(id, rows)?;
        Ok(())
    }
    /// Upserts one type dependency link.
    pub fn set_type_link(&self, program: &str, row: &TypeLinkRow) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.set_type_link(id, row)?;
        Ok(())
    }


    /// Lists recovered stack variables, optionally for one function.
    pub fn stack_variables(
        &self,
        program: &str,
        function: Option<&Address>,
    ) -> Result<Vec<StackVariableRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.stack_variables(id, function)?)
    }

    /// Lists type nodes and provenance-bearing dependency edges.
    pub fn type_graph(
        &self,
        program: &str,
    ) -> Result<(Vec<TypeGraphNode>, Vec<TypeLinkRow>)> {
        let id = self.db.program_id(program)?;
        Ok(self.db.type_graph(id)?)
    }

    /// Returns the durable type-link set after transitive propagation.
    ///
    /// Propagated edges are explicitly marked, so consumers can distinguish
    /// provider evidence from an inferred relationship.
    pub fn propagate_type_links(&self, program: &str) -> Result<Vec<TypeLinkRow>> {
        let id = self.db.program_id(program)?;
        let mut links = self.db.type_links(id)?;
        let mut changed = true;
        while changed {
            changed = false;
            let snapshot = links.clone();
            for left in &snapshot {
                for right in &snapshot {
                    if left.target != right.source || left.source == right.target {
                        continue;
                    }
                    let candidate = TypeLinkRow {
                        source: left.source.clone(),
                        target: right.target.clone(),
                        kind: "transitive".into(),
                        provenance: "type-propagation".into(),
                    };
                    if !links.contains(&candidate) {
                        links.push(candidate);
                        changed = true;
                    }
                }
            }
        }
        if links.len() != self.db.type_links(id)?.len() {
            self.db.replace_type_links(id, &links)?;
        }
        Ok(links)
    }


    /// Incoming xrefs from the project store (no JVM).
    pub fn xrefs_to(&self, program: &str, address: &lre_model::Address) -> Result<Vec<XrefRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.xrefs_to(id, address)?)
    }

    /// Outgoing xrefs from the project store (no JVM).
    pub fn xrefs_from(&self, program: &str, address: &lre_model::Address) -> Result<Vec<XrefRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.xrefs_from(id, address)?)
    }

    /// Applies an analyst rename in the project store and bumps the revision.
    /// (Direct mutation — no journal entry.)
    pub fn rename_function(&self, program: &str, entry: &lre_model::Address, name: &str) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.rename_function(id, entry, name)?;
        Ok(())
    }

    /// UNDOABLE command: rename with journal entry + captured undo state
    /// (CORE-006). The UI and automation go through this, not raw renames.
    pub fn rename_command(&self, program: &str, entry: &lre_model::Address, name: &str) -> Result<()> {
        let id = self.db.program_id(program)?;
        let old_name = self
            .db
            .functions(id)?
            .into_iter()
            .find(|f| f.entry == *entry)
            .map(|f| f.name)
            .ok_or_else(|| {
                CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no function at {entry}"),
                ))
            })?;
        self.db.rename_command(id, entry, name, &old_name)?;
        Ok(())
    }

    /// UNDOABLE analyst comment command. Comment rows, revision events, and
    /// the prior value all enter the same durable transaction.
    pub fn comment_command(
        &self,
        program: &str,
        address: &Address,
        function: &Address,
        kind: &str,
        text: &str,
    ) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db
            .comment_command(id, address, function, kind, text)?;
        Ok(())
    }

    /// Undoes the latest undone command, returning what it did (CORE-006).
    pub fn undo_last(&self, program: &str) -> Result<String> {
        let id = self.db.program_id(program)?;
        let entry = self
            .db
            .journal_latest(id)?
            .ok_or_else(|| {
                CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "nothing to undo",
                ))
            })?;
        match entry.kind.as_str() {
            "rename" => {
                let undo: serde_json::Value =
                    serde_json::from_str(&entry.undo_payload).map_err(|e| {
                        CoreError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("bad undo payload: {e}"),
                        ))
                    })?;
                let entry_addr = lre_model::Address::parse_ram_hex(
                    undo.get("entry").and_then(|v| v.as_str()).unwrap_or_default(),
                )
                .ok_or_else(|| {
                    CoreError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "undo payload has no entry",
                    ))
                })?;
                let old_name = undo
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                self.db.undo_rename(id, &entry_addr, &old_name, entry.seq)?;
                Ok(format!(
                    "undid rename seq {} ({} -> {old_name})",
                    entry.seq, entry_addr
                ))
            }
            "comment" => {
                let undo: serde_json::Value =
                    serde_json::from_str(&entry.undo_payload).map_err(|e| {
                        CoreError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("bad comment undo payload: {e}"),
                        ))
                    })?;
                let address = lre_model::Address::parse_ram_hex(
                    undo.get("address").and_then(|value| value.as_str()).unwrap_or_default(),
                )
                .ok_or_else(|| {
                    CoreError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "comment undo payload has no address",
                    ))
                })?;
                let kind = undo
                    .get("kind")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| {
                        CoreError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "comment undo payload has no kind",
                        ))
                    })?;
                let previous = if undo
                    .get("exists")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false)
                {
                    let function = lre_model::Address::parse_ram_hex(
                        undo.get("function")
                            .and_then(|value| value.as_str())
                            .unwrap_or_default(),
                    )
                    .ok_or_else(|| {
                        CoreError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "comment undo payload has no prior function",
                        ))
                    })?;
                    let text = undo
                        .get("text")
                        .and_then(|value| value.as_str())
                        .unwrap_or_default()
                        .to_string();
                    Some((function, text))
                } else {
                    None
                };
                let prior = previous
                    .as_ref()
                    .map(|(function, text)| (function, text.as_str()));
                self.db.undo_comment(id, &address, kind, prior, entry.seq)?;
                Ok(format!("undid comment seq {} at {}", entry.seq, address))
            }
            other => Err(CoreError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("unsupported command kind: {other}"),
            ))),
        }
    }

    /// Imports `binary` natively (no JVM): format parse, flow discovery
    /// (in-Rust walk + SLEIGH console closure when the binary looks
    /// stripped), and store writes with native provenance.
    pub fn import_native(&self, binary: &Path, name: &str) -> Result<ProgramSummary> {
        let mut imp = native::load_native(binary)?;
        // SLEIGH-first (review CORE-008): when the pinned console is
        // available its disassembly is the primary flow source; the in-Rust
        // two-path walk (already run by load_native) is the fallback /
        // cross-check. Both sets are unioned so nothing available is lost.
        let console_available = self
            .config
            .console_path
            .as_ref()
            .map(|p| p.is_file())
            .unwrap_or(false);
        if console_available {
            let seeds = native_runtime::console_seeds(&imp);
            match native_runtime::console_discover(&self.config, binary, &seeds) {
                Ok((funcs, calls)) => {
                    for (entry, size) in funcs {
                        if !imp.functions.iter().any(|f| f.entry == entry) {
                            let fname = native::extern_name(&imp, entry)
                                .unwrap_or_else(|| format!("FUN_{entry:08x}"));
                            imp.functions.push(native::NativeFunction {
                                entry,
                                name: fname,
                                size: size.max(1),
                            });
                        }
                    }
                    for (from, to) in calls {
                        if !imp.xrefs.iter().any(|x| x.from == from && x.to == to) {
                            imp.xrefs.push(native::NativeXref {
                                from,
                                to,
                                kind: "UNCONDITIONAL_CALL".into(),
                            });
                        }
                    }
                }
                Err(e) => eprintln!("console discovery skipped: {e}"),
            }
        }
        Ok(native::store_import(&self.db, name, &imp)?)
    }

    /// Native disassembly of `count` instructions at `address`.
    pub fn disasm_native(&self, binary: &Path, address: &str, count: u32) -> Result<String> {
        Ok(native_runtime::disasm_native(&self.config, binary, address, count)?)
    }

    /// Native decompilation of one function at `address` (program must be in
    /// `project_dir`'s store; `base` defaults to the PE image base or
    /// 0x400000).
    pub fn decompile_native(
        &self,
        binary: &Path,
        address: &str,
        program: &str,
        base: Option<u64>,
    ) -> Result<String> {
        Ok(native_runtime::decompile_native(
            &self.config,
            binary,
            address,
            program,
            &self.db_path,
            base,
        )?)
    }

    /// Native structured decompilation for a typed RAM address. The document
    /// is stamped with the durable store revision observed after the worker
    /// returns, so a view can reject stale metadata.
    pub fn decompile_native_doc(
        &self,
        binary: &Path,
        address: &Address,
        program: &str,
        base: Option<u64>,
    ) -> Result<DecompDoc> {
        if !matches!(&address.space, AddressSpace::Ram) {
            return Err(CoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("native decompiler only accepts RAM addresses: {address}"),
            )));
        }
        let address_hex = format!("{:x}", address.offset);
        let mut doc = native_runtime::decompile_native_doc(
            &self.config,
            binary,
            &address_hex,
            program,
            &self.db_path,
            base,
        )?;
        doc.address = address.clone();
        let id = self.db.program_id(program)?;
        doc.revision = self.db.revision(id)?;
        Ok(doc)
    }

    /// Bytes at `vaddr` from the binary's mappings (native memory inspection).
    ///
    /// Uses a one-entry cache of the parsed import so viewport-sized reads
    /// don't re-read and re-discover the whole binary per call.
    pub fn mem_native(&self, binary: &Path, vaddr: u64, size: usize) -> Result<Vec<u8>> {
        let binary = binary.to_path_buf();
        let image = {
            let mut cache = self.native_cache.borrow_mut();
            let hit = cache.as_ref().map(|(p, _)| p == &binary).unwrap_or(false);
            if !hit {
                let opened = std::sync::Arc::new(session::ProgramImage::open(&binary)?);
                *cache = Some((binary.clone(), opened.clone()));
                opened
            } else {
                cache.as_ref().unwrap().1.clone()
            }
        };
        image
            .read(vaddr, size as u64)
            .ok_or_else(|| {
                CoreError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("no mapping covers {vaddr:#x}..+{size:#x}"),
                ))
            })
    }

    /// Opens a program session: the binary mapped once, regions derived,
    /// metadata captured. Every interactive view and worker shares the
    /// image; repeated reads never re-parse or re-discover the file.
    pub fn open_session(&self, binary: &Path, program: &str) -> Result<session::ProgramSession> {
        let imp = native::load_native(binary)?;
        let image = std::sync::Arc::new(session::ProgramImage::open(binary)?);
        let metadata = session::SessionMetadata::from_import(&imp);
        Ok(session::ProgramSession {
            program: program.to_string(),
            image,
            metadata,
        })
    }

    /// Re-exports fresh facts from the bridge after an edit session.
    pub fn refresh_from_bridge(
        &self,
        bridge: &mut bridge::Bridge,
        session: &str,
        program: &str,
    ) -> Result<ProgramSummary> {
        let id = self.db.program_id(program)?;
        let functions = bridge.functions(session)?;
        let symbols = bridge.symbols(session)?;
        self.db.replace_symbols(id, &symbols)?;
        self.export(bridge, session, id, &functions)?;
        Ok(ProgramSummary {
            program: program.to_string(),
            functions: functions.len() as u64,
            language: self.db.program_language(id)?,
        })
    }

    /// Reads bytes through the bridge (memory lives in the JVM for Stage 1).
    pub fn read_memory(
        &self,
        bridge: &mut bridge::Bridge,
        session: &str,
        address: &str,
        size: u32,
    ) -> Result<Vec<u8>> {
        Ok(bridge.read_memory(session, address, size)?)
    }

    /// Decompiles through the bridge (native worker replaces this in Stage 3).
    pub fn decompile(
        &self,
        bridge: &mut bridge::Bridge,
        session: &str,
        address: &str,
    ) -> Result<String> {
        Ok(bridge.decompile(session, address)?)
    }

    /// Disassembles through the bridge (native SLEIGH replaces this in Stage 3).
    pub fn disassemble(
        &self,
        bridge: &mut bridge::Bridge,
        session: &str,
        address: &str,
        n: u32,
    ) -> Result<Vec<DisasmRow>> {
        Ok(bridge.disassemble(session, address, n)?)
    }

    fn export(
        &self,
        bridge: &mut bridge::Bridge,
        session: &str,
        id: ProgramId,
        functions: &[FunctionRow],
    ) -> Result<()> {
        self.db.replace_functions(id, functions)?;
        // One batched round-trip instead of one RPC per function: the per-call
        // overhead after analysis dominated the import time otherwise.
        let (functions, xrefs, comments, datatypes) = bridge.export_facts(session)?;
        self.db.replace_functions(id, &functions)?;
        self.db.replace_xrefs(id, &xrefs)?;
        self.db.replace_comments(id, &comments)?;
        self.db.replace_datatypes(id, &datatypes)?;
        Ok(())
    }
}

/// Parses a function sort spec: "entry" | "name" | "size" with an optional
/// ":asc"/":desc" suffix.
fn parse_function_sort(text: &str) -> Result<(lre_db::FunctionSort, bool)> {
    let (key, direction) = match text.split_once(':') {
        Some((key, dir)) => (
            key,
            match dir {
                "asc" => true,
                "desc" => false,
                _ => return Err(CoreError::InvalidSortKey(text.into())),
            },
        ),
        None => (text, true),
    };
    let key = lre_db::FunctionSort::parse(key)
        .ok_or_else(|| CoreError::InvalidSortKey(text.into()))?;
    Ok((key, direction))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn collaboration_rename_applies_once_through_core() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let core = Core::open(&std::env::temp_dir().join(format!("ventris-core-collab-{nonce}")))
            .unwrap();
        let id = core
            .store_handle()
            .unwrap()
            .upsert_program(
                "p",
                "x86:LE:64:default",
                &lre_model::Provenance {
                    producer: "test".into(),
                    upstream_version: "test".into(),
                },
            )
            .unwrap();
        core.store_handle()
            .unwrap()
            .replace_functions(
                id,
                &[FunctionRow {
                    entry: Address::ram(0x400000),
                    name: "FUN_00400000".into(),
                    size: 4,
                    signature: None,
                    calling_convention: None,
                }],
            )
            .unwrap();
        let operation = CollaborationOp {
            op_id: "rename-1".into(),
            actor: "tester".into(),
            lamport: 1,
            kind: "rename".into(),
            payload: serde_json::json!({
                "address": "00400000",
                "name": "main"
            })
            .to_string(),
            applied: false,
            provenance: "test".into(),
        };
        assert!(core.append_collaboration_op("p", &operation).unwrap());
        assert!(core.apply_collaboration_op("p", "rename-1").unwrap());
        assert_eq!(core.functions("p").unwrap()[0].name, "main");
        assert!(!core.apply_collaboration_op("p", "rename-1").unwrap());
    }
}
