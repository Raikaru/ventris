//! lre-core: the CoreService facade.
//!
//! The core owns durable state (lre-db) and orchestrates the bridge. Every
//! imported fact is exported into the project database with provenance, so
//! reopening and browsing never needs the JVM (spec 14.4, Phase 3 exit).

pub mod bridge;
pub mod disasm;
pub mod native;
pub mod native_runtime;
pub mod session;

use lre_db::ProjectDb;
use lre_model::{CommentRow, DataTypeRow, DisasmRow, FunctionRow, ProgramId, ProgramSummary, SymbolRow, XrefRow};
use std::path::{Path, PathBuf};

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
    /// Revision events after `since` for the program (CORE-005).
    pub fn events_since(&self, program: &str, since: u64) -> Result<Vec<lre_model::RevisionEvent>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.events_since(id, since)?)
    }

    /// Paged functions (review CORE-004): bounded window + total + revision.
    pub fn functions_page(
        &self,
        program: &str,
        offset: u64,
        limit: u64,
    ) -> Result<lre_model::Page<FunctionRow>> {
        let id = self.db.program_id(program)?;
        let (rows, total, revision) = self.db.functions_page(id, offset, limit)?;
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
