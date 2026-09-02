//! lre-core: the CoreService facade.
//!
//! The core owns durable state (lre-db) and orchestrates the bridge. Every
//! imported fact is exported into the project database with provenance, so
//! reopening and browsing never needs the JVM (spec 14.4, Phase 3 exit).

pub mod bridge;
pub mod disasm;
pub mod native;

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
}

impl Core {
    /// Opens (or creates) a project at `project_dir` holding `project.sqlite`.
    pub fn open(project_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(project_dir)?;
        let db = ProjectDb::open(&project_dir.join("project.sqlite"))?;
        Ok(Self { db, db_path: project_dir.to_path_buf() })
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
    pub fn xrefs_to(&self, program: &str, address: &str) -> Result<Vec<XrefRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.xrefs_to(id, address)?)
    }

    /// Outgoing xrefs from the project store (no JVM).
    pub fn xrefs_from(&self, program: &str, address: &str) -> Result<Vec<XrefRow>> {
        let id = self.db.program_id(program)?;
        Ok(self.db.xrefs_from(id, address)?)
    }

    /// Applies an analyst rename in the project store and bumps the revision.
    pub fn rename_function(&self, program: &str, entry: &str, name: &str) -> Result<()> {
        let id = self.db.program_id(program)?;
        self.db.rename_function(id, entry, name)?;
        Ok(())
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
