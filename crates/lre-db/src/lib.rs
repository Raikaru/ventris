//! SQLite persistence for durable facts (spec 13.1, 14.4).
//!
//! The database stores project-owned records: the program identity, functions,
//! symbols, xrefs, and the provenance of whoever produced them. Every mutation
//! runs in a transaction and bumps the program revision; bridge exports carry
//! producer + upstream version so reopening never depends on the bridge.

use lre_model::{
    BookmarkRow, CollaborationOp, CommentRow, DataTypeRow, FunctionRow, GraphEdge, GraphNode,
    JournalEntry, MemoryRegion, PatchRow, ProgramId, PrototypeRow, Provenance, RevisionEvent,
    SearchHit, StackVariableRow, StringRow, SymbolRow, TraceEvent, TypeDefRow, TypeFieldRow,
    TypeGraphNode, TypeLinkRow, XrefRow,
};
use rusqlite::{params, Connection, OptionalExtension, Row};
use std::path::Path;

/// Schema version; bump on any incompatible change and add a migration.
pub const SCHEMA_VERSION: i64 = 4;

/// Database open or query failure.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// Underlying SQLite failure.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Program ID not present.
    #[error("program not found: {0}")]
    ProgramNotFound(u64),
    /// Stored patch data was not valid hexadecimal.
    #[error("invalid hexadecimal patch data: {0}")]
    InvalidHex(String),
    /// Stored collaboration operation was not present.
    #[error("collaboration operation not found: {0}")]
    OperationNotFound(String),

}
/// Convenience alias with the error defaulted per project convention.
pub type Result<T, E = DbError> = std::result::Result<T, E>;

/// Opened project database.
pub struct ProjectDb {
    conn: Connection,
}

impl ProjectDb {
    /// Opens (creating if needed) a project database at `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // WAL: durable enough for crash tests, allows concurrent readers while
        // the CLI writes (spec 13.1 leaves WAL vs rollback to measurement).
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Opens an in-memory database (tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS meta (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', '2');

             CREATE TABLE IF NOT EXISTS programs (
                 id INTEGER PRIMARY KEY,
                 name TEXT NOT NULL UNIQUE,
                 language TEXT NOT NULL,
                 revision INTEGER NOT NULL DEFAULT 1,
                 imported_at TEXT NOT NULL DEFAULT (datetime('now'))
             );

             CREATE TABLE IF NOT EXISTS provenance (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 producer TEXT NOT NULL,
                 upstream_version TEXT NOT NULL,
                 PRIMARY KEY (program_id)
             );

             CREATE TABLE IF NOT EXISTS functions (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 entry TEXT NOT NULL,
                 name TEXT NOT NULL,
                 size INTEGER NOT NULL,
                 signature TEXT,
                 calling_convention TEXT,
                 PRIMARY KEY (program_id, entry)
             );

             CREATE TABLE IF NOT EXISTS symbols (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 address TEXT NOT NULL,
                 name TEXT NOT NULL,
                 external INTEGER NOT NULL,
                 source TEXT NOT NULL,
                 PRIMARY KEY (program_id, address, name)
             );

             CREATE TABLE IF NOT EXISTS xrefs (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 src TEXT NOT NULL,
                 dst TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 PRIMARY KEY (program_id, src, dst, kind)
             );
             CREATE INDEX IF NOT EXISTS idx_xrefs_dst ON xrefs(program_id, dst);

             CREATE TABLE IF NOT EXISTS comments (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 address TEXT NOT NULL,
                 function TEXT NOT NULL,
                 type TEXT NOT NULL,
                 text TEXT NOT NULL,
                 PRIMARY KEY (program_id, address, type)
             );
             CREATE INDEX IF NOT EXISTS idx_comments_fn ON comments(program_id, function);

             CREATE TABLE IF NOT EXISTS datatypes (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 name TEXT NOT NULL,
                 definition TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (program_id, name)
             );

             CREATE TABLE IF NOT EXISTS strings (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 address TEXT NOT NULL,
                 value TEXT NOT NULL,
                 kind TEXT NOT NULL DEFAULT 'string',
                 PRIMARY KEY (program_id, address, value)
             );
             CREATE INDEX IF NOT EXISTS idx_strings_value
                 ON strings(program_id, value);

             CREATE TABLE IF NOT EXISTS memory_regions (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 name TEXT NOT NULL,
                 start TEXT NOT NULL,
                 size INTEGER NOT NULL,
                 permissions TEXT NOT NULL DEFAULT '',
                 source TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (program_id, name, start)
             );

             CREATE TABLE IF NOT EXISTS bookmarks (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 address TEXT NOT NULL,
                 label TEXT NOT NULL,
                 comment TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (program_id, address)
             );

             CREATE TABLE IF NOT EXISTS patches (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 address TEXT NOT NULL,
                 original_hex TEXT NOT NULL,
                 patched_hex TEXT NOT NULL,
                 enabled INTEGER NOT NULL DEFAULT 1,
                 PRIMARY KEY (program_id, address)
             );

             CREATE TABLE IF NOT EXISTS type_defs (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 name TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 definition TEXT NOT NULL DEFAULT '',
                 size INTEGER,
                 alignment INTEGER,
                 base_type TEXT,
                 provenance TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (program_id, name)
             );

             CREATE TABLE IF NOT EXISTS type_fields (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 type_name TEXT NOT NULL,
                 ordinal INTEGER NOT NULL,
                 field_name TEXT NOT NULL,
                 offset INTEGER NOT NULL,
                 size INTEGER,
                 type_ref TEXT,
                 PRIMARY KEY (program_id, type_name, ordinal)
             );

             CREATE TABLE IF NOT EXISTS prototypes (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 function TEXT NOT NULL,
                 signature TEXT NOT NULL,
                 calling_convention TEXT,
                 return_type TEXT,
                 PRIMARY KEY (program_id, function)
             );

             CREATE TABLE IF NOT EXISTS stack_variables (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 function TEXT NOT NULL,
                 ordinal INTEGER NOT NULL,
                 name TEXT NOT NULL,
                 storage TEXT NOT NULL,
                 type_name TEXT,
                 offset INTEGER,
                 size INTEGER,
                 PRIMARY KEY (program_id, function, ordinal)
             );

             CREATE TABLE IF NOT EXISTS type_links (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 source TEXT NOT NULL,
                 target TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 provenance TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (program_id, source, target, kind)
             );

             CREATE TABLE IF NOT EXISTS revision_events (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 revision INTEGER NOT NULL,
                 kind TEXT NOT NULL,
                 detail TEXT NOT NULL DEFAULT '',
                 at TEXT NOT NULL DEFAULT (datetime('now'))
             );
             CREATE INDEX IF NOT EXISTS idx_rev_events
                 ON revision_events(program_id, revision);

             CREATE TABLE IF NOT EXISTS command_journal (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 seq INTEGER NOT NULL,
                 kind TEXT NOT NULL,
                 payload TEXT NOT NULL DEFAULT '',
                 undo_payload TEXT NOT NULL DEFAULT '',
                 done INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (program_id, seq)
             );
             CREATE TABLE IF NOT EXISTS trace_events (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 sequence INTEGER NOT NULL,
                 at TEXT NOT NULL,
                 thread TEXT NOT NULL DEFAULT '',
                 address TEXT,
                 kind TEXT NOT NULL,
                 payload TEXT NOT NULL DEFAULT '',
                 provenance TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (program_id, sequence)
             );
             CREATE INDEX IF NOT EXISTS idx_trace_events
                 ON trace_events(program_id, sequence);

             CREATE TABLE IF NOT EXISTS collaboration_ops (
                 program_id INTEGER NOT NULL REFERENCES programs(id),
                 op_id TEXT NOT NULL,
                 actor TEXT NOT NULL,
                 lamport INTEGER NOT NULL,
                 kind TEXT NOT NULL,
                 payload TEXT NOT NULL DEFAULT '',
                 applied INTEGER NOT NULL DEFAULT 0,
                 provenance TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (program_id, op_id)
             );
             CREATE INDEX IF NOT EXISTS idx_collaboration_order
                 ON collaboration_ops(program_id, lamport, actor, op_id);
             COMMIT;",
        )?;
        let v_text: String = self
            .conn
            .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| {
                r.get(0)
            })?;
        let v: i64 = v_text.parse().map_err(|_| {
            DbError::Sqlite(rusqlite::Error::InvalidParameterName(
                "meta.schema_version not an integer".into(),
            ))
        })?;
        if v > SCHEMA_VERSION {
            return Err(DbError::Sqlite(rusqlite::Error::InvalidParameterName(
                format!("database schema {v} newer than supported {SCHEMA_VERSION}"),
            )));
        }
        if v < SCHEMA_VERSION {
            self.conn.execute(
                "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
                params![SCHEMA_VERSION.to_string()],
            )?;
        }
        Ok(())
    }

    /// Inserts or replaces a program summary and its provenance. Returns the ID.
    pub fn upsert_program(
        &self,
        name: &str,
        language: &str,
        provenance: &Provenance,
    ) -> Result<ProgramId> {
        self.conn.execute(
            "INSERT INTO programs(name, language) VALUES (?1, ?2)
             ON CONFLICT(name) DO UPDATE SET language = excluded.language,
                                              revision = revision + 1",
            params![name, language],
        )?;
        let id = self.conn.query_row(
            "SELECT id FROM programs WHERE name = ?1",
            params![name],
            |r| r.get(0),
        )?;
        self.conn.execute(
            "INSERT INTO provenance(program_id, producer, upstream_version)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(program_id) DO UPDATE SET producer = excluded.producer,
                                                   upstream_version = excluded.upstream_version",
            params![id, provenance.producer, provenance.upstream_version],
        )?;
        Ok(ProgramId(id))
    }

    /// Replaces the function set of a program inside one transaction.
    pub fn replace_functions(&self, program: ProgramId, rows: &[FunctionRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM functions WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT INTO functions(program_id, entry, name, size, signature, calling_convention)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        let mut seen = std::collections::HashSet::new();
        for r in rows {
            if !seen.insert(r.entry.clone()) {
                continue;
            }
            stmt.execute(params![
                program.0,
                addr_cell(&r.entry),
                r.name,
                r.size,
                r.signature,
                r.calling_convention
            ])?;
        }
        drop(stmt);
                self.bump_and_record(&tx, program, "replace-functions", &format!("{}", rows.len()))?;
        tx.commit()?;
        Ok(())
    }

    /// Replaces the symbol set of a program inside one transaction.
    pub fn replace_symbols(&self, program: ProgramId, rows: &[SymbolRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM symbols WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT INTO symbols(program_id, address, name, external, source)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        // Real binaries (libc) repeat (address, name) pairs — versioned
        // exporters alias the same entry; dedupe within the batch or the
        // UNIQUE index aborts the whole replace.
        let mut seen = std::collections::HashSet::new();
        for r in rows {
            if !seen.insert((r.address.clone(), r.name.clone())) {
                continue;
            }
            stmt.execute(params![program.0, addr_cell(&r.address), r.name, r.external as i64, r.source])?;
        }
        drop(stmt);
                self.bump_and_record(&tx, program, "replace-symbols", &format!("{}", rows.len()))?;
        tx.commit()?;
        Ok(())
    }

    /// Replaces the xref set of a program inside one transaction.
    pub fn replace_xrefs(&self, program: ProgramId, rows: &[XrefRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM xrefs WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx
            .prepare("INSERT INTO xrefs(program_id, src, dst, kind) VALUES (?1, ?2, ?3, ?4)")?;
        let mut seen = std::collections::HashSet::new();
        for r in rows {
            if !seen.insert((r.from.clone(), r.to.clone(), r.kind.clone())) {
                continue;
            }
            stmt.execute(params![program.0, addr_cell(&r.from), addr_cell(&r.to), r.kind])?;
        }
        drop(stmt);
                self.bump_and_record(&tx, program, "replace-xrefs", &format!("{}", rows.len()))?;
        tx.commit()?;
        Ok(())
    }

    /// Applies an analyst rename: bumps the program revision and rewrites the
    /// function name. Fails when the function is unknown.
    pub fn rename_function(&self, program: ProgramId, entry: &lre_model::Address, name: &str) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let n = tx.execute(
            "UPDATE functions SET name = ?3 WHERE program_id = ?1 AND entry = ?2",
            params![program.0, addr_cell(entry), name],
        )?;
        if n == 0 {
            return Err(DbError::ProgramNotFound(program.0));
        }
        self.bump_and_record(&tx, program, "rename", name)?;
        tx.commit()?;
        Ok(())
    }

    /// Applies an analyst comment command and records its prior state for
    /// undo. One transaction owns the row mutation, revision event, and
    /// journal entry.
    pub fn comment_command(
        &self,
        program: ProgramId,
        address: &lre_model::Address,
        function: &lre_model::Address,
        kind: &str,
        text: &str,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let previous: Option<(String, String)> = tx
            .query_row(
                "SELECT function, text FROM comments
                 WHERE program_id = ?1 AND address = ?2 AND type = ?3",
                params![program.0, addr_cell(address), kind],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if previous.is_some() {
            tx.execute(
                "UPDATE comments SET function = ?4, text = ?5
                 WHERE program_id = ?1 AND address = ?2 AND type = ?3",
                params![program.0, addr_cell(address), kind, addr_cell(function), text],
            )?;
        } else {
            tx.execute(
                "INSERT INTO comments(program_id, address, function, type, text)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![program.0, addr_cell(address), addr_cell(function), kind, text],
            )?;
        }
        self.bump_and_record(&tx, program, "comment", text)?;
        let payload = serde_json::json!({
            "address": address.hex(),
            "function": function.hex(),
            "kind": kind,
            "text": text,
        })
        .to_string();
        let undo = serde_json::json!({
            "address": address.hex(),
            "kind": kind,
            "exists": previous.is_some(),
            "function": previous.as_ref().map(|(function, _)| function),
            "text": previous.as_ref().map(|(_, text)| text),
        })
        .to_string();
        self.journal_push(&tx, program, "comment", &payload, &undo)?;
        tx.commit()?;
        Ok(())
    }

    /// Restores one comment's prior state and marks its journal entry done.
    pub fn undo_comment(
        &self,
        program: ProgramId,
        address: &lre_model::Address,
        kind: &str,
        previous: Option<(&lre_model::Address, &str)>,
        seq: u64,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        if let Some((function, text)) = previous {
            tx.execute(
                "INSERT INTO comments(program_id, address, function, type, text)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(program_id, address, type)
                 DO UPDATE SET function = excluded.function, text = excluded.text",
                params![program.0, addr_cell(address), addr_cell(function), kind, text],
            )?;
        } else {
            tx.execute(
                "DELETE FROM comments WHERE program_id = ?1 AND address = ?2 AND type = ?3",
                params![program.0, addr_cell(address), kind],
            )?;
        }
        self.bump_and_record(
            &tx,
            program,
            "comment-undo",
            if previous.is_some() { "restore" } else { "delete" },
        )?;
        tx.execute(
            "UPDATE command_journal SET done = 1 WHERE program_id = ?1 AND seq = ?2",
            params![program.0, seq],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Lists functions of a program ordered by entry address.
    pub fn functions(&self, program: ProgramId) -> Result<Vec<FunctionRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT entry, name, size, signature, calling_convention
             FROM functions WHERE program_id = ?1 ORDER BY entry",
        )?;
        let rows = stmt
            .query_map(params![program.0], map_function)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Paged functions (review CORE-004): a bounded window + total + the
    /// revision the window was read at. Views never preload.
    pub fn functions_page(
        &self,
        program: ProgramId,
        offset: u64,
        limit: u64,
    ) -> Result<(Vec<FunctionRow>, Option<u64>, u64)> {
        let total: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM functions WHERE program_id = ?1", params![program.0], |r| r.get(0))?;
        let mut stmt = self.conn.prepare(
            "SELECT entry, name, size, signature, calling_convention
             FROM functions WHERE program_id = ?1 ORDER BY entry LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt
            .query_map(params![program.0, limit, offset], map_function)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((rows, Some(total as u64), self.revision(program)?))
    }

    /// Paged symbols (review CORE-004).
    pub fn symbols_page(
        &self,
        program: ProgramId,
        offset: u64,
        limit: u64,
    ) -> Result<(Vec<SymbolRow>, Option<u64>, u64)> {
        let total: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM symbols WHERE program_id = ?1", params![program.0], |r| r.get(0))?;
        let mut stmt = self.conn.prepare(
            "SELECT address, name, external, source FROM symbols
             WHERE program_id = ?1 ORDER BY address LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt
            .query_map(params![program.0, limit, offset], map_symbol)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((rows, Some(total as u64), self.revision(program)?))
    }

    /// Paged xrefs in one direction (review CORE-004).
    pub fn xrefs_page(
        &self,
        program: ProgramId,
        address: &lre_model::Address,
        incoming: bool,
        offset: u64,
        limit: u64,
    ) -> Result<(Vec<XrefRow>, Option<u64>, u64)> {
        let cell = addr_cell(address);
        let (src, dst) = (cell.clone(), cell);
        let sql_total = if incoming {
            "SELECT COUNT(*) FROM xrefs WHERE program_id = ?1 AND dst = ?2"
        } else {
            "SELECT COUNT(*) FROM xrefs WHERE program_id = ?1 AND src = ?2"
        };
        let total: i64 = self.conn
            .query_row(sql_total, params![program.0, dst], |r| r.get(0))?;
        let (sql_win, key) = if incoming {
            ("SELECT src, dst, kind FROM xrefs WHERE program_id = ?1 AND dst = ?2
              ORDER BY src LIMIT ?3 OFFSET ?4", dst)
        } else {
            ("SELECT src, dst, kind FROM xrefs WHERE program_id = ?1 AND src = ?2
              ORDER BY dst LIMIT ?3 OFFSET ?4", src)
        };
        let mut stmt = self.conn.prepare(sql_win)?;
        let rows = stmt
            .query_map(params![program.0, key, limit, offset], map_xref)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((rows, Some(total as u64), self.revision(program)?))
    }

    /// Lists xrefs pointing at `address`.
    pub fn xrefs_to(&self, program: ProgramId, address: &lre_model::Address) -> Result<Vec<XrefRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT src, dst, kind FROM xrefs WHERE program_id = ?1 AND dst = ?2 ORDER BY src",
        )?;
        let rows = stmt
            .query_map(params![program.0, addr_cell(address)], map_xref)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Lists xrefs leaving `address`.
    pub fn xrefs_from(&self, program: ProgramId, address: &lre_model::Address) -> Result<Vec<XrefRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT src, dst, kind FROM xrefs WHERE program_id = ?1 AND src = ?2 ORDER BY dst",
        )?;
        let rows = stmt
            .query_map(params![program.0, addr_cell(address)], map_xref)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Lists symbols of a program ordered by address.
    pub fn symbols(&self, program: ProgramId) -> Result<Vec<SymbolRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, name, external, source
             FROM symbols WHERE program_id = ?1 ORDER BY address",
        )?;
        let rows = stmt
            .query_map(params![program.0], map_symbol)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Replaces discovered strings atomically.
    pub fn replace_strings(&self, program: ProgramId, rows: &[StringRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM strings WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO strings(program_id, address, value, kind)
             VALUES (?1, ?2, ?3, ?4)",
        )?;
        for row in rows {
            stmt.execute(params![
                program.0,
                addr_cell(&row.address),
                row.value,
                row.kind
            ])?;
        }
        drop(stmt);
        self.bump_and_record(&tx, program, "replace-strings", &rows.len().to_string())?;
        tx.commit()?;
        Ok(())
    }

    /// Lists strings ordered by address.
    pub fn strings(&self, program: ProgramId) -> Result<Vec<StringRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, value, kind FROM strings
             WHERE program_id = ?1 ORDER BY address, value",
        )?;
        Ok(stmt
            .query_map(params![program.0], |row| {
                Ok(StringRow {
                    address: addr_from_cell(row.get(0)?),
                    value: row.get(1)?,
                    kind: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Searches durable names, strings, comments, and data types. The query
    /// is bounded by `limit` and never loads native bytes or starts a worker.
    pub fn search(&self, program: ProgramId, term: &str, limit: u64) -> Result<Vec<SearchHit>> {
        let pattern = format!("%{term}%");
        let mut hits = Vec::new();
        {
            let mut stmt = self.conn.prepare(
                "SELECT entry, name FROM functions
                 WHERE program_id = ?1 AND (entry LIKE ?2 OR name LIKE ?2)",
            )?;
            for row in stmt.query_map(params![program.0, pattern], |row| {
                Ok(SearchHit {
                    address: Some(addr_from_cell(row.get(0)?)),
                    kind: "function".into(),
                    name: row.get(1)?,
                    context: String::new(),
                })
            })? {
                hits.push(row?);
            }
        }
        {
            let mut stmt = self.conn.prepare(
                "SELECT address, name, source FROM symbols
                 WHERE program_id = ?1 AND (address LIKE ?2 OR name LIKE ?2 OR source LIKE ?2)",
            )?;
            for row in stmt.query_map(params![program.0, pattern], |row| {
                Ok(SearchHit {
                    address: Some(addr_from_cell(row.get(0)?)),
                    kind: "symbol".into(),
                    name: row.get(1)?,
                    context: row.get(2)?,
                })
            })? {
                hits.push(row?);
            }
        }
        {
            let mut stmt = self.conn.prepare(
                "SELECT address, value, kind FROM strings
                 WHERE program_id = ?1 AND (address LIKE ?2 OR value LIKE ?2 OR kind LIKE ?2)",
            )?;
            for row in stmt.query_map(params![program.0, pattern], |row| {
                Ok(SearchHit {
                    address: Some(addr_from_cell(row.get(0)?)),
                    kind: "string".into(),
                    name: row.get(1)?,
                    context: row.get(2)?,
                })
            })? {
                hits.push(row?);
            }
        }
        {
            let mut stmt = self.conn.prepare(
                "SELECT address, type, text FROM comments
                 WHERE program_id = ?1 AND (address LIKE ?2 OR type LIKE ?2 OR text LIKE ?2)",
            )?;
            for row in stmt.query_map(params![program.0, pattern], |row| {
                Ok(SearchHit {
                    address: Some(addr_from_cell(row.get(0)?)),
                    kind: "comment".into(),
                    name: row.get(2)?,
                    context: row.get(1)?,
                })
            })? {
                hits.push(row?);
            }
        }
        {
            let mut stmt = self.conn.prepare(
                "SELECT name, definition FROM datatypes
                 WHERE program_id = ?1 AND (name LIKE ?2 OR definition LIKE ?2)",
            )?;
            for row in stmt.query_map(params![program.0, pattern], |row| {
                Ok(SearchHit {
                    address: None,
                    kind: "datatype".into(),
                    name: row.get(0)?,
                    context: row.get(1)?,
                })
            })? {
                hits.push(row?);
            }
        }
        hits.sort_by_key(|hit| {
            (
                hit.address.as_ref().map(|address| address.offset).unwrap_or(u64::MAX),
                hit.kind.clone(),
                hit.name.clone(),
            )
        });
        hits.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(hits)
    }

    /// Returns graph nodes for functions and all stored reference edges.
    pub fn function_graph(&self, program: ProgramId) -> Result<(Vec<GraphNode>, Vec<GraphEdge>)> {
        let mut nodes = self
            .functions(program)?
            .into_iter()
            .map(|function| GraphNode {
                address: function.entry,
                name: function.name,
            })
            .collect::<Vec<_>>();
        let mut known = nodes
            .iter()
            .map(|node| node.address.clone())
            .collect::<std::collections::HashSet<_>>();
        let mut stmt = self
            .conn
            .prepare("SELECT src, dst, kind FROM xrefs WHERE program_id = ?1 ORDER BY src, dst")?;
        let edges = stmt
            .query_map(params![program.0], |row| {
                Ok(GraphEdge {
                    from: addr_from_cell(row.get(0)?),
                    to: addr_from_cell(row.get(1)?),
                    kind: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for edge in &edges {
            if known.insert(edge.to.clone()) {
                nodes.push(GraphNode {
                    name: format!("loc_{}", edge.to.hex()),
                    address: edge.to.clone(),
                });
            }
            if known.insert(edge.from.clone()) {
                nodes.push(GraphNode {
                    name: format!("loc_{}", edge.from.hex()),
                    address: edge.from.clone(),
                });
            }
        }
        nodes.sort_by_key(|node| node.address.offset);
        Ok((nodes, edges))
    }



    /// Replaces the memory map associated with a program.
    pub fn replace_memory_regions(
        &self,
        program: ProgramId,
        rows: &[MemoryRegion],
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM memory_regions WHERE program_id = ?1",
            params![program.0],
        )?;
        let mut stmt = tx.prepare(
            "INSERT INTO memory_regions(program_id, name, start, size, permissions, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        for row in rows {
            stmt.execute(params![
                program.0,
                row.name,
                addr_cell(&row.start),
                row.size,
                row.permissions,
                row.source
            ])?;
        }
        drop(stmt);
        self.bump_and_record(
            &tx,
            program,
            "replace-memory-regions",
            &rows.len().to_string(),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Lists mapped memory regions by start address.
    pub fn memory_regions(&self, program: ProgramId) -> Result<Vec<MemoryRegion>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, start, size, permissions, source FROM memory_regions
             WHERE program_id = ?1 ORDER BY start, name",
        )?;
        Ok(stmt
            .query_map(params![program.0], |row| {
                Ok(MemoryRegion {
                    name: row.get(0)?,
                    start: addr_from_cell(row.get(1)?),
                    size: row.get(2)?,
                    permissions: row.get(3)?,
                    source: row.get(4)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Upserts one bookmark and records the revision change.
    pub fn set_bookmark(&self, program: ProgramId, row: &BookmarkRow) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO bookmarks(program_id, address, label, comment)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(program_id, address)
             DO UPDATE SET label = excluded.label, comment = excluded.comment",
            params![program.0, addr_cell(&row.address), row.label, row.comment],
        )?;
        self.bump_and_record(&tx, program, "bookmark", &row.label)?;
        tx.commit()?;
        Ok(())
    }

    /// Removes one bookmark and records the revision change.
    pub fn delete_bookmark(&self, program: ProgramId, address: &lre_model::Address) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM bookmarks WHERE program_id = ?1 AND address = ?2",
            params![program.0, addr_cell(address)],
        )?;
        self.bump_and_record(&tx, program, "bookmark-delete", &address.hex())?;
        tx.commit()?;
        Ok(())
    }

    /// Lists bookmarks by address.
    pub fn bookmarks(&self, program: ProgramId) -> Result<Vec<BookmarkRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, label, comment FROM bookmarks
             WHERE program_id = ?1 ORDER BY address",
        )?;
        Ok(stmt
            .query_map(params![program.0], |row| {
                Ok(BookmarkRow {
                    address: addr_from_cell(row.get(0)?),
                    label: row.get(1)?,
                    comment: row.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Stores both the original bytes and the currently selected patch.
    pub fn set_patch(
        &self,
        program: ProgramId,
        row: &PatchRow,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO patches(program_id, address, original_hex, patched_hex, enabled)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(program_id, address)
             DO UPDATE SET original_hex = excluded.original_hex,
                           patched_hex = excluded.patched_hex,
                           enabled = excluded.enabled",
            params![
                program.0,
                addr_cell(&row.address),
                hex_encode(&row.original),
                hex_encode(&row.patched),
                row.enabled as i64
            ],
        )?;
        self.bump_and_record(&tx, program, "patch", &row.address.hex())?;
        tx.commit()?;
        Ok(())
    }

    /// Removes one patch record.
    pub fn delete_patch(&self, program: ProgramId, address: &lre_model::Address) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM patches WHERE program_id = ?1 AND address = ?2",
            params![program.0, addr_cell(address)],
        )?;
        self.bump_and_record(&tx, program, "patch-delete", &address.hex())?;
        tx.commit()?;
        Ok(())
    }

    /// Lists patch records by address.
    pub fn patches(&self, program: ProgramId) -> Result<Vec<PatchRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, original_hex, patched_hex, enabled FROM patches
             WHERE program_id = ?1 ORDER BY address",
        )?;
        let raw = stmt
            .query_map(params![program.0], |row| {
                Ok((
                    addr_from_cell(row.get(0)?),
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)? != 0,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        raw.into_iter()
            .map(|(address, original, patched, enabled)| {
                Ok(PatchRow {
                    address,
                    original: hex_decode(&original)?,
                    patched: hex_decode(&patched)?,
                    enabled,
                })
            })
            .collect()
    }

    /// Replaces the comment set of a program inside one transaction.
    pub fn replace_comments(&self, program: ProgramId, rows: &[CommentRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM comments WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT INTO comments(program_id, address, function, type, text)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for r in rows {
            stmt.execute(params![
                program.0,
                addr_cell(&r.address),
                addr_cell(&r.function),
                r.kind,
                r.text
            ])?;
        }
        drop(stmt);
                self.bump_and_record(&tx, program, "replace-comments", &format!("{}", rows.len()))?;
        tx.commit()?;
        Ok(())
    }

    /// Replaces the datatype set of a program inside one transaction.
    pub fn replace_datatypes(&self, program: ProgramId, rows: &[DataTypeRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM datatypes WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO datatypes(program_id, name, definition)
             VALUES (?1, ?2, ?3)",
        )?;
        for r in rows {
            stmt.execute(params![program.0, r.name, r.definition])?;
        }
        drop(stmt);
                self.bump_and_record(&tx, program, "replace-datatypes", &format!("{}", rows.len()))?;
        tx.commit()?;
        Ok(())
    }

    /// Lists comments of a program ordered by address.
    pub fn comments(&self, program: ProgramId) -> Result<Vec<CommentRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT address, function, type, text FROM comments
             WHERE program_id = ?1 ORDER BY address",
        )?;
        let rows = stmt
            .query_map(params![program.0], |r| {
                Ok(CommentRow {
                    address: addr_from_cell(r.get(0)?),
                    function: addr_from_cell(r.get(1)?),
                    kind: r.get(2)?,
                    text: r.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Lists datatypes of a program ordered by name.
    pub fn datatypes(&self, program: ProgramId) -> Result<Vec<DataTypeRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, definition FROM datatypes
             WHERE program_id = ?1 ORDER BY name",
        )?;
        let rows = stmt
            .query_map(params![program.0], |r| {
                Ok(DataTypeRow {
                    name: r.get(0)?,
                    definition: r.get(1)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
    /// Upserts one rich type definition.
    pub fn set_type_def(&self, program: ProgramId, row: &TypeDefRow) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO type_defs(
                 program_id, name, kind, definition, size, alignment, base_type, provenance
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(program_id, name) DO UPDATE SET
                 kind = excluded.kind, definition = excluded.definition,
                 size = excluded.size, alignment = excluded.alignment,
                 base_type = excluded.base_type, provenance = excluded.provenance",
            params![
                program.0,
                row.name,
                row.kind,
                row.definition,
                row.size,
                row.alignment,
                row.base_type,
                row.provenance
            ],
        )?;
        self.bump_and_record(&tx, program, "type-def", &row.name)?;
        tx.commit()?;
        Ok(())
    }

    /// Upserts one composite type field.
    pub fn set_type_field(&self, program: ProgramId, row: &TypeFieldRow) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO type_fields(
                 program_id, type_name, ordinal, field_name, offset, size, type_ref
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(program_id, type_name, ordinal) DO UPDATE SET
                 field_name = excluded.field_name, offset = excluded.offset,
                 size = excluded.size, type_ref = excluded.type_ref",
            params![
                program.0,
                row.type_name,
                row.ordinal,
                row.field_name,
                row.offset,
                row.size,
                row.type_ref
            ],
        )?;
        self.bump_and_record(&tx, program, "type-field", &row.type_name)?;
        tx.commit()?;
        Ok(())
    }

    /// Replaces the rich type definitions exported by a provider.
    pub fn replace_type_defs(&self, program: ProgramId, rows: &[TypeDefRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM type_defs WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT INTO type_defs(
                 program_id, name, kind, definition, size, alignment, base_type, provenance
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for row in rows {
            stmt.execute(params![
                program.0,
                row.name,
                row.kind,
                row.definition,
                row.size,
                row.alignment,
                row.base_type,
                row.provenance
            ])?;
        }
        drop(stmt);
        self.bump_and_record(&tx, program, "replace-type-defs", &rows.len().to_string())?;
        tx.commit()?;
        Ok(())
    }

    /// Lists rich type definitions by name.
    pub fn type_defs(&self, program: ProgramId) -> Result<Vec<TypeDefRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, kind, definition, size, alignment, base_type, provenance
             FROM type_defs WHERE program_id = ?1 ORDER BY name",
        )?;
        Ok(stmt
            .query_map(params![program.0], |row| {
                Ok(TypeDefRow {
                    name: row.get(0)?,
                    kind: row.get(1)?,
                    definition: row.get(2)?,
                    size: row.get::<_, Option<i64>>(3)?.map(|value| value as u64),
                    alignment: row.get::<_, Option<i64>>(4)?.map(|value| value as u64),
                    base_type: row.get(5)?,
                    provenance: row.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Replaces all composite fields for a program.
    pub fn replace_type_fields(&self, program: ProgramId, rows: &[TypeFieldRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM type_fields WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT INTO type_fields(
                 program_id, type_name, ordinal, field_name, offset, size, type_ref
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for row in rows {
            stmt.execute(params![
                program.0,
                row.type_name,
                row.ordinal,
                row.field_name,
                row.offset,
                row.size,
                row.type_ref
            ])?;
        }
        drop(stmt);
        self.bump_and_record(&tx, program, "replace-type-fields", &rows.len().to_string())?;
        tx.commit()?;
        Ok(())
    }

    /// Lists fields, optionally restricted to one type.
    pub fn type_fields(
        &self,
        program: ProgramId,
        type_name: Option<&str>,
    ) -> Result<Vec<TypeFieldRow>> {
        let mut rows = Vec::new();
        if let Some(type_name) = type_name {
            let mut stmt = self.conn.prepare(
                "SELECT type_name, ordinal, field_name, offset, size, type_ref
                 FROM type_fields WHERE program_id = ?1 AND type_name = ?2
                 ORDER BY ordinal",
            )?;
            for row in stmt.query_map(params![program.0, type_name], map_type_field)? {
                rows.push(row?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT type_name, ordinal, field_name, offset, size, type_ref
                 FROM type_fields WHERE program_id = ?1 ORDER BY type_name, ordinal",
            )?;
            for row in stmt.query_map(params![program.0], map_type_field)? {
                rows.push(row?);
            }
        }
        Ok(rows)
    }

    /// Lists the type graph and its provenance-bearing edges.
    pub fn type_graph(
        &self,
        program: ProgramId,
    ) -> Result<(Vec<TypeGraphNode>, Vec<TypeLinkRow>)> {
        let nodes = self
            .type_defs(program)?
            .into_iter()
            .map(|row| TypeGraphNode {
                name: row.name,
                kind: row.kind,
                size: row.size,
            })
            .collect();
        Ok((nodes, self.type_links(program)?))
    }

    /// Replaces function prototypes.
    pub fn replace_prototypes(&self, program: ProgramId, rows: &[PrototypeRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM prototypes WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT INTO prototypes(program_id, function, signature, calling_convention, return_type)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for row in rows {
            stmt.execute(params![
                program.0,
                addr_cell(&row.function),
                row.signature,
                row.calling_convention,
                row.return_type
            ])?;
        }
        drop(stmt);
        self.bump_and_record(&tx, program, "replace-prototypes", &rows.len().to_string())?;
        tx.commit()?;
        Ok(())
    }

    /// Upserts one function prototype.
    pub fn set_prototype(&self, program: ProgramId, row: &PrototypeRow) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO prototypes(
                 program_id, function, signature, calling_convention, return_type
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(program_id, function) DO UPDATE SET
                 signature = excluded.signature,
                 calling_convention = excluded.calling_convention,
                 return_type = excluded.return_type",
            params![
                program.0,
                addr_cell(&row.function),
                row.signature,
                row.calling_convention,
                row.return_type
            ],
        )?;
        self.bump_and_record(&tx, program, "prototype", &row.function.hex())?;
        tx.commit()?;
        Ok(())
    }

    /// Lists prototypes ordered by function address.
    pub fn prototypes(&self, program: ProgramId) -> Result<Vec<PrototypeRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT function, signature, calling_convention, return_type
             FROM prototypes WHERE program_id = ?1 ORDER BY function",
        )?;
        Ok(stmt
            .query_map(params![program.0], |row| {
                Ok(PrototypeRow {
                    function: addr_from_cell(row.get(0)?),
                    signature: row.get(1)?,
                    calling_convention: row.get(2)?,
                    return_type: row.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }

    /// Replaces recovered stack variables.
    pub fn replace_stack_variables(
        &self,
        program: ProgramId,
        rows: &[StackVariableRow],
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM stack_variables WHERE program_id = ?1",
            params![program.0],
        )?;
        let mut stmt = tx.prepare(
            "INSERT INTO stack_variables(
                 program_id, function, ordinal, name, storage, type_name, offset, size
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for row in rows {
            stmt.execute(params![
                program.0,
                addr_cell(&row.function),
                row.ordinal,
                row.name,
                row.storage,
                row.type_name,
                row.offset,
                row.size
            ])?;
        }
        drop(stmt);
        self.bump_and_record(
            &tx,
            program,
            "replace-stack-variables",
            &rows.len().to_string(),
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Upserts one recovered stack variable.
    pub fn set_stack_variable(
        &self,
        program: ProgramId,
        row: &StackVariableRow,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO stack_variables(
                 program_id, function, ordinal, name, storage, type_name, offset, size
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(program_id, function, ordinal) DO UPDATE SET
                 name = excluded.name, storage = excluded.storage,
                 type_name = excluded.type_name, offset = excluded.offset,
                 size = excluded.size",
            params![
                program.0,
                addr_cell(&row.function),
                row.ordinal,
                row.name,
                row.storage,
                row.type_name,
                row.offset,
                row.size
            ],
        )?;
        self.bump_and_record(&tx, program, "stack-variable", &row.name)?;
        tx.commit()?;
        Ok(())
    }


    /// Lists stack variables, optionally restricted to a function.
    pub fn stack_variables(
        &self,
        program: ProgramId,
        function: Option<&lre_model::Address>,
    ) -> Result<Vec<StackVariableRow>> {
        let mut rows = Vec::new();
        if let Some(function) = function {
            let mut stmt = self.conn.prepare(
                "SELECT function, ordinal, name, storage, type_name, offset, size
                 FROM stack_variables WHERE program_id = ?1 AND function = ?2
                 ORDER BY ordinal",
            )?;
            for row in stmt.query_map(params![program.0, addr_cell(function)], map_stack_variable)? {
                rows.push(row?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT function, ordinal, name, storage, type_name, offset, size
                 FROM stack_variables WHERE program_id = ?1 ORDER BY function, ordinal",
            )?;
            for row in stmt.query_map(params![program.0], map_stack_variable)? {
                rows.push(row?);
            }
        }
        Ok(rows)
    }

    /// Replaces type dependency edges and their provenance.
    pub fn replace_type_links(&self, program: ProgramId, rows: &[TypeLinkRow]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM type_links WHERE program_id = ?1", params![program.0])?;
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO type_links(program_id, source, target, kind, provenance)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        for row in rows {
            stmt.execute(params![
                program.0,
                row.source,
                row.target,
                row.kind,
                row.provenance
            ])?;
        }
        drop(stmt);
        self.bump_and_record(&tx, program, "replace-type-links", &rows.len().to_string())?;
        tx.commit()?;
        Ok(())
    }

    /// Upserts one provenance-bearing type dependency.
    pub fn set_type_link(&self, program: ProgramId, row: &TypeLinkRow) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO type_links(program_id, source, target, kind, provenance)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(program_id, source, target, kind) DO UPDATE SET
                 provenance = excluded.provenance",
            params![
                program.0,
                row.source,
                row.target,
                row.kind,
                row.provenance
            ],
        )?;
        self.bump_and_record(
            &tx,
            program,
            "type-link",
            &format!("{} -> {}", row.source, row.target),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Lists type dependency edges.
    pub fn type_links(&self, program: ProgramId) -> Result<Vec<TypeLinkRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT source, target, kind, provenance FROM type_links
             WHERE program_id = ?1 ORDER BY source, target",
        )?;
        Ok(stmt
            .query_map(params![program.0], |row| {
                Ok(TypeLinkRow {
                    source: row.get(0)?,
                    target: row.get(1)?,
                    kind: row.get(2)?,
                    provenance: row.get(3)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?)
    }


    /// Looks up a program ID by name.
    pub fn program_id(&self, name: &str) -> Result<ProgramId> {
        let id = self
            .conn
            .query_row(
                "SELECT id FROM programs WHERE name = ?1",
                params![name],
                |r| r.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => DbError::ProgramNotFound(0),
                other => other.into(),
            })?;
        Ok(ProgramId(id))
    }

    /// Appends one timeline event and assigns its per-program sequence.
    pub fn append_trace_event(&self, program: ProgramId, row: &TraceEvent) -> Result<TraceEvent> {
        let tx = self.conn.unchecked_transaction()?;
        let sequence: i64 = tx.query_row(
            "SELECT COALESCE(MAX(sequence), 0) + 1 FROM trace_events WHERE program_id = ?1",
            params![program.0],
            |r| r.get(0),
        )?;
        let address = row.address.as_ref().map(addr_cell);
        tx.execute(
            "INSERT INTO trace_events(
                 program_id, sequence, at, thread, address, kind, payload, provenance
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                program.0,
                sequence,
                row.at,
                row.thread,
                address,
                row.kind,
                row.payload,
                row.provenance
            ],
        )?;
        self.bump_and_record(&tx, program, "trace-event", &row.kind)?;
        tx.commit()?;
        let mut stored = row.clone();
        stored.sequence = sequence as u64;
        Ok(stored)
    }

    /// Lists timeline events after `since`, in sequence order.
    pub fn trace_events(
        &self,
        program: ProgramId,
        since: u64,
        limit: u64,
    ) -> Result<Vec<TraceEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT sequence, at, thread, address, kind, payload, provenance
             FROM trace_events
             WHERE program_id = ?1 AND sequence > ?2
             ORDER BY sequence
             LIMIT ?3",
        )?;
        let limit = limit.min(i64::MAX as u64) as i64;
        let rows = stmt
            .query_map(params![program.0, since, limit], |row| {
                let address: Option<String> = row.get(3)?;
                Ok(TraceEvent {
                    sequence: row.get::<_, i64>(0)? as u64,
                    at: row.get(1)?,
                    thread: row.get(2)?,
                    address: address.and_then(|value| lre_model::Address::parse_ram_hex(&value)),
                    kind: row.get(4)?,
                    payload: row.get(5)?,
                    provenance: row.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Adds a collaboration operation once. Duplicate op ids are idempotent
    /// and do not advance the program revision.
    pub fn append_collaboration_op(
        &self,
        program: ProgramId,
        row: &CollaborationOp,
    ) -> Result<bool> {
        let tx = self.conn.unchecked_transaction()?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO collaboration_ops(
                 program_id, op_id, actor, lamport, kind, payload, applied, provenance
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                program.0,
                row.op_id,
                row.actor,
                row.lamport,
                row.kind,
                row.payload,
                row.applied as i64,
                row.provenance
            ],
        )? != 0;
        if inserted {
            self.bump_and_record(&tx, program, "collaboration-op", &row.op_id)?;
        }
        tx.commit()?;
        Ok(inserted)
    }

    /// Lists operations in deterministic Lamport/actor/id order.
    pub fn collaboration_ops(&self, program: ProgramId) -> Result<Vec<CollaborationOp>> {
        let mut stmt = self.conn.prepare(
            "SELECT op_id, actor, lamport, kind, payload, applied, provenance
             FROM collaboration_ops
             WHERE program_id = ?1
             ORDER BY lamport, actor, op_id",
        )?;
        let rows = stmt
            .query_map(params![program.0], |row| {
                Ok(CollaborationOp {
                    op_id: row.get(0)?,
                    actor: row.get(1)?,
                    lamport: row.get::<_, i64>(2)? as u64,
                    kind: row.get(3)?,
                    payload: row.get(4)?,
                    applied: row.get::<_, i64>(5)? != 0,
                    provenance: row.get(6)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Marks an existing operation applied; repeating the call is idempotent.
    pub fn apply_collaboration_op(&self, program: ProgramId, op_id: &str) -> Result<bool> {
        let tx = self.conn.unchecked_transaction()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM collaboration_ops WHERE program_id = ?1 AND op_id = ?2
             )",
            params![program.0, op_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(DbError::OperationNotFound(op_id.into()));
        }
        let changed = tx.execute(
            "UPDATE collaboration_ops
             SET applied = 1
             WHERE program_id = ?1 AND op_id = ?2 AND applied = 0",
            params![program.0, op_id],
        )? != 0;
        if changed {
            self.bump_and_record(&tx, program, "collaboration-apply", op_id)?;
        }
        tx.commit()?;
        Ok(changed)
    }

    /// Current revision of a program; facts older than this are stale.
    pub fn revision(&self, program: ProgramId) -> Result<u64> {
        let rev = self.conn.query_row(
            "SELECT revision FROM programs WHERE id = ?1",
            params![program.0],
            |r| r.get(0),
        )?;
        Ok(rev)
    }

    /// Events after `since` (exclusive) for the program, ascending.
    pub fn events_since(&self, program: ProgramId, since: u64) -> Result<Vec<RevisionEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT revision, kind, detail FROM revision_events
             WHERE program_id = ?1 AND revision > ?2 ORDER BY revision",
        )?;
        let rows = stmt
            .query_map(params![program.0, since], |r| {
                Ok(RevisionEvent {
                    revision: r.get::<_, i64>(0)? as u64,
                    kind: r.get(1)?,
                    detail: r.get(2)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// UNDOABLE rename (CORE-006): rename + revision bump/event + journal
    /// entry, all in one transaction.
    pub fn rename_command(
        &self,
        program: ProgramId,
        entry: &lre_model::Address,
        name: &str,
        undo_name: &str,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let n = tx.execute(
            "UPDATE functions SET name = ?3 WHERE program_id = ?1 AND entry = ?2",
            params![program.0, addr_cell(entry), name],
        )?;
        if n == 0 {
            return Err(DbError::ProgramNotFound(program.0));
        }
        self.bump_and_record(&tx, program, "rename", name)?;
        let payload = serde_json::json!({"entry": entry.hex(), "name": name}).to_string();
        let undo = serde_json::json!({"entry": entry.hex(), "name": undo_name}).to_string();
        self.journal_push(&tx, program, "rename", &payload, &undo)?;
        tx.commit()?;
        Ok(())
    }

    /// Applies the undo for a rename (CORE-006): rename back + event +
    /// journal marked done, one transaction.
    pub fn undo_rename(
        &self,
        program: ProgramId,
        entry: &lre_model::Address,
        name: &str,
        seq: u64,
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        let n = tx.execute(
            "UPDATE functions SET name = ?3 WHERE program_id = ?1 AND entry = ?2",
            params![program.0, addr_cell(entry), name],
        )?;
        if n == 0 {
            return Err(DbError::ProgramNotFound(program.0));
        }
        self.bump_and_record(&tx, program, "rename-undo", name)?;
        tx.execute(
            "UPDATE command_journal SET done = 1 WHERE program_id = ?1 AND seq = ?2",
            params![program.0, seq],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Pushes one command-journal entry (inside a transaction).
    pub fn journal_push(
        &self,
        tx: &rusqlite::Transaction<'_>,
        program: ProgramId,
        kind: &str,
        payload: &str,
        undo_payload: &str,
    ) -> Result<u64> {
        let seq: i64 = tx.query_row(
            "SELECT COALESCE(MAX(seq), 0) + 1 FROM command_journal WHERE program_id = ?1",
            params![program.0],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO command_journal(program_id, seq, kind, payload, undo_payload)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![program.0, seq, kind, payload, undo_payload],
        )?;
        Ok(seq as u64)
    }

    /// The latest undone-able entry (done = 0), if any.
    pub fn journal_latest(&self, program: ProgramId) -> Result<Option<JournalEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, kind, payload, undo_payload, done FROM command_journal
             WHERE program_id = ?1 AND done = 0
             ORDER BY seq DESC LIMIT 1",
        )?;
        let rows = stmt
            .query_map(params![program.0], |r| {
                Ok(JournalEntry {
                    seq: r.get::<_, i64>(0)? as u64,
                    kind: r.get(1)?,
                    payload: r.get(2)?,
                    undo_payload: r.get(3)?,
                    done: r.get::<_, i64>(4)? != 0,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows.into_iter().next())
    }

    /// Marks an entry undone.
    pub fn journal_mark_done(&self, program: ProgramId, seq: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE command_journal SET done = 1 WHERE program_id = ?1 AND seq = ?2",
            params![program.0, seq],
        )?;
        Ok(())
    }

    /// Record one mutation event (inside the caller's transaction).
    fn record_event(
        &self,
        tx: &rusqlite::Transaction<'_>,
        program: ProgramId,
        revision: u64,
        kind: &str,
        detail: &str,
    ) -> Result<()> {
        tx.execute(
            "INSERT INTO revision_events(program_id, revision, kind, detail)
             VALUES (?1, ?2, ?3, ?4)",
            params![program.0, revision, kind, detail],
        )?;
        Ok(())
    }

    /// Bumps the program revision by one and records an event (inside the
    /// caller's transaction).
    fn bump_and_record(
        &self,
        tx: &rusqlite::Transaction<'_>,
        program: ProgramId,
        kind: &str,
        detail: &str,
    ) -> Result<u64> {
        tx.execute(
            "UPDATE programs SET revision = revision + 1 WHERE id = ?1",
            params![program.0],
        )?;
        let rev: i64 = tx.query_row(
            "SELECT revision FROM programs WHERE id = ?1",
            params![program.0],
            |r| r.get(0),
        )?;
        self.record_event(tx, program, rev as u64, kind, detail)?;
        Ok(rev as u64)
    }


    /// Language ID recorded for a program.
    pub fn program_language(&self, program: ProgramId) -> Result<String> {
        let lang = self.conn.query_row(
            "SELECT language FROM programs WHERE id = ?1",
            params![program.0],
            |r| r.get(0),
        )?;
        Ok(lang)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(DbError::InvalidHex(value.into()));
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair).map_err(|_| DbError::InvalidHex(value.into()))?;
        let byte = u8::from_str_radix(text, 16)
            .map_err(|_| DbError::InvalidHex(value.into()))?;
        out.push(byte);
    }
    Ok(out)
}

fn map_symbol(r: &Row<'_>) -> rusqlite::Result<SymbolRow> {
    Ok(SymbolRow {
        address: addr_from_cell(r.get(0)?),
        name: r.get(1)?,
        external: r.get::<_, i64>(2)? != 0,
        source: r.get(3)?,
    })
}

/// Store-side address mapping: the schema persists canonical hex string
/// offsets (single-space contract: the store holds `ram` addresses). This is
/// the one serialization edge where rendered text is allowed — the model
/// contract is typed above it.
fn addr_cell(a: &lre_model::Address) -> String {
    format!("{:08x}", a.offset)
}
fn addr_from_cell(s: String) -> lre_model::Address {
    lre_model::Address::parse_ram_hex(&s).unwrap_or_default()
}

fn map_function(r: &Row<'_>) -> rusqlite::Result<FunctionRow> {
    Ok(FunctionRow {
        entry: addr_from_cell(r.get(0)?),
        name: r.get(1)?,
        size: r.get(2)?,
        signature: r.get(3)?,
        calling_convention: r.get(4)?,
    })
}

fn map_xref(r: &Row<'_>) -> rusqlite::Result<XrefRow> {
    Ok(XrefRow {
        from: addr_from_cell(r.get(0)?),
        to: addr_from_cell(r.get(1)?),
        kind: r.get(2)?,
    })
}

fn map_type_field(r: &Row<'_>) -> rusqlite::Result<TypeFieldRow> {
    Ok(TypeFieldRow {
        type_name: r.get(0)?,
        ordinal: r.get(1)?,
        field_name: r.get(2)?,
        offset: r.get(3)?,
        size: r.get::<_, Option<i64>>(4)?.map(|value| value as u64),
        type_ref: r.get(5)?,
    })
}

fn map_stack_variable(r: &Row<'_>) -> rusqlite::Result<StackVariableRow> {
    Ok(StackVariableRow {
        function: addr_from_cell(r.get(0)?),
        ordinal: r.get(1)?,
        name: r.get(2)?,
        storage: r.get(3)?,
        type_name: r.get(4)?,
        offset: r.get(5)?,
        size: r.get::<_, Option<i64>>(6)?.map(|value| value as u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prov() -> Provenance {
        Provenance {
            producer: "ghidra-bridge".into(),
            upstream_version: "12.1.3".into(),
        }
    }

    #[test]
    fn program_roundtrip_and_revision_bump() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("smoke_bin", "x86:LE:64:default", &prov()).unwrap();
        assert_eq!(db.revision(id).unwrap(), 1);
        db.upsert_program("smoke_bin", "x86:LE:64:default", &prov()).unwrap();
        assert_eq!(db.revision(id).unwrap(), 2, "upsert bumps revision");
    }

    #[test]
    fn functions_replaced_atomically() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let rows = vec![FunctionRow {
            entry: lre_model::Address::ram(0x400466),
            name: "add".into(),
            size: 20,
            signature: None,
            calling_convention: None,
        }];
        db.replace_functions(id, &rows).unwrap();
        db.replace_functions(id, &[]).unwrap();
        assert!(db.functions(id).unwrap().is_empty());
    }

    #[test]
    fn rename_updates_name_and_revision() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let rows = vec![FunctionRow {
            entry: lre_model::Address::ram(0x400000),
            name: "FUN_00400000".into(),
            size: 4,
            signature: None,
            calling_convention: None,
        }];
        db.replace_functions(id, &rows).unwrap();
        let before = db.revision(id).unwrap();
        db.rename_function(id, &lre_model::Address::ram(0x400000), "main").unwrap();
        assert_eq!(db.revision(id).unwrap(), before + 1);
        assert_eq!(db.functions(id).unwrap()[0].name, "main");
    }

    #[test]
    fn comments_and_types_replace_atomically() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let cmts = vec![CommentRow {
            address: lre_model::Address::ram(0x400488),
            function: lre_model::Address::ram(0x400466),
            kind: "eol".into(),
            text: "a + b".into(),
        }];
        db.replace_comments(id, &cmts).unwrap();
        assert_eq!(db.comments(id).unwrap().len(), 1);
        let types = vec![DataTypeRow {
            name: "int".into(),
            definition: "4-byte signed".into(),
        }];
        db.replace_datatypes(id, &types).unwrap();
        assert_eq!(db.datatypes(id).unwrap()[0].name, "int");
        db.replace_comments(id, &[]).unwrap();
        assert!(db.comments(id).unwrap().is_empty());
    }

    #[test]
    fn comment_command_undo_roundtrip() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let address = lre_model::Address::ram(0x400466);
        db.comment_command(id, &address, &address, "eol", "first").unwrap();
        let after_add = db.revision(id).unwrap();
        assert_eq!(db.comments(id).unwrap()[0].text, "first");
        let journal = db.journal_latest(id).unwrap().unwrap();
        assert_eq!(journal.kind, "comment");
        let undo = serde_json::from_str::<serde_json::Value>(&journal.undo_payload).unwrap();
        assert_eq!(undo["exists"], false);
        db.undo_comment(id, &address, "eol", None, journal.seq).unwrap();
        assert!(db.comments(id).unwrap().is_empty());
        assert!(db.revision(id).unwrap() > after_add);
        assert!(db.journal_latest(id).unwrap().is_none());
    }

    #[test]
    fn paged_functions_window() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let rows: Vec<FunctionRow> = (0..100u64)
            .map(|i| FunctionRow {
                entry: lre_model::Address::ram(0x400000 + i * 0x10),
                name: format!("f{i}"),
                size: 16,
                signature: None,
                calling_convention: None,
            })
            .collect();
        db.replace_functions(id, &rows).unwrap();
        let (p1, total, rev) = db.functions_page(id, 0, 10).unwrap();
        assert_eq!(p1.len(), 10);
        assert_eq!(total, Some(100));
        assert_eq!(p1[0].entry.offset, 0x400000);
        let (p2, _, _) = db.functions_page(id, 90, 10).unwrap();
        assert_eq!(p2.len(), 10);
        assert_eq!(p2[0].entry.offset, 0x400000 + 90 * 0x10);
        let (p3, _, _) = db.functions_page(id, 999, 10).unwrap();
        assert!(p3.is_empty());
        // replace bumps the revision (mutation event model: CORE-005)
        assert!(rev >= 2);
    }

    #[test]
    fn rename_command_undo_roundtrip() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let rows = vec![FunctionRow {
            entry: lre_model::Address::ram(0x400000),
            name: "FUN_00400000".into(),
            size: 4,
            signature: None,
            calling_convention: None,
        }];
        db.replace_functions(id, &rows).unwrap();
        db.rename_command(id, &lre_model::Address::ram(0x400000), "main", "FUN_00400000").unwrap();
        assert_eq!(db.functions(id).unwrap()[0].name, "main");
        let latest = db.journal_latest(id).unwrap().unwrap();
        assert_eq!(latest.kind, "rename");
        assert!(!latest.done);
        assert!(latest.undo_payload.contains("FUN_00400000"));
        db.undo_rename(id, &lre_model::Address::ram(0x400000), "FUN_00400000", latest.seq)
            .unwrap();
        assert_eq!(db.functions(id).unwrap()[0].name, "FUN_00400000");
        assert!(db.journal_latest(id).unwrap().is_none(), "entry marked done");
    }

    #[test]
    fn revision_events_recorded() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        assert!(db.events_since(id, 0).unwrap().is_empty());
        let rows = vec![FunctionRow {
            entry: lre_model::Address::ram(0x400000),
            name: "FUN_00400000".into(),
            size: 4,
            signature: None,
            calling_convention: None,
        }];
        db.replace_functions(id, &rows).unwrap();
        let evs = db.events_since(id, 0).unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "replace-functions");
        assert_eq!(evs[0].revision, 2, "upsert=1, replace bumps to 2");
        db.rename_function(id, &lre_model::Address::ram(0x400000), "main").unwrap();
        // after the replace (rev 2); the rename is rev 3
        let evs = db.events_since(id, 2).unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "rename");
        assert_eq!(evs[0].detail, "main");
        assert_eq!(evs[0].revision, 3);
        // since = current revision -> nothing
        assert!(db.events_since(id, 3).unwrap().is_empty());
    }

    #[test]
    fn xref_directional_queries() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let rows = vec![XrefRow {
            from: lre_model::Address::ram(0x400488),
            to: lre_model::Address::ram(0x400466),
            kind: "UNCONDITIONAL_CALL".into(),
        }];
        db.replace_xrefs(id, &rows).unwrap();
        assert_eq!(db.xrefs_to(id, &lre_model::Address::ram(0x400466)).unwrap().len(), 1);
        assert_eq!(db.xrefs_from(id, &lre_model::Address::ram(0x400488)).unwrap().len(), 1);
        assert!(db.xrefs_to(id, &lre_model::Address::ram(0x400488)).unwrap().is_empty());
    }

    #[test]
    fn analysis_records_search_graph_memory_bookmarks_and_patches() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let entry = lre_model::Address::ram(0x400000);
        db.replace_functions(
            id,
            &[FunctionRow {
                entry: entry.clone(),
                name: "main".into(),
                size: 8,
                signature: None,
                calling_convention: None,
            }],
        )
        .unwrap();
        db.replace_symbols(
            id,
            &[SymbolRow {
                name: "main".into(),
                address: entry.clone(),
                external: false,
                source: "USER_DEFINED".into(),
            }],
        )
        .unwrap();
        db.replace_strings(
            id,
            &[StringRow {
                address: lre_model::Address::ram(0x401000),
                value: "hello ventris".into(),
                kind: "ASCII".into(),
            }],
        )
        .unwrap();
        db.replace_xrefs(
            id,
            &[XrefRow {
                from: entry.clone(),
                to: lre_model::Address::ram(0x401000),
                kind: "DATA".into(),
            }],
        )
        .unwrap();
        assert_eq!(db.search(id, "hello", 10).unwrap()[0].kind, "string");
        let (nodes, edges) = db.function_graph(id).unwrap();
        assert!(nodes.iter().any(|node| node.address.offset == 0x401000));
        assert_eq!(edges.len(), 1);
        db.replace_memory_regions(
            id,
            &[MemoryRegion {
                name: "elf:0".into(),
                start: entry.clone(),
                size: 0x100,
                permissions: "r-x".into(),
                source: "native-import".into(),
            }],
        )
        .unwrap();
        assert_eq!(db.memory_regions(id).unwrap()[0].permissions, "r-x");
        db.set_bookmark(
            id,
            &BookmarkRow {
                address: entry.clone(),
                label: "entry".into(),
                comment: "start".into(),
            },
        )
        .unwrap();
        assert_eq!(db.bookmarks(id).unwrap()[0].label, "entry");
        db.set_patch(
            id,
            &PatchRow {
                address: entry.clone(),
                original: vec![0x55, 0x48],
                patched: vec![0x90, 0x90],
                enabled: true,
            },
        )
        .unwrap();
        assert_eq!(db.patches(id).unwrap()[0].patched, vec![0x90, 0x90]);
    }
    #[test]
    fn rich_types_and_provenance_roundtrip() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        db.replace_type_defs(
            id,
            &[TypeDefRow {
                name: "struct point".into(),
                kind: "structure".into(),
                definition: "struct point { int x; int y; }".into(),
                size: Some(8),
                alignment: Some(4),
                base_type: None,
                provenance: "native-analysis".into(),
            }],
        )
        .unwrap();
        db.replace_type_fields(
            id,
            &[TypeFieldRow {
                type_name: "struct point".into(),
                ordinal: 0,
                field_name: "x".into(),
                offset: 0,
                size: Some(4),
                type_ref: Some("int".into()),
            }],
        )
        .unwrap();
        db.replace_type_links(
            id,
            &[TypeLinkRow {
                source: "struct point".into(),
                target: "int".into(),
                kind: "field".into(),
                provenance: "native-analysis".into(),
            }],
        )
        .unwrap();
        let function = lre_model::Address::ram(0x400000);
        db.replace_prototypes(
            id,
            &[PrototypeRow {
                function: function.clone(),
                signature: "int main(void)".into(),
                calling_convention: Some("__cdecl".into()),
                return_type: Some("int".into()),
            }],
        )
        .unwrap();
        db.replace_stack_variables(
            id,
            &[StackVariableRow {
                function,
                ordinal: 0,
                name: "point".into(),
                storage: "stack[-0x10]".into(),
                type_name: Some("struct point".into()),
                offset: Some(-16),
                size: Some(8),
            }],
        )
        .unwrap();
        assert_eq!(db.type_defs(id).unwrap()[0].name, "struct point");
        assert_eq!(db.type_fields(id, Some("struct point")).unwrap()[0].field_name, "x");
        assert_eq!(db.type_graph(id).unwrap().1[0].provenance, "native-analysis");
        assert_eq!(db.prototypes(id).unwrap()[0].signature, "int main(void)");
        assert_eq!(db.stack_variables(id, None).unwrap()[0].offset, Some(-16));
    }
    #[test]
    fn trace_and_collaboration_logs_are_ordered_and_idempotent() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let first = db
            .append_trace_event(
                id,
                &TraceEvent {
                    sequence: 0,
                    at: "2026-09-02T08:00:00Z".into(),
                    thread: "main".into(),
                    address: Some(lre_model::Address::ram(0x401000)),
                    kind: "breakpoint".into(),
                    payload: r#"{"reason":"entry"}"#.into(),
                    provenance: "debug-gdb".into(),
                },
            )
            .unwrap();
        let second = db
            .append_trace_event(
                id,
                &TraceEvent {
                    sequence: 0,
                    at: "2026-09-02T08:00:01Z".into(),
                    thread: "main".into(),
                    address: None,
                    kind: "step".into(),
                    payload: String::new(),
                    provenance: "debug-gdb".into(),
                },
            )
            .unwrap();
        assert_eq!((first.sequence, second.sequence), (1, 2));
        let events = db.trace_events(id, 0, 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].address.as_ref().unwrap().offset, 0x401000);
        assert_eq!(events[1].kind, "step");

        let op_b = CollaborationOp {
            op_id: "b-2".into(),
            actor: "b".into(),
            lamport: 2,
            kind: "rename".into(),
            payload: r#"{"name":"second"}"#.into(),
            applied: false,
            provenance: "team-b".into(),
        };
        let op_a = CollaborationOp {
            op_id: "a-1".into(),
            actor: "a".into(),
            lamport: 1,
            kind: "comment".into(),
            payload: r#"{"text":"first"}"#.into(),
            applied: false,
            provenance: "team-a".into(),
        };
        assert!(db.append_collaboration_op(id, &op_b).unwrap());
        assert!(db.append_collaboration_op(id, &op_a).unwrap());
        assert!(!db.append_collaboration_op(id, &op_a).unwrap());
        let operations = db.collaboration_ops(id).unwrap();
        assert_eq!(
            operations.iter().map(|op| op.op_id.as_str()).collect::<Vec<_>>(),
            vec!["a-1", "b-2"]
        );
        assert!(db.apply_collaboration_op(id, "a-1").unwrap());
        assert!(!db.apply_collaboration_op(id, "a-1").unwrap());
        assert!(db.collaboration_ops(id).unwrap()[0].applied);
        assert!(matches!(
            db.apply_collaboration_op(id, "missing"),
            Err(DbError::OperationNotFound(_))
        ));
    }
}
