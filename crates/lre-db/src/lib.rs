//! SQLite persistence for durable facts (spec 13.1, 14.4).
//!
//! The database stores project-owned records: the program identity, functions,
//! symbols, xrefs, and the provenance of whoever produced them. Every mutation
//! runs in a transaction and bumps the program revision; bridge exports carry
//! producer + upstream version so reopening never depends on the bridge.

use lre_model::{
    CommentRow, DataTypeRow, FunctionRow, JournalEntry, ProgramId, Provenance, RevisionEvent,
    SymbolRow, XrefRow,
};
use rusqlite::{params, Connection, Row};
use std::path::Path;

/// Schema version; bump on any incompatible change and add a migration.
pub const SCHEMA_VERSION: i64 = 2;

/// Database open or query failure.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// Underlying SQLite failure.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Program ID not present.
    #[error("program not found: {0}")]
    ProgramNotFound(u64),
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
}
