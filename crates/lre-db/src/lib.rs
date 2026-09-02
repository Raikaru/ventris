//! SQLite persistence for durable facts (spec 13.1, 14.4).
//!
//! The database stores project-owned records: the program identity, functions,
//! symbols, xrefs, and the provenance of whoever produced them. Every mutation
//! runs in a transaction and bumps the program revision; bridge exports carry
//! producer + upstream version so reopening never depends on the bridge.

use lre_model::{
    CommentRow, DataTypeRow, FunctionRow, ProgramId, Provenance, SymbolRow, XrefRow,
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
                r.entry,
                r.name,
                r.size,
                r.signature,
                r.calling_convention
            ])?;
        }
        drop(stmt);
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
            stmt.execute(params![program.0, r.address, r.name, r.external as i64, r.source])?;
        }
        drop(stmt);
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
            stmt.execute(params![program.0, r.from, r.to, r.kind])?;
        }
        drop(stmt);
        tx.commit()?;
        Ok(())
    }

    /// Applies an analyst rename: bumps the program revision and rewrites the
    /// function name. Fails when the function is unknown.
    pub fn rename_function(&self, program: ProgramId, entry: &str, name: &str) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE functions SET name = ?3 WHERE program_id = ?1 AND entry = ?2",
            params![program.0, entry, name],
        )?;
        if n == 0 {
            return Err(DbError::ProgramNotFound(program.0));
        }
        self.conn.execute(
            "UPDATE programs SET revision = revision + 1 WHERE id = ?1",
            params![program.0],
        )?;
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

    /// Lists xrefs pointing at `address`.
    pub fn xrefs_to(&self, program: ProgramId, address: &str) -> Result<Vec<XrefRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT src, dst, kind FROM xrefs WHERE program_id = ?1 AND dst = ?2 ORDER BY src",
        )?;
        let rows = stmt
            .query_map(params![program.0, address], map_xref)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Lists xrefs leaving `address`.
    pub fn xrefs_from(&self, program: ProgramId, address: &str) -> Result<Vec<XrefRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT src, dst, kind FROM xrefs WHERE program_id = ?1 AND src = ?2 ORDER BY dst",
        )?;
        let rows = stmt
            .query_map(params![program.0, address], map_xref)?
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
                r.address,
                r.function,
                r.kind,
                r.text
            ])?;
        }
        drop(stmt);
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
                    address: r.get(0)?,
                    function: r.get(1)?,
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
        address: r.get(0)?,
        name: r.get(1)?,
        external: r.get::<_, i64>(2)? != 0,
        source: r.get(3)?,
    })
}

fn map_function(r: &Row<'_>) -> rusqlite::Result<FunctionRow> {
    Ok(FunctionRow {
        entry: r.get(0)?,
        name: r.get(1)?,
        size: r.get(2)?,
        signature: r.get(3)?,
        calling_convention: r.get(4)?,
    })
}

fn map_xref(r: &Row<'_>) -> rusqlite::Result<XrefRow> {
    Ok(XrefRow {
        from: r.get(0)?,
        to: r.get(1)?,
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
            entry: "00400466".into(),
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
            entry: "00400000".into(),
            name: "FUN_00400000".into(),
            size: 4,
            signature: None,
            calling_convention: None,
        }];
        db.replace_functions(id, &rows).unwrap();
        let before = db.revision(id).unwrap();
        db.rename_function(id, "00400000", "main").unwrap();
        assert_eq!(db.revision(id).unwrap(), before + 1);
        assert_eq!(db.functions(id).unwrap()[0].name, "main");
    }

    #[test]
    fn comments_and_types_replace_atomically() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let cmts = vec![CommentRow {
            address: "00400488".into(),
            function: "00400466".into(),
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
    fn xref_directional_queries() {
        let db = ProjectDb::open_in_memory().unwrap();
        let id = db.upsert_program("p", "x86:LE:64:default", &prov()).unwrap();
        let rows = vec![XrefRow {
            from: "00400488".into(),
            to: "00400466".into(),
            kind: "UNCONDITIONAL_CALL".into(),
        }];
        db.replace_xrefs(id, &rows).unwrap();
        assert_eq!(db.xrefs_to(id, "00400466").unwrap().len(), 1);
        assert_eq!(db.xrefs_from(id, "00400488").unwrap().len(), 1);
        assert!(db.xrefs_to(id, "00400488").unwrap().is_empty());
    }
}
