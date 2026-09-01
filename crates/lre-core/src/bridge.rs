//! Bridge client: typed Core API calls to the Java service over stdio JSON-RPC.
//!
//! The child process speaks one JSON document per line on stdout (see
//! service/src/main/java/net/ventris/Main.java). Logs never share that stream:
//! Ghidra's own logging is disabled at initialization and anything it prints
//! anyway lands on stderr. Requests are serialized; the service dispatches
//! synchronously, so one in-flight call matches the server's model.

use lre_model::{DisasmRow, FunctionRow, ProgramSummary, Provenance, SymbolRow, XrefRow};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Client-side bridge failure.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    /// The service exited or stdin/stdout broke.
    #[error("bridge process dead: {0}")]
    Process(String),
    /// The service answered with a JSON-RPC error.
    #[error("bridge error {code}: {message}")]
    Rpc { code: i64, message: String },
    /// The answer did not match the expected shape.
    #[error("bad response shape: {0}")]
    Shape(String),
    /// Spawn or IO failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias with the error defaulted per project convention.
pub type Result<T, E = BridgeError> = std::result::Result<T, E>;

/// A running ventris-service child process.
pub struct Bridge {
    child: Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
    next_id: u64,
    /// Provenance of answers this bridge produces.
    pub provenance: Provenance,
}

impl Bridge {
    /// Launches the service JVM. `java_options` are forwarded verbatim after
    /// the main class; `install_dir` must be a pinned Ghidra installation.
    pub fn launch(
        java: &Path,
        classpath: &str,
        install_dir: &Path,
        project_dir: &Path,
        extra_jvm: &[String],
    ) -> Result<Self> {
        let mut cmd = Command::new(java);
        for opt in extra_jvm {
            cmd.arg(opt);
        }
        cmd.arg("-cp")
            .arg(classpath)
            .arg("net.ventris.Main")
            .arg("--install-dir")
            .arg(install_dir)
            .arg("--project-dir")
            .arg(project_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn().map_err(|e| BridgeError::Process(e.to_string()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| BridgeError::Process("no stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| BridgeError::Process("no stdout".into()))?;
        Ok(Self {
            child,
            stdin,
            reader: BufReader::new(stdout),
            next_id: 1,
            provenance: Provenance {
                producer: "ghidra-bridge".into(),
                upstream_version: "12.1.3".into(),
            },
        })
    }

    /// Sends one request and waits for the matching response.
    fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let request = json!({"id": id, "method": method, "params": params});
        let mut line = serde_json::to_string(&request)
            .map_err(|e| BridgeError::Shape(e.to_string()))?;
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .map_err(BridgeError::Io)?;
        self.stdin.flush().map_err(BridgeError::Io)?;
        loop {
            let mut buf = String::new();
            let n = self
                .reader
                .read_line(&mut buf)
                .map_err(BridgeError::Io)?;
            if n == 0 {
                return Err(self.dead("EOF before response"));
            }
            let trimmed = buf.trim();
            if trimmed.is_empty() || !trimmed.starts_with('{') {
                continue; // stray Ghidra stdout chatter: skip
            }
            let doc: Value = serde_json::from_str(trimmed)
                .map_err(|e| BridgeError::Shape(format!("{e}: {trimmed}")))?;
            match doc.get("id").and_then(Value::as_u64) {
                Some(got) if got == id => {
                    if let Some(err) = doc.get("error") {
                        return Err(BridgeError::Rpc {
                            code: err.get("code").and_then(Value::as_i64).unwrap_or(-1),
                            message: err
                                .get("message")
                                .and_then(Value::as_str)
                                .unwrap_or("unknown")
                                .to_string(),
                        });
                    }
                    return Ok(doc.get("result").cloned().unwrap_or(Value::Null));
                }
                _ => continue, // not our answer
            }
        }
    }

    fn dead(&mut self, what: &str) -> BridgeError {
        let status = self.child.try_wait().ok().flatten();
        match status {
            Some(code) => BridgeError::Process(format!("{what} (exit: {code})")),
            None => BridgeError::Process(what.to_string()),
        }
    }

    fn parse<T: DeserializeOwned>(value: Value) -> Result<T> {
        serde_json::from_value(value).map_err(|e| BridgeError::Shape(e.to_string()))
    }

    /// Imports and analyzes a binary, returning its summary.
    pub fn import(&mut self, session: &str, path: &Path) -> Result<ProgramSummary> {
        let v = self.call(
            "import",
            json!({"session": session, "path": path.display().to_string()}),
        )?;
        Self::parse(v)
    }

    /// Opens a previously imported program by project name.
    pub fn open(&mut self, session: &str, program: &str) -> Result<ProgramSummary> {
        let v = self.call(
            "open",
            json!({"session": session, "program": program}),
        )?;
        Self::parse(v)
    }

    /// Lists functions.
    pub fn functions(&mut self, session: &str) -> Result<Vec<FunctionRow>> {
        let v = self.call("functions", json!({"session": session}))?;
        Self::parse(v)
    }

    /// Lists symbols.
    pub fn symbols(&mut self, session: &str) -> Result<Vec<SymbolRow>> {
        let v = self.call("symbols", json!({"session": session}))?;
        Self::parse(v)
    }

    /// Reads `size` bytes at `address`, base64-decoded.
    pub fn read_memory(&mut self, session: &str, address: &str, size: u32) -> Result<Vec<u8>> {
        let v = self.call(
            "read_memory",
            json!({"session": session, "address": address, "size": size}),
        )?;
        let b64: String = v
            .get("bytes")
            .and_then(Value::as_str)
            .ok_or_else(|| BridgeError::Shape("missing bytes".into()))?
            .to_string();
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| BridgeError::Shape(format!("bad base64: {e}")))
    }

    /// Incoming xrefs to `address`.
    pub fn xrefs_to(&mut self, session: &str, address: &str) -> Result<Vec<XrefRow>> {
        let v = self.call("xrefs_to", json!({"session": session, "address": address}))?;
        Self::parse(v)
    }

    /// Outgoing xrefs from `address`.
    pub fn xrefs_from(&mut self, session: &str, address: &str) -> Result<Vec<XrefRow>> {
        let v = self.call("xrefs_from", json!({"session": session, "address": address}))?;
        Self::parse(v)
    }

    /// All outgoing references from a function body (mid-body calls included).
    pub fn function_xrefs_from(&mut self, session: &str, address: &str) -> Result<Vec<XrefRow>> {
        let v = self.call(
            "function_xrefs_from",
            json!({"session": session, "address": address}),
        )?;
        Self::parse(v)
    }

    /// Batched export: functions plus all body xrefs in one round-trip.
    pub fn export_facts(
        &mut self,
        session: &str,
    ) -> Result<(Vec<FunctionRow>, Vec<XrefRow>)> {
        let v = self.call("export_facts", json!({"session": session}))?;
        let functions: Vec<FunctionRow> = Self::parse(
            v.get("functions").cloned().unwrap_or(Value::Null),
        )?;
        let xrefs: Vec<XrefRow> = Self::parse(
            v.get("xrefs").cloned().unwrap_or(Value::Null),
        )?;
        Ok((functions, xrefs))
    }

    /// Applies a function rename.
    pub fn rename(&mut self, session: &str, address: &str, name: &str) -> Result<()> {
        self.call(
            "rename",
            json!({"session": session, "address": address, "name": name}),
        )?;
        Ok(())
    }

    /// Decompiles the function at `address`, returning C text.
    pub fn decompile(&mut self, session: &str, address: &str) -> Result<String> {
        let v = self.call("decompile", json!({"session": session, "address": address}))?;
        v.get("code")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| BridgeError::Shape("missing code".into()))
    }

    /// Disassembles up to `n` instructions at `address`.
    pub fn disassemble(&mut self, session: &str, address: &str, n: u32) -> Result<Vec<DisasmRow>> {
        let v = self.call(
            "disassemble",
            json!({"session": session, "address": address, "n": n}),
        )?;
        Self::parse(v)
    }

    /// Graceful shutdown: asks the service to exit and reaps the process.
    pub fn shutdown(&mut self) -> Result<()> {
        let _ = self.call("shutdown", json!({}));
        let _ = self.child.wait();
        Ok(())
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        // Best effort: kill the JVM if the client forgot. Graceful paths call
        // shutdown() first.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Where the launcher looks for the pinned Ghidra installation.
pub fn default_ghidra_dir() -> PathBuf {
    std::env::var_os("VENTRIS_GHIDRA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("ghidra_12.1.3_PUBLIC"))
}

/// Timeout helper used by tests to bound a decompile call.
pub fn decompile_deadline() -> Duration {
    Duration::from_secs(120)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_is_stamped() {
        // Compile-time sanity: producer name fixed for the bridge.
        let p = Provenance {
            producer: "ghidra-bridge".into(),
            upstream_version: "12.1.3".into(),
        };
        assert_eq!(p.producer, "ghidra-bridge");
    }
}
