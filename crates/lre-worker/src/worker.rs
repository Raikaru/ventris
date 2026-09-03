//! The native decompiler worker client: ghidra_opt as a supervised child
//! process speaking the burst/packed protocol (WORKER-001 extraction — the
//! protocol client is now a library so sessions can pool/lease/restart it).
//!
//! Spawns the pinned `ghidra_opt` binary, speaks the burst/packed protocol
//! on its stdio, and answers its program queries from the project store
//! (`lre-db`) plus the raw binary via a read-only file mapping. This is the
//! no-JVM replacement for the Stage-1 bridge, per ADR-0001.

use lre_db::ProjectDb;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::provider::ProgramProvider;
use crate::wire::{burst, decode_burst, encode_addr_element};
#[cfg(test)]
use crate::wire::{encode_burst, encode_string_stream};

/// Worker failure.
#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    /// Process spawn or pipe failure.
    #[error("worker process: {0}")]
    Process(String),
    /// The decompiler answered with an exception burst.
    #[error("decompiler exception: {0}")]
    Decompiler(String),
    /// Protocol violation (wrong burst sequence).
    #[error("protocol: {0}")]
    Protocol(String),
    /// The pinned binary or specs are missing.
    #[error("setup: {0}")]
    Setup(String),
    /// Underlying IO.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Store failure while serving callbacks.
    #[error("store: {0}")]
    Store(#[from] lre_db::DbError),
}

/// Convenience alias with the error defaulted per project convention.
pub type Result<T, E = WorkerError> = std::result::Result<T, E>;

/// A running `ghidra_opt` child with one registered program.
pub struct NativeWorker {
    /// The child, behind a mutex so a watchdog thread can kill it (deadline
    /// semantics, WORKER-002) while the protocol read is blocked.
    child: std::sync::Arc<std::sync::Mutex<Option<Child>>>,
    pub(crate) stdin: Option<ChildStdin>,
    pub(crate) stdout: ChildStdout,
    pub(crate) out_buf: Vec<u8>,
    /// Architecture slot returned by registerProgram.
    arch_id: i32,
    /// Path passed to ghidra_opt for diagnostics.
    pub binary: PathBuf,
}

impl NativeWorker {
    /// Spawns `ghidra_opt` from the pinned build.
    pub fn launch(ghidra_opt: &Path) -> Result<Self> {
        let mut child = Command::new(ghidra_opt)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| WorkerError::Process(e.to_string()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| WorkerError::Process("no stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| WorkerError::Process("no stdout".into()))?;
        Ok(Self {
            child: std::sync::Arc::new(std::sync::Mutex::new(Some(child))),
            arch_id: 0,
            stdin: Some(stdin),
            stdout,
            out_buf: Vec::new(),
            binary: ghidra_opt.to_path_buf(),
        })
    }

    /// Writes one complete frame to the child's stdin.
    pub(crate) fn write_frame(&mut self, buf: &[u8]) -> Result<()> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| WorkerError::Process("stdin closed".into()))?;
        stdin.write_all(buf).map_err(WorkerError::Io)?;
        stdin.flush().map_err(WorkerError::Io)?;
        if let Ok(log) = std::env::var("WORKER_LOG") {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
                .unwrap();
            use std::io::Write as _;
            let _ = writeln!(
                f,
                "--> {}",
                buf.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
        }
        Ok(())
    }

    /// Sends `registerProgram` with the four spec XML documents the pinned
    /// ArchitectureGhidra::buildSpecFile expects plus a packed function-shell
    /// document. The empty shell document preserves the old lazy symbol
    /// lookup behavior for pooled callers.
    ///
    /// The native program queries are answered by `provider` during
    /// registration (getBytes, getRegister, ...) exactly as during any
    /// other command.
    pub fn register_program(
        &mut self,
        provider: &mut ProgramProvider,
        pspec: &str,
        cspec: &str,
        tspec: &str,
        corespec: &str,
    ) -> Result<()> {
        let shell = Self::encode_function_shell_doc(provider.ram_space_index as u32, &[]);
        self.register_program_with_shell(provider, pspec, cspec, tspec, corespec, &shell)
    }

    /// Sends `registerProgram` with one or more preloaded function shells.
    /// Shells are symbol-table backed by the native process, which lets the
    /// subsequent `setFunctionSignature` command apply a full C prototype.
    pub fn register_program_with_shell(
        &mut self,
        provider: &mut ProgramProvider,
        pspec: &str,
        cspec: &str,
        tspec: &str,
        corespec: &str,
        function_shell: &[u8],
    ) -> Result<()> {
        let response = self.run_command(
            provider,
            "registerProgram",
            &[
                pspec.as_bytes(),
                cspec.as_bytes(),
                tspec.as_bytes(),
                corespec.as_bytes(),
                function_shell,
            ],
        )?;
        self.arch_id = std::str::from_utf8(&response)
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .ok_or_else(|| WorkerError::Protocol("registerProgram returned no architecture id".into()))?;
        Ok(())
    }

    /// Applies a C declaration to a preloaded function through the native
    /// decompiler's own prototype parser.
    pub fn set_function_signature(
        &mut self,
        provider: &mut ProgramProvider,
        function_address: u64,
        function_name: &str,
        signature: &str,
    ) -> Result<()> {
        let arch_id = self.arch_id.to_string();
        let address = format!("{function_address:x}");
        let signature = signature.trim();
        let normalized = if signature.ends_with(';') {
            signature.to_owned()
        } else {
            format!("{signature};")
        };
        let response = self.run_command(
            provider,
            "setFunctionSignature",
            &[
                arch_id.as_bytes(),
                function_name.as_bytes(),
                normalized.as_bytes(),
                address.as_bytes(),
            ],
        )?;
        if !response.is_empty() {
            return Err(WorkerError::Decompiler(
                String::from_utf8_lossy(&response).trim().to_string(),
            ));
        }
        Ok(())
    }

    /// Encodes the packed document accepted as registerProgram's fifth
    /// parameter. Entries are `(RAM address, function name, byte size)`.
    pub fn encode_function_shell_doc(
        space_index: u32,
        entries: &[(u64, &str, u64)],
    ) -> Vec<u8> {
        let mut doc = Vec::new();
        crate::wire::encode_header(&mut doc, crate::wire::ELEMENT_START, crate::wire::elem::DOC);
        for (offset, name, size) in entries {
            crate::wire::encode_header(
                &mut doc,
                crate::wire::ELEMENT_START,
                crate::wire::elem::MAPSYM,
            );
            crate::wire::encode_header(
                &mut doc,
                crate::wire::ELEMENT_START,
                crate::wire::elem::FUNCTIONSHELL,
            );
            crate::wire::encode_string_attribute(&mut doc, crate::wire::attr::NAME, name.as_bytes());
            crate::wire::encode_string_attribute(&mut doc, crate::wire::attr::LABEL, name.as_bytes());
            crate::wire::encode_header(
                &mut doc,
                crate::wire::ELEMENT_END,
                crate::wire::elem::FUNCTIONSHELL,
            );
            crate::wire::encode_addr_element_size(&mut doc, space_index, *offset, *size);
            crate::wire::encode_header(
                &mut doc,
                crate::wire::ELEMENT_START,
                crate::wire::elem::RANGELIST,
            );
            crate::wire::encode_header(
                &mut doc,
                crate::wire::ELEMENT_END,
                crate::wire::elem::RANGELIST,
            );
            crate::wire::encode_header(
                &mut doc,
                crate::wire::ELEMENT_END,
                crate::wire::elem::MAPSYM,
            );
        }
        crate::wire::encode_header(&mut doc, crate::wire::ELEMENT_END, crate::wire::elem::DOC);
        doc
    }

    /// Frame shape per DecompileProcess.sendCommandTimeout (Java client):
    /// command name, then the arch id as a string stream, then the packed
    /// `<addr>` parameter, then command close. The C++ base
    /// GhidraCommand::loadParameters (ghidra_process.cc:82-97) reads that
    /// arch-id frame first, so omitting it kills the command.
    pub fn decompile_at(
        &mut self,
        provider: &mut ProgramProvider,
        space_index: u32,
        offset: u64,
    ) -> Result<Vec<u8>> {
        let mut addr = Vec::new();
        encode_addr_element(&mut addr, space_index, offset);
        let arch_id = self.arch_id.to_string();
        self.run_command(provider, "decompileAt", &[arch_id.as_bytes(), &addr])
    }

    /// Selects the decompiler action root (Java: `setAction "decompile" ""`),
    /// which also enables C-code printing on the result. Without it the
    /// default action name leaves the raw C out of the response.
    pub fn set_action(
        &mut self,
        provider: &mut ProgramProvider,
        action: &str,
        print: &str,
    ) -> Result<()> {
        let arch_id = self.arch_id.to_string();
        let _ = self.run_command(
            provider,
            "setAction",
            &[arch_id.as_bytes(), action.as_bytes(), print.as_bytes()],
        )?;
        Ok(())
    }

    pub(crate) fn next_burst(&mut self) -> Result<u8> {
        let mut pos = 0usize;
        loop {
            if let Some(code) = decode_burst(&self.out_buf, &mut pos) {
                self.out_buf.drain(..pos);
                return Ok(code);
            }
            pos = 0;
            let mut chunk = [0u8; 4096];
            let n = self.stdout.read(&mut chunk).map_err(WorkerError::Io)?;
            if n == 0 {
                return Err(WorkerError::Process("decompiler died".into()));
            }
            if let Ok(log) = std::env::var("WORKER_LOG") {
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log)
                    .unwrap();
                use std::io::Write as _;
                let _ = writeln!(
                    f,
                    "<-- {}",
                    chunk[..n].iter().map(|b| format!("{b:02x}")).collect::<String>()
                );
            }
            self.out_buf.extend_from_slice(&chunk[..n]);
        }
    }

    pub(crate) fn expect_burst(&mut self, want: u8) -> Result<()> {
        let got = self.next_burst()?;
        if got != want {
            return Err(WorkerError::Protocol(format!(
                "expected burst 0x{want:x}, got 0x{got:x}"
            )));
        }
        Ok(())
    }

    /// Reads the payload of a string stream whose 0x0e open burst was
    /// already consumed, up to the close burst (0x0f), answering any
    /// query the decompiler interleaves mid-stream. This mirrors the Java
    /// readResponse loop: the C++ encodes the result via packed element
    /// writes that themselves trigger client queries (e.g. namespaces),
    /// which arrive as 0x04 frames between result bytes.
    pub(crate) fn read_string_payload(&mut self, provider: &mut ProgramProvider) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let byte = self.raw_byte()?;
            if byte == 0 {
                // Structural burst: skip NULs, expect 0x01 then a code.
                let code = loop {
                    let b = self.raw_byte()?;
                    if b == 0 {
                        continue;
                    }
                    if b != 1 {
                        return Err(WorkerError::Protocol(format!(
                            "malformed burst under payload (got 0x{b:x})"
                        )));
                    }
                    break self.raw_byte()?;
                };
                match code {
                    burst::STRINGSTREAM_CLOSE => return Ok(out),
                    burst::QUERY_OPEN => {
                        // Queries inside the result stream are answered and
                        // the ingest continues (Java readResponse, same).
                        self.answer_query(provider)?;
                    }
                    other => {
                        let tail: Vec<String> = out
                            .iter()
                            .rev()
                            .take(24)
                            .rev()
                            .map(|b| format!("{b:02x}"))
                            .collect();
                        return Err(WorkerError::Protocol(format!(
                            "unexpected burst 0x{other:x} in payload (tail: {})",
                            tail.join("")
                        )));
                    }
                }
            } else {
                out.push(byte);
            }
        }
    }

    /// Reads one raw byte from the child's stdout, blocking until data.
    pub(crate) fn raw_byte(&mut self) -> Result<u8> {
        loop {
            if let Some(b) = self.out_buf.first().copied() {
                self.out_buf.drain(..1);
                return Ok(b);
            }
            let mut chunk = [0u8; 4096];
            let n = self.stdout.read(&mut chunk).map_err(WorkerError::Io)?;
            if n == 0 {
                return Err(WorkerError::Process("decompiler died".into()));
            }
            if let Ok(log) = std::env::var("WORKER_LOG") {
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log)
                    .unwrap();
                use std::io::Write as _;
                let _ = writeln!(
                    f,
                    "<-- {}",
                    chunk[..n].iter().map(|b| format!("{b:02x}")).collect::<String>()
                );
            }
            self.out_buf.extend_from_slice(&chunk[..n]);
        }
    }

    pub(crate) fn read_string_stream(&mut self) -> Result<Vec<u8>> {
        self.expect_burst(burst::STRINGSTREAM_OPEN)?;
        // Query answers need the provider for interleaved queries; the
        // plain read_string_stream is only used by answer paths, where the
        // payload is the query's own data (no nested queries to expect).
        self.read_payload_plain()
    }

    /// Payload read without provider support (query payloads).
    pub(crate) fn read_payload_plain(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let byte = self.raw_byte()?;
            if byte == 0 {
                let code = loop {
                    let b = self.raw_byte()?;
                    if b == 0 {
                        continue;
                    }
                    if b != 1 {
                        return Err(WorkerError::Protocol(format!(
                            "malformed burst under payload (got 0x{b:x})"
                        )));
                    }
                    break self.raw_byte()?;
                };
                if code == burst::STRINGSTREAM_CLOSE {
                    return Ok(out);
                }
                return Err(WorkerError::Protocol(format!(
                    "unexpected burst 0x{code:x} in plain payload"
                )));
            }
            out.push(byte);
        }
    }

    /// Reads raw payload bytes until a burst with the given code. Used for
    /// the warnings frame (ghidra_process.cc:146-148) which carries the
    /// text unwrapped between the 0x10 and 0x11 markers.
    pub(crate) fn read_until(&mut self, code: u8) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let got = self.next_burst()?;
            if got == code {
                return Ok(out);
            }
            out.push(got);
        }
    }

}

impl Drop for NativeWorker {
    fn drop(&mut self) {
        // Closing our side of the stdin pipe makes ghidra_opt exit on EOF
        // (readToAnyBurst, ghidra_arch.cc:96), so wait() cannot block on a
        // live child holding the pipe. The child may be mid-query with
        // nothing to answer; closing stdin is the only guaranteed exit.
        drop(self.stdin.take());
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut child) = guard.take() {
                let _ = child.wait();
            }
        }
    }
}

impl NativeWorker {
    /// A handle a watchdog can use to kill the child from another thread
    /// (deadline semantics).
    pub fn kill_handle(&self) -> std::sync::Arc<std::sync::Mutex<Option<Child>>> {
        self.child.clone()
    }

    /// Kills the child immediately (used when a deadline was exceeded).
    pub fn kill(&mut self) -> Result<()> {
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut c) = guard.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
        Ok(())
    }

    /// The child's process id, when alive (diagnostics/tests).
    pub fn pid(&self) -> Option<u32> {
        self.child
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|c| c.id()))
    }
}

/// Verifies the pinned build is present; called before launch.
pub fn check_setup(ghidra_opt: &Path, sla_path: &Path) -> Result<()> {
    for p in [ghidra_opt, sla_path] {
        if !p.is_file() {
            return Err(WorkerError::Setup(format!("missing: {}", p.display())));
        }
    }
    Ok(())
}

/// Loads the four spec documents from a language directory laid out like
/// the spike tree (pspec, cspec, sleigh tspec, coretypes).
pub fn load_specs(lang_dir: &Path) -> Result<(String, String, String, String)> {
    let read = |name: &str| -> Result<String> {
        std::fs::read_to_string(lang_dir.join(name))
            .map_err(|e| WorkerError::Setup(format!("{name}: {e}")))
    };
    Ok((
        read("pspec.xml")?,
        read("cspec.xml")?,
        read("tspec.xml")?,
        read("coretypes.xml")?,
    ))
}

/// Opens (or creates) the store the callbacks will read facts from.
pub fn open_store(project_dir: &Path) -> Result<ProjectDb> {
    Ok(ProjectDb::open(&project_dir.join("project.sqlite"))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_program_frame_shape() {
        // Frame: burst(2) "registerProgram" 4 XML streams, one packed
        // function-shell stream, then burst(3).
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::COMMAND_OPEN);
        encode_string_stream(&mut buf, b"registerProgram");
        encode_string_stream(&mut buf, b"<p/>");
        encode_string_stream(&mut buf, b"<c/>");
        encode_string_stream(&mut buf, b"<t/>");
        encode_string_stream(&mut buf, b"<k/>");
        encode_string_stream(&mut buf, &NativeWorker::encode_function_shell_doc(3, &[]));
        encode_burst(&mut buf, burst::COMMAND_CLOSE);
        // Spot-check the ordering of markers.
        assert_eq!(&buf[3..4], &[burst::COMMAND_OPEN]);
        assert!(buf.windows(15).any(|w| w == b"registerProgram"));
        assert_eq!(*buf.last().unwrap(), burst::COMMAND_CLOSE);
    }

    #[test]
    fn check_setup_rejects_missing_binary() {
        let err = check_setup(Path::new("/nonexistent/ghidra_opt"), Path::new("/tmp"))
            .unwrap_err();
        assert!(matches!(err, WorkerError::Setup(_)));
    }
}
