//! The native decompiler worker (Stage 3 shell).
//!
//! Spawns the pinned `ghidra_opt` binary, speaks the burst/packed protocol
//! on its stdio, and answers its program queries from the project store
//! (`lre-db`) plus the raw binary via a read-only file mapping. This is the
//! no-JVM replacement for the Stage-1 bridge, per ADR-0001.

mod provider;
mod wire;

use lre_db::ProjectDb;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
pub use provider::{decode_addr_element, spec_dir, ProgramProvider};
use wire::{burst, decode_burst, encode_burst, encode_string_stream};

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
    child: Child,
    pub(crate) stdin: ChildStdin,
    pub(crate) stdout: ChildStdout,
    pub(crate) out_buf: Vec<u8>,
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
            child,
            stdin,
            stdout,
            out_buf: Vec::new(),
            binary: ghidra_opt.to_path_buf(),
        })
    }

    /// Sends `registerProgram` with the four spec XML documents the pinned
    /// ArchitectureGhidra::buildSpecFile expects (pspec, cspec, tspec,
    /// corespec, in that order — see RegisterProgram::loadParameters).
    pub fn register_program(
        &mut self,
        pspec: &str,
        cspec: &str,
        tspec: &str,
        corespec: &str,
    ) -> Result<()> {
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::COMMAND_OPEN);
        encode_string_stream(&mut buf, b"registerProgram");
        encode_string_stream(&mut buf, pspec.as_bytes());
        encode_string_stream(&mut buf, cspec.as_bytes());
        encode_string_stream(&mut buf, tspec.as_bytes());
        encode_string_stream(&mut buf, corespec.as_bytes());
        encode_burst(&mut buf, burst::COMMAND_CLOSE);
        self.stdin
            .write_all(&buf)
            .map_err(WorkerError::Io)?;
        self.stdin.flush().map_err(WorkerError::Io)?;
        self.read_command_response()
    }

    /// Sends `decompileAt` for `space:offset` and returns the C text.
    /// The address arrives as the packed-encoded `<addr>` element the
    /// pinned DecompileAt::loadParameters reads (space index + offset).
    pub fn decompile_at(&mut self, space_index: u32, offset: u64) -> Result<String> {
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::COMMAND_OPEN);
        encode_string_stream(&mut buf, b"decompileAt");
        // PackedEncode <addr> element: element id for ELEM_ADDR_ADDR family
        // is resolved by the decompiler; the Java side encodes the address
        // with AttributeId space + offset inside an <addr> element. We emit
        // element id 1 (addr) with SPACE and UNSIGNED_INT attributes; the
        // exact ids are wired to the decompiler's ElementId table, which
        // assigns them deterministically at startup.
        encode_addr_element(&mut buf, space_index, offset);
        encode_burst(&mut buf, burst::COMMAND_CLOSE);
        self.stdin.write_all(&buf).map_err(WorkerError::Io)?;
        self.stdin.flush().map_err(WorkerError::Io)?;

        // The decompiler will interleave queries (getBytes, symbols, ...).
        // This loop answers each one from the store until the command
        // response completes. The store-backed callbacks are the next task;
        // for now the loop only recognizes the response/exception frames and
        // fails loudly on anything else.
        loop {
            let code = self.next_burst()?;
            match code {
                burst::RESPONSE_OPEN => {
                    let text = self.read_string_stream()?;
                    let _ = self.expect_burst(burst::RESPONSE_CLOSE)?;
                    return Ok(String::from_utf8_lossy(&text).into_owned());
                }
                burst::EXCEP_OPEN => {
                    let msg = self.read_string_stream()?;
                    let _ = self.expect_burst(burst::EXCEP_CLOSE)?;
                    return Err(WorkerError::Decompiler(
                        String::from_utf8_lossy(&msg).into_owned(),
                    ));
                }
                burst::QUERY_OPEN => {
                    return Err(WorkerError::Protocol(
                        "program queries not yet wired (next task)".into(),
                    ));
                }
                other => {
                    return Err(WorkerError::Protocol(format!(
                        "unexpected burst 0x{other:x} waiting for response"
                    )));
                }
            }
        }
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

    /// Reads one string stream into a Vec, expecting `STRINGSTREAM_OPEN`.
    pub(crate) fn read_string_stream(&mut self) -> Result<Vec<u8>> {
        self.expect_burst(burst::STRINGSTREAM_OPEN)?;
        // Streams end at the close burst; NULs inside payload are possible
        // in byte streams but string payloads here are text or packed.
        let mut out = Vec::new();
        loop {
            let code = self.next_burst()?;
            if code == burst::STRINGSTREAM_CLOSE {
                return Ok(out);
            }
            // Payload bytes arrive as raw stream content; burst decoder
            // surfaces them one byte at a time (see decode_burst leniency).
            out.push(code);
        }
    }

    fn read_command_response(&mut self) -> Result<()> {
        loop {
            let code = self.next_burst()?;
            match code {
                burst::RESPONSE_OPEN => {
                    let _ = self.read_string_stream()?; // warnings stream
                    self.expect_burst(burst::RESPONSE_CLOSE)?;
                    return Ok(());
                }
                burst::EXCEP_OPEN => {
                    let msg = self.read_string_stream()?;
                    let _ = self.expect_burst(burst::EXCEP_CLOSE)?;
                    return Err(WorkerError::Decompiler(
                        String::from_utf8_lossy(&msg).into_owned(),
                    ));
                }
                other => {
                    return Err(WorkerError::Protocol(format!(
                        "unexpected burst 0x{other:x} in registerProgram response"
                    )));
                }
            }
        }
    }
}

impl Drop for NativeWorker {
    fn drop(&mut self) {
        // ghidra_opt exits when its stdin closes (readToAnyBurst exits on
        // EOF); take() drops the pipe, then we reap the child.
        // stdin is a ChildStdin (not Option): dropping it closes the pipe,
        // and ghidra_opt exits on EOF (readToAnyBurst).
        let _ = self.child.wait();
    }
}

/// Encodes the `<addr>` element in PackedFormat. Element/attribute ids here
/// must match the decompiler's ElementId/AttributeId tables; the spike
/// validates them before any store wiring.
fn encode_addr_element(out: &mut Vec<u8>, space_index: u32, offset: u64) {
    // ELEM_ADDR_ADDR id comes from the decompiler's AttributeId table; the
    // provisional value is validated by the differential test task.
    const ELEM_ADDR: u32 = 1;
    wire::encode_attribute_header(out, ELEM_ADDR, wire::attr_type::SPACE, if space_index == 0 { 0 } else { 1 });
    if space_index != 0 {
        wire::encode_packed_int(out, space_index as u64);
    }
    wire::encode_attribute_header(out, ELEM_ADDR, wire::attr_type::UNSIGNED_INT, 1);
    wire::encode_packed_int(out, offset);
    out.push(wire::ELEMENT_END | (ELEM_ADDR as u8 & 0x1f));
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
        read("x86-64.pspec")?,
        read("x86-64-gcc.cspec")?,
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
        // Frame: burst(2) "registerProgram" 4 string streams burst(3).
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::COMMAND_OPEN);
        encode_string_stream(&mut buf, b"registerProgram");
        encode_string_stream(&mut buf, b"<p/>");
        encode_string_stream(&mut buf, b"<c/>");
        encode_string_stream(&mut buf, b"<t/>");
        encode_string_stream(&mut buf, b"<k/>");
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

/// Smoke entry: launches the pinned ghidra_opt, registers the program from
/// the spec dir, and decompiles one address passed as args.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: lre-worker <ghidra_opt> <lang-dir> <addr-hex>");
        std::process::exit(2);
    }
    if let Err(e) = run(&args[1], &args[2], &args[3]) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(ghidra_opt: &str, lang_dir: &str, addr: &str) -> Result<()> {
    let (pspec, cspec) = {
        let read = |n: &str| -> Result<String> {
            std::fs::read_to_string(Path::new(lang_dir).join(n))
                .map_err(|e| WorkerError::Setup(format!("{n}: {e}")))
        };
        (read("x86-64.pspec")?, read("x86-64-gcc.cspec")?)
    };
    let mut worker = NativeWorker::launch(Path::new(ghidra_opt))?;
    let _ = worker.register_program(&pspec, &cspec, "", "")?;
    let offset = u64::from_str_radix(addr.trim_start_matches("0x"), 16)
        .map_err(|e| WorkerError::Setup(e.to_string()))?;
    let text = worker.decompile_at(0, offset)?;
    println!("{text}");
    Ok(())
}
