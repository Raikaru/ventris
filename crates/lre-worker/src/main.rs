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
    child: Option<Child>,
    pub(crate) stdin: Option<ChildStdin>,
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
            child: Some(child),
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
    /// ArchitectureGhidra::buildSpecFile expects (pspec, cspec, tspec,
    /// corespec, in that order — see RegisterProgram::loadParameters).
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
        let _ = self.run_command(
            provider,
            "registerProgram",
            &[pspec.as_bytes(), cspec.as_bytes(), tspec.as_bytes(), corespec.as_bytes()],
        )?;
        Ok(())
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
        wire::encode_addr_element(&mut addr, space_index, offset);
        self.run_command(provider, "decompileAt", &[b"0", &addr])
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
        let _ = self.run_command(
            provider,
            "setAction",
            &[b"0", action.as_bytes(), print.as_bytes()],
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
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
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

/// the spec dir, and decompiles one function of a program in the store.
///
/// Usage:
///   lre-worker <ghidra_opt> <lang-dir> <binary> <program> <addr-hex> [--project DIR]
///
/// The language dir must contain the four spec documents (`dump_specs`
/// output) plus registers.txt; the program and its functions come from the
/// project store so the worker is the store-backed no-JVM decompiler.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!(
            "usage: lre-worker <ghidra_opt> <lang-dir> <binary> <program> <addr-hex> [--project DIR]"
        );
        std::process::exit(2);
    }
    let project = std::env::args()
        .position(|a| a == "--project")
        .and_then(|i| std::env::args().nth(i + 1))
        .unwrap_or_else(|| ".lre".into());
    if let Err(e) = run(&args[1], &args[2], &args[3], &args[4], &args[5], &project) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(
    ghidra_opt: &str,
    lang_dir: &str,
    binary: &str,
    program: &str,
    addr: &str,
    project: &str,
) -> Result<()> {
    let mut provider = provider::ProgramProvider::new(
        provider::BinaryBacking::from_file(Path::new(binary))?,
        0x400000, // image base; taken from the store when the importer records it
        Vec::new(),
    );
    provider.load_language_info(Path::new(lang_dir))?;

    // Function entries from the project store.
    let db = open_store(Path::new(project))?;
    let pid = db.program_id(program)?;
    for f in db.functions(pid)? {
        if let Ok(off) = u64::from_str_radix(f.entry.trim_start_matches("0x"), 16) {
            provider.functions.push(off);
            provider.function_names.insert(off, f.name);
            provider.function_sizes.insert(off, f.size as u64);
        }
    }

    let offset = u64::from_str_radix(addr.trim_start_matches("0x"), 16)
        .map_err(|e| WorkerError::Setup(e.to_string()))?;
    let specs = load_specs(Path::new(lang_dir))?;
    let mut worker = NativeWorker::launch(Path::new(ghidra_opt))?;
    worker.register_program(&mut provider, &specs.0, &specs.1, &specs.2, &specs.3)?;
    worker.set_action(&mut provider, "decompile", "")?;
    let ram = provider.ram_space_index as u32;
    let raw = worker.decompile_at(&mut provider, ram, offset)?;
    // The C text is printed by the C++ as <syntax> markup: every printable
    // token is an ATTRIB_CONTENT string (EmitMarkup::print, prettyprint.cc:
    // 311-317) in stream order. Concatenate them; the packed doc only wraps.
    let c_text = {
        let mut out = String::new();
        let mut p = 0usize;
        while p < raw.len() {
            let h = raw[p];
            p += 1;
            let k = h & 0xc0;
            if k == 0xc0 {
                let mut aid = (h & 0x1f) as u64;
                if h & 0x20 != 0 {
                    aid = (aid << 7) | (raw[p] & 0x7f) as u64;
                    p += 1;
                }
                let tb = raw[p];
                p += 1;
                let tc = tb >> 4;
                let ln = (tb & 0xf) as usize;
                let mut v = 0u64;
                for _ in 0..ln {
                    v = (v << 7) | (raw[p] & 0x7f) as u64;
                    p += 1;
                }
                if tc == 7 && aid == 1 && p + v as usize <= raw.len() {
                    out.push_str(&String::from_utf8_lossy(&raw[p..p + v as usize]));
                    p += v as usize;
                } else if tc == 7 {
                    p += v as usize;
                }
            } else if k == 0x40 || k == 0x80 {
                if h & 0x20 != 0 {
                    p += 1;
                }
            } else {
                p += 1;
            }
        }
        out
    };
    if std::env::var_os("WORKER_DUMP").is_some() {
        let mut f = std::fs::File::create("/tmp/ctext_dump.txt").unwrap();
        use std::io::Write as _;
        let _ = f.write_all(c_text.as_bytes());
    }
    println!("{c_text}");
    Ok(())
}
