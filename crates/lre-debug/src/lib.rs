//! Isolated, read-only debugger commands.
//!
//! Each request starts a fresh debugger subprocess with shell execution
//! disabled, a fixed command allowlist, and a deadline. The backend never
//! attaches to the API process and never exposes debugger mutation commands.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Gdb,
    Lldb,
}

impl BackendKind {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "gdb" => Ok(Self::Gdb),
            "lldb" => Ok(Self::Lldb),
            other => Err(DebugError::InvalidBackend(other.into())),
        }
    }

    pub fn executable(self) -> &'static str {
        match self {
            Self::Gdb => "gdb",
            Self::Lldb => "lldb",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebugCommand {
    Backtrace,
    Registers,
    Memory { address: u64, count: u32 },
}

impl DebugCommand {
    fn expressions(&self, kind: BackendKind) -> Result<Vec<String>> {
        let command = match (kind, self) {
            (_, Self::Backtrace) => "bt".into(),
            (BackendKind::Gdb, Self::Registers) => "info registers".into(),
            (BackendKind::Lldb, Self::Registers) => "register read".into(),
            (BackendKind::Gdb, Self::Memory { address, count }) => {
                validate_memory_count(*count)?;
                format!("x/{count}bx {address:#x}")
            }
            (BackendKind::Lldb, Self::Memory { address, count }) => {
                validate_memory_count(*count)?;
                format!("memory read --format x --size 1 --count {count} {address:#x}")
            }
        };
        let start = match kind {
            BackendKind::Gdb => "start",
            BackendKind::Lldb => "process launch --stop-at-entry",
        };
        Ok(vec![start.into(), command])
    }
}

fn validate_memory_count(count: u32) -> Result<()> {
    if count == 0 || count > 4096 {
        return Err(DebugError::InvalidMemoryCount(count));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugOutput {
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DebugError {
    #[error("unsupported debugger backend {0:?}")]
    InvalidBackend(String),
    #[error("program is not a regular file: {0}")]
    InvalidProgram(PathBuf),
    #[error("memory count must be between 1 and 4096 (got {0})")]
    InvalidMemoryCount(u32),
    #[error("debugger command failed to start: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("debugger I/O failed: {0}")]
    Io(#[source] std::io::Error),
    #[error("debugger timed out after {0:?}")]
    Timeout(Duration),
    #[error("debugger exited with status {status}: {stderr}")]
    Failed { status: i32, stderr: String },
    #[error("debugger output exceeded {0} bytes")]
    OutputTooLarge(usize),
}

pub type Result<T> = std::result::Result<T, DebugError>;

/// A target descriptor whose commands execute in isolated debugger children.
#[derive(Debug, Clone)]
pub struct DebugBackend {
    kind: BackendKind,
    program: PathBuf,
    timeout: Duration,
}

impl DebugBackend {
    pub fn new(kind: BackendKind, program: impl AsRef<Path>) -> Result<Self> {
        let program = program.as_ref().to_path_buf();
        if !program.is_file() {
            return Err(DebugError::InvalidProgram(program));
        }
        Ok(Self {
            kind,
            program,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(DebugError::Timeout(timeout));
        }
        self.timeout = timeout;
        Ok(self)
    }

    pub fn kind(&self) -> BackendKind {
        self.kind
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn execute(&self, command: DebugCommand) -> Result<DebugOutput> {
        let expressions = command.expressions(self.kind)?;
        let mut process = Command::new(self.kind.executable());
        process
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match self.kind {
            BackendKind::Gdb => {
                process.args(["--nx", "--quiet", "--batch"]);
                for expression in &expressions {
                    process.arg("-ex").arg(expression);
                }
            }
            BackendKind::Lldb => {
                process.args(["--no-lldbinit", "--batch"]);
                for expression in &expressions {
                    process.arg("-o").arg(expression);
                }
            }
        }
        process.arg(&self.program);

        let mut child = process.spawn().map_err(DebugError::Spawn)?;
        let started = Instant::now();
        loop {
            if child.try_wait().map_err(DebugError::Io)?.is_some() {
                let output = child.wait_with_output().map_err(DebugError::Io)?;
                return finish(output);
            }
            if started.elapsed() >= self.timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(DebugError::Timeout(self.timeout));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    pub fn backtrace(&self) -> Result<DebugOutput> {
        self.execute(DebugCommand::Backtrace)
    }

    pub fn registers(&self) -> Result<DebugOutput> {
        self.execute(DebugCommand::Registers)
    }

    pub fn memory(&self, address: u64, count: u32) -> Result<DebugOutput> {
        self.execute(DebugCommand::Memory { address, count })
    }
}

fn finish(output: std::process::Output) -> Result<DebugOutput> {
    if output.stdout.len() > MAX_OUTPUT_BYTES {
        return Err(DebugError::OutputTooLarge(MAX_OUTPUT_BYTES));
    }
    if output.stderr.len() > MAX_OUTPUT_BYTES {
        return Err(DebugError::OutputTooLarge(MAX_OUTPUT_BYTES));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        return Err(DebugError::Failed {
            status: output.status.code().unwrap_or(-1),
            stderr,
        });
    }
    Ok(DebugOutput { stdout, stderr })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_and_command_parsing_are_bounded() {
        assert_eq!(BackendKind::parse("GDB").unwrap(), BackendKind::Gdb);
        assert_eq!(BackendKind::parse("lldb").unwrap(), BackendKind::Lldb);
        assert!(BackendKind::parse("bash").is_err());
        assert_eq!(
            DebugCommand::Memory {
                address: 0x401000,
                count: 4,
            }
            .expressions(BackendKind::Gdb)
            .unwrap(),
            vec!["start", "x/4bx 0x401000"]
        );
        assert!(
            DebugCommand::Memory {
                address: 0,
                count: 0,
            }
            .expressions(BackendKind::Lldb)
            .is_err()
        );
    }

    #[test]
    fn target_must_be_a_regular_file() {
        let error = DebugBackend::new(BackendKind::Gdb, ".").unwrap_err();
        assert!(matches!(error, DebugError::InvalidProgram(_)));
    }

    #[test]
    fn timeout_rejects_zero() {
        let backend = DebugBackend::new(BackendKind::Gdb, "/bin/sh").unwrap();
        assert!(matches!(
            backend.with_timeout(Duration::ZERO),
            Err(DebugError::Timeout(Duration::ZERO))
        ));
    }
}
