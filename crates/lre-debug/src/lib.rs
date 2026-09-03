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
    #[error("Dolphin GDB connection failed: {0}")]
    RemoteConnect(#[source] std::io::Error),
    #[error("Dolphin GDB I/O failed: {0}")]
    RemoteIo(#[source] std::io::Error),
    #[error("Dolphin GDB protocol error: {0}")]
    RemoteProtocol(String),
    #[error("Dolphin GDB target error: {0}")]
    RemoteTarget(String),
    #[error("Dolphin GDB memory count must be between 1 and 1048576 (got {0})")]
    RemoteMemoryCount(usize),
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

const MAX_REMOTE_MEMORY_BYTES: usize = 1024 * 1024;
const DEFAULT_REMOTE_TIMEOUT: Duration = Duration::from_secs(5);

/// Read-only client for Dolphin's GDB remote-serial-protocol stub.
///
/// The client deliberately exposes only memory reads. It sends the ordinary
/// acknowledged `mADDR,LENGTH` request and never exposes execution or
/// register-write operations to callers.
#[derive(Debug)]
pub struct DolphinGdb {
    stream: std::net::TcpStream,
}

impl DolphinGdb {
    /// Connects to an endpoint such as `127.0.0.1:24689`.
    pub fn connect(endpoint: &str) -> Result<Self> {
        Self::connect_with_timeout(endpoint, DEFAULT_REMOTE_TIMEOUT)
    }

    /// Connects to an endpoint with explicit connect and I/O deadlines.
    pub fn connect_with_timeout(endpoint: &str, timeout: Duration) -> Result<Self> {
        let mut addresses = std::net::ToSocketAddrs::to_socket_addrs(&endpoint)
            .map_err(DebugError::RemoteConnect)?;
        let address = addresses.next().ok_or_else(|| {
            DebugError::RemoteProtocol(format!("endpoint has no addresses: {endpoint}"))
        })?;
        Self::connect_addr(address, timeout)
    }

    /// Connects to a resolved socket address.
    pub fn connect_addr(address: std::net::SocketAddr, timeout: Duration) -> Result<Self> {
        let stream = std::net::TcpStream::connect_timeout(&address, timeout)
            .map_err(DebugError::RemoteConnect)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(DebugError::RemoteConnect)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(DebugError::RemoteConnect)?;
        Ok(Self { stream })
    }

    /// Reads `count` bytes from the target's address space.
    pub fn read_memory(&mut self, address: u64, count: usize) -> Result<Vec<u8>> {
        validate_remote_memory_count(count)?;
        let command = format!("m{address:x},{count:x}");
        let response = self.request(command.as_bytes())?;
        if response.first() == Some(&b'E') {
            return Err(DebugError::RemoteTarget(
                String::from_utf8_lossy(&response).into_owned(),
            ));
        }
        if response == b"OK" {
            return Err(DebugError::RemoteProtocol(
                "memory read returned OK without data".into(),
            ));
        }
        if response.len() != count * 2 {
            return Err(DebugError::RemoteProtocol(format!(
                "memory read returned {} hex digits, expected {}",
                response.len(),
                count * 2
            )));
        }
        let mut bytes = Vec::with_capacity(count);
        for pair in response.chunks_exact(2) {
            let high = hex_digit(pair[0]).ok_or_else(|| {
                DebugError::RemoteProtocol("memory response contains non-hex data".into())
            })?;
            let low = hex_digit(pair[1]).ok_or_else(|| {
                DebugError::RemoteProtocol("memory response contains non-hex data".into())
            })?;
            bytes.push((high << 4) | low);
        }
        Ok(bytes)
    }

    fn request(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let frame = encode_remote_packet(payload);
        std::io::Write::write_all(&mut self.stream, &frame).map_err(DebugError::RemoteIo)?;
        std::io::Write::flush(&mut self.stream).map_err(DebugError::RemoteIo)?;
        let response = self.read_packet()?;
        std::io::Write::write_all(&mut self.stream, b"+").map_err(DebugError::RemoteIo)?;
        std::io::Write::flush(&mut self.stream).map_err(DebugError::RemoteIo)?;
        Ok(response)
    }

    fn read_packet(&mut self) -> Result<Vec<u8>> {
        loop {
            let start = read_remote_byte(&mut self.stream)?;
            match start {
                b'+' => continue,
                b'-' => {
                    return Err(DebugError::RemoteProtocol(
                        "remote rejected the request packet".into(),
                    ));
                }
                b'$' => break,
                other => {
                    return Err(DebugError::RemoteProtocol(format!(
                        "expected packet start, got 0x{other:02x}"
                    )));
                }
            }
        }

        let mut encoded = Vec::new();
        let mut checksum = 0u8;
        let mut escaped = false;
        loop {
            let byte = read_remote_byte(&mut self.stream)?;
            if byte == b'#' && !escaped {
                break;
            }
            checksum = checksum.wrapping_add(byte);
            encoded.push(byte);
            if escaped {
                escaped = false;
            } else {
                escaped = byte == b'}';
            }
        }
        let high = hex_digit(read_remote_byte(&mut self.stream)?) .ok_or_else(|| {
            DebugError::RemoteProtocol("packet checksum has a non-hex high digit".into())
        })?;
        let low = hex_digit(read_remote_byte(&mut self.stream)?) .ok_or_else(|| {
            DebugError::RemoteProtocol("packet checksum has a non-hex low digit".into())
        })?;
        let expected = (high << 4) | low;
        if checksum != expected {
            return Err(DebugError::RemoteProtocol(format!(
                "packet checksum mismatch: calculated {checksum:02x}, received {expected:02x}"
            )));
        }

        let mut payload = Vec::with_capacity(encoded.len());
        let mut escaped = false;
        for byte in encoded {
            if escaped {
                payload.push(byte ^ 0x20);
                escaped = false;
            } else if byte == b'}' {
                escaped = true;
            } else {
                payload.push(byte);
            }
        }
        if escaped {
            return Err(DebugError::RemoteProtocol(
                "packet ends with an escape byte".into(),
            ));
        }
        Ok(payload)
    }
}

fn validate_remote_memory_count(count: usize) -> Result<()> {
    if count == 0 || count > MAX_REMOTE_MEMORY_BYTES {
        return Err(DebugError::RemoteMemoryCount(count));
    }
    Ok(())
}

fn encode_remote_packet(payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(payload.len() + 4);
    encoded.push(b'$');
    let mut checksum = 0u8;
    for &byte in payload {
        let escaped = matches!(byte, b'$' | b'#' | b'}' | b'*');
        let transmitted = if escaped { byte ^ 0x20 } else { byte };
        if escaped {
            encoded.push(b'}');
            checksum = checksum.wrapping_add(b'}');
        }
        checksum = checksum.wrapping_add(transmitted);
        encoded.push(transmitted);
    }
    encoded.extend_from_slice(format!("#{checksum:02x}").as_bytes());
    encoded
}

fn read_remote_byte(stream: &mut std::net::TcpStream) -> Result<u8> {
    let mut byte = [0u8; 1];
    std::io::Read::read_exact(stream, &mut byte).map_err(DebugError::RemoteIo)?;
    Ok(byte[0])
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod remote_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn read_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
        let mut start = [0u8; 1];
        stream.read_exact(&mut start).unwrap();
        assert_eq!(start[0], b'$');
        let mut payload = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).unwrap();
            if byte[0] == b'#' {
                break;
            }
            payload.push(byte[0]);
        }
        let mut checksum = [0u8; 2];
        stream.read_exact(&mut checksum).unwrap();
        payload
    }

    #[test]
    fn reads_memory_using_acknowledged_rsp() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert_eq!(read_request(&mut stream), b"m1000,4");
            stream.write_all(b"+").unwrap();
            stream.write_all(&encode_remote_packet(b"01020304")).unwrap();
            let mut ack = [0u8; 1];
            stream.read_exact(&mut ack).unwrap();
            assert_eq!(ack[0], b'+');
        });

        let mut client = DolphinGdb::connect_addr(address, Duration::from_secs(1)).unwrap();
        assert_eq!(client.read_memory(0x1000, 4).unwrap(), vec![1, 2, 3, 4]);
        server.join().unwrap();
    }

    #[test]
    fn rejects_bad_checksum() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut stream);
            let mut frame = encode_remote_packet(b"00");
            let last = frame.len() - 1;
            frame[last] = if frame[last] == b'0' { b'1' } else { b'0' };
            stream.write_all(&frame).unwrap();
        });

        let mut client = DolphinGdb::connect_addr(address, Duration::from_secs(1)).unwrap();
        let error = client.read_memory(0x10, 1).unwrap_err();
        assert!(matches!(error, DebugError::RemoteProtocol(message) if message.contains("checksum mismatch")));
        server.join().unwrap();
    }

    #[test]
    fn surfaces_target_error_and_bounds_reads() {
        assert!(matches!(
            validate_remote_memory_count(0),
            Err(DebugError::RemoteMemoryCount(0))
        ));
        assert!(matches!(
            validate_remote_memory_count(MAX_REMOTE_MEMORY_BYTES + 1),
            Err(DebugError::RemoteMemoryCount(_))
        ));

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_request(&mut stream);
            stream.write_all(&encode_remote_packet(b"E14")).unwrap();
        });
        let mut client = DolphinGdb::connect_addr(address, Duration::from_secs(1)).unwrap();
        assert!(matches!(
            client.read_memory(0x10, 1),
            Err(DebugError::RemoteTarget(message)) if message == "E14"
        ));
        server.join().unwrap();
    }
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
