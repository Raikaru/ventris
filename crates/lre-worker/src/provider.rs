//! Program-provider callbacks.
//!
//! While a command (e.g. `decompileAt`) runs, the pinned decompiler issues
//! *queries* on the same stdio pair (burst 0x04 … 0x05), and our answers
//! (0x08 … 0x09) are its only view of the program — this is exactly what
//! `ArchitectureGhidra` does on the Java side. Each callback mirrors one
//! query function from ghidra_arch.cc.

use crate::wire::{self, burst, encode_burst, encode_string_stream};
use crate::{NativeWorker, Result, WorkerError};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Read-only bytes of the analyzed binary, resolved at file offsets.
#[derive(Clone)]
pub struct BinaryBacking {
    data: Arc<Vec<u8>>,
}

impl BinaryBacking {
    /// Reads the whole binary. (Spec 8.4 mmap comes with the memory-layer
    /// refactor; a shared owned buffer is correct for the spike-sized
    /// fixtures and keeps `unsafe` out of this crate.)
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)
            .map_err(|e| WorkerError::Setup(format!("{}: {e}", path.display())))?;
        Ok(Self { data: Arc::new(data) })
    }

    /// Bytes at `vaddr` honoring the raw image base the worker registered.
    pub fn slice_at(&self, vaddr: u64, size: u64, base: u64) -> Option<&[u8]> {
        let start = usize::try_from(vaddr.checked_sub(base)?).ok()?;
        let end = start.checked_add(usize::try_from(size).ok()?)?;
        self.data.get(start..end)
    }
}

/// Program facts the callbacks serve: binary bytes + function entries from
/// the store. Types/comments/context answer empty for now — the decompiler
/// treats missing data as "unknown", which is the honest state.
pub struct ProgramProvider {
    pub backing: BinaryBacking,
    /// Raw image base (ELF fixture: 0x400000).
    pub base: u64,
    /// Function entry addresses, sorted.
    pub functions: Vec<u64>,
    /// Track which space index `ram` occupies once the tspec registers it.
    pub ram_space_index: i64,
}

impl ProgramProvider {
    pub fn new(backing: BinaryBacking, base: u64, functions: Vec<u64>) -> Self {
        let mut functions = functions;
        functions.sort_unstable();
        Self { backing, base, functions, ram_space_index: 0 }
    }
}

impl NativeWorker {
    /// Drives one full command lifecycle, answering every query the
    /// decompiler interleaves. Returns the command's own response text.
    pub fn run_command(
        &mut self,
        provider: &mut ProgramProvider,
        command: &str,
        params: &[&[u8]],
    ) -> Result<String> {
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::COMMAND_OPEN);
        encode_string_stream(&mut buf, command.as_bytes());
        for p in params {
            encode_string_stream(&mut buf, p);
        }
        encode_burst(&mut buf, burst::COMMAND_CLOSE);
        self.stdin.write_all(&buf).map_err(WorkerError::Io)?;
        self.stdin.flush().map_err(WorkerError::Io)?;

        loop {
            let code = self.next_burst()?;
            match code {
                burst::QUERY_OPEN => self.answer_query(provider)?,
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
                other => {
                    return Err(WorkerError::Protocol(format!(
                        "unexpected burst 0x{other:x} in command stream"
                    )));
                }
            }
        }
    }

    /// Dispatches one query. The query name arrives as the first string
    /// stream inside the query (packed command element, ghidra_arch.cc).
    fn answer_query(&mut self, provider: &mut ProgramProvider) -> Result<()> {
        let name = self.read_string_stream()?;
        let name = String::from_utf8_lossy(&name).into_owned();
        match name.as_str() {
            "command_getbytes" => self.answer_getbytes(provider),
            // Legitimately-empty callbacks: an empty query response means
            // "no data", which every query fn in ghidra_arch.cc treats as
            // a non-fatal unknown.
            "command_getmappedsymbols" | "command_gettrackedregisters"
            | "command_getregister" | "command_getregistername"
            | "command_getdatatype" | "command_getcomments"
            | "command_getcallfixup" | "command_getcallmech"
            | "command_getcallotherfixup" | "command_getpcode"
            | "command_getpcodeexecutable" | "command_getuseropname"
            | "command_getnamespacepath" | "command_getexternalref"
            | "command_getcpoolref" | "command_getcodelabel"
            | "command_getstringdata" | "command_isnameused" => self.answer_empty(),
            other => {
                // Unknown query: exception burst aborts the command loudly
                // instead of hanging the decompiler waiting for data.
                let msg = format!("ventris-worker: unsupported query {other}");
                let mut buf = Vec::new();
                encode_burst(&mut buf, burst::EXCEP_OPEN);
                encode_string_stream(&mut buf, msg.as_bytes());
                encode_burst(&mut buf, burst::EXCEP_CLOSE);
                self.stdin.write_all(&buf).map_err(WorkerError::Io)?;
                self.stdin.flush().map_err(WorkerError::Io)?;
                // Consume to the query close so the stream stays aligned.
                while self.next_burst()? != burst::QUERY_CLOSE {}
                Ok(())
            }
        }
    }

    /// getBytes (ghidra_arch.cc `ArchitectureGhidra::getBytes`): the query
    /// carries a packed `<addr>`; the answer is a byte stream with each
    /// byte encoded as two nibble chars biased by 'A', or an exception
    /// burst for unmapped memory.
    fn answer_getbytes(&mut self, provider: &mut ProgramProvider) -> Result<()> {
        // The packed <addr> payload arrives as one string stream.
        let packed = self.read_string_stream()?;
        let (_space, vaddr, size) = decode_addr_element(&packed)
            .ok_or_else(|| WorkerError::Protocol("bad packed <addr>".into()))?;

        // Consume the query terminator.
        self.expect_burst(burst::QUERY_CLOSE)?;

        let mut buf = Vec::new();
        match provider.backing.slice_at(vaddr, size, provider.base) {
            Some(bytes) => {
                encode_burst(&mut buf, burst::QRESPONSE_OPEN);
                encode_burst(&mut buf, burst::BYTESTREAM_OPEN);
                let nibbles: Vec<u8> = bytes
                    .iter()
                    .flat_map(|b| [(b >> 4) + b'A', (b & 0xf) + b'A'])
                    .collect();
                buf.extend_from_slice(&nibbles);
                encode_burst(&mut buf, burst::BYTESTREAM_CLOSE);
                encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
            }
            None => {
                encode_burst(&mut buf, burst::EXCEP_OPEN);
                encode_string_stream(
                    &mut buf,
                    format!("GHIDRA has no data in the loadimage at {vaddr:#x}").as_bytes(),
                );
                encode_burst(&mut buf, burst::EXCEP_CLOSE);
            }
        }
        self.stdin.write_all(&buf).map_err(WorkerError::Io)?;
        self.stdin.flush().map_err(WorkerError::Io)?;
        Ok(())
    }

    /// Empty query response: open immediately closed.
    fn answer_empty(&mut self) -> Result<()> {
        // Drain any remaining payload streams until the query close.
        while self.next_burst()? != burst::QUERY_CLOSE {}
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.stdin.write_all(&buf).map_err(WorkerError::Io)?;
        self.stdin.flush().map_err(WorkerError::Io)?;
        Ok(())
    }
}

/// Parses a packed `<addr>` element. Returns (space, offset, size).
///
/// Attribute order matches `Address::encode`: space, offset, size. Ids are
/// the low-5-bit header values; the differential test pins the exact bytes
/// against the decompiler's ElementId table.
pub fn decode_addr_element(data: &[u8]) -> Option<(i64, u64, u64)> {
    let mut pos = 0usize;
    let mut space: Option<i64> = None;
    let mut offset: Option<u64> = None;
    let mut size: Option<u64> = None;
    let mut depth = 0usize;

    while pos < data.len() {
        let header = data[pos];
        pos += 1;
        match header & wire::HEADER_MASK_EQ {
            h if h == wire::ELEMENT_START_EQ => {
                depth += 1;
            }
            h if h == wire::ELEMENT_END_EQ => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            h if h == wire::ATTRIBUTE_EQ => {
                if pos >= data.len() {
                    return None;
                }
                let type_byte = data[pos];
                pos += 1;
                let type_code = type_byte >> 4;
                let length_code = (type_byte & 0xf) as u64;
                let mut value: u64 = 0;
                for _ in 0..length_code {
                    if pos >= data.len() {
                        return None;
                    }
                    let b = data[pos] & 0x7f;
                    pos += 1;
                    value = (value << 7) | b as u64;
                }
                match type_code {
                    wire::attr_type::SPACE => space = Some(value as i64),
                    wire::attr_type::UNSIGNED_INT => {
                        if offset.is_none() {
                            offset = Some(value);
                        } else if size.is_none() {
                            size = Some(value);
                        }
                    }
                    _ => {}
                }
            }
            _ => return None,
        }
    }
    Some((space?, offset?, size.unwrap_or(0)))
}

/// Path helper for the pinned language tree (spike layout).
pub fn spec_dir(root: &Path) -> PathBuf {
    root.join("Ghidra/Processors/x86/data/languages")
}
