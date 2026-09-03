//! Program-provider callbacks.
//!
//! While a command (e.g. `decompileAt`) runs, the pinned decompiler issues
//! *queries* on the same stdio pair (burst 0x04 … 0x05), and our answers
//! (0x08 … 0x09) are its only view of the program — this is exactly what
//! `ArchitectureGhidra` does on the Java side. Each callback mirrors one
//! query function from ghidra_arch.cc.
use crate::wire::{self, burst, encode_burst, encode_string_stream};
use crate::{NativeWorker, Result, WorkerError};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Read-only bytes of the analyzed binary, resolved at file offsets.
///
/// `maps` carries the section map (vaddr -> file offset) so ELF and PE both
/// resolve their addresses correctly (PE RVAs are NOT base-relative).
#[derive(Clone)]
pub struct BinaryBacking {
    data: Arc<Vec<u8>>,
    /// (vaddr, size, file_off) per allocated section, ascending vaddr.
    pub maps: Vec<(u64, u64, u64)>,
}

impl BinaryBacking {
    /// Reads the whole binary. (Spec 8.4 mmap comes with the memory-layer
    /// refactor; a shared owned buffer is correct for the spike-sized
    /// fixtures and keeps `unsafe` out of this crate.)
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)
            .map_err(|e| WorkerError::Setup(format!("{}: {e}", path.display())))?;
        Ok(Self {
            data: Arc::new(data),
            maps: Vec::new(),
        })
    }

    /// Bytes at `vaddr` via the section map; falls back to base-relative
    /// when no section covers it (ELF loaded-at-base fixtures).
    pub fn slice_at(&self, vaddr: u64, size: u64, base: u64) -> Option<&[u8]> {
        for (sv, ss, sf) in &self.maps {
            if vaddr >= *sv && vaddr.checked_add(size)? <= sv + ss {
                let start = (vaddr - sv) as usize + *sf as usize;
                let end = start.checked_add(size as usize)?;
                return self.data.get(start..end);
            }
        }
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
    /// Entry address -> name (from the store; used by getMappedSymbols).
    pub function_names: HashMap<u64, String>,
    /// Entry address -> byte size (from the store).
    pub function_sizes: HashMap<u64, u64>,
    /// Symbol names at arbitrary addresses, including imported labels.
    pub symbol_names: HashMap<u64, String>,
    /// Function-address to comments exported from the durable store.
    pub comments: HashMap<u64, Vec<(u64, String, String)>>,
    /// Data-type name to a human-readable definition.
    pub datatypes: HashMap<String, String>,
    /// External address/name pairs used by getExternalRef.
    pub external_names: HashMap<u64, String>,
    /// String data indexed by address for getStringData.
    pub strings: HashMap<u64, String>,
    /// Entry address -> prototype signature override (from the store).
    pub prototypes: HashMap<u64, String>,
    /// Track which space index `ram` occupies once the tspec registers it.
    pub ram_space_index: i64,
    /// Register space index from the tspec (x86-64: 4).
    pub register_space_index: i64,
    /// Register name -> (offset, size) from registers.txt (register space).
    pub registers: HashMap<String, (u64, u64)>,
}

impl ProgramProvider {
    pub fn new(backing: BinaryBacking, base: u64, functions: Vec<u64>) -> Self {
        let mut functions = functions;
        functions.sort_unstable();
        Self {
            backing,
            base,
            functions,
            function_names: HashMap::new(),
            function_sizes: HashMap::new(),
            symbol_names: HashMap::new(),
            comments: HashMap::new(),
            datatypes: HashMap::new(),
            external_names: HashMap::new(),
            strings: HashMap::new(),
            prototypes: HashMap::new(),
            ram_space_index: 3,
            register_space_index: 4,
            registers: HashMap::new(),
        }
    }

    /// Name of the function at `vaddr`, if known.
    pub fn function_name(&self, vaddr: u64) -> Option<String> {
        self.function_names.get(&vaddr).cloned()
    }

    /// Installs the section map for section-aware byte resolution.
    pub fn set_mappings(&mut self, maps: Vec<(u64, u64, u64)>) {
        self.backing.maps = maps;
    }

    /// Loads registers.txt (name<TAB>offset<TAB>size) and the ram/register
    /// space indices from the tspec — the two files `dump_specs` writes.
    pub fn load_language_info(&mut self, lang_dir: &Path) -> Result<()> {
        let regs = std::fs::read_to_string(lang_dir.join("registers.txt"))
            .map_err(|e| WorkerError::Setup(format!("registers.txt: {e}")))?;
        for line in regs.lines() {
            let mut it = line.split('\t');
            if let (Some(name), Some(off), Some(sz)) = (it.next(), it.next(), it.next()) {
                if let (Ok(off), Ok(sz)) = (off.parse::<u64>(), sz.parse::<u64>()) {
                    self.registers.insert(name.to_string(), (off, sz));
                }
            }
        }
        let tspec = std::fs::read_to_string(lang_dir.join("tspec.xml"))
            .map_err(|e| WorkerError::Setup(format!("tspec.xml: {e}")))?;
        // <space name="ram" index="3" ...> — index may appear before name;
        // scan for either order within a <space ...> start tag.
        self.ram_space_index = find_space_index(&tspec, "ram")
            .ok_or_else(|| WorkerError::Setup("tspec has no ram space".into()))?;
        self.register_space_index = find_space_index(&tspec, "register")
            .ok_or_else(|| WorkerError::Setup("tspec has no register space".into()))?;
        Ok(())
    }
}

/// Extracts `index="N"` from the `<space name="NAME"` start tag in a tspec.
fn find_space_index(tspec: &str, name: &str) -> Option<i64> {
    let mut rest = tspec;
    while let Some(pos) = rest.find("<space ") {
        let tag = &rest[pos..];
        let end = tag.find('>')?;
        let start_tag = &tag[..end];
        let has_name = start_tag.contains(&format!("name=\"{name}\""));
        let has_index = start_tag
            .find("index=\"")
            .and_then(|i| {
                let after = &start_tag[i + 7..];
                after.find('"').map(|j| after[..j].to_string())
            });
        if let (Some(i), true) = (has_index, has_name) {
            return i.parse().ok();
        }
        rest = &tag[end..];
    }
    None
}

impl NativeWorker {
    /// Drives one full command lifecycle, answering every query the
    /// decompiler interleaves. Returns the command's own response text.
    pub fn run_command(
        &mut self,
        provider: &mut ProgramProvider,
        command: &str,
        params: &[&[u8]],
    ) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::COMMAND_OPEN);
        encode_string_stream(&mut buf, command.as_bytes());
        for p in params {
            encode_string_stream(&mut buf, p);
        }
        encode_burst(&mut buf, burst::COMMAND_CLOSE);
        self.write_frame(&buf)?;

        // The C++ writes the 0x06 header first (doit, ghidra_process.cc:138),
        // then interleaves program queries while rawAction runs, then the
        // result stream, the warnings frame, and the 0x07 closer. Queries
        // may arrive between 0x06 and the result, so stay in the loop.
        let mut in_response = false;
        loop {
            let code = self.next_burst()?;
            if code == burst::QUERY_OPEN {
                self.answer_query(provider)?;
                continue;
            }
            match code {
                burst::RESPONSE_OPEN => in_response = true,
                0x0e if in_response => {
                    let text = self.read_string_payload(provider)?;
                    // sendResult then writes the warnings frame (raw text
                    // between 0x10 and 0x11), and the caller the 0x07 closer
                    // (ghidra_process.cc:146-149, 489).
                    self.expect_burst(0x10)?;
                    let _ = self.read_until(0x11)?;
                    self.expect_burst(burst::RESPONSE_CLOSE)?;
                    return Ok(text);
                }
                0x10 if in_response => {
                    // Warning-only response: the command errored inside
                    // rawAction (e.g. bad address) and sendResult carried
                    // the message; surface it as the result.
                    let warnings = self.read_until(0x11)?;
                    self.expect_burst(burst::RESPONSE_CLOSE)?;
                    return Ok(warnings);
                }
                burst::EXCEP_OPEN => {
                    let tp = self.read_string_stream()?;
                    let msg = self.read_string_stream()?;
                    let _ = self.expect_burst(burst::EXCEP_CLOSE)?;
                    return Err(WorkerError::Decompiler(
                        format!(
                            "{}: {}",
                            String::from_utf8_lossy(&tp),
                            String::from_utf8_lossy(&msg)
                        ),
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

    /// Dispatches one query by its packed root element id (the C++ writes
    /// the query as a packed command element; the id table is ghidra_arch
    /// .cc:30-48). Answers are 0x08..0x09 frames; an unanswered query hangs
    /// the decompiler, so unknown ids abort loudly.
    pub(crate) fn answer_query(&mut self, provider: &mut ProgramProvider) -> Result<()> {
        let payload = self.read_string_stream()?;
        let id = decode_root_element_id(&payload)
            .ok_or_else(|| WorkerError::Protocol("query payload has no element".into()))?;
        self.expect_burst(burst::QUERY_CLOSE)?;
        match id {
            wire::query::GETBYTES => self.answer_getbytes(provider, &payload),
            wire::query::GETMAPPEDSYMBOLS => self.answer_getmappedsymbols(provider, &payload),
            wire::query::GETREGISTER => self.answer_getregister(provider, &payload),
            wire::query::GETREGISTERNAME => self.answer_getregistername(provider, &payload),
            wire::query::GETCODELABEL => self.answer_code_label(provider, &payload),
            wire::query::GETSTRINGDATA => self.answer_string_data(provider, &payload),
            wire::query::GETCOMMENTS => self.answer_comments(provider, &payload),
            wire::query::GETDATATYPE => self.answer_datatype(provider, &payload),
            wire::query::GETEXTERNALREF => self.answer_external_ref(provider, &payload),
            wire::query::ISNAMEUSED => self.answer_name_used(provider, &payload),
            // These callbacks have no durable facts in the current model.
            // An empty response is the protocol's defined "unknown" value,
            // not a hang or a fabricated fallback.
            wire::query::GETCALLFIXUP
            | wire::query::GETCALLMECH
            | wire::query::GETCALLOTHERFIXUP
            | wire::query::GETCPOOLREF
            | wire::query::GETNAMESPACEPATH
            | wire::query::GETPCODE
            | wire::query::GETPCODEEXECUTABLE => self.answer_empty(),
            wire::query::GETUSEROPNAME => self.answer_str(""),
            wire::query::GETTRACKEDREGISTERS => self.answer_tracked_pointset(),
            other => {
                let msg = format!("ventris-worker: unsupported query id {other}");
                let mut buf = Vec::new();
                encode_burst(&mut buf, burst::EXCEP_OPEN);
                encode_string_stream(&mut buf, msg.as_bytes());
                encode_burst(&mut buf, burst::EXCEP_CLOSE);
                self.write_frame(&buf)?;
                Ok(())
            }
        }
    }

    /// getBytes (ghidra_arch.cc `ArchitectureGhidra::getBytes`): the query
    /// carries a packed `<addr>`; the answer is a byte stream with each
    /// byte encoded as two nibble chars biased by 'A', or an exception
    /// burst for unmapped memory.
    fn answer_getbytes(&mut self, provider: &mut ProgramProvider, payload: &[u8]) -> Result<()> {
        let (_space, vaddr, size) = decode_addr_element(payload)
            .ok_or_else(|| WorkerError::Protocol("bad packed <addr>".into()))?;

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
                // JavaError carries TWO string streams (type, message);
                // passJavaException writes both (ghidra_arch.cc:241-246).
                encode_string_stream(&mut buf, b"DataUnavailError");
                encode_string_stream(
                    &mut buf,
                    format!("GHIDRA has no data in the loadimage at {vaddr:#x}").as_bytes(),
                );
                encode_burst(&mut buf, burst::EXCEP_CLOSE);
            }
        }
        self.write_frame(&buf)?;
        Ok(())
    }

    /// Boolean query response (getIsNameUsed readBoolStream): a string
    /// stream with "t" or "f".
    fn answer_bool(&mut self, value: bool) -> Result<()> {
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        encode_string_stream(&mut buf, if value { b"t" } else { b"f" });
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)?;
        Ok(())
    }

    /// String query response (getCodeLabel, getUserOpName).
    fn answer_str(&mut self, value: &str) -> Result<()> {
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        encode_string_stream(&mut buf, value.as_bytes());
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)?;
        Ok(())
    }

    /// Empty <tracked_pointset> for getTrackedRegisters.
    fn answer_tracked_pointset(&mut self) -> Result<()> {
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        let mut el = Vec::new();
        wire::encode_header(&mut el, wire::ELEMENT_START, wire::elem::TRACKED_POINTSET);
        wire::encode_header(&mut el, wire::ELEMENT_END, wire::elem::TRACKED_POINTSET);
        encode_string_stream(&mut buf, &el);
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)?;
        Ok(())
    }

    /// Empty query response: open immediately closed. The query payload
    /// was already consumed by answer_query, so no drain is needed.
    fn answer_empty(&mut self) -> Result<()> {
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)?;
        Ok(())
    }

    /// getMappedSymbols (ArchitectureGhidra::getMappedSymbolsXML): the
    /// answer for a function entry is the doc/mapsym/function encoding the
    /// Java DecompCallback.getMappedSymbols writes (encodeResult +
    /// HighSymbol.encodeMapSym); anything else answers an empty response,
    /// which readAll treats as "no data" (a hole).
    /// Resolves labels from durable symbols and function names.
    fn answer_code_label(
        &mut self,
        provider: &mut ProgramProvider,
        payload: &[u8],
    ) -> Result<()> {
        let (_, address, _) = decode_addr_element(payload)
            .ok_or_else(|| WorkerError::Protocol("bad getCodeLabel address".into()))?;
        let name = provider
            .symbol_names
            .get(&address)
            .or_else(|| provider.function_names.get(&address))
            .map(String::as_str)
            .unwrap_or("");
        self.answer_str(name)
    }

    /// Answers `isNameUsed` from all durable function and symbol names.
    fn answer_name_used(
        &mut self,
        provider: &mut ProgramProvider,
        payload: &[u8],
    ) -> Result<()> {
        let name = find_name_attribute(payload).unwrap_or_default();
        let used = provider.function_names.values().any(|value| value == &name)
            || provider.symbol_names.values().any(|value| value == &name);
        self.answer_bool(used)
    }

    /// Returns UTF-8 string bytes using the exact A-biased byte-stream shape
    /// consumed by ArchitectureGhidra::getStringData.
    fn answer_string_data(
        &mut self,
        provider: &mut ProgramProvider,
        payload: &[u8],
    ) -> Result<()> {
        let (_, address, _) = decode_addr_element(payload)
            .ok_or_else(|| WorkerError::Protocol("bad getStringData address".into()))?;
        let max_size = find_numeric_attribute(payload, wire::attr::MAXSIZE)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(4096)
            .min(1024 * 1024);
        let bytes = provider
            .strings
            .get(&address)
            .map(|value| value.as_bytes().to_vec())
            .or_else(|| {
                provider
                    .backing
                    .slice_at(address, max_size as u64, provider.base)
                    .map(|value| value.to_vec())
            })
            .unwrap_or_default();
        let mut utf8 = bytes;
        if let Some(nul) = utf8.iter().position(|byte| *byte == 0) {
            utf8.truncate(nul);
        }
        utf8.truncate(max_size);
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        encode_burst(&mut buf, burst::BYTESTREAM_OPEN);
        for byte in &utf8 {
            buf.extend_from_slice(&[(byte >> 4) + b'A', (byte & 0xf) + b'A']);
        }
        encode_burst(&mut buf, burst::BYTESTREAM_CLOSE);
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)
    }

    /// Encodes store comments in the packed `<commentdb>` form consumed by
    /// CommentDatabaseInternal::decode.
    fn answer_comments(
        &mut self,
        provider: &mut ProgramProvider,
        payload: &[u8],
    ) -> Result<()> {
        let (_, function, _) = decode_addr_element(payload)
            .ok_or_else(|| WorkerError::Protocol("bad getComments address".into()))?;
        let mut doc = Vec::new();
        wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::COMMENTDB);
        for (address, kind, text) in provider.comments.get(&function).into_iter().flatten() {
            wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::COMMENT);
            wire::encode_string_attribute(
                &mut doc,
                wire::attr::TYPE,
                comment_type_name(kind).as_bytes(),
            );
            wire::encode_addr_element(&mut doc, provider.ram_space_index as u32, function);
            wire::encode_addr_element(&mut doc, provider.ram_space_index as u32, *address);
            wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::TEXT);
            wire::encode_string_attribute(&mut doc, wire::attr::CONTENT, text.as_bytes());
            wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::TEXT);
            wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::COMMENT);
        }
        wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::COMMENTDB);
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        encode_string_stream(&mut buf, &doc);
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)
    }

    /// Encodes a conservative basic datatype response. The durable type
    /// definition is intentionally retained as store text; the decompiler
    /// needs the name/size/metatype wire fields to continue safely.
    fn answer_datatype(
        &mut self,
        provider: &mut ProgramProvider,
        payload: &[u8],
    ) -> Result<()> {
        let name = find_name_attribute(payload).unwrap_or_default();
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        if provider.datatypes.contains_key(&name) {
            let mut doc = Vec::new();
            wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::TYPE);
            wire::encode_string_attribute(&mut doc, wire::attr::NAME, name.as_bytes());
            wire::encode_attribute(&mut doc, wire::attr::ID, wire::attr_type::UNSIGNED_INT, 1);
            wire::encode_attribute(&mut doc, wire::attr::SIZE, wire::attr_type::POSITIVE_INT, 1);
            wire::encode_string_attribute(
                &mut doc,
                wire::attr::METATYPE,
                datatype_metatype(provider.datatypes.get(&name).map(String::as_str).unwrap_or(""))
                    .as_bytes(),
            );
            wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::TYPE);
            encode_string_stream(&mut buf, &doc);
        }
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)
    }

    /// Resolves imported addresses to an external-reference symbol.
    fn answer_external_ref(
        &mut self,
        provider: &mut ProgramProvider,
        payload: &[u8],
    ) -> Result<()> {
        let (_, address, _) = decode_addr_element(payload)
            .ok_or_else(|| WorkerError::Protocol("bad getExternalRef address".into()))?;
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        if let Some(name) = provider.external_names.get(&address) {
            let mut doc = Vec::new();
            wire::encode_header(
                &mut doc,
                wire::ELEMENT_START,
                wire::elem::EXTERNREFSYMBOL,
            );
            wire::encode_string_attribute(&mut doc, wire::attr::NAME, name.as_bytes());
            wire::encode_addr_element(&mut doc, provider.ram_space_index as u32, address);
            wire::encode_header(
                &mut doc,
                wire::ELEMENT_END,
                wire::elem::EXTERNREFSYMBOL,
            );
            encode_string_stream(&mut buf, &doc);
        }
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)
    }

    fn answer_getmappedsymbols(
        &mut self,
        provider: &mut ProgramProvider,
        payload: &[u8],
    ) -> Result<()> {
        let (space, vaddr, _size) = decode_addr_element(payload)
            .ok_or_else(|| WorkerError::Protocol("bad packed <addr>".into()))?;
        let is_function = space == provider.ram_space_index
            && provider.functions.binary_search(&vaddr).is_ok();
        let mut buf = Vec::new();
        if !is_function {
            encode_burst(&mut buf, burst::QRESPONSE_OPEN);
            encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        } else {
            let name = provider
                .function_name(vaddr)
                .unwrap_or_else(|| "FUN_".to_string() + &format!("{vaddr:x}"));
            encode_burst(&mut buf, burst::QRESPONSE_OPEN);
            let mut doc = Vec::new();
            // <doc id=0><mapsym><function name size><addr/></function>
            // <addr .../><rangelist/></mapsym></doc>
            wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::DOC);
            wire::encode_attribute(&mut doc, wire::attr::ID, wire::attr_type::UNSIGNED_INT, 0);
            wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::MAPSYM);
            wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::FUNCTION);
            // Scope id must be nonzero/unique: Funcdata::decode creates a
            // ScopeLocal with this id; id 0 collides with the global scope
            // (database.cc:822). The entry address is unique per function.
            wire::encode_attribute(&mut doc, wire::attr::ID, wire::attr_type::UNSIGNED_INT, vaddr);
            wire::encode_string_attribute(&mut doc, wire::attr::NAME, name.as_bytes());
            let size = provider.function_sizes.get(&vaddr).copied().unwrap_or(8);
            wire::encode_attribute(
                &mut doc,
                wire::attr::SIZE,
                wire::attr_type::POSITIVE_INT,
                size,
            );
            wire::encode_addr_element(&mut doc, space as u32, vaddr);
            wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::FUNCTION);
            wire::encode_addr_element_size(&mut doc, space as u32, vaddr, size);
            wire::encode_header(&mut doc, wire::ELEMENT_START, wire::elem::RANGELIST);
            wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::RANGELIST);
            wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::MAPSYM);
            wire::encode_header(&mut doc, wire::ELEMENT_END, wire::elem::DOC);
            encode_string_stream(&mut buf, &doc);
            encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        }
        self.write_frame(&buf)?;
        Ok(())
    }

    /// getRegister (ArchitectureGhidra::getRegister): the answer is a
    /// packed `<addr>` in the register space (encodeRegister in Java); an
    /// unknown register is an exception, matching the Java client.
    fn answer_getregister(
        &mut self,
        provider: &mut ProgramProvider,
        payload: &[u8],
    ) -> Result<()> {
        let name = find_name_attribute(payload)
            .ok_or_else(|| WorkerError::Protocol("getregister without name".into()))?;
        let mut buf = Vec::new();
        match provider.registers.get(&name) {
            Some((off, sz)) => {
                encode_burst(&mut buf, burst::QRESPONSE_OPEN);
                let mut addr = Vec::new();
                wire::encode_addr_element_size(
                    &mut addr,
                    provider.register_space_index as u32,
                    *off,
                    *sz,
                );
                encode_string_stream(&mut buf, &addr);
                encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
            }
            None => {
                encode_burst(&mut buf, burst::EXCEP_OPEN);
                encode_string_stream(&mut buf, b"RuntimeException");
                encode_string_stream(
                    &mut buf,
                    format!("No Register Defined: {name}").as_bytes(),
                );
                encode_burst(&mut buf, burst::EXCEP_CLOSE);
            }
        }
        self.write_frame(&buf)?;
        Ok(())
    }

    /// getRegisterName (ArchitectureGhidra::getRegisterName): answer is a
    /// plain string (the Java handler writeString(res)); empty when the
    /// storage maps no register.
    fn answer_getregistername(
        &mut self,
        provider: &mut ProgramProvider,
        payload: &[u8],
    ) -> Result<()> {
        let (_space, off, sz) = decode_addr_element(payload)
            .ok_or_else(|| WorkerError::Protocol("bad packed <addr>".into()))?;
        let mut buf = Vec::new();
        encode_burst(&mut buf, burst::QRESPONSE_OPEN);
        let found = provider
            .registers
            .iter()
            .find(|(_, (o, s))| *o == off && *s == sz)
            .map(|(n, _)| n.as_str())
            .unwrap_or("");
        encode_string_stream(&mut buf, found.as_bytes());
        encode_burst(&mut buf, burst::QRESPONSE_CLOSE);
        self.write_frame(&buf)?;
        Ok(())
    }
}

/// The query payloads wrap the addr inside a command element, so the walk
/// also handles element-start/end headers with the extension byte (ids
/// above 0x1f, per PackedEncode::writeHeader, marshal.hh:661).
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
                if header & 0x20 != 0 {
                    pos += 1; // extension byte
                }
                depth += 1;
            }
            h if h == wire::ELEMENT_END_EQ => {
                if header & 0x20 != 0 {
                    pos += 1; // extension byte
                }
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            h if h == wire::ATTRIBUTE_EQ => {
                let (aid, ty) = decode_attr_header(header, data, &mut pos)?;
                let value = match ty >> 4 {
                    wire::attr_type::STRING => continue, // raw string attrs not numeric
                    _ => decode_int_value(&data, pos, &mut pos, (ty & 0xf) as usize)?,
                };
                match (aid, ty >> 4) {
                    (wire::attr::SPACE, wire::attr_type::SPACE) => space = Some(value as i64),
                    (wire::attr::OFFSET, wire::attr_type::UNSIGNED_INT) => {
                        if offset.is_none() {
                            offset = Some(value);
                        } else if size.is_none() {
                            size = Some(value);
                        }
                    }
                    (wire::attr::SIZE, _) => size = Some(value),
                    _ => {}
                }
            }
            _ => return None,
        }
    }
    Some((space?, offset?, size.unwrap_or(0)))
}

/// Completes an attribute whose header byte is already consumed: reads the
/// extension byte if set, then the type byte. Returns (attr id, type byte).
fn decode_attr_header(header: u8, data: &[u8], pos: &mut usize) -> Option<(u32, u8)> {
    let mut id = (header & 0x1f) as u32;
    if header & 0x20 != 0 {
        id = (id << 7) | (data.get(*pos).copied()? & 0x7f) as u32;
        *pos += 1;
    }
    // Attribute headers carry a type byte; element headers do not.
    let ty = data.get(*pos).copied()?;
    *pos += 1;
    Some((id, ty))
}

/// Decodes the 7-bit-groups integer value (may be zero groups).
fn decode_int_value(data: &[u8], start: usize, pos: &mut usize, groups: usize) -> Option<u64> {
    let mut value = 0u64;
    let mut p = start;
    for _ in 0..groups {
        value = (value << 7) | (data.get(p).copied()? & 0x7f) as u64;
        p += 1;
    }
    *pos = p;
    Some(value)
}

/// Reads the root element id of a packed payload (with extension byte).
pub fn decode_root_element_id(data: &[u8]) -> Option<u32> {
    let header = data.first().copied()?;
    if header & wire::HEADER_MASK_EQ != wire::ELEMENT_START_EQ {
        return None;
    }
    let mut id = (header & 0x1f) as u32;
    if header & 0x20 != 0 {
        id = (id << 7) | (data.get(1).copied()? & 0x7f) as u32;
    }
    Some(id)
}

/// Returns the byte offset where the raw C text starts inside the result.
///
/// DecompileAt::rawAction writes the packed `<doc>` and, inside its
/// element, the printer's C output as raw bytes (ghidra_process.cc:330-332,
/// 173-175). The doc's packed children end before the C text, so the first
/// byte inside the doc that is not a packed header/attribute starts the C.
/// Returns `None` only when no doc/child structure was found.
pub fn packed_element_span(data: &[u8]) -> Option<usize> {
    let mut pos = 0usize;
    let mut depth = 0usize;
    let mut first_elem = false;
    let mut fail_point = None;
    while pos < data.len() {
        let header = data[pos];
        pos += 1;
        match header & wire::HEADER_MASK_EQ {
            h if h == wire::ELEMENT_START_EQ => {
                if header & 0x20 != 0 {
                    pos += 1;
                }
                depth += 1;
                first_elem = true;
            }
            h if h == wire::ELEMENT_END_EQ => {
                if header & 0x20 != 0 {
                    pos += 1;
                }
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(pos);
                }
            }
            h if h == wire::ATTRIBUTE_EQ => {
                let (aid, ty) = decode_attr_header(header, data, &mut pos)?;
                let tc = ty >> 4;
                let len = (ty & 0xf) as usize;
                let v = decode_int_value(data, pos, &mut pos, len)?;
                if tc == wire::attr_type::STRING {
                    pos = pos.checked_add(v as usize)?;
                }
                let _ = aid;
            }
            _ => {
                // Non-packed byte at the (in)side of the doc: the printer's
                // raw C output starts here. Only meaningful once at least
                // one element was seen; otherwise this is not a result doc.
                if first_elem && fail_point.is_none() {
                    fail_point = Some(pos - 1);
                }
                return fail_point.or(Some(pos - 1));
            }
        }
    }
    None
}

/// Finds the string attribute with the given id (e.g. the getregister name).
pub fn find_name_attribute(data: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    let mut name: Option<String> = None;
    while pos < data.len() {
        let header = data[pos];
        pos += 1;
        match header & wire::HEADER_MASK_EQ {
            h if h == wire::ELEMENT_START_EQ => {
                if header & 0x20 != 0 {
                    pos += 1;
                }
            }
            h if h == wire::ELEMENT_END_EQ => {
                if header & 0x20 != 0 {
                    pos += 1;
                }
            }
            h if h == wire::ATTRIBUTE_EQ => {
                if pos >= data.len() {
                    return None;
                }
                let (aid, ty) = decode_attr_header(header, data, &mut pos)?;
                if aid == wire::attr::NAME && ty >> 4 == wire::attr_type::STRING {
                    let len = decode_int_value(data, pos, &mut pos, (ty & 0xf) as usize)? as usize;
                    let end = pos.checked_add(len)?;
                    let raw = data.get(pos..end)?.to_vec();
                    name = Some(String::from_utf8_lossy(&raw).into_owned());
                    pos = end;
                }
            }
            _ => return None,
        }
    }
    name
}

/// Finds a numeric packed attribute without assuming it is the first one.
pub fn find_numeric_attribute(data: &[u8], target: u32) -> Option<i64> {
    let mut pos = 0usize;
    while pos < data.len() {
        let header = data[pos];
        pos += 1;
        match header & wire::HEADER_MASK_EQ {
            h if h == wire::ELEMENT_START_EQ || h == wire::ELEMENT_END_EQ => {
                if header & 0x20 != 0 {
                    pos = pos.checked_add(1)?;
                }
            }
            h if h == wire::ATTRIBUTE_EQ => {
                let (id, ty) = decode_attr_header(header, data, &mut pos)?;
                let groups = (ty & 0xf) as usize;
                if ty >> 4 == wire::attr_type::STRING {
                    let len = decode_int_value(data, pos, &mut pos, groups)? as usize;
                    pos = pos.checked_add(len)?;
                    continue;
                }
                let value = decode_int_value(data, pos, &mut pos, groups)?;
                if id == target {
                    return match ty >> 4 {
                        wire::attr_type::NEGATIVE_INT => Some(-(value as i64)),
                        _ => i64::try_from(value).ok(),
                    };
                }
            }
            _ => return None,
        }
    }
    None
}

fn comment_type_name(kind: &str) -> &'static str {
    match kind.to_ascii_lowercase().as_str() {
        "header" | "plate" | "pre" => "header",
        "warning" => "warning",
        "warningheader" => "warningheader",
        "user2" => "user2",
        "user3" => "user3",
        _ => "user1",
    }
}

fn datatype_metatype(definition: &str) -> &'static str {
    let definition = definition.to_ascii_lowercase();
    if definition.contains("struct") {
        "struct"
    } else if definition.contains("union") {
        "union"
    } else if definition.contains("enum") {
        "enum_int"
    } else if definition.contains("float") {
        "float"
    } else if definition.contains("bool") {
        "bool"
    } else {
        "int"
    }
}

/// Path helper for the pinned language tree (spike layout).
pub fn spec_dir(root: &Path) -> PathBuf {
    root.join("Ghidra/Processors/x86/data/languages")
}
