//! Native (no-JVM) runtime services: SLEIGH console + the decompiler worker.
//!
//! These were CLI-local until the review that tightened the facade contract
//! (a GUI — the intended consumer — could not reuse `decompile-native` /
//! `disasm-native` without copying `Command::new` spawn logic out of
//! lre-cli/main.rs). They now live behind the Core facade so every consumer
//! (CLI, GUI, agents) speaks only Core API methods.
//!
//! The runtime contract is `RuntimeConfig` (crate::session): services take
//! an explicit value — never read process-wide env vars. The environment is
//! consulted only when the config is BUILT (`RuntimeConfig::from_env`), so
//! the CLI's env surface is preserved while everything below it is honest
//! about its inputs.

use crate::native::{elf_image_base, pe_image_base, NativeImport};
use crate::session::RuntimeConfig;
use std::path::{Path, PathBuf};
use std::process::Command;
mod image;
use image::MappedImage;

/// Facade error for the native runtime (string-typed: these are setup and
/// child-process failures, reported verbatim to the caller).
#[derive(Debug)]
pub struct NativeRuntimeError(pub String);

impl std::fmt::Display for NativeRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NativeRuntimeError {}

pub type Result<T> = std::result::Result<T, NativeRuntimeError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(NativeRuntimeError(msg.into()))
}

/// The pinned Ghidra install root (env override, then the default path).
pub fn ghidra_dir() -> PathBuf {
    std::env::var("VENTRIS_GHIDRA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(format!(
                "{}/ghidra_12.1.3_PUBLIC",
                std::env::var("HOME").unwrap_or_default()
            ))
        })
}

pub fn find_console(cfg: &RuntimeConfig) -> Result<PathBuf> {
    if let Some(ref p) = cfg.console_path {
        if p.is_file() {
            return Ok(p.clone());
        }
    }
    if let Ok(val) = std::env::var("VENTRIS_CONSOLE") {
        let p = PathBuf::from(val);
        if p.is_file() {
            return Ok(p);
        }
    }
    for candidate in [
        PathBuf::from("native/build/decomp_native"),
        PathBuf::from("../../native/build/decomp_native"),
        PathBuf::from("../native/build/decomp_native"),
    ] {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    err("SLEIGH console missing: build native/build_console.sh (needs binutils-devel) or configure console_path")
}

fn console_output(cfg: &RuntimeConfig, binary: &Path, address: &str) -> Result<String> {
    let console = find_console(cfg)?;
    let ghroot = cfg.ghidra_install.to_string_lossy().into_owned();
    let langs = cfg.language_dir.to_string_lossy().into_owned();
    let hex_addr = if address.starts_with("0x") {
        address.to_string()
    } else {
        format!("0x{address}")
    };
    let mapped = MappedImage::for_elf_or_dol(binary)?;
    let bfd_target = bfd_target_for(&cfg.language_id, binary)?;
    let load_script = if let Some(image) = &mapped {
        image.command()
    } else if cfg.language_id.starts_with("x86:") {
        format!(
            "load file {} {}\nadjust vma 0x400000\n",
            bfd_target,
            binary.display()
        )
    } else {
        format!("load file {} {}\n", bfd_target, binary.display())
    };
    let script =
        format!("{load_script}map function {hex_addr} func\nload function func\ndisassemble\n",);
    let mut child = Command::new(&console)
        .arg("-s")
        .arg(&langs)
        .env("SLEIGHHOME", &ghroot)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| NativeRuntimeError(format!("console spawn: {e}")))?;
    use std::io::Write as _;
    child
        .stdin
        .take()
        .ok_or_else(|| NativeRuntimeError("console stdin".into()))?
        .write_all(script.as_bytes())
        .map_err(|e| NativeRuntimeError(format!("console write: {e}")))?;
    let out = child
        .wait_with_output()
        .map_err(|e| NativeRuntimeError(format!("console wait: {e}")))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn instruction_line(line: &str) -> bool {
    let Some((address, _)) = line.trim().split_once(':') else {
        return false;
    };
    let address = address.trim().trim_start_matches("0x");
    !address.is_empty() && u64::from_str_radix(address, 16).is_ok()
}

fn structural_line(line: &str) -> bool {
    let line = line.trim();
    line.starts_with("Function ")
        || line.starts_with("Block ")
        || line.starts_with("Label ")
        || line.starts_with("Data ")
}

fn filtered_listing(output: &str, count: u32, include_structural: bool) -> Vec<String> {
    let mut instructions = 0u32;
    let mut lines = Vec::new();
    for line in output.lines() {
        let is_instruction = instruction_line(line);
        let is_structural = include_structural && structural_line(line);
        if !is_instruction && !is_structural {
            continue;
        }
        if is_instruction {
            if instructions >= count {
                break;
            }
            instructions += 1;
        }
        lines.push(line.to_string());
    }
    lines
}

/// Performs `disasm-native`: one function mapped + disassembled by the
/// SLEIGH console, returning only address-prefixed instruction lines.
pub fn disasm_native(
    cfg: &RuntimeConfig,
    binary: &Path,
    address: &str,
    count: u32,
) -> Result<String> {
    let output = console_output(cfg, binary, address)?;
    let lines = filtered_listing(&output, count, false);
    if lines.is_empty() {
        return err("console produced no listing");
    }
    Ok(lines.join("\n"))
}

/// Runs the same console request as `disasm_native`, preserving structural
/// marker lines for the Core listing parser.
pub fn listing_native(
    cfg: &RuntimeConfig,
    binary: &Path,
    address: &str,
    count: u32,
) -> Result<String> {
    let output = console_output(cfg, binary, address)?;
    let lines = filtered_listing(&output, count, true);
    if !lines.iter().any(|line| instruction_line(line)) {
        return err("console produced no listing");
    }
    Ok(lines.join("\n"))
}

/// Resolves the decompile inputs for a program language id: the compiled
/// SLA (from the install's .ldefs), the language dir, and the vendored
/// spec bundle (native/specs/<lang>, generated once via `dump-specs`).
/// Falls back to the configured x86 defaults when the language is the
/// default x86-64 or the env explicitly set the pieces.
fn language_decompile_config(
    cfg: &RuntimeConfig,
    language: &str,
) -> Result<(
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    String,
)> {
    // Explicit env wins (existing behavior).
    if let Some(sla) = &cfg.sla_path {
        return Ok((
            sla.clone(),
            cfg.spec_root.clone(),
            cfg.language_dir.clone(),
            cfg.language_id.clone(),
        ));
    }
    // Default x86-64: keep the vendored x86 bundle.
    if language == "x86:LE:64:default" {
        return Ok((
            cfg.ghidra_install
                .join("Ghidra/Processors/x86/data/languages/x86-64.sla"),
            cfg.spec_root.clone(),
            cfg.language_dir.clone(),
            cfg.language_id.clone(),
        ));
    }
    // Other languages: resolve the sla from the install ldefs and the
    // vendored spec bundle keyed by the language id.
    let specs = crate::architecture::discover(&cfg.ghidra_install)
        .map_err(|e| NativeRuntimeError(e.to_string()))?;
    let spec = specs.iter().find(|s| s.id == language).ok_or_else(|| {
        NativeRuntimeError(format!(
            "language {language} not found in the Ghidra install"
        ))
    })?;
    let lang_dir = std::path::PathBuf::from(&spec.language_dir);
    let slafile = crate::architecture::slafile_for_id(&lang_dir, language)
        .map_err(|e| NativeRuntimeError(e.to_string()))?
        .ok_or_else(|| {
            NativeRuntimeError(format!("no .sla listed for {language} in its .ldefs"))
        })?;
    let sla = lang_dir.join(slafile);
    let bundle = cfg.spec_root.join(language.replace(':', "-"));
    if !bundle.join("tspec.xml").is_file() {
        return err(format!(
            "spec bundle missing for {language}: {} — generate it once with \
             `lre-cli dump-specs <program> --out {}` (JVM bridge)",
            bundle.display(),
            bundle.display()
        ));
    }
    Ok((sla, bundle, lang_dir, language.to_string()))
}

/// Performant `decompile-native`: one address decompiled by the patched
/// `ghidra_opt` through `lre-worker` (raw-SLEIGH, no JVM).
fn run_decompiler(
    cfg: &RuntimeConfig,
    binary: &Path,
    address: &str,
    program: &str,
    project_dir: &Path,
    base: Option<u64>,
    structured: bool,
) -> Result<Vec<u8>> {
    let opt = &cfg.decompiler_path;
    let worker = &cfg.worker_path;
    // The patched ghidra_opt self-disassembles only when a compiled .sla is
    // configured (see native/build_ghidra_opt.sh). The program language
    // drives the SLA + spec bundle; explicit env overrides win.
    let language = crate::session::program_language(cfg, program, project_dir)
        .unwrap_or_else(|_| cfg.language_id.clone());
    let (sla, specs, lang_dir, language_id) = language_decompile_config(cfg, &language)?;
    if !sla.is_file() {
        return err(format!(
            "configured SLA does not exist: {} — the decompiler silently fails \
             (\"no architecture registered\") without a readable .sla",
            sla.display()
        ));
    }
    if !opt.is_file() {
        return err(format!(
            "native decompiler missing: {} — build it via native/build_ghidra_opt.sh",
            opt.display()
        ));
    }
    if !specs.join("tspec.xml").is_file() {
        return err(format!(
            "spec dir incomplete: {} (needs tspec.xml; use native/specs)",
            specs.display()
        ));
    }
    let base = match base {
        Some(b) => b,
        None => {
            let data = std::fs::read(binary)
                .map_err(|e| NativeRuntimeError(format!("{}: {e}", binary.display())))?;
            pe_image_base(&data)
                .or_else(|| elf_image_base(&data))
                .unwrap_or(0x400000)
        }
    };
    let mut command = Command::new(worker);
    command
        .arg(opt)
        .arg(specs)
        .arg(binary)
        .arg(program)
        .arg(address)
        .arg("--project")
        .arg(project_dir)
        .arg("--base")
        .arg(format!("{base:#x}"))
        .env("VENTRIS_LANGUAGE", &language_id)
        .env("VENTRIS_LANGUAGE_DIR", &lang_dir)
        .env("VENTRIS_SLA", &sla);
    if structured {
        command.env("WORKER_STRUCTURED", "1");
    }
    let out = command
        .output()
        .map_err(|e| NativeRuntimeError(format!("worker spawn: {e}")))?;
    if !out.status.success() {
        return err(format!(
            "worker failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

/// Perform `decompile-native`: one address decompiled by the patched
/// `ghidra_opt` through `lre-worker` (raw-SLEIGH, no JVM).
pub fn decompile_native(
    cfg: &RuntimeConfig,
    binary: &Path,
    address: &str,
    program: &str,
    project_dir: &Path,
    base: Option<u64>,
) -> Result<String> {
    let stdout = run_decompiler(cfg, binary, address, program, project_dir, base, false)?;
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

/// Performs the same native decompile but returns the packed document as
/// structured model data. The worker stamped revision is zero; the Core
/// facade replaces it with the current durable program revision.
pub fn decompile_native_doc(
    cfg: &RuntimeConfig,
    binary: &Path,
    address: &str,
    program: &str,
    project_dir: &Path,
    base: Option<u64>,
) -> Result<lre_model::DecompDoc> {
    let stdout = run_decompiler(cfg, binary, address, program, project_dir, base, true)?;
    let text = String::from_utf8(stdout)
        .map_err(|e| NativeRuntimeError(format!("worker document is not UTF-8: {e}")))?;
    serde_json::from_str(text.trim())
        .map_err(|e| NativeRuntimeError(format!("invalid structured worker document: {e}")))
}

/// Reads console output until the interactive prompt "[decomp]> " is seen.
/// The prompt carries no trailing newline, so `read_line` deadlocks; the
/// console also buffers, so the read must be byte-wise.
fn read_until_prompt(reader: &mut std::io::BufReader<std::process::ChildStdout>) -> Result<String> {
    use std::io::Read as _;
    const PROMPT: &[u8] = b"[decomp]> ";
    let mut buf: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader
            .read(&mut byte)
            .map_err(|e| NativeRuntimeError(format!("console read: {e}")))?;
        if n == 0 {
            return err("console closed before prompt");
        }
        buf.push(byte[0]);
        if buf.ends_with(PROMPT) {
            return Ok(String::from_utf8_lossy(&buf).into_owned());
        }
    }
}

/// Maps the configured Ghidra language id + binary format to the BFD target
/// name the console's `load file` command expects. The console's BFD loader
/// derives the SLEIGH language from the image header itself, so the target
/// must be a BFD name, never a Ghidra language id.
fn bfd_target_for(language_id: &str, binary: &Path) -> Result<String> {
    use std::io::Read as _;
    let mut magic = [0u8; 4];
    let mut file = std::fs::File::open(binary)
        .map_err(|e| NativeRuntimeError(format!("bfd target probe: {e}")))?;
    let got = file
        .read(&mut magic)
        .map_err(|e| NativeRuntimeError(format!("bfd target probe: {e}")))?;
    if got >= 2 && &magic[..2] == b"MZ" {
        let sixty_four = language_id.contains(":64:");
        return Ok(if sixty_four {
            "pei-x86-64".into()
        } else {
            "pei-i386".into()
        });
    }
    if language_id.starts_with("PowerPC:") {
        return Ok("PowerPC:BE:32:default".into());
    }
    let sixty_four = language_id.contains(":64:");
    Ok(if sixty_four {
        "elf64-x86-64".into()
    } else {
        "elf32-i386".into()
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FlowKind {
    Branch,
    CBranch,
    BranchInd,
    Call,
    CallInd,
    Return,
    Fallthrough,
    Bad,
    Unimpl,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FlowResult {
    pub address: u64,
    pub length: u8,
    pub fallthrough: Option<u64>,
    pub targets: Vec<u64>,
    pub kind: FlowKind,
    /// True only for a single, side-effect-free direct SLEIGH branch operation.
    #[serde(default)]
    pub pure_jump: bool,
    /// True only when SLEIGH successfully decodes an instruction with no p-code.
    #[serde(default)]
    pub no_op: bool,
}

/// Bounded SLEIGH evidence for an indirect transfer through a pointer slot.
/// A slot alone is not an imported function: the loader must establish its identity.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct LinkageResult {
    pub address: u64,
    pub length: u32,
    pub slot: Option<u64>,
    /// A possible local linkage shape, not proof of an imported function.
    pub needs_context: bool,
}

#[derive(Debug)]
pub(crate) struct LinkageContext {
    pub origin: u64,
    pub branch: u64,
    pub target: u64,
}

pub fn console_flow(cfg: &RuntimeConfig, binary: &Path, address: u64) -> Result<FlowResult> {
    let console = find_console(cfg)?;
    let ghroot = cfg.ghidra_install.to_string_lossy().into_owned();
    let langs = cfg.language_dir.to_string_lossy().into_owned();

    let mapped = MappedImage::for_elf_or_dol(binary)?;
    let target = bfd_target_for(&cfg.language_id, binary)?;
    let mappings = crate::native::load_native_mappings(binary).unwrap_or_default();
    let adjust_vma = mappings
        .iter()
        .find(|m| address >= m.vaddr && address < m.vaddr + m.size)
        .or_else(|| mappings.first())
        .map(|m| m.vaddr.wrapping_sub(m.file_off))
        .unwrap_or(0);

    let script = if let Some(image) = &mapped {
        format!("{}flow 0x{address:x}\nquit\n", image.command())
    } else if cfg.language_id.starts_with("x86:") {
        format!(
            "load file {} {}\nflow 0x{:x}\nquit\n",
            target,
            binary.display(),
            address
        )
    } else {
        format!(
            "load file {} {}\nadjust vma 0x{:x}\nflow 0x{:x}\nquit\n",
            target,
            binary.display(),
            adjust_vma,
            address
        )
    };
    let mut child = Command::new(&console)
        .arg("-s")
        .arg(&langs)
        .env("SLEIGHHOME", &ghroot)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| NativeRuntimeError(format!("console spawn: {e}")))?;

    use std::io::Write as _;
    child
        .stdin
        .take()
        .ok_or_else(|| NativeRuntimeError("console stdin".into()))?
        .write_all(script.as_bytes())
        .map_err(|e| NativeRuntimeError(format!("console write: {e}")))?;

    let out = child
        .wait_with_output()
        .map_err(|e| NativeRuntimeError(format!("console wait: {e}")))?;

    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_flow_output(&stdout, address)
}

fn parse_address_token(text: &str) -> Option<u64> {
    let clean = text
        .trim()
        .trim_start_matches(|c: char| c.is_alphabetic() || c == ':');
    let hex = clean.trim_start_matches("0x");
    (!hex.is_empty())
        .then(|| u64::from_str_radix(hex, 16).ok())
        .flatten()
}

fn parse_flow_output(stdout: &str, expected_addr: u64) -> Result<FlowResult> {
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("FLOW ") {
            let mut addr = expected_addr;
            let mut length = 1u8;
            let mut fallthrough = None;
            let mut kind = FlowKind::Fallthrough;
            let mut targets = Vec::new();
            let mut pure_jump = false;
            let mut no_op = false;

            for part in rest.split_whitespace() {
                if let Some(val) = part.strip_prefix("len=") {
                    length = val.parse().unwrap_or(1);
                } else if let Some(val) = part.strip_prefix("fall=") {
                    if val != "none" {
                        fallthrough = parse_address_token(val);
                    }
                } else if let Some(val) = part.strip_prefix("kind=") {
                    kind = match val {
                        "BRANCH" => FlowKind::Branch,
                        "CBRANCH" => FlowKind::CBranch,
                        "BRANCHIND" => FlowKind::BranchInd,
                        "CALL" => FlowKind::Call,
                        "CALLIND" => FlowKind::CallInd,
                        "RETURN" => FlowKind::Return,
                        "BAD" => FlowKind::Bad,
                        "UNIMPL" => FlowKind::Unimpl,
                        _ => FlowKind::Fallthrough,
                    };
                } else if let Some(val) = part.strip_prefix("pure_jump=") {
                    pure_jump = val == "1";
                } else if let Some(val) = part.strip_prefix("no_op=") {
                    no_op = val == "1";
                } else if let Some(val) = part.strip_prefix("targets=") {
                    for t in val.split(',') {
                        if let Some(target_addr) = parse_address_token(t) {
                            targets.push(target_addr);
                        }
                    }
                } else if let Some(a) = parse_address_token(part) {
                    addr = a;
                }
            }
            return Ok(FlowResult {
                no_op,
                pure_jump,
                address: addr,
                length,
                fallthrough,
                targets,
                kind,
            });
        }
    }
    err(format!("console produced no FLOW line: {stdout}"))
}
/// Persistent SLEIGH console session (m1-003-b).
///
/// Spawns `decomp_native` once and reuses the process for many `flow`
/// requests, avoiding the per-instruction spawn cost that makes the
/// one-shot `console_flow` unsuitable for whole-binary discovery.
pub struct ConsoleSession {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: std::io::BufReader<std::process::ChildStdout>,
    language_id: String,
}

impl ConsoleSession {
    /// Spawn the console and wait for the first interactive prompt.
    pub fn new(cfg: &RuntimeConfig) -> Result<Self> {
        let console = find_console(cfg)?;
        let ghroot = cfg.ghidra_install.to_string_lossy().into_owned();
        let langs = cfg.language_dir.to_string_lossy().into_owned();

        let mut child = Command::new(&console)
            .arg("-s")
            .arg(&langs)
            .env("SLEIGHHOME", &ghroot)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| NativeRuntimeError(format!("console spawn: {e}")))?;

        let stdin = child.stdin.take().expect("console stdin");
        let stdout = child.stdout.take().expect("console stdout");
        let mut reader = std::io::BufReader::with_capacity(128 * 1024, stdout);

        // The console prints an initial "[decomp]> " prompt.
        let _ = read_until_prompt(&mut reader)?;

        Ok(Self {
            child,
            stdin,
            reader,
            language_id: cfg.language_id.clone(),
        })
    }

    /// Load ELF/DOL through the native mapped image. Other formats retain
    /// their BFD/raw address-base handling.
    pub fn load(&mut self, binary: &Path, base: u64) -> Result<()> {
        if let Some(image) = MappedImage::for_elf_or_dol(binary)? {
            return self.load_xml(&image);
        }
        let target = bfd_target_for(&self.language_id, binary)?;
        let script = if self.language_id.starts_with("x86:") {
            format!("load file {} {}\n", target, binary.display())
        } else {
            format!(
                "load file {} {}\nadjust vma 0x{:x}\n",
                target,
                binary.display(),
                base
            )
        };
        self.send(&script)?;

        // One prompt per command written (load + optional adjust).
        let prompts = if self.language_id.starts_with("x86:") {
            1
        } else {
            2
        };
        for _ in 0..prompts {
            let _ = read_until_prompt(&mut self.reader)?;
        }
        Ok(())
    }

    /// Load existing native mappings without flattening sparse virtual addresses.
    pub fn load_mapped(&mut self, import: &NativeImport) -> Result<()> {
        let image = MappedImage::new(import)?;
        self.load_xml(&image)
    }

    fn load_xml(&mut self, image: &MappedImage) -> Result<()> {
        self.send(&image.command())?;
        let response = read_until_prompt(&mut self.reader)?;
        if !response.contains("successfully loaded:") {
            return err(format!("mapped image load failed: {response}"));
        }
        Ok(())
    }

    /// Ask the console for the control-flow of one instruction.
    pub fn flow(&mut self, address: u64) -> Result<FlowResult> {
        let script = format!("flow 0x{:x}\n", address);
        self.send(&script)?;

        use std::io::{BufRead as _, Read as _};
        // The console echoes the command; read and discard it.
        let mut echo = String::new();
        if self
            .reader
            .read_line(&mut echo)
            .map_err(|e| NativeRuntimeError(format!("console read: {e}")))?
            == 0
        {
            return err("console closed before flow output");
        }

        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .map_err(|e| NativeRuntimeError(format!("console read: {e}")))?;
        if n == 0 {
            return err("console closed before flow output");
        }

        // Every command is followed by the prompt "[decomp]> " (no newline).
        let mut prompt = [0u8; 10];
        self.reader
            .read_exact(&mut prompt)
            .map_err(|e| NativeRuntimeError(format!("console prompt: {e}")))?;

        // Bad addresses produce a "Low-level ERROR" line and no FLOW.
        if line.contains("Low-level ERROR") {
            return Ok(FlowResult {
                no_op: false,
                pure_jump: false,
                address,
                length: 1,
                fallthrough: Some(address + 1),
                targets: Vec::new(),
                kind: FlowKind::Bad,
            });
        }

        parse_flow_output(&line, address)
    }

    /// Same as `flow` but never fails: unparseable/missing output becomes a
    /// length-1 `Bad` result so a walk can continue.
    pub fn try_flow(&mut self, address: u64) -> FlowResult {
        self.flow(address).unwrap_or(FlowResult {
            no_op: false,
            pure_jump: false,
            address,
            length: 1,
            fallthrough: Some(address + 1),
            targets: Vec::new(),
            kind: FlowKind::Bad,
        })
    }
    /// Queries control-flow for multiple addresses in a single batch request.
    pub fn flow_batch(&mut self, addresses: &[u64]) -> Result<Vec<FlowResult>> {
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        use std::fmt::Write as _;
        use std::io::{BufRead as _, Read as _};
        let mut script = String::with_capacity(addresses.len() * 12 + 8);
        script.push_str("flow");
        for addr in addresses {
            let _ = write!(script, " 0x{:x}", addr);
        }
        script.push('\n');
        self.send(&script)?;

        // Read and discard echo line
        let mut echo = String::new();
        if self
            .reader
            .read_line(&mut echo)
            .map_err(|e| NativeRuntimeError(format!("console read echo: {e}")))?
            == 0
        {
            return err("console closed before flow_batch output");
        }

        let mut results = Vec::with_capacity(addresses.len());
        let mut line = String::with_capacity(256);
        for &addr in addresses {
            line.clear();
            let n = self
                .reader
                .read_line(&mut line)
                .map_err(|e| NativeRuntimeError(format!("console read line: {e}")))?;
            if n == 0 {
                return err("console closed during flow_batch output");
            }
            if line.contains("Low-level ERROR") {
                results.push(FlowResult {
                    no_op: false,
                    pure_jump: false,
                    address: addr,
                    length: 1,
                    fallthrough: Some(addr + 1),
                    targets: Vec::new(),
                    kind: FlowKind::Bad,
                });
            } else {
                results.push(parse_flow_output(&line, addr).unwrap_or(FlowResult {
                    no_op: false,
                    pure_jump: false,
                    address: addr,
                    length: 1,
                    fallthrough: Some(addr + 1),
                    targets: Vec::new(),
                    kind: FlowKind::Bad,
                }));
            }
        }

        // Read trailing prompt "[decomp]> "
        let mut prompt = [0u8; 10];
        self.reader
            .read_exact(&mut prompt)
            .map_err(|e| NativeRuntimeError(format!("console prompt: {e}")))?;

        Ok(results)
    }

    /// Same as `flow_batch` but never errors, returning fallback results on failure.
    pub fn try_flow_batch(&mut self, addresses: &[u64]) -> Vec<FlowResult> {
        self.flow_batch(addresses).unwrap_or_else(|_| {
            addresses
                .iter()
                .map(|&addr| FlowResult {
                    no_op: false,
                    pure_jump: false,
                    address: addr,
                    length: 1,
                    fallthrough: Some(addr + 1),
                    targets: Vec::new(),
                    kind: FlowKind::Bad,
                })
                .collect()
        })
    }

    /// Identify linkage stubs without reading or fabricating imported pointer values.
    pub fn linkage_batch(&mut self, addresses: &[u64]) -> Result<Vec<LinkageResult>> {
        self.query_linkages(addresses, "linkage")
    }

    /// PLT metadata establishes entry boundaries; register setup need not be pure.
    pub(crate) fn plt_linkage_batch(&mut self, addresses: &[u64]) -> Result<Vec<LinkageResult>> {
        self.query_linkages(addresses, "linkage --table")
    }

    pub(crate) fn context_linkage_batch(
        &mut self,
        contexts: &[LinkageContext],
    ) -> Result<Vec<LinkageResult>> {
        use std::fmt::Write as _;
        if contexts.is_empty() {
            return Ok(Vec::new());
        }
        let mut command = String::with_capacity(contexts.len() * 57 + 15);
        command.push_str("linkage --from");
        for context in contexts {
            let _ = write!(
                command,
                " 0x{:x} 0x{:x} 0x{:x}",
                context.origin, context.branch, context.target
            );
        }
        command.push('\n');
        self.send(&command)?;
        self.read_linkages(contexts.iter().map(|context| context.target))
    }

    fn query_linkages(&mut self, addresses: &[u64], prefix: &str) -> Result<Vec<LinkageResult>> {
        use std::fmt::Write as _;
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        let mut command = String::with_capacity(addresses.len() * 19 + prefix.len() + 1);
        command.push_str(prefix);
        for address in addresses {
            let _ = write!(command, " 0x{address:x}");
        }
        command.push('\n');
        self.send(&command)?;
        self.read_linkages(addresses.iter().copied())
    }

    fn read_linkages(
        &mut self,
        expected: impl ExactSizeIterator<Item = u64>,
    ) -> Result<Vec<LinkageResult>> {
        let response = read_until_prompt(&mut self.reader)?;
        let results: Vec<LinkageResult> = response
            .lines()
            .filter_map(|line| line.strip_prefix("LINKAGE "))
            .map(|line| {
                serde_json::from_str(line).map_err(|error| {
                    NativeRuntimeError(format!("invalid linkage response: {error}"))
                })
            })
            .collect::<Result<_>>()?;
        if results.len() != expected.len()
            || results.iter().zip(expected).any(|(result, address)| {
                result.address != address
                    || result.slot.is_some() != (result.length != 0)
                    || (result.needs_context && result.length != 0)
            })
        {
            return err("incomplete or mismatched linkage response");
        }
        Ok(results)
    }

    /// Close stdin and wait for the child to exit.
    pub fn quit(mut self) -> Result<()> {
        let _ = self.send("quit\n");
        let _ = self.child.wait();
        Ok(())
    }

    fn send(&mut self, s: &str) -> Result<()> {
        use std::io::Write as _;
        self.stdin
            .write_all(s.as_bytes())
            .and_then(|_| self.stdin.flush())
            .map_err(|e| NativeRuntimeError(format!("console write: {e}")))
    }
}
impl Drop for ConsoleSession {
    fn drop(&mut self) {
        use std::io::Write as _;
        let _ = self.stdin.write_all(b"quit\n");
        let _ = self.stdin.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcode_flow_x86_and_ppc() {
        let cfg = RuntimeConfig::from_env();
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let x86_bin = manifest_dir.join("../../tests/fixtures-src/tiny_bin");
        if !x86_bin.is_file() {
            eprintln!("SKIP: tiny_bin not present");
            return;
        }
        let flow_ret = console_flow(&cfg, &x86_bin, 0x400479).expect("x86 ret flow");
        assert_eq!(flow_ret.kind, FlowKind::Return);
        assert_eq!(flow_ret.fallthrough, None);
        assert_eq!(flow_ret.length, 1);

        let flow_fall = console_flow(&cfg, &x86_bin, 0x400466).expect("x86 add flow");
        assert_eq!(flow_fall.kind, FlowKind::Fallthrough);
        assert_eq!(flow_fall.fallthrough, Some(0x400467));

        let ppc_bin =
            Path::new("/home/raikaru/Projects/agent-under-fire/orig/GQFE78/files/base.elf");
        if ppc_bin.is_file() {
            let mut ppc_cfg = cfg.clone();
            ppc_cfg.language_id = "PowerPC:BE:32:default".into();
            ppc_cfg.language_dir = ppc_cfg
                .ghidra_install
                .join("Ghidra/Processors/PowerPC/data/languages");
            let flow_fall =
                console_flow(&ppc_cfg, ppc_bin, 0x80680000).expect("ppc fallthrough flow");
            assert_eq!(flow_fall.length, 4);
            assert_eq!(flow_fall.kind, FlowKind::Fallthrough);
            assert_eq!(flow_fall.fallthrough, Some(0x80680004));

            let flow_cbranch =
                console_flow(&ppc_cfg, ppc_bin, 0x8068001c).expect("ppc cbranch flow");
            assert_eq!(flow_cbranch.length, 4);
            assert_eq!(flow_cbranch.kind, FlowKind::CBranch);
            assert_eq!(flow_cbranch.fallthrough, Some(0x80680020));
            assert_eq!(flow_cbranch.targets, vec![0x80680030]);
        }
    }

    #[test]
    fn console_session_persists_multiple_flows() {
        let cfg = RuntimeConfig::from_env();
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let x86_bin = manifest_dir.join("../../tests/fixtures-src/tiny_bin");
        if !x86_bin.is_file() {
            eprintln!("SKIP: tiny_bin not present");
            return;
        }
        let mut session = ConsoleSession::new(&cfg).expect("console session");
        let mappings = crate::native::load_native_mappings(&x86_bin).unwrap_or_default();
        let base = mappings
            .first()
            .map(|m| m.vaddr.wrapping_sub(m.file_off))
            .unwrap_or(0);
        session.load(&x86_bin, base).expect("load tiny_bin");

        let flow_ret = session.flow(0x400479).expect("x86 ret flow");
        assert_eq!(flow_ret.kind, FlowKind::Return);
        assert_eq!(flow_ret.length, 1);

        let flow_fall = session.flow(0x400466).expect("x86 fall flow");
        assert_eq!(flow_fall.kind, FlowKind::Fallthrough);
        assert_eq!(flow_fall.length, 1);
        assert_eq!(flow_fall.fallthrough, Some(0x400467));

        session.quit().unwrap();
    }

    #[test]
    fn linkage_queries_require_bounded_side_effect_free_slot_flow() {
        let mut cfg = RuntimeConfig::from_env();
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/x86/data/languages");
        if find_console(&cfg).is_err() {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        }
        // LLVM llvm-mc encodings; every positive computes the slot at 0x3008.
        let cases: &[(&str, &str, &[u8], &[u8], &[u8])] = &[
            (
                "x86",
                "x86:LE:64:default",
                &[0xff, 0x25, 0x02, 0x20, 0, 0],
                &[0xff, 0xe0],
                &[0xb8, 1, 0, 0, 0],
            ),
            (
                "x86",
                "x86:LE:32:default",
                &[0xff, 0x25, 0x08, 0x30, 0, 0],
                &[0xff, 0xe0],
                &[0xb8, 1, 0, 0, 0],
            ),
            (
                "AARCH64",
                "AARCH64:LE:64:v8A",
                &[0x10, 0, 0, 0xd0, 0x11, 6, 0x40, 0xf9, 0x20, 2, 0x1f, 0xd6],
                &[0x20, 2, 0x1f, 0xd6],
                &[0x20, 0, 0x80, 0xd2],
            ),
            (
                "PowerPC",
                "PowerPC:BE:32:default",
                &[
                    0x3d, 0x60, 0, 0, 0x81, 0x6b, 0x30, 8, 0x7d, 0x69, 3, 0xa6, 0x4e, 0x80, 4, 0x20,
                ],
                &[0x4e, 0x80, 4, 0x20],
                &[0x38, 0x60, 0, 1],
            ),
        ];
        for &(processor, language, code, unknown, extra_write) in cases {
            let mut cfg = cfg.clone();
            cfg.language_id = language.into();
            cfg.language_dir = cfg
                .ghidra_install
                .join(format!("Ghidra/Processors/{processor}/data/languages"));
            let mut bytes = vec![0; 0x300];
            bytes[..code.len()].copy_from_slice(code);
            bytes[0x100..0x100 + unknown.len()].copy_from_slice(unknown);
            bytes[0x200..0x200 + extra_write.len()].copy_from_slice(extra_write);
            bytes[0x200 + extra_write.len()..0x200 + extra_write.len() + code.len()]
                .copy_from_slice(code);
            let import = NativeImport {
                language: language.into(),
                mappings: vec![crate::native::Mapping {
                    vaddr: 0x1000,
                    size: bytes.len() as u64,
                    file_off: 0,
                    flags: 6,
                    bytes,
                }],
                ..Default::default()
            };
            let mut session = ConsoleSession::new(&cfg).unwrap();
            session.load_mapped(&import).unwrap();
            let rows = session.linkage_batch(&[0x1000, 0x1100, 0x1200]).unwrap();
            assert_eq!(rows[0].slot, Some(0x3008), "{language}");
            assert_eq!(rows[0].length as usize, code.len(), "{language}");
            assert!(
                rows[1].slot.is_none(),
                "{language}: unknown incoming register"
            );
            assert!(rows[2].slot.is_none(), "{language}: unused register write");
            // A rejected query must not poison the following console request.
            assert_eq!(session.flow(0x1000).unwrap().address, 0x1000);
        }
        let mut session = ConsoleSession::new(&cfg).unwrap();
        let mut bytes = vec![0; 0x300];
        // A store to a constant address, followed by a valid indirect transfer.
        bytes[..13].copy_from_slice(&[0xc6, 5, 0, 0, 0, 0, 1, 0xff, 0x25, 0xfb, 0x1f, 0, 0]);
        // One load, seven self-copies, one jump: exceeds the eight-instruction bound.
        bytes[0x100..0x107].copy_from_slice(&[0x48, 0x8b, 5, 1, 0x1f, 0, 0]);
        for i in 0..7 {
            bytes[0x107 + i * 3..0x10a + i * 3].copy_from_slice(&[0x48, 0x89, 0xc0]);
        }
        bytes[0x11c..0x11e].copy_from_slice(&[0xff, 0xe0]);
        session
            .load_mapped(&NativeImport {
                language: cfg.language_id.clone(),
                mappings: vec![crate::native::Mapping {
                    vaddr: 0x1000,
                    size: bytes.len() as u64,
                    file_off: 0,
                    flags: 6,
                    bytes,
                }],
                ..Default::default()
            })
            .unwrap();
        let rows = session.linkage_batch(&[0x1000, 0x1100]).unwrap();
        assert!(
            rows.iter().all(|row| row.slot.is_none()),
            "stores and unbounded chains are not thunks"
        );
    }

    #[test]
    fn elf_pattern_selection_uses_loader_compiler() {
        let mut cfg = crate::session::RuntimeConfig::from_env();
        let Ok(console) = find_console(&cfg) else {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        };
        cfg.console_path = Some(console);
        cfg.language_id = "x86:LE:64:default".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/x86/data/languages");
        // ELF64 with one allocated code section: ret; push rbp; mov rbp,rsp; ret.
        // The pinned GCC patterns recognize the entry after ret; Windows does not.
        let mut elf = vec![0u8; 0x200];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (offset, value) in [(16, 2u16), (18, 62), (58, 64), (60, 2)] {
            elf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        elf[40..48].copy_from_slice(&0x80u64.to_le_bytes());
        elf[0xc4..0xc8].copy_from_slice(&1u32.to_le_bytes());
        for (offset, value) in [(0xc8, 6u64), (0xd0, 0x1000), (0xd8, 0x180), (0xe0, 6)] {
            elf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        elf[0x180..0x186].copy_from_slice(&[0xc3, 0x55, 0x48, 0x89, 0xe5, 0xc3]);
        let import = crate::native::import_elf(&elf).unwrap();
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session.load_mapped(&import).unwrap();
        session.send("functionstarts 0x1000 0x1006\n").unwrap();
        let response = read_until_prompt(&mut session.reader).unwrap();
        let payload = response
            .lines()
            .find_map(|line| line.strip_prefix("PATTERNS "))
            .unwrap_or_else(|| panic!("missing pattern response: {response}"));
        let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert!(
            parsed["matches"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["address"] == 0x1001),
            "ELF compiler selection must recognize the GCC entry: {response}"
        );
    }

    #[test]
    fn function_pattern_queries_preserve_prefix_marks_and_range_bounds() {
        let mut cfg = crate::session::RuntimeConfig::from_env();
        let Ok(console) = find_console(&cfg) else {
            eprintln!("SKIP: SLEIGH console not available");
            return;
        };
        cfg.console_path = Some(console);
        cfg.language_id = "AARCH64:LE:64:v8A".into();
        cfg.language_dir = cfg
            .ghidra_install
            .join("Ghidra/Processors/AARCH64/data/languages");
        let query = |session: &mut ConsoleSession, end: u64| {
            session
                .send(&format!("functionstarts 0x1000 0x{end:x}\n"))
                .unwrap();
            let response = read_until_prompt(&mut session.reader).unwrap();
            let payload = response
                .lines()
                .find_map(|line| line.strip_prefix("PATTERNS "))
                .unwrap_or_else(|| panic!("missing pattern response: {response}"));
            let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();
            let mut addresses: Vec<_> = parsed["matches"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["address"].as_u64().unwrap())
                .collect();
            addresses.sort_unstable();
            addresses.dedup();
            addresses
        };
        let cases: &[(&[u32], &[u64])] = &[
            // ret; nop; stp x29,x30,[sp,#-32]!; mov x29,sp; ret.
            // Both the wildcard prefix and the pair's post-pattern mark match.
            (
                &[0xd65f03c0, 0xd503201f, 0xa9be7bfd, 0x910003fd, 0xd65f03c0],
                &[0x1004, 0x1008],
            ),
            // ret; sub sp,sp,#16; add sp,sp,#16; ret: pair-only match.
            (&[0xd65f03c0, 0xd10043ff, 0x910043ff, 0xd65f03c0], &[0x1004]),
        ];
        for &(words, expected) in cases {
            let bytes: Vec<_> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let end = 0x1000 + bytes.len() as u64;
            let mut session = ConsoleSession::new(&cfg).unwrap();
            session
                .load_mapped(&NativeImport {
                    language: cfg.language_id.clone(),
                    mappings: vec![crate::native::Mapping {
                        vaddr: 0x1000,
                        size: bytes.len() as u64,
                        file_off: 0,
                        flags: 6,
                        bytes,
                    }],
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(query(&mut session, end).as_slice(), expected);
            assert!(
                query(&mut session, 0x1007).is_empty(),
                "a pattern must not read past the requested mapped range"
            );
        }

        // A private pattern root exercises DSL boundaries without modifying the SDK.
        struct PatternRoot(PathBuf);
        impl Drop for PatternRoot {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root =
            std::env::temp_dir().join(format!("ventris-pattern-grammar-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let root = PatternRoot(root);
        let patterns = root.0.join("Ghidra/Processors/Fixture/data/patterns");
        std::fs::create_dir_all(&patterns).unwrap();
        std::fs::write(
            patterns.join("patternconstraints.xml"),
            r#"
<patternconstraints><language id="AARCH64:*:64:*">
  <patternfile>grammar.xml</patternfile>
  <compiler id="not-the-selected-compiler"><patternfile>missing.xml</patternfile></compiler>
</language></patternconstraints>"#,
        )
        .unwrap();
        std::fs::write(
            patterns.join("grammar.xml"),
            r#"
<patternlist>
  <pattern mark="0"><data>0xa. * 1011....</data>
    <align mark="0x100000001" bits="2"/><possiblefuncstart/>
  </pattern>
  <patternpairs totalbits="9" postbits="4">
    <prepatterns><data>0xc.</data></prepatterns>
    <postpatterns><data>0xd.</data><funcstart/></postpatterns>
  </patternpairs>
  <patternpairs totalbits="8" postbits="5">
    <prepatterns><data>0xe.</data></prepatterns>
    <postpatterns><data>0xf.</data><funcstart/></postpatterns>
  </patternpairs>
</patternlist>"#,
        )
        .unwrap();
        cfg.ghidra_install = root.0.clone();
        let mut bytes = vec![0; 0x10002];
        bytes[3..5].copy_from_slice(&[0xa1, 0xb2]);
        bytes[0xffff..0x10001].copy_from_slice(&[0xa3, 0xb4]);
        bytes[0x13..0x15].copy_from_slice(&[0xc1, 0xd2]);
        bytes[0x17..0x19].copy_from_slice(&[0xe3, 0xf4]);
        let mut session = ConsoleSession::new(&cfg).unwrap();
        session
            .load_mapped(&NativeImport {
                language: cfg.language_id.clone(),
                mappings: vec![crate::native::Mapping {
                    vaddr: 0x1000,
                    size: bytes.len() as u64,
                    file_off: 0,
                    flags: 6,
                    bytes,
                }],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            query(&mut session, 0x11002),
            vec![0x1004, 0x11000],
            "marks override attributes; alignment uses the raw start; fixed-bit thresholds apply"
        );
        assert_eq!(
            query(&mut session, 0x11000),
            vec![0x1004],
            "a match across a scan-buffer boundary still needs its complete byte sequence"
        );
    }
}
