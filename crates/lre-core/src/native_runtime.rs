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

use crate::native::{pe_image_base, NativeImport};
use crate::session::RuntimeConfig;
use std::path::{Path, PathBuf};
use std::process::Command;

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

fn console_output(cfg: &RuntimeConfig, binary: &Path, address: &str) -> Result<String> {
    let console = cfg
        .console_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("native/build/decomp_native"));
    let ghroot = cfg.ghidra_install.to_string_lossy().into_owned();
    let langs = cfg.language_dir.to_string_lossy().into_owned();
    if !console.is_file() {
        return err(format!(
            "SLEIGH console missing: {} — build native/build_console.sh \
             (needs binutils-devel) or configure console_path",
            console.display()
        ));
    }
    let hex_addr = if address.starts_with("0x") {
        address.to_string()
    } else {
        format!("0x{address}")
    };
    let bfd_target = bfd_target_for(&cfg.language_id, binary)?;
    let load_script = if cfg.language_id.starts_with("x86:") {
        format!(
            "load file {} {}\nadjust vma 0x400000\n",
            bfd_target,
            binary.display()
        )
    } else {
        format!("load file {} {}\n", bfd_target, binary.display())
    };
    let script = format!(
        "{load_script}map function {hex_addr} func\nload function func\ndisassemble\n",
    );
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
pub fn disasm_native(cfg: &RuntimeConfig, binary: &Path, address: &str, count: u32) -> Result<String> {
    let output = console_output(cfg, binary, address)?;
    let lines = filtered_listing(&output, count, false);
    if lines.is_empty() {
        return err("console produced no listing");
    }
    Ok(lines.join("\n"))
}

/// Runs the same console request as `disasm_native`, preserving structural
/// marker lines for the Core listing parser.
pub fn listing_native(cfg: &RuntimeConfig, binary: &Path, address: &str, count: u32) -> Result<String> {
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
) -> Result<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf, String)> {
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
    let spec = specs
        .iter()
        .find(|s| s.id == language)
        .ok_or_else(|| {
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
    let bundle = cfg
        .spec_root
        .join(language.replace(':', "-"));
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
            pe_image_base(&data).unwrap_or(0x400000)
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

/// Console-driven function discovery: the pinned console disassembles each
/// seeded function with the real SLEIGH translator; direct call targets
/// become new seeds until closure. Returns (entry -> size, calls).
///
/// This is the closure machinery `import-native --discover` uses (and the
/// auto-`wants_flow` heuristic), kept console-bound: the in-Rust flow walk
/// in `disasm::discover` handles the direct-call closure; the console adds
/// the ELF `_start` RDI convention and SLEIGH-exact disconnections.
pub fn console_discover(
    cfg: &RuntimeConfig,
    binary: &Path,
    seeds: &[u64],
) -> Result<(Vec<(u64, u64)>, Vec<(u64, u64)>)> {
    use std::io::{BufReader, Read as _, Write as _};
    let console = cfg
        .console_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("native/build/decomp_native"));
    let ghroot = cfg.ghidra_install.to_string_lossy().into_owned();
    let langs = cfg.language_dir.to_string_lossy().into_owned();
    if !console.is_file() {
        return err(format!(
            "SLEIGH console missing: {} — build native/build_console.sh or \
             configure console_path",
            console.display()
        ));
    }
    let mut child = Command::new(&console)
        .arg("-s")
        .arg(&langs)
        .env("SLEIGHHOME", &ghroot)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| NativeRuntimeError(format!("console spawn: {e}")))?;
    let mut stdin = child.stdin.take().expect("console stdin");
    let stdout = child.stdout.take().expect("console stdout");
    let mut reader = BufReader::new(stdout);

    let bfd_target = bfd_target_for(&cfg.language_id, binary)?;
    let init_script = if cfg.language_id.starts_with("x86:") {
        format!(
            "load file {} {}\nadjust vma 0x400000\n",
            bfd_target,
            binary.display()
        )
    } else {
        format!("load file {} {}\n", bfd_target, binary.display())
    };
    stdin
        .write_all(init_script.as_bytes())
        .and_then(|_| stdin.flush())
        .map_err(|e| NativeRuntimeError(format!("console write: {e}")))?;
    // The prompt "[decomp]> " carries no trailing newline, so line reads
    // deadlock; each command's response is read until the next prompt.
    for _ in 0..2 {
        read_until_prompt(&mut reader)?;
    }
    // The initial seed list is uncapped (import may have found thousands of
    // functions); discovery processes at most the first 64 per the same
    // budget that caps seeds discovered mid-round.
    let mut pending_seeds: Vec<u64> = seeds.iter().copied().take(64).collect();
    let mut all: Vec<(u64, u64)> = Vec::new();
    let mut calls: Vec<(u64, u64)> = Vec::new();
    let mut seen: Vec<u64> = Vec::new();
    let mut rounds = 0;
    // Discovery budget: large binaries (libc-class) disassemble slowly per
    // function; the in-Rust walk already covers the closure, so the console
    // pass stops on time rather than blocking imports for minutes.
    let budget = std::time::Duration::from_secs(60);
    let deadline = std::time::Instant::now() + budget;
    while !pending_seeds.is_empty() && rounds < 8 {
        rounds += 1;
        let this_round = std::mem::take(&mut pending_seeds);
        for (i, s) in this_round.iter().enumerate() {
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                return derive_functions(all, calls);
            }
            let script = format!(
                "map function {s:#x} f{i}\nload function f{i}\ndisassemble\n"
            );
            stdin
                .write_all(script.as_bytes())
                .and_then(|_| stdin.flush())
                .map_err(|e| NativeRuntimeError(format!("console write: {e}")))?;
            all.push((*s, 0));
            let mut last_addr: Option<u64> = None;
            // One prompt per command; each chunk carries the echoed command
            // and its output, terminated by the next prompt.
            for _ in 0..3 {
                let chunk = read_until_prompt(&mut reader)?;
                for line_buf in chunk.lines() {
                let line = line_buf.trim_end();
                let line = line.strip_prefix("[decomp]> ").unwrap_or(line);
                if line.is_empty() {
                    continue;
                }
                if let Some(rest) = line.strip_prefix("0x") {
                    if let Some((addr_s, tail)) = rest.split_once(':') {
                        if let Ok(addr) = u64::from_str_radix(addr_s.trim(), 16) {
                            last_addr = Some(addr);
                            // ELF startup convention: right before the indirect
                            // __libc_start_main GOT call, RDI holds main. Capped
                            // like the CALL handler: on libc-class binaries every
                            // MOV RDI immediate would otherwise become a seed.
                            if tail.contains("MOV") && tail.contains("RDI")
                                && pending_seeds.len() < 64
                            {
                                let mov_line = tail.split(',').nth(1).unwrap_or("");
                                for tok in mov_line.split_whitespace() {
                                    if let Ok(t) = u64::from_str_radix(
                                        tok.trim_start_matches("0x").trim_end_matches(','),
                                        16,
                                    ) {
                                        if !seen.contains(&t) && t != 0 {
                                            seen.push(t);
                                            pending_seeds.push(t);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if line.contains("CALL") && line.contains(":") {
                    let after = line.split(':').last().unwrap_or("");
                    let mut toks = after.split_whitespace();
                    let _ = toks.next();
                    if let Some(op) = toks.next() {
                        let clean = op.trim_end_matches(';');
                        if let Ok(t) = u64::from_str_radix(clean.trim_start_matches("0x"), 16) {
                            let frm = last_addr.unwrap_or(0);
                            if t != 0 && !calls.iter().any(|(f, c)| *f == frm && *c == t) {
                                calls.push((frm, t));
                            }
                            if !seen.contains(&t)
                                && !this_round.contains(&t)
                                && pending_seeds.len() < 64
                            {
                                seen.push(t);
                                pending_seeds.push(t);
                            }
                        }
                    }
                }
            }
            }
        }
    }
    let _ = stdin.write_all(b"\n");
    let _ = stdin.flush();
    drop(stdin);
    let _ = child.wait();
    derive_functions(all, calls)
}

/// Derives function sizes from the sorted discovered entry list.
fn derive_functions(all: Vec<(u64, u64)>, calls: Vec<(u64, u64)>)
    -> Result<(Vec<(u64, u64)>, Vec<(u64, u64)>)>
{
    let mut funcs: Vec<(u64, u64)> = Vec::new();
    let mut sorted: Vec<u64> = all.iter().map(|(a, _)| *a).collect();
    sorted.sort_unstable();
    sorted.dedup();
    for (i, a) in sorted.iter().enumerate() {
        let next = sorted.get(i + 1).copied().unwrap_or(a + 16);
        funcs.push((*a, next - *a));
    }
    Ok((funcs, calls))
}

/// Reads console output until the interactive prompt "[decomp]> " is seen.
/// The prompt carries no trailing newline, so `read_line` deadlocks; the
/// console also buffers, so the read must be byte-wise.
fn read_until_prompt(
    reader: &mut std::io::BufReader<std::process::ChildStdout>,
) -> Result<String> {
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
    let mut magic = [0u8; 2];
    let mut file = std::fs::File::open(binary)
        .map_err(|e| NativeRuntimeError(format!("bfd target probe: {e}")))?;
    let got = file
        .read(&mut magic)
        .map_err(|e| NativeRuntimeError(format!("bfd target probe: {e}")))?;
    let pe = got == 2 && &magic == b"MZ";
    let sixty_four = language_id.contains(":64:");
    Ok(match (pe, sixty_four) {
        (true, true) => "pei-x86-64".into(),
        (true, false) => "pei-i386".into(),
        (false, true) => "elf64-x86-64".into(),
        (false, false) => "elf32-i386".into(),
    })
}

/// Convenience: seeds for the console discovery rounds from an import
/// (the CLI's `wants_flow` heuristic + seed filter).
pub fn console_seeds(imp: &NativeImport) -> Vec<u64> {
    let code = crate::native::code_ranges(imp);
    let in_code = |a: u64| code.iter().any(|(v, e)| a >= *v && a < *e);
    imp.functions
        .iter()
        .map(|f| f.entry)
        .chain(imp.externals.iter().map(|(a, _)| *a))
        .filter(|a| *a != 0 && in_code(*a))
        .collect()
}
