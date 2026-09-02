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

/// Performat `disasm-native`: one function mapped + disassembled by the
/// SLEIGH console, returned as the console's listing text.
pub fn disasm_native(cfg: &RuntimeConfig, binary: &Path, address: &str, count: u32) -> Result<String> {
    let console = cfg
        .console_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("native/build/decomp_native"));
    let ghroot = cfg.ghidra_install.to_string_lossy().into_owned();
    let langs = cfg
        .ghidra_install
        .join("Ghidra/Processors/x86/data/languages")
        .to_string_lossy()
        .into_owned();
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
    let script = format!(
        "load file x86:LE:64:default {}\nadjust vma 0x400000\n\
         map function {hex_addr} func\nload function func\ndisassemble\n",
        binary.display()
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
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with(|c: char| c.is_ascii_hexdigit() || c == ':') {
            lines.push(line.to_string());
        }
    }
    if lines.is_empty() {
        return err(format!(
            "console produced no listing: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(lines.into_iter().take(count as usize).collect::<Vec<_>>().join("\n"))
}

/// Performant `decompile-native`: one address decompiled by the patched
/// `ghidra_opt` through `lre-worker` (raw-SLEIGH, no JVM).
pub fn decompile_native(
    cfg: &RuntimeConfig,
    binary: &Path,
    address: &str,
    program: &str,
    project_dir: &Path,
    base: Option<u64>,
) -> Result<String> {
    let opt = &cfg.decompiler_path;
    let specs = &cfg.spec_root;
    let worker = &cfg.worker_path;
    // The patched ghidra_opt self-disassembles only when a compiled .sla is
    // configured (see native/build_ghidra_opt.sh).
    let sla = cfg.sla_path.as_ref().ok_or_else(|| {
        NativeRuntimeError(
            "no SLA configured: point VENTRIS_SLA (or RuntimeConfig::sla_path) \
             at the compiled x86-64.sla"
                .into(),
        )
    })?;
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
    let out = Command::new(worker)
        .arg(opt)
        .arg(specs)
        .arg(binary)
        .arg(program)
        .arg(address)
        .arg("--project")
        .arg(project_dir)
        .arg("--base")
        .arg(format!("{base:#x}"))
        .output()
        .map_err(|e| NativeRuntimeError(format!("worker spawn: {e}")))?;
    if !out.status.success() {
        return err(format!(
            "worker failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
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
    use std::io::{BufRead, BufReader, Write as _};
    let console = cfg
        .console_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("native/build/decomp_native"));
    let ghroot = cfg.ghidra_install.to_string_lossy().into_owned();
    let langs = cfg
        .ghidra_install
        .join("Ghidra/Processors/x86/data/languages")
        .to_string_lossy()
        .into_owned();
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

    let init_script = format!(
        "load file x86:LE:64:default {}\nadjust vma 0x400000\n",
        binary.display()
    );
    stdin
        .write_all(init_script.as_bytes())
        .and_then(|_| stdin.flush())
        .map_err(|e| NativeRuntimeError(format!("console write: {e}")))?;
    let mut line_buf = String::new();
    for _ in 0..2 {
        line_buf.clear();
        let n = reader
            .read_line(&mut line_buf)
            .map_err(|e| NativeRuntimeError(format!("console read: {e}")))?;
        if n == 0 {
            return err("console closed during init");
        }
    }
    let mut pending_seeds: Vec<u64> = seeds.to_vec();
    let mut all: Vec<(u64, u64)> = Vec::new();
    let mut calls: Vec<(u64, u64)> = Vec::new();
    let mut seen: Vec<u64> = Vec::new();
    let mut rounds = 0;
    while !pending_seeds.is_empty() && rounds < 8 {
        rounds += 1;
        let this_round = std::mem::take(&mut pending_seeds);
        let mut pending: Vec<String> = Vec::new();
        for (i, s) in this_round.iter().enumerate() {
            pending.push(format!("map function {s:#x} f{i}"));
            pending.push(format!("load function f{i}"));
            pending.push("disassemble".into());
            all.push((*s, 0));
        }
        let expected_prompts = this_round.len() * 3;
        let script = pending.join("\n") + "\n";
        stdin
            .write_all(script.as_bytes())
            .and_then(|_| stdin.flush())
            .map_err(|e| NativeRuntimeError(format!("console write: {e}")))?;
        let mut last_addr: Option<u64> = None;
        let mut prompts_seen = 0usize;
        while prompts_seen < expected_prompts {
            line_buf.clear();
            let n = reader
                .read_line(&mut line_buf)
                .map_err(|e| NativeRuntimeError(format!("console read: {e}")))?;
            if n == 0 {
                break;
            }
            let line = line_buf.trim_end();
            if line.ends_with("> ") || line.ends_with("decomp]>") {
                prompts_seen += 1;
                continue;
            }
            if let Some(rest) = line.strip_prefix("0x") {
                if let Some((addr_s, tail)) = rest.split_once(':') {
                    if let Ok(addr) = u64::from_str_radix(addr_s.trim(), 16) {
                        last_addr = Some(addr);
                        // ELF startup convention: right before the indirect
                        // __libc_start_main GOT call, RDI holds main.
                        if tail.contains("MOV") && tail.contains("RDI") {
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
    drop(stdin);
    let _ = child.wait();
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
