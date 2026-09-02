//! The native decompiler worker (Stage 3 shell).
//!
//! Spawns the pinned `ghidra_opt` binary, speaks the burst/packed protocol
//! on its stdio, and answers its program queries from the project store
//! (`lre-db`) plus the raw binary via a read-only file mapping. This is the
//! no-JVM replacement for the Stage-1 bridge, per ADR-0001.

use lre_db::ProjectDb;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
pub use lre_worker::{decode_addr_element, spec_dir, ProgramProvider};

/// the spec dir, and decompiles one function of a program in the store.
///
/// Usage:
///   lre-worker <ghidra_opt> <lang-dir> <binary> <program> <addr-hex> [--project DIR]
///
/// The language dir must contain the four spec documents (`dump_specs`
/// output) plus registers.txt; the program and its functions come from the
/// project store so the worker is the store-backed no-JVM decompiler.
fn main() {
    // Raw-SLEIGH mode: when VENTRIS_SLA points at a compiled .sla, the
    // patched (out-of-tree) ghidra_opt self-disassembles instead of asking
    // the client for pcode (see crates docs / upstream-ghidra.md).
    if let Ok(sla) = std::env::var("VENTRIS_SLA") {
        // SAFETY: set before any thread spawns; single-threaded main start.
        unsafe { std::env::set_var("VENTRIS_SLA", sla) };
    }
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!(
            "usage: lre-worker <ghidra_opt> <lang-dir> <binary> <program> <addr-hex> [--project DIR] [--base HEX]"
        );
        std::process::exit(2);
    }
    let project = std::env::args()
        .position(|a| a == "--project")
        .and_then(|i| std::env::args().nth(i + 1))
        .unwrap_or_else(|| ".lre".into());
    let base = std::env::args()
        .position(|a| a == "--base")
        .and_then(|i| std::env::args().nth(i + 1))
        .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x400000);
    if let Err(e) = run(&args[1], &args[2], &args[3], &args[4], &args[5], &project, base) {
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
    base: u64,
) -> lre_worker::Result<()> {
    let mut provider = lre_worker::ProgramProvider::new(
        lre_worker::BinaryBacking::from_file(Path::new(binary))?,
        base,
        Vec::new(),
    );
    // Section map (ELF file offsets / PE RVA-to-raw) from the native loader.
    if let Ok(imp) = lre_core::native::load_native(Path::new(binary)) {
        let maps: Vec<(u64, u64, u64)> = imp
            .mappings
            .iter()
            .map(|m| (m.vaddr, m.size, m.file_off))
            .collect();
        provider.set_mappings(maps);
    }
    provider.load_language_info(Path::new(lang_dir))?;

    // Function entries from the project store.
    let db = lre_worker::open_store(Path::new(project))?;
    let pid = db.program_id(program)?;
    for f in db.functions(pid)? {
        let off = f.entry.offset;
        provider.functions.push(off);
        provider.function_names.insert(off, f.name);
        provider.function_sizes.insert(off, f.size as u64);
    }

    let offset = u64::from_str_radix(addr.trim_start_matches("0x"), 16)
        .map_err(|e| lre_worker::WorkerError::Setup(e.to_string()))?;
    let specs = lre_worker::load_specs(Path::new(lang_dir))?;
    let mut worker = lre_worker::NativeWorker::launch(Path::new(ghidra_opt))?;
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
