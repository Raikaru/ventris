//! The native decompiler worker (Stage 3 shell).
//!
//! Spawns the pinned `ghidra_opt` binary, speaks the burst/packed protocol
//! on its stdio, and answers its program queries from the project store
//! (`lre-db`) plus the raw binary via a read-only file mapping. This is the
//! no-JVM replacement for the Stage-1 bridge, per ADR-0001.

use std::io::Write;
use std::path::Path;

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
        lre_worker::BinaryBacking::from_file(Path::new(binary), base)?,
        Vec::new(),
    );
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
    for symbol in db.symbols(pid)? {
        provider
            .symbol_names
            .entry(symbol.address.offset)
            .or_insert_with(|| symbol.name.clone());
        if symbol.external {
            provider
                .external_names
                .insert(symbol.address.offset, symbol.name);
        }
    }
    for comment in db.comments(pid)? {
        provider
            .comments
            .entry(comment.function.offset)
            .or_default()
            .push((comment.address.offset, comment.kind, comment.text));
    }
    for datatype in db.datatypes(pid)? {
        provider.datatypes.insert(datatype.name, datatype.definition);
    }
    for prototype in db.prototypes(pid)? {
        if !prototype.signature.is_empty() {
            provider
                .prototypes
                .insert(prototype.function.offset, prototype.signature);
        }
    }
    for string in db.strings(pid)? {
        provider.strings.insert(string.address.offset, string.value);
    }

    let offset = u64::from_str_radix(addr.trim_start_matches("0x"), 16)
        .map_err(|e| lre_worker::WorkerError::Setup(e.to_string()))?;
    let specs = lre_worker::load_specs(Path::new(lang_dir))?;
    let mut worker = lre_worker::NativeWorker::launch(Path::new(ghidra_opt))?;
    let function_shell = provider
        .function_names
        .get(&offset)
        .map(|name| {
            let size = provider.function_sizes.get(&offset).copied().unwrap_or(8);
            lre_worker::NativeWorker::encode_function_shell_doc(
                provider.ram_space_index as u32,
                &[(offset, name.as_str(), size)],
            )
        })
        .unwrap_or_else(|| {
            lre_worker::NativeWorker::encode_function_shell_doc(
                provider.ram_space_index as u32,
                &[],
            )
        });
    worker.register_program_with_shell(
        &mut provider,
        &specs.0,
        &specs.1,
        &specs.2,
        &specs.3,
        &function_shell,
    )?;
    if let Some(signature) = provider.prototypes.get(&offset).cloned() {
        let function_name = provider
            .function_names
            .get(&offset)
            .cloned()
            .ok_or_else(|| lre_worker::WorkerError::Setup("prototype target has no function name".into()))?;
        worker.set_function_signature(&mut provider, offset, &function_name, &signature)?;
    }
    worker.set_action(&mut provider, "decompile", "")?;
    let ram = provider.ram_space_index as u32;
    let raw = worker.decompile_at(&mut provider, ram, offset)?;
    // The packed response is the source of truth for both structured tokens
    // and rendered compatibility text. `decode_tokens_with_ram_space` follows
    // PackedDecode.java and preserves token metadata; concatenation is only
    // the legacy CLI presentation boundary.
    let tokens = lre_worker::decode_tokens_with_ram_space(&raw, Some(ram as u64));
    if std::env::var_os("WORKER_STRUCTURED").is_some() {
        let doc = lre_model::DecompDoc {
            tokens,
            address: lre_model::Address::ram(offset),
            revision: 0,
        };
        println!(
            "{}",
            serde_json::to_string(&doc)
                .map_err(|e| lre_worker::WorkerError::Setup(format!("encode document: {e}")))?
        );
        return Ok(());
    }
    let c_text: String = tokens.iter().map(|token| token.text.as_str()).collect();
    if std::env::var_os("WORKER_DUMP").is_some() {
        let mut f = std::fs::File::create("/tmp/ctext_dump.txt").unwrap();
        let _ = f.write_all(c_text.as_bytes());
    }
    println!("{c_text}");
    Ok(())
}
