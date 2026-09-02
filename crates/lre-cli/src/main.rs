//! lre-cli: scriptable automation over the Core API (spec 17.1).
//!
//! End-to-end sequence proven by this binary:
//!   lre-cli import <binary> [--project DIR]
//!   lre-cli open <program> [--project DIR]
//!   lre-cli functions <program> [--project DIR]
//!   lre-cli symbols <program>
//!   lre-cli xrefs <program> --to|--from <address>
//!   lre-cli rename <program> <address> <name>
//!   lre-cli decompile <program> <address>   (bridge required)
//!   lre-cli disasm <program> <address> [-n N]
//!   lre-cli open <program>                  (store-only reopen: no JVM)
//!
//! The native commands (`import-native`, `mem`, `disasm-native`,
//! `decompile-native`) are thin delegates to Core — the same methods a GUI
//! consumes — so no consumer has to re-implement the spawn logic.

use lre_core::{bridge::Bridge, Core};
use std::path::{Path, PathBuf};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
    }
    let code = run(&args);
    std::process::exit(code);
}

fn usage() {
    eprintln!(
        "usage:
  lre-cli import <binary> [--project DIR] [--ghidra DIR]
  lre-cli import-native <binary> [--name NAME] [--project DIR]   (no JVM)
  lre-cli architectures [--project DIR]   (uses VENTRIS_GHIDRA)
  lre-cli functions <program> [--project DIR]
  lre-cli symbols <program> [--project DIR]
  lre-cli strings <program> [--project DIR]
  lre-cli search <program> <term> [--limit N] [--project DIR]
  lre-cli graph <program> [--project DIR]
  lre-cli memory-regions <program> [--project DIR]
  lre-cli bookmarks <program> [--project DIR]
  lre-cli bookmark <program> <address> <label> [comment] [--project DIR]
  lre-cli patches <program> [--project DIR]
  lre-cli patch <program> <address> <original-hex> <patched-hex> [--disabled] [--project DIR]
  lre-cli rename <program> <address> <new-name> [--project DIR]
  lre-cli decompile <program> <address> [--ghidra DIR]
  lre-cli disasm <program> <address> [-n N] [--ghidra DIR]
  lre-cli decompile-native <binary> <address> [--name NAME] [--project DIR] [--base HEX]
  lre-cli decompile-native-doc <binary> <address> [--name NAME] [--project DIR] [--base HEX]
  lre-cli disasm-native <binary> <address> [-n N]                  (no JVM)
  lre-cli dump-specs <program> --out <dir> [--ghidra DIR]"
        );
    std::process::exit(2);
}


fn parse_bytes(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim_start_matches("0x");
    if value.len() % 2 != 0 {
        return Err(format!("hex byte string has odd length: {value}"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
            u8::from_str_radix(text, 16).map_err(|e| format!("bad byte {text}: {e}"))
        })
        .collect()
}

fn hex_bytes(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn project_dir(args: &[String]) -> PathBuf {
    flag(args, "--project")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".lre"))
}

/// Launch the bridge JVM against the pinned install.
fn launch_bridge(args: &[String]) -> Result<Bridge, String> {
    let install = ghidra_dir(args);
    let classpath = find_ghidra_classpath(&install)?;
    let project = project_dir(args).join("bridge-projects");
    Bridge::launch(
        &PathBuf::from("java"),
        &classpath,
        &install,
        &project,
        &jvm_opens(),
    )
    .map_err(|e| e.to_string())
}

fn ghidra_dir(args: &[String]) -> PathBuf {
    flag(args, "--ghidra")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var("VENTRIS_GHIDRA")
                .unwrap_or_else(|_| {
                    format!(
                        "{}/ghidra_12.1.3_PUBLIC",
                        std::env::var("HOME").unwrap_or_default()
                    )
                })
                .into()
        })
}

fn jvm_opens() -> Vec<String> {
    [
        "--add-opens=java.base/java.lang=ALL-UNNAMED",
        "--add-opens=java.base/java.lang.invoke=ALL-UNNAMED",
        "--add-opens=java.base/java.lang.ref=ALL-UNNAMED",
        "--add-opens=java.base/java.util=ALL-UNNAMED",
        "--add-opens=java.base/java.io=ALL-UNNAMED",
        "--add-opens=java.desktop/java.awt=ALL-UNNAMED",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Builds the classpath from every runtime jar of the install.
fn find_ghidra_classpath(install: &Path) -> Result<String, String> {
    let pattern = install.join("Ghidra");
    let mut jars = Vec::new();
    collect_jars(&pattern, &mut jars)
        .map_err(|e| format!("classpath scan failed: {e}"))?;
    jars.retain(|p| {
        let name = p.to_string_lossy();
        !name.contains("src.zip") && !name.contains("/Extension")
    });
    if jars.is_empty() {
        return Err(format!("no Ghidra jars under {}", install.display()));
    }
    let service = service_jar();
    jars.push(service);
    Ok(jars
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(":"))
}

fn service_jar() -> PathBuf {
    // The service jar lives next to the crate; resolve from the executable's
    // build location via env override first.
    std::env::var_os("VENTRIS_SERVICE_JAR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("service/build/ventris-service.jar"))
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("service/build/ventris-service.jar"))
}

fn collect_jars(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if dir.is_file() {
        if dir.extension().map(|e| e == "jar").unwrap_or(false) {
            out.push(dir.to_path_buf());
        }
        return Ok(());
    }
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "Extension" || name.ends_with("-src.zip") {
            continue;
        }
        if path.is_dir() {
            collect_jars(&path, out)?;
        } else if name.ends_with(".jar") {
            out.push(path);
        }
    }
    Ok(())
}

fn run(args: &[String]) -> i32 {
    match run_inner(args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn run_inner(args: &[String]) -> Result<(), String> {
    let core = Core::open(&project_dir(args)).map_err(|e| e.to_string())?;
    let cmd = args[1].as_str();
    match cmd {
        "import-native" => {
            let binary = args
                .get(2)
                .ok_or("import-native needs a binary path")?
                .clone();
            let program = flag(args, "--name")
                .unwrap_or_else(|| {
                    Path::new(&binary)
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "program".into())
                });
            let summary = core
                .import_native(Path::new(&binary), &program)
                .map_err(|e| e.to_string())?;
            println!(
                "imported {} natively ({} functions, {})",
                summary.program, summary.functions, summary.language
            );
        }
        "mem" => {
            let binary = args.get(2).ok_or("mem needs a binary path")?.clone();
            let vaddr = u64::from_str_radix(
                args.get(3).ok_or("mem needs a vaddr (hex)")?,
                16,
            )
            .map_err(|e| e.to_string())?;
            let size: usize = args
                .get(4)
                .and_then(|s| s.parse().ok())
                .unwrap_or(32);
            let bytes = core
                .mem_native(Path::new(&binary), vaddr, size)
                .map_err(|e| e.to_string())?;
            for b in &bytes {
                print!("{b:02x} ");
            }
            println!();
        }
        "disasm-native" => {
            let binary = args.get(2).ok_or("disasm-native needs a binary path")?.clone();
            let addr = args.get(3).ok_or("disasm-native needs a vaddr (hex)")?.clone();
            let n: u32 = flag(args, "-n").and_then(|v| v.parse().ok()).unwrap_or(8);
            let text = core
                .disasm_native(Path::new(&binary), &addr, n)
                .map_err(|e| e.to_string())?;
            println!("{text}");
        }
        "decompile-native" => {
            let binary = args
                .get(2)
                .ok_or("decompile-native needs a binary path")?
                .clone();
            let address = args
                .get(3)
                .ok_or("decompile-native needs a vaddr (hex)")?
                .clone();
            let program = flag(args, "--name").unwrap_or_else(|| {
                Path::new(&binary)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "program".into())
            });
            let base = flag(args, "--base")
                .and_then(|b| u64::from_str_radix(b.trim_start_matches("0x"), 16).ok());
            let code = core
                .decompile_native(
                    Path::new(&binary),
                    &address,
                    &program,
                    base,
                )
                .map_err(|e| e.to_string())?;
            print!("{code}");
        }
        "decompile-native-doc" => {
            let binary = args
                .get(2)
                .ok_or("decompile-native-doc needs a binary path")?
                .clone();
            let address_arg = args
                .get(3)
                .ok_or("decompile-native-doc needs a vaddr (hex)")?
                .clone();
            let address = lre_model::Address::parse_ram_hex(&address_arg)
                .ok_or_else(|| format!("bad address: {address_arg}"))?;
            let program = flag(args, "--name").unwrap_or_else(|| {
                Path::new(&binary)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "program".into())
            });
            let base = flag(args, "--base")
                .and_then(|b| u64::from_str_radix(b.trim_start_matches("0x"), 16).ok());
            let doc = core
                .decompile_native_doc(Path::new(&binary), &address, &program, base)
                .map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string(&doc).map_err(|e| e.to_string())?
            );
        }
        "architectures" => {
            for architecture in core.architectures().map_err(|e| e.to_string())? {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    architecture.id,
                    architecture.processor,
                    architecture.endian,
                    architecture.bits.map_or_else(|| "?".into(), |bits| bits.to_string()),
                    architecture.sla_count
                );
            }
        }
        "import" => {
            let binary = args
                .get(2)
                .ok_or("import needs a binary path")?
                .clone();
            let mut bridge = launch_bridge(args)?;
            let summary = core
                .import_program(&mut bridge, "main", Path::new(&binary))
                .map_err(|e| e.to_string())?;
            println!(
                "imported {} ({} functions, {})",
                summary.program, summary.functions, summary.language
            );
            bridge.shutdown().map_err(|e| e.to_string())?;
        }
        "open" => {
            let program = args.get(2).ok_or("open needs a program name")?.clone();
            let summary = core.open_program(&program).map_err(|e| e.to_string())?;
            println!(
                "reopened {} ({} functions, {})",
                summary.program, summary.functions, summary.language
            );
        }
        "functions" => {
            let program = args.get(2).ok_or("functions needs a program name")?.clone();
            let offset: u64 = flag(args, "--offset").and_then(|v| v.parse().ok()).unwrap_or(0);
            let limit: u64 = flag(args, "--limit").and_then(|v| v.parse().ok()).unwrap_or(0);
            let rows = if limit > 0 {
                let page = core
                    .functions_page(&program, offset, limit)
                    .map_err(|e| e.to_string())?;
                println!("-- paged {}..{} of {:?} (rev {})", page.offset, page.offset + page.rows.len() as u64, page.total, page.revision);
                page.rows
            } else {
                core.functions(&program).map_err(|e| e.to_string())?
            };
            for f in &rows {
                println!("{}  {:6}  {}", f.entry, f.size, f.name);
            }
            if limit == 0 {
                println!("-- {} functions", rows.len());
            }
        }
        "comments" => {
            let program = args.get(2).ok_or("comments needs a program name")?.clone();
            let rows = core.comments(&program).map_err(|e| e.to_string())?;
            for c in &rows {
                println!("{}  [{:5}]  {}", c.address, c.kind, c.text);
            }
            println!("-- {} comments", rows.len());
        }
        "types" => {
            let program = args.get(2).ok_or("types needs a program name")?.clone();
            let rows = core.datatypes(&program).map_err(|e| e.to_string())?;
            for t in &rows {
                println!("{}  {}", t.name, t.definition);
            }
            println!("-- {} types", rows.len());
        }
        "symbols" => {
            let program = args.get(2).ok_or("symbols needs a program name")?.clone();
            let rows = core.symbols(&program).map_err(|e| e.to_string())?;
            for s in &rows {
                println!(
                    "{}  {:8}  {}  {}",
                    s.address,
                    if s.external { "EXT" } else { "LOC" },
                    s.source,
                    s.name
                );
            }
            println!("-- {} symbols", rows.len());
        }
        "strings" => {
            let program = args.get(2).ok_or("strings needs a program name")?.clone();
            let rows = core.strings(&program).map_err(|e| e.to_string())?;
            for row in &rows {
                println!("{}  [{}]  {}", row.address, row.kind, row.value);
            }
            println!("-- {} strings", rows.len());
        }
        "search" => {
            let program = args.get(2).ok_or("search needs a program name")?.clone();
            let term = args.get(3).ok_or("search needs a term")?.clone();
            let limit = flag(args, "--limit")
                .and_then(|value| value.parse().ok())
                .unwrap_or(256);
            let rows = core.search(&program, &term, limit).map_err(|e| e.to_string())?;
            for row in &rows {
                let address = row
                    .address
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "-".into());
                println!("{address}  [{}]  {}  {}", row.kind, row.name, row.context);
            }
            println!("-- {} search hits", rows.len());
        }
        "graph" => {
            let program = args.get(2).ok_or("graph needs a program name")?.clone();
            let (nodes, edges) = core.function_graph(&program).map_err(|e| e.to_string())?;
            for node in &nodes {
                println!("node {} {}", node.address, node.name);
            }
            for edge in &edges {
                println!("edge {} --{}--> {}", edge.from, edge.kind, edge.to);
            }
            println!("-- {} nodes, {} edges", nodes.len(), edges.len());
        }
        "memory-regions" => {
            let program = args.get(2).ok_or("memory-regions needs a program name")?.clone();
            let rows = core.memory_regions(&program).map_err(|e| e.to_string())?;
            for row in &rows {
                println!(
                    "{}  {:#x}  {:#x}  {}  {}",
                    row.name, row.start.offset, row.size, row.permissions, row.source
                );
            }
            println!("-- {} memory regions", rows.len());
        }
        "bookmarks" => {
            let program = args.get(2).ok_or("bookmarks needs a program name")?.clone();
            let rows = core.bookmarks(&program).map_err(|e| e.to_string())?;
            for row in &rows {
                println!("{}  {}  {}", row.address, row.label, row.comment);
            }
            println!("-- {} bookmarks", rows.len());
        }
        "bookmark" => {
            let program = args.get(2).ok_or("bookmark needs a program name")?.clone();
            let address_arg = args.get(3).ok_or("bookmark needs an address")?.clone();
            let label = args.get(4).ok_or("bookmark needs a label")?.clone();
            let comment = args
                .get(5)
                .filter(|value| !value.starts_with("--"))
                .cloned()
                .unwrap_or_default();
            let address = lre_model::Address::parse_ram_hex(&address_arg)
                .ok_or_else(|| format!("bad address: {address_arg}"))?;
            core.set_bookmark(
                &program,
                &lre_model::BookmarkRow {
                    address: address.clone(),
                    label: label.clone(),
                    comment,
                },
            )
            .map_err(|e| e.to_string())?;
            println!("bookmarked {} -> {}", address, label);
        }
        "patches" => {
            let program = args.get(2).ok_or("patches needs a program name")?.clone();
            let rows = core.patches(&program).map_err(|e| e.to_string())?;
            for row in &rows {
                println!(
                    "{}  {} -> {}  {}",
                    row.address,
                    hex_bytes(&row.original),
                    hex_bytes(&row.patched),
                    if row.enabled { "enabled" } else { "disabled" }
                );
            }
            println!("-- {} patches", rows.len());
        }
        "patch" => {
            let program = args.get(2).ok_or("patch needs a program name")?.clone();
            let address_arg = args.get(3).ok_or("patch needs an address")?.clone();
            let original = args.get(4).ok_or("patch needs original bytes")?.clone();
            let patched = args.get(5).ok_or("patch needs patched bytes")?.clone();
            let address = lre_model::Address::parse_ram_hex(&address_arg)
                .ok_or_else(|| format!("bad address: {address_arg}"))?;
            core.set_patch(
                &program,
                &lre_model::PatchRow {
                    address: address.clone(),
                    original: parse_bytes(&original)?,
                    patched: parse_bytes(&patched)?,
                    enabled: !args.iter().any(|value| value == "--disabled"),
                },
            )
            .map_err(|e| e.to_string())?;
            println!("patched {}", address);
        }
        "xrefs" => {
            let program = args.get(2).ok_or("xrefs needs a program name")?.clone();

            let addr_arg = flag(args, "--to")
                .or_else(|| flag(args, "--from"))
                .ok_or("xrefs needs --to or --from ADDRESS")?;
            let address = lre_model::Address::parse_ram_hex(&addr_arg)
                .ok_or_else(|| format!("bad address: {addr_arg}"))?;
            let rows = if args.iter().any(|a| a == "--to") {
                core.xrefs_to(&program, &address)
            } else {
                core.xrefs_from(&program, &address)
            }
            .map_err(|e| e.to_string())?;
            for r in &rows {
                println!("{} --{}--> {}", r.from, r.kind, r.to);
            }
            println!("-- {} xrefs", rows.len());
        }
        "rename" => {
            let program = args.get(2).ok_or("rename needs a program name")?.clone();
            let addr_arg = args.get(3).ok_or("rename needs an address")?.clone();
            let name = args.get(4).ok_or("rename needs a new name")?.clone();
            let address = lre_model::Address::parse_ram_hex(&addr_arg)
                .ok_or_else(|| format!("bad address: {addr_arg}"))?;
            core.rename_command(&program, &address, &name)
                .map_err(|e| e.to_string())?;
            println!("renamed {} -> {}", address, name);
        }
        "comment" => {
            let program = args.get(2).ok_or("comment needs a program name")?.clone();
            let address_arg = args.get(3).ok_or("comment needs an address")?.clone();
            let text = args.get(4).ok_or("comment needs comment text")?.clone();
            let address = lre_model::Address::parse_ram_hex(&address_arg)
                .ok_or_else(|| format!("bad address: {address_arg}"))?;
            let function = flag(args, "--function")
                .map(|value| {
                    lre_model::Address::parse_ram_hex(&value)
                        .ok_or_else(|| format!("bad function address: {value}"))
                })
                .transpose()?
                .unwrap_or_else(|| address.clone());
            let kind = flag(args, "--kind").unwrap_or_else(|| "eol".into());
            core.comment_command(&program, &address, &function, &kind, &text)
                .map_err(|e| e.to_string())?;
            println!("commented {} [{}]", address, kind);
        }
        "undo" => {
            let program = args.get(2).ok_or("undo needs a program name")?.clone();
            let what = core.undo_last(&program).map_err(|e| e.to_string())?;
            println!("{what}");
        }
        "dump-specs" => {
            let program = args.get(2).ok_or("dump-specs needs a program name")?.clone();
            let out = flag(args, "--out").ok_or("dump-specs needs --out DIR")?;
            let mut bridge = launch_bridge(args)?;
            let session = format!("cli-{program}");
            bridge
                .open(&session, &program)
                .map_err(|e| e.to_string())?;
            bridge
                .dump_specs(&session, &out)
                .map_err(|e| e.to_string())?;
            println!("specs written to {out}");
            bridge.shutdown().map_err(|e| e.to_string())?;
        }
        "decompile" | "disasm" => {
            let program = args.get(2).ok_or("command needs a program name")?.clone();
            let address = args.get(3).ok_or("command needs an address")?.clone();
            let mut bridge = launch_bridge(args)?;
            let session = format!("cli-{program}");
            bridge
                .open(&session, &program)
                .map_err(|e| e.to_string())?;
            if cmd == "decompile" {
                let code = core
                    .decompile(&mut bridge, &session, &address)
                    .map_err(|e| e.to_string())?;
                println!("{code}");
            } else {
                let n: u32 = flag(args, "-n").and_then(|v| v.parse().ok()).unwrap_or(32);
                let rows = core
                    .disassemble(&mut bridge, &session, &address, n)
                    .map_err(|e| e.to_string())?;
                for r in &rows {
                    println!("{}  {}", r.address, r.text);
                }
            }
            bridge.shutdown().map_err(|e| e.to_string())?;
        }
        _ => return Err(format!("unknown command: {cmd}")),
    }
    Ok(())
}
