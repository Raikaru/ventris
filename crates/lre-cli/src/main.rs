//! lre-cli: scriptable automation over the Core API (spec 17.1).
//!
//! End-to-end sequence proven by this binary:
//!   lre-cli import <binary> [--project DIR]
//!   lre-cli functions <program> [--project DIR]
//!   lre-cli symbols <program>
//!   lre-cli xrefs <program> --to|--from <address>
//!   lre-cli rename <program> <address> <name>
//!   lre-cli decompile <program> <address>   (bridge required)
//!   lre-cli disasm <program> <address> [-n N]
//!   lre-cli open <program>                  (store-only reopen: no JVM)

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
  lre-cli open <program> [--project DIR]                  (store-only, no JVM)
  lre-cli functions <program> [--project DIR]
  lre-cli symbols <program> [--project DIR]
  lre-cli xrefs <program> (--to | --from) <address> [--project DIR]
    lre-cli rename <program> <address> <new-name> [--project DIR]
  lre-cli decompile <program> <address> [--ghidra DIR]
  lre-cli disasm <program> <address> [-n N] [--ghidra DIR]
  lre-cli dump-specs <program> --out <dir> [--ghidra DIR]"
        );
    std::process::exit(2);
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


/// Launches the bridge JVM against the pinned install.
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
            let rows = core.functions(&program).map_err(|e| e.to_string())?;
            for f in &rows {
                println!("{}  {:6}  {}", f.entry, f.size, f.name);
            }
            println!("-- {} functions", rows.len());
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
        "xrefs" => {
            let program = args.get(2).ok_or("xrefs needs a program name")?.clone();
            let address = flag(args, "--to")
                .or_else(|| flag(args, "--from"))
                .ok_or("xrefs needs --to or --from ADDRESS")?;
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
            let address = args.get(3).ok_or("rename needs an address")?.clone();
            let name = args.get(4).ok_or("rename needs a new name")?.clone();
            core.rename_function(&program, &address, &name)
                .map_err(|e| e.to_string())?;
            println!("renamed {} -> {}", address, name);
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
