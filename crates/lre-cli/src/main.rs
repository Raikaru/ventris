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
  lre-cli decompile-native <binary> <address> [--name NAME] [--project DIR] [--base HEX]
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

fn console_discover(
    binary: &str,
    seeds: &[u64],
) -> Result<(Vec<(u64, u64)>, Vec<(u64, u64)>), String> {
    use std::io::{BufRead, BufReader, Write as _};
    let console = std::env::var("VENTRIS_CONSOLE")
        .unwrap_or_else(|_| "native/build/decomp_native".into());
    let ghroot = std::env::var("VENTRIS_GHROOT")
        .unwrap_or_else(|_| ghidra_dir(&[]).to_string_lossy().into_owned());
    let langs = std::env::var("VENTRIS_LANGS")
        .unwrap_or_else(|_| ghidra_dir(&[]).join("Ghidra/Processors/x86/data/languages").to_string_lossy().into_owned());
    let mut child = std::process::Command::new(&console)
        .arg("-s")
        .arg(&langs)
        .env("SLEIGHHOME", &ghroot)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    // init the session once (2 extra prompts outside the rounds).
    let init_script = format!(
        "load file x86:LE:64:default {binary}\nadjust vma 0x400000\n"
    );
    stdin
        .write_all(init_script.as_bytes())
        .map_err(|e| e.to_string())?;
    stdin.flush().map_err(|e| e.to_string())?;
    let mut line_buf = String::new();
    for _ in 0..2 {
        line_buf.clear();
        let n = reader.read_line(&mut line_buf).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("console closed during init".into());
        }
    }
    let mut pending: Vec<String> = Vec::new();
    let mut pending_seeds: Vec<u64> = seeds.to_vec();
    let mut all: Vec<(u64, u64)> = Vec::new(); // (entry, size)
    let mut calls: Vec<(u64, u64)> = Vec::new();
    let mut seen: Vec<u64> = Vec::new();
    let mut rounds = 0;
    while !pending_seeds.is_empty() && rounds < 8 {
        rounds += 1;
        let this_round = std::mem::take(&mut pending_seeds);
        for (i, s) in this_round.iter().enumerate() {
            pending.push(format!("map function {s:#x} f{i}"));
            pending.push(format!("load function f{i}"));
            pending.push("disassemble".into());
            all.push((*s, 0)); // the mapped function is the function
        }
        // write + drain until the round's prompts are exhausted
        let expected_prompts = this_round.len() * 3;
        let script = pending.join("\n") + "\n";
        stdin.write_all(script.as_bytes()).map_err(|e| e.to_string())?;
        stdin.flush().map_err(|e| e.to_string())?;
        pending.clear();
        let mut last_addr: Option<u64> = None;
        let mut line_buf = String::new();
        let mut prompts_seen = 0usize;
        while prompts_seen < expected_prompts {
            line_buf.clear();
            let n = reader
                .read_line(&mut line_buf)
                .map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            let line = line_buf.trim_end();
            if line.ends_with("> ") || line.ends_with("decomp]>") {
                prompts_seen += 1;
                continue;
            }
            // "0x00400466: PUSH      RBP"
            if let Some(rest) = line.strip_prefix("0x") {
                if let Some((addr_s, tail)) = rest.split_once(':') {
                    if let Ok(addr) = u64::from_str_radix(addr_s.trim(), 16) {
                        last_addr = Some(addr);
                        // ELF startup convention: right before the indirect
                        // __libc_start_main GOT call, RDI holds main.
                        if tail.contains("MOV") && tail.contains("RDI") {
                            let after = tail.split(':').next().unwrap_or("");
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
                                        if !seen.contains(&t) && !this_round.contains(&t) && pending_seeds.len() < 64 {
                            seen.push(t);
                            pending_seeds.push(t);
                        }
                    }
                }
            }
        }
        // close the round: leave the console ready for the next batch
    }
    let _ = stdin;
    let _ = child.wait();
    // sizes: distance to the next entry
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

fn run_inner(args: &[String]) -> Result<(), String> {
    let core = Core::open(&project_dir(args)).map_err(|e| e.to_string())?;
    let cmd = args[1].as_str();
    match cmd {
        "disasm-native" => {
            let binary = args.get(2).ok_or("disasm-native needs a binary path")?.clone();
            let addr = args.get(3).ok_or("disasm-native needs a vaddr (hex)")?.clone();
            let console = std::env::var("VENTRIS_CONSOLE")
                .unwrap_or_else(|_| "native/build/decomp_native".into());
            let ghroot = std::env::var("VENTRIS_GHROOT")
                .unwrap_or_else(|_| ghidra_dir(&[]).to_string_lossy().into_owned().into());
            let langs = std::env::var("VENTRIS_LANGS")
                .unwrap_or_else(|_| ghidra_dir(&[]).join("Ghidra/Processors/x86/data/languages").to_string_lossy().into_owned().into());
            use std::io::Write as _;
            let mut child = std::process::Command::new(&console)
                .arg("-s")
                .arg(&langs)
                .env("SLEIGHHOME", &ghroot)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .map_err(|e| e.to_string())?;
            let mut stdin = child.stdin.take().unwrap();
            let hex_addr = if addr.starts_with("0x") {
                addr.clone()
            } else {
                format!("0x{addr}")
            };
            let script = format!(
                "load file x86:LE:64:default {binary}\nadjust vma 0x400000\nmap function {hex_addr} func\nload function func\ndisassemble\n"
            );
            stdin.write_all(script.as_bytes()).map_err(|e| e.to_string())?;
            drop(stdin);
            let out = child.wait_with_output().map_err(|e| e.to_string())?;
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if line.trim_start().starts_with(|c: char| c.is_ascii_hexdigit() || c == ':') {
                    println!("{line}");
                }
            }
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
            let imp = lre_core::native::load_native(Path::new(&binary))
                .map_err(|e| e.to_string())?;
            let mut found = false;
            for m in &imp.mappings {
                if vaddr >= m.vaddr && vaddr + size as u64 <= m.vaddr + m.size {
                    let off = (vaddr - m.vaddr) as usize;
                    for b in &m.bytes[off..off + size] {
                        print!("{b:02x} ");
                    }
                    println!();
                    found = true;
                    break;
                }
            }
            if !found {
                return Err(format!("no mapping covers {vaddr:#x}..+{size:#x}"));
            }
        }

/// Console-driven function discovery: the pinned console disassembles each
/// mapped function with the real SLEIGH translator; direct call targets
/// become new seeds until closure. Returns (entry->size, calls) as hex
/// strings. Requires VENTRIS_CONSOLE/VENTRIS_GHROOT/VENTRIS_LANGS env
/// (defaults mirror the spike layout).
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
            let mut imp = lre_core::native::load_native(Path::new(&binary))
                .map_err(|e| e.to_string())?;
            // Console-driven flow discovery (stripped binaries): env
            // VENTRIS_CONSOLE/{GHROOT,LANGS} must point at the pinned
            // console + language dirs.
            let wants_flow = args.iter().any(|a| a == "--discover")
                || imp.functions.iter().filter(|f| !f.name.starts_with("_")).count() <= 2;
            if wants_flow {
                let code = lre_core::native::code_ranges(&imp);
                let seeds: Vec<u64> = imp
                    .functions
                    .iter()
                    .map(|f| f.entry)
                    .chain(imp.externals.iter().map(|(a, _)| *a))
                    .filter(|a| *a != 0 && code.iter().any(|(v, e)| *a >= *v && *a < *e))
                    .collect();
                match console_discover(&binary, &seeds) {
                    Ok((funcs, calls)) => {
                        for (entry, size) in funcs {
                            if !imp.functions.iter().any(|f| f.entry == entry) {
                                let name = lre_core::native::extern_name(&imp, entry)
                                    .unwrap_or_else(|| format!("FUN_{entry:08x}"));
                                imp.functions.push(lre_core::native::NativeFunction {
                                    entry,
                                    name,
                                    size: size.max(1),
                                });
                            }
                        }
                        for (from, to) in calls {
                            if !imp.xrefs.iter().any(|x| x.from == from && x.to == to) {
                                imp.xrefs.push(lre_core::native::NativeXref {
                                    from,
                                    to,
                                    kind: "UNCONDITIONAL_CALL".into(),
                                });
                            }
                        }
                    }
                    Err(e) => eprintln!("console discovery skipped: {e}"),
                }
            }
            let db = core.store_handle().map_err(|e| e.to_string())?;
            let summary = lre_core::native::store_import(&db, &program, &imp)
                .map_err(|e| e.to_string())?;
            println!(
                "imported {} natively ({} functions, {} xrefs, {})",
                summary.program,
                summary.functions,
                imp.xrefs.len(),
                imp.format
            );
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
            let opt = std::env::var("VENTRIS_GHIDRA_OPT")
                .unwrap_or_else(|_| "native/build/ghidra_opt".into());
            let specs = std::env::var("VENTRIS_SPECS")
                .unwrap_or_else(|_| "native/specs".into());
            let worker = std::env::var("VENTRIS_WORKER")
                .unwrap_or_else(|_| "target/debug/lre-worker".into());
            // The patched ghidra_opt self-disassembles only when VENTRIS_SLA
            // names a compiled .sla (see native/build_ghidra_opt.sh).
            std::env::var("VENTRIS_SLA").map_err(|_| {
                "VENTRIS_SLA must point at the compiled x86-64.sla \
                (build with native/build_ghidra_opt.sh)"
                    .to_string()
            })?;
            if !Path::new(&opt).is_file() {
                return Err(format!(
                    "native decompiler missing: {opt} — build it via native/build_ghidra_opt.sh"
                ));
            }
            if !Path::new(&specs).join("tspec.xml").is_file() {
                return Err(format!(
                    "spec dir incomplete: {specs} (needs tspec.xml; use native/specs)"
                ));
            }
            let base = match flag(args, "--base") {
                Some(b) => u64::from_str_radix(b.trim_start_matches("0x"), 16)
                    .map_err(|e| e.to_string())?,
                None => {
                    let data = std::fs::read(&binary).map_err(|e| e.to_string())?;
                    lre_core::native::pe_image_base(&data).unwrap_or(0x400000)
                }
            };
            let proj = project_dir(args);
            let out = std::process::Command::new(&worker)
                .arg(&opt)
                .arg(&specs)
                .arg(&binary)
                .arg(&program)
                .arg(&address)
                .arg("--project")
                .arg(&proj)
                .arg("--base")
                .arg(format!("{base:#x}"))
                .output()
                .map_err(|e| format!("worker: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "worker failed ({}): {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            print!("{}", String::from_utf8_lossy(&out.stdout));
        }
        _ => return Err(format!("unknown command: {cmd}")),
    }
    Ok(())
}
