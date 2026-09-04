use lre_core::native::load_native;
use std::{env, path::Path, time::Instant};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: bench_load_native <binary>");
        std::process::exit(2);
    }

    let path = Path::new(&args[1]);
    let start = Instant::now();
    let imp = load_native(path).expect("load_native failed");
    let wall = start.elapsed().as_secs_f64();

    let mut entries: Vec<String> = imp
        .functions
        .iter()
        .map(|f| format!("{:08x}", f.entry))
        .collect();
    entries.sort_unstable();

    let out = serde_json::json!({
        "wall_s": wall,
        "count": entries.len(),
        "entries": entries,
    });
    println!("{}", out);
}
