use lre_debug::{BackendKind, DebugBackend};
use std::env;
use std::path::PathBuf;
use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "usage: lre-debug --backend gdb|lldb --program FILE [--timeout-ms N] \
COMMAND [ADDRESS COUNT]"
    );
    eprintln!("commands: backtrace | registers | memory");
    std::process::exit(2);
}

fn main() {
    let mut args = env::args().skip(1);
    let mut backend = None;
    let mut program = None;
    let mut timeout_ms = 10_000u64;
    let mut command = None;
    let mut positional = Vec::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--backend" | "-b" => backend = args.next(),
            "--program" | "-p" => program = args.next().map(PathBuf::from),
            "--timeout-ms" => {
                timeout_ms = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--help" | "-h" => usage(),
            value if value.starts_with('-') => usage(),
            value if command.is_none() => command = Some(value.to_owned()),
            value => positional.push(value.to_owned()),
        }
    }

    let kind = backend
        .as_deref()
        .and_then(|value| BackendKind::parse(value).ok())
        .unwrap_or_else(|| usage());
    let program = program.unwrap_or_else(|| usage());
    let backend = DebugBackend::new(kind, program)
        .and_then(|backend| backend.with_timeout(Duration::from_millis(timeout_ms)))
        .unwrap_or_else(|error| {
            eprintln!("lre-debug: {error}");
            std::process::exit(1);
        });
    let output = match command.as_deref() {
        Some("backtrace") if positional.is_empty() => backend.backtrace(),
        Some("registers") if positional.is_empty() => backend.registers(),
        Some("memory") if positional.len() == 2 => {
            let address = u64::from_str_radix(positional[0].trim_start_matches("0x"), 16)
                .unwrap_or_else(|_| usage());
            let count = positional[1].parse().unwrap_or_else(|_| usage());
            backend.memory(address, count)
        }
        _ => usage(),
    };
    match output {
        Ok(output) => {
            print!("{}", output.stdout);
            if !output.stderr.is_empty() {
                eprint!("{}", output.stderr);
            }
        }
        Err(error) => {
            eprintln!("lre-debug: {error}");
            std::process::exit(1);
        }
    }
}
