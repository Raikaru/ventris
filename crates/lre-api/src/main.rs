use lre_api::{serve_stdio, serve_tcp, ApiService};
use lre_core::Core;
use std::env;
use std::net::TcpListener;
use std::path::PathBuf;

fn usage() -> ! {
    eprintln!("usage: lre-api --project DIR [--listen HOST:PORT]");
    std::process::exit(2);
}

fn main() {
    let mut args = env::args().skip(1);
    let mut project = None;
    let mut listen = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--project" | "-p" => project = args.next().map(PathBuf::from),
            "--listen" | "-l" => listen = args.next(),
            "--help" | "-h" => usage(),
            _ => usage(),
        }
    }
    let project = project.unwrap_or_else(|| usage());
    let core = Core::open(&project).unwrap_or_else(|error| {
        eprintln!("lre-api: {error}");
        std::process::exit(1);
    });
    let service = ApiService::new(core);
    let result = if let Some(address) = listen {
        let listener = TcpListener::bind(&address).unwrap_or_else(|error| {
            eprintln!("lre-api: cannot listen on {address}: {error}");
            std::process::exit(1);
        });
        eprintln!("lre-api listening on http://{address}/v1");
        serve_tcp(&service, listener)
    } else {
        serve_stdio(&service)
    };
    if let Err(error) = result {
        eprintln!("lre-api: {error}");
        std::process::exit(1);
    }
}
