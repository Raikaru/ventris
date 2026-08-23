mod game_input;
mod json;

use json::{object, stringify, Value};

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::fmt::Write as FmtWrite;
use std::io::{Read as IoRead, Write as IoWrite};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use ventris_addr::hash::stable64;
use ventris_db::{
    Authority, Memo, MemoKey, Project, ProjectAssertion, ProjectCache, ProjectData,
    ProjectFunction, ProjectGeneration, ProjectImage, ProjectPlacement, ProjectReference,
    ProjectReferenceKind, ProjectRegion, ProjectRelocation, ProjectSegment, ProjectSpace,
    ProjectSymbol, QueryId,
};
use ventris_decompiler::native::{NativeDecompiler, NativeMemory};
use ventris_format::{Endian, Format, Image, ImageMetadata, Loader, Placement};
use ventris_game::assets::{
    AssetCatalog, AssetKind, AssetLinkKind, AssetTarget, GameAsset, GameScript,
};
use ventris_game::diff::{diff_revisions, BinaryRevision, RegionChangeKind, RevisionRegion};
use ventris_game::reconstruction::SourceReconstruction;
use ventris_game::runtime::{ingest as ingest_runtime_events, RuntimeEvent, RuntimeEventKind};
use ventris_game::{
    corpus, recover_function, AccessKind, RecoveryInput, RelocationFact, SymbolFact,
};
use ventris_gen::Generation;
use ventris_lifter::{
    discover_functions, AArch64, Architecture, Arm32, Flow, GameCube, Lifter, M68k, Mips32,
    Mips32Be, Ppc32, Ppc64, Ps1, Rv32, Rv64, Sh2, Sh4, Spu, Thumb, M6502, N64, X86_32, X86_64, Z80,
};
use ventris_target::TargetProfile;

// Bump whenever native lifting/decompilation semantics change.
const NATIVE_ANALYZER_CODE_VERSION: u32 = 8;
const USAGE: &str = "Usage:
  ventris help
  ventris version
  ventris corpus [--json]
  ventris project runtime <project> <trace> [--json]
  ventris project assets <project> <manifest> [--json]
  ventris diff <before> <after> [--target <target>] [--loader <loader>] [--base <addr>] [--slice <n>] [--region <name>] [--json]
  ventris project analyze <project> (--arch <arch>|--target <target>) [--limit <n>] [--json]
  ventris project show <project> [--json]
  ventris project refs <project> <address> [--incoming|--outgoing] [--json]
  ventris discover <image> (--arch <arch>|--target <target>) [--loader <loader>] [--base <addr>] [--slice <n>] [--limit <n>] [--json]
  ventris inspect <image> [--target <target>] [--loader <loader>] [--base <addr>] [--slice <n>] [--json]
  ventris decompile-native <image> <address> (--arch <arch>|--target <target>) [--loader <loader>] [--base <addr>] [--slice <n>] [--limit <n>] [--raw] [--cache <dir>] [--json]
  ventris decompile-native --project <project> --function <name-or-address> (--arch <arch>|--target <target>) [--limit <n>] [--cache <dir>] [--json]
  ventris lift <image> <address> (--arch <arch>|--target <target>) [--loader <loader>] [--base <addr>] [--slice <n>] [--limit <n>] [--raw] [--json]
  ventris recover-types <image> <address> --target <target> [--loader <loader>] [--base <addr>] [--slice <n>] [--limit <n>] [--raw] [--json]
  ventris reconstruct-source <image> <address> --target <target> [--metadata <file>] [--loader <loader>] [--base <addr>] [--slice <n>] [--limit <n>] [--raw] [--cache <dir>] [--json]

Commands:
  diff                Compare binary revisions by named image regions.
  project             Create, analyze, inspect, ingest runtime evidence, or link assets/scripts in a persistent project.
  discover            Discover a bounded function and data inventory.
  inspect             Parse an ELF, PE, Mach-O, Nintendo 64 ROM, or GameCube/Wii DOL (including a selected universal slice) and print facts without guessing a language.
  resolve             Resolve a qualified or unambiguous bare address.
  lift                Lift a function into architecture-neutral p-code.
  decompile-native    Lift, analyze, and render native C without a JVM.
  recover-types       Recover console ABI facts and evidence-backed field candidates.
  reconstruct-source  Render native C with recovered game structs and ABI facts.
  batch               Process JSON Lines analysis requests with stable JSON Lines results.
  serve               Serve local HTTP analysis endpoints.

  --arch <arch>       Explicit architecture: x86_64, x86_32, aarch64, arm32, thumb, mips32, mips32be, ps1, n64, rv64, rv32, ppc32, ppc64, gamecube, m68k, sh2, sh4, m6502, z80, or spu.
  --target <target>   Console profile supplying architecture, loader, ABI, and image parts.
  --loader <loader>   Image container: auto, raw, elf, pe, macho, coff, ihex, srec, n64-rom, dol, nds, ncch, psp-prx, vita-self, wiiu-rpl, xex, or ps3-self.
  --limit <n>         Maximum instructions to discover (default: 4096).
  --slice <n>         Select zero-based slice n from a universal Mach-O.
  --raw                Treat input as a raw architecture image.
  --cache <dir>       Persist native analysis results in the supplied directory.
  --json              Wrap successful output in a stable JSON envelope.

Game recovery options:
  --metadata <file>   JSON sidecar with nominal types, annotations, and assertions.

Batch options:
  --input <file|->    JSON Lines requests; '-' reads stdin.
  --output <file|->   JSON Lines results; '-' or omitted writes stdout.
  --cache <dir>       Reuse native decompiler results across requests.

";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct ImageOptions {
    loader: Loader,
    base: Option<u64>,
    slice: Option<usize>,
    target: Option<TargetProfile>,
}

impl Default for ImageOptions {
    fn default() -> Self {
        Self {
            loader: Loader::Auto,
            base: None,
            slice: None,
            target: None,
        }
    }
}

#[derive(Debug)]
enum Command {
    Corpus(OutputFormat),
    Help,
    Version,
    Project(ProjectOptions),
    Discover(DiscoverOptions),
    Diff(DiffOptions),
    Serve(ServeOptions),
    Inspect {
        image: PathBuf,
        options: ImageOptions,
        format: OutputFormat,
    },
    Resolve {
        image: PathBuf,
        address: String,
        options: ImageOptions,
        format: OutputFormat,
    },
    RecoverTypes(GameOptions),
    ReconstructSource(GameOptions),
    Lift(LiftOptions),
    DecompileNative(LiftOptions),
    DecompileNativeProject(ProjectDecompileOptions),
    Batch(BatchOptions),
}

#[derive(Debug)]
enum ProjectAction {
    Init {
        image: PathBuf,
        project: PathBuf,
        options: ImageOptions,
    },
    Analyze {
        project: PathBuf,
        architecture: Architecture,
        target: Option<TargetProfile>,
        limit: usize,
    },
    Show {
        project: PathBuf,
    },
    References {
        project: PathBuf,
        address: u64,
        incoming: bool,
        outgoing: bool,
    },
    Runtime {
        project: PathBuf,
        trace: PathBuf,
    },
    Assets {
        project: PathBuf,
        manifest: PathBuf,
    },
}

#[derive(Debug)]
struct ProjectOptions {
    action: ProjectAction,
    format: OutputFormat,
}

#[derive(Debug)]
struct DiscoverOptions {
    image: PathBuf,
    architecture: Architecture,
    target: Option<TargetProfile>,
    limit: usize,
    loader: Loader,
    base: Option<u64>,
    slice: Option<usize>,
    format: OutputFormat,
}

#[derive(Debug)]
struct DiffOptions {
    before: PathBuf,
    after: PathBuf,
    options: ImageOptions,
    region: Option<String>,
    format: OutputFormat,
}

#[derive(Clone, Debug)]
struct LiftOptions {
    image: PathBuf,
    address: String,
    architecture: Architecture,
    target: Option<TargetProfile>,
    limit: usize,
    cache: Option<PathBuf>,
    loader: Loader,
    base: Option<u64>,
    slice: Option<usize>,
    raw: bool,
    format: OutputFormat,
}

#[derive(Debug)]
struct ProjectDecompileOptions {
    project: PathBuf,
    function: String,
    architecture: Architecture,
    target: Option<TargetProfile>,
    limit: usize,
    cache: Option<PathBuf>,
    format: OutputFormat,
}

#[derive(Clone, Debug)]
struct GameOptions {
    lift: LiftOptions,
    metadata: Option<PathBuf>,
}

#[derive(Debug)]
struct BatchOptions {
    input: PathBuf,
    output: Option<PathBuf>,
    cache: Option<PathBuf>,
}

#[derive(Debug)]
struct ServeOptions {
    bind: String,
    once: bool,
}

impl Command {
    fn output_format(&self) -> OutputFormat {
        match self {
            Self::Corpus(format) | Self::Project(ProjectOptions { format, .. }) => *format,
            Self::Discover(options) => options.format,
            Self::Diff(options) => options.format,
            Self::Inspect { format, .. } | Self::Resolve { format, .. } => *format,
            Self::Lift(options) | Self::DecompileNative(options) => options.format,
            Self::DecompileNativeProject(options) => options.format,
            Self::RecoverTypes(options) | Self::ReconstructSource(options) => options.lift.format,
            Self::Batch(_) => OutputFormat::Json,
            Self::Help | Self::Version | Self::Serve(_) => OutputFormat::Text,
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = match parse_command(&args) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("ventris: {message}");
            eprintln!();
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    };
    let format = command.output_format();
    match run(command) {
        Ok(output) => {
            if !output.is_empty() {
                print!("{output}");
            }
        }
        Err(message) if format == OutputFormat::Json => {
            println!(
                "{}",
                stringify(&object([
                    ("ok".into(), Value::Bool(false)),
                    ("error".into(), Value::string(message)),
                ]))
            );
            std::process::exit(2);
        }
        Err(message) => {
            eprintln!("ventris: {message}");
            eprintln!();
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    }
}

fn parse_command(args: &[String]) -> Result<Command, String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(Command::Help);
    };
    match command {
        "help" | "--help" | "-h" => Ok(Command::Help),
        "version" | "--version" | "-V" => Ok(Command::Version),
        "corpus" => Ok(Command::Corpus(parse_corpus_options(&args[1..])?)),
        "diff" => Ok(Command::Diff(parse_diff_options(&args[1..])?)),
        "project" => Ok(Command::Project(parse_project_options(&args[1..])?)),
        "discover" => Ok(Command::Discover(parse_discover_options(&args[1..])?)),
        "serve" => Ok(Command::Serve(parse_serve_options(&args[1..])?)),
        "inspect" => {
            let (image, options, format) = parse_path_options(&args[1..], "inspect")?;
            Ok(Command::Inspect {
                image,
                options,
                format,
            })
        }
        "resolve" => {
            if args.len() < 3 {
                return Err(
                    "resolve expects <image> <address> [--loader <loader>] [--base <addr>] [--slice <n>] [--json]"
                        .into(),
                );
            }
            let (options, format) = parse_image_flags(&args[3..], "resolve")?;
            Ok(Command::Resolve {
                image: PathBuf::from(&args[1]),
                address: args[2].clone(),
                options,
                format,
            })
        }
        "lift" => Ok(Command::Lift(parse_lift_options(&args[1..])?)),
        "decompile-native" => {
            if args.iter().any(|arg| arg == "--project") {
                Ok(Command::DecompileNativeProject(
                    parse_project_decompile_options(&args[1..])?,
                ))
            } else {
                Ok(Command::DecompileNative(parse_lift_options(&args[1..])?))
            }
        }
        "recover-types" | "game-model" => {
            Ok(Command::RecoverTypes(parse_game_model_options(&args[1..])?))
        }
        "reconstruct-source" | "source-reconstruct" => Ok(Command::ReconstructSource(
            parse_game_model_options(&args[1..])?,
        )),
        "batch" => Ok(Command::Batch(parse_batch_options(&args[1..])?)),
        other => Err(format!("unknown command {other:?}")),
    }
}

fn parse_project_options(args: &[String]) -> Result<ProjectOptions, String> {
    let action = args
        .first()
        .ok_or_else(|| "project expects init, analyze, show, or refs".to_string())?;
    match action.as_str() {
        "init" => {
            if args.len() < 3 {
                return Err(
                    "project init expects <image> <project> [--target <target>] [--loader <loader>] [--base <addr>] [--slice <n>] [--json]"
                        .into(),
                );
            }
            let (options, format) = parse_image_flags(&args[3..], "project init")?;
            Ok(ProjectOptions {
                action: ProjectAction::Init {
                    image: PathBuf::from(&args[1]),
                    project: PathBuf::from(&args[2]),
                    options,
                },
                format,
            })
        }
        "analyze" => {
            if args.len() < 2 {
                return Err(
                    "project analyze expects <project> (--arch <arch>|--target <target>) [--limit <n>] [--json]"
                        .into(),
                );
            }
            let mut architecture = None;
            let mut target = None;
            let mut limit = 4096usize;
            let mut format = OutputFormat::Text;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--arch" => {
                        let value = args
                            .get(i + 1)
                            .ok_or_else(|| "project analyze --arch requires a value".to_string())?;
                        architecture = Some(parse_architecture(value)?);
                        i += 2;
                    }
                    "--target" => {
                        let value = args.get(i + 1).ok_or_else(|| {
                            "project analyze --target requires a value".to_string()
                        })?;
                        target = Some(
                            TargetProfile::parse(value)
                                .ok_or_else(|| format!("unknown target {value:?}"))?,
                        );
                        i += 2;
                    }
                    "--limit" => {
                        limit = args
                            .get(i + 1)
                            .ok_or_else(|| "project analyze --limit requires a value".to_string())?
                            .parse()
                            .map_err(|_| {
                                "project analyze --limit must be an integer".to_string()
                            })?;
                        i += 2;
                    }
                    "--json" => {
                        format = OutputFormat::Json;
                        i += 1;
                    }
                    other => {
                        return Err(format!("project analyze received unknown option {other:?}"));
                    }
                }
            }
            let architecture = architecture
                .or_else(|| target.as_ref().map(|profile| profile.spec().architecture))
                .ok_or_else(|| "project analyze requires --arch or --target".to_string())?;
            Ok(ProjectOptions {
                action: ProjectAction::Analyze {
                    project: PathBuf::from(&args[1]),
                    architecture,
                    target,
                    limit,
                },
                format,
            })
        }
        "show" => {
            if args.len() < 2 {
                return Err("project show expects <project> [--json]".into());
            }
            let mut format = OutputFormat::Text;
            for arg in &args[2..] {
                match arg.as_str() {
                    "--json" => format = OutputFormat::Json,
                    other => return Err(format!("project show received unknown option {other:?}")),
                }
            }
            Ok(ProjectOptions {
                action: ProjectAction::Show {
                    project: PathBuf::from(&args[1]),
                },
                format,
            })
        }
        "runtime" | "ingest-runtime" => {
            if args.len() < 3 {
                return Err("project runtime expects <project> <trace> [--json]".into());
            }
            let mut format = OutputFormat::Text;
            for arg in &args[3..] {
                match arg.as_str() {
                    "--json" => format = OutputFormat::Json,
                    other => {
                        return Err(format!("project runtime received unknown option {other:?}"))
                    }
                }
            }
            Ok(ProjectOptions {
                action: ProjectAction::Runtime {
                    project: PathBuf::from(&args[1]),
                    trace: PathBuf::from(&args[2]),
                },
                format,
            })
        }
        "assets" | "link-assets" => {
            if args.len() < 3 {
                return Err("project assets expects <project> <manifest> [--json]".into());
            }
            let mut format = OutputFormat::Text;
            for arg in &args[3..] {
                match arg.as_str() {
                    "--json" => format = OutputFormat::Json,
                    other => {
                        return Err(format!("project assets received unknown option {other:?}"))
                    }
                }
            }
            Ok(ProjectOptions {
                action: ProjectAction::Assets {
                    project: PathBuf::from(&args[1]),
                    manifest: PathBuf::from(&args[2]),
                },
                format,
            })
        }
        "refs" | "references" | "navigate" => {
            if args.len() < 3 {
                return Err(
                    "project refs expects <project> <address> [--incoming|--outgoing] [--json]"
                        .into(),
                );
            }
            let address = parse_offset(&args[2])?;
            let mut incoming = false;
            let mut outgoing = false;
            let mut format = OutputFormat::Text;
            for arg in &args[3..] {
                match arg.as_str() {
                    "--incoming" => incoming = true,
                    "--outgoing" => outgoing = true,
                    "--json" => format = OutputFormat::Json,
                    other => return Err(format!("project refs received unknown option {other:?}")),
                }
            }
            if !incoming && !outgoing {
                incoming = true;
                outgoing = true;
            }
            Ok(ProjectOptions {
                action: ProjectAction::References {
                    project: PathBuf::from(&args[1]),
                    address,
                    incoming,
                    outgoing,
                },
                format,
            })
        }
        other => Err(format!(
            "unknown project action {other:?}; expected init, analyze, show, or refs"
        )),
    }
}

fn parse_discover_options(args: &[String]) -> Result<DiscoverOptions, String> {
    if args.is_empty() {
        return Err(
            "discover expects <image> (--arch <arch>|--target <target>) [--loader <loader>] [--base <addr>] [--slice <n>] [--limit <n>] [--json]"
                .into(),
        );
    }
    let image = PathBuf::from(&args[0]);
    let mut architecture = None;
    let mut target = None;
    let mut loader = Loader::Auto;
    let mut base = None;
    let mut slice = None;
    let mut limit = 4096usize;
    let mut format = OutputFormat::Text;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--arch" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "discover --arch requires a value".to_string())?;
                architecture = Some(parse_architecture(value)?);
                i += 2;
            }
            "--target" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "discover --target requires a value".to_string())?;
                target = Some(
                    TargetProfile::parse(value)
                        .ok_or_else(|| format!("unknown target {value:?}"))?,
                );
                i += 2;
            }
            "--loader" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "discover --loader requires a value".to_string())?;
                loader = Loader::parse(value).ok_or_else(|| format!("unknown loader {value:?}"))?;
                i += 2;
            }
            "--base" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "discover --base requires a value".to_string())?;
                base = Some(parse_offset(value)?);
                i += 2;
            }
            "--slice" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "discover --slice requires a value".to_string())?;
                slice = Some(
                    value
                        .parse()
                        .map_err(|_| format!("invalid slice {value:?}"))?,
                );
                i += 2;
            }
            "--limit" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "discover --limit requires a value".to_string())?;
                limit = value
                    .parse()
                    .map_err(|_| "discover --limit must be an integer".to_string())?;
                i += 2;
            }
            "--json" => {
                format = OutputFormat::Json;
                i += 1;
            }
            other => return Err(format!("discover received unknown option {other:?}")),
        }
    }
    let architecture = architecture
        .or_else(|| target.as_ref().map(|profile| profile.spec().architecture))
        .ok_or_else(|| "discover requires --arch or --target".to_string())?;
    Ok(DiscoverOptions {
        image,
        architecture,
        target,
        limit,
        loader,
        base,
        slice,
        format,
    })
}

fn parse_diff_options(args: &[String]) -> Result<DiffOptions, String> {
    if args.len() < 2 {
        return Err(
            "diff expects <before> <after> [--target <target>] [--loader <loader>] [--base <addr>] [--slice <n>] [--region <name>] [--json]"
                .into(),
        );
    }
    let before = PathBuf::from(&args[0]);
    let after = PathBuf::from(&args[1]);
    let mut image_args = Vec::new();
    let mut region = None;
    let mut i = 2;
    while i < args.len() {
        if args[i] == "--region" {
            let value = args
                .get(i + 1)
                .ok_or_else(|| "diff --region needs a name".to_string())?;
            if value.is_empty() {
                return Err("diff --region needs a non-empty name".into());
            }
            region = Some(value.clone());
            i += 2;
        } else {
            image_args.push(args[i].clone());
            i += 1;
        }
    }
    let (options, format) = parse_image_flags(&image_args, "diff")?;
    Ok(DiffOptions {
        before,
        after,
        options,
        region,
        format,
    })
}

fn parse_corpus_options(args: &[String]) -> Result<OutputFormat, String> {
    let mut format = OutputFormat::Text;
    for arg in args {
        match arg.as_str() {
            "--json" => format = OutputFormat::Json,
            other => return Err(format!("corpus received unknown option {other:?}")),
        }
    }
    Ok(format)
}

fn parse_path_options(
    args: &[String],
    command: &str,
) -> Result<(PathBuf, ImageOptions, OutputFormat), String> {
    if args.is_empty() {
        return Err(format!(
            "{command} expects <image> [--target <target>] [--loader <loader>] [--base <addr>] [--slice <n>] [--json]"
        ));
    }
    let (options, format) = parse_image_flags(&args[1..], command)?;
    Ok((PathBuf::from(&args[0]), options, format))
}

fn parse_image_flags(
    args: &[String],
    command: &str,
) -> Result<(ImageOptions, OutputFormat), String> {
    let mut options = ImageOptions::default();
    let mut format = OutputFormat::Text;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--loader" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--loader needs a value".to_string())?;
                options.loader = Loader::parse(value).ok_or_else(|| {
                    format!(
                        "unknown loader {value:?}; expected auto, raw, elf, pe, macho, coff, ihex, srec, n64-rom, dol, nds, ncch, psp-prx, vita-self, wiiu-rpl, xex, or ps3-self"
                    )
                })?;
                i += 2;
            }
            "--base" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--base needs an address".to_string())?;
                options.base = Some(parse_offset(value)?);
                i += 2;
            }
            "--slice" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--slice needs an index".to_string())?;
                options.slice = Some(parse_slice_index(value)?);
                i += 2;
            }
            "--target" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--target needs a value".to_string())?;
                options.target = Some(
                    TargetProfile::parse(value)
                        .ok_or_else(|| format!("unknown target {value:?}"))?,
                );
                i += 2;
            }
            "--json" => {
                format = OutputFormat::Json;
                i += 1;
            }
            other => return Err(format!("{command} has unknown option {other:?}")),
        }
    }
    Ok((options, format))
}

fn parse_serve_options(args: &[String]) -> Result<ServeOptions, String> {
    let mut bind = "127.0.0.1:8787".to_string();
    let mut once = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                bind = args
                    .get(i + 1)
                    .ok_or_else(|| "--bind needs a host:port value".to_string())?
                    .clone();
                i += 2;
            }
            "--once" => {
                once = true;
                i += 1;
            }
            other => return Err(format!("unknown serve option {other:?}")),
        }
    }
    Ok(ServeOptions { bind, once })
}

fn parse_lift_options(args: &[String]) -> Result<LiftOptions, String> {
    if args.len() < 4 {
        return Err(
            "lift expects <image> <address> --arch <arch> or --target <target> [--loader <loader>] [--base <addr>] [--slice <n>]"
                .into(),
        );
    }
    let image = PathBuf::from(&args[0]);
    let address = args[1].clone();
    let mut architecture = None;
    let mut target = None;
    let mut limit = 4096usize;
    let mut cache = None;
    let mut loader = Loader::Auto;
    let mut base = None;
    let mut slice = None;
    let mut raw = false;
    let mut format = OutputFormat::Text;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--arch" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--arch needs a value".to_string())?;
                architecture = Some(parse_architecture(value)?);
                i += 2;
            }
            "--limit" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--limit needs a value".to_string())?;
                limit = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid instruction limit {value:?}"))?;
                if limit == 0 {
                    return Err("--limit must be greater than zero".into());
                }
                i += 2;
            }
            "--cache" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--cache needs a directory".to_string())?;
                cache = Some(PathBuf::from(value));
                i += 2;
            }
            "--loader" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--loader needs a value".to_string())?;
                loader = Loader::parse(value).ok_or_else(|| {
                    format!(
                        "unknown loader {value:?}; expected auto, raw, elf, pe, macho, coff, ihex, srec, n64-rom, dol, nds, ncch, psp-prx, vita-self, wiiu-rpl, xex, or ps3-self"
                    )
                })?;
                i += 2;
            }
            "--base" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--base needs an address".to_string())?;
                base = Some(parse_offset(value)?);
                i += 2;
            }
            "--slice" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--slice needs an index".to_string())?;
                slice = Some(parse_slice_index(value)?);
                i += 2;
            }
            "--target" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--target needs a value".to_string())?;
                target = Some(
                    TargetProfile::parse(value)
                        .ok_or_else(|| format!("unknown target {value:?}"))?,
                );
                i += 2;
            }
            "--raw" => {
                raw = true;
                i += 1;
            }
            "--json" => {
                format = OutputFormat::Json;
                i += 1;
            }
            other => return Err(format!("unknown lift option {other:?}")),
        }
    }
    Ok(LiftOptions {
        image,
        address,
        architecture: architecture
            .or_else(|| target.map(|target| target.spec().architecture))
            .ok_or_else(|| "lift requires --arch or --target".to_string())?,
        target,
        limit,
        cache,
        loader,
        base,
        slice,
        raw,
        format,
    })
}

fn parse_project_decompile_options(args: &[String]) -> Result<ProjectDecompileOptions, String> {
    let mut project = None;
    let mut function = None;
    let mut architecture = None;
    let mut target = None;
    let mut limit = 4096usize;
    let mut cache = None;
    let mut format = OutputFormat::Text;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--project" => {
                project =
                    Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                        "--project needs a project file".to_string()
                    })?));
                i += 2;
            }
            "--function" => {
                function = Some(
                    args.get(i + 1)
                        .ok_or_else(|| "--function needs a name or address".to_string())?
                        .clone(),
                );
                i += 2;
            }
            "--arch" => {
                architecture = Some(parse_architecture(
                    args.get(i + 1)
                        .ok_or_else(|| "--arch needs a value".to_string())?,
                )?);
                i += 2;
            }
            "--target" => {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| "--target needs a value".to_string())?;
                target = Some(
                    TargetProfile::parse(value)
                        .ok_or_else(|| format!("unknown target {value:?}"))?,
                );
                i += 2;
            }
            "--limit" => {
                limit = args
                    .get(i + 1)
                    .ok_or_else(|| "--limit needs a value".to_string())?
                    .parse()
                    .map_err(|_| "invalid instruction limit".to_string())?;
                if limit == 0 {
                    return Err("--limit must be greater than zero".into());
                }
                i += 2;
            }
            "--cache" => {
                cache = Some(PathBuf::from(
                    args.get(i + 1)
                        .ok_or_else(|| "--cache needs a directory".to_string())?,
                ));
                i += 2;
            }
            "--json" => {
                format = OutputFormat::Json;
                i += 1;
            }
            other => {
                return Err(format!(
                    "unknown project decompile option {other:?}; project image settings come from the project"
                ));
            }
        }
    }
    Ok(ProjectDecompileOptions {
        project: project.ok_or_else(|| "--project is required".to_string())?,
        function: function.ok_or_else(|| "--function is required".to_string())?,
        architecture: architecture
            .or_else(|| target.map(|target| target.spec().architecture))
            .ok_or_else(|| "project decompile requires --arch or --target".to_string())?,
        target,
        limit,
        cache,
        format,
    })
}

fn parse_game_model_options(args: &[String]) -> Result<GameOptions, String> {
    let mut lift_args = Vec::with_capacity(args.len());
    let mut metadata = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--metadata" {
            metadata =
                Some(PathBuf::from(args.get(i + 1).ok_or_else(|| {
                    "--metadata needs a JSON sidecar".to_string()
                })?));
            i += 2;
        } else {
            lift_args.push(args[i].clone());
            i += 1;
        }
    }
    let lift = parse_lift_options(&lift_args)?;
    if lift.target.is_none() {
        return Err(
            "recover-types requires --target; --arch alone cannot select a console ABI".into(),
        );
    }
    Ok(GameOptions { lift, metadata })
}
fn parse_batch_options(args: &[String]) -> Result<BatchOptions, String> {
    let mut input = None;
    let mut output = None;
    let mut cache = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                input = Some(PathBuf::from(
                    args.get(i + 1)
                        .ok_or_else(|| "--input needs a file or '-'".to_string())?,
                ));
                i += 2;
            }
            "--output" => {
                output = Some(PathBuf::from(
                    args.get(i + 1)
                        .ok_or_else(|| "--output needs a file or '-'".to_string())?,
                ));
                i += 2;
            }
            "--cache" => {
                cache = Some(PathBuf::from(
                    args.get(i + 1)
                        .ok_or_else(|| "--cache needs a directory".to_string())?,
                ));
                i += 2;
            }
            other => return Err(format!("unknown batch option {other:?}")),
        }
    }
    Ok(BatchOptions {
        input: input.ok_or_else(|| "batch requires --input <file|->".to_string())?,
        output,
        cache,
    })
}

fn parse_architecture(value: &str) -> Result<Architecture, String> {
    match value.to_ascii_lowercase().as_str() {
        "x86_64" | "x86-64" | "amd64" => Ok(Architecture::X86_64),
        "x86_32" | "x86" | "i386" | "i686" => Ok(Architecture::X86_32),
        "aarch64" | "arm64" => Ok(Architecture::AArch64),
        "arm32" | "arm" | "armv7" => Ok(Architecture::Arm32),
        "thumb" | "thumb16" | "arm-thumb" => Ok(Architecture::Thumb),
        "mips32" | "mips" => Ok(Architecture::Mips32),
        "mips32be" | "mips-be" | "mips32-big" => Ok(Architecture::Mips32Be),
        "ps1" | "playstation1" | "mips1" => Ok(Architecture::Ps1),
        "n64" | "mips64" | "r4300" => Ok(Architecture::N64),
        "rv64" | "riscv64" => Ok(Architecture::Rv64),
        "rv32" | "riscv32" => Ok(Architecture::Rv32),
        "ppc32" | "powerpc" | "powerpc32" => Ok(Architecture::Ppc32),
        "ppc64" | "powerpc64" | "ppu" | "cell-ppu" => Ok(Architecture::Ppc64),
        "gamecube" | "gc" | "ppc750" => Ok(Architecture::GameCube),
        "m68k" | "68000" | "motorola68000" => Ok(Architecture::M68k),
        "sh2" | "superh2" => Ok(Architecture::Sh2),
        "sh4" | "superh4" => Ok(Architecture::Sh4),
        "m6502" | "6502" => Ok(Architecture::M6502),
        "z80" => Ok(Architecture::Z80),
        "spu" | "cell-spu" => Ok(Architecture::Spu),
        _ => Err(format!("unknown architecture {value:?}")),
    }
}

fn run(command: Command) -> Result<String, String> {
    match command {
        Command::Help => Ok(USAGE.into()),
        Command::Corpus(format) => output("corpus", render_corpus(format), format),
        Command::Diff(options) => {
            let format = options.format;
            output("diff", diff_command(options)?, format)
        }
        Command::Project(options) => {
            let format = options.format;
            output("project", project_command(options)?, format)
        }
        Command::Discover(options) => {
            let format = options.format;
            output("discover", discover_command(options)?, format)
        }
        Command::Serve(options) => serve(options),
        Command::Resolve {
            image,
            address,
            options,
            format,
        } => output("resolve", resolve(&image, &address, options)?, format),
        Command::Version => Ok(format!("ventris {}\n", env!("CARGO_PKG_VERSION"))),
        Command::Inspect {
            image,
            options,
            format,
        } => output("inspect", inspect(&image, options)?, format),
        Command::Lift(options) => {
            let format = options.format;
            output("lift", lift(options)?, format)
        }
        Command::Batch(options) => batch(options),
        Command::DecompileNative(options) => {
            let format = options.format;
            output("decompile-native", decompile_native(options)?, format)
        }
        Command::DecompileNativeProject(options) => {
            let format = options.format;
            output(
                "decompile-native",
                decompile_project_function(options)?,
                format,
            )
        }
        Command::RecoverTypes(options) => {
            let format = options.lift.format;
            output("recover-types", recover_types(options)?, format)
        }
        Command::ReconstructSource(options) => {
            let format = options.lift.format;
            output("reconstruct-source", reconstruct_source(options)?, format)
        }
    }
}

fn output(command: &str, text: String, format: OutputFormat) -> Result<String, String> {
    if format == OutputFormat::Text {
        return Ok(text);
    }
    Ok(format!(
        "{}\n",
        stringify(&object([
            ("ok".into(), Value::Bool(true)),
            ("command".into(), Value::string(command)),
            ("result".into(), Value::string(text)),
        ]))
    ))
}

fn render_corpus(format: OutputFormat) -> String {
    if format == OutputFormat::Json {
        let entries = corpus::entries()
            .iter()
            .map(|entry| {
                object([
                    ("id".into(), Value::string(entry.id)),
                    ("title".into(), Value::string(entry.title)),
                    ("target".into(), Value::string(entry.target.name())),
                    ("source_url".into(), Value::string(entry.source_url)),
                    ("source_commit".into(), Value::string(entry.source_commit)),
                    ("source_license".into(), Value::string(entry.source_license)),
                    ("binary_name".into(), Value::string(entry.binary_name)),
                    (
                        "binary_sha256".into(),
                        entry
                            .binary_sha256
                            .map(Value::string)
                            .unwrap_or(Value::Null),
                    ),
                    ("status".into(), Value::string(entry.status)),
                    (
                        "functions".into(),
                        Value::Array(
                            entry
                                .functions
                                .iter()
                                .map(|function| {
                                    object([
                                        ("name".into(), Value::string(function.name)),
                                        ("source_path".into(), Value::string(function.source_path)),
                                        (
                                            "address".into(),
                                            Value::string(format!("0x{:x}", function.address)),
                                        ),
                                        (
                                            "size".into(),
                                            Value::string(format!("0x{:x}", function.size)),
                                        ),
                                        ("note".into(), Value::string(function.note)),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                ])
            })
            .collect();
        return stringify(&Value::Array(entries));
    }

    let mut out = String::new();
    writeln!(out, "corpus:").unwrap();
    for entry in corpus::entries() {
        render_corpus_entry(&mut out, entry);
    }
    out
}

fn render_corpus_entry(out: &mut String, entry: &corpus::CorpusEntry) {
    writeln!(
        out,
        "  {} target={} license={} status={}\n    source={} @ {}\n    image={}",
        entry.id,
        entry.target.name(),
        entry.source_license,
        entry.status,
        entry.source_url,
        entry.source_commit,
        entry.binary_name
    )
    .unwrap();
    if let Some(hash) = entry.binary_sha256 {
        writeln!(out, "    sha256={hash}").unwrap();
    }
    for function in entry.functions {
        writeln!(
            out,
            "    function {} {} size=0x{:x} source={}",
            function.name,
            format!("0x{:x}", function.address),
            function.size,
            function.source_path
        )
        .unwrap();
    }
}

fn revision_from_image(
    path: &Path,
    loaded: &ImageFile,
    target: Option<TargetProfile>,
) -> Result<BinaryRevision, String> {
    let source = path.to_string_lossy().into_owned();
    let label = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&source)
        .to_owned();
    let mut revision = BinaryRevision::new(source.clone(), label, source, target)
        .map_err(|error| error.to_string())?;
    for (index, segment) in loaded.image.segments.iter().enumerate() {
        let start = usize::try_from(segment.file_off)
            .map_err(|_| format!("{path:?}: segment {index} file offset is too large"))?;
        let size = usize::try_from(segment.file_size)
            .map_err(|_| format!("{path:?}: segment {index} file size is too large"))?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| format!("{path:?}: segment {index} range overflows"))?;
        let bytes = loaded
            .bytes
            .get(start..end)
            .ok_or_else(|| format!("{path:?}: segment {index} exceeds the loaded image"))?
            .to_vec();
        let base_name = segment
            .name
            .clone()
            .unwrap_or_else(|| format!("segment-{index}"));
        let mut name = base_name.clone();
        let mut suffix = 1;
        while revision.region(&name).is_some() {
            name = format!("{base_name}#{suffix}");
            suffix += 1;
        }
        revision
            .add_region(RevisionRegion::new(name, segment.addr, bytes))
            .map_err(|error| error.to_string())?;
    }
    Ok(revision)
}

fn diff_command(options: DiffOptions) -> Result<String, String> {
    let effective = effective_image_options(options.options);
    let before_loaded = read_image(&options.before, effective)?;
    let after_loaded = read_image(&options.after, effective)?;
    let mut diff = diff_revisions(
        &revision_from_image(&options.before, &before_loaded, options.options.target)?,
        &revision_from_image(&options.after, &after_loaded, options.options.target)?,
    );
    if let Some(region) = options.region {
        diff.regions.retain(|item| item.name == region);
        if diff.regions.is_empty() {
            return Err(format!("unknown diff region {region:?}"));
        }
        diff.changed_regions = diff.regions.iter().filter(|item| item.is_changed()).count();
        diff.changed_bytes = diff.regions.iter().map(|item| item.changed_bytes).sum();
    }
    render_binary_diff(&diff, options.format)
}

fn region_change_name(kind: RegionChangeKind) -> &'static str {
    match kind {
        RegionChangeKind::Added => "added",
        RegionChangeKind::Removed => "removed",
        RegionChangeKind::Modified => "modified",
        RegionChangeKind::Unchanged => "unchanged",
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            out.push(' ');
        }
        write!(&mut out, "{byte:02x}").unwrap();
    }
    out
}

fn render_binary_diff(
    diff: &ventris_game::diff::BinaryDiff,
    format: OutputFormat,
) -> Result<String, String> {
    if format == OutputFormat::Json {
        let regions = diff
            .regions
            .iter()
            .map(|region| {
                let hunks = region
                    .hunks
                    .iter()
                    .map(|hunk| {
                        object([
                            (
                                "offset".into(),
                                Value::string(format!("0x{:x}", hunk.offset)),
                            ),
                            (
                                "address_before".into(),
                                hunk.address_before
                                    .map(|value| Value::string(format!("0x{value:x}")))
                                    .unwrap_or(Value::Null),
                            ),
                            (
                                "address_after".into(),
                                hunk.address_after
                                    .map(|value| Value::string(format!("0x{value:x}")))
                                    .unwrap_or(Value::Null),
                            ),
                            ("before".into(), Value::string(hex_bytes(&hunk.before))),
                            ("after".into(), Value::string(hex_bytes(&hunk.after))),
                        ])
                    })
                    .collect();
                object([
                    ("name".into(), Value::string(region.name.clone())),
                    (
                        "kind".into(),
                        Value::string(region_change_name(region.kind)),
                    ),
                    (
                        "address_before".into(),
                        region
                            .address_before
                            .map(|value| Value::string(format!("0x{value:x}")))
                            .unwrap_or(Value::Null),
                    ),
                    (
                        "address_after".into(),
                        region
                            .address_after
                            .map(|value| Value::string(format!("0x{value:x}")))
                            .unwrap_or(Value::Null),
                    ),
                    ("before_size".into(), Value::number(region.before_size)),
                    ("after_size".into(), Value::number(region.after_size)),
                    ("changed_bytes".into(), Value::number(region.changed_bytes)),
                    ("hunks".into(), Value::Array(hunks)),
                ])
            })
            .collect();
        return Ok(format!(
            "{}\n",
            stringify(&object([
                ("before".into(), Value::string(diff.before_id.clone())),
                ("after".into(), Value::string(diff.after_id.clone())),
                (
                    "target_before".into(),
                    diff.target_before
                        .map(|target| Value::string(target.name()))
                        .unwrap_or(Value::Null),
                ),
                (
                    "target_after".into(),
                    diff.target_after
                        .map(|target| Value::string(target.name()))
                        .unwrap_or(Value::Null),
                ),
                (
                    "changed_regions".into(),
                    Value::number(diff.changed_regions)
                ),
                ("changed_bytes".into(), Value::number(diff.changed_bytes)),
                ("regions".into(), Value::Array(regions)),
            ]))
        ));
    }
    let mut out = String::new();
    writeln!(&mut out, "before: {}", diff.before_id).unwrap();
    writeln!(&mut out, "after: {}", diff.after_id).unwrap();
    writeln!(
        &mut out,
        "regions: {} changed={} changed_bytes={}",
        diff.regions.len(),
        diff.changed_regions,
        diff.changed_bytes
    )
    .unwrap();
    for region in &diff.regions {
        writeln!(
            &mut out,
            "  {} kind={} before=0x{:x} after=0x{:x} changed_bytes={} hunks={}",
            region.name,
            region_change_name(region.kind),
            region.before_size,
            region.after_size,
            region.changed_bytes,
            region.hunks.len()
        )
        .unwrap();
        for hunk in &region.hunks {
            writeln!(
                &mut out,
                "    +0x{:x} before=[{}] after=[{}]",
                hunk.offset,
                hex_bytes(&hunk.before),
                hex_bytes(&hunk.after)
            )
            .unwrap();
        }
    }
    Ok(out)
}

const NATIVE_CACHE_BUDGET: usize = 64 * 1024 * 1024;

struct NativeCache {
    path: Option<PathBuf>,
    memo: Memo,
}

impl NativeCache {
    fn load(cache_dir: Option<&Path>, image_hash: u64) -> Result<Self, String> {
        let path =
            cache_dir.map(|directory| directory.join(format!("native-{image_hash:016x}.memo")));
        let memo = match path.as_deref() {
            Some(path) if path.exists() => {
                Memo::load_from(path, NATIVE_CACHE_BUDGET).map_err(|error| error.to_string())?
            }
            _ => Memo::new(NATIVE_CACHE_BUDGET),
        };
        Ok(Self { path, memo })
    }

    fn save(&self) -> Result<(), String> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        self.memo.save_to(path).map_err(|error| error.to_string())
    }
}

struct BatchContext {
    cache_dir: Option<PathBuf>,
    caches: HashMap<u64, NativeCache>,
}

impl BatchContext {
    fn new(cache_dir: Option<PathBuf>) -> Self {
        Self {
            cache_dir,
            caches: HashMap::new(),
        }
    }

    fn decompile_native(&mut self, options: LiftOptions) -> Result<String, String> {
        let (file, image) = read_lift_image(&options)?;
        let image_hash = stable64(&file);
        if !self.caches.contains_key(&image_hash) {
            let cache = NativeCache::load(self.cache_dir.as_deref(), image_hash)?;
            self.caches.insert(image_hash, cache);
        }
        let cache = self
            .caches
            .get_mut(&image_hash)
            .ok_or_else(|| "native cache was not inserted".to_string())?;
        decompile_native_with_memo(options, &file, &image, &mut cache.memo)
    }

    fn cache_stats(&self) -> (u64, u64) {
        self.caches.values().fold((0, 0), |(hits, misses), cache| {
            let stats = cache.memo.stats();
            (hits + stats.hits, misses + stats.misses)
        })
    }

    fn save(&self) -> Result<(), String> {
        for cache in self.caches.values() {
            cache.save()?;
        }
        Ok(())
    }
}

fn batch(options: BatchOptions) -> Result<String, String> {
    let input = if options.input == Path::new("-") {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .map_err(|error| format!("read batch stdin: {error}"))?;
        input
    } else {
        std::fs::read_to_string(&options.input)
            .map_err(|error| format!("{}: {error}", options.input.display()))?
    };
    let mut context = BatchContext::new(options.cache);
    let results = batch_lines(&input, &mut context);
    context.save()?;
    if let Some(output) = options.output {
        if output != Path::new("-") {
            if let Some(parent) = output
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent).map_err(|error| {
                    format!(
                        "create batch output directory {}: {error}",
                        parent.display()
                    )
                })?;
            }
            std::fs::write(&output, results)
                .map_err(|error| format!("{}: {error}", output.display()))?;
            return Ok(String::new());
        }
    }
    Ok(results)
}

fn batch_lines(input: &str, context: &mut BatchContext) -> String {
    let mut results = String::new();
    for (index, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let response = match json::parse(line) {
            Ok(request) => match batch_request(&request, context) {
                Ok((command, result)) => {
                    let (cache_hits, cache_misses) = context.cache_stats();
                    object([
                        ("ok".into(), Value::Bool(true)),
                        ("index".into(), Value::number(index)),
                        ("command".into(), Value::string(command)),
                        ("result".into(), Value::string(result)),
                        ("cache_hits".into(), Value::number(cache_hits)),
                        ("cache_misses".into(), Value::number(cache_misses)),
                    ])
                }
                Err(error) => {
                    let (cache_hits, cache_misses) = context.cache_stats();
                    object([
                        ("ok".into(), Value::Bool(false)),
                        ("index".into(), Value::number(index)),
                        ("error".into(), Value::string(error)),
                        ("cache_hits".into(), Value::number(cache_hits)),
                        ("cache_misses".into(), Value::number(cache_misses)),
                    ])
                }
            },
            Err(error) => {
                let (cache_hits, cache_misses) = context.cache_stats();
                object([
                    ("ok".into(), Value::Bool(false)),
                    ("index".into(), Value::number(index)),
                    (
                        "error".into(),
                        Value::string(format!("invalid request: {error}")),
                    ),
                    ("cache_hits".into(), Value::number(cache_hits)),
                    ("cache_misses".into(), Value::number(cache_misses)),
                ])
            }
        };
        writeln!(results, "{}", stringify(&response)).unwrap();
    }
    results
}

fn batch_request(request: &Value, context: &mut BatchContext) -> Result<(String, String), String> {
    let command = request
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| "request field command must be a string".to_string())?;
    let image = request
        .get("image")
        .and_then(Value::as_str)
        .map(PathBuf::from);
    match command {
        "diff" => {
            let before = PathBuf::from(required_request_string(request, "before")?);
            let after = PathBuf::from(required_request_string(request, "after")?);
            let region = request
                .get("region")
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| "request field region must be a string".to_string())
                })
                .transpose()?;
            let result = diff_command(DiffOptions {
                before,
                after,
                options: request_image_options(request)?,
                region,
                format: OutputFormat::Text,
            })?;
            Ok(("diff".into(), result))
        }
        "inspect" => {
            let image = image.ok_or_else(|| "inspect requires image".to_string())?;
            let options = request_image_options(request)?;
            Ok(("inspect".into(), inspect(&image, options)?))
        }
        "resolve" => {
            let image = image.ok_or_else(|| "resolve requires image".to_string())?;
            let address = required_request_string(request, "address")?;
            let options = request_image_options(request)?;
            Ok(("resolve".into(), resolve(&image, address, options)?))
        }
        "discover" => {
            let image = image.ok_or_else(|| "discover requires image".to_string())?;
            let image_options = request_image_options(request)?;
            let architecture = match request.get("arch").and_then(Value::as_str) {
                Some(value) => parse_architecture(value)?,
                None => image_options
                    .target
                    .map(|target| target.spec().architecture)
                    .ok_or_else(|| "discover requires arch or target".to_string())?,
            };
            let limit = request
                .get("limit")
                .map(|value| {
                    value
                        .as_u64()
                        .ok_or_else(|| "limit must be a positive integer".to_string())
                        .and_then(|value| {
                            usize::try_from(value)
                                .map_err(|_| "limit is too large for this platform".to_string())
                        })
                })
                .transpose()?
                .unwrap_or(4096);
            if limit == 0 {
                return Err("limit must be greater than zero".into());
            }
            let result = discover_command(DiscoverOptions {
                image,
                architecture,
                target: image_options.target,
                limit,
                loader: image_options.loader,
                base: image_options.base,
                slice: image_options.slice,
                format: OutputFormat::Text,
            })?;
            Ok(("discover".into(), result))
        }
        "reconstruct-source" => {
            let image = image.ok_or_else(|| "reconstruct-source requires image".to_string())?;
            let address = required_request_string(request, "address")?.to_string();
            let image_options = request_image_options(request)?;
            let target = image_options
                .target
                .ok_or_else(|| "reconstruct-source requires target".to_string())?;
            let limit = request
                .get("limit")
                .map(|value| {
                    value
                        .as_u64()
                        .ok_or_else(|| "limit must be a positive integer".to_string())
                        .and_then(|value| {
                            usize::try_from(value)
                                .map_err(|_| "limit is too large for this platform".to_string())
                        })
                })
                .transpose()?
                .unwrap_or(4096);
            if limit == 0 {
                return Err("limit must be greater than zero".into());
            }
            let raw = request
                .get("raw")
                .map(|value| {
                    value
                        .as_bool()
                        .ok_or_else(|| "raw must be a boolean".to_string())
                })
                .transpose()?
                .unwrap_or(false);
            let metadata = request
                .get("metadata")
                .map(|value| {
                    value
                        .as_str()
                        .map(PathBuf::from)
                        .ok_or_else(|| "metadata must be a string".to_string())
                })
                .transpose()?;
            let options = GameOptions {
                lift: LiftOptions {
                    image,
                    address,
                    architecture: target.spec().architecture,
                    limit,
                    cache: None,
                    loader: image_options.loader,
                    base: image_options.base,
                    slice: image_options.slice,
                    target: Some(target),
                    raw,
                    format: OutputFormat::Text,
                },
                metadata,
            };
            Ok(("reconstruct-source".into(), reconstruct_source(options)?))
        }
        "lift" | "decompile-native" => {
            let image = image.ok_or_else(|| format!("{command} requires image"))?;
            let address = required_request_string(request, "address")?.to_string();
            let image_options = request_image_options(request)?;
            let architecture = match request.get("arch").and_then(Value::as_str) {
                Some(value) => parse_architecture(value)?,
                None => image_options
                    .target
                    .map(|target| target.spec().architecture)
                    .unwrap_or(Architecture::X86_64),
            };
            let limit = request
                .get("limit")
                .map(|value| {
                    value
                        .as_u64()
                        .ok_or_else(|| "limit must be a positive integer".to_string())
                        .and_then(|value| {
                            usize::try_from(value)
                                .map_err(|_| "limit is too large for this platform".to_string())
                        })
                })
                .transpose()?
                .unwrap_or(4096);
            if limit == 0 {
                return Err("limit must be greater than zero".into());
            }
            let raw = request
                .get("raw")
                .map(|value| {
                    value
                        .as_bool()
                        .ok_or_else(|| "raw must be a boolean".to_string())
                })
                .transpose()?
                .unwrap_or(false);
            let options = LiftOptions {
                image,
                address,
                architecture,
                limit,
                cache: None,
                loader: image_options.loader,
                base: image_options.base,
                slice: image_options.slice,
                target: image_options.target,
                raw,
                format: OutputFormat::Text,
            };
            let result = if command == "lift" {
                lift(options)?
            } else {
                context.decompile_native(options)?
            };
            Ok((command.into(), result))
        }
        other => Err(format!("unsupported batch command {other:?}")),
    }
}

fn required_request_string<'a>(request: &'a Value, name: &str) -> Result<&'a str, String> {
    request
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("request field {name} must be a string"))
}
fn request_image_options(request: &Value) -> Result<ImageOptions, String> {
    let loader = match request.get("loader") {
        None => Loader::Auto,
        Some(value) => {
            let name = value
                .as_str()
                .ok_or_else(|| "request field loader must be a string".to_string())?;
            Loader::parse(name).ok_or_else(|| format!("unknown loader {name:?}"))?
        }
    };
    let base = match request.get("base") {
        None => None,
        Some(value) => match value.as_str() {
            Some(text) => Some(parse_offset(text)?),
            None => Some(
                value
                    .as_u64()
                    .ok_or_else(|| "request field base must be an address".to_string())?,
            ),
        },
    };
    let slice = match request.get("slice") {
        None => None,
        Some(value) => match value.as_str() {
            Some(text) => Some(parse_slice_index(text)?),
            None => Some(
                usize::try_from(
                    value
                        .as_u64()
                        .ok_or_else(|| "request field slice must be an index".to_string())?,
                )
                .map_err(|_| "request field slice is too large".to_string())?,
            ),
        },
    };
    let target = match request.get("target") {
        None => None,
        Some(value) => {
            let name = value
                .as_str()
                .ok_or_else(|| "request field target must be a string".to_string())?;
            Some(TargetProfile::parse(name).ok_or_else(|| format!("unknown target {name:?}"))?)
        }
    };
    Ok(ImageOptions {
        loader,
        base,
        slice,
        target,
    })
}

fn effective_image_options(mut options: ImageOptions) -> ImageOptions {
    if let Some(target) = options.target {
        let spec = target.spec();
        if options.loader == Loader::Auto {
            options.loader = spec.loader;
        }
        if options.base.is_none() {
            options.base = spec.default_base;
        }
    }
    options
}

struct ImageFile {
    source: Vec<u8>,
    bytes: Vec<u8>,
    image: Image,
}

fn read_image(path: &Path, options: ImageOptions) -> Result<ImageFile, String> {
    let source = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let options = effective_image_options(options);
    let loaded = Image::load_with_slice(&source, options.loader, options.base, options.slice)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(ImageFile {
        source,
        bytes: loaded.bytes,
        image: loaded.image,
    })
}

fn read_lift_image(options: &LiftOptions) -> Result<(Vec<u8>, Image), String> {
    let bytes = std::fs::read(&options.image)
        .map_err(|error| format!("{}: {error}", options.image.display()))?;
    if !options.raw {
        let image_options = effective_image_options(ImageOptions {
            loader: options.loader,
            base: options.base,
            slice: options.slice,
            target: options.target,
        });
        let loaded = Image::load_with_slice(
            &bytes,
            image_options.loader,
            image_options.base,
            image_options.slice,
        )
        .map_err(|error| format!("{}: {error}", options.image.display()))?;
        return Ok((loaded.bytes, loaded.image));
    }
    let address = parse_offset(&options.address)?;
    if bytes.is_empty() {
        return Err(format!("{}: raw image is empty", options.image.display()));
    }
    let loaded = Image::load(&bytes, Loader::Raw, Some(address))
        .map_err(|error| format!("{}: {error}", options.image.display()))?;
    Ok((loaded.bytes, loaded.image))
}

fn make_lifter(architecture: Architecture) -> Box<dyn Lifter> {
    match architecture {
        Architecture::X86_64 => Box::new(X86_64::new()),
        Architecture::X86_32 => Box::new(X86_32),
        Architecture::AArch64 => Box::new(AArch64),
        Architecture::Arm32 => Box::new(Arm32),
        Architecture::Thumb => Box::new(Thumb),
        Architecture::Mips32 => Box::new(Mips32),
        Architecture::Mips32Be => Box::new(Mips32Be),
        Architecture::Ps1 => Box::new(Ps1),
        Architecture::N64 => Box::new(N64),
        Architecture::Rv64 => Box::new(Rv64),
        Architecture::Rv32 => Box::new(Rv32),
        Architecture::Ppc32 => Box::new(Ppc32),
        Architecture::Ppc64 => Box::new(Ppc64),
        Architecture::GameCube => Box::new(GameCube),
        Architecture::M68k => Box::new(M68k),
        Architecture::Sh2 => Box::new(Sh2),
        Architecture::Sh4 => Box::new(Sh4),
        Architecture::Spu => Box::new(Spu),
        Architecture::M6502 => Box::new(M6502),
        Architecture::Z80 => Box::new(Z80),
    }
}

fn code_address(image: &Image, address: u64) -> bool {
    let has_explicit_executable_segment = image
        .segments
        .iter()
        .any(|segment| segment.perms.exec == Some(true));
    image.segments.iter().any(|segment| {
        segment.addr <= address
            && address < segment.end()
            && if has_explicit_executable_segment {
                segment.perms.exec == Some(true)
            } else {
                segment.perms.exec != Some(false)
            }
    })
}

fn discovery_seeds(
    image: &Image,
    file: &[u8],
    architecture: Architecture,
    symbols: &[ProjectSymbol],
) -> BTreeSet<u64> {
    let mut seeds = BTreeSet::new();
    if let Some(entry) = image.entry {
        seeds.insert(entry);
    }
    for symbol in symbols {
        if code_address(image, symbol.address) {
            seeds.insert(symbol.address);
        }
    }
    let has_explicit_data_segment = image
        .segments
        .iter()
        .any(|segment| segment.perms.exec == Some(false));
    let width = pointer_width(architecture);
    for segment in &image.segments {
        if segment.file_size == 0 || (has_explicit_data_segment && segment.perms.exec == Some(true))
        {
            continue;
        }
        let start = usize::try_from(segment.file_off).unwrap_or(usize::MAX);
        let length = usize::try_from(segment.file_size).unwrap_or(0);
        let Some(end) = start.checked_add(length) else {
            continue;
        };
        let Some(bytes) = file.get(start..end) else {
            continue;
        };
        if width > bytes.len() {
            continue;
        }
        for offset in (0..=bytes.len() - width).step_by(width) {
            let little = match width {
                4 => u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as u64,
                8 => u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()),
                _ => unreachable!(),
            };
            let big = match width {
                4 => u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as u64,
                8 => u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap()),
                _ => unreachable!(),
            };
            if code_address(image, little) {
                seeds.insert(little);
            }
            if code_address(image, big) {
                seeds.insert(big);
            }
        }
    }
    if seeds.is_empty() {
        if let Some(segment) = image
            .segments
            .iter()
            .find(|segment| segment.perms.exec != Some(false))
        {
            seeds.insert(segment.addr);
        }
    }
    seeds
}

fn mapped_address(image: &Image, address: u64) -> bool {
    image
        .segments
        .iter()
        .any(|segment| segment.addr <= address && address < segment.end())
}

fn pointer_width(architecture: Architecture) -> usize {
    match architecture {
        Architecture::AArch64
        | Architecture::N64
        | Architecture::Ppc64
        | Architecture::Rv64
        | Architecture::X86_64 => 8,
        _ => 4,
    }
}

fn discovered_data(
    project_image: &ProjectImage,
    image: &Image,
    file: &[u8],
    architecture: Architecture,
    generation: u32,
) -> Vec<ProjectData> {
    let mut records = Vec::new();
    let has_explicit_data_segment = image
        .segments
        .iter()
        .any(|segment| segment.perms.exec == Some(false));
    let width = pointer_width(architecture);
    let mut seen = BTreeSet::new();
    for segment in &image.segments {
        if segment.file_size == 0 || (has_explicit_data_segment && segment.perms.exec == Some(true))
        {
            continue;
        }
        let start = usize::try_from(segment.file_off).unwrap_or(usize::MAX);
        let length = usize::try_from(segment.file_size).unwrap_or(0);
        let Some(end) = start.checked_add(length) else {
            continue;
        };
        let Some(bytes) = file.get(start..end) else {
            continue;
        };
        let mut string_start = None;
        for (offset, byte) in bytes.iter().copied().enumerate() {
            let printable = (0x20..=0x7e).contains(&byte);
            if printable {
                string_start.get_or_insert(offset);
                continue;
            }
            if let Some(begin) = string_start.take() {
                if offset.saturating_sub(begin) >= 4 && records.len() < 4096 {
                    let address = segment.addr.saturating_add(begin as u64);
                    if seen.insert(address) {
                        records.push(ProjectData {
                            address,
                            size: (offset - begin + usize::from(byte == 0)) as u64,
                            name: None,
                            type_name: Some("string".into()),
                            comment: None,
                            confidence: 75,
                            source: Some("string-discovery".into()),
                            generation,
                        });
                    }
                }
            }
        }
        if let Some(begin) = string_start {
            if bytes.len().saturating_sub(begin) >= 4 && records.len() < 4096 {
                let address = segment.addr.saturating_add(begin as u64);
                if seen.insert(address) {
                    records.push(ProjectData {
                        address,
                        size: (bytes.len() - begin) as u64,
                        name: None,
                        type_name: Some("string".into()),
                        comment: None,
                        confidence: 75,
                        source: Some("string-discovery".into()),
                        generation,
                    });
                }
            }
        }
        let scan_pointers = !has_explicit_data_segment || segment.perms.exec != Some(true);
        if scan_pointers && width <= bytes.len() {
            for offset in (0..=bytes.len() - width).step_by(width) {
                let little = match width {
                    4 => u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as u64,
                    8 => u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()),
                    _ => unreachable!(),
                };
                let big = match width {
                    4 => u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as u64,
                    8 => u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap()),
                    _ => unreachable!(),
                };
                let value = if mapped_address(image, little) {
                    Some(little)
                } else if mapped_address(image, big) {
                    Some(big)
                } else {
                    None
                };
                if let Some(value) = value {
                    let address = segment.addr.saturating_add(offset as u64);
                    if seen.insert(address) && records.len() < 4096 {
                        records.push(ProjectData {
                            address,
                            size: width as u64,
                            name: None,
                            type_name: Some("pointer".into()),
                            comment: Some(format!("points to 0x{value:x}")),
                            confidence: 65,
                            source: Some("pointer-discovery".into()),
                            generation,
                        });
                    }
                }
            }
        }
    }
    for relocation in &project_image.relocations {
        if mapped_address(image, relocation.address) && seen.insert(relocation.address) {
            records.push(ProjectData {
                address: relocation.address,
                size: 4,
                name: relocation.symbol.clone(),
                type_name: Some("global".into()),
                comment: None,
                confidence: 95,
                source: Some("relocation-discovery".into()),
                generation,
            });
        }
    }
    records
}

fn automatic_data(
    project_image: &ProjectImage,
    image: &Image,
    file: &[u8],
    architecture: Architecture,
    generation: u32,
) -> Vec<ProjectData> {
    let mut records = BTreeMap::<u64, ProjectData>::new();
    for symbol in &project_image.symbols {
        if code_address(image, symbol.address) {
            continue;
        }
        records.insert(
            symbol.address,
            ProjectData {
                address: symbol.address,
                size: symbol.size.max(1),
                name: Some(symbol.name.clone()),
                type_name: None,
                comment: None,
                confidence: 90,
                source: Some("symbol-discovery".into()),
                generation,
            },
        );
    }
    for item in discovered_data(project_image, image, file, architecture, generation) {
        match records.get(&item.address) {
            Some(existing) if existing.confidence > item.confidence => {}
            _ => {
                records.insert(item.address, item);
            }
        }
    }
    if records.is_empty() {
        for segment in image
            .segments
            .iter()
            .filter(|segment| segment.perms.exec == Some(false))
        {
            records.insert(
                segment.addr,
                ProjectData {
                    address: segment.addr,
                    size: segment.size,
                    name: segment.name.clone(),
                    type_name: Some("segment".into()),
                    comment: None,
                    confidence: 70,
                    source: Some("segment-discovery".into()),
                    generation,
                },
            );
        }
    }
    records.into_values().collect()
}

fn discover_image(
    image: &Image,
    file: &[u8],
    architecture: Architecture,
    seeds: impl IntoIterator<Item = u64>,
    instruction_limit: usize,
) -> ventris_lifter::FunctionDiscovery {
    discover_functions(
        &*make_lifter(architecture),
        image,
        file,
        seeds,
        instruction_limit,
        4096,
    )
}

fn discover_command(options: DiscoverOptions) -> Result<String, String> {
    let effective = effective_image_options(ImageOptions {
        loader: options.loader,
        base: options.base,
        slice: options.slice,
        target: options.target,
    });
    let loaded = read_image(&options.image, effective)?;
    let metadata = loaded
        .image
        .metadata(&loaded.source)
        .map_err(|error| format!("{}: {error}", options.image.display()))?;
    let image_model = project_image(&options.image, &loaded, effective, &metadata)?;
    let seeds = discovery_seeds(&loaded.image, &loaded.bytes, options.architecture, &[]);
    if seeds.is_empty() {
        return Err(format!(
            "{}: no entry point or mapped code seed was found",
            options.image.display()
        ));
    }
    let discovery = discover_image(
        &loaded.image,
        &loaded.bytes,
        options.architecture,
        seeds.clone(),
        options.limit,
    );
    let data = automatic_data(
        &image_model,
        &loaded.image,
        &loaded.bytes,
        options.architecture,
        0,
    );
    let mut out = String::new();
    writeln!(&mut out, "architecture: {:?}", options.architecture).unwrap();
    writeln!(&mut out, "seeds: {}", seeds.len()).unwrap();
    writeln!(&mut out, "functions: {}", discovery.functions.len()).unwrap();
    writeln!(&mut out, "data: {}", data.len()).unwrap();
    writeln!(&mut out, "calls: {}", discovery.calls.len()).unwrap();
    writeln!(&mut out, "failed: {}", discovery.failures.len()).unwrap();
    for function in discovery.functions.values().take(32) {
        writeln!(
            &mut out,
            "  0x{:x} size=0x{:x} instructions={}",
            function.entry,
            function.byte_length(),
            function.instruction_count()
        )
        .unwrap();
    }
    for item in data.iter().take(32) {
        writeln!(
            &mut out,
            "  data 0x{:x} size=0x{:x} type={}{}",
            item.address,
            item.size,
            item.type_name.as_deref().unwrap_or("data"),
            item.name
                .as_deref()
                .map(|name| format!(" name={name}"))
                .unwrap_or_default()
        )
        .unwrap();
    }
    Ok(out)
}

fn runtime_required_string<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("runtime event field {name} must be a string"))
}

fn runtime_required_u64(value: &Value, name: &str) -> Result<u64, String> {
    let field = value
        .get(name)
        .ok_or_else(|| format!("runtime event field {name} is required"))?;
    if let Some(text) = field.as_str() {
        return parse_offset(text).map_err(|error| format!("runtime event field {name}: {error}"));
    }
    field
        .as_u64()
        .ok_or_else(|| format!("runtime event field {name} must be an address or integer"))
}

fn runtime_optional_u64(value: &Value, name: &str) -> Result<Option<u64>, String> {
    let Some(field) = value.get(name) else {
        return Ok(None);
    };
    if matches!(field, Value::Null) {
        return Ok(None);
    }
    runtime_required_u64(&object([(name.to_string(), field.clone())]), name).map(Some)
}

fn runtime_event_from_value(value: &Value, line: usize) -> Result<RuntimeEvent, String> {
    let kind = runtime_required_string(value, "kind")
        .map_err(|error| format!("trace line {line}: {error}"))?;
    let sequence = runtime_required_u64(value, "sequence")
        .map_err(|error| format!("trace line {line}: {error}"))?;
    let instruction = runtime_required_u64(value, "instruction")
        .map_err(|error| format!("trace line {line}: {error}"))?;
    match kind {
        "memory" => {
            let access = match runtime_required_string(value, "access")
                .map_err(|error| format!("trace line {line}: {error}"))?
            {
                "read" => AccessKind::Read,
                "write" => AccessKind::Write,
                other => {
                    return Err(format!(
                    "trace line {line}: runtime event access must be read or write, got {other:?}"
                ))
                }
            };
            let address = runtime_required_u64(value, "address")
                .map_err(|error| format!("trace line {line}: {error}"))?;
            let width = runtime_required_u64(value, "width")
                .map_err(|error| format!("trace line {line}: {error}"))?;
            let width = u32::try_from(width)
                .map_err(|_| format!("trace line {line}: runtime event width is too large"))?;
            let value = runtime_optional_u64(value, "value")
                .map_err(|error| format!("trace line {line}: {error}"))?;
            Ok(RuntimeEvent::memory(
                sequence,
                instruction,
                access,
                address,
                width,
                value,
            ))
        }
        "call" => {
            let target = runtime_required_u64(value, "target")
                .map_err(|error| format!("trace line {line}: {error}"))?;
            Ok(RuntimeEvent::call(sequence, instruction, target))
        }
        "register" => {
            let register = runtime_required_string(value, "register")
                .map_err(|error| format!("trace line {line}: {error}"))?;
            let register_value = runtime_required_u64(value, "value")
                .map_err(|error| format!("trace line {line}: {error}"))?;
            Ok(RuntimeEvent::register(
                sequence,
                instruction,
                register,
                register_value,
            ))
        }
        "marker" => {
            let text = runtime_required_string(value, "text")
                .map_err(|error| format!("trace line {line}: {error}"))?;
            Ok(RuntimeEvent::marker(sequence, instruction, text))
        }
        other => Err(format!(
            "trace line {line}: unknown runtime event kind {other:?}"
        )),
    }
}

fn read_runtime_trace(path: &Path) -> Result<Vec<RuntimeEvent>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut events = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value = json::parse(line)
            .map_err(|error| format!("{} line {}: {error}", path.display(), index + 1))?;
        events.push(runtime_event_from_value(&value, index + 1)?);
    }
    Ok(events)
}

fn runtime_access_name(access: AccessKind) -> &'static str {
    match access {
        AccessKind::Read => "read",
        AccessKind::Write => "write",
    }
}

fn ingest_runtime_trace(
    project_path: &Path,
    trace_path: &Path,
    format: OutputFormat,
) -> Result<String, String> {
    let events = read_runtime_trace(trace_path)?;
    let report = ingest_runtime_events(&events);
    let mut project = Project::load_from(project_path)
        .map_err(|error| format!("{}: {error}", project_path.display()))?;
    let mut references_added = 0usize;
    let mut assertions_added = 0usize;
    for event in &events {
        match &event.kind {
            RuntimeEventKind::Memory {
                access,
                address,
                width,
                value,
            } => {
                let before = project.references.len();
                project.add_reference(ProjectReference {
                    from: event.instruction,
                    to: *address,
                    kind: match access {
                        AccessKind::Read => ProjectReferenceKind::Read,
                        AccessKind::Write => ProjectReferenceKind::Write,
                    },
                    offset: None,
                    confidence: 95,
                    generation: 0,
                });
                references_added += project.references.len() - before;
                let before = project.assertions.len();
                project.add_assertion(ProjectAssertion {
                    address: event.instruction,
                    kind: "runtime-memory".into(),
                    value: format!(
                        "{} address=0x{:x} width={} value={}",
                        runtime_access_name(*access),
                        address,
                        width,
                        value
                            .map(|value| format!("0x{value:x}"))
                            .unwrap_or_else(|| "unknown".into())
                    ),
                    note: format!(
                        "sequence={} instruction=0x{:x}",
                        event.sequence, event.instruction
                    ),
                    authority: Authority::Machine,
                });
                assertions_added += project.assertions.len() - before;
            }
            RuntimeEventKind::Call { target } => {
                let before = project.references.len();
                project.add_reference(ProjectReference {
                    from: event.instruction,
                    to: *target,
                    kind: ProjectReferenceKind::Call,
                    offset: None,
                    confidence: 90,
                    generation: 0,
                });
                references_added += project.references.len() - before;
            }
            RuntimeEventKind::Register { register, value } => {
                let before = project.assertions.len();
                project.add_assertion(ProjectAssertion {
                    address: event.instruction,
                    kind: "runtime-register".into(),
                    value: format!("{register}=0x{value:x}"),
                    note: format!(
                        "sequence={} instruction=0x{:x}",
                        event.sequence, event.instruction
                    ),
                    authority: Authority::Machine,
                });
                assertions_added += project.assertions.len() - before;
            }
            RuntimeEventKind::Marker { text } => {
                let before = project.assertions.len();
                project.add_assertion(ProjectAssertion {
                    address: event.instruction,
                    kind: "runtime-marker".into(),
                    value: text.clone(),
                    note: format!(
                        "sequence={} instruction=0x{:x}",
                        event.sequence, event.instruction
                    ),
                    authority: Authority::Machine,
                });
                assertions_added += project.assertions.len() - before;
            }
        }
    }
    project.cache.entries =
        (project.functions.len() + project.data.len() + project.references.len()) as u64;
    project
        .save_to(project_path)
        .map_err(|error| format!("{}: {error}", project_path.display()))?;
    if format == OutputFormat::Json {
        return Ok(format!(
            "{}\n",
            stringify(&object([
                (
                    "trace".into(),
                    Value::string(trace_path.display().to_string())
                ),
                ("events".into(), Value::number(events.len())),
                ("memory".into(), Value::number(report.memory.len())),
                ("calls".into(), Value::number(report.calls.len())),
                ("registers".into(), Value::number(report.registers.len())),
                ("markers".into(), Value::number(report.markers.len())),
                ("references_added".into(), Value::number(references_added)),
                ("assertions_added".into(), Value::number(assertions_added)),
            ]))
        ));
    }
    let mut out = String::new();
    writeln!(&mut out, "trace: {}", trace_path.display()).unwrap();
    writeln!(&mut out, "events: {}", events.len()).unwrap();
    writeln!(&mut out, "memory: {}", report.memory.len()).unwrap();
    writeln!(&mut out, "calls: {}", report.calls.len()).unwrap();
    writeln!(&mut out, "registers: {}", report.registers.len()).unwrap();
    writeln!(&mut out, "markers: {}", report.markers.len()).unwrap();
    writeln!(&mut out, "references_added: {references_added}").unwrap();
    writeln!(&mut out, "assertions_added: {assertions_added}").unwrap();
    Ok(out)
}

fn manifest_array<'a>(value: &'a Value, name: &str) -> Result<&'a [Value], String> {
    match value.get(name) {
        None => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => Err(format!("asset manifest field {name} must be an array")),
    }
}

fn manifest_required_string<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("asset manifest field {name} must be a string"))
}

fn manifest_optional_string<'a>(value: &'a Value, name: &str) -> Result<Option<&'a str>, String> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(field) => field
            .as_str()
            .map(Some)
            .ok_or_else(|| format!("asset manifest field {name} must be a string")),
    }
}

fn manifest_optional_u64(value: &Value, name: &str) -> Result<Option<u64>, String> {
    let Some(field) = value.get(name) else {
        return Ok(None);
    };
    if matches!(field, Value::Null) {
        return Ok(None);
    }
    if let Some(text) = field.as_str() {
        return parse_offset(text)
            .map(Some)
            .map_err(|error| format!("asset manifest field {name}: {error}"));
    }
    field
        .as_u64()
        .map(Some)
        .ok_or_else(|| format!("asset manifest field {name} must be an address or integer"))
}

fn manifest_properties(value: &Value) -> Result<BTreeMap<String, String>, String> {
    let Some(properties) = value.get("properties") else {
        return Ok(BTreeMap::new());
    };
    let Value::Object(properties) = properties else {
        return Err("asset manifest field properties must be an object".into());
    };
    properties
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_owned()))
                .ok_or_else(|| format!("asset manifest property {key:?} must be a string"))
        })
        .collect()
}

fn parse_asset_kind(value: &str) -> Option<AssetKind> {
    match value.to_ascii_lowercase().as_str() {
        "texture" => Some(AssetKind::Texture),
        "model" => Some(AssetKind::Model),
        "animation" => Some(AssetKind::Animation),
        "sound" => Some(AssetKind::Sound),
        "table" => Some(AssetKind::Table),
        "script" => Some(AssetKind::Script),
        "unknown" => Some(AssetKind::Unknown),
        _ => None,
    }
}

fn parse_asset_link_kind(value: &str) -> Option<AssetLinkKind> {
    match value.to_ascii_lowercase().as_str() {
        "references" | "reference" => Some(AssetLinkKind::References),
        "loads" | "load" => Some(AssetLinkKind::Loads),
        "defines" | "define" => Some(AssetLinkKind::Defines),
        "calls" | "call" => Some(AssetLinkKind::Calls),
        "generates" | "generate" => Some(AssetLinkKind::Generates),
        "unknown" => Some(AssetLinkKind::Unknown),
        _ => None,
    }
}

fn read_asset_manifest(path: &Path) -> Result<AssetCatalog, String> {
    let source =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let root = json::parse(&source).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut catalog = AssetCatalog::default();
    for (index, item) in manifest_array(&root, "assets")?.iter().enumerate() {
        let id = manifest_required_string(item, "id")
            .map_err(|error| format!("asset {index}: {error}"))?;
        let name = manifest_optional_string(item, "name")
            .map_err(|error| format!("asset {index}: {error}"))?
            .unwrap_or(id);
        let kind_name = manifest_optional_string(item, "kind")
            .map_err(|error| format!("asset {index}: {error}"))?
            .unwrap_or("unknown");
        let kind = parse_asset_kind(kind_name)
            .ok_or_else(|| format!("asset {index}: unknown asset kind {kind_name:?}"))?;
        let source = manifest_required_string(item, "source")
            .map_err(|error| format!("asset {index}: {error}"))?;
        let mut asset = GameAsset::new(id, name, kind, source);
        asset.address = manifest_optional_u64(item, "address")
            .map_err(|error| format!("asset {index}: {error}"))?;
        asset.size = manifest_optional_u64(item, "size")
            .map_err(|error| format!("asset {index}: {error}"))?;
        asset.properties =
            manifest_properties(item).map_err(|error| format!("asset {index}: {error}"))?;
        catalog
            .register_asset(asset)
            .map_err(|error| format!("asset {index}: {error}"))?;
    }
    for (index, item) in manifest_array(&root, "scripts")?.iter().enumerate() {
        let id = manifest_required_string(item, "id")
            .map_err(|error| format!("script {index}: {error}"))?;
        let name = manifest_optional_string(item, "name")
            .map_err(|error| format!("script {index}: {error}"))?
            .unwrap_or(id);
        let source = manifest_required_string(item, "source")
            .map_err(|error| format!("script {index}: {error}"))?;
        let mut script = GameScript::new(id, name, source);
        script.entry = manifest_optional_u64(item, "entry")
            .map_err(|error| format!("script {index}: {error}"))?;
        script.language = manifest_optional_string(item, "language")
            .map_err(|error| format!("script {index}: {error}"))?
            .map(str::to_owned);
        script.properties =
            manifest_properties(item).map_err(|error| format!("script {index}: {error}"))?;
        catalog
            .register_script(script)
            .map_err(|error| format!("script {index}: {error}"))?;
    }
    for (index, item) in manifest_array(&root, "links")?.iter().enumerate() {
        let code_address = manifest_optional_u64(item, "code_address")
            .map_err(|error| format!("link {index}: {error}"))?
            .ok_or_else(|| format!("link {index}: code_address is required"))?;
        let target = if let Some(id) = manifest_optional_string(item, "asset")
            .map_err(|error| format!("link {index}: {error}"))?
        {
            AssetTarget::Asset(id.to_owned())
        } else if let Some(id) = manifest_optional_string(item, "script")
            .map_err(|error| format!("link {index}: {error}"))?
        {
            AssetTarget::Script(id.to_owned())
        } else {
            return Err(format!("link {index}: one of asset or script is required"));
        };
        let kind_name = manifest_optional_string(item, "kind")
            .map_err(|error| format!("link {index}: {error}"))?
            .unwrap_or("references");
        let kind = parse_asset_link_kind(kind_name)
            .ok_or_else(|| format!("link {index}: unknown link kind {kind_name:?}"))?;
        let confidence = manifest_optional_u64(item, "confidence")
            .map_err(|error| format!("link {index}: {error}"))?
            .unwrap_or(100);
        let confidence = u8::try_from(confidence)
            .map_err(|_| format!("link {index}: confidence is too large"))?;
        let note = manifest_optional_string(item, "note")
            .map_err(|error| format!("link {index}: {error}"))?
            .map(str::to_owned);
        catalog
            .link(code_address, target, kind, confidence, note)
            .map_err(|error| format!("link {index}: {error}"))?;
    }
    Ok(catalog)
}

fn add_automatic_asset_links(catalog: &mut AssetCatalog, project: &Project) -> Result<(), String> {
    let mut candidates = Vec::new();
    for reference in &project.references {
        for asset in &catalog.assets {
            let (Some(address), Some(size)) = (asset.address, asset.size) else {
                continue;
            };
            let Some(end) = address.checked_add(size) else {
                continue;
            };
            if reference.to < address || reference.to >= end {
                continue;
            }
            let kind = match reference.kind {
                ProjectReferenceKind::Read | ProjectReferenceKind::Write => AssetLinkKind::Loads,
                _ => AssetLinkKind::References,
            };
            candidates.push((
                reference.from,
                AssetTarget::Asset(asset.id.clone()),
                kind,
                reference.confidence,
                Some(format!(
                    "automatic project reference to 0x{:x}",
                    reference.to
                )),
            ));
        }
        if reference.kind == ProjectReferenceKind::Call {
            for script in &catalog.scripts {
                if script.entry == Some(reference.to) {
                    candidates.push((
                        reference.from,
                        AssetTarget::Script(script.id.clone()),
                        AssetLinkKind::Calls,
                        reference.confidence,
                        Some(format!("automatic call reference to 0x{:x}", reference.to)),
                    ));
                }
            }
        }
    }
    for (code_address, target, kind, confidence, note) in candidates {
        if catalog
            .links
            .iter()
            .any(|link| link.code_address == code_address && link.target == target)
        {
            continue;
        }
        catalog
            .link(code_address, target, kind, confidence, note)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn link_game_assets(
    project_path: &Path,
    manifest_path: &Path,
    format: OutputFormat,
) -> Result<String, String> {
    let mut catalog = read_asset_manifest(manifest_path)?;
    let mut project = Project::load_from(project_path)
        .map_err(|error| format!("{}: {error}", project_path.display()))?;
    add_automatic_asset_links(&mut catalog, &project)?;
    let mut assertions_added = 0usize;
    for link in &catalog.links {
        let (target_kind, target_id) = match &link.target {
            AssetTarget::Asset(id) => ("asset-link", id),
            AssetTarget::Script(id) => ("script-link", id),
        };
        let before = project.assertions.len();
        project.add_assertion(ProjectAssertion {
            address: link.code_address,
            kind: target_kind.into(),
            value: target_id.clone(),
            note: format!(
                "kind={:?} confidence={} source={}{}",
                link.kind,
                link.confidence,
                manifest_path.display(),
                link.note
                    .as_deref()
                    .map(|note| format!(" note={note}"))
                    .unwrap_or_default()
            ),
            authority: Authority::Machine,
        });
        assertions_added += project.assertions.len() - before;
    }
    project.cache.entries =
        (project.functions.len() + project.data.len() + project.references.len()) as u64;
    project
        .save_to(project_path)
        .map_err(|error| format!("{}: {error}", project_path.display()))?;
    let asset_links = catalog
        .links
        .iter()
        .filter(|link| matches!(link.target, AssetTarget::Asset(_)))
        .count();
    let script_links = catalog
        .links
        .iter()
        .filter(|link| matches!(link.target, AssetTarget::Script(_)))
        .count();
    if format == OutputFormat::Json {
        let links = catalog
            .links
            .iter()
            .map(|link| {
                let (target_type, target_id) = match &link.target {
                    AssetTarget::Asset(id) => ("asset", id),
                    AssetTarget::Script(id) => ("script", id),
                };
                object([
                    (
                        "code_address".into(),
                        Value::string(format!("0x{:x}", link.code_address)),
                    ),
                    ("target_type".into(), Value::string(target_type)),
                    ("target".into(), Value::string(target_id.clone())),
                    ("kind".into(), Value::string(format!("{:?}", link.kind))),
                    ("confidence".into(), Value::number(link.confidence)),
                    (
                        "note".into(),
                        link.note.clone().map(Value::string).unwrap_or(Value::Null),
                    ),
                ])
            })
            .collect();
        return Ok(format!(
            "{}\n",
            stringify(&object([
                (
                    "manifest".into(),
                    Value::string(manifest_path.display().to_string())
                ),
                ("assets".into(), Value::number(catalog.assets.len())),
                ("scripts".into(), Value::number(catalog.scripts.len())),
                ("links".into(), Value::Array(links)),
                ("asset_links".into(), Value::number(asset_links)),
                ("script_links".into(), Value::number(script_links)),
                ("assertions_added".into(), Value::number(assertions_added)),
            ]))
        ));
    }
    let mut out = String::new();
    writeln!(&mut out, "manifest: {}", manifest_path.display()).unwrap();
    writeln!(&mut out, "assets: {}", catalog.assets.len()).unwrap();
    writeln!(&mut out, "scripts: {}", catalog.scripts.len()).unwrap();
    writeln!(&mut out, "links: {}", catalog.links.len()).unwrap();
    writeln!(&mut out, "asset_links: {asset_links}").unwrap();
    writeln!(&mut out, "script_links: {script_links}").unwrap();
    writeln!(&mut out, "assertions_added: {assertions_added}").unwrap();
    for link in &catalog.links {
        let target = match &link.target {
            AssetTarget::Asset(id) => format!("asset:{id}"),
            AssetTarget::Script(id) => format!("script:{id}"),
        };
        writeln!(
            &mut out,
            "  0x{:x} -> {target} kind={:?} confidence={}",
            link.code_address, link.kind, link.confidence
        )
        .unwrap();
    }
    Ok(out)
}

fn project_command(options: ProjectOptions) -> Result<String, String> {
    let format = options.format;
    match options.action {
        ProjectAction::Init {
            image,
            project,
            options,
        } => {
            let effective = effective_image_options(options);
            let loaded = read_image(&image, effective)?;
            let metadata = loaded
                .image
                .metadata(&loaded.source)
                .map_err(|error| format!("{}: {error}", image.display()))?;
            let image_model = project_image(&image, &loaded, effective, &metadata)?;
            let config_digest = stable64(
                format!(
                    "{}:{:?}:{:?}:{:?}",
                    effective.loader.name(),
                    effective.target.map(TargetProfile::name),
                    effective.base,
                    effective.slice
                )
                .as_bytes(),
            );
            let mut model = Project::new(image_model);
            model.record_generation(ProjectGeneration {
                id: 0,
                analyzer_version: NATIVE_ANALYZER_CODE_VERSION,
                config_digest,
                human_log_digest: 0,
                status: "created".into(),
                function_count: 0,
                data_count: 0,
            });
            model.cache = ProjectCache {
                key_digest: stable64(&loaded.source),
                generation: 0,
                entries: 0,
                bytes: 0,
                budget: 0,
            };
            model
                .save_to(&project)
                .map_err(|error| format!("{}: {error}", project.display()))?;
            render_project(&model, format)
        }
        ProjectAction::Analyze {
            project,
            architecture,
            target: _target,
            limit,
        } => analyze_project(&project, architecture, limit, format),
        ProjectAction::Show { project } => {
            let model = Project::load_from(&project)
                .map_err(|error| format!("{}: {error}", project.display()))?;
            render_project(&model, format)
        }
        ProjectAction::Runtime { project, trace } => ingest_runtime_trace(&project, &trace, format),
        ProjectAction::Assets { project, manifest } => {
            link_game_assets(&project, &manifest, format)
        }
        ProjectAction::References {
            project,
            address,
            incoming,
            outgoing,
        } => {
            let model = Project::load_from(&project)
                .map_err(|error| format!("{}: {error}", project.display()))?;
            render_project_references(&model, address, incoming, outgoing, format)
        }
    }
}

fn analyze_project(
    project_path: &Path,
    architecture: Architecture,
    instruction_limit: usize,
    format: OutputFormat,
) -> Result<String, String> {
    let mut project = Project::load_from(project_path)
        .map_err(|error| format!("{}: {error}", project_path.display()))?;
    let source_path = PathBuf::from(&project.image.source);
    let source = std::fs::read(&source_path)
        .map_err(|error| format!("{}: {error}", source_path.display()))?;
    let loader = Loader::parse(&project.image.loader).ok_or_else(|| {
        format!(
            "{}: project stores an unknown loader {:?}",
            project_path.display(),
            project.image.loader
        )
    })?;
    let slice = project
        .image
        .slice
        .map(|value| usize::try_from(value).map_err(|_| "project slice is too large".to_string()))
        .transpose()?;
    let loaded = Image::load_with_slice(&source, loader, project.image.base, slice)
        .map_err(|error| format!("{}: {error}", source_path.display()))?;
    let seeds = discovery_seeds(
        &loaded.image,
        &loaded.bytes,
        architecture,
        &project.image.symbols,
    );
    if seeds.is_empty() {
        return Err(format!(
            "{}: no entry point or mapped code seed was found",
            source_path.display()
        ));
    }
    let discovery = discover_image(
        &loaded.image,
        &loaded.bytes,
        architecture,
        seeds,
        instruction_limit,
    );
    let generation = project
        .generations
        .iter()
        .map(|item| item.id)
        .max()
        .unwrap_or(0)
        .saturating_add(1);

    project
        .functions
        .retain(|item| item.source.as_deref() != Some("native-discovery"));
    project.data.retain(|item| {
        !matches!(
            item.source.as_deref(),
            Some(
                "segment-discovery"
                    | "symbol-discovery"
                    | "string-discovery"
                    | "pointer-discovery"
                    | "relocation-discovery"
            )
        )
    });
    project.references.retain(|item| item.generation == 0);

    for function in discovery.functions.values() {
        let name = project
            .image
            .symbols
            .iter()
            .find(|symbol| symbol.address == function.entry)
            .map(|symbol| symbol.name.clone());
        project.upsert_function(ProjectFunction {
            address: function.entry,
            size: function.byte_length(),
            name,
            signature: None,
            comment: None,
            confidence: 80,
            source: Some("native-discovery".into()),
            generation,
        });
        for (&from, instruction) in &function.instructions {
            match instruction.flow {
                Flow::Call { target, .. } => project.add_reference(ProjectReference {
                    from,
                    to: target,
                    kind: ProjectReferenceKind::Call,
                    offset: None,
                    confidence: 90,
                    generation,
                }),
                Flow::Jump(target) | Flow::Conditional { target, .. } => {
                    project.add_reference(ProjectReference {
                        from,
                        to: target,
                        kind: ProjectReferenceKind::Jump,
                        offset: None,
                        confidence: 90,
                        generation,
                    });
                }
                Flow::FallThrough(_) | Flow::Return => {}
            }
        }
    }

    for item in automatic_data(
        &project.image,
        &loaded.image,
        &loaded.bytes,
        architecture,
        generation,
    ) {
        project.upsert_data(item);
    }

    let status = if discovery.failures.is_empty() {
        "analyzed".to_string()
    } else {
        format!("analyzed with {} failed entries", discovery.failures.len())
    };
    project.record_generation(ProjectGeneration {
        id: generation,
        analyzer_version: NATIVE_ANALYZER_CODE_VERSION,
        config_digest: stable64(format!("{architecture:?}:{instruction_limit}").as_bytes()),
        human_log_digest: 0,
        status,
        function_count: discovery.functions.len() as u64,
        data_count: project
            .data
            .iter()
            .filter(|item| item.generation == generation)
            .count() as u64,
    });
    project.cache.generation = generation;
    project.cache.entries =
        (project.functions.len() + project.data.len() + project.references.len()) as u64;
    project.cache.bytes = loaded.bytes.len() as u64;
    project
        .save_to(project_path)
        .map_err(|error| format!("{}: {error}", project_path.display()))?;
    render_project(&project, format)
}
fn decompile_project_function(options: ProjectDecompileOptions) -> Result<String, String> {
    let model = Project::load_from(&options.project)
        .map_err(|error| format!("{}: {error}", options.project.display()))?;
    let address = parse_offset(&options.function).or_else(|_| {
        model
            .functions
            .iter()
            .find(|item| item.name.as_deref() == Some(options.function.as_str()))
            .map(|item| item.address)
            .ok_or_else(|| format!("unknown discovered function {:?}", options.function))
    })?;
    let loader = Loader::parse(&model.image.loader).ok_or_else(|| {
        format!(
            "{}: project stores an unknown loader {:?}",
            options.project.display(),
            model.image.loader
        )
    })?;
    let target = options
        .target
        .or_else(|| model.image.target.as_deref().and_then(TargetProfile::parse));
    let lift_options = LiftOptions {
        image: PathBuf::from(&model.image.source),
        address: format!("0x{address:x}"),
        architecture: options.architecture,
        target,
        limit: options.limit,
        cache: options.cache,
        loader,
        base: model.image.base,
        slice: model
            .image
            .slice
            .map(|value| usize::try_from(value).map_err(|_| "project slice is too large"))
            .transpose()
            .map_err(|error| error.to_string())?,
        raw: false,
        format: options.format,
    };
    decompile_native(lift_options)
}

fn project_image(
    path: &Path,
    loaded: &ImageFile,
    options: ImageOptions,
    metadata: &ImageMetadata,
) -> Result<ProjectImage, String> {
    let segments = loaded
        .image
        .segments
        .iter()
        .map(|segment| ProjectSegment {
            name: segment.name.clone(),
            address: segment.addr,
            size: segment.size,
            file_offset: segment.file_off,
            file_size: segment.file_size,
            read: segment.perms.read,
            write: segment.perms.write,
            execute: segment.perms.exec,
        })
        .collect::<Vec<_>>();
    let regions = loaded
        .image
        .regions
        .iter()
        .map(|region| {
            let placement = match region.placement {
                Placement::Mapped => ProjectPlacement::Mapped,
                Placement::Aliases { of } => ProjectPlacement::Aliased {
                    segment: u32::try_from(of)
                        .map_err(|_| "image segment index is too large".to_string())?,
                },
                Placement::Unaddressed => ProjectPlacement::Unaddressed,
            };
            Ok(ProjectRegion {
                name: region.name.clone(),
                address: region.addr,
                size: region.size,
                allocated: region.alloc,
                placement,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut spaces = Vec::new();
    for (index, segment) in loaded.image.segments.iter().enumerate() {
        let id = u32::try_from(index).map_err(|_| "too many image segments".to_string())?;
        spaces.push(ProjectSpace {
            id,
            name: segment
                .name
                .clone()
                .unwrap_or_else(|| format!("segment-{index}")),
            kind: if segment.perms.exec == Some(true) {
                "code".into()
            } else {
                "data".into()
            },
            base: segment.addr,
            size: segment.size,
            overlay_of: None,
        });
    }
    for (index, region) in loaded.image.regions.iter().enumerate() {
        let Placement::Aliases { of } = region.placement else {
            continue;
        };
        let id = u32::try_from(
            loaded
                .image
                .segments
                .len()
                .checked_add(index)
                .ok_or_else(|| "too many image spaces".to_string())?,
        )
        .map_err(|_| "too many image spaces".to_string())?;
        spaces.push(ProjectSpace {
            id,
            name: region.name.clone(),
            kind: "overlay".into(),
            base: region.addr,
            size: region.size,
            overlay_of: Some(
                u32::try_from(of).map_err(|_| "image segment index is too large".to_string())?,
            ),
        });
    }
    Ok(ProjectImage {
        source: path.to_string_lossy().into_owned(),
        content_hash: Image::content_hash(&loaded.source),
        loader: options.loader.name().into(),
        target: options.target.map(TargetProfile::name).map(str::to_owned),
        base: options.base,
        slice: options.slice.map(|value| value as u64),
        file_size: loaded.source.len() as u64,
        normalized_size: loaded.bytes.len() as u64,
        entry: loaded.image.entry,
        segments,
        regions,
        spaces,
        symbols: metadata
            .symbols
            .iter()
            .map(|symbol| ProjectSymbol {
                address: symbol.address,
                name: symbol.name.clone(),
                size: symbol.size,
                section: symbol.section,
            })
            .collect(),
        relocations: metadata
            .relocations
            .iter()
            .map(|relocation| ProjectRelocation {
                address: relocation.address,
                symbol: relocation.symbol.clone(),
                kind: relocation.kind,
                addend: relocation.addend,
            })
            .collect(),
    })
}

fn render_project_references(
    project: &Project,
    address: u64,
    incoming: bool,
    outgoing: bool,
    format: OutputFormat,
) -> Result<String, String> {
    let function = project.function_containing(address).map(|item| {
        item.name
            .clone()
            .unwrap_or_else(|| format!("sub_{:x}", item.address))
    });
    let data = project.data_containing(address).map(|item| {
        item.name
            .clone()
            .unwrap_or_else(|| format!("data_{:x}", item.address))
    });
    let incoming_refs: Vec<_> = if incoming {
        project.references_to(address).collect()
    } else {
        Vec::new()
    };
    let outgoing_refs: Vec<_> = if outgoing {
        project.references_from(address).collect()
    } else {
        Vec::new()
    };
    if format == OutputFormat::Json {
        let render = |reference: &ProjectReference, direction: &str| {
            let (endpoint, key) = if direction == "incoming" {
                (reference.from, "from")
            } else {
                (reference.to, "to")
            };
            object([
                (key.into(), Value::string(format!("0x{endpoint:x}"))),
                (
                    "kind".into(),
                    Value::string(format!("{:?}", reference.kind)),
                ),
                (
                    "offset".into(),
                    reference.offset.map(Value::number).unwrap_or(Value::Null),
                ),
                ("confidence".into(), Value::number(reference.confidence)),
                ("generation".into(), Value::number(reference.generation)),
            ])
        };
        return Ok(format!(
            "{}\n",
            stringify(&object([
                ("address".into(), Value::string(format!("0x{address:x}")),),
                (
                    "function".into(),
                    function.map(Value::string).unwrap_or(Value::Null),
                ),
                (
                    "data".into(),
                    data.map(Value::string).unwrap_or(Value::Null)
                ),
                (
                    "incoming".into(),
                    Value::Array(
                        incoming_refs
                            .iter()
                            .map(|reference| render(reference, "incoming"))
                            .collect(),
                    ),
                ),
                (
                    "outgoing".into(),
                    Value::Array(
                        outgoing_refs
                            .iter()
                            .map(|reference| render(reference, "outgoing"))
                            .collect(),
                    ),
                ),
            ]))
        ));
    }
    let mut out = String::new();
    writeln!(&mut out, "address: 0x{address:x}").unwrap();
    if let Some(function) = function {
        writeln!(&mut out, "function: {function}").unwrap();
    }
    if let Some(data) = data {
        writeln!(&mut out, "data: {data}").unwrap();
    }
    writeln!(&mut out, "incoming: {}", incoming_refs.len()).unwrap();
    for reference in incoming_refs {
        writeln!(
            &mut out,
            "  from=0x{:x} kind={:?} confidence={}",
            reference.from, reference.kind, reference.confidence
        )
        .unwrap();
    }
    writeln!(&mut out, "outgoing: {}", outgoing_refs.len()).unwrap();
    for reference in outgoing_refs {
        writeln!(
            &mut out,
            "  to=0x{:x} kind={:?} confidence={}",
            reference.to, reference.kind, reference.confidence
        )
        .unwrap();
    }
    Ok(out)
}

fn render_project(project: &Project, format: OutputFormat) -> Result<String, String> {
    if format == OutputFormat::Json {
        let image = &project.image;
        let segments = image
            .segments
            .iter()
            .map(|segment| {
                object([
                    ("name".into(), optional_string(segment.name.as_deref())),
                    (
                        "address".into(),
                        Value::string(format!("0x{:x}", segment.address)),
                    ),
                    (
                        "size".into(),
                        Value::string(format!("0x{:x}", segment.size)),
                    ),
                    (
                        "file_offset".into(),
                        Value::string(format!("0x{:x}", segment.file_offset)),
                    ),
                    (
                        "file_size".into(),
                        Value::string(format!("0x{:x}", segment.file_size)),
                    ),
                ])
            })
            .collect();
        let spaces = image
            .spaces
            .iter()
            .map(|space| {
                object([
                    ("id".into(), Value::number(space.id)),
                    ("name".into(), Value::string(space.name.clone())),
                    ("kind".into(), Value::string(space.kind.clone())),
                    ("base".into(), Value::string(format!("0x{:x}", space.base))),
                    ("size".into(), Value::string(format!("0x{:x}", space.size))),
                    (
                        "overlay_of".into(),
                        space.overlay_of.map(Value::number).unwrap_or(Value::Null),
                    ),
                ])
            })
            .collect();
        return Ok(format!(
            "{}\n",
            stringify(&object([
                ("source".into(), Value::string(image.source.clone())),
                (
                    "content_hash".into(),
                    Value::string(format!("0x{:016x}", image.content_hash)),
                ),
                ("loader".into(), Value::string(image.loader.clone())),
                (
                    "target".into(),
                    image
                        .target
                        .clone()
                        .map(Value::string)
                        .unwrap_or(Value::Null),
                ),
                (
                    "entry".into(),
                    image
                        .entry
                        .map(|value| Value::string(format!("0x{value:x}")))
                        .unwrap_or(Value::Null),
                ),
                ("segments".into(), Value::Array(segments)),
                ("spaces".into(), Value::Array(spaces)),
                ("symbol_count".into(), Value::number(image.symbols.len())),
                (
                    "relocation_count".into(),
                    Value::number(image.relocations.len())
                ),
                (
                    "function_count".into(),
                    Value::number(project.functions.len())
                ),
                ("data_count".into(), Value::number(project.data.len())),
                (
                    "reference_count".into(),
                    Value::number(project.references.len())
                ),
                (
                    "assertion_count".into(),
                    Value::number(project.assertions.len())
                ),
                (
                    "generation_count".into(),
                    Value::number(project.generations.len())
                ),
            ]))
        ));
    }
    let image = &project.image;
    let mut out = String::new();
    writeln!(&mut out, "source: {}", image.source).unwrap();
    writeln!(&mut out, "loader: {}", image.loader).unwrap();
    if let Some(target) = &image.target {
        writeln!(&mut out, "target: {target}").unwrap();
    }
    writeln!(&mut out, "content_hash: 0x{:016x}", image.content_hash).unwrap();
    writeln!(
        &mut out,
        "sizes: file=0x{:x} normalized=0x{:x}",
        image.file_size, image.normalized_size
    )
    .unwrap();
    if let Some(entry) = image.entry {
        writeln!(&mut out, "entry: 0x{entry:x}").unwrap();
    }
    writeln!(&mut out, "segments: {}", image.segments.len()).unwrap();
    writeln!(&mut out, "regions: {}", image.regions.len()).unwrap();
    writeln!(&mut out, "spaces: {}", image.spaces.len()).unwrap();
    writeln!(&mut out, "symbols: {}", image.symbols.len()).unwrap();
    writeln!(&mut out, "relocations: {}", image.relocations.len()).unwrap();
    writeln!(&mut out, "functions: {}", project.functions.len()).unwrap();
    writeln!(&mut out, "data: {}", project.data.len()).unwrap();
    writeln!(&mut out, "references: {}", project.references.len()).unwrap();
    writeln!(&mut out, "assertions: {}", project.assertions.len()).unwrap();
    writeln!(&mut out, "generations: {}", project.generations.len()).unwrap();
    Ok(out)
}

fn optional_string(value: Option<&str>) -> Value {
    value
        .map(|value| Value::string(value.to_owned()))
        .unwrap_or(Value::Null)
}

fn serve(options: ServeOptions) -> Result<String, String> {
    let listener =
        TcpListener::bind(&options.bind).map_err(|error| format!("{}: {error}", options.bind))?;
    eprintln!("ventris: HTTP server listening on {}", options.bind);
    for incoming in listener.incoming() {
        let mut stream = incoming.map_err(|error| format!("accept: {error}"))?;
        if let Err(error) = handle_http(&mut stream) {
            eprintln!("ventris: HTTP request ignored: {error}");
            continue;
        }
        if options.once {
            break;
        }
    }
    Ok(String::new())
}

fn handle_http(stream: &mut TcpStream) -> Result<(), String> {
    let (method, target, body) = read_http_request(stream)?;
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let is_batch = method == "POST" && path == "/batch";
    if (method != "GET" && !is_batch) || (path == "/batch" && method != "POST") {
        return write_http(
            stream,
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            "GET is required; POST is supported for /batch\n",
        );
    }
    let format = if is_batch {
        OutputFormat::Json
    } else {
        match query_value(query, "format").as_deref() {
            None | Some("text") => OutputFormat::Text,
            Some("json") => OutputFormat::Json,
            Some(other) => {
                return write_http(
                    stream,
                    "400 Bad Request",
                    "text/plain; charset=utf-8",
                    &format!("invalid format {other:?}; use text or json\n"),
                )
            }
        }
    };
    let result = match (method.as_str(), path) {
        ("GET", "/health") => Ok((
            "{\"status\":\"ok\",\"service\":\"ventris\"}\n".to_string(),
            "application/json",
        )),
        ("GET", "/inspect") => endpoint_inspect(query),
        ("GET", "/diff") => endpoint_diff(query),
        ("GET", "/discover") => endpoint_discover(query),
        ("GET", "/resolve") => endpoint_resolve(query),
        ("GET", "/recover-types") => endpoint_recover_types(query),
        ("GET", "/reconstruct-source") => endpoint_reconstruct_source(query),
        ("GET", "/lift") => endpoint_lift(query, false),
        ("GET", "/decompile-native") => endpoint_lift(query, true),
        ("POST", "/batch") => endpoint_batch(&body),
        _ => Err(format!("unknown endpoint {path:?}")),
    };
    match result {
        Ok((body, content_type))
            if format == OutputFormat::Json && content_type != "application/json" =>
        {
            let body = format!(
                "{}\n",
                stringify(&object([
                    ("ok".into(), Value::Bool(true)),
                    ("endpoint".into(), Value::string(path)),
                    ("result".into(), Value::string(body)),
                ]))
            );
            write_http(stream, "200 OK", "application/json", &body)
        }
        Ok((body, content_type)) => write_http(stream, "200 OK", content_type, &body),
        Err(error)
            if format == OutputFormat::Json
                && matches!(
                    path,
                    "/inspect"
                        | "/diff"
                        | "/discover"
                        | "/resolve"
                        | "/recover-types"
                        | "/reconstruct-source"
                        | "/lift"
                        | "/decompile-native"
                        | "/batch"
                ) =>
        {
            let body = format!(
                "{}\n",
                stringify(&object([
                    ("ok".into(), Value::Bool(false)),
                    ("endpoint".into(), Value::string(path)),
                    ("error".into(), Value::string(error)),
                ]))
            );
            write_http(stream, "400 Bad Request", "application/json", &body)
        }
        Err(error) if path == "/health" => write_http(
            stream,
            "500 Internal Server Error",
            "text/plain; charset=utf-8",
            &format!("{error}\n"),
        ),
        Err(error)
            if matches!(
                path,
                "/inspect"
                    | "/diff"
                    | "/discover"
                    | "/resolve"
                    | "/recover-types"
                    | "/lift"
                    | "/decompile-native"
                    | "/batch"
            ) =>
        {
            write_http(
                stream,
                "400 Bad Request",
                "text/plain; charset=utf-8",
                &format!("{error}\n"),
            )
        }
        Err(error) => write_http(
            stream,
            "404 Not Found",
            "text/plain; charset=utf-8",
            &format!("{error}\n"),
        ),
    }
}

fn read_http_request(stream: &mut TcpStream) -> Result<(String, String, String), String> {
    const MAX_HEADER: usize = 16 * 1024;
    const MAX_BODY: usize = 4 * 1024 * 1024;
    let mut bytes = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index;
        }
        if bytes.len() >= MAX_HEADER {
            return Err("HTTP headers are too large".into());
        }
        let mut chunk = [0u8; 4096];
        let count = stream
            .read(&mut chunk)
            .map_err(|error| format!("read request: {error}"))?;
        if count == 0 {
            return Err("incomplete HTTP headers".into());
        }
        bytes.extend_from_slice(&chunk[..count]);
    };
    let header_text = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "HTTP headers are not UTF-8".to_string())?;
    let line = header_text
        .lines()
        .next()
        .ok_or_else(|| "empty HTTP request".to_string())?;
    let mut fields = line.split_whitespace();
    let method = fields.next().unwrap_or_default().to_string();
    let target = fields.next().unwrap_or_default().to_string();
    if method.is_empty() || target.is_empty() {
        return Err("malformed HTTP request line".into());
    }
    let content_length = header_text
        .lines()
        .skip(1)
        .find_map(|header| {
            let (name, value) = header.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim())
        })
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| "invalid Content-Length".to_string())
        })
        .transpose()?
        .unwrap_or(0);
    if content_length > MAX_BODY {
        return Err("HTTP request body is too large".into());
    }
    let body_start = header_end + 4;
    let body_end = body_start
        .checked_add(content_length)
        .ok_or_else(|| "HTTP request body length overflow".to_string())?;
    while bytes.len() < body_end {
        let mut chunk = [0u8; 4096];
        let count = stream
            .read(&mut chunk)
            .map_err(|error| format!("read request body: {error}"))?;
        if count == 0 {
            return Err("incomplete HTTP request body".into());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    let body = std::str::from_utf8(&bytes[body_start..body_end])
        .map_err(|_| "HTTP request body is not UTF-8".to_string())?
        .to_string();
    Ok((method, target, body))
}

fn endpoint_inspect(query: &str) -> Result<(String, &'static str), String> {
    let file =
        query_value(query, "file").ok_or_else(|| "query parameter file is required".to_string())?;
    let options = query_image_options(query)?;
    inspect(Path::new(&file), options).map(|body| (body, "text/plain; charset=utf-8"))
}

fn endpoint_diff(query: &str) -> Result<(String, &'static str), String> {
    let before = query_value(query, "before")
        .ok_or_else(|| "query parameter before is required".to_string())?;
    let after = query_value(query, "after")
        .ok_or_else(|| "query parameter after is required".to_string())?;
    let options = DiffOptions {
        before: PathBuf::from(before),
        after: PathBuf::from(after),
        options: query_image_options(query)?,
        region: query_value(query, "region"),
        format: OutputFormat::Text,
    };
    diff_command(options).map(|body| (body, "text/plain; charset=utf-8"))
}

fn endpoint_discover(query: &str) -> Result<(String, &'static str), String> {
    let file =
        query_value(query, "file").ok_or_else(|| "query parameter file is required".to_string())?;
    let image_options = query_image_options(query)?;
    let architecture = match query_value(query, "arch") {
        Some(value) => parse_architecture(&value)?,
        None => image_options
            .target
            .map(|target| target.spec().architecture)
            .ok_or_else(|| "query parameter arch or target is required".to_string())?,
    };
    let limit = query_value(query, "limit")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| format!("invalid limit {value:?}"))
        })
        .transpose()?
        .unwrap_or(4096);
    if limit == 0 {
        return Err("limit must be greater than zero".into());
    }
    discover_command(DiscoverOptions {
        image: PathBuf::from(file),
        architecture,
        target: image_options.target,
        limit,
        loader: image_options.loader,
        base: image_options.base,
        slice: image_options.slice,
        format: OutputFormat::Text,
    })
    .map(|body| (body, "text/plain; charset=utf-8"))
}

fn endpoint_resolve(query: &str) -> Result<(String, &'static str), String> {
    let file =
        query_value(query, "file").ok_or_else(|| "query parameter file is required".to_string())?;
    let address = query_value(query, "address")
        .ok_or_else(|| "query parameter address is required".to_string())?;
    let options = query_image_options(query)?;
    resolve(Path::new(&file), &address, options).map(|body| (body, "text/plain; charset=utf-8"))
}

fn endpoint_recover_types(query: &str) -> Result<(String, &'static str), String> {
    endpoint_game_model(query, false)
}

fn endpoint_reconstruct_source(query: &str) -> Result<(String, &'static str), String> {
    endpoint_game_model(query, true)
}

fn endpoint_game_model(query: &str, reconstruct: bool) -> Result<(String, &'static str), String> {
    let file =
        query_value(query, "file").ok_or_else(|| "query parameter file is required".to_string())?;
    let address = query_value(query, "address")
        .ok_or_else(|| "query parameter address is required".to_string())?;
    let image_options = query_image_options(query)?;
    let target = image_options
        .target
        .ok_or_else(|| "query parameter target is required".to_string())?;
    let limit = query_value(query, "limit")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| format!("invalid limit {value:?}"))
        })
        .transpose()?
        .unwrap_or(4096);
    if limit == 0 {
        return Err("limit must be greater than zero".into());
    }
    let raw = query_value(query, "raw")
        .map(|value| match value.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(format!("invalid raw flag {value:?}; use true or false")),
        })
        .transpose()?
        .unwrap_or(false);
    let options = GameOptions {
        lift: LiftOptions {
            image: PathBuf::from(file),
            address,
            architecture: target.spec().architecture,
            limit,
            cache: query_value(query, "cache").map(PathBuf::from),
            loader: image_options.loader,
            base: image_options.base,
            slice: image_options.slice,
            target: Some(target),
            raw,
            format: OutputFormat::Text,
        },
        metadata: query_value(query, "metadata").map(PathBuf::from),
    };
    let body = if reconstruct {
        reconstruct_source(options)?
    } else {
        recover_types(options)?
    };
    Ok((body, "text/plain; charset=utf-8"))
}

fn endpoint_batch(body: &str) -> Result<(String, &'static str), String> {
    let mut context = BatchContext::new(None);
    let results = batch_lines(body, &mut context);
    context.save()?;
    Ok((results, "application/json"))
}

fn endpoint_lift(query: &str, native: bool) -> Result<(String, &'static str), String> {
    let file =
        query_value(query, "file").ok_or_else(|| "query parameter file is required".to_string())?;
    let address = query_value(query, "address")
        .ok_or_else(|| "query parameter address is required".to_string())?;
    let image_options = query_image_options(query)?;
    let architecture = match query_value(query, "arch") {
        Some(value) => parse_architecture(&value)?,
        None => image_options
            .target
            .map(|target| target.spec().architecture)
            .unwrap_or(Architecture::X86_64),
    };
    let limit = query_value(query, "limit")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| format!("invalid limit {value:?}"))
        })
        .transpose()?
        .unwrap_or(4096);
    if limit == 0 {
        return Err("limit must be greater than zero".into());
    }
    let options = LiftOptions {
        image: PathBuf::from(file),
        address,
        architecture,
        limit,
        cache: None,
        loader: image_options.loader,
        base: image_options.base,
        slice: image_options.slice,
        target: image_options.target,
        raw: false,
        format: OutputFormat::Text,
    };
    let body = if native {
        decompile_native(options)?
    } else {
        lift(options)?
    };
    Ok((body, "text/plain; charset=utf-8"))
}

fn query_value(query: &str, wanted: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|part| part.split_once('='))
        .find_map(|(key, value)| (percent_decode(key) == wanted).then(|| percent_decode(value)))
}

fn query_image_options(query: &str) -> Result<ImageOptions, String> {
    let loader = match query_value(query, "loader") {
        None => Loader::Auto,
        Some(value) => Loader::parse(&value).ok_or_else(|| format!("unknown loader {value:?}"))?,
    };
    let base = query_value(query, "base")
        .map(|value| parse_offset(&value))
        .transpose()?;
    let slice = query_value(query, "slice")
        .map(|value| parse_slice_index(&value))
        .transpose()?;
    let target = query_value(query, "target")
        .map(|value| {
            TargetProfile::parse(&value).ok_or_else(|| format!("unknown target {value:?}"))
        })
        .transpose()?;
    Ok(ImageOptions {
        loader,
        base,
        slice,
        target,
    })
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            decoded.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            let high = (bytes[i + 1] as char).to_digit(16);
            let low = (bytes[i + 2] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                decoded.push((high * 16 + low) as u8);
                i += 3;
            } else {
                decoded.push(bytes[i]);
                i += 1;
            }
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn write_http(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> Result<(), String> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| format!("write response: {error}"))
}

fn inspect(path: &Path, options: ImageOptions) -> Result<String, String> {
    let loaded = read_image(path, options)?;
    let source_hash = Image::content_hash(&loaded.source);
    let image = loaded.image;
    let mut out = String::new();
    writeln!(out, "file: {}", path.display()).unwrap();
    writeln!(out, "length: {}", image.len).unwrap();
    writeln!(out, "content_hash: {source_hash:#018x}").unwrap();
    match image.format {
        Format::Elf(facts) => {
            writeln!(out, "format: ELF{}", facts.class_bits).unwrap();
            writeln!(out, "endian: {}", endian_name(facts.endian)).unwrap();
            writeln!(out, "machine: {:#06x}", facts.machine).unwrap();
            writeln!(out, "type: {:#06x}", facts.obj_type).unwrap();
            writeln!(out, "flags: {:#010x}", facts.flags).unwrap();
            writeln!(
                out,
                "languages: {}",
                facts.consistent_languages().join(", ")
            )
            .unwrap();
        }
        Format::Pe(facts) => {
            writeln!(out, "format: PE{}", if facts.plus { "32+" } else { "32" }).unwrap();
            writeln!(out, "machine: {:#06x}", facts.machine).unwrap();
            writeln!(out, "image_base: {:#x}", facts.image_base).unwrap();
        }
        Format::Mach(facts) => {
            writeln!(out, "format: Mach-O{}", facts.class_bits).unwrap();
            writeln!(out, "endian: {}", endian_name(facts.endian)).unwrap();
            writeln!(out, "cpu_type: {:#010x}", facts.cpu_type).unwrap();
            writeln!(out, "cpu_subtype: {:#010x}", facts.cpu_subtype).unwrap();
            writeln!(out, "type: {:#010x}", facts.file_type).unwrap();
            writeln!(out, "flags: {:#010x}", facts.flags).unwrap();
            writeln!(
                out,
                "languages: {}",
                facts.consistent_languages().join(", ")
            )
            .unwrap();
        }
        Format::Raw(facts) => {
            writeln!(out, "format: raw").unwrap();
            writeln!(out, "base: {:#x}", facts.base).unwrap();
        }
        Format::Coff(facts) => {
            writeln!(out, "format: COFF").unwrap();
            writeln!(out, "machine: {:#06x}", facts.machine).unwrap();
            writeln!(out, "sections: {}", facts.section_count).unwrap();
            writeln!(out, "characteristics: {:#06x}", facts.characteristics).unwrap();
        }
        Format::IntelHex(facts) => {
            writeln!(out, "format: Intel HEX").unwrap();
            writeln!(out, "address_bits: {}", facts.address_bits).unwrap();
            writeln!(out, "data_records: {}", facts.data_records).unwrap();
            writeln!(out, "start: {}", format_option_u64(facts.start)).unwrap();
        }
        Format::MotorolaSrec(facts) => {
            writeln!(out, "format: Motorola S-record").unwrap();
            writeln!(out, "address_bits: {}", facts.address_bits).unwrap();
            writeln!(out, "data_records: {}", facts.data_records).unwrap();
            writeln!(out, "start: {}", format_option_u64(facts.start)).unwrap();
        }
        Format::N64Rom(facts) => {
            writeln!(out, "format: Nintendo 64 ROM").unwrap();
            writeln!(out, "code_offset: {:#x}", facts.code_offset).unwrap();
            writeln!(out, "entry: {:#x}", facts.entry).unwrap();
        }
        Format::Dol(facts) => {
            writeln!(out, "format: GameCube/Wii DOL").unwrap();
            writeln!(
                out,
                "text_sections: {}",
                facts
                    .text
                    .iter()
                    .filter(|section| section.size != 0)
                    .count()
            )
            .unwrap();
            writeln!(
                out,
                "data_sections: {}",
                facts
                    .data
                    .iter()
                    .filter(|section| section.size != 0)
                    .count()
            )
            .unwrap();
            writeln!(
                out,
                "bss: address={:#x} size={:#x}",
                facts.bss_address, facts.bss_size
            )
            .unwrap();
            writeln!(out, "entry: {:#x}", facts.entry).unwrap();
        }
        Format::NintendoDs(facts) => {
            writeln!(out, "format: Nintendo DS").unwrap();
            writeln!(
                out,
                "arm9: entry={:#x} ram={:#x} offset={:#x} size={:#x}",
                facts.arm9_entry, facts.arm9_ram, facts.arm9_offset, facts.arm9_size
            )
            .unwrap();
            writeln!(
                out,
                "arm7: entry={:#x} ram={:#x} offset={:#x} size={:#x}",
                facts.arm7_entry, facts.arm7_ram, facts.arm7_offset, facts.arm7_size
            )
            .unwrap();
        }
        Format::Ncch(facts) => {
            writeln!(out, "format: NCCH/3DS").unwrap();
            writeln!(out, "flags: {:#04x}", facts.flags).unwrap();
            writeln!(
                out,
                "code: address={:#x} size={:#x} file_off={:#x}",
                facts.code_address, facts.code_size, facts.code_file_off
            )
            .unwrap();
        }
        Format::PspPrx(facts) => {
            writeln!(out, "format: PSP PRX").unwrap();
            writeln!(out, "machine: {:#06x}", facts.elf.machine).unwrap();
            writeln!(out, "class: {}", facts.elf.class_bits).unwrap();
            writeln!(out, "endian: {}", endian_name(facts.elf.endian)).unwrap();
        }
        Format::SceSelf(facts) => {
            writeln!(
                out,
                "format: {} SELF",
                match facts.kind {
                    ventris_format::SceSelfKind::Vita => "Vita",
                    ventris_format::SceSelfKind::Ps3 => "PS3",
                }
            )
            .unwrap();
            writeln!(out, "version: {:#x}", facts.version).unwrap();
            writeln!(out, "flags: {:#x}", facts.flags).unwrap();
            writeln!(out, "header_type: {:#x}", facts.header_type).unwrap();
            writeln!(out, "header_size: {:#x}", facts.header_size).unwrap();
            writeln!(out, "extracted_size: {:#x}", facts.extracted_size).unwrap();
            writeln!(out, "info_offset: {:#x}", facts.info_offset).unwrap();
            writeln!(out, "encrypted: {}", facts.encrypted).unwrap();
            writeln!(out, "elf_offset: {:#x}", facts.elf_offset).unwrap();
            writeln!(out, "elf_filesize: {:#x}", facts.elf_filesize).unwrap();
        }
        Format::WiiURpl(facts) => {
            writeln!(out, "format: Wii U RPL").unwrap();
            writeln!(out, "compressed_sections: {}", facts.compressed_sections).unwrap();
            writeln!(out, "machine: {:#06x}", facts.elf.machine).unwrap();
            writeln!(out, "class: {}", facts.elf.class_bits).unwrap();
            writeln!(out, "endian: {}", endian_name(facts.elf.endian)).unwrap();
        }
        Format::Xex(facts) => {
            writeln!(out, "format: Xbox 360 XEX").unwrap();
            writeln!(out, "version: {:#x}", facts.version).unwrap();
            writeln!(out, "module_flags: {:#010x}", facts.module_flags).unwrap();
            writeln!(out, "code_offset: {:#x}", facts.code_offset).unwrap();
            writeln!(out, "certificate_offset: {:#x}", facts.certificate_offset).unwrap();
            writeln!(out, "header_count: {}", facts.header_count).unwrap();
            writeln!(out, "image_base: {}", format_option_u64(facts.image_base)).unwrap();
            writeln!(out, "entry: {}", format_option_u64(facts.entry)).unwrap();
        }
    }
    writeln!(out, "entry: {}", format_option_u64(image.entry)).unwrap();
    writeln!(out, "symbols: {}", image.symbol_count).unwrap();
    writeln!(out, "segments: {}", image.segments.len()).unwrap();
    for (index, segment) in image.segments.iter().enumerate() {
        writeln!(
            out,
            "  segment[{index}]: addr={:#x} size={:#x} file_off={:#x} file_size={:#x} perms={} name={}",
            segment.addr,
            segment.size,
            segment.file_off,
            segment.file_size,
            perms(segment.perms),
            segment.name.as_deref().unwrap_or("-")
        )
        .unwrap();
    }
    writeln!(out, "regions: {}", image.regions.len()).unwrap();
    for region in &image.regions {
        writeln!(
            out,
            "  region: {} addr={:#x} size={:#x} alloc={} placement={}",
            region.name,
            region.addr,
            region.size,
            region.alloc,
            placement(region.placement)
        )
        .unwrap();
    }
    Ok(out)
}

fn resolve(path: &Path, address: &str, options: ImageOptions) -> Result<String, String> {
    let loaded = read_image(path, options)?;
    let image = loaded.image;
    let table = image.space_table();
    let addr = table.resolve(address).map_err(|e| e.to_string())?;
    let space = table
        .get(addr.space)
        .ok_or_else(|| format!("resolved to missing space {}", addr.space.0))?;
    let base = table.to_base(addr).unwrap_or(addr);
    let base_space = table
        .get(base.space)
        .ok_or_else(|| format!("base resolved to missing space {}", base.space.0))?;
    let mut out = String::new();
    writeln!(out, "space: {}", space.name).unwrap();
    writeln!(out, "id: {}", addr.space.0).unwrap();
    writeln!(out, "offset: {:#x}", addr.off).unwrap();
    writeln!(out, "address: {}::{:#x}", space.name, addr.off).unwrap();
    writeln!(out, "base: {}::{:#x}", base_space.name, base.off).unwrap();
    Ok(out)
}

fn lift(options: LiftOptions) -> Result<String, String> {
    let (file, image) = read_lift_image(&options)?;
    let table = image.space_table();
    let resolved = table.resolve(&options.address).map_err(|e| e.to_string())?;
    let base = table.to_base(resolved).unwrap_or(resolved);
    let lifter: Box<dyn Lifter> = match options.architecture {
        Architecture::X86_64 => Box::new(X86_64::new()),
        Architecture::X86_32 => Box::new(X86_32),
        Architecture::AArch64 => Box::new(AArch64),
        Architecture::Arm32 => Box::new(Arm32),
        Architecture::Thumb => Box::new(Thumb),
        Architecture::Mips32 => Box::new(Mips32),
        Architecture::Mips32Be => Box::new(Mips32Be),
        Architecture::Ps1 => Box::new(Ps1),
        Architecture::N64 => Box::new(N64),
        Architecture::Rv64 => Box::new(Rv64),
        Architecture::Rv32 => Box::new(Rv32),
        Architecture::Ppc32 => Box::new(Ppc32),
        Architecture::Ppc64 => Box::new(Ppc64),
        Architecture::GameCube => Box::new(GameCube),
        Architecture::M68k => Box::new(M68k),
        Architecture::Sh2 => Box::new(Sh2),
        Architecture::Sh4 => Box::new(Sh4),
        Architecture::Spu => Box::new(Spu),
        Architecture::M6502 => Box::new(M6502),
        Architecture::Z80 => Box::new(Z80),
    };
    let function = lifter
        .discover(&image, &file, base.off, options.limit)
        .map_err(|e| e.to_string())?;
    let mut out = String::new();
    writeln!(
        out,
        "architecture: {:?}\nentry: {:#x}\ninstructions: {}\nbytes: {}",
        lifter.architecture(),
        function.entry,
        function.instruction_count(),
        function.byte_length()
    )
    .unwrap();
    for instruction in function.instructions.values() {
        let bytes = instruction
            .bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("");
        writeln!(
            out,
            "  {:#x}: {} {} flow={:?}",
            instruction.address, instruction.pcode.len, bytes, instruction.flow
        )
        .unwrap();
        for op in &instruction.pcode.ops {
            writeln!(
                out,
                "    op {} output={:?} inputs={:?}",
                op.opcode, op.output, op.inputs
            )
            .unwrap();
        }
    }
    if !function.calls.is_empty() {
        writeln!(out, "calls: {:?}", function.calls).unwrap();
    }
    if !function.edges.is_empty() {
        writeln!(out, "edges: {:?}", function.edges).unwrap();
    }
    Ok(out)
}

fn recover_types(options: GameOptions) -> Result<String, String> {
    Ok(recover_types_report(&options)?.render_text())
}

fn recover_types_report(options: &GameOptions) -> Result<ventris_game::RecoveredFunction, String> {
    let target = options
        .lift
        .target
        .ok_or_else(|| "recover-types requires --target".to_string())?;
    let source = std::fs::read(&options.lift.image)
        .map_err(|error| format!("{}: {error}", options.lift.image.display()))?;
    let sidecar = game_input::load(options.metadata.as_deref())?;
    let (file, image) = read_lift_image(&options.lift)?;
    let image_metadata: ImageMetadata = image
        .metadata(&source)
        .map_err(|error| format!("{}: {error}", options.lift.image.display()))?;
    let symbols = image_metadata
        .symbols
        .into_iter()
        .map(|symbol| SymbolFact {
            address: symbol.address,
            name: symbol.name,
        })
        .collect::<Vec<_>>();
    let relocations = image_metadata
        .relocations
        .into_iter()
        .filter_map(|relocation| {
            relocation.symbol.map(|symbol| RelocationFact {
                address: relocation.address,
                symbol,
            })
        })
        .collect::<Vec<_>>();
    let table = image.space_table();
    let resolved = table
        .resolve(&options.lift.address)
        .map_err(|e| e.to_string())?;
    let base = table.to_base(resolved).unwrap_or(resolved);
    let lifter: Box<dyn Lifter> = match options.lift.architecture {
        Architecture::X86_64 => Box::new(X86_64::new()),
        Architecture::X86_32 => Box::new(X86_32),
        Architecture::AArch64 => Box::new(AArch64),
        Architecture::Arm32 => Box::new(Arm32),
        Architecture::Thumb => Box::new(Thumb),
        Architecture::Mips32 => Box::new(Mips32),
        Architecture::Mips32Be => Box::new(Mips32Be),
        Architecture::Ps1 => Box::new(Ps1),
        Architecture::N64 => Box::new(N64),
        Architecture::Rv64 => Box::new(Rv64),
        Architecture::Rv32 => Box::new(Rv32),
        Architecture::Ppc32 => Box::new(Ppc32),
        Architecture::Ppc64 => Box::new(Ppc64),
        Architecture::GameCube => Box::new(GameCube),
        Architecture::M68k => Box::new(M68k),
        Architecture::Sh2 => Box::new(Sh2),
        Architecture::Sh4 => Box::new(Sh4),
        Architecture::Spu => Box::new(Spu),
        Architecture::M6502 => Box::new(M6502),
        Architecture::Z80 => Box::new(Z80),
    };
    let function = lifter
        .discover(&image, &file, base.off, options.lift.limit)
        .map_err(|e| e.to_string())?;
    Ok(recover_function(
        target,
        RecoveryInput {
            function: &function,
            nominal_types: &sidecar.nominal_types,
            symbols: &symbols,
            relocations: &relocations,
            annotations: &sidecar.annotations,
            assertions: &sidecar.assertions,
        },
    ))
}

fn reconstruct_source(options: GameOptions) -> Result<String, String> {
    let body = decompile_native(options.lift.clone())?;
    let report = recover_types_report(&options)?;
    SourceReconstruction::from_report(&report, body)
        .map(|source| source.render())
        .map_err(|error| error.to_string())
}

fn decompile_native(options: LiftOptions) -> Result<String, String> {
    let (file, image) = read_lift_image(&options)?;
    let mut cache = NativeCache::load(options.cache.as_deref(), stable64(&file))?;
    let rendered = decompile_native_with_memo(options, &file, &image, &mut cache.memo)?;
    cache.save()?;
    Ok(rendered)
}

fn decompile_native_with_memo(
    options: LiftOptions,
    file: &[u8],
    image: &Image,
    memo: &mut Memo,
) -> Result<String, String> {
    let table = image.space_table();
    let mut symbols = BTreeMap::new();
    if let Ok(metadata) = image.metadata(file) {
        for symbol in metadata.symbols {
            symbols.insert(symbol.address, symbol.name);
        }
        for relocation in metadata.relocations {
            if let Some(name) = relocation.symbol {
                symbols.entry(relocation.address).or_insert(name);
            }
        }
    }
    let resolved = table.resolve(&options.address).map_err(|e| e.to_string())?;
    let base = table.to_base(resolved).unwrap_or(resolved);
    let architecture = options.architecture;
    let config_text = format!(
        "{architecture:?}|target={:?}|loader={:?}|raw_base={:?}|raw={}|space={}|base={}|limit={}",
        options.target,
        options.loader,
        options.base,
        options.raw,
        base.space.0,
        base.off,
        options.limit
    );
    let key = MemoKey {
        image: stable64(file),
        code_version: NATIVE_ANALYZER_CODE_VERSION,
        config: stable64(config_text.as_bytes()),
        human_log: 0,
    };
    let rendered = memo
        .get_or_try_compute(
            key,
            Generation(1),
            QueryId::new("native-c", base.off),
            || {
                let lifter: Box<dyn Lifter> = match architecture {
                    Architecture::X86_64 => Box::new(X86_64::new()),
                    Architecture::X86_32 => Box::new(X86_32),
                    Architecture::AArch64 => Box::new(AArch64),
                    Architecture::Arm32 => Box::new(Arm32),
                    Architecture::Thumb => Box::new(Thumb),
                    Architecture::Mips32 => Box::new(Mips32),
                    Architecture::Mips32Be => Box::new(Mips32Be),
                    Architecture::Ps1 => Box::new(Ps1),
                    Architecture::N64 => Box::new(N64),
                    Architecture::Rv64 => Box::new(Rv64),
                    Architecture::Rv32 => Box::new(Rv32),
                    Architecture::Ppc32 => Box::new(Ppc32),
                    Architecture::Ppc64 => Box::new(Ppc64),
                    Architecture::GameCube => Box::new(GameCube),
                    Architecture::M68k => Box::new(M68k),
                    Architecture::Sh2 => Box::new(Sh2),
                    Architecture::Spu => Box::new(Spu),
                    Architecture::Sh4 => Box::new(Sh4),
                    Architecture::M6502 => Box::new(M6502),
                    Architecture::Z80 => Box::new(Z80),
                };
                let function = lifter
                    .discover(image, file, base.off, options.limit)
                    .map_err(|e| e.to_string())?;
                let mut decompiler = NativeDecompiler;
                let read_memory = |address, width| {
                    target_memory_value(options.target, image, file, address, width)
                };
                let is_volatile =
                    |address, width| target_memory_is_volatile(options.target, address, width);
                let memory = NativeMemory {
                    read: &read_memory,
                    is_volatile: &is_volatile,
                };
                let resolve_symbol = |address| symbols.get(&address).cloned();
                let document = decompiler.decompile_with_memory_and_symbols(
                    lifter.architecture(),
                    &function,
                    Some(&memory),
                    Some(&resolve_symbol),
                );
                for warning in &document.warnings {
                    eprintln!("ventris: native decompiler warning: {warning}");
                }
                Ok::<_, String>(document.render().into_bytes())
            },
        )
        .map_err(|e| e.to_string())?;
    String::from_utf8(rendered)
        .map_err(|_| "native decompiler returned non-UTF-8 output".to_string())
}

fn target_memory_value(
    target: Option<TargetProfile>,
    image: &Image,
    file: &[u8],
    address: u64,
    width: u32,
) -> Option<u64> {
    if target != Some(TargetProfile::Gba) || !matches!(width, 1 | 2 | 4 | 8) {
        return None;
    }
    let width = usize::try_from(width).ok()?;
    let bytes = image.bytes_at(file, address, width)?;
    (bytes.len() == width).then(|| {
        bytes.iter().enumerate().fold(0u64, |value, (index, byte)| {
            value | (u64::from(*byte) << (index * 8))
        })
    })
}

fn target_memory_is_volatile(target: Option<TargetProfile>, address: u64, _width: u32) -> bool {
    target == Some(TargetProfile::Gba) && (0x0400_0000..0x0400_0400).contains(&address)
}

fn parse_offset(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    u64::from_str_radix(
        t,
        if s.trim().starts_with("0x") || s.trim().starts_with("0X") {
            16
        } else {
            10
        },
    )
    .or_else(|_| u64::from_str_radix(t, 16))
    .map_err(|_| format!("cannot parse {s:?} as an address"))
}

fn parse_slice_index(s: &str) -> Result<usize, String> {
    usize::try_from(parse_offset(s)?).map_err(|_| format!("slice index is too large: {s:?}"))
}

fn endian_name(endian: Endian) -> &'static str {
    match endian {
        Endian::Little => "little",
        Endian::Big => "big",
    }
}

fn format_option_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "none".into(), |v| format!("{v:#x}"))
}

fn perms(p: ventris_format::Perms) -> String {
    [p.read, p.write, p.exec]
        .into_iter()
        .map(|v| match v {
            Some(true) => '1',
            Some(false) => '0',
            None => '?',
        })
        .collect()
}

fn placement(value: Placement) -> &'static str {
    match value {
        Placement::Mapped => "mapped",
        Placement::Unaddressed => "unaddressed",
        Placement::Aliases { .. } => "alias",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_help_without_arguments() {
        assert!(matches!(parse_command(&[]).unwrap(), Command::Help));
    }

    #[test]
    fn help_lists_every_top_level_command() {
        let help = match parse_command(&[]).unwrap() {
            Command::Help => run(Command::Help).unwrap(),
            _ => panic!("expected help command"),
        };
        for command in [
            "inspect",
            "project",
            "discover",
            "corpus",
            "resolve",
            "lift",
            "decompile-native",
            "recover-types",
            "batch",
        ] {
            assert!(help.contains(command), "missing {command} in help");
        }
    }

    #[test]
    fn corpus_command_exposes_licensed_and_observed_entries() {
        let command = parse_command(&["corpus".into(), "--json".into()]).unwrap();
        assert!(matches!(command, Command::Corpus(OutputFormat::Json)));
        let output = run(command).unwrap();
        assert!(output.contains("n64-perfect-dark-ntsc-final"));
        assert!(output.contains("gamecube-animal-crossing-gafe01"));
        assert!(output.contains("gba-pokemon-emerald"));
    }

    #[test]
    fn parses_resolve_arguments() {
        let args = vec!["resolve".into(), "a.elf".into(), "ram::0x1000".into()];
        assert!(matches!(
            parse_command(&args).unwrap(),
            Command::Resolve { .. }
        ));
    }

    #[test]
    fn parses_loader_and_base_options() {
        let args = vec![
            "inspect".into(),
            "image.bin".into(),
            "--loader".into(),
            "raw".into(),
            "--base".into(),
            "0x4000".into(),
            "--slice".into(),
            "0x2".into(),
            "--json".into(),
        ];
        let Command::Inspect {
            options, format, ..
        } = parse_command(&args).unwrap()
        else {
            panic!("expected inspect command");
        };
        assert_eq!(options.loader, Loader::Raw);
        assert_eq!(options.base, Some(0x4000));
        assert_eq!(options.slice, Some(2));
        assert_eq!(format, OutputFormat::Json);
    }

    #[test]
    fn project_init_persists_image_facts_and_show_reloads_them() {
        let image =
            std::env::temp_dir().join(format!("ventris-project-image-{}.bin", std::process::id()));
        let project = std::env::temp_dir().join(format!(
            "ventris-project-model-{}.vproj",
            std::process::id()
        ));
        std::fs::write(&image, [1_u8, 2, 3, 4]).unwrap();
        let command = Command::Project(ProjectOptions {
            action: ProjectAction::Init {
                image: image.clone(),
                project: project.clone(),
                options: ImageOptions {
                    loader: Loader::Raw,
                    base: Some(0x4000),
                    slice: None,
                    target: None,
                },
            },
            format: OutputFormat::Text,
        });
        let created = run(command).unwrap();
        let restored = Project::load_from(&project).unwrap();
        assert_eq!(restored.image.loader, "raw");
        assert_eq!(restored.image.base, Some(0x4000));
        assert_eq!(restored.image.segments.len(), 1);
        assert!(created.contains("functions: 0"));
        let shown = run(Command::Project(ProjectOptions {
            action: ProjectAction::Show {
                project: project.clone(),
            },
            format: OutputFormat::Text,
        }))
        .unwrap();
        assert!(shown.contains("loader: raw"));
        assert!(shown.contains("spaces: 1"));
        let _ = std::fs::remove_file(image);
        let _ = std::fs::remove_file(project);
    }
    #[test]
    fn parses_discover_architecture_and_bounds() {
        let args = vec![
            "discover".into(),
            "image.bin".into(),
            "--arch".into(),
            "x86_64".into(),
            "--loader".into(),
            "raw".into(),
            "--base".into(),
            "0x4000".into(),
            "--limit".into(),
            "64".into(),
            "--json".into(),
        ];
        let Command::Discover(options) = parse_command(&args).unwrap() else {
            panic!("expected discover command");
        };
        assert_eq!(options.architecture, Architecture::X86_64);
        assert_eq!(options.loader, Loader::Raw);
        assert_eq!(options.base, Some(0x4000));
        assert_eq!(options.limit, 64);
        assert_eq!(options.format, OutputFormat::Json);
    }

    #[test]
    fn project_runtime_ingest_persists_emulator_evidence() {
        let image =
            std::env::temp_dir().join(format!("ventris-runtime-image-{}.bin", std::process::id()));
        let project = std::env::temp_dir().join(format!(
            "ventris-runtime-project-{}.vproj",
            std::process::id()
        ));
        let trace = std::env::temp_dir().join(format!(
            "ventris-runtime-trace-{}.jsonl",
            std::process::id()
        ));
        std::fs::write(&image, [0xc3_u8, 0x90, 0x90]).unwrap();
        std::fs::write(
            &trace,
            concat!(
                "{\"sequence\":2,\"instruction\":\"0x4004\",\"kind\":\"call\",\"target\":\"0x5000\"}\n",
                "{\"sequence\":1,\"instruction\":\"0x4000\",\"kind\":\"memory\",\"access\":\"read\",\"address\":\"0x6000\",\"width\":4,\"value\":\"0xbeef\"}\n",
                "{\"sequence\":3,\"instruction\":\"0x4008\",\"kind\":\"register\",\"register\":\"$v0\",\"value\":7}\n",
                "{\"sequence\":4,\"instruction\":\"0x400c\",\"kind\":\"marker\",\"text\":\"damage-applied\"}\n",
            ),
        )
        .unwrap();

        run(Command::Project(ProjectOptions {
            action: ProjectAction::Init {
                image: image.clone(),
                project: project.clone(),
                options: ImageOptions {
                    loader: Loader::Raw,
                    base: Some(0x4000),
                    slice: None,
                    target: None,
                },
            },
            format: OutputFormat::Text,
        }))
        .unwrap();
        let output = run(Command::Project(ProjectOptions {
            action: ProjectAction::Runtime {
                project: project.clone(),
                trace: trace.clone(),
            },
            format: OutputFormat::Text,
        }))
        .unwrap();
        assert!(output.contains("events: 4"), "{output}");
        assert!(output.contains("references_added: 2"), "{output}");
        assert!(output.contains("assertions_added: 3"), "{output}");

        let restored = Project::load_from(&project).unwrap();
        assert!(restored
            .references
            .iter()
            .any(|reference| reference.from == 0x4000 && reference.to == 0x6000));
        assert!(restored
            .references
            .iter()
            .any(|reference| reference.from == 0x4004 && reference.to == 0x5000));
        assert!(restored
            .assertions
            .iter()
            .any(|assertion| assertion.kind == "runtime-marker"));

        let args = vec![
            "project".into(),
            "runtime".into(),
            "project.vproj".into(),
            "trace.jsonl".into(),
            "--json".into(),
        ];
        let Command::Project(options) = parse_command(&args).unwrap() else {
            panic!("expected project command");
        };
        assert!(matches!(options.action, ProjectAction::Runtime { .. }));
        assert_eq!(options.format, OutputFormat::Json);

        let _ = std::fs::remove_file(image);
        let _ = std::fs::remove_file(project);
        let _ = std::fs::remove_file(trace);
    }

    #[test]
    fn project_assets_link_references_to_manifest_targets() {
        let project = std::env::temp_dir().join(format!(
            "ventris-assets-project-{}.vproj",
            std::process::id()
        ));
        let manifest = std::env::temp_dir().join(format!(
            "ventris-assets-manifest-{}.json",
            std::process::id()
        ));
        let mut model = Project::default();
        model.add_reference(ProjectReference {
            from: 0x1000,
            to: 0x5004,
            kind: ProjectReferenceKind::Read,
            offset: None,
            confidence: 90,
            generation: 0,
        });
        model.add_reference(ProjectReference {
            from: 0x1010,
            to: 0x7000,
            kind: ProjectReferenceKind::Call,
            offset: None,
            confidence: 88,
            generation: 0,
        });
        model.save_to(&project).unwrap();
        std::fs::write(
            &manifest,
            r#"{
                "assets": [
                    {"id":"hero","name":"Hero model","kind":"model","source":"assets.tbl","address":"0x5000","size":"0x20"}
                ],
                "scripts": [
                    {"id":"battle-start","name":"Battle start","source":"scripts/battle.lua","entry":"0x7000","language":"lua"}
                ]
            }"#,
        )
        .unwrap();

        let output = run(Command::Project(ProjectOptions {
            action: ProjectAction::Assets {
                project: project.clone(),
                manifest: manifest.clone(),
            },
            format: OutputFormat::Text,
        }))
        .unwrap();
        assert!(output.contains("asset_links: 1"), "{output}");
        assert!(output.contains("script_links: 1"), "{output}");
        assert!(output.contains("asset:hero"), "{output}");
        assert!(output.contains("script:battle-start"), "{output}");

        let restored = Project::load_from(&project).unwrap();
        assert_eq!(
            restored
                .assertions
                .iter()
                .filter(|assertion| assertion.kind.ends_with("-link"))
                .count(),
            2
        );
        let _ = std::fs::remove_file(project);
        let _ = std::fs::remove_file(manifest);
    }

    #[test]
    fn parses_binary_diff_options() {
        let args = vec![
            "diff".into(),
            "old.bin".into(),
            "new.bin".into(),
            "--loader".into(),
            "raw".into(),
            "--base".into(),
            "0x4000".into(),
            "--region".into(),
            "segment-0".into(),
            "--json".into(),
        ];
        let Command::Diff(options) = parse_command(&args).unwrap() else {
            panic!("expected diff command");
        };
        assert_eq!(options.options.loader, Loader::Raw);
        assert_eq!(options.options.base, Some(0x4000));
        assert_eq!(options.region.as_deref(), Some("segment-0"));
        assert_eq!(options.format, OutputFormat::Json);
    }

    #[test]
    fn binary_diff_reports_changed_region_bytes() {
        let before =
            std::env::temp_dir().join(format!("ventris-diff-before-{}.bin", std::process::id()));
        let after =
            std::env::temp_dir().join(format!("ventris-diff-after-{}.bin", std::process::id()));
        std::fs::write(&before, [0xc3_u8, 0x90, 0x90]).unwrap();
        std::fs::write(&after, [0xc3_u8, 0xcc, 0x90]).unwrap();
        let output = run(Command::Diff(DiffOptions {
            before: before.clone(),
            after: after.clone(),
            options: ImageOptions {
                loader: Loader::Raw,
                base: Some(0x4000),
                slice: None,
                target: None,
            },
            region: None,
            format: OutputFormat::Text,
        }))
        .unwrap();
        let _ = std::fs::remove_file(before);
        let _ = std::fs::remove_file(after);
        assert!(output.contains("changed=1"), "{output}");
        assert!(output.contains("kind=modified"), "{output}");
        assert!(output.contains("before=[90] after=[cc]"), "{output}");
    }

    #[test]
    fn project_analyze_persists_recursive_function_and_call_inventory() {
        let image = std::env::temp_dir().join(format!(
            "ventris-discovery-image-{}.bin",
            std::process::id()
        ));
        let project = std::env::temp_dir().join(format!(
            "ventris-discovery-project-{}.vproj",
            std::process::id()
        ));
        std::fs::write(&image, [0xe8_u8, 0x01, 0, 0, 0, 0xc3, 0xc3]).unwrap();
        run(Command::Project(ProjectOptions {
            action: ProjectAction::Init {
                image: image.clone(),
                project: project.clone(),
                options: ImageOptions {
                    loader: Loader::Raw,
                    base: Some(0x1000),
                    slice: None,
                    target: None,
                },
            },
            format: OutputFormat::Text,
        }))
        .unwrap();
        let analyzed = run(Command::Project(ProjectOptions {
            action: ProjectAction::Analyze {
                project: project.clone(),
                architecture: Architecture::X86_64,
                target: None,
                limit: 32,
            },
            format: OutputFormat::Text,
        }))
        .unwrap();
        let restored = Project::load_from(&project).unwrap();
        assert!(analyzed.contains("functions: 2"));
        assert!(analyzed.contains("references: 1"));
        assert_eq!(restored.functions.len(), 2);
        assert_eq!(restored.references.len(), 1);
        assert_eq!(restored.generations.len(), 2);
        let decompiled = run(Command::DecompileNativeProject(ProjectDecompileOptions {
            project: project.clone(),
            function: "0x1000".into(),
            architecture: Architecture::X86_64,
            target: None,
            limit: 32,
            cache: None,
            format: OutputFormat::Text,
        }))
        .unwrap();
        assert!(decompiled.contains("void sub_1000"));
        let navigation = run(Command::Project(ProjectOptions {
            action: ProjectAction::References {
                project: project.clone(),
                address: 0x1006,
                incoming: true,
                outgoing: false,
            },
            format: OutputFormat::Text,
        }))
        .unwrap();
        assert!(navigation.contains("incoming: 1"), "{navigation}");
        assert!(navigation.contains("from=0x1000"), "{navigation}");
        let _ = std::fs::remove_file(image);
        let _ = std::fs::remove_file(project);
    }

    #[test]
    fn project_analyze_seeds_code_pointers_from_raw_data() {
        let image =
            std::env::temp_dir().join(format!("ventris-pointer-image-{}.bin", std::process::id()));
        let project = std::env::temp_dir().join(format!(
            "ventris-pointer-project-{}.vproj",
            std::process::id()
        ));
        std::fs::write(&image, [0xc3_u8, 0, 0, 0, 0x08, 0x10, 0, 0, 0xc3]).unwrap();
        run(Command::Project(ProjectOptions {
            action: ProjectAction::Init {
                image: image.clone(),
                project: project.clone(),
                options: ImageOptions {
                    loader: Loader::Raw,
                    base: Some(0x1000),
                    slice: None,
                    target: None,
                },
            },
            format: OutputFormat::Text,
        }))
        .unwrap();
        let analyzed = run(Command::Project(ProjectOptions {
            action: ProjectAction::Analyze {
                project: project.clone(),
                architecture: Architecture::X86_32,
                target: None,
                limit: 32,
            },
            format: OutputFormat::Text,
        }))
        .unwrap();
        assert!(analyzed.contains("functions: 2"), "{analyzed}");
        let _ = std::fs::remove_file(image);
        let _ = std::fs::remove_file(project);
    }

    #[test]
    fn project_analyze_records_embedded_strings_as_data() {
        let image =
            std::env::temp_dir().join(format!("ventris-data-image-{}.bin", std::process::id()));
        let project =
            std::env::temp_dir().join(format!("ventris-data-project-{}.vproj", std::process::id()));
        std::fs::write(&image, [0xc3_u8, 0, b'H', b'e', b'l', b'l', b'o', 0]).unwrap();
        run(Command::Project(ProjectOptions {
            action: ProjectAction::Init {
                image: image.clone(),
                project: project.clone(),
                options: ImageOptions {
                    loader: Loader::Raw,
                    base: Some(0x1000),
                    slice: None,
                    target: None,
                },
            },
            format: OutputFormat::Text,
        }))
        .unwrap();
        run(Command::Project(ProjectOptions {
            action: ProjectAction::Analyze {
                project: project.clone(),
                architecture: Architecture::X86_64,
                target: None,
                limit: 32,
            },
            format: OutputFormat::Text,
        }))
        .unwrap();
        let restored = Project::load_from(&project).unwrap();
        assert!(restored
            .data
            .iter()
            .any(|item| item.type_name.as_deref() == Some("string")));
        let _ = std::fs::remove_file(image);
        let _ = std::fs::remove_file(project);
    }

    #[test]
    fn discover_reports_function_and_data_inventory() {
        let image =
            std::env::temp_dir().join(format!("ventris-discover-image-{}.bin", std::process::id()));
        std::fs::write(&image, [0xc3_u8, 0, b'H', b'e', b'l', b'l', b'o', 0]).unwrap();
        let output = run(Command::Discover(DiscoverOptions {
            image: image.clone(),
            architecture: Architecture::X86_64,
            target: None,
            limit: 32,
            loader: Loader::Raw,
            base: Some(0x1000),
            slice: None,
            format: OutputFormat::Text,
        }))
        .unwrap();
        let _ = std::fs::remove_file(image);
        assert!(output.contains("functions: 1"), "{output}");
        assert!(output.contains("data: 1"), "{output}");
        assert!(output.contains("type=string"), "{output}");
    }

    #[test]
    fn target_selects_architecture_and_loader_defaults() {
        let args = vec![
            "lift".into(),
            "image.bin".into(),
            "0x1000".into(),
            "--target".into(),
            "ps3-ppu".into(),
        ];
        let Command::Lift(options) = parse_command(&args).unwrap() else {
            panic!("expected lift command");
        };
        assert_eq!(options.architecture, Architecture::Ppc64);
        assert_eq!(options.target, Some(TargetProfile::Ps3Ppu));
        assert_eq!(options.loader, Loader::Auto);

        let effective = effective_image_options(ImageOptions {
            loader: options.loader,
            base: options.base,
            slice: options.slice,
            target: options.target,
        });
        assert_eq!(effective.loader, Loader::Ps3Self);
    }

    #[test]
    fn recover_types_requires_console_target_and_accepts_alias() {
        let args = vec![
            "game-model".into(),
            "image.bin".into(),
            "0x1000".into(),
            "--target".into(),
            "gamecube".into(),
        ];
        let Command::RecoverTypes(options) = parse_command(&args).unwrap() else {
            panic!("expected recover-types command");
        };
        assert_eq!(options.lift.target, Some(TargetProfile::GameCube));
        assert_eq!(options.lift.architecture, Architecture::GameCube);
        assert!(parse_command(&[
            "recover-types".into(),
            "image.bin".into(),
            "0x1000".into(),
            "--arch".into(),
            "mips32".into(),
        ])
        .is_err());
    }

    #[test]
    fn reconstruct_source_requires_console_target_and_preserves_options() {
        let args = vec![
            "reconstruct-source".into(),
            "image.bin".into(),
            "0x1000".into(),
            "--target".into(),
            "ps2".into(),
            "--metadata".into(),
            "facts.json".into(),
            "--cache".into(),
            "cache".into(),
            "--json".into(),
        ];
        let Command::ReconstructSource(options) = parse_command(&args).unwrap() else {
            panic!("expected reconstruct-source command");
        };
        assert_eq!(options.lift.target, Some(TargetProfile::Ps2));
        assert_eq!(options.metadata, Some(PathBuf::from("facts.json")));
        assert_eq!(options.lift.cache, Some(PathBuf::from("cache")));
        assert_eq!(options.lift.format, OutputFormat::Json);
    }

    #[test]
    fn inspect_supports_explicit_raw_loader() {
        let path =
            std::env::temp_dir().join(format!("ventris-cli-loader-{}.bin", std::process::id()));
        std::fs::write(&path, [1_u8, 2, 3, 4]).unwrap();
        let output = run(Command::Inspect {
            image: path.clone(),
            options: ImageOptions {
                loader: Loader::Raw,
                base: Some(0x4000),
                slice: None,
                target: None,
            },
            format: OutputFormat::Text,
        })
        .unwrap();
        let _ = std::fs::remove_file(path);
        assert!(output.contains("format: raw"));
        assert!(output.contains("base: 0x4000"));
    }

    #[test]
    fn inspect_auto_detects_intel_hex_fixture() {
        let path =
            std::env::temp_dir().join(format!("ventris-cli-loader-{}.hex", std::process::id()));
        std::fs::write(&path, b":0400000001020304F2\n:00000001FF\n").unwrap();
        let output = run(Command::Inspect {
            image: path.clone(),
            options: ImageOptions::default(),
            format: OutputFormat::Text,
        })
        .unwrap();
        let _ = std::fs::remove_file(path);
        assert!(output.contains("format: Intel HEX"));
        assert!(output.contains("data_records: 1"));
    }

    #[test]
    fn parses_http_loader_options() {
        let options = query_image_options("file=image.bin&loader=raw&base=0x4000").unwrap();
        assert_eq!(options.loader, Loader::Raw);
        assert_eq!(options.base, Some(0x4000));
    }

    #[test]
    fn compares_binary_revisions_through_http_and_batch_endpoints() {
        let before = std::env::temp_dir().join(format!(
            "ventris-http-diff-before-{}.bin",
            std::process::id()
        ));
        let after = std::env::temp_dir().join(format!(
            "ventris-http-diff-after-{}.bin",
            std::process::id()
        ));
        std::fs::write(&before, [0xc3_u8, 0x90, 0x90]).unwrap();
        std::fs::write(&after, [0xc3_u8, 0xcc, 0x90]).unwrap();

        let query = format!(
            "before={}&after={}&loader=raw&base=0x4000",
            before.display(),
            after.display()
        );
        let (body, content_type) = endpoint_diff(&query).unwrap();
        assert_eq!(content_type, "text/plain; charset=utf-8");
        assert!(body.contains("changed=1"), "{body}");

        let request = object([
            ("command".into(), Value::string("diff")),
            ("before".into(), Value::string(before.display().to_string())),
            ("after".into(), Value::string(after.display().to_string())),
            ("loader".into(), Value::string("raw")),
            ("base".into(), Value::string("0x4000")),
        ]);
        let mut context = BatchContext::new(None);
        let (command, batch_body) = batch_request(&request, &mut context).unwrap();
        assert_eq!(command, "diff");
        assert!(batch_body.contains("changed=1"), "{batch_body}");

        let _ = std::fs::remove_file(before);
        let _ = std::fs::remove_file(after);
    }

    #[test]
    fn recovers_types_through_http_endpoint_contract() {
        let path =
            std::env::temp_dir().join(format!("ventris-cli-recover-{}.bin", std::process::id()));
        std::fs::write(
            &path,
            [
                0x10, 0x00, 0x82, 0x8c, 0x14, 0x00, 0x83, 0x8c, 0x08, 0x00, 0xe0, 0x03, 0, 0, 0, 0,
            ],
        )
        .unwrap();
        let query = format!(
            "file={}&address=0x1000&target=ps2&loader=raw&base=0x1000&raw=true",
            path.display()
        );
        let (body, content_type) = endpoint_recover_types(&query).unwrap();
        let _ = std::fs::remove_file(path);

        assert_eq!(content_type, "text/plain; charset=utf-8");
        assert!(body.contains("target: ps2-r5900-o32"));
        assert!(body.contains("memory_accesses: 2"));
        assert!(body.contains("field offset=+0x14"));
    }

    #[test]
    fn reconstructs_source_through_http_and_batch_contracts() {
        let path =
            std::env::temp_dir().join(format!("ventris-cli-source-{}.bin", std::process::id()));
        std::fs::write(
            &path,
            [
                0x10, 0x00, 0x82, 0x8c, 0x14, 0x00, 0x83, 0x8c, 0x08, 0x00, 0xe0, 0x03, 0, 0, 0, 0,
            ],
        )
        .unwrap();
        let query = format!(
            "file={}&address=0x1000&target=ps2&loader=raw&base=0x1000&raw=true",
            path.display()
        );
        let (body, content_type) = endpoint_reconstruct_source(&query).unwrap();
        assert_eq!(content_type, "text/plain; charset=utf-8");
        assert!(body.contains("#include <stdint.h>"), "{body}");
        assert!(body.contains("sub_1000"), "{body}");

        let request = object([
            ("command".into(), Value::string("reconstruct-source")),
            ("image".into(), Value::string(path.display().to_string())),
            ("address".into(), Value::string("0x1000")),
            ("target".into(), Value::string("ps2")),
            ("loader".into(), Value::string("raw")),
            ("base".into(), Value::string("0x1000")),
            ("raw".into(), Value::Bool(true)),
        ]);
        let mut context = BatchContext::new(None);
        let (command, batch_body) = batch_request(&request, &mut context).unwrap();
        let _ = std::fs::remove_file(path);

        assert_eq!(command, "reconstruct-source");
        assert!(batch_body.contains("#include <stdint.h>"), "{batch_body}");
        assert!(batch_body.contains("sub_1000"), "{batch_body}");
    }

    #[test]
    fn parses_decimal_and_hex_offsets() {
        assert_eq!(parse_offset("16").unwrap(), 16);
        assert_eq!(parse_offset("0x10").unwrap(), 16);
        assert_eq!(parse_offset("ff").unwrap(), 255);
    }
    #[test]
    fn parses_native_cache_directory() {
        let args = vec![
            "decompile-native".into(),
            "a.elf".into(),
            "0x1000".into(),
            "--arch".into(),
            "x86_64".into(),
            "--cache".into(),
            "cache".into(),
        ];
        let Command::DecompileNative(options) = parse_command(&args).unwrap() else {
            panic!("expected native decompile command");
        };
        assert_eq!(options.cache, Some(PathBuf::from("cache")));
    }
    #[test]
    fn decompile_native_supports_common_processor_raw_images() {
        let cases: [(&str, Architecture, &[u8], &str); 13] = [
            (
                "ps1",
                Architecture::Ps1,
                &[0x2a, 0x00, 0x02, 0x24, 0x08, 0x00, 0xe0, 0x03, 0, 0, 0, 0],
                "uint32_t sub_1000",
            ),
            (
                "n64",
                Architecture::N64,
                &[0x64, 0x02, 0x00, 0x2a, 0x03, 0xe0, 0x00, 0x08, 0, 0, 0, 0],
                "uint64_t sub_1000",
            ),
            (
                "gamecube",
                Architecture::GameCube,
                &[0x38, 0x60, 0x00, 0x2a, 0x4e, 0x80, 0x00, 0x20],
                "uint32_t sub_1000",
            ),
            (
                "ppc64",
                Architecture::Ppc64,
                &[0x38, 0x60, 0x00, 0x2a, 0x4e, 0x80, 0x00, 0x20],
                "uint64_t sub_1000",
            ),
            (
                "x86_32",
                Architecture::X86_32,
                &[0xb8, 0x2a, 0, 0, 0, 0xc3],
                "uint32_t sub_1000",
            ),
            (
                "thumb",
                Architecture::Thumb,
                &[0x2a, 0x20, 0x70, 0x47],
                "uint32_t sub_1000",
            ),
            (
                "mips32be",
                Architecture::Mips32Be,
                &[0x24, 0x02, 0x00, 0x2a, 0x03, 0xe0, 0x00, 0x08, 0, 0, 0, 0],
                "uint32_t sub_1000",
            ),
            (
                "rv32",
                Architecture::Rv32,
                &[0x13, 0x05, 0xa0, 0x02, 0x67, 0x80, 0, 0, 0x13, 0, 0, 0],
                "uint32_t sub_1000",
            ),
            (
                "m68k",
                Architecture::M68k,
                &[0x70, 0x2a, 0x4e, 0x75],
                "uint32_t sub_1000",
            ),
            (
                "sh2",
                Architecture::Sh2,
                &[0xe0, 0x2a, 0x00, 0x0b, 0x00, 0x09],
                "uint32_t sub_1000",
            ),
            (
                "sh4",
                Architecture::Sh4,
                &[0x2a, 0xe0, 0x0b, 0x00, 0x09, 0x00],
                "uint32_t sub_1000",
            ),
            (
                "m6502",
                Architecture::M6502,
                &[0xa9, 0x2a, 0x60],
                "uint8_t sub_1000",
            ),
            (
                "z80",
                Architecture::Z80,
                &[0x3e, 0x2a, 0xc9],
                "uint8_t sub_1000",
            ),
        ];
        for (name, architecture, bytes, signature) in cases {
            let path = std::env::temp_dir().join(format!(
                "ventris-processor-{name}-{}-{}.bin",
                std::process::id(),
                bytes.len()
            ));
            std::fs::write(&path, bytes).unwrap();
            let output = run(Command::DecompileNative(LiftOptions {
                image: path.clone(),
                address: "0x1000".into(),
                architecture,
                limit: 32,
                cache: None,
                loader: Loader::Auto,
                base: None,
                target: None,
                slice: None,
                raw: true,
                format: OutputFormat::Text,
            }))
            .unwrap();
            let _ = std::fs::remove_file(path);
            assert!(output.contains(signature), "{name}: {output}");
            assert!(output.contains("return 0x2a;"), "{name}: {output}");
        }
    }
}
