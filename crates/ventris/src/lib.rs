//! Ventris's canonical native-function pipeline.
//!
//! Every front end supplies bytes, target facts, and optional hints to this
//! immutable sequence: load, lift, analyze, then render. Project files, HTTP,
//! Python, and editor integrations are adapters; none owns analysis behavior.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use ventris_addr::Addr;
use ventris_decompiler::native::{
    NativeCallPrototype, NativeDecompiler, NativeDocument, NativeMemory,
};
use ventris_format::{Image, ImageMetadata, LoadedImage, Loader};
use ventris_game::reconstruction::{SourceParameter, SourceReconstruction, SourceSignature};
use ventris_game::{
    AnnotationFact, Evidence, NominalType, RecoveredFunction, RecoveryInput, RelocationFact,
    SymbolFact, TypeAssertion, recover_function,
};
use ventris_gen::inventory::{
    self, Inventory, RelocationFact as InventoryRelocation, SymbolFact as InventorySymbol,
};
use ventris_lifter::{Architecture, LiftError, NativeFunction, lifter_for};
use ventris_target::{DecompilationSupport, TargetProfile};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct LoadOptions {
    pub architecture: Option<Architecture>,
    pub target: Option<TargetProfile>,
    pub loader: Loader,
    pub base: Option<u64>,
    pub slice: Option<usize>,
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self {
            architecture: None,
            target: None,
            loader: Loader::Auto,
            base: None,
            slice: None,
        }
    }
}

impl LoadOptions {
    pub fn for_target(target: TargetProfile) -> Self {
        Self {
            target: Some(target),
            ..Self::default()
        }
    }

    fn resolve(self) -> Result<ResolvedOptions, PipelineError> {
        let target_spec = self.target.map(TargetProfile::spec);
        if let (Some(architecture), Some(spec)) = (self.architecture, target_spec) {
            if architecture != spec.architecture {
                return Err(PipelineError::TargetArchitectureMismatch {
                    target: spec.profile,
                    expected: spec.architecture,
                    supplied: architecture,
                });
            }
        }
        let architecture = self
            .architecture
            .or_else(|| target_spec.map(|spec| spec.architecture));
        Ok(ResolvedOptions {
            architecture,
            target: self.target,
            loader: if self.loader == Loader::Auto {
                target_spec.map_or(Loader::Auto, |spec| spec.loader)
            } else {
                self.loader
            },
            base: self
                .base
                .or_else(|| target_spec.and_then(|spec| spec.default_base)),
            slice: self.slice,
        })
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct ResolvedOptions {
    architecture: Option<Architecture>,
    target: Option<TargetProfile>,
    loader: Loader,
    base: Option<u64>,
    slice: Option<usize>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Hints {
    pub nominal_types: Vec<NominalType>,
    pub symbols: Vec<SymbolFact>,
    pub relocations: Vec<RelocationFact>,
    pub annotations: Vec<AnnotationFact>,
    pub provenance: Vec<Evidence>,
    pub assertions: Vec<TypeAssertion>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ResolvedAddress {
    pub requested: Addr,
    pub base: Addr,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AnalysisResult {
    pub function: NativeFunction,
    pub document: NativeDocument,
    pub recovered: Option<RecoveredFunction>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Decompilation {
    pub analysis: AnalysisResult,
    pub source: String,
}

impl Decompilation {
    pub fn warnings(&self) -> &[String] {
        &self.analysis.document.warnings
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PipelineError {
    ArchitectureRequired,
    TargetArchitectureMismatch {
        target: TargetProfile,
        expected: Architecture,
        supplied: Architecture,
    },
    Load(String),
    Address(String),
    Lift(LiftError),
    Metadata(String),
    Reconstruction(String),
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArchitectureRequired => {
                write!(f, "an architecture or target profile is required")
            }
            Self::TargetArchitectureMismatch {
                target,
                expected,
                supplied,
            } => write!(
                f,
                "target {} requires {expected:?}, not {supplied:?}",
                target.name()
            ),
            Self::Load(error) | Self::Metadata(error) | Self::Reconstruction(error) => {
                f.write_str(error)
            }
            Self::Address(error) => write!(f, "address: {error}"),
            Self::Lift(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for PipelineError {}

/// Whether the caller asked for the ported graph pipeline.
///
/// Selected with `VENTRIS_PIPELINE=graph`. An environment switch rather than a
/// flag because the choice is a measurement tool, not part of the interface.
///
/// Still opt-in. Against the Ghidra oracle the graph path now leads on seven of
/// the census families and ties four, but it fails `corpus-smoke`'s semantic
/// comparison on three PS2 entries that the address-ordered path passes, so
/// switching the default would trade a measured gain for a gate regression. The
/// residual is `declaration_order` and `casts`: this path names locals the other
/// inlines, and each name carries a declaration and usually a cast.
/// Which path renders a function.
///
/// The graph path is the default wherever a calling convention is known, which
/// is every `--target`. Its parameters, return storage and globals all come from
/// the convention: `ActionFuncLink`'s trials are the convention's argument
/// locations, `guard_returns` needs its result storage, and a global pointer is
/// a convention register. Given only `--arch` there is no convention to port
/// from - measured, three separate ways: a forwarding function lost its
/// parameter, a function returning a value reported `void`, and a global base
/// went undeclared - so the address-ordered path, which defaults those decisions
/// per architecture, still answers there.
///
/// `VENTRIS_PIPELINE` forces either path, which is how the census and the smoke
/// gate compare them.
fn graph_pipeline_default(abi: Option<&ventris_target::Abi>) -> bool {
    match std::env::var("VENTRIS_PIPELINE") {
        Ok(value) if value.eq_ignore_ascii_case("address") => false,
        Ok(value) if value.eq_ignore_ascii_case("graph") => true,
        _ => abi.is_some(),
    }
}

/// An immutable loaded binary plus its explicit target decision.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pipeline {
    source: Vec<u8>,
    loaded: LoadedImage,
    architecture: Option<Architecture>,
    target: Option<TargetProfile>,
}

/// Rounds of jump-table discovery. Ghidra restarts until nothing new is
/// reached; a table found inside a case body needs a second pass.
const MULTISTAGE_ROUNDS: usize = 3;

impl Pipeline {
    pub fn load(source: impl Into<Vec<u8>>, options: LoadOptions) -> Result<Self, PipelineError> {
        let source = source.into();
        let options = options.resolve()?;
        let loaded = Image::load_with_slice(&source, options.loader, options.base, options.slice)
            .map_err(|error| PipelineError::Load(error.to_string()))?;
        Ok(Self {
            source,
            loaded,
            architecture: options.architecture,
            target: options.target,
        })
    }

    pub fn source(&self) -> &[u8] {
        &self.source
    }

    pub fn bytes(&self) -> &[u8] {
        &self.loaded.bytes
    }

    pub fn image(&self) -> &Image {
        &self.loaded.image
    }

    pub fn loader(&self) -> Loader {
        self.loaded.loader
    }

    pub fn architecture(&self) -> Option<Architecture> {
        self.architecture
    }

    pub fn target(&self) -> Option<TargetProfile> {
        self.target
    }

    pub fn decompilation_support(&self) -> DecompilationSupport {
        self.target
            .map_or(DecompilationSupport::LiftOnly, |target| {
                target.spec().decompilation
            })
    }

    pub fn metadata(&self) -> Result<ImageMetadata, PipelineError> {
        self.loaded
            .image
            .metadata(&self.source)
            .map_err(|error| PipelineError::Metadata(error.to_string()))
    }

    pub fn resolve(&self, address: &str) -> Result<ResolvedAddress, PipelineError> {
        let table = self.loaded.image.space_table();
        let requested = table
            .resolve(address)
            .map_err(|error| PipelineError::Address(error.to_string()))?;
        let base = table.to_base(requested).unwrap_or(requested);
        Ok(ResolvedAddress { requested, base })
    }

    pub fn lift(
        &self,
        address: &str,
        instruction_limit: usize,
    ) -> Result<NativeFunction, PipelineError> {
        let resolved = self.resolve(address)?;
        self.lift_at(resolved.base.off, instruction_limit)
    }

    pub fn lift_at(
        &self,
        address: u64,
        instruction_limit: usize,
    ) -> Result<NativeFunction, PipelineError> {
        let architecture = self
            .architecture
            .ok_or(PipelineError::ArchitectureRequired)?;
        lifter_for(architecture)
            .discover(
                &self.loaded.image,
                &self.loaded.bytes,
                address,
                instruction_limit,
            )
            .map_err(PipelineError::Lift)
    }

    /// Discovers the code a jump table reaches and merges it into the function.
    ///
    /// Ghidra reaches a switch's case bodies through its restart mechanism:
    /// `JumpTable::matchModel` records a multistage jump and sets
    /// `setRestartPending`, and the next pass over the function follows the
    /// recovered targets. Discovery here stops at the `BRANCHIND` because
    /// `sleigh_flow` reports `Flow::Return` for it and `discover` only follows
    /// `Jump`/`Conditional`, so the case bodies were never lifted and
    /// `rule_block_switch` never saw more than one successor.
    ///
    /// This is that restart, at the layer where re-lifting is possible: recover
    /// the table from the first lift, discover from every case and default
    /// target, merge the instructions, and add the branch-to-case edges the
    /// structurer needs.
    fn discover_through_jump_tables(
        &self,
        mut function: ventris_lifter::NativeFunction,
        instruction_limit: usize,
    ) -> ventris_lifter::NativeFunction {
        let Some(architecture) = self.architecture else {
            return function;
        };
        // Skippable so a regression can be attributed to this stage without a
        // rebuild. Every behaviour added late in a session needs this: a change
        // inside pipeline wiring with no switch cost five commits of bisection.
        if std::env::var_os("VENTRIS_NO_MULTISTAGE").is_some() {
            return function;
        }
        let read = |address, width| self.target_memory_value(address, width);
        for _ in 0..MULTISTAGE_ROUNDS {
            let mut data = ventris_decompiler::graph::Funcdata::from_lifted(&function);
            // `from_lifted` makes every read a free varnode, so nothing has a
            // definition and the table's address chain cannot be walked. Heritage
            // is what links reads to their definitions.
            ventris_decompiler::graph::heritage::heritage_with_endianness(
                &mut data,
                !ventris_decompiler::native::architecture_is_big_endian(architecture),
            );
            // The address chain is only walkable after the expression rules have
            // folded it, which is why Ghidra's restart re-runs the whole
            // analysis rather than re-reading the raw graph.
            let pipeline = ventris_decompiler::graph::action::default_pipeline();
            for _ in 0..2 {
                data.invalidate_types();
                if ventris_decompiler::graph::action::Action::apply(pipeline.as_ref(), &mut data)
                    == 0
                {
                    break;
                }
            }
            let tables = ventris_decompiler::graph::jumptable::recover_jump_tables(&data, &read);
            if tables.is_empty() {
                break;
            }
            let mut added = false;
            for table in &tables {
                let Some(branch) = data.op(table.branch).seq.address.into() else {
                    continue;
                };
                let targets = table
                    .cases
                    .iter()
                    .map(|(_, target)| *target)
                    .chain(table.default_target)
                    .collect::<std::collections::BTreeSet<_>>();
                for target in targets {
                    if function.edges.insert((branch, target)) {
                        added = true;
                    }
                    if function.instructions.contains_key(&target) {
                        continue;
                    }
                    if let Ok(reached) = ventris_lifter::lifter_for(architecture).discover(
                        &self.loaded.image,
                        &self.loaded.bytes,
                        target,
                        instruction_limit,
                    ) {
                        for (address, instruction) in reached.instructions {
                            function.instructions.entry(address).or_insert(instruction);
                        }
                        function.edges.extend(reached.edges);
                        function.calls.extend(reached.calls);
                        added = true;
                    }
                }
            }
            if !added {
                break;
            }
        }
        function
    }

    pub fn inventory(
        &self,
        hints: &Hints,
        instruction_limit: usize,
    ) -> Result<Inventory, PipelineError> {
        let architecture = self
            .architecture
            .ok_or(PipelineError::ArchitectureRequired)?;
        let (symbols, relocations) = self.inventory_facts(hints)?;
        Ok(inventory::discover_inventory(
            &*lifter_for(architecture),
            &self.loaded.image,
            &self.loaded.bytes,
            architecture,
            &symbols,
            &relocations,
            instruction_limit,
        ))
    }

    pub fn analyze(
        &self,
        address: &str,
        instruction_limit: usize,
        hints: &Hints,
    ) -> Result<AnalysisResult, PipelineError> {
        let function = self.lift(address, instruction_limit)?;
        let function = self.discover_through_jump_tables(function, instruction_limit);
        let (symbols, relocations) = self.recovery_facts(hints)?;
        let symbol_names = symbols
            .iter()
            .map(|symbol| (symbol.address, symbol.name.clone()))
            .collect::<BTreeMap<_, _>>();
        let read_memory = |address, width| self.target_memory_value(address, width);
        let is_volatile = |address, width| self.target_memory_is_volatile(address, width);
        let memory = NativeMemory {
            read: &read_memory,
            is_volatile: &is_volatile,
        };
        let resolve_symbol = |address| symbol_names.get(&address).cloned();
        let abi = self.target.map(|target| &target.spec().abi);
        let call_prototypes = self.direct_call_prototypes(
            &function,
            instruction_limit,
            abi,
            Some(&memory),
            Some(&resolve_symbol),
        );
        let mut decompiler = NativeDecompiler;
        let architecture = self
            .architecture
            .ok_or(PipelineError::ArchitectureRequired)?;
        // The graph path is the default wherever a convention is known. Measured
        // against the Ghidra oracle on all thirty-seven hash-verified corpus
        // functions it leads the address-ordered one on `agrees`,
        // `excess-casts`, `unstructured-control-flow`, `missing-loop-or-switch`,
        // `return-presence`, `oversized-expression` and
        // `unreduced-flag-expression`, and it passes `corpus-smoke` on every
        // entry.
        let document = if graph_pipeline_default(abi) {
            decompiler.decompile_via_graph(
                architecture,
                &function,
                abi,
                Some(&call_prototypes),
                Some(&memory),
            )
        } else {
            decompiler.decompile_with_call_prototypes(
                architecture,
                &function,
                abi,
                Some(&memory),
                Some(&resolve_symbol),
                Some(&call_prototypes),
            )
        };
        let recovered = self.target.map(|target| {
            recover_function(
                target,
                RecoveryInput {
                    function: &function,
                    nominal_types: &hints.nominal_types,
                    symbols: &symbols,
                    relocations: &relocations,
                    annotations: &hints.annotations,
                    metadata_provenance: &hints.provenance,
                    assertions: &hints.assertions,
                },
            )
        });
        Ok(AnalysisResult {
            function,
            document,
            recovered,
        })
    }

    fn direct_call_prototypes(
        &self,
        caller: &NativeFunction,
        instruction_limit: usize,
        abi: Option<&ventris_target::Abi>,
        memory: Option<&NativeMemory<'_>>,
        symbols: Option<&dyn Fn(u64) -> Option<String>>,
    ) -> BTreeMap<u64, NativeCallPrototype> {
        self.call_prototypes_to_depth(caller, instruction_limit, abi, memory, symbols, 1)
    }

    /// Recovers each direct callee's prototype, giving the callee its own
    /// callees' prototypes down to `depth`.
    ///
    /// A callee's parameters are only visible once its own calls carry
    /// arguments: `sub_8005d01c` forwards all three of its arguments to
    /// `sub_8009d098`, so decompiling it with no prototype for that call
    /// recovers no parameters, and the caller then sees arity zero and drops
    /// the arguments it computed. Ghidra has the whole program's prototypes
    /// available; one level of recursion is what makes a forwarding callee
    /// readable without decompiling transitively forever.
    fn call_prototypes_to_depth(
        &self,
        caller: &NativeFunction,
        instruction_limit: usize,
        abi: Option<&ventris_target::Abi>,
        memory: Option<&NativeMemory<'_>>,
        symbols: Option<&dyn Fn(u64) -> Option<String>>,
        depth: usize,
    ) -> BTreeMap<u64, NativeCallPrototype> {
        let architecture = match self.architecture {
            Some(architecture) => architecture,
            None => return BTreeMap::new(),
        };
        caller
            .calls
            .iter()
            .filter(|target| **target != caller.entry)
            .filter_map(|target| {
                let callee = self
                    .lift_at(*target, instruction_limit.clamp(1, 1024))
                    .ok()?;
                let nested = depth.checked_sub(1).map(|next| {
                    self.call_prototypes_to_depth(
                        &callee,
                        instruction_limit,
                        abi,
                        memory,
                        symbols,
                        next,
                    )
                });
                let document = NativeDecompiler.decompile_with_call_prototypes(
                    architecture,
                    &callee,
                    abi,
                    memory,
                    symbols,
                    nested.as_ref(),
                );
                Some((
                    *target,
                    NativeCallPrototype {
                        return_type: document.return_type,
                        parameters: document
                            .parameters
                            .into_iter()
                            .map(|parameter| parameter.ty)
                            .collect(),
                    },
                ))
            })
            .collect()
    }

    pub fn decompile(
        &self,
        address: &str,
        instruction_limit: usize,
        hints: &Hints,
    ) -> Result<Decompilation, PipelineError> {
        let analysis = self.analyze(address, instruction_limit, hints)?;
        let native_source = analysis.document.render();
        let native_signature = SourceSignature {
            name: analysis.document.name.clone(),
            return_type: analysis.document.return_type.c_name().to_owned(),
            parameters: analysis
                .document
                .parameters
                .iter()
                .map(|parameter| SourceParameter {
                    name: parameter.name.clone(),
                    c_type: parameter.ty.c_name().to_owned(),
                })
                .collect(),
        };
        let source = match analysis.recovered.as_ref() {
            Some(report) => {
                SourceReconstruction::from_signature(report, native_source, native_signature)
                    .map(|source| source.render())
                    .map_err(|error| PipelineError::Reconstruction(error.to_string()))?
            }
            None => native_source,
        };
        Ok(Decompilation { analysis, source })
    }

    fn recovery_facts(
        &self,
        hints: &Hints,
    ) -> Result<(Vec<SymbolFact>, Vec<RelocationFact>), PipelineError> {
        let metadata = self.metadata()?;
        let mut symbols = metadata
            .symbols
            .into_iter()
            .map(|symbol| (symbol.address, symbol.name))
            .collect::<BTreeMap<_, _>>();
        for symbol in &hints.symbols {
            symbols.insert(symbol.address, symbol.name.clone());
        }
        let mut relocations = metadata
            .relocations
            .into_iter()
            .filter_map(|relocation| {
                relocation.symbol.map(|symbol| RelocationFact {
                    address: relocation.address,
                    symbol,
                })
            })
            .collect::<Vec<_>>();
        relocations.extend(hints.relocations.iter().cloned());
        Ok((
            symbols
                .into_iter()
                .map(|(address, name)| SymbolFact { address, name })
                .collect(),
            relocations,
        ))
    }

    fn inventory_facts(
        &self,
        hints: &Hints,
    ) -> Result<(Vec<InventorySymbol>, Vec<InventoryRelocation>), PipelineError> {
        let metadata = self.metadata()?;
        let mut symbols = metadata
            .symbols
            .into_iter()
            .map(|symbol| {
                (
                    symbol.address,
                    InventorySymbol {
                        address: symbol.address,
                        size: symbol.size,
                        name: symbol.name,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        for symbol in &hints.symbols {
            symbols.insert(
                symbol.address,
                InventorySymbol {
                    address: symbol.address,
                    size: 0,
                    name: symbol.name.clone(),
                },
            );
        }
        let mut relocations = metadata
            .relocations
            .into_iter()
            .map(|relocation| InventoryRelocation {
                address: relocation.address,
                symbol: relocation.symbol,
            })
            .collect::<Vec<_>>();
        relocations.extend(
            hints
                .relocations
                .iter()
                .map(|relocation| InventoryRelocation {
                    address: relocation.address,
                    symbol: Some(relocation.symbol.clone()),
                }),
        );
        Ok((symbols.into_values().collect(), relocations))
    }

    fn target_memory_value(&self, address: u64, width: u32) -> Option<u64> {
        // Ghidra reads any mapped address through `LoadImage::loadFill`, and a
        // jump table lives in the image rather than the graph - so refusing every
        // target but one meant no switch could ever be recovered outside it.
        if !matches!(width, 1 | 2 | 4 | 8) {
            return None;
        }
        let width = usize::try_from(width).ok()?;
        let bytes = self
            .loaded
            .image
            .bytes_at(&self.loaded.bytes, address, width)?;
        // The byte order is the architecture's. Folding little-endian
        // unconditionally is why this was scoped to one target: a big-endian
        // table read that way yields a byte-swapped address.
        let big_endian = self
            .architecture
            .map(ventris_decompiler::native::architecture_is_big_endian)
            .unwrap_or(false);
        (bytes.len() == width).then(|| {
            bytes.iter().enumerate().fold(0u64, |value, (index, byte)| {
                let shift = if big_endian { width - 1 - index } else { index };
                value | (u64::from(*byte) << (shift * 8))
            })
        })
    }

    fn target_memory_is_volatile(&self, address: u64, _width: u32) -> bool {
        self.target == Some(TargetProfile::Gba) && (0x0400_0000..0x0400_0400).contains(&address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_defaults_select_loader_architecture_and_support_claim() {
        let source = [0x08, 0x00, 0xe0, 0x03, 0, 0, 0, 0];
        let pipeline = Pipeline::load(
            source,
            LoadOptions {
                target: Some(TargetProfile::Ps1),
                loader: Loader::Raw,
                ..LoadOptions::default()
            },
        )
        .unwrap();
        assert_eq!(pipeline.architecture(), Some(Architecture::Ps1));
        assert_eq!(pipeline.image().segments[0].addr, 0x8001_0000);
        assert_eq!(
            pipeline.decompilation_support(),
            DecompilationSupport::Experimental
        );
    }

    #[test]
    fn target_abi_parameters_survive_native_and_source_reconstruction() {
        let pipeline = Pipeline::load(
            [
                0x01, 0x00, 0xc2, 0x24, // addiu v0, a2, 1
                0x08, 0x00, 0xe0, 0x03, // jr ra
                0x00, 0x00, 0x00, 0x00, // delay slot
            ],
            LoadOptions {
                target: Some(TargetProfile::Ps1),
                loader: Loader::Raw,
                ..LoadOptions::default()
            },
        )
        .unwrap();
        let address = "0x80010000";
        let expected = "uint32_t sub_80010000(uint32_t arg0, uint32_t arg1, uint32_t arg2)";
        let analysis = pipeline.analyze(address, 32, &Hints::default()).unwrap();
        let rendered = analysis.document.render();
        assert!(rendered.contains(expected), "{rendered}");
        let source = pipeline
            .decompile(address, 32, &Hints::default())
            .unwrap()
            .source;
        assert!(source.contains(expected), "{source}");
        assert!(source.contains("return arg2 + 1;"), "{source}");
    }

    #[test]
    fn gamecube_pipeline_recovers_direct_callee_prototype() {
        let mut source = vec![
            0x48, 0x00, 0x00, 0x21, // bl 0x80003120
            0x4e, 0x80, 0x00, 0x20, // blr
        ];
        source.resize(0x20, 0);
        source.extend([
            0x38, 0x63, 0x00, 0x01, // addi r3, r3, 1
            0x4e, 0x80, 0x00, 0x20, // blr
        ]);
        let pipeline = Pipeline::load(
            source,
            LoadOptions {
                target: Some(TargetProfile::GameCube),
                loader: Loader::Raw,
                base: Some(0x8000_3100),
                ..LoadOptions::default()
            },
        )
        .unwrap();

        let source = pipeline
            .decompile("0x80003100", 16, &Hints::default())
            .unwrap()
            .source;

        assert!(source.contains("sub_80003120(arg0)"), "{source}");
        assert!(source.contains("return"), "{source}");
    }

    #[test]
    fn target_and_architecture_cannot_silently_disagree() {
        let error = Pipeline::load(
            [0xc3],
            LoadOptions {
                architecture: Some(Architecture::X86_64),
                target: Some(TargetProfile::Ps2),
                loader: Loader::Raw,
                ..LoadOptions::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            PipelineError::TargetArchitectureMismatch { .. }
        ));
    }

    #[test]
    fn canonical_stages_share_one_lifted_function() {
        let pipeline = Pipeline::load(
            [0xc3],
            LoadOptions {
                architecture: Some(Architecture::X86_64),
                loader: Loader::Raw,
                base: Some(0x1000),
                ..LoadOptions::default()
            },
        )
        .unwrap();
        let lifted = pipeline.lift("0x1000", 32).unwrap();
        let analyzed = pipeline.analyze("0x1000", 32, &Hints::default()).unwrap();
        let decompiled = pipeline.decompile("0x1000", 32, &Hints::default()).unwrap();
        assert_eq!(lifted, analyzed.function);
        assert_eq!(analyzed.function, decompiled.analysis.function);
        assert_eq!(analyzed.document.render(), decompiled.source);
        assert!(decompiled.source.contains("void sub_1000"));
    }

    #[test]
    fn inventory_uses_the_same_loaded_image_and_target_decision() {
        let pipeline = Pipeline::load(
            [0xc3, 0, b'H', b'e', b'l', b'l', b'o', 0],
            LoadOptions {
                architecture: Some(Architecture::X86_64),
                loader: Loader::Raw,
                base: Some(0x1000),
                ..LoadOptions::default()
            },
        )
        .unwrap();
        let inventory = pipeline.inventory(&Hints::default(), 32).unwrap();
        assert_eq!(inventory.functions.functions.len(), 1);
        assert!(
            inventory
                .data
                .iter()
                .any(|fact| fact.type_name == Some("string"))
        );
    }
}
