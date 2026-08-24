//! Native instruction lifting for Ventris.
//!
//! Stage 1 deliberately has a small, explicit boundary: a lifter consumes
//! file-backed bytes and returns p-code plus control-flow facts. It never
//! guesses a processor from ELF machine facts; the caller selects an
//! architecture after applying an L1 language choice.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::sync::LazyLock;
use ventris_format::Image;
pub use ventris_pcode::{CONST_SPACE, OTHER_SPACE, RAM_SPACE, REGISTER_SPACE, UNIQUE_SPACE};
use ventris_pcode::{InstPcode, PcodeOp, op};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Architecture {
    X86_64,
    /// Intel/AMD 32-bit x86.
    X86_32,
    AArch64,
    Arm32,
    /// ARM Thumb-1/Thumb-2 16-bit instruction baseline.
    Thumb,
    /// Generic little-endian MIPS32 (also exposed as the PS1 baseline).
    Mips32,
    /// Generic big-endian MIPS32.
    Mips32Be,
    /// Sony PlayStation 2 Emotion Engine: little-endian MIPS64 with 32-bit pointers.
    Ps2,
    /// Sony PlayStation 1: MIPS R3000A, little-endian MIPS32.
    Ps1,
    /// Nintendo 64: MIPS R4300i, big-endian MIPS64.
    N64,
    Rv64,
    /// Generic 32-bit RISC-V.
    Rv32,
    /// Generic big-endian PowerPC32 (also exposed as the GameCube baseline).
    Ppc32,
    /// Big-endian PowerPC64 used by the Cell PPU.
    Ppc64,
    /// Nintendo GameCube: PowerPC 750-derived, big-endian PPC32.
    GameCube,
    M68k,
    /// Sega Saturn-class SuperH-2, big-endian.
    Sh2,
    /// Dreamcast-class SuperH-4, little-endian.
    Sh4,
    /// MOS 6502-family, little-endian.
    M6502,
    /// Zilog Z80-family, little-endian.
    Z80,
    /// Sony Cell Synergistic Processing Unit, 32-bit big-endian instructions.
    Spu,
}

impl Architecture {
    /// Every processor family exposed by the CLI and public documentation.
    pub const ALL: [Self; 21] = [
        Self::X86_64,
        Self::X86_32,
        Self::AArch64,
        Self::Arm32,
        Self::Thumb,
        Self::Mips32,
        Self::Mips32Be,
        Self::Ps2,
        Self::Ps1,
        Self::N64,
        Self::Rv64,
        Self::Rv32,
        Self::Ppc32,
        Self::Ppc64,
        Self::GameCube,
        Self::M68k,
        Self::Sh2,
        Self::Sh4,
        Self::M6502,
        Self::Z80,
        Self::Spu,
    ];
}
/// Construct the one native lifter implementation for an architecture.
///
/// Front ends call this factory instead of maintaining their own architecture
/// dispatch tables.
pub fn lifter_for(architecture: Architecture) -> Box<dyn Lifter> {
    Box::new(CompiledSleigh { architecture })
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LiftError {
    AddressUnavailable(u64),
    Truncated {
        address: u64,
        needed: usize,
    },
    Unsupported {
        architecture: Architecture,
        address: u64,
        opcode: u8,
    },
    InvalidEncoding {
        architecture: Architecture,
        address: u64,
        reason: &'static str,
    },
    Semantics {
        architecture: Architecture,
        address: u64,
        reason: String,
    },
    InstructionLimit(usize),
}

impl fmt::Display for LiftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddressUnavailable(a) => write!(f, "no file-backed bytes at {a:#x}"),
            Self::Truncated { address, needed } => {
                write!(f, "instruction at {address:#x} needs {needed} bytes")
            }
            Self::Unsupported {
                architecture,
                address,
                opcode,
            } => write!(
                f,
                "unsupported {architecture:?} opcode {opcode:#x} at {address:#x}"
            ),
            Self::InvalidEncoding {
                architecture,
                address,
                reason,
            } => {
                write!(
                    f,
                    "invalid {architecture:?} instruction at {address:#x}: {reason}"
                )
            }
            Self::Semantics {
                architecture,
                address,
                reason,
            } => write!(
                f,
                "{architecture:?} semantic execution failed at {address:#x}: {reason}"
            ),
            Self::InstructionLimit(n) => write!(f, "function exceeded {n} instruction limit"),
        }
    }
}

impl std::error::Error for LiftError {}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Flow {
    FallThrough(u64),
    Return,
    Jump(u64),
    Conditional { target: u64, fallthrough: u64 },
    Call { target: u64, fallthrough: u64 },
}

impl Flow {
    pub fn fallthrough(&self) -> Option<u64> {
        match self {
            Self::FallThrough(a)
            | Self::Conditional { fallthrough: a, .. }
            | Self::Call { fallthrough: a, .. } => Some(*a),
            Self::Return | Self::Jump(_) => None,
        }
    }

    pub fn branch_target(&self) -> Option<u64> {
        match self {
            Self::Jump(a) | Self::Conditional { target: a, .. } | Self::Call { target: a, .. } => {
                Some(*a)
            }
            Self::FallThrough(_) | Self::Return => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LiftedInstruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub pcode: InstPcode,
    pub flow: Flow,
    /// Bytes of delay-slot semantics already spliced into `pcode`.
    pub embedded_delay_slot_bytes: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NativeFunction {
    pub entry: u64,
    pub instructions: BTreeMap<u64, LiftedInstruction>,
    pub edges: BTreeSet<(u64, u64)>,
    pub calls: BTreeSet<u64>,
}

impl NativeFunction {
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    pub fn byte_length(&self) -> u64 {
        self.instructions
            .values()
            .map(|i| i.address.saturating_add(i.pcode.len as u64))
            .max()
            .unwrap_or(self.entry)
            .saturating_sub(self.entry)
    }
}

pub trait Lifter {
    fn architecture(&self) -> Architecture;
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError>;
    fn has_delay_slot(&self) -> bool {
        false
    }
    /// Maximum byte window required to resolve one instruction and any
    /// architecture-defined delay slots.
    fn decode_window_size(&self) -> usize {
        15
    }

    /// Discover one function by following intra-function control flow.
    /// Calls are recorded but not traversed; conditional and unconditional
    /// branch targets are traversed, and fall-through is followed until return.
    fn discover(
        &self,
        image: &Image,
        file: &[u8],
        entry: u64,
        limit: usize,
    ) -> Result<NativeFunction, LiftError> {
        let mut pending = VecDeque::from([entry]);
        let mut seen = BTreeSet::new();
        let mut instructions = BTreeMap::new();
        let mut edges = BTreeSet::new();
        let mut calls = BTreeSet::new();

        while let Some(address) = pending.pop_front() {
            if !seen.insert(address) {
                continue;
            }
            if instructions.len() >= limit {
                return Err(LiftError::InstructionLimit(limit));
            }
            let bytes = image
                .bytes_at(file, address, self.decode_window_size())
                .ok_or(LiftError::AddressUnavailable(address))?;
            let instruction = self.lift_instruction(address, bytes)?;
            instructions.insert(address, instruction.clone());
            let next = instruction.flow.fallthrough().map(|next| {
                if self.has_delay_slot() && !matches!(instruction.flow, Flow::FallThrough(_)) {
                    next.saturating_add(instruction.pcode.len as u64)
                } else {
                    next
                }
            });
            if let Some(next) = next {
                edges.insert((address, next));
                pending.push_back(next);
            }
            if let Some(target) = instruction.flow.branch_target() {
                match instruction.flow {
                    Flow::Call { .. } => {
                        calls.insert(target);
                        if let Some(next) = next {
                            pending.push_back(next);
                        }
                    }
                    Flow::Jump(_) | Flow::Conditional { .. } => {
                        edges.insert((address, target));
                        pending.push_back(target);
                    }
                    Flow::FallThrough(_) | Flow::Return => {}
                }
            }
            if self.has_delay_slot() && !matches!(instruction.flow, Flow::FallThrough(_)) {
                let delay_address = address.saturating_add(instruction.pcode.len as u64);
                if seen.insert(delay_address) {
                    if let Some(delay_bytes) = image.bytes_at(file, delay_address, 4) {
                        let delay = self.lift_instruction(delay_address, delay_bytes)?;
                        instructions.insert(delay_address, delay);
                    }
                }
            }
        }

        Ok(NativeFunction {
            entry,
            instructions,
            edges,
            calls,
        })
    }
}

/// Result of recursively discovering functions from a set of asserted entry
/// points. Calls are queued as new candidates, but are never traversed as part
/// of their caller's control-flow graph.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct FunctionDiscovery {
    pub functions: BTreeMap<u64, NativeFunction>,
    pub failures: BTreeMap<u64, LiftError>,
    pub calls: BTreeSet<(u64, u64)>,
}

/// Discover a bounded function graph without guessing a processor or a code
/// region. The caller supplies seeds after applying image and target policy.
pub fn discover_functions(
    lifter: &dyn Lifter,
    image: &Image,
    file: &[u8],
    seeds: impl IntoIterator<Item = u64>,
    instruction_limit: usize,
    function_limit: usize,
) -> FunctionDiscovery {
    let mut pending: BTreeSet<u64> = seeds.into_iter().collect();
    let mut result = FunctionDiscovery::default();
    while let Some(entry) = pending.iter().next().copied() {
        pending.remove(&entry);
        if result.functions.len() >= function_limit || result.functions.contains_key(&entry) {
            continue;
        }
        match lifter.discover(image, file, entry, instruction_limit) {
            Ok(function) => {
                for target in &function.calls {
                    result.calls.insert((entry, *target));
                    if !result.functions.contains_key(target) {
                        pending.insert(*target);
                    }
                }
                result.functions.insert(entry, function);
            }
            Err(error) => {
                result.failures.insert(entry, error);
            }
        }
    }
    result
}

#[derive(Copy, Clone, Debug, Default)]
pub struct X86_64;

impl X86_64 {
    pub const fn new() -> Self {
        Self
    }
}

impl Lifter for X86_64 {
    fn architecture(&self) -> Architecture {
        Architecture::X86_64
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::X86_64, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct AArch64;

impl Lifter for AArch64 {
    fn architecture(&self) -> Architecture {
        Architecture::AArch64
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::AArch64, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Mips32;

impl Lifter for Mips32 {
    fn architecture(&self) -> Architecture {
        Architecture::Mips32
    }

    fn has_delay_slot(&self) -> bool {
        true
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::Mips32, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Ps2;

impl Lifter for Ps2 {
    fn architecture(&self) -> Architecture {
        Architecture::Ps2
    }

    fn has_delay_slot(&self) -> bool {
        true
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::Ps2, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct N64;

impl Lifter for N64 {
    fn architecture(&self) -> Architecture {
        Architecture::N64
    }

    fn has_delay_slot(&self) -> bool {
        true
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::N64, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Ps1;

impl Lifter for Ps1 {
    fn architecture(&self) -> Architecture {
        Architecture::Ps1
    }

    fn has_delay_slot(&self) -> bool {
        true
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::Ps1, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Arm32;

impl Lifter for Arm32 {
    fn architecture(&self) -> Architecture {
        Architecture::Arm32
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::Arm32, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Rv64;

impl Lifter for Rv64 {
    fn architecture(&self) -> Architecture {
        Architecture::Rv64
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::Rv64, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Ppc32;

impl Lifter for Ppc32 {
    fn architecture(&self) -> Architecture {
        Architecture::Ppc32
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::Ppc32, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Ppc64;

impl Lifter for Ppc64 {
    fn architecture(&self) -> Architecture {
        Architecture::Ppc64
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::Ppc64, address, bytes)
    }
}
#[derive(Copy, Clone, Debug, Default)]
pub struct GameCube;

fn sleigh_flow(address: u64, length: u32, operations: &[PcodeOp]) -> Flow {
    let fallthrough = address.wrapping_add(u64::from(length));
    for operation in operations.iter().rev() {
        let target = operation.inputs.first().copied();
        match operation.opcode {
            op::RETURN | op::BRANCHIND => return Flow::Return,
            op::CALLIND => return Flow::FallThrough(fallthrough),
            op::CALL => {
                if let Some(target) = target {
                    return Flow::Call {
                        target: target.offset,
                        fallthrough,
                    };
                }
            }
            op::BRANCH => {
                if let Some(target) = target
                    .filter(|target| target.space != CONST_SPACE && target.offset != fallthrough)
                {
                    return Flow::Jump(target.offset);
                }
            }
            op::CBRANCH => {
                if let Some(target) = target
                    .filter(|target| target.space != CONST_SPACE && target.offset != fallthrough)
                {
                    return Flow::Conditional {
                        target: target.offset,
                        fallthrough,
                    };
                }
            }
            _ => {}
        }
    }
    Flow::FallThrough(fallthrough)
}

#[derive(Copy, Clone, Debug)]
struct CompiledSleigh {
    architecture: Architecture,
}

fn compiled_lift_instruction(
    architecture: Architecture,
    address: u64,
    bytes: &[u8],
) -> Result<LiftedInstruction, LiftError> {
    CompiledSleigh { architecture }.lift_instruction(address, bytes)
}

fn bundled_sleigh_spec(
    architecture: Architecture,
) -> Result<&'static ventris_sleigh::SleighSpec, String> {
    macro_rules! cached {
        ($bytes:expr) => {{
            static SPEC: LazyLock<Result<ventris_sleigh::SleighSpec, String>> =
                LazyLock::new(|| {
                    let artifact = ventris_sleigh::SlaArtifact::from_bytes($bytes)
                        .map_err(|error| error.to_string())?;
                    ventris_sleigh::SleighSpec::from_artifact(&artifact)
                        .map_err(|error| error.to_string())
                });
            SPEC.as_ref().map_err(Clone::clone)
        }};
    }

    match architecture {
        Architecture::X86_64 => cached!(ventris_sleigh::X86_64_SLA),
        Architecture::X86_32 => cached!(ventris_sleigh::X86_32_SLA),
        Architecture::AArch64 => cached!(ventris_sleigh::AARCH64_SLA),
        Architecture::Arm32 => cached!(ventris_sleigh::ARM32_SLA),
        Architecture::Thumb => cached!(ventris_sleigh::THUMB_SLA),
        Architecture::Mips32 | Architecture::Ps1 => cached!(ventris_sleigh::MIPS32_LE_SLA),
        Architecture::Mips32Be => cached!(ventris_sleigh::MIPS32_BE_SLA),
        Architecture::Ps2 => cached!(ventris_sleigh::PS2_R5900_SLA),
        Architecture::N64 => cached!(ventris_sleigh::MIPS64_BE_SLA),
        Architecture::Rv64 => cached!(ventris_sleigh::RISCV64_SLA),
        Architecture::Rv32 => cached!(ventris_sleigh::RISCV32_SLA),
        Architecture::Ppc32 => cached!(ventris_sleigh::POWERPC32_BE_SLA),
        Architecture::Ppc64 => cached!(ventris_sleigh::POWERPC64_BE_SLA),
        Architecture::GameCube => cached!(ventris_sleigh::GAMECUBE_GEKKO_SLA),
        Architecture::M68k => cached!(ventris_sleigh::M68020_SLA),
        Architecture::Sh2 => cached!(ventris_sleigh::SH2_SLA),
        Architecture::Sh4 => cached!(ventris_sleigh::SH4_SLA),
        Architecture::M6502 => cached!(ventris_sleigh::M6502_SLA),
        Architecture::Z80 => cached!(ventris_sleigh::Z80_SLA),
        Architecture::Spu => cached!(ventris_sleigh::SPU_SLA),
    }
}

/// Resolves a bundled SLEIGH CALLOTHER index to its declared user-op name.
pub fn sleigh_userop_name(architecture: Architecture, index: u64) -> Option<&'static str> {
    bundled_sleigh_spec(architecture)
        .ok()
        .and_then(|spec| spec.userop_name(index))
}

/// Resolves a named register to the varnode the bundled language compiles it to.
///
/// Returns the p-code space, offset, and declared width. Consumers that need
/// ABI registers must use this instead of assuming a register stride: the same
/// architecture family can space its registers differently per language.
pub fn sleigh_register_varnode(
    architecture: Architecture,
    register: &str,
) -> Option<(u32, u64, u32)> {
    bundled_sleigh_spec(architecture)
        .ok()
        .and_then(|spec| spec.register_varnode(register))
}

fn bundled_sleigh_context(architecture: Architecture) -> Result<[u32; 4], String> {
    fn build(architecture: Architecture, settings: &[(&str, u32)]) -> Result<[u32; 4], String> {
        let spec = bundled_sleigh_spec(architecture)?;
        let mut context = [0_u32; 4];
        for (name, value) in settings {
            spec.set_context_variable(&mut context, name, *value)
                .map_err(|error| error.to_string())?;
        }
        Ok(context)
    }

    macro_rules! cached {
        ($architecture:expr, $settings:expr) => {{
            static CONTEXT: LazyLock<Result<[u32; 4], String>> =
                LazyLock::new(|| build($architecture, $settings));
            CONTEXT.as_ref().map(Clone::clone).map_err(Clone::clone)
        }};
    }

    match architecture {
        Architecture::X86_64 => cached!(
            Architecture::X86_64,
            &[
                ("addrsize", 2),
                ("opsize", 1),
                ("rexprefix", 0),
                ("longMode", 1),
            ]
        ),
        Architecture::X86_32 => cached!(Architecture::X86_32, &[("addrsize", 1), ("opsize", 1)]),
        Architecture::Thumb => cached!(Architecture::Thumb, &[("TMode", 1), ("LRset", 0)]),
        Architecture::Arm32 => cached!(Architecture::Arm32, &[("LRset", 0)]),
        Architecture::Mips32 | Architecture::Ps1 => cached!(
            Architecture::Mips32,
            &[("PAIR_INSTRUCTION_FLAG", 0), ("RELP", 1)]
        ),
        Architecture::Mips32Be => cached!(
            Architecture::Mips32Be,
            &[("PAIR_INSTRUCTION_FLAG", 0), ("RELP", 1)]
        ),
        Architecture::Ps2 => cached!(Architecture::Ps2, &[("PAIR_INSTRUCTION_FLAG", 0)]),
        Architecture::N64 => cached!(
            Architecture::N64,
            &[("PAIR_INSTRUCTION_FLAG", 0), ("RELP", 1)]
        ),
        _ => Ok([0_u32; 4]),
    }
}

fn sleigh_pointer_size(architecture: Architecture) -> u32 {
    match architecture {
        Architecture::X86_64
        | Architecture::AArch64
        | Architecture::Ps2
        | Architecture::N64
        | Architecture::Rv64
        | Architecture::Ppc64 => 8,
        _ => 4,
    }
}

impl Lifter for CompiledSleigh {
    fn architecture(&self) -> Architecture {
        self.architecture
    }

    fn has_delay_slot(&self) -> bool {
        matches!(
            self.architecture,
            Architecture::Mips32
                | Architecture::Mips32Be
                | Architecture::Ps1
                | Architecture::Ps2
                | Architecture::N64
                | Architecture::Sh2
                | Architecture::Sh4
        )
    }

    fn decode_window_size(&self) -> usize {
        256
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        let spec =
            bundled_sleigh_spec(self.architecture).map_err(|reason| LiftError::Semantics {
                architecture: self.architecture,
                address,
                reason,
            })?;
        let context =
            bundled_sleigh_context(self.architecture).map_err(|reason| LiftError::Semantics {
                architecture: self.architecture,
                address,
                reason,
            })?;
        let mut padded = [0_u8; 256];
        let input = if bytes.len() < padded.len() {
            padded[..bytes.len()].copy_from_slice(bytes);
            padded.as_slice()
        } else {
            bytes
        };
        let constructors = spec
            .instruction_table()
            .resolve_candidates(input, &context)
            .map_err(|error| LiftError::Semantics {
                architecture: self.architecture,
                address,
                reason: error.to_string(),
            })?;
        let mut last_error = None;
        let mut emitted = None;
        for constructor in constructors {
            match ventris_sleigh::emit_instruction_details(
                spec,
                constructor,
                input,
                &context,
                address,
                RAM_SPACE,
                sleigh_pointer_size(self.architecture),
            ) {
                Ok(result) => {
                    emitted = Some(result);
                    break;
                }
                Err(error) => last_error = Some(error.to_string()),
            }
        }
        let emitted = emitted.ok_or_else(|| LiftError::Semantics {
            architecture: self.architecture,
            address,
            reason: last_error.unwrap_or_else(|| "no viable SLEIGH constructor".to_owned()),
        })?;
        let length = emitted.length;
        let embedded_delay_slot_bytes = emitted.delay_slot_bytes;
        let operations = emitted.operations;
        let flow = sleigh_flow(address, length, &operations);
        Ok(LiftedInstruction {
            address,
            bytes: bytes
                .get(..length as usize)
                .ok_or(LiftError::Truncated {
                    address,
                    needed: length as usize,
                })?
                .to_vec(),
            pcode: InstPcode {
                len: length,
                space: RAM_SPACE,
                offset: address,
                ops: operations,
            },
            flow,
            embedded_delay_slot_bytes,
        })
    }
}

impl Lifter for GameCube {
    fn architecture(&self) -> Architecture {
        Architecture::GameCube
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::GameCube, address, bytes)
    }
}
#[derive(Copy, Clone, Debug, Default)]
pub struct X86_32;

impl Lifter for X86_32 {
    fn architecture(&self) -> Architecture {
        Architecture::X86_32
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::X86_32, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Mips32Be;

impl Lifter for Mips32Be {
    fn architecture(&self) -> Architecture {
        Architecture::Mips32Be
    }

    fn has_delay_slot(&self) -> bool {
        true
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::Mips32Be, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Rv32;

impl Lifter for Rv32 {
    fn architecture(&self) -> Architecture {
        Architecture::Rv32
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::Rv32, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Thumb;

impl Lifter for Thumb {
    fn architecture(&self) -> Architecture {
        Architecture::Thumb
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::Thumb, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct M68k;

impl Lifter for M68k {
    fn architecture(&self) -> Architecture {
        Architecture::M68k
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::M68k, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Sh2;

impl Lifter for Sh2 {
    fn architecture(&self) -> Architecture {
        Architecture::Sh2
    }

    fn has_delay_slot(&self) -> bool {
        true
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::Sh2, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Sh4;

impl Lifter for Sh4 {
    fn architecture(&self) -> Architecture {
        Architecture::Sh4
    }

    fn has_delay_slot(&self) -> bool {
        true
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::Sh4, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct M6502;

impl Lifter for M6502 {
    fn architecture(&self) -> Architecture {
        Architecture::M6502
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::M6502, address, bytes)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Z80;

impl Lifter for Z80 {
    fn architecture(&self) -> Architecture {
        Architecture::Z80
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::Z80, address, bytes)
    }
}

/// Cell SPU lifter backed by the bundled compiled SLEIGH specification.
#[derive(Copy, Clone, Debug, Default)]
pub struct Spu;

impl Lifter for Spu {
    fn architecture(&self) -> Architecture {
        Architecture::Spu
    }
    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        compiled_lift_instruction(Architecture::Spu, address, bytes)
    }
}
