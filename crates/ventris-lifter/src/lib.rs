//! Native instruction lifting for Ventris.
//!
//! Stage 1 deliberately has a small, explicit boundary: a lifter consumes
//! file-backed bytes and returns p-code plus control-flow facts. It never
//! guesses a processor from ELF machine facts; the caller selects an
//! architecture after applying an L1 language choice.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use ventris_format::Image;
use ventris_pcode::{InstPcode, PcodeOp, Varnode, op};

pub const CONST_SPACE: u32 = 0;
pub const OTHER_SPACE: u32 = 1;
pub const UNIQUE_SPACE: u32 = 2;
pub const RAM_SPACE: u32 = 3;
pub const REGISTER_SPACE: u32 = 4;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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
    pub const ALL: [Self; 20] = [
        Self::X86_64,
        Self::X86_32,
        Self::AArch64,
        Self::Arm32,
        Self::Thumb,
        Self::Mips32,
        Self::Mips32Be,
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
        Architecture::M6502 => Box::new(M6502),
        Architecture::Z80 => Box::new(Z80),
        Architecture::Spu => Box::new(Spu),
    }
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
                .bytes_at(file, address, 15)
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

fn reg(index: u8, size: u32) -> Varnode {
    Varnode::new(REGISTER_SPACE, u64::from(index & 0x0f) * 8, size)
}
fn x86_byte_reg(index: u8, rex: u8) -> Varnode {
    let index = index & 0x0f;
    if rex == 0 && index >= 4 && index < 8 {
        Varnode::new(REGISTER_SPACE, u64::from(index - 4) * 8 + 1, 1)
    } else {
        reg(index, 1)
    }
}
fn x86_xmm_reg(index: u8) -> Varnode {
    Varnode::new(
        REGISTER_SPACE,
        0x1000u64.wrapping_add(u64::from(index & 0x0f) * 16),
        16,
    )
}
fn aarch64_reg(index: u8, size: u32) -> Varnode {
    Varnode::new(
        REGISTER_SPACE,
        0x4000u64.wrapping_add(u64::from(index) * 8),
        size,
    )
}

fn aarch64_flag(offset: u64) -> Varnode {
    Varnode::new(REGISTER_SPACE, offset, 1)
}

fn flag(offset: u64) -> Varnode {
    Varnode::new(REGISTER_SPACE, offset, 1)
}
fn x86_ram_space(size: u32) -> Varnode {
    constant(433, size)
}
fn x86_register(offset: u64, size: u32) -> Varnode {
    Varnode::new(REGISTER_SPACE, offset, size)
}

fn x86_emit_return(ops: &mut Vec<PcodeOp>, stack_adjust: u64) {
    let return_address = x86_register(648, 8);
    let stack_pointer = x86_register(32, 8);
    ops.push(p(
        op::LOAD,
        Some(return_address),
        vec![x86_ram_space(8), stack_pointer],
    ));
    ops.push(p(
        op::INT_ADD,
        Some(stack_pointer),
        vec![stack_pointer, constant(stack_adjust, 8)],
    ));
    ops.push(p(op::RETURN, None, vec![return_address]));
}

fn x86_add_flag_prefix(ops: &mut Vec<PcodeOp>, destination: Varnode, source: Varnode) {
    ops.push(p(op::INT_CARRY, Some(flag(512)), vec![destination, source]));
    ops.push(p(
        op::INT_SCARRY,
        Some(flag(523)),
        vec![destination, source],
    ));
}
fn x86_add_flag_suffix(address: u64, ops: &mut Vec<PcodeOp>, result: Varnode) {
    ops.push(p(
        op::INT_SLESS,
        Some(flag(519)),
        vec![result, constant(0, result.size)],
    ));
    ops.push(p(
        op::INT_EQUAL,
        Some(flag(518)),
        vec![result, constant(0, result.size)],
    ));
    let parity_input = unique(address, 1, result.size);
    ops.push(p(
        op::INT_AND,
        Some(parity_input),
        vec![result, constant(255, result.size)],
    ));
    let parity_count = unique(address, 2, 1);
    ops.push(p(op::POPCOUNT, Some(parity_count), vec![parity_input]));
    let parity = unique(address, 3, 1);
    ops.push(p(
        op::INT_AND,
        Some(parity),
        vec![parity_count, constant(1, 1)],
    ));
    ops.push(p(
        op::INT_EQUAL,
        Some(flag(514)),
        vec![parity, constant(0, 1)],
    ));
}
fn x86_set_test_flags(address: u64, ops: &mut Vec<PcodeOp>, result: Varnode) {
    ops.push(p(op::COPY, Some(flag(512)), vec![constant(0, 1)]));
    ops.push(p(op::COPY, Some(flag(523)), vec![constant(0, 1)]));
    x86_add_flag_suffix(address, ops, result);
}

fn constant(value: u64, size: u32) -> Varnode {
    Varnode::new(CONST_SPACE, value, size)
}

fn unique(address: u64, slot: u32, size: u32) -> Varnode {
    Varnode::new(
        UNIQUE_SPACE,
        address
            .wrapping_mul(32)
            .wrapping_add(u64::from(slot) * 0x100),
        size,
    )
}

fn p(opcode: i32, output: Option<Varnode>, inputs: impl Into<Vec<Varnode>>) -> PcodeOp {
    PcodeOp::new(opcode, output, inputs.into())
}

fn x86_condition(cc: u8, address: u64, ops: &mut Vec<PcodeOp>) -> Option<Varnode> {
    let zf = flag(518);
    let cf = flag(512);
    let sf = flag(519);
    let of = flag(523);
    let pf = flag(514);
    let negate = |value: Varnode, ops: &mut Vec<PcodeOp>| {
        let output = unique(address, 0x10 + u32::from(cc), 1);
        ops.push(p(op::BOOL_NEGATE, Some(output), vec![value]));
        output
    };
    let combine = |opcode: i32, left: Varnode, right: Varnode, ops: &mut Vec<PcodeOp>| {
        let output = unique(address, 0x20 + u32::from(cc), 1);
        ops.push(p(opcode, Some(output), vec![left, right]));
        output
    };
    Some(match cc {
        0x0 => of,
        0x1 => negate(of, ops),
        0x2 => cf,
        0x3 => negate(cf, ops),
        0x4 => zf,
        0x5 => negate(zf, ops),
        0x6 => combine(op::BOOL_OR, cf, zf, ops),
        0x7 => negate(combine(op::BOOL_OR, cf, zf, ops), ops),
        0x8 => sf,
        0x9 => negate(sf, ops),
        0xa => pf,
        0xb => negate(pf, ops),
        0xc => combine(op::BOOL_XOR, sf, of, ops),
        0xd => negate(combine(op::BOOL_XOR, sf, of, ops), ops),
        0xe => combine(op::BOOL_OR, zf, combine(op::BOOL_XOR, sf, of, ops), ops),
        0xf => negate(
            combine(op::BOOL_OR, zf, combine(op::BOOL_XOR, sf, of, ops), ops),
            ops,
        ),
        _ => return None,
    })
}

fn read_i8(bytes: &[u8], at: usize) -> Result<i64, ()> {
    bytes.get(at).copied().map(|v| i64::from(v as i8)).ok_or(())
}

fn read_i32(bytes: &[u8], at: usize) -> Result<i64, ()> {
    let b = bytes.get(at..at + 4).ok_or(())?;
    Ok(i64::from(i32::from_le_bytes([b[0], b[1], b[2], b[3]])))
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u64, ()> {
    let b = bytes.get(at..at + 4).ok_or(())?;
    Ok(u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
}

fn target(address: u64, end: usize, displacement: i64) -> Result<u64, ()> {
    let end = i64::try_from(address.checked_add(end as u64).ok_or(())?).map_err(|_| ())?;
    u64::try_from(end.checked_add(displacement).ok_or(())?).map_err(|_| ())
}

fn modrm_register(bytes: &[u8], at: usize, rex: u8) -> Result<(u8, u8), &'static str> {
    let byte = *bytes.get(at).ok_or("missing ModRM")?;
    if byte >> 6 != 3 {
        return Err("memory ModRM is not supported by this decoder");
    }
    let reg_field = ((byte >> 3) & 7) | (((rex >> 2) & 1) << 3);
    let rm_field = (byte & 7) | ((rex & 1) << 3);
    Ok((reg_field, rm_field))
}

#[derive(Copy, Clone, Debug)]
enum RmOperand {
    Register(u8),
    Memory {
        base: Option<u8>,
        index: Option<(u8, u8)>,
        displacement: i64,
        rip_relative: bool,
    },
}

#[derive(Copy, Clone, Debug)]
struct ParsedModRm {
    reg: u8,
    operand: RmOperand,
    len: usize,
}

fn decode_modrm(bytes: &[u8], at: usize, rex: u8) -> Result<ParsedModRm, &'static str> {
    let byte = *bytes.get(at).ok_or("missing ModRM")?;
    let mode = byte >> 6;
    let reg_field = ((byte >> 3) & 7) | (((rex >> 2) & 1) << 3);
    let rm_raw = byte & 7;
    let rm_field = rm_raw | ((rex & 1) << 3);
    if mode == 3 {
        return Ok(ParsedModRm {
            reg: reg_field,
            operand: RmOperand::Register(rm_field),
            len: 1,
        });
    }

    let mut cursor = at + 1;
    let mut base = None;
    let mut index = None;
    let mut displacement = 0i64;
    let mut rip_relative = false;
    if rm_raw == 4 {
        let sib = *bytes.get(cursor).ok_or("missing SIB")?;
        cursor += 1;
        let scale = 1u8 << (sib >> 6);
        let index_raw = (sib >> 3) & 7;
        if index_raw != 4 {
            index = Some((index_raw | (((rex >> 1) & 1) << 3), scale));
        }
        let base_raw = sib & 7;
        if mode == 0 && base_raw == 5 {
            displacement = read_i32(bytes, cursor).map_err(|_| "missing SIB displacement")?;
            cursor += 4;
        } else {
            base = Some(base_raw | ((rex & 1) << 3));
        }
    } else if mode == 0 && rm_raw == 5 {
        displacement = read_i32(bytes, cursor).map_err(|_| "missing RIP displacement")?;
        cursor += 4;
        rip_relative = true;
    } else {
        base = Some(rm_field);
    }
    match mode {
        1 => {
            displacement = read_i8(bytes, cursor).map_err(|_| "missing byte displacement")?;
            cursor += 1;
        }
        2 => {
            displacement = read_i32(bytes, cursor).map_err(|_| "missing displacement")?;
            cursor += 4;
        }
        _ => {}
    }
    Ok(ParsedModRm {
        reg: reg_field,
        operand: RmOperand::Memory {
            base,
            index,
            displacement,
            rip_relative,
        },
        len: cursor - at,
    })
}

fn materialize_memory_address(
    instruction_end: u64,
    slot: u32,
    operand: RmOperand,
    ops: &mut Vec<PcodeOp>,
) -> Result<Varnode, &'static str> {
    let RmOperand::Memory {
        base,
        index,
        displacement,
        rip_relative,
    } = operand
    else {
        return Err("register operand has no memory address");
    };
    if let (Some(base), None) = (base, index) {
        if displacement == 0 {
            return Ok(reg(base, 8));
        }
    }
    let address = unique(instruction_end, slot, 8);
    if let Some(base) = base {
        if displacement == 0 {
            ops.push(p(op::COPY, Some(address), vec![reg(base, 8)]));
        } else {
            ops.push(p(
                op::INT_ADD,
                Some(address),
                vec![reg(base, 8), constant(displacement as u64, 8)],
            ));
        }
    } else {
        let absolute = if rip_relative {
            instruction_end.wrapping_add(displacement as u64)
        } else {
            displacement as u64
        };
        ops.push(p(op::COPY, Some(address), vec![constant(absolute, 8)]));
    }
    if let Some((index, scale)) = index {
        let index_value = if scale == 1 {
            reg(index, 8)
        } else {
            let shifted = unique(instruction_end, slot + 1, 8);
            ops.push(p(
                op::INT_LEFT,
                Some(shifted),
                vec![
                    reg(index, 8),
                    constant(u64::from(scale.trailing_zeros()), 1),
                ],
            ));
            shifted
        };
        ops.push(p(op::INT_ADD, Some(address), vec![address, index_value]));
    }
    Ok(address)
}

impl Lifter for X86_64 {
    fn architecture(&self) -> Architecture {
        Architecture::X86_64
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        let first = *bytes
            .first()
            .ok_or(LiftError::Truncated { address, needed: 1 })?;
        let mut at = 0usize;
        let mut rex = 0u8;
        if (0x40..=0x4f).contains(&first) {
            rex = first;
            at = 1;
        }
        let opcode = *bytes.get(at).ok_or(LiftError::Truncated {
            address,
            needed: at + 1,
        })?;
        let mut ops = Vec::new();
        let flow;
        let len;
        let width = if rex & 8 != 0 { 8 } else { 4 };

        match opcode {
            0x90 => {
                len = at + 1;
                flow = Flow::FallThrough(address + len as u64);
            }
            0xc3 => {
                x86_emit_return(&mut ops, 8);
                len = at + 1;
                flow = Flow::Return;
            }
            0xc2 => {
                let imm = bytes.get(at + 1..at + 3).ok_or(LiftError::Truncated {
                    address,
                    needed: at + 3,
                })?;
                let amount = u64::from(u16::from_le_bytes([imm[0], imm[1]]));
                x86_emit_return(&mut ops, 8 + amount);
                len = at + 3;
                flow = Flow::Return;
            }
            0x55 => {
                len = at + 1;
                ops.push(p(
                    op::INT_SUB,
                    Some(reg(4, 8)),
                    vec![reg(4, 8), constant(8, 8)],
                ));
                ops.push(p(
                    op::STORE,
                    None,
                    vec![x86_ram_space(4), reg(4, 8), reg(5, 8)],
                ));
                flow = Flow::FallThrough(address + len as u64);
            }
            0x5d => {
                len = at + 1;
                ops.push(p(
                    op::LOAD,
                    Some(reg(5, 8)),
                    vec![x86_ram_space(4), reg(4, 8)],
                ));
                ops.push(p(
                    op::INT_ADD,
                    Some(reg(4, 8)),
                    vec![reg(4, 8), constant(8, 8)],
                ));
                flow = Flow::FallThrough(address + len as u64);
            }
            0xc9 => {
                len = at + 1;
                ops.push(p(op::COPY, Some(reg(4, 8)), vec![reg(5, 8)]));
                ops.push(p(
                    op::LOAD,
                    Some(reg(5, 8)),
                    vec![x86_ram_space(4), reg(4, 8)],
                ));
                ops.push(p(
                    op::INT_ADD,
                    Some(reg(4, 8)),
                    vec![reg(4, 8), constant(8, 8)],
                ));
                flow = Flow::FallThrough(address + len as u64);
            }
            0x50..=0x57 => {
                let index = (opcode - 0x50) | ((rex & 1) << 3);
                len = at + 1;
                ops.push(p(
                    op::INT_SUB,
                    Some(reg(4, 8)),
                    vec![reg(4, 8), constant(8, 8)],
                ));
                ops.push(p(
                    op::STORE,
                    None,
                    vec![x86_ram_space(4), reg(4, 8), reg(index, 8)],
                ));
                flow = Flow::FallThrough(address + len as u64);
            }
            0x58..=0x5f => {
                let index = (opcode - 0x58) | ((rex & 1) << 3);
                len = at + 1;
                ops.push(p(
                    op::LOAD,
                    Some(reg(index, 8)),
                    vec![x86_ram_space(4), reg(4, 8)],
                ));
                ops.push(p(
                    op::INT_ADD,
                    Some(reg(4, 8)),
                    vec![reg(4, 8), constant(8, 8)],
                ));
                flow = Flow::FallThrough(address + len as u64);
            }
            0xb0..=0xb7 => {
                let index = (opcode - 0xb0) | ((rex & 1) << 3);
                let immediate = *bytes.get(at + 1).ok_or(LiftError::Truncated {
                    address,
                    needed: at + 2,
                })?;
                ops.push(p(
                    op::COPY,
                    Some(x86_byte_reg(index, rex)),
                    vec![constant(u64::from(immediate), 1)],
                ));
                len = at + 2;
                flow = Flow::FallThrough(address + len as u64);
            }
            0xb8..=0xbf => {
                let index = (opcode - 0xb8) | ((rex & 1) << 3);
                if width == 8 {
                    let b = bytes.get(at + 1..at + 9).ok_or(LiftError::Truncated {
                        address,
                        needed: at + 9,
                    })?;
                    ops.push(p(
                        op::COPY,
                        Some(reg(index, 8)),
                        vec![constant(u64::from_le_bytes(b.try_into().unwrap()), 8)],
                    ));
                    len = at + 9;
                } else {
                    let value = read_u32(bytes, at + 1).map_err(|_| LiftError::Truncated {
                        address,
                        needed: at + 5,
                    })?;
                    ops.push(p(op::COPY, Some(reg(index, 4)), vec![constant(value, 4)]));
                    len = at + 5;
                }
                flow = Flow::FallThrough(address + len as u64);
            }
            0x63 | 0x89 | 0x8b | 0x8d => {
                let parsed = decode_modrm(bytes, at + 1, rex).map_err(|reason| {
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason,
                    }
                })?;
                let instruction_len = at + 1 + parsed.len;
                let instruction_end = address.checked_add(instruction_len as u64).ok_or(
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "instruction address overflow",
                    },
                )?;
                match (opcode, parsed.operand) {
                    (0x63, RmOperand::Register(source)) => {
                        ops.push(p(
                            op::INT_SEXT,
                            Some(reg(parsed.reg, 8)),
                            vec![reg(source, 4)],
                        ));
                    }
                    (0x89, RmOperand::Register(destination)) => {
                        ops.push(p(
                            op::COPY,
                            Some(reg(destination, width)),
                            vec![reg(parsed.reg, width)],
                        ));
                    }
                    (0x8b, RmOperand::Register(source)) => {
                        ops.push(p(
                            op::COPY,
                            Some(reg(parsed.reg, width)),
                            vec![reg(source, width)],
                        ));
                    }
                    (0x8d, RmOperand::Register(source)) => {
                        ops.push(p(op::COPY, Some(reg(parsed.reg, 8)), vec![reg(source, 8)]));
                    }
                    (0x63, operand @ RmOperand::Memory { .. }) => {
                        let address_vn =
                            materialize_memory_address(instruction_end, 0, operand, &mut ops)
                                .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                        let loaded = unique(address, 0, 4);
                        ops.push(p(
                            op::LOAD,
                            Some(loaded),
                            vec![x86_ram_space(4), address_vn],
                        ));
                        ops.push(p(op::INT_SEXT, Some(reg(parsed.reg, 8)), vec![loaded]));
                    }
                    (0x89, operand @ RmOperand::Memory { .. }) => {
                        let address_vn =
                            materialize_memory_address(instruction_end, 0, operand, &mut ops)
                                .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                        ops.push(p(
                            op::STORE,
                            None,
                            vec![x86_ram_space(4), address_vn, reg(parsed.reg, width)],
                        ));
                    }
                    (0x8b, operand @ RmOperand::Memory { .. }) => {
                        let address_vn =
                            materialize_memory_address(instruction_end, 0, operand, &mut ops)
                                .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                        ops.push(p(
                            op::LOAD,
                            Some(reg(parsed.reg, width)),
                            vec![x86_ram_space(4), address_vn],
                        ));
                    }
                    (0x8d, operand @ RmOperand::Memory { .. }) => {
                        let address_vn =
                            materialize_memory_address(instruction_end, 0, operand, &mut ops)
                                .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                        ops.push(p(op::COPY, Some(reg(parsed.reg, 8)), vec![address_vn]));
                    }
                    _ => unreachable!("all opcode/operand combinations are covered"),
                }
                len = instruction_len;
                flow = Flow::FallThrough(instruction_end);
            }
            0x88 | 0x8a => {
                let parsed = decode_modrm(bytes, at + 1, rex).map_err(|reason| {
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason,
                    }
                })?;
                let instruction_len = at + 1 + parsed.len;
                let instruction_end = address.checked_add(instruction_len as u64).ok_or(
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "instruction address overflow",
                    },
                )?;
                match (opcode, parsed.operand) {
                    (0x88, RmOperand::Register(destination)) => {
                        ops.push(p(
                            op::COPY,
                            Some(x86_byte_reg(destination, rex)),
                            vec![x86_byte_reg(parsed.reg, rex)],
                        ));
                    }
                    (0x88, operand @ RmOperand::Memory { .. }) => {
                        let address_vn =
                            materialize_memory_address(instruction_end, 0, operand, &mut ops)
                                .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                        ops.push(p(
                            op::STORE,
                            None,
                            vec![x86_ram_space(4), address_vn, x86_byte_reg(parsed.reg, rex)],
                        ));
                    }
                    (0x8a, RmOperand::Register(source)) => {
                        ops.push(p(
                            op::COPY,
                            Some(x86_byte_reg(parsed.reg, rex)),
                            vec![x86_byte_reg(source, rex)],
                        ));
                    }
                    (0x8a, operand @ RmOperand::Memory { .. }) => {
                        let address_vn =
                            materialize_memory_address(instruction_end, 0, operand, &mut ops)
                                .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                        ops.push(p(
                            op::LOAD,
                            Some(x86_byte_reg(parsed.reg, rex)),
                            vec![x86_ram_space(4), address_vn],
                        ));
                    }
                    _ => unreachable!("all byte move combinations are covered"),
                }
                len = instruction_len;
                flow = Flow::FallThrough(instruction_end);
            }
            0x30 | 0x32 => {
                let parsed = decode_modrm(bytes, at + 1, rex).map_err(|reason| {
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason,
                    }
                })?;
                let instruction_len = at + 1 + parsed.len;
                let instruction_end = address.checked_add(instruction_len as u64).ok_or(
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "instruction address overflow",
                    },
                )?;
                let source = x86_byte_reg(parsed.reg, rex);
                let result = if opcode == 0x30 {
                    match parsed.operand {
                        RmOperand::Register(destination) => {
                            let destination = x86_byte_reg(destination, rex);
                            ops.push(p(op::INT_XOR, Some(destination), vec![destination, source]));
                            destination
                        }
                        operand @ RmOperand::Memory { .. } => {
                            let address_vn =
                                materialize_memory_address(instruction_end, 0, operand, &mut ops)
                                    .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                            let loaded = unique(address, 0, 1);
                            ops.push(p(
                                op::LOAD,
                                Some(loaded),
                                vec![x86_ram_space(4), address_vn],
                            ));
                            let result = unique(address, 1, 1);
                            ops.push(p(op::INT_XOR, Some(result), vec![loaded, source]));
                            ops.push(p(
                                op::STORE,
                                None,
                                vec![x86_ram_space(4), address_vn, result],
                            ));
                            result
                        }
                    }
                } else {
                    let destination = x86_byte_reg(parsed.reg, rex);
                    let operand = match parsed.operand {
                        RmOperand::Register(source) => x86_byte_reg(source, rex),
                        operand @ RmOperand::Memory { .. } => {
                            let address_vn =
                                materialize_memory_address(instruction_end, 0, operand, &mut ops)
                                    .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                            let loaded = unique(address, 0, 1);
                            ops.push(p(
                                op::LOAD,
                                Some(loaded),
                                vec![x86_ram_space(4), address_vn],
                            ));
                            loaded
                        }
                    };
                    ops.push(p(
                        op::INT_XOR,
                        Some(destination),
                        vec![destination, operand],
                    ));
                    destination
                };
                x86_set_test_flags(address, &mut ops, result);
                len = instruction_len;
                flow = Flow::FallThrough(instruction_end);
            }
            0xc6 => {
                let parsed = decode_modrm(bytes, at + 1, rex).map_err(|reason| {
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason,
                    }
                })?;
                if parsed.reg != 0 {
                    return Err(LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "C6 requires ModRM /0",
                    });
                }
                let immediate_at = at + 1 + parsed.len;
                let immediate = *bytes.get(immediate_at).ok_or(LiftError::Truncated {
                    address,
                    needed: immediate_at + 1,
                })?;
                let instruction_len = immediate_at + 1;
                let instruction_end = address.checked_add(instruction_len as u64).ok_or(
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "instruction address overflow",
                    },
                )?;
                match parsed.operand {
                    RmOperand::Register(destination) => {
                        ops.push(p(
                            op::COPY,
                            Some(x86_byte_reg(destination, rex)),
                            vec![constant(u64::from(immediate), 1)],
                        ));
                    }
                    operand @ RmOperand::Memory { .. } => {
                        let address_vn =
                            materialize_memory_address(instruction_end, 0, operand, &mut ops)
                                .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                        ops.push(p(
                            op::STORE,
                            None,
                            vec![
                                x86_ram_space(4),
                                address_vn,
                                constant(u64::from(immediate), 1),
                            ],
                        ));
                    }
                }
                len = instruction_len;
                flow = Flow::FallThrough(instruction_end);
            }
            0xc7 => {
                let parsed = decode_modrm(bytes, at + 1, rex).map_err(|reason| {
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason,
                    }
                })?;
                if parsed.reg != 0 {
                    return Err(LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "C7 requires ModRM /0",
                    });
                }
                let immediate_at = at + 1 + parsed.len;
                let raw = read_u32(bytes, immediate_at).map_err(|_| LiftError::Truncated {
                    address,
                    needed: immediate_at + 4,
                })?;
                let immediate = if width == 8 {
                    (raw as i32 as i64) as u64
                } else {
                    raw
                };
                let instruction_len = immediate_at + 4;
                let instruction_end = address.checked_add(instruction_len as u64).ok_or(
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "instruction address overflow",
                    },
                )?;
                let value = constant(immediate, width);
                match parsed.operand {
                    RmOperand::Register(destination) => {
                        ops.push(p(op::COPY, Some(reg(destination, width)), vec![value]));
                    }
                    operand @ RmOperand::Memory { .. } => {
                        let address_vn =
                            materialize_memory_address(instruction_end, 0, operand, &mut ops)
                                .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                        ops.push(p(
                            op::STORE,
                            None,
                            vec![x86_ram_space(4), address_vn, value],
                        ));
                    }
                }
                len = instruction_len;
                flow = Flow::FallThrough(instruction_end);
            }
            0xa8 | 0xa9 => {
                let size = if opcode == 0xa8 { 1 } else { width };
                let immediate_at = at + 1;
                let immediate = if opcode == 0xa8 {
                    u64::from(*bytes.get(immediate_at).ok_or(LiftError::Truncated {
                        address,
                        needed: immediate_at + 1,
                    })?)
                } else {
                    let raw = read_u32(bytes, immediate_at).map_err(|_| LiftError::Truncated {
                        address,
                        needed: immediate_at + 4,
                    })?;
                    if width == 8 {
                        i64::from(raw as i32) as u64
                    } else {
                        raw
                    }
                };
                len = at + if opcode == 0xa8 { 2 } else { 5 };
                let source = if opcode == 0xa8 {
                    x86_byte_reg(0, rex)
                } else {
                    reg(0, size)
                };
                let result = unique(address, 0, size);
                ops.push(p(
                    op::INT_AND,
                    Some(result),
                    vec![source, constant(immediate, size)],
                ));
                x86_set_test_flags(address, &mut ops, result);
                flow = Flow::FallThrough(address + len as u64);
            }
            0x84 | 0x85 => {
                let parsed = decode_modrm(bytes, at + 1, rex).map_err(|reason| {
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason,
                    }
                })?;
                let instruction_len = at + 1 + parsed.len;
                let instruction_end = address.checked_add(instruction_len as u64).ok_or(
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "instruction address overflow",
                    },
                )?;
                let size = if opcode == 0x84 { 1 } else { width };
                let source = if opcode == 0x84 {
                    x86_byte_reg(parsed.reg, rex)
                } else {
                    reg(parsed.reg, size)
                };
                let operand = match parsed.operand {
                    RmOperand::Register(index) => {
                        if opcode == 0x84 {
                            x86_byte_reg(index, rex)
                        } else {
                            reg(index, size)
                        }
                    }
                    operand @ RmOperand::Memory { .. } => {
                        let address_vn =
                            materialize_memory_address(instruction_end, 0, operand, &mut ops)
                                .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                        let loaded = unique(address, 0, size);
                        ops.push(p(
                            op::LOAD,
                            Some(loaded),
                            vec![x86_ram_space(4), address_vn],
                        ));
                        loaded
                    }
                };
                let result = unique(address, 1, size);
                ops.push(p(op::INT_AND, Some(result), vec![operand, source]));
                x86_set_test_flags(address, &mut ops, result);
                len = instruction_len;
                flow = Flow::FallThrough(instruction_end);
            }
            0x31 | 0x33 | 0x01 | 0x03 | 0x29 | 0x2b | 0x39 | 0x3b => {
                let parsed = decode_modrm(bytes, at + 1, rex).map_err(|reason| {
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason,
                    }
                })?;
                let instruction_len = at + 1 + parsed.len;
                let instruction_end = address.checked_add(instruction_len as u64).ok_or(
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "instruction address overflow",
                    },
                )?;
                let (rm_value, memory_address) = match parsed.operand {
                    RmOperand::Register(index) => (reg(index, width), None),
                    operand @ RmOperand::Memory { .. } => {
                        let address_vn =
                            materialize_memory_address(instruction_end, 0, operand, &mut ops)
                                .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                        let loaded = unique(address, 0, width);
                        ops.push(p(
                            op::LOAD,
                            Some(loaded),
                            vec![x86_ram_space(4), address_vn],
                        ));
                        (loaded, Some(address_vn))
                    }
                };
                let reg_value = reg(parsed.reg, width);
                let destination_is_rm = matches!(opcode, 0x31 | 0x01 | 0x29 | 0x39);
                let (destination, source, code) = match opcode {
                    0x31 => (rm_value, reg_value, op::INT_XOR),
                    0x33 => (reg_value, rm_value, op::INT_XOR),
                    0x01 => (rm_value, reg_value, op::INT_ADD),
                    0x03 => (reg_value, rm_value, op::INT_ADD),
                    0x29 => (rm_value, reg_value, op::INT_SUB),
                    0x2b => (reg_value, rm_value, op::INT_SUB),
                    0x39 => (rm_value, reg_value, op::INT_SUB),
                    0x3b => (reg_value, rm_value, op::INT_SUB),
                    _ => unreachable!(),
                };
                let is_compare = matches!(opcode, 0x39 | 0x3b);
                let result = if is_compare || (destination_is_rm && memory_address.is_some()) {
                    unique(address, if memory_address.is_some() { 1 } else { 0 }, width)
                } else {
                    destination
                };
                ops.push(p(code, Some(result), vec![destination, source]));
                if is_compare {
                    ops.push(p(
                        op::INT_EQUAL,
                        Some(flag(518)),
                        vec![result, constant(0, width)],
                    ));
                } else if destination_is_rm {
                    if let Some(address_vn) = memory_address {
                        ops.push(p(
                            op::STORE,
                            None,
                            vec![x86_ram_space(4), address_vn, result],
                        ));
                    }
                }
                ops.push(p(
                    op::INT_SLESS,
                    Some(flag(519)),
                    vec![result, constant(0, width)],
                ));
                len = instruction_len;
                flow = Flow::FallThrough(instruction_end);
            }
            0x81 | 0x83 => {
                let parsed = decode_modrm(bytes, at + 1, rex).map_err(|reason| {
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason,
                    }
                })?;
                let immediate_at = at + 1 + parsed.len;
                let immediate = if opcode == 0x81 {
                    let raw = read_u32(bytes, immediate_at).map_err(|_| LiftError::Truncated {
                        address,
                        needed: immediate_at + 4,
                    })?;
                    if width == 8 {
                        i64::from(raw as i32) as u64
                    } else {
                        raw
                    }
                } else {
                    let signed =
                        read_i8(bytes, immediate_at).map_err(|_| LiftError::Truncated {
                            address,
                            needed: immediate_at + 1,
                        })?;
                    if width == 8 {
                        signed as u64
                    } else {
                        (signed as i32 as u32) as u64
                    }
                };
                let instruction_len = immediate_at + if opcode == 0x81 { 4 } else { 1 };
                let instruction_end = address.checked_add(instruction_len as u64).ok_or(
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "instruction address overflow",
                    },
                )?;
                let (operand, memory_address) = match parsed.operand {
                    RmOperand::Register(index) => (reg(index, width), None),
                    operand @ RmOperand::Memory { .. } => {
                        let address_vn =
                            materialize_memory_address(instruction_end, 0, operand, &mut ops)
                                .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                        let loaded = unique(address, 0, width);
                        ops.push(p(
                            op::LOAD,
                            Some(loaded),
                            vec![x86_ram_space(4), address_vn],
                        ));
                        (loaded, Some(address_vn))
                    }
                };
                let immediate = constant(immediate, width);
                match parsed.reg {
                    0 => {
                        let result = if memory_address.is_some() {
                            unique(address, 1, width)
                        } else {
                            operand
                        };
                        x86_add_flag_prefix(&mut ops, operand, immediate);
                        ops.push(p(op::INT_ADD, Some(result), vec![operand, immediate]));
                        x86_add_flag_suffix(address, &mut ops, result);
                        if let Some(address_vn) = memory_address {
                            ops.push(p(
                                op::STORE,
                                None,
                                vec![x86_ram_space(4), address_vn, result],
                            ));
                        }
                    }
                    5 => {
                        let result = if memory_address.is_some() {
                            unique(address, 1, width)
                        } else {
                            operand
                        };
                        ops.push(p(op::INT_SUB, Some(result), vec![operand, immediate]));
                        ops.push(p(
                            op::INT_SLESS,
                            Some(flag(519)),
                            vec![result, constant(0, width)],
                        ));
                        if let Some(address_vn) = memory_address {
                            ops.push(p(
                                op::STORE,
                                None,
                                vec![x86_ram_space(4), address_vn, result],
                            ));
                        }
                    }
                    7 => {
                        let result =
                            unique(address, if memory_address.is_some() { 1 } else { 0 }, width);
                        ops.push(p(op::INT_SUB, Some(result), vec![operand, immediate]));
                        ops.push(p(
                            op::INT_EQUAL,
                            Some(flag(518)),
                            vec![result, constant(0, width)],
                        ));
                        ops.push(p(
                            op::INT_SLESS,
                            Some(flag(519)),
                            vec![result, constant(0, width)],
                        ));
                    }
                    4 => {
                        let result = if memory_address.is_some() {
                            unique(address, 1, width)
                        } else {
                            operand
                        };
                        ops.push(p(op::INT_AND, Some(result), vec![operand, immediate]));
                        x86_set_test_flags(address, &mut ops, result);
                        if let Some(address_vn) = memory_address {
                            ops.push(p(
                                op::STORE,
                                None,
                                vec![x86_ram_space(4), address_vn, result],
                            ));
                        }
                    }
                    _ => {
                        return Err(LiftError::Unsupported {
                            architecture: self.architecture(),
                            address,
                            opcode,
                        });
                    }
                }
                len = instruction_len;
                flow = Flow::FallThrough(instruction_end);
            }
            0xe8 => {
                let displacement = read_i32(bytes, at + 1).map_err(|_| LiftError::Truncated {
                    address,
                    needed: at + 5,
                })?;
                len = at + 5;
                let target =
                    target(address, len, displacement).map_err(|_| LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "call target overflow",
                    })?;
                ops.push(p(op::CALL, None, vec![constant(target, 8)]));
                flow = Flow::Call {
                    target,
                    fallthrough: address + len as u64,
                };
            }
            0xe9 => {
                let displacement = read_i32(bytes, at + 1).map_err(|_| LiftError::Truncated {
                    address,
                    needed: at + 5,
                })?;
                len = at + 5;
                let target =
                    target(address, len, displacement).map_err(|_| LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "jump target overflow",
                    })?;
                ops.push(p(op::BRANCH, None, vec![constant(target, 8)]));
                flow = Flow::Jump(target);
            }
            0xeb => {
                let displacement = read_i8(bytes, at + 1).map_err(|_| LiftError::Truncated {
                    address,
                    needed: at + 2,
                })?;
                len = at + 2;
                let target =
                    target(address, len, displacement).map_err(|_| LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "jump target overflow",
                    })?;
                ops.push(p(op::BRANCH, None, vec![constant(target, 8)]));
                flow = Flow::Jump(target);
            }
            0x0f => {
                let secondary = *bytes.get(at + 1).ok_or(LiftError::Truncated {
                    address,
                    needed: at + 2,
                })?;
                if matches!(secondary, 0x10 | 0x11 | 0x28 | 0x29) {
                    let parsed = decode_modrm(bytes, at + 2, rex).map_err(|reason| {
                        LiftError::InvalidEncoding {
                            architecture: self.architecture(),
                            address,
                            reason,
                        }
                    })?;
                    let instruction_len = at + 2 + parsed.len;
                    let instruction_end = address.checked_add(instruction_len as u64).ok_or(
                        LiftError::InvalidEncoding {
                            architecture: self.architecture(),
                            address,
                            reason: "instruction address overflow",
                        },
                    )?;
                    let destination = x86_xmm_reg(parsed.reg);
                    let stores = matches!(secondary, 0x11 | 0x29);
                    if stores {
                        match parsed.operand {
                            RmOperand::Register(destination_register) => {
                                ops.push(p(
                                    op::COPY,
                                    Some(x86_xmm_reg(destination_register)),
                                    vec![destination],
                                ));
                            }
                            operand @ RmOperand::Memory { .. } => {
                                let address_vn = materialize_memory_address(
                                    instruction_end,
                                    0,
                                    operand,
                                    &mut ops,
                                )
                                .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                                ops.push(p(
                                    op::STORE,
                                    None,
                                    vec![x86_ram_space(4), address_vn, destination],
                                ));
                            }
                        }
                    } else {
                        match parsed.operand {
                            RmOperand::Register(source) => {
                                ops.push(p(op::COPY, Some(destination), vec![x86_xmm_reg(source)]));
                            }
                            operand @ RmOperand::Memory { .. } => {
                                let address_vn = materialize_memory_address(
                                    instruction_end,
                                    0,
                                    operand,
                                    &mut ops,
                                )
                                .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                                ops.push(p(
                                    op::LOAD,
                                    Some(destination),
                                    vec![x86_ram_space(4), address_vn],
                                ));
                            }
                        }
                    }
                    len = instruction_len;
                    flow = Flow::FallThrough(instruction_end);
                } else if (0x40..=0x4f).contains(&secondary) {
                    let (reg_field, rm) = modrm_register(bytes, at + 2, rex).map_err(|reason| {
                        LiftError::InvalidEncoding {
                            architecture: self.architecture(),
                            address,
                            reason,
                        }
                    })?;
                    let condition = x86_condition(secondary & 0x0f, address, &mut ops).ok_or(
                        LiftError::Unsupported {
                            architecture: self.architecture(),
                            address,
                            opcode: secondary,
                        },
                    )?;
                    ops.push(p(
                        op::CMOV,
                        Some(reg(reg_field, width)),
                        vec![condition, reg(rm, width), reg(reg_field, width)],
                    ));
                    len = at + 3;
                    flow = Flow::FallThrough(address + len as u64);
                } else if (0x80..=0x8f).contains(&secondary) {
                    let displacement =
                        read_i32(bytes, at + 2).map_err(|_| LiftError::Truncated {
                            address,
                            needed: at + 6,
                        })?;
                    len = at + 6;
                    let target = target(address, len, displacement).map_err(|_| {
                        LiftError::InvalidEncoding {
                            architecture: self.architecture(),
                            address,
                            reason: "conditional target overflow",
                        }
                    })?;
                    let condition = x86_condition(secondary & 0x0f, address, &mut ops).ok_or(
                        LiftError::Unsupported {
                            architecture: self.architecture(),
                            address,
                            opcode: secondary,
                        },
                    )?;
                    ops.push(p(op::CBRANCH, None, vec![constant(target, 8), condition]));
                    flow = Flow::Conditional {
                        target,
                        fallthrough: address + len as u64,
                    };
                } else {
                    return Err(LiftError::Unsupported {
                        architecture: self.architecture(),
                        address,
                        opcode: secondary,
                    });
                }
            }
            0xff => {
                let parsed = decode_modrm(bytes, at + 1, rex).map_err(|reason| {
                    LiftError::InvalidEncoding {
                        address,
                        architecture: self.architecture(),
                        reason,
                    }
                })?;
                let instruction_len = at + 1 + parsed.len;
                let instruction_end = address.checked_add(instruction_len as u64).ok_or(
                    LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "instruction address overflow",
                    },
                )?;
                let target = match parsed.operand {
                    RmOperand::Register(index) => reg(index, 8),
                    operand @ RmOperand::Memory { .. } => {
                        let address_vn =
                            materialize_memory_address(instruction_end, 0, operand, &mut ops)
                                .map_err(|reason| LiftError::InvalidEncoding {
                                    architecture: self.architecture(),
                                    address,
                                    reason,
                                })?;
                        let loaded = unique(address, 0, 8);
                        ops.push(p(
                            op::LOAD,
                            Some(loaded),
                            vec![x86_ram_space(4), address_vn],
                        ));
                        loaded
                    }
                };
                match parsed.reg {
                    2 => {
                        ops.push(p(op::CALLIND, None, vec![target]));
                        len = instruction_len;
                        flow = Flow::FallThrough(instruction_end);
                    }
                    4 => {
                        ops.push(p(op::BRANCHIND, None, vec![target]));
                        len = instruction_len;
                        flow = Flow::Return;
                    }
                    _ => {
                        return Err(LiftError::Unsupported {
                            architecture: self.architecture(),
                            address,
                            opcode,
                        });
                    }
                }
            }
            0x70..=0x7f => {
                let displacement = read_i8(bytes, at + 1).map_err(|_| LiftError::Truncated {
                    address,
                    needed: at + 2,
                })?;
                len = at + 2;
                let target =
                    target(address, len, displacement).map_err(|_| LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "conditional target overflow",
                    })?;
                let condition = x86_condition(opcode & 0x0f, address, &mut ops).ok_or(
                    LiftError::Unsupported {
                        architecture: self.architecture(),
                        address,
                        opcode,
                    },
                )?;
                ops.push(p(op::CBRANCH, None, vec![constant(target, 8), condition]));
                flow = Flow::Conditional {
                    target,
                    fallthrough: address + len as u64,
                };
            }
            _ => {
                return Err(LiftError::Unsupported {
                    architecture: self.architecture(),
                    address,
                    opcode,
                });
            }
        }

        let bytes = bytes
            .get(..len)
            .ok_or(LiftError::Truncated {
                address,
                needed: len,
            })?
            .to_vec();
        let pcode = InstPcode {
            len: len as u32,
            space: RAM_SPACE,
            offset: address,
            ops,
        };
        Ok(LiftedInstruction {
            address,
            bytes,
            pcode,
            flow,
        })
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct AArch64;

impl Lifter for AArch64 {
    fn architecture(&self) -> Architecture {
        Architecture::AArch64
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        if bytes.len() < 4 {
            return Err(LiftError::Truncated { address, needed: 4 });
        }
        let word = u32::from_le_bytes(bytes[..4].try_into().expect("four bytes"));
        let next = address.wrapping_add(4);
        let mut ops = Vec::new();
        let flow;
        if word == 0xd503201f {
            flow = Flow::FallThrough(next);
        } else if word & 0xffff_fc1f == 0xd65f_0000 {
            let rn = ((word >> 5) & 0x1f) as u8;
            let pc = Varnode::new(REGISTER_SPACE, 0, 8);
            ops.push(p(op::COPY, Some(pc), vec![aarch64_reg(rn, 8)]));
            ops.push(p(op::RETURN, None, vec![pc]));
            flow = Flow::Return;
        } else if word & 0xffff_fc1f == 0xd61f_0000 {
            let rn = ((word >> 5) & 0x1f) as u8;
            ops.push(p(op::BRANCHIND, None, vec![aarch64_reg(rn, 8)]));
            flow = Flow::Return;
        } else if word & 0xffff_fc1f == 0xd63f_0000 {
            let rn = ((word >> 5) & 0x1f) as u8;
            ops.push(p(op::CALLIND, None, vec![aarch64_reg(rn, 8)]));
            flow = Flow::FallThrough(next);
        } else if word & 0xfc00_0000 == 0x1400_0000 {
            let raw = i64::from(word & 0x03ff_ffff);
            let displacement = if raw & (1 << 25) != 0 {
                raw - (1 << 26)
            } else {
                raw
            } << 2;
            let target = u64::try_from(i128::from(address).wrapping_add(i128::from(displacement)))
                .map_err(|_| LiftError::InvalidEncoding {
                    architecture: self.architecture(),
                    address,
                    reason: "branch target overflow",
                })?;
            ops.push(p(op::BRANCH, None, vec![constant(target, 8)]));
            flow = Flow::Jump(target);
        } else if word & 0xfc00_0000 == 0x9400_0000 {
            let raw = i64::from(word & 0x03ff_ffff);
            let displacement = if raw & (1 << 25) != 0 {
                raw - (1 << 26)
            } else {
                raw
            } << 2;
            let target = u64::try_from(i128::from(address).wrapping_add(i128::from(displacement)))
                .map_err(|_| LiftError::InvalidEncoding {
                    architecture: self.architecture(),
                    address,
                    reason: "call target overflow",
                })?;
            ops.push(p(op::CALL, None, vec![constant(target, 8)]));
            flow = Flow::Call {
                target,
                fallthrough: next,
            };
        } else if word & 0xff00_0010 == 0x5400_0000 {
            let raw = i64::from((word >> 5) & 0x7ffff);
            let immediate = if raw & (1 << 18) != 0 {
                raw - (1 << 19)
            } else {
                raw
            };
            let target =
                u64::try_from(i128::from(address).wrapping_add(i128::from(immediate << 2)))
                    .map_err(|_| LiftError::InvalidEncoding {
                        architecture: self.architecture(),
                        address,
                        reason: "conditional target overflow",
                    })?;
            let condition = match word & 0xf {
                0 => aarch64_flag(257),
                1 => {
                    let inverted = unique(address, 1, 1);
                    ops.push(p(op::BOOL_NEGATE, Some(inverted), vec![aarch64_flag(257)]));
                    inverted
                }
                _ => {
                    return Err(LiftError::Unsupported {
                        architecture: self.architecture(),
                        address,
                        opcode: (word >> 24) as u8,
                    });
                }
            };
            ops.push(p(op::CBRANCH, None, vec![constant(target, 8), condition]));
            flow = Flow::Conditional {
                target,
                fallthrough: next,
            };
        } else if word & 0x7f00_0000 == 0x3400_0000 {
            let raw = i64::from((word >> 5) & 0x7ffff);
            let displacement = if raw & (1 << 18) != 0 {
                raw - (1 << 19)
            } else {
                raw
            } << 2;
            let target = u64::try_from(i128::from(address).wrapping_add(i128::from(displacement)))
                .map_err(|_| LiftError::InvalidEncoding {
                    architecture: self.architecture(),
                    address,
                    reason: "conditional target overflow",
                })?;
            let rt = (word & 0x1f) as u8;
            let mut condition = unique(address, 0, 1);
            ops.push(p(
                op::INT_EQUAL,
                Some(condition),
                vec![
                    aarch64_reg(rt, if word & (1 << 31) != 0 { 8 } else { 4 }),
                    constant(0, if word & (1 << 31) != 0 { 8 } else { 4 }),
                ],
            ));
            if word & 0x0100_0000 != 0 {
                let inverted = unique(address, 1, 1);
                ops.push(p(op::BOOL_NEGATE, Some(inverted), vec![condition]));
                condition = inverted;
            }
            ops.push(p(op::CBRANCH, None, vec![constant(target, 8), condition]));
            flow = Flow::Conditional {
                target,
                fallthrough: next,
            };
        } else if word & 0x1f00_0000 == 0x1100_0000 {
            let sf = if word & (1 << 31) != 0 { 8 } else { 4 };
            let immediate =
                u64::from((word >> 10) & 0xfff) << if word & (1 << 22) != 0 { 12 } else { 0 };
            let rn = ((word >> 5) & 0x1f) as u8;
            let rd = (word & 0x1f) as u8;
            if word & (1 << 30) == 0 {
                let immediate_vn = unique(address, 0, sf);
                ops.push(p(
                    op::COPY,
                    Some(immediate_vn),
                    vec![constant(immediate, sf)],
                ));
                let result = unique(address, 1, sf);
                ops.push(p(
                    op::INT_CARRY,
                    Some(aarch64_flag(261)),
                    vec![aarch64_reg(rn, sf), immediate_vn],
                ));
                ops.push(p(
                    op::INT_SCARRY,
                    Some(aarch64_flag(262)),
                    vec![aarch64_reg(rn, sf), immediate_vn],
                ));
                ops.push(p(
                    op::INT_ADD,
                    Some(result),
                    vec![aarch64_reg(rn, sf), immediate_vn],
                ));
                ops.push(p(
                    op::INT_SLESS,
                    Some(aarch64_flag(263)),
                    vec![result, constant(0, sf)],
                ));
                ops.push(p(
                    op::INT_EQUAL,
                    Some(aarch64_flag(264)),
                    vec![result, constant(0, sf)],
                ));
                ops.push(p(op::COPY, Some(aarch64_reg(rd, sf)), vec![result]));
            } else {
                ops.push(p(
                    op::INT_SUB,
                    Some(aarch64_reg(rd, sf)),
                    vec![aarch64_reg(rn, sf), constant(immediate, sf)],
                ));
            }
            flow = Flow::FallThrough(next);
        } else if word & 0xffe0_ffe0 == 0xaa00_03e0 {
            let rd = (word & 0x1f) as u8;
            let rn = ((word >> 5) & 0x1f) as u8;
            let rm = ((word >> 16) & 0x1f) as u8;
            ops.push(p(
                op::COPY,
                Some(aarch64_reg(rd, 8)),
                vec![aarch64_reg(rm, 8)],
            ));
            let _ = rn;
            flow = Flow::FallThrough(next);
        } else if word & 0x3b00_0000 == 0x3900_0000 {
            let is_load = word & (1 << 22) != 0;
            let size_code = (word >> 30) & 3;
            let size = 1u32 << size_code;
            let offset = u64::from((word >> 10) & 0xfff) * u64::from(size);
            let rn = ((word >> 5) & 0x1f) as u8;
            let rt = (word & 0x1f) as u8;
            let address_vn = unique(address, 0, 8);
            if offset == 0 {
                ops.push(p(op::COPY, Some(address_vn), vec![aarch64_reg(rn, 8)]));
            } else {
                ops.push(p(
                    op::INT_ADD,
                    Some(address_vn),
                    vec![aarch64_reg(rn, 8), constant(offset, 8)],
                ));
            }
            if is_load {
                ops.push(p(
                    op::LOAD,
                    Some(aarch64_reg(rt, size)),
                    vec![constant(433, 8), address_vn],
                ));
            } else {
                ops.push(p(
                    op::STORE,
                    None,
                    vec![constant(433, 8), address_vn, aarch64_reg(rt, size)],
                ));
            }
            flow = Flow::FallThrough(next);
        } else {
            return Err(LiftError::Unsupported {
                architecture: self.architecture(),
                address,
                opcode: (word >> 24) as u8,
            });
        }
        Ok(LiftedInstruction {
            address,
            bytes: bytes[..4].to_vec(),
            pcode: InstPcode {
                len: 4,
                space: RAM_SPACE,
                offset: address,
                ops,
            },
            flow,
        })
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Mips32;

fn mips_reg(index: u8, size: u32) -> Varnode {
    Varnode::new(REGISTER_SPACE, u64::from(index) * 4, size)
}
fn mips_register(offset: u64, size: u32) -> Varnode {
    Varnode::new(REGISTER_SPACE, offset, size)
}

fn mips_o32_call_inputs(target: Varnode) -> Vec<Varnode> {
    vec![
        target,
        mips_reg(4, 4),
        mips_reg(5, 4),
        mips_reg(6, 4),
        mips_reg(7, 4),
        mips_register(0x200 + 12 * 4, 4),
        mips_register(0x200 + 14 * 4, 4),
    ]
}
fn mips_ram_space(size: u32) -> Varnode {
    constant(417, size)
}
fn mips_branch_target(address: u64, immediate: i64) -> u64 {
    address
        .wrapping_add(4)
        .wrapping_add(immediate.wrapping_mul(4) as u64)
}

fn mips_address(address: u64, base: u8, immediate: i64, ops: &mut Vec<PcodeOp>) -> Varnode {
    let address_vn = unique(address, 0, 4);
    ops.push(p(
        op::INT_ADD,
        Some(address_vn),
        vec![mips_reg(base, 4), constant(immediate as u64, 4)],
    ));
    address_vn
}

fn mips_branch_condition(
    address: u64,
    opcode: u32,
    rs: u8,
    rt: u8,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let condition = unique(address, 1, 1);
    match opcode {
        4 | 20 => ops.push(p(
            op::INT_EQUAL,
            Some(condition),
            vec![mips_reg(rs, 4), mips_reg(rt, 4)],
        )),
        5 | 21 => {
            let equal = unique(address, 2, 1);
            ops.push(p(
                op::INT_EQUAL,
                Some(equal),
                vec![mips_reg(rs, 4), mips_reg(rt, 4)],
            ));
            ops.push(p(op::BOOL_NEGATE, Some(condition), vec![equal]));
        }
        6 | 22 => ops.push(p(
            op::INT_SLESSEQUAL,
            Some(condition),
            vec![mips_reg(rs, 4), constant(0, 4)],
        )),
        7 | 23 => ops.push(p(
            op::INT_SLESS,
            Some(condition),
            vec![constant(0, 4), mips_reg(rs, 4)],
        )),
        _ => return None,
    }
    Some(condition)
}

fn mips_extend_load(
    address: u64,
    rt: u8,
    width: u32,
    signed: bool,
    address_vn: Varnode,
    ops: &mut Vec<PcodeOp>,
) {
    let loaded = if width == 4 {
        mips_reg(rt, 4)
    } else {
        unique(address, 2, width)
    };
    ops.push(p(
        op::LOAD,
        Some(loaded),
        vec![mips_ram_space(8), address_vn],
    ));
    if width < 4 {
        ops.push(p(
            if signed { op::INT_SEXT } else { op::INT_ZEXT },
            Some(mips_reg(rt, 4)),
            vec![loaded],
        ));
    }
}

fn mips_memory(
    address: u64,
    base: u8,
    rt: u8,
    immediate: i64,
    width: u32,
    load: bool,
    signed: bool,
    ops: &mut Vec<PcodeOp>,
) {
    let address_vn = mips_address(address, base, immediate, ops);
    if load {
        if width < 4 {
            mips_extend_load(address, rt, width, signed, address_vn, ops);
        } else {
            ops.push(p(
                op::LOAD,
                Some(mips_reg(rt, width)),
                vec![mips_ram_space(8), address_vn],
            ));
        }
    } else {
        ops.push(p(
            op::STORE,
            None,
            vec![mips_ram_space(8), address_vn, mips_reg(rt, width)],
        ));
    }
}

fn mips_unsupported(address: u64, opcode: u32) -> LiftError {
    LiftError::Unsupported {
        architecture: Architecture::Mips32,
        address,
        opcode: opcode as u8,
    }
}

fn mips_return(address: u64, ops: &mut Vec<PcodeOp>) {
    let target = unique(address, 0, 4);
    ops.push(p(
        op::INT_AND,
        Some(target),
        vec![mips_reg(31, 4), constant(1, 4)],
    ));
    let likely = mips_register(16128, 1);
    ops.push(p(
        op::INT_NOTEQUAL,
        Some(likely),
        vec![target, constant(0, 4)],
    ));
    ops.push(p(op::CALLOTHER, None, vec![constant(0, 4), likely]));
    let return_target = unique(address, 1, 4);
    ops.push(p(op::INT_2COMP, Some(return_target), vec![constant(2, 4)]));
    ops.push(p(
        op::INT_AND,
        Some(return_target),
        vec![return_target, mips_reg(31, 4)],
    ));
    let pc = mips_register(128, 4);
    ops.push(p(op::COPY, Some(pc), vec![return_target]));
    ops.push(p(op::RETURN, None, vec![pc]));
}

impl Lifter for Mips32 {
    fn architecture(&self) -> Architecture {
        Architecture::Mips32
    }

    fn has_delay_slot(&self) -> bool {
        true
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        if bytes.len() < 4 {
            return Err(LiftError::Truncated { address, needed: 4 });
        }
        let word = u32::from_le_bytes(bytes[..4].try_into().expect("four bytes"));
        let next = address.wrapping_add(4);
        let opcode = (word >> 26) & 0x3f;
        let rs = ((word >> 21) & 0x1f) as u8;
        let rt = ((word >> 16) & 0x1f) as u8;
        let rd = ((word >> 11) & 0x1f) as u8;
        let sa = ((word >> 6) & 0x1f) as u8;
        let funct = (word & 0x3f) as u8;
        let immediate = i64::from(i16::from_be_bytes([(word >> 8) as u8, word as u8]));
        let mut ops = Vec::new();
        let flow;

        match opcode {
            0 => match funct {
                0 => {
                    if word == 0 {
                        flow = Flow::FallThrough(next);
                    } else {
                        ops.push(p(
                            op::INT_LEFT,
                            Some(mips_reg(rd, 4)),
                            vec![mips_reg(rt, 4), constant(u64::from(sa), 4)],
                        ));
                        flow = Flow::FallThrough(next);
                    }
                }
                2 | 3 => {
                    ops.push(p(
                        if funct == 2 {
                            op::INT_RIGHT
                        } else {
                            op::INT_SRIGHT
                        },
                        Some(mips_reg(rd, 4)),
                        vec![mips_reg(rt, 4), constant(u64::from(sa), 4)],
                    ));
                    flow = Flow::FallThrough(next);
                }
                4 | 6 | 7 => {
                    ops.push(p(
                        match funct {
                            4 => op::INT_LEFT,
                            6 => op::INT_RIGHT,
                            _ => op::INT_SRIGHT,
                        },
                        Some(mips_reg(rd, 4)),
                        vec![mips_reg(rt, 4), mips_reg(rs, 4)],
                    ));
                    flow = Flow::FallThrough(next);
                }
                8 => {
                    if rs == 31 {
                        mips_return(address, &mut ops);
                        flow = Flow::Return;
                    } else {
                        ops.push(p(op::BRANCHIND, None, vec![mips_reg(rs, 4)]));
                        flow = Flow::Return;
                    }
                }
                9 => {
                    ops.push(p(
                        op::CALLIND,
                        Some(mips_reg(2, 4)),
                        mips_o32_call_inputs(mips_reg(rs, 4)),
                    ));
                    flow = Flow::FallThrough(next);
                }
                10 | 11 => {
                    let condition = unique(address, 3, 1);
                    ops.push(p(
                        if funct == 10 {
                            op::INT_EQUAL
                        } else {
                            op::INT_NOTEQUAL
                        },
                        Some(condition),
                        vec![mips_reg(rt, 4), constant(0, 4)],
                    ));
                    ops.push(p(
                        op::CMOV,
                        Some(mips_reg(rd, 4)),
                        vec![condition, mips_reg(rs, 4), mips_reg(rd, 4)],
                    ));
                    flow = Flow::FallThrough(next);
                }
                12 | 13 => {
                    ops.push(p(op::CALLOTHER, None, vec![constant(u64::from(funct), 4)]));
                    flow = Flow::FallThrough(next);
                }
                15 => flow = Flow::FallThrough(next),
                16 | 17 | 18 | 19 => {
                    let special =
                        mips_register(if funct == 16 || funct == 17 { 132 } else { 136 }, 4);
                    if funct == 16 || funct == 18 {
                        ops.push(p(op::COPY, Some(mips_reg(rd, 4)), vec![special]));
                    } else {
                        ops.push(p(op::COPY, Some(special), vec![mips_reg(rs, 4)]));
                    }
                    flow = Flow::FallThrough(next);
                }
                24 | 25 => {
                    let left = unique(address, 6, 8);
                    let right = unique(address, 7, 8);
                    let product = unique(address, 8, 8);
                    let lo = mips_register(136, 4);
                    let hi = mips_register(132, 4);
                    let extension = if funct == 24 {
                        op::INT_SEXT
                    } else {
                        op::INT_ZEXT
                    };
                    ops.push(p(extension, Some(left), vec![mips_reg(rs, 4)]));
                    ops.push(p(extension, Some(right), vec![mips_reg(rt, 4)]));
                    ops.push(p(op::INT_MULT, Some(product), vec![left, right]));
                    ops.push(p(op::SUBPIECE, Some(lo), vec![product, constant(0, 4)]));
                    ops.push(p(op::SUBPIECE, Some(hi), vec![product, constant(4, 4)]));
                    if rd != 0 {
                        ops.push(p(op::COPY, Some(mips_reg(rd, 4)), vec![lo]));
                    }
                    flow = Flow::FallThrough(next);
                }
                32 | 33 | 34 | 35 | 36 | 37 | 38 | 39 | 42 | 43 | 44 | 45 | 46 | 47 => {
                    let width = if funct >= 44 { 8 } else { 4 };
                    let code = match funct {
                        32 | 33 | 44 | 45 => op::INT_ADD,
                        34 | 35 | 46 | 47 => op::INT_SUB,
                        36 => op::INT_AND,
                        37 => op::INT_OR,
                        38 => op::INT_XOR,
                        42 => op::INT_SLESS,
                        43 => op::INT_LESS,
                        39 => op::INT_OR,
                        _ => unreachable!(),
                    };
                    if funct == 39 {
                        let inverted = unique(address, 5, width);
                        ops.push(p(
                            code,
                            Some(inverted),
                            vec![mips_reg(rs, width), mips_reg(rt, width)],
                        ));
                        ops.push(p(
                            op::INT_XOR,
                            Some(mips_reg(rd, width)),
                            vec![inverted, constant(u64::MAX, width)],
                        ));
                    } else {
                        ops.push(p(
                            code,
                            Some(mips_reg(rd, width)),
                            vec![mips_reg(rs, width), mips_reg(rt, width)],
                        ));
                    }
                    flow = Flow::FallThrough(next);
                }
                _ => return Err(mips_unsupported(address, opcode)),
            },
            1 => {
                let condition = unique(address, 4, 1);
                match rt {
                    0 | 2 | 16 | 18 => ops.push(p(
                        op::INT_SLESS,
                        Some(condition),
                        vec![mips_reg(rs, 4), constant(0, 4)],
                    )),
                    1 | 3 | 17 | 19 => ops.push(p(
                        op::INT_SLESSEQUAL,
                        Some(condition),
                        vec![constant(0, 4), mips_reg(rs, 4)],
                    )),
                    _ => return Err(mips_unsupported(address, opcode)),
                }
                if rt >= 16 {
                    ops.push(p(
                        op::COPY,
                        Some(mips_reg(31, 4)),
                        vec![constant(address.wrapping_add(8), 4)],
                    ));
                }
                let target = mips_branch_target(address, immediate);
                ops.push(p(op::CBRANCH, None, vec![constant(target, 4), condition]));
                flow = Flow::Conditional {
                    target,
                    fallthrough: next,
                };
            }
            2 | 3 => {
                let target =
                    (address.wrapping_add(4) & !0x0fff_ffff) | (u64::from(word & 0x03ff_ffff) << 2);
                if opcode == 3 {
                    ops.push(p(
                        op::CALL,
                        Some(mips_reg(2, 4)),
                        mips_o32_call_inputs(constant(target, 4)),
                    ));
                    flow = Flow::Call {
                        target,
                        fallthrough: next,
                    };
                } else {
                    ops.push(p(op::BRANCH, None, vec![constant(target, 4)]));
                    flow = Flow::Jump(target);
                }
            }
            4..=7 | 20..=23 => {
                let target = mips_branch_target(address, immediate);
                if matches!(opcode, 4 | 20) && rs == rt {
                    ops.push(p(op::BRANCH, None, vec![constant(target, 4)]));
                    flow = Flow::Jump(target);
                } else {
                    let Some(condition) = mips_branch_condition(address, opcode, rs, rt, &mut ops)
                    else {
                        return Err(mips_unsupported(address, opcode));
                    };
                    ops.push(p(op::CBRANCH, None, vec![constant(target, 4), condition]));
                    flow = Flow::Conditional {
                        target,
                        fallthrough: next,
                    };
                }
            }
            8 | 9 => {
                ops.push(p(
                    op::INT_ADD,
                    Some(mips_reg(rt, 4)),
                    vec![mips_reg(rs, 4), constant(immediate as u64, 4)],
                ));
                flow = Flow::FallThrough(next);
            }
            10 | 11 => {
                ops.push(p(
                    if opcode == 10 {
                        op::INT_SLESS
                    } else {
                        op::INT_LESS
                    },
                    Some(mips_reg(rt, 4)),
                    vec![mips_reg(rs, 4), constant(immediate as u64, 4)],
                ));
                flow = Flow::FallThrough(next);
            }
            12..=14 => {
                ops.push(p(
                    match opcode {
                        12 => op::INT_AND,
                        13 => op::INT_OR,
                        _ => op::INT_XOR,
                    },
                    Some(mips_reg(rt, 4)),
                    vec![mips_reg(rs, 4), constant(u64::from(word & 0xffff), 4)],
                ));
                flow = Flow::FallThrough(next);
            }
            15 => {
                ops.push(p(
                    op::COPY,
                    Some(mips_reg(rt, 4)),
                    vec![constant(u64::from(word & 0xffff) << 16, 4)],
                ));
                flow = Flow::FallThrough(next);
            }
            24 | 25 => {
                ops.push(p(
                    op::INT_ADD,
                    Some(mips_reg(rt, 8)),
                    vec![mips_reg(rs, 8), constant(immediate as u64, 8)],
                ));
                flow = Flow::FallThrough(next);
            }
            28 => match funct {
                2 => {
                    ops.push(p(
                        op::INT_MULT,
                        Some(mips_reg(rd, 4)),
                        vec![mips_reg(rs, 4), mips_reg(rt, 4)],
                    ));
                    flow = Flow::FallThrough(next);
                }
                32 | 33 => {
                    ops.push(p(
                        op::CALLOTHER,
                        Some(mips_reg(rd, 4)),
                        vec![constant(u64::from(funct), 4), mips_reg(rs, 4)],
                    ));
                    flow = Flow::FallThrough(next);
                }
                _ => return Err(mips_unsupported(address, opcode)),
            },
            30 | 31 => {
                mips_memory(
                    address,
                    rs,
                    rt,
                    immediate,
                    16,
                    opcode == 30,
                    false,
                    &mut ops,
                );
                flow = Flow::FallThrough(next);
            }
            32 | 33 | 35 | 36 | 37 | 39 | 40 | 41 | 43 | 47 | 48 | 51 | 55 | 56 | 63 => {
                let (width, load, signed) = match opcode {
                    32 => (1, true, true),
                    33 => (2, true, true),
                    35 => (4, true, false),
                    36 => (1, true, false),
                    37 => (2, true, false),
                    39 => (4, true, false),
                    40 => (1, false, false),
                    41 => (2, false, false),
                    43 => (4, false, false),
                    48 => (4, true, false),
                    56 => (4, false, false),
                    63 => (8, true, false),
                    47 | 51 | 55 => (0, false, false),
                    _ => unreachable!(),
                };
                if width != 0 {
                    mips_memory(address, rs, rt, immediate, width, load, signed, &mut ops);
                    if opcode == 56 {
                        ops.push(p(op::COPY, Some(mips_reg(rt, 4)), vec![constant(1, 4)]));
                    }
                }
                flow = Flow::FallThrough(next);
            }
            16 | 17 | 18 | 19 => {
                let cop_rs = ((word >> 21) & 0x1f) as u8;
                match (opcode, cop_rs) {
                    (16, 0) | (17, 0) | (18, 0) | (19, 0) => {
                        let cop_reg = mips_register(0x200 + u64::from(rd) * 4, 4);
                        ops.push(p(op::COPY, Some(mips_reg(rt, 4)), vec![cop_reg]));
                    }
                    (16, 4) | (17, 4) | (18, 4) | (19, 4) => {
                        let cop_reg = mips_register(0x200 + u64::from(rd) * 4, 4);
                        ops.push(p(op::COPY, Some(cop_reg), vec![mips_reg(rt, 4)]));
                    }
                    _ => ops.push(p(
                        op::CALLOTHER,
                        None,
                        vec![constant(u64::from(opcode), 4), constant(u64::from(word), 4)],
                    )),
                }
                flow = Flow::FallThrough(next);
            }
            _ => return Err(mips_unsupported(address, opcode)),
        }

        Ok(LiftedInstruction {
            address,
            bytes: bytes[..4].to_vec(),
            pcode: InstPcode {
                len: 4,
                space: RAM_SPACE,
                offset: address,
                ops,
            },
            flow,
        })
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct N64;

fn n64_reg(index: u8, size: u32) -> Varnode {
    Varnode::new(REGISTER_SPACE, u64::from(index) * 8, size)
}

fn n64_register(offset: u64, size: u32) -> Varnode {
    Varnode::new(REGISTER_SPACE, offset, size)
}

fn n64_ram_space(size: u32) -> Varnode {
    constant(417, size)
}

fn n64_branch_target(address: u64, immediate: i64) -> u64 {
    address
        .wrapping_add(4)
        .wrapping_add(immediate.wrapping_mul(4) as u64)
}

fn n64_address(address: u64, base: u8, immediate: i64, ops: &mut Vec<PcodeOp>) -> Varnode {
    let address_vn = unique(address, 0, 8);
    ops.push(p(
        op::INT_ADD,
        Some(address_vn),
        vec![n64_reg(base, 8), constant(immediate as u64, 8)],
    ));
    address_vn
}

fn n64_branch_condition(
    address: u64,
    opcode: u32,
    rs: u8,
    rt: u8,
    ops: &mut Vec<PcodeOp>,
) -> Option<Varnode> {
    let condition = unique(address, 1, 1);
    match opcode {
        4 | 20 => ops.push(p(
            op::INT_EQUAL,
            Some(condition),
            vec![n64_reg(rs, 8), n64_reg(rt, 8)],
        )),
        5 | 21 => {
            let equal = unique(address, 2, 1);
            ops.push(p(
                op::INT_EQUAL,
                Some(equal),
                vec![n64_reg(rs, 8), n64_reg(rt, 8)],
            ));
            ops.push(p(op::BOOL_NEGATE, Some(condition), vec![equal]));
        }
        6 | 22 => ops.push(p(
            op::INT_SLESSEQUAL,
            Some(condition),
            vec![n64_reg(rs, 8), constant(0, 8)],
        )),
        7 | 23 => {
            let non_positive = unique(address, 2, 1);
            ops.push(p(
                op::INT_SLESSEQUAL,
                Some(non_positive),
                vec![n64_reg(rs, 8), constant(0, 8)],
            ));
            ops.push(p(op::BOOL_NEGATE, Some(condition), vec![non_positive]));
        }
        _ => return None,
    }
    Some(condition)
}

fn n64_extend_load(
    address: u64,
    rt: u8,
    width: u32,
    signed: bool,
    address_vn: Varnode,
    ops: &mut Vec<PcodeOp>,
) {
    let loaded = if width == 8 {
        n64_reg(rt, 8)
    } else {
        unique(address, 2, width)
    };
    ops.push(p(
        op::LOAD,
        Some(loaded),
        vec![n64_ram_space(8), address_vn],
    ));
    if width < 8 {
        ops.push(p(
            if signed { op::INT_SEXT } else { op::INT_ZEXT },
            Some(n64_reg(rt, 8)),
            vec![loaded],
        ));
    }
}

fn n64_memory(
    address: u64,
    base: u8,
    rt: u8,
    immediate: i64,
    width: u32,
    load: bool,
    signed: bool,
    ops: &mut Vec<PcodeOp>,
) {
    let address_vn = n64_address(address, base, immediate, ops);
    if load {
        n64_extend_load(address, rt, width, signed, address_vn, ops);
    } else {
        ops.push(p(
            op::STORE,
            None,
            vec![n64_ram_space(8), address_vn, n64_reg(rt, width)],
        ));
    }
}

fn n64_unsupported(address: u64, opcode: u32) -> LiftError {
    LiftError::Unsupported {
        architecture: Architecture::N64,
        address,
        opcode: opcode as u8,
    }
}

fn n64_return(address: u64, ops: &mut Vec<PcodeOp>) {
    let target = unique(address, 0, 8);
    ops.push(p(
        op::INT_AND,
        Some(target),
        vec![n64_reg(31, 8), constant(1, 8)],
    ));
    let likely = n64_register(16128, 1);
    ops.push(p(
        op::INT_NOTEQUAL,
        Some(likely),
        vec![target, constant(0, 8)],
    ));
    ops.push(p(op::CALLOTHER, None, vec![constant(0, 8), likely]));
    let return_target = unique(address, 1, 8);
    ops.push(p(op::INT_2COMP, Some(return_target), vec![constant(2, 8)]));
    ops.push(p(
        op::INT_AND,
        Some(return_target),
        vec![return_target, n64_reg(31, 8)],
    ));
    let pc = n64_register(128, 8);
    ops.push(p(op::COPY, Some(pc), vec![return_target]));
    ops.push(p(op::RETURN, None, vec![pc]));
}

impl Lifter for N64 {
    fn architecture(&self) -> Architecture {
        Architecture::N64
    }

    fn has_delay_slot(&self) -> bool {
        true
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        if bytes.len() < 4 {
            return Err(LiftError::Truncated { address, needed: 4 });
        }
        // Ghidra's current mips64be.slaspec selects big-endian instruction
        // bytes and includes the MIPS32 and MIPS64 instruction families.
        let word = u32::from_be_bytes(bytes[..4].try_into().expect("four bytes"));
        let next = address.wrapping_add(4);
        let opcode = (word >> 26) & 0x3f;
        let rs = ((word >> 21) & 0x1f) as u8;
        let rt = ((word >> 16) & 0x1f) as u8;
        let rd = ((word >> 11) & 0x1f) as u8;
        let sa = ((word >> 6) & 0x1f) as u8;
        let funct = (word & 0x3f) as u8;
        let immediate = i64::from(i16::from_be_bytes([(word >> 8) as u8, word as u8]));
        let mut ops = Vec::new();
        let flow;

        match opcode {
            0 => match funct {
                0 => {
                    if word == 0 {
                        flow = Flow::FallThrough(next);
                    } else {
                        ops.push(p(
                            op::INT_LEFT,
                            Some(n64_reg(rd, 8)),
                            vec![n64_reg(rt, 8), constant(u64::from(sa), 8)],
                        ));
                        flow = Flow::FallThrough(next);
                    }
                }
                2 | 3 => {
                    ops.push(p(
                        if funct == 2 {
                            op::INT_RIGHT
                        } else {
                            op::INT_SRIGHT
                        },
                        Some(n64_reg(rd, 8)),
                        vec![n64_reg(rt, 8), constant(u64::from(sa), 8)],
                    ));
                    flow = Flow::FallThrough(next);
                }
                4 | 6 | 7 | 20 | 22 | 23 => {
                    let shift = if funct >= 20 {
                        n64_reg(rs, 8)
                    } else {
                        constant(u64::from(sa), 8)
                    };
                    let code = match funct {
                        4 | 20 => op::INT_LEFT,
                        6 | 22 => op::INT_RIGHT,
                        _ => op::INT_SRIGHT,
                    };
                    ops.push(p(code, Some(n64_reg(rd, 8)), vec![n64_reg(rt, 8), shift]));
                    flow = Flow::FallThrough(next);
                }
                8 => {
                    if rs == 31 {
                        n64_return(address, &mut ops);
                        flow = Flow::Return;
                    } else {
                        ops.push(p(op::BRANCHIND, None, vec![n64_reg(rs, 8)]));
                        flow = Flow::Return;
                    }
                }
                9 => {
                    let link = if rd == 0 { 31 } else { rd };
                    ops.push(p(
                        op::COPY,
                        Some(n64_reg(link, 8)),
                        vec![constant(address + 8, 8)],
                    ));
                    ops.push(p(op::CALLIND, None, vec![n64_reg(rs, 8)]));
                    flow = Flow::FallThrough(next);
                }
                10 | 11 => {
                    let condition = unique(address, 3, 1);
                    ops.push(p(
                        if funct == 10 {
                            op::INT_EQUAL
                        } else {
                            op::INT_NOTEQUAL
                        },
                        Some(condition),
                        vec![n64_reg(rt, 8), constant(0, 8)],
                    ));
                    ops.push(p(
                        op::CMOV,
                        Some(n64_reg(rd, 8)),
                        vec![condition, n64_reg(rs, 8), n64_reg(rd, 8)],
                    ));
                    flow = Flow::FallThrough(next);
                }
                12 | 13 | 24 | 25 | 26 | 27 => {
                    ops.push(p(op::CALLOTHER, None, vec![constant(u64::from(funct), 8)]));
                    flow = Flow::FallThrough(next);
                }
                16 | 17 | 18 | 19 => {
                    let special =
                        n64_register(if funct == 16 || funct == 17 { 132 } else { 136 }, 8);
                    if funct == 16 || funct == 18 {
                        ops.push(p(op::COPY, Some(n64_reg(rd, 8)), vec![special]));
                    } else {
                        ops.push(p(op::COPY, Some(special), vec![n64_reg(rs, 8)]));
                    }
                    flow = Flow::FallThrough(next);
                }
                32 | 33 | 34 | 35 | 36 | 37 | 38 | 42 | 43 | 44 | 45 | 46 | 47 => {
                    let code = match funct {
                        32 | 33 | 44 | 45 => op::INT_ADD,
                        34 | 35 | 46 | 47 => op::INT_SUB,
                        36 => op::INT_AND,
                        37 => op::INT_OR,
                        38 => op::INT_XOR,
                        42 => op::INT_SLESS,
                        43 => op::INT_LESS,
                        _ => unreachable!(),
                    };
                    ops.push(p(
                        code,
                        Some(n64_reg(rd, 8)),
                        vec![n64_reg(rs, 8), n64_reg(rt, 8)],
                    ));
                    flow = Flow::FallThrough(next);
                }
                39 => {
                    let inverted = unique(address, 5, 8);
                    ops.push(p(
                        op::INT_OR,
                        Some(inverted),
                        vec![n64_reg(rs, 8), n64_reg(rt, 8)],
                    ));
                    ops.push(p(
                        op::INT_XOR,
                        Some(n64_reg(rd, 8)),
                        vec![inverted, constant(u64::MAX, 8)],
                    ));
                    flow = Flow::FallThrough(next);
                }
                56 | 58 | 59 | 60 | 62 | 63 => {
                    let shift = match funct {
                        60 | 62 | 63 => u64::from(sa) + 32,
                        _ => u64::from(sa),
                    };
                    let code = match funct {
                        56 | 60 => op::INT_LEFT,
                        58 | 62 => op::INT_RIGHT,
                        _ => op::INT_SRIGHT,
                    };
                    ops.push(p(
                        code,
                        Some(n64_reg(rd, 8)),
                        vec![n64_reg(rt, 8), constant(shift, 8)],
                    ));
                    flow = Flow::FallThrough(next);
                }
                _ => return Err(n64_unsupported(address, opcode)),
            },
            1 => {
                let condition = unique(address, 4, 1);
                match rt {
                    0 | 2 | 16 | 18 => ops.push(p(
                        op::INT_SLESS,
                        Some(condition),
                        vec![n64_reg(rs, 8), constant(0, 8)],
                    )),
                    1 | 3 | 17 | 19 => {
                        let non_positive = unique(address, 5, 1);
                        ops.push(p(
                            op::INT_SLESSEQUAL,
                            Some(non_positive),
                            vec![n64_reg(rs, 8), constant(0, 8)],
                        ));
                        ops.push(p(op::BOOL_NEGATE, Some(condition), vec![non_positive]));
                    }
                    _ => return Err(n64_unsupported(address, opcode)),
                }
                let target = n64_branch_target(address, immediate);
                ops.push(p(op::CBRANCH, None, vec![constant(target, 8), condition]));
                if rt >= 16 {
                    ops.push(p(
                        op::COPY,
                        Some(n64_reg(31, 8)),
                        vec![constant(address + 8, 8)],
                    ));
                    flow = Flow::Call {
                        target,
                        fallthrough: next,
                    };
                } else {
                    flow = Flow::Conditional {
                        target,
                        fallthrough: next,
                    };
                }
            }
            2 | 3 => {
                let target = ((address.wrapping_add(4)) & !0x0fff_ffff)
                    | (u64::from(word & 0x03ff_ffff) << 2);
                if opcode == 3 {
                    ops.push(p(
                        op::COPY,
                        Some(n64_reg(31, 8)),
                        vec![constant(address + 8, 8)],
                    ));
                    ops.push(p(op::CALL, None, vec![constant(target, 8)]));
                    flow = Flow::Call {
                        target,
                        fallthrough: next,
                    };
                } else {
                    ops.push(p(op::BRANCH, None, vec![constant(target, 8)]));
                    flow = Flow::Jump(target);
                }
            }
            4..=7 | 20..=23 => {
                let condition = n64_branch_condition(address, opcode, rs, rt, &mut ops)
                    .ok_or_else(|| n64_unsupported(address, opcode))?;
                let target = n64_branch_target(address, immediate);
                ops.push(p(op::CBRANCH, None, vec![constant(target, 8), condition]));
                flow = Flow::Conditional {
                    target,
                    fallthrough: next,
                };
            }
            8 | 9 | 24 | 25 => {
                let code = op::INT_ADD;
                ops.push(p(
                    code,
                    Some(n64_reg(rt, 8)),
                    vec![n64_reg(rs, 8), constant(immediate as u64, 8)],
                ));
                flow = Flow::FallThrough(next);
            }
            10 | 11 => {
                ops.push(p(
                    if opcode == 10 {
                        op::INT_SLESS
                    } else {
                        op::INT_LESS
                    },
                    Some(n64_reg(rt, 8)),
                    vec![n64_reg(rs, 8), constant(immediate as u64, 8)],
                ));
                flow = Flow::FallThrough(next);
            }
            12..=14 => {
                let code = match opcode {
                    12 => op::INT_AND,
                    13 => op::INT_OR,
                    _ => op::INT_XOR,
                };
                ops.push(p(
                    code,
                    Some(n64_reg(rt, 8)),
                    vec![n64_reg(rs, 8), constant(u64::from(word & 0xffff), 8)],
                ));
                flow = Flow::FallThrough(next);
            }
            15 => {
                let loaded = unique(address, 6, 4);
                ops.push(p(
                    op::COPY,
                    Some(loaded),
                    vec![constant(u64::from(word & 0xffff) << 16, 4)],
                ));
                ops.push(p(op::INT_SEXT, Some(n64_reg(rt, 8)), vec![loaded]));
                flow = Flow::FallThrough(next);
            }
            16..=19 => {
                ops.push(p(
                    op::CALLOTHER,
                    None,
                    vec![constant(u64::from(opcode), 8), constant(u64::from(word), 8)],
                ));
                flow = Flow::FallThrough(next);
            }
            32 => {
                n64_memory(address, rs, rt, immediate, 1, true, true, &mut ops);
                flow = Flow::FallThrough(next);
            }
            33 => {
                n64_memory(address, rs, rt, immediate, 2, true, true, &mut ops);
                flow = Flow::FallThrough(next);
            }
            35 => {
                n64_memory(address, rs, rt, immediate, 4, true, true, &mut ops);
                flow = Flow::FallThrough(next);
            }
            36 => {
                n64_memory(address, rs, rt, immediate, 1, true, false, &mut ops);
                flow = Flow::FallThrough(next);
            }
            37 => {
                n64_memory(address, rs, rt, immediate, 2, true, false, &mut ops);
                flow = Flow::FallThrough(next);
            }
            39 => {
                n64_memory(address, rs, rt, immediate, 4, true, false, &mut ops);
                flow = Flow::FallThrough(next);
            }
            40 => {
                n64_memory(address, rs, rt, immediate, 1, false, false, &mut ops);
                flow = Flow::FallThrough(next);
            }
            41 => {
                n64_memory(address, rs, rt, immediate, 2, false, false, &mut ops);
                flow = Flow::FallThrough(next);
            }
            43 => {
                n64_memory(address, rs, rt, immediate, 4, false, false, &mut ops);
                flow = Flow::FallThrough(next);
            }
            44 | 45 | 60 | 63 => {
                n64_memory(address, rs, rt, immediate, 8, false, false, &mut ops);
                flow = Flow::FallThrough(next);
            }
            46 | 47 => {
                n64_memory(address, rs, rt, immediate, 8, true, false, &mut ops);
                flow = Flow::FallThrough(next);
            }
            48 | 56 => {
                n64_memory(address, rs, rt, immediate, 4, opcode == 48, true, &mut ops);
                flow = Flow::FallThrough(next);
            }
            _ => return Err(n64_unsupported(address, opcode)),
        }

        Ok(LiftedInstruction {
            address,
            bytes: bytes[..4].to_vec(),
            pcode: InstPcode {
                len: 4,
                space: RAM_SPACE,
                offset: address,
                ops,
            },
            flow,
        })
    }
}

fn relabel_lift_error(error: LiftError, architecture: Architecture) -> LiftError {
    match error {
        LiftError::Unsupported {
            address, opcode, ..
        } => LiftError::Unsupported {
            architecture,
            address,
            opcode,
        },
        LiftError::InvalidEncoding {
            address, reason, ..
        } => LiftError::InvalidEncoding {
            architecture,
            address,
            reason,
        },
        other => other,
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
        Mips32
            .lift_instruction(address, bytes)
            .map(|mut instruction| {
                for operation in &mut instruction.pcode.ops {
                    if matches!(operation.opcode, op::CALL | op::CALLIND) {
                        operation.inputs.truncate(5);
                    }
                }
                instruction
            })
            .map_err(|error| relabel_lift_error(error, Architecture::Ps1))
    }
}
fn sign_extend(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

fn checked_target(
    address: u64,
    displacement: i64,
    architecture: Architecture,
    reason: &'static str,
) -> Result<u64, LiftError> {
    u64::try_from(i128::from(address) + i128::from(displacement)).map_err(|_| {
        LiftError::InvalidEncoding {
            architecture,
            address,
            reason,
        }
    })
}

fn arm_reg(index: u8, size: u32) -> Varnode {
    Varnode::new(
        REGISTER_SPACE,
        32u64.wrapping_add(u64::from(index) * 4),
        size,
    )
}

fn arm_register(offset: u64, size: u32) -> Varnode {
    Varnode::new(REGISTER_SPACE, offset, size)
}
fn arm_ram_space(size: u32) -> Varnode {
    constant(417, size)
}

fn arm_condition(cond: u8, address: u64, ops: &mut Vec<PcodeOp>) -> Option<Varnode> {
    match cond {
        0xe => None,
        0x0 => Some(arm_register(97, 1)),
        0x1 => {
            let out = unique(address, 0x40, 1);
            ops.push(p(op::BOOL_NEGATE, Some(out), vec![arm_register(97, 1)]));
            Some(out)
        }
        _ => Some(unique(address, 0x40 + u32::from(cond), 1)),
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Arm32;

impl Lifter for Arm32 {
    fn architecture(&self) -> Architecture {
        Architecture::Arm32
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        if bytes.len() < 4 {
            return Err(LiftError::Truncated { address, needed: 4 });
        }
        let word = u32::from_le_bytes(bytes[..4].try_into().expect("four bytes"));
        let next = address.wrapping_add(4);
        let mut ops = Vec::new();
        let flow;
        if word == 0xe1a0_0000 {
            flow = Flow::FallThrough(next);
        } else if word & 0x0fff_fff0 == 0x012f_ff10 {
            let rn = (word & 0x0f) as u8;
            if rn == 14 {
                let target = unique(address, 0, 4);
                ops.push(p(
                    op::INT_AND,
                    Some(target),
                    vec![arm_register(88, 4), constant(1, 4)],
                ));
                let thumb = arm_register(105, 1);
                ops.push(p(
                    op::INT_NOTEQUAL,
                    Some(thumb),
                    vec![target, constant(0, 4)],
                ));
                ops.push(p(op::CALLOTHER, None, vec![constant(62, 4), thumb]));
                let pc = arm_register(92, 4);
                ops.push(p(
                    op::INT_AND,
                    Some(pc),
                    vec![arm_register(88, 4), constant(0xffff_fffe, 4)],
                ));
                ops.push(p(op::RETURN, None, vec![pc]));
                flow = Flow::Return;
            } else {
                ops.push(p(op::BRANCHIND, None, vec![arm_reg(rn, 4)]));
                flow = Flow::Return;
            }
        } else if (word >> 25) & 0x7 == 0b101 {
            let cond = (word >> 28) as u8;
            let displacement = sign_extend(u64::from(word & 0x00ff_ffff), 24) << 2;
            let target = checked_target(
                address.wrapping_add(8),
                displacement,
                self.architecture(),
                "branch target overflow",
            )?;
            let link = word & (1 << 24) != 0;
            if link && cond != 0xe {
                return Err(LiftError::Unsupported {
                    architecture: self.architecture(),
                    address,
                    opcode: (word >> 24) as u8,
                });
            }
            if link {
                ops.push(p(op::CALL, None, vec![constant(target, 4)]));
                flow = Flow::Call {
                    target,
                    fallthrough: next,
                };
            } else if let Some(condition) = arm_condition(cond, address, &mut ops) {
                ops.push(p(op::CBRANCH, None, vec![constant(target, 4), condition]));
                flow = Flow::Conditional {
                    target,
                    fallthrough: next,
                };
            } else {
                ops.push(p(op::BRANCH, None, vec![constant(target, 4)]));
                flow = Flow::Jump(target);
            }
        } else if (word >> 26) & 0x3 == 0b01 {
            let load = word & (1 << 20) != 0;
            let byte = word & (1 << 22) != 0;
            let up = word & (1 << 23) != 0;
            let rn = ((word >> 16) & 0x0f) as u8;
            let rt = ((word >> 12) & 0x0f) as u8;
            let mut displacement = i64::from((word & 0x0fff) as i32);
            if !up {
                displacement = -displacement;
            }
            let address_vn = unique(address, 0, 4);
            ops.push(p(
                op::INT_ADD,
                Some(address_vn),
                vec![arm_reg(rn, 4), constant(displacement as u64, 4)],
            ));
            let size = if byte { 1 } else { 4 };
            if load {
                ops.push(p(
                    op::LOAD,
                    Some(arm_reg(rt, size)),
                    vec![arm_ram_space(8), address_vn],
                ));
            } else {
                ops.push(p(
                    op::STORE,
                    None,
                    vec![arm_ram_space(8), address_vn, arm_reg(rt, size)],
                ));
            }
            flow = Flow::FallThrough(next);
        } else if (word >> 25) & 1 != 0 && ((word >> 21) & 0xf) == 0xd {
            let cond = (word >> 28) as u8;
            if cond != 0xe {
                return Err(LiftError::Unsupported {
                    architecture: self.architecture(),
                    address,
                    opcode: (word >> 24) as u8,
                });
            }
            let rd = ((word >> 12) & 0x0f) as u8;
            let immediate = word & 0xff;
            ops.push(p(
                op::COPY,
                Some(arm_reg(rd, 4)),
                vec![constant(immediate.into(), 4)],
            ));
            flow = Flow::FallThrough(next);
        } else if (word >> 25) & 1 != 0 && matches!((word >> 21) & 0xf, 2 | 4 | 10) {
            let cond = (word >> 28) as u8;
            if cond != 0xe {
                return Err(LiftError::Unsupported {
                    architecture: self.architecture(),
                    address,
                    opcode: (word >> 24) as u8,
                });
            }
            let opcode = (word >> 21) & 0xf;
            let rn = ((word >> 16) & 0x0f) as u8;
            let rd = ((word >> 12) & 0x0f) as u8;
            let immediate = u64::from(word & 0xff);
            let destination = arm_reg(rd, 4);
            let source = arm_reg(rn, 4);
            if opcode == 4 {
                let shift = unique(address, 0, 4);
                ops.push(p(
                    op::INT_RIGHT,
                    Some(shift),
                    vec![constant(immediate, 4), constant(31, 4)],
                ));
                let carry_seed = unique(address, 1, 1);
                ops.push(p(
                    op::INT_EQUAL,
                    Some(carry_seed),
                    vec![constant(0, 1), constant(0, 1)],
                ));
                let carry_from_cpsr = unique(address, 2, 1);
                ops.push(p(
                    op::BOOL_AND,
                    Some(carry_from_cpsr),
                    vec![carry_seed, arm_register(98, 1)],
                ));
                let carry_not_zero = unique(address, 3, 1);
                ops.push(p(
                    op::INT_NOTEQUAL,
                    Some(carry_not_zero),
                    vec![constant(0, 1), constant(0, 1)],
                ));
                let shifted_byte = unique(address, 4, 1);
                ops.push(p(
                    op::SUBPIECE,
                    Some(shifted_byte),
                    vec![shift, constant(0, 4)],
                ));
                let carry_from_operand = unique(address, 5, 1);
                ops.push(p(
                    op::BOOL_AND,
                    Some(carry_from_operand),
                    vec![carry_not_zero, shifted_byte],
                ));
                ops.push(p(
                    op::BOOL_OR,
                    Some(arm_register(104, 1)),
                    vec![carry_from_cpsr, carry_from_operand],
                ));
                ops.push(p(
                    op::INT_CARRY,
                    Some(arm_register(102, 1)),
                    vec![source, constant(immediate, 4)],
                ));
                ops.push(p(
                    op::INT_SCARRY,
                    Some(arm_register(103, 1)),
                    vec![source, constant(immediate, 4)],
                ));
                ops.push(p(
                    op::INT_ADD,
                    Some(destination),
                    vec![source, constant(immediate, 4)],
                ));
                ops.push(p(
                    op::INT_SLESS,
                    Some(arm_register(100, 1)),
                    vec![destination, constant(0, 4)],
                ));
                ops.push(p(
                    op::INT_EQUAL,
                    Some(arm_register(101, 1)),
                    vec![destination, constant(0, 4)],
                ));
            } else {
                let code = match opcode {
                    2 => op::INT_SUB,
                    10 => op::INT_SUB,
                    _ => op::INT_ADD,
                };
                let output = if opcode == 10 {
                    unique(address, 1, 4)
                } else {
                    destination
                };
                ops.push(p(code, Some(output), vec![source, constant(immediate, 4)]));
            }
            flow = Flow::FallThrough(next);
        } else {
            return Err(LiftError::Unsupported {
                architecture: self.architecture(),
                address,
                opcode: (word >> 24) as u8,
            });
        }
        Ok(LiftedInstruction {
            address,
            bytes: bytes[..4].to_vec(),
            pcode: InstPcode {
                len: 4,
                space: RAM_SPACE,
                offset: address,
                ops,
            },
            flow,
        })
    }
}
fn rv_reg(index: u8, size: u32) -> Varnode {
    Varnode::new(
        REGISTER_SPACE,
        0x2000u64.wrapping_add(u64::from(index) * 8),
        size,
    )
}
fn rv_unique(address: u64, slot: u32, size: u32) -> Varnode {
    Varnode::new(
        UNIQUE_SPACE,
        address.wrapping_mul(32).wrapping_add(u64::from(slot)),
        size,
    )
}

fn rv_ram_space(size: u32) -> Varnode {
    constant(433, size)
}

fn rv_immediate_i(word: u32) -> i64 {
    sign_extend(u64::from(word >> 20), 12)
}

fn rv_immediate_s(word: u32) -> i64 {
    let raw = u64::from((word >> 7) & 0x1f) | (u64::from(word >> 25) << 5);
    sign_extend(raw, 12)
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Rv64;

impl Lifter for Rv64 {
    fn architecture(&self) -> Architecture {
        Architecture::Rv64
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        if bytes.len() < 4 {
            return Err(LiftError::Truncated { address, needed: 4 });
        }
        let word = u32::from_le_bytes(bytes[..4].try_into().expect("four bytes"));
        let next = address.wrapping_add(4);
        let rd = ((word >> 7) & 0x1f) as u8;
        let rs1 = ((word >> 15) & 0x1f) as u8;
        let rs2 = ((word >> 20) & 0x1f) as u8;
        let funct3 = ((word >> 12) & 7) as u8;
        let funct7 = (word >> 25) as u8;
        let opcode = (word & 0x7f) as u8;
        let mut ops = Vec::new();
        let flow;
        match opcode {
            0x6f => {
                let raw = (u64::from(word >> 31) << 20)
                    | (u64::from((word >> 12) & 0xff) << 12)
                    | (u64::from((word >> 20) & 1) << 11)
                    | (u64::from((word >> 21) & 0x3ff) << 1);
                let target = checked_target(
                    address,
                    sign_extend(raw, 21),
                    self.architecture(),
                    "JAL target overflow",
                )?;
                if rd == 0 {
                    ops.push(p(op::BRANCH, None, vec![constant(target, 8)]));
                    flow = Flow::Jump(target);
                } else {
                    ops.push(p(op::CALL, None, vec![constant(target, 8)]));
                    flow = Flow::Call {
                        target,
                        fallthrough: next,
                    };
                }
            }
            0x67 => {
                let immediate = rv_immediate_i(word);
                if rd == 0 && rs1 == 1 && immediate == 0 {
                    let mask = unique(address, 0, 8);
                    ops.push(p(op::INT_NEGATE, Some(mask), vec![constant(1, 8)]));
                    let target = unique(address, 1, 8);
                    ops.push(p(op::INT_AND, Some(target), vec![rv_reg(1, 8), mask]));
                    ops.push(p(op::RETURN, None, vec![target]));
                    flow = Flow::Return;
                } else {
                    let address_vn = unique(address, 0, 8);
                    ops.push(p(
                        op::INT_ADD,
                        Some(address_vn),
                        vec![rv_reg(rs1, 8), constant(immediate as u64, 8)],
                    ));
                    if rd == 0 {
                        ops.push(p(op::BRANCHIND, None, vec![address_vn]));
                        flow = Flow::Return;
                    } else {
                        ops.push(p(op::CALLIND, None, vec![address_vn]));
                        flow = Flow::FallThrough(next);
                    }
                }
            }
            0x63 => {
                let raw = (u64::from(word >> 31) << 12)
                    | (u64::from((word >> 7) & 1) << 11)
                    | (u64::from((word >> 25) & 0x3f) << 5)
                    | (u64::from((word >> 8) & 0x0f) << 1);
                let target = checked_target(
                    address,
                    sign_extend(raw, 13),
                    self.architecture(),
                    "branch target overflow",
                )?;
                let condition = unique(address, 1, 1);
                let compare = match funct3 {
                    0 => op::INT_EQUAL,
                    1 => op::INT_NOTEQUAL,
                    4 => op::INT_SLESS,
                    5 => op::INT_SLESSEQUAL,
                    6 => op::INT_LESS,
                    7 => op::INT_LESSEQUAL,
                    _ => {
                        return Err(LiftError::Unsupported {
                            architecture: self.architecture(),
                            address,
                            opcode,
                        });
                    }
                };
                ops.push(p(
                    compare,
                    Some(condition),
                    vec![rv_reg(rs1, 8), rv_reg(rs2, 8)],
                ));
                flow = Flow::Conditional {
                    target,
                    fallthrough: next,
                };
            }
            0x13 => {
                let immediate = rv_immediate_i(word);
                let destination = rv_reg(rd, 8);
                let source = rv_reg(rs1, 8);
                let (code, value) = match funct3 {
                    0 => {
                        let value = unique(address, 0, 8);
                        ops.push(p(
                            op::COPY,
                            Some(value),
                            vec![constant(immediate as u64, 8)],
                        ));
                        (op::INT_ADD, value)
                    }
                    4 => (op::INT_XOR, constant(immediate as u64, 8)),
                    6 => (op::INT_OR, constant(immediate as u64, 8)),
                    7 => (op::INT_AND, constant(immediate as u64, 8)),
                    1 => (op::INT_LEFT, constant(u64::from((word >> 20) & 0x3f), 1)),
                    5 if funct7 == 0 => {
                        (op::INT_RIGHT, constant(u64::from((word >> 20) & 0x3f), 1))
                    }
                    5 if funct7 == 0x20 => {
                        (op::INT_SRIGHT, constant(u64::from((word >> 20) & 0x3f), 1))
                    }
                    _ => {
                        return Err(LiftError::Unsupported {
                            architecture: self.architecture(),
                            address,
                            opcode,
                        });
                    }
                };
                ops.push(p(code, Some(destination), vec![source, value]));
                flow = Flow::FallThrough(next);
            }
            0x33 => {
                let code = match (funct7, funct3) {
                    (0x00, 0) => op::INT_ADD,
                    (0x20, 0) => op::INT_SUB,
                    (0x01, 0) => op::INT_MULT,
                    (0x00, 4) => op::INT_XOR,
                    (0x00, 6) => op::INT_OR,
                    (0x00, 7) => op::INT_AND,
                    (0x00, 1) => op::INT_LEFT,
                    (0x00, 5) => op::INT_RIGHT,
                    (0x20, 5) => op::INT_SRIGHT,
                    _ => {
                        return Err(LiftError::Unsupported {
                            architecture: self.architecture(),
                            address,
                            opcode,
                        });
                    }
                };
                ops.push(p(
                    code,
                    Some(rv_reg(rd, 8)),
                    vec![rv_reg(rs1, 8), rv_reg(rs2, 8)],
                ));
                flow = Flow::FallThrough(next);
            }
            0x03 => {
                let size = match funct3 {
                    0 | 4 => 1,
                    1 | 5 => 2,
                    2 => 4,
                    3 => 8,
                    _ => {
                        return Err(LiftError::Unsupported {
                            architecture: self.architecture(),
                            address,
                            opcode,
                        });
                    }
                };
                let immediate = rv_immediate_i(word);
                let offset_vn = rv_unique(address, 0, 8);
                ops.push(p(
                    op::COPY,
                    Some(offset_vn),
                    vec![constant(immediate as u64, 8)],
                ));
                let address_vn = rv_unique(address, 1, 8);
                ops.push(p(
                    op::INT_ADD,
                    Some(address_vn),
                    vec![rv_reg(rs1, 8), offset_vn],
                ));
                ops.push(p(
                    op::LOAD,
                    Some(rv_reg(rd, size)),
                    vec![rv_ram_space(8), address_vn],
                ));
                flow = Flow::FallThrough(next);
            }
            0x23 => {
                let size = match funct3 {
                    0 => 1,
                    1 => 2,
                    2 => 4,
                    3 => 8,
                    _ => {
                        return Err(LiftError::Unsupported {
                            architecture: self.architecture(),
                            address,
                            opcode,
                        });
                    }
                };
                let immediate = rv_immediate_s(word);
                let offset_vn = rv_unique(address, 0, 8);
                ops.push(p(
                    op::COPY,
                    Some(offset_vn),
                    vec![constant(immediate as u64, 8)],
                ));
                let address_vn = rv_unique(address, 1, 8);
                ops.push(p(
                    op::INT_ADD,
                    Some(address_vn),
                    vec![rv_reg(rs1, 8), offset_vn],
                ));
                ops.push(p(
                    op::STORE,
                    None,
                    vec![rv_ram_space(8), address_vn, rv_reg(rs2, size)],
                ));
                flow = Flow::FallThrough(next);
            }
            0x37 => {
                ops.push(p(
                    op::COPY,
                    Some(rv_reg(rd, 8)),
                    vec![constant(u64::from(word & 0xffff_f000), 8)],
                ));
                flow = Flow::FallThrough(next);
            }
            0x17 => {
                let value = checked_target(
                    address,
                    sign_extend(u64::from(word & 0xffff_f000), 32),
                    self.architecture(),
                    "AUIPC value overflow",
                )?;
                ops.push(p(op::COPY, Some(rv_reg(rd, 8)), vec![constant(value, 8)]));
                flow = Flow::FallThrough(next);
            }
            0x0f => {
                flow = Flow::FallThrough(next);
            }
            _ => {
                return Err(LiftError::Unsupported {
                    architecture: self.architecture(),
                    address,
                    opcode,
                });
            }
        }
        Ok(LiftedInstruction {
            address,
            bytes: bytes[..4].to_vec(),
            pcode: InstPcode {
                len: 4,
                space: RAM_SPACE,
                offset: address,
                ops,
            },
            flow,
        })
    }
}
fn ppc_reg(index: u8, size: u32, register_size: u32) -> Varnode {
    Varnode::new(
        REGISTER_SPACE,
        u64::from(index) * u64::from(register_size),
        size,
    )
}

fn ppc_lr(size: u32, register_size: u32) -> Varnode {
    Varnode::new(REGISTER_SPACE, 32 * u64::from(register_size), size)
}

fn ppc_ram_space(size: u32) -> Varnode {
    constant(417, size)
}

fn ppc_lift_instruction(
    address: u64,
    bytes: &[u8],
    architecture: Architecture,
    register_size: u32,
) -> Result<LiftedInstruction, LiftError> {
    if bytes.len() < 4 {
        return Err(LiftError::Truncated { address, needed: 4 });
    }
    let word = u32::from_be_bytes(bytes[..4].try_into().expect("four bytes"));
    let next = address.wrapping_add(4);
    let opcode = (word >> 26) as u8;
    let mut ops = Vec::new();
    let flow;
    match opcode {
        18 => {
            let displacement = sign_extend(u64::from(word & 0x03ff_fffc), 26);
            let absolute = word & 2 != 0;
            let target = if absolute {
                u64::try_from(displacement).map_err(|_| LiftError::InvalidEncoding {
                    architecture,
                    address,
                    reason: "absolute branch target is negative",
                })?
            } else {
                checked_target(
                    address,
                    displacement,
                    architecture,
                    "branch target overflow",
                )?
            };
            if word & 1 != 0 {
                ops.push(p(op::CALL, None, vec![constant(target, register_size)]));
                flow = Flow::Call {
                    target,
                    fallthrough: next,
                };
            } else {
                ops.push(p(op::BRANCH, None, vec![constant(target, register_size)]));
                flow = Flow::Jump(target);
            }
        }
        16 => {
            let displacement = sign_extend(u64::from((word >> 2) & 0x3fff) << 2, 16);
            let target = if word & 2 != 0 {
                u64::try_from(displacement).map_err(|_| LiftError::InvalidEncoding {
                    architecture,
                    address,
                    reason: "absolute conditional target is negative",
                })?
            } else {
                checked_target(
                    address,
                    displacement,
                    architecture,
                    "conditional target overflow",
                )?
            };
            let condition = unique(address, 0, 1);
            ops.push(p(
                op::COPY,
                Some(condition),
                vec![constant(u64::from((word >> 16) & 0x1f), 1)],
            ));
            ops.push(p(
                op::CBRANCH,
                None,
                vec![constant(target, register_size), condition],
            ));
            flow = Flow::Conditional {
                target,
                fallthrough: next,
            };
        }
        19 if word == 0x4e80_0020 => {
            ops.push(p(
                op::RETURN,
                None,
                vec![ppc_lr(register_size, register_size)],
            ));
            flow = Flow::Return;
        }
        19 if ((word >> 1) & 0x3ff) == 16 => {
            ops.push(p(
                op::BRANCHIND,
                None,
                vec![ppc_lr(register_size, register_size)],
            ));
            flow = Flow::Return;
        }
        14 | 15 => {
            let rd = ((word >> 21) & 0x1f) as u8;
            let ra = ((word >> 16) & 0x1f) as u8;
            let immediate = i64::from((word & 0xffff) as i16);
            let immediate = if opcode == 15 {
                immediate << 16
            } else {
                immediate
            };
            let source = if ra == 0 {
                constant(0, register_size)
            } else {
                ppc_reg(ra, register_size, register_size)
            };
            ops.push(p(
                op::INT_ADD,
                Some(ppc_reg(rd, register_size, register_size)),
                vec![source, constant(immediate as u64, register_size)],
            ));
            flow = Flow::FallThrough(next);
        }
        24 => {
            let rd = ((word >> 21) & 0x1f) as u8;
            let ra = ((word >> 16) & 0x1f) as u8;
            let immediate = u64::from(word & 0xffff);
            ops.push(p(
                op::INT_OR,
                Some(ppc_reg(rd, register_size, register_size)),
                vec![
                    ppc_reg(ra, register_size, register_size),
                    constant(immediate, register_size),
                ],
            ));
            flow = Flow::FallThrough(next);
        }
        31 => {
            let rd = ((word >> 21) & 0x1f) as u8;
            let ra = ((word >> 16) & 0x1f) as u8;
            let rb = ((word >> 11) & 0x1f) as u8;
            let xo = (word >> 1) & 0x3ff;
            if xo == 339 {
                ops.push(p(
                    op::COPY,
                    Some(ppc_reg(rd, register_size, register_size)),
                    vec![ppc_lr(register_size, register_size)],
                ));
            } else if xo == 467 {
                ops.push(p(
                    op::COPY,
                    Some(ppc_lr(register_size, register_size)),
                    vec![ppc_reg(rd, register_size, register_size)],
                ));
            } else {
                let (code, left, right) = match xo {
                    266 => (
                        op::INT_ADD,
                        ppc_reg(ra, register_size, register_size),
                        ppc_reg(rb, register_size, register_size),
                    ),
                    40 => (
                        op::INT_SUB,
                        ppc_reg(rb, register_size, register_size),
                        ppc_reg(ra, register_size, register_size),
                    ),
                    444 => (
                        op::INT_OR,
                        ppc_reg(ra, register_size, register_size),
                        ppc_reg(rb, register_size, register_size),
                    ),
                    316 => (
                        op::INT_XOR,
                        ppc_reg(ra, register_size, register_size),
                        ppc_reg(rb, register_size, register_size),
                    ),
                    28 => (
                        op::INT_AND,
                        ppc_reg(ra, register_size, register_size),
                        ppc_reg(rb, register_size, register_size),
                    ),
                    _ => {
                        return Err(LiftError::Unsupported {
                            architecture,
                            address,
                            opcode,
                        });
                    }
                };
                ops.push(p(
                    code,
                    Some(ppc_reg(rd, register_size, register_size)),
                    vec![left, right],
                ));
            }
            flow = Flow::FallThrough(next);
        }
        32 | 33 | 34 => {
            let rt = ((word >> 21) & 0x1f) as u8;
            let ra = ((word >> 16) & 0x1f) as u8;
            let immediate = i64::from((word & 0xffff) as i16);
            let size = if opcode == 34 { 1 } else { 4 };
            let address_vn = unique(address, 0, register_size);
            let base = if ra == 0 {
                constant(0, register_size)
            } else {
                ppc_reg(ra, register_size, register_size)
            };
            ops.push(p(
                op::INT_ADD,
                Some(address_vn),
                vec![base, constant(immediate as u64, register_size)],
            ));
            ops.push(p(
                op::LOAD,
                Some(ppc_reg(rt, size, register_size)),
                vec![ppc_ram_space(8), address_vn],
            ));
            flow = Flow::FallThrough(next);
        }
        36 | 37 => {
            let rs = ((word >> 21) & 0x1f) as u8;
            let ra = ((word >> 16) & 0x1f) as u8;
            let immediate = i64::from((word & 0xffff) as i16);
            let address_vn = unique(address, 0, register_size);
            let base = if ra == 0 {
                constant(0, register_size)
            } else {
                ppc_reg(ra, register_size, register_size)
            };
            ops.push(p(
                op::INT_ADD,
                Some(address_vn),
                vec![base, constant(immediate as u64, register_size)],
            ));
            ops.push(p(
                op::STORE,
                None,
                vec![
                    ppc_ram_space(8),
                    address_vn,
                    ppc_reg(rs, register_size, register_size),
                ],
            ));
            flow = Flow::FallThrough(next);
        }
        _ => {
            return Err(LiftError::Unsupported {
                architecture,
                address,
                opcode,
            });
        }
    }
    Ok(LiftedInstruction {
        address,
        bytes: bytes[..4].to_vec(),
        pcode: InstPcode {
            len: 4,
            space: RAM_SPACE,
            offset: address,
            ops,
        },
        flow,
    })
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Ppc32;

impl Lifter for Ppc32 {
    fn architecture(&self) -> Architecture {
        Architecture::Ppc32
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        ppc_lift_instruction(address, bytes, Architecture::Ppc32, 4)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Ppc64;

impl Lifter for Ppc64 {
    fn architecture(&self) -> Architecture {
        Architecture::Ppc64
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        ppc_lift_instruction(address, bytes, Architecture::Ppc64, 8)
    }
}
#[derive(Copy, Clone, Debug, Default)]
pub struct GameCube;

impl Lifter for GameCube {
    fn architecture(&self) -> Architecture {
        Architecture::GameCube
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        Ppc32
            .lift_instruction(address, bytes)
            .map_err(|error| relabel_lift_error(error, Architecture::GameCube))
    }
}
#[derive(Copy, Clone, Debug, Default)]
pub struct X86_32;

impl Lifter for X86_32 {
    fn architecture(&self) -> Architecture {
        Architecture::X86_32
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        X86_64::new()
            .lift_instruction(address, bytes)
            .map_err(|error| relabel_lift_error(error, Architecture::X86_32))
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
        if bytes.len() < 4 {
            return Mips32
                .lift_instruction(address, bytes)
                .map_err(|error| relabel_lift_error(error, Architecture::Mips32Be));
        }
        let little_endian = [bytes[3], bytes[2], bytes[1], bytes[0]];
        let mut instruction = Mips32
            .lift_instruction(address, &little_endian)
            .map_err(|error| relabel_lift_error(error, Architecture::Mips32Be))?;
        instruction.bytes = bytes[..4].to_vec();
        Ok(instruction)
    }
}

fn narrow_rv32_varnode(varnode: Varnode) -> Varnode {
    Varnode::new(varnode.space, varnode.offset, varnode.size.min(4))
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Rv32;

impl Lifter for Rv32 {
    fn architecture(&self) -> Architecture {
        Architecture::Rv32
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        if bytes.len() >= 4 {
            let word = u32::from_le_bytes(bytes[..4].try_into().expect("four bytes"));
            let opcode = word & 0x7f;
            let funct3 = (word >> 12) & 7;
            if (opcode == 0x03 || opcode == 0x23) && funct3 == 3 {
                return Err(LiftError::Unsupported {
                    architecture: Architecture::Rv32,
                    address,
                    opcode: opcode as u8,
                });
            }
        }
        let mut instruction = Rv64
            .lift_instruction(address, bytes)
            .map_err(|error| relabel_lift_error(error, Architecture::Rv32))?;
        for operation in &mut instruction.pcode.ops {
            operation.output = operation.output.map(narrow_rv32_varnode);
            operation.inputs = operation
                .inputs
                .iter()
                .copied()
                .map(narrow_rv32_varnode)
                .collect();
        }
        Ok(instruction)
    }
}

fn thumb_condition(address: u64, condition: u8, ops: &mut Vec<PcodeOp>) -> Varnode {
    match condition {
        0 => arm_register(97, 1),
        1 => {
            let output = unique(address, 0x40, 1);
            ops.push(p(op::BOOL_NEGATE, Some(output), vec![arm_register(97, 1)]));
            output
        }
        _ => unique(address, 0x40 + u32::from(condition), 1),
    }
}

fn thumb_memory(
    address: u64,
    ops: &mut Vec<PcodeOp>,
    rn: u8,
    rt: u8,
    load: bool,
    size: u32,
    displacement: u64,
) {
    let address_vn = unique(address, 0, 4);
    ops.push(p(
        op::INT_ADD,
        Some(address_vn),
        vec![arm_reg(rn, 4), constant(displacement, 4)],
    ));
    if load {
        ops.push(p(
            op::LOAD,
            Some(arm_reg(rt, size)),
            vec![arm_ram_space(8), address_vn],
        ));
    } else {
        ops.push(p(
            op::STORE,
            None,
            vec![arm_ram_space(8), address_vn, arm_reg(rt, size)],
        ));
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Thumb;

impl Lifter for Thumb {
    fn architecture(&self) -> Architecture {
        Architecture::Thumb
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        if bytes.len() < 2 {
            return Err(LiftError::Truncated { address, needed: 2 });
        }
        let word = u16::from_le_bytes(bytes[..2].try_into().expect("two bytes"));
        let next = address.wrapping_add(2);
        let mut ops = Vec::new();
        let flow;
        if word == 0xbf00 {
            flow = Flow::FallThrough(next);
        } else if word & 0xf800 == 0x2000 {
            let rd = ((word >> 8) & 7) as u8;
            ops.push(p(
                op::COPY,
                Some(arm_reg(rd, 4)),
                vec![constant(u64::from(word & 0xff), 4)],
            ));
            flow = Flow::FallThrough(next);
        } else if word & 0xf800 == 0x3000 || word & 0xf800 == 0x3800 {
            let rd = ((word >> 8) & 7) as u8;
            let code = if word & 0x0800 == 0 {
                op::INT_ADD
            } else {
                op::INT_SUB
            };
            ops.push(p(
                code,
                Some(arm_reg(rd, 4)),
                vec![arm_reg(rd, 4), constant(u64::from(word & 0xff), 4)],
            ));
            flow = Flow::FallThrough(next);
        } else if word & 0xf800 == 0x4800 {
            let rt = ((word >> 8) & 7) as u8;
            let literal_address =
                (address.wrapping_add(4) & !3).wrapping_add(u64::from(word & 0xff) << 2);
            ops.push(p(
                op::LOAD,
                Some(arm_reg(rt, 4)),
                vec![arm_ram_space(8), constant(literal_address, 4)],
            ));
            flow = Flow::FallThrough(next);
        } else if word & 0xf200 == 0x5000 {
            let kind = ((word >> 9) & 7) as u8;
            let (load, size) = match kind {
                0 => (false, 4),
                1 => (false, 2),
                2 => (false, 1),
                4 => (true, 4),
                5 => (true, 2),
                6 => (true, 1),
                _ => {
                    return Err(LiftError::Unsupported {
                        architecture: Architecture::Thumb,
                        address,
                        opcode: (word >> 8) as u8,
                    });
                }
            };
            let rn = ((word >> 3) & 7) as u8;
            let rm = ((word >> 6) & 7) as u8;
            let rt = (word & 7) as u8;
            let address_vn = unique(address, 0, 4);
            ops.push(p(
                op::INT_ADD,
                Some(address_vn),
                vec![arm_reg(rn, 4), arm_reg(rm, 4)],
            ));
            if load {
                ops.push(p(
                    op::LOAD,
                    Some(arm_reg(rt, size)),
                    vec![arm_ram_space(8), address_vn],
                ));
            } else {
                ops.push(p(
                    op::STORE,
                    None,
                    vec![arm_ram_space(8), address_vn, arm_reg(rt, size)],
                ));
            }
            flow = Flow::FallThrough(next);
        } else if word & 0xe000 == 0x6000 {
            let byte = word & 0x1000 != 0;
            let load = word & 0x0800 != 0;
            let rn = ((word >> 3) & 7) as u8;
            let rt = (word & 7) as u8;
            let displacement = u64::from((word >> 6) & 0x1f) << if byte { 0 } else { 2 };
            thumb_memory(
                address,
                &mut ops,
                rn,
                rt,
                load,
                if byte { 1 } else { 4 },
                displacement,
            );
            flow = Flow::FallThrough(next);
        } else if word & 0xf000 == 0x8000 {
            let load = word & 0x0800 != 0;
            let rn = ((word >> 3) & 7) as u8;
            let rt = (word & 7) as u8;
            let displacement = u64::from((word >> 6) & 0x1f) << 1;
            thumb_memory(address, &mut ops, rn, rt, load, 2, displacement);
            flow = Flow::FallThrough(next);
        } else if word & 0xf000 == 0x9000 {
            let load = word & 0x0800 != 0;
            let rt = ((word >> 8) & 7) as u8;
            let displacement = u64::from(word & 0xff) << 2;
            thumb_memory(address, &mut ops, 13, rt, load, 4, displacement);
            flow = Flow::FallThrough(next);
        } else if word & 0xff87 == 0x4700 {
            let rm = (((word >> 3) & 0x0f) | ((word >> 3) & 0x10)) as u8;
            if rm == 14 {
                ops.push(p(op::RETURN, None, vec![arm_register(92, 4)]));
                flow = Flow::Return;
            } else {
                ops.push(p(op::BRANCHIND, None, vec![arm_reg(rm, 4)]));
                flow = Flow::Return;
            }
        } else if word & 0xf800 == 0xe000 {
            let displacement = sign_extend(u64::from(word & 0x07ff), 11) << 1;
            let target = next.wrapping_add(displacement as u64);
            ops.push(p(op::BRANCH, None, vec![constant(target, 4)]));
            flow = Flow::Jump(target);
        } else if word & 0xf000 == 0xd000 && word & 0x0f00 != 0x0f00 {
            let condition = ((word >> 8) & 0x0f) as u8;
            let displacement = sign_extend(u64::from(word & 0xff), 8) << 1;
            let target = next.wrapping_add(displacement as u64);
            let condition_vn = thumb_condition(address, condition, &mut ops);
            ops.push(p(
                op::CBRANCH,
                None,
                vec![constant(target, 4), condition_vn],
            ));
            flow = Flow::Conditional {
                target,
                fallthrough: next,
            };
        } else {
            return Err(LiftError::Unsupported {
                architecture: Architecture::Thumb,
                address,
                opcode: (word >> 8) as u8,
            });
        }
        Ok(LiftedInstruction {
            address,
            bytes: bytes[..2].to_vec(),
            pcode: InstPcode {
                len: 2,
                space: RAM_SPACE,
                offset: address,
                ops,
            },
            flow,
        })
    }
}
fn m68k_reg(index: u8, size: u32) -> Varnode {
    Varnode::new(REGISTER_SPACE, u64::from(index) * 4, size)
}

fn m68k_finish(address: u64, bytes: &[u8], ops: Vec<PcodeOp>, flow: Flow) -> LiftedInstruction {
    let len = bytes.len() as u32;
    LiftedInstruction {
        address,
        bytes: bytes.to_vec(),
        pcode: InstPcode {
            len,
            space: RAM_SPACE,
            offset: address,
            ops,
        },
        flow,
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct M68k;

impl Lifter for M68k {
    fn architecture(&self) -> Architecture {
        Architecture::M68k
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        if bytes.len() < 2 {
            return Err(LiftError::Truncated { address, needed: 2 });
        }
        let word = u16::from_be_bytes(bytes[..2].try_into().expect("two bytes"));
        let next = address.wrapping_add(2);
        let mut ops = Vec::new();
        if word == 0x4e71 {
            return Ok(m68k_finish(
                address,
                &bytes[..2],
                ops,
                Flow::FallThrough(next),
            ));
        }
        if word == 0x4e75 || word == 0x4e73 {
            ops.push(p(op::RETURN, None, vec![m68k_reg(16, 4)]));
            return Ok(m68k_finish(address, &bytes[..2], ops, Flow::Return));
        }
        if word & 0xf100 == 0x7000 {
            let register = ((word >> 9) & 7) as u8;
            let immediate = sign_extend(u64::from(word & 0xff), 8);
            ops.push(p(
                op::COPY,
                Some(m68k_reg(register, 4)),
                vec![constant(immediate as u64, 4)],
            ));
            return Ok(m68k_finish(
                address,
                &bytes[..2],
                ops,
                Flow::FallThrough(next),
            ));
        }
        if word & 0xfff8 == 0x4280 {
            let register = (word & 7) as u8;
            ops.push(p(
                op::COPY,
                Some(m68k_reg(register, 4)),
                vec![constant(0, 4)],
            ));
            return Ok(m68k_finish(
                address,
                &bytes[..2],
                ops,
                Flow::FallThrough(next),
            ));
        }
        if word & 0xfff8 == 0x4e90 || word & 0xfff8 == 0x4ed0 {
            let register = (word & 7) as u8;
            if word & 0x40 == 0 {
                ops.push(p(op::CALLIND, None, vec![m68k_reg(8 + register, 4)]));
                return Ok(m68k_finish(
                    address,
                    &bytes[..2],
                    ops,
                    Flow::FallThrough(next),
                ));
            }
            ops.push(p(op::BRANCHIND, None, vec![m68k_reg(8 + register, 4)]));
            return Ok(m68k_finish(address, &bytes[..2], ops, Flow::Return));
        }
        if word & 0xf000 == 0x6000 {
            let condition = ((word >> 8) & 0x0f) as u8;
            let (length, displacement) = if word & 0xff == 0 {
                if bytes.len() < 4 {
                    return Err(LiftError::Truncated { address, needed: 4 });
                }
                (4usize, i64::from(i16::from_be_bytes([bytes[2], bytes[3]])))
            } else {
                (2usize, sign_extend(u64::from(word & 0xff), 8))
            };
            let target = address
                .wrapping_add(length as u64)
                .wrapping_add(displacement as u64);
            if condition == 0 {
                ops.push(p(op::BRANCH, None, vec![constant(target, 4)]));
                return Ok(m68k_finish(
                    address,
                    &bytes[..length],
                    ops,
                    Flow::Jump(target),
                ));
            }
            if condition == 1 {
                ops.push(p(op::CALL, None, vec![constant(target, 4)]));
                return Ok(m68k_finish(
                    address,
                    &bytes[..length],
                    ops,
                    Flow::Call {
                        target,
                        fallthrough: address.wrapping_add(length as u64),
                    },
                ));
            }
            let condition_vn = unique(address, 0, 1);
            ops.push(p(
                op::CBRANCH,
                None,
                vec![constant(target, 4), condition_vn],
            ));
            return Ok(m68k_finish(
                address,
                &bytes[..length],
                ops,
                Flow::Conditional {
                    target,
                    fallthrough: address.wrapping_add(length as u64),
                },
            ));
        }
        if word == 0x303c || word == 0x203c {
            let long = word == 0x203c;
            let needed = if long { 6 } else { 4 };
            if bytes.len() < needed {
                return Err(LiftError::Truncated { address, needed });
            }
            let immediate = if long {
                u64::from(u32::from_be_bytes(
                    bytes[2..6].try_into().expect("four bytes"),
                ))
            } else {
                u64::from(u16::from_be_bytes([bytes[2], bytes[3]]))
            };
            ops.push(p(
                op::COPY,
                Some(m68k_reg(0, if long { 4 } else { 2 })),
                vec![constant(immediate, if long { 4 } else { 2 })],
            ));
            return Ok(m68k_finish(
                address,
                &bytes[..needed],
                ops,
                Flow::FallThrough(address + needed as u64),
            ));
        }
        Err(LiftError::Unsupported {
            architecture: Architecture::M68k,
            address,
            opcode: (word >> 8) as u8,
        })
    }
}

fn sh_reg(index: u8, size: u32) -> Varnode {
    Varnode::new(REGISTER_SPACE, u64::from(index) * 4, size)
}

fn sh_ram_space(size: u32) -> Varnode {
    constant(417, size)
}

fn lift_sh(
    address: u64,
    bytes: &[u8],
    big_endian: bool,
    architecture: Architecture,
) -> Result<LiftedInstruction, LiftError> {
    if bytes.len() < 2 {
        return Err(LiftError::Truncated { address, needed: 2 });
    }
    let word = if big_endian {
        u16::from_be_bytes(bytes[..2].try_into().expect("two bytes"))
    } else {
        u16::from_le_bytes(bytes[..2].try_into().expect("two bytes"))
    };
    let next = address.wrapping_add(2);
    let mut ops = Vec::new();
    let flow;
    if word == 0x0009 {
        flow = Flow::FallThrough(next);
    } else if word == 0x000b || word == 0x002b {
        ops.push(p(op::RETURN, None, vec![sh_reg(16, 4)]));
        flow = Flow::Return;
    } else if word & 0xf0ff == 0x402b || word & 0xf0ff == 0x400b {
        let register = ((word >> 8) & 0x0f) as u8;
        if word & 0x20 == 0 {
            ops.push(p(op::CALLIND, None, vec![sh_reg(register, 4)]));
            flow = Flow::FallThrough(next);
        } else {
            ops.push(p(op::BRANCHIND, None, vec![sh_reg(register, 4)]));
            flow = Flow::Return;
        }
    } else if word & 0xf000 == 0xe000 {
        let register = ((word >> 8) & 0x0f) as u8;
        let immediate = sign_extend(u64::from(word & 0xff), 8);
        ops.push(p(
            op::COPY,
            Some(sh_reg(register, 4)),
            vec![constant(immediate as u64, 4)],
        ));
        flow = Flow::FallThrough(next);
    } else if word & 0xf000 == 0x7000 {
        let register = ((word >> 8) & 0x0f) as u8;
        let immediate = sign_extend(u64::from(word & 0xff), 8);
        ops.push(p(
            op::INT_ADD,
            Some(sh_reg(register, 4)),
            vec![sh_reg(register, 4), constant(immediate as u64, 4)],
        ));
        flow = Flow::FallThrough(next);
    } else if word & 0xf00f == 0x6003 {
        let destination = ((word >> 8) & 0x0f) as u8;
        let source = ((word >> 4) & 0x0f) as u8;
        ops.push(p(
            op::COPY,
            Some(sh_reg(destination, 4)),
            vec![sh_reg(source, 4)],
        ));
        flow = Flow::FallThrough(next);
    } else if word & 0xf00f == 0x3008
        || word & 0xf00f == 0x300c
        || word & 0xf00f == 0x2008
        || word & 0xf00f == 0x2009
        || word & 0xf00f == 0x200a
        || word & 0xf00f == 0x200b
    {
        let destination = ((word >> 8) & 0x0f) as u8;
        let source = ((word >> 4) & 0x0f) as u8;
        let code = match word & 0x000f {
            0x8 => op::INT_SUB,
            0x9 => op::INT_AND,
            0xa => op::INT_XOR,
            0xb => op::INT_OR,
            0xc => op::INT_ADD,
            _ => op::INT_EQUAL,
        };
        ops.push(p(
            code,
            Some(sh_reg(destination, 4)),
            vec![sh_reg(destination, 4), sh_reg(source, 4)],
        ));
        flow = Flow::FallThrough(next);
    } else if word & 0xf00f == 0x6002 || word & 0xf00f == 0x2002 {
        let register = ((word >> 8) & 0x0f) as u8;
        let base = ((word >> 4) & 0x0f) as u8;
        let address_vn = unique(address, 0, 4);
        ops.push(p(
            op::INT_ADD,
            Some(address_vn),
            vec![sh_reg(base, 4), constant(0, 4)],
        ));
        if word & 0xf000 == 0x6000 {
            ops.push(p(
                op::LOAD,
                Some(sh_reg(register, 4)),
                vec![sh_ram_space(8), address_vn],
            ));
        } else {
            ops.push(p(
                op::STORE,
                None,
                vec![sh_ram_space(8), address_vn, sh_reg(register, 4)],
            ));
        }
        flow = Flow::FallThrough(next);
    } else if word & 0xf000 == 0xa000 || word & 0xf000 == 0xb000 {
        let displacement = sign_extend(u64::from(word & 0x0fff), 12) << 1;
        let target = address.wrapping_add(4).wrapping_add(displacement as u64);
        if word & 0x1000 == 0 {
            ops.push(p(op::BRANCH, None, vec![constant(target, 4)]));
            flow = Flow::Jump(target);
        } else {
            ops.push(p(op::CALL, None, vec![constant(target, 4)]));
            flow = Flow::Call {
                target,
                fallthrough: next,
            };
        }
    } else if word & 0xff00 == 0x8900 || word & 0xff00 == 0x8b00 {
        let displacement = sign_extend(u64::from(word & 0xff), 8) << 1;
        let target = address.wrapping_add(4).wrapping_add(displacement as u64);
        let condition = unique(address, 1, 1);
        ops.push(p(op::CBRANCH, None, vec![constant(target, 4), condition]));
        flow = Flow::Conditional {
            target,
            fallthrough: next,
        };
    } else if word & 0xf000 == 0x9000 {
        let register = ((word >> 8) & 0x0f) as u8;
        let displacement = u64::from(word & 0xff) * 4;
        let address_vn = unique(address, 0, 4);
        ops.push(p(
            op::INT_ADD,
            Some(address_vn),
            vec![sh_reg(16, 4), constant(displacement, 4)],
        ));
        ops.push(p(
            op::LOAD,
            Some(sh_reg(register, 4)),
            vec![sh_ram_space(8), address_vn],
        ));
        flow = Flow::FallThrough(next);
    } else {
        return Err(LiftError::Unsupported {
            architecture,
            address,
            opcode: (word >> 8) as u8,
        });
    }
    Ok(LiftedInstruction {
        address,
        bytes: bytes[..2].to_vec(),
        pcode: InstPcode {
            len: 2,
            space: RAM_SPACE,
            offset: address,
            ops,
        },
        flow,
    })
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
        lift_sh(address, bytes, true, Architecture::Sh2)
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
        lift_sh(address, bytes, false, Architecture::Sh4)
    }
}
fn m6502_reg(index: u8, size: u32) -> Varnode {
    Varnode::new(REGISTER_SPACE, u64::from(index), size)
}

fn m6502_ram_space(size: u32) -> Varnode {
    constant(417, size)
}

fn m6502_address(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

#[derive(Copy, Clone, Debug, Default)]
pub struct M6502;

impl Lifter for M6502 {
    fn architecture(&self) -> Architecture {
        Architecture::M6502
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        if bytes.is_empty() {
            return Err(LiftError::Truncated { address, needed: 1 });
        }
        let opcode = bytes[0];
        let next = address.wrapping_add(1);
        let mut ops = Vec::new();
        let (length, flow) = match opcode {
            0xea | 0x18 | 0x38 => (1, Flow::FallThrough(next)),
            0x60 | 0x40 => {
                ops.push(p(op::RETURN, None, vec![m6502_reg(8, 2)]));
                (1, Flow::Return)
            }
            0xa9 | 0xa2 | 0xa0 => {
                if bytes.len() < 2 {
                    return Err(LiftError::Truncated { address, needed: 2 });
                }
                let register = match opcode {
                    0xa9 => 0,
                    0xa2 => 1,
                    _ => 2,
                };
                ops.push(p(
                    op::COPY,
                    Some(m6502_reg(register, 1)),
                    vec![constant(u64::from(bytes[1]), 1)],
                ));
                (2, Flow::FallThrough(address.wrapping_add(2)))
            }
            0xaa | 0xa8 | 0x8a | 0x98 => {
                let (destination, source) = match opcode {
                    0xaa => (1, 0),
                    0xa8 => (2, 0),
                    0x8a => (0, 1),
                    _ => (0, 2),
                };
                ops.push(p(
                    op::COPY,
                    Some(m6502_reg(destination, 1)),
                    vec![m6502_reg(source, 1)],
                ));
                (1, Flow::FallThrough(next))
            }
            0xe8 | 0xc8 | 0xca | 0x88 => {
                let (register, code) = match opcode {
                    0xe8 => (1, op::INT_ADD),
                    0xc8 => (2, op::INT_ADD),
                    0xca => (1, op::INT_SUB),
                    _ => (2, op::INT_SUB),
                };
                ops.push(p(
                    code,
                    Some(m6502_reg(register, 1)),
                    vec![m6502_reg(register, 1), constant(1, 1)],
                ));
                (1, Flow::FallThrough(next))
            }
            0x69 | 0xe9 | 0x29 | 0x09 | 0x49 => {
                if bytes.len() < 2 {
                    return Err(LiftError::Truncated { address, needed: 2 });
                }
                let code = match opcode {
                    0x69 => op::INT_ADD,
                    0xe9 => op::INT_SUB,
                    0x29 => op::INT_AND,
                    0x09 => op::INT_OR,
                    _ => op::INT_XOR,
                };
                ops.push(p(
                    code,
                    Some(m6502_reg(0, 1)),
                    vec![m6502_reg(0, 1), constant(u64::from(bytes[1]), 1)],
                ));
                (2, Flow::FallThrough(address.wrapping_add(2)))
            }
            0x8d | 0xad | 0x85 | 0xa5 => {
                let (length, target) = if opcode == 0x85 || opcode == 0xa5 {
                    if bytes.len() < 2 {
                        return Err(LiftError::Truncated { address, needed: 2 });
                    }
                    (2, u16::from(bytes[1]))
                } else {
                    if bytes.len() < 3 {
                        return Err(LiftError::Truncated { address, needed: 3 });
                    }
                    (3, m6502_address(bytes, 1))
                };
                let address_vn = constant(u64::from(target), 2);
                if opcode & 0x20 == 0 {
                    ops.push(p(
                        op::STORE,
                        None,
                        vec![m6502_ram_space(8), address_vn, m6502_reg(0, 1)],
                    ));
                } else {
                    ops.push(p(
                        op::LOAD,
                        Some(m6502_reg(0, 1)),
                        vec![m6502_ram_space(8), address_vn],
                    ));
                }
                (
                    length,
                    Flow::FallThrough(address.wrapping_add(length as u64)),
                )
            }
            0x4c | 0x20 => {
                if bytes.len() < 3 {
                    return Err(LiftError::Truncated { address, needed: 3 });
                }
                let target = u64::from(m6502_address(bytes, 1));
                if opcode == 0x4c {
                    ops.push(p(op::BRANCH, None, vec![constant(target, 2)]));
                    (3, Flow::Jump(target))
                } else {
                    ops.push(p(op::CALL, None, vec![constant(target, 2)]));
                    (
                        3,
                        Flow::Call {
                            target,
                            fallthrough: address.wrapping_add(3),
                        },
                    )
                }
            }
            0x10 | 0x30 | 0x50 | 0x70 | 0x90 | 0xb0 | 0xd0 | 0xf0 => {
                if bytes.len() < 2 {
                    return Err(LiftError::Truncated { address, needed: 2 });
                }
                let displacement = sign_extend(u64::from(bytes[1]), 8);
                let target = address.wrapping_add(2).wrapping_add(displacement as u64);
                let condition = unique(address, 1, 1);
                ops.push(p(op::CBRANCH, None, vec![constant(target, 2), condition]));
                (
                    2,
                    Flow::Conditional {
                        target,
                        fallthrough: address.wrapping_add(2),
                    },
                )
            }
            _ => {
                return Err(LiftError::Unsupported {
                    architecture: Architecture::M6502,
                    address,
                    opcode,
                });
            }
        };
        Ok(m68k_finish(address, &bytes[..length], ops, flow))
    }
}

fn z80_reg(index: u8, size: u32) -> Varnode {
    Varnode::new(REGISTER_SPACE, u64::from(index), size)
}

fn z80_ram_space(size: u32) -> Varnode {
    constant(417, size)
}

fn z80_address(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Z80;

impl Lifter for Z80 {
    fn architecture(&self) -> Architecture {
        Architecture::Z80
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        if bytes.is_empty() {
            return Err(LiftError::Truncated { address, needed: 1 });
        }
        let opcode = bytes[0];
        let mut ops = Vec::new();
        let next = address.wrapping_add(1);
        let (length, flow) = match opcode {
            0x00 => (1, Flow::FallThrough(next)),
            0xc9 => {
                ops.push(p(op::RETURN, None, vec![z80_reg(8, 2)]));
                (1, Flow::Return)
            }
            0x3e | 0x06 | 0x0e | 0x16 | 0x1e | 0x26 | 0x2e => {
                if bytes.len() < 2 {
                    return Err(LiftError::Truncated { address, needed: 2 });
                }
                let register = match opcode {
                    0x3e => 0,
                    0x06 => 2,
                    0x0e => 3,
                    0x16 => 4,
                    0x1e => 5,
                    0x26 => 6,
                    _ => 7,
                };
                ops.push(p(
                    op::COPY,
                    Some(z80_reg(register, 1)),
                    vec![constant(u64::from(bytes[1]), 1)],
                ));
                (2, Flow::FallThrough(address.wrapping_add(2)))
            }
            0x3c | 0x3d => {
                let code = if opcode == 0x3c {
                    op::INT_ADD
                } else {
                    op::INT_SUB
                };
                ops.push(p(
                    code,
                    Some(z80_reg(0, 1)),
                    vec![z80_reg(0, 1), constant(1, 1)],
                ));
                (1, Flow::FallThrough(next))
            }
            0xc6 | 0xd6 | 0xe6 | 0xf6 | 0xee => {
                if bytes.len() < 2 {
                    return Err(LiftError::Truncated { address, needed: 2 });
                }
                let code = match opcode {
                    0xc6 => op::INT_ADD,
                    0xd6 => op::INT_SUB,
                    0xe6 => op::INT_AND,
                    0xf6 => op::INT_OR,
                    _ => op::INT_XOR,
                };
                ops.push(p(
                    code,
                    Some(z80_reg(0, 1)),
                    vec![z80_reg(0, 1), constant(u64::from(bytes[1]), 1)],
                ));
                (2, Flow::FallThrough(address.wrapping_add(2)))
            }
            0xaf => {
                ops.push(p(
                    op::INT_XOR,
                    Some(z80_reg(0, 1)),
                    vec![z80_reg(0, 1), z80_reg(0, 1)],
                ));
                (1, Flow::FallThrough(next))
            }
            0x32 | 0x3a => {
                if bytes.len() < 3 {
                    return Err(LiftError::Truncated { address, needed: 3 });
                }
                let target = z80_address(bytes, 1);
                let address_vn = constant(u64::from(target), 2);
                if opcode == 0x32 {
                    ops.push(p(
                        op::STORE,
                        None,
                        vec![z80_ram_space(8), address_vn, z80_reg(0, 1)],
                    ));
                } else {
                    ops.push(p(
                        op::LOAD,
                        Some(z80_reg(0, 1)),
                        vec![z80_ram_space(8), address_vn],
                    ));
                }
                (3, Flow::FallThrough(address.wrapping_add(3)))
            }
            0xc3 | 0xcd => {
                if bytes.len() < 3 {
                    return Err(LiftError::Truncated { address, needed: 3 });
                }
                let target = u64::from(z80_address(bytes, 1));
                if opcode == 0xc3 {
                    ops.push(p(op::BRANCH, None, vec![constant(target, 2)]));
                    (3, Flow::Jump(target))
                } else {
                    ops.push(p(op::CALL, None, vec![constant(target, 2)]));
                    (
                        3,
                        Flow::Call {
                            target,
                            fallthrough: address.wrapping_add(3),
                        },
                    )
                }
            }
            0x18 | 0x20 | 0x28 => {
                if bytes.len() < 2 {
                    return Err(LiftError::Truncated { address, needed: 2 });
                }
                let displacement = sign_extend(u64::from(bytes[1]), 8);
                let target = address.wrapping_add(2).wrapping_add(displacement as u64);
                if opcode == 0x18 {
                    ops.push(p(op::BRANCH, None, vec![constant(target, 2)]));
                    (2, Flow::Jump(target))
                } else {
                    let condition = unique(address, 1, 1);
                    ops.push(p(op::CBRANCH, None, vec![constant(target, 2), condition]));
                    (
                        2,
                        Flow::Conditional {
                            target,
                            fallthrough: address.wrapping_add(2),
                        },
                    )
                }
            }
            _ => {
                return Err(LiftError::Unsupported {
                    architecture: Architecture::Z80,
                    address,
                    opcode,
                });
            }
        };
        Ok(m68k_finish(address, &bytes[..length], ops, flow))
    }
}
fn spu_reg(index: u8) -> Varnode {
    Varnode::new(REGISTER_SPACE, u64::from(index) * 16, 16)
}

fn spu_finish(address: u64, bytes: &[u8], ops: Vec<PcodeOp>, flow: Flow) -> LiftedInstruction {
    LiftedInstruction {
        address,
        bytes: bytes.to_vec(),
        pcode: InstPcode {
            len: 4,
            space: RAM_SPACE,
            offset: address,
            ops,
        },
        flow,
    }
}

/// Minimal Cell SPU control-flow lifter.  The format and ABI profile are
/// useful before the full vector ALU is implemented; unsupported arithmetic
/// remains an explicit error instead of silently becoming data.
#[derive(Copy, Clone, Debug, Default)]
pub struct Spu;

impl Lifter for Spu {
    fn architecture(&self) -> Architecture {
        Architecture::Spu
    }

    fn lift_instruction(&self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, LiftError> {
        if bytes.len() < 4 {
            return Err(LiftError::Truncated { address, needed: 4 });
        }
        let word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let opcode = word >> 21;
        let next = address.wrapping_add(4);
        let mut ops = Vec::new();
        let flow = match opcode {
            // STOP, LNОP, SYNC, and DSYNC are terminal/barrier-free for
            // intra-function discovery.  STOP is the SPU return analogue.
            0x000 => {
                ops.push(p(op::RETURN, None, vec![constant(0, 4)]));
                Flow::Return
            }
            0x001 | 0x002 | 0x003 => Flow::FallThrough(next),
            // BRA/BR/BRSL use a signed instruction displacement.
            0x180 | 0x190 => {
                let displacement = sign_extend(u64::from(word & 0xffff), 16) * 4;
                let target = next.wrapping_add(displacement as u64);
                ops.push(p(op::BRANCH, None, vec![constant(target, 4)]));
                Flow::Jump(target)
            }
            0x198 => {
                let displacement = sign_extend(u64::from(word & 0xffff), 16) * 4;
                let target = next.wrapping_add(displacement as u64);
                let link = ((word >> 14) & 0x7f) as u8;
                ops.push(p(op::CALL, Some(spu_reg(link)), vec![constant(target, 4)]));
                Flow::Call {
                    target,
                    fallthrough: next,
                }
            }
            // BI is register-indirect.  Keep the target in p-code and stop
            // local discovery; the caller can add an explicit function edge.
            0x1a8 => {
                let register = ((word >> 14) & 0x7f) as u8;
                ops.push(p(op::BRANCHIND, None, vec![spu_reg(register)]));
                Flow::Return
            }
            _ => {
                return Err(LiftError::Unsupported {
                    architecture: Architecture::Spu,
                    address,
                    opcode: (opcode & 0xff) as u8,
                });
            }
        };
        Ok(spu_finish(address, &bytes[..4], ops, flow))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_xor_and_return_are_lifted_with_control_flow() {
        let x = X86_64::new();
        let xor = x.lift_instruction(0x1000, &[0x31, 0xc0]).unwrap();
        assert_eq!(xor.pcode.len, 2);
        assert_eq!(xor.flow, Flow::FallThrough(0x1002));
        let ret = x.lift_instruction(0x1002, &[0xc3]).unwrap();
        assert_eq!(ret.flow, Flow::Return);
        assert!(ret.pcode.ops.iter().any(|op| op.opcode == op::RETURN));
    }

    #[test]
    fn x86_relative_call_is_recorded_without_inlining() {
        let x = X86_64::new();
        let call = x
            .lift_instruction(0x1000, &[0xe8, 0xfb, 0x00, 0x00, 0x00])
            .unwrap();
        assert_eq!(
            call.flow,
            Flow::Call {
                target: 0x1100,
                fallthrough: 0x1005
            }
        );
    }

    #[test]
    fn x86_sse_moves_lift_register_and_memory_operands() {
        let x = X86_64::new();

        let load = x
            .lift_instruction(0x1000, &[0x0f, 0x10, 0x85, 0xf0, 0x01, 0, 0])
            .unwrap();
        assert_eq!(load.flow, Flow::FallThrough(0x1007));
        assert!(
            load.pcode
                .ops
                .iter()
                .any(|op| op.opcode == op::LOAD && op.output.map(|output| output.size) == Some(16))
        );

        let store = x
            .lift_instruction(0x2000, &[0x0f, 0x29, 0x85, 0xe0, 0x02, 0, 0])
            .unwrap();
        assert_eq!(store.flow, Flow::FallThrough(0x2007));
        assert!(store.pcode.ops.iter().any(|op| {
            op.opcode == op::STORE && op.inputs.last().map(|input| input.size) == Some(16)
        }));

        let register = x.lift_instruction(0x3000, &[0x0f, 0x10, 0xc1]).unwrap();
        assert!(
            register
                .pcode
                .ops
                .iter()
                .any(|op| op.opcode == op::COPY && op.output == Some(x86_xmm_reg(0)))
        );
    }

    #[test]
    fn x86_immediate_extensions_and_indirect_terminators_are_lifted() {
        let x = X86_64::new();
        let sub = x
            .lift_instruction(0x1000, &[0x48, 0x81, 0xec, 0x28, 0, 0, 0])
            .unwrap();
        assert_eq!(sub.flow, Flow::FallThrough(0x1007));
        assert!(sub.pcode.ops.iter().any(|op| op.opcode == op::INT_SUB));

        let and = x.lift_instruction(0x1007, &[0x83, 0xe0, 0x01]).unwrap();
        assert_eq!(and.flow, Flow::FallThrough(0x100a));
        assert!(and.pcode.ops.iter().any(|op| op.opcode == op::INT_AND));

        let cmov = x
            .lift_instruction(0x100a, &[0x48, 0x0f, 0x48, 0xc1])
            .unwrap();
        assert_eq!(cmov.flow, Flow::FallThrough(0x100e));
        assert!(cmov.pcode.ops.iter().any(|op| op.opcode == op::CMOV));
        let tail = x.lift_instruction(0x100e, &[0xff, 0xe0]).unwrap();
        assert_eq!(tail.flow, Flow::Return);
        assert!(tail.pcode.ops.iter().any(|op| op.opcode == op::BRANCHIND));
    }

    #[test]
    fn ps2_three_operand_mult_writes_named_destination_and_lo_hi() {
        let instruction = Mips32
            .lift_instruction(0x125088, &[0x18, 0x18, 0xe5, 0x00])
            .unwrap();
        assert_eq!(instruction.flow, Flow::FallThrough(0x12508c));
        assert!(
            instruction
                .pcode
                .ops
                .iter()
                .any(|operation| operation.opcode == op::INT_MULT)
        );
        assert!(instruction.pcode.ops.iter().any(|operation| {
            operation.opcode == op::COPY && operation.output == Some(mips_reg(3, 4))
        }));
        assert!(instruction.pcode.ops.iter().any(|operation| {
            operation.opcode == op::SUBPIECE && operation.output == Some(mips_register(132, 4))
        }));
    }

    #[test]
    fn architecture_return_encodings_are_recognized() {
        assert_eq!(
            AArch64
                .lift_instruction(0x1000, &0xd65f03c0u32.to_le_bytes())
                .unwrap()
                .flow,
            Flow::Return
        );
        assert_eq!(
            Mips32
                .lift_instruction(0x1000, &0x03e00008u32.to_le_bytes())
                .unwrap()
                .flow,
            Flow::Return
        );
        assert_eq!(
            Ps1.lift_instruction(0x1000, &0x03e00008u32.to_le_bytes())
                .unwrap()
                .flow,
            Flow::Return
        );
        assert_eq!(
            N64.lift_instruction(0x1000, &0x03e00008u32.to_be_bytes())
                .unwrap()
                .flow,
            Flow::Return
        );
        assert_eq!(
            Ppc32
                .lift_instruction(0x1000, &0x4e800020u32.to_be_bytes())
                .unwrap()
                .flow,
            Flow::Return
        );
        assert_eq!(
            GameCube
                .lift_instruction(0x1000, &0x4e800020u32.to_be_bytes())
                .unwrap()
                .flow,
            Flow::Return
        );
    }

    #[test]
    fn processor_variants_preserve_register_widths_and_endianness() {
        let ps1 = Ps1
            .lift_instruction(0x1000, &0x2402002au32.to_le_bytes())
            .unwrap();
        assert_eq!(
            ps1.pcode.ops[0].output,
            Some(Varnode::new(REGISTER_SPACE, 8, 4))
        );

        let n64 = N64
            .lift_instruction(0x1000, &0x6402002au32.to_be_bytes())
            .unwrap();
        assert_eq!(
            n64.pcode.ops[0].output,
            Some(Varnode::new(REGISTER_SPACE, 16, 8))
        );

        let gamecube = GameCube
            .lift_instruction(0x1000, &0x3860002au32.to_be_bytes())
            .unwrap();
        assert_eq!(
            gamecube.pcode.ops[0].output,
            Some(Varnode::new(REGISTER_SPACE, 3 * 4, 4))
        );
    }

    #[test]
    fn arm64_conditional_branch_and_mips_indirect_call_keep_control_flow_local() {
        let arm = AArch64
            .lift_instruction(0x1000, &0x5400_0040u32.to_le_bytes())
            .unwrap();
        assert_eq!(
            arm.flow,
            Flow::Conditional {
                target: 0x1008,
                fallthrough: 0x1004
            }
        );
        assert!(arm.pcode.ops.iter().any(|op| op.opcode == op::CBRANCH));

        let mips = Mips32
            .lift_instruction(0x2000, &0x0320_0009u32.to_le_bytes())
            .unwrap();
        assert_eq!(mips.flow, Flow::FallThrough(0x2004));
        assert!(mips.pcode.ops.iter().any(|op| op.opcode == op::CALLIND));
    }

    #[test]
    fn mips_o32_calls_preserve_targets_argument_order_and_return_register() {
        let direct_target: u64 = 0x2000;
        let direct_word = (3u32 << 26) | (((direct_target >> 2) as u32) & 0x03ff_ffff);
        let direct = Mips32
            .lift_instruction(0x1000, &direct_word.to_le_bytes())
            .unwrap();
        assert_eq!(
            direct.flow,
            Flow::Call {
                target: direct_target,
                fallthrough: 0x1004
            }
        );
        let direct_call = direct
            .pcode
            .ops
            .iter()
            .find(|operation| operation.opcode == op::CALL)
            .expect("direct MIPS call p-code");
        assert_eq!(direct_call.output, Some(mips_reg(2, 4)));
        assert_eq!(
            direct_call.inputs,
            vec![
                constant(direct_target, 4),
                mips_reg(4, 4),
                mips_reg(5, 4),
                mips_reg(6, 4),
                mips_reg(7, 4),
                mips_register(0x230, 4),
                mips_register(0x238, 4),
            ]
        );

        let indirect_word = (25u32 << 21) | (31u32 << 11) | 9;
        let indirect = Mips32
            .lift_instruction(0x1100, &indirect_word.to_le_bytes())
            .unwrap();
        assert_eq!(indirect.flow, Flow::FallThrough(0x1104));
        let indirect_call = indirect
            .pcode
            .ops
            .iter()
            .find(|operation| operation.opcode == op::CALLIND)
            .expect("indirect MIPS call p-code");
        assert_eq!(indirect_call.output, Some(mips_reg(2, 4)));
        assert_eq!(
            indirect_call.inputs,
            vec![
                mips_reg(25, 4),
                mips_reg(4, 4),
                mips_reg(5, 4),
                mips_reg(6, 4),
                mips_reg(7, 4),
                mips_register(0x230, 4),
                mips_register(0x238, 4),
            ]
        );
    }

    #[test]
    fn ps1_calls_do_not_claim_ps2_hard_float_argument_registers() {
        let target: u64 = 0x2000;
        let word = (3u32 << 26) | (((target >> 2) as u32) & 0x03ff_ffff);
        let instruction = Ps1.lift_instruction(0x1000, &word.to_le_bytes()).unwrap();
        let call = instruction
            .pcode
            .ops
            .iter()
            .find(|operation| operation.opcode == op::CALL)
            .expect("direct PS1 call p-code");
        assert_eq!(
            call.inputs,
            vec![
                constant(target, 4),
                mips_reg(4, 4),
                mips_reg(5, 4),
                mips_reg(6, 4),
                mips_reg(7, 4),
            ]
        );
    }

    #[test]
    fn mips_call_discovery_keeps_delay_slots() {
        let image = Image {
            len: 16,
            format: ventris_format::Format::Pe(ventris_format::PeFacts {
                machine: 0x8664,
                plus: true,
                image_base: 0,
            }),
            segments: vec![ventris_format::Segment {
                name: Some(".text".into()),
                addr: 0x1000,
                size: 16,
                file_off: 0,
                file_size: 16,
                perms: ventris_format::Perms {
                    read: Some(true),
                    write: Some(false),
                    exec: Some(true),
                },
            }],
            regions: Vec::new(),
            entry: Some(0x1000),
            symbol_count: 0,
        };
        let file = [
            0x00, 0x08, 0x00, 0x0c, // jal 0x2000
            0x01, 0x00, 0x84, 0x24, // addiu a0, a0, 1
            0x08, 0x00, 0xe0, 0x03, // jr ra
            0x00, 0x00, 0x00, 0x00, // delay-slot nop
        ];
        let function = Mips32.discover(&image, &file, 0x1000, 8).unwrap();
        assert_eq!(function.calls, BTreeSet::from([0x2000]));
        assert!(function.instructions.contains_key(&0x1004));
        assert!(function.instructions.contains_key(&0x100c));
    }

    #[test]
    fn mips_jump_discovery_does_not_follow_delay_slot_fallthrough() {
        let image = Image {
            len: 12,
            format: ventris_format::Format::Pe(ventris_format::PeFacts {
                machine: 0x8664,
                plus: true,
                image_base: 0,
            }),
            segments: vec![ventris_format::Segment {
                name: Some(".text".into()),
                addr: 0x1000,
                size: 12,
                file_off: 0,
                file_size: 12,
                perms: ventris_format::Perms {
                    read: Some(true),
                    write: Some(false),
                    exec: Some(true),
                },
            }],
            regions: Vec::new(),
            entry: Some(0x1000),
            symbol_count: 0,
        };
        let file = [
            0x00, 0x04, 0x00, 0x08, // j 0x1000
            0x00, 0x00, 0x00, 0x00, // delay-slot nop
            0xff, 0xff, 0xff, 0xff, // unreachable invalid instruction
        ];
        let function = Mips32.discover(&image, &file, 0x1000, 8).unwrap();
        assert_eq!(
            function.instructions.keys().copied().collect::<Vec<_>>(),
            vec![0x1000, 0x1004]
        );
    }

    #[test]
    fn x86_test_lifts_byte_register_and_memory_operands() {
        let x = X86_64::new();

        let register = x.lift_instruction(0x1000, &[0x84, 0xc0]).unwrap();
        assert_eq!(register.pcode.len, 2);
        assert!(register.pcode.ops.iter().any(|op| op.opcode == op::INT_AND));
        assert!(register.pcode.ops.iter().any(|op| {
            op.opcode == op::COPY
                && op.output == Some(flag(512))
                && op.inputs == vec![constant(0, 1)]
        }));
        assert!(register.pcode.ops.iter().any(|op| {
            op.opcode == op::COPY
                && op.output == Some(flag(523))
                && op.inputs == vec![constant(0, 1)]
        }));

        let memory = x.lift_instruction(0x2000, &[0x84, 0x00]).unwrap();
        assert_eq!(memory.pcode.len, 2);
        assert!(
            memory.pcode.ops.iter().any(|op| {
                op.opcode == op::LOAD && op.output.map(|output| output.size) == Some(1)
            })
        );

        let high_byte = x.lift_instruction(0x3000, &[0x84, 0xe0]).unwrap();
        let and = high_byte
            .pcode
            .ops
            .iter()
            .find(|op| op.opcode == op::INT_AND)
            .unwrap();
        assert!(and.inputs.iter().any(|input| input.offset == 1));
        assert!(and.inputs.iter().any(|input| input.offset == 0));
    }

    #[test]
    fn x86_real_binary_byte_immediates_and_memory_calls_are_lifted() {
        let x = X86_64::new();

        let byte_imm = x.lift_instruction(0x1000, &[0x40, 0xb6, 0x01]).unwrap();
        assert_eq!(byte_imm.flow, Flow::FallThrough(0x1003));
        assert!(byte_imm.pcode.ops.iter().any(|op| {
            op.opcode == op::COPY
                && op.output == Some(x86_byte_reg(6, 0x40))
                && op.inputs == vec![constant(1, 1)]
        }));

        let byte_store = x
            .lift_instruction(0x1003, &[0x40, 0x88, 0x74, 0x24, 0x20])
            .unwrap();
        assert_eq!(byte_store.flow, Flow::FallThrough(0x1008));
        assert!(byte_store.pcode.ops.iter().any(|op| {
            op.opcode == op::STORE && op.inputs.last().map(|input| input.size) == Some(1)
        }));

        let immediate_memory = x
            .lift_instruction(0x2000, &[0x48, 0x83, 0x38, 0x00])
            .unwrap();
        assert!(
            immediate_memory
                .pcode
                .ops
                .iter()
                .any(|op| op.opcode == op::LOAD)
        );
        assert!(
            immediate_memory
                .pcode
                .ops
                .iter()
                .any(|op| op.opcode == op::INT_EQUAL)
        );

        let store_immediate = x
            .lift_instruction(0x3000, &[0xc7, 0x05, 0, 0, 0, 0, 1, 0, 0, 0])
            .unwrap();
        assert_eq!(store_immediate.flow, Flow::FallThrough(0x300a));
        assert!(
            store_immediate
                .pcode
                .ops
                .iter()
                .any(|op| op.opcode == op::STORE)
        );

        let indirect_call = x
            .lift_instruction(0x4000, &[0xff, 0x15, 0, 0, 0, 0])
            .unwrap();
        assert_eq!(indirect_call.flow, Flow::FallThrough(0x4006));
        assert!(
            indirect_call
                .pcode
                .ops
                .iter()
                .any(|op| op.opcode == op::CALLIND)
        );
    }

    #[test]
    fn discovery_follows_branches_and_excludes_calls() {
        let image = Image {
            len: 3,

            format: ventris_format::Format::Pe(ventris_format::PeFacts {
                machine: 0x8664,
                plus: true,
                image_base: 0,
            }),
            segments: vec![ventris_format::Segment {
                name: Some(".text".into()),
                addr: 0x1000,
                size: 3,
                file_off: 0,
                file_size: 3,
                perms: ventris_format::Perms {
                    read: Some(true),
                    write: Some(false),
                    exec: Some(true),
                },
            }],
            regions: Vec::new(),
            entry: Some(0x1000),
            symbol_count: 0,
        };
        let function = X86_64
            .discover(&image, &[0x31, 0xc0, 0xc3], 0x1000, 8)
            .unwrap();
        assert_eq!(function.instruction_count(), 2);
        assert_eq!(function.byte_length(), 3);
        assert!(function.calls.is_empty());
    }
}
