//! Game-oriented ABI facts and evidence-backed type recovery.
//!
//! This crate is deliberately conservative. It consumes lifted p-code and
//! externally asserted metadata, but never turns an observed width into a
//! guessed `int`, pointer, or engine type. Unknown bytes remain explicit and
//! every recovered field carries the evidence that caused it to exist.

#![forbid(unsafe_code)]

pub mod assets;
pub mod corpus;
pub mod diff;
pub mod patterns;
pub mod reconstruction;
pub mod runtime;
use std::collections::BTreeMap;
use std::fmt::Write;
use ventris_lifter::{Architecture, NativeFunction};
use ventris_pcode::{op, Varnode, CONST_SPACE};
use ventris_target::TargetProfile;

/// Whether a register class is known for a target ABI.
///
/// `Some(&[])` means the ABI explicitly has no registers in that class;
/// `None` means the profile has not asserted the class yet. The distinction is
/// important for vector and platform-specific FPU conventions.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RegisterGroup {
    pub names: Option<&'static [&'static str]>,
    pub single: Option<&'static str>,
}

impl RegisterGroup {
    pub const fn known(names: &'static [&'static str]) -> Self {
        Self {
            names: Some(names),
            single: None,
        }
    }

    pub const fn known_single(name: &'static str) -> Self {
        Self {
            names: None,
            single: Some(name),
        }
    }

    pub const fn unknown() -> Self {
        Self {
            names: None,
            single: None,
        }
    }

    pub fn is_known(self) -> bool {
        self.names.is_some() || self.single.is_some()
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AbiRegisterClass {
    Integer,
    Floating,
    Vector,
}

impl RegisterGroup {
    /// Return the register spelling for an ABI argument/return slot.
    pub fn at(self, index: usize) -> Option<&'static str> {
        self.names
            .and_then(|names| names.get(index).copied())
            .or_else(|| (index == 0).then_some(self.single).flatten())
    }

    pub fn count(self) -> Option<usize> {
        self.names
            .map(|names| names.len())
            .or_else(|| self.single.map(|_| 1))
    }
}

impl AbiRegisterClasses {
    pub const fn group(self, class: AbiRegisterClass) -> RegisterGroup {
        match class {
            AbiRegisterClass::Integer => self.integer,
            AbiRegisterClass::Floating => self.floating,
            AbiRegisterClass::Vector => self.vector,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct AbiRegisterClasses {
    pub integer: RegisterGroup,
    pub floating: RegisterGroup,
    pub vector: RegisterGroup,
}

/// The ABI facts needed before rendering game C/C++.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct GameAbiProfile {
    pub target: TargetProfile,
    pub name: &'static str,
    pub architecture: Architecture,
    pub pointer_bits: u8,
    pub stack_alignment: u8,
    pub stack_pointer: &'static str,
    pub frame_pointer: Option<&'static str>,
    pub return_address: Option<&'static str>,
    pub delay_slots: u8,
    pub arguments: AbiRegisterClasses,
    pub returns: AbiRegisterClasses,
    pub caller_saved: RegisterGroup,
    pub callee_saved: RegisterGroup,
    pub small_struct_max_bytes: Option<u8>,
    pub small_struct_returns: RegisterGroup,
}

const EMPTY: &[&str] = &[];
const MIPS_ARGS: &[&str] = &["$a0", "$a1", "$a2", "$a3"];
const MIPS_RETURNS: &[&str] = &["$v0", "$v1"];
const MIPS_FLOAT_ARGS: &[&str] = &["$f12", "$f14"];
const MIPS_FLOAT_RETURNS: &[&str] = &["$f0", "$f2"];
const MIPS_CALLER: &[&str] = &[
    "$v0", "$v1", "$a0", "$a1", "$a2", "$a3", "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6",
    "$t7", "$t8", "$t9",
];
const MIPS_CALLEE: &[&str] = &[
    "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7", "$fp",
];
const ARM_ARGS: &[&str] = &["r0", "r1", "r2", "r3"];
const ARM_RETURNS: &[&str] = &["r0", "r1"];
const ARM_FLOAT_ARGS: &[&str] = &[
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13", "s14",
    "s15",
];
const ARM_FLOAT_RETURNS: &[&str] = &["s0", "s1"];
const ARM_CALLER: &[&str] = &["r0", "r1", "r2", "r3", "r12", "lr"];
const ARM_CALLEE: &[&str] = &["r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"];
const PPC_ARGS: &[&str] = &["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"];
const PPC_RETURNS: &[&str] = &["r3", "r4"];
const PPC_FLOAT_ARGS: &[&str] = &["f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8"];
const PPC_FLOAT_RETURNS: &[&str] = &["f1", "f2"];
const PPC_CALLER: &[&str] = &[
    "r0", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr", "f0", "f1", "f2",
    "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10", "f11", "f12", "f13",
];
const PPC_CALLEE: &[&str] = &[
    "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26",
    "r27", "r28", "r29", "r30", "r31",
];

fn classes(
    integer: RegisterGroup,
    floating: RegisterGroup,
    vector: RegisterGroup,
) -> AbiRegisterClasses {
    AbiRegisterClasses {
        integer,
        floating,
        vector,
    }
}

impl GameAbiProfile {
    /// Return the explicit ABI profile for a console target.
    pub fn for_target(target: TargetProfile) -> Self {
        match target {
            TargetProfile::Ps2 => Self {
                target,
                name: "ps2-r5900-o32",
                architecture: Architecture::Mips32,
                pointer_bits: 32,
                stack_alignment: 8,
                stack_pointer: "$sp",
                frame_pointer: Some("$fp"),
                return_address: Some("$ra"),
                delay_slots: 1,
                arguments: classes(
                    RegisterGroup::known(MIPS_ARGS),
                    RegisterGroup::known(MIPS_FLOAT_ARGS),
                    RegisterGroup::unknown(),
                ),
                returns: classes(
                    RegisterGroup::known(MIPS_RETURNS),
                    RegisterGroup::known(MIPS_FLOAT_RETURNS),
                    RegisterGroup::unknown(),
                ),
                caller_saved: RegisterGroup::known(MIPS_CALLER),
                callee_saved: RegisterGroup::known(MIPS_CALLEE),
                small_struct_max_bytes: Some(8),
                small_struct_returns: RegisterGroup::known(MIPS_RETURNS),
            },
            TargetProfile::Psp => Self {
                target,
                name: "psp-allegrex-o32",
                architecture: Architecture::Mips32,
                pointer_bits: 32,
                stack_alignment: 8,
                stack_pointer: "$sp",
                frame_pointer: Some("$fp"),
                return_address: Some("$ra"),
                delay_slots: 1,
                arguments: classes(
                    RegisterGroup::known(MIPS_ARGS),
                    RegisterGroup::known(MIPS_FLOAT_ARGS),
                    RegisterGroup::unknown(),
                ),
                returns: classes(
                    RegisterGroup::known(MIPS_RETURNS),
                    RegisterGroup::known(MIPS_FLOAT_RETURNS),
                    RegisterGroup::unknown(),
                ),
                caller_saved: RegisterGroup::known(MIPS_CALLER),
                callee_saved: RegisterGroup::known(MIPS_CALLEE),
                small_struct_max_bytes: Some(8),
                small_struct_returns: RegisterGroup::known(MIPS_RETURNS),
            },
            TargetProfile::GameCube | TargetProfile::Wii | TargetProfile::WiiU => Self {
                target,
                name: "powerpc-eabi-game",
                architecture: target.spec().architecture,
                pointer_bits: 32,
                stack_alignment: 16,
                stack_pointer: "r1",
                frame_pointer: None,
                return_address: Some("lr"),
                delay_slots: 0,
                arguments: classes(
                    RegisterGroup::known(PPC_ARGS),
                    RegisterGroup::known(PPC_FLOAT_ARGS),
                    RegisterGroup::unknown(),
                ),
                returns: classes(
                    RegisterGroup::known(PPC_RETURNS),
                    RegisterGroup::known(PPC_FLOAT_RETURNS),
                    RegisterGroup::unknown(),
                ),
                caller_saved: RegisterGroup::known(PPC_CALLER),
                callee_saved: RegisterGroup::known(PPC_CALLEE),
                small_struct_max_bytes: Some(8),
                small_struct_returns: RegisterGroup::known(PPC_RETURNS),
            },
            TargetProfile::Xbox360 => Self {
                target,
                name: "xbox360-xenon-pprc",
                architecture: Architecture::Ppc32,
                pointer_bits: 32,
                stack_alignment: 16,
                stack_pointer: "r1",
                frame_pointer: None,
                return_address: Some("lr"),
                delay_slots: 0,
                arguments: classes(
                    RegisterGroup::known(PPC_ARGS),
                    RegisterGroup::known(PPC_FLOAT_ARGS),
                    RegisterGroup::unknown(),
                ),
                returns: classes(
                    RegisterGroup::known(PPC_RETURNS),
                    RegisterGroup::known(PPC_FLOAT_RETURNS),
                    RegisterGroup::unknown(),
                ),
                caller_saved: RegisterGroup::known(PPC_CALLER),
                callee_saved: RegisterGroup::known(PPC_CALLEE),
                small_struct_max_bytes: Some(8),
                small_struct_returns: RegisterGroup::known(PPC_RETURNS),
            },
            TargetProfile::Ps3Ppu => Self {
                target,
                name: "ps3-ppu-elfv2",
                architecture: Architecture::Ppc64,
                pointer_bits: 64,
                stack_alignment: 16,
                stack_pointer: "r1",
                frame_pointer: None,
                return_address: Some("lr"),
                delay_slots: 0,
                arguments: classes(
                    RegisterGroup::known(PPC_ARGS),
                    RegisterGroup::known(PPC_FLOAT_ARGS),
                    RegisterGroup::unknown(),
                ),
                returns: classes(
                    RegisterGroup::known(PPC_RETURNS),
                    RegisterGroup::known(PPC_FLOAT_RETURNS),
                    RegisterGroup::unknown(),
                ),
                caller_saved: RegisterGroup::known(PPC_CALLER),
                callee_saved: RegisterGroup::known(PPC_CALLEE),
                small_struct_max_bytes: Some(16),
                small_struct_returns: RegisterGroup::known(PPC_RETURNS),
            },
            TargetProfile::Ps3Spu => Self {
                target,
                name: "ps3-spu-ls",
                architecture: Architecture::Spu,
                pointer_bits: 32,
                stack_alignment: 16,
                stack_pointer: "r1",
                frame_pointer: None,
                return_address: None,
                delay_slots: 0,
                arguments: classes(
                    RegisterGroup::known(PPC_ARGS),
                    RegisterGroup::unknown(),
                    RegisterGroup::known(EMPTY),
                ),
                returns: classes(
                    RegisterGroup::known(&["r3"]),
                    RegisterGroup::unknown(),
                    RegisterGroup::known(EMPTY),
                ),
                caller_saved: RegisterGroup::unknown(),
                callee_saved: RegisterGroup::unknown(),
                small_struct_max_bytes: None,
                small_struct_returns: RegisterGroup::unknown(),
            },
            TargetProfile::NintendoDs
            | TargetProfile::Nintendo3Ds
            | TargetProfile::Vita
            | TargetProfile::Gba => Self {
                target,
                name: "arm-aapcs-game",
                architecture: target.spec().architecture,
                pointer_bits: 32,
                stack_alignment: if target == TargetProfile::Gba { 4 } else { 8 },
                stack_pointer: "r13",
                frame_pointer: Some("r11"),
                return_address: Some("lr"),
                delay_slots: 0,
                arguments: classes(
                    RegisterGroup::known(ARM_ARGS),
                    RegisterGroup::known(ARM_FLOAT_ARGS),
                    RegisterGroup::unknown(),
                ),
                returns: classes(
                    RegisterGroup::known(ARM_RETURNS),
                    RegisterGroup::known(ARM_FLOAT_RETURNS),
                    RegisterGroup::unknown(),
                ),
                caller_saved: RegisterGroup::known(ARM_CALLER),
                callee_saved: RegisterGroup::known(ARM_CALLEE),
                small_struct_max_bytes: Some(4),
                small_struct_returns: RegisterGroup::known(ARM_RETURNS),
            },
            TargetProfile::Ps1 => Self {
                target,
                name: "ps1-mips-o32",
                architecture: Architecture::Ps1,
                pointer_bits: 32,
                stack_alignment: 8,
                stack_pointer: "$sp",
                frame_pointer: Some("$fp"),
                return_address: Some("$ra"),
                delay_slots: 1,
                arguments: classes(
                    RegisterGroup::known(MIPS_ARGS),
                    RegisterGroup::unknown(),
                    RegisterGroup::unknown(),
                ),
                returns: classes(
                    RegisterGroup::known(MIPS_RETURNS),
                    RegisterGroup::unknown(),
                    RegisterGroup::unknown(),
                ),
                caller_saved: RegisterGroup::known(MIPS_CALLER),
                callee_saved: RegisterGroup::known(MIPS_CALLEE),
                small_struct_max_bytes: Some(8),
                small_struct_returns: RegisterGroup::known(MIPS_RETURNS),
            },
            TargetProfile::N64 => Self {
                target,
                name: "n64-mips-n64",
                architecture: Architecture::N64,
                pointer_bits: 64,
                stack_alignment: 16,
                stack_pointer: "$sp",
                frame_pointer: Some("$fp"),
                return_address: Some("$ra"),
                delay_slots: 1,
                arguments: classes(
                    RegisterGroup::known(MIPS_ARGS),
                    RegisterGroup::known(MIPS_FLOAT_ARGS),
                    RegisterGroup::unknown(),
                ),
                returns: classes(
                    RegisterGroup::known(MIPS_RETURNS),
                    RegisterGroup::known(MIPS_FLOAT_RETURNS),
                    RegisterGroup::unknown(),
                ),
                caller_saved: RegisterGroup::known(MIPS_CALLER),
                callee_saved: RegisterGroup::known(MIPS_CALLEE),
                small_struct_max_bytes: Some(16),
                small_struct_returns: RegisterGroup::known(MIPS_RETURNS),
            },
            _ => Self::generic(target),
        }
    }

    fn generic(target: TargetProfile) -> Self {
        let spec = target.spec();
        Self {
            target,
            name: spec.abi.name,
            architecture: spec.architecture,
            pointer_bits: spec.abi.pointer_bits,
            stack_alignment: spec.abi.stack_alignment,
            stack_pointer: "sp",
            frame_pointer: None,
            return_address: None,
            delay_slots: 0,
            arguments: classes(
                RegisterGroup::unknown(),
                RegisterGroup::unknown(),
                RegisterGroup::unknown(),
            ),
            returns: classes(
                RegisterGroup::known_single(spec.abi.return_register),
                RegisterGroup::unknown(),
                RegisterGroup::unknown(),
            ),
            caller_saved: RegisterGroup::unknown(),
            callee_saved: RegisterGroup::unknown(),
            small_struct_max_bytes: None,
            small_struct_returns: RegisterGroup::unknown(),
        }
    }
    pub fn argument_register(&self, class: AbiRegisterClass, index: usize) -> Option<&'static str> {
        self.arguments.group(class).at(index)
    }

    pub fn return_register(&self, class: AbiRegisterClass, index: usize) -> Option<&'static str> {
        self.returns.group(class).at(index)
    }

    /// Return the byte offset of an overflow argument relative to the first
    /// stack-passed argument, using pointer-sized ABI slots.
    pub fn stack_argument_offset(&self, index: usize, width_bits: u32) -> u32 {
        let pointer_bytes = u32::from(self.pointer_bits.div_ceil(8)).max(1);
        let width_bytes = width_bits.div_ceil(8).max(1);
        let slot_bytes = width_bytes.div_ceil(pointer_bytes) * pointer_bytes;
        (index as u32).saturating_mul(slot_bytes)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Confidence(u8);

impl Confidence {
    pub const fn new(value: u8) -> Option<Self> {
        if value <= 100 {
            Some(Self(value))
        } else {
            None
        }
    }

    pub const fn value(self) -> u8 {
        self.0
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AccessKind {
    Read,
    Write,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EvidenceSource {
    PcodeAccess {
        instruction: u64,
        opcode: i32,
        access: AccessKind,
    },
    PcodeStride {
        instruction: u64,
        stride: u32,
    },
    Symbol {
        address: u64,
        name: String,
    },
    Relocation {
        address: u64,
        symbol: String,
    },
    Annotation {
        address: u64,
        text: String,
    },
    NominalType {
        id: u64,
        name: String,
    },
    EmulatorMemory {
        sequence: u64,
        instruction: u64,
        access: AccessKind,
        address: u64,
        width: u32,
        value: Option<u64>,
    },
    EmulatorCall {
        sequence: u64,
        instruction: u64,
        target: u64,
    },
    EmulatorRegister {
        sequence: u64,
        instruction: u64,
        register: String,
        value: u64,
    },
    EmulatorMarker {
        sequence: u64,
        instruction: u64,
        text: String,
    },
    UserAssertion {
        note: String,
    },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Evidence {
    pub source: EvidenceSource,
    pub confidence: Confidence,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum GameType {
    /// Width observed, but no semantic type asserted.
    UnknownBytes {
        width: u32,
    },
    Primitive {
        name: String,
        bits: u16,
        signed: Option<bool>,
    },
    Nominal {
        id: Option<u64>,
        name: String,
        size: u32,
    },
    Pointer {
        to: Box<GameType>,
        bits: u16,
    },
    Array {
        element: Box<GameType>,
        count: Option<u32>,
        stride: u32,
    },
    /// A named integer domain whose values are supplied by game metadata.
    Enum {
        name: String,
        bits: u16,
        signed: Option<bool>,
    },
    /// A code pointer; target is optional because stripped images may not
    /// provide a resolved destination yet.
    FunctionPointer {
        target: Option<u64>,
        bits: u16,
    },
    Vector {
        lane: Box<GameType>,
        lanes: u8,
    },
    Handle {
        name: String,
        bits: u16,
    },
}

impl GameType {
    pub fn unknown(width: u32) -> Self {
        Self::UnknownBytes { width }
    }

    pub fn nominal(id: Option<u64>, name: impl Into<String>, size: u32) -> Self {
        Self::Nominal {
            id,
            name: name.into(),
            size,
        }
    }

    pub fn enum_type(name: impl Into<String>, bits: u16, signed: Option<bool>) -> Self {
        Self::Enum {
            name: name.into(),
            bits,
            signed,
        }
    }

    pub fn function_pointer(target: Option<u64>, bits: u16) -> Self {
        Self::FunctionPointer { target, bits }
    }

    fn display(&self) -> String {
        match self {
            Self::UnknownBytes { width } => format!("unknown_bytes[{width}]"),
            Self::Primitive { name, bits, signed } => match signed {
                Some(true) => format!("{name}{bits}"),
                Some(false) => format!("u{bits}"),
                None => name.clone(),
            },
            Self::Nominal { name, .. } => name.clone(),
            Self::Pointer { to, bits } => format!("{}*[{bits}]", to.display()),
            Self::Array {
                element,
                count,
                stride,
            } => format!(
                "{}[{}; stride={stride}]",
                element.display(),
                count.map_or_else(|| "?".into(), |n| n.to_string())
            ),
            Self::Enum { name, .. } => name.clone(),
            Self::FunctionPointer { target, bits } => target.map_or_else(
                || format!("fn*[{bits}]"),
                |target| format!("fn@0x{target:x}[{bits}]"),
            ),
            Self::Vector { lane, lanes } => format!("vec{lanes}<{}>", lane.display()),
            Self::Handle { name, bits } => format!("{name} handle[{bits}]"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NominalField {
    pub offset: i64,
    pub name: String,
    pub ty: GameType,
    pub width: u32,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NominalType {
    pub id: u64,
    pub name: String,
    pub size: u32,
    pub fields: Vec<NominalField>,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SymbolFact {
    pub address: u64,
    pub name: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RelocationFact {
    pub address: u64,
    pub symbol: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AnnotationFact {
    pub address: u64,
    pub text: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TypeAssertion {
    pub base: Varnode,
    pub offset: i64,
    pub name: Option<String>,
    pub ty: GameType,
    pub note: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MemoryAccess {
    pub instruction: u64,
    pub kind: AccessKind,
    pub width: u32,
    pub address: AddressFact,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AddressFact {
    Absolute {
        address: u64,
    },
    BaseOffset {
        base: Varnode,
        offset: i64,
        stride: Option<u32>,
    },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecoveredField {
    pub offset: i64,
    pub width: u32,
    pub name: Option<String>,
    pub ty: GameType,
    pub accesses: Vec<MemoryAccess>,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StructCandidate {
    pub base: Varnode,
    pub name: Option<String>,
    pub fields: Vec<RecoveredField>,
    pub strides: Vec<u32>,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecoveredFunction {
    pub target: TargetProfile,
    pub abi: GameAbiProfile,
    pub entry: u64,
    pub name: Option<String>,
    pub accesses: Vec<MemoryAccess>,
    pub structs: Vec<StructCandidate>,
    pub provenance: Vec<Evidence>,
}

pub struct RecoveryInput<'a> {
    pub function: &'a NativeFunction,
    pub nominal_types: &'a [NominalType],
    pub symbols: &'a [SymbolFact],
    pub relocations: &'a [RelocationFact],
    pub annotations: &'a [AnnotationFact],
    pub assertions: &'a [TypeAssertion],
}

impl<'a> RecoveryInput<'a> {
    pub fn new(function: &'a NativeFunction) -> Self {
        Self {
            function,
            nominal_types: &[],
            symbols: &[],
            relocations: &[],
            annotations: &[],
            assertions: &[],
        }
    }
}

#[derive(Clone, Debug)]
enum AddressExpr {
    Absolute(u64),
    Base {
        base: Varnode,
        offset: i64,
        stride: Option<u32>,
    },
}

impl AddressExpr {
    fn add(self, value: i64) -> Self {
        match self {
            Self::Absolute(address) => Self::Absolute(address.wrapping_add(value as u64)),
            Self::Base {
                base,
                offset,
                stride,
            } => Self::Base {
                base,
                offset: offset.saturating_add(value),
                stride,
            },
        }
    }

    fn fact(self) -> AddressFact {
        match self {
            Self::Absolute(address) => AddressFact::Absolute { address },
            Self::Base {
                base,
                offset,
                stride,
            } => AddressFact::BaseOffset {
                base,
                offset,
                stride,
            },
        }
    }
}

fn signed_constant(v: Varnode) -> Option<i64> {
    if v.space != CONST_SPACE || v.size == 0 {
        return None;
    }
    let bits = v.size.saturating_mul(8).min(64);
    if bits == 64 {
        return Some(v.offset as i64);
    }
    let shift = 64 - bits;
    Some(((v.offset << shift) as i64) >> shift)
}

fn address_expr(v: Varnode, values: &BTreeMap<VarnodeKey, AddressExpr>) -> AddressExpr {
    if let Some(expr) = values.get(&VarnodeKey::from(v)) {
        return expr.clone();
    }
    if let Some(value) = signed_constant(v) {
        return AddressExpr::Absolute(value as u64);
    }
    AddressExpr::Base {
        base: v,
        offset: 0,
        stride: None,
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct VarnodeKey {
    space: u32,
    offset: u64,
    size: u32,
}

impl From<Varnode> for VarnodeKey {
    fn from(v: Varnode) -> Self {
        Self {
            space: v.space,
            offset: v.offset,
            size: v.size,
        }
    }
}

fn set_copy(
    output: Option<Varnode>,
    input: Option<Varnode>,
    values: &mut BTreeMap<VarnodeKey, AddressExpr>,
) {
    let (Some(output), Some(input)) = (output, input) else {
        return;
    };
    if let Some(expr) = values.get(&VarnodeKey::from(input)).cloned() {
        values.insert(VarnodeKey::from(output), expr);
    } else if input.space == CONST_SPACE {
        if let Some(value) = signed_constant(input) {
            values.insert(
                VarnodeKey::from(output),
                AddressExpr::Absolute(value as u64),
            );
        }
    } else {
        values.insert(
            VarnodeKey::from(output),
            AddressExpr::Base {
                base: input,
                offset: 0,
                stride: None,
            },
        );
    }
}

fn set_add(
    output: Option<Varnode>,
    inputs: &[Varnode],
    subtract: bool,
    values: &mut BTreeMap<VarnodeKey, AddressExpr>,
) {
    let (Some(output), Some(left), Some(right)) = (output, inputs.first(), inputs.get(1)) else {
        return;
    };
    let left_expr = address_expr(*left, values);
    let right_expr = address_expr(*right, values);
    let expr = match (left_expr, right_expr) {
        (AddressExpr::Absolute(a), AddressExpr::Absolute(b)) => {
            AddressExpr::Absolute(if subtract {
                a.wrapping_sub(b)
            } else {
                a.wrapping_add(b)
            })
        }
        (left, AddressExpr::Absolute(value)) => left.add(if subtract {
            -(value as i64)
        } else {
            value as i64
        }),
        (AddressExpr::Absolute(value), right) if !subtract => right.add(value as i64),
        _ => return,
    };
    values.insert(VarnodeKey::from(output), expr);
}

fn set_ptradd(
    output: Option<Varnode>,
    inputs: &[Varnode],
    values: &mut BTreeMap<VarnodeKey, AddressExpr>,
) {
    let (Some(output), Some(base), Some(index), Some(stride)) =
        (output, inputs.first(), inputs.get(1), inputs.get(2))
    else {
        return;
    };
    let stride = signed_constant(*stride).and_then(|v| u32::try_from(v).ok());
    let base_expr = address_expr(*base, values);
    let index_value = signed_constant(*index);
    let AddressExpr::Base {
        base,
        offset,
        stride: old_stride,
    } = base_expr
    else {
        return;
    };
    let offset = match (index_value, stride) {
        (Some(index), Some(stride)) => {
            offset.saturating_add(index.saturating_mul(i64::from(stride)))
        }
        _ => offset,
    };
    values.insert(
        VarnodeKey::from(output),
        AddressExpr::Base {
            base,
            offset,
            stride: stride.or(old_stride),
        },
    );
}

fn collect_accesses(function: &NativeFunction) -> Vec<MemoryAccess> {
    let mut values = BTreeMap::new();
    let mut accesses = Vec::new();
    for instruction in function.instructions.values() {
        for operation in &instruction.pcode.ops {
            match operation.opcode {
                op::COPY | op::CAST | op::SUBPIECE | op::INT_ZEXT | op::INT_SEXT => set_copy(
                    operation.output,
                    operation.inputs.first().copied(),
                    &mut values,
                ),
                op::INT_ADD => set_add(operation.output, &operation.inputs, false, &mut values),
                op::INT_SUB | op::PTRSUB => {
                    set_add(operation.output, &operation.inputs, true, &mut values)
                }
                op::PTRADD => set_ptradd(operation.output, &operation.inputs, &mut values),
                op::LOAD => {
                    if let Some(address) = operation.inputs.get(1).copied() {
                        let address = address_expr(address, &values).fact();
                        let width = operation.output.map_or(0, |output| output.size);
                        accesses.push(MemoryAccess {
                            instruction: instruction.address,
                            kind: AccessKind::Read,
                            width,
                            address,
                            evidence: vec![Evidence {
                                source: EvidenceSource::PcodeAccess {
                                    instruction: instruction.address,
                                    opcode: operation.opcode,
                                    access: AccessKind::Read,
                                },
                                confidence: Confidence(90),
                            }],
                        });
                    }
                }
                op::STORE => {
                    if let (Some(address), Some(value)) =
                        (operation.inputs.get(1), operation.inputs.get(2))
                    {
                        let address = address_expr(*address, &values).fact();
                        accesses.push(MemoryAccess {
                            instruction: instruction.address,
                            kind: AccessKind::Write,
                            width: value.size,
                            address,
                            evidence: vec![Evidence {
                                source: EvidenceSource::PcodeAccess {
                                    instruction: instruction.address,
                                    opcode: operation.opcode,
                                    access: AccessKind::Write,
                                },
                                confidence: Confidence(90),
                            }],
                        });
                    }
                }
                _ => {}
            }
        }
    }
    for access in &mut accesses {
        if let AddressFact::BaseOffset {
            stride: Some(stride),
            ..
        } = access.address
        {
            access.evidence.push(Evidence {
                source: EvidenceSource::PcodeStride {
                    instruction: access.instruction,
                    stride,
                },
                confidence: Confidence(80),
            });
        }
    }
    accesses
}

fn find_nominal<'a>(input: &'a RecoveryInput<'_>, base: Varnode) -> Option<&'a NominalType> {
    input.assertions.iter().find_map(|assertion| {
        if assertion.base != base || assertion.offset != 0 {
            return None;
        }
        match &assertion.ty {
            GameType::Nominal { id: Some(id), .. } => {
                input.nominal_types.iter().find(|ty| ty.id == *id)
            }
            _ => None,
        }
    })
}

fn field_assertion<'a>(
    input: &'a RecoveryInput<'_>,
    base: Varnode,
    offset: i64,
) -> Option<&'a TypeAssertion> {
    input
        .assertions
        .iter()
        .find(|assertion| assertion.base == base && assertion.offset == offset)
}

fn build_structs(input: &RecoveryInput<'_>, accesses: &[MemoryAccess]) -> Vec<StructCandidate> {
    let mut grouped: BTreeMap<VarnodeKey, Vec<MemoryAccess>> = BTreeMap::new();
    for access in accesses {
        if let AddressFact::BaseOffset { base, .. } = access.address {
            grouped
                .entry(VarnodeKey::from(base))
                .or_default()
                .push(access.clone());
        }
    }
    grouped
        .into_iter()
        .map(|(key, accesses)| {
            let base = Varnode::new(key.space, key.offset, key.size);
            let nominal = find_nominal(input, base);
            let name = nominal.map(|ty| ty.name.clone());
            let mut fields: BTreeMap<i64, RecoveredField> = BTreeMap::new();
            let mut strides = Vec::new();
            let mut evidence = Vec::new();
            if let Some(nominal) = nominal {
                evidence.extend(nominal.evidence.clone());
                evidence.push(Evidence {
                    source: EvidenceSource::NominalType {
                        id: nominal.id,
                        name: nominal.name.clone(),
                    },
                    confidence: Confidence(100),
                });
            }
            for access in accesses {
                let (offset, stride) = match &access.address {
                    AddressFact::BaseOffset { offset, stride, .. } => (*offset, *stride),
                    AddressFact::Absolute { .. } => continue,
                };
                if let Some(stride) = stride {
                    if !strides.contains(&stride) {
                        strides.push(stride);
                    }
                }
                let assertion = field_assertion(input, base, offset);
                let nominal_field =
                    nominal.and_then(|ty| ty.fields.iter().find(|field| field.offset == offset));
                let (field_name, ty, mut field_evidence) = if let Some(assertion) = assertion {
                    let evidence = vec![Evidence {
                        source: EvidenceSource::UserAssertion {
                            note: assertion.note.clone(),
                        },
                        confidence: Confidence(100),
                    }];
                    (assertion.name.clone(), assertion.ty.clone(), evidence)
                } else if let Some(field) = nominal_field {
                    let mut evidence = field.evidence.clone();
                    if let Some(nominal) = nominal {
                        evidence.push(Evidence {
                            source: EvidenceSource::NominalType {
                                id: nominal.id,
                                name: nominal.name.clone(),
                            },
                            confidence: Confidence(95),
                        });
                    }
                    (Some(field.name.clone()), field.ty.clone(), evidence)
                } else {
                    (None, GameType::unknown(access.width), Vec::new())
                };
                field_evidence.extend(access.evidence.clone());
                let field = fields.entry(offset).or_insert_with(|| RecoveredField {
                    offset,
                    width: access.width,
                    name: field_name.clone(),
                    ty: ty.clone(),
                    accesses: Vec::new(),
                    evidence: Vec::new(),
                });
                field.width = field.width.max(access.width);
                if field.name.is_none() {
                    field.name = field_name;
                }
                if matches!(field.ty, GameType::UnknownBytes { .. })
                    && !matches!(ty, GameType::UnknownBytes { .. })
                {
                    field.ty = ty;
                }
                field.accesses.push(access);
                field.evidence.extend(field_evidence);
            }
            evidence.extend(
                fields
                    .values()
                    .flat_map(|field| field.evidence.iter().cloned()),
            );
            let mut remaining = fields.into_values().collect::<Vec<_>>();
            let mut ordered = Vec::with_capacity(remaining.len());
            if let Some(nominal) = nominal {
                for nominal_field in &nominal.fields {
                    if let Some(index) = remaining
                        .iter()
                        .position(|field| field.offset == nominal_field.offset)
                    {
                        ordered.push(remaining.remove(index));
                    }
                }
            }
            ordered.extend(remaining);
            StructCandidate {
                base,
                name,
                fields: ordered,
                strides,
                evidence,
            }
        })
        .collect()
}

/// Recover only facts supported by p-code and supplied metadata.
pub fn recover_function(target: TargetProfile, input: RecoveryInput<'_>) -> RecoveredFunction {
    let abi = GameAbiProfile::for_target(target);
    let accesses = collect_accesses(input.function);
    let function_end = input
        .function
        .entry
        .saturating_add(input.function.byte_length());
    let mut provenance = Vec::new();
    let name = input
        .symbols
        .iter()
        .find(|symbol| symbol.address == input.function.entry)
        .map(|symbol| {
            provenance.push(Evidence {
                source: EvidenceSource::Symbol {
                    address: symbol.address,
                    name: symbol.name.clone(),
                },
                confidence: Confidence(100),
            });
            symbol.name.clone()
        });
    for relocation in input.relocations.iter().filter(|relocation| {
        relocation.address >= input.function.entry && relocation.address < function_end
    }) {
        provenance.push(Evidence {
            source: EvidenceSource::Relocation {
                address: relocation.address,
                symbol: relocation.symbol.clone(),
            },
            confidence: Confidence(90),
        });
    }
    for annotation in input.annotations.iter().filter(|annotation| {
        annotation.address >= input.function.entry && annotation.address < function_end
    }) {
        provenance.push(Evidence {
            source: EvidenceSource::Annotation {
                address: annotation.address,
                text: annotation.text.clone(),
            },
            confidence: Confidence(85),
        });
    }
    let structs = build_structs(&input, &accesses);
    RecoveredFunction {
        target,
        abi,
        entry: input.function.entry,
        name,
        accesses,
        structs,
        provenance,
    }
}

fn register_group_text(group: RegisterGroup) -> String {
    if let Some(single) = group.single {
        return single.into();
    }
    match group.names {
        Some(names) if names.is_empty() => "none".into(),
        Some(names) => names.join(","),
        None => "unknown".into(),
    }
}

fn varnode_text(v: Varnode) -> String {
    format!("space={} offset={:#x} size={}", v.space, v.offset, v.size)
}

impl RecoveredFunction {
    /// Stable human-readable report used by the CLI and editor integrations.
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        writeln!(out, "target: {}", self.abi.name).unwrap();
        writeln!(
            out,
            "function: {} at {:#x}",
            self.name.as_deref().unwrap_or("<unnamed>"),
            self.entry
        )
        .unwrap();
        writeln!(out, "abi.pointer_bits: {}", self.abi.pointer_bits).unwrap();
        writeln!(
            out,
            "abi.stack: {} align={} delay_slots={} frame_pointer={} return_address={}",
            self.abi.stack_pointer,
            self.abi.stack_alignment,
            self.abi.delay_slots,
            self.abi.frame_pointer.unwrap_or("unknown"),
            self.abi.return_address.unwrap_or("unknown")
        )
        .unwrap();
        writeln!(
            out,
            "abi.arguments.integer: {}",
            register_group_text(self.abi.arguments.integer)
        )
        .unwrap();
        writeln!(
            out,
            "abi.arguments.floating: {}",
            register_group_text(self.abi.arguments.floating)
        )
        .unwrap();
        writeln!(
            out,
            "abi.arguments.vector: {}",
            register_group_text(self.abi.arguments.vector)
        )
        .unwrap();
        writeln!(
            out,
            "abi.returns.integer: {}",
            register_group_text(self.abi.returns.integer)
        )
        .unwrap();
        writeln!(
            out,
            "abi.returns.floating: {}",
            register_group_text(self.abi.returns.floating)
        )
        .unwrap();
        writeln!(
            out,
            "abi.returns.vector: {}",
            register_group_text(self.abi.returns.vector)
        )
        .unwrap();
        writeln!(
            out,
            "abi.caller_saved: {}",
            register_group_text(self.abi.caller_saved)
        )
        .unwrap();
        writeln!(
            out,
            "abi.callee_saved: {}",
            register_group_text(self.abi.callee_saved)
        )
        .unwrap();
        writeln!(
            out,
            "abi.small_struct: max_bytes={} returns={}",
            self.abi
                .small_struct_max_bytes
                .map_or_else(|| "unknown".into(), |n| n.to_string()),
            register_group_text(self.abi.small_struct_returns)
        )
        .unwrap();
        writeln!(out, "memory_accesses: {}", self.accesses.len()).unwrap();
        for access in &self.accesses {
            let kind = match access.kind {
                AccessKind::Read => "read",
                AccessKind::Write => "write",
            };
            match access.address {
                AddressFact::Absolute { address } => {
                    writeln!(
                        out,
                        "  {kind} @{:#x} width={} at {:#x}",
                        access.instruction, access.width, address
                    )
                    .unwrap();
                }
                AddressFact::BaseOffset {
                    base,
                    offset,
                    stride,
                } => {
                    writeln!(
                        out,
                        "  {kind} @{:#x} width={} base=({}) offset={:+#x} stride={}",
                        access.instruction,
                        access.width,
                        varnode_text(base),
                        offset,
                        stride.map_or_else(|| "none".into(), |n| n.to_string())
                    )
                    .unwrap();
                }
            }
        }
        writeln!(out, "struct_candidates: {}", self.structs.len()).unwrap();
        for (index, candidate) in self.structs.iter().enumerate() {
            writeln!(
                out,
                "  struct[{index}] name={} base=({}) fields={} strides={}",
                candidate.name.as_deref().unwrap_or("<anonymous>"),
                varnode_text(candidate.base),
                candidate.fields.len(),
                if candidate.strides.is_empty() {
                    "none".into()
                } else {
                    candidate
                        .strides
                        .iter()
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                }
            )
            .unwrap();
            for field in &candidate.fields {
                writeln!(
                    out,
                    "    field offset={:+#x} width={} name={} type={} evidence={}",
                    field.offset,
                    field.width,
                    field.name.as_deref().unwrap_or("<unknown>"),
                    field.ty.display(),
                    field.evidence.len()
                )
                .unwrap();
            }
        }
        writeln!(out, "provenance: {}", self.provenance.len()).unwrap();
        for evidence in &self.provenance {
            writeln!(
                out,
                "  confidence={} {:?}",
                evidence.confidence.value(),
                evidence.source
            )
            .unwrap();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use ventris_format::{Image, Loader};
    use ventris_lifter::{Flow, LiftedInstruction, Lifter, Mips32};
    use ventris_pcode::{InstPcode, PcodeOp};

    fn constant(value: u64, size: u32) -> Varnode {
        Varnode::new(CONST_SPACE, value, size)
    }

    fn function(ops: Vec<PcodeOp>) -> NativeFunction {
        let instruction = LiftedInstruction {
            address: 0x1000,
            bytes: vec![0; 4],
            pcode: InstPcode {
                len: 4,
                space: 3,
                offset: 0x1000,
                ops,
            },
            flow: Flow::Return,
        };
        let mut instructions = BTreeMap::new();
        instructions.insert(instruction.address, instruction);
        NativeFunction {
            entry: 0x1000,
            instructions,
            edges: BTreeSet::new(),
            calls: BTreeSet::new(),
        }
    }

    #[test]
    fn console_profiles_keep_unknown_vector_conventions_explicit() {
        let ps2 = GameAbiProfile::for_target(TargetProfile::Ps2);
        assert_eq!(ps2.name, "ps2-r5900-o32");
        assert_eq!(ps2.delay_slots, 1);
        assert!(ps2.arguments.integer.is_known());
        assert!(!ps2.arguments.vector.is_known());

        let xenon = GameAbiProfile::for_target(TargetProfile::Xbox360);
        assert_eq!(xenon.stack_pointer, "r1");
        assert_eq!(xenon.returns.integer.names, Some(PPC_RETURNS));
    }

    #[test]
    fn abi_register_and_stack_queries_preserve_classes() {
        let ps2 = GameAbiProfile::for_target(TargetProfile::Ps2);
        assert_eq!(
            ps2.argument_register(AbiRegisterClass::Integer, 0),
            Some("$a0")
        );
        assert_eq!(
            ps2.return_register(AbiRegisterClass::Integer, 1),
            Some("$v1")
        );
        assert_eq!(ps2.argument_register(AbiRegisterClass::Integer, 4), None);
        assert_eq!(ps2.stack_argument_offset(0, 32), 0);
        assert_eq!(ps2.stack_argument_offset(1, 32), 4);
        assert_eq!(ps2.stack_argument_offset(1, 64), 8);
    }
    #[test]
    fn repeated_base_offsets_become_conservative_struct_fields() {
        let base = Varnode::new(4, 0, 4);
        let address_a = Varnode::new(2, 0, 4);
        let address_b = Varnode::new(2, 4, 4);
        let loaded = Varnode::new(4, 8, 4);
        let function = function(vec![
            PcodeOp::new(op::INT_ADD, Some(address_a), vec![base, constant(0x10, 4)]),
            PcodeOp::new(op::LOAD, Some(loaded), vec![constant(417, 4), address_a]),
            PcodeOp::new(op::INT_ADD, Some(address_b), vec![base, constant(0x14, 4)]),
            PcodeOp::new(op::STORE, None, vec![constant(417, 4), address_b, loaded]),
        ]);
        let report = recover_function(TargetProfile::Ps2, RecoveryInput::new(&function));
        assert_eq!(report.structs.len(), 1);
        assert_eq!(report.structs[0].fields.len(), 2);
        assert_eq!(report.structs[0].fields[0].offset, 0x10);
        assert_eq!(
            report.structs[0].fields[0].ty,
            GameType::UnknownBytes { width: 4 }
        );
        assert_eq!(report.structs[0].fields[1].offset, 0x14);
    }

    #[test]
    fn ptradd_preserves_observed_array_stride() {
        let base = Varnode::new(4, 0, 4);
        let index = Varnode::new(4, 4, 4);
        let address = Varnode::new(2, 0, 4);
        let loaded = Varnode::new(4, 8, 4);
        let function = function(vec![
            PcodeOp::new(
                op::PTRADD,
                Some(address),
                vec![base, index, constant(16, 4)],
            ),
            PcodeOp::new(op::LOAD, Some(loaded), vec![constant(417, 4), address]),
        ]);
        let report = recover_function(TargetProfile::Ps2, RecoveryInput::new(&function));
        assert_eq!(report.structs[0].strides, vec![16]);
        assert_eq!(report.structs[0].fields[0].offset, 0);
    }

    #[test]
    fn user_assertion_and_nominal_metadata_override_unknown_width_only() {
        let base = Varnode::new(4, 0, 4);
        let address = Varnode::new(2, 0, 4);
        let loaded = Varnode::new(4, 8, 4);
        let function = function(vec![
            PcodeOp::new(op::INT_ADD, Some(address), vec![base, constant(0x20, 4)]),
            PcodeOp::new(op::LOAD, Some(loaded), vec![constant(417, 4), address]),
        ]);
        let nominal = NominalType {
            id: 7,
            name: "Actor".into(),
            size: 0x40,
            fields: vec![NominalField {
                offset: 0x20,
                name: "position".into(),
                ty: GameType::Vector {
                    lane: Box::new(GameType::Primitive {
                        name: "float".into(),
                        bits: 32,
                        signed: None,
                    }),
                    lanes: 3,
                },
                width: 12,
                evidence: Vec::new(),
            }],
            evidence: Vec::new(),
        };
        let assertion = TypeAssertion {
            base,
            offset: 0,
            name: None,
            ty: GameType::nominal(Some(7), "Actor", 0x40),
            note: "this-pointer type assertion".into(),
        };
        let nominal_types = [nominal];
        let assertions = [assertion];
        let mut input = RecoveryInput::new(&function);
        input.nominal_types = &nominal_types;
        input.assertions = &assertions;
        let report = recover_function(TargetProfile::GameCube, input);
        let field = &report.structs[0].fields[0];
        assert_eq!(field.name.as_deref(), Some("position"));
        assert!(matches!(field.ty, GameType::Vector { lanes: 3, .. }));
        assert!(field
            .evidence
            .iter()
            .any(|e| matches!(e.source, EvidenceSource::NominalType { id: 7, .. })));
    }

    #[test]
    fn nominal_field_declaration_order_survives_address_sorting() {
        let base = Varnode::new(4, 0, 4);
        let address_a = Varnode::new(2, 0, 4);
        let address_b = Varnode::new(2, 4, 4);
        let loaded_a = Varnode::new(4, 8, 4);
        let loaded_b = Varnode::new(4, 12, 4);
        let function = function(vec![
            PcodeOp::new(op::INT_ADD, Some(address_a), vec![base, constant(0x10, 4)]),
            PcodeOp::new(op::LOAD, Some(loaded_a), vec![constant(417, 4), address_a]),
            PcodeOp::new(op::INT_ADD, Some(address_b), vec![base, constant(0x20, 4)]),
            PcodeOp::new(op::LOAD, Some(loaded_b), vec![constant(417, 4), address_b]),
        ]);
        let nominal = NominalType {
            id: 9,
            name: "Actor".into(),
            size: 0x40,
            fields: vec![
                NominalField {
                    offset: 0x20,
                    name: "later".into(),
                    ty: GameType::Primitive {
                        name: "int".into(),
                        bits: 32,
                        signed: Some(true),
                    },
                    width: 4,
                    evidence: Vec::new(),
                },
                NominalField {
                    offset: 0x10,
                    name: "earlier".into(),
                    ty: GameType::Primitive {
                        name: "int".into(),
                        bits: 32,
                        signed: Some(true),
                    },
                    width: 4,
                    evidence: Vec::new(),
                },
            ],
            evidence: Vec::new(),
        };
        let assertion = TypeAssertion {
            base,
            offset: 0,
            name: None,
            ty: GameType::nominal(Some(9), "Actor", 0x40),
            note: "declaration order test".into(),
        };
        let nominal_types = [nominal];
        let assertions = [assertion];
        let mut input = RecoveryInput::new(&function);
        input.nominal_types = &nominal_types;
        input.assertions = &assertions;
        let report = recover_function(TargetProfile::GameCube, input);
        let fields = &report.structs[0].fields;
        assert_eq!(
            fields
                .iter()
                .map(|field| field.name.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("later"), Some("earlier")]
        );
    }

    #[test]
    fn ps2_mips_fixture_recovers_exact_memory_facts() {
        let bytes = [
            0x10, 0x00, 0x82, 0x8c, // lw $v0, 0x10($a0)
            0x14, 0x00, 0x83, 0x8c, // lw $v1, 0x14($a0)
            0x08, 0x00, 0xe0, 0x03, // jr $ra
            0x00, 0x00, 0x00, 0x00, // delay slot
        ];
        let loaded = Image::load(&bytes, Loader::Raw, Some(0x1000)).unwrap();
        let function = Mips32
            .discover(&loaded.image, &loaded.bytes, 0x1000, 16)
            .unwrap();
        let report = recover_function(TargetProfile::Ps2, RecoveryInput::new(&function));
        let expected = concat!(
            "target: ps2-r5900-o32\n",
            "function: <unnamed> at 0x1000\n",
            "abi.pointer_bits: 32\n",
            "abi.stack: $sp align=8 delay_slots=1 frame_pointer=$fp return_address=$ra\n",
            "abi.arguments.integer: $a0,$a1,$a2,$a3\n",
            "abi.arguments.floating: $f12,$f14\n",
            "abi.arguments.vector: unknown\n",
            "abi.returns.integer: $v0,$v1\n",
            "abi.returns.floating: $f0,$f2\n",
            "abi.returns.vector: unknown\n",
            "abi.caller_saved: $v0,$v1,$a0,$a1,$a2,$a3,$t0,$t1,$t2,$t3,$t4,$t5,$t6,$t7,$t8,$t9\n",
            "abi.callee_saved: $s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$fp\n",
            "abi.small_struct: max_bytes=8 returns=$v0,$v1\n",
            "memory_accesses: 2\n",
            "  read @0x1000 width=4 base=(space=4 offset=0x10 size=4) offset=+0x10 stride=none\n",
            "  read @0x1004 width=4 base=(space=4 offset=0x10 size=4) offset=+0x14 stride=none\n",
            "struct_candidates: 1\n",
            "  struct[0] name=<anonymous> base=(space=4 offset=0x10 size=4) fields=2 strides=none\n",
            "    field offset=+0x10 width=4 name=<unknown> type=unknown_bytes[4] evidence=1\n",
            "    field offset=+0x14 width=4 name=<unknown> type=unknown_bytes[4] evidence=1\n",
            "provenance: 0\n",
        );
        assert_eq!(report.render_text(), expected);

        assert_eq!(report.abi.name, "ps2-r5900-o32");
        assert_eq!(report.accesses.len(), 2);
        assert_eq!(report.structs.len(), 1);
        assert_eq!(
            report.structs[0]
                .fields
                .iter()
                .map(|field| field.offset)
                .collect::<Vec<_>>(),
            vec![0x10, 0x14]
        );
        assert_eq!(report.structs[0].fields[0].width, 4);
        assert!(matches!(
            report.structs[0].fields[0].ty,
            GameType::UnknownBytes { width: 4 }
        ));
    }

    #[test]
    fn confidence_rejects_out_of_range_values() {
        assert_eq!(Confidence::new(100).unwrap().value(), 100);
        assert!(Confidence::new(101).is_none());
    }
}
