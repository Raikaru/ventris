//! Target profiles: console identity, loader, ISA, and ABI defaults.
//!
//! A target is not an instruction set.  The same ISA is used by several
//! consoles with different image containers, address maps, and calling
//! conventions.  Callers may override the loader, base, or ISA when a title
//! uses a non-default arrangement; the profile only supplies conservative
//! defaults.

#![forbid(unsafe_code)]

use ventris_format::Loader;
use ventris_lifter::Architecture;

#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TargetProfile {
    Atari2600,
    Nes,
    Snes,
    MasterSystem,
    GameGear,
    Genesis,
    NeoGeo,
    C64,
    Ps1,
    Ps2,
    N64,
    Saturn,
    Dreamcast,
    GameCube,
    Wii,
    Gba,
    NintendoDs,
    Nintendo3Ds,
    Psp,
    Vita,
    WiiU,
    Xbox360,
    Ps3Ppu,
    Ps3Spu,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DecompilationSupport {
    /// Loading and lifting exist; decompiler output is not quality-claimed.
    LiftOnly,
    /// The native decompiler runs, but no pinned real-image gate protects it.
    Experimental,
    /// A pinned real-image corpus measures semantic and compiler output.
    Measured,
}

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
    pub const fn is_known(self) -> bool {
        self.names.is_some() || self.single.is_some()
    }

    pub fn at(self, index: usize) -> Option<&'static str> {
        self.names
            .and_then(|names| names.get(index).copied())
            .or_else(|| (index == 0).then_some(self.single).flatten())
    }

    pub fn count(self) -> Option<usize> {
        self.names
            .map(<[_]>::len)
            .or_else(|| self.single.map(|_| 1))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum AbiRegisterClass {
    Integer,
    Floating,
    Vector,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct AbiRegisterClasses {
    pub integer: RegisterGroup,
    pub floating: RegisterGroup,
    pub vector: RegisterGroup,
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

/// How integer and floating-point argument registers consume source-level
/// argument positions.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ArgumentRegisterMode {
    /// Every argument consumes one slot from a single register sequence.
    Unified,
    /// Integer and floating registers name alternate views of shared slots.
    Coupled,
    /// Integer and floating register sequences advance independently.
    Independent,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct StackArguments {
    /// Entry-stack offset of the first argument not passed in registers.
    pub first_offset: u16,
    pub slot_size: u8,
    /// Number of source-level slots preceding `first_offset`.
    pub register_slots: u8,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Abi {
    pub name: &'static str,
    pub pointer_bits: u8,
    pub stack_alignment: u8,
    pub stack_grows_down: bool,
    pub stack_pointer: &'static str,
    pub frame_pointer: Option<&'static str>,
    pub return_address: Option<&'static str>,
    pub return_register: &'static str,
    pub delay_slots: u8,
    pub argument_mode: ArgumentRegisterMode,
    pub arguments: AbiRegisterClasses,
    pub returns: AbiRegisterClasses,
    pub stack_arguments: Option<StackArguments>,
    pub caller_saved: RegisterGroup,
    pub callee_saved: RegisterGroup,
    pub hidden_return_pointer: Option<&'static str>,
    pub small_struct_max_bytes: Option<u8>,
    pub small_struct_returns: RegisterGroup,
}

impl Abi {
    pub fn argument_register(self, class: AbiRegisterClass, index: usize) -> Option<&'static str> {
        self.arguments.group(class).at(index)
    }

    pub fn return_register(self, class: AbiRegisterClass, index: usize) -> Option<&'static str> {
        self.returns.group(class).at(index)
    }

    pub fn for_target(target: TargetProfile) -> Self {
        target.spec().abi
    }

    /// Byte offset within the ABI's stack-argument area for a value at
    /// `index`, rounded up to pointer-sized slots.
    pub fn stack_argument_offset(self, index: usize, width_bits: u32) -> u32 {
        let pointer_bytes = u32::from(self.pointer_bits.div_ceil(8)).max(1);
        let width_bytes = width_bits.div_ceil(8).max(1);
        let slot_bytes = width_bytes.div_ceil(pointer_bytes) * pointer_bytes;
        (index as u32).saturating_mul(slot_bytes)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TargetSpec {
    pub profile: TargetProfile,
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub architecture: Architecture,
    pub loader: Loader,
    pub default_base: Option<u64>,
    pub abi: Abi,
    /// Named image parts when the container has more than one code image.
    pub parts: &'static [&'static str],
    pub decompilation: DecompilationSupport,
}

const EMPTY: &[&str] = &[];
const UNKNOWN: RegisterGroup = RegisterGroup::unknown();
const MIPS_ARGS: &[&str] = &["$a0", "$a1", "$a2", "$a3"];
const MIPS_N64_ARGS: &[&str] = &["$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$a6", "$a7"];
const MIPS_RETURNS: &[&str] = &["$v0", "$v1"];
const MIPS_FLOAT_ARGS: &[&str] = &["$f12", "$f14"];
const MIPS_N64_FLOAT_ARGS: &[&str] = &[
    "$f12", "$f13", "$f14", "$f15", "$f16", "$f17", "$f18", "$f19",
];
const MIPS_FLOAT_RETURNS: &[&str] = &["$f0", "$f2"];
const MIPS_CALLER: &[&str] = &[
    "$v0", "$v1", "$a0", "$a1", "$a2", "$a3", "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6",
    "$t7", "$t8", "$t9", "$ra", "$f0", "$f1", "$f2", "$f3", "$f4", "$f5", "$f6", "$f7", "$f8",
    "$f9", "$f10", "$f11", "$f12", "$f13", "$f14", "$f15", "$f16", "$f17", "$f18", "$f19",
];
const MIPS_CALLEE: &[&str] = &[
    "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7", "$gp", "$fp", "$f20", "$f21", "$f22",
    "$f23", "$f24", "$f25", "$f26", "$f27", "$f28", "$f29", "$f30", "$f31",
];
const ARM_ARGS: &[&str] = &["r0", "r1", "r2", "r3"];
const ARM_RETURNS: &[&str] = &["r0", "r1"];
const ARM_FLOAT_ARGS: &[&str] = &[
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13", "s14",
    "s15",
];
const ARM_FLOAT_RETURNS: &[&str] = &["s0", "s1"];
const ARM_CALLER: &[&str] = &[
    "r0", "r1", "r2", "r3", "r12", "lr", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8",
    "s9", "s10", "s11", "s12", "s13", "s14", "s15",
];
const ARM_CALLEE: &[&str] = &[
    "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "s16", "s17", "s18", "s19", "s20", "s21",
    "s22", "s23", "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31",
];
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
    "r27", "r28", "r29", "r30", "r31", "f14", "f15", "f16", "f17", "f18", "f19", "f20", "f21",
    "f22", "f23", "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31",
];

const fn classes(
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

const fn basic_abi(
    name: &'static str,
    pointer_bits: u8,
    stack_alignment: u8,
    stack_pointer: &'static str,
    frame_pointer: Option<&'static str>,
    return_address: Option<&'static str>,
    return_register: &'static str,
    delay_slots: u8,
) -> Abi {
    Abi {
        name,
        pointer_bits,
        stack_alignment,
        stack_grows_down: true,
        stack_pointer,
        frame_pointer,
        return_address,
        return_register,
        delay_slots,
        argument_mode: ArgumentRegisterMode::Unified,
        arguments: classes(UNKNOWN, UNKNOWN, UNKNOWN),
        returns: classes(
            RegisterGroup::known_single(return_register),
            UNKNOWN,
            UNKNOWN,
        ),
        stack_arguments: None,
        caller_saved: UNKNOWN,
        callee_saved: UNKNOWN,
        hidden_return_pointer: None,
        small_struct_max_bytes: None,
        small_struct_returns: UNKNOWN,
    }
}

const ABI_6502: Abi = basic_abi("6502", 16, 1, "sp", None, None, "a", 0);
const ABI_Z80: Abi = basic_abi("z80", 16, 2, "sp", None, None, "hl", 0);
const ABI_M68K: Abi = basic_abi("m68k-c", 32, 4, "a7", Some("a6"), None, "d0", 0);
const ABI_SH: Abi = basic_abi("sh-c", 32, 4, "r15", Some("r14"), Some("pr"), "r0", 1);

const ABI_MIPS_O32: Abi = Abi {
    name: "mips-o32",
    pointer_bits: 32,
    stack_alignment: 8,
    stack_grows_down: true,
    stack_pointer: "$sp",
    frame_pointer: Some("$fp"),
    return_address: Some("$ra"),
    return_register: "$v0",
    delay_slots: 1,
    argument_mode: ArgumentRegisterMode::Coupled,
    arguments: classes(
        RegisterGroup::known(MIPS_ARGS),
        RegisterGroup::known(MIPS_FLOAT_ARGS),
        UNKNOWN,
    ),
    returns: classes(
        RegisterGroup::known(MIPS_RETURNS),
        RegisterGroup::known(MIPS_FLOAT_RETURNS),
        UNKNOWN,
    ),
    stack_arguments: Some(StackArguments {
        first_offset: 16,
        slot_size: 4,
        register_slots: 4,
    }),
    caller_saved: RegisterGroup::known(MIPS_CALLER),
    callee_saved: RegisterGroup::known(MIPS_CALLEE),
    hidden_return_pointer: Some("$a0"),
    small_struct_max_bytes: None,
    small_struct_returns: UNKNOWN,
};

const ABI_PS2_R5900_O32: Abi = Abi {
    name: "ps2-r5900-o32",
    ..ABI_MIPS_O32
};

const ABI_PS1_O32: Abi = Abi {
    name: "ps1-mips-o32",
    argument_mode: ArgumentRegisterMode::Unified,
    arguments: classes(
        RegisterGroup::known(MIPS_ARGS),
        RegisterGroup::known(EMPTY),
        UNKNOWN,
    ),
    returns: classes(
        RegisterGroup::known(MIPS_RETURNS),
        RegisterGroup::known(EMPTY),
        UNKNOWN,
    ),
    ..ABI_MIPS_O32
};

const ABI_MIPS_N64: Abi = Abi {
    name: "mips-n64",
    pointer_bits: 64,
    stack_alignment: 16,
    arguments: classes(
        RegisterGroup::known(MIPS_N64_ARGS),
        RegisterGroup::known(MIPS_N64_FLOAT_ARGS),
        UNKNOWN,
    ),
    stack_arguments: Some(StackArguments {
        first_offset: 0,
        slot_size: 8,
        register_slots: 8,
    }),
    small_struct_max_bytes: Some(16),
    ..ABI_MIPS_O32
};

const ABI_ARM_AAPCS: Abi = Abi {
    name: "aapcs32",
    pointer_bits: 32,
    stack_alignment: 8,
    stack_grows_down: true,
    stack_pointer: "r13",
    frame_pointer: Some("r11"),
    return_address: Some("lr"),
    return_register: "r0",
    delay_slots: 0,
    argument_mode: ArgumentRegisterMode::Independent,
    arguments: classes(
        RegisterGroup::known(ARM_ARGS),
        RegisterGroup::known(ARM_FLOAT_ARGS),
        UNKNOWN,
    ),
    returns: classes(
        RegisterGroup::known(ARM_RETURNS),
        RegisterGroup::known(ARM_FLOAT_RETURNS),
        UNKNOWN,
    ),
    stack_arguments: Some(StackArguments {
        first_offset: 0,
        slot_size: 4,
        register_slots: 4,
    }),
    caller_saved: RegisterGroup::known(ARM_CALLER),
    callee_saved: RegisterGroup::known(ARM_CALLEE),
    hidden_return_pointer: Some("r0"),
    small_struct_max_bytes: Some(4),
    small_struct_returns: RegisterGroup::known(ARM_RETURNS),
};

const ABI_ARM_GBA: Abi = Abi {
    name: "aapcs32-gba",
    stack_alignment: 4,
    argument_mode: ArgumentRegisterMode::Unified,
    arguments: classes(
        RegisterGroup::known(ARM_ARGS),
        RegisterGroup::known(EMPTY),
        UNKNOWN,
    ),
    returns: classes(
        RegisterGroup::known(ARM_RETURNS),
        RegisterGroup::known(EMPTY),
        UNKNOWN,
    ),
    ..ABI_ARM_AAPCS
};

const ABI_PPC_EABI: Abi = Abi {
    name: "powerpc-eabi",
    pointer_bits: 32,
    stack_alignment: 16,
    stack_grows_down: true,
    stack_pointer: "r1",
    frame_pointer: None,
    return_address: Some("lr"),
    return_register: "r3",
    delay_slots: 0,
    argument_mode: ArgumentRegisterMode::Independent,
    arguments: classes(
        RegisterGroup::known(PPC_ARGS),
        RegisterGroup::known(PPC_FLOAT_ARGS),
        UNKNOWN,
    ),
    returns: classes(
        RegisterGroup::known(PPC_RETURNS),
        RegisterGroup::known(PPC_FLOAT_RETURNS),
        UNKNOWN,
    ),
    stack_arguments: Some(StackArguments {
        first_offset: 8,
        slot_size: 4,
        register_slots: 8,
    }),
    caller_saved: RegisterGroup::known(PPC_CALLER),
    callee_saved: RegisterGroup::known(PPC_CALLEE),
    hidden_return_pointer: Some("r3"),
    small_struct_max_bytes: Some(8),
    small_struct_returns: RegisterGroup::known(PPC_RETURNS),
};

const ABI_XENON: Abi = Abi {
    name: "xenon-ppc",
    arguments: classes(RegisterGroup::known(PPC_ARGS), UNKNOWN, UNKNOWN),
    returns: classes(RegisterGroup::known(PPC_RETURNS), UNKNOWN, UNKNOWN),
    stack_arguments: None,
    small_struct_max_bytes: None,
    small_struct_returns: UNKNOWN,
    ..ABI_PPC_EABI
};
const ABI_PPU: Abi = Abi {
    name: "powerpc64-elfv1",
    arguments: classes(RegisterGroup::known(PPC_ARGS), UNKNOWN, UNKNOWN),
    returns: classes(RegisterGroup::known(PPC_RETURNS), UNKNOWN, UNKNOWN),
    pointer_bits: 64,
    stack_arguments: None,
    small_struct_max_bytes: None,
    small_struct_returns: UNKNOWN,
    ..ABI_PPC_EABI
};
const ABI_SPU: Abi = Abi {
    name: "spu-ls",
    pointer_bits: 32,
    stack_alignment: 16,
    stack_grows_down: true,
    stack_pointer: "r1",
    frame_pointer: None,
    return_address: None,
    return_register: "r3",
    delay_slots: 0,
    argument_mode: ArgumentRegisterMode::Unified,
    arguments: classes(UNKNOWN, UNKNOWN, RegisterGroup::known(EMPTY)),
    returns: classes(UNKNOWN, UNKNOWN, RegisterGroup::known_single("r3")),
    stack_arguments: None,
    caller_saved: UNKNOWN,
    callee_saved: UNKNOWN,
    hidden_return_pointer: Some("r3"),
    small_struct_max_bytes: None,
    small_struct_returns: UNKNOWN,
};

impl TargetProfile {
    pub const ALL: [Self; 24] = [
        Self::Atari2600,
        Self::Nes,
        Self::Snes,
        Self::MasterSystem,
        Self::GameGear,
        Self::Genesis,
        Self::NeoGeo,
        Self::C64,
        Self::Ps1,
        Self::Ps2,
        Self::N64,
        Self::Saturn,
        Self::Dreamcast,
        Self::GameCube,
        Self::Wii,
        Self::Gba,
        Self::NintendoDs,
        Self::Nintendo3Ds,
        Self::Psp,
        Self::Vita,
        Self::WiiU,
        Self::Xbox360,
        Self::Ps3Ppu,
        Self::Ps3Spu,
    ];

    pub fn name(self) -> &'static str {
        self.spec().name
    }

    pub fn parse(value: &str) -> Option<Self> {
        let value = value.to_ascii_lowercase();
        TARGET_SPECS
            .iter()
            .find(|spec| spec.aliases.contains(&value.as_str()))
            .map(|spec| spec.profile)
    }

    pub fn spec(self) -> &'static TargetSpec {
        &TARGET_SPECS[self as usize]
    }
}

const TARGET_SPECS: [TargetSpec; 24] = [
    TargetSpec {
        profile: TargetProfile::Atari2600,
        name: "atari2600",
        aliases: &["atari2600", "atari-2600", "2600"],
        architecture: Architecture::M6502,
        loader: Loader::Raw,
        default_base: Some(0),
        abi: ABI_6502,
        parts: &[],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::Nes,
        name: "nes",
        aliases: &["nes", "nintendo", "nintendo-entertainment-system"],
        architecture: Architecture::M6502,
        loader: Loader::Raw,
        default_base: Some(0x8000),
        abi: ABI_6502,
        parts: &[],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::Snes,
        name: "snes",
        aliases: &["snes", "super-nes", "super-nintendo"],
        architecture: Architecture::M6502,
        loader: Loader::Raw,
        default_base: Some(0x8000),
        abi: ABI_6502,
        parts: &[],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::MasterSystem,
        name: "master-system",
        aliases: &["sms", "master-system", "mastersystem"],
        architecture: Architecture::Z80,
        loader: Loader::Raw,
        default_base: Some(0),
        abi: ABI_Z80,
        parts: &[],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::GameGear,
        name: "game-gear",
        aliases: &["game-gear", "gamegear", "gg"],
        architecture: Architecture::Z80,
        loader: Loader::Raw,
        default_base: Some(0),
        abi: ABI_Z80,
        parts: &[],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::Genesis,
        name: "genesis",
        aliases: &["genesis", "mega-drive", "megadrive"],
        architecture: Architecture::M68k,
        loader: Loader::Raw,
        default_base: Some(0),
        abi: ABI_M68K,
        parts: &[],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::NeoGeo,
        name: "neo-geo",
        aliases: &["neo-geo", "neogeo"],
        architecture: Architecture::M68k,
        loader: Loader::Raw,
        default_base: Some(0),
        abi: ABI_M68K,
        parts: &[],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::C64,
        name: "c64",
        aliases: &["c64", "commodore-64", "commodore64"],
        architecture: Architecture::M6502,
        loader: Loader::Raw,
        default_base: Some(0),
        abi: ABI_6502,
        parts: &[],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::Ps1,
        name: "ps1",
        aliases: &["ps1", "playstation", "playstation1", "psx"],
        architecture: Architecture::Ps1,
        loader: Loader::Raw,
        default_base: Some(0x8001_0000),
        abi: ABI_PS1_O32,
        parts: &[],
        decompilation: DecompilationSupport::Experimental,
    },
    TargetSpec {
        profile: TargetProfile::Ps2,
        name: "ps2",
        aliases: &["ps2", "playstation2"],
        architecture: Architecture::Ps2,
        loader: Loader::Elf,
        default_base: None,
        abi: ABI_PS2_R5900_O32,
        parts: &[],
        decompilation: DecompilationSupport::Measured,
    },
    TargetSpec {
        profile: TargetProfile::N64,
        name: "n64",
        aliases: &["n64", "nintendo-64", "nintendo64"],
        architecture: Architecture::N64,
        loader: Loader::N64Rom,
        default_base: None,
        abi: ABI_MIPS_N64,
        parts: &[],
        decompilation: DecompilationSupport::Experimental,
    },
    TargetSpec {
        profile: TargetProfile::Saturn,
        name: "saturn",
        aliases: &["saturn", "sega-saturn"],
        architecture: Architecture::Sh2,
        loader: Loader::Raw,
        default_base: Some(0),
        abi: ABI_SH,
        parts: &[],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::Dreamcast,
        name: "dreamcast",
        aliases: &["dreamcast", "dc"],
        architecture: Architecture::Sh4,
        loader: Loader::Elf,
        default_base: None,
        abi: ABI_SH,
        parts: &[],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::GameCube,
        name: "gamecube",
        aliases: &["gamecube", "gc"],
        architecture: Architecture::GameCube,
        loader: Loader::Dol,
        default_base: None,
        abi: ABI_PPC_EABI,
        parts: &[],
        decompilation: DecompilationSupport::Experimental,
    },
    TargetSpec {
        profile: TargetProfile::Wii,
        name: "wii",
        aliases: &["wii"],
        architecture: Architecture::GameCube,
        loader: Loader::Dol,
        default_base: None,
        abi: ABI_PPC_EABI,
        parts: &[],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::Gba,
        name: "gba",
        aliases: &["gba", "game-boy-advance", "gameboy-advance"],
        architecture: Architecture::Thumb,
        loader: Loader::Raw,
        default_base: Some(0x0800_0000),
        abi: ABI_ARM_GBA,
        parts: &[],
        decompilation: DecompilationSupport::Experimental,
    },
    TargetSpec {
        profile: TargetProfile::NintendoDs,
        name: "nds",
        aliases: &["nds", "ds", "nintendo-ds", "nintendods"],
        architecture: Architecture::Arm32,
        loader: Loader::NintendoDs,
        default_base: None,
        abi: ABI_ARM_AAPCS,
        parts: &["arm9", "arm7"],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::Nintendo3Ds,
        name: "3ds",
        aliases: &["3ds", "nintendo-3ds", "nintendo3ds"],
        architecture: Architecture::Arm32,
        loader: Loader::Ncch,
        default_base: None,
        abi: ABI_ARM_AAPCS,
        parts: &["arm11"],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::Psp,
        name: "psp",
        aliases: &["psp", "playstation-portable"],
        architecture: Architecture::Mips32,
        loader: Loader::PspPrx,
        default_base: None,
        abi: ABI_MIPS_O32,
        parts: &[],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::Vita,
        name: "vita",
        aliases: &["vita", "psvita", "playstation-vita"],
        architecture: Architecture::Arm32,
        loader: Loader::VitaSelf,
        default_base: None,
        abi: ABI_ARM_AAPCS,
        parts: &[],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::WiiU,
        name: "wiiu",
        aliases: &["wiiu", "wii-u"],
        architecture: Architecture::Ppc32,
        loader: Loader::WiiURpl,
        default_base: None,
        abi: ABI_PPC_EABI,
        parts: &[],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::Xbox360,
        name: "xbox360",
        aliases: &["xbox360", "xbox-360", "xenon"],
        architecture: Architecture::Ppc32,
        loader: Loader::Xex,
        default_base: None,
        abi: ABI_XENON,
        parts: &[],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::Ps3Ppu,
        name: "ps3-ppu",
        aliases: &["ps3", "ps3-ppu", "cell-ppu"],
        architecture: Architecture::Ppc64,
        loader: Loader::Ps3Self,
        default_base: None,
        abi: ABI_PPU,
        parts: &["ppu"],
        decompilation: DecompilationSupport::LiftOnly,
    },
    TargetSpec {
        profile: TargetProfile::Ps3Spu,
        name: "ps3-spu",
        aliases: &["ps3-spu", "spu", "cell-spu"],
        architecture: Architecture::Spu,
        loader: Loader::Ps3Self,
        default_base: None,
        abi: ABI_SPU,
        parts: &["spu"],
        decompilation: DecompilationSupport::LiftOnly,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declarative_table_covers_every_profile_once() {
        assert_eq!(TARGET_SPECS.len(), TargetProfile::ALL.len());
        for (index, profile) in TargetProfile::ALL.into_iter().enumerate() {
            let spec = profile.spec();
            assert_eq!(spec.profile, profile);
            assert_eq!(profile as usize, index);
            assert!(spec.aliases.contains(&spec.name));
        }
    }

    #[test]
    fn target_profiles_do_not_collapse_to_loader_identity() {
        assert_eq!(TargetProfile::Ps2.spec().architecture, Architecture::Ps2);
        assert_eq!(TargetProfile::Ps2.spec().loader, Loader::Elf);
        assert_eq!(TargetProfile::WiiU.spec().architecture, Architecture::Ppc32);
        assert_eq!(TargetProfile::WiiU.spec().loader, Loader::WiiURpl);
        assert_eq!(TargetProfile::N64.spec().loader, Loader::N64Rom);
    }

    #[test]
    fn gba_target_selects_thumb_raw_rom_defaults() {
        let spec = TargetProfile::Gba.spec();
        assert_eq!(spec.architecture, Architecture::Thumb);
        assert_eq!(spec.loader, Loader::Raw);
        assert_eq!(spec.default_base, Some(0x0800_0000));
    }

    #[test]
    fn target_aliases_cover_handheld_and_modern_names() {
        assert_eq!(TargetProfile::parse("nds"), Some(TargetProfile::NintendoDs));
        assert_eq!(TargetProfile::parse("xenon"), Some(TargetProfile::Xbox360));
        assert_eq!(
            TargetProfile::parse("cell-spu"),
            Some(TargetProfile::Ps3Spu)
        );
    }

    #[test]
    fn modern_target_profiles_keep_loader_abi_and_image_parts() {
        let cases = [
            (
                TargetProfile::NintendoDs,
                Architecture::Arm32,
                Loader::NintendoDs,
                &["arm9", "arm7"][..],
                "aapcs32",
            ),
            (
                TargetProfile::Nintendo3Ds,
                Architecture::Arm32,
                Loader::Ncch,
                &["arm11"][..],
                "aapcs32",
            ),
            (
                TargetProfile::Psp,
                Architecture::Mips32,
                Loader::PspPrx,
                &[][..],
                "mips-o32",
            ),
            (
                TargetProfile::Vita,
                Architecture::Arm32,
                Loader::VitaSelf,
                &[][..],
                "aapcs32",
            ),
            (
                TargetProfile::Wii,
                Architecture::GameCube,
                Loader::Dol,
                &[][..],
                "powerpc-eabi",
            ),
            (
                TargetProfile::WiiU,
                Architecture::Ppc32,
                Loader::WiiURpl,
                &[][..],
                "powerpc-eabi",
            ),
            (
                TargetProfile::Xbox360,
                Architecture::Ppc32,
                Loader::Xex,
                &[][..],
                "xenon-ppc",
            ),
            (
                TargetProfile::Ps3Ppu,
                Architecture::Ppc64,
                Loader::Ps3Self,
                &["ppu"][..],
                "powerpc64-elfv1",
            ),
            (
                TargetProfile::Ps3Spu,
                Architecture::Spu,
                Loader::Ps3Self,
                &["spu"][..],
                "spu-ls",
            ),
        ];
        for (profile, architecture, loader, parts, abi) in cases {
            let spec = profile.spec();
            assert_eq!(spec.architecture, architecture, "{profile:?}");
            assert_eq!(spec.loader, loader, "{profile:?}");
            assert_eq!(spec.parts, parts, "{profile:?}");
            assert_eq!(spec.abi.name, abi, "{profile:?}");
        }
    }

    #[test]
    fn console_abi_argument_layouts_are_explicit_and_target_owned() {
        let ps1 = TargetProfile::Ps1.spec().abi;
        assert_eq!(ps1.name, "ps1-mips-o32");
        assert_eq!(ps1.argument_mode, ArgumentRegisterMode::Unified);
        assert_eq!(ps1.arguments.integer.names, Some(MIPS_ARGS));
        assert_eq!(ps1.arguments.floating.names, Some(EMPTY));
        assert_eq!(
            ps1.stack_arguments,
            Some(StackArguments {
                first_offset: 16,
                slot_size: 4,
                register_slots: 4,
            })
        );

        for profile in [TargetProfile::GameCube, TargetProfile::Wii] {
            let abi = profile.spec().abi;
            assert_eq!(abi.argument_mode, ArgumentRegisterMode::Independent);
            assert_eq!(abi.arguments.integer.names, Some(PPC_ARGS));
            assert_eq!(abi.arguments.floating.names, Some(PPC_FLOAT_ARGS));
            assert_eq!(
                abi.return_register(AbiRegisterClass::Integer, 0),
                Some("r3")
            );
            assert_eq!(
                abi.stack_arguments,
                Some(StackArguments {
                    first_offset: 8,
                    slot_size: 4,
                    register_slots: 8,
                })
            );
        }

        for profile in [TargetProfile::Xbox360, TargetProfile::Ps3Ppu] {
            let abi = profile.spec().abi;
            assert_eq!(abi.stack_arguments, None, "{profile:?}");
            assert_eq!(abi.arguments.floating, UNKNOWN, "{profile:?}");
            assert_eq!(abi.returns.floating, UNKNOWN, "{profile:?}");
            assert_eq!(abi.small_struct_max_bytes, None, "{profile:?}");
            assert_eq!(abi.small_struct_returns, UNKNOWN, "{profile:?}");
        }

        let gba = TargetProfile::Gba.spec().abi;
        assert_eq!(gba.argument_mode, ArgumentRegisterMode::Unified);
        assert_eq!(gba.arguments.integer.names, Some(ARM_ARGS));
        assert_eq!(gba.arguments.floating.names, Some(EMPTY));
        assert_eq!(gba.stack_alignment, 4);
    }

    #[test]
    fn console_abi_return_and_preservation_classes_are_explicit() {
        let ps1 = TargetProfile::Ps1.spec().abi;
        assert_eq!(ps1.hidden_return_pointer, Some("$a0"));
        assert_eq!(ps1.small_struct_max_bytes, None);
        assert_eq!(ps1.small_struct_returns, UNKNOWN);
        assert!(ps1.caller_saved.names.unwrap().contains(&"$f19"));
        assert!(ps1.callee_saved.names.unwrap().contains(&"$f20"));

        let gamecube = TargetProfile::GameCube.spec().abi;
        assert_eq!(gamecube.hidden_return_pointer, Some("r3"));
        assert_eq!(gamecube.small_struct_max_bytes, Some(8));
        assert_eq!(gamecube.small_struct_returns.names, Some(PPC_RETURNS));
        assert!(gamecube.caller_saved.names.unwrap().contains(&"f13"));
        assert!(gamecube.callee_saved.names.unwrap().contains(&"f14"));

        let gba = TargetProfile::Gba.spec().abi;
        assert_eq!(gba.hidden_return_pointer, Some("r0"));
        assert_eq!(gba.small_struct_max_bytes, Some(4));
        assert_eq!(gba.small_struct_returns.names, Some(ARM_RETURNS));
        assert!(gba.caller_saved.names.unwrap().contains(&"s15"));
        assert!(gba.callee_saved.names.unwrap().contains(&"s16"));
    }
}
