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

const ABI_6502: Abi = Abi {
    name: "6502",
    pointer_bits: 16,
    stack_alignment: 1,
    stack_grows_down: true,
    stack_pointer: "sp",
    frame_pointer: None,
    return_address: None,
    return_register: "a",
    delay_slots: 0,
};
const ABI_Z80: Abi = Abi {
    name: "z80",
    pointer_bits: 16,
    stack_alignment: 2,
    stack_grows_down: true,
    stack_pointer: "sp",
    frame_pointer: None,
    return_address: None,
    return_register: "hl",
    delay_slots: 0,
};
const ABI_M68K: Abi = Abi {
    name: "m68k-c",
    pointer_bits: 32,
    stack_alignment: 4,
    stack_grows_down: true,
    stack_pointer: "a7",
    frame_pointer: Some("a6"),
    return_address: None,
    return_register: "d0",
    delay_slots: 0,
};
const ABI_SH: Abi = Abi {
    name: "sh-c",
    pointer_bits: 32,
    stack_alignment: 4,
    stack_grows_down: true,
    stack_pointer: "r15",
    frame_pointer: Some("r14"),
    return_address: Some("pr"),
    return_register: "r0",
    delay_slots: 1,
};
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
};
const ABI_MIPS_N64: Abi = Abi {
    name: "mips-n64",
    pointer_bits: 64,
    stack_alignment: 16,
    stack_grows_down: true,
    stack_pointer: "$sp",
    frame_pointer: Some("$fp"),
    return_address: Some("$ra"),
    return_register: "$v0",
    delay_slots: 1,
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
};
const ABI_ARM_GBA: Abi = Abi {
    name: "aapcs32-gba",
    pointer_bits: 32,
    stack_alignment: 4,
    stack_grows_down: true,
    stack_pointer: "r13",
    frame_pointer: Some("r11"),
    return_address: Some("lr"),
    return_register: "r0",
    delay_slots: 0,
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
};
const ABI_XENON: Abi = Abi {
    name: "xenon-pprc",
    pointer_bits: 32,
    stack_alignment: 16,
    stack_grows_down: true,
    stack_pointer: "r1",
    frame_pointer: None,
    return_address: Some("lr"),
    return_register: "r3",
    delay_slots: 0,
};
const ABI_PPU: Abi = Abi {
    name: "powerpc64-elfv2",
    pointer_bits: 64,
    stack_alignment: 16,
    stack_grows_down: true,
    stack_pointer: "r1",
    frame_pointer: None,
    return_address: Some("lr"),
    return_register: "r3",
    delay_slots: 0,
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
        abi: ABI_MIPS_O32,
        parts: &[],
        decompilation: DecompilationSupport::Experimental,
    },
    TargetSpec {
        profile: TargetProfile::Ps2,
        name: "ps2",
        aliases: &["ps2", "playstation2"],
        architecture: Architecture::Mips32,
        loader: Loader::Elf,
        default_base: None,
        abi: ABI_MIPS_O32,
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
        assert_eq!(TargetProfile::Ps2.spec().architecture, Architecture::Mips32);
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
                "xenon-pprc",
            ),
            (
                TargetProfile::Ps3Ppu,
                Architecture::Ppc64,
                Loader::Ps3Self,
                &["ppu"][..],
                "powerpc64-elfv2",
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
}
