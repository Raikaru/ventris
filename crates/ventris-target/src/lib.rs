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
pub struct Abi {
    pub name: &'static str,
    pub pointer_bits: u8,
    pub stack_alignment: u8,
    pub stack_grows_down: bool,
    pub return_register: &'static str,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TargetSpec {
    pub profile: TargetProfile,
    pub name: &'static str,
    pub architecture: Architecture,
    pub loader: Loader,
    pub default_base: Option<u64>,
    pub abi: Abi,
    /// Named image parts when the container has more than one code image.
    pub parts: &'static [&'static str],
}

const ABI_6502: Abi = Abi {
    name: "6502",
    pointer_bits: 16,
    stack_alignment: 1,
    stack_grows_down: true,
    return_register: "a",
};
const ABI_Z80: Abi = Abi {
    name: "z80",
    pointer_bits: 16,
    stack_alignment: 2,
    stack_grows_down: true,
    return_register: "hl",
};
const ABI_M68K: Abi = Abi {
    name: "m68k-c",
    pointer_bits: 32,
    stack_alignment: 4,
    stack_grows_down: true,
    return_register: "d0",
};
const ABI_SH: Abi = Abi {
    name: "sh-c",
    pointer_bits: 32,
    stack_alignment: 4,
    stack_grows_down: true,
    return_register: "r0",
};
const ABI_MIPS_O32: Abi = Abi {
    name: "mips-o32",
    pointer_bits: 32,
    stack_alignment: 8,
    stack_grows_down: true,
    return_register: "$v0",
};
const ABI_MIPS_N64: Abi = Abi {
    name: "mips-n64",
    pointer_bits: 64,
    stack_alignment: 16,
    stack_grows_down: true,
    return_register: "$v0",
};
const ABI_ARM_AAPCS: Abi = Abi {
    name: "aapcs32",
    pointer_bits: 32,
    stack_alignment: 8,
    stack_grows_down: true,
    return_register: "r0",
};
const ABI_ARM_GBA: Abi = Abi {
    name: "aapcs32-gba",
    pointer_bits: 32,
    stack_alignment: 4,
    stack_grows_down: true,
    return_register: "r0",
};
const ABI_PPC_EABI: Abi = Abi {
    name: "powerpc-eabi",
    pointer_bits: 32,
    stack_alignment: 16,
    stack_grows_down: true,
    return_register: "r3",
};
const ABI_XENON: Abi = Abi {
    name: "xenon-pprc",
    pointer_bits: 32,
    stack_alignment: 16,
    stack_grows_down: true,
    return_register: "r3",
};
const ABI_PPU: Abi = Abi {
    name: "powerpc64-elfv2",
    pointer_bits: 64,
    stack_alignment: 16,
    stack_grows_down: true,
    return_register: "r3",
};
const ABI_SPU: Abi = Abi {
    name: "spu-ls",
    pointer_bits: 32,
    stack_alignment: 16,
    stack_grows_down: true,
    return_register: "r3",
};

impl TargetProfile {
    pub fn name(self) -> &'static str {
        self.spec().name
    }

    pub fn parse(value: &str) -> Option<Self> {
        let value = value.to_ascii_lowercase();
        match value.as_str() {
            "atari2600" | "atari-2600" | "2600" => Some(Self::Atari2600),
            "nes" | "nintendo" | "nintendo-entertainment-system" => Some(Self::Nes),
            "snes" | "super-nes" | "super-nintendo" => Some(Self::Snes),
            "sms" | "master-system" | "mastersystem" => Some(Self::MasterSystem),
            "game-gear" | "gamegear" | "gg" => Some(Self::GameGear),
            "genesis" | "mega-drive" | "megadrive" => Some(Self::Genesis),
            "neo-geo" | "neogeo" => Some(Self::NeoGeo),
            "c64" | "commodore-64" | "commodore64" => Some(Self::C64),
            "ps1" | "playstation" | "playstation1" | "psx" => Some(Self::Ps1),
            "ps2" | "playstation2" => Some(Self::Ps2),
            "n64" | "nintendo-64" | "nintendo64" => Some(Self::N64),
            "saturn" | "sega-saturn" => Some(Self::Saturn),
            "dreamcast" | "dc" => Some(Self::Dreamcast),
            "gamecube" | "gc" => Some(Self::GameCube),
            "wii" => Some(Self::Wii),
            "gba" | "game-boy-advance" | "gameboy-advance" => Some(Self::Gba),
            "nds" | "ds" | "nintendo-ds" | "nintendods" => Some(Self::NintendoDs),
            "3ds" | "nintendo-3ds" | "nintendo3ds" => Some(Self::Nintendo3Ds),
            "psp" | "playstation-portable" => Some(Self::Psp),
            "vita" | "psvita" | "playstation-vita" => Some(Self::Vita),
            "wiiu" | "wii-u" => Some(Self::WiiU),
            "xbox360" | "xbox-360" | "xenon" => Some(Self::Xbox360),
            "ps3" | "ps3-ppu" | "cell-ppu" => Some(Self::Ps3Ppu),
            "ps3-spu" | "spu" | "cell-spu" => Some(Self::Ps3Spu),
            _ => None,
        }
    }

    pub fn spec(self) -> TargetSpec {
        let (name, architecture, loader, default_base, abi, parts) = match self {
            Self::Atari2600 => (
                "atari2600",
                Architecture::M6502,
                Loader::Raw,
                Some(0),
                ABI_6502,
                &[][..],
            ),
            Self::Nes => (
                "nes",
                Architecture::M6502,
                Loader::Raw,
                Some(0x8000),
                ABI_6502,
                &[][..],
            ),
            Self::Snes => (
                "snes",
                Architecture::M6502,
                Loader::Raw,
                Some(0x8000),
                ABI_6502,
                &[][..],
            ),
            Self::MasterSystem => (
                "master-system",
                Architecture::Z80,
                Loader::Raw,
                Some(0),
                ABI_Z80,
                &[][..],
            ),
            Self::GameGear => (
                "game-gear",
                Architecture::Z80,
                Loader::Raw,
                Some(0),
                ABI_Z80,
                &[][..],
            ),
            Self::Genesis => (
                "genesis",
                Architecture::M68k,
                Loader::Raw,
                Some(0),
                ABI_M68K,
                &[][..],
            ),
            Self::NeoGeo => (
                "neo-geo",
                Architecture::M68k,
                Loader::Raw,
                Some(0),
                ABI_M68K,
                &[][..],
            ),
            Self::C64 => (
                "c64",
                Architecture::M6502,
                Loader::Raw,
                Some(0),
                ABI_6502,
                &[][..],
            ),
            Self::Ps1 => (
                "ps1",
                Architecture::Ps1,
                Loader::Raw,
                Some(0x8001_0000),
                ABI_MIPS_O32,
                &[][..],
            ),
            Self::Ps2 => (
                "ps2",
                Architecture::Mips32,
                Loader::Elf,
                None,
                ABI_MIPS_O32,
                &[][..],
            ),
            Self::N64 => (
                "n64",
                Architecture::N64,
                Loader::N64Rom,
                None,
                ABI_MIPS_N64,
                &[][..],
            ),
            Self::Saturn => (
                "saturn",
                Architecture::Sh2,
                Loader::Raw,
                Some(0),
                ABI_SH,
                &[][..],
            ),
            Self::Dreamcast => (
                "dreamcast",
                Architecture::Sh4,
                Loader::Elf,
                None,
                ABI_SH,
                &[][..],
            ),
            Self::GameCube => (
                "gamecube",
                Architecture::GameCube,
                Loader::Dol,
                None,
                ABI_PPC_EABI,
                &[][..],
            ),
            Self::Wii => (
                "wii",
                Architecture::GameCube,
                Loader::Dol,
                None,
                ABI_PPC_EABI,
                &[][..],
            ),
            Self::Gba => (
                "gba",
                Architecture::Thumb,
                Loader::Raw,
                Some(0x0800_0000),
                ABI_ARM_GBA,
                &[][..],
            ),
            Self::NintendoDs => (
                "nds",
                Architecture::Arm32,
                Loader::NintendoDs,
                None,
                ABI_ARM_AAPCS,
                &["arm9", "arm7"][..],
            ),
            Self::Nintendo3Ds => (
                "3ds",
                Architecture::Arm32,
                Loader::Ncch,
                None,
                ABI_ARM_AAPCS,
                &["arm11"][..],
            ),
            Self::Psp => (
                "psp",
                Architecture::Mips32,
                Loader::PspPrx,
                None,
                ABI_MIPS_O32,
                &[][..],
            ),
            Self::Vita => (
                "vita",
                Architecture::Arm32,
                Loader::VitaSelf,
                None,
                ABI_ARM_AAPCS,
                &[][..],
            ),
            Self::WiiU => (
                "wiiu",
                Architecture::Ppc32,
                Loader::WiiURpl,
                None,
                ABI_PPC_EABI,
                &[][..],
            ),
            Self::Xbox360 => (
                "xbox360",
                Architecture::Ppc32,
                Loader::Xex,
                None,
                ABI_XENON,
                &[][..],
            ),
            Self::Ps3Ppu => (
                "ps3-ppu",
                Architecture::Ppc64,
                Loader::Ps3Self,
                None,
                ABI_PPU,
                &["ppu"][..],
            ),
            Self::Ps3Spu => (
                "ps3-spu",
                Architecture::Spu,
                Loader::Ps3Self,
                None,
                ABI_SPU,
                &["spu"][..],
            ),
        };
        TargetSpec {
            profile: self,
            name,
            architecture,
            loader,
            default_base,
            abi,
            parts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
