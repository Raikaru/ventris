//! Source-backed game corpus metadata.
//!
//! The manifest contains addresses and provenance only. It deliberately does
//! not redistribute game binaries or copied source; users provide a legally
//! obtained image and run the listed command locally.

use ventris_target::TargetProfile;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CorpusFunction {
    pub name: &'static str,
    pub source_path: &'static str,
    pub address: u64,
    pub size: u32,
    pub note: &'static str,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CorpusEntry {
    pub id: &'static str,
    pub title: &'static str,
    pub target: TargetProfile,
    pub source_url: &'static str,
    pub source_commit: &'static str,
    pub source_license: &'static str,
    pub binary_name: &'static str,
    pub binary_sha256: Option<&'static str>,
    pub status: &'static str,
    pub functions: &'static [CorpusFunction],
}

const PERFECT_DARK_FUNCTIONS: &[CorpusFunction] = &[
    CorpusFunction {
        name: "preamble",
        source_path: "src/preamble/preamble.s",
        address: 0x8000_1000,
        size: 0x50,
        note: "NTSC linker preamble; the address is defined by ld/pd.ld",
    },
    CorpusFunction {
        name: "vm_boot",
        source_path: "src/lib/vm.s",
        address: 0x8000_1050,
        size: 0x54,
        note: "ld/pd.ld documents vm_boot at 0x70001050; 0x80001050 is the pre-TLB alias used by preamble; linked span is 0x54",
    },
    CorpusFunction {
        name: "vm_init_vars",
        source_path: "src/lib/vm.s",
        address: 0x8000_10a0,
        size: 0x9c,
        note: "src/lib/vm.s follows vm_boot; 0x800010a0 is the same raw-image alias; linked span is 0x9c",
    },
];

const ANIMAL_CROSSING_FUNCTIONS: &[CorpusFunction] = &[
    CorpusFunction {
        name: "memset",
        source_path: "src/static/Runtime.PPCEABI.H/__mem.c",
        address: 0x8000_33a8,
        size: 0x30,
        note: "GAFE01_00 symbol map entry",
    },
    CorpusFunction {
        name: "TRK_memset",
        source_path: "src/static/TRK_MINNOW_DOLPHIN/mem_TRK.c",
        address: 0x8000_34e0,
        size: 0x30,
        note: "GAFE01_00 symbol map entry",
    },
];

const STREET_FIGHTER_FUNCTIONS: &[CorpusFunction] = &[
    CorpusFunction {
        name: "flBeginRender",
        source_path: "src/anniversary/sf33rd/AcrSDK/ps2/flps2render.c",
        address: 0x0011_c1d0,
        size: 0x20,
        note: "anniversary syms_sfiii.txt render_start entry; size is the next-symbol span",
    },
    CorpusFunction {
        name: "flEndRender",
        source_path: "src/anniversary/sf33rd/AcrSDK/ps2/flps2render.c",
        address: 0x0011_c1f0,
        size: 0x20,
        note: "anniversary syms_sfiii.txt render_end entry; size is the next-symbol span",
    },
    CorpusFunction {
        name: "flPS2InitRenderState",
        source_path: "src/anniversary/sf33rd/AcrSDK/ps2/flps2render.c",
        address: 0x0011_c210,
        size: 0x120,
        note: "anniversary syms_sfiii.txt initRenderState entry; size is the next-symbol span",
    },
];

const POKEMON_EMERALD_FUNCTIONS: &[CorpusFunction] = &[
    CorpusFunction {
        name: "StartTimer1",
        source_path: "src/main.c",
        address: 0x0800_0554,
        size: 0x0c,
        note:
            "symbols branch pokeemerald.sym @ 9acaa0b2; source function is in the pinned src/main.c",
    },
    CorpusFunction {
        name: "SeedRngAndSetTrainerId",
        source_path: "src/main.c",
        address: 0x0800_0560,
        size: 0x28,
        note:
            "symbols branch pokeemerald.sym @ 9acaa0b2; source function is in the pinned src/main.c",
    },
    CorpusFunction {
        name: "GetGeneratedTrainerIdLower",
        source_path: "src/main.c",
        address: 0x0800_0588,
        size: 0x0c,
        note:
            "symbols branch pokeemerald.sym @ 9acaa0b2; source function is in the pinned src/main.c",
    },
    CorpusFunction {
        name: "InitKeys",
        source_path: "src/main.c",
        address: 0x0800_05bc,
        size: 0x28,
        note:
            "symbols branch pokeemerald.sym @ 9acaa0b2; source function is in the pinned src/main.c",
    },
];

/// Public corpus metadata with pinned symbols and source revisions.
///
/// The license field is factual metadata. A missing explicit license is not
/// converted into a different license or treated as a source-code omission.
/// `binary_sha256` pins the independently obtained reference image used by the
/// opt-in real-image smoke runner; Ventris does not bundle those images.
pub const CORPUS: &[CorpusEntry] = &[
    CorpusEntry {
        id: "n64-perfect-dark-ntsc-final",
        title: "Perfect Dark (N64, NTSC final)",
        target: TargetProfile::N64,
        source_url: "https://github.com/n64decomp/perfect_dark",
        source_commit: "169ed48bdcbfb3b568b028bd5bebb27680073514",
        source_license: "MIT",
        binary_name: "perfect_dark_ntsc_final.z64",
        binary_sha256: Some("4e51142acac686d96861cecc58cf7cb7c3b06b21733b7f8ed609a709dc039a21"),
        status: "licensed-source-metadata",
        functions: PERFECT_DARK_FUNCTIONS,
    },
    CorpusEntry {
        id: "gamecube-animal-crossing-gafe01",
        title: "Animal Crossing (GameCube, GAFE01_00)",
        target: TargetProfile::GameCube,
        source_url: "https://github.com/ACreTeam/ac-decomp",
        source_commit: "09ca8e8b5b24e6ab44047ee980cf0088ad7ecb4c",
        source_license: "CC0-1.0",
        binary_name: "animal_crossing_gafe01.dol",
        binary_sha256: Some("e3166b15b810ff20397784fc83b2eb053db5d0c2a9e22ac2ead63a645881d150"),
        status: "licensed-source-metadata",
        functions: ANIMAL_CROSSING_FUNCTIONS,
    },
    CorpusEntry {
        id: "ps2-street-fighter-iii-anniversary",
        title: "Street Fighter III 3rd Strike Anniversary (PS2)",
        target: TargetProfile::Ps2,
        source_url: "https://github.com/crowded-street/3s-decomp",
        source_commit: "be9b9bc69dc19822a8eca9ce3e72ba560d5a3835",
        source_license: "AGPL-3.0",
        binary_name: "street_fighter_iii_3rd_strike_anniversary.elf",
        binary_sha256: Some("b609c9ab16561696deeb05133f897f68959c8e1e5ea1998e5c212960f0b32a74"),
        status: "licensed-source-metadata",
        functions: STREET_FIGHTER_FUNCTIONS,
    },
    CorpusEntry {
        id: "gba-pokemon-emerald",
        title: "Pokémon Emerald (GBA)",
        target: TargetProfile::Gba,
        source_url: "https://github.com/pret/pokeemerald",
        source_commit: "201378bdc09692df7ba3530c9fe68b4c8efe1c00",
        source_license: "unspecified",
        binary_name: "pokeemerald.gba",
        binary_sha256: Some("a9dec84dfe7f62ab2220bafaef7479da0929d066ece16a6885f6226db19085af"),
        status: "public-reference",
        functions: POKEMON_EMERALD_FUNCTIONS,
    },
];

pub fn entries() -> &'static [CorpusEntry] {
    CORPUS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use ventris_lifter::Architecture;

    #[test]
    fn corpus_has_unique_ids_and_target_architectures() {
        let mut ids = BTreeSet::new();
        for entry in CORPUS {
            assert!(ids.insert(entry.id));
            assert!(!entry.functions.is_empty());
            assert_eq!(
                entry.target.spec().architecture,
                match entry.target {
                    TargetProfile::N64 => Architecture::N64,
                    TargetProfile::GameCube => Architecture::GameCube,
                    TargetProfile::Ps2 => Architecture::Mips32,
                    TargetProfile::Gba => Architecture::Thumb,
                    _ => unreachable!(),
                }
            );
        }
    }

    #[test]
    fn corpus_entries_have_multiple_unique_functions() {
        for entry in CORPUS {
            assert!(
                entry.functions.len() >= 2,
                "{} must expose more than one function",
                entry.id
            );
            let mut names = BTreeSet::new();
            let mut addresses = BTreeSet::new();
            for function in entry.functions {
                assert!(
                    names.insert(function.name),
                    "{} has duplicate function names",
                    entry.id
                );
                assert!(
                    addresses.insert(function.address),
                    "{} has duplicate function addresses",
                    entry.id
                );
                assert!(
                    function.size > 0,
                    "{} has a zero-sized function",
                    function.name
                );
            }
        }
    }

    #[test]
    fn gba_public_reference_retains_unspecified_license() {
        let entry = CORPUS
            .iter()
            .find(|entry| entry.target == TargetProfile::Gba)
            .unwrap();
        assert_eq!(entry.source_license, "unspecified");
        assert_eq!(entry.status, "public-reference");
    }
    fn recover_fixture<L: ventris_lifter::Lifter>(
        target: TargetProfile,
        bytes: &[u8],
        base: u64,
        lifter: L,
    ) -> crate::RecoveredFunction {
        let loaded =
            ventris_format::Image::load(bytes, ventris_format::Loader::Raw, Some(base)).unwrap();
        let function = lifter
            .discover(&loaded.image, &loaded.bytes, base, 32)
            .unwrap();
        crate::recover_function(target, crate::RecoveryInput::new(&function))
    }

    #[test]
    fn representative_console_fixtures_recover_target_abis() {
        let n64 = recover_fixture(
            TargetProfile::N64,
            &[
                0x8c82_0010u32.to_be_bytes(),
                0x03e0_0008u32.to_be_bytes(),
                0x0000_0000u32.to_be_bytes(),
            ]
            .concat(),
            0x8000_1000,
            ventris_lifter::N64,
        );
        assert_eq!(n64.abi.pointer_bits, 64);
        assert_eq!(n64.abi.stack_alignment, 16);
        assert_eq!(n64.accesses.len(), 1);

        let ps2 = recover_fixture(
            TargetProfile::Ps2,
            &[
                0x8c82_0010u32.to_le_bytes(),
                0x03e0_0008u32.to_le_bytes(),
                0x0000_0000u32.to_le_bytes(),
            ]
            .concat(),
            0x0011_c1d0,
            ventris_lifter::Mips32,
        );
        assert_eq!(ps2.abi.name, "ps2-r5900-o32");
        assert_eq!(ps2.abi.pointer_bits, 32);
        assert_eq!(ps2.abi.stack_alignment, 8);
        assert_eq!(ps2.accesses.len(), 1);
        let gamecube = recover_fixture(
            TargetProfile::GameCube,
            &[0x8064_0010u32.to_be_bytes(), 0x4e80_0020u32.to_be_bytes()].concat(),
            0x8000_33a8,
            ventris_lifter::GameCube,
        );
        assert_eq!(gamecube.abi.pointer_bits, 32);
        assert_eq!(gamecube.abi.stack_alignment, 16);
        assert_eq!(gamecube.accesses.len(), 1);

        let gba = recover_fixture(
            TargetProfile::Gba,
            &[0x4901u16, 0x2080, 0x8008, 0x4770]
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<_>>(),
            0x0800_0554,
            ventris_lifter::Thumb,
        );
        assert_eq!(gba.abi.architecture, ventris_lifter::Architecture::Thumb);
        assert_eq!(gba.abi.stack_alignment, 4);
        assert_eq!(gba.accesses.len(), 2);
    }
}
