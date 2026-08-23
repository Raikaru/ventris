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

/// Reviewable source-derived facts used by the opt-in semantic corpus gate.
///
/// These are facts, not copied source. An empty dimension means the pinned
/// source establishes that the construct is absent.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CorpusSemanticBaseline {
    pub control_flow: &'static [&'static str],
    pub calls: &'static [&'static str],
    pub globals: &'static [&'static str],
    pub access_types: &'static [&'static str],
    pub casts: u32,
    pub aggregate_copies: u32,
    pub declaration_order: &'static [&'static str],
    pub nominal_fields: &'static [&'static str],
    pub source_structure: &'static [&'static str],
}
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct CorpusCompilerBaseline {
    pub compiler: &'static str,
    pub target: &'static str,
    pub minimum_mnemonic_lcs_ratio: f64,
}

const CLANG_MIPSEL: &str = "clang --target=mipsel-none-elf -O2";

const DUNGEON_FADE_BASELINE: CorpusSemanticBaseline = CorpusSemanticBaseline {
    control_flow: &["if", "return"],
    calls: &[],
    globals: &[],
    access_types: &["bool", "u8"],
    casts: 0,
    aggregate_copies: 0,
    declaration_order: &[],
    nominal_fields: &[
        "GameWorld.drawFadeScreen",
        "GameWorld.fadeAlpha",
        "GameWorld.fadeIn",
        "GameWorld.fadeOut",
    ],
    source_structure: &["if", "return"],
};

const DUNGEON_FADE_FINISHED_BASELINE: CorpusSemanticBaseline = CorpusSemanticBaseline {
    control_flow: &[],
    calls: &[],
    globals: &[],
    access_types: &["bool"],
    casts: 0,
    aggregate_copies: 0,
    declaration_order: &[],
    nominal_fields: &["GameWorld.drawFadeScreen"],
    source_structure: &[],
};

const DUNGEON_ALLOC_ENEMY_BASELINE: CorpusSemanticBaseline =
    dungeon_alloc_baseline(&["GameWorld.enemyEntitiesInUse"]);
const DUNGEON_ALLOC_RENDER_BASELINE: CorpusSemanticBaseline =
    dungeon_alloc_baseline(&["GameWorld.renderEntitiesInUse"]);
const DUNGEON_ALLOC_SHADOW_BASELINE: CorpusSemanticBaseline =
    dungeon_alloc_baseline(&["GameWorld.shadowBlobsInUse"]);
const DUNGEON_ALLOC_LIGHTMAP_BASELINE: CorpusSemanticBaseline =
    dungeon_alloc_baseline(&["GameWorld.lightmapsInUse"]);
const DUNGEON_ALLOC_PARTICLE_BASELINE: CorpusSemanticBaseline =
    dungeon_alloc_baseline(&["GameWorld.prtEmittersInUse"]);

const fn dungeon_alloc_baseline(nominal_fields: &'static [&'static str]) -> CorpusSemanticBaseline {
    CorpusSemanticBaseline {
        control_flow: &["return"],
        calls: &[],
        globals: &[],
        access_types: &["u32"],
        casts: 1,
        aggregate_copies: 0,
        declaration_order: &[],
        nominal_fields,
        source_structure: &["return"],
    }
}

/// Source-controlled facts consumed by `recover-types` and
/// `reconstruct-source` for the public Dungeon Game acceptance corpus.
pub const DUNGEON_GAME_METADATA_JSON: &str = r#"{
  "provenance": {
    "url": "https://github.com/glampert/ps2-homebrew",
    "commit": "602441a6877a3136709d6320664340d52e3027a1",
    "license": "MIT",
    "path": "source/demos/dungeon_game/game_world.hpp"
  },
  "nominal_types": [{
    "id": 1,
    "name": "GameWorld",
    "size": 22224,
    "fields": [
      {"offset": 1186, "name": "fadeAlpha", "width": 1,
       "type": {"kind": "primitive", "name": "uint8_t", "bits": 8, "signed": false}},
      {"offset": 1187, "name": "drawFadeScreen", "width": 1,
       "type": {"kind": "primitive", "name": "bool", "bits": 8}},
      {"offset": 1188, "name": "fadeOut", "width": 1,
       "type": {"kind": "primitive", "name": "bool", "bits": 8}},
      {"offset": 1189, "name": "fadeIn", "width": 1,
       "type": {"kind": "primitive", "name": "bool", "bits": 8}},
      {"offset": 1190, "name": "inMainMenu", "width": 1,
       "type": {"kind": "primitive", "name": "bool", "bits": 8}},
      {"offset": 1192, "name": "currLevel", "width": 4,
       "type": {"kind": "enum", "name": "LevelId", "bits": 32, "signed": true}},
      {"offset": 1200, "name": "enemyEntitiesInUse", "width": 4,
       "type": {"kind": "primitive", "name": "uint32_t", "bits": 32, "signed": false}},
      {"offset": 1204, "name": "renderEntitiesInUse", "width": 4,
       "type": {"kind": "primitive", "name": "uint32_t", "bits": 32, "signed": false}},
      {"offset": 1208, "name": "shadowBlobsInUse", "width": 4,
       "type": {"kind": "primitive", "name": "uint32_t", "bits": 32, "signed": false}},
      {"offset": 1212, "name": "lightmapsInUse", "width": 4,
       "type": {"kind": "primitive", "name": "uint32_t", "bits": 32, "signed": false}},
      {"offset": 1216, "name": "prtEmittersInUse", "width": 4,
       "type": {"kind": "primitive", "name": "uint32_t", "bits": 32, "signed": false}}
    ]
  }],
  "assertions": [{
    "space": 4,
    "base": 16,
    "size": 4,
    "offset": 0,
    "name": "this_",
    "type": {"kind": "nominal", "id": 1, "name": "GameWorld", "size": 22224},
    "note": "GameWorld member-function receiver from pinned source metadata"
  }]
}"#;

pub fn semantic_baseline(entry_id: &str, function: &str) -> Option<CorpusSemanticBaseline> {
    match (entry_id, function) {
        ("ps2-dungeon-game", "_ZN9GameWorld12beginFadeOutEv")
        | ("ps2-dungeon-game", "_ZN9GameWorld11beginFadeInEv") => Some(DUNGEON_FADE_BASELINE),
        ("ps2-dungeon-game", "_ZN9GameWorld16onFadeInFinishedEv") => {
            Some(DUNGEON_FADE_FINISHED_BASELINE)
        }
        ("ps2-dungeon-game", "_ZN9GameWorld16allocEnemyEntityEv") => {
            Some(DUNGEON_ALLOC_ENEMY_BASELINE)
        }
        ("ps2-dungeon-game", "_ZN9GameWorld17allocRenderEntityEv") => {
            Some(DUNGEON_ALLOC_RENDER_BASELINE)
        }
        ("ps2-dungeon-game", "_ZN9GameWorld15allocShadowBlobEv") => {
            Some(DUNGEON_ALLOC_SHADOW_BASELINE)
        }
        ("ps2-dungeon-game", "_ZN9GameWorld13allocLightmapEv") => {
            Some(DUNGEON_ALLOC_LIGHTMAP_BASELINE)
        }
        ("ps2-dungeon-game", "_ZN9GameWorld20allocParticleEmitterEv") => {
            Some(DUNGEON_ALLOC_PARTICLE_BASELINE)
        }
        _ => None,
    }
}
pub fn compiler_baseline(entry_id: &str, function: &str) -> Option<CorpusCompilerBaseline> {
    let minimum_mnemonic_lcs_ratio = match (entry_id, function) {
        ("ps2-dungeon-game", "_ZN9GameWorld12beginFadeOutEv") => 3.0 / 13.0,
        ("ps2-dungeon-game", "_ZN9GameWorld11beginFadeInEv") => 2.0 / 13.0,
        ("ps2-dungeon-game", "_ZN9GameWorld16onFadeInFinishedEv") => 1.0 / 6.0,
        ("ps2-dungeon-game", "_ZN9GameWorld16allocEnemyEntityEv")
        | ("ps2-dungeon-game", "_ZN9GameWorld17allocRenderEntityEv")
        | ("ps2-dungeon-game", "_ZN9GameWorld15allocShadowBlobEv")
        | ("ps2-dungeon-game", "_ZN9GameWorld13allocLightmapEv")
        | ("ps2-dungeon-game", "_ZN9GameWorld20allocParticleEmitterEv") => 0.5,
        _ => return None,
    };
    Some(CorpusCompilerBaseline {
        compiler: CLANG_MIPSEL,
        target: "ps2",
        minimum_mnemonic_lcs_ratio,
    })
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
    pub binary_sha1: Option<&'static str>,
    pub status: &'static str,
    pub metadata_json: Option<&'static str>,
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
        address: 0x003e_e930,
        size: 0x80,
        note: "anniversary syms_sfiii.txt flBeginRender entry; size is the next-symbol span",
    },
    CorpusFunction {
        name: "flEndRender",
        source_path: "src/anniversary/sf33rd/AcrSDK/ps2/flps2render.c",
        address: 0x003e_e9b0,
        size: 0x70,
        note: "anniversary syms_sfiii.txt flEndRender entry; size is the next-symbol span",
    },
    CorpusFunction {
        name: "flPS2InitRenderState",
        source_path: "src/anniversary/sf33rd/AcrSDK/ps2/flps2render.c",
        address: 0x003e_ea20,
        size: 0x230,
        note: "anniversary syms_sfiii.txt flPS2InitRenderState entry; size is the next-symbol span",
    },
];

const DUNGEON_GAME_FUNCTIONS: &[CorpusFunction] = &[
    CorpusFunction {
        name: "_ZN9GameWorld12beginFadeOutEv",
        source_path: "source/demos/dungeon_game/game_world.cpp",
        address: 0x0012_4058,
        size: 0x28,
        note: "GameWorld::beginFadeOut; checked-in ELF symbol and next-symbol span",
    },
    CorpusFunction {
        name: "_ZN9GameWorld11beginFadeInEv",
        source_path: "source/demos/dungeon_game/game_world.cpp",
        address: 0x0012_4080,
        size: 0x28,
        note: "GameWorld::beginFadeIn; checked-in ELF symbol and next-symbol span",
    },
    CorpusFunction {
        name: "_ZN9GameWorld16onFadeInFinishedEv",
        source_path: "source/demos/dungeon_game/game_world.cpp",
        address: 0x0012_40e8,
        size: 0x08,
        note: "GameWorld::onFadeInFinished; checked-in ELF symbol and next-symbol span",
    },
    CorpusFunction {
        name: "_ZN9GameWorld15drawMainMenuOptER5Vec2fPKcb",
        source_path: "source/demos/dungeon_game/game_world.cpp",
        address: 0x0012_3cd0,
        size: 0xb4,
        note: "GameWorld::drawMainMenuOpt; bounded call/conditional smoke from checked-in ELF",
    },
    CorpusFunction {
        name: "_ZNK9GameWorld17getBuiltInTextureEPKc",
        source_path: "source/demos/dungeon_game/game_world.cpp",
        address: 0x0012_4fa8,
        size: 0xd4,
        note: "GameWorld::getBuiltInTexture; bounded call-chain smoke from checked-in ELF",
    },
    CorpusFunction {
        name: "_ZN9GameWorld16allocEnemyEntityEv",
        source_path: "source/demos/dungeon_game/game_world.cpp",
        address: 0x0012_5080,
        size: 0x20,
        note: "GameWorld::allocEnemyEntity; checked-in ELF symbol and next-symbol span",
    },
    CorpusFunction {
        name: "_ZN9GameWorld17allocRenderEntityEv",
        source_path: "source/demos/dungeon_game/game_world.cpp",
        address: 0x0012_50a0,
        size: 0x20,
        note: "GameWorld::allocRenderEntity; checked-in ELF symbol and next-symbol span",
    },
    CorpusFunction {
        name: "_ZN9GameWorld15allocShadowBlobEv",
        source_path: "source/demos/dungeon_game/game_world.cpp",
        address: 0x0012_50c0,
        size: 0x20,
        note: "GameWorld::allocShadowBlob; checked-in ELF symbol and next-symbol span",
    },
    CorpusFunction {
        name: "_ZN9GameWorld13allocLightmapEv",
        source_path: "source/demos/dungeon_game/game_world.cpp",
        address: 0x0012_50e0,
        size: 0x20,
        note: "GameWorld::allocLightmap; checked-in ELF symbol and next-symbol span",
    },
    CorpusFunction {
        name: "_ZN9GameWorld20allocParticleEmitterEv",
        source_path: "source/demos/dungeon_game/game_world.cpp",
        address: 0x0012_5100,
        size: 0x20,
        note: "GameWorld::allocParticleEmitter; checked-in ELF symbol and next-symbol span",
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
/// `binary_sha256` or `binary_sha1` pins the independently obtained reference
/// image used by the opt-in real-image smoke runner; Ventris does not bundle
/// those images.
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
        binary_sha1: None,
        metadata_json: None,
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
        binary_sha1: None,
        metadata_json: None,
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
        binary_name: "THIRD_U.BIN",
        binary_sha256: None,
        binary_sha1: Some("cf58495054c31ad852175c66e9ca04d5094f000e"),
        metadata_json: None,
        status: "licensed-source-metadata",
        functions: STREET_FIGHTER_FUNCTIONS,
    },
    CorpusEntry {
        id: "ps2-dungeon-game",
        title: "Dungeon Game (PS2 homebrew)",
        target: TargetProfile::Ps2,
        source_url: "https://github.com/glampert/ps2-homebrew",
        source_commit: "602441a6877a3136709d6320664340d52e3027a1",
        source_license: "MIT",
        binary_name: "dungeon_game.elf",
        binary_sha256: Some("25faee2f98483f7f86d0dd7043e7b506c998728989347c8a38ae8af49c0a1af4"),
        binary_sha1: None,
        metadata_json: Some(DUNGEON_GAME_METADATA_JSON),
        status: "public-reference",
        functions: DUNGEON_GAME_FUNCTIONS,
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
        binary_sha1: None,
        metadata_json: None,
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
    #[test]
    fn ps2_reference_is_pinned_to_the_source_project_image() {
        let entry = CORPUS
            .iter()
            .find(|entry| entry.id == "ps2-street-fighter-iii-anniversary")
            .unwrap();
        assert_eq!(entry.binary_name, "THIRD_U.BIN");
        assert_eq!(
            entry.binary_sha1,
            Some("cf58495054c31ad852175c66e9ca04d5094f000e")
        );
        assert_eq!(
            entry
                .functions
                .iter()
                .map(|function| (function.name, function.address, function.size))
                .collect::<Vec<_>>(),
            vec![
                ("flBeginRender", 0x003e_e930, 0x80),
                ("flEndRender", 0x003e_e9b0, 0x70),
                ("flPS2InitRenderState", 0x003e_ea20, 0x230),
            ]
        );
        assert!(entry
            .functions
            .iter()
            .all(|function| semantic_baseline(entry.id, function.name).is_none()));
    }

    #[test]
    fn public_ps2_game_pins_checked_in_elf_and_source_symbols() {
        let entry = CORPUS
            .iter()
            .find(|entry| entry.id == "ps2-dungeon-game")
            .unwrap();
        assert_eq!(entry.binary_name, "dungeon_game.elf");
        assert_eq!(
            entry.binary_sha256,
            Some("25faee2f98483f7f86d0dd7043e7b506c998728989347c8a38ae8af49c0a1af4")
        );
        assert_eq!(
            entry.source_commit,
            "602441a6877a3136709d6320664340d52e3027a1"
        );
        assert_eq!(entry.functions.len(), 10);
        assert_eq!(
            entry
                .functions
                .iter()
                .filter(|function| semantic_baseline(entry.id, function.name).is_some())
                .count(),
            8
        );
        assert_eq!(
            entry
                .functions
                .iter()
                .filter(|function| compiler_baseline(entry.id, function.name).is_some())
                .count(),
            8
        );
        assert_eq!(
            compiler_baseline(entry.id, "_ZN9GameWorld12beginFadeOutEv")
                .unwrap()
                .minimum_mnemonic_lcs_ratio,
            3.0 / 13.0
        );
        assert!(entry
            .functions
            .iter()
            .all(|function| function.source_path == "source/demos/dungeon_game/game_world.cpp"));
        assert!(entry.metadata_json.is_some());
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
