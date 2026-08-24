//! Regressions pinned against real PlayStation 2 retail bytes.
//!
//! Every behaviour here was wrong before and is architecture-neutral: the
//! defects were in memory ordering, likely-branch control flow, and merge
//! points, not in anything specific to the R5900.

use std::collections::{BTreeMap, BTreeSet};

use ventris_decompiler::native::NativeDecompiler;
use ventris_lifter::{Architecture, Flow, NativeFunction, lifter_for};
use ventris_target::TargetProfile;

/// `GameWorld::allocEnemyEntity`, which post-increments a member and returns a
/// pointer computed from the value *before* the increment.
const ALLOC_ENEMY_ENTITY: &[u8] = &[
    0xb0, 0x04, 0x87, 0x8c, 0x70, 0x00, 0x05, 0x24, 0x18, 0x18, 0xe5, 0x00, 0x01, 0x00, 0xe2, 0x24,
    0xb0, 0x04, 0x82, 0xac, 0x21, 0x30, 0x64, 0x00, 0x08, 0x00, 0xe0, 0x03, 0xd0, 0x04, 0xc2, 0x24,
];

/// `GameWorld::getBuiltInTexture`, a chain of `memcmp` tests that ends in a
/// likely-branch and merges every path into one epilogue.
const GET_BUILT_IN_TEXTURE: &[u8] = &[
    0xe0, 0xff, 0xbd, 0x27, 0x15, 0x00, 0x02, 0x3c, 0x00, 0x00, 0xb0, 0xff, 0x2d, 0x20, 0xa0, 0x00,
    0x2d, 0x80, 0xa0, 0x00, 0x0e, 0x00, 0x06, 0x24, 0x10, 0x00, 0xbf, 0xff, 0xfe, 0x94, 0x04, 0x0c,
    0xb0, 0xc0, 0x45, 0x24, 0x06, 0x00, 0x40, 0x14, 0x3c, 0x00, 0x03, 0x3c, 0xc0, 0xcd, 0x62, 0x24,
    0x10, 0x00, 0xbf, 0xdf, 0x00, 0x00, 0xb0, 0xdf, 0x08, 0x00, 0xe0, 0x03, 0x20, 0x00, 0xbd, 0x27,
    0x15, 0x00, 0x02, 0x3c, 0x2d, 0x20, 0x00, 0x02, 0x0e, 0x00, 0x06, 0x24, 0xfe, 0x94, 0x04, 0x0c,
    0xc0, 0xc0, 0x45, 0x24, 0x03, 0x00, 0x40, 0x14, 0x3c, 0x00, 0x04, 0x3c, 0xf4, 0xff, 0x00, 0x10,
    0xf8, 0x27, 0x82, 0x24, 0x15, 0x00, 0x07, 0x3c, 0x2d, 0x20, 0x00, 0x02, 0x0d, 0x00, 0x06, 0x24,
    0xfe, 0x94, 0x04, 0x0c, 0xd0, 0xc0, 0xe5, 0x24, 0x03, 0x00, 0x40, 0x14, 0x3c, 0x00, 0x05, 0x3c,
    0xeb, 0xff, 0x00, 0x10, 0x60, 0xaa, 0xa2, 0x24, 0x15, 0x00, 0x08, 0x3c, 0x2d, 0x20, 0x00, 0x02,
    0x0c, 0x00, 0x06, 0x24, 0xfe, 0x94, 0x04, 0x0c, 0xe0, 0xc0, 0x05, 0x25, 0x03, 0x00, 0x40, 0x14,
    0x39, 0x00, 0x06, 0x3c, 0xe2, 0xff, 0x00, 0x10, 0x98, 0x4f, 0xc2, 0x24, 0x15, 0x00, 0x09, 0x3c,
    0x2d, 0x20, 0x00, 0x02, 0x09, 0x00, 0x06, 0x24, 0xfe, 0x94, 0x04, 0x0c, 0xf0, 0xc0, 0x25, 0x25,
    0xdb, 0xff, 0x40, 0x54, 0x2d, 0x10, 0x00, 0x00, 0x3a, 0x00, 0x0a, 0x3c, 0xd8, 0xff, 0x00, 0x10,
    0xb0, 0xb8, 0x42, 0x25,
];

fn discover(bytes: &[u8], entry: u64) -> NativeFunction {
    let lifter = lifter_for(Architecture::Ps2);
    let mut instructions = BTreeMap::new();
    let mut edges = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let end = entry + bytes.len() as u64;
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let address = entry + index as u64 * 4;
        let instruction = lifter
            .lift_instruction(address, chunk)
            .unwrap_or_else(|error| panic!("{address:#x}: {error}"));
        if let Some(next) = instruction.flow.fallthrough().filter(|next| *next < end) {
            edges.insert((address, next));
        }
        match instruction.flow {
            Flow::Jump(target) | Flow::Conditional { target, .. }
                if (entry..end).contains(&target) =>
            {
                edges.insert((address, target));
            }
            Flow::Call { target, .. } => {
                calls.insert(target);
            }
            _ => {}
        }
        instructions.insert(address, instruction);
    }
    NativeFunction {
        entry,
        instructions,
        edges,
        calls,
    }
}

fn render(bytes: &[u8], entry: u64) -> String {
    let abi = TargetProfile::Ps2.spec().abi;
    NativeDecompiler
        .decompile_with_abi_memory_and_symbols(
            Architecture::Ps2,
            &discover(bytes, entry),
            Some(&abi),
            None,
            None,
        )
        .render()
}

#[test]
fn a_value_read_before_a_store_is_not_read_again_after_it() {
    let source = render(ALLOC_ENEMY_ENTITY, 0x125080);
    let lines: Vec<&str> = source.lines().collect();
    let snapshot = lines
        .iter()
        .position(|line| line.contains("mem_"))
        .unwrap_or_else(|| panic!("no value was read before the store\n{source}"));
    let store = lines
        .iter()
        .position(|line| line.contains("0x4b0)) =") || line.contains("0x4b0) ="))
        .unwrap_or_else(|| panic!("no store to the member\n{source}"));
    assert!(
        snapshot < store,
        "the read must be emitted before the store\n{source}"
    );
    assert!(
        lines[snapshot].contains("0x4b0"),
        "the snapshot must hold the member's value\n{source}"
    );
    let after_store = lines[store + 1..].join("\n");
    assert!(
        after_store.contains("mem_"),
        "the value read before the store must be the one used afterwards\n{source}"
    );
}

#[test]
fn a_likely_branch_keeps_both_successors() {
    let lifter = lifter_for(Architecture::Ps2);
    // `bnel $v0, $zero, -0x94` at 0x125068, the tail of getBuiltInTexture.
    let instruction = lifter
        .lift_instruction(0x125068, &[0xdb, 0xff, 0x40, 0x54])
        .unwrap();
    assert!(instruction.skips_delay_slot(), "{:?}", instruction.flow);
    match instruction.flow {
        Flow::Conditional {
            target,
            fallthrough,
        } => {
            assert_eq!(fallthrough, 0x12506c);
            assert_eq!(target, 0x124fd8);
        }
        flow => panic!("likely branch reported {flow:?}"),
    }
}

#[test]
fn a_likely_branch_does_not_truncate_the_function() {
    let function = discover(GET_BUILT_IN_TEXTURE, 0x124fa8);
    assert_eq!(
        function.instructions.len(),
        GET_BUILT_IN_TEXTURE.len() / 4,
        "every instruction of the function must be discovered"
    );
    let source = render(GET_BUILT_IN_TEXTURE, 0x124fa8);
    for target in ["loc_12506c"] {
        if source.contains(&format!("goto {target};")) {
            assert!(
                source.contains(&format!("{target}:")),
                "{target} is jumped to but never defined\n{source}"
            );
        }
    }
}

#[test]
fn a_merge_point_does_not_adopt_one_path_s_value() {
    let source = render(GET_BUILT_IN_TEXTURE, 0x124fa8);
    // Five paths reach the epilogue with five different values. Carrying the
    // first path's value made the function claim one of them unconditionally.
    let epilogue = source
        .lines()
        .skip_while(|line| line.contains("loc_124fd8:") == false)
        .nth(1)
        .unwrap_or_else(|| panic!("no epilogue\n{source}"));
    assert!(
        epilogue.find("return 0x").is_none(),
        "the epilogue must not return one path's constant\n{source}"
    );
    // Each comparison keeps its own length argument rather than the first's.
    for length in ["0xe", "0xd", "0xc", "9"] {
        assert!(
            source.contains(&format!("{length},")) || source.contains(&format!("{length})")),
            "comparison length {length} was lost\n{source}"
        );
    }
}
