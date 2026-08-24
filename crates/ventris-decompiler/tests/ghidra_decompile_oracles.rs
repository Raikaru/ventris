use std::collections::{BTreeMap, BTreeSet};

use ventris_decompiler::native::{NativeDecompiler, NativeDocument};
use ventris_lifter::{Architecture, Flow, GameCube, Lifter, NativeFunction};
use ventris_target::TargetProfile;

const TRK_FILL_MEM: &str = include_str!("fixtures/gamecube/trk_fill_mem.ghidra-decompile");
const CONVERT_PARTIAL_ADDRESS: &str =
    include_str!("fixtures/gamecube/convert_partial_address.ghidra-decompile");
const FRAME_CALLBACK: &str = include_str!("fixtures/gamecube/frame_callback.ghidra-decompile");

struct Oracle<'a> {
    entry: u64,
    bytes: Vec<u8>,
    c: &'a str,
}

fn parse_oracle(text: &str) -> Oracle<'_> {
    assert!(text.starts_with("format ventris-ghidra-decompile-1\n"));
    assert!(text.contains("language PowerPC:BE:32:Gekko_Broadway\n"));
    let entry = text
        .lines()
        .find_map(|line| line.strip_prefix("entry "))
        .unwrap()
        .parse()
        .unwrap();
    let length = text
        .lines()
        .find_map(|line| line.strip_prefix("length "))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let hex = text
        .lines()
        .find_map(|line| line.strip_prefix("bytes "))
        .unwrap();
    let bytes = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(bytes.len(), length);
    let c = text
        .split_once("c_begin\n")
        .and_then(|(_, body)| body.strip_suffix("c_end\n"))
        .unwrap();
    Oracle { entry, bytes, c }
}

fn lift(oracle: &Oracle<'_>) -> NativeFunction {
    let mut instructions = BTreeMap::new();
    let mut edges = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let end = oracle.entry + oracle.bytes.len() as u64;
    for (index, bytes) in oracle.bytes.chunks_exact(4).enumerate() {
        let address = oracle.entry + index as u64 * 4;
        let instruction = GameCube.lift_instruction(address, bytes).unwrap();
        if let Some(fallthrough) = instruction.flow.fallthrough().filter(|next| *next < end) {
            edges.insert((address, fallthrough));
        }
        match instruction.flow {
            Flow::Jump(target) | Flow::Conditional { target, .. }
                if (oracle.entry..end).contains(&target) =>
            {
                edges.insert((address, target));
            }
            Flow::Call { target, .. } => {
                calls.insert(target);
            }
            Flow::FallThrough(_) | Flow::Return | Flow::Jump(_) | Flow::Conditional { .. } => {}
        }
        instructions.insert(address, instruction);
    }
    NativeFunction {
        entry: oracle.entry,
        instructions,
        edges,
        calls,
    }
}

fn decompile(oracle: &Oracle<'_>) -> NativeDocument {
    let abi = TargetProfile::GameCube.spec().abi;
    NativeDecompiler.decompile_with_abi_memory_and_symbols(
        Architecture::GameCube,
        &lift(oracle),
        Some(&abi),
        None,
        None,
    )
}

#[test]
fn trk_fill_mem_fixture_covers_loops_alignment_and_mixed_store_widths() {
    let oracle = parse_oracle(TRK_FILL_MEM);
    assert!(oracle.c.contains("for ("));
    assert!(oracle.c.contains("do {"));
    assert!(oracle.c.contains("byte *"));
    assert!(oracle.c.contains("uint *"));

    let document = decompile(&oracle);
    let source = document.render();
    assert_eq!(document.parameters.len(), 3, "{source}");
    assert!(source.contains("uint8_t *)(uintptr_t)"), "{source}");
    assert!(source.contains("uint32_t *)(uintptr_t)"), "{source}");
}

#[test]
fn convert_partial_address_fixture_covers_call_branch_and_pointer_arithmetic() {
    let oracle = parse_oracle(CONVERT_PARTIAL_ADDRESS);
    assert!(oracle.c.contains("func_0x800056c8("));
    assert!(oracle.c.contains("if (iVar1 == 0)"));
    assert!(oracle.c.contains("0x10000000"));

    let document = decompile(&oracle);
    let source = document.render();
    assert_eq!(document.parameters.len(), 1, "{source}");
    assert_eq!(source.matches("sub_800056c8(").count(), 1, "{source}");
    assert!(source.contains(" ? "), "{source}");
    assert!(source.contains("0x1ffffff"), "{source}");
}

#[test]
fn frame_callback_fixture_covers_paired_single_calls_globals_and_looping() {
    let oracle = parse_oracle(FRAME_CALLBACK);
    assert!(oracle.c.contains("unaff_GQR0"));
    assert!(oracle.c.contains("func_0x8000b160("));
    assert!(oracle.c.contains("func_0x800183a0("));
    assert!(oracle.c.contains("do {"));

    let document = decompile(&oracle);
    let source = document.render();
    assert_eq!(document.parameters.len(), 1, "{source}");
    assert!(source.contains("sub_8000b160("), "{source}");
    assert!(source.contains("sub_800183a0("), "{source}");
    assert!(source.contains("if ("), "{source}");
}
