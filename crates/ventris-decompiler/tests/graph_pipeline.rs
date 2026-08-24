//! The ported graph pipeline, measured against real retail bytes.

use std::collections::{BTreeMap, BTreeSet};

use ventris_decompiler::native::NativeDecompiler;
use ventris_lifter::{Architecture, Flow, NativeFunction, lifter_for};
use ventris_target::TargetProfile;

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

fn render_via_graph(bytes: &[u8], entry: u64) -> String {
    let abi = TargetProfile::Ps2.spec().abi;
    NativeDecompiler
        .decompile_via_graph(Architecture::Ps2, &discover(bytes, entry), Some(&abi))
        .render()
}

#[test]
fn a_merged_value_is_declared_and_assigned_on_each_path() {
    // The address-ordered pass dropped a register whose value differed per
    // path, because it had no way to name the merge. The graph pipeline
    // declares it once and assigns it where each path ends.
    let source = render_via_graph(GET_BUILT_IN_TEXTURE, 0x124fa8);
    let declarations: Vec<&str> = source
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("uint") && line.contains("phi_") && line.ends_with(';'))
        .filter(|line| !line.contains('='))
        .collect();
    assert!(
        !declarations.is_empty(),
        "no merged value was declared\n{source}"
    );
    let merged = declarations.iter().any(|declaration| {
        let name = declaration
            .split_whitespace()
            .nth(1)
            .expect("a declaration names a variable")
            .trim_end_matches(';');
        source
            .lines()
            .filter(|line| line.trim().starts_with(&format!("{name} =")))
            .count()
            > 1
    });
    assert!(
        merged,
        "a declared merge must be assigned on more than one path\n{source}"
    );
}

#[test]
fn direct_calls_and_conditionals_survive_the_graph_pipeline() {
    // A branch or call target is a `ram` space address, not a `const`. Reading
    // only constants turned every conditional into an unconditional jump and
    // every direct call into an indirect one.
    let source = render_via_graph(GET_BUILT_IN_TEXTURE, 0x124fa8);
    assert!(
        source.contains("sub_1253f8()"),
        "the direct call target is named\n{source}"
    );
    assert!(
        source.lines().any(|line| line.trim().starts_with("if (")),
        "a conditional branch stays conditional\n{source}"
    );
}
