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

/// The locals a rendered function declares, by name.
///
/// A declaration is a line naming a C type and an identifier. Matching on "ends
/// with a semicolon" also catches `goto`, which is why the type prefix matters.
fn declared_locals(source: &str) -> Vec<String> {
    const TYPES: &[&str] = &[
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "uintptr_t",
        "bool",
        "float",
        "double",
    ];
    source
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with(';'))
        .filter_map(|line| {
            let (ty, rest) = line.split_once(' ')?;
            TYPES.contains(&ty).then_some(rest)
        })
        .map(|rest| {
            rest.split(['=', ';'])
                .next()
                .unwrap_or(rest)
                .trim()
                .to_string()
        })
        .filter(|name| !name.is_empty() && !name.contains('*'))
        .collect()
}

#[test]
fn a_merged_variable_is_declared_once_and_written_on_several_paths() {
    // The address-ordered pass dropped a register whose value differed per
    // path. Merging gives every version one name, declared at function scope
    // and assigned wherever a path computes it.
    let source = render_via_graph(GET_BUILT_IN_TEXTURE, 0x124fa8);
    let scoped: Vec<String> = source
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with(';') && !line.contains('='))
        .filter_map(|line| line.split_once(' '))
        .map(|(_, name)| name.trim_end_matches(';').to_string())
        .filter(|name| name.starts_with("v_") || name.starts_with("phi_"))
        .collect();
    assert!(!scoped.is_empty(), "no merged variable declared\n{source}");
    let written_twice = scoped.iter().any(|name| {
        source
            .lines()
            .filter(|line| line.trim().starts_with(&format!("{name} =")))
            .count()
            > 1
    });
    assert!(
        written_twice,
        "no merged variable is written on more than one path\n{source}"
    );
}

#[test]
fn direct_calls_and_conditionals_survive_the_graph_pipeline() {
    // A branch or call target is a `ram` space address, not a `const`. Reading
    // only constants turned every conditional into an unconditional jump and
    // every direct call into an indirect one.
    let source = render_via_graph(GET_BUILT_IN_TEXTURE, 0x124fa8);
    assert!(
        source.contains("sub_1253f8("),
        "the direct call target is named\n{source}"
    );
    assert!(
        source.lines().any(|line| line.trim().starts_with("if (")),
        "a conditional branch stays conditional\n{source}"
    );
}

#[test]
fn a_dereferenced_stack_value_is_declared_as_a_pointer() {
    // Type recovery runs on the graph, so a value used as an address is
    // declared as a pointer rather than as its storage width.
    let source = render_via_graph(GET_BUILT_IN_TEXTURE, 0x124fa8);
    assert!(
        source.contains("uintptr_t"),
        "no pointer type was recovered\n{source}"
    );
}

#[test]
fn recovered_calls_carry_their_arguments() {
    // Every call here is `memcmp(candidate, name, length)`. Without prototype
    // recovery a call instruction names no operands at all, and the graph path
    // rendered `sub_1253f8()`.
    let source = render_via_graph(GET_BUILT_IN_TEXTURE, 0x124fa8);
    let calls: Vec<&str> = source
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("sub_1253f8("))
        .collect();
    assert!(!calls.is_empty(), "no call was emitted\n{source}");
    assert!(
        calls.iter().all(|line| !line.contains("sub_1253f8()")),
        "a call was emitted with no arguments\n{source}"
    );
}

#[test]
fn each_local_is_declared_exactly_once() {
    // Merging puts every version of a variable under one name, and several
    // merges can land in one variable. A name declared twice does not compile.
    let source = render_via_graph(GET_BUILT_IN_TEXTURE, 0x124fa8);
    let mut declared = declared_locals(&source);
    let before = declared.len();
    assert!(before > 0, "nothing was declared\n{source}");
    declared.sort();
    declared.dedup();
    assert_eq!(
        declared.len(),
        before,
        "a local was declared more than once\n{source}"
    );
}

#[test]
fn a_merged_variable_needs_no_self_assignment() {
    // Before merging, every join emitted one assignment per incoming path even
    // when both sides named the same value.
    let source = render_via_graph(GET_BUILT_IN_TEXTURE, 0x124fa8);
    for line in source.lines().map(str::trim) {
        if let Some((left, right)) = line.split_once(" = ") {
            assert_ne!(
                left.trim(),
                right.trim_end_matches(';').trim(),
                "a variable was assigned to itself\n{source}"
            );
        }
    }
}

#[test]
fn a_pointer_valued_address_carries_no_integer_conversion() {
    // Every memory access used to render as `*(T *)(uintptr_t)(x)` even when
    // `x` was already recovered as a pointer.
    let source = render_via_graph(GET_BUILT_IN_TEXTURE, 0x124fa8);
    assert!(
        source.contains(" *)("),
        "no memory access was emitted\n{source}"
    );
    assert!(
        !source.contains("*)(uintptr_t)("),
        "a pointer-valued address still carries an integer conversion\n{source}"
    );
}
