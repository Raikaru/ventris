//! Audits the compiled register layout of every bundled language.
//!
//! ABI recovery resolves register names to varnodes. Hardcoding a per-family
//! stride is only safe while every bundled language in that family agrees, and
//! the R5900 does not: it spaces 128-bit general registers 16 bytes apart where
//! generic MIPS64 spaces 64-bit registers 8 bytes apart. This test pins the
//! layout facts the decompiler's ABI mapping depends on, so a future language
//! swap fails here instead of silently misidentifying arguments.

use ventris_lifter::{Architecture, sleigh_register_varnode};

const REGISTER_SPACE: u32 = 4;

fn offsets(architecture: Architecture, names: &[&str]) -> Vec<(u64, u32)> {
    names
        .iter()
        .map(|name| {
            let (space, offset, size) = sleigh_register_varnode(architecture, name)
                .unwrap_or_else(|| panic!("{architecture:?} has no register {name}"));
            assert_eq!(
                space, REGISTER_SPACE,
                "{architecture:?} {name} is not a register"
            );
            (offset, size)
        })
        .collect()
}

#[test]
fn ps2_general_registers_are_quadword_spaced() {
    assert_eq!(
        offsets(
            Architecture::Ps2,
            &["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3"]
        ),
        vec![
            (0, 8),
            (16, 8),
            (32, 8),
            (48, 8),
            (64, 8),
            (80, 8),
            (96, 8),
            (112, 8)
        ]
    );
}

#[test]
fn n64_general_registers_are_doubleword_spaced() {
    assert_eq!(
        offsets(Architecture::N64, &["zero", "at", "v0", "v1", "a0", "a1"]),
        vec![(0, 8), (8, 8), (16, 8), (24, 8), (32, 8), (40, 8)]
    );
}

#[test]
fn mips32_general_registers_are_word_spaced() {
    assert_eq!(
        offsets(
            Architecture::Mips32,
            &["zero", "at", "v0", "v1", "a0", "a1"]
        ),
        vec![(0, 4), (4, 4), (8, 4), (12, 4), (16, 4), (20, 4)]
    );
}

#[test]
fn ps2_float_registers_follow_the_language_not_the_family() {
    let ps2 = offsets(Architecture::Ps2, &["f0", "f1", "f12"]);
    let n64 = offsets(Architecture::N64, &["f0", "f1", "f12"]);
    assert_ne!(
        ps2, n64,
        "PS2 and N64 float layouts coincide; the audit no longer proves anything"
    );
}

#[test]
fn every_bundled_language_resolves_its_stack_pointer() {
    let cases = [
        (Architecture::X86_64, "RSP"),
        (Architecture::X86_32, "ESP"),
        (Architecture::AArch64, "sp"),
        (Architecture::Arm32, "sp"),
        (Architecture::Thumb, "sp"),
        (Architecture::Mips32, "sp"),
        (Architecture::Mips32Be, "sp"),
        (Architecture::Ps1, "sp"),
        (Architecture::Ps2, "sp"),
        (Architecture::N64, "sp"),
        (Architecture::Rv32, "sp"),
        (Architecture::Rv64, "sp"),
        (Architecture::Ppc32, "r1"),
        (Architecture::Ppc64, "r1"),
        (Architecture::GameCube, "r1"),
        (Architecture::M68k, "SP"),
        (Architecture::Sh2, "r15"),
        (Architecture::Sh4, "r15"),
        (Architecture::M6502, "SP"),
        (Architecture::Z80, "SP"),
    ];
    let mut unresolved = Vec::new();
    for (architecture, register) in cases {
        if sleigh_register_varnode(architecture, register).is_none() {
            unresolved.push(format!("{architecture:?}/{register}"));
        }
    }
    assert!(unresolved.is_empty(), "unresolved: {unresolved:?}");
}
