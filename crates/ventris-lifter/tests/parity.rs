use ventris_lifter::{
    AArch64, Architecture, Arm32, Flow, Lifter, M68k, Mips32, Mips32Be, Ppc32, Ppc64, Ps1, Rv32,
    Rv64, Sh2, Sh4, Spu, Thumb, M6502, N64, X86_32, X86_64, Z80,
};
use ventris_pcode::op;

struct Fixture {
    name: &'static str,
    architecture: Architecture,
    address: u64,
    bytes: &'static [u8],
    length: u32,
    flow: Flow,
    opcodes: &'static [i32],
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "x86_64 add immediate",
        architecture: Architecture::X86_64,
        address: 0x1000,
        bytes: &[0x48, 0x83, 0xc0, 0x08],
        length: 4,
        flow: Flow::FallThrough(0x1004),
        opcodes: &[
            op::INT_CARRY,
            op::INT_SCARRY,
            op::INT_ADD,
            op::INT_SLESS,
            op::INT_EQUAL,
            op::INT_AND,
            op::POPCOUNT,
            op::INT_AND,
            op::INT_EQUAL,
        ],
    },
    Fixture {
        name: "aarch64 add immediate",
        architecture: Architecture::AArch64,
        address: 0x2000,
        bytes: &0x9100_0400u32.to_le_bytes(),
        length: 4,
        flow: Flow::FallThrough(0x2004),
        opcodes: &[
            op::COPY,
            op::INT_CARRY,
            op::INT_SCARRY,
            op::INT_ADD,
            op::INT_SLESS,
            op::INT_EQUAL,
            op::COPY,
        ],
    },
    Fixture {
        name: "mips32 add immediate",
        architecture: Architecture::Mips32,
        address: 0x3000,
        bytes: &0x2508_0001u32.to_le_bytes(),
        length: 4,
        flow: Flow::FallThrough(0x3004),
        opcodes: &[op::INT_ADD],
    },
    Fixture {
        name: "arm32 branch",
        architecture: Architecture::Arm32,
        address: 0x4000,
        bytes: &0xea00_0000u32.to_le_bytes(),
        length: 4,
        flow: Flow::Jump(0x4008),
        opcodes: &[op::BRANCH],
    },
    Fixture {
        name: "rv64 add immediate",
        architecture: Architecture::Rv64,
        address: 0x5000,
        bytes: &0x0010_8093u32.to_le_bytes(),
        length: 4,
        flow: Flow::FallThrough(0x5004),
        opcodes: &[op::COPY, op::INT_ADD],
    },
    Fixture {
        name: "ppc32 add immediate",
        architecture: Architecture::Ppc32,
        address: 0x6000,
        bytes: &0x3863_0001u32.to_be_bytes(),
        length: 4,
        flow: Flow::FallThrough(0x6004),
        opcodes: &[op::INT_ADD],
    },
    Fixture {
        name: "ppc64 add immediate",
        architecture: Architecture::Ppc64,
        address: 0x6800,
        bytes: &0x3863_0001u32.to_be_bytes(),
        length: 4,
        flow: Flow::FallThrough(0x6804),
        opcodes: &[op::INT_ADD],
    },
    Fixture {
        name: "ps1 add immediate",
        architecture: Architecture::Ps1,
        address: 0x7000,
        bytes: &0x2402_002au32.to_le_bytes(),
        length: 4,
        flow: Flow::FallThrough(0x7004),
        opcodes: &[op::INT_ADD],
    },
    Fixture {
        name: "n64 add immediate",
        architecture: Architecture::N64,
        address: 0x8000,
        bytes: &0x6402_002au32.to_be_bytes(),
        length: 4,
        flow: Flow::FallThrough(0x8004),
        opcodes: &[op::INT_ADD],
    },
    Fixture {
        name: "gamecube add immediate",
        architecture: Architecture::GameCube,
        address: 0x9000,
        bytes: &0x3860_0001u32.to_be_bytes(),
        length: 4,
        flow: Flow::FallThrough(0x9004),
        opcodes: &[op::INT_ADD],
    },
    Fixture {
        name: "x86_32 immediate",
        architecture: Architecture::X86_32,
        address: 0xa000,
        bytes: &[0xb8, 0x2a, 0, 0, 0],
        length: 5,
        flow: Flow::FallThrough(0xa005),
        opcodes: &[op::COPY],
    },
    Fixture {
        name: "thumb immediate",
        architecture: Architecture::Thumb,
        address: 0xb000,
        bytes: &0x202au16.to_le_bytes(),
        length: 2,
        flow: Flow::FallThrough(0xb002),
        opcodes: &[op::COPY],
    },
    Fixture {
        name: "mips32 big-endian immediate",
        architecture: Architecture::Mips32Be,
        address: 0xc000,
        bytes: &0x2508_0001u32.to_be_bytes(),
        length: 4,
        flow: Flow::FallThrough(0xc004),
        opcodes: &[op::INT_ADD],
    },
    Fixture {
        name: "rv32 immediate",
        architecture: Architecture::Rv32,
        address: 0xd000,
        bytes: &0x02a0_0513u32.to_le_bytes(),
        length: 4,
        flow: Flow::FallThrough(0xd004),
        opcodes: &[op::COPY, op::INT_ADD],
    },
    Fixture {
        name: "m68k immediate",
        architecture: Architecture::M68k,
        address: 0xe000,
        bytes: &0x702au16.to_be_bytes(),
        length: 2,
        flow: Flow::FallThrough(0xe002),
        opcodes: &[op::COPY],
    },
    Fixture {
        name: "sh2 immediate",
        architecture: Architecture::Sh2,
        address: 0xf000,
        bytes: &0xe02au16.to_be_bytes(),
        length: 2,
        flow: Flow::FallThrough(0xf002),
        opcodes: &[op::COPY],
    },
    Fixture {
        name: "sh4 immediate",
        architecture: Architecture::Sh4,
        address: 0x10000,
        bytes: &0xe02au16.to_le_bytes(),
        length: 2,
        flow: Flow::FallThrough(0x10002),
        opcodes: &[op::COPY],
    },
    Fixture {
        name: "6502 immediate",
        architecture: Architecture::M6502,
        address: 0x11000,
        bytes: &[0xa9, 0x2a],
        length: 2,
        flow: Flow::FallThrough(0x11002),
        opcodes: &[op::COPY],
    },
    Fixture {
        name: "z80 immediate",
        architecture: Architecture::Z80,
        address: 0x12000,
        bytes: &[0x3e, 0x2a],
        length: 2,
        flow: Flow::FallThrough(0x12002),
        opcodes: &[op::COPY],
    },
    Fixture {
        name: "spu stop",
        architecture: Architecture::Spu,
        address: 0x13000,
        bytes: &[0x00, 0x00, 0x00, 0x00],
        length: 4,
        flow: Flow::Return,
        opcodes: &[op::RETURN],
    },
];

#[test]
fn new_architectures_reject_unknown_opcodes() {
    let ppc = Ppc64
        .lift_instruction(0x14000, &[0xff, 0xff, 0xff, 0xff])
        .unwrap_err();
    assert!(matches!(
        ppc,
        ventris_lifter::LiftError::Unsupported {
            architecture: Architecture::Ppc64,
            ..
        }
    ));

    let spu = Spu
        .lift_instruction(0x14004, &[0xff, 0xff, 0xff, 0xff])
        .unwrap_err();
    assert!(matches!(
        spu,
        ventris_lifter::LiftError::Unsupported {
            architecture: Architecture::Spu,
            ..
        }
    ));
}

fn lift(fixture: &Fixture) -> ventris_lifter::LiftedInstruction {
    match fixture.architecture {
        Architecture::X86_64 => X86_64.lift_instruction(fixture.address, fixture.bytes),
        Architecture::X86_32 => X86_32.lift_instruction(fixture.address, fixture.bytes),
        Architecture::AArch64 => AArch64.lift_instruction(fixture.address, fixture.bytes),
        Architecture::Arm32 => Arm32.lift_instruction(fixture.address, fixture.bytes),
        Architecture::Thumb => Thumb.lift_instruction(fixture.address, fixture.bytes),
        Architecture::Mips32 | Architecture::Ps1 => {
            Mips32.lift_instruction(fixture.address, fixture.bytes)
        }
        Architecture::Mips32Be => Mips32Be.lift_instruction(fixture.address, fixture.bytes),
        Architecture::N64 => N64.lift_instruction(fixture.address, fixture.bytes),
        Architecture::Rv64 => Rv64.lift_instruction(fixture.address, fixture.bytes),
        Architecture::Rv32 => Rv32.lift_instruction(fixture.address, fixture.bytes),
        Architecture::Ppc32 => Ppc32.lift_instruction(fixture.address, fixture.bytes),
        Architecture::Ppc64 => Ppc64.lift_instruction(fixture.address, fixture.bytes),
        Architecture::GameCube => Ppc32.lift_instruction(fixture.address, fixture.bytes),
        Architecture::M68k => M68k.lift_instruction(fixture.address, fixture.bytes),
        Architecture::Sh2 => Sh2.lift_instruction(fixture.address, fixture.bytes),
        Architecture::Sh4 => Sh4.lift_instruction(fixture.address, fixture.bytes),
        Architecture::M6502 => M6502.lift_instruction(fixture.address, fixture.bytes),
        Architecture::Z80 => Z80.lift_instruction(fixture.address, fixture.bytes),
        Architecture::Spu => Spu.lift_instruction(fixture.address, fixture.bytes),
    }
    .unwrap_or_else(|error| panic!("{}: {error}", fixture.name))
}

#[test]
fn every_advertised_architecture_has_one_instruction_fixture() {
    for architecture in Architecture::ALL {
        assert_eq!(
            FIXTURES
                .iter()
                .filter(|fixture| fixture.architecture == architecture)
                .count(),
            1,
            "{architecture:?} must have exactly one checked fixture"
        );
    }
}

#[test]
fn checked_in_instruction_corpus_is_stable() {
    for fixture in FIXTURES {
        let instruction = lift(fixture);
        assert_eq!(
            instruction.pcode.len, fixture.length,
            "{} length",
            fixture.name
        );
        assert_eq!(instruction.flow, fixture.flow, "{} flow", fixture.name);
        let actual: Vec<_> = instruction
            .pcode
            .ops
            .iter()
            .map(|operation| operation.opcode)
            .collect();
        assert_eq!(actual, fixture.opcodes, "{} p-code", fixture.name);
    }
}

#[test]
fn control_flow_fixture_keeps_calls_out_of_the_function_body() {
    let x86 = X86_64
        .discover(
            &ventris_format::Image {
                len: 7,
                format: ventris_format::Format::Pe(ventris_format::PeFacts {
                    machine: 0x8664,
                    plus: true,
                    image_base: 0,
                }),
                segments: vec![ventris_format::Segment {
                    name: Some(".text".into()),
                    addr: 0x1000,
                    size: 7,
                    file_off: 0,
                    file_size: 7,
                    perms: ventris_format::Perms {
                        read: Some(true),
                        write: Some(false),
                        exec: Some(true),
                    },
                }],
                regions: Vec::new(),
                entry: Some(0x1000),
                symbol_count: 0,
            },
            &[0xe8, 0xfb, 0x00, 0x00, 0x00, 0xc3, 0x90],
            0x1000,
            8,
        )
        .unwrap();
    assert_eq!(x86.calls, [0x1100].into_iter().collect());
    assert_eq!(x86.instruction_count(), 2);
}
