use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use ventris_decompiler::native::{
    BinaryOp, Expr, NativeDecompiler, NativeDocument, NativeParameter, NativeStatement, Type,
};
use ventris_lifter::{Flow, NativeFunction, lifter_for};
use ventris_target::TargetProfile;

struct Fixture {
    source: &'static [u8],
    bytes_hex: &'static str,
    provenance: &'static str,
}

const PS1_GAP: Fixture = Fixture {
    source: include_bytes!("../testdata/abi/ps1_o32_argument_gap.c"),
    bytes_hex: include_str!("../testdata/abi/ps1_o32_argument_gap.hex"),
    provenance: include_str!("../testdata/abi/ps1_o32_argument_gap.json"),
};

const PS1_STACK: Fixture = Fixture {
    source: include_bytes!("../testdata/abi/ps1_o32_stack_overflow.c"),
    bytes_hex: include_str!("../testdata/abi/ps1_o32_stack_overflow.hex"),
    provenance: include_str!("../testdata/abi/ps1_o32_stack_overflow.json"),
};

const PS2_GAP: Fixture = Fixture {
    source: include_bytes!("../testdata/abi/ps2_r5900_o32_argument_gap.c"),
    bytes_hex: include_str!("../testdata/abi/ps2_r5900_o32_argument_gap.hex"),
    provenance: include_str!("../testdata/abi/ps2_r5900_o32_argument_gap.json"),
};

const PPC_GAP: Fixture = Fixture {
    source: include_bytes!("../testdata/abi/ppc_eabi_argument_gap.c"),
    bytes_hex: include_str!("../testdata/abi/ppc_eabi_argument_gap.hex"),
    provenance: include_str!("../testdata/abi/ppc_eabi_argument_gap.json"),
};

const PPC_STACK: Fixture = Fixture {
    source: include_bytes!("../testdata/abi/ppc_eabi_stack_overflow.c"),
    bytes_hex: include_str!("../testdata/abi/ppc_eabi_stack_overflow.hex"),
    provenance: include_str!("../testdata/abi/ppc_eabi_stack_overflow.json"),
};

const PPC_FRAME: Fixture = Fixture {
    source: include_bytes!("../testdata/abi/ppc_eabi_frame_call.c"),
    bytes_hex: include_str!("../testdata/abi/ppc_eabi_frame_call.hex"),
    provenance: include_str!("../testdata/abi/ppc_eabi_frame_call.json"),
};

const GBA_GAP: Fixture = Fixture {
    source: include_bytes!("../testdata/abi/gba_thumb_argument_gap.c"),
    bytes_hex: include_str!("../testdata/abi/gba_thumb_argument_gap.hex"),
    provenance: include_str!("../testdata/abi/gba_thumb_argument_gap.json"),
};

const GBA_STACK: Fixture = Fixture {
    source: include_bytes!("../testdata/abi/gba_thumb_stack_overflow.c"),
    bytes_hex: include_str!("../testdata/abi/gba_thumb_stack_overflow.hex"),
    provenance: include_str!("../testdata/abi/gba_thumb_stack_overflow.json"),
};

fn parse_hex(text: &str) -> Vec<u8> {
    text.split_whitespace()
        .map(|byte| {
            u8::from_str_radix(byte, 16).unwrap_or_else(|error| {
                panic!("invalid fixture byte {byte:?}: {error}");
            })
        })
        .collect()
}

fn sidecar_string<'a>(json: &'a str, key: &str) -> &'a str {
    let needle = format!("\"{key}\"");
    let value = json
        .find(&needle)
        .and_then(|start| json[start + needle.len()..].strip_prefix(':'))
        .map(str::trim_start)
        .and_then(|value| value.strip_prefix('"'))
        .and_then(|value| value.split('"').next())
        .unwrap_or_else(|| panic!("provenance is missing string field {key:?}"));
    value
}

fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() + 8) % 64 != 0 {
        padded.push(0);
    }
    padded.extend_from_slice(&(u64::try_from(data.len()).unwrap() * 8).to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut schedule = [0u32; 64];
        for (word, bytes) in schedule[..16].iter_mut().zip(chunk.chunks_exact(4)) {
            *word = u32::from_be_bytes(bytes.try_into().expect("SHA-256 word is four bytes"));
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }

        let mut working = state;
        for index in 0..64 {
            let choose = (working[4] & working[5]) ^ ((!working[4]) & working[6]);
            let majority =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let sigma0 = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let sigma1 = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let temp1 = working[7]
                .wrapping_add(sigma1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(schedule[index]);
            let temp2 = sigma0.wrapping_add(majority);
            working[7] = working[6];
            working[6] = working[5];
            working[5] = working[4];
            working[4] = working[3].wrapping_add(temp1);
            working[3] = working[2];
            working[2] = working[1];
            working[1] = working[0];
            working[0] = temp1.wrapping_add(temp2);
        }
        for (state_word, working_word) in state.iter_mut().zip(working) {
            *state_word = state_word.wrapping_add(working_word);
        }
    }

    let mut output = String::with_capacity(64);
    for word in state {
        write!(&mut output, "{word:08x}").expect("writing to a String cannot fail");
    }
    output
}

fn assert_provenance(fixture: Fixture, label: &str) -> Vec<u8> {
    let bytes = parse_hex(fixture.bytes_hex);
    assert_eq!(
        sidecar_string(fixture.provenance, "source_sha256"),
        sha256_hex(fixture.source),
        "{label}: source hash changed without updating provenance"
    );
    assert_eq!(
        sidecar_string(fixture.provenance, "bytes_sha256"),
        sha256_hex(&bytes),
        "{label}: byte hash changed without updating provenance"
    );
    for field in [
        "compiler_identity",
        "generation_method",
        "target_triple",
        "cpu",
        "abi_flags",
        "command",
    ] {
        assert!(
            fixture.provenance.contains(&format!("\"{field}\"")),
            "{label}: provenance is missing {field}"
        );
    }
    assert!(
        !sidecar_string(fixture.provenance, "compiler_identity").starts_with("not executed"),
        "{label}: fixture is not source-backed by an executed compiler"
    );
    assert!(
        sidecar_string(fixture.provenance, "generation_method").starts_with("compiled from"),
        "{label}: generation method does not describe executed compilation"
    );
    bytes
}

fn lift(bytes: &[u8], target: TargetProfile) -> NativeFunction {
    let spec = target.spec();
    let lifter = lifter_for(spec.architecture);
    assert_eq!(lifter.architecture(), spec.architecture);
    let mut instructions = BTreeMap::new();
    let mut edges = BTreeSet::new();
    let mut calls = BTreeSet::new();
    let mut offset = 0usize;
    let mut address = 0x1000u64;
    while offset < bytes.len() {
        let instruction = lifter
            .lift_instruction(address, &bytes[offset..])
            .unwrap_or_else(|error| panic!("{target:?} lift failed at {address:#x}: {error}"));
        let next = address + instruction.bytes.len() as u64;
        if let Some(fallthrough) = instruction.flow.fallthrough() {
            edges.insert((address, fallthrough));
        }
        if let Some(branch_target) = instruction.flow.branch_target() {
            if matches!(&instruction.flow, Flow::Call { .. }) {
                calls.insert(branch_target);
            } else {
                edges.insert((address, branch_target));
            }
        }
        offset += instruction.bytes.len();
        instructions.insert(address, instruction);
        address = next;
    }
    NativeFunction {
        entry: 0x1000,
        instructions,
        edges,
        calls,
    }
}

fn decompile(bytes: &[u8], target: TargetProfile) -> NativeDocument {
    let spec = target.spec();
    let function = lift(bytes, target);
    NativeDecompiler::default().decompile_with_abi_memory_and_symbols(
        spec.architecture,
        &function,
        Some(&spec.abi),
        None,
        None,
    )
}

fn argument(index: usize) -> Expr {
    Expr::Parameter {
        name: format!("arg{index}"),
        ty: Type::Unsigned(32),
    }
}

fn add(left: Expr, right: Expr) -> Expr {
    Expr::Binary {
        op: BinaryOp::Add,
        left: Box::new(left),
        right: Box::new(right),
    }
}

fn assert_signature(document: &NativeDocument, count: usize, expected_return: Expr) {
    assert_eq!(document.name, "sub_1000");
    assert_eq!(document.return_type, Type::Unsigned(32));
    let expected_parameters = (0..count)
        .map(|index| NativeParameter {
            name: format!("arg{index}"),
            ty: Type::Unsigned(32),
        })
        .collect::<Vec<_>>();
    assert_eq!(document.parameters, expected_parameters);
    assert_eq!(document.warnings, Vec::<String>::new());
    assert_eq!(
        document.statements,
        vec![NativeStatement::Return(Some(expected_return))]
    );
    let rendered = document.render();
    let signature = (0..count)
        .map(|index| format!("uint32_t arg{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    assert!(
        rendered.contains(&format!("uint32_t sub_1000({signature})")),
        "{rendered}"
    );
}

#[test]
fn ps1_o32_argument_gap_fixture_recovers_target_abi() {
    let bytes = assert_provenance(PS1_GAP, "PS1 O32 gap");
    let document = decompile(&bytes, TargetProfile::Ps1);
    assert_signature(
        &document,
        3,
        add(argument(2), Expr::Constant { value: 1, width: 4 }),
    );
}

#[test]
fn ps1_o32_stack_overflow_fixture_keeps_register_prefix_and_stack_semantics() {
    let bytes = assert_provenance(PS1_STACK, "PS1 O32 stack overflow");
    assert!(
        PS1_STACK
            .source
            .windows(b"overflow".len())
            .any(|window| window == b"overflow")
    );
    let document = decompile(&bytes, TargetProfile::Ps1);
    assert_signature(&document, 5, add(argument(4), argument(2)));
}

#[test]
fn ps2_r5900_o32_argument_gap_fixture_recovers_target_abi() {
    let bytes = assert_provenance(PS2_GAP, "PS2 R5900 O32 gap");
    let document = decompile(&bytes, TargetProfile::Ps2);
    assert_signature(
        &document,
        3,
        add(argument(2), Expr::Constant { value: 1, width: 4 }),
    );
}

fn assert_ppc_gap(target: TargetProfile) {
    let bytes = decompile_bytes(PPC_GAP, "PPC EABI gap");
    let document = decompile(&bytes, target);
    assert_signature(&document, 3, add(argument(2), argument(0)));
}

fn assert_ppc_stack(target: TargetProfile) {
    let bytes = decompile_bytes(PPC_STACK, "PPC EABI stack overflow");
    let document = decompile(&bytes, target);
    assert_signature(&document, 9, add(argument(8), argument(0)));
}

fn decompile_bytes(fixture: Fixture, label: &str) -> Vec<u8> {
    assert_provenance(fixture, label)
}

#[test]
fn gamecube_ppc_eabi_argument_gap_fixture_recovers_target_abi() {
    assert_ppc_gap(TargetProfile::GameCube);
}

#[test]
fn gamecube_ppc_eabi_stack_fixture_recovers_ninth_argument() {
    assert_ppc_stack(TargetProfile::GameCube);
}

#[test]
fn wii_reuses_ppc_eabi_bytes_but_exercises_wii_profile() {
    assert_ppc_gap(TargetProfile::Wii);
}

#[test]
fn wii_ppc_eabi_stack_fixture_recovers_ninth_argument() {
    assert_ppc_stack(TargetProfile::Wii);
}

#[test]
fn gamecube_ppc_eabi_frame_call_removes_machine_frame_and_keeps_live_parameters() {
    let bytes = decompile_bytes(PPC_FRAME, "PPC EABI frame call");
    let document = decompile(&bytes, TargetProfile::GameCube);
    let rendered = document.render();
    assert_eq!(
        document.parameters,
        (0..4)
            .map(|index| NativeParameter {
                name: format!("arg{index}"),
                ty: Type::Unsigned(32),
            })
            .collect::<Vec<_>>(),
        "{rendered}"
    );
    assert!(!rendered.contains("r1"), "{rendered}");
    assert!(!rendered.contains("lr"), "{rendered}");
    assert!(rendered.contains("arg3(arg0, arg1, arg2);"), "{rendered}");
    assert!(!rendered.contains("farg"), "{rendered}");
    assert!(rendered.contains("return arg0;"), "{rendered}");
}

#[test]
fn gba_thumb_argument_gap_fixture_recovers_target_abi() {
    let bytes = assert_provenance(GBA_GAP, "GBA Thumb gap");
    let document = decompile(&bytes, TargetProfile::Gba);
    assert_signature(&document, 3, add(argument(2), argument(0)));
}

#[test]
fn gba_thumb_stack_fixture_recovers_fifth_argument() {
    let bytes = assert_provenance(GBA_STACK, "GBA Thumb stack overflow");
    let document = decompile(&bytes, TargetProfile::Gba);
    assert_signature(&document, 5, add(argument(4), argument(0)));
}
