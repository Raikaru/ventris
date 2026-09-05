use super::*;
use crate::native::Mapping;
use crate::native_runtime::FlowResult;

fn result(address: u64, kind: FlowKind, target: Option<u64>, pure_jump: bool) -> FlowResult {
    FlowResult { no_op: false, address, length: 2, fallthrough: None,
        targets: target.into_iter().collect(), kind, pure_jump }
}

fn image() -> NativeImport {
    NativeImport {
        mappings: vec![Mapping { vaddr: 0x1000, size: 0x2000, file_off: 0,
            flags: 4, bytes: vec![0; 0x2000] }],
        functions: vec![NativeFunction { entry: 0x1000, size: 1, name: "entry".into() }],
        ..Default::default()
    }
}

fn landing(address: u64) -> FlowResult {
    let mut flow = result(address, FlowKind::Fallthrough, None, false);
    flow.length = 4;
    flow.fallthrough = Some(address + 4);
    flow.no_op = true;
    flow
}

#[test]
fn landing_prefix_preserves_entry_extent_and_actual_jump_xref() {
    let mut imp = image();
    flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&a| match a {
        0x1000 | 0x2000 => landing(a),
        0x1004 => result(a, FlowKind::Branch, Some(0x2000), true),
        0x2004 => result(a, FlowKind::Branch, Some(0x2100), true),
        _ => result(a, FlowKind::Return, None, false),
    }).collect());
    assert_eq!(imp.functions.iter().map(|f| (f.entry, f.size)).collect::<Vec<_>>(),
               vec![(0x1000, 6), (0x2000, 6), (0x2100, 2)]);
    for (from, to) in [(0x1004, 0x2000), (0x2004, 0x2100)] {
        assert!(imp.xrefs.iter().any(|x| x.from == from && x.to == to
            && x.kind == "UNCONDITIONAL_JUMP" && x.provenance == "native-import:thunk"));
    }
    assert!(!imp.xrefs.iter().any(|x| x.kind.contains("CALL")));
}

#[test]
fn landing_prefix_requires_exact_single_no_op_and_valid_jump() {
    for case in ["missing-evidence", "wrong-address", "zero-length", "noncontiguous",
                 "multiple", "effects", "conditional", "self", "invalid-target", "truncated-jump", "weak"] {
        let mut imp = image();
        if case == "weak" {
            imp.functions[0].entry = 0x1100;
            imp.pointer_candidates.push(0x1000);
        }
        if case == "truncated-jump" {
            imp.mappings[0].size = 5;
            imp.mappings[0].bytes.truncate(5);
            imp.mappings.push(Mapping { vaddr: 0x2000, size: 2, file_off: 0,
                flags: 4, bytes: vec![0; 2] });
        }
        flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&a| {
            if a == 0x1000 {
                let mut flow = landing(a);
                if case == "missing-evidence" { flow.no_op = false; }
                if case == "wrong-address" { flow.address += 1; }
                if case == "zero-length" { flow.length = 0; }
                if case == "noncontiguous" { flow.fallthrough = Some(0x1008); }
                return flow;
            }
            if a == 0x1004 && case == "multiple" { return landing(a); }
            if a == 0x1004 || a == 0x1008 {
                return result(a, if case == "conditional" { FlowKind::CBranch } else { FlowKind::Branch },
                    Some(if case == "self" { 0x1000 } else { 0x2000 }), case != "effects");
            }
            result(a, if a == 0x2000 && case == "invalid-target" { FlowKind::Bad } else { FlowKind::Return }, None, false)
        }).collect());
        assert!(!imp.functions.iter().any(|f| f.entry == 0x2000), "{case}");
        assert!(!imp.xrefs.iter().any(|x| x.provenance == "native-import:thunk"), "{case}");
    }
}

#[test]
fn landing_jump_chain_returning_to_source_body_is_demoted() {
    let mut imp = image();
    flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&a| match a {
        0x1000 => landing(a),
        0x1004 => result(a, FlowKind::Branch, Some(0x1100), true),
        0x1100 => result(a, FlowKind::Branch, Some(0x1200), true),
        0x1200 => result(a, FlowKind::Branch, Some(0x1006), true),
        _ => result(a, FlowKind::Return, None, false),
    }).collect());
    assert_eq!(imp.functions.iter().map(|f| f.entry).collect::<Vec<_>>(), vec![0x1000]);
    assert!(!imp.xrefs.iter().any(|x| x.provenance == "native-import:thunk"));
}

#[test]
fn conditional_fallthrough_discovers_call_target() {
    let mut imp = image();
    flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&a| {
        let mut flow = match a {
            0x1000 => result(a, FlowKind::CBranch, Some(0x1100), false),
            0x1002 => result(a, FlowKind::Call, Some(0x2000), false),
            _ => result(a, FlowKind::Return, None, false),
        };
        if a == 0x1000 || a == 0x1002 { flow.fallthrough = Some(a + 2); }
        flow
    }).collect());
    assert_eq!(imp.functions.iter().map(|f| f.entry).collect::<Vec<_>>(), vec![0x1000, 0x2000]);
    assert!(imp.xrefs.iter().any(|x| x.from == 0x1002 && x.to == 0x2000 && x.kind == "UNCONDITIONAL_CALL"));
}

#[test]
fn candidate_entry_uses_flow_instead_of_opcode_prefix() {
    for (byte, kind) in [(0x90, FlowKind::Return), (0x01, FlowKind::Fallthrough), (0x01, FlowKind::Call)] {
        let mut imp = image();
        imp.mappings[0].bytes.fill(byte);
        imp.functions.push(NativeFunction { entry: 0x2002, size: 2, name: "neighbor".into() });
        imp.reloc_candidates.push(0x2000);
        flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&a| {
            let mut flow = result(a, FlowKind::Return, None, false);
            if a == 0x2000 && kind != FlowKind::Return {
                flow.kind = kind.clone();
                if kind == FlowKind::Call { flow.targets.push(0x60); }
                flow.fallthrough = Some(0x2002);
            }
            flow
        }).collect());
        let expected = if kind == FlowKind::Fallthrough { vec![0x1000, 0x2002] }
                       else { vec![0x1000, 0x2000, 0x2002] };
        assert_eq!(imp.functions.iter().map(|f| f.entry).collect::<Vec<_>>(), expected);
    }
}

#[test]
fn pure_entry_jump_preserves_thunk_and_destination() {
    let mut imp = image();
    flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&a| match a {
        0x1000 => result(a, FlowKind::Branch, Some(0x2000), true),
        0x2000 => result(a, FlowKind::Branch, Some(0x2100), true),
        _ => result(a, FlowKind::Return, None, false),
    }).collect());
    assert_eq!(imp.functions.iter().map(|f| (f.entry, f.size)).collect::<Vec<_>>(),
               vec![(0x1000, 2), (0x2000, 2), (0x2100, 2)]);
    for (from, to) in [(0x1000, 0x2000), (0x2000, 0x2100)] {
        assert!(imp.xrefs.iter().any(|x| x.from == from && x.to == to && x.kind == "UNCONDITIONAL_JUMP"));
        assert!(!imp.xrefs.iter().any(|x| x.from == from && x.kind.contains("CALL")));
    }
}

#[test]
fn conditional_interior_and_effectful_branches_are_not_thunks() {
    for case in ["conditional", "interior", "effects", "self", "outside", "known-body"] {
        let mut imp = image();
        if case == "known-body" {
            imp.functions.push(NativeFunction { entry: 0x1ff0, size: 0x40, name: "other".into() });
        }
        flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&a| {
            if a == 0x1000 && case == "interior" {
                let mut flow = result(a, FlowKind::Fallthrough, None, false);
                flow.fallthrough = Some(0x1002);
                return flow;
            }
            if a == 0x1000 || (a == 0x1002 && case == "interior") {
                return result(a, if case == "conditional" { FlowKind::CBranch } else { FlowKind::Branch },
                    Some(match case { "self" => 0x1000, "outside" => 0x4000, _ => 0x2000 }), case != "effects");
            }
            result(a, FlowKind::Return, None, false)
        }).collect());
        let expected = if case == "known-body" { vec![0x1000, 0x1ff0] } else { vec![0x1000] };
        assert_eq!(imp.functions.iter().map(|f| f.entry).collect::<Vec<_>>(), expected, "{case}");
    }
}

#[test]
fn thunk_destination_requires_corresponding_valid_flow() {
    for case in ["missing", "bad", "unimplemented", "wrong-address", "zero-length"] {
        let mut imp = image();
        flow_discover_with_provider(&mut imp, |addresses| addresses.iter().filter_map(|&a| {
            if a == 0x1000 { return Some(result(a, FlowKind::Branch, Some(0x2000), true)); }
            if case == "missing" { return None; }
            let mut flow = result(a, match case {
                "bad" => FlowKind::Bad, "unimplemented" => FlowKind::Unimpl, _ => FlowKind::Return,
            }, None, false);
            if case == "wrong-address" { flow.address += 1; }
            if case == "zero-length" { flow.length = 0; }
            Some(flow)
        }).collect());
        assert!(!imp.functions.iter().any(|f| f.entry == 0x2000), "{case}");
    }
}

#[test]
fn weak_jump_seed_does_not_establish_a_second_function() {
    let mut imp = image();
    imp.pointer_candidates.push(0x1100);
    flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&a| {
        result(a, if a == 0x1100 { FlowKind::Branch } else { FlowKind::Return },
            (a == 0x1100).then_some(0x2000), a == 0x1100)
    }).collect());
    assert!(imp.functions.iter().any(|f| f.entry == 0x1100));
    assert!(!imp.functions.iter().any(|f| f.entry == 0x2000));
}

#[test]
fn later_body_flow_demotes_a_provisional_thunk_destination() {
    let mut imp = image();
    imp.functions.push(NativeFunction { entry: 0x1ff0, size: 1, name: "other".into() });
    flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&a| {
        if a == 0x1000 { return result(a, FlowKind::Branch, Some(0x2000), true); }
        if (0x1ff0..0x2000).contains(&a) {
            let mut flow = result(a, FlowKind::Fallthrough, None, false);
            flow.fallthrough = Some(a + 2);
            return flow;
        }
        result(a, FlowKind::Return, None, false)
    }).collect());
    assert!(!imp.functions.iter().any(|f| f.entry == 0x2000));
}

#[test]
fn entry_jump_chain_returning_to_own_body_is_not_a_thunk_chain() {
    let mut imp = image();
    flow_discover_with_provider(&mut imp, |addresses| addresses.iter().map(|&a| match a {
        0x1000 => result(a, FlowKind::Branch, Some(0x1100), true),
        0x1100 => result(a, FlowKind::Branch, Some(0x1200), true),
        0x1200 => result(a, FlowKind::Branch, Some(0x1002), true),
        _ => result(a, FlowKind::Return, None, false),
    }).collect());
    assert_eq!(imp.functions.iter().map(|f| f.entry).collect::<Vec<_>>(), vec![0x1000]);
}

#[test]
fn branch_target_requires_proven_linkage_and_imported_slot() {
    let mut cfg = crate::session::RuntimeConfig::from_env();
    let Ok(console) = crate::native_runtime::find_console(&cfg) else {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    };
    cfg.console_path = Some(console);
    cfg.language_id = "PowerPC:BE:32:default".into();
    cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/PowerPC/data/languages");
    for (bound, conditional, promoted, sweep) in [
        (true, false, true, false), (false, false, false, false), (true, true, false, false),
        (true, false, true, true), (false, false, false, true), (true, true, false, true),
    ] {
        let mut bytes = vec![0; 0x50];
        bytes[..4].copy_from_slice(&[0x38, 0x60, 0, 0]); // li r3,0: caller setup, not a pure-entry jump
        bytes[4..8].copy_from_slice(&if conditional { [0x40, 0x82, 0, 0x3c] } else { [0x48, 0, 0, 0x3c] });
        bytes[8..12].copy_from_slice(&[0x4e, 0x80, 0, 0x20]);
        bytes[0x40..].copy_from_slice(&[
            0x3d, 0x60, 0, 0, 0x81, 0x6b, 0x30, 0,
            0x7d, 0x69, 3, 0xa6, 0x4e, 0x80, 4, 0x20,
        ]); // lis/lwz/mtctr/bctr through the imported slot at 0x3000
        let mut import = NativeImport {
            cfg: cfg.clone(), language: cfg.language_id.clone(), format: "elf32".into(),
            mappings: vec![
                Mapping { vaddr: 0x1000, size: bytes.len() as u64, file_off: 0, flags: 6, bytes },
                Mapping { vaddr: 0x3000, size: 4, file_off: 0, flags: 2, bytes: vec![0; 4] },
            ],
            functions: vec![NativeFunction { entry: 0x1000, name: "_entry".into(), size: 1 }],
            externals: if bound { vec![(0x3000, "libc_entry".into())] } else { Vec::new() },
            ..Default::default()
        };
        if sweep { discover_mapped(&mut import).unwrap(); } else { discover_seeded(&mut import); }
        let function = import.functions.iter().find(|function| function.entry == 0x1040);
        assert_eq!(function.is_some(), promoted, "bound={bound}, conditional={conditional}, sweep={sweep}");
        if let Some(function) = function {
            assert_eq!(function.name, "libc_entry");
            assert_eq!(function.size, 16);
            assert_eq!(import.functions.iter().find(|f| f.entry == 0x1000).unwrap().size, 8,
                "a separate linkage entry must not remain in the caller's body");
        }
    }
}

#[test]
fn pic_linkage_requires_proven_consistent_caller_context() {
    let mut cfg = crate::session::RuntimeConfig::from_env();
    let Ok(console) = crate::native_runtime::find_console(&cfg) else {
        eprintln!("SKIP: SLEIGH console not available");
        return;
    };
    cfg.console_path = Some(console);
    cfg.language_id = "PowerPC:BE:32:default".into();
    cfg.language_dir = cfg.ghidra_install.join("Ghidra/Processors/PowerPC/data/languages");
    for (known, caller) in [(true, "none"), (false, "none"), (true, "strong"), (true, "weak"), (true, "bypass")] {
        let mut bytes = vec![0; 0x120];
        let setup = [
            0x90, 0x01, 0, 0,       // stw r0,0(r1): caller effects are not thunk effects
            0x42, 0x9f, 0, 5,       // bcl to the next instruction, capturing PC
            0x7f, 0xc8, 2, 0xa6,    // mflr r30
            0x3b, 0xde, 0x1f, 0xf8, // addi r30,r30,8184: r30 = 0x3000
            0x48, 0, 0, 0x30,       // b 0x1040
        ];
        bytes[..setup.len()].copy_from_slice(&setup);
        if !known {
            bytes[8..12].copy_from_slice(&[0x7c, 0x7e, 0x1b, 0x78]); // mr r30,r3
        }
        bytes[0x40..0x4c].copy_from_slice(&[
            0x81, 0x7e, 0, 0x48, 0x7d, 0x69, 3, 0xa6, 0x4e, 0x80, 4, 0x20,
        ]); // lwz r11,72(r30); mtctr r11; bctr
        let mut functions = vec![NativeFunction { entry: 0x1000, name: "_entry".into(), size: 1 }];
        if caller != "none" {
            bytes[0x100..0x114].copy_from_slice(&setup);
            bytes[0x10c..0x110].copy_from_slice(&[0x3b, 0xde, 0x3e, 0xf8]); // r30 = 0x5000
            bytes[0x110..0x114].copy_from_slice(&[0x4b, 0xff, 0xff, 0x30]); // b 0x1040
            if caller == "bypass" {
                bytes[0x100..0x108].copy_from_slice(&[
                    0x7c, 0x7e, 0x1b, 0x78, // unknown r30
                    0x4b, 0xff, 0xff, 0x08, // enter the first caller at 0x100c, skipping its PC setup
                ]);
            }
            if caller != "weak" {
                functions.push(NativeFunction { entry: 0x1100, name: "other".into(), size: 1 });
            }
        }
        let mut import = NativeImport {
            cfg: cfg.clone(), language: cfg.language_id.clone(), format: "elf32".into(),
            mappings: vec![
                Mapping { vaddr: 0x1000, size: bytes.len() as u64, file_off: 0, flags: 6, bytes },
                Mapping { vaddr: 0x3000, size: 0x100, file_off: 0, flags: 2, bytes: vec![0; 0x100] },
                Mapping { vaddr: 0x5000, size: 0x100, file_off: 0, flags: 2, bytes: vec![0; 0x100] },
            ],
            functions,
            pointer_candidates: if caller == "weak" { vec![0x1100] } else { Vec::new() },
            externals: vec![(0x3048, "libc_entry".into()), (0x5048, "different_entry".into())],
            ..Default::default()
        };
        discover_seeded(&mut import);
        let function = import.functions.iter().find(|function| function.entry == 0x1040);
        assert_eq!(function.is_some(), known && caller == "none",
            "known={known}, caller={caller}");
        if let Some(function) = function {
            assert_eq!(function.name, "libc_entry");
            assert_eq!(function.size, 12);
        }
    }
}
