use super::*;
use crate::native::Mapping;
use crate::native_runtime::FlowResult;

fn result(address: u64, kind: FlowKind, target: Option<u64>, pure_jump: bool) -> FlowResult {
    FlowResult { address, length: 2, fallthrough: None,
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
