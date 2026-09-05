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
        assert!(!imp.functions.iter().any(|f| f.entry == 0x2000), "{case}");
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
