use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use ventris_pcode::{PcodeOp, Varnode, op};
use ventris_sleigh::{
    AttributeValue, ELEM_SLEIGH, SlaArtifact, SleighSpec, TemplateContext, emit_constructor,
    emit_template,
};

fn installed_sla_files(root: &Path) -> Vec<PathBuf> {
    let processors = root.join("Ghidra").join("Processors");
    let mut files = Vec::new();
    for processor in fs::read_dir(processors).expect("read Ghidra processors") {
        let languages = processor
            .expect("read processor entry")
            .path()
            .join("data")
            .join("languages");
        let Ok(entries) = fs::read_dir(languages) else {
            continue;
        };
        for entry in entries {
            let path = entry.expect("read language entry").path();
            if path.extension().is_some_and(|extension| extension == "sla") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[test]
#[ignore = "requires GHIDRA_INSTALL_DIR pointing to Ghidra 12.1.3"]
fn decodes_every_installed_ghidra_12_1_3_sla() {
    let root = PathBuf::from(env::var_os("GHIDRA_INSTALL_DIR").expect("GHIDRA_INSTALL_DIR"));
    let properties = fs::read_to_string(root.join("Ghidra").join("application.properties"))
        .expect("read Ghidra application.properties");
    assert!(
        properties
            .lines()
            .any(|line| line.trim() == "application.version=12.1.3"),
        "corpus gate requires exactly Ghidra 12.1.3"
    );

    let files = installed_sla_files(&root);
    assert!(files.len() >= 100, "expected full processor corpus");

    let mut element_ids = BTreeSet::new();
    let mut value_kinds = BTreeSet::new();
    let mut decoded_bytes = 0_usize;
    let mut has_multi_section = false;
    let mut template_count = 0_usize;
    let mut operation_count = 0_usize;
    for path in &files {
        let artifact = SlaArtifact::from_path(path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert_eq!(artifact.root.id, ELEM_SLEIGH, "{}", path.display());
        let spec = SleighSpec::from_artifact(&artifact)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        for table in spec.subtables.values() {
            for constructor in &table.constructors {
                template_count += constructor.templates.len();
                operation_count += constructor
                    .templates
                    .iter()
                    .map(|template| template.operations.len())
                    .sum::<usize>();
            }
        }
        has_multi_section |= matches!(
            artifact.root.attribute(40),
            Some(AttributeValue::Unsigned(value)) if *value > 0
        );
        decoded_bytes += artifact.decoded_len;
        for element in artifact.root.descendants() {
            element_ids.insert(element.id);
            for attribute in &element.attributes {
                value_kinds.insert(match attribute.value {
                    AttributeValue::Boolean(_) => "boolean",
                    AttributeValue::Signed(_) => "signed",
                    AttributeValue::Unsigned(_) => "unsigned",
                    AttributeValue::AddressSpace(_) => "address-space",
                    AttributeValue::SpecialSpace(_) => "special-space",
                    AttributeValue::String(_) => "string",
                });
            }
        }
    }
    // Freeze the element vocabulary actually emitted by Ghidra 12.1.3. IDs 60,
    // 62, 63, 78, and 82 are defined by slaformat.cc but compiled away or unused
    // by every shipped language; their absence is not a decoder defect.
    let expected_element_ids = (1_u16..=59)
        .chain([61])
        .chain(64..=77)
        .chain([79, 80, 81, 83, 84])
        .collect::<BTreeSet<_>>();
    assert_eq!(element_ids, expected_element_ids);
    assert!(
        has_multi_section,
        "installed corpus did not exercise multi-section constructors"
    );
    assert_eq!(
        value_kinds,
        BTreeSet::from(["address-space", "boolean", "signed", "string", "unsigned",])
    );
    assert!(
        template_count > 100_000,
        "expected the full constructor-template corpus"
    );
    assert!(
        operation_count > 100_000,
        "expected the full p-code-template corpus"
    );
    println!(
        "decoded {} Ghidra 12.1.3 SLA files ({} bytes, {} element kinds, {} templates, {} operations)",
        files.len(),
        decoded_bytes,
        element_ids.len(),
        template_count,
        operation_count
    );
}

#[test]
#[ignore = "requires GHIDRA_INSTALL_DIR pointing to Ghidra 12.1.3"]
fn resolves_powerpc_instruction_decisions() {
    let root = PathBuf::from(env::var_os("GHIDRA_INSTALL_DIR").expect("GHIDRA_INSTALL_DIR"));
    let sla = root
        .join("Ghidra")
        .join("Processors")
        .join("PowerPC")
        .join("data")
        .join("languages")
        .join("ppc_32_be.sla");
    let spec = SleighSpec::from_path(sla).expect("decode PowerPC SLA");

    for (bytes, mnemonic) in [
        ([0x7c, 0x08, 0x02, 0xa6], "mfspr"),
        ([0x4e, 0x80, 0x00, 0x20], "blr"),
        ([0x28, 0x07, 0x00, 0x00], "cmpli"),
    ] {
        let constructor = spec
            .resolve_instruction(&bytes, &[0])
            .unwrap_or_else(|error| panic!("{bytes:02x?}: {error}"));
        assert_eq!(constructor.minimum_length, 4);
        let literal_print = constructor.print_pieces.join("");
        assert!(
            literal_print.contains(mnemonic),
            "{bytes:02x?}: expected {mnemonic}, got {:?}",
            constructor.print_pieces
        );
    }

    let mfspr = spec
        .resolve_instruction(&[0x7c, 0x08, 0x02, 0xa6], &[0])
        .expect("resolve mfspr");
    assert_eq!(
        emit_constructor(
            &spec,
            mfspr,
            &[0x7c, 0x08, 0x02, 0xa6],
            &[0],
            &TemplateContext::at(0x1000, 4, 3, 4),
        )
        .expect("emit mfspr p-code"),
        vec![PcodeOp::new(
            op::COPY,
            Some(Varnode::new(4, 0, 4)),
            vec![Varnode::new(4, 4128, 4)],
        )]
    );
}

#[test]
#[ignore = "requires GHIDRA_INSTALL_DIR pointing to Ghidra 12.1.3"]
fn probes_trk_memset_emission_frontier() {
    let root = PathBuf::from(env::var_os("GHIDRA_INSTALL_DIR").expect("GHIDRA_INSTALL_DIR"));
    let spec = SleighSpec::from_path(
        root.join("Ghidra")
            .join("Processors")
            .join("PowerPC")
            .join("data")
            .join("languages")
            .join("ppc_32_be.sla"),
    )
    .expect("decode PowerPC SLA");
    let bytes = [
        0x94, 0x21, 0xff, 0xf0, 0x7c, 0x08, 0x02, 0xa6, 0x90, 0x01, 0x00, 0x14, 0x93, 0xe1, 0x00,
        0x0c, 0x7c, 0x7f, 0x1b, 0x78, 0x48, 0x0a, 0x32, 0xe5, 0x80, 0x01, 0x00, 0x14, 0x7f, 0xe3,
        0xfb, 0x78, 0x83, 0xe1, 0x00, 0x0c, 0x7c, 0x08, 0x03, 0xa6, 0x38, 0x21, 0x00, 0x10, 0x4e,
        0x80, 0x00, 0x20,
    ];
    for (index, instruction) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let constructor = spec
            .resolve_instruction(instruction, &[0])
            .expect("resolve instruction");
        let result = emit_constructor(
            &spec,
            constructor,
            instruction,
            &[0],
            &TemplateContext::at(0x8000_34e0 + index as u64 * 4, 4, 3, 4),
        );
        println!(
            "{index}: {:02x?} {:?} => {result:?}",
            instruction, constructor.print_pieces
        );
        for table_id in [3808, 3899, 3902] {
            if let Ok(nested) = spec.subtables[&table_id].resolve(instruction, &[0]) {
                println!("  table {table_id}: {nested:#?}");
            }
        }
    }
}

#[test]
#[ignore = "requires GHIDRA_INSTALL_DIR pointing to Ghidra 12.1.3"]
fn emits_exact_powerpc_blr_pcode() {
    let root = PathBuf::from(env::var_os("GHIDRA_INSTALL_DIR").expect("GHIDRA_INSTALL_DIR"));
    let spec = SleighSpec::from_path(
        root.join("Ghidra")
            .join("Processors")
            .join("PowerPC")
            .join("data")
            .join("languages")
            .join("ppc_32_be.sla"),
    )
    .expect("decode PowerPC SLA");
    let constructor = spec
        .resolve_instruction(&[0x4e, 0x80, 0x00, 0x20], &[0])
        .expect("resolve blr");
    let template = constructor
        .templates
        .iter()
        .find(|template| template.section.is_none())
        .expect("blr main constructor template");
    let pcode =
        emit_template(template, &TemplateContext::at(0x1000, 4, 3, 4)).expect("emit blr p-code");

    assert_eq!(
        pcode,
        vec![PcodeOp::new(
            op::RETURN,
            None,
            vec![Varnode::new(4, 4128, 4)],
        )]
    );
}
