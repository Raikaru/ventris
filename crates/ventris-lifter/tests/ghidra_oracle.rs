use std::collections::BTreeMap;

use ventris_lifter::{GameCube, Lifter};
use ventris_pcode::{
    CONST_SPACE, OTHER_SPACE, PcodeOp, RAM_SPACE, REGISTER_SPACE, UNIQUE_SPACE, Varnode,
};

const TRK_MEMSET: &str = include_str!("fixtures/gamecube/trk_memset.ghidra-capsule");
const PAIRED_SINGLE_STORE: &str =
    include_str!("fixtures/gamecube/paired_single_store.ghidra-capsule");
const STORE_MULTIPLE: &str = include_str!("fixtures/gamecube/store_multiple.ghidra-capsule");
const LOAD_MULTIPLE: &str = include_str!("fixtures/gamecube/load_multiple.ghidra-capsule");
const CONDITIONAL_BRANCH: &str =
    include_str!("fixtures/gamecube/conditional_branch.ghidra-capsule");

#[derive(Debug)]
struct OracleInstruction {
    address: u64,
    length: u32,
    operations: Vec<PcodeOp>,
}

#[derive(Debug)]
struct OracleFixture {
    metadata: BTreeMap<String, String>,
    function: String,
    language: String,
    entry: u64,
    length: u32,
    bytes: Vec<u8>,
    instructions: Vec<OracleInstruction>,
}

fn parse_integer(value: &str) -> u64 {
    if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).unwrap()
    } else {
        value.parse().unwrap()
    }
}

fn parse_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex input must contain complete bytes");
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn parse_varnode(value: &str) -> Varnode {
    let mut parts = value.split(':');
    let space = match parts.next().unwrap() {
        "const" => CONST_SPACE,
        "other" => OTHER_SPACE,
        "unique" => UNIQUE_SPACE,
        "ram" => RAM_SPACE,
        "register" => REGISTER_SPACE,
        unknown => panic!("unknown Ghidra address space {unknown}"),
    };
    let offset = parse_integer(parts.next().unwrap());
    let size = parse_integer(parts.next().unwrap()) as u32;
    assert!(parts.next().is_none(), "extra varnode fields in {value}");
    Varnode::new(space, offset, size)
}

fn parse_operation(line: &str) -> PcodeOp {
    let mut fields = line.split_whitespace();
    assert_eq!(fields.next(), Some("op"));
    let opcode = fields.next().unwrap().parse().unwrap();
    let output = fields.next().unwrap();
    if output == "void" {
        return PcodeOp::new(opcode, None, fields.map(parse_varnode).collect());
    }
    PcodeOp::new(
        opcode,
        Some(parse_varnode(output)),
        fields.map(parse_varnode).collect(),
    )
}

fn parse_fixture(text: &str) -> OracleFixture {
    assert!(text.starts_with("# ventris-ghidra-fixture 1\n"));
    let mut metadata = BTreeMap::new();
    let mut function = None;
    let mut language = None;
    let mut entry = None;
    let mut length = None;
    let mut bytes = None;
    let mut instructions = Vec::new();
    let mut lines = text.lines();

    while let Some(line) = lines.next() {
        if let Some(comment) = line.strip_prefix("# ") {
            if let Some((key, value)) = comment.split_once('=') {
                metadata.insert(key.to_owned(), value.to_owned());
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("function ") {
            function = Some(value.to_owned());
        } else if let Some(value) = line.strip_prefix("language ") {
            language = Some(value.to_owned());
        } else if let Some(value) = line.strip_prefix("entry ") {
            entry = Some(parse_integer(value));
        } else if let Some(value) = line.strip_prefix("length ") {
            length = Some(parse_integer(value) as u32);
        } else if let Some(value) = line.strip_prefix("bytes ") {
            bytes = Some(parse_hex(value));
        } else if line.starts_with("inst ") {
            let mut fields = line.split_whitespace();
            assert_eq!(fields.next(), Some("inst"));
            let address = parse_integer(fields.next().unwrap());
            let instruction_length = parse_integer(fields.next().unwrap()) as u32;
            let operation_count = parse_integer(fields.next().unwrap()) as usize;
            let operations = (0..operation_count)
                .map(|_| parse_operation(lines.next().expect("truncated Ghidra operation list")))
                .collect();
            instructions.push(OracleInstruction {
                address,
                length: instruction_length,
                operations,
            });
        }
    }

    OracleFixture {
        metadata,
        function: function.expect("fixture function"),
        language: language.expect("fixture language"),
        entry: entry.expect("fixture entry"),
        length: length.expect("fixture length"),
        bytes: bytes.expect("fixture bytes"),
        instructions,
    }
}

fn canonicalize(operations: &[PcodeOp]) -> Vec<PcodeOp> {
    fn node(value: Varnode, unique: &mut BTreeMap<u64, u64>) -> Varnode {
        if value.space != UNIQUE_SPACE {
            return value;
        }
        let next = unique.len() as u64;
        let offset = *unique.entry(value.offset).or_insert(next);
        Varnode::new(value.space, offset, value.size)
    }

    let mut unique = BTreeMap::new();
    operations
        .iter()
        .map(|operation| {
            PcodeOp::new(
                operation.opcode,
                operation.output.map(|value| node(value, &mut unique)),
                operation
                    .inputs
                    .iter()
                    .copied()
                    .map(|value| node(value, &mut unique))
                    .collect(),
            )
        })
        .collect()
}

fn assert_matches_ghidra(fixture: &OracleFixture) {
    assert_eq!(fixture.length as usize, fixture.bytes.len());
    assert!(!fixture.instructions.is_empty());

    for expected in &fixture.instructions {
        let offset = usize::try_from(expected.address - fixture.entry).unwrap();
        let input = fixture
            .bytes
            .get(offset..)
            .expect("instruction outside fixture");
        let actual = GameCube
            .lift_instruction(expected.address, input)
            .unwrap_or_else(|error| panic!("Ghidra instruction {:#x}: {error}", expected.address));
        assert_eq!(
            actual.pcode.len, expected.length,
            "{:#x} length",
            expected.address
        );
        assert_eq!(
            canonicalize(&actual.pcode.ops),
            canonicalize(&expected.operations),
            "{:#x} Ghidra p-code",
            expected.address
        );
    }
}

fn assert_pinned_provenance(
    fixture: &OracleFixture,
    entry: u64,
    length: u32,
    instruction_count: usize,
    function_bytes_sha256: &str,
) {
    assert_eq!(fixture.metadata["oracle"], "Ghidra");
    assert_eq!(fixture.metadata["ghidra_version"], "12.1.3");
    assert_eq!(
        fixture.metadata["ghidra_release_tag"],
        "Ghidra_12.1.3_build"
    );
    assert_eq!(
        fixture.metadata["ghidra_source_commit"],
        "8b4c91d4d5bd1549622bfbade0df199585b98365"
    );
    assert_eq!(
        fixture.metadata["ghidra_release_sha256"],
        "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54"
    );
    assert_eq!(fixture.metadata["architecture"], "gamecube");
    assert_eq!(
        fixture.metadata["source_image"],
        "animal_crossing_gafe01.dol"
    );
    assert_eq!(
        fixture.metadata["source_image_sha256"],
        "e3166b15b810ff20397784fc83b2eb053db5d0c2a9e22ac2ead63a645881d150"
    );
    assert_eq!(
        fixture.metadata["function_bytes_sha256"],
        function_bytes_sha256
    );
    assert_eq!(fixture.function, fixture.metadata["function"]);
    assert_eq!(fixture.language, fixture.metadata["language"]);
    assert_eq!(fixture.language, "PowerPC:BE:32:Gekko_Broadway");
    assert_eq!(fixture.entry, entry);
    assert_eq!(fixture.length, length);
    assert_eq!(fixture.instructions.len(), instruction_count);
}

#[test]
fn trk_memset_matches_pinned_ghidra_12_1_3_capsule() {
    let fixture = parse_fixture(TRK_MEMSET);
    assert_pinned_provenance(
        &fixture,
        0x8000_34e0,
        0x30,
        12,
        "56a00810c03976a0fd8a186752444e2dd27e5bc0aa5fe6da7836bb5ef8412d0d",
    );
    assert_matches_ghidra(&fixture);
}

#[test]
fn paired_single_store_matches_pinned_ghidra_capsule() {
    let fixture = parse_fixture(PAIRED_SINGLE_STORE);
    assert_pinned_provenance(
        &fixture,
        0x8000_b590,
        4,
        1,
        "e0c8d287e3ce398129d5b6c13830e48b0f6d122369065519672a8084bbafde84",
    );
    assert_eq!(fixture.instructions[0].operations.len(), 54);
    assert_matches_ghidra(&fixture);
}

#[test]
fn store_multiple_matches_pinned_ghidra_capsule() {
    let fixture = parse_fixture(STORE_MULTIPLE);
    assert_pinned_provenance(
        &fixture,
        0x800a_94e0,
        4,
        1,
        "bf6fe94c92f0f484fe89d91e84330af79617de865ca46d456fb32a671ff11dde",
    );
    assert_eq!(
        fixture.instructions[0]
            .operations
            .iter()
            .filter(|operation| operation.opcode == ventris_pcode::op::STORE)
            .count(),
        10
    );
    assert_matches_ghidra(&fixture);
}

#[test]
fn load_multiple_matches_pinned_ghidra_capsule() {
    let fixture = parse_fixture(LOAD_MULTIPLE);
    assert_pinned_provenance(
        &fixture,
        0x800a_9764,
        4,
        1,
        "adefb83ce0ff4cc2ea28e53991b5c58f37b7d2328a3411c56ef30fe10ffdba11",
    );
    assert_eq!(
        fixture.instructions[0]
            .operations
            .iter()
            .filter(|operation| operation.opcode == ventris_pcode::op::LOAD)
            .count(),
        10
    );
    assert_matches_ghidra(&fixture);
}

#[test]
fn conditional_branch_matches_pinned_ghidra_capsule() {
    let fixture = parse_fixture(CONDITIONAL_BRANCH);
    assert_pinned_provenance(
        &fixture,
        0x800a_9500,
        4,
        1,
        "710da5a3f96debc61af33f108196bde62cf02ea3336658c6205b6b05e7e2344e",
    );
    assert_eq!(
        fixture.instructions[0].operations.last().unwrap().opcode,
        ventris_pcode::op::CBRANCH
    );
    assert_matches_ghidra(&fixture);
}
