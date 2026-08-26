use std::fmt::Write;

use crate::{GameType, RecoveredFunction, StructCandidate};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SourceParameter {
    pub name: String,
    pub c_type: String,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SourceSignature {
    pub name: String,
    pub return_type: String,
    pub parameters: Vec<SourceParameter>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SourceField {
    pub offset: i64,
    pub name: String,
    pub c_type: String,
    pub declarator_suffix: String,
    pub width: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SourceStruct {
    pub name: String,
    pub parameter_name: Option<String>,
    pub fields: Vec<SourceField>,
    pub unresolved: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SourceReconstruction {
    pub signature: SourceSignature,
    pub structs: Vec<SourceStruct>,
    pub body: String,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ReconstructionError {
    EmptyBody,
}

impl std::fmt::Display for ReconstructionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyBody => {
                f.write_str("source reconstruction requires a non-empty function body")
            }
        }
    }
}

impl std::error::Error for ReconstructionError {}

impl SourceReconstruction {
    /// Combine a native decompiler body with the game ABI and field facts.
    /// The body is intentionally supplied by the caller: this layer never
    /// invents executable semantics from a type recovery report.
    pub fn from_report(
        report: &RecoveredFunction,
        body: impl Into<String>,
    ) -> Result<Self, ReconstructionError> {
        let body = body.into();
        let signature = source_signature(report, &body);
        Self::from_signature(report, body, signature)
    }

    /// Reconstruct source while preserving an analyzer-owned structured
    /// signature. The canonical pipeline uses this path instead of reparsing
    /// rendered C to rediscover ABI facts.
    pub fn from_signature(
        report: &RecoveredFunction,
        body: impl Into<String>,
        mut signature: SourceSignature,
    ) -> Result<Self, ReconstructionError> {
        let mut body = body.into();
        if body.trim().is_empty() {
            return Err(ReconstructionError::EmptyBody);
        }
        if let Some(name) = report
            .name
            .as_deref()
            .map(c_identifier)
            .filter(|name| !name.is_empty())
        {
            signature.name = name;
        }
        let mut diagnostics = Vec::new();
        let structs = report
            .structs
            .iter()
            .enumerate()
            .map(|(index, candidate)| source_struct(candidate, index, &mut diagnostics))
            .collect::<Vec<_>>();
        rewrite_recovered_field_accesses(&mut signature, &structs, &mut body);
        prune_unused_parameters(&mut signature, &body);
        Ok(Self {
            signature,
            structs,
            body,
            diagnostics,
        })
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("#include <stdbool.h>\n#include <stdint.h>\n\n");
        for structure in &self.structs {
            writeln!(out, "typedef struct {} {{", structure.name).unwrap();
            // The layout starts where the first field does, not at zero. A
            // structure reached through a global-pointer register has negative
            // offsets, and measuring padding from zero reported every one of its
            // fields as overlapping a predecessor it does not have.
            let mut cursor = structure
                .fields
                .first()
                .map(|field| field.offset)
                .unwrap_or(0);
            for field in &structure.fields {
                if field.offset > cursor {
                    let padding = field.offset - cursor;
                    // Named the way the fields are, so a negative offset reads
                    // as one rather than as its 64-bit two's complement.
                    let label = field_name_for_offset(cursor);
                    let label = label.strip_prefix("field_").unwrap_or(&label);
                    writeln!(out, "    uint8_t _pad_{label}[{padding}];").unwrap();
                    cursor = field.offset;
                }
                if field.offset < cursor {
                    writeln!(
                        out,
                        "    /* overlapping field at offset {:#x}; retained as observed */",
                        field.offset
                    )
                    .unwrap();
                }
                writeln!(
                    out,
                    "    {} {}{};",
                    field.c_type, field.name, field.declarator_suffix
                )
                .unwrap();
                cursor = cursor.max(field.offset.saturating_add(i64::from(field.width)));
            }
            writeln!(out, "}} {};\n", structure.name).unwrap();
            for unresolved in &structure.unresolved {
                writeln!(out, "/* unresolved: {unresolved} */").unwrap();
            }
        }
        if !self.diagnostics.is_empty() {
            out.push_str("/* reconstruction diagnostics:\n");
            for diagnostic in &self.diagnostics {
                writeln!(out, " * {diagnostic}").unwrap();
            }
            out.push_str(" */\n");
        }

        let parameters = if self.signature.parameters.is_empty() {
            "void".to_owned()
        } else {
            self.signature
                .parameters
                .iter()
                .map(|parameter| format!("{} {}", parameter.c_type, parameter.name))
                .collect::<Vec<_>>()
                .join(", ")
        };
        writeln!(
            out,
            "{} {}({parameters})",
            self.signature.return_type, self.signature.name
        )
        .unwrap();

        if let Some(body) = function_body(&self.body) {
            out.push_str(body);
            if !body.ends_with('\n') {
                out.push('\n');
            }
        } else {
            out.push_str("{\n");
            for line in self.body.trim().lines() {
                writeln!(out, "    {line}").unwrap();
            }
            out.push_str("}\n");
        }
        out
    }
}

fn function_body(source: &str) -> Option<&str> {
    let start = source.find('{')?;
    let end = source.rfind('}')?;
    (start <= end).then(|| source[start..=end].trim())
}

fn source_signature(report: &RecoveredFunction, body: &str) -> SourceSignature {
    let name = report
        .name
        .as_deref()
        .map(c_identifier)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| format!("sub_{:x}", report.entry));
    let return_type = source_return_type(body).unwrap_or_else(|| {
        report
            .abi
            .return_register(crate::AbiRegisterClass::Integer, 0)
            .map(|_| "uintptr_t".to_owned())
            .unwrap_or_else(|| "void".to_owned())
    });
    let parameters = source_parameters(body).unwrap_or_else(|| {
        let mut parameters = Vec::new();
        if let Some(names) = report.abi.arguments.integer.names {
            for name in names {
                parameters.push(SourceParameter {
                    name: c_identifier(name),
                    c_type: "uintptr_t".into(),
                });
            }
        }
        if let Some(names) = report.abi.arguments.floating.names {
            for name in names {
                parameters.push(SourceParameter {
                    name: c_identifier(name),
                    c_type: "float".into(),
                });
            }
        }
        parameters
    });
    SourceSignature {
        name,
        return_type,
        parameters,
    }
}

fn source_return_type(source: &str) -> Option<String> {
    let signature = source.lines().find(|line| {
        line.contains('(') && !line.trim_start().starts_with('#') && !line.trim_end().ends_with(';')
    })?;
    let open = signature.find('(')?;
    let prefix = signature[..open].trim();
    let name_start = prefix.rfind(char::is_whitespace)?;
    let return_type = prefix[..name_start].trim();
    (!return_type.is_empty()).then(|| return_type.to_owned())
}

fn source_parameters(source: &str) -> Option<Vec<SourceParameter>> {
    let signature = source.lines().find(|line| {
        line.contains('(') && !line.trim_start().starts_with('#') && !line.trim_end().ends_with(';')
    })?;
    let open = signature.find('(')?;
    let close = signature[open + 1..].find(')')? + open + 1;
    let parameters = signature[open + 1..close].trim();
    if parameters.is_empty() || parameters == "void" {
        return None;
    }
    parameters
        .split(',')
        .map(|parameter| {
            let parameter = parameter.trim();
            let split = parameter.rfind(char::is_whitespace)?;
            let c_type = parameter[..split].trim();
            let name = parameter[split..].trim();
            (!c_type.is_empty() && !name.is_empty()).then(|| SourceParameter {
                name: name.to_owned(),
                c_type: c_type.to_owned(),
            })
        })
        .collect()
}
fn prune_unused_parameters(signature: &mut SourceSignature, source: &str) {
    let body = function_body(source).unwrap_or(source);
    while signature
        .parameters
        .last()
        .is_some_and(|parameter| !identifier_is_used(body, &parameter.name))
    {
        signature.parameters.pop();
    }
}

fn preserve_residual_byte_arithmetic(source: &str, name: &str) -> String {
    let mut output = String::with_capacity(source.len() + name.len());
    let mut cursor = 0;
    for (index, _) in source.match_indices(name) {
        let before = source[..index].chars().next_back();
        let after = source[index + name.len()..].chars().next();
        if before.is_some_and(|character| character == '_' || character.is_ascii_alphanumeric())
            || after.is_some_and(|character| character == '_' || character.is_ascii_alphanumeric())
        {
            continue;
        }
        let prefix_operator = source[..index]
            .chars()
            .rev()
            .find(|character| !character.is_whitespace())
            .is_some_and(|character| matches!(character, '+' | '-'));
        let suffix = source[index + name.len()..].trim_start();
        let suffix_operator = !suffix.starts_with("->")
            && suffix
                .chars()
                .next()
                .is_some_and(|character| matches!(character, '+' | '-'));
        if !prefix_operator && !suffix_operator {
            continue;
        }
        output.push_str(&source[cursor..index]);
        output.push_str("(uintptr_t)");
        output.push_str(name);
        cursor = index + name.len();
    }
    output.push_str(&source[cursor..]);
    output
}

fn identifier_is_used(source: &str, name: &str) -> bool {
    source.match_indices(name).any(|(index, _)| {
        let before = source[..index].chars().next_back();
        let after = source[index + name.len()..].chars().next();
        !before.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
            && !after.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    })
}

fn replace_identifier(source: &str, old: &str, new: &str) -> String {
    let mut output = String::with_capacity(source.len() + new.len().saturating_sub(old.len()));
    let mut cursor = 0;
    for (index, _) in source.match_indices(old) {
        let before = source[..index].chars().next_back();
        let after = source[index + old.len()..].chars().next();
        if before.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
            || after.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        {
            continue;
        }
        output.push_str(&source[cursor..index]);
        output.push_str(new);
        cursor = index + old.len();
    }
    output.push_str(&source[cursor..]);
    output
}

/// A unique C identifier for a field at a byte offset.
///
/// Clamping the offset to zero named every field below the base `field_0`, so a
/// structure recovered from negative offsets declared the same member twice and
/// the rendered C did not compile.
fn field_name_for_offset(offset: i64) -> String {
    if offset < 0 {
        format!("field_neg_{:x}", offset.unsigned_abs())
    } else {
        format!("field_{offset:x}")
    }
}

/// How the graph emitter spells a field it recovered without a name for it.
///
/// It names the member after the offset, which is all it knows. This pass holds
/// the nominal name, so it has to recognise that spelling to replace it.
fn recovered_member(parameter: &str, offset: i64) -> String {
    format!("{parameter}->{}", field_name_for_offset(offset))
}

fn rewrite_recovered_field_accesses(
    signature: &mut SourceSignature,
    structs: &[SourceStruct],
    body: &mut String,
) {
    for structure in structs {
        let Some((parameter_index, match_count)) = signature
            .parameters
            .iter()
            .enumerate()
            .map(|(index, parameter)| {
                let count = structure
                    .fields
                    .iter()
                    .filter(|field| {
                        // Either spelling counts. The address-ordered emitter
                        // writes the access as arithmetic under a cast; the
                        // graph emitter already recovered the field, and only
                        // this pass knows the declared member type, so the
                        // access still has to be normalised here.
                        body.contains(&format!(
                            "({} + 0x{:x})",
                            parameter.name,
                            field.offset.max(0)
                        )) || body.contains(&format!("{}->{}", parameter.name, field.name))
                            || body
                                .contains(&recovered_member(&parameter.name, field.offset.max(0)))
                    })
                    .count();
                (index, count)
            })
            .max_by_key(|(_, count)| *count)
        else {
            continue;
        };
        if match_count == 0 {
            continue;
        }
        let parameter = signature.parameters[parameter_index].name.clone();
        signature.parameters[parameter_index].c_type = format!("{} *", structure.name);
        for field in &structure.fields {
            let address = format!("({parameter} + 0x{:x})", field.offset.max(0));
            let member = if field.declarator_suffix.is_empty() {
                format!("({parameter}->{})", field.name)
            } else {
                format!("({parameter}->{}[0])", field.name)
            };
            for cast in field_cast_types(field.width) {
                for qualifier in ["", "volatile "] {
                    let access = format!("*({qualifier}{cast} *)(uintptr_t){address}");
                    *body = body.replace(&access, &member);
                }
            }
            // The graph emitter has already recovered the access and named the
            // member after its offset, because only this pass knows what the
            // source called it. Rewriting that spelling is what lets a nominal
            // field name reach the output at all: without it the accesses stayed
            // `p->field_4a4`, the structure never matched a parameter, and the
            // declared type fell back to `uintptr_t`.
            let recovered = recovered_member(&parameter, field.offset);
            *body = body.replace(&format!("({recovered}[0])"), &member);
            *body = body.replace(&format!("({recovered})"), &member);
            *body = replace_bare_member(body, &recovered, &member);
            strip_redundant_field_casts(body, field, &member);
            // A member declared as a byte array cannot be read or assigned
            // whole, so the recovered access needs its index. Without this the
            // graph emitter's `p->field_4b8 = v` did not compile.
            if !field.declarator_suffix.is_empty() {
                let bare = format!("{parameter}->{}", field.name);
                *body = replace_bare_member(body, &bare, &member);
            }
        }
        *body = preserve_residual_byte_arithmetic(body, &parameter);
        let desired_name = structure
            .parameter_name
            .as_deref()
            .map(c_identifier)
            .filter(|name| !name.is_empty() && name != &parameter)
            .filter(|name| {
                !signature
                    .parameters
                    .iter()
                    .enumerate()
                    .any(|(index, candidate)| index != parameter_index && candidate.name == *name)
            });
        let final_parameter = if let Some(desired_name) = desired_name {
            *body = replace_identifier(body, &parameter, &desired_name);
            signature.parameters[parameter_index].name = desired_name.clone();
            desired_name
        } else {
            parameter
        };
        for field in &structure.fields {
            let member = if field.declarator_suffix.is_empty() {
                format!("({final_parameter}->{})", field.name)
            } else {
                format!("({final_parameter}->{}[0])", field.name)
            };
            strip_redundant_field_casts(body, field, &member);
        }
    }
}
/// Replaces a member access that is not already indexed or parenthesised.
///
/// The same field name is a prefix of nothing else, but the already-rewritten
/// form contains the bare form, so a plain `replace` would rewrite its own
/// output.
fn replace_bare_member(body: &str, bare: &str, member: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(at) = rest.find(bare) {
        let (before, after) = rest.split_at(at);
        out.push_str(before);
        let tail = &after[bare.len()..];
        let already_indexed = tail.starts_with('[');
        let inside_rewrite = before.ends_with('(') && tail.starts_with(')');
        let longer_name = tail
            .chars()
            .next()
            .is_some_and(|next| next.is_alphanumeric() || next == '_');
        if already_indexed || inside_rewrite || longer_name {
            out.push_str(bare);
        } else {
            out.push_str(member);
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

fn strip_redundant_field_casts(body: &mut String, field: &SourceField, member: &str) {
    *body = body.replace(&format!("({})({member})", field.c_type), member);
    if field.width == 1 {
        for cast in ["uint32_t", "int32_t", "uint64_t", "int64_t"] {
            *body = body.replace(&format!("({cast})({member})"), member);
        }
    }
    if field.width == 4 && field.declarator_suffix.is_empty() {
        for wide in ["int64_t", "uint64_t"] {
            *body = body.replace(&format!("({wide})({member})"), member);
        }
        for narrow in ["uint32_t", "int32_t"] {
            *body = body.replace(&format!("({narrow})({member} * "), &format!("({member} * "));
        }
    }
}

fn field_cast_types(width: u32) -> &'static [&'static str] {
    match width {
        1 => &["bool", "uint8_t", "int8_t"],
        2 => &["uint16_t", "int16_t"],
        4 => &["uint32_t", "int32_t", "float"],
        8 => &["uint64_t", "int64_t", "double"],
        _ => &[],
    }
}

fn source_struct(
    candidate: &StructCandidate,
    index: usize,
    diagnostics: &mut Vec<String>,
) -> SourceStruct {
    let name = candidate
        .name
        .as_deref()
        .map(c_identifier)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| format!("RecoveredStruct{index}"));
    let mut unresolved = Vec::new();
    let fields = candidate
        .fields
        .iter()
        .map(|field| {
            let field_name = field
                .name
                .as_deref()
                .map(c_identifier)
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| field_name_for_offset(field.offset));
            let (c_type, declarator_suffix) = c_declarator(&field.ty, &mut unresolved);
            SourceField {
                offset: field.offset,
                name: field_name,
                c_type,
                declarator_suffix,
                width: field.width.max(1),
            }
        })
        .collect::<Vec<_>>();
    if !unresolved.is_empty() {
        diagnostics.push(format!("{} contains unresolved type facts", name));
    }
    SourceStruct {
        parameter_name: candidate
            .parameter_name
            .as_deref()
            .map(c_identifier)
            .filter(|name| !name.is_empty()),
        name,
        fields,
        unresolved,
    }
}

fn c_declarator(ty: &GameType, unresolved: &mut Vec<String>) -> (String, String) {
    match ty {
        GameType::UnknownBytes { width } => ("uint8_t".into(), format!("[{width}]")),
        GameType::Array { element, count, .. } => {
            let (c_type, suffix) = c_declarator(element, unresolved);
            let count = count.map_or_else(String::new, |value| value.to_string());
            (c_type, format!("{suffix}[{count}]"))
        }
        _ => (c_type(ty, unresolved), String::new()),
    }
}

fn c_type(ty: &GameType, unresolved: &mut Vec<String>) -> String {
    match ty {
        GameType::UnknownBytes { .. } => "uint8_t".into(),
        GameType::Primitive { name, bits, signed } => primitive_type(name, *bits, *signed),
        GameType::Nominal { name, .. } => c_identifier(name),
        GameType::Pointer { to, .. } => format!("{} *", c_type(to, unresolved)),
        GameType::Array { element, .. } => c_type(element, unresolved),
        GameType::Enum { name, .. } => c_identifier(name),
        GameType::FunctionPointer { target, .. } => {
            unresolved.push(format!(
                "function pointer target {:?} is not a complete prototype",
                target
            ));
            "uintptr_t".into()
        }
        GameType::Vector { lane, lanes } => {
            format!("struct {{ {} lane[{lanes}]; }}", c_type(lane, unresolved))
        }
        GameType::Handle { name, bits } => {
            unresolved.push(format!(
                "handle {name} retains an opaque {bits}-bit representation"
            ));
            "uintptr_t".into()
        }
    }
}

fn primitive_type(name: &str, bits: u16, signed: Option<bool>) -> String {
    match name {
        "bool" => "bool".into(),
        "char" => "char".into(),
        "float" => "float".into(),
        "double" => "double".into(),
        "void" => "void".into(),
        _ => match (signed, bits) {
            (Some(true), 8) => "int8_t".into(),
            (Some(true), 16) => "int16_t".into(),
            (Some(true), 32) => "int32_t".into(),
            (Some(true), 64) => "int64_t".into(),
            (Some(false), 8) => "uint8_t".into(),
            (Some(false), 16) => "uint16_t".into(),
            (Some(false), 32) => "uint32_t".into(),
            (Some(false), 64) => "uint64_t".into(),
            _ => c_identifier(name),
        },
    }
}

fn c_identifier(value: &str) -> String {
    let value = value.trim_start_matches(|character| character == '$' || character == '%');
    let mut output = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if output.is_empty() {
        return output;
    }
    if output.as_bytes()[0].is_ascii_digit() {
        output.insert(0, '_');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Abi, Confidence, StructCandidate, Varnode};
    use ventris_target::TargetProfile;

    fn report() -> RecoveredFunction {
        RecoveredFunction {
            target: TargetProfile::Ps2,
            abi: Abi::for_target(TargetProfile::Ps2),
            entry: 0x1000,
            name: Some("Actor::update".into()),
            accesses: Vec::new(),
            structs: vec![StructCandidate {
                base: Varnode::new(4, 0, 4),
                name: Some("Actor".into()),
                parameter_name: None,
                fields: vec![
                    crate::RecoveredField {
                        offset: 0,
                        width: 4,
                        name: Some("health".into()),
                        ty: GameType::Primitive {
                            name: "int".into(),
                            bits: 32,
                            signed: Some(true),
                        },
                        accesses: Vec::new(),
                        evidence: Vec::new(),
                    },
                    crate::RecoveredField {
                        offset: 8,
                        width: 4,
                        name: None,
                        ty: GameType::UnknownBytes { width: 4 },
                        accesses: Vec::new(),
                        evidence: Vec::new(),
                    },
                ],
                strides: Vec::new(),
                evidence: vec![crate::Evidence {
                    source: crate::EvidenceSource::UserAssertion {
                        note: "test".into(),
                    },
                    confidence: Confidence::new(100).unwrap(),
                }],
            }],
            provenance: Vec::new(),
        }
    }
    #[test]
    fn renders_typed_structs_and_preserves_observed_offsets() {
        let reconstruction =
            SourceReconstruction::from_report(&report(), "int body(void) { return 1; }").unwrap();
        assert_eq!(reconstruction.signature.name, "Actor__update");
        assert!(reconstruction.signature.parameters.is_empty());
        let source = reconstruction.render();
        assert!(source.contains("int Actor__update(void)"));
        assert!(source.contains("typedef struct Actor"));
        assert!(source.contains("int32_t health;"));
        assert!(source.contains("uint8_t _pad_4[4];"));
        assert!(source.contains("int Actor__update("));
        assert!(source.contains("{ return 1; }"));
        assert!(!source.contains("int body(void)"));
    }
    #[test]
    fn trailing_pruning_preserves_unused_interior_abi_positions() {
        let reconstruction = SourceReconstruction::from_report(
            &report(),
            "void body(void) { consume(a0, a2); return; }",
        )
        .unwrap();
        assert_eq!(
            reconstruction
                .signature
                .parameters
                .iter()
                .map(|parameter| parameter.name.as_str())
                .collect::<Vec<_>>(),
            vec!["a0", "a1", "a2"]
        );
        let source = reconstruction.render();
        assert!(source.contains("void Actor__update(uintptr_t a0, uintptr_t a1, uintptr_t a2)"));
        assert!(!source.contains("uintptr_t a3"), "{source}");
        assert!(!source.contains("float f12"), "{source}");
    }

    #[test]
    fn preserves_native_void_return_type() {
        let reconstruction =
            SourceReconstruction::from_report(&report(), "void body(void) { return; }").unwrap();
        assert_eq!(reconstruction.signature.return_type, "void");
        assert!(reconstruction.render().contains("void Actor__update("));
    }
    #[test]
    fn rewrites_evidence_backed_offsets_to_recovered_fields() {
        let reconstruction = SourceReconstruction::from_report(
            &report(),
            "void body(void) { *(uint32_t *)(uintptr_t)(a0 + 0x8) = 1; return; }",
        )
        .unwrap();
        let source = reconstruction.render();
        assert!(source.contains("Actor * a0"), "{source}");
        assert!(source.contains("(a0->field_8[0]) = 1;"), "{source}");
        assert!(!source.contains("(uintptr_t)(a0 + 0x8)"), "{source}");
        assert!(
            source.contains("void Actor__update(Actor * a0)"),
            "{source}"
        );
        assert!(!source.contains("uintptr_t a1"), "{source}");
        assert!(!source.contains("float f12"), "{source}");
    }
    #[test]
    fn applies_source_backed_parameter_name_to_typed_receiver() {
        let mut report = report();
        report.structs[0].parameter_name = Some("this_".into());
        let reconstruction = SourceReconstruction::from_report(
            &report,
            "void body(void) { *(uint32_t *)(uintptr_t)(a0 + 0x8) = 1; return; }",
        )
        .unwrap();
        let source = reconstruction.render();
        assert!(
            source.contains("void Actor__update(Actor * this_)"),
            "{source}"
        );
        assert!(source.contains("(this_->field_8[0]) = 1;"), "{source}");
        assert!(!source.contains("Actor * a0"), "{source}");
    }
    #[test]
    fn removes_redundant_integer_cast_from_recovered_byte_field() {
        let mut report = report();
        report.structs[0].fields[1].width = 1;
        report.structs[0].fields[1].ty = GameType::UnknownBytes { width: 1 };
        let reconstruction = SourceReconstruction::from_report(
            &report,
            "void body(void) { if ((uint64_t)(*(bool *)(uintptr_t)(a0 + 0x8)) == 1) return; }",
        )
        .unwrap();
        let source = reconstruction.render();
        assert!(source.contains("if ((a0->field_8[0]) == 1)"), "{source}");
        assert!(!source.contains("(uint64_t)"), "{source}");
    }

    #[test]
    fn removes_cast_matching_recovered_field_type() {
        let mut report = report();
        report.structs[0].fields[0].ty = GameType::Primitive {
            name: "uint32_t".into(),
            bits: 32,
            signed: Some(false),
        };
        let reconstruction = SourceReconstruction::from_report(
            &report,
            "uint32_t body(void) { *(uint32_t *)(uintptr_t)(a0 + 0x0) = (uint32_t)(*(uint32_t *)(uintptr_t)(a0 + 0x0)) + 1; return (uintptr_t)a0; }",
        )
        .unwrap();
        let source = reconstruction.render();
        assert!(!source.contains("(uint32_t)((a0->health))"), "{source}");
        assert!(source.contains("(uintptr_t)a0"), "{source}");
    }

    #[test]
    fn removes_redundant_integer_promotion_around_recovered_word_field() {
        let reconstruction = SourceReconstruction::from_report(
            &report(),
            "uint32_t body(void) { return (uint32_t)((int64_t)(*(uint32_t *)(uintptr_t)(a0 + 0x0)) * 0x70); }",
        )
        .unwrap();

        let source = reconstruction.render();
        assert!(source.contains("return ((a0->health) * 0x70);"), "{source}");
        assert!(!source.contains("(uint32_t)"), "{source}");
        assert!(!source.contains("(int64_t)"), "{source}");
    }
    #[test]
    fn preserves_byte_arithmetic_for_unrecovered_offsets_after_retyping_receiver() {
        let reconstruction = SourceReconstruction::from_report(
            &report(),
            "uint32_t body(void) { *(uint32_t *)(uintptr_t)(a0 + 0x0) = 1; return *(uint32_t *)(uintptr_t)(a0 + 0xc); }",
        )
        .unwrap();
        let source = reconstruction.render();
        assert!(source.contains("Actor * a0"), "{source}");
        assert!(source.contains("((uintptr_t)a0 + 0xc)"), "{source}");
        assert!(!source.contains("(a0 + 0xc)"), "{source}");
    }

    #[test]
    fn preserves_byte_arithmetic_when_receiver_is_an_interior_operand() {
        let reconstruction = SourceReconstruction::from_report(
            &report(),
            "uint32_t body(void) { *(uint32_t *)(uintptr_t)(a0 + 0x0) = 1; return 0x70 + a0 + 0x4d0; }",
        )
        .unwrap();
        let source = reconstruction.render();
        assert!(source.contains("0x70 + (uintptr_t)a0 + 0x4d0"), "{source}");
    }

    #[test]
    fn keeps_unresolved_function_pointer_facts_explicit() {
        let mut report = report();
        report.structs[0].fields[0].ty = GameType::FunctionPointer {
            target: Some(0x2000),
            bits: 32,
        };
        let reconstruction =
            SourceReconstruction::from_report(&report, "void body(void) {}").unwrap();
        assert_eq!(reconstruction.structs[0].fields[0].c_type, "uintptr_t");
        assert!(reconstruction.render().contains("unresolved"));
    }

    #[test]
    fn rejects_empty_source_body() {
        assert_eq!(
            SourceReconstruction::from_report(&report(), "   "),
            Err(ReconstructionError::EmptyBody)
        );
    }

    #[test]
    fn fields_below_the_base_get_distinct_names() {
        // Clamping negative offsets to zero declared two members called
        // `field_0` in one struct, which does not compile.
        assert_ne!(
            field_name_for_offset(-0x51e0),
            field_name_for_offset(-0x51dc)
        );
        assert_ne!(field_name_for_offset(-4), field_name_for_offset(0));
        assert_eq!(field_name_for_offset(0x10), "field_10");
    }
    /// The graph emitter names a recovered member after its offset, because only
    /// this pass knows what the source called it. That spelling has to be
    /// rewritten, or the structure matches no parameter and the declared type
    /// falls back.
    #[test]
    fn an_offset_named_member_is_rewritten_to_its_nominal_name() {
        let mut signature = SourceSignature {
            name: "f".into(),
            return_type: "void".into(),
            parameters: vec![SourceParameter {
                name: "arg0".into(),
                c_type: "RecoveredStruct0 *".into(),
            }],
        };
        let structs = vec![SourceStruct {
            name: "GameWorld".into(),
            parameter_name: Some("this_".into()),
            fields: vec![SourceField {
                offset: 0x4a4,
                name: "fadeOut".into(),
                c_type: "uint8_t".into(),
                declarator_suffix: "[1]".into(),
                width: 1,
            }],
            unresolved: Vec::new(),
        }];
        let mut body = String::from("void f(void) {\n    (arg0->field_4a4[0]) = 1;\n}\n");
        rewrite_recovered_field_accesses(&mut signature, &structs, &mut body);
        assert!(
            body.contains("this_->fadeOut"),
            "the nominal name must reach the body, got {body}"
        );
        assert!(!body.contains("field_4a4"), "got {body}");
        assert_eq!(signature.parameters[0].c_type, "GameWorld *");
        assert_eq!(signature.parameters[0].name, "this_");
    }
}
