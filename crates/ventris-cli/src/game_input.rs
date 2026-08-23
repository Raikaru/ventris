use crate::json::Value;
use std::path::Path;
use ventris_game::{
    AnnotationFact, Confidence, Evidence, EvidenceSource, GameType, NominalField, NominalType,
    TypeAssertion,
};
use ventris_pcode::Varnode;

#[derive(Debug, Default)]
pub struct GameMetadata {
    pub nominal_types: Vec<NominalType>,
    pub annotations: Vec<AnnotationFact>,
    pub provenance: Vec<Evidence>,
    pub assertions: Vec<TypeAssertion>,
}

/// Read user-owned game metadata from a small, stable JSON sidecar.
pub fn load(path: Option<&Path>) -> Result<GameMetadata, String> {
    let Some(path) = path else {
        return Ok(GameMetadata::default());
    };
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let value = crate::json::parse(&text)
        .map_err(|error| format!("{}: invalid metadata JSON: {error}", path.display()))?;
    parse_root(&value).map_err(|error| format!("{}: {error}", path.display()))
}

fn parse_root(value: &Value) -> Result<GameMetadata, String> {
    let object = as_object(value, "metadata root")?;
    let provenance = parse_provenance(object.get("provenance"))?;
    Ok(GameMetadata {
        nominal_types: parse_nominal_types(object.get("nominal_types"), &provenance)?,
        annotations: parse_annotations(object.get("annotations"))?,
        provenance,
        assertions: parse_assertions(object.get("assertions"))?,
    })
}

fn parse_provenance(value: Option<&Value>) -> Result<Vec<Evidence>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let object = as_object(value, "provenance")?;
    Ok(vec![Evidence {
        source: EvidenceSource::SourceMetadata {
            url: required_string(object, "url")?.to_owned(),
            commit: required_string(object, "commit")?.to_owned(),
            license: required_string(object, "license")?.to_owned(),
            path: required_string(object, "path")?.to_owned(),
        },
        confidence: Confidence::new(100).expect("valid source-metadata confidence"),
    }])
}

fn parse_nominal_types(
    value: Option<&Value>,
    provenance: &[Evidence],
) -> Result<Vec<NominalType>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    as_array(value, "nominal_types")?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let object = as_object(value, &format!("nominal_types[{index}]"))?;
            let fields = match object.get("fields") {
                Some(value) => as_array(value, "nominal type fields")?
                    .iter()
                    .enumerate()
                    .map(|(field_index, value)| {
                        let field = as_object(
                            value,
                            &format!("nominal_types[{index}].fields[{field_index}]"),
                        )?;
                        Ok(NominalField {
                            offset: required_i64(field, "offset")?,
                            name: required_string(field, "name")?.to_owned(),
                            ty: parse_type(field.get("type").ok_or_else(|| {
                                format!(
                                    "nominal_types[{index}].fields[{field_index}] requires type"
                                )
                            })?)?,
                            width: required_u64(field, "width")?
                                .try_into()
                                .map_err(|_| "nominal field width is too large".to_string())?,
                            evidence: provenance.to_vec(),
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
                None => Vec::new(),
            };
            Ok(NominalType {
                id: required_u64(object, "id")?,
                name: required_string(object, "name")?.to_owned(),
                size: required_u64(object, "size")?
                    .try_into()
                    .map_err(|_| "nominal type size is too large".to_string())?,
                fields,
                evidence: provenance.to_vec(),
            })
        })
        .collect()
}

fn parse_annotations(value: Option<&Value>) -> Result<Vec<AnnotationFact>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    as_array(value, "annotations")?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let object = as_object(value, &format!("annotations[{index}]"))?;
            Ok(AnnotationFact {
                address: required_u64(object, "address")?,
                text: required_string(object, "text")?.to_owned(),
            })
        })
        .collect()
}

fn parse_assertions(value: Option<&Value>) -> Result<Vec<TypeAssertion>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    as_array(value, "assertions")?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let object = as_object(value, &format!("assertions[{index}]"))?;
            let name = match object.get("name") {
                None | Some(Value::Null) => None,
                Some(value) => Some(as_string(value, "assertion name")?.to_owned()),
            };
            let note = object
                .get("note")
                .map(|value| as_string(value, "assertion note"))
                .transpose()?
                .unwrap_or("sidecar assertion")
                .to_owned();
            Ok(TypeAssertion {
                base: Varnode::new(
                    required_u64(object, "space")?
                        .try_into()
                        .map_err(|_| "assertion space is too large".to_string())?,
                    required_u64(object, "base")?,
                    required_u64(object, "size")?
                        .try_into()
                        .map_err(|_| "assertion size is too large".to_string())?,
                ),
                offset: required_i64(object, "offset")?,
                name,
                ty: parse_type(
                    object
                        .get("type")
                        .ok_or_else(|| format!("assertions[{index}] requires type"))?,
                )?,
                note,
            })
        })
        .collect()
}

fn parse_type(value: &Value) -> Result<GameType, String> {
    let object = as_object(value, "type")?;
    let kind = required_string(object, "kind")?;
    match kind {
        "unknown" => Ok(GameType::UnknownBytes {
            width: required_u64(object, "width")?
                .try_into()
                .map_err(|_| "unknown type width is too large".to_string())?,
        }),
        "primitive" => Ok(GameType::Primitive {
            name: required_string(object, "name")?.to_owned(),
            bits: required_u64(object, "bits")?
                .try_into()
                .map_err(|_| "primitive bit width is too large".to_string())?,
            signed: match object.get("signed") {
                None | Some(Value::Null) => None,
                Some(value) => Some(
                    value
                        .as_bool()
                        .ok_or_else(|| "primitive signed must be boolean or null".to_string())?,
                ),
            },
        }),
        "enum" => Ok(GameType::Enum {
            name: required_string(object, "name")?.to_owned(),
            bits: required_u64(object, "bits")?
                .try_into()
                .map_err(|_| "enum bit width is too large".to_string())?,
            signed: match object.get("signed") {
                None | Some(Value::Null) => None,
                Some(value) => Some(
                    value
                        .as_bool()
                        .ok_or_else(|| "enum signed must be boolean or null".to_string())?,
                ),
            },
        }),
        "nominal" => Ok(GameType::Nominal {
            id: object.get("id").map(parse_u64).transpose()?,
            name: required_string(object, "name")?.to_owned(),
            size: required_u64(object, "size")?
                .try_into()
                .map_err(|_| "nominal type size is too large".to_string())?,
        }),
        "pointer" => Ok(GameType::Pointer {
            to: Box::new(parse_type(
                object
                    .get("to")
                    .ok_or_else(|| "pointer type requires to".to_string())?,
            )?),
            bits: required_u64(object, "bits")?
                .try_into()
                .map_err(|_| "pointer bit width is too large".to_string())?,
        }),
        "array" => Ok(GameType::Array {
            element: Box::new(parse_type(
                object
                    .get("element")
                    .ok_or_else(|| "array type requires element".to_string())?,
            )?),
            count: object
                .get("count")
                .filter(|value| !matches!(value, Value::Null))
                .map(parse_u64)
                .transpose()?
                .map(|value| {
                    value
                        .try_into()
                        .map_err(|_| "array count is too large".to_string())
                })
                .transpose()?,
            stride: required_u64(object, "stride")?
                .try_into()
                .map_err(|_| "array stride is too large".to_string())?,
        }),
        "function_pointer" => Ok(GameType::FunctionPointer {
            target: object
                .get("target")
                .filter(|value| !matches!(value, Value::Null))
                .map(parse_u64)
                .transpose()?,
            bits: required_u64(object, "bits")?
                .try_into()
                .map_err(|_| "function pointer bit width is too large".to_string())?,
        }),
        "vector" => Ok(GameType::Vector {
            lane: Box::new(parse_type(
                object
                    .get("lane")
                    .ok_or_else(|| "vector type requires lane".to_string())?,
            )?),
            lanes: required_u64(object, "lanes")?
                .try_into()
                .map_err(|_| "vector lane count is too large".to_string())?,
        }),
        "handle" => Ok(GameType::Handle {
            name: required_string(object, "name")?.to_owned(),
            bits: required_u64(object, "bits")?
                .try_into()
                .map_err(|_| "handle bit width is too large".to_string())?,
        }),
        other => Err(format!("unknown game type kind {other:?}")),
    }
}

fn as_object<'a>(
    value: &'a Value,
    context: &str,
) -> Result<&'a std::collections::BTreeMap<String, Value>, String> {
    match value {
        Value::Object(value) => Ok(value),
        _ => Err(format!("{context} must be an object")),
    }
}

fn as_array<'a>(value: &'a Value, context: &str) -> Result<&'a [Value], String> {
    match value {
        Value::Array(value) => Ok(value),
        _ => Err(format!("{context} must be an array")),
    }
}

fn as_string<'a>(value: &'a Value, context: &str) -> Result<&'a str, String> {
    value
        .as_str()
        .ok_or_else(|| format!("{context} must be a string"))
}

fn required_string<'a>(
    object: &'a std::collections::BTreeMap<String, Value>,
    name: &str,
) -> Result<&'a str, String> {
    object
        .get(name)
        .ok_or_else(|| format!("missing {name}"))
        .and_then(|value| as_string(value, name))
}

fn required_u64(
    object: &std::collections::BTreeMap<String, Value>,
    name: &str,
) -> Result<u64, String> {
    object
        .get(name)
        .ok_or_else(|| format!("missing {name}"))
        .and_then(parse_u64)
}

fn required_i64(
    object: &std::collections::BTreeMap<String, Value>,
    name: &str,
) -> Result<i64, String> {
    object
        .get(name)
        .ok_or_else(|| format!("missing {name}"))
        .and_then(parse_i64)
}

fn parse_u64(value: &Value) -> Result<u64, String> {
    let text = match value {
        Value::Number(value) | Value::String(value) => value,
        _ => return Err("expected an integer or address string".into()),
    };
    let text = text.trim();
    let digits = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"));
    if let Some(digits) = digits {
        return u64::from_str_radix(digits, 16).map_err(|_| format!("invalid integer {text:?}"));
    }
    text.parse::<u64>()
        .or_else(|_| u64::from_str_radix(text, 16))
        .map_err(|_| format!("invalid integer {text:?}"))
}

fn parse_i64(value: &Value) -> Result<i64, String> {
    let text = match value {
        Value::Number(value) | Value::String(value) => value.trim(),
        _ => return Err("expected an integer or offset string".into()),
    };
    if let Some(rest) = text.strip_prefix('-') {
        let magnitude = parse_u64(&Value::String(rest.to_owned()))?;
        return i64::try_from(magnitude)
            .map(|value| -value)
            .map_err(|_| format!("offset is out of range {text:?}"));
    }
    i64::try_from(parse_u64(&Value::String(text.to_owned()))?)
        .map_err(|_| format!("offset is out of range {text:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_annotations_assertions_and_nominal_types() {
        let value = crate::json::parse(
            r#"{
                "provenance": {
                    "url": "https://example.test/game",
                    "commit": "abc123",
                    "license": "MIT",
                    "path": "src/actor.hpp"
                },
                "nominal_types": [{
                    "id": 7,
                    "name": "Actor",
                    "size": 64,
                    "fields": [{
                        "offset": 16,
                        "name": "position",
                        "width": 12,
                        "type": {
                            "kind": "vector",
                            "lanes": 3,
                            "lane": {"kind": "primitive", "name": "float", "bits": 32}
                        }
                    }]
                }],
                "annotations": [{"address": "0x1000", "text": "entry"}],
                "assertions": [{
                    "space": 4,
                    "base": "0x20",
                    "size": 4,
                    "offset": -16,
                    "name": "owner",
                    "type": {"kind": "pointer", "bits": 32, "to": {
                        "kind": "nominal", "id": 7, "name": "Actor", "size": 64
                    }},
                    "note": "user supplied"
                }]
            }"#,
        )
        .unwrap();
        let metadata = parse_root(&value).unwrap();
        assert_eq!(metadata.nominal_types[0].name, "Actor");
        assert_eq!(metadata.nominal_types[0].fields[0].offset, 16);
        assert!(matches!(
            metadata.provenance[0].source,
            EvidenceSource::SourceMetadata { ref commit, .. } if commit == "abc123"
        ));
        assert_eq!(
            metadata.nominal_types[0].fields[0].evidence,
            metadata.provenance
        );
        assert_eq!(metadata.annotations[0].address, 0x1000);
        assert_eq!(metadata.assertions[0].base.offset, 0x20);
        assert_eq!(metadata.assertions[0].offset, -16);
        assert!(matches!(
            metadata.assertions[0].ty,
            GameType::Pointer { .. }
        ));
    }

    #[test]
    fn parses_enum_and_function_pointer_types() {
        let enum_ty = parse_type(
            &crate::json::parse(r#"{"kind":"enum","name":"Mode","bits":8,"signed":false}"#)
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            enum_ty,
            GameType::Enum {
                bits: 8,
                signed: Some(false),
                ..
            }
        ));

        let function_ty = parse_type(
            &crate::json::parse(r#"{"kind":"function_pointer","bits":32,"target":"0x401000"}"#)
                .unwrap(),
        )
        .unwrap();
        assert!(matches!(
            function_ty,
            GameType::FunctionPointer {
                target: Some(0x401000),
                bits: 32
            }
        ));
    }
}
