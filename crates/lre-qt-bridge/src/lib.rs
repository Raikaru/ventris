//! CXX-facing adapter for the native Qt consumer.
//!
//! Qt owns widgets and schedules calls on its worker pool. Rust remains the
//! semantic owner: every request below dispatches to `lre_core::Core`, never
//! to a second storage or process-launch implementation. The wire value is a
//! small JSON envelope so the C++ side does not duplicate Rust model structs.

use lre_core::Core;
use lre_model::{Address, AddressSpace};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[cxx::bridge(namespace = "ventris")]
mod ffi {
    extern "Rust" {
        type CoreHandle;

        fn core_open(project: &str) -> Result<Box<CoreHandle>>;
        fn core_request(core: &CoreHandle, request_json: &str) -> String;
    }
}

/// Thread-safe handle held by the C++ bridge. The mutex serializes SQLite and
/// Core's one-entry native image cache while Qt may issue concurrent requests.
pub struct CoreHandle {
    core: Mutex<Core>,
}

pub fn core_open(project: &str) -> Result<Box<CoreHandle>, Box<dyn std::error::Error>> {
    let core = Core::open(Path::new(project))?;
    Ok(Box::new(CoreHandle {
        core: Mutex::new(core),
    }))
}

pub fn core_request(core: &CoreHandle, request_json: &str) -> String {
    let result = (|| -> Result<Value, String> {
        let request: Value = serde_json::from_str(request_json)
            .map_err(|e| format!("invalid request JSON: {e}"))?;
        let guard = core
            .core
            .lock()
            .map_err(|_| "Core mutex poisoned".to_string())?;
        dispatch(&guard, &request)
    })();
    match result {
        Ok(result) => serde_json::to_string(&json!({ "ok": true, "result": result }))
            .unwrap_or_else(|e| error_json(&format!("encode response: {e}"))),
        Err(error) => error_json(&error),
    }
}

fn error_json(error: &str) -> String {
    serde_json::to_string(&json!({ "ok": false, "error": error }))
        .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"response encoding failed\"}".into())
}

fn dispatch(core: &Core, request: &Value) -> Result<Value, String> {
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| "request.method must be a string".to_string())?;
    match method {
        "ping" => Ok(json!({ "service": "lre-core", "api": 1 })),
        "architectures" => to_value(core.architectures()),
        "open" => {
            let program = required_string(request, "program")?;
            to_value(core.open_program(&program))
        }
        "import_native" => {
            let binary = required_path(request, "binary")?;
            let name = request
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    binary
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "program".into())
                });
            to_value(core.import_native(&binary, &name))
        }
        "functions_page" => {
            let program = required_string(request, "program")?;
            let offset = optional_u64(request, "offset")?.unwrap_or(0);
            let limit = optional_u64(request, "limit")?.unwrap_or(256);
            let filter = request.get("filter").and_then(Value::as_str);
            let sort = request.get("sort").and_then(Value::as_str);
            to_value(core.functions_page(&program, offset, limit, filter, sort))
        }
        "symbols_page" => {
            let program = required_string(request, "program")?;
            let offset = optional_u64(request, "offset")?.unwrap_or(0);
            let limit = optional_u64(request, "limit")?.unwrap_or(256);
            to_value(core.symbols_page(&program, offset, limit))
        }
        "xrefs_page" => {
            let program = required_string(request, "program")?;
            let address = required_address(request, "address")?;
            let incoming = request
                .get("incoming")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let offset = optional_u64(request, "offset")?.unwrap_or(0);
            let limit = optional_u64(request, "limit")?.unwrap_or(256);
            to_value(core.xrefs_page(
                &program, &address, incoming, offset, limit,
            ))
        }
        "comments" => {
            let program = required_string(request, "program")?;
            to_value(core.comments(&program))
        }
        "datatypes" => {
            let program = required_string(request, "program")?;
            to_value(core.datatypes(&program))
        }
        "type_defs" => {
            let program = required_string(request, "program")?;
            to_value(core.type_defs(&program))
        }
        "type_fields" => {
            let program = required_string(request, "program")?;
            let type_name = request.get("type_name").and_then(Value::as_str);
            to_value(core.type_fields(&program, type_name))
        }
        "prototypes" => {
            let program = required_string(request, "program")?;
            to_value(core.prototypes(&program))
        }
        "stack_variables" => {
            let program = required_string(request, "program")?;
            let function = request
                .get("function")
                .map(|_| required_address(request, "function"))
                .transpose()?;
            to_value(core.stack_variables(&program, function.as_ref()))
        }
        "type_graph" => {
            let program = required_string(request, "program")?;
            let (nodes, edges) = core.type_graph(&program).map_err(|e| e.to_string())?;
            Ok(json!({ "nodes": nodes, "edges": edges }))
        }
        "propagate_type_links" => {
            let program = required_string(request, "program")?;
            to_value(core.propagate_type_links(&program))
        }
        "replace_type_defs" => {
            let program = required_string(request, "program")?;
            let rows: Vec<lre_model::TypeDefRow> = required_rows(request, "rows")?;
            let count = rows.len();
            core.replace_type_defs(&program, &rows)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "count": count }))
        }
        "replace_type_fields" => {
            let program = required_string(request, "program")?;
            let rows: Vec<lre_model::TypeFieldRow> = required_rows(request, "rows")?;
            let count = rows.len();
            core.replace_type_fields(&program, &rows)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "count": count }))
        }
        "replace_prototypes" => {
            let program = required_string(request, "program")?;
            let rows: Vec<lre_model::PrototypeRow> = required_rows(request, "rows")?;
            let count = rows.len();
            core.replace_prototypes(&program, &rows)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "count": count }))
        }
        "replace_stack_variables" => {
            let program = required_string(request, "program")?;
            let rows: Vec<lre_model::StackVariableRow> = required_rows(request, "rows")?;
            let count = rows.len();
            core.replace_stack_variables(&program, &rows)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "count": count }))
        }
        "replace_type_links" => {
            let program = required_string(request, "program")?;
            let rows: Vec<lre_model::TypeLinkRow> = required_rows(request, "rows")?;
            let count = rows.len();
            core.replace_type_links(&program, &rows)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "count": count }))
        }
        "set_type_def" => {
            let program = required_string(request, "program")?;
            let row: lre_model::TypeDefRow = required_row(request, "row")?;
            core.set_type_def(&program, &row).map_err(|e| e.to_string())?;
            Ok(json!({ "name": row.name }))
        }
        "set_type_field" => {
            let program = required_string(request, "program")?;
            let row: lre_model::TypeFieldRow = required_row(request, "row")?;
            core.set_type_field(&program, &row)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "type_name": row.type_name, "ordinal": row.ordinal }))
        }
        "set_prototype" => {
            let program = required_string(request, "program")?;
            let row: lre_model::PrototypeRow = required_row(request, "row")?;
            core.set_prototype(&program, &row).map_err(|e| e.to_string())?;
            Ok(json!({ "function": row.function }))
        }
        "set_stack_variable" => {
            let program = required_string(request, "program")?;
            let row: lre_model::StackVariableRow = required_row(request, "row")?;
            core.set_stack_variable(&program, &row)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "function": row.function, "ordinal": row.ordinal }))
        }
        "set_type_link" => {
            let program = required_string(request, "program")?;
            let row: lre_model::TypeLinkRow = required_row(request, "row")?;
            core.set_type_link(&program, &row).map_err(|e| e.to_string())?;
            Ok(json!({ "source": row.source, "target": row.target }))
        }
        "strings" => {
            let program = required_string(request, "program")?;
            to_value(core.strings(&program))
        }
        "search" => {
            let program = required_string(request, "program")?;
            let term = required_string(request, "term")?;
            let limit = optional_u64(request, "limit")?.unwrap_or(256);
            to_value(core.search(&program, &term, limit))
        }
        "function_graph" => {
            let program = required_string(request, "program")?;
            let (nodes, edges) = core.function_graph(&program).map_err(|e| e.to_string())?;
            Ok(json!({ "nodes": nodes, "edges": edges }))
        }
        "memory_regions" => {
            let program = required_string(request, "program")?;
            to_value(core.memory_regions(&program))
        }
        "bookmarks" => {
            let program = required_string(request, "program")?;
            to_value(core.bookmarks(&program))
        }
        "set_bookmark" => {
            let program = required_string(request, "program")?;
            let row: lre_model::BookmarkRow = serde_json::from_value(
                request.get("bookmark").cloned().unwrap_or(Value::Null),
            )
            .map_err(|e| format!("request.bookmark is invalid: {e}"))?;
            core.set_bookmark(&program, &row).map_err(|e| e.to_string())?;
            Ok(json!({ "address": row.address, "label": row.label }))
        }
        "delete_bookmark" => {
            let program = required_string(request, "program")?;
            let address = required_address(request, "address")?;
            core.delete_bookmark(&program, &address)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "address": address }))
        }
        "patches" => {
            let program = required_string(request, "program")?;
            to_value(core.patches(&program))
        }
        "set_patch" => {
            let program = required_string(request, "program")?;
            let address = required_address(request, "address")?;
            let original = required_bytes(request, "original")?;
            let patched = required_bytes(request, "patched")?;
            let enabled = request
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let row = lre_model::PatchRow {
                address: address.clone(),
                original,
                patched,
                enabled,
            };
            core.set_patch(&program, &row).map_err(|e| e.to_string())?;
            Ok(json!({ "address": address, "enabled": enabled }))
        }
        "delete_patch" => {
            let program = required_string(request, "program")?;
            let address = required_address(request, "address")?;
            core.delete_patch(&program, &address)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "address": address }))
        }
        "trace_events" => {
            let program = required_string(request, "program")?;
            let since = optional_u64(request, "since")?.unwrap_or(0);
            let limit = optional_u64(request, "limit")?.unwrap_or(256);
            to_value(core.trace_events(&program, since, limit))
        }
        "append_trace_event" => {
            let program = required_string(request, "program")?;
            let row: lre_model::TraceEvent = required_row(request, "event")?;
            to_value(core.append_trace_event(&program, &row))
        }
        "collab_ops" => {
            let program = required_string(request, "program")?;
            to_value(core.collaboration_ops(&program))
        }
        "append_collab_op" => {
            let program = required_string(request, "program")?;
            let row: lre_model::CollaborationOp = required_row(request, "operation")?;
            let op_id = row.op_id.clone();
            let inserted = core
                .append_collaboration_op(&program, &row)
                .map_err(|error| error.to_string())?;
            Ok(json!({"op_id": op_id, "inserted": inserted}))
        }
        "apply_collab_op" => {
            let program = required_string(request, "program")?;
            let op_id = required_string(request, "op_id")?;
            let applied = core
                .apply_collaboration_op(&program, &op_id)
                .map_err(|error| error.to_string())?;
            Ok(json!({"op_id": op_id, "applied": applied}))
        }
        "events_since" => {
            let program = required_string(request, "program")?;
            let since = optional_u64(request, "since")?.unwrap_or(0);
            to_value(core.events_since(&program, since))
        }
        "memory" => {
            let binary = required_path(request, "binary")?;
            let address = required_address(request, "address")?;
            require_ram(&address)?;
            let size = optional_u64(request, "size")?.unwrap_or(64);
            let size = usize::try_from(size).map_err(|_| "size is too large".to_string())?;
            let bytes = core
                .mem_native(&binary, address.offset, size)
                .map_err(|e| e.to_string())?;
            Ok(json!({
                "address": address,
                "size": bytes.len(),
                "bytes_hex": bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            }))
        }
        "rename" => {
            let program = required_string(request, "program")?;
            let address = required_address(request, "address")?;
            let name = required_string(request, "name")?;
            core.rename_command(&program, &address, &name)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "address": address, "name": name }))
        }
        "comment" => {
            let program = required_string(request, "program")?;
            let address = required_address(request, "address")?;
            let function = request
                .get("function")
                .map(|value| {
                    serde_json::from_value(value.clone())
                        .map_err(|e| format!("request.function is invalid: {e}"))
                })
                .transpose()?
                .unwrap_or_else(|| address.clone());
            let kind = request

                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("eol");
            let text = required_string(request, "text")?;
            core.comment_command(&program, &address, &function, kind, &text)
                .map_err(|e| e.to_string())?;
            Ok(json!({ "address": address, "kind": kind, "text": text }))
        }
        "undo" => {
            let program = required_string(request, "program")?;
            let message = core.undo_last(&program).map_err(|e| e.to_string())?;
            Ok(json!({ "message": message }))
        }
        "listing" => {
            let binary = required_path(request, "binary")?;
            let start = required_address(request, "start")?;
            let count = optional_u64(request, "count")?.unwrap_or(64);
            let count = u32::try_from(count).map_err(|_| "count is too large".to_string())?;
            let overscan = request
                .get("overscan_fraction")
                .and_then(Value::as_f64)
                .unwrap_or(0.25) as f32;
            to_value(core.listing_window(&binary, &start, count, overscan))
        }
        "disasm_native" => {
            let binary = required_path(request, "binary")?;
            let address = required_address(request, "address")?;
            require_ram(&address)?;
            let count = optional_u64(request, "count")?.unwrap_or(16);
            let count = u32::try_from(count).map_err(|_| "count is too large".to_string())?;
            to_value(core.disasm_native(&binary, &address.hex(), count))
        }
        "decompile_doc" => {
            let binary = required_path(request, "binary")?;
            let program = required_string(request, "program")?;
            let address = required_address(request, "address")?;
            let base = optional_u64(request, "base")?;
            to_value(core.decompile_native_doc(&binary, &address, &program, base))
        }
        _ => Err(format!("unknown Core API method: {method}")),
    }
}

fn required_string(request: &Value, key: &str) -> Result<String, String> {
    request
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("request.{key} must be a string"))
}

fn required_path(request: &Value, key: &str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(required_string(request, key)?))
}

fn optional_u64(request: &Value, key: &str) -> Result<Option<u64>, String> {
    let Some(value) = request.get(key) else {
        return Ok(None);
    };
    if let Some(number) = value.as_u64() {
        return Ok(Some(number));
    }
    if let Some(string) = value.as_str() {
        return u64::from_str_radix(string.trim_start_matches("0x"), 16)
            .map(Some)
            .map_err(|e| format!("request.{key} is not a number: {e}"));
    }
    Err(format!("request.{key} must be an unsigned integer"))
}

fn required_row<T: DeserializeOwned>(request: &Value, key: &str) -> Result<T, String> {
    let value = request
        .get(key)
        .ok_or_else(|| format!("request.{key} is required"))?;
    serde_json::from_value(value.clone())
        .map_err(|error| format!("request.{key} is invalid: {error}"))
}

fn required_rows<T: DeserializeOwned>(request: &Value, key: &str) -> Result<Vec<T>, String> {
    let value = request
        .get(key)
        .ok_or_else(|| format!("request.{key} is required"))?;
    serde_json::from_value(value.clone())
        .map_err(|error| format!("request.{key} is invalid: {error}"))
}

fn required_bytes(request: &Value, key: &str) -> Result<Vec<u8>, String> {
    let value = request
        .get(key)
        .ok_or_else(|| format!("request.{key} is required"))?;
    let values = value
        .as_array()
        .ok_or_else(|| format!("request.{key} must be an array of bytes"))?;
    values
        .iter()
        .map(|value| {
            let byte = value
                .as_u64()
                .ok_or_else(|| format!("request.{key} contains a non-integer byte"))?;
            u8::try_from(byte).map_err(|_| format!("request.{key} contains byte > 255"))
        })
        .collect()
}


fn required_address(request: &Value, key: &str) -> Result<Address, String> {
    let value = request
        .get(key)
        .ok_or_else(|| format!("request.{key} is required"))?;
    serde_json::from_value(value.clone()).map_err(|e| format!("request.{key} is invalid: {e}"))
}

fn require_ram(address: &Address) -> Result<(), String> {
    if matches!(&address.space, AddressSpace::Ram) {
        Ok(())
    } else {
        Err(format!("this operation requires a RAM address: {address}"))
    }
}

fn to_value<T, E>(result: Result<T, E>) -> Result<Value, String>
where
    T: Serialize,
    E: std::fmt::Display,
{
    result
        .map_err(|error| error.to_string())
        .and_then(|value| {
            serde_json::to_value(value).map_err(|error| format!("encode result: {error}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_project() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ventris-qt-bridge-{nonce}"))
    }

    #[test]
    fn ping_is_versioned_and_json_enveloped() {
        let handle = core_open(temp_project().to_str().unwrap()).unwrap();
        let response: Value = serde_json::from_str(&core_request(&handle, r#"{"method":"ping"}"#))
            .unwrap();
        assert_eq!(response["ok"], true);
        assert_eq!(response["result"]["api"], 1);
    }

    #[test]
    fn malformed_and_unknown_requests_are_errors_not_panics() {
        let handle = core_open(temp_project().to_str().unwrap()).unwrap();
        for request in ["not-json", r#"{"method":"nope"}"#, r#"{"method":1}"#] {
            let response: Value = serde_json::from_str(&core_request(&handle, request)).unwrap();
            assert_eq!(response["ok"], false);
            assert!(
                response["error"].as_str().unwrap().contains("request")
                    || response["error"].as_str().unwrap().contains("unknown")
            );
        }
    }

    #[test]
    fn address_parser_accepts_core_wire_forms() {
        let request = json!({"address": "ram:00400466"});
        assert_eq!(required_address(&request, "address").unwrap(), Address::ram(0x400466));
        let request = json!({"address": {"space": {"Other": "register"}, "offset": 8}});
        assert!(required_address(&request, "address").is_ok());
    }
}
