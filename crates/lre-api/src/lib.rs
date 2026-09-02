//! Versioned local API over the authoritative [`lre_core::Core`] facade.
//!
//! The service deliberately has no second state store. Stdio is the default
//! transport for scripts and tests; [`serve_tcp`] provides a small HTTP
//! transport for GUI/plugin clients that need a local endpoint.

use lre_core::Core;
use lre_debug::{BackendKind, DebugBackend, DebugCommand};
use lre_model::{Address, AddressSpace};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

pub const API_VERSION: u64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("request: {0}")]
    Request(String),
}

#[derive(Clone, Debug, Deserialize)]
struct RequestEnvelope {
    api: u64,
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Clone, Debug, Serialize)]
struct ErrorEnvelope {
    code: String,
    message: String,
}

#[derive(Clone, Debug, Serialize)]
struct ResponseEnvelope {
    api: u64,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorEnvelope>,
}

/// One Core-backed API endpoint. It is intentionally single-threaded: Core's
/// native image cache and SQLite connection are not shared across workers.
pub struct ApiService {
    core: Core,
}

impl ApiService {
    pub fn new(core: Core) -> Self {
        Self { core }
    }

    pub fn core(&self) -> &Core {
        &self.core
    }

    /// Handles one versioned JSON request and always returns a versioned JSON
    /// response, including malformed or unsupported requests.
    pub fn handle_line(&self, line: &str) -> String {
        let parsed = serde_json::from_str::<RequestEnvelope>(line)
            .map_err(|error| ApiError::Request(format!("invalid JSON envelope: {error}")));
        let response = match parsed {
            Ok(request) => self.handle(request),
            Err(error) => ResponseEnvelope {
                api: API_VERSION,
                id: Value::Null,
                result: None,
                error: Some(ErrorEnvelope {
                    code: "invalid_request".into(),
                    message: error.to_string(),
                }),
            },
        };
        serde_json::to_string(&response).unwrap_or_else(|error| {
            format!(
                "{{\"api\":{API_VERSION},\"id\":null,\"error\":{{\"code\":\"encode\",\"message\":{}}}}}",
                serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "\"encode\"".into())
            )
        })
    }

    fn handle(&self, request: RequestEnvelope) -> ResponseEnvelope {
        let id = request.id.clone();
        if request.api != API_VERSION {
            return failure(
                id,
                "unsupported_api",
                format!("api {} is unsupported; expected {API_VERSION}", request.api),
            );
        }
        match self.dispatch(&request.method, &request.params) {
            Ok(result) => ResponseEnvelope {
                api: API_VERSION,
                id,
                result: Some(result),
                error: None,
            },
            Err(error) => failure(id, error.code(), error.to_string()),
        }
    }

    fn dispatch(&self, method: &str, params: &Value) -> Result<Value, DispatchError> {
        match method {
            "ping" => Ok(json!({"service": "lre-core", "api": API_VERSION})),
            "architectures" => value(self.core.architectures()),
            "open" => {
                let program = string_param(params, "program")?;
                value(self.core.open_program(&program))
            }
            "import_native" => {
                let binary = path_param(params, "binary")?;
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("program");
                value(self.core.import_native(&binary, name))
            }
            "functions" => {
                let program = string_param(params, "program")?;
                value(self.core.functions(&program))
            }
            "functions_page" => {
                let program = string_param(params, "program")?;
                let filter = params.get("filter").and_then(Value::as_str);
                let sort = params.get("sort").and_then(Value::as_str);
                value(self.core.functions_page(
                    &program,
                    u64_param(params, "offset")?.unwrap_or(0),
                    u64_param(params, "limit")?.unwrap_or(256),
                    filter,
                    sort,
                ))
            }
            "symbols" => {
                let program = string_param(params, "program")?;
                value(self.core.symbols(&program))
            }
            "symbols_page" => {
                let program = string_param(params, "program")?;
                value(self.core.symbols_page(
                    &program,
                    u64_param(params, "offset")?.unwrap_or(0),
                    u64_param(params, "limit")?.unwrap_or(256),
                ))
            }
            "xrefs" => {
                let program = string_param(params, "program")?;
                let address = address_param(params, "address")?;
                if params.get("incoming").and_then(Value::as_bool).unwrap_or(true) {
                    value(self.core.xrefs_to(&program, &address))
                } else {
                    value(self.core.xrefs_from(&program, &address))
                }
            }
            "xrefs_page" => {
                let program = string_param(params, "program")?;
                value(self.core.xrefs_page(
                    &program,
                    &address_param(params, "address")?,
                    params.get("incoming").and_then(Value::as_bool).unwrap_or(true),
                    u64_param(params, "offset")?.unwrap_or(0),
                    u64_param(params, "limit")?.unwrap_or(256),
                ))
            }
            "comments" => {
                let program = string_param(params, "program")?;
                value(self.core.comments(&program))
            }
            "datatypes" => {
                let program = string_param(params, "program")?;
                value(self.core.datatypes(&program))
            }
            "strings" => {
                let program = string_param(params, "program")?;
                value(self.core.strings(&program))
            }
            "search" => {
                let program = string_param(params, "program")?;
                let term = string_param(params, "term")?;
                value(self.core.search(&program, &term, u64_param(params, "limit")?.unwrap_or(256)))
            }
            "function_graph" => {
                let program = string_param(params, "program")?;
                let (nodes, edges) = self.core.function_graph(&program)?;
                Ok(json!({"nodes": nodes, "edges": edges}))
            }
            "memory_regions" => {
                let program = string_param(params, "program")?;
                value(self.core.memory_regions(&program))
            }
            "memory" => {
                let binary = path_param(params, "binary")?;
                let address = address_param(params, "address")?;
                require_ram(&address)?;
                let size = usize::try_from(u64_param(params, "size")?.unwrap_or(64))
                    .map_err(|_| DispatchError::Request("size is too large".into()))?;
                let bytes = self.core.mem_native(&binary, address.offset, size)?;
                Ok(json!({
                    "address": address,
                    "size": bytes.len(),
                    "bytes": bytes,
                }))
            }
            "listing" => {
                let binary = path_param(params, "binary")?;
                let start = address_param(params, "start")?;
                let count = u32::try_from(u64_param(params, "count")?.unwrap_or(64))
                    .map_err(|_| DispatchError::Request("count is too large".into()))?;
                value(self.core.listing_window(
                    &binary,
                    &start,
                    count,
                    params
                        .get("overscan_fraction")
                        .and_then(Value::as_f64)
                        .unwrap_or(0.25) as f32,
                ))
            }
            "disasm_native" => {
                let binary = path_param(params, "binary")?;
                let address = address_param(params, "address")?;
                require_ram(&address)?;
                let count = u32::try_from(u64_param(params, "count")?.unwrap_or(16))
                    .map_err(|_| DispatchError::Request("count is too large".into()))?;
                value(self.core.disasm_native(&binary, &address.hex(), count))
            }
            "decompile_doc" => {
                let binary = path_param(params, "binary")?;
                let program = string_param(params, "program")?;
                let address = address_param(params, "address")?;
                value(self.core.decompile_native_doc(
                    &binary,
                    &address,
                    &program,
                    u64_param(params, "base")?,
                ))
            }
            "rename" => {
                let program = string_param(params, "program")?;
                let address = address_param(params, "address")?;
                let name = string_param(params, "name")?;
                self.core.rename_command(&program, &address, &name)?;
                Ok(json!({"address": address, "name": name}))
            }
            "comment" => {
                let program = string_param(params, "program")?;
                let address = address_param(params, "address")?;
                let function = params
                    .get("function")
                    .map(|value| serde_json::from_value(value.clone()))
                    .transpose()
                    .map_err(|error| DispatchError::Request(format!("function is invalid: {error}")))?
                    .unwrap_or_else(|| address.clone());
                let kind = params
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or("eol");
                let text = string_param(params, "text")?;
                self.core
                    .comment_command(&program, &address, &function, kind, &text)?;
                Ok(json!({"address": address, "kind": kind, "text": text}))
            }
            "undo" => {
                let program = string_param(params, "program")?;
                Ok(json!({"message": self.core.undo_last(&program)?}))
            }
            "bookmarks" => {
                let program = string_param(params, "program")?;
                value(self.core.bookmarks(&program))
            }
            "set_bookmark" => {
                let program = string_param(params, "program")?;
                let row = from_param(params, "bookmark")?;
                self.core.set_bookmark(&program, &row)?;
                Ok(json!({"address": row.address, "label": row.label}))
            }
            "patches" => {
                let program = string_param(params, "program")?;
                value(self.core.patches(&program))
            }
            "set_patch" => {
                let program = string_param(params, "program")?;
                let row = from_param(params, "patch")?;
                self.core.set_patch(&program, &row)?;
                Ok(json!({"address": row.address, "enabled": row.enabled}))
            }
            "type_defs" => {
                let program = string_param(params, "program")?;
                value(self.core.type_defs(&program))
            }
            "type_fields" => {
                let program = string_param(params, "program")?;
                value(self.core.type_fields(
                    &program,
                    params.get("type_name").and_then(Value::as_str),
                ))
            }
            "prototypes" => {
                let program = string_param(params, "program")?;
                value(self.core.prototypes(&program))
            }
            "stack_variables" => {
                let program = string_param(params, "program")?;
                let function = params
                    .get("function")
                    .map(|value| serde_json::from_value(value.clone()))
                    .transpose()
                    .map_err(|error| DispatchError::Request(format!("function is invalid: {error}")))?;
                value(self.core.stack_variables(&program, function.as_ref()))
            }
            "type_graph" => {
                let program = string_param(params, "program")?;
                let (nodes, edges) = self.core.type_graph(&program)?;
                Ok(json!({"nodes": nodes, "edges": edges}))
            }
            "propagate_type_links" => {
                let program = string_param(params, "program")?;
                value(self.core.propagate_type_links(&program))
            }
            "trace_events" => {
                let program = string_param(params, "program")?;
                value(self.core.trace_events(
                    &program,
                    u64_param(params, "since")?.unwrap_or(0),
                    u64_param(params, "limit")?.unwrap_or(256),
                ))
            }
            "append_trace_event" => {
                let program = string_param(params, "program")?;
                let row: lre_model::TraceEvent = from_param(params, "event")?;
                value(self.core.append_trace_event(&program, &row))
            }
            "collab_ops" => {
                let program = string_param(params, "program")?;
                value(self.core.collaboration_ops(&program))
            }
            "append_collab_op" => {
                let program = string_param(params, "program")?;
                let row: lre_model::CollaborationOp = from_param(params, "operation")?;
                let op_id = row.op_id.clone();
                let inserted = self.core.append_collaboration_op(&program, &row)?;
                Ok(json!({"op_id": op_id, "inserted": inserted}))
            }
            "apply_collab_op" => {
                let program = string_param(params, "program")?;
                let op_id = string_param(params, "op_id")?;
                Ok(json!({
                    "op_id": op_id,
                    "applied": self.core.apply_collaboration_op(&program, &op_id)?,
                }))
            }
            "debug_backtrace" => debug_output(params, DebugCommand::Backtrace),
            "debug_registers" => debug_output(params, DebugCommand::Registers),
            "debug_memory" => {
                let address = u64_param(params, "address")?
                    .ok_or_else(|| DispatchError::Request("params.address is required".into()))?;
                let count = u32::try_from(
                    u64_param(params, "count")?
                        .ok_or_else(|| DispatchError::Request("params.count is required".into()))?,
                )
                .map_err(|_| DispatchError::Request("params.count is too large".into()))?;
                debug_output(params, DebugCommand::Memory { address, count })
            }
            "events_since" => {
                let program = string_param(params, "program")?;
                value(self.core.events_since(&program, u64_param(params, "since")?.unwrap_or(0)))
            }
            _ => Err(DispatchError::UnknownMethod(method.into())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum DispatchError {
    #[error("request: {0}")]
    Request(String),
    #[error("core: {0}")]
    Core(#[from] lre_core::CoreError),
    #[error("debugger: {0}")]
    Debugger(#[from] lre_debug::DebugError),
    #[error("unknown_method: {0}")]
    UnknownMethod(String),
}

impl DispatchError {
    fn code(&self) -> &'static str {
        match self {
            Self::Request(_) => "invalid_params",
            Self::Core(_) => "core_error",
            Self::Debugger(_) => "debugger_error",
            Self::UnknownMethod(_) => "unknown_method",
        }
    }
}

fn failure(id: Value, code: impl Into<String>, message: String) -> ResponseEnvelope {
    ResponseEnvelope {
        api: API_VERSION,
        id,
        result: None,
        error: Some(ErrorEnvelope {
            code: code.into(),
            message,
        }),
    }
}

fn value<T: Serialize, E: std::fmt::Display>(result: Result<T, E>) -> Result<Value, DispatchError> {
    let value = result.map_err(|error| DispatchError::Request(error.to_string()))?;
    serde_json::to_value(value)
        .map_err(|error| DispatchError::Request(format!("encode result: {error}")))
}

fn string_param(params: &Value, key: &str) -> Result<String, DispatchError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| DispatchError::Request(format!("params.{key} must be a string")))
}

fn path_param(params: &Value, key: &str) -> Result<PathBuf, DispatchError> {
    Ok(PathBuf::from(string_param(params, key)?))
}

fn u64_param(params: &Value, key: &str) -> Result<Option<u64>, DispatchError> {
    let Some(value) = params.get(key) else {
        return Ok(None);
    };
    if let Some(number) = value.as_u64() {
        return Ok(Some(number));
    }
    if let Some(string) = value.as_str() {
        return u64::from_str_radix(string.trim_start_matches("0x"), 16)
            .map(Some)
            .map_err(|error| DispatchError::Request(format!("params.{key} is not a number: {error}")));
    }
    Err(DispatchError::Request(format!(
        "params.{key} must be an unsigned integer"
    )))
}

fn address_param(params: &Value, key: &str) -> Result<Address, DispatchError> {
    let value = params
        .get(key)
        .ok_or_else(|| DispatchError::Request(format!("params.{key} is required")))?;
    serde_json::from_value(value.clone())
        .map_err(|error| DispatchError::Request(format!("params.{key} is invalid: {error}")))
}

fn from_param<T: for<'de> Deserialize<'de>>(
    params: &Value,
    key: &str,
) -> Result<T, DispatchError> {
    let value = params
        .get(key)
        .ok_or_else(|| DispatchError::Request(format!("params.{key} is required")))?;
    serde_json::from_value(value.clone())
        .map_err(|error| DispatchError::Request(format!("params.{key} is invalid: {error}")))
}

fn require_ram(address: &Address) -> Result<(), DispatchError> {
    if matches!(address.space, AddressSpace::Ram) {
        Ok(())
    } else {
        Err(DispatchError::Request(format!(
            "operation requires a RAM address: {address}"
        )))
    }
}

fn debug_output(params: &Value, command: DebugCommand) -> Result<Value, DispatchError> {
    let kind = BackendKind::parse(&string_param(params, "backend")?)?;
    let program = path_param(params, "program")?;
    let mut backend = DebugBackend::new(kind, &program)?;
    if let Some(timeout_ms) = u64_param(params, "timeout_ms")? {
        backend = backend.with_timeout(Duration::from_millis(timeout_ms))?;
    }
    let output = backend.execute(command)?;
    Ok(json!({
        "backend": params.get("backend").and_then(Value::as_str).unwrap_or_default(),
        "program": program,
        "stdout": output.stdout,
        "stderr": output.stderr,
    }))
}

/// Serves newline-delimited API envelopes over stdin/stdout.
pub fn serve_stdio(service: &ApiService) -> Result<(), ApiError> {
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout());
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        writeln!(stdout, "{}", service.handle_line(&line))?;
        stdout.flush()?;
    }
    Ok(())
}

/// Serves one versioned API endpoint per TCP connection. Requests are
/// ordinary HTTP/1.1 POSTs to `/v1`; the server is intended for localhost and
/// does not expose an authentication boundary by itself.
pub fn serve_tcp(service: &ApiService, listener: TcpListener) -> Result<(), ApiError> {
    for stream in listener.incoming() {
        let mut stream = stream?;
        if let Err(error) = handle_http(service, &mut stream) {
            let body = serde_json::to_string(&ResponseEnvelope {
                api: API_VERSION,
                id: Value::Null,
                result: None,
                error: Some(ErrorEnvelope {
                    code: "http_request".into(),
                    message: error.to_string(),
                }),
            })
            .unwrap_or_else(|_| format!("{{\"api\":{API_VERSION},\"id\":null}}"));
            let _ = write_http(&mut stream, "400 Bad Request", &body);
        }
    }
    Ok(())
}

fn handle_http(service: &ApiService, stream: &mut TcpStream) -> Result<(), ApiError> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    if !request_line.starts_with("POST /v1 ") {
        return Err(ApiError::Request("only POST /v1 is supported".into()));
    }
    let mut content_length = None;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header)?;
        if header == "\r\n" || header == "\n" {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = Some(value.trim().parse::<usize>().map_err(|error| {
                    ApiError::Request(format!("invalid content length: {error}"))
                })?);
            }
        }
    }
    let length = content_length.ok_or_else(|| ApiError::Request("missing content length".into()))?;
    if length > 4 * 1024 * 1024 {
        return Err(ApiError::Request("request body is too large".into()));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let response = service.handle_line(std::str::from_utf8(&body).map_err(|error| {
        ApiError::Request(format!("request body is not UTF-8: {error}"))
    })?);
    write_http(stream, "200 OK", &response)
}

fn write_http(stream: &mut TcpStream, status: &str, body: &str) -> Result<(), ApiError> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )?;
    stream.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn service() -> ApiService {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        ApiService::new(Core::open(Path::new(&format!(
            "/tmp/ventris-api-test-{nonce}"
        )))
        .unwrap())
    }

    #[test]
    fn ping_is_explicitly_versioned() {
        let response: Value = serde_json::from_str(
            &service().handle_line(r#"{"api":1,"id":7,"method":"ping","params":{}}"#),
        )
        .unwrap();
        assert_eq!(response["api"], 1);
        assert_eq!(response["id"], 7);
        assert_eq!(response["result"]["service"], "lre-core");
        assert!(response.get("error").is_none());
    }

    #[test]
    fn unsupported_versions_and_methods_are_structured_errors() {
        let service = service();
        for request in [
            r#"{"api":2,"id":"v","method":"ping","params":{}}"#,
            r#"{"api":1,"id":"m","method":"nope","params":{}}"#,
            "not-json",
        ] {
            let response: Value = serde_json::from_str(&service.handle_line(request)).unwrap();
            assert_eq!(response["api"], 1);
            assert!(response["error"]["code"].is_string());
            assert!(response.get("result").is_none());
        }
    }
    #[test]
    fn http_v1_roundtrip_uses_same_envelope() {
        let service = service();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            handle_http(&service, &mut stream).unwrap();
        });
        let body = r#"{"api":1,"id":"http","method":"ping","params":{}}"#;
        let mut client = TcpStream::connect(address).unwrap();
        write!(
            client,
            "POST /v1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        server.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains(r#""api":1"#));
        assert!(response.contains(r#""service":"lre-core""#));
    }

}
