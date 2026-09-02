"""Small dependency-free client for the versioned Ventris API.

The client uses the same JSON envelope over either the local ``lre-api``
stdio service or an HTTP ``/v1`` endpoint. It does not maintain a second
project model; responses are the Core service's serialized rows.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import subprocess
import threading
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

API_VERSION = 1


class ApiError(RuntimeError):
    """A version, transport, or Core API failure."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class _Transport:
    def request(self, envelope: Mapping[str, Any]) -> Mapping[str, Any]:
        raise NotImplementedError

    def close(self) -> None:
        pass


class _StdioTransport(_Transport):
    def __init__(self, command: Sequence[str]):
        self._process = subprocess.Popen(
            list(command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            bufsize=1,
        )
        self._lock = threading.Lock()

    def request(self, envelope: Mapping[str, Any]) -> Mapping[str, Any]:
        with self._lock:
            if self._process.poll() is not None:
                raise ApiError("transport", "lre-api process exited")
            assert self._process.stdin is not None
            assert self._process.stdout is not None
            self._process.stdin.write(json.dumps(envelope, separators=(",", ":")) + "\n")
            self._process.stdin.flush()
            line = self._process.stdout.readline()
            if not line:
                raise ApiError("transport", "lre-api returned no response")
        try:
            return json.loads(line)
        except json.JSONDecodeError as error:
            raise ApiError("transport", f"invalid API response: {error}") from error

    def close(self) -> None:
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()


class _HttpTransport(_Transport):
    def __init__(self, url: str, timeout: float):
        self._url = url.rstrip("/") + "/v1"
        self._timeout = timeout

    def request(self, envelope: Mapping[str, Any]) -> Mapping[str, Any]:
        body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        request = Request(
            self._url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urlopen(request, timeout=self._timeout) as response:
                payload = response.read()
        except (HTTPError, URLError, TimeoutError) as error:
            raise ApiError("transport", str(error)) from error
        try:
            return json.loads(payload)
        except json.JSONDecodeError as error:
            raise ApiError("transport", f"invalid API response: {error}") from error


@dataclass
class Client:
    """Thread-safe request client for one API service."""

    _transport: _Transport
    _next_id: int = 1
    _id_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    @classmethod
    def stdio(cls, project: str, executable: str = "lre-api") -> "Client":
        return cls(_StdioTransport([executable, "--project", project]))

    @classmethod
    def http(cls, url: str = "http://127.0.0.1:8765", timeout: float = 30.0) -> "Client":
        return cls(_HttpTransport(url, timeout))

    def request(self, method: str, **params: Any) -> Any:
        with self._id_lock:
            request_id = self._next_id
            self._next_id += 1
        response = self._transport.request(
            {"api": API_VERSION, "id": request_id, "method": method, "params": params}
        )
        if response.get("api") != API_VERSION:
            raise ApiError("protocol", f"unexpected API version {response.get('api')!r}")
        if response.get("id") != request_id:
            raise ApiError("protocol", f"unexpected response id {response.get('id')!r}")
        error = response.get("error")
        if error is not None:
            raise ApiError(str(error.get("code", "api_error")), str(error.get("message", error)))
        return response.get("result")

    def close(self) -> None:
        self._transport.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def ping(self) -> Any:
        return self.request("ping")

    def open(self, program: str) -> Any:
        return self.request("open", program=program)

    def import_native(self, binary: str, name: str = "program") -> Any:
        return self.request("import_native", binary=binary, name=name)

    def functions(self, program: str) -> Any:
        return self.request("functions", program=program)

    def symbols(self, program: str) -> Any:
        return self.request("symbols", program=program)

    def xrefs(self, program: str, address: Any, incoming: bool = True) -> Any:
        return self.request("xrefs", program=program, address=address, incoming=incoming)

    def strings(self, program: str) -> Any:
        return self.request("strings", program=program)

    def search(self, program: str, term: str, limit: int = 256) -> Any:
        return self.request("search", program=program, term=term, limit=limit)

    def decompile(self, binary: str, program: str, address: Any, base: int | None = None) -> Any:
        params: dict[str, Any] = {"binary": binary, "program": program, "address": address}
        if base is not None:
            params["base"] = base
        return self.request("decompile_doc", **params)

    def debug_backtrace(
        self, program: str, backend: str = "gdb", timeout_ms: int | None = None
    ) -> Any:
        return self._debug("debug_backtrace", program, backend, timeout_ms)

    def debug_registers(
        self, program: str, backend: str = "gdb", timeout_ms: int | None = None
    ) -> Any:
        return self._debug("debug_registers", program, backend, timeout_ms)

    def debug_memory(
        self,
        program: str,
        address: int,
        count: int,
        backend: str = "gdb",
        timeout_ms: int | None = None,
    ) -> Any:
        params: dict[str, Any] = {
            "program": program,
            "backend": backend,
            "address": address,
            "count": count,
        }
        if timeout_ms is not None:
            params["timeout_ms"] = timeout_ms
        return self.request("debug_memory", **params)

    def _debug(
        self, method: str, program: str, backend: str, timeout_ms: int | None
    ) -> Any:
        params: dict[str, Any] = {"program": program, "backend": backend}
        if timeout_ms is not None:
            params["timeout_ms"] = timeout_ms
        return self.request(method, **params)

    def trace_events(self, program: str, since: int = 0, limit: int = 256) -> Any:
        return self.request("trace_events", program=program, since=since, limit=limit)

    def append_trace_event(self, program: str, event: Mapping[str, Any]) -> Any:
        return self.request("append_trace_event", program=program, event=dict(event))

    def collaboration_ops(self, program: str) -> Any:
        return self.request("collab_ops", program=program)

    def append_collaboration_op(self, program: str, operation: Mapping[str, Any]) -> Any:
        return self.request("append_collab_op", program=program, operation=dict(operation))

    def apply_collaboration_op(self, program: str, op_id: str) -> Any:
        return self.request("apply_collab_op", program=program, op_id=op_id)

    def rename(self, program: str, address: Any, name: str) -> Any:
        return self.request("rename", program=program, address=address, name=name)

    def comment(self, program: str, address: Any, text: str, kind: str = "eol") -> Any:
        return self.request("comment", program=program, address=address, text=text, kind=kind)

    def undo(self, program: str) -> Any:
        return self.request("undo", program=program)

    def types(self, program: str) -> Any:
        return self.request("type_defs", program=program)

    def type_fields(self, program: str, type_name: str | None = None) -> Any:
        params: dict[str, Any] = {"program": program}
        if type_name is not None:
            params["type_name"] = type_name
        return self.request("type_fields", **params)

    def type_graph(self, program: str) -> Any:
        return self.request("type_graph", program=program)
