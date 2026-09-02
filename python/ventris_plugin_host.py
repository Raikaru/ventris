#!/usr/bin/env python3
"""Run a Ventris plugin in a separate Python process with API capabilities.

A plugin is a Python file exporting ``main(api)``. The only project capability
provided by this host is ``api.call(method, **params)``; method access is
checked against the declared permission set before it reaches lre-api.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import pathlib
import runpy
import subprocess
import sys
from typing import Any, Mapping, Sequence

from ventris_sdk import ApiError, Client

_READ_METHODS = {
    "ping", "open", "functions", "functions_page", "symbols", "symbols_page",
    "xrefs", "xrefs_page", "comments", "datatypes", "strings", "search",
    "function_graph", "memory_regions", "memory", "listing", "disasm_native",
    "decompile_doc", "bookmarks", "patches", "type_defs", "type_fields",
    "prototypes", "stack_variables", "type_graph", "events_since",
    "debug_backtrace", "debug_registers", "debug_memory", "trace_events",
    "collab_ops",
}
_WRITE_METHODS = {
    "import_native", "rename", "comment", "undo", "set_bookmark", "set_patch",
    "replace_type_defs", "replace_type_fields", "replace_prototypes",
    "replace_stack_variables", "replace_type_links", "set_type_def",
    "set_type_field", "set_prototype", "set_stack_variable", "set_type_link",
    "propagate_type_links", "append_trace_event", "append_collab_op",
    "apply_collab_op",
}
_PERMISSION_METHODS = {
    "read": _READ_METHODS,
    "write": _WRITE_METHODS,
    "types": {
        "type_defs", "type_fields", "prototypes", "stack_variables", "type_graph",
        "replace_type_defs", "replace_type_fields", "replace_prototypes",
        "replace_stack_variables", "replace_type_links", "set_type_def",
        "set_type_field", "set_prototype", "set_stack_variable", "set_type_link",
        "propagate_type_links",
    },
    "native": {"import_native", "memory", "listing", "disasm_native", "decompile_doc"},
}


class PluginError(RuntimeError):
    pass


class PermissionedClient:
    def __init__(self, client: Client, permissions: Sequence[str]):
        unknown = set(permissions) - set(_PERMISSION_METHODS)
        if unknown:
            raise PluginError(f"unknown plugin permissions: {', '.join(sorted(unknown))}")
        self._client = client
        self._allowed = set().union(*(  # empty permissions intentionally grant nothing
            _PERMISSION_METHODS[name] for name in permissions
        )) if permissions else set()

    def call(self, method: str, **params: Any) -> Any:
        if method not in self._allowed:
            raise PluginError(f"plugin permission denied for {method!r}")
        return self._client.request(method, **params)


def _run_worker(
    plugin: pathlib.Path,
    project: str,
    permissions: Sequence[str],
    api_executable: str,
) -> int:
    with Client.stdio(project, api_executable) as client:
        api = PermissionedClient(client, permissions)
        with contextlib.redirect_stdout(io.StringIO()):
            namespace = runpy.run_path(str(plugin))
            entry = namespace.get("main")
            if not callable(entry):
                raise PluginError("plugin must export callable main(api)")
            result = entry(api)
        json.dump({"ok": True, "result": result}, sys.stdout)
        sys.stdout.write("\n")
    return 0


def run_plugin(
    plugin: str | pathlib.Path,
    project: str,
    permissions: Sequence[str] = ("read",),
    timeout: float = 30.0,
    executable: str = sys.executable,
    api_executable: str = "lre-api",
) -> Mapping[str, Any]:
    """Execute a plugin out-of-process and return its JSON result envelope."""
    path = pathlib.Path(plugin).resolve()
    if not path.is_file():
        raise PluginError(f"plugin does not exist: {path}")
    if timeout <= 0:
        raise PluginError("timeout must be positive")
    command = [
        executable,
        str(pathlib.Path(__file__).resolve()),
        "--worker",
        str(path),
        "--project",
        project,
        "--api-executable",
        api_executable,
    ]
    for permission in permissions:
        command.extend(["--permission", permission])
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise PluginError(f"plugin timed out after {timeout:g}s") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "plugin failed"
        raise PluginError(detail)
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise PluginError(f"plugin returned invalid JSON: {error}") from error
    if not result.get("ok"):
        raise PluginError(str(result.get("error", "plugin failed")))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a permissioned Ventris plugin")
    parser.add_argument("plugin", nargs="?", type=pathlib.Path)
    parser.add_argument("--project", default=".lre")
    parser.add_argument("--permission", action="append", default=None)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--api-executable", default="lre-api")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.plugin is None:
        parser.error("plugin is required")
    permissions = (
        args.permission
        if args.permission is not None
        else ([] if args.worker else ["read"])
    )
    try:
        if args.worker:
            return _run_worker(args.plugin, args.project, permissions, args.api_executable)
        result = run_plugin(
            args.plugin,
            args.project,
            permissions,
            args.timeout,
            api_executable=args.api_executable,
        )
        print(json.dumps(result, indent=2))
        return 0
    except (ApiError, PluginError) as error:
        print(f"ventris-plugin-host: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
