"""Dependency-free Python API and console entry point for Ventris."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Iterable, Mapping, Sequence


class VentrisError(RuntimeError):
    """Raised when the Rust Ventris process cannot complete a request."""

    def __init__(self, message: str, *, returncode: int | None = None, stderr: str = "") -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


def _binary(explicit: str | os.PathLike[str] | None = None) -> list[str]:
    value = explicit or os.environ.get("VENTRIS_BIN")
    if value:
        return [os.fspath(value)]

    for name in ("ventris-rs", "ventris-native"):
        found = shutil.which(name)
        if found:
            return [found]

    here = Path(__file__).resolve()
    workspace = next((parent for parent in here.parents if (parent / "Cargo.toml").is_file()), None)
    if workspace is not None:
        candidates = [
            workspace / "target" / "release" / ("ventris.exe" if os.name == "nt" else "ventris"),
            workspace / "target" / "debug" / ("ventris.exe" if os.name == "nt" else "ventris"),
        ]
        existing = [path for path in candidates if path.is_file()]
        if existing:
            newest = max(existing, key=lambda path: path.stat().st_mtime_ns)
            return [os.fspath(newest)]
        cargo = shutil.which("cargo")
        if cargo:
            return [cargo, "run", "--quiet", "-p", "ventris-cli", "--"]

    raise VentrisError(
        "Ventris Rust binary not found; set VENTRIS_BIN to a cargo-built ventris executable"
    )


def run(
    args: Sequence[str | os.PathLike[str]],
    *,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    input_text: str | None = None,
) -> str:
    """Run a Ventris command and return stdout as text.

    ``binary`` is optional; ``VENTRIS_BIN`` is useful for virtualenvs and CI.
    The Rust process owns parsing, errors, and output formatting.
    """

    command = _binary(binary) + [os.fspath(arg) for arg in args]
    completed = subprocess.run(
        command,
        input=input_text,
        cwd=os.fspath(cwd) if cwd is not None else None,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip() or "command failed"
        raise VentrisError(detail, returncode=completed.returncode, stderr=completed.stderr)
    return completed.stdout


def _address(address: int | str) -> str:
    return hex(address) if isinstance(address, int) else str(address)

def _image_options(
    command: list[str | os.PathLike[str]],
    *,
    loader: str | None,
    base: int | str | None,
    slice: int | str | None,
    target: str | None,
) -> None:
    if target is not None:
        command.extend(["--target", target])
    if loader is not None:
        command.extend(["--loader", loader])
    if base is not None:
        command.extend(["--base", _address(base)])
    if slice is not None:
        command.extend(["--slice", _address(slice)])

def version(
    *,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    return run(["version"], binary=binary, cwd=cwd)


def corpus(
    *,
    as_json: bool = False,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    """List source-backed cross-console corpus metadata."""
    command: list[str | os.PathLike[str]] = ["corpus"]
    if as_json:
        command.append("--json")
    return run(command, binary=binary, cwd=cwd)

def diff(
    before: str | os.PathLike[str],
    after: str | os.PathLike[str],
    *,
    target: str | None = None,
    loader: str | None = None,
    base: int | str | None = None,
    slice: int | str | None = None,
    region: str | None = None,
    as_json: bool = False,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    """Compare two binary revisions by named image regions."""
    command: list[str | os.PathLike[str]] = ["diff", before, after]
    _image_options(command, loader=loader, base=base, slice=slice, target=target)
    if region is not None:
        command.extend(["--region", region])
    if as_json:
        command.append("--json")
    return run(command, binary=binary, cwd=cwd)

def ingest_runtime(
    project: str | os.PathLike[str],
    trace: str | os.PathLike[str],
    *,
    as_json: bool = False,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    """Ingest a JSONL emulator trace into a persisted analysis project."""
    command: list[str | os.PathLike[str]] = ["project", "runtime", project, trace]
    if as_json:
        command.append("--json")
    return run(command, binary=binary, cwd=cwd)

def link_assets(
    project: str | os.PathLike[str],
    manifest: str | os.PathLike[str],
    *,
    as_json: bool = False,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    """Link discovered code references to an asset/script manifest."""
    command: list[str | os.PathLike[str]] = ["project", "assets", project, manifest]
    if as_json:
        command.append("--json")
    return run(command, binary=binary, cwd=cwd)

def discover(
    image: str | os.PathLike[str],
    *,
    arch: str | None = None,
    target: str | None = None,
    limit: int = 4096,
    as_json: bool = False,
    loader: str | None = None,
    base: int | str | None = None,
    slice: int | str | None = None,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    """Discover function boundaries and calls from a binary image."""
    if arch is None and target is None:
        raise ValueError("discover requires arch or target")
    command: list[str | os.PathLike[str]] = ["discover", image]
    if arch is not None:
        command.extend(["--arch", arch])
    _image_options(command, loader=loader, base=base, slice=slice, target=target)
    command.extend(["--limit", str(limit)])
    if as_json:
        command.append("--json")
    return run(command, binary=binary, cwd=cwd)


def inspect(
    image: str | os.PathLike[str],
    *,
    as_json: bool = False,
    loader: str | None = None,
    base: int | str | None = None,
    slice: int | str | None = None,
    target: str | None = None,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    command: list[str | os.PathLike[str]] = ["inspect", image]
    _image_options(command, loader=loader, base=base, slice=slice, target=target)
    if as_json:
        command.append("--json")
    return run(command, binary=binary, cwd=cwd)


def resolve(
    image: str | os.PathLike[str],
    address: int | str,
    *,
    as_json: bool = False,
    loader: str | None = None,
    base: int | str | None = None,
    slice: int | str | None = None,
    target: str | None = None,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    command: list[str | os.PathLike[str]] = ["resolve", image, _address(address)]
    _image_options(command, loader=loader, base=base, slice=slice, target=target)
    if as_json:
        command.append("--json")
    return run(command, binary=binary, cwd=cwd)



def lift(
    image: str | os.PathLike[str],
    address: int | str,
    *,
    arch: str | None = None,
    target: str | None = None,
    limit: int = 4096,
    raw: bool = False,
    as_json: bool = False,
    loader: str | None = None,
    base: int | str | None = None,
    slice: int | str | None = None,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    command: list[str | os.PathLike[str]] = ["lift", image, _address(address)]
    if arch is not None:
        command.extend(["--arch", arch])
    elif target is None:
        command.extend(["--arch", "x86_64"])
    command.extend(["--limit", str(limit)])
    _image_options(command, loader=loader, base=base, slice=slice, target=target)
    if raw:
        command.append("--raw")
    if as_json:
        command.append("--json")
    return run(command, binary=binary, cwd=cwd)


def decompile_native(
    image: str | os.PathLike[str],
    address: int | str,
    *,
    arch: str | None = None,
    target: str | None = None,
    limit: int = 4096,
    raw: bool = False,
    cache: str | os.PathLike[str] | None = None,
    as_json: bool = False,
    loader: str | None = None,
    base: int | str | None = None,
    slice: int | str | None = None,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    command: list[str | os.PathLike[str]] = [
        "decompile-native",
        image,
        _address(address),
    ]
    if arch is not None:
        command.extend(["--arch", arch])
    elif target is None:
        command.extend(["--arch", "x86_64"])
    command.extend(["--limit", str(limit)])
    _image_options(command, loader=loader, base=base, slice=slice, target=target)
    if raw:
        command.append("--raw")
    if cache is not None:
        command.extend(["--cache", cache])
    if as_json:
        command.append("--json")
    return run(command, binary=binary, cwd=cwd)

def decompile_project_function(
    project: str | os.PathLike[str],
    function: int | str,
    *,
    arch: str | None = None,
    target: str | None = None,
    limit: int = 4096,
    cache: str | os.PathLike[str] | None = None,
    as_json: bool = False,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    """Decompile a function record persisted by project analysis."""
    if arch is None and target is None:
        raise ValueError("decompile_project_function requires arch or target")
    command: list[str | os.PathLike[str]] = [
        "decompile-native",
        "--project",
        project,
        "--function",
        _address(function),
    ]
    if arch is not None:
        command.extend(["--arch", arch])
    if target is not None:
        command.extend(["--target", target])
    command.extend(["--limit", str(limit)])
    if cache is not None:
        command.extend(["--cache", cache])
    if as_json:
        command.append("--json")
    return run(command, binary=binary, cwd=cwd)
def project_references(
    project: str | os.PathLike[str],
    address: int | str,
    *,
    incoming: bool = False,
    outgoing: bool = False,
    as_json: bool = False,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    """List incoming and/or outgoing project references at an address."""
    command: list[str | os.PathLike[str]] = [
        "project",
        "refs",
        project,
        _address(address),
    ]
    if incoming:
        command.append("--incoming")
    if outgoing:
        command.append("--outgoing")
    if as_json:
        command.append("--json")
    return run(command, binary=binary, cwd=cwd)



def recover_types(
    image: str | os.PathLike[str],
    address: int | str,
    *,
    target: str,
    metadata: str | os.PathLike[str] | None = None,
    loader: str | None = None,
    base: int | str | None = None,
    slice: int | str | None = None,
    limit: int = 4096,
    raw: bool = False,
    as_json: bool = False,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    """Recover console ABI facts and evidence-backed field candidates."""
    command = ["recover-types", os.fspath(image), _address(address)]
    _image_options(
        command,
        loader=loader,
        base=base,
        slice=slice,
        target=target,
    )
    if metadata is not None:
        command.extend(["--metadata", os.fspath(metadata)])
    command.extend(["--limit", str(limit)])
    if raw:
        command.append("--raw")
    if as_json:
        command.append("--json")
    return run(command, binary=binary, cwd=cwd)


def reconstruct_source(
    image: str | os.PathLike[str],
    address: int | str,
    *,
    target: str,
    metadata: str | os.PathLike[str] | None = None,
    loader: str | None = None,
    base: int | str | None = None,
    slice: int | str | None = None,
    limit: int = 4096,
    raw: bool = False,
    cache: str | os.PathLike[str] | None = None,
    as_json: bool = False,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    """Render a native function with recovered game structs and diagnostics."""
    command = ["reconstruct-source", os.fspath(image), _address(address)]
    _image_options(
        command,
        loader=loader,
        base=base,
        slice=slice,
        target=target,
    )
    if metadata is not None:
        command.extend(["--metadata", os.fspath(metadata)])
    command.extend(["--limit", str(limit)])
    if raw:
        command.append("--raw")
    if cache is not None:
        command.extend(["--cache", os.fspath(cache)])
    if as_json:
        command.append("--json")
    return run(command, binary=binary, cwd=cwd)


def batch(
    requests: str | os.PathLike[str] | Iterable[Mapping[str, object]],
    *,
    cache: str | os.PathLike[str] | None = None,
    output: str | os.PathLike[str] | None = None,
    binary: str | os.PathLike[str] | None = None,
    cwd: str | os.PathLike[str] | None = None,
) -> str:
    command: list[str | os.PathLike[str]] = ["batch"]
    input_text = None
    if isinstance(requests, (str, os.PathLike)):
        command.extend(["--input", requests])
    else:
        command.extend(["--input", "-"])
        input_text = "".join(
            json.dumps(dict(request), default=os.fspath, separators=(",", ":")) + "\n"
            for request in requests
        )
    if cache is not None:
        command.extend(["--cache", cache])
    if output is not None:
        command.extend(["--output", output])
    return run(command, binary=binary, cwd=cwd, input_text=input_text)


def main(argv: Iterable[str] | None = None) -> int:
    """Forward console arguments to Rust while preserving stdout/stderr."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        command = _binary() + arguments
    except VentrisError as error:
        print(str(error), file=sys.stderr)
        return 127
    completed = subprocess.run(command, text=True, check=False)
    return completed.returncode
