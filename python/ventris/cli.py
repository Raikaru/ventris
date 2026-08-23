"""Dependency-free Python adapter for Ventris's function pipeline."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Sequence


class VentrisError(RuntimeError):
    """Raised when the Ventris process cannot complete a request."""

    def __init__(
        self,
        message: str,
        *,
        returncode: int | None = None,
        stderr: str = "",
    ) -> None:
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr


def _binary(explicit: str | os.PathLike[str] | None = None) -> list[str]:
    if explicit is not None:
        return [os.fspath(explicit)]
    value = os.environ.get("VENTRIS_BIN", "ventris")
    found = shutil.which(value)
    if found:
        return [found]

    here = Path(__file__).resolve()
    workspace = next(
        (parent for parent in here.parents if (parent / "Cargo.toml").is_file()),
        None,
    )
    if workspace is not None:
        executable = "ventris.exe" if os.name == "nt" else "ventris"
        candidates = [
            workspace / "target" / "release" / executable,
            workspace / "target" / "debug" / executable,
        ]
        existing = [path for path in candidates if path.is_file()]
        if existing:
            newest = max(existing, key=lambda path: path.stat().st_mtime_ns)
            return [os.fspath(newest)]
        if shutil.which("cargo"):
            return ["cargo", "run", "--quiet", "-p", "ventris-cli", "--"]

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
    """Run Ventris and return stdout exactly as emitted."""

    command = _binary(binary) + [os.fspath(argument) for argument in args]
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
        raise VentrisError(
            detail,
            returncode=completed.returncode,
            stderr=completed.stderr,
        )
    return completed.stdout


def _address(value: int | str) -> str:
    return hex(value) if isinstance(value, int) else str(value)


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
    if arch is None and target is None:
        raise ValueError("lift requires arch or target")
    command: list[str | os.PathLike[str]] = ["lift", image, _address(address)]
    if arch is not None:
        command.extend(["--arch", arch])
    command.extend(["--limit", str(limit)])
    _image_options(command, loader=loader, base=base, slice=slice, target=target)
    if raw:
        command.append("--raw")
    if as_json:
        command.append("--json")
    return run(command, binary=binary, cwd=cwd)


def decompile(
    image: str | os.PathLike[str],
    address: int | str,
    *,
    arch: str | None = None,
    target: str | None = None,
    metadata: str | os.PathLike[str] | None = None,
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
    if arch is None and target is None:
        raise ValueError("decompile requires arch or target")
    if metadata is not None and target is None:
        raise ValueError("decompile metadata requires target")
    command: list[str | os.PathLike[str]] = ["decompile", image, _address(address)]
    if arch is not None:
        command.extend(["--arch", arch])
    _image_options(command, loader=loader, base=base, slice=slice, target=target)
    if metadata is not None:
        command.extend(["--metadata", metadata])
    command.extend(["--limit", str(limit)])
    if raw:
        command.append("--raw")
    if cache is not None:
        command.extend(["--cache", cache])
    if as_json:
        command.append("--json")
    return run(command, binary=binary, cwd=cwd)


def main(argv: Sequence[str] | None = None) -> int:
    """Forward command-line arguments to Rust while preserving process output."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        command = _binary() + arguments
    except VentrisError as error:
        print(str(error), file=sys.stderr)
        return 127
    completed = subprocess.run(command, text=True, check=False)
    return completed.returncode
