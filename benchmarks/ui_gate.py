#!/usr/bin/env python3
"""Run the offscreen Qt UI gate and write the frozen gate report schema."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


NUMERIC_METRICS = (
    "ui.list.load_ms",
    "ui.list.filter_ms",
    "ui.sync_ms",
    "ui.graph.layout_ms",
    "ui.graph.paint_ms",
)
ALL_METRICS = (*NUMERIC_METRICS, "ui.install.ok")
THRESHOLDS = {
    "ui.list.load_ms": 500.0,
    "ui.list.filter_ms": 100.0,
    "ui.sync_ms": 16.0,
    "ui.graph.layout_ms": 200.0,
    "ui.graph.paint_ms": 50.0,
}


class GateError(RuntimeError):
    """The app did not produce a usable UI gate sample."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def physical_memory_gb() -> float:
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (AttributeError, OSError, ValueError):
        return 0.0
    if pages <= 0 or page_size <= 0:
        return 0.0
    return round((pages * page_size) / (1024**3), 2)


def build_date() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is not None:
        try:
            return dt.datetime.fromtimestamp(int(epoch), dt.timezone.utc).date().isoformat()
        except (ValueError, OverflowError, OSError):
            pass
    return dt.datetime.now(dt.timezone.utc).date().isoformat()


def git_commit(root: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    commit = result.stdout.strip()
    if result.returncode != 0 or len(commit) != 40:
        raise GateError("cannot determine repository commit")
    return commit


def default_binary() -> Path:
    configured = os.environ.get("VENTRIS_UI_BINARY")
    candidates = [
        Path(configured) if configured else None,
        Path("/usr/lib64/libc.so.6"),
        Path("/usr/lib/x86_64-linux-gnu/libc.so.6"),
        Path("/lib/x86_64-linux-gnu/libc.so.6"),
    ]
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate
    raise GateError("no libc binary found; pass --binary")


def default_app(root: Path) -> Path:
    configured = os.environ.get("VENTRIS_QT_APP")
    candidates = [
        Path(configured) if configured else None,
        root / "build" / "ventris-qt" / "ventris-qt",
        root / "desktop" / "ventris-qt" / "build" / "ventris-qt",
    ]
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate
    raise GateError("no Qt app found; pass --app or set VENTRIS_QT_APP")


def parse_metrics(stdout: str) -> dict[str, Any]:
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        metrics = payload.get("metrics", payload)
        if isinstance(metrics, dict):
            return metrics
    raise GateError("Qt gate output did not contain a JSON metrics object")


def validate_metrics(metrics: dict[str, Any]) -> None:
    missing = [metric for metric in ALL_METRICS if metric not in metrics]
    if missing:
        raise GateError(f"Qt gate output missing metrics: {', '.join(missing)}")
    invalid = [
        metric
        for metric in NUMERIC_METRICS
        if isinstance(metrics[metric], bool) or not isinstance(metrics[metric], (int, float))
    ]
    if invalid:
        raise GateError(f"Qt gate numeric metrics are invalid: {', '.join(invalid)}")
    if not isinstance(metrics["ui.install.ok"], bool):
        raise GateError("Qt gate ui.install.ok must be boolean")


def run_app(
    app: Path,
    project: Path,
    binary: Path,
    program: str,
    address: str,
    timeout: float,
) -> dict[str, Any]:
    command = [
        str(app),
        "--gate",
        "--project",
        str(project),
        "--name",
        program,
        "--binary",
        str(binary),
        "--address",
        address,
    ]
    env = os.environ.copy()
    env["QT_QPA_PLATFORM"] = "offscreen"
    root = Path(__file__).resolve().parent.parent
    env.setdefault("VENTRIS_SPECS", str(root / "native" / "specs"))
    env.setdefault("VENTRIS_GHIDRA_OPT", str(root / "native" / "build" / "ghidra_opt"))
    env.setdefault("VENTRIS_LANGUAGE", "x86:LE:64:default")
    env.setdefault("VENTRIS_CONSOLE", str(root / "native" / "build" / "decomp_native"))
    env.setdefault(
        "VENTRIS_SLA",
        str(Path(os.environ.get("VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC")))
            / "Ghidra" / "Processors" / "x86" / "data" / "languages" / "x86-64.sla"),
    )
    result = subprocess.run(
        command,
        cwd=app.parent,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise GateError(f"Qt gate exited {result.returncode}: {detail[-1000:]}")
    metrics = parse_metrics(result.stdout)
    validate_metrics(metrics)
    return metrics


def median(values: list[float]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def aggregate(samples: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        **{metric: median([float(sample[metric]) for sample in samples]) for metric in NUMERIC_METRICS},
        "ui.install.ok": all(sample["ui.install.ok"] for sample in samples),
    }


def report_document(
    root: Path,
    binary: Path,
    program: str,
    metrics: dict[str, Any],
    runs: int,
    status: str,
) -> dict[str, Any]:
    corpus: dict[str, Any] = {
        "id": program,
        "sha256": sha256(binary),
        "status": status,
        "metrics": metrics,
        "thresholds": THRESHOLDS,
        "runs": runs,
    }
    summary = {
        "pass": int(status == "pass"),
        "fail": int(status == "fail"),
        "skipped": 0,
    }
    return {
        "gate": "ui",
        "milestone": "M0",
        "commit": git_commit(root),
        "date": build_date(),
        "machine": {
            "os": platform.platform(aliased=True),
            "cpu": platform.processor() or platform.machine() or "unknown",
            "ram_gb": physical_memory_gb(),
        },
        "corpus": [corpus],
        "summary": summary,
        "passed": status == "pass",
    }


def write_report(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, help="Qt executable; defaults to VENTRIS_QT_APP or build/ventris-qt")
    parser.add_argument("--binary", type=Path, help="corpus binary; defaults to libc")
    parser.add_argument("--project", type=Path, help="project directory passed to the Qt app")
    parser.add_argument("--program", default=os.environ.get("VENTRIS_UI_PROGRAM", "libc"))
    parser.add_argument("--address", default=os.environ.get("VENTRIS_UI_ADDRESS", "00400466"))
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "benchmarks" / "reports" / "ui-gate.json",
    )
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be at least 1")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    try:
        app = (args.app or default_app(root)).resolve()
        binary = (args.binary or default_binary()).resolve()
        if not app.is_file():
            raise GateError(f"Qt app does not exist: {app}")
        if not binary.is_file():
            raise GateError(f"corpus binary does not exist: {binary}")
        if args.project is None:
            with tempfile.TemporaryDirectory(prefix="ventris-ui-gate-") as directory:
                project = Path(directory)
                samples = [
                    run_app(app, project, binary, args.program, args.address, args.timeout)
                    for _ in range(args.runs)
                ]
        else:
            project = args.project.resolve()
            project.mkdir(parents=True, exist_ok=True)
            samples = [
                run_app(app, project, binary, args.program, args.address, args.timeout)
                for _ in range(args.runs)
            ]
        metrics = aggregate(samples)
        within_thresholds = all(
            metrics[metric] <= THRESHOLDS[metric] for metric in NUMERIC_METRICS
        )
        status = "pass" if within_thresholds and metrics["ui.install.ok"] else "fail"
        document = report_document(root, binary, args.program, metrics, len(samples), status)
    except (GateError, OSError, subprocess.SubprocessError) as error:
        try:
            binary = (args.binary or default_binary()).resolve()
            if not binary.is_file():
                raise GateError(str(error))
            document = report_document(
                root,
                binary,
                args.program,
                {},
                0,
                "fail",
            )
        except (GateError, OSError) as report_error:
            print(f"ui gate: {report_error}", file=sys.stderr)
            return 2
        write_report(args.output.resolve(), document)
        print(json.dumps(document, indent=2))
        return 1

    write_report(args.output.resolve(), document)
    print(json.dumps(document, indent=2))
    return 0 if document["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
