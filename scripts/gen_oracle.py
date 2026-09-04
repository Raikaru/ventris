#!/usr/bin/env python3
"""m1-007: SHA-keyed bridge function references for the 20 ELF corpus entries.

Addresses remain in Ghidra's coordinate system; image_base is recorded explicitly.
This is an oracle-generation gate, not a discovery precision/recall score.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BRIDGE_SOURCE = ROOT / "service/src/main/java/net/ventris"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def provenance(install):
    properties = dict(line.split("=", 1) for line in
                      (install / "Ghidra/application.properties").read_text().splitlines()
                      if "=" in line and not line.startswith("#"))
    if properties["application.version"] != "12.1.3":
        raise ValueError("Oracle requires pinned Ghidra 12.1.3")
    source_hash = hashlib.sha256()
    for path in sorted(BRIDGE_SOURCE.glob("*.java")):
        source_hash.update(path.name.encode() + b"\0" + path.read_bytes())
    return {"producer": "ghidra-bridge", "upstream_version": properties["application.version"],
            "upstream_revision": properties["application.revision.ghidra"],
            "bridge_sources_sha256": source_hash.hexdigest(),
            "analysis": "GhidraProject.analyze:defaults", "language_selection": "automatic"}


def address(text):
    if not isinstance(text, str) or not re.fullmatch(r"(?:ram:)?[0-9a-fA-F]+", text):
        raise ValueError(f"Unsupported oracle address: {text!r}")
    return format(int(text.removeprefix("ram:"), 16), "08x")


def validate_reference(reference, expected):
    if not isinstance(reference, dict):
        raise ValueError("Oracle reference must be a JSON object")
    for key, value in expected.items():
        if reference.get(key) != value:
            raise ValueError(f"Oracle {key} mismatch")
    if not isinstance(reference.get("language"), str) or not reference["language"]:
        raise ValueError("Oracle analysis language missing")
    entries = reference["entries"]
    if not isinstance(entries, list) or not entries:
        raise ValueError("Oracle has no function entries")
    if entries != sorted({address(entry) for entry in entries}, key=lambda entry: int(entry, 16)):
        raise ValueError("Oracle entries are not canonical, unique and sorted")
    if reference["imported_function_count"] != len(entries):
        raise ValueError("Oracle import/export function counts disagree")
    if address(reference["image_base"]) != reference["image_base"]:
        raise ValueError("Oracle image base is not canonical")


def bridge_command(install, java):
    # Rebuild current bridge sources once per generation run, never trust a stale jar.
    subprocess.run(["sh", str(ROOT / "service/build.sh"), str(install)], cwd=ROOT,
                   check=True, capture_output=True, text=True, timeout=120)
    jars = sorted(path for path in (install / "Ghidra").rglob("*.jar")
                  if not any(part.startswith("Extension") for part in path.parts))
    if not jars:
        raise ValueError("Ghidra runtime jars missing")
    jars.append(ROOT / "service/build/ventris-service.jar")
    # Same module opens as lre-cli::jvm_opens; the existing bridge owns analysis.
    opens = [f"--add-opens=java.base/{name}=ALL-UNNAMED" for name in
             ("java.lang", "java.lang.invoke", "java.lang.ref", "java.util", "java.io")]
    return [java, *opens, "--add-opens=java.desktop/java.awt=ALL-UNNAMED",
            "-Djava.awt.headless=true", "-cp", os.pathsep.join(map(str, jars)),
            "net.ventris.Main", "--install-dir", str(install)]


def generate_reference(command, binary, expected, timeout):
    requests = [
        {"id": 1, "method": "import", "params": {"session": "oracle", "path": str(binary)}},
        {"id": 2, "method": "functions", "params": {"session": "oracle"}},
        {"id": 3, "method": "close", "params": {"session": "oracle"}},
    ]
    # One isolated project per input. EOF invokes the bridge's existing shutdown path.
    with tempfile.TemporaryDirectory(prefix="m1-007-project-") as project:
        result = subprocess.run(command + ["--project-dir", project],
                                input="".join(json.dumps(row) + "\n" for row in requests),
                                capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise ValueError(f"Bridge exited {result.returncode}: {result.stderr[-1000:]}")
    replies = {}
    for line in result.stdout.splitlines():
        if not line.strip().startswith("{"):
            continue  # Same allowance for Ghidra diagnostics as the existing Rust client.
        reply = json.loads(line)
        if reply.get("id") in (1, 2, 3):
            if reply["id"] in replies:
                raise ValueError("Duplicate bridge reply")
            if "error" in reply:
                raise ValueError(f"Bridge RPC error: {reply['error']}")
            replies[reply["id"]] = reply["result"]
    if set(replies) != {1, 2, 3} or replies[3].get("ok") is not True:
        raise ValueError("Incomplete bridge response")
    imported = replies[1]
    reference = {**expected, "language": imported["language"],
                 "image_base": address(imported["image_base"]),
                 "imported_function_count": imported["functions"],
                 "entries": sorted((address(row["entry"]) for row in replies[2]),
                                   key=lambda entry: int(entry, 16))}
    validate_reference(reference, expected)
    return reference


def write_reference(path, reference):
    # Never expose partial JSON or replace an old reference until analysis succeeds.
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as output:
        pending = Path(output.name)
        try:
            json.dump(reference, output, indent=2)
            output.write("\n")
            output.close()
            pending.replace(path)
        finally:
            pending.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "oracle")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path, default=Path(os.environ.get(
        "VENTRIS_GHIDRA", str(Path.home() / "ghidra_12.1.3_PUBLIC"))))
    parser.add_argument("--java", default="java")
    parser.add_argument("--timeout", type=int, default=180, help="Per-binary bridge timeout in seconds")
    parser.add_argument("--check", action="store_true", help="Validate existing references without launching Java")
    args = parser.parse_args()
    args.corpus_dir = args.corpus_dir.resolve()
    args.ghidra = args.ghidra.resolve()
    lock = json.loads((ROOT / "tests/corpus.lock.json").read_text())
    required = {(row["architecture"], row["variant"]): row
                for row in lock["entries"] if row["format"] == "elf"}
    if len(required) != 20:
        raise ValueError("m1-007 requires the 20-entry ELF matrix")
    setup_error = None
    actual = {}
    try:
        manifest = json.loads((args.corpus_dir / "manifest.json").read_text())
        if manifest["sources"] != lock["sources"]:
            raise ValueError("Corpus source manifest mismatch")
        for name, info in lock["sources"].items():
            if digest(ROOT / "tests/corpus-src" / name) != info["sha256"]:
                raise ValueError(f"Corpus source changed: {name}")
        for row in manifest["entries"]:
            key = (row["architecture"], row["variant"])
            if key in actual:
                raise ValueError(f"Duplicate corpus entry: {key}")
            actual[key] = row
        if set(actual) - {(row["architecture"], row["variant"]) for row in lock["entries"]}:
            raise ValueError("Unknown corpus entries")
        producer = provenance(args.ghidra)
    except (OSError, ValueError, KeyError) as error:
        setup_error = str(error)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows, command = [], None
    hits = generated = 0
    for key, recipe in required.items():
        row = {"id": "_".join(key), "sha256": None, "status": "skipped",
               "metrics": {}, "thresholds": {}, "runs": 1}
        try:
            if setup_error:
                raise ValueError(setup_error)
            item = actual.get(key)
            if not item or item.get("status") != "ok":
                raise ValueError("Corpus binary missing or skipped in manifest")
            if item["binary"] != recipe["binary"] or item["command"] != recipe["command"]:
                raise ValueError("Corpus primary/recipe mismatch")
            binary = args.corpus_dir / recipe["binary"]
            if not binary.is_file():
                raise ValueError(f"Primary binary missing: {binary.name}")
            sha = digest(binary)
            row["sha256"] = sha
            if sha != item["binary_sha256"]:
                raise ValueError("Primary binary SHA-256 mismatch")
            expected = {"schema_version": 1, "sha256": sha, "binary_size": binary.stat().st_size,
                        **producer, "address_basis": "ghidra"}
            cache = args.output_dir / f"{sha}.json"
            try:
                reference = json.loads(cache.read_text())
                validate_reference(reference, expected)
                hits += 1
                source = "hit"
            except (OSError, ValueError, KeyError, TypeError) as error:
                if args.check:
                    raise ValueError(f"Missing or invalid oracle cache: {error}") from error
                if command is None:
                    command = bridge_command(args.ghidra, args.java)
                reference = generate_reference(command, binary, expected, args.timeout)
                if digest(binary) != sha:
                    raise ValueError("Primary changed during analysis")
                write_reference(cache, reference)
                generated += 1
                source = "generated"
            row.update(status="pass", functions=len(reference["entries"]), cache=source,
                       oracle=f"oracle/{cache.name}", oracle_sha256=digest(cache))
            print(f"PASS {row['id']}: {len(reference['entries'])} functions ({source})", flush=True)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            row["reason"] = str(error)
            print(f"SKIPPED {row['id']}: {error}", flush=True)
        rows.append(row)
    summary = {status: sum(row["status"] == status for row in rows)
               for status in ("pass", "fail", "skipped")}
    report = {"gate": "m1-007", "milestone": "M1",
              "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "date": datetime.now(timezone.utc).date().isoformat(),
              "machine": {"os": platform.platform(), "cpu": platform.machine(),
                          "ram_gb": round(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / 2**30, 2)},
              "corpus": rows, "summary": summary, "passed": summary["pass"] == 20,
              "cache_hits": hits, "generated": generated}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"summary": summary, "passed": report["passed"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
