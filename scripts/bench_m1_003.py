#!/usr/bin/env python3
"""m1-003-d benchmark: 3-run median load_native wall time for hand vs console
x86-64 discovery, plus precision/recall vs the Ghidra oracle. Writes
benchmarks/reports/m1-003.json and updates STATUS.md with the keep/delete
decision for disasm.rs.
"""
import json
import hashlib
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent.resolve()
REPORT = ROOT / "benchmarks" / "reports" / "m1-003.json"
STATUS = ROOT / "STATUS.md"
EXAMPLE = "bench_load_native"
CC = os.environ.get("CC", "cc")
CXX = os.environ.get("CXX", "c++")
RUNS = 3


def run(cmd, **kw):
    print(f"+ {' '.join(str(c) for c in cmd)}")
    return subprocess.run(cmd, check=True, **kw)


def example_bin(profile: str, features: str) -> Path:
    """Return the path to the compiled bench_load_native example."""
    target = "release" if profile == "release" else "debug"
    return ROOT / "target" / target / "examples" / EXAMPLE


def build_example(profile: str, hand: bool) -> Path:
    cargo = ["cargo", "build", "-p", "lre-core", "--example", EXAMPLE]
    if profile == "release":
        cargo.append("--release")
    if hand:
        cargo.extend(["--features", "x86_decoder"])
    else:
        cargo.append("--no-default-features")
    run(cargo, cwd=ROOT)
    return example_bin(profile, "hand" if hand else "console")


def build_fixtures(tmp: Path) -> dict:
    """Build the same x86-64 corpus fixtures as tests/corpus.sh."""
    plain_c = tmp / "plain.c"
    plain_c.write_text(
        '#include <stdio.h>\n'
        '#include <string.h>\n'
        'static int sum(int n){int s=0;for(int i=0;i<n;i++)s+=i;return s;}\n'
        'int main(void){char b[64];memset(b,0,64);strcpy(b,"hello");'
        'printf("%d %s\\n",sum(10),b);return 0;}\n'
    )

    src_cpp = tmp / "src.cpp"
    src_cpp.write_text(
        '#include <cstdio>\n'
        '#include <vector>\n'
        '#include <stdexcept>\n'
        '#include <string>\n'
        '#include <map>\n'
        'static __thread int tls_counter;\n'
        'static std::vector<std::string> texts;\n'
        'static std::map<int, std::string> by_id;\n'
        'static int classify(int v) {\n'
        '    switch (v) {\n'
        '        case 0: return 10; case 1: return 20; case 2: return 30;\n'
        '        case 3: return 40; case 4: return 50; case 5: return 60;\n'
        '        case 6: return 70; case 7: return 80; case 8: return 90;\n'
        '        default: return -1;\n'
        '    }\n'
        '}\n'
        'static int work(int n) {\n'
        '    if (n < 0) throw std::runtime_error("negative");\n'
        '    try {\n'
        '        for (int i = 0; i < n; i++) { tls_counter += classify(i % 9); texts.push_back("x"); }\n'
        '    } catch (...) { return -2; }\n'
        '    by_id[1] = "one";\n'
        '    return tls_counter + (int)texts.size();\n'
        '}\n'
        'int main() {\n'
        '    int r = work(64);\n'
        '    std::printf("%d\\n", r);\n'
        '    return 0;\n'
        '}\n'
    )

    many_c = tmp / "many.c"
    many_c.write_text("#include <stdio.h>\n")
    with many_c.open("a") as f:
        for i in range(1, 401):
            f.write(f"static int fn_{i}(int x){{return x+{i}*3;}}\n")
        f.write("int main(void){int s=0; int v=0;\n")
        for i in range(1, 401):
            f.write(f"s+=fn_{i}(v++);\n")
        f.write('printf("%d",s);return 0;}\n')

    bins = {}
    oracles = {}
    for name, source, compiler, flags in [
        ("plain_o0", plain_c, CC, ["-O0", "-g"]),
        ("plain_o2", plain_c, CC, ["-O2"]),
        ("plain_pie", plain_c, CC, ["-O2", "-fPIE", "-pie"]),
        ("cpp_o2", src_cpp, CXX, ["-O2"]),
        ("many_o2", many_c, CC, ["-O1", "-fno-inline"]),
    ]:
        unstripped = tmp / f"{name}.unstripped"
        out = tmp / f"{name}.bin"
        run([compiler, *flags, str(source), "-o", str(unstripped)])
        run(["strip", str(unstripped), "-o", str(out)])
        bins[name] = out

        # Extract oracle function symbols from unstripped reference
        sym_out = subprocess.check_output(["readelf", "-s", "-W", str(unstripped)]).decode()
        oracle = set()
        for line in sym_out.splitlines():
            parts = line.split()
            if len(parts) >= 8 and parts[3] == "FUNC" and parts[6] not in ("UND", "ABS"):
                val = int(parts[1], 16)
                if val != 0:
                    oracle.add(f"{val:08x}")
        oracles[name] = oracle
    return bins, oracles


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def run_example(bin: Path, exe: Path, env: dict) -> dict:
    """Run the example once and return parsed JSON."""
    proc = subprocess.run(
        [str(exe), str(bin)],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
        cwd=ROOT,
        env=env,
    )
    return json.loads(proc.stdout.splitlines()[-1])


def median(values: list) -> float:
    return statistics.median(values)


def score(entries: list, oracle: set) -> tuple:
    if oracle is None:
        return (None, None)
    e = set(entries)
    matched = e & oracle
    precision = len(matched) / len(e) if e else 0.0
    recall = len(matched) / len(oracle) if oracle else 0.0
    return (precision, recall)


def machine_info() -> dict:
    mem_gb = 0.0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_gb = int(line.split()[1]) / (1024 * 1024)
                    break
    except OSError:
        pass
    return {
        "os": platform.platform(),
        "cpu": platform.machine(),
        "ram_gb": round(mem_gb, 2),
    }


def apply_rule(speedup: float, hand_metrics: tuple, console_metrics: tuple) -> dict:
    """Decision rule: keep disasm.rs only if it is >=2x faster AND
    set-metrics are equal against the oracle.
    """
    hp, hr = hand_metrics
    cp, cr = console_metrics
    metrics_equal = (abs(hr - cr) < 1e-6) and (abs(hp - cp) < 1e-6)
    keep = (speedup >= 2.0) and metrics_equal
    if keep:
        reason = (
            f"hand decoder is {speedup:.1f}\u00d7 faster than console and "
            "set-metrics are equal against the oracle; keep disasm.rs."
        )
    elif not metrics_equal:
        reason = (
            f"hand decoder is {speedup:.1f}\u00d7 faster than console but "
            f"set-metrics differ (hand p={hp:.4f} r={hr:.4f}, console p={cp:.4f} r={cr:.4f}); "
            "do not keep disasm.rs."
        )
    else:
        reason = (
            f"hand decoder is {speedup:.1f}\u00d7 faster than console (<2.0\u00d7 threshold) "
            f"even though set-metrics are equal against the oracle; do not keep disasm.rs."
        )
    return {"keep_disasm_rs": keep, "speedup": round(speedup, 4), "reason": reason}

def main():
    profile = "release" if os.environ.get("M1_003_RELEASE") else "debug"
    print(f"m1-003-d benchmark using cargo profile: {profile}")

    with tempfile.TemporaryDirectory(prefix="ventris-m1-003-") as tmp:
        tmp = Path(tmp)
        fixtures, corpus_oracles = build_fixtures(tmp)

        # Add libc as the primary real target.
        libc = Path("/usr/lib64/libc.so.6")
        if libc.is_file():
            fixtures["libc"] = libc

        # Build the two versions and copy them out so the second build
        # does not overwrite the first.

        hand_src = build_example(profile, hand=True)
        hand_exe = tmp / f"bench_load_native-hand-{profile}"
        shutil.copy(hand_src, hand_exe)
        console_src = build_example(profile, hand=False)
        console_exe = tmp / f"bench_load_native-console-{profile}"
        shutil.copy(console_src, console_exe)

        oracle_for = dict(corpus_oracles)
        oracle_path = ROOT / "oracle" / "01cccbe278d898add05282986a9346d4dda4b3d2b84bc496f9c04c66016528db.json"
        if "libc" in fixtures and oracle_path.is_file():
            with oracle_path.open() as f:
                oracle_for["libc"] = {e.lower().zfill(8) for e in json.load(f)["entries"]}
        env = os.environ.copy()
        # Ensure the console is discoverable from the repo tree.
        if "VENTRIS_GHIDRA" not in env:
            env["VENTRIS_GHIDRA"] = str(Path.home() / "ghidra_12.1.3_PUBLIC")

        targets = []
        for name, bin_path in fixtures.items():
            print(f"\nBenchmarking {name}: {bin_path}")
            hand_runs = []
            console_runs = []
            for _ in range(RUNS):
                hand_runs.append(run_example(bin_path, hand_exe, env))
                console_runs.append(run_example(bin_path, console_exe, env))

            hand_walls = [r["wall_s"] for r in hand_runs]
            console_walls = [r["wall_s"] for r in console_runs]

            # Use the median run's entry set for scoring.
            hand_median_idx = sorted(range(RUNS), key=lambda i: hand_walls[i])[RUNS // 2]
            console_median_idx = sorted(range(RUNS), key=lambda i: console_walls[i])[RUNS // 2]
            hand_entries = hand_runs[hand_median_idx]["entries"]
            console_entries = console_runs[console_median_idx]["entries"]

            oracle = oracle_for.get(name)
            hand_p, hand_r = score(hand_entries, oracle)
            console_p, console_r = score(console_entries, oracle)

            hand_count = len(set(hand_entries))
            console_count = len(set(console_entries))

            speedup = median(console_walls) / median(hand_walls) if median(hand_walls) > 0 else 0.0

            targets.append({
                "id": name,
                "sha256": sha256_file(bin_path),
                "path": str(bin_path),
                "oracle_sha256": "01cccbe278d898add05282986a9346d4dda4b3d2b84bc496f9c04c66016528db" if name == "libc" else None,
                "runs": RUNS,
                "hand": {
                    "median_wall_s": round(median(hand_walls), 6),
                    "count": hand_count,
                    "precision": round(hand_p, 6) if hand_p is not None else None,
                    "recall": round(hand_r, 6) if hand_r is not None else None,
                },
                "console": {
                    "median_wall_s": round(median(console_walls), 6),
                    "count": console_count,
                    "precision": round(console_p, 6) if console_p is not None else None,
                    "recall": round(console_r, 6) if console_r is not None else None,
                },
                "speedup": round(speedup, 4),
            })

    libc_target = next((t for t in targets if t["id"] == "libc"), None)
    if libc_target is None:
        raise RuntimeError("libc target missing")

    decision = apply_rule(
        libc_target["speedup"],
        (libc_target["hand"]["precision"], libc_target["hand"]["recall"]),
        (libc_target["console"]["precision"], libc_target["console"]["recall"]),
    )

    report = {
        "gate": "m1-003",
        "milestone": "M1",
        "date": time.strftime("%Y-%m-%d"),
        "machine": machine_info(),
        "targets": targets,
        "decision": decision,
        "passed": True,
    }

    REPORT.write_text(json.dumps(report, indent=2) + "\n")
    print(f"\nWrote {REPORT}")

    # Update STATUS.md with the number and sentence.
    status = STATUS.read_text()
    marker = "## M1 progress"
    if marker in status:
        before, after = status.split(marker, 1)
        new_entry = (
            "- m1-003-d: benchmarked hand decoder vs console flow on libc and the "
            f"x86-64 corpus. Median speedup on libc: {decision['speedup']}\u00d7. "
            f"{decision['reason']}\n"
        )
        status = before + marker + "\n" + new_entry + after
        STATUS.write_text(status)
        print(f"Updated {STATUS}")

    print(json.dumps(decision, indent=2))


if __name__ == "__main__":
    main()
