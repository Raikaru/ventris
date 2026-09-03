#!/usr/bin/env python3
"""Acceptance test for m0-009: AGENTS.md II.0/II.1 verbatim and CONTRIBUTING.md."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

II_0_VERBATIM = """1. Read STATUS.md "Current milestone" and "Next task". Work only on that task.
2. Before writing implementation code, write or extend the acceptance test
   named in the task. It must fail. Commit it as "<id>: test".
3. Implement. Run `cargo test --workspace`, `tests/corpus.sh`, and the
   milestone's gate script. Commit as "<id>: <one-line summary>".
4. Update STATUS.md: numbers, not adjectives. "Recall 0.987 on libc" is
   acceptable; "works well" is not. Record the next task id.
5. Stop. Do not begin the next task in the same session unless STATUS.md
   lists it as the next task and its acceptance test already exists.

Hard rules:
- Never start a task from a later milestone. If a later-milestone task
  seems necessary, write it into STATUS.md "Blocked on" and stop.
- Never mark a gate passed without a committed benchmarks/reports/*.json
  produced by the gate script in this session.
- Never edit a committed baseline-*.json.
- Never change a metric definition (II.3). Propose the change in
  STATUS.md "Proposed changes" and stop.
- Never consult, quote, or reproduce output of proprietary tools or any
  leaked source. Cite only: the pinned Ghidra tree, published papers,
  public SDK headers, and OSI-licensed projects (record license in
  docs/third-party.md when borrowing an approach).
- If a corpus binary is missing or an oracle cannot be produced, record
  "skipped" in the report with the reason. Never substitute a smaller
  fixture and call the gate passed.
- Commit ranges over 800 changed lines require splitting into sub-tasks
  first (record them in STATUS.md, then execute one at a time)."""


def main() -> int:
    agents_path = ROOT / "AGENTS.md"
    contrib_path = ROOT / "CONTRIBUTING.md"

    if not contrib_path.is_file():
        sys.exit(f"FAIL: {contrib_path} does not exist")

    contrib_text = contrib_path.read_text(encoding="utf-8")
    if "Clean-room" not in contrib_text and "clean-room" not in contrib_text:
        sys.exit("FAIL: CONTRIBUTING.md does not contain clean-room policy")
    if "gate" not in contrib_text:
        sys.exit("FAIL: CONTRIBUTING.md does not contain gate rule")

    if not agents_path.is_file():
        sys.exit(f"FAIL: {agents_path} does not exist")

    agents_text = agents_path.read_text(encoding="utf-8")
    if II_0_VERBATIM not in agents_text:
        sys.exit("FAIL: AGENTS.md does not contain II.0 Operating loop block verbatim")

    if "II.1 Reserved for the human" not in agents_text:
        sys.exit("FAIL: AGENTS.md does not contain II.1 Reserved for the human section")

    print("m0-009 acceptance: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
