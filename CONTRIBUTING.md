# Contributing to Ventris

Thank you for your interest in contributing to Ventris. To maintain the project's integrity, legal standing, and engineering rigor, all contributors—human and AI agents—must follow these rules.

## Clean-room policy

Ventris is a clean-room, JVM-free reverse-engineering platform aiming to match and exceed Ghidra's decompilation quality without proprietary encumbrances.

- **No proprietary or leaked material**: Never consult, quote, or reproduce code, decompiled output, or internal material from proprietary decompilers or leaked sources.
- **Allowed sources**: Contributors may consult only:
  1. Upstream open-source code (the pinned Ghidra tree in `third_party/ghidra/` and `.ghidra-java/`).
  2. Published academic papers and specifications.
  3. Public SDK headers and documentation.
  4. Permissively licensed, OSI-approved open-source projects. When borrowing an approach from an open-source project, cite the source and record the license in `docs/third-party.md`.
- This clean-room guarantee protects the project's reputation and ensures its technical claims are beyond dispute.

## Gate-file rule

Nothing is "done" until its gate file is committed and continuous integration enforces it.

- Each milestone defines a gate in `benchmarks/reports/*-gate.json` following the standard schema (II.2).
- Never mark a gate passed without a committed gate report produced by the gate script in that session.
- Never edit a committed `baseline-*.json` by hand.
- Metric definitions are frozen (see `AGENTS.md` and roadmap). Never change a metric definition without human review.

## Operating loop and commit conventions

All development follows the disciplined operating loop documented in `AGENTS.md` (Section II.0):

1. **One task per commit range**: Work only on the task specified in `STATUS.md`.
2. **Test-first discipline**: Write or extend the acceptance test named in the task before writing implementation code. The test must fail. Commit it as `<id>: test`.
3. **Implementation**: Implement the minimum necessary to make the test pass. Run `cargo test --workspace`, `tests/corpus.sh`, and the relevant gate scripts. Commit as `<id>: <summary>`.
4. **Metrics in STATUS.md**: Update `STATUS.md` with concrete measurements (numbers, not adjectives), and record the next task ID.
5. **No skipping**: Never start a task from a later milestone. If blocked, document the blocker in `STATUS.md` and stop.

## Human-reserved decisions

Certain architectural, legal, and operational decisions are strictly reserved for the project maintainer. See `AGENTS.md` Section II.1 for the complete list.
