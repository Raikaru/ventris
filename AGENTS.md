# AGENTS.md

Rules for any agent working in this repository.

1. Read `STATUS.md`, `README.md`, and the latest ADRs before working.
2. Every Ghidra API call must be verified against the extracted sources in
   `.ghidra-java/` (or the installed jars' `-src.zip`) — never from memory.
   Known traps are documented in `service/src/main/java/net/ventris/
   GhidraBootstrap.java` header comments; re-check them when touching
   lifecycle code.
3. The bridge is temporary (Stage 1). Do not grow it into the permanent
   owner of project state; new durable facts go into `lre-db` with
   provenance.
4. `third_party/ghidra/` is pinned, hash-manifested upstream source. Never
   edit in place.
5. Follow the staged generations in README.md. Do not silently skip stages
   or claim capability without a test proving it.
6. Rust conventions: typed errors (`thiserror`), `Result<T, E = ...>`
   aliases, match ergonomics, no `unsafe` outside reviewed FFI modules.
7. Tests must pass (`cargo test --workspace`) before committing.
8. Subagents: read-only research tasks only (e.g. spec/library lookups);
   all edits go through the primary agent.

## II.0 Operating loop (goes in AGENTS.md, verbatim)
1. Read STATUS.md "Current milestone" and "Next task". Work only on that task.
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
  first (record them in STATUS.md, then execute one at a time).

## II.1 Reserved for the human

The agent stops and asks when any of these come up. They are listed in AGENTS.md and repeated here.

| Decision | Why it is reserved |
|---|---|
| Adding or removing a corpus binary, target game, or platform | Defines what "complete" means |
| Any change to a metric definition in II.3 | Metric drift is how gates get gamed |
| First commit that breaks oracle-mode token identity (M4) | Irreversible reputational choice |
| Enabling any M4 pass by default rather than behind a flag | Changes user-visible output |
| Tagging a release | Public claim |
| Adding a runtime dependency to any crate | Project identity ("dependency-free") |
| Merging outside contributions | Clean-room liability |
| Any network call at runtime (signature DB fetch, model download) | Offline guarantee |
