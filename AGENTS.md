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
