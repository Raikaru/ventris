# Ventris architecture

## Product boundary

Ventris decompiles one native function at a time:

```text
LoadRequest
    -> LoadedImage
    -> LiftedFunction
    -> AnalyzedFunction
    -> StructuredC
    -> DecompilationResult
```

This is the product architecture. Project databases, asset workflows, runtime
trace ingestion, HTTP transport, editor state, and corpus orchestration are not
core analysis concepts. Integrations may consume the pipeline, but must not
create a second implementation of it.

## Invariants

1. **One pipeline.** CLI, Python, and editor requests reach the same Rust
   implementation.
2. **Function-first.** The requested function is the unit of work. Context such
   as symbols, relocations, callees, globals, neighboring boundaries, SDK types,
   and user assertions is input evidence, not a reason to require a project.
3. **Target facts are declarative.** Endianness, pointer width, stack rules,
   delay slots, ABI registers, loader defaults, and named image parts are data.
   Executable processor behavior stays in narrow lifter/analyzer hooks.
4. **Unknown remains unknown.** Missing evidence is represented explicitly.
   Rendering must not manufacture a convenient type, call target, field name,
   or control-flow claim.
5. **Provenance survives.** Machine observations, target knowledge, source/SDK
   metadata, and user assertions remain distinguishable through analysis and
   rendering.
6. **Deterministic and inspectable.** Equal bytes, request facts, and analyzer
   version produce equal facts and output. Intermediate representations remain
   available for diagnosing the stage that failed.
7. **Monotonic verification.** A function may improve without updating its
   baseline. Accepting a regression requires an explicit reviewed baseline
   change.

## Public API

The `ventris` facade crate owns the canonical request path.

Conceptually:

```rust
pub struct Pipeline {
    // immutable target registry and analysis configuration
}

impl Pipeline {
    pub fn inspect(&self, request: InspectRequest) -> Result<ImageReport, Error>;
    pub fn lift(&self, request: FunctionRequest) -> Result<LiftedFunction, Error>;
    pub fn decompile(
        &self,
        request: DecompileRequest,
    ) -> Result<DecompilationResult, Error>;
}
```

The concrete API may evolve, but front ends must depend on this boundary rather
than assembling loaders, lifters, and analysis passes independently.

A `DecompilationResult` contains more than a string:

```text
DecompilationResult
+-- request/image identity
+-- selected address space and function range
+-- lifted p-code
+-- analyzed facts and structured control flow
+-- rendered C
+-- diagnostics and unresolved facts
+-- provenance/confidence
+-- verification metadata
```

The CLI may print only the requested representation, while library consumers
retain the structured result.

## Stage ownership

### Loading

Owned by `ventris-format` and `ventris-addr`.

Responsibilities:

- detect or apply the requested loader;
- parse the selected container/slice/image part;
- preserve named address spaces, overlays, mappings, and relocations;
- map file bytes to virtual addresses without collapsing distinct spaces;
- reject ambiguous or out-of-range function addresses.

Loading does not infer C types or discover a convenient function boundary.

### Target and ABI facts

Owned by `ventris-target`.

`TargetSpec` is the source of truth for a named target profile. It contains:

- architecture and endianness;
- loader and base defaults;
- ABI name, pointer width, alignment, stack direction, frame/stack/return
  registers, caller/callee-saved classes, return classes, and delay-slot count;
- named image parts when a container holds several code images;
- declared support level.

Architecture identity and loader identity never collapse into each other. The
same processor may appear in different containers and ABIs; the same container
may hold more than one processor image.

### Lifting

Owned by `ventris-lifter` and `ventris-pcode`.

A lifter converts bounded native instructions into versioned,
architecture-neutral p-code. It records instruction addresses, widths, branch
and delay-slot behavior, register spaces, constants, and memory operations.
Unsupported instructions remain explicit diagnostics; they are not silently
replaced with no-ops.

### Analysis

Owned by focused modules under `ventris-decompiler`.

The native analysis boundary is intentionally modular:

- `control_flow`: blocks, edges, structured regions, loop/condition recovery;
- `ssa`: value versions, merges, constraints, and propagated facts;
- `calls`: direct/indirect call sites, ABI arguments and returns, known callees;
- `types`: width/sign/pointer/aggregate constraints and conservative merges;
- `memory`: load/store interpretation and aggregate/field evidence;
- `c_score`: semantic comparison of rendered candidates;
- `native`: orchestration only.

A module owns one kind of fact. No stage reparses rendered C to recover facts
that existed earlier in the pipeline.

### Context and game knowledge

Owned by `ventris-game`, `ventris-db`, and request metadata adapters.

Useful contextual inputs include:

- function boundaries and signatures;
- symbol names and relocations;
- known globals and callee signatures;
- nominal SDK/engine types and field layouts;
- explicit object relations;
- source-backed or user assertions.

These inputs join the same fact model used by machine analysis. Precedence and
provenance are explicit:

```text
Machine | Target | Source | User
```

Later evidence may refine a compatible unknown. A conflict remains a conflict;
it is never resolved by silently replacing machine evidence with a preferred
name or type.

### Rendering

Owned by `ventris-decompiler` and `ventris-format`.

The C renderer consumes analyzed structure. It chooses deterministic names,
emits includes and declarations, preserves required casts and aggregate
operations, and leaves unresolved constructs visible. Formatting is a pure
presentation step; it cannot change control flow or type facts.

## Front ends

### CLI

`ventris-cli` parses three public commands: `inspect`, `lift`, and `decompile`.
It adapts arguments to the facade API and formats text or the stable JSON
process envelope. It owns no analysis algorithm.

Developer regression commands are intentionally hidden under an internal
namespace. They may change with the test harness and are not product API.

### Python

`python/ventris` is a dependency-free subprocess adapter over those three CLI
commands. It does not load binaries or duplicate Rust option semantics.

### VS Code

`integrations/vscode` spawns the configured executable without a shell and
renders returned text. It registers the same three operations. Editor-specific
state never enters the analysis crates.

Other integrations may exist experimentally. They remain thin consumers and
are not allowed to drive the core roadmap.

## Caching

Caching is optional and belongs at the pipeline boundary. A cache key includes:

- image content identity;
- selected image part/address space and function range;
- architecture/target and loader options;
- supplied metadata identity;
- native analyzer code version.

Snapshots are bounded and fail closed. A corrupt, oversized, stale, or
incompatible entry is a miss, never trusted analysis.

## Verification

Quality is measured per function and per stage.

### Structural checks

Unit and corpus fixtures check loader mappings, instruction semantics,
control-flow edges, SSA/type facts, call behavior, and deterministic rendering.
These identify which stage regressed.

### Semantic baselines

Source-backed legal corpus entries record expected control-flow constructs,
calls, globals, access types, casts, aggregate copies, declaration order,
nominal fields, and source structure. Comparison reports exact, diverged,
unsupported, or unavailable dimensions; absence of evidence is not a pass.

### Compiler baselines

Each compiler-gated function stores its own minimum normalized mnemonic LCS
ratio, compiler/target identity, and source provenance. The gate enforces the
stored floor. A command-line minimum can strengthen but never weaken it. Exact
mnemonic and byte matches are reported separately.

This avoids a global score hiding a regression in one function behind an
improvement in another.

### Support claims

Support is staged:

| Level | Claim |
|---|---|
| Loadable | Container and address spaces are represented correctly |
| Liftable | Instructions become valid p-code with bounded diagnostics |
| Decompilable | The function pipeline produces structured C |
| Measured | Function-specific semantic/compiler evidence is checked |
| Exact | The declared exactness metric passes for that function |

Architecture count is inventory, not quality. Public claims cite the highest
verified level and the functions that establish it.

## Dependency direction

```text
ventris-cli / adapters
        |
      ventris                 canonical facade
        |
  +-----+-------------------------------+
  |             |            |          |
format/addr   target       lifter     game/db facts
                              |
                            pcode
                              |
                         decompiler
```

Lower crates do not depend on CLI, editor, transport, corpus runner, or release
code. Cycles are design failures, not something to hide behind re-exports.

## Non-goals

Ventris does not currently promise:

- a full interactive reverse-engineering environment;
- whole-program project management;
- universal processor parity;
- automatic correctness for every supported loader/lifter;
- source-identical or byte-identical matching C;
- inferred SDK/game knowledge without provenance;
- stable internal corpus, compiler, oracle, or packaging commands.

The roadmap is driven by measured function improvements: better facts, better
control flow, better types, and fewer unresolved constructs through the one
pipeline above.
