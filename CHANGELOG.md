# Changelog

All notable Ventris changes are documented here.

## [Unreleased]

### Added

- Added `ventris_decompiler::graph`, a mutable p-code data-flow graph ported
  from Ghidra 12.1.3's `Funcdata`/`Varnode`/`PcodeOp` object model: one varnode
  per definition, descendant lists, operand replacement, operation insertion and
  destruction, and construction from lifter output. Ghidra's Actions and Rules
  rewrite a live graph rather than build expressions, so this object model is
  the prerequisite for porting them instead of reinventing them.
- Added location refinement ported from `Heritage::buildRefinement`,
  `splitByRefinement`, `refineRead`, `refineWrite`, `concatPieces`, and
  `splitPieces`: overlapping accesses are cut at every access boundary, a read
  spanning several cells becomes a `PIECE` chain, and a write becomes one
  `SUBPIECE` per cell. Ventris previously keyed SSA on exact locations and
  handled sub-register views with an ad-hoc widening cast at read time.
- Added data-flow guards ported from `Heritage::guardCalls`, `guardStores`, and
  `guardReturns`: a call or aliasing store gains an `INDIRECT` definition for
  each location it may change, and a return reads its result storage. The effect
  model is supplied by the target ABI rather than guessed, so a preserved
  register is not needlessly invalidated.
- Added SSA construction on the graph, ported from `Heritage::calcMultiequals`
  and `renameRecurse`: reverse postorder, Cooper-Harvey-Kennedy immediate
  dominators, Cytron dominance frontiers and iterated phi placement, real
  `MULTIEQUAL` operations at joins, and renaming that rewrites every read to the
  definition dominating it. An undefined read becomes a function input rather
  than a bare register name.
- Added graph value resolution, ported from `ActionMarkExplicit` and
  `PrintC::pushVn`: a read resolves by following its definition edge, a value
  with several readers or an unduplicatable definition is named and declared,
  and a merged value is named with one assignment per incoming path instead of
  being dropped. Resolution is order-independent, so a definition below its use
  is found.
- Added graph statement emission, ported from `PrintC::emitBlockBasic`: blocks
  emit in address order into the label-and-goto form the structuring pass
  consumes, phi assignments land at the end of each predecessor, and a shared
  computation is spelled once and reused. No join repair, path-invariance proof,
  or predecessor-state intersection is needed, because the graph already records
  which values merge.
- Added dead code elimination, ported from `ActionDeadCode`: bit-level consumed
  masks propagate backwards from stores, calls, branches, and returns, so a byte
  extracted from a word keeps only that byte live. A call keeps its effect and
  loses only its unread result. Guarding and SSA construction over-approximate
  by design, and this is what removes the merges nothing reads.
- Added `NativeStatement::Assign` and `NativeStatement::DeclareLocal`. A merged
  value needs one declaration dominating an assignment on each path, which
  neither `Declare` (single definition site) nor `Copy` (block memory copy)
  could express; phi lowering previously rendered as `__builtin_memcpy`.
- Added `NativeDecompiler::decompile_via_graph`, the ported pipeline end to end.
  Branch and call targets are read as `ram` space addresses rather than `const`
  constants, which is what a direct call and a conditional branch actually are.
- Added the graph Action and Rule framework, ported from `Action`, `Rule`,
  `ActionPool`, and `ActionGroup`. Rules are registered by opcode and rewrite
  the graph in place, so one rule's result is another's input. Ported rules:
  `RuleMultiCollapse`, `RuleCollapseConstants`, `RuleTrivialArith`,
  `RulePropagateCopy`, `RuleIndirectCollapse`.
- Added unreachable-block removal, ported from
  `Funcdata::removeUnreachableBlocks`, including dropping the merge operand a
  removed predecessor contributed so operand slots stay aligned with the
  predecessor list.
- Fixed graph construction pre-linking reads in address order, which defeated
  renaming: a read already bound to a lower definition was skipped, so a call's
  result read afterwards showed the value from before the call. Reads are now
  free varnodes and renaming alone decides what they see.
- Fixed the graph pipeline running the statement-level action database. Those
  rules repair the address-ordered emitter's output and assume its shape; on
  graph-emitted statements they deleted conditional branches.
- Added type inference on the graph, ported from `ActionInferTypes`: types flow
  along data-flow edges under `Datatype::typeOrder`, bounded at seven passes.
  Propagation is bidirectional through copies, merges, and offsets, so a pointer
  discovered at a dereference reaches the argument register it arrived in and
  the base a field access started from. The previous solver only merged
  constraints per value, which could not carry a type upward at all.
- Added call prototype recovery, ported from `ParamActive::registerTrial`,
  `FuncCallSpecs::checkInputTrialUse`, and `buildInputFromTrials`: one trial per
  convention parameter location, read from the guard that names the location's
  value at the call, kept when the function actually produced that value. A call
  through the graph pipeline now carries arguments instead of none.
- Fixed graph value names colliding when one location holds values of different
  widths at one address, which emitted two C declarations of the same identifier
  with different types.
- Added variable merging, ported from `Merge::mergeOpcode` and `HighVariable`:
  the values a `MULTIEQUAL` or `INDIRECT` relates become one C variable, so a
  merge carries no content of its own and its per-path assignments disappear.
  Names belong to variables rather than SSA values, a merged variable is
  declared once at function scope, and writes to it are assignments rather than
  redeclarations.
- Added cast placement, ported from `ActionSetCasts` and `CastStrategyC`: a cast
  is emitted only where C would not perform the conversion itself. Integer
  widening and signedness changes, and testing any scalar as a condition, are
  implicit; crossing between integers and pointers, changing a pointer's target,
  and float conversions are spelled. A value already recovered as a pointer no
  longer carries `(uintptr_t)` at every dereference.
- Added expression rules ported from `ruleaction.cc`: `RuleBoolNegate`,
  `RuleEquality`, `RuleAndMask`, `RuleTrivialBool`, `RuleSubExtComm`, and
  `RuleEqual2Zero`, with the non-zero-bit analysis from `Varnode::getNZMask`
  that two of them need. These recognise machine idioms — a comparison against
  zero of a difference, a mask that cannot clear a bit, a negated comparison —
  and rewrite them to what the source said.
- Added control-flow structuring on the graph, ported from
  `CollapseStructure`: concatenation, if/else, if without else, while/do, and
  do/while rules collapse the block graph into a construct tree, with a
  conditional `goto` for any edge no rule claimed. Each rule tests the edge
  conditions the construct requires, which a flat statement list cannot express.
  Statements following an unconditional transfer are dropped, since a node that
  surrendered an edge has no fallthrough.
- Added `VENTRIS_PIPELINE=graph`, which routes the public `decompile` command
  through the ported graph pipeline so the quality census can measure both paths
  on identical input. The address-ordered path remains the default: measured
  against the Ghidra oracle across all 37 hash-verified corpus functions, it
  agrees on 19 and the graph path on 6.
- Fixed the graph pipeline reading a `RETURN`'s first operand as the returned
  value. It is the return address, so every function claimed to return a value.
- Fixed graph-pipeline calls losing arguments a function forwards without
  touching. Parameter locations now get a trial from the convention rather than
  only when they appear as a varnode, and a known callee's arity bounds the
  argument list, matching `FuncCallSpecs`' use of the callee prototype.
- Fixed a returned register holding whatever the last callee left being reported
  as a return value. A result must be produced by this function, looking through
  guards and merges, to count.
- Added `ruleBlockOr`, `ruleBlockInfLoop`, and the returning-clause case of
  `ruleBlockIfNoExit` to graph structuring, and corrected the rule ordering to
  match `CollapseStructure::collapseInternal`: conditions collapse in their own
  pass first, and the no-join `if` rule runs only when nothing preferable
  applies, because running it early costs loops and if/else regions. Conditions
  are now expression trees, so a short-circuit operator keeps its operand order.
- Added `Funcdata::remove_edge` and `Funcdata::splice_block`, the latter ported
  from `Funcdata::spliceBlockBasic`, refusing whenever the removal would be
  observable.
- Added dead-store elimination for private frame slots. A store into this
  function's own frame is not a sink, because the frame dies with the call; a
  slot no load reads, in a frame whose address never reaches a call or leaves
  through memory, is dead. This is what removes the prologue that previously
  preceded every graph-pipeline function body.
- Fixed the graph structurer emitting a jump to the label immediately following
  it, and made the last-resort edge surrender prefer edges into multi-predecessor
  joins, which is the state Ghidra reaches by marking edges unstructured before
  its main loop.
- Ported a batch of Ghidra passes onto the graph and registered them in the
  pipeline:
  - `ActionNonzeroMask` with `Varnode::getNZMask` as a real forward fixpoint
    (`graph/nonzero.rs`).
  - `SubvariableFlow` and the `RuleSubvar*` family, plus `RuleBoolZext` and
    `RuleLogic2Bool` (`graph/subflow.rs`). This reduces a comparison packed into
    a condition-register field back to the comparison, which took the
    `unreduced-flag-expression` family from 11 of 37 corpus functions to none.
  - `Cover`/`CoverBlock` live ranges with Ghidra's boundary-vs-interval
    intersection semantics (`graph/cover.rs`), and `ActionMergeCopy`,
    `ActionMergeAdjacent`, `ActionMergeType` speculative merging gated on them
    (`graph/mergeaction.rs`). The renderer now names variables from this
    partition instead of required merges alone.
  - 27 `ruleaction.cc` expression rules (`graph/expr_rules.rs`).
  - `ActionDeterminedBranch`, `ActionRedundBranch`, `ActionUnreachable`,
    `ActionDoNothing`, `ActionNormalizeBranches`, `ActionCse`, `ActionMultiCse`
    (`graph/branchaction.rs`).
  - `ActionReturnRecovery` and `ActionActiveReturn`, with report-only helpers for
    `ActionInputPrototype` and `ActionOutputPrototype` (`graph/protoaction.rs`).
  `ActionReturnRecovery` replaces the hand-rolled return-value check that
  previously lived in `graph/guard.rs`, which has been removed.
- Fixed speculative merging folding function inputs into variables the function
  overwrites, which lost the argument from every recovered prototype;
  `Merge::mergeTestSpeculative` refuses this and now so does the port.
- Commutative identities are recognised with the constant on either operand,
  since nothing yet canonicalises constants onto the second slot the way Ghidra
  does before those rules run.
- Ported a second batch of Ghidra passes and wired them into the pipeline:
  - `ActionNameVars` with the `ScopeLocal`/`ScopeInternal` naming rules
    (`graph/namevars.rs`). Variables are now named `uVar2`, `pVar4`, `local_10`
    by type class and frame offset rather than by the address that defined them.
  - `JumpBasic`/`JumpModelTrivial` jump-table recovery and `ActionSwitchNorm`
    (`graph/jumptable.rs`).
  - `ActionStackPtrFlow` with `AliasChecker` escape reasoning and frame slot
    widths (`graph/stackframe.rs`).
  - `ActionConditionalConst`, `ActionConditionalExe`, `ActionDeindirect`,
    `ActionConstantPtr` (`graph/condprop.rs`).
- Ported Ghidra's natural-loop analysis into structuring: `labelLoops`,
  `LoopBody::findBase`, `LoopBody::findExit`, and `markExitsAsGotos` run before
  the collapse, so a loop's exits are surrendered while its back edge is kept.
- Fixed three structuring defects that between them prevented every loop from
  being recovered:
  - `absorb` dropped an absorbed member's edge back to the composite, which is
    the loop's back edge. `newBlockList` keeps it.
  - `absorb` did not rewire a predecessor of an absorbed member onto the
    composite, leaving stale edges.
  - the last-resort goto scored back edges *highest*, so it surrendered loop
    edges first. Ghidra never surrenders a back edge; `markExitsAsGotos` marks
    the edges leaving a loop.
  Measured effect on the corpus: `missing-loop-or-switch` fell from 11 functions
  to 5 and `unstructured-control-flow` from 16 to 13.
- Fixed `ActionReturnRecovery` looking through a call's `INDIRECT`, which
  credited this function with whatever register a callee left behind.
  `return-presence` fell from 13 functions to 1.
- Fixed a named `INDIRECT` result being read but never declared, and a merged
  variable being redeclared at each of its definition sites; both emitted C that
  does not compile.
- Fixed nine expression rules testing `Varnode::isHeritageKnown` where Ghidra
  tests `Varnode::isFree`. The two are not complements: a constant is
  heritage-known *and* free, so those rules fired on constant operands that
  Ghidra declines, hoisting a value past the point its definition reaches.
  Both predicates are now spelled exactly as `varnode.hh` defines them, with a
  test pinning the four-way distinction between a constant, a written value, an
  undefined read, and a function input.
- Fixed a `const` space `BRANCH` operand being read as a code address. It is a
  p-code-relative offset within one instruction's expansion, and treating it as
  an address emitted jumps to addresses like `loc_2`; because a jump ends a
  block, the rest of the function was then discarded as unreachable.
- Fixed structuring discarding reachable statements after a surrendered edge. A
  block reached only by falling through carries no label, so it looked
  unreachable; pruning now applies only inside a construct's body, where the
  construct is the only way in. `finish` additionally guarantees every live block
  appears in the tree, so a rule that mishandles an edge can no longer silently
  drop part of a function.
- Removed unreachable-code pruning from graph emission entirely. It looked safe,
  since nothing after an unconditional transfer runs, but a block reached only by
  falling through carries no label, so one spurious jump made the rest of a body
  look dead. It was deleting whole inner loops and the calls inside them: on
  `Emem_KillSwMember__Fv` it removed one of two calls to the same callee. An ugly
  jump is cosmetic; deleting a reachable statement is a wrong answer.
- Loops now drop jumps to their own header from their body. A surrendered back
  edge and a recovered loop state the same thing, and keeping both left a jump
  contradicting the construct wrapped around it — which is what made the
  following statements look unreachable in the first place.
- Added `VENTRIS_SKIP_PASS`, a comma-separated list of pass names to disable, so
  a defect can be attributed to one pass without a rebuild per guess.
- Added a field-read expression, rendered `p->field_40`. `*(uint32_t *)(p + 0x40)`
  says the same thing but carries a cast, and a cast is a claim that the value's
  type is not what the context wants. When type recovery knows the structure, no
  such claim is needed. This is the whole of the measured `excess-casts` gap
  against Ghidra: on `changeGroupID__7JKRHeapFUc` every one of our two casts is a
  memory-access spelling where Ghidra names a field.
- A construct no longer prints the jump its header surrendered. The header's
  edges belong to the construct that claimed them, so a jump left on the header
  put an `if` directly after an unconditional transfer — output that says the
  test never runs. On `getBuiltInTexture` this removed every remaining `goto`,
  and `Na_CheckRestartReady` now renders as nested `if` and `do/while` with none
  at all.
- Labels are now emitted wherever control can arrive other than by falling
  through, then removed again when neither a jump nor a post-transfer position
  needs one. Deciding per block is not possible, because whether a label is
  needed depends on what is emitted before it, and emission order does not have
  to follow the control-flow graph.
- Jump targets are collected from surviving block branches as well as from
  explicit goto nodes. Only the second kind was counted, so a surrendered branch
  could print a jump to a label that was never emitted.
- Measured against Ghidra on the corpus, the graph path improves to
  `unstructured-control-flow` 10 (from 13) and `missing-loop-or-switch` 4, against
  15 and 11 on the address-ordered default.
- Port coverage, counted against the pinned Ghidra 12.1.3 headers: 66 of 168
  `Rule` subclasses and 28 of 75 `Action` subclasses, 39% and 37%. 102 rules and
  47 actions remain. Of the missing rules 68 are ordinary integer and boolean
  rewriting, 18 concern sub-variable and piece flow, 10 are pointer or
  type-directed, and 6 are floating-point.
- Wired the third wave of ported passes into the graph pipeline: the twenty
  further expression rules, prototype and parameter recovery, and rich type
  inference with structure and array recovery. `excess-casts` and
  `missing-parameters` both improve; the graph path now leads the address-ordered
  default on six families and ties on three.
- `RuleHumptyOr` now declines the case `RuleAndDistribute` would reverse.
  They are exact inverses, and with a constant shared operand both guards
  passed, so each undid the other and the graph grew without bound: one function
  never finished. Ghidra survives the same pair because its pool visits an
  operation a bounded number of times; this pool iterates to a fixpoint, so the
  conditions have to be genuinely disjoint. This is deliberately stronger than
  Ghidra's rule.
- One "may be non-zero" mask implementation, cached on the graph and invalidated
  by every mutator. There were two, and rules reading different ones disagreed
  about the same value — which is what let the pair above both fire. Recomputing
  the fixpoint per rule application was also the reason the expression phase was
  quadratic.
- `ActionActiveParam` no longer shortens a call. An argument whose ancestry the
  analysis cannot justify is not an absent argument: Ghidra marks that trial
  no-use and substitutes a zero constant, keeping the operand. Rebuilding the
  list dropped real arguments, and since a dropped operand was often a value's
  only use, the stores feeding it were then removed as dead — two functions were
  reduced to stubs with no memory accesses at all.
- Removed four `marking` actions that computed an analysis and discarded the
  result. They mutated nothing, so they could only cost time, and one recomputed
  an explicit-value analysis per value: a single function took 198 seconds, and
  the corpus census 496. Both are now 2.2 seconds and 12 seconds. The module's
  real analysis — `Explicit`, `cast_standard`, the promotion helpers and
  `ActionLikelyTrash` — is kept for the renderer to consult.
- The graph path now emits `CALLOTHER` userops, naming them from the SLEIGH
  userop table exactly as the address-ordered path does, and suppressing the ones
  the MIPS and Arm lifters use for branch-state bookkeeping. They were dropped
  because they have no result, and the resultless case fell through to a `Skip`:
  every coprocessor and TLB write disappeared from the output.
- `call-census` now counts call sites rather than only calls to unnamed targets.
  It was measuring symbol availability: on `getBuiltInTexture` Ghidra resolves
  `memcmp` where we print `sub_1201144`, and that scored as five lost calls on a
  function where both emit exactly five. With the measurement corrected, three
  real losses appear that the old form hid, all of them upstream of both
  pipelines in instruction discovery.
- A recovered structure field below its base no longer collapses to `field_0`.
  Clamping the offset to zero declared the same member twice, so the rendered C
  did not compile.
- Reads at a recovered structure field render as `p->field_2868` instead of a
  cast through a computed address. The rich type table is now threaded to the
  resolver, since the shared `Type` cannot carry a structure. A field only forms
  when the address computation inlines into the read and the offset is exactly a
  field start: a named address already added the offset, and a read part-way into
  a field is not that field.
- Fixed a stack overflow in call-argument recovery. `is_used` looks through
  merges to decide whether a value is real, and excluded only the value itself,
  so two merges naming each other — an ordinary loop-carried value — recursed
  until the stack ran out. `decompSZS_subroutine__FPUcPUc` crashed the
  decompiler outright; it now decompiles, which is also why it starts appearing
  in the structural families it fails.
- A jump or return directly following another is dropped. A transfer computes
  nothing, so removing an unreachable one loses no work — unlike the general
  unreachable-code pruning, which did.
- Stores to a recovered field render as `p->field_4a4 = v`, and a field read no
  longer requires its address to be unnamed. Resolving the base rather than the
  offset address applies the offset once, which leaves the address temporary
  with no readers.
- Added removal of assignments and locals that nothing reads, for pure
  right-hand sides only. Folding address arithmetic into a field access is what
  strands them; a call or a memory read is never removed whatever its result is
  used for.
- Measured effect on the graph path: `excess-casts` goes from six functions to
  none, and `agrees` from seventeen to twenty-two of thirty-seven. Against the
  address-ordered default the graph path now leads on `agrees`, `excess-casts`,
  `unstructured-control-flow`, `missing-loop-or-switch`, `return-presence`,
  `oversized-expression` and `unreduced-flag-expression`, ties four families, and
  trails only `call-census`.
- Heritage now resolves a narrow read of part of a wider definition. It keyed
  definitions on the exact `(space, offset, size)` triple, so `sb v1` after
  `addiu v1,zero,1` read a location nothing had ever defined and printed the bare
  register name, losing the constant. A read whose bytes lie inside a dominating
  definition is now a `SUBPIECE` of it, measured from the correct end for the
  target's endianness. `beginFadeOut` and `beginFadeIn` now store `1` where they
  stored an undefined register.
- A hardwired-zero register read is replaced by the constant zero, so
  `addiu rd,zero,imm` folds instead of adding an undefined register.
- `SUBPIECE` now has a spelling on the graph path: taking the low bytes is a
  cast, taking bytes further up is a shift and a cast. Without it the truncation
  heritage inserts had no rendering and appeared as an unnamed placeholder,
  which is how `allocLightmap` lost its multiply.
- A value is named at its definition when an operand's variable is written again
  before the value is read. Emission follows graph order, so such a value
  inlined into its reader and read the *new* operand: `allocEnemyEntity`
  multiplied the incremented counter instead of the counter. This was a wrong
  answer, not a formatting difference.
- That decision now uses the operand's live range, the criterion Ghidra uses,
  rather than a comparison of sequence numbers. The coarse form was sound but
  named values whose operands were rewritten anywhere in the interval even when
  the reader came first, and every unnecessary name carries a declaration and
  usually a cast.
- Added single-use copy propagation over the emitted statements. A name that
  carries a value to exactly one reader and nothing else has served its purpose
  and is spelled at that reader instead; the substitution stops at anything that
  writes a name the expression reads, and at a loop, whose body runs an unknown
  number of times. A definition is only removed once a use has actually been
  replaced — the first attempt removed it unconditionally and left an undefined
  value, which is a wrong answer rather than a tidier one.
- A negated test wrapped around a whole function body becomes a guard clause:
  `if (!C) { BODY } return;` is written `if (C) { return; } BODY`. Both describe
  the same program, but the second says what the condition means, and it is the
  shape the authors wrote — `beginFadeOut`'s source is a guard clause and the
  smoke baseline records one. A test with an `else`, or a single-statement body,
  is left alone.
- A value that only re-spells a constant — a copy, extension or truncation of
  one — is no longer named. The printer writes a literal either way, so the name
  only added a declaration and a cast.
  A value like that is also kept out of speculative variable merging, since
  otherwise the group takes its name from another member and the constant is
  assigned to it anyway. `required_union` is deliberately unaffected: a phi's
  operands must share the phi's variable whatever they hold, and excluding them
  there broke that invariant.
- Dead-assignment removal is now position-aware. Liveness by name alone kept
  every earlier assignment to a reused variable alive, because the name is read
  further down; `allocEnemyEntity` carried a dead `pVar1 = arg0 + 0x4b0` whose
  only reader had been replaced by a field access. A branch that writes the name
  on one side does not end the range, and a loop never does.
- A load with a single reader is spelled at that reader rather than named, unless
  a store or a call separates the two. One reader is one read either way, so the
  name only added a local; moving a read across a write would read the wrong
  value, which is what the store check prevents. `beginFadeOut` now declares
  nothing at all, matching its source.
- The inlining test asks whether another version of an operand's variable is live
  at the reader, not whether the operand's own range reaches it. A chain of
  single-use values collapses precisely because each range ends at the next, so
  the liveness form refused every chain and named its every link.
- The graph path stays opt-in. It leads the address-ordered path on seven census
  families and ties four, but it fails `corpus-smoke`'s semantic comparison on
  three PS2 entries the address-ordered path passes: two diverge on control-flow
  shape and one still loses a multiply whose result the lifter routes through a
  wide temporary. Switching the default would trade a measured gain for a gate
  regression, so it is not switched.

- Added `LiftedInstruction::skips_delay_slot`, which reports the MIPS
  likely-branch shape so consumers stop treating its sequential successor as
  implicit.
- Added a `declaration-narrowing` action rule: a temporary that every use
  narrows is declared at the narrow type instead.
- Added PS2 retail regressions pinned to real Dungeon Game bytes covering
  memory ordering, likely-branch flow, and merge points.
- Added epilogue inlining: a jump to a block that only returns becomes that
  return, so a shared epilogue no longer turns every path into a label.
- Added frame-slot promotion: a stack slot that is provably a private scalar is
  declared and named as a local instead of rendered as `sp`-relative memory. A
  slot whose address escapes, whose bytes are accessed at more than one width,
  or that overlaps another slot keeps its memory form.
- Added the Apache-2.0 R5900 language and routed the PS2 target to it. The
  generic MIPS64 language cannot decode the R5900's multimedia or COP2/VU
  macro-mode instructions.
- Added `SleighSpec::register_varnode` so ABI recovery reads register offsets
  from the language instead of assuming a per-family stride, plus a bundled
  register-layout audit over every shipped language.
- Added `tools/quality_census.py` and `tools/CensusDecompile.java`, which
  classify Ventris output against Ghidra's decompiler across every
  hash-verified corpus function and rank defects by affected function count.

### Fixed

- A value read before a store is now read once, before it. A definition holding
  a load that a following store may overwrite is captured in a named temporary,
  so `p->count++` no longer returns the incremented value where the program
  returns the original.
- MIPS likely-branches (`beql`, `bnel`, `bgtzl`, …) keep both successors. They
  were lifted as unconditional jumps, which deleted the not-taken path and
  truncated any function whose last branch was likely: `getBuiltInTexture` was
  discovered 12 bytes short and jumped to a label that was never emitted.
- A label reached from several blocks now keeps only the values every
  predecessor agrees on. Carrying one path's value made four of five
  comparisons in `getBuiltInTexture` test the wrong string and made the
  function claim one path's return value unconditionally.
- Casts that restate a value's own type are dropped, halving the cast count of
  an ordinary field read.
- Constant offsets fold through a truncating cast, since truncation commutes
  with addition; `(uint32_t)(sp - 0x40) + 0x40` is `sp`.
- A return register the function never writes is no longer reported as the
  return value: an untouched register holds the incoming argument, not a
  result.
- Derived PS2 register offsets, register names, and O32 argument slots from the
  R5900 language. The previous MIPS64 stride misidentified every argument and
  return register, which silently disabled PS2 type recovery.
- Narrowing casts of constants now truncate: a byte store of `0x1234` reports
  `0x34`, matching Ghidra, instead of the untruncated value.
- Widening casts of constants now adopt the declared width, so a 32-bit result
  materialized from a 16-bit immediate no longer infers a 16-bit type.
- Dropped redundant widen-then-narrow cast pairs, which the R5900 emits for
  every 32-bit arithmetic result.
- A value left in the return register is still recognized as a store byproduct
  when the store and the register disagree only about declared width.
- Recovered the comparison behind a packed condition-register field. A branch
  that tested `(a < b) << 3 | (b < a) << 2 | (a == b) << 1 | so` now renders as
  `a < b`, so no corpus function spells a comparison as a bit-field chain and
  the widest rendered expression in `TRK_fill_mem` fell from 2836 to 247
  characters.
- Collapsed rotate-and-mask pairs whose mask erases one half, folded chained
  constant offsets into one addition, dropped shifts at or beyond a value's own
  width, and dropped `x - 0`.
- Negative folded offsets render as subtraction: `rsp - 0x10` instead of
  `rsp + 0xfffffffffffffff0`.

## [0.3.0] - 2026-08-24

### Added

- Added a native Rust reader for Ghidra 12.1.3 compiled `.sla` files: bounded
  zlib inflation, packed marshal decoding, typed `ELEM_SLEIGH` trees,
  constructor decision selection, and p-code template parsing. The installed
  12.1.3 corpus gate decodes 137 processor specifications, 128,421 constructor
  templates, and 810,755 operation templates.
- Routed all 21 public architecture profiles through pinned compiled SLEIGH
  specifications, including Apache-2.0 community definitions for
  Gekko/Broadway and Cell SPU. The runtime now measures variable-length
  constructor trees, backtracks overlapping constructors on invalid operand
  tables, applies context actions, expands recursive BUILDs, and emits delay
  slots.
- Added a 21-function Animal Crossing differential corpus covering 1,704
  reachable Ghidra-decoded instructions with zero p-code differences,
  including paired-single and load/store-multiple semantics.
- Completed the native decompiler stage pipeline with Ghidra-derived
  Heritage/SSA versioning, ordered action-rule fixed points, conservative type
  propagation, block-action control-flow structuring, and a precedence-aware C
  AST printer. Stage fixtures and source-backed real-image baselines now gate
  the complete path rather than only lifting.
- Added provenance-pinned, Ghidra-authored offline GameCube p-code fixtures for
  `TRK_memset`, conditional branching, paired-single storage, and
  load/store-multiple expansion, plus deterministic exact-varnode regression
  tests.
- Added pinned Ghidra decompiler-stage oracles for `TRK_fill_mem`,
  `convert_partial_address`, and `__FrameCallback`. The exporter records raw
  function bytes, high-variable types, inferred parameters and return types,
  direct calls, structured C, and immutable source/Ghidra provenance.
- Added target-ABI direct-callee prototype recovery. Call arguments now come
  from the callee's recovered signature, known return types propagate through
  call results, and branch conditions reuse one materialized call result.

### Fixed

- Generate release checksum manifests with explicit binary-mode markers.
- Qualified compiler-gate addresses with their image spaces and accepted
  Windows LLVM object headers without weakening instruction parsing.
- Corrected the measured PowerPC EABI ninth-argument offset to `r1 + 8`;
  unmeasured Xenon and PS3 PPU floating-point, stack, and aggregate conventions
  now remain unknown instead of inheriting incompatible 32-bit EABI facts.
- Recovered PowerPC EABI frame save/restore sequences as machine state instead
  of C, limited function parameters to live-in values, propagated register
  copies through calls and returns, and excluded stack-frame accesses from
  recovered application structs. A pinned Animal Crossing `TRK_memset`
  baseline now gates the GameCube path against source-backed semantics.
- Pinned the Ghidra executable specification and p-code differential harness to
  Ghidra 12.1.3 (`Ghidra_12.1.3_build`), with install-version enforcement and
  recorded upstream commit and release checksum.
- Added bounded raw-function export and compact summary output to the Ghidra
  differential harness.
- Prevented GameCube DOL differential runs from deadlocking on the loader's
  interactive symbol-map prompt, selected Ventris's DOL loader explicitly, and
  bounded explicit-range comparisons to the Ghidra capsule address range.
- Canonicalized each compiled language's declared default address space to the
  stable RAM p-code space, including 6502 languages whose default is not named
  `ram`.
- Updated PS2 source-metadata receiver coordinates for canonical 64-bit R5900
  register varnodes and removed casts made redundant by recovered nominal field
  types.
- Merged SSA definitions from conditional fallthrough and branch paths before
  structuring, preserving branch-dependent call results without duplicating
  side effects in rendered C.
- Synchronized Rust, Python, VS Code, CI, and release-workflow metadata for
  0.3.0; Python distributions now use PEP 639 license metadata and every Rust
  crate records its canonical repository.

## [0.2.0] - 2026-08-23

### Breaking changes

- Reduced the public CLI to `inspect`, `lift`, and `decompile`.
- Replaced `decompile-native`, `recover-types`, and `reconstruct-source` with
  the canonical `decompile` command. Project, discovery, diff, batch, corpus,
  and HTTP commands are no longer public product API.
- Reduced the Python package to `inspect`, `lift`, `decompile`, `version`, and
  the low-level `run` process helper.
- Raised the Rust edition to 2024 and the minimum supported Rust version to
  1.98.

### Added

- Added a canonical `ventris::Pipeline` facade for loading, lifting, analysis,
  inventory, and deterministic C rendering.
- Added declarative target profiles that keep architecture, loader, ABI,
  address-space, image-part, and support-level facts together.
- Added executed legal-PS2 semantic baselines and machine-readable exact,
  diverged, unsupported, and unavailable comparison reports.
- Expanded the legal Dungeon Game ELF gate to ten bounded functions and added
  three per-function Clang `mipsel-none-elf` compiler floors whose retail
  instructions are fully decoded by the configured disassembler.
- Added a non-publishing release-candidate workflow mode.

### Changed

- Moved reusable function/data inventory and game-recovery algorithms from the
  CLI into library ownership.
- Split native decompilation into focused control-flow, SSA, and semantic-score
  modules without creating a second pipeline.
- Moved corpus, compiler, oracle, transport, project, batch, and packaging
  workflows behind development-only tools.
- Reduced Python and VS Code to thin adapters over the native executable.
- Froze the GPUI desktop workspace outside the product pipeline while retaining
  its formatting and test jobs as release compatibility gates.
- Corrected MIPS/N64 delay-slot discovery and ordering, made conditional-return
  folding label-safe, preserved partial-layout field offsets, and retained
  externally referenced control-flow labels.

### Known limitations

- Decompilation quality remains function-specific; a supported loader or lifter
  is not a uniform C-quality claim.
- Native function signatures are not yet selected from a container-specific
  ABI at every decompiler entry point.
- The Python and VS Code packages require a separately installed matching native
  executable.

## [0.1.0] - 2026-08-23

### Added

- Bounded binary inspection and address resolution for ELF, PE, COFF,
  Mach-O, Intel HEX, Motorola S-record, and supported console containers.
- Native lifting and checked-in p-code/decompiler corpus coverage across the
  documented architecture paths.
- Console target profiles and evidence-backed ABI/type recovery through the
  canonical Rust pipeline, CLI, Python adapter, and VS Code adapter.
- Source-backed corpus metadata and opt-in hash-verified real-image smoke tests.
- Release packaging now emits and verifies native archives, VSIX payloads, and
  Python wheel/source artifacts with policy and provenance files.
- Release smoke gates exercise the optimized release-profile executable before
  archive packaging.
- Cross-platform native release smoke checks and strict archive verification.

### Known limitations

- Native semantic parity is proven for the checked-in corpus, not for every
  instruction or every compiler idiom on every supported processor.
- Game recovery is an initial vertical slice. Engine/runtime pattern models and
  matching-C emission are not complete.
- The Python package forwards to an externally installed Ventris executable; it
  does not bundle a platform-specific Rust binary.
- Manual visual VS Code acceptance remains a release check.
