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
- Ported `TraceDAG` from `blockaction.cc` into `graph/tracedag.rs`, with its
  `BranchPoint`, `BlockTrace` and `BadEdgeScore` helpers: `initialize`,
  `pushBranches`, `checkOpen`, `openBranch`, `checkRetirement`, `retireBranch`,
  `removeTrace`, `selectBadEdge`, `processExitConflict`, `markPath`, `distance`
  and `compareFinal`. It pushes a trace along every path out of every branch
  point, opens a node only once all its incoming DAG edges have been traced, and
  when nothing can advance scores the stuck traces against each other to pick the
  edge to surrender. Five tests: a diamond, a straight line, a nested diamond
  whose join has three predecessors, a cross edge, and one asserting the chosen
  edge targets the shared join rather than the structured path through it.
- Wired it in two places. `rule_goto` consults it before its own heuristic. More
  importantly `mark_loop_exits` now surrenders **one** edge per pass and asks the
  trace which one, bounded as Ghidra bounds it — rooted at the loop head, with a
  tail as the finish block and the edges leaving the body excluded from the DAG,
  which is `setFinishBlock` plus `setExitMarks`. It previously surrendered every
  exit edge but one, unconditionally and all at once; Ghidra's `selectGoto` pops
  its candidate list an edge at a time and re-runs the collapse rules between
  each, so it gives up the fewest that let structuring proceed.
- Measured effect so far: `queryMapAddress_single` drops from 22 `goto`s to 21 and
  no function regresses; the census families are unchanged. The port is faithful
  and the integration is at the right place, but it has not yet moved a function
  into `agrees`, and saying otherwise would be false. `rule_goto` turns out to be
  reached rarely — `mark_loop_exits` almost always makes progress first — so the
  remaining work is in how the loop body and its official exit are chosen, which
  is `LoopBody::labelExitEdges` and `emitLikelyEdges` ordering rather than the
  trace itself.
- Fixed the wrong condition in `DBGEXIImm`: the graph path emitted `0 < 1`
  where Ghidra and the address-ordered path both test `0 < (int32_t)(arg1 - 8)`.
  The data flow was always correct — `INT_SLESS(arg1 + 0xfffffff8, 1)`, whose
  negation is Ghidra's form. Statement propagation substituted a dead value into
  the reader.
  `single_reader_after` counts a read before a write in the same statement,
  deliberately, because `p = p + q` reads the carried value and then replaces it;
  refusing that would give every link of an address chain its own name. But that
  ordering is only knowable for a simple assignment. A *construct* that reassigns
  the name in its body and then reads it was counted as the single reader of the
  old value, so the old value — here a constant zero — was substituted past a
  reassignment it could not see. The allowance now applies to simple statements
  only, and the window-closing test recurses into bodies rather than looking at
  the top level alone. Two tests pin both halves: one that a value must not cross
  a reassignment inside a construct, and one that a carried value still reaches
  its reader in `p = p + q`.
  Rule `intlessequal` was necessary for the shape to arise and was never wrong,
  which is why bisection pointed at it and reading it found nothing. Disabling
  propagation was the measurement that located the real culprit.
  `missing-loop-or-switch` drops from 6 findings to 5; nothing else moves.
- Measured for prioritisation: rule coverage rose from 66 to 128 of 162 across
  this session's waves while `agrees` stayed at 22 of 37 throughout. Of the 34
  rules still unported, three are control-flow-shaped (`RuleCondNegate`,
  `RuleConditionalMove`, `RuleSwitchSingle`) and the rest serve bitfields,
  double-precision pairs, strings, segments, constant pools and peephole
  arithmetic — families against which the corpus records no findings at all.
  Coverage has decoupled from measured agreement, so it is the wrong thing to
  optimise next. The exception is the mutable `BlockGraph`, which is both the
  blocker for 15 unported actions and for the largest census family, and is
  therefore the one piece of remaining port work that pays.
- Corrected the structuring diagnosis twice over, by reading the pinned source
  rather than reasoning from the symptom.
  - The earlier note said the stray `goto`s need Ghidra's mutable `BlockGraph` so
    a shared join block can be duplicated. That is wrong: Ghidra's own
    `Funcdata::nodeSplit` refuses a block with out-flow — "Cannot (currently)
    nodesplit block with out flow" — and is used only by `ActionReturnSplit` on
    return blocks. Ghidra does not duplicate joins either.
  - Comparing rule sets directly: Ghidra's `CollapseStructure` has 11 collapse
    rules and 9 are ported, with two naming mismatches that hid the match —
    `ruleBlockProperIf` is our `rule_if_no_exit`, and `ruleBlockIfNoExit` is our
    `rule_block_if_return`. The only genuinely missing rules are `ruleBlockSwitch`
    and `ruleCaseFallthru`, both switch recovery, which accounts for exactly one
    census finding (`dl_G_MOVEWORD`, `switch 0 vs 1`).
  - So the stray `goto`s are not missing rules. Instrumenting the collapse showed
    the rules decline on their preconditions — `second-has-many-preds` 22 times on
    one function. What Ghidra has that this does not is the *goto-selection*
    machinery: `TraceDAG` with likely-unstructured-edge generation, plus
    `onlyReachableFromRoot`, `markExitsAsGotos`, `clipExtraRoots` and `LoopBody`
    ordering. Our `rule_goto` surrenders an edge by local heuristic, preferring a
    back edge. Ghidra chooses the edge by tracing paths, so fewer survive. That is
    the piece to port, and it is a different and better-defined target than either
    earlier guess.
- Also measured and isolated, each one function: `TRK_fill_mem` returns a value
  where the oracle returns void and misses two `for` loops; `osContGetReadData`
  recovers no parameters where the oracle does; `changeGroupID` emits one call the
  oracle does not; and `DBGEXIImm` renders `(x << 29) & 0x1fffffff | x >> 3` where
  the mask makes the whole first term dead, which Ghidra prints as `x >> 3`.
- Added `ventris-format/src/mdebug.rs`, a MIPS symbolic debug reader, and
  `src/debuginfo.rs` holding the shared model both readers populate.
  `Image::debug_info` now merges them. It recovers 785 procedure names and their
  source files from `dungeon_game.elf`, including
  `_ZN9GameWorld16allocEnemyEntityEv` at `0x125080` attributed to
  `/Users/Lampert/.../game_world.cpp` — the same path Ghidra prints. The header's
  fields five and six are the *procedure* descriptors, not the file descriptors;
  reading them as the file table walked 785 procedure records as though they were
  72-byte file headers and every field came out as noise, which a test now pins.
- It supplies names and source files and deliberately no types. The auxiliary
  type table in this image is a placeholder: for `game_world.cpp` it holds the
  monotonic sequence `0x03, 0x05, 0x07, ...` at alternating slots, decoding as
  `long`, `unsigned long`, `char` in basic-type declaration order rather than as
  any procedure's type, and the file emits no `stParam` symbols at all. This
  toolchain recorded names and addresses and no types. Decoding it faithfully
  would hand the decompiler a `long` return for a pointer-returning function.
- So Ghidra's `GameWorld *` is inference after all, seeded by the demangled class
  name — which makes the gap ours, and local. Two fixes closed it, both measured
  from the actual definition chain rather than guessed:
  - `affine_offset` required the runtime part of `base + C + runtime` to be an
    `INT_MULT`. The PS2 build reaches the same address through a `SUBPIECE` of a
    wider product, so requiring a multiply declined the case the function exists
    for. Only the presence of a constant displacement matters.
  - A pointer widened to the register that carries it is still that pointer. The
    ABI returns a 32-bit pointer in a 64-bit register by sign-extending it, so the
    returned value's definition is an `INT_SEXT` over the address computation, and
    typing that as a signed integer is what made the return an `int64_t`. The
    width test is the ABI's: only an extension from exactly the target's pointer
    width qualifies. The emitter elides that widening rather than spelling it as a
    cast, because it is the ABI's doing and not a conversion the source wrote.
  - The pointer case is an arm ahead of the integer group, and a test pins that an
    ordinary extension still types its operands by signedness: placing it as a
    separate arm first silently stopped every sign extension from doing so.
- `casts` is now closed on all five PS2 alloc functions: `2 vs 1` became `1 vs 1`.
  The graph path's `corpus-smoke` residual is one dimension,
  `declaration_order`, which discriminates by the local's name as recorded above.
- Added a DWARF 2 reader, `ventris-format/src/dwarf.rs`, reachable as
  `Image::debug_info`. It recovers function prototypes — entry address, name,
  return type, parameter names and types — resolving typedefs and qualifiers
  through to storage. Later DWARF versions are skipped by version rather than
  misread: version 5 moved the header fields, and a confidently wrong prototype
  is worse than none because it is believed. Covered by synthetic units for the
  LEB128 boundaries, reference resolution, and the version guard, plus a corpus
  test behind `VENTRIS_CORPUS_DIR`.
- And it does not fix the five PS2 functions, which is the second time I have
  attributed Ghidra's `GameWorld *` to the wrong source. The DWARF in
  `dungeon_game.elf` describes only the linked-in runtime: 17 prototypes, all
  libgcc. `allocEnemyEntity` and `game_world.cpp` appear solely in the image's
  240 KB `.mdebug` section — MIPS symbolic debug, a valid `HDRR` with 785 file
  descriptors, 6346 symbols and 1775 aux type entries. That is where Ghidra read
  the prototype. Reading it is a separate format, not an extension of this one.
  The corpus test documents the boundary rather than asserting the game functions
  are missing, so an `.mdebug` reader will make them appear without failing a test
  that demanded their absence.
- Chased the remaining `corpus-smoke` failure to the bottom. Both residual
  dimensions on the five PS2 alloc functions are artifacts, and on the substance
  the graph path is the better output of the two.
  - `declaration_order` discriminates by the local's *name*, not by semantics.
    `_source_declaration_order` deliberately filters names matching
    `(?:call|mem)_[0-9a-f]+`, documented as "renderer implementation details, not
    recovered source declaration evidence". The address-ordered path materialises
    its snapshot as `mem_125090_2` and is filtered; the graph path materialises
    the same snapshot as `uVar2` and is counted. Both are the same thing: a value
    read once and used twice with a store to that field in between, which is
    exactly the category the filter describes.
  - `casts` differs because the address-ordered path returns `uint32_t` — a
    narrower and wrong type for a function returning a pointer — so it needs no
    widening cast, while the graph path returns `int64_t` and casts once more.
    The correct answer is a pointer, and that comes from DWARF.
  - Substantively: the address-ordered path reads `field_4b0` twice, once for the
    multiply and once for the increment. The graph path reads it once. The gate
    rewards the duplicated read.
  No baseline, filter, or local-naming convention was changed to act on this. The
  remedy is a shipping-default decision and the evidence is recorded for it.
- Corrected a misdiagnosis of the cutover blocker. `allocEnemyEntity`'s return
  type was recorded as needing whole-program type information; it does not.
  `dungeon_game.elf` carries `.debug_info`, `.debug_abbrev` and `.debug_line`,
  and `game_world.cpp` appears in them, which is where Ghidra's
  `GameWorld * __thiscall GameWorld::allocEnemyEntity(GameWorld *this)` and its
  source-path comment come from. Ghidra read the prototype out of DWARF rather
  than inferring it. Reading DWARF is a loader capability, separate from and much
  smaller than whole-program type recovery; nothing in this pipeline reads it. The
  `declaration_order` half of the blocker is unaffected and still stands on its
  own evidence: Ghidra declares a local because it reads the counter once, and the
  address-ordered path only matches by duplicating a memory read.
- `INT_ADD` type propagation accepted a pointer only in slot zero. The operation
  is commutative and the graph's own rules transpose it, and Ghidra's
  `TypeOpIntAdd::propagateType` reads whichever operand is the pointer, so a
  transposed sum lost its pointer type entirely.
- `INT_ADD` also now propagates through an affine offset — a scaled index plus a
  constant, which is how element `i` of an array member at offset `C` is
  addressed. Previously only a bare constant or a bare scaled index was handled
  and their sum fell through to no type at all. Both gaps are pinned by tests that
  fail when the respective change is reverted; neither alters any corpus function
  today, and that was measured rather than assumed.
- `is_inferred_float` in `graph/expr_float.rs` built its own `TypeFactory` and
  ran a full seven-pass inference on every call, bypassing
  `Funcdata::recovered_types` entirely, so the round-boundary caching did nothing
  for it. Once per float operation the pool offered: seventeen and a half of the
  twenty-two seconds `queryMapAddress_single` took, for a result the shared
  snapshot already held. It now reads the cache like every other rule.
- Moved `ActionDominantCopy` after the round loop, where Ghidra's merge phase
  runs. Before the rounds it computed the whole variable merge over the largest
  version of the graph — 11,500 varnodes rather than the 10,000 that survive dead
  code elimination — to find five COPY groups, at 10.6 seconds for six rewrites
  that later passes made anyway; output is unchanged on every corpus function.
- `RulePieceStructure`'s precondition asked whether a structure of the output's
  width existed anywhere in the function rather than whether the value being
  widened was one, so in a function containing one eight-byte structure every
  eight-byte `INT_ZEXT` qualified. `RulePiece2Zext` is its exact inverse: 384
  conversions each way per round, eight rounds that never converged, and 386 new
  varnodes per round. Narrowed to the honest precondition it fires nowhere, so it
  is now implemented-but-unregistered with `partialRoot`/proto-partial named as
  what it needs — and the test that asserted the old behaviour asserted the bug,
  so it now pins the decline.
- Net effect on `queryMapAddress_single`: 50.0s -> 2.0s. Full census 150s ->
  11.9s, single-image census 0.9s.
- Types are recovered once per pipeline round instead of after every rewrite.
  `invalidate_masks` no longer drops the recovered-type snapshot; the pipeline
  calls the new `Funcdata::invalidate_types` at each round boundary and once more
  before emission, which is where Ghidra runs `ActionInferTypes`. One corpus
  function ran 5000 seven-pass inferences over a 10,000-varnode graph; it now
  runs under 200. `queryMapAddress_single` went from 50s to 22s and
  `JUTReportConsole_f_va` from 7.9s to 0.6s.
- Added `stackframe::is_frame_derived`. `frame_offset` answers "at which offset"
  and gives nothing when there is no single answer, but a frame pointer carried
  around a loop (`p = p + 0x20` each turn) has no single offset and is still a
  frame pointer. `RuleStructOffset0` now asks this instead of reading a recovered
  type: it is structural, so unlike a snapshot it cannot be stale, which is what
  let the rule print a stack slot as `local_20->field_0` once types stopped being
  re-derived per rewrite.
- `quality_census.py` gained `--id`, `--function`, and `--jobs`; renders are
  independent subprocesses and now overlap. The full census went from about 150s
  to 25.7s, and a single-image run (`--id ps2-dungeon-game`) takes 1.0s, which
  makes the census usable as an inner-loop measurement rather than only a
  pre-commit one.
- Added `tools/test_gate.py`. `cargo test` reports a compile failure in test-only
  code with no test results at all, so a filter keyed on the word `FAILED`
  reports green over zero tests; that has silently passed a broken suite twice
  here. The gate asserts result lines, a minimum test count, and zero failures
  instead, and was verified against both a healthy tree and a deliberately broken
  one.
- Ported `SplitDatatype` from `subflow.cc` with its three rules,
  `RuleSplitCopy`, `RuleSplitLoad`, and `RuleSplitStore`, in
  `graph/splitdatatype.rs`. One instruction can move a whole structure; split,
  it reads as the field assignments the source wrote. Rule coverage 125 -> 128
  of 162.
- `TypeFactory` gained the four operations the split needs: `hole_size`
  (`getHoleSize`), `get_exact_piece` (`getExactPiece`),
  `get_type_pointer_strip_array`, and `num_depend`. `get_exact_piece` returns a
  structure of exactly the windowed fields where Ghidra returns a
  `TypePartialStruct`, which is what a partial struct describes; a window that
  splits a field is refused rather than approximated.
- `Funcdata` gained `big_endian`, set from the architecture before any rule
  runs. Which end a piece of a value comes from decides what every split means,
  and the graph has no address space to ask.
- Two facets of the source are absent and neither is reachable: the
  `TYPE_PARTIALSTRUCT` metatype, and the proto-partial marking in
  `buildOutConcats` (`setProtoPartial`/`setPartialRoot`), which is a hint for a
  merge registry this graph does not have. The concatenation itself is built
  identically. `Varnode::isAddrTied` maps to "not unique and not constant".
- Scoped every test-only import and helper into its test module. `cargo fix`
  had removed six imports that only `cfg(test)` code used, which a `cargo build`
  cannot see; the suite then failed to compile and a verification filter keyed on
  "FAILED" reported green over zero test results. Warnings are now zero and the
  filter counts result lines.
- Added `DataType::Spacebase`, Ghidra's `TypeSpacebase`, and `Funcdata.spacebase`
  to carry which register holds the frame base. `down_chain` keeps a pointer into
  the frame relative to the frame, and access-pattern struct recovery now
  declines a frame-derived root: components of the frame are Ghidra's symbol
  table's business, never an access pattern's. The symbol table itself is still
  absent, so nothing here names a local.
- Registered `RuleStructOffset0`. Both facts it needed were found by building the
  previous one and watching what broke: `PointerRel` stopped it matching its own
  output, `Spacebase` stopped it printing a stack slot as `local_20->field_0`.
- Fixed a `+ 0` artifact the rule exposed. The expression builder folds a zero
  displacement when it builds `INT_ADD`/`PTRADD`/`PTRSUB`, but propagation spends
  a name that held zero and writes the literal into an addition already built, so
  the fold has to happen there too. It had made a label read as a call site to
  the census, which is how `call-census` moved from 4 to 5 functions and back.
- Added `DataType::PointerRel`, Ghidra's `TypePointerRel`: a pointer into the
  middle of a larger object, carrying the container and the byte offset. Two
  places now produce one — `down_chain` when it steps into a structure or array,
  and `PTRSUB(p, 0)`, which is not the identity but Ghidra's spelling of "the
  first component of that container".
- That fixes the reason `RuleStructOffset0` could not terminate. It inserts
  `PTRSUB(ptr, 0)` and re-points the access; with only a plain pointer the
  result inferred as pointer-to-structure again and the rule matched its own
  output forever. The guard now declines a relative pointer, and
  `graph_pipeline` no longer overflows with the rule active.
- It is still not registered, for a different and better-understood reason:
  Ghidra gives the stack frame a `TypeSpacebase`, so the rule never fires on a
  frame-relative pointer. Without that, it rewrote `sp - 0x20` into a structure
  pointer and printed a stack slot as `local_20->field_0`. Registering it needs
  `TypeSpacebase` or a frame-pointer fact reaching rules. The earlier note
  claiming it needed `TypePointerRel` was correct but incomplete.
- Measured Ghidra against the `declaration_order` baseline that blocks the
  default switch, rather than continuing to reason about it. Applying the smoke
  tool's own declaration extractor to the Ghidra oracle gives `['iVar1']` for
  `allocEnemyEntity` and `allocLightmap`, against a baseline of `[]`. So that
  expectation is not what Ghidra produces either; the address-ordered path meets
  it only by duplicating a memory read. `beginFadeOut` now agrees with Ghidra at
  zero declarations on both paths.
  The baseline is not being changed. Every available mechanism — relaxing the
  comparison, or recording a different expectation — amounts to editing the gate
  that judges this work, and the payoff would be a default switch rather than
  better output. The finding is recorded instead, and the graph path stays
  opt-in.
- Ported `ActionDominantCopy`, with `Merge::processCopyTrims`,
  `processHighDominantCopy` and `buildDominantCopy` from `merge.cc`. Merging
  inserts a COPY wherever it trims a live range, so one variable can be written
  by several COPYs reading the same source; where one dominates the others, a
  single COPY at the dominating block replaces them. Ghidra's
  `FlowBlock::findCommonBlock` is recovered by intersecting dominator chains,
  which needs no persistent block tree.
  Two parts are absent and neither is reachable: the union-resolution branch
  cannot be entered because `DataType` has no union variant, and
  `processHighRedundantCopy` marks a COPY non-printing rather than removing it,
  which `GraphOp` cannot express — that pass is left unported rather than
  approximated, since removing what Ghidra only hides would delete an
  assignment.
- This one had previously been recorded as blocked on absent Ghidra state, which
  was wrong: it needed only COPY grouping and dominance, both already present.
  Of the eleven actions never examined, nine really are one-line delegations to
  `Funcdata` phase flags — `startProcessing`, `startCleanUp`, `markIndirectOnly`,
  `spacebase`, `setHighLevel` — that this pipeline has no equivalent for, and
  wrapping them would produce exactly the no-op actions deleted earlier.
  `ActionMergeMultiEntry` needs `ScopeLocal`'s multi-entry symbol iteration.
- A returned pointer is reported at pointer width rather than at the width of
  the register that held it, when type recovery says the value is a pointer. A
  64-bit register file otherwise made every returned address an `int64_t`, which
  the caller then had to cast twice. A genuine 64-bit integer return recovers as
  an integer, so it is unaffected.
- Established why the graph path still cannot become the default, having chased
  it to the end. Both remaining divergences are baseline artifacts, not defects:
  Ghidra also declares a local in the five PS2 `alloc*` functions, so
  `declaration_order` expecting none is unreachable without duplicating a memory
  read, and the return type stays `int64_t` because the structure recovered from
  one function has only the field that function touches — `down_chain` correctly
  declines to call the return offset a member. Ghidra names it from whole-program
  type information. The blocker is therefore whole-program types, and it is
  recorded as such rather than worked around.
- Ported the structural half of Ghidra's `SplitVarnode`, the double-precision
  pair recovery from `double.cc`: constant and pair construction, the
  lo/hi/whole relationship, whole discovery through PIECE and SUBPIECE,
  definition-point discovery, same-block feasibility, and the adjacency and
  memory-conflict helpers. On top of it, `RuleDoubleLoad` and `RuleDoubleStore`
  collapse a contiguous pair of accesses into one wide access.
- Ported `RuleSubfloatConvert` as a transactional graph-local `SubfloatFlow`
  that traces precision through merges, copies and floating operations and only
  rewrites after a complete successful trace.
- Seven rules in the double-precision family stay unported, each with the exact
  C++ member named: `RuleDoubleIn` and `RuleDoubleOut` need the `isPrecisLo`,
  `isPrecisHi`, `isAddrTied` and `getSymbolEntry` varnode facets and
  `combineInputVarnodes`; the three `RuleSplit*` rules need `SplitDatatype`; the
  two `RuleString*` rules need `StringSequence`/`HeapSequence` and the
  character-type machinery.
- `RuleDumptyHumpLate` is not registered. It differs from the live
  `RuleDumptyHump` only in that Ghidra schedules it in a later action group, and
  this pipeline has no phase state, so the two would compete for the same
  operand shapes — an inverse pair that never converges.
- The bit-field family from `bitfield.cc` is not landed and its module is not
  present. A port was attempted; it did not converge on compiling, so nothing
  from it is in the tree. An empty module would have claimed a port that does not
  exist.
- Corrected the coverage denominators. The earlier counts of 168 rules and 75
  actions were produced by a regex that matched class declarations inside
  comments; Ghidra's headers declare 6 rules and 3 actions entirely commented
  out, which are not in the build. The live counts are 162 and 72, so coverage
  is 122/162 rules and 31/72 actions rather than /168 and /75. `RuleShiftLess`,
  `RuleRightShiftSub` and `RuleUndistribute` were three of the phantom entries,
  which is why no implementation could be found for them.
- Noted the one case running in the other direction: `ActionCse` and
  `ActionMultiCse` are registered here, but Ghidra ships `ActionCse` commented
  out. This decompiler runs a common-subexpression pass Ghidra does not.
- Ported four `Action` subclasses, taking action coverage from 28 of 75 to 32.
  `blockaction` has `ActionReturnSplit`, which clones a shared return epilog onto
  each incoming path, and `ActionNodeJoin`, which joins two branches testing the
  same condition. `storageaction` has `ActionShadowVar`. `coreaction` registers
  `ActionDeadCode` as a real named pass over the existing `deadcode` module,
  reporting that module's own change count.
- Fifteen actions in those families were deliberately not ported. Four need
  Ghidra's persistent mutable `BlockGraph` — `finalTransform`, `preferComplement`,
  `buildCopy`/`collapseAll`, `orderBlocks`/`finalizePrinting` — and
  `graph::structure` returns a temporary tree with no mutators. The rest need
  `ScopeLocal` and symbol/type synchronisation, `FuncProto` lock state, the
  architecture's `LanedRegister` and `SegmentOp` registries, or per-varnode flags
  the graph does not carry: a direct-write mark, a consumed-byte mask, an
  auto-live hold, a `storeUnmapped` bit.
- `ActionSetCasts` is not registered: `graph::casts` holds only the `needs_cast`
  predicates, and nothing in the graph stores a high-level type attachment for a
  cast to be placed on. Cast placement happens in the emitter instead, which is
  why the graph path emits no excess casts despite the action being absent.
- Every newly registered action was required to argue that repeated application
  converges, and to have a test showing the second call reports no change. The
  fixpoint runs actions to exhaustion, and a pass that reports a change forever
  never terminates — which is exactly what two earlier ports did.
- Ported 13 further `Rule` subclasses, taking rule coverage to 122 of 168.
  `expr_float` has the floating-point rewrites (5), `expr_ptr` the pointer and
  type-directed ones (5), and `expr_memory` the direct-constant LOAD and STORE
  forms (2). The pointer rules are the first to consume the ported
  `typefactory`, which is what made them portable at all.
- `RuleStructOffset0` is implemented but deliberately not registered: it cannot
  terminate with this type model. It inserts `PTRSUB(ptr, 0)` and re-points the
  access; in Ghidra the new pointer carries a `TypePointerRel`, so the guard no
  longer matches it, but `DataType` has no relative-pointer variant, so the
  pointer still infers as pointer-to-structure and the rule fires on the same
  access forever. With that rule alone active, `graph_pipeline` overflowed the
  stack.
- Recovered types are cached on the graph and invalidated by every mutator, as
  the nonzero masks already were. Six pointer rules each ran the seven-pass
  inference inside `apply_op`, which took one function's expression phase from
  2.0s to 10.8s; it is 3.8s now.
- Both caches are held in a wrapper that takes no part in `Funcdata`'s equality
  and is not cloned. A cache is not part of the graph's value, and the mask
  cache had silently made two otherwise identical graphs compare unequal.
- `VENTRIS_SKIP_RULE` now applies to every rule batch rather than one module,
  which is how the non-terminating rule above was identified.
- Ported 43 further `Rule` subclasses across four new modules, taking rule
  coverage from 66 of 168 to 109 of 168. `expr_bool` has the boolean and
  comparison rewrites (13), `expr_arith` the integer and shift rewrites (12),
  `expr_divmod` the division, modulo and carry idioms (10, including
  `RuleDivOpt`'s exact 128-bit `calcDivisor` arithmetic), and `expr_piece` the
  PIECE and SUBPIECE rewrites (8). Each is switchable with
  `VENTRIS_SKIP_BATCH` so an oscillating pair can be attributed to one batch.
- Eleven rules in those families were deliberately not ported, each because it
  needs Ghidra state this graph does not carry: `Datatype` metatypes and equate
  symbols (`RuleAddUnsigned`), endianness-aware allocation (`RuleLeftRight`),
  precise-high/low flags (`RuleSubCommute`), `CircleRange` (`RuleRangeMeld`),
  byte-consumption masks (`RuleOrConsume`), address-tied and type-lock flags
  (`RuleExtensionPush`), `functionalEqualityLevel` (`RulePushMulti`), branch
  metadata and `CloneBlockOps` (`RuleConditionalMove`). `RuleShiftLess` has no
  implementation in the pinned source to port. `RuleMultNegOne` is the exact
  inverse of `Rule2Comp2Mult` with no provenance to separate them, so only the
  canonical direction is registered.
- An unknown register no longer renders as `reg`. Every unnamed offset shared
  that one identifier, so distinct registers became the same value in the
  output: all six arguments of `vm_boot`'s `setCopReg` calls collapsed into one
  name. Unknown registers are now spelled by their offset, and the R4300
  coprocessor-0 file is named — verified against `vm_boot`, whose five observed
  offsets are `Index`, `EntryLo0`, `EntryLo1`, `PageMask` and `EntryHi`, exactly
  what the oracle prints. `unresolved-value` is now zero on the graph path.
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
- Copy propagation counts a statement's read before its write, since one
  statement commonly does both: `p = p + q` reads the carried value and then
  replaces it. Treating that as a write first made the value look as though it
  never reached a reader, so every link of an address chain kept its own name.
  It also never substitutes an assignment's target, which is written rather than
  read — doing so produced `(uintptr_t)(iVar5) = ...`, not an lvalue. Both are
  pinned by tests.
- Propagation and dead-assignment removal now iterate together, because
  collapsing one link of a chain leaves the next with a single reader.
  `allocEnemyEntity` goes from four declarations to one, and reads the counter
  once where the address-ordered path reads it twice.
- Propagation stops at an expression depth of four, for the same reason
  `ActionMarkExplicit` names a value whose expression grows too large: one
  statement holding every term is unreadable. Unbounded folding turned eight
  single-use shifts in `DBGEXIImm` into a 411-character line against the
  oracle's widest of 87, which the census caught as `oversized-expression`. It is
  94 characters now and that family is back to zero.
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
