# Changelog

All notable Ventris changes are documented here.

## [Unreleased]

### Added

- `ZPULL` and `SPULL` are now spelled by the printer. `RuleBitFieldLoad` rewrites
  a shift-and-mask extraction into one of them, and nothing in `value.rs`,
  `emit.rs` or `native.rs` handled either opcode - so `translate` returned
  nothing, the extracted value fell back to storage, and a UNIQUE-space varnode
  printed as a bare `loc_2_*` placeholder. That is why
  `ksNesDrawBG__FP18ksNesCommonWorkObjP13ksNesStateObj` tested `if (loc_2_55)`
  where the oracle tests `if ((*(byte *)(iVar3 + 0xbb9) & 8) != 0)`: the
  comparison was not lost in analysis, it was unprintable. With no field metadata
  the faithful C is the shift and mask the rule collapsed, so a pull renders as
  `(root >> pos) & mask`, and a signed pull carries the recovered type as a cast.
  All five placeholders in that function are gone and its conditionals now read
  as real bit tests - `if (uVar36 >> 3 & 1)` against the oracle's masked
  comparison. Nine lines shorter, gates clean, and the regression test resolves
  to `Temporary { name: "loc_2_0" }` without the arm.
- Corrected the earlier diagnosis this replaces: the bisect to `bitfield_load`
  was right about the rule but wrong about the mechanism. A probe over every
  UNIQUE varnode with readers and no definition found that the rule creates no
  orphans at all - `destroy_dead_value` is correct. The values always had
  definitions; the printer simply could not express them.
- Located the source of those unresolved temporaries by bisecting the pipeline
  with `VENTRIS_SKIP_GROUP` and `VENTRIS_SKIP_RULE`: the `cleanup` pool, and
  within it `bitfield_load`. Skipping that one rule takes
  `ksNesDrawBG__FP18ksNesCommonWorkObjP13ksNesStateObj` from five undeclared
  temporaries to none, with the same eleven conditionals and one line fewer;
  skipping `pull_absorb` leaves four. `RuleBitFieldLoad` rewrites an extraction
  tree into `ZPULL`/`SPULL` and then calls `destroy_dead_value` on the old input.
  That helper does guard on remaining descendants, so the orphan comes from the
  interaction between rewriting one branch of a shared tree and destroying
  another, not from a missing check at the call site. No control-flow action is
  involved - all fourteen were skipped individually with no effect. The output is
  valid C because every temporary is now declared, and the census is unaffected,
  so this is a latent defect rather than a visible one, recorded with the exact
  bisect that finds it.
- Every temporary the body names is now declared. A value with no definition and
  no register name renders as `Expr::Temporary`, which prints as a bare
  identifier; Ghidra declares such a value instead - it prints `int unaff_r2;`
  for a register the function never writes - and an undeclared identifier does
  not compile. `ksNesDrawBG__FP18ksNesCommonWorkObjP13ksNesStateObj` named five
  of them, `loc_2_35` through `loc_2_82`, all UNIQUE-space reads that reached the
  printer unresolved. Verified pre-existing rather than introduced by the p-code
  block split: the same five appear at `42ec853`, before it. `output_check.py`
  now checks for undeclared identifiers too, and fails with exactly those five
  when the declaration pass is removed.
- Every block leader must name a lifted instruction. The p-code split added an
  exemption for machine-level leaders, keeping one whose address had no lifted
  instruction: the block then received no operations while still carrying the
  edges that named it, which is a block with two successors and no branch to
  choose between them. Census-neutral and gate-clean, but the invariant now holds
  by construction rather than by luck.
- Refuted: suppressing a conditional whose test is fabricated. `condition_expr`
  falls back on a constant when a `Condition::Branch` names a block whose
  terminator is not a `CBRANCH`, and `DBGEXIImm` printed `if (!1)` around its
  whole main loop - a body our output therefore never executes. Emitting that
  body unconditionally when the test is not carried by the graph does remove the
  fabrication, but it also suppresses `TRK_fill_mem`'s real conditional return,
  taking `missing-conditional` 3 -> 4 and `return-presence` back with it. The
  predicate cannot distinguish the two cases as written, so the fix belongs in
  the structurer - not building an `IfElse` with no test - rather than in the
  emitter deciding not to print one.
- A `CBRANCH` to an address that is not its instruction's last operation now
  splits that instruction, which recovers PPC's conditional return. `beqlr`
  lifts to `if (!cond) goto <next>; return;` - the whole conditional return
  inside one instruction - and `sleigh_flow` reports it as plain `FallThrough` so
  the fall-through survives. With the instruction unsplit the guard was merged
  away entirely: `TRK_fill_mem` lost the oracle's `if (param_3 != 0)` and one of
  its two returns, and rendered the guarded loop unconditionally.
  `missing-conditional` 4 -> 3, and `TRK_fill_mem` now matches the oracle on both
  counts - four conditionals and two returns.
- Measured while narrowing that rule: making the branch's *target* a leader as
  well costs `unstructured-control-flow` 4 -> 5 when the target is the
  instruction's own sequential successor, because that is already where the
  following block begins and splitting again separates operations Ghidra keeps
  together. The leader is therefore added only for a target elsewhere, which is
  the case that genuinely needs one.
- Added `tools/output_check.py`, a gate that asserts the rendered C is
  structurally well formed on every corpus function. The quality census measures
  how close the output is to Ghidra's; this measures something weaker but
  absolute - that it is valid C at all. Ghidra never declares a variable twice,
  never jumps to a label it did not print and never emits a statement after an
  unconditional return, so each of those is an equivalence failure however the
  census classifies the function. It checks parameter shadowing, repeated local
  and global declarations, dangling jumps, brace balance, and statements after a
  return. It is now a required tool in `release_check.py`, and it passes on all
  36 functions.
- Two defects it caught, both fixed. A parameter is declared by the signature, so
  the variable holding it must not be declared again: `TRK_fill_mem` emitted
  `uintptr_t arg0;` beside the parameter `arg0`, and suppressing only the
  function-scope declaration then produced `uint32_t arg2 = arg2 + ...;` inside a
  block - shadowing the parameter it was assigning to. Parameter names now stay
  in `scoped_names` so a write to one is an assignment, while emitting no
  declaration of their own.
- A `return` immediately followed by reachable code is now removed. Nothing can
  reach a statement after an unconditional return except by falling through it,
  so when the next statement is not a label the return is the wrong statement,
  not the code after it - dropping the code would lose real behaviour, and Ghidra
  emits the code. `TRK_fill_mem` printed `return arg0;` directly before a live
  `do { ... } while (arg2 != 0);`, from a block placed out of construct order; it
  now renders one return where the oracle has two, 65 lines against 56, with the
  loop intact. A return before a *label* is kept, because a jump can arrive
  there.
- One root cause now accounts for three separate residuals, and it is block
  placement in structuring rather than anything downstream. When a rule leaves an
  edge to a block no construct claims, `finish()` appends that block as its own
  region - deliberately, so the output stays complete rather than silently losing
  code - and the guard that should have wrapped it is gone. The three shapes it
  produces: `TRK_fill_mem` emits `return arg0;` immediately followed by a live
  `do { ... } while (arg2 != 0);` where the oracle has
  `if (param_3 != 0) { do { ... } while (...); return; }`, which is its whole
  `if 3 vs 4` gap; `__FrameCallback__Fl` never places the block holding the
  oracle's `return &DAT_800eaff8;`, which is its void-versus-value and its call
  count; and `decompSZS_subroutine__FPUcPUc` plus `queryMapAddress_single` keep
  gotos to blocks placed out of construct order. Verified that this is not the
  single-live-node completeness guard added this session - removing it changes
  neither the conditional count nor the unreachable tail.
- `TRK_fill_mem` now matches the oracle on `for`, `while`, `do` and `goto` counts
  exactly (2/2/2/0) after the parameter-name fix, leaving only the conditional
  above and its return. Its `return arg0;` against the oracle's void is r3 being
  both the first argument and the return register on this ABI: the value is the
  unmodified incoming pointer. The two functions that legitimately `return
  param_1;` - `Sou_BgmTenkiConv__FUc` and `convert_partial_address` - have the
  same shape, so no local rule separates them, which is why all three archived
  ancestry attempts traded one for the others.
- A variable group holding a function input at an argument location now takes
  that parameter's own name. This closes the chain traced earlier: the trials
  were right, the prototype held all three parameters, and the group even
  resolved to `arg2` - but `make_unique` reserves the `arg`/`farg`/`varg`
  namespace so an ordinary local can never collide with a parameter, which is
  right for a local and wrong for the parameter itself. It renamed the
  parameter's own variable to `var_arg2`, and because `recover_parameters`
  derives the signature from the names in the emitted statements, the parameter
  disappeared from it. `TRK_fill_mem` now renders
  `sub_800a67d8(uintptr_t arg0, uint32_t arg1, uint32_t arg2)` against the
  oracle's `FUN_800a67d8(int param_1, byte param_2, uint param_3)` - three
  parameters where it previously showed two. The reserved-namespace rule still
  applies to every other group, which the regression test pins from both sides.
  The earlier attempt at this failed because it stopped at preferring the name;
  the guard downstream was the actual blocker.
- One global-pointer base is now declared once however many recovered structures
  reach it. `rewrite_recovered_field_accesses` pushed a declaration per
  structure, so a register reached as two different structures emitted two
  globals with the same name - `DBGEXIImm` printed both
  `RecoveredStruct0 *pVar18;` and `RecoveredStruct1 *pVar18;`, which does not
  compile. One storage location has one type, so the first declaration stands.
  Census-neutral; the regression test fails without it, producing exactly that
  pair.
- Refuted, and recorded so it is not retried: making a parameter's name outrank
  the register spelling does not recover `TRK_fill_mem`'s third parameter.
  Exempting a function input from `register_name_for_group`'s
  "this register is written somewhere" refusal does change the naming - `uVar8`
  and `pVar18` become `r20` and `r12` - so the group is nameable. But threading
  the parameter map into group naming and preferring it produced no `arg2` at
  all, which means no varnode in that group carries `flags.input` at `(4, 20)`
  with no definition; the register spelling is reached by a different route than
  the input flag. It also cost `call-census` 2 -> 3. Both halves reverted. The
  next step is to find what actually holds r5's entry value in that group, not to
  add another naming preference on top.
- `TRK_fill_mem`'s two families trace to one cause, now located exactly. Its
  input trials are right - r3, r4 and r5 all `Active` with values - and
  `promote_input_trials` puts all three into the prototype, verified by probe
  (`proto_params=[(12,..),(16,..),(20,..)]`). The signature still renders two
  parameters because `recover_parameters` derives them from the *names in the
  emitted statements*, and r5's value prints as `uVar8` rather than `arg2`: r5 is
  reassigned inside the function, so its value passes through a phi, and our
  naming is per-SSA-version while Ghidra's is per-`HighVariable`. Ghidra merges
  the parameter and its phi into one variable and prints `param_3` throughout,
  which is why its signature keeps all three. Closing this needs the parameter
  and its phi to share a name - `merge.rs`/`namevars.rs` territory - not more
  work in trial promotion, and the spurious return value is the same shape of
  defect one location further along.
- A terminator that outlives the block it names is now repaired in the graph.
  Ghidra's branch operands are block references, so removing a block cannot leave
  a predecessor pointing at it; ours are addresses, and unreachable removal drops
  the edge without touching the operand. `ActionPruneDeadTargets` converts a
  conditional whose remaining destination is its own fall-through into a plain
  branch, and destroys an unconditional one that names nothing at all. Measured
  against the emitter's dangling-jump pass: with the graph pruner alone,
  `TRK_fill_mem` and `decompSZS_subroutine__FPUcPUc` have no dangling jump left
  to print, so the repair happens at the source rather than in the output for
  two of the three cases; `__FrameCallback__Fl` still needs the emitter pass, so
  both are kept. Its regression test fails without the action.
- Located `__FrameCallback__Fl`'s remaining two families precisely. Three jump
  targets - `0x8000b594`, `0x8000b59c` and `0x8000b684` - are named by surviving
  jumps but never labelled, because the structurer leaves an edge to a block it
  does not place in the tree. `0x8000b684` is where the oracle's
  `return &DAT_800eaff8;` lives, which is why the function reads as void against
  the oracle's `undefined2 *`, and why its call count is 5 against 8. The
  dangling-jump pass makes the output valid C but cannot recover the block: the
  fix is to place every block a surviving edge reaches, in the structurer, not to
  print a label for statements that were never emitted.
- Re-measured the three archived output-ancestry commits (`7066912`, `4212d8d`,
  `f38a689`) against the current tree, since the resolver, terminator and
  emission fixes changed everything around them. All three still take
  `return-presence` 2 -> 3 for no gain elsewhere, so the working tree remains the
  best measured state and `TRK_fill_mem`'s void-versus-value stands open.
- The remaining loop residual is located precisely, and it is a structurer
  capability gap rather than emitter cleanup. `decompSZS_subroutine__FPUcPUc`
  recovers the oracle's two inner `do`/`while` loops but renders the outer one as
  `while (1)` with four `goto`s to two exit labels, where the oracle has
  `do { ... } while (param_2 < pbVar10)` and no gotos: `rule_do_while` does not
  attach the bottom test when the loop carries more than one exit edge, so the
  loop becomes an infinite one with jumps out. Three emitter-side attempts were
  measured and reverted because they changed no output - pruning a jump across
  intervening labels, extending the trailing-jump pruner past the first following
  label (which also broke the standing rule that a trailing jump out of a *loop*
  is an early exit, not a fallthrough), and collapsing a run of consecutive
  labels onto the last. `queryMapAddress_single` renders `for=0` against 2 for
  the same reason: its loops are recovered, but not in the shape that carries an
  initializer and an iterator.
- `preamble`'s six missing calls are closed. Two pieces were needed. The trivial
  jump model now evaluates a destination built out of constants: MIPS `jr` clears
  the target's low bits, so a folded address arrives as
  `INT_AND(INT_2COMP(2), target)` through a COPY rather than as a bare constant,
  and a destination that evaluates to one address is routed to the trivial model
  before the table models - which all fail on a target already known. Multistage
  discovery then reaches `0x80001050` and emits exactly the oracle's five
  `setCopReg` and `TLB_write_indexed_entry`. Second, `ActionResolvedIndirect`
  turns a `BRANCHIND` whose destination folded to a constant into an ordinary
  `BRANCH` when the block already reaches exactly that target, so the jump stops
  rendering as `goto *(...)`. `call-census` 3 -> 2 with `agrees` holding at 26
  and `unstructured-control-flow` unchanged; `preamble` emits no gotos at all.
  This is the same fix that cost `agrees` earlier in the session - it pays for
  itself now that the resolver and the emitter no longer leave a dangling jump
  behind it.
- A jump whose label was never emitted is now removed, so the output is valid C.
  It arises when structuring surrenders an edge into a region later analysis
  proved unreachable and therefore never printed: `drop_labels_nothing_needs`
  removed labels no jump names, but nothing removed jumps no label answers.
  `__FrameCallback__Fl` had three such jumps and `TRK_fill_mem` two before any of
  this session's work, so the defect is not new. The complement pass runs to a
  fixed point with the label pruner, since each exposes the other.
  `__FrameCallback__Fl` now emits zero gotos, matching the oracle, and
  `unstructured-control-flow` falls 4 -> 3.
- A relative p-code destination past an instruction's last operation is a branch
  to the next address, and is now spelled as one. `__FrameCallback__Fl` has four
  such branches (target 16 in a thirteen-operation instruction). Their taken edge
  was dropped, so the block kept a `CBRANCH` with a single successor - a test
  deciding nothing - and `Funcdata::branch_target` returned `None`, which is the
  condition that silently disables every pass asking where a branch goes. The
  next instruction is now a leader, the edge is drawn, and the destination
  operand becomes an ordinary address. Inert on the present corpus; the
  regression test fails without it, resolving to `None`.
- A rendered condition now comes from the block's terminator. `condition_expr`
  took the *first* `CBRANCH` found anywhere in the block, while every pass that
  reasons about a branch uses the last operation. With one instruction split into
  several blocks an interior `CBRANCH` could sit mid-block, and its condition -
  already folded to a constant, which is why no pass had removed the branch -
  was rendered as the block's test. `__FrameCallback__Fl` printed
  `if (!(0 || !(...)))` and two `if (0)`; it now prints none of them, three
  fabricated constants down to zero, with the census unchanged.
- Also measured and rejected: re-running the control-flow passes to convergence
  after `ActionDominantCopy` (Ghidra keeps that pass inside the pool, so its pool
  does re-converge). Changes no census family and no function's output, so the
  constants it was meant to catch were never reachable that way.
- Every pass that asks where a branch goes now uses one resolver.
  `branchaction.rs`, `blockaction.rs`, `structuretransform.rs` and
  `jumptable.rs` each mapped a branch's destination varnode to a block by
  matching `block.start == offset`. For a relative p-code destination the offset
  is an operation index, so the match found nothing and `ActionDeterminedBranch`,
  the block actions and the guard analysis all silently became no-ops on any
  instruction that branches internally. `Funcdata::branch_target` resolves both
  forms, `Funcdata::block_starting_at` is the address-only lookup, and the entry
  lookups now require `start_order == 0` so a mid-instruction block can never be
  mistaken for the entry. `__FrameCallback__Fl` drops from eleven gotos to five
  and from 123 rendered lines to 94.
- Consequence, measured and accepted: with the dead branch now correctly folded,
  `__FrameCallback__Fl`'s only `return` carrying a value was in it, so the
  function became void where the oracle returns `undefined2 *` -
  `return-presence` 1 -> 2. `agrees` holds at 26. The value was previously
  printed only inside an `if (0)` that should never have survived, so this is a
  real defect surfacing rather than a new one.
- Consecutive blocks within one instruction now fall through to each other.
  With the p-code split in place but no fall-through edge, the guarded body of an
  internal branch had no successor at all and read as a dead end. Inert on the
  present corpus - `__FrameCallback__Fl`'s residual gotos have an unrelated cause
  - but load-bearing by construction, and the regression test proves it: without
  the pass the body's successors are `[]`.
- Basic blocks are now p-code level, as Ghidra's are. A `CBRANCH` whose
  destination lies in the constant space is a *relative* p-code branch - the
  constant is added to the branching operation's own index - so it branches
  within one instruction. `block_leaders` and `from_lifted` worked on machine
  addresses only, so such a branch was never a block boundary and its guard was
  discarded: `__FrameCallback__Fl` carries eighteen of them from PPC
  paired-single arithmetic and rendered `if 3` against the oracle's 7. Leaders
  are now `(address, p-code index)`, `GraphBlock` carries `start_order`, an
  instruction splits into as many blocks as its own branches require, and
  `taken_successor` resolves a constant destination to the block at that
  operation so `successors[0]` stays the taken side. `missing-conditional`
  5 -> 4, every other family unchanged, and `__FrameCallback__Fl` leaves that
  family with its conditional count matching exactly.
- Measured negative on the remaining loop shapes. `queryMapAddress_single`
  renders `for=0` against the oracle's 2 (and `while=7 do=4 goto=8` against
  `while=6 do=6 goto=4`); `decompSZS_subroutine__FPUcPUc` now matches the
  oracle's three `while` but renders `do=2 goto=6` against `do=3 goto=0`. The
  suspected cause - `find_loop_variable`'s `path[4]` bound - is not it: the bound
  is written against the work stack's length rather than the traversal depth, so
  it is not Ghidra's rule, but carrying the depth per work item changes no output
  on any corpus function, so the loop variable is not being lost there. Both
  functions' residual is upstream of the loop finder.
- Keep the composite's own edges out when absorbing a clause that returns.
  `rule_block_if_return` collapses an `if` whose clause returns, so that clause
  contributes no external successor and the union of the members' exits is empty.
  Replacing the composite's successors with it dropped the head's other path
  outright, leaving a dead end no later loop rule could recognise.
  `decompSZS_subroutine__FPUcPUc` goes from seven gotos to six. Census-neutral,
  with a regression test that proves the dead end (`successors: []`) without the
  fix. The wider variant - keeping the head's own edges in *every* absorption -
  is wrong and was measured as such: `agrees` 26 -> 25, `missing-loop-or-switch`
  2 -> 4, gotos 7 -> 13, because a loop head's edges into its own body are
  internal once absorbed.
- Measured, not landed: `preamble`'s six missing calls are recoverable and the
  fix does not pay for itself yet. MIPS `jr` masks its target, so the resolved
  destination reaches `recover_trivial` as `INT_AND(INT_2COMP(2), target)`
  through a COPY rather than as a bare constant, and `constant_value` reports it
  unknown. Evaluating that chain and routing a folded-constant destination to the
  trivial model before the table models - which all fail on a target already
  known - lets multistage discovery reach `0x80001050` and emit exactly the
  oracle's five `setCopReg` and `TLB_write_indexed_entry`, taking `call-census`
  3 -> 2. It costs `unstructured-control-flow` 4 -> 6: the resolved BRANCHIND
  still prints `goto *(0x80001050 & ...)` ahead of the block it reaches, and
  `vm_boot` regresses identically, so `agrees` drops 26 -> 25.
- Found while chasing that goto: `ActionSwitchNorm` is ported, unit-tested, and
  registered in no pipeline - it has never run. Registering it after the
  expression fixed point (normalization needs the folded destination) does remove
  both gotos, `unstructured-control-flow` 6 -> 4, but its pre-existing
  branch-input fold then damages a switch that previously worked:
  `missing-conditional` 5 -> 6 and `missing-loop-or-switch` 2 -> 3. Dropping the
  requirement that the graph already reach the target gives `call-census` 3 -> 4
  with the same two regressions. All three variants are neutral or worse than
  baseline on `agrees`, so none landed; the port of the branch-input fold needs
  auditing against `JumpTable::foldInNormalization` before the pass is enabled.
- `__FrameCallback__Fl` (`goto` 2 vs 0, `if` 3 vs 7) is blocked on
  intra-instruction p-code control flow: a PPC paired-single lifts to a
  `CALLOTHER` guarded by a `CBRANCH` whose target is in CONST space, meaning
  "skip N p-code ops within this instruction". `block_leaders` in graph.rs builds
  blocks purely from `function.edges`, which are machine addresses, so such a
  branch is never a block boundary and its guard is lost. Ghidra's basic blocks
  are p-code level; matching that is a structural change to `from_lifted` and
  everything keyed on address-to-block.
- `queryMapAddress_single`'s missing `for` loops are blocked earlier than the
  loop finder: its condition reaches a free input varnode with no definition, so
  `forloop.rs` cannot locate the head `MULTIEQUAL` or the iterator. The loop
  code is not at fault; the value's definition is missing upstream.
- Link a narrow register read to an overlapping wider definition regardless of
  offset. `tightest_containing` searched only for a wider definition at the
  *same* offset, but a big-endian bank writes the whole register at its base and
  reads the low half further in: MIPS64 `lui` defines `(64, 8)` and the
  following `addiu` reads `(68, 4)`. Every `lui`/`addiu` address on N64
  therefore minted an entry value, so real constants became invented parameters.
  `preamble` rendered its base as `(uint32_t)(arg4 >> 0x20) - 0x51e0` and now
  renders the oracle's `0x8008ae20`, and its computed jump folds from
  `((uint32_t)(arg4 >> 0xa0) + 0x1050 & ...)()` to the concrete `0x80001050`.
  `SUBPIECE`'s operand is now the distance to the wide value's least significant
  end rather than a hardcoded zero, which is the far end of the register on a
  big-endian bank. Census-neutral and gate-clean; it is a correctness fix and the
  prerequisite for resolving `preamble`'s tail.
- Give every direct callee its own call prototypes when recovering a caller.
  `direct_call_prototypes` decompiled each callee with no prototypes for the
  callee's own calls, so a forwarding callee recovered no parameters and the
  caller then read arity zero and discarded the arguments it had computed.
  `osContGetReadData` rendered `(void)` and called `sub_8005d01c()` empty; it now
  renders `uint32_t arg0` and passes three arguments. `agrees` 25 -> 26,
  `missing-parameters` 1 -> 0.
- Require active output evidence before promoting a return value, porting
  `AncestorRealistic` and `ancestorOpUse` with the COPY/PIECE ancestry that keeps
  a direct pass-through valid. `agrees` 24 -> 25, `return-presence` 3 -> 1.
- Measured negatives, recorded so they are not re-attempted blind: two of the
  three `call-census` entries are census-tool artifacts rather than decompiler
  defects. `changeGroupID__7JKRHeapFUc` emits one indirect call and so does the
  oracle - `uVar2()` against `(**(code **)(*param_1 + 0x40))()` - and the lexical
  counter cannot see the double-pointer spelling; `__FrameCallback__Fl` has both
  real calls on both sides, and the 7-versus-8 is two `CONCAT44` pseudo-calls
  counted in the oracle against one cast counted in ours. Only `preamble` is a
  real defect, and measurement moved its diagnosis: discovery is not the cause.
  `preamble` lifts 79 instructions over 316 bytes and does reach the
  `0x80001050` tail; reclassifying `BRANCHIND` as fall-through rather than
  return changes neither the lifted extent nor any census family. What actually
  fails is target folding - `jr t2` renders as
  `((uint32_t)(arg4 >> 0xa0) + 0x1050 & ...)()`, holding the `0x1050` offset
  symbolically instead of folding it to a concrete address the way Ghidra does
  before continuing there. The `arg4 >> 0xa0` operand is the compounding defect:
  a MIPS64 32-bit sub-register read is modelled as a shift of a 64-bit pair, so
  the base is unusable and no fold is possible. Fixing the sub-register width
  modelling is the prerequisite, not flow classification or call recognition.
- Rejected on measurement: extending the output-ancestry check to reject values
  reaching stores makes `TRK_fill_mem` void as the oracle has it, and takes two
  other functions' return values away with it - `return-presence` 1 -> 3 for no
  `agrees` gain.
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
- Ported `CollapseStructure::ruleCaseFallthru`, the eleventh and last of
  Ghidra's collapse rules. A case that runs on into another case cannot be spelled
  by this construct tree — there is no "continue into the next case" — so the
  fallthrough edge is surrendered and the switch rule claims the rest. It is
  offered after `ruleBlockSwitch` for a reason the test makes concrete: when the
  fallthrough target has two predecessors it *is* the switch's exit, and the whole
  shape structures with no surrendered edge at all, one labelled case breaking out
  to the same block a direct selector would reach.
- `CollapseStructure` is now fully ported: all 11 collapse rules.
- Ported `CollapseStructure::ruleBlockSwitch`, the last collapse rule that
  handles a node with more than two successors. Every other rule requires a
  two-way branch, so an indirect branch was a node no construct could claim and
  each of its edges left as a `goto`. The rule finds the exit block — a case
  target that loops back, or that several paths reach, or that itself branches,
  falling back to the single successor the cases share — checks that each case is
  entered only by falling in from the switch and leaves only to that exit, and
  collapses the lot into one construct.
- Added `Structured::Switch` and its emission as `NativeStatement::Switch`, which
  the printer already supported. It carries the selector varnode and each case's
  recovered label, and the traversals that walk the construct tree
  (`drop_jumps_to`, `collect_blocks`, `ends_in_transfer`, `goto_targets`) handle
  it.
- The case labels come from `jumptable::recover_jump_tables`, which reads the
  table out of the image, so `decompile_via_graph` now takes the memory accessor
  and threads the recovered tables to the structurer. **Without a table the rule
  declines**: the cases are alternatives, and emitting them unlabelled would
  print them as a sequence that runs in turn. Two tests pin both directions — a
  multi-way branch with a table becomes a switch with no `goto`, and the same
  branch without one keeps its edges.
- Census unchanged at 22 agrees: none of the 37 corpus functions has a
  table-backed switch the rule can claim, and `dl_G_MOVEWORD`'s `switch 0 vs 1`
  is a `BRANCHIND` whose table this pipeline does not recover. The rule is
  correct and tested; it has no corpus function to improve yet.
- The graph path is the shipping default wherever a calling convention is known,
  which is every `--target`. Measured against the Ghidra oracle on all
  thirty-seven hash-verified corpus functions it leads the address-ordered path
  on eight families, ties one and trails two:

  | family | graph | address |
  | --- | --- | --- |
  | agrees | 21 | 19 |
  | unstructured-control-flow | 10 | 15 |
  | missing-loop-or-switch | 4 | 11 |
  | excess-casts | 0 | 5 |
  | oversized-expression | 0 | 3 |
  | unreduced-flag-expression | 0 | 1 |
  | missing-parameters | 0 | 1 |
  | return-presence | 2 | 3 |
  | call-census | 4 | 3 |
  | missing-conditional | 7 | 2 |

  Given only `--arch` there is no convention to port from, and that showed up
  three separate ways before this landed - a forwarding function lost its
  parameter, a function returning a value reported `void`, and a global base went
  undeclared - so the address-ordered path still answers there. Two of those are
  now fixed regardless; the third is why the switch is conditional rather than
  unconditional. `VENTRIS_PIPELINE=address` forces the old path and
  `VENTRIS_PIPELINE=graph` forces the new one, which is how the census compares
  them.
  One assertion changed with it, stated plainly: `raw_mips_ps2_source_reconstruction_smoke`
  checked that 16-bit accesses survive into the C types by looking for
  `uint16_t`, which the address-ordered path produced as an invented local. Those
  are globals reached through the convention's global pointer, not locals, so the
  graph path declares them as 2-byte members of the recovered structure. The
  assertion now accepts either spelling of the same fact. I did not type the
  members `uint16_t` to satisfy it - two bytes of unknown type are honestly
  `uint8_t[2]`.
- A structure reached through a register that is not a parameter now gets its
  base declared and its members indexed. On a raw PS2 image the graph path
  rendered `gp->field_neg_47e6 = 0` with `gp` introduced nowhere and a two-byte
  member assigned whole; it now emits `RecoveredStruct0 *gp;` and
  `(gp->field_neg_47e6[0]) = 0`, so the output compiles. The base is accepted
  only when it is the sole identifier the structure's members are reached
  through, so a partial match cannot rename an unrelated variable.
  This is the shape the address-ordered path spells as invented locals
  (`uint16_t local_47e6`), which is a plausible-looking but wrong claim: these
  are globals reached through the convention's global pointer, not locals.
- A member the body writes is now a member the structure declares. The graph
  emitter named a field from its offset's unsigned bit pattern and the source
  reconstruction named it from the signed value, so a structure reached through a
  global-pointer register declared `field_neg_47e6` while the body wrote
  `gp->field_ffffb81a` - a member that does not exist. Both spell it
  `field_neg_<magnitude>` now, and the access rewriter recognises that spelling
  instead of clamping a negative offset to zero.
- A structure's layout starts where its first field does, not at zero. One
  reached through a global-pointer register has negative offsets, and measuring
  padding from zero reported every field as overlapping a predecessor it does not
  have: three fields at `-0x47e8`, `-0x47e6` and `-0x47e4` each carried an
  "overlapping field ... retained as observed" comment. Padding is also named the
  way the fields are, so a gap at a negative offset reads as `_pad_neg_47e7`
  rather than as its 64-bit two's complement. Both paths render these structures,
  so both improved.
- The graph path passes `corpus-smoke` on every entry. That gate has been the one
  thing keeping it behind an environment variable since it was written.
  The last dimension was `declaration_order`, and the filter's own comment
  described the construct exactly: "a snapshot exists because a store would
  otherwise change what a later read observes; the original source names no such
  variable." Its pattern matched only `mem_<address>_<n>` and `call_<address>`,
  the address-ordered renderer's spelling. The graph emitter names such a local
  like any other temporary - and so does Ghidra, which calls the one in
  `allocEnemyEntity` `uVar1`, so naming is not the distinguishing feature.
  `_memory_snapshots` now recognises one structurally: a local assigned a
  member's value where a later statement assigns to that same member. This is a
  defect fix in the instrument, not a change of baseline - the filter now
  exempts the artifact it was written to exempt, whichever emitter produced it.
- A call's arguments come from the convention, not from every heritaged register.
  Guarding all of them made an argument out of whatever the call instruction
  itself read: PowerPC's `bl` touches `r2`, so a forwarding function rendered
  `sub_80003120(r2)` and lost its own parameter, where the address-ordered path
  recovered `sub_80003120(arg0)`. Ghidra's trials come from the prototype model
  for the same reason. With no convention every location still stands.
  Census `missing-parameters` 1 function -> 0.
- With no convention, the graph path guards the architecture's own result
  register, which is what the address-ordered path has always done. Without it
  `--arch ps1` with no target returned `void` where a value was returned.
- `decompile_native_supports_common_processor_raw_images` asserted a per-
  architecture default return type. The width is the architecture fact it exists
  to check; signedness is now recovered rather than defaulted, and on PS2 the
  inference reads MIPS64's sign-extending immediate as signed. The assertion
  accepts either spelling of the width.
- Tried making the graph path the default and reverted it, on evidence. Three
  no-convention gaps surfaced and were fixed - the forwarding parameter, the
  return register, and `decompile-native`'s signedness - but one remains: on a
  raw image with no symbols the graph path renders a convention register's base
  as `gp->field_ffffb81a`, which is closer to the truth than the address-ordered
  path's invented `local_47e6`, and leaves `gp` undeclared with the 2-byte
  members typed as byte arrays. Both paths already emit undeclared registers, so
  this is not new; what is new is that it would be the default. Reverted rather
  than shipped, with the reason recorded in `graph_pipeline_requested`.
- Closed `casts` on the graph path. `graph::types::infer_types` propagated a
  pointer type to *every* non-constant operand of an addition, so a scaled index
  became a pointer and the emitter dutifully spelled the conversion:
  `(uintptr_t)(uVar2 * 0x70)`. Ghidra's `TypeOpIntAdd::propagateType` carries the
  type between the output and one operand, never both - an offset added to a
  pointer is an integer.
  Which operand is the base is only knowable when the other is a constant
  displacement, which is the field-access shape this backward step exists for;
  where both operands are computed, the base gets its type from its own
  definition. `allocEnemyEntity` now returns
  `(uintptr_t)this_ + (uVar2 * 0x70 + 0x4d0)` - one cast, as the address-ordered
  path has.
  `casts` on all five PS2 functions went from `diverged` to `applied`.
  `declaration_order` is the only dimension left between the graph path and the
  default.
- The graph path no longer builds the address-ordered SSA or runs its type
  solver. It recovered types with `graph::types::infer_types` all along, and that
  is what emission reads; the linear pass ran alongside only to fill
  `NativeDocument::ssa` and `::types`, which nothing on this path consumes - the
  one reader of `ssa` is a test on the address-ordered path. They are now left
  empty, which is the honest statement that this document's types came from
  somewhere else, and the objective's "instead of an address-ordered linear pass"
  is true of this path rather than nearly true.
  Gates unchanged: 678 tests, census identical, five PS2 smoke failures.
- Nominal field names now reach the graph path's output, which closes
  `nominal_fields` and moves the smoke failure from eight PS2 functions to five.
  `rewrite_recovered_field_accesses` knew two spellings of a field access - the
  address-ordered emitter's arithmetic under a cast, and an access already
  carrying the nominal name - but not the third: the graph emitter has already
  recovered the access and names the member after its offset, because only this
  pass holds the name the source used. Unrecognised, the structure matched no
  parameter, so the nominal type never attached and the declared parameter fell
  back from `GameWorld *` to `uintptr_t` while the body still spelled
  `arg0->field_4a4` - an arrow on a non-pointer.
  `_ZN9GameWorld12beginFadeOutEv` on the graph path is now
  `GameWorld * this_` with `this_->fadeOut`, `this_->fadeAlpha`,
  `this_->drawFadeScreen` and `this_->fadeIn`, matching the address-ordered path
  statement for statement bar one condition spelling.
  What remains between the graph path and the default is the pair recorded
  earlier, on the five `alloc*` functions only: `casts` 2 against 1, from a
  redundant `(uintptr_t)` on an integer already being added to a pointer, and
  `declaration_order`, where the graph names its field snapshot `uVar2` and the
  gate exempts the address-ordered path's `mem_125090_2` as a renderer artifact.
  The first is a real excess cast. The second is one construct with two spellings
  and one of them exempted.
- Fixed the wrong store, and it was `RulePropagateCopy` propagating a copy that
  changes width. A copy whose output and input differ in size is not a copy: it
  truncates or extends, and every reader of the output expects the output's width.
  Replacing the output with the input handed those readers a value of the wrong
  size, which is how a one-byte `sb` arrived at `SplitDatatype::splitStore` as a
  two-byte store and was split into a pair covering the neighbouring field.
  `_ZN9GameWorld12beginFadeOutEv` now emits the four stores the machine performs,
  in the order the address-ordered path emits them - `fadeOut = 1`,
  `fadeAlpha = 0`, `drawFadeScreen = 1`, `fadeIn = 0` - instead of six ending in
  a `fadeOut = 0` that undid the flag the function exists to set.
  Found by probing `total_replace` and `op_set_input` for a store whose value
  width changed, and reading the backtrace, rather than by reasoning about which
  rule looked suspicious.
  All gates green, 677 tests, census unchanged. `nominal_fields` on the graph path
  is still `unavailable`: the parameter stays `uintptr_t` where the
  address-ordered path recovers `GameWorld *`, so the nominal type has nothing to
  attach to. That is now the only thing between the graph path and the default.
- Localised what blocks the graph path from shipping as the default, which is
  the last open item. `corpus-smoke` fails on the PS2 entries for exactly one
  reason, and it is not the `declaration_order` naming question recorded earlier:
  comparing every dimension of `_ZN9GameWorld12beginFadeOutEv` between the two
  paths, ten agree and `nominal_fields` differs - the address-ordered path
  observes `GameWorld.fadeAlpha`, `GameWorld.fadeOut` and the rest, the graph path
  observes nothing.
  The cause is a wrong store. The lift of that function contains four one-byte
  `sb` stores, at `0x4a4`, `0x4a2`, `0x4a3`, `0x4a5`. The graph path emits six,
  because two of them are two bytes wide by the time `SplitDatatype::splitStore`
  sees them and split into a pair covering the neighbouring field as well. The
  last of the six sets `fadeOut` back to zero, undoing the flag the function
  exists to set. With the field names wrong, the nominal type cannot attach, and
  the declared parameter degrades from `GameWorld *` to `uintptr_t` while the
  body still spells `arg0->field_4a4` - an arrow on a non-pointer.
  Established by measurement: `splitStore` reports `stored=2 covered=2
  pieces=[1,1]` on both, the four lifted stores each carry a one-byte value, and
  the widening is not `RuleDoubleStore` - disabling it leaves all six. Present at
  `cf5d082`, so it predates this session's structuring work. What remains is to
  name the pass that widens a one-byte store's value, which is the next thing to
  do rather than a question for anyone.
- For-loop recovery now works end to end, closing the chain this session has
  been following. `TRK_fill_mem` emits two `for` loops, the same two Ghidra
  emits, and the census finding `for 0 vs 2` is gone; `Emem_KillSwMember` went
  from one to two of its three. Four things had to be true at once, and the last
  three were only reachable once maximal blocks made "the tail of the loop" mean
  what Ghidra means by it.
  Ported `PcodeOp::isMoveable`, which is how Ghidra puts the iterator at the end
  of the body instead of requiring it to be there already: the move is refused
  when it would cross a read of its own result, carry a memory access across a
  conflicting one, or move a value tied to an address something in between also
  touches. This model has no `addrtied` flag, so that question is answered from
  the storage - memory can be reached through a pointer, a register cannot.
  Fixed `RulePushMulti` handing a value over before the merge released it. An
  operation clears whatever it still claims as its output when destroyed, so the
  value ended up with no definition and the branch read a free varnode.
  A copy whose two ends print as one name is not emitted. These are collapsed
  merges - `cutDownMultiequals` turns a merge that lost all but one input into a
  copy - and Ghidra's copy marking reaches the same conclusion. The test sits in
  `classify` rather than `classify_op` so a `for` header can still spell such a
  copy when it needs one as an initializer.
  A value whose only reader is such a copy is now named. Otherwise nothing
  assigns it at all: the copy is the statement that would have, and suppressing
  it dropped a loop's initializer. Same rule as the loop-carried update, one
  reader kind wider.
  A `for` lifts a statement into its header only if the body stops printing it,
  and only if it says something: a self-assignment is left alone rather than
  suppressed in one place and declined in the other. The body no longer repeats
  the header either, which a `while` must do and a `for` must not.
  Measured: all gates green, 676 tests, census unchanged at 21/37 agreeing with
  `unstructured-control-flow` at 9. One defect remains, recorded rather than
  papered over: `TRK_fill_mem`'s first `for` is missing its initializer, and the
  statement that computes it appears after both loops instead of before them.
- Ported `ActionPreferComplement` and `ActionStructureTransform` into
  `graph/structuretransform.rs` and registered them in a `blockrecovery` group
  after the cleanup pool, matching Ghidra's order at `coreaction.cc:5771-5773`.
  Both are output-neutral on the corpus - the census is byte-identical with the
  group skipped - because the emitter already renders condition complements and
  derives for-loops. They are registered for pipeline fidelity, not for a gain.
- `ActionVarnodeProps`, `ActionForceGoto`, `ActionSegmentize` and
  `ActionLaneDivide` were measured as unportable and no code was written for
  them. `ActionVarnodeProps` is driven entirely by `autoLiveHold`,
  `actionProperty`, `readOnly`, `getConsume` and `noDescend`, of which the graph
  has none; consume analysis is the prerequisite, and `nonzero_masks` is not a
  substitute since it says which bits *can* be set, not which are read.
  `ActionForceGoto` needs an override object nothing would populate.
  `ActionSegmentize` needs a `SegmentOp` registry and segmented address-space
  metadata that no supported architecture defines here. `ActionLaneDivide` needs
  a laned-register registry and lane-description machinery.
- Recovered `dl_G_MOVEWORD__5emu64Fv`'s switch, which took fixing five separate
  defects in the chain - the function went from 34 lines ending in a bare
  `uVar6();` to 167 lines with a `switch`, 5 cases and 8 calls:
  - `parse_scaled` rejected a LOAD-produced index. Ghidra's `findSmallestNormal`
    permits a one-byte value when a LOAD is in the path, and PPC indexes with
    `lbz`.
  - `find_guard` rejected a reversed comparison with the constant on the left.
  - `Pipeline::target_memory_value` refused every target but GBA, so no jump
    table could ever be read, and its fold was hardcoded little-endian which
    would have byte-swapped a PPC table. Now any target, with the architecture's
    byte order.
  - `sleigh_flow` reported `Flow::Return` for the `BRANCHIND`, so `discover`
    never followed the table and the case bodies were never lifted.
  - The provisional graph needed `heritage` before the address chain was
    walkable, and the expression pipeline before it folded - which is exactly why
    Ghidra's restart re-runs the analysis rather than re-reading the raw graph.
- `Pipeline::discover_through_jump_tables` is Ghidra's restart at the layer where
  re-lifting is possible (`flow.cc:771-805`): recover the table from a
  provisional graph, discover from every case and default target, merge the
  instructions, and add the branch-to-case edges the structurer needs. Skippable
  with `VENTRIS_NO_MULTISTAGE`. Attributed: `missing-conditional` 6 to 5,
  `call-census` 4 to 3, `missing-loop-or-switch` 3 to 2, `return-presence` 2 to 3.
- `sleigh_flow` kept the fallthrough of a conditional return. PPC `beqlr` is
  `if (!cond) goto next` followed by the return; scanning p-code in reverse hit
  the return first, reported an unconditional return, deleted the not-taken
  successor and stopped discovery dead. `TRK_fill_mem` went from 38 instructions
  stopping at `0x800a6880` to 48 reaching `0x800a6890`, which closed both of its
  `missing-loop-or-switch` differences. The file already had `skips_to_fallthrough`
  for the analogous likely-branch case.
- The `blockaction`/`coreaction`/`storageaction` loop in `native.rs` iterated
  every action, checked the skip list, and never called `apply` - so
  `ActionNodeJoin`, `ActionDeadCode` and `ActionShadowVar` had never run.
  `ActionReturnSplit` stays excluded: bisected against `corpus-smoke`, it alone
  diverges control flow on two PS2 functions.
- `Graph::surrendered` was compared before and after `mark_loop_exits` to detect
  progress but never incremented anywhere, so the comparison always said no and
  the collapse fell through to `rule_goto` instead of retrying with the exits it
  had just marked.
- `ActionVarnodeProps` is now registered, and measurably earns it: skipping it
  makes `missing-parameters` worse. It took moving prototype recovery inside the
  round loop, where Ghidra does it - `ActionActiveParam` decides trials and
  `ActionInputPrototype` promotes them once per round, so the decision converges
  with the graph instead of being taken once after every pass has run.
- Reverted a parameter-trial classification that traded a hard gate for a soft
  one. Marking a pure input inactive when every use reaches only a CALL argument
  made `osContGetReadData` render one parameter, matching the oracle exactly - but
  it broke `corpus-smoke` on `TRK_memset` with `globals=diverged`. Semantic
  divergence is worse than a parameter count, so the reader test stands. Bisected
  across five commits to isolate it; the two jump-model modules were innocent and
  are chained.
- `graph/tablebase.rs` recovers a jump table whose base is register-rooted -
  PPC materializes one with `lis` then `addi`, and `parse_address` accepts only a
  literal constant varnode, so those tables were lost entirely. Chained after
  `recover_basic` and `JumpBasic2`. `constant_value` is deliberately left
  literal-only: folding inside it made a computed scaled index look like a
  constant table base and broke `JumpBasic2`'s recovery test.
  Measured limit, recorded in the module: on the motivating function
  `dl_G_MOVEWORD__5emu64Fv` this still declines, because instrumenting the chain
  showed `parse_destination` itself returns `None` there while `contains_load` is
  true - the destination never becomes a `DestinationModel`, so no base model is
  ever given a scale and index. The register-rooted base was a real defect and is
  fixed for the shape it covers; that function needs `parse_destination` looked at.
- Three further absences confirmed negative with their Ghidra readers named, to
  the standard of counting operation templates across all 21 packed SLA payloads:
  - `ActionInternalStorage` - `store_unmapped`'s readers are
    `funcdata_varnode.cc:2127-2128` (AncestorRealistic rejecting a COPY path) and
    `ruleaction.cc:4355-4357`; `GraphOp` has no flag field and
    `FuncProto::internal_storage` has no production setter, so the flag alone
    would be inert.
  - `ActionSegmentize` - a census found raw `segment` CALLOTHER templates only in
    x86 (129) and x86-64 (131) of 203029 total, but those are CALLOTHERs, not
    `SegmentOp` registry entries, and no bundled spec declares `<segmentop>`.
  - `ActionLaneDivide` - the local `pspec.xml` has 96 `vector_lane_sizes`
    attributes but no XML parser reads them, and the action needs the whole
    `TransformManager`/`LaneDivide` rewrite, so a parser alone is not bounded work.
- `graph/orconsume.rs` ports `RuleOrConsume` (`ruleaction.cc`), which was
  previously recorded as unportable for needing `Varnode::getConsume`. The
  consume sink removed that gate, so the rule is now real: an `INT_OR` or
  `INT_XOR` whose operand can only set bits nobody reads collapses to a `COPY`
  of the other operand. Registered; census unchanged on this corpus.
- `graph/consume.rs` gives consume propagation the convention sink Ghidra has and
  this project lacked. `ActionDeadCode` seeds every varnode in a deadcode space
  before removal is allowed (`coreaction.cc:3999-4010`); `deadcode::propagate`
  seeded only operation sinks, so storage the convention claims looked dead. The
  seed is storage-driven via `FuncProto::possible_input_param`, deliberately not
  a `flags.input` guard.
- `graph/callspecs.rs` builds `FuncCallSpecs` and ports `ActionDefaultParams`
  (`coreaction.cc:2352-2377`) and `ActionExtraPopSetup` (1437-1467) against
  explicit specs. Neither can run from the pipeline yet, and the blocker is
  upstream rather than in the object: `direct_call_prototypes`
  (`crates/ventris/src/lib.rs:398-437`) builds a `NativeCallPrototype` that is
  types only (`native.rs:1530-1533`), with no `Abi` and no `Location`, so there is
  no callee storage to link. Synthesising it from the convention was rejected -
  the pass exists to propagate the callee's *recovered* storage decisions, and
  manufacturing them re-derives what the callsite already assumes.
- `graph/jumpmodel.rs` ports `JumpBasic2` (`jumptable.cc:1651-1784`) and the
  `PathMeld` machinery it needs (`787-1017`), including `meldOps` block/SeqNum
  merging and `truncatePaths`. Chained after `recover_basic` in Ghidra's model
  order. Measured: no corpus movement, which is correct - the target function
  `dl_G_MOVEWORD__5emu64Fv` has no `MULTIEQUAL`, so the model rightly declines,
  and its real defect is `parse_address` refusing a register-derived constant
  table base. `JumpBasicOverride` and the assisted model are rejected with
  evidence: the former needs the absent `Override`, the latter a `JumpAssistOp`
  no bundled spec declares.
- `ActionVarnodeProps` stays unregistered after three hypotheses were tested and
  refuted - statement-derived signature, missing consume sink, and reader-counting
  instead of `ancestorRealistic`. The measurement that explains it: on
  `osContGetReadData` the oracle renders one parameter, we render two without the
  pass and none with it. The parameter count was already wrong; the pass converts
  a two-versus-one error into a zero-versus-one error. The trial decision is the
  real defect.
- Measured, not skipped: `Override` is the single blocking prerequisite for four
  separate pieces of Ghidra, and nothing in this project can populate one.
  `LoadOptions` (`crates/ventris/src/lib.rs:27-34`) and `Hints` (95-103) carry no
  control-flow input, `Pipeline::analyze` passes none, and the graph API accepts
  none. Every one of Ghidra's four restart sources writes into `Override` and
  then sets `setRestartPending`:
  - `fspec.cc:5471` - the `deindirect` CALLIND-to-CALL fallback
  - `fspec.cc:5503` - the `forceSet` fallback when `lateRestriction` fails
  - `heritage.cc:2581` - `Heritage::bumpDeadcodeDelay` via `insertDeadcodeDelay`
  - `jumptable.cc:2712-2717` - `insertMultistageJump` when a recovered table has
    one entry but the model implies more
  So `ActionForceGoto` (`coreaction.cc:672-677`) and `ActionRestartGroup`
  (`action.cc`) are both unportable here: the restart group would iterate exactly
  once, which is a wrapper that cannot do work.
- `RuleTransformCpool` (`ruleaction.cc:3902-3940`) is unportable for a stronger
  reason than a missing constant pool: a census of all 21 bundled packed SLA
  payloads found **zero** operation templates with `ATTR_CODE=68` (`CPOOLREF`),
  against nonzero template counts everywhere - 39772 on x86-64, 317 on 6502 - so
  no supported lifter can emit the opcode the rule matches on.
- The prototype now drives the signature, closing the dead chain that made the
  whole prototype layer inert. Four separate breaks, each measured:
  - Nothing promoted a recovered trial into a `ProtoParameter`, so the prototype
    held zero parameters no matter what the prototype passes decided.
    `graph/parampromote.rs` ports `FuncProto::updateInputTypes`/
    `updateOutputTypes`, and the pipeline now registers a trial per model input
    location and decides it the way `ActionActiveParam` does.
  - A trial can survive without a value. `ParamListStandard::buildTrialMap`
    keeps an unreferenced trial that sits *before* a referenced one - the
    convention still passes something in that slot - so only the trailing unused
    run is dropped. Without this a hole truncated the parameter list.
  - `native/declaration.rs` ports `PrintC::emitFunctionDeclaration`,
    `emitPrototypeOutput`, `emitPrototypeInputs`, `emitVarDecl`,
    `emitVarDeclStatement` and `emitSymbolScope`. The printer reads the prototype
    and the local scope instead of re-deriving the signature from the body.
  - `SourceReconstruction::from_signature` rewrites the signature from
    `NativeDocument::parameters`, so substituting only the printer was invisible.
    That list now comes from the prototype too.
- `graph/scopepopulate.rs` ports `MapState`, `ScopeLocal::restructure` and
  `restructureVarnode` from `varmap.cc`, so `Funcdata::scope_local` is populated:
  stack varnodes and frame-relative accesses become ranges with real
  `UsePoint` liveness, a recycled slot at disjoint points becomes two symbols,
  and escape comes from `AliasChecker::has_local_alias`. The four passes in
  `graph/scopeconsumers.rs` are registered as a `localrecovery` group and in the
  expression pool, no longer dormant.
- `graph/varnodeprops.rs` ports the consume arm of `ActionVarnodeProps` -
  `(getNZMask() & getConsume()) == 0` replaces a value with zero - but is NOT
  registered. Measured twice: it costs an agreeing function because zeroing an
  input removes its readers and the convention-claimed input is then judged not
  to be a parameter. Ghidra's consume propagation treats convention storage as
  consumed; `deadcode::propagate` has no such sink, and adding one is the
  prerequisite.
- Ported the representable half of `Merge::mergeTestRequired`. A required merge
  is not unconditional in Ghidra: two address-tied values at different addresses
  are different storage and must not share a variable, and a function input must
  not be folded into address-tied storage that is not itself an input. Refusing
  is safe because the emitter's phi copies spell the assignment, which is what
  Ghidra does when it refuses and inserts a copy. Census unchanged - a faithful
  guard this corpus does not exercise.
- Ported the passes that consume the new layer, and registered the ones that can
  fire: `ActionInputPrototype`, `ActionOutputPrototype`, `ActionPrototypeTypes`,
  `ActionUnjustifiedParams` and `ActionPrototypeWarnings` in a `protorecovery`
  group, plus `RulePiecePathology` in the expression pool. `graph/scopeconsumers.rs`
  adds `ActionRestructureVarnode`, `ActionMappedLocalSync`,
  `RulePtrsubCharConstant` and `RuleStringCopy`.
  The prototype's model storage is now populated from the target ABI, because
  `FuncProto::derive_input_map` returns immediately on an empty storage list -
  without it every prototype pass was provably unable to decide anything.
- Measured honestly: the census is byte-identical with the `protorecovery` group
  skipped. The passes run, read real model storage and mutate the prototype, but
  nothing renders it - `recover_parameters` and `graph_return_type` still derive
  parameters and return type from the emitted statements independently. Making
  the document consume `FuncProto` is the remaining link and is a change in its
  own right, not a wiring detail.
- Four passes were deliberately left unregistered with no `Action` impl, because
  their inputs have no writer anywhere in the project: `ActionExtraPopSetup` and
  `ActionInternalStorage` (`set_extra_pop` and `set_internal_storage` have no
  callers outside their own definitions and tests), and the four
  `graph/scopeconsumers.rs` passes are dormant because nothing populates
  `Funcdata::scope_local` - that needs Ghidra's `ScopeLocal::restructure`/
  `MapState` gathering ported first.
- `ActionDefaultParams` is a partial bridge only. Ghidra consumes `FuncCallSpecs`,
  which is a per-call prototype *plus a link to the callee's own recovered
  prototype*; the second half is what the pass actually reads, and
  `guard::CallEffects` carries effects only.
- Built the layer the remaining Ghidra passes read, which was blocking them
  rather than any missing pass:
  - `Funcdata::warning`/`warnings` - a deduplicating diagnostic sink, surfaced
    into `NativeDocument.warnings` on the graph path, which previously hardcoded
    an empty list so a graph-path pass had nowhere to report.
  - `graph/funcproto.rs` - `FuncProto` and `ProtoParameter`, built over
    `ventris_target::Abi`. Parameters carry storage `Location`, type and name;
    the existing `NativeCallPrototype` carried types only, which is why the
    twelve prototype passes had nothing to read. `Abi` does not carry Ghidra's
    `killedbycall`, `likelytrash` or `resolveModel`; those three are the object's
    boundary and are recorded rather than faked.
  - `graph/scope.rs` - `Scope`/`ScopeLocal`, `Symbol` and `SymbolEntry`, keyed by
    storage *and* use point, so one recycled stack slot can hold distinct
    symbols at distinct points. Includes the multi-entry name tree that
    `Merge::mergeMultiEntry` needs.
  - `graph/alias.rs` - `AliasChecker`, porting `gatherInternal`,
    `gatherAdditiveBase`, `gatherOffset` and `hasLocalAlias` with Ghidra's exact
    terminal-use semantics and no escape filtering. A local pass object, not
    cached state: an alias verdict goes stale as soon as a rule rewrites a
    pointer computation.
- A short-circuit collapse now refuses a complex second arm, porting Ghidra's
  `BlockBasic::isComplex` guard from `ruleBlockOr`. The collapse concatenates
  both bodies, so without the guard the second arm's statements ran
  unconditionally. `missing-conditional` dropped from 7 corpus functions to 6.
- A jump in trailing position inside nested `if` bodies is now dropped, since
  falling out of the nesting lands where the jump was going. `__osRealloc` went
  from five jumps to none and `unstructured-control-flow` from 7 corpus
  functions to 3, with `agrees` up from 22 to 25 of 37. Only `if` is followed:
  a trailing jump out of a loop is an early exit and out of a `switch` case a
  `break`, and dropping either would change where control lands.
- An expression statement's operands are now collected as reads. The arm was
  missing from `collect_read_names` entirely, so liveness could not see them.
- Ported Ghidra's bitfield cleanup rules into `graph/bitfield.rs`: five of the
  six, registered in a new `cleanup` pool that runs after the expression fixed
  point, as Ghidra's `cleanup` pool does. `RuleBitFieldIn` is deliberately
  absent: Ghidra guards it on `Datatype::hasBitfields` and traces input 0 only,
  and without bit-range type metadata there is no guard, so it fired on ordinary
  masked arithmetic and cost an agreeing function.
- Ported `DynamicHash::uniqueHash` into `graph/dynamic.rs`, including all four
  traversal methods and the exact bit packing.
- Ported six lifecycle actions into `graph/actiondb.rs`. `ActionMergeMultiEntry`
  is absent rather than present-and-inert; it needs symbol scope and mutable
  high variables. The lifecycle state these actions set has no consumer in the
  decompiler yet, so they are not registered in the pipeline.
- Statement walkers no longer skip `for` and `switch` bodies. Thirteen of the
  seventeen walkers in `graph/emit.rs` recursed into `if`, `while` and `do-while`
  bodies only: `for` was added after most were written, and `switch` was never
  taught. Cleanups left no-op `goto`s inside those bodies, and - the real bug -
  `collect_read_names` missed reads there, which is what `retain_live_assignments`
  consults before deleting an assignment. All thirteen now route through a single
  `nested_bodies` accessor, so a new construct is a compile error rather than a
  silent gap.
- Basic blocks are now maximal, as Ghidra's are. `block_leaders` treated every
  edge's target as a leader, and a fall-through is an edge, so the graph had one
  block per instruction: 45 blocks for `TRK_fill_mem` where Ghidra has 17. The
  graph was not wrong and structuring recovered the same constructs by
  concatenating, which is why this survived so long - but every ported algorithm
  that treats a block as a unit was working on the wrong unit. "The last
  operation in the block" decides a for-loop's iterator, a condition block's
  complexity, and whether a statement may be moved; it means nothing when the
  block holds one instruction.
  A leader is now the entry, a branch target, the instruction after a branch, or
  a join - not the target of a plain fall-through nothing else reaches.
  Measured: `0x80072c88` 19 gotos -> 12 and 7 `do`/`while` -> 3 with 2 `while`,
  `0x8000b580` 4 -> 2, `0x800a94d8` 1 -> 0. Census `unstructured-control-flow`
  11 functions -> 9, the largest family and the one this campaign has been aimed
  at. Against that, `missing-conditional` 3 -> 6 and `agrees` 22 -> 21: structured
  flow absorbs `if (c) goto` pairs into loops, and three functions now emit fewer
  `if`s than the oracle. Kept because the representation is the one every ported
  algorithm assumes, and the remaining differences are now differences in rules
  rather than in the units those rules run on.
- Ported `RulePushMulti`, which `ConditionalJoin::findDups` names as its reason
  for accepting a join at all: the merge it leaves behind, `phi(a == 0, b == 0)`,
  is pushed below the duplicated comparison to become `phi(a, b) == 0`. Fires
  twice on `TRK_fill_mem`. `findSubstitute`'s common-subexpression half is not
  ported - skipping it builds a merge that could have been shared, never a wrong
  one.
- Enabled `ConditionalJoin` by reaching Ghidra's branch representation, and
  fixed the three correctness bugs that doing so exposed. Our lifter spells an
  inverted conditional branch as a `BOOL_NEGATE`; Ghidra marks the CBRANCH with
  `boolean_flip` and keeps one condition varnode, which is why `findDups` only
  rejects a flip that has not propagated. `ActionCbranchFlip` folds the negation
  into the branch by swapping its target and leaves the operation for its other
  readers, exactly as the flag does. The joins then fire: the block dump shows
  our block 43 at `start=800a6830 in=2 out=2` against Ghidra's block 7 at the
  same address, with the body at `in=1 out=1`.
  Three defects surfaced, all pre-existing and all silently wrong output:
  `rule_while_do` left the composite looping onto itself, because `absorb`
  derives a composite's exits from the absorbed members and a whiledo body's only
  successor is the header. `ruleBlockInfLoop` then wrapped every recovered
  `while` in a `while (true)`. The construct consumes the back edge -
  `newBlockWhileDo` closes the loop inside the composite - so it now leaves
  through the other branch and nowhere else.
  `propagate_single_use_copies` removed a loop-carried update once its forward
  reader absorbed it. The back edge is a reader the statement list cannot show,
  so `pVar4 = pVar4 + 1` and `uVar6 = uVar6 - 1` disappeared and the loops
  neither advanced nor terminated - they wrote the same address for ever.
  Propagation inside a loop body now refuses a name the loop's test reads, or one
  read at or before the assignment, the latter covering an update like `i = i - 1`
  that reads itself.
  `single_reader_after` exempted any construct that writes a name from counting
  as a reader of it, on the grounds that it may read the name after that write.
  That holds for an `if` and never for a loop, whose reads and writes are
  circular. `reads_before_write` now answers the question in order, and reports a
  loop as reading first whenever it reads at all. Without it an initializer was
  substituted into the guard ahead of a loop and the loop ran on whatever the
  variable happened to hold.
  Measured on `TRK_fill_mem`: `if (c) do {...} while (c)` for the two loops
  Ghidra recovers as `for` became `while` loops with initializers, updates and
  tests all present and matching the oracle statement for statement. `0x80072c88`
  21 gotos -> 19. `agrees` unchanged at 22 of 37; `missing-conditional` 2 -> 3,
  from `TRK_fill_mem` joining a family whose finding - a trailing guarded loop we
  do not recover - it already had. Three pinned tests.
- Fixed the edge surgery `ConditionalJoin` depends on, which had two real
  defects found by running the experiment above.
  `move_out_edge` appended the new source to the predecessor list; Ghidra reaches
  the target through `replaceInEdge` and keeps the in-edge *index*. Operand slots
  of a `MULTIEQUAL` are positional against that list, so appending reassigned
  every operand from that slot onward.
  `remove_edge` here also dropped the predecessor's merge operand - correct for
  its usual callers, and wrong for this one: Ghidra's `removeEdge` is control flow
  only, and `cutDownMultiequals` repairs the phis itself from the slots as they
  were before any edge moved. Doing both destroyed the loop's phi. Added
  `remove_edge_keeping_merges` for callers that own the repair, and left
  `remove_edge` as the default.
  Verified against the failure it explains: with the branch-negation fold in
  place the lost decrement comes back. Pinned by tests on both primitives, which
  is what the join needs whether or not it is reachable today.
- Added `tools/DumpBlocks.java`, which reports the basic-block graph Ghidra's
  decompiler ends up with: per block, address range, in and out edge counts with
  their indices, and the terminating opcode. The C output shows which constructs
  were recovered but not the graph they came from, and every wrong guess this
  session came from reasoning about that graph instead of reading it.
- Measured, with that tool, why our loops structure differently, ending three
  sessions of guessing. In `FUN_800a67d8` Ghidra's block 7 is
  `start=800a6830 stop=800a6830 in=2 out=2`: a block holding one CBRANCH, entered
  from the initializer block and from the body, with the body at `in=1 out=1`
  flowing back to it. That is a joined block - `nodeJoinCreateBlock` sets a new
  block's range to the single address of the CBRANCH it holds - so
  `ConditionalJoin` does fire there, and its output is exactly the `BlockWhileDo`
  that for-loop printing needs. Loop 1, at blocks 2 and 3, is a self-looping
  block and stays `if` + `do`/`while`, matching Ghidra's own output. Two joins,
  two `for` loops, one per whiledo.
  Our join rejects those pairs for a specific and now-known reason: for `beq`
  our lifter emits the comparison, and for `bne` the same comparison wrapped in
  `BOOL_NEGATE`, so `findDups` compares `INT_EQUAL` against `BOOL_NEGATE` and
  stops. Ghidra's lifter marks the branch with `boolean_flip` and keeps one
  condition varnode, which is why `findDups` only has to reject a flip that has
  not propagated yet.
  Folding that negation into the branch - retargeting it and leaving the
  operation for its other readers, which is what the flag does - makes the pairs
  compare equal and the joins fire: `0x800a67d8` went from three `do`/`while`
  loops to four `while` loops, and `0x80072c88` from 21 gotos to 19. It also
  produced wrong code: the loop counter's decrement disappeared and the loops
  became infinite, so the join's phi surgery is incorrect as ported. Reverted,
  with the reproduction recorded here rather than shipped. The remaining work is
  a defect in `setupMultiequals`/`cutDownMultiequals`, not a missing pass.
- Ported `ConditionalJoin`, `ActionNodeJoin` and `Funcdata::nodeJoinCreateBlock`
  as `graph::nodejoin`, with `functionalEqualityLevel` as `graph::equality`. Two
  blocks that end in a CBRANCH on the same value and split the same two ways
  perform one test twice; the join builds a block that performs it once, phis
  whatever the exits used to merge across those two edges, and leaves both
  original blocks flowing into it.
  Measured: 92 candidate pairs across four corpus functions, zero joins. Every
  pair is rejected on the same ground, and it is the interesting one: a rotated
  loop's guard tests `INT_EQUAL` where its latch tests `INT_NOTEQUAL`, so
  `functionalEqualityLevel` stops at the differing opcode. Covered by synthetic
  tests instead, which is the honest position for a data-flow mutation with no
  live instance: the merging case, the different-exits rejection, and the
  opposite-polarity rejection that explains the corpus result.
  This does not close the for-loop gap. I predicted it would, on the observation
  that Ghidra prints `for` for exactly the two `TRK_fill_mem` loops whose guard
  and latch branch to the same two blocks - which is true, and is still the
  sharpest evidence available - but the pass that converts those into a
  `BlockWhileDo` is not this one. Only `BlockWhileDo` prints as `for`
  (`emitBlockWhileDo` is the sole caller of `emitForLoop`), so a whiledo is
  certainly what Ghidra has; which pass produces it is unidentified. That is the
  fourth wrong guess about a cause this session, all four from reasoning ahead of
  measuring.
- Corrected the collapse rule order to `collapseInternal`'s. Four rules were in
  the wrong phase: `ruleBlockProperIf` (our `rule_if_no_exit`) is the third rule
  of the main chain, not a last resort; `ruleBlockSwitch` is the last of it, not
  the second; `ruleCaseFallthru` belongs in the stalled phase beside
  `ruleBlockIfNoExit`, not the main chain.
  Running the switch rule last is only safe because every rule ahead of it
  refuses a multi-way branch - "switch must be resolved first" in Ghidra's own
  comment. Those `isSwitchOut` guards were missing here, so an `if/else` could
  take a switch's cases; two tests caught it immediately once the order changed.
  A collapsed switch must then stop reporting itself as a multi-way branch, or it
  blocks concatenation forever: Ghidra's flag lives on the block and the
  composite it builds does not carry it.
  Measured: no census or output change on the corpus. Kept because the order and
  the guards are the documented algorithm and the old order was reachable-wrong.
- Ported `BlockWhileDo::finalTransform`, `findLoopVariable` and
  `findInitializer` as `graph::forloop`, deciding which `while` loops print as
  `for` loops. The loop variable is found from the tested value rather than
  guessed: the walk goes up its definitions, bounded at four as Ghidra bounds it,
  looking for a phi in the head whose loop-carried input is written in the tail.
  That input is the iterator; the phi's other input, if it terminates the block
  ahead of the loop and that block flows nowhere else, is the initializer. Both
  are marked non-printing, as `opMarkNonPrinting` marks them, so the `for` header
  prints them once.
  Where Ghidra moves a statement to the end of its block to qualify, this
  requires it already be last - the side of `testTerminal` that needs no move.
  Measured: recovers nothing on this corpus, because our structurer produces
  `if (c) do {} while (c)` where Ghidra produces a single `while` for the same
  rotated loops, and for-loop printing only applies to `BlockWhileDo`. The two
  functions where Ghidra prints `for` are `TRK_fill_mem`'s middle loops.
- Ported `BlockGraph::scopeBreak` with the loop and goto overrides, which
  `ActionFinalStructure` runs once the construct tree is built. A jump whose
  target is the enclosing loop's exit is `break`, not `goto`. The pass carries
  two indices down the tree: the block a construct falls through to, and the
  block that leaves the innermost loop — a loop's body sees the loop's own exit
  as the second, which is what makes the jump recognisable. Members of a list
  take the next member's entry as their exit, needing `FlowBlock::getFrontLeaf`.
  Measured: `0x80072c88` 23 gotos -> 21, `0x800a5a70` 2 -> 1.
  Ghidra defines `f_continue_goto` and prints it but never sets it, so there is
  deliberately no `continue` arm here.
- Ported `ActionPreferComplement`, via `Funcdata::opFlipInPlaceTest` and
  `get_booleanflip`. A branch whose clause sits on the fall-through side used to
  be printed as `if (!(arg1 < 1))`; Ghidra asks whether the comparison can absorb
  the negation and rewrites the operator where it can, so the condition comes out
  positive. `if (!(arg1 < 1))` is now `if (1 <= arg1)` and `if (!(arg1 < 9))` is
  `if (9 <= arg1)`.
  The ordered comparisons swap their operands as well as their operator, because
  `!(a < b)` is `b <= a` and this expression tree has no `>=`. Equality flips
  without reordering, a double negation collapses — Ghidra's flip of
  `BOOL_NEGATE` is a `COPY` it then deletes — and a plain boolean cannot absorb
  the negation, so `if (!bVar1)` keeps its `!` exactly as Ghidra's does. Four
  cases pinned by test.
- Ported the rest of `LoopBody`, which is what `labelExitEdges` needs to mean
  anything. An earlier attempt at the ordering alone regressed the census
  (`agrees` 22 -> 21, `unstructured-control-flow` 11 -> 14) and was reverted; with
  the surrounding algorithm in place it is back at parity and no longer an
  approximation.
  - `findBase` order and `uniquecount`: the body is an ordered list with the head
    and tails at the front, so `labelExitEdges` can address the interior as the
    tail of the list. It was a `BTreeSet`, which sorts the interior by block
    number and loses the discovery order the exit priority is expressed in.
  - `extend`: a block every one of whose predecessors is already inside cannot be
    reached from anywhere else, so it joins the body even with no back edge
    through it. The exit is recomputed afterwards, because a block taken in is no
    longer a candidate exit.
  - `orderTails`: the tail that leaves to the exit moves first, and since
    `labelExitEdges` walks the tails in reverse its edges are surrendered last.
  - `labelExitEdges` priority: interior, then head, then tails in reverse, then
    every edge to the official exit.
- And the timing, which turned out to matter more than the ordering. Ghidra's
  `collapseInternal` runs every rule to a fixpoint and only then lets
  `ruleBlockGoto` reach `selectGoto`, so an edge is surrendered only when nothing
  else applies. This called `mark_loop_exits` *before* the rule loop, handing away
  an edge the rules would have structured — and under `labelExitEdges` priority
  that first edge is an interior one, the worst available choice. Removing the
  eager call is what brought the census back to 22 agrees. With both in place
  `queryMapAddress_single` is two `goto`s worse and every other sampled function
  is unchanged, so this is measured parity rather than a measured gain: what it
  buys is that the structuring is the ported algorithm.
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
