#!/usr/bin/env python3
"""Measure Ventris/Ghidra agreement by comparing tokens, not counting constructs.

`quality_census.py` classifies a function pair into nine defect families, each a
counting or threshold test: more `goto`s than the oracle, fewer `if`s, a call
count that differs, casts more than doubled. That is the right shape for a
regression gate - it is stable, and it names a family a human can act on - but
it is a floor and not an equivalence relation. Two renders can differ in every
identifier, every literal, the order of every statement, and the spelling of
every operator while agreeing on all nine counts, and the census will call that
"agrees". Several of its tests are deliberately one-directional, so emitting
*more* loops or *fewer* gotos than Ghidra also scores as agreement.

This tool answers the stricter question by comparing the token streams. It is
graded, because "equal" has more than one useful meaning here:

  exact      Byte-identical after normalising line endings and trailing space.
  token      Identical token sequence: same identifiers, literals, operators.
  alpha      Identical after canonically renaming *local* identifiers in order
             of first appearance. This is the honest headline: it accepts that
             `uVar1` versus `total` is a naming policy, and accepts nothing
             else. Keywords, types, callee names, field names and every literal
             must still match exactly.
  skeleton   Identical after also replacing every identifier with `ID` and
             every numeric literal with `NUM`. Control flow and expression
             shape must match exactly; names and constants are ignored. A
             function that reaches only this level has the right structure and
             the wrong contents.
  (none)     Fails all four. Reported with a token-level similarity ratio and
             the first divergence, so the failures rank themselves.

Comments are stripped before tokenising. Ghidra emits `WARNING:` banners and
`/* ... */` notes that are commentary on its own analysis, not translated code.

The similarity ratio and first-divergence classification exist so this is not
merely a harsher pass/fail: a function at 0.97 with one differing cast is a
different problem from one at 0.30, and the ranked divergence classes say which
defect costs the most functions.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))

import quality_census as census

C_KEYWORDS = frozenset(
    """auto break case char const continue default do double else enum extern float for goto if
    inline int long register restrict return short signed sizeof static struct switch typedef
    union unsigned void volatile while _Bool""".split()
)

# Types and helpers both renderers spell the same way. These are not local
# names, so alpha-renaming must leave them alone or it would launder a real
# type difference into agreement.
C_TYPE_WORDS = frozenset(
    """uint uint8_t uint16_t uint32_t uint64_t int8_t int16_t int32_t int64_t size_t ssize_t
    byte word dword qword undefined undefined1 undefined2 undefined4 undefined8 bool
    ushort uchar ulong longlong ulonglong code float10 unkbyte9 unkuint9""".split()
)

# One concrete type, two vocabularies. Ghidra prints `uint`/`byte`/`ushort`;
# this port prints C99 fixed-width names. Comparing those spellings as unequal
# measures the vocabulary and nothing else - and it does so on essentially every
# function, which is enough on its own to drive agreement to zero and bury every
# real defect underneath. Canonicalising to a width-and-class token fixes that
# without hiding anything: a genuine width or signedness difference still lands
# on two different tokens.
#
# `undefined*` is deliberately NOT folded into the unsigned integer of the same
# width. It is Ghidra declining to assign a type, which carries different
# information from asserting `uint32_t`, and collapsing the two would let this
# port claim agreement precisely where the oracle said "I do not know".
TYPE_CANON = {
    "uint8_t": "T1u", "byte": "T1u", "uchar": "T1u", "unsigned char": "T1u",
    "int8_t": "T1s", "char": "T1s", "sbyte": "T1s",
    "uint16_t": "T2u", "ushort": "T2u", "word": "T2u", "unsigned short": "T2u",
    "int16_t": "T2s", "short": "T2s",
    "uint32_t": "T4u", "uint": "T4u", "dword": "T4u", "ulong": "T4u",
    "int32_t": "T4s", "int": "T4s", "long": "T4s",
    "uint64_t": "T8u", "ulonglong": "T8u", "qword": "T8u",
    "int64_t": "T8s", "longlong": "T8s",
    "float": "Tf4", "double": "Tf8",
    "undefined": "T?", "undefined1": "T1?", "undefined2": "T2?",
    "undefined4": "T4?", "undefined8": "T8?",
}

TOKEN_RE = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<comment>/\*.*?\*/|//[^\n]*)
    | (?P<str>"(?:\\.|[^"\\])*")
    | (?P<char>'(?:\\.|[^'\\])*')
    | (?P<num>0[xX][0-9a-fA-F]+[uUlL]*|\d+\.\d+[fF]?|\d+[uUlL]*)
    | (?P<ident>[A-Za-z_$][A-Za-z0-9_$]*)
    | (?P<op><<=|>>=|\.\.\.|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||\+=|-=|\*=|/=|%=|&=|\^=|\|=)
    | (?P<punct>[-+*/%&|^~!<>=?:;,.\[\]{}()])
    | (?P<other>.)
    """,
    re.VERBOSE | re.DOTALL,
)


@dataclass
class Token:
    kind: str
    text: str


def tokenize(source: str) -> list[Token]:
    """Splits C into tokens, dropping whitespace and comments."""
    tokens: list[Token] = []
    for match in TOKEN_RE.finditer(source):
        kind = match.lastgroup
        if kind in ("ws", "comment"):
            continue
        tokens.append(Token(kind, match.group()))
    return tokens


def function_body(source: str) -> str:
    """Returns the text from the first `{` of the outermost function onward.

    Both renderers print a signature line, and the signature is compared
    separately by the census. Restricting the token comparison to the body
    keeps a differing return type from being counted once here and again there.
    """
    depth = 0
    start = None
    for index, char in enumerate(source):
        if char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0 and start is not None:
                return source[start : index + 1]
    return source


DECL_START_WORDS = frozenset(TYPE_CANON) | C_TYPE_WORDS | {
    "struct", "union", "enum", "const", "volatile", "static", "unsigned", "signed",
}


def split_prologue(tokens: Sequence[Token]) -> tuple[list[Token], list[Token]]:
    """Splits a function body into its declaration prologue and its statements.

    Both renderers print every local's declaration in a block at the top, so the
    *first* place two renders diverge is nearly always in that block - which made
    the first-divergence ranking report "type" for functions whose real
    difference was a missing `switch` several lines later.

    Splitting them apart lets the two questions be asked separately: do we
    recover the same statements, and do we give them the same types. A function
    whose body matches and whose prologue does not is a type-recovery defect, and
    that is a different piece of work from a control-flow defect.

    The prologue is the leading run of `;`-terminated statements whose first
    token introduces a declaration. The first statement that does not stops the
    scan, so a declaration appearing later stays with the body - matching C89
    style, which is what both renderers emit.
    """
    index = 0
    if index < len(tokens) and tokens[index].text == "{":
        index = 1
    prologue_end = index
    while index < len(tokens):
        if tokens[index].text not in DECL_START_WORDS:
            break
        terminator = index
        depth = 0
        while terminator < len(tokens):
            text = tokens[terminator].text
            if text in "([{":
                depth += 1
            elif text in ")]}":
                depth -= 1
            elif text == ";" and depth == 0:
                break
            terminator += 1
        if terminator >= len(tokens):
            break
        index = terminator + 1
        prologue_end = index
    return list(tokens[:prologue_end]), list(tokens[prologue_end:])

def is_local_name(token: Token, callees: frozenset[str]) -> bool:
    """Whether a name may be canonically renamed without hiding a difference."""
    if token.kind != "ident":
        return False
    text = token.text
    if text in C_KEYWORDS or text in C_TYPE_WORDS:
        return False
    if text in callees:
        return False
    return True


def callee_names(tokens: Sequence[Token]) -> frozenset[str]:
    """Identifiers used in call position, which name callees rather than locals.

    A call through a variable (`(*pfn)(x)`) reaches this too, and that is
    deliberate: if one renderer resolved a pointer to a name and the other did
    not, that is a real difference and must not be renamed away.
    """
    names = set()
    for index, token in enumerate(tokens[:-1]):
        if token.kind == "ident" and tokens[index + 1].text == "(":
            if token.text not in C_KEYWORDS:
                names.add(token.text)
    return frozenset(names)


def alpha_normalize(tokens: Sequence[Token], callees: frozenset[str]) -> list[str]:
    """Renames locals to `v0, v1, ...` and folds type spellings to one vocabulary."""
    mapping: dict[str, str] = {}
    out = []
    for token in tokens:
        canonical = TYPE_CANON.get(token.text)
        if canonical is not None:
            out.append(canonical)
        elif is_local_name(token, callees):
            if token.text not in mapping:
                mapping[token.text] = f"v{len(mapping)}"
            out.append(mapping[token.text])
        else:
            out.append(token.text)
    return out


def skeleton_normalize(tokens: Sequence[Token]) -> list[str]:
    """Replaces every identifier with `ID` and every number with `NUM`."""
    out = []
    for token in tokens:
        if token.kind == "ident" and token.text not in C_KEYWORDS:
            out.append("ID")
        elif token.kind == "num":
            out.append("NUM")
        elif token.kind in ("str", "char"):
            out.append("LIT")
        else:
            out.append(token.text)
    return out


def normalize_text(source: str) -> str:
    lines = source.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return "\n".join(line.rstrip() for line in lines).strip()


DIVERGENCE_CLASSES = (
    # Ordered most specific first; the first matching rule names the divergence.
    #
    # `cast` precedes the type classes deliberately: a cast difference always
    # involves a type token, but "a cast appeared" is the more specific finding
    # than "these two types differ".
    #
    # `local-slot` and `symbol-name` exist as separate classes because an earlier
    # single `call-target` class conflated them, and the split is not cosmetic:
    # sampling 40 functions put 535 of its 548 chunks in `local-slot` and only 13
    # in `symbol-name`. Reported as one class it read as "callee naming", which
    # would have aimed the work at symbolisation instead of at the real finding -
    # that the two renderers partition values into different numbers of locals.
    ("cast", lambda a, b: _is_cast_edge(a, b)),
    ("type-unknown", lambda a, b: _type_edge(a, b, unknown=True)),
    ("type-width-or-sign", lambda a, b: _type_edge(a, b, unknown=False)),
    ("char-literal", lambda a, b: _either_kind_text(a, b, _looks_char)),
    ("integer-literal", lambda a, b: _both_kind(a, b, "num")),
    ("control-keyword", lambda a, b: _both_in(a, b, C_KEYWORDS)),
    ("negation", lambda a, b: _either_in(a, b, {"!", "~"})),
    ("argument-list", lambda a, b: _is_argument_chunk(a) or _is_argument_chunk(b)),
    ("dereference-or-index", lambda a, b: _either_in(a, b, {"*", "[", "]", "->", "."})),
    ("operator", lambda a, b: _either_kind(a, b, "op")),
    ("local-slot", lambda a, b: _either_kind_text(a, b, _looks_local_slot)),
    ("symbol-name", lambda a, b: _is_name_edge(a, b)),
    ("block-punctuation", lambda a, b: _is_punctuation_chunk(a) or _is_punctuation_chunk(b)),
)


def _looks_char(text: str) -> bool:
    return text.startswith("'") or text == "LIT"


def _looks_local_slot(text: str) -> bool:
    return bool(re.fullmatch(r"v\d+", text))


def _either_kind_text(a: list[str], b: list[str], predicate) -> bool:
    return any(predicate(t) for t in a) or any(predicate(t) for t in b)


def _is_argument_chunk(chunk: list[str]) -> bool:
    """A chunk that is only commas and operands, i.e. an arity difference."""
    if not chunk or "," not in chunk:
        return False
    return all(
        t == "," or _looks_local_slot(t) or _looks_numeric(t) or t == "ID" for t in chunk
    )


def _is_punctuation_chunk(chunk: list[str]) -> bool:
    return bool(chunk) and all(t in {"(", ")", "{", "}", ";", ","} for t in chunk)


CANON_TYPE_TOKENS = frozenset(TYPE_CANON.values())


def _type_edge(a: list[str], b: list[str], unknown: bool) -> bool:
    """Whether the divergence is between two canonical type tokens.

    `unknown=True` isolates the case where exactly one side declined to assign a
    type (`undefined4` against `uint32_t`), which is a different finding from
    the two sides asserting incompatible widths or signedness.
    """
    left = next((t for t in a if t in CANON_TYPE_TOKENS), None)
    right = next((t for t in b if t in CANON_TYPE_TOKENS), None)
    if left is None and right is None:
        return False
    either_unknown = (left or "").endswith("?") or (right or "").endswith("?")
    return either_unknown if unknown else not either_unknown

def _both_kind(a: list[str], b: list[str], kind: str) -> bool:
    return bool(a) and bool(b) and _looks_numeric(a[0]) and _looks_numeric(b[0])


def _looks_numeric(text: str) -> bool:
    return bool(re.fullmatch(r"NUM|0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*|\d+\.\d+[fF]?", text))


def _both_in(a: list[str], b: list[str], words: frozenset[str] | set[str]) -> bool:
    return bool(a) and bool(b) and (a[0] in words or b[0] in words)


def _either_in(a: list[str], b: list[str], words: frozenset[str] | set[str]) -> bool:
    return (bool(a) and a[0] in words) or (bool(b) and b[0] in words)


def _either_kind(a: list[str], b: list[str], kind: str) -> bool:
    ops = {"<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "++", "--"}
    return (bool(a) and a[0] in ops) or (bool(b) and b[0] in ops)


def _is_cast_edge(a: list[str], b: list[str]) -> bool:
    """Whether a differing chunk opens a parenthesised type, i.e. a cast.

    The streams reaching here are already canonicalised, so the type word is a
    `TYPE_CANON` value rather than its original spelling.
    """
    cast_words = CANON_TYPE_TOKENS | C_TYPE_WORDS

    def opens_cast(chunk: list[str]) -> bool:
        return bool(chunk) and chunk[0] == "(" and len(chunk) > 1 and chunk[1] in cast_words

    return opens_cast(list(a)) or opens_cast(list(b))


def _is_name_edge(a: list[str], b: list[str]) -> bool:
    return (bool(a) and re.fullmatch(r"ID|v\d+|[A-Za-z_$][\w$]*", a[0]) is not None) or (
        bool(b) and re.fullmatch(r"ID|v\d+|[A-Za-z_$][\w$]*", b[0]) is not None
    )


def classify_divergence(ours: Sequence[str], theirs: Sequence[str]) -> tuple[str, str]:
    """Names the first place two normalized streams part, and how."""
    matcher = difflib.SequenceMatcher(a=list(ours), b=list(theirs), autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        left = list(ours[i1:i2])[:4]
        right = list(theirs[j1:j2])[:4]
        for name, predicate in DIVERGENCE_CLASSES:
            try:
                if predicate(left, right):
                    return name, f"{' '.join(left) or '-'} | {' '.join(right) or '-'}"
            except Exception:
                continue
        return "other", f"{' '.join(left) or '-'} | {' '.join(right) or '-'}"
    return "none", ""


def classify_all_divergences(ours: Sequence[str], theirs: Sequence[str]) -> Counter:
    """Counts every differing chunk by class, not just the first.

    First-divergence alone ranks by whatever happens to appear earliest in the
    text, which for a decompiled function is the declaration block. Counting all
    of them says which defect actually dominates a function.
    """
    counts: Counter = Counter()
    matcher = difflib.SequenceMatcher(a=list(ours), b=list(theirs), autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        left = list(ours[i1:i2])[:4]
        right = list(theirs[j1:j2])[:4]
        for name, predicate in DIVERGENCE_CLASSES:
            try:
                if predicate(left, right):
                    counts[name] += 1
                    break
            except Exception:
                continue
        else:
            counts["other"] += 1
    return counts


@dataclass
class Row:
    entry_id: str
    name: str
    address: str
    level: str = "fail"
    body_level: str = "fail"
    prologue_matches: bool = False
    similarity: float = 0.0
    body_similarity: float = 0.0
    divergence: str = ""
    detail: str = ""
    body_divergences: dict = field(default_factory=dict)
    ours_tokens: int = 0
    theirs_tokens: int = 0
    error: str | None = None


@dataclass
class Comparison:
    level: str
    body_level: str
    prologue_matches: bool
    similarity: float
    body_similarity: float
    divergence: str
    detail: str
    body_divergences: Counter
    ours_tokens: int
    theirs_tokens: int


def grade(ours: Sequence[Token], theirs: Sequence[Token]) -> tuple[str, float]:
    """Grades one token pair, returning the strongest level it reaches."""
    if [t.text for t in ours] == [t.text for t in theirs]:
        return "token", 1.0
    ours_alpha = alpha_normalize(ours, callee_names(ours))
    theirs_alpha = alpha_normalize(theirs, callee_names(theirs))
    if ours_alpha == theirs_alpha:
        return "alpha", 1.0
    if skeleton_normalize(ours) == skeleton_normalize(theirs):
        return "skeleton", 1.0
    ratio = difflib.SequenceMatcher(a=ours_alpha, b=theirs_alpha, autojunk=False).ratio()
    return "fail", ratio


def compare(ours: str, theirs: str) -> Comparison:
    """Grades a function pair whole, then its statements and prologue apart."""
    ours_text = function_body(ours)
    theirs_text = function_body(theirs)
    ours_tokens = tokenize(ours_text)
    theirs_tokens = tokenize(theirs_text)
    n_ours, n_theirs = len(ours_tokens), len(theirs_tokens)

    ours_decl, ours_stmts = split_prologue(ours_tokens)
    theirs_decl, theirs_stmts = split_prologue(theirs_tokens)
    prologue_matches = alpha_normalize(ours_decl, frozenset()) == alpha_normalize(
        theirs_decl, frozenset()
    )
    body_level, body_similarity = grade(ours_stmts, theirs_stmts)
    body_divergences = (
        classify_all_divergences(
            alpha_normalize(ours_stmts, callee_names(ours_stmts)),
            alpha_normalize(theirs_stmts, callee_names(theirs_stmts)),
        )
        if body_level == "fail"
        else Counter()
    )

    if normalize_text(ours_text) == normalize_text(theirs_text):
        level, similarity = "exact", 1.0
    else:
        level, similarity = grade(ours_tokens, theirs_tokens)

    if level == "fail":
        ours_alpha = alpha_normalize(ours_tokens, callee_names(ours_tokens))
        theirs_alpha = alpha_normalize(theirs_tokens, callee_names(theirs_tokens))
        divergence, detail = classify_divergence(ours_alpha, theirs_alpha)
    else:
        divergence, detail = "none", ""

    return Comparison(
        level=level,
        body_level=body_level,
        prologue_matches=prologue_matches,
        similarity=similarity,
        body_similarity=body_similarity,
        divergence=divergence,
        detail=detail,
        body_divergences=body_divergences,
        ours_tokens=n_ours,
        theirs_tokens=n_theirs,
    )


LEVELS = ("exact", "token", "alpha", "skeleton", "fail")

SELF_TEST_BASE = """void f(void) {
  int total = 0;
  for (int i = 0; i < 10; i = i + 1) {
    total = total + arr[i];
  }
  helper(total);
  return;
}"""


def self_test() -> None:
    """Pins what each level accepts, because the headline number depends on it.

    A grading scale nobody has probed is indistinguishable from a scale that
    always answers "agrees". Each case below is a single, named difference and
    the weakest level that must still absorb it.
    """
    base = SELF_TEST_BASE
    renamed = (
        base.replace("total", "uVar1")
        .replace("i ", "iVar2 ")
        .replace("i]", "iVar2]")
        .replace("i;", "iVar2;")
        .replace("i <", "iVar2 <")
    )
    cases = [
        ("identical", base, "exact", None),
        ("trailing space", "\n".join(l + "   " for l in base.split("\n")), "exact", None),
        ("crlf endings", base.replace("\n", "\r\n"), "exact", None),
        # Indentation is formatting policy, not trailing space. Keeping it at
        # `token` is what makes `exact` a claim about bytes, not about tokens.
        ("indentation", base.replace("  ", "    "), "token", None),
        ("comment added", base.replace("int total", "/* n */ int total"), "token", None),
        ("locals renamed", renamed, "alpha", None),
        ("literal changed", base.replace("< 10", "< 12"), "skeleton", None),
        ("callee renamed", base.replace("helper", "other_fn"), "skeleton", None),
        # `int32_t` and `int` are one type in two vocabularies, so folding them
        # must reach `alpha`. Everything below asserts the fold is not too wide.
        ("type spelling", base.replace("int total", "int32_t total"), "alpha", None),
        ("type width", base.replace("int total", "char total"), "fail", "type-width-or-sign"),
        ("type signedness", base.replace("int total", "uint total"), "fail", "type-width-or-sign"),
        ("type unknown", base.replace("int total", "undefined4 total"), "fail", "type-unknown"),
        ("cast added", base.replace("arr[i]", "(uint)arr[i]"), "fail", "cast"),
        ("operator", base.replace("i < 10", "i <= 10"), "fail", "operator"),
        (
            "for became while",
            base.replace("for (int i = 0; i < 10; i = i + 1)", "while (i < 10)"),
            "fail",
            "control-keyword",
        ),
    ]
    for name, text, expected_level, expected_divergence in cases:
        result = compare(text, base)
        level, divergence = result.level, result.divergence
        if level != expected_level:
            raise AssertionError(f"{name}: expected level {expected_level}, got {level}")
        if expected_divergence is not None and divergence != expected_divergence:
            raise AssertionError(
                f"{name}: expected divergence {expected_divergence}, got {divergence}"
            )

    # A local rename must not launder a callee rename: `helper` sits in call
    # position, so it is excluded from alpha-renaming by construction.
    tokens = tokenize(SELF_TEST_BASE)
    if "helper" not in callee_names(tokens):
        raise AssertionError("callee_names missed a called identifier")
    if "total" in callee_names(tokens):
        raise AssertionError("callee_names captured a local")

    # The prologue split is what stops a declaration difference from being
    # reported as the whole function's defect, so its boundary is pinned too.
    declared = tokenize("{ int a; uint b; helper(a); if (b) { return; } }")
    prologue, statements = split_prologue(declared)
    if [t.text for t in prologue] != ["{", "int", "a", ";", "uint", "b", ";"]:
        raise AssertionError(f"prologue mis-split: {[t.text for t in prologue]}")
    if [t.text for t in statements][:4] != ["helper", "(", "a", ")"]:
        raise AssertionError(f"statements mis-split: {[t.text for t in statements][:4]}")

    # A function differing only in its declarations must grade `fail` whole and
    # `alpha` on statements: that pair is the type-recovery finding.
    typed = SELF_TEST_BASE.replace("int total = 0;", "short total = 0;")
    split = compare(typed, SELF_TEST_BASE)
    if split.level != "fail" or split.body_level not in ("token", "alpha"):
        raise AssertionError(
            f"declaration-only difference graded {split.level}/{split.body_level}"
        )
    if split.prologue_matches:
        raise AssertionError("prologue reported matching when the declared type differs")
    print(f"equivalence self-test: ok ({len(cases)} cases)")


def render_ventris(
    ventris: str, image: Path, target: str, address: str, limit: int, timeout: float
):
    args = [
        ventris,
        "__internal",
        "decompile-native",
        os.fspath(image),
        address,
        "--target",
        target,
        "--limit",
        str(limit),
        "--json",
    ]
    # One pathological function must not stall a sweep of hundreds. A render that
    # exceeds the budget is reported as its own class rather than silently
    # dropped, so the count of "too slow to measure" stays visible.
    try:
        completed = subprocess.run(
            args, capture_output=True, text=True, check=False, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return None, f"render timeout after {timeout:.0f}s"
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None, (completed.stderr.strip() or "no JSON envelope")[:200]
    if not payload.get("ok"):
        return None, str(payload.get("error", "unknown error"))[:200]
    return payload["result"], None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-dir", type=Path)
    parser.add_argument("--ventris")
    parser.add_argument("--oracle", type=Path, help="sweep_oracle.py --out dir")
    parser.add_argument("--out", type=Path, help="write the full JSON report here")
    parser.add_argument("--limit", type=int, default=4096)
    parser.add_argument("--jobs", type=int, default=0)
    parser.add_argument("--id", action="append", dest="ids")
    parser.add_argument("--max-per-image", type=int, default=0)
    parser.add_argument("--worst", type=int, default=12, help="lowest-similarity rows to print")
    parser.add_argument(
        "--render-timeout", type=float, default=60.0, help="per-function render budget, seconds"
    )
    parser.add_argument("--self-test", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.self_test:
        self_test()
        return 0
    missing = [n for n in ("image_dir", "ventris", "oracle") if getattr(args, n) is None]
    if missing:
        build_parser().error(
            "--" + ", --".join(m.replace("_", "-") for m in missing)
            + " required unless --self-test is used"
        )
    manifest = {e["id"]: e for e in census.read_manifest(args.ventris)}

    jobs = []
    for entry_dir in sorted(args.oracle.iterdir()):
        if not entry_dir.is_dir() or entry_dir.name.startswith("_"):
            continue
        entry_id = entry_dir.name
        if args.ids and entry_id not in set(args.ids):
            continue
        entry = manifest.get(entry_id)
        sweep = entry_dir / "sweep-manifest.tsv"
        if entry is None or not sweep.is_file():
            continue
        image = args.image_dir / entry["binary_name"]
        lines = [l for l in sweep.read_text(encoding="utf-8").splitlines() if l.strip()]
        if args.max_per_image:
            lines = lines[: args.max_per_image]
        # An ELF whose sections overlay `ram` maps one offset in two spaces, and
        # a bare address is then ambiguous. The manifest already records which
        # space the corpus means, and `Target.qualified_address` uses it the same
        # way; without it every PS2 function fails to render.
        space = entry.get("address_space")
        for line in lines:
            key, name, address, _length = line.split("\t")
            qualified = address if ("::" in address or not space) else f"{space}::{address}"
            jobs.append((entry_id, entry["target"], image, key, name, qualified, entry_dir))

    if not jobs:
        print("no oracle functions found; run sweep_oracle.py first", file=sys.stderr)
        return 2

    def run(job) -> Row:
        entry_id, target, image, key, name, address, entry_dir = job
        row = Row(entry_id=entry_id, name=name, address=address)
        try:
            oracle_text = (entry_dir / f"{key}.ghidra-decompile").read_text(
                encoding="utf-8", errors="replace"
            )
            theirs = census.oracle_c(oracle_text)
        except Exception as error:
            row.error = f"oracle unreadable: {error}"
            return row
        ours, error = render_ventris(
            args.ventris, image, target, address, args.limit, args.render_timeout
        )
        if ours is None:
            row.error = error
            return row
        result = compare(ours, theirs)
        row.level = result.level
        row.body_level = result.body_level
        row.prologue_matches = result.prologue_matches
        row.similarity = result.similarity
        row.body_similarity = result.body_similarity
        row.divergence = result.divergence
        row.detail = result.detail
        row.body_divergences = dict(result.body_divergences)
        row.ours_tokens = result.ours_tokens
        row.theirs_tokens = result.theirs_tokens
        return row

    workers = args.jobs or min(32, (os.cpu_count() or 4))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        rows = list(pool.map(run, jobs))

    ok = [r for r in rows if r.error is None]
    errored = [r for r in rows if r.error is not None]
    levels = Counter(r.level for r in ok)
    total = len(ok)

    print(f"compared {total} functions ({len(errored)} could not be rendered)\n")
    cumulative = 0
    for level in LEVELS:
        count = levels.get(level, 0)
        if level != "fail":
            cumulative += count
        share = 100.0 * count / total if total else 0.0
        print(f"  {level:9s} {count:5d}  {share:5.1f}%")
    print(f"\n  equivalent at alpha or better: {sum(levels.get(l, 0) for l in LEVELS[:3])}"
          f" of {total}"
          f" ({100.0 * sum(levels.get(l, 0) for l in LEVELS[:3]) / total if total else 0:.1f}%)")
    print(f"  right structure or better:     {cumulative} of {total}"
          f" ({100.0 * cumulative / total if total else 0:.1f}%)")

    body_levels = Counter(r.body_level for r in ok)
    print("\nstatements only, with the declaration prologue set aside:")
    body_cumulative = 0
    for level in LEVELS:
        count = body_levels.get(level, 0)
        if level != "fail":
            body_cumulative += count
        share = 100.0 * count / total if total else 0.0
        print(f"  {level:9s} {count:5d}  {share:5.1f}%")
    body_alpha = sum(body_levels.get(l, 0) for l in LEVELS[:3])
    print(f"\n  statements equivalent at alpha or better: {body_alpha} of {total}"
          f" ({100.0 * body_alpha / total if total else 0:.1f}%)")
    prologue_only = [r for r in ok if r.level == "fail" and r.body_level in LEVELS[:3]]
    print(f"  differ ONLY in the declaration prologue:  {len(prologue_only)} of {total}"
          f" ({100.0 * len(prologue_only) / total if total else 0:.1f}%)")

    failing = sorted([r for r in ok if r.level == "fail"], key=lambda r: r.similarity)
    if failing:
        median = failing[len(failing) // 2].similarity
        print(f"\n  failing similarity: median {median:.3f}, "
              f"best {failing[-1].similarity:.3f}, worst {failing[0].similarity:.3f}")
        body_failing = [r for r in ok if r.body_level == "fail"]
        if body_failing:
            weighted: Counter = Counter()
            for row in body_failing:
                weighted.update(row.body_divergences)
            print(f"\nevery divergence in the statements, by class"
                  f" ({len(body_failing)} functions, {sum(weighted.values())} chunks):")
            for name, count in weighted.most_common():
                print(f"  {name:24s} {count:6d}  {100.0 * count / sum(weighted.values()):5.1f}%")
            print("\nfunctions whose statements diverge most, by class share:")
            ranked = sorted(
                body_failing, key=lambda r: r.body_similarity
            )[: args.worst]
            for row in ranked:
                top = Counter(row.body_divergences).most_common(2)
                summary = ", ".join(f"{n}x{c}" for n, c in top) or "-"
                print(f"  {row.body_similarity:5.3f}  {row.entry_id}/{row.name[:44]:44s} {summary}")

    if errored:
        print(f"\nrender failures: {len(errored)}")
        for reason, count in Counter(
            (r.error or "").split(":")[0][:60] for r in errored
        ).most_common(8):
            print(f"  {count:5d}  {reason}")

    if args.out:
        args.out.write_text(
            json.dumps(
                {
                    "compared": total,
                    "levels": dict(levels),
                    "body_levels": dict(body_levels),
                    "rows": [vars(r) for r in rows],
                },
                indent=1,
            ),
            encoding="utf-8",
            newline="\n",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
