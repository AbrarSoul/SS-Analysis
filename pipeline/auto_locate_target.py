"""
Automatic replacement for the hand-curated per-case TARGETS/BRACE_ANCHOR_CASES
tables in extract_context_python.py / extract_context_java.py /
extract_context_js_ts.py.

Locating "which function contains the vulnerable code" is a mechanical,
derivable task, not a judgment call: parse patch.diff's hunk header
(@@ -oldstart,oldcount +newstart,newcount @@) to get the changed line
number in each revision, then find the innermost function/method (and its
enclosing class, if any) whose span in that revision's source actually
contains that line. This module does that for all three languages, sharing
one diff-line-parsing routine and one "smallest enclosing span wins" rule.

Python uses the stdlib `ast` module directly (exact, no heuristics needed).
Java and JS/TS have no available parser, so both use the same general
strategy: scan the WHOLE file's brace structure once (reusing this
project's own literal/comment-aware brace matchers), tag every brace block
by whether the text immediately preceding its "{" looks method-like (has a
"(...)" parameter list, or is a bare/static initializer block) and is NOT a
control-flow construct (if/for/while/switch/catch/else/try/do/synchronized),
then pick the smallest such block containing the target line. This is
deliberately a general block-classifier rather than a single method-
signature regex, since Java/JS method signatures are too syntactically
varied (generics, multi-line params, annotations, arrow functions, getters/
setters, ...) to match reliably with one pattern -- classifying every block
this project's own brace matcher already finds is more robust than trying
to recognize a signature before ever finding its brace.

When no confident single answer exists (no hunk found, target line matches
no block, or -- for a class lookup -- the block sits directly at module/
file top level with no enclosing class), this raises AutoLocateError rather
than guessing, so the caller can fall back to manual handling for that one
case instead of silently extracting the wrong function.
"""
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class AutoLocateError(Exception):
    pass


# ---------------------------------------------------------------------------
# Diff parsing (shared by all languages)
# ---------------------------------------------------------------------------

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass
class HunkTarget:
    old_line: int  # a representative changed/context line number in the OLD (vulnerable) revision
    new_line: int  # a representative changed/context line number in the NEW (patched) revision
    changed_line_count: int  # +/- lines in this hunk, used to disambiguate when hunks land in different functions
    has_deletion: bool  # this run included at least one '-' line, so old_line is a REAL existing old-file line
    has_insertion: bool  # this run included at least one '+' line, so new_line is a REAL existing new-file line


def all_hunk_targets(diff_text: str) -> list:
    """Returns one HunkTarget per CONTIGUOUS run of changed (+/-) lines,
    across every hunk in the diff -- not one per '@@ ... @@' hunk header.

    Two distinct problems this solves, both found live on real cases:
    - A single-file diff can still touch several disjoint regions -- e.g.
      an added import at the top of the file plus the actual vulnerable
      function much further down (CASE-0002's first hunk was only
      `-from typing import Dict` / `+import ast ...`, module level, no
      enclosing function at all). Trusting only the first hunk would pick
      that noise over the real fix.
    - A single HUNK can itself contain more than one such region, separated
      by unchanged context lines -- also CASE-0002: one large hunk touches
      both the class's own docstring (module/class level, not inside any
      function) AND a complete rewrite of execute()/_safe_eval()/etc.
      (very much inside functions). Sampling only the hunk's FIRST changed
      line landed on the docstring and reported "no function contains this
      line" for the whole hunk, even though most of it plainly was inside
      real functions. Splitting on contiguous change-runs (a run ends
      whenever a context line is seen) gives each logically separate edit
      its own candidate target line.

    Returning every run's target lets the caller try each one and prefer
    whichever resolves to a real, substantively-changed function --
    see _best_across_hunks(). A changed line that is purely a comment
    contributes 0 to `changed_line_count` (though it still counts for
    has_deletion/has_insertion, since the line genuinely exists) rather
    than the usual 1 -- otherwise a comment-only edit can OUTRANK a real
    code edit purely by winning a tie on raw line count, or even win via
    _best_across_hunks()'s dict-iteration-order tie-break when weights are
    literally equal. Found live on Dav-Git/Dav-Cogs's ticketer.py
    (CASE-0045): a single-character comment-spacing fix (`#Thanks` ->
    `# Thanks`) tied in weight with, and happened to be resolved before,
    the actual fix (two `.format(user=ctx.author)` -> `.format(user=
    SafeMember(ctx.author))` format-string-injection sites) -- confirmed
    not a one-off by scanning all 301 final cases for a vulnerable/patched
    pair that becomes IDENTICAL once comments are stripped, which found 10.
    Deliberately NOT also discounting blank lines, even though they carry
    no more behavior than a comment does -- tried that first and it
    regressed a previously-correct pilot case (CASE-0008): a blank '+'
    line legitimately added as spacing right after a real one-line code
    insertion lowered that hunk's weight enough for an unrelated, equal-
    weight hunk elsewhere in the same diff to win instead. A blank line
    almost always accompanies a real, deliberate code edit; a comment
    virtually never IS one -- different enough signals to not conflate.
    Safe across all four languages: an unquoted '#' or '//' essentially
    never starts a real Python/Java/JS/TS statement (JS/TS private class
    fields, e.g. "#count = 0;", are the one known exception -- accepted as
    a rare miss rather than adding per-language syntax awareness here)."""
    def _is_comment_only_line(text: str) -> bool:
        s = text.strip()
        return s.startswith("#") or s.startswith("//")

    lines = diff_text.splitlines()
    targets = []
    i = 0
    while i < len(lines):
        m = _HUNK_RE.match(lines[i])
        if not m:
            i += 1
            continue
        old_start = int(m.group(1))
        new_start = int(m.group(3))
        old_line = old_start
        new_line = new_start
        j = i + 1
        run_old_line = run_new_line = None
        run_changed = 0
        run_has_deletion = run_has_insertion = False

        def flush_run():
            nonlocal run_old_line, run_new_line, run_changed, run_has_deletion, run_has_insertion
            if run_old_line is not None:
                targets.append(HunkTarget(old_line=run_old_line, new_line=run_new_line,
                                           changed_line_count=run_changed,
                                           has_deletion=run_has_deletion,
                                           has_insertion=run_has_insertion))
            run_old_line = run_new_line = None
            run_changed = 0
            run_has_deletion = run_has_insertion = False

        while j < len(lines) and not _HUNK_RE.match(lines[j]):
            body_line = lines[j]
            if body_line.startswith("-") and not body_line.startswith("---"):
                if run_old_line is None:
                    run_old_line, run_new_line = old_line, new_line
                if not _is_comment_only_line(body_line[1:]):
                    run_changed += 1
                run_has_deletion = True
                old_line += 1
            elif body_line.startswith("+") and not body_line.startswith("+++"):
                if run_old_line is None:
                    run_old_line, run_new_line = old_line, new_line
                if not _is_comment_only_line(body_line[1:]):
                    run_changed += 1
                run_has_insertion = True
                new_line += 1
            else:
                # context line -- ends any in-progress change run
                flush_run()
                old_line += 1
                new_line += 1
            j += 1
        flush_run()
        i = j
    if not targets:
        raise AutoLocateError("no hunk header found in diff")
    return targets


def _best_across_hunks(hunks: list, resolve_one) -> tuple:
    """Tries every hunk's target line through resolve_one(line) -> (start,
    end, payload), and returns the payload of whichever DISTINCT function
    span accumulated the most total changed_line_count across the hunks
    that landed in it.

    Why not just the first hunk: a single-file diff can still touch several
    disjoint regions -- an added import at module level (no enclosing
    function at all -- simply fails to resolve and is skipped, exactly as
    it should be) plus the actual vulnerable function elsewhere. Why not
    just "the first hunk that resolves to anything": if an early hunk is a
    small, real-but-secondary change (e.g. a one-line docstring tweak in an
    unrelated method) and a later, larger hunk is the actual fix, weighting
    by total changed-line count across hunks favors the function that was
    genuinely, substantively modified -- the same intuition Section 7.1
    already applies at the case-selection level (single-file, localized
    fixes) applied here at the function level."""
    by_span = {}  # (start, end) -> [total_changed, payload]
    errors = []
    for h in hunks:
        try:
            start, end, payload = resolve_one(h)
        except AutoLocateError as e:
            errors.append(str(e))
            continue
        key = (start, end)
        if key not in by_span:
            by_span[key] = [0, payload]
        by_span[key][0] += h.changed_line_count
    if not by_span:
        raise AutoLocateError("; ".join(errors) if errors else "no hunk resolved to a function")
    best = max(by_span.values(), key=lambda v: v[0])
    return best[1]


def _is_boundary_sensitive(hunk: "HunkTarget", side: str) -> bool:
    """True when this hunk's target line for `side` is a GAP position
    between two real lines of that revision, not a line that revision
    itself actually contains -- a pure insertion's old_line (nothing was
    deleted, so no old-file line was touched) or a pure deletion's new_line
    (nothing was inserted, so no new-file line exists there).

    Matters because such a gap position can numerically coincide with the
    very first line of the next, completely untouched function/method --
    found live on CASE-0042 (copyparty/authsrv.py): two new methods were
    inserted immediately before the existing _ls_nope(), so the insertion's
    old_line landed exactly on _ls_nope's own def line and was silently
    attributed to _ls_nope, an unrelated 1-line stub with zero connection
    to the actual missing-authorization vulnerability. When this flag is
    true, resolve_at_line must require the target line to fall STRICTLY
    after the candidate's own signature line, not merely on-or-after it --
    a real "first line of this function's body" insertion always lands at
    signature_line + 1 or later (the signature line itself is always
    unchanged context preceding the run), so this cannot reject any
    genuine same-function insertion, only the boundary false-positive."""
    return not (hunk.has_deletion if side == "old" else hunk.has_insertion)


def _locate_two_pass(hunks: list, side: str, resolve_at_line):
    """Runs _best_across_hunks() twice: first with every hunk's EXACT
    target line only, falling back to a tolerant (+/-1 line) second pass
    ONLY if the exact pass found nothing at all across every hunk.

    The tolerant retry (target_line, then -1, then +1) exists for pure
    insertions (a hunk with only '+' lines): the diff's own line numbering
    can legitimately land on the blank line immediately after a function's
    last statement -- e.g. inserting a new call at the end of a method
    body, right before the blank line separating it from the next method.
    AST/brace end-of-span boundaries don't include that trailing blank
    line, so the exact line resolves to nothing even though the insertion
    obviously belongs to the function right above it (found live on
    frappe/lms's CourseChapter.on_update()).

    Tried applying that tolerance unconditionally on every failed line
    first, and it backfired: verified against the pilot's 40 known-correct
    cases, it REGRESSED two previously-correct results (CASE-0003,
    CASE-0015) by letting an imprecise +/-1 match on one hunk outvote a
    different hunk's exact, correct match in _best_across_hunks()'s
    changed-line-weighted comparison. Restricting tolerance to a genuinely
    last-resort second pass -- only when EVERY hunk's exact line already
    failed -- keeps exact matches strictly preferred while still covering
    the pure-insertion case that has no exact match to compete with."""
    def exact_resolve(hunk: HunkTarget):
        target_line = hunk.old_line if side == "old" else hunk.new_line
        return resolve_at_line(target_line, boundary_sensitive=_is_boundary_sensitive(hunk, side))

    try:
        return _best_across_hunks(hunks, exact_resolve)
    except AutoLocateError:
        pass

    def tolerant_resolve(hunk: HunkTarget):
        target_line = hunk.old_line if side == "old" else hunk.new_line
        errors = []
        for candidate in (target_line - 1, target_line + 1):
            try:
                return resolve_at_line(candidate, boundary_sensitive=False)
            except AutoLocateError as e:
                errors.append(str(e))
        raise AutoLocateError("; ".join(errors))

    return _best_across_hunks(hunks, tolerant_resolve)


# ---------------------------------------------------------------------------
# Python (exact, via ast)
# ---------------------------------------------------------------------------

def locate_python(source: str, hunks: list, side: str):
    """Returns (function_source_text, containing_class_name_or_None).
    side: "old" or "new", selects which revision's line number each hunk carries."""
    import ast
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)

    def resolve_at_line(target_line: int, boundary_sensitive: bool = False):
        func_candidates = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                lo = node.lineno + 1 if boundary_sensitive else node.lineno
                if lo <= target_line <= node.end_lineno:
                    func_candidates.append((node.end_lineno - node.lineno, node))
        if not func_candidates:
            raise AutoLocateError(f"no function contains line {target_line}")
        func_candidates.sort(key=lambda t: t[0])
        func_node = func_candidates[0][1]

        class_candidates = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                if node.lineno <= func_node.lineno and func_node.end_lineno <= node.end_lineno:
                    class_candidates.append((node.end_lineno - node.lineno, node.name))
        class_candidates.sort(key=lambda t: t[0])
        class_name = class_candidates[0][1] if class_candidates else None
        func_text = "".join(lines[func_node.lineno - 1:func_node.end_lineno])
        return func_node.lineno, func_node.end_lineno, (func_text, class_name)

    return _locate_two_pass(hunks, side, resolve_at_line)


# ---------------------------------------------------------------------------
# Shared brace-block enumeration (Java + JS/TS)
# ---------------------------------------------------------------------------

_CONTROL_FLOW_TAIL_RE = re.compile(
    r"(?:^|[;}{])\s*(?:if|for|while|switch|catch|else|do|synchronized|try|finally)\s*(?:\(|$|\{)"
)


@dataclass
class BraceBlock:
    start_line: int  # 1-indexed -- start of the SIGNATURE (may be several lines before the "{", e.g. Allman-style braces on their own line), used for extraction
    brace_line: int  # 1-indexed, the line actually containing the opening "{"
    end_line: int  # 1-indexed, line containing the matching closing "}"
    start_offset: int  # absolute character offset (into the whole source string) where the signature begins
    end_offset: int  # absolute character offset one PAST the matching closing "}" -- extraction is source[start_offset:end_offset], not whole trailing lines
    opening_context: str  # text from the start of the current statement through the opening "{", for classifying whether it looks method-like


def _compute_code_line_flags(source: str, line_start_offsets: list) -> list:
    """Returns one bool per line: True if that line contains at least one
    character of REAL code (not inside a string/comment, not pure
    whitespace). Used to skip past a preceding Javadoc/comment block (which
    is real text, not blank, so a naive .strip()=="" check wrongly treats
    it as significant) when finding where a function's signature actually
    begins. A separate simple pass rather than folded into the main
    brace-scanning loop, since interleaving both kinds of state tracking in
    one loop is exactly the kind of thing that produced this project's own
    earlier bugs (see the ';' and Allman-brace fixes above) -- a second
    linear pass over a single source file is cheap, and correctness here
    matters more than saving one pass."""
    n = len(source)
    flags = [False] * len(line_start_offsets)
    cur_line = 0
    i = 0
    in_string = None
    in_line_comment = False
    in_block_comment = False
    while i < n:
        c = source[i]
        if c == "\n":
            in_line_comment = False
            cur_line += 1
            i += 1
            continue
        if in_line_comment:
            i += 1
            continue
        if in_block_comment:
            if c == "*" and i + 1 < n and source[i + 1] == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_string:
            flags[cur_line] = True
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == in_string:
                in_string = None
            i += 1
            continue
        if c == "/" and i + 1 < n and source[i + 1] == "/":
            in_line_comment = True
            i += 2
            continue
        if c == "/" and i + 1 < n and source[i + 1] == "*":
            in_block_comment = True
            i += 2
            continue
        if c in ('"', "'", "`"):
            in_string = c
            flags[cur_line] = True
            i += 1
            continue
        if not c.isspace():
            flags[cur_line] = True
        i += 1
    return flags


_REGEX_PRECEDING_CHARS = "=([{,!&|?:;\n"


def _looks_like_regex_start(source: str, i: int) -> bool:
    """True if the '/' at `source[i]` is plausibly the start of a JS/TS
    regex literal rather than division -- the previous non-whitespace
    character is one that can only precede the start of a new expression
    (assignment, opening bracket, comma, boolean/comparison operator,
    statement separator, ...), or there is no previous character at all.
    A real division always has a value (identifier/number/`)`/`]`/closing
    quote) immediately before the `/`, which this deliberately excludes."""
    k = i - 1
    while k >= 0 and source[k] in " \t\n\r":
        k -= 1
    if k < 0:
        return True
    return source[k] in _REGEX_PRECEDING_CHARS


def _scan_regex_literal_end(source: str, start: int):
    """`start` points at the opening '/' of a suspected regex literal.
    Returns the index just past it (including trailing flag letters like
    'g'/'i') if it looks like a genuine, single-line regex literal, else
    None. Returning None on anything unexpected (hits a newline before an
    unescaped closing '/') means the caller falls back to treating '/' as
    an ordinary character -- a heuristic miss here costs nothing beyond
    what already happened before this fix existed, it never corrupts state
    the way a wrong hit would."""
    n = len(source)
    i = start + 1
    in_char_class = False
    while i < n:
        c = source[i]
        if c == "\n":
            return None
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == "[":
            in_char_class = True
        elif c == "]":
            in_char_class = False
        elif c == "/" and not in_char_class:
            i += 1
            while i < n and source[i].isalpha():
                i += 1
            return i
        i += 1
    return None


def enumerate_brace_blocks(source: str, language: str = "javascript") -> list:
    """Finds every brace-delimited block in the file via a single
    depth-tracking scan (literal/comment-aware, character-exact), returning
    each one's line span, absolute character span, and the text of its own
    opening signature/statement (for classifying whether it looks
    method-like).

    Two things this deliberately gets exact rather than approximate, both
    found live by comparing against the pilot's hand-extracted functions:
    - start_line/start_offset is where the CURRENT STATEMENT began, not
      necessarily the line the "{" itself sits on -- Allman-style
      Java/C-family code puts the brace on its own line after the
      signature (CASE-0019) -- and skips past any purely comment/blank
      lines immediately before it (e.g. a preceding Javadoc block,
      CASE-0014 and others), so extraction starts at the real signature.
    - end_offset stops exactly at the matching "}", not at the end of that
      line -- a whole-line extraction pulls in trailing same-line
      characters that belong to an OUTER enclosing statement (e.g. the
      ");" closing a `.set('key', function() {...})` call, CASE-0029),
      which the pilot's own anchor-based extraction never included either.

    Scans the raw source character-by-character with its own inline
    string/comment tracking (rather than calling a separate line-cleaning
    pass) specifically so absolute character offsets stay exact throughout
    -- a pre-cleaned, comment-blanked copy of each line does not
    necessarily have the same length as the original when a line comment
    or line-spanning block comment is involved, which would otherwise
    silently misalign every offset computed from it."""
    n = len(source)
    stack = []  # each entry: [sig_start_offset, brace_offset]
    blocks = []
    statement_start_offset = 0
    line_start_offsets = [0]
    off = 0
    for ch in source:
        off += 1
        if ch == "\n":
            line_start_offsets.append(off)

    def offset_to_line(offset: int) -> int:
        # 0-indexed line number containing `offset`
        lo, hi = 0, len(line_start_offsets) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_start_offsets[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo

    code_line_flags = _compute_code_line_flags(source, line_start_offsets)

    def is_blank_line(line_idx: int) -> bool:
        return not code_line_flags[line_idx]

    _ANNOTATION_LINE_RE = re.compile(r"^\s*@\w+(?:\([^)]*\))?\s*$")

    def is_annotation_only_line(line_idx: int) -> bool:
        start = line_start_offsets[line_idx]
        end = line_start_offsets[line_idx + 1] if line_idx + 1 < len(line_start_offsets) else n
        return bool(_ANNOTATION_LINE_RE.match(source[start:end]))

    def normalize_to_next_line_if_trailing(offset: int) -> int:
        """If everything from `offset` to the end of its line is whitespace
        (the common case: a '}' or ';' was the last real thing on its
        line), advances to the start of the NEXT line. Otherwise leaves
        `offset` untouched (same-line continuations like "} foo();" keep
        scanning from right after the '}', not the next line).

        Needed because `offset` right after a closing '}' typically points
        AT the newline character that ends that same line -- and
        offset_to_line() correctly considers that offset still part of the
        CURRENT line (the one with the '}'), which is not blank (the '}'
        itself is real code). Without this, the blank/comment-skipping loop
        below never even starts, since it only skips lines that are
        entirely blank -- found live on CASE-0014, where the previous
        method's closing '}' on its own line was silently treated as the
        signature's own start line, pulling in that stray '}' plus the
        Javadoc between it and the real signature."""
        line_idx = offset_to_line(offset)
        line_end = line_start_offsets[line_idx + 1] if line_idx + 1 < len(line_start_offsets) else n
        if source[offset:line_end].strip() == "" and line_idx + 1 < len(line_start_offsets):
            return line_start_offsets[line_idx + 1]
        return offset

    i = 0
    in_string = None
    in_line_comment = False
    in_block_comment = False
    paren_depth = 0  # unclosed '(' count SINCE THE INNERMOST OPEN BRACE (not
    # file-wide -- see the paren_depth save/restore at each '{'/'}' below) --
    # a ';' inside a resource list or for-loop header (e.g. Java's
    # try (out = ...; writer = ...) { ... }) is NOT a statement terminator,
    # just a separator -- treating it as one reset statement_start_offset
    # mid-declaration, stripping the leading "try" keyword from what
    # _looks_method_like() sees and making it wrongly classify the
    # try-with-resources BODY as a method -- found live on alfio-event/
    # alfio's ExportUtils.exportCsv() (CASE-0093), a try with two
    # semicolon-separated resources. Scoping the counter to reset at every
    # brace boundary (rather than tracking it file-wide) matters just as
    # much: a still-open '(' from an outer call wrapping a whole code block
    # -- e.g. GObject.registerClass({ ... methods with real statements ... })
    # -- must not suppress real ';' statement separators inside THOSE
    # methods just because some unrelated outer '(' hasn't closed yet.
    # Backtick template literals need more than simple string-delimiter
    # tracking: they can contain `${...}` interpolations holding REAL CODE,
    # including its own braces (an inline object literal, an arrow function
    # body, ...) that must NOT be counted as closing whatever function block
    # is currently open. Treating a backtick exactly like a plain quote
    # character (as an earlier version of this scanner did) let an
    # interpolation's own braces desynchronize the depth counter, matching a
    # much-later, unrelated closing brace -- found live on a real case
    # (agenticmail's storage-routes file, a "confident" auto-located result
    # that actually spanned 1214 lines across several unrelated functions).
    # Ports the same mode-stack approach already proven in the pilot's own
    # extract_context_js_ts.py (extract_block_by_anchor): while inside a
    # `${...}` interpolation ("template_expr" mode), "{"/"}" behave like
    # ordinary code and are free to open/close nested blocks of their own;
    # the specific "}" that closes the interpolation itself is distinguished
    # by mode alone, not by depth, exactly as that proven implementation
    # does. Harmless no-op for Java, which has no backtick literals at all.
    mode_stack = ["code"]
    skipped_literal_depth = 0  # >0 while inside a default-parameter-value
    # object/array literal being skipped (see the '{' handler below) --
    # separate from paren_depth because a call argument that's ALSO an
    # object literal, e.g. GObject.registerClass({...}, class Foo {...}),
    # must NOT be skipped (that class body has real methods to find) even
    # though it too sits inside an unclosed '('. Only a '{' that's a
    # DEFAULT VALUE -- immediately preceded by '=' -- is skipped; nesting
    # inside an already-skipped literal (e.g. `x = {a: {b: 1}}`) doesn't
    # need its own '='-check, it's already inside the skip zone.
    while i < n:
        c = source[i]
        mode = mode_stack[-1]
        if in_line_comment:
            if c == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if c == "*" and i + 1 < n and source[i + 1] == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_string:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == in_string:
                in_string = None
            i += 1
            continue
        if mode == "template":
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == "`":
                mode_stack.pop()
                i += 1
                continue
            if c == "$" and i + 1 < n and source[i + 1] == "{":
                mode_stack.append("template_expr")
                i += 2
                continue
            i += 1
            continue
        if c == "/" and i + 1 < n and source[i + 1] == "/":
            in_line_comment = True
            i += 2
            continue
        if c == "/" and i + 1 < n and source[i + 1] == "*":
            in_block_comment = True
            i += 2
            continue
        if language in ("javascript", "typescript") and c == "/" and _looks_like_regex_start(source, i):
            # A JS/TS regex literal (e.g. /^[0-9]{1,15}$/g) can contain
            # '{'/'}' inside a quantifier that have NOTHING to do with code
            # blocks -- with no regex awareness at all, those characters
            # desynchronized the depth counter for the rest of the file,
            # producing garbage extracted "functions" starting mid-regex --
            # found live on mafintosh/is-my-json-valid's formats.js
            # (CVE-2016-2537): an EARLIER regex's `{6,14}` quantifier threw
            # off matching for a completely unrelated LATER line. Mirrors
            # the backtick-template mode fix above: recognize the literal
            # as a unit and skip over it whole, rather than character-by-
            # character through generic code-brace tracking.
            end = _scan_regex_literal_end(source, i)
            if end is not None:
                i = end
                continue
        if c in ('"', "'"):
            in_string = c
            i += 1
            continue
        if c == "`":
            mode_stack.append("template")
            i += 1
            continue
        if c == "{":
            if mode == "template_expr":
                # A brace opening real code (an object literal, an inline
                # arrow function, ...) INSIDE a "${...}" interpolation.
                # Deliberately not pushed onto the block-tracking stack --
                # matches the pilot's own proven extract_block_by_anchor()
                # exactly (only "code" mode braces count), which keeps the
                # matching "}" logic below simple: the FIRST "}" seen while
                # still in "template_expr" mode always ends the
                # interpolation, never confused with a nested pair's close.
                # Checked BEFORE the paren_depth guard below -- a template
                # literal with an interpolation can itself sit inside an
                # unclosed '(...)' (e.g. `new Error(\`${x}\`, {cause})`),
                # and mode-based handling must win there: found live when
                # the paren_depth guard, checked first, swallowed the '}'
                # that should have closed the interpolation and popped
                # mode_stack, desyncing every mode decision for the rest of
                # the file (CASE-0033, a TypeScript template literal used
                # as a `new Error(...)` argument).
                i += 1
                continue
            if skipped_literal_depth > 0:
                # Nested inside an already-skipped default-value literal
                # (e.g. the inner '{' of `x = {a: {b: 1}}`) -- no need to
                # re-check what precedes it, it's already in the skip zone.
                skipped_literal_depth += 1
                i += 1
                continue
            k = i - 1
            while k >= 0 and source[k] in " \t\n\r":
                k -= 1
            if paren_depth > 0 and k >= 0 and source[k] == "=":
                # A '{' inside an unclosed '(...)', immediately preceded by
                # '=', is a default PARAMETER value (e.g.
                # `listen(port, options = {})`), never a real statement
                # block -- no valid Java/JS/TS signature has one. Treating
                # it as a block anyway split the signature in two: the
                # tiny default-value object became its own spurious block,
                # and statement_start_offset got reset partway through the
                # signature, so the REAL method body's opening brace lost
                # its own leading "static listen(port, options = " context,
                # leaving only ") {" -- which then failed the method-like
                # classifier outright (no "(" left in what it could see).
                # Found live on Aarondoran/servify-express's StartServer
                # .listen() (CASE-0044).
                #
                # Deliberately narrower than "any brace inside unclosed
                # parens" (tried that first): a '{' that's a CALL argument
                # rather than a default value -- e.g.
                # GObject.registerClass({...}, class Foo { ...real methods
                # to find... }) -- sits inside unclosed parens too, but is
                # a real, meaningful block that must still be pushed. The
                # '='-precedes check is what tells the two apart; without
                # it this regressed a previously-correct pilot case
                # (CASE-0022) by silently discarding that class body.
                #
                # Known accepted gap: a default value that's itself an
                # arrow function with a real block body (e.g.
                # `f(cb = () => { doWork(); })`) would have that inner
                # block invisible to the locator too -- rare enough not to
                # be worth the added complexity of telling it apart from a
                # plain object/array default value.
                skipped_literal_depth = 1
                i += 1
                continue
            sig_start = statement_start_offset
            sig_start_line = offset_to_line(sig_start)
            brace_line = offset_to_line(i)
            while sig_start_line < brace_line and (
                is_blank_line(sig_start_line) or is_annotation_only_line(sig_start_line)
            ):
                sig_start_line += 1
                sig_start = line_start_offsets[sig_start_line]
            stack.append([sig_start, i, paren_depth])
            paren_depth = 0
            statement_start_offset = normalize_to_next_line_if_trailing(i + 1)
            i += 1
            continue
        if c == "}":
            if mode == "template_expr":
                # Ends this "${...}" interpolation, back to "template" mode --
                # NOT a block-closing brace for the function/method stack.
                # Checked before the paren_depth guard below -- see the
                # matching '{' branch above for why the ordering matters.
                mode_stack.pop()
                i += 1
                continue
            if skipped_literal_depth > 0:
                # Symmetric with the '{' guard above: closes either the
                # skipped default-value literal itself or one level of
                # nesting inside it -- either way, not a real block, must
                # not pop whatever real, unrelated block happens to
                # already be on the stack.
                skipped_literal_depth -= 1
                i += 1
                continue
            if stack:
                sig_start, brace_off, paren_depth = stack.pop()
                blocks.append(BraceBlock(
                    start_line=offset_to_line(sig_start) + 1,
                    brace_line=offset_to_line(brace_off) + 1,
                    end_line=offset_to_line(i) + 1,
                    start_offset=sig_start,
                    end_offset=i + 1,
                    opening_context=source[sig_start:brace_off + 1].strip()[-300:],
                ))
            statement_start_offset = normalize_to_next_line_if_trailing(i + 1)
            i += 1
            continue
        if c == "(":
            paren_depth += 1
            i += 1
            continue
        if c == ")":
            if paren_depth > 0:
                paren_depth -= 1
            i += 1
            continue
        if c == ";":
            if paren_depth == 0:
                statement_start_offset = normalize_to_next_line_if_trailing(i + 1)
            i += 1
            continue
        i += 1
    return blocks


_CLASS_LIKE_TAIL_RE = re.compile(r"\b(?:class|interface|enum)\s+\w+[^{]*$")


def _looks_method_like(opening_context: str) -> bool:
    ctx = opening_context.strip()
    if not ctx:
        return False
    # A class/interface/enum declaration's own brace can otherwise satisfy
    # the "(...)" check below purely because of an annotation on it (e.g.
    # "@Component(\"cubeMgmtService\")\npublic class CubeService ... {") --
    # found live on CASE-0016, where the whole class was picked as
    # "method-like" this way. Mutually exclusive with _looks_class_like():
    # a brace is one or the other, never both.
    if _CLASS_LIKE_TAIL_RE.search(ctx):
        return False
    # Bare/static initializer block, e.g. "static {". ctx always includes
    # the trailing "{" itself (opening_context is built up to and including
    # the brace), so the pattern must account for it -- checking "\s*$"
    # alone never matches "static {" (the "{" isn't whitespace). Found live
    # on a real case (jackson-databind's SubTypeValidator, a Java
    # security-relevant denylist built entirely inside a static block --
    # the same construct as the pilot's own hand-special-cased CASE-0011).
    if re.search(r"\bstatic\s*\{$", ctx):
        return True
    if _CONTROL_FLOW_TAIL_RE.search(ctx):
        return False
    # Must have a parameter-list-shaped "(...)" somewhere near the end
    # (allowing a trailing return-type/throws/arrow after it).
    m = re.search(r"\)([^()]*)$", ctx)
    if not (m and "(" in ctx):
        return False
    # Text after the last ")" must look like a return-type/throws/arrow tail.
    # An operator there means the "{" opens an object literal in an
    # expression, e.g. "registry.get(owner) ?? {" (found live on CASE-0085).
    tail = re.sub(r"<[^<>]*>", "", m.group(1))
    if re.search(r"\?\?|\|\||&&|(?<![=!<>])=(?![=>])", tail):
        return False
    return True


def _looks_class_like(opening_context: str, language: str) -> bool:
    ctx = opening_context.strip()
    if language == "java":
        return bool(re.search(r"\bclass\s+\w+[^{]*$", ctx) or re.search(r"\b(?:interface|enum)\s+\w+[^{]*$", ctx))
    return bool(re.search(r"\bclass\s+\w+[^{]*$", ctx))


def locate_brace_language(source: str, hunks: list, side: str, language: str):
    """Shared Java / JS / TS implementation. Returns (function_text,
    containing_class_name_or_None)."""
    blocks = enumerate_brace_blocks(source, language=language)

    def resolve_at_line(target_line: int, boundary_sensitive: bool = False):
        method_candidates = [
            b for b in blocks
            if (b.start_line + 1 if boundary_sensitive else b.start_line) <= target_line <= b.end_line
            and _looks_method_like(b.opening_context)
        ]
        if not method_candidates:
            raise AutoLocateError(f"no method-like block contains line {target_line}")
        method_candidates.sort(key=lambda b: b.end_line - b.start_line)
        chosen = method_candidates[0]

        class_candidates = [
            b for b in blocks
            if b.start_line <= chosen.start_line and chosen.end_line <= b.end_line and _looks_class_like(b.opening_context, language)
        ]
        class_name = None
        if class_candidates:
            class_candidates.sort(key=lambda b: b.end_line - b.start_line)
            m = re.search(r"\b(?:class|interface|enum)\s+(\w+)", class_candidates[0].opening_context)
            class_name = m.group(1) if m else None

        func_text = source[chosen.start_offset:chosen.end_offset]
        return chosen.start_line, chosen.end_line, (func_text, class_name)

    return _locate_two_pass(hunks, side, resolve_at_line)


def locate_java(source: str, hunks: list, side: str):
    return locate_brace_language(source, hunks, side, "java")


def locate_js_ts(source: str, hunks: list, side: str):
    return locate_brace_language(source, hunks, side, "javascript")
