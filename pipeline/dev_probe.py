"""
Development-probe mechanism, implementing Research_Direction_20261011.md Item 5 /
Controlled_2x2_Protocol_Draft_20261012.md §5's design as it stands after three correction rounds
(see Bounded_Investigation_Tracking.md's Item 5 section for the full history: circular
validation-oracle -> AST-isomorphism oracle; "different family" framing self-contradicting its own
construction -> explicit within-family framing; no reflection safety -> eligibility filter;
parameter renaming breaking keyword callers -> local-only non-parameter renaming).

Builds, from PERMITTED information only (`PatchInfo.vulnerable_function`/`patched_function` -- NEVER
the hidden variant files), a probe pair: the same function with exactly one local, non-parameter
binding renamed. Validity is checked by (1) re-parsing the transformed source and (2) an
AST-isomorphism check against the original -- structurally identical except at the renamed
identifier's nodes -- NEVER by running any Semgrep rule, baseline or candidate, as the oracle.

Four languages are supported, matching the diagnostic's own case set (Python/Java/JavaScript/
TypeScript). Python uses the stdlib `ast` module, which gives real scope/binding information
(Store vs. Load context, explicit `global`/`nonlocal` declarations). Java/JavaScript/TypeScript use
`tree_sitter` concrete syntax trees, which do NOT resolve scope the way `ast` does -- the
language-specific eligibility/candidate logic below is accordingly a documented, conservative
heuristic, not a semantic guarantee, and says so at each point it matters.

New dependencies added for this module: `tree_sitter`, `tree_sitter_java`, `tree_sitter_javascript`,
`tree_sitter_typescript` (grammar packages only, no network/IO at runtime).

A SECOND safety finding, beyond the Python-specific reflection filter already in the design,
was made empirically while building this module and is new to this file: in JavaScript/TypeScript,
an ES6 "shorthand" object property (`{token}`, equivalent to `{token: token}`) ties the resulting
object's KEY to the variable's NAME, not just its value -- renaming the variable there would also
silently rename the object's key, an observable structural change outside the variable itself,
exactly the same class of risk the reflection filter exists to catch. Confirmed directly via
tree-sitter's own node types: a shorthand property is a `shorthand_property_identifier`, distinct
from both `identifier` (a genuine variable reference, safe to rename) and `property_identifier`
(an explicit object key or member-access field name, never a variable reference, never renamed).
Any candidate whose name appears in a `shorthand_property_identifier` anywhere in the function is
excluded, the same conservative "skip this candidate" response the Python reflection filter uses.

A THIRD finding, also empirical, specific to Python: the FIRST version of this module reconstructed
the renamed source via `ast.unparse()`, which turned out to not be formatting-preserving in a way
that matters here -- Python's own parser collapses adjacent implicit string-literal concatenation
(`r'a' r'b' r'c'` on separate lines, a common idiom for long regexes) into a single `Constant` at
parse time, so `ast.unparse()` always re-emits it as ONE literal, never as the original multiple
adjacent literals. Confirmed directly against a real development case (CASE-0134): Semgrep's OWN
Python parser does NOT perform this collapse -- it matched a rule whose pattern was literally just
ONE of four adjacent raw-string lines, against the real benchmark file, at exactly that one line.
`ast.unparse()`'s reformatting silently destroyed the very structure that rule's pattern depended
on, producing a false "the probe exposes a weakness" result that was actually a probe-construction
artifact, not a real renaming-robustness finding. Fixed by reconstructing the probe via TEXT-SPAN
replacement on the original source (using each `Name` node's `lineno`/`col_offset`/`end_lineno`/
`end_col_offset`), the same approach already used for the tree-sitter languages, which preserves
every other character of the original source exactly -- `ast.unparse()` is no longer used anywhere
in this module.
"""
import ast
import textwrap
from dataclasses import dataclass
from typing import Optional

import tree_sitter_java as _tsjava
import tree_sitter_javascript as _tsjs
import tree_sitter_typescript as _tsts
from tree_sitter import Language, Parser

SUPPORTED_LANGUAGES = {"python", "java", "javascript", "typescript"}

_JAVA_LANGUAGE = Language(_tsjava.language())
_JS_LANGUAGE = Language(_tsjs.language())
_TS_LANGUAGE = Language(_tsts.language_typescript())

# Reflection-equivalent APIs that make a function's identifiers reachable by their literal NAME
# rather than only by lexical reference -- renaming is unsafe if any of these are present, per the
# design's reflection-eligibility filter. See _ts_has_reflection() below for the actual (parsed-
# tree-based, not substring-based) check and its own correction history.


@dataclass
class ProbeResult:
    case_id: str
    language: str
    old_name: str
    new_name: str
    vulnerable_probe: str
    patched_probe: str
    patched_probe_renamed: bool  # False if patched_function didn't parse or didn't contain old_name


@dataclass
class ProbeIneligible:
    case_id: str
    language: str
    reason: str


# --------------------------------------------------------------------------------------------
# Python (stdlib ast -- real scope information)
# --------------------------------------------------------------------------------------------

_PY_REFLECTION_NAMES = {"locals", "globals", "getattr", "setattr", "vars", "eval", "exec"}


def _py_dedent(src: str) -> str:
    """vulnerable_function/patched_function are often extracted still carrying their original
    class-body indentation, which ast.parse() cannot handle at module level."""
    return textwrap.dedent(src).strip()


def _py_parse(src: str):
    """Returns (tree, dedented_text) -- callers that go on to rename need the exact dedented text
    the positions in `tree` are relative to, for text-span replacement (see _py_rename_text)."""
    dedented = _py_dedent(src)
    return ast.parse(dedented), dedented


def _py_find_function(tree: ast.Module):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    return None


def _py_has_reflection(func) -> bool:
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
            if name in _PY_REFLECTION_NAMES:
                return True
    return False


def _py_param_names(func) -> set:
    names = set()
    a = func.args
    for group in (a.posonlyargs, a.args, a.kwonlyargs):
        names.update(x.arg for x in group)
    if a.vararg:
        names.add(a.vararg.arg)
    if a.kwarg:
        names.add(a.kwarg.arg)
    return names


def _py_names_touched_in_nested_scopes(func) -> set:
    """CORRECTED 2026-10-13 after an independent review reproduced a real bug: the prior version
    of this function (`_py_nested_param_names`) only excluded names that collide with a NESTED
    function/lambda's PARAMETERS -- it missed a nested scope's own LOCAL ASSIGNMENTS and, more
    fundamentally, never accounted for genuine closures (a nested function reading or writing the
    OUTER function's binding as a free variable). Reproduced directly: `def f(): def g(): token=1;
    return token\\n    return token+g()` -- `token` is local to `g`, unrelated to any binding of
    `f`, but the old renamer walked f's ENTIRE subtree (including g's body) and renamed every
    `Name` node textually matching the candidate, renaming g's own distinct local too and breaking
    it; `f()`'s own direct reference to a DIFFERENT (module-level global) `token` got renamed as
    well, corrupting that too -- `Store`/`Load` context alone, with no real symbol-table
    resolution, cannot distinguish these cases.

    This module does not implement free-variable/closure resolution (that's real scope-resolution
    work, not safe to approximate). Instead: any name that is referenced, assigned, or used as a
    parameter ANYWHERE inside any nested function/lambda/class definition inside `func` is excluded
    from candidacy entirely -- the same "when in doubt, don't use this candidate" response already
    used for reflection/string-literal/shorthand-property risk. This means a genuinely safe rename
    of an outer-scope variable that some nested closure legitimately reads is also excluded, which
    is strictly over-cautious, not unsafe -- the alternative (attempting it without real scope
    resolution) is exactly what produced the reproduced bug.

    FURTHER CORRECTED 2026-10-13 (follow-up review): comprehensions (`ListComp`/`SetComp`/
    `DictComp`/`GeneratorExp`) also introduce their own scope in Python 3 -- a comprehension's
    `for` target is NOT a binding of the enclosing function, even though the previous version of
    `_py_candidate_locals` treated it as one. Reproduced directly: `def f(): [token for token in
    (1,2)]; return token` with a module global `token=10` -- the comprehension's own `token` got
    treated as `f`'s candidate, and the unrelated `return token` (reading the global) was renamed
    too, raising `NameError`. Comprehension nodes are now treated as scope boundaries exactly like
    nested function defs: any name touched anywhere inside one is excluded entirely.

    FURTHER CORRECTED 2026-10-13 (bounded binding-form audit): a nested `def NAME(): ...`/
    `class NAME: ...` STATEMENT is itself a binding of `NAME` in whatever scope CONTAINS it (just
    like `NAME = ...` would be) -- but the declaration site is the `FunctionDef`/`ClassDef` node's
    own `.name` string attribute, NOT a child `ast.Name` node, so it is invisible to text-span
    replacement by construction (the same blind-spot class as `ExceptHandler.name`, fixed earlier
    as `_py_exception_bound_names`). Reproduced directly: `token = 1; def token(): return 2;
    return token()` -- the later reference to the REBOUND function got renamed
    (`return token_renamed()`), while the `def`'s own name stayed `token`, so the call tried to
    invoke the (renamed, still-holding-`1`) int instead, raising `TypeError: 'int' object is not
    callable`. The def/class statement's OWN name is now also added to this same exclusion set."""
    names = set()
    for node in ast.walk(func):
        if node is func:
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef,
                              ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            for n in ast.walk(node):
                if isinstance(n, ast.Name):
                    names.add(n.id)
                elif isinstance(n, ast.arg):
                    names.add(n.arg)
    return names


def _py_names_in_signature(func) -> set:
    """FOLLOW-UP FIX 2026-10-13: a function's parameter DEFAULT VALUES (and annotations) are
    evaluated at `def`-time in the ENCLOSING scope, not the function's own body scope -- reproduced
    directly: `def f(x=token): token=1; return x+token` with a module global `token=10`. The body's
    own local `token` assignment got selected as a candidate, and the textually-identical `token` in
    the default expression (a free reference to the OUTER/global `token`, unrelated to the body
    local) was renamed along with it, raising `NameError` while even just DEFINING the renamed
    function. Any name appearing in `func.args.defaults`/`kw_defaults`/any parameter or return
    annotation is excluded from candidacy entirely, matching the same conservative philosophy as
    nested-scope exclusion above.

    FURTHER CORRECTED 2026-10-13 (binding-form audit review): decorator expressions
    (`FunctionDef.decorator_list`) are evaluated at `def`-time in the ENCLOSING scope by the exact
    same mechanism as parameter defaults, but were not covered here at all -- a separate AST field,
    not `func.args` or `func.returns`. Reproduced directly: `@decorate(token)\\ndef f(): token=1;
    return token` with a module global `token=10` and `decorate = lambda value: lambda fn: fn` --
    the body's own local `token` and the decorator expression's free reference to the OUTER/global
    `token` were renamed together, raising `NameError` at the `@decorate(token_renamed)` line
    itself (evaluated while DEFINING `f`, before the body ever runs). Any name appearing in a
    decorator expression is now excluded the same way."""
    names = set()
    a = func.args
    default_exprs = list(a.defaults) + [d for d in a.kw_defaults if d is not None]
    annotation_exprs = [x.annotation for x in (list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs))
                         if x.annotation is not None]
    if a.vararg is not None and a.vararg.annotation is not None:
        annotation_exprs.append(a.vararg.annotation)
    if a.kwarg is not None and a.kwarg.annotation is not None:
        annotation_exprs.append(a.kwarg.annotation)
    if func.returns is not None:
        annotation_exprs.append(func.returns)
    decorator_exprs = list(func.decorator_list)
    for expr in default_exprs + annotation_exprs + decorator_exprs:
        for n in ast.walk(expr):
            if isinstance(n, ast.Name):
                names.add(n.id)
    return names


def _py_global_nonlocal_names(func) -> set:
    names = set()
    for node in ast.walk(func):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            names.update(node.names)
    return names


def _py_exception_bound_names(func) -> set:
    """FOLLOW-UP FIX 2026-10-13 (third review): `except SomeError as token:` binds `token` as a
    real but NON-`ast.Name` binding site -- `ExceptHandler.name` is a plain string attribute, so
    text-span replacement (which only ever touches `ast.Name` node positions) never updates it.
    Reproduced directly: `token = 1; try: raise ValueError(7)\\nexcept ValueError as token: return
    token` -- the outer `token = 1` and the handler's OWN `return token` (which refers to the
    CAUGHT EXCEPTION, shadowing the outer `token` for the duration of the handler, and is
    implicitly deleted at the end of the handler per Python 3 semantics) got conflated: the
    outer assignment and the handler's `return` were both renamed as if they were the same
    binding, changing the original's `ValueError(7)` result into a plain integer `1`. Any name
    EVER used as an `except ... as <name>:` binding anywhere in `func` is excluded from candidacy
    entirely, matching the same conservative philosophy as nested-scope/comprehension exclusion."""
    names = set()
    for node in ast.walk(func):
        if isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
    return names


def _py_import_bound_names(func) -> set:
    """BOUNDED BINDING-FORM AUDIT 2026-10-13: `import os as token` / `from mod import x as token`
    bind `token` via `ast.alias.asname` (or, for a plain `import os.path` with no `as`, via
    `alias.name`'s first dotted component) -- a plain string attribute, not an `ast.Name` node,
    the same blind-spot class as `ExceptHandler.name`. Reproduced directly: `token = 1; import os
    as token; return token.getcwd()` -- the import statement's own alias stayed `token` while the
    later `return token.getcwd()` (actually referring to the `os` module via that alias) got
    renamed to `token_renamed.getcwd()`, raising `AttributeError` (the renamed int has no such
    method). Any name ever bound by an import alias anywhere in `func` is excluded entirely."""
    names = set()
    for node in ast.walk(func):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                names.add(alias.asname if alias.asname else alias.name.split(".")[0])
    return names


_PY_MATCH_PATTERN_TYPES = tuple(
    t for t in (getattr(ast, "MatchAs", None), getattr(ast, "MatchStar", None), getattr(ast, "MatchMapping", None))
    if t is not None
)


def _py_match_bound_names(func) -> set:
    """BOUNDED BINDING-FORM AUDIT 2026-10-13: a `match`/`case` capture pattern (`case int() as
    token:`, `case [*token]:`, `case {**token}:`) binds `token` via a plain string attribute
    (`MatchAs.name` / `MatchStar.name` / `MatchMapping.rest`), not an `ast.Name` node -- the same
    blind-spot class as `ExceptHandler.name` and import aliases. Reproduced directly: `token = 1;
    match obj:\\n    case int() as token: return token\\n return token` -- the `case` body's
    `return token` (referring to the MATCHED value via the capture pattern) got renamed to
    `return token_renamed` (referring to the unrelated outer `1`), changing the result from the
    matched value to `1`. Guarded with `getattr` since `match` syntax is Python 3.10+; on an older
    interpreter these `ast` attributes don't exist and no such node can appear in a parsed tree
    anyway. Any name ever bound by a match capture pattern anywhere in `func` is excluded."""
    names = set()
    if not _PY_MATCH_PATTERN_TYPES:
        return names
    for node in ast.walk(func):
        if isinstance(node, _PY_MATCH_PATTERN_TYPES):
            name = getattr(node, "name", None) or getattr(node, "rest", None)
            if name:
                names.add(name)
    return names


def _py_string_literal_contains(func, name: str) -> bool:
    for node in ast.walk(func):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and name in node.value:
            return True
        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str) and name in v.value:
                    return True
    return False


def _py_candidate_locals(func) -> list:
    """Local, non-parameter, non-global/nonlocal, non-nested-touched simple-Name assignment
    targets, in first-seen source order. Only plain Name targets (never attribute/subscript
    targets) -- we only ever rename a simple local binding, never an attribute or item.

    CORRECTED 2026-10-13: candidate collection now walks `func`'s OWN body only -- it no longer
    descends into nested function/lambda/class definitions at all (a nested scope's own local
    assignment, e.g. a different function's unrelated same-named variable, was previously
    collected as if it were usable for the OUTER function; see
    `_py_names_touched_in_nested_scopes`'s docstring for the exact reproduced bug this caused).
    The exclusion set below additionally removes any name touched anywhere in a nested scope, as a
    second, independent safety net. FURTHER CORRECTED 2026-10-13 (follow-up review): comprehensions
    are also scope boundaries (see `_py_names_touched_in_nested_scopes`'s docstring) and are no
    longer walked for candidates -- a comprehension's own `for` target was previously collected
    here as if it belonged to the enclosing function, which it does not in Python 3. Parameter
    default/annotation expressions are excluded via `_py_names_in_signature` for the same reason:
    they execute in the enclosing scope, not the function body. FURTHER CORRECTED 2026-10-13
    (third review): `except ... as <name>:` bindings are excluded via `_py_exception_bound_names`
    -- that binding is not an `ast.Name` node, so it is invisible to text-span replacement and
    would otherwise be silently left stale while a same-spelled outer binding got renamed.
    FURTHER CORRECTED 2026-10-13 (bounded binding-form audit): import aliases
    (`_py_import_bound_names`) and `match`/`case` capture patterns (`_py_match_bound_names`) are
    excluded for the identical reason -- both are non-`ast.Name` binding sites. A nested def/class
    statement's own name is excluded via `_py_names_touched_in_nested_scopes` itself (see its
    docstring) rather than a separate function here."""
    excluded = (_py_param_names(func) | _py_names_touched_in_nested_scopes(func)
                | _py_global_nonlocal_names(func) | _py_names_in_signature(func)
                | _py_exception_bound_names(func) | _py_import_bound_names(func)
                | _py_match_bound_names(func))
    seen = []

    def add(name):
        if name not in excluded and name not in seen:
            seen.append(name)

    def walk_own_scope(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef,
                                   ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                continue  # never collect candidates from inside a nested scope
            if isinstance(child, ast.Assign):
                for t in child.targets:
                    if isinstance(t, ast.Name):
                        add(t.id)
            elif isinstance(child, (ast.AugAssign, ast.AnnAssign)):
                if isinstance(child.target, ast.Name):
                    add(child.target.id)
            elif isinstance(child, ast.For):
                if isinstance(child.target, ast.Name):
                    add(child.target.id)
            elif isinstance(child, ast.withitem):
                if isinstance(child.optional_vars, ast.Name):
                    add(child.optional_vars.id)
            # NOTE: comprehension `for` targets are intentionally never collected here -- they
            # belong to the comprehension's own scope, not this function's (see above); the
            # `continue` for ListComp/SetComp/DictComp/GeneratorExp above means this walk never
            # even reaches an `ast.comprehension` node directly.
            walk_own_scope(child)

    walk_own_scope(func)
    return seen


def _py_rename_text(dedented_src: str, func, old: str, new: str) -> str:
    """Text-span replacement, not ast.unparse() -- see the module docstring's third finding for
    why: unparse() is not formatting-preserving for Python's implicit adjacent string-literal
    concatenation, which broke a real rule's match in exactly this way. Spans come from each
    matching Name node's own lineno/col_offset/end_lineno/end_col_offset (reliable since Python
    3.8), applied back-to-front so earlier replacements never shift the offsets of ones still to
    come -- the same pattern already used for the tree-sitter languages below. Walking the whole
    `func` subtree (including nested scopes) for matching Name nodes is safe ONLY because
    `_py_candidate_locals`'s exclusion set already guarantees `old` cannot appear inside any
    nested function/lambda/class def at all -- if that invariant is ever weakened, this function
    must be revisited too."""
    line_starts = [0]
    for line in dedented_src.splitlines(keepends=True):
        line_starts.append(line_starts[-1] + len(line))

    def offset(lineno, col):
        return line_starts[lineno - 1] + col

    spans = [(offset(n.lineno, n.col_offset), offset(n.end_lineno, n.end_col_offset))
             for n in ast.walk(func) if isinstance(n, ast.Name) and n.id == old]
    spans.sort(reverse=True)
    text = dedented_src
    for start, end in spans:
        text = text[:start] + new + text[end:]
    return text


def _py_ast_isomorphic(a, b, old, new) -> bool:
    """Walk two ASTs in lockstep. Every field must match exactly except a Name node's `id`, which
    may differ ONLY as the (old, new) pair, consistently."""
    if type(a) is not type(b):
        return False
    if not isinstance(a, ast.AST):
        return a == b
    fields_b = dict(ast.iter_fields(b))
    for fname, fval in ast.iter_fields(a):
        bval = fields_b.get(fname)
        if fname == "id" and isinstance(a, ast.Name):
            if fval == bval or (fval == old and bval == new):
                continue
            return False
        if isinstance(fval, list):
            if not isinstance(bval, list) or len(fval) != len(bval):
                return False
            if not all(_py_ast_isomorphic(x, y, old, new) for x, y in zip(fval, bval)):
                return False
        elif isinstance(fval, ast.AST):
            if not _py_ast_isomorphic(fval, bval, old, new):
                return False
        else:
            if fval != bval:
                return False
    return True


def _py_parses_to_function(src: str) -> bool:
    """FOLLOW-UP FIX 2026-10-13: an unparseable `patched_function` previously fell through
    `_rename_patched_python`'s generic `except SyntaxError: return patched_function, False`, which
    is indistinguishable from the legitimate "patched source is fine, just doesn't need renaming"
    case -- the overall pair was still returned as an eligible `ProbeResult` with the ORIGINAL,
    unparseable patched text silently substituted in as the "probe". Checked once, up front, so a
    genuine parse/validation failure makes the whole case ineligible instead."""
    try:
        tree, _ = _py_parse(src)
    except SyntaxError:
        return False
    return _py_find_function(tree) is not None


def _build_probe_python(case_id: str, vulnerable_function: str, patched_function: str):
    try:
        tree, dedented = _py_parse(vulnerable_function)
    except SyntaxError as e:
        return ProbeIneligible(case_id, "python", f"vulnerable_function does not parse: {e}")
    func = _py_find_function(tree)
    if func is None:
        return ProbeIneligible(case_id, "python", "no function definition found in vulnerable_function")
    if _py_has_reflection(func):
        return ProbeIneligible(case_id, "python", "function uses locals/globals/getattr/setattr/vars/eval/exec")
    if not _py_parses_to_function(patched_function):
        return ProbeIneligible(case_id, "python", "patched_function does not parse")

    candidates = _py_candidate_locals(func)
    for old_name in candidates:
        if _py_string_literal_contains(func, old_name):
            continue  # name is reflection-reachable via a string literal; try the next candidate
        all_names = {n.id for n in ast.walk(func) if isinstance(n, ast.Name)}
        new_name = _pick_new_name(old_name, all_names)

        new_vulnerable_src = _py_rename_text(dedented, func, old_name, new_name)
        try:
            reparsed, _ = _py_parse(new_vulnerable_src)
        except SyntaxError:
            continue
        reparsed_func = _py_find_function(reparsed)
        if reparsed_func is None or not _py_ast_isomorphic(func, reparsed_func, old_name, new_name):
            continue  # isomorphism check failed -- never serve this candidate, try the next one

        patched_src, patched_renamed = _rename_patched_python(patched_function, old_name, new_name)
        return ProbeResult(case_id, "python", old_name, new_name, new_vulnerable_src, patched_src, patched_renamed)

    return ProbeIneligible(case_id, "python", "no eligible local binding found (all candidates excluded or exhausted)")


def _rename_patched_python(patched_function: str, old_name: str, new_name: str):
    """CORRECTED 2026-10-13: an independent review reproduced that this previously reused the
    vulnerable side's old/new names on the patched source with no independent eligibility check
    at all -- confirmed directly: a patched `def f(token): return token` (token now a PARAMETER,
    a different role than in the vulnerable side) became `def f(token): return token_renamed`,
    a declaration/reference mismatch raising NameError, while still reporting
    `patched_probe_renamed=True`.

    FURTHER CORRECTED 2026-10-13 (follow-up review): the first fix's own "is `old_name` present in
    the patched function at all" check (`old_name in names_in_patched`, built from EVERY `Name`
    node regardless of Store/Load context) was still not strict enough -- it accepted a patched
    `def f(): return token` reading a module-level global `token=7` as if `token` were a genuine
    local of the patched function, and renamed that free/global reference, raising `NameError`.
    `old_name` must now be one of the patched function's OWN eligible local candidates --
    `_py_candidate_locals(func)` (the exact same function the vulnerable side uses, which already
    excludes parameters, nested-scope-touched names, global/nonlocal names, and signature-default/
    annotation names) -- not merely present as *some* `Name` node anywhere in the function. Any
    failure here (including an unparseable patched function, defensively, though `build_probe` now
    checks that up front and makes the whole case ineligible instead) leaves the patched side
    unchanged (`patched_renamed=False`) rather than attempting a renamed result that cannot be
    validated as safe."""
    try:
        tree, dedented = _py_parse(patched_function)
    except SyntaxError:
        return patched_function, False
    func = _py_find_function(tree)
    if func is None:
        return patched_function, False
    if _py_has_reflection(func):
        return patched_function, False
    if old_name not in _py_candidate_locals(func):
        return patched_function, False  # not a genuine, independently-eligible local of the patched function
    all_names = {n.id for n in ast.walk(func) if isinstance(n, ast.Name)}
    if new_name in all_names:
        return patched_function, False  # new_name would collide with something already in patched
    if _py_string_literal_contains(func, old_name):
        return patched_function, False
    new_src = _py_rename_text(dedented, func, old_name, new_name)
    try:
        reparsed, _ = _py_parse(new_src)
    except SyntaxError:
        return patched_function, False
    reparsed_func = _py_find_function(reparsed)
    if reparsed_func is None or not _py_ast_isomorphic(func, reparsed_func, old_name, new_name):
        return patched_function, False
    return new_src, True


def _pick_new_name(old_name: str, taken: set) -> str:
    for suffix in ("_renamed", "_probe", "_v2", "_alt", "_x"):
        candidate = old_name + suffix
        if candidate not in taken:
            return candidate
    i = 0
    while f"{old_name}_{i}" in taken:
        i += 1
    return f"{old_name}_{i}"


# --------------------------------------------------------------------------------------------
# Java / JavaScript / TypeScript (tree_sitter -- no real scope resolution; conservative heuristic)
# --------------------------------------------------------------------------------------------

def _ts_parser(language: str) -> Parser:
    if language == "java":
        return Parser(_JAVA_LANGUAGE)
    if language == "javascript":
        return Parser(_JS_LANGUAGE)
    if language == "typescript":
        return Parser(_TS_LANGUAGE)
    raise ValueError(language)


def _ts_walk(node):
    yield node
    for c in node.children:
        yield from _ts_walk(c)


_JAVA_REFLECTION_CALL_NAMES = {"getDeclaredField", "getField", "getDeclaredMethod", "getMethod", "forName", "invoke"}
_JS_REFLECTION_CALL_NAMES = {"eval"}
_JS_DYNAMIC_GLOBAL_OBJECTS = {"window", "globalThis", "self"}


def _ts_has_reflection(root_node, language: str) -> bool:
    """CORRECTED 2026-10-13: the original version did a raw substring match on the UNPARSED
    source text (e.g. `"eval(" in src_text`), which an independent review broke with a single
    space (`eval (text)` passes the old filter, `eval(text)` doesn't -- the same call, cosmetically
    different). Rewritten to walk the PARSED tree and check actual call-expression/method-
    invocation structure, matching the robustness the Python filter already had (an AST `Call`
    check, never a text search) -- whitespace, comments and formatting cannot evade a structural
    check the way they can a substring one.

    Also newly added, for the SAME review's `String.fromCharCode`-constructed-name reproduction:
    JS/TS dynamic global-object bracket access (`window[...]`, `globalThis[...]`, `self[...]`) is
    flagged regardless of what constructs the computed key -- this is the actual reflection vector
    that example used (a programmatically-built property name read off the global object), not
    `eval` itself. This remains a documented heuristic, not exhaustive semantic detection, exactly
    like the Python filter's fixed name list -- an attacker-grade obfuscation search is out of
    scope for a development-time probe-eligibility filter."""
    for n in _ts_walk(root_node):
        if language == "java":
            name_node = None
            if n.type == "method_invocation":
                name_node = n.child_by_field_name("name")
            if name_node is not None and name_node.text.decode() in _JAVA_REFLECTION_CALL_NAMES:
                return True
        else:
            if n.type == "call_expression":
                callee = n.child_by_field_name("function")
                if callee is not None and callee.type == "identifier" and callee.text.decode() in _JS_REFLECTION_CALL_NAMES:
                    return True
            if n.type == "subscript_expression":  # bracket notation ONLY -- window.X (dot
                # notation / member_expression) is an ordinary, extremely common global-API check
                # (confirmed directly: CASE-0220's real `window.XMLHttpRequest` is exactly this and
                # is not reflection-risk at all).
                obj = n.child_by_field_name("object")
                idx = n.child_by_field_name("index")
                if (obj is not None and obj.type == "identifier" and obj.text.decode() in _JS_DYNAMIC_GLOBAL_OBJECTS
                        and idx is not None and idx.type not in ("string", "number", "template_string")):
                    # a LITERAL key (confirmed directly: CASE-0220's real `window['alertHttpRequest']`
                    # is exactly this) is semantically identical to dot notation -- no additional
                    # reflection risk. Only a genuinely COMPUTED key (not a literal) is the actual
                    # dynamic-access vector the review's String.fromCharCode reproduction
                    # demonstrated.
                    return True
    return False


def _ts_parse_function_src(src: str, language: str):
    """Returns (tree, function_node, wrapped_prefix_len) -- Java constructors/methods need a class
    wrapper to parse correctly (confirmed directly: tree_sitter_java mis-parses a bare constructor
    as a malformed method_declaration with no return type; wrapping in `class Dummy { ... }` fixes
    it). JS/TS function declarations parse fine unwrapped."""
    parser = _ts_parser(language)
    if language == "java":
        wrapped = "class Dummy {\n" + src + "\n}\n"
        tree = parser.parse(wrapped.encode())
        func = None
        for n in _ts_walk(tree.root_node):
            if n.type in ("method_declaration", "constructor_declaration"):
                func = n
                break
        return tree, func, wrapped
    tree = parser.parse(src.encode())
    func = None
    for n in _ts_walk(tree.root_node):
        if n.type in ("function_declaration", "function", "method_definition", "arrow_function"):
            func = n
            break
    if func is None:
        func = tree.root_node
    return tree, func, src


def _ts_param_names(func_node, language: str) -> set:
    names = set()
    params_type = {"java": "formal_parameters", "javascript": "formal_parameters", "typescript": "formal_parameters"}[language]
    for n in _ts_walk(func_node):
        if n.type == params_type:
            for c in _ts_walk(n):
                if c.type == "identifier":
                    parent = c.parent
                    # Only the parameter's own name identifier, not a type annotation's identifier.
                    if parent is not None and parent.type in ("formal_parameter", "required_parameter",
                                                                 "optional_parameter", "spread_parameter"):
                        names.add(c.text.decode())
                    elif parent is not None and parent.type == params_type:
                        names.add(c.text.decode())
    return names


_TS_DEFAULT_VALUE_FIELD = {"assignment_pattern": "right", "required_parameter": "value", "optional_parameter": "value"}


def _ts_names_in_signature_defaults(func_node, language: str) -> set:
    """FOLLOW-UP FIX 2026-10-13 (third review): a JS/TS parameter default value expression
    (`function f(x=token) {...}`) is evaluated in a scope that sees the ENCLOSING scope, not the
    function body's own `let`/`const`/`var` declarations -- the same free-reference risk already
    fixed for Python's `_py_names_in_signature`, but the tree-sitter path had no equivalent at all.
    Reproduced directly with a global `token=10`: `function f(x=token) { let token=1; return
    x+token; }` -- the default's free reference to the OUTER `token` and the body's own distinct
    `let token` got renamed together (`function f(x=token_renamed) { let token_renamed=1; return
    x+token_renamed; }`), and the renamed probe throws `ReferenceError` (the default still only
    sees the ORIGINAL global `token`, which is unrenamed, so `token_renamed` is undefined there).
    Java has no default parameter values, so this is a no-op for that language (none of the
    `assignment_pattern`/`required_parameter`/`optional_parameter` node types exist in its
    grammar)."""
    names = set()
    if language == "java":
        return names
    params_type = "formal_parameters"
    for n in _ts_walk(func_node):
        if n.type == params_type:
            for c in _ts_walk(n):
                field_name = _TS_DEFAULT_VALUE_FIELD.get(c.type)
                if field_name is None:
                    continue
                value_node = c.child_by_field_name(field_name)
                if value_node is None:
                    continue
                for leaf in _ts_walk(value_node):
                    if leaf.type == "identifier":
                        names.add(leaf.text.decode())
    return names


_DECLARATION_NAME_PARENT_TYPES = {
    "method_declaration", "constructor_declaration", "class_declaration", "interface_declaration",
    "function_declaration", "method_definition", "class", "generator_function_declaration",
}


def _ts_is_excluded_position(node) -> bool:
    """True if this `identifier` leaf is NOT a genuine LOCAL-VARIABLE reference -- a field_access's
    `field` child, a method_invocation/call's `name`/method-name child, or (CORRECTED 2026-10-13,
    an independent review reproduced this exact bug directly: `int token() { int token = 1; return
    token; }` had its METHOD's own declaration name renamed to `token_renamed` too, violating the
    "local only, never anything externally visible" contract) a method/function/class/constructor
    DECLARATION's own `name` field -- confirmed via each grammar's own named fields."""
    parent = node.parent
    if parent is None:
        return False
    fname = parent.field_name_for_child(list(parent.children).index(node)) if node in parent.children else None
    if parent.type in _DECLARATION_NAME_PARENT_TYPES and fname == "name":
        return True
    if parent.type == "field_access" and fname == "field":
        return True
    if parent.type == "method_invocation" and fname == "name":
        return True
    if parent.type in ("member_expression",) and fname == "property":
        return True
    if parent.type in ("call_expression",) and fname == "function" and parent.children and parent.children[0] is not node:
        # a function-call CALLEE identifier that is itself a plain name (not a member expression)
        # is ambiguous between "calling a local variable holding a function" and "calling a
        # same-named global function" -- excluded conservatively rather than guessed at.
        return True
    return False


def _ts_is_called_as_bare_function(func_node, name: str) -> bool:
    """CORRECTED 2026-10-13: a follow-up to the exclusion above. Silently skipping a callee
    identifier from renaming (above) while renaming its DECLARATION elsewhere is itself unsafe --
    reproduced directly: `function f() { const cb = () => 7; return cb(); }` -> the declaration
    `cb` was renamed to `cb_renamed` but the call site `cb()` was left untouched (excluded by the
    check above), leaving a declaration/reference mismatch that raises ReferenceError. Rather than
    try to resolve whether a given callee identifier really is the same binding (tree-sitter gives
    no real scope information to decide this), the whole CANDIDATE is now rejected outright if its
    name is ever used as a bare-identifier call callee anywhere in the function -- the same
    "exclude the candidate, don't guess" response used for shorthand properties and reflection."""
    for n in _ts_walk(func_node):
        if n.type == "call_expression":  # JS/TS only -- Java has no bare-identifier-callee syntax
            callee = n.child_by_field_name("function")
            if callee is not None and callee.type == "identifier" and callee.text.decode() == name:
                return True
    return False


def _ts_collect_declared_locals(func_node, language: str) -> list:
    seen = []
    for n in _ts_walk(func_node):
        if n.type == "local_variable_declaration" and language == "java":
            for c in _ts_walk(n):
                if c.type == "variable_declarator":
                    name_node = c.child_by_field_name("name")
                    if name_node is not None and name_node.type == "identifier":
                        nm = name_node.text.decode()
                        if nm not in seen:
                            seen.append(nm)
        elif n.type == "variable_declarator" and language in ("javascript", "typescript"):
            name_node = n.child_by_field_name("name")
            if name_node is not None and name_node.type == "identifier":
                nm = name_node.text.decode()
                if nm not in seen:
                    seen.append(nm)
    return seen


_TS_BLOCK_SCOPED_DECL_TYPES = {"java": ("local_variable_declaration",),
                                "javascript": ("lexical_declaration",),
                                "typescript": ("lexical_declaration",)}


def _ts_block_scoped_outside_function_body(func_node, name: str, language: str) -> bool:
    """CORRECTED 2026-10-13: JS/TS `let`/`const` create BLOCK scope, not function scope -- an
    independent review reproduced directly that this module didn't account for that: `function f()
    { { let token = 1; } return token; }` -- `token` inside the nested `{}` is a DIFFERENT binding
    from any `token` visible at function scope outside that block, but the old renamer (which only
    checked for nested FUNCTION scopes, not nested BLOCKS) renamed both occurrences as if they were
    the same name, breaking the function. Conservatively excludes any `let`/`const` candidate whose
    declaration is not a DIRECT CHILD of the function's own top-level body block -- `var` is
    unaffected (function-scoped regardless of block nesting, already correctly handled).

    FURTHER CORRECTED 2026-10-13 (follow-up review): this previously returned `False` unconditionally
    for Java, on the mistaken assumption Java has no block-scope-only declarations analogous to
    `let`/`const`. That is wrong -- EVERY Java local variable declaration is block-scoped (Java has
    no function-scoped-regardless-of-block-nesting equivalent of JS `var` at all). Reproduced
    directly: `int f() { { int token=1; } return token; }` with an enclosing field `int token=10` --
    the inner block-local `token` and the OUTER `return token` (which actually reads the class field,
    since no method-scope local is visible there) got renamed as if the same binding, and the
    renamed probe failed to compile (`cannot find symbol`). Generalized to check `local_variable_
    declaration` for Java using the identical direct-child-of-body structural test already used for
    `lexical_declaration` in JS/TS."""
    body = func_node.child_by_field_name("body")
    if body is None:
        return False
    decl_types = _TS_BLOCK_SCOPED_DECL_TYPES[language]
    for n in _ts_walk(func_node):
        if n.type == "variable_declarator":
            name_node = n.child_by_field_name("name")
            if name_node is not None and name_node.type == "identifier" and name_node.text.decode() == name:
                decl = n.parent  # variable_declaration (var) / lexical_declaration (let/const) / local_variable_declaration (Java)
                # .id, never `is` -- tree_sitter returns a fresh Python wrapper object on every
                # attribute access, so two references to the SAME underlying node fail an `is`
                # check even though they're structurally identical (confirmed directly: a
                # genuinely-top-level `let` inside the function's own body failed `decl.parent is
                # body` while `decl.parent.id == body.id` correctly matched).
                if decl is not None and decl.type in decl_types and decl.parent.id != body.id:
                    return True
    return False


def _ts_shadowed_in_nested_function(func_node, name: str, language: str) -> bool:
    nested_types = {"java": ("lambda_expression",),
                     "javascript": ("function", "function_declaration", "arrow_function", "method_definition"),
                     "typescript": ("function", "function_declaration", "arrow_function", "method_definition")}[language]
    for n in _ts_walk(func_node):
        if n is func_node:
            continue
        if n.type in nested_types:
            if name in _ts_param_names(n, language):
                return True
            if name in _ts_collect_declared_locals(n, language):
                return True
    return False


def _ts_string_literal_contains(func_node, name: str) -> bool:
    string_types = {"string", "template_string", "character_literal", "string_literal"}
    for n in _ts_walk(func_node):
        if n.type in string_types and name in n.text.decode(errors="replace"):
            return True
    return False


_TS_SHORTHAND_PROPERTY_TYPES = {"shorthand_property_identifier", "shorthand_property_identifier_pattern"}


def _ts_has_shorthand_property(func_node, name: str) -> bool:
    """CORRECTED 2026-10-13 (binding-form audit review): previously only checked
    `shorthand_property_identifier` (object-LITERAL-construction shorthand, `{token}` when
    BUILDING an object). `shorthand_property_identifier_pattern` -- the DESTRUCTURING shorthand,
    `var {token} = obj`, a DIFFERENT node type -- was missed entirely. That single node
    simultaneously represents the destructured property's key AND the bound local variable, but
    is invisible to `_ts_rename_all`'s `n.type == "identifier"` matching (a different type), so
    when a same-named candidate was chosen elsewhere, the destructuring binding was left stale
    while the chosen candidate's OTHER occurrences were renamed. Reproduced directly: `var
    token=1; var {token}=obj; return token;` -- `f({token:99})` originally returns `99`; the
    pre-fix probe returned `1` (the renamed declaration's stale initial value, since the
    destructuring reassignment silently stopped applying to the renamed variable). Array
    destructuring (`var [token]=obj`) and renamed-key object destructuring (`var {other:
    token}=obj`) were checked and confirmed SAFE -- both bind via a plain `identifier` node,
    the same type as an ordinary reference, so they are already renamed consistently; only the
    shorthand form uses this special, differently-typed node."""
    for n in _ts_walk(func_node):
        if n.type in _TS_SHORTHAND_PROPERTY_TYPES and n.text.decode() == name:
            return True
    return False


def _ts_rename_all(src: str, func_node, old_name: str, new_name: str, language: str) -> Optional[str]:
    """Text-level rename of every `identifier` leaf matching old_name, EXCLUDING field/method-name
    positions (see _ts_is_excluded_position), applied back-to-front by byte offset so earlier
    replacements never shift the byte positions of ones still to come. Returns None if the
    candidate also appears as a shorthand property (unsafe -- renaming would change an object's key)."""
    if _ts_has_shorthand_property(func_node, old_name):
        return None
    src_bytes = src.encode()
    spans = []
    for n in _ts_walk(func_node):
        if n.type == "identifier" and n.text.decode() == old_name and not _ts_is_excluded_position(n):
            spans.append((n.start_byte, n.end_byte))
    spans.sort(reverse=True)
    new_bytes = bytearray(src_bytes)
    new_name_bytes = new_name.encode()
    for start, end in spans:
        new_bytes[start:end] = new_name_bytes
    return bytes(new_bytes).decode()


def _ts_ast_isomorphic(a, b, old_name: str, new_name: str) -> bool:
    if a.type != b.type or a.child_count != b.child_count:
        return False
    if a.child_count == 0:
        a_text, b_text = a.text.decode(errors="replace"), b.text.decode(errors="replace")
        if a_text == b_text:
            return True
        if a.type == "identifier" and a_text == old_name and b_text == new_name:
            return True
        return False
    return all(_ts_ast_isomorphic(x, y, old_name, new_name) for x, y in zip(a.children, b.children))


_TS_NAMED_DECLARATION_TYPES = {"function_declaration", "generator_function_declaration", "class_declaration"}


def _ts_has_same_named_declaration(func_node, name: str) -> bool:
    """BOUNDED BINDING-FORM AUDIT 2026-10-13: a nested `function NAME() {...}` / `class NAME
    {...}` STATEMENT is itself a binding of `NAME` in whatever scope contains it (the JS/TS
    equivalent of Python's nested-def/class-name blind spot -- see
    `_py_names_touched_in_nested_scopes`'s docstring). `_DECLARATION_NAME_PARENT_TYPES` already
    stops the declaration's OWN name from being renamed, but that alone is not enough: any OTHER
    reference elsewhere in `func` that shares the candidate's spelling would still get renamed,
    going stale relative to the untouched declaration. Reproduced directly in JS (construction
    requires reading the name via hoisting before a same-named `var` assignment runs, to avoid the
    sequential-overwrite semantics that would otherwise mask the bug either way): `var fn = token;
    var token = 1; function token() { return 2; } return fn() + token;` -- original returns `3`
    (hoisting means `fn` captures the function); the probe renamed the LATER declaration/reads of
    the outer `token` but not the nested function's own name, leaving `fn` holding the unrenamed
    function while the call site (`fn()`) itself stayed correct, OTHER instances broke the
    correspondence and raised `TypeError: fn is not a function` in the actually-reproduced case.
    Confirmed structurally safe for Java specifically (local-class value-position references use a
    DIFFERENT node type, `type_identifier`, than the declaration's `identifier` name field; the one
    plausible same-node-type case, an unqualified static-method call shadowed by a same-named local
    variable, does not even compile) -- applied to all three languages anyway for simplicity and
    because the conservative direction is always safe, never a correctness risk."""
    for n in _ts_walk(func_node):
        if n is func_node:
            continue
        if n.type in _TS_NAMED_DECLARATION_TYPES:
            name_node = n.child_by_field_name("name")
            if name_node is not None and name_node.text.decode() == name:
                return True
    return False


def _ts_is_eligible_local(func, name: str, language: str) -> bool:
    """FOLLOW-UP FIX 2026-10-13: factored out of `_build_probe_tree_sitter`'s candidate loop so
    `_rename_patched_tree_sitter` can apply the EXACT SAME per-candidate risk checks to the patched
    side, instead of its own hand-duplicated copy (which had drifted and under-checked -- see that
    function's docstring)."""
    if _ts_string_literal_contains(func, name):
        return False
    if _ts_shadowed_in_nested_function(func, name, language):
        return False
    if _ts_block_scoped_outside_function_body(func, name, language):
        return False
    if language != "java" and _ts_is_called_as_bare_function(func, name):
        return False  # declaration/callee renaming mismatch risk -- see that function's docstring
    if _ts_has_same_named_declaration(func, name):
        return False
    return True


def _ts_parses_to_function(src: str, language: str) -> bool:
    """FOLLOW-UP FIX 2026-10-13, same reason as `_py_parses_to_function`: an unparseable
    `patched_function` previously fell through to `_rename_patched_tree_sitter`'s generic
    `return patched_function, False`, indistinguishable from a legitimate "doesn't need renaming"
    case -- the overall pair was still served as an eligible `ProbeResult` with the original,
    unparseable patched text substituted in as the "probe". Checked once, up front."""
    tree, func, _ = _ts_parse_function_src(src, language)
    return func is not None and not tree.root_node.has_error


def _build_probe_tree_sitter(case_id: str, language: str, vulnerable_function: str, patched_function: str):
    tree, func, wrapped_src = _ts_parse_function_src(vulnerable_function, language)
    if func is None or tree.root_node.has_error:
        return ProbeIneligible(case_id, language, "vulnerable_function does not parse cleanly")
    if _ts_has_reflection(tree.root_node, language):
        return ProbeIneligible(case_id, language, "function uses a reflection-equivalent API (see _ts_has_reflection)")
    if not _ts_parses_to_function(patched_function, language):
        return ProbeIneligible(case_id, language, "patched_function does not parse cleanly")

    params = _ts_param_names(func, language)
    sig_defaults = _ts_names_in_signature_defaults(func, language)
    candidates = [n for n in _ts_collect_declared_locals(func, language)
                  if n not in params and n not in sig_defaults]

    for old_name in candidates:
        if not _ts_is_eligible_local(func, old_name, language):
            continue
        all_identifier_text = {n.text.decode() for n in _ts_walk(tree.root_node) if n.type in ("identifier", "property_identifier", "type_identifier", "shorthand_property_identifier")}
        new_name = _pick_new_name(old_name, all_identifier_text)

        new_wrapped = _ts_rename_all(wrapped_src, func, old_name, new_name, language)
        if new_wrapped is None:
            continue  # shorthand-property risk

        new_tree = _ts_parser(language).parse(new_wrapped.encode())
        if new_tree.root_node.has_error:
            continue
        new_func = None
        for n in _ts_walk(new_tree.root_node):
            if n.type == func.type:
                new_func = n
                break
        if new_func is None or not _ts_ast_isomorphic(func, new_func, old_name, new_name):
            continue

        if language == "java":
            new_vulnerable_src = new_wrapped[len("class Dummy {\n"):-len("\n}\n")]
        else:
            new_vulnerable_src = new_wrapped

        patched_src, patched_renamed = _rename_patched_tree_sitter(patched_function, old_name, new_name, language)
        return ProbeResult(case_id, language, old_name, new_name, new_vulnerable_src, patched_src, patched_renamed)

    return ProbeIneligible(case_id, language, "no eligible local binding found (all candidates excluded or exhausted)")


def _rename_patched_tree_sitter(patched_function: str, old_name: str, new_name: str, language: str):
    """CORRECTED 2026-10-13, the same fix and reason as `_rename_patched_python` -- see its
    docstring. Independently checks parameter/reflection/shadowing/collision eligibility against
    the PATCHED source specifically, rather than reusing the vulnerable side's clearance.

    FURTHER CORRECTED 2026-10-13 (follow-up review): the "is `old_name` present in the patched
    function at all" check (`old_name in all_identifiers_in_patched`, built from EVERY `identifier`
    leaf regardless of whether it's a declaration or a free/global reference) was still not strict
    enough. `old_name` must now be one of the patched function's OWN declared locals
    (`_ts_collect_declared_locals`, minus parameters) AND pass the exact same per-candidate risk
    checks the vulnerable side uses (`_ts_is_eligible_local`), not merely appear as *some*
    identifier somewhere in the function."""
    tree, func, wrapped_src = _ts_parse_function_src(patched_function, language)
    if func is None or tree.root_node.has_error:
        return patched_function, False
    if _ts_has_reflection(tree.root_node, language):
        return patched_function, False
    declared_patched = [n for n in _ts_collect_declared_locals(func, language)
                         if n not in _ts_param_names(func, language)
                         and n not in _ts_names_in_signature_defaults(func, language)]
    if old_name not in declared_patched:
        return patched_function, False  # not a genuine, independently-eligible local declaration
    if not _ts_is_eligible_local(func, old_name, language):
        return patched_function, False
    all_identifiers_in_patched = {n.text.decode() for n in _ts_walk(func) if n.type == "identifier"}
    if new_name in all_identifiers_in_patched:
        return patched_function, False  # new_name would collide with something already in patched
    new_wrapped = _ts_rename_all(wrapped_src, func, old_name, new_name, language)
    if new_wrapped is None:
        return patched_function, False
    new_tree = _ts_parser(language).parse(new_wrapped.encode())
    if new_tree.root_node.has_error:
        return patched_function, False
    new_func = None
    for n in _ts_walk(new_tree.root_node):
        if n.type == func.type:
            new_func = n
            break
    if new_func is None or not _ts_ast_isomorphic(func, new_func, old_name, new_name):
        return patched_function, False
    if language == "java":
        return new_wrapped[len("class Dummy {\n"):-len("\n}\n")], True
    return new_wrapped, True


# --------------------------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------------------------

def build_probe(case_id: str, language: str, vulnerable_function: str, patched_function: str):
    """Returns a ProbeResult on success or ProbeIneligible with a stated reason -- never raises for
    an ordinary ineligibility outcome (unexpected exceptions still propagate, since those indicate a
    real bug in this module rather than an expected "this function can't be safely probed" case)."""
    if language not in SUPPORTED_LANGUAGES:
        return ProbeIneligible(case_id, language, f"unsupported language {language!r}")
    if language == "python":
        return _build_probe_python(case_id, vulnerable_function, patched_function)
    return _build_probe_tree_sitter(case_id, language, vulnerable_function, patched_function)
