"""
Offline tests for pipeline/dev_probe.py -- Research_Direction_20261011.md Item 5's development-probe
mechanism. Covers the specific risks found while building this module (reflection-equivalent calls,
a name reachable via a string literal, JS/TS shorthand object properties leaking the variable's name
into an object key, parameter/shadowing exclusion) plus a real end-to-end build against one
development case per language, each verified with the module's own AST-isomorphism check.

The behavioral section at the end (added 2026-10-13 in response to
Dev_Probe_Implementation_Review_20261013.md) goes further than isomorphism: it actually EXECUTES
the generated probes -- via exec() for Python, a `node` subprocess for JavaScript, and a
javac+java subprocess for Java -- and compares real return values/output before vs. after
renaming, since the review demonstrated isomorphism alone passes several behavior-changing bugs.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "pipeline"))
from dev_probe import build_probe, ProbeResult, ProbeIneligible

NODE = shutil.which("node") or "/usr/local/bin/node"
_JDK_BIN = "/Library/Java/JavaVirtualMachines/jdk-26.jdk/Contents/Home/bin"
JAVAC = shutil.which("javac") or f"{_JDK_BIN}/javac"
JAVA = shutil.which("java") or f"{_JDK_BIN}/java"
_HAVE_NODE = Path(NODE).exists()
_HAVE_JAVA = Path(JAVAC).exists() and Path(JAVA).exists()


def test_python_reflection_locals_makes_function_ineligible():
    src = "def f():\n    token = 1\n    return locals()['token']\n"
    r = build_probe("t", "python", src, src)
    assert isinstance(r, ProbeIneligible)
    assert "reflection" in r.reason or "locals" in r.reason


def test_python_reflection_getattr_makes_function_ineligible():
    src = "def f(obj):\n    token = 1\n    return getattr(obj, 'x')\n"
    r = build_probe("t", "python", src, src)
    assert isinstance(r, ProbeIneligible)


def test_python_name_only_reachable_via_string_literal_is_skipped():
    """A single-candidate function where that candidate's name also appears in a string literal
    must become ineligible (no OTHER candidate exists to fall back to) rather than renaming anyway."""
    src = 'def f():\n    token = 1\n    log("token value logged")\n    return token\n'
    r = build_probe("t", "python", src, src)
    assert isinstance(r, ProbeIneligible)


def test_python_parameter_never_renamed():
    src = "def f(token):\n    other = token + 1\n    return other\n"
    r = build_probe("t", "python", src, src)
    assert isinstance(r, ProbeResult)
    assert r.old_name != "token"  # the only non-parameter local is "other"
    assert r.old_name == "other"


def test_python_successful_rename_and_patched_side():
    vuln = "def f(x):\n    token = x\n    return token\n"
    patched = "def f(x):\n    token = sanitize(x)\n    return token\n"
    r = build_probe("t", "python", vuln, patched)
    assert isinstance(r, ProbeResult)
    assert r.old_name == "token"
    assert r.new_name in r.vulnerable_probe
    assert "token" not in r.vulnerable_probe.split("def f(x):")[1].replace(r.new_name, "")
    assert r.patched_probe_renamed is True
    assert r.new_name in r.patched_probe


def test_python_name_collision_avoided():
    src = "def f():\n    token = 1\n    token_renamed = 2\n    return token + token_renamed\n"
    r = build_probe("t", "python", src, src)
    assert isinstance(r, ProbeResult)
    assert r.new_name != "token_renamed"  # already taken -- must pick something else


def test_js_shorthand_property_candidate_is_skipped():
    """A candidate whose only use is inside an ES6 shorthand property ({token}) must not be
    renamed -- that would silently change the resulting object's key, not just the variable.
    With token as the ONLY local candidate, the whole function must become ineligible rather
    than renaming it anyway."""
    src = "function f(x) {\n  var token = x;\n  return {token};\n}\n"
    r = build_probe("t", "javascript", src, src)
    assert isinstance(r, ProbeIneligible)


def test_js_shorthand_property_risk_falls_through_to_another_candidate():
    """When a SECOND, safe candidate exists, the mechanism must fall through to it rather than
    giving up entirely just because the first candidate hit the shorthand-property risk."""
    src = "function f(x) {\n  var token = x;\n  var obj = {token};\n  return obj;\n}\n"
    r = build_probe("t", "javascript", src, src)
    assert isinstance(r, ProbeResult)
    assert r.old_name != "token"


def test_js_member_access_property_not_confused_with_variable():
    """obj.token's property name must never be renamed even though it shares text with the real
    local variable `token` being renamed elsewhere."""
    src = (
        "function f(x) {\n"
        "  var token = x;\n"
        "  var obj = {other: token};\n"
        "  return obj.token;\n"
        "}\n"
    )
    r = build_probe("t", "javascript", src, src)
    assert isinstance(r, ProbeResult)
    assert r.old_name == "token"
    assert "obj.token" in r.vulnerable_probe  # the property access itself must survive untouched


def test_js_eval_makes_function_ineligible():
    src = "function f(x) {\n  var token = x;\n  return eval(token);\n}\n"
    r = build_probe("t", "javascript", src, src)
    assert isinstance(r, ProbeIneligible)


def test_typescript_successful_rename():
    vuln = "function f(x: string): string {\n  let token: string = x;\n  return token;\n}\n"
    patched = "function f(x: string): string {\n  let token: string = sanitize(x);\n  return token;\n}\n"
    r = build_probe("t", "typescript", vuln, patched)
    assert isinstance(r, ProbeResult)
    assert r.old_name == "token"
    assert r.patched_probe_renamed is True


def test_java_field_access_property_not_confused_with_local_variable():
    """this.token's field name must never be renamed even though the method also has a local
    variable literally named `token`."""
    src = (
        "class Dummy {\n"
        "  String token;\n"
        "  void f() {\n"
        "    String token = this.token;\n"
        "    System.out.println(token);\n"
        "  }\n"
        "}\n"
    )
    # build_probe is given just the method body text, matching how vulnerable_function is
    # actually extracted (no enclosing class) -- the module wraps it in `class Dummy { ... }` itself.
    method_src = "  void f() {\n    String token = this.token;\n    System.out.println(token);\n  }\n"
    r = build_probe("t", "java", method_src, method_src)
    assert isinstance(r, ProbeResult)
    assert r.old_name == "token"
    assert "this.token" in r.vulnerable_probe  # the field access itself must survive untouched


def test_java_reflection_getDeclaredField_makes_method_ineligible():
    src = "void f() throws Exception {\n  String token = \"x\";\n  Object v = getClass().getDeclaredField(\"token\").get(this);\n}\n"
    r = build_probe("t", "java", src, src)
    assert isinstance(r, ProbeIneligible)


def test_java_constructor_parses_via_class_wrapper():
    """A bare constructor (no return type) mis-parses in tree-sitter-java without a class wrapper
    -- confirmed directly while building this module. build_probe must handle this correctly."""
    src = "public NettyHttpHeaders() {\n    String token = \"x\";\n    this.nettyHeaders = token;\n}\n"
    r = build_probe("t", "java", src, src)
    assert isinstance(r, ProbeResult)


@pytest.mark.parametrize("case_id,language", [
    ("CASE-0046", "python"),
    ("CASE-0184", "java"),
    ("CASE-0173", "typescript"),
])
def test_real_development_case_builds_a_valid_probe(case_id, language):
    """End-to-end check against one real development-set case per language that remains
    eligible after the 2026-10-13 scope-safety corrections (CASE-0081/CASE-0339, used here
    before those fixes, lost eligibility because their only candidates turned out to be
    block-scoped `let`/`const` declarations -- correctly excluded now, not a regression; CASE-0116,
    used here as the java slot before the follow-up block-scope generalization to Java, lost
    eligibility the same way -- see `test_real_java_case_now_ineligible_after_block_scope_fix`
    below). No real development-set JavaScript case remains eligible post-fix (see
    `test_real_js_case_now_ineligible_after_scope_fix` below for why); JS end-to-end coverage
    is carried by the synthetic tests elsewhere in this file instead."""
    import json
    ctx = json.loads((ROOT / f"benchmark/model_context/{case_id}.json").read_text())
    r = build_probe(case_id, language, ctx["vulnerable_function"], ctx["patched_function"])
    assert isinstance(r, ProbeResult), f"expected a successful probe for {case_id}, got {r}"
    assert r.new_name in r.vulnerable_probe
    assert r.old_name not in r.vulnerable_probe or r.old_name in r.new_name


def test_real_js_case_now_ineligible_after_scope_fix():
    """Documents, as a test rather than just a comment, why CASE-0339 (the real-case javascript
    slot before the 2026-10-13 fixes) is correctly ineligible now: its only candidate
    (`tokenRegex`) is declared with `const` inside a nested `for` loop, exactly the block-scope
    risk `_ts_block_scoped_outside_function_body` exists to catch."""
    import json
    ctx = json.loads((ROOT / "benchmark/model_context/CASE-0339.json").read_text())
    r = build_probe("CASE-0339", "javascript", ctx["vulnerable_function"], ctx["patched_function"])
    assert isinstance(r, ProbeIneligible)


def test_real_java_case_now_ineligible_after_block_scope_fix():
    """Documents why CASE-0116 (the real-case java slot before the follow-up review's block-scope
    generalization to Java) is correctly ineligible now: its only candidate (`socket`) is declared
    inside a `try { }` block, not the method's own top-level body -- exactly the Java block-scope
    risk the generalized `_ts_block_scoped_outside_function_body` now exists to catch (Java has no
    function-scoped-regardless-of-block-nesting local declaration at all, unlike JS `var`)."""
    import json
    ctx = json.loads((ROOT / "benchmark/model_context/CASE-0116.json").read_text())
    r = build_probe("CASE-0116", "java", ctx["vulnerable_function"], ctx["patched_function"])
    assert isinstance(r, ProbeIneligible)


# --------------------------------------------------------------------------------------------
# Behavioral regressions (2026-10-13) -- execute real code before/after renaming instead of
# only checking structural isomorphism. Each test below pairs with a specific reproduction in
# Dev_Probe_Implementation_Review_20261013.md.
# --------------------------------------------------------------------------------------------


def _py_exec_call(src: str, func_name: str, args: tuple):
    ns: dict = {}
    exec(src, ns)
    return ns[func_name](*args)


def test_python_behavioral_roundtrip_preserves_return_value():
    """Finding 1 asked for independent behavior tests, not just isomorphism. Execute the
    original and the probed function on the same input and require identical return values."""
    vuln = "def f(x):\n    token = x\n    return token + 1\n"
    r = build_probe("t", "python", vuln, vuln)
    assert isinstance(r, ProbeResult)
    original_result = _py_exec_call(vuln, "f", (41,))
    probe_result = _py_exec_call(r.vulnerable_probe, "f", (41,))
    assert original_result == probe_result == 42


def test_python_nested_scope_review_reproduction_is_ineligible():
    """Direct reproduction of Finding 1's Python counterexample: a nested function g() has its
    own local `token`; f() itself never assigns a local `token` (it only reads the module
    global). Before the fix, the builder's buggy nested-scope walk treated g()'s assignment as
    a candidate for f() and renamed both occurrences, changing f()'s behavior (original returns
    global-token + g()'s result; the broken probe raises NameError). After the fix, f() has no
    local-to-its-own-scope Store candidate at all, so the builder must refuse rather than guess."""
    vuln = (
        "def f():\n"
        "    def g():\n"
        "        token = 1\n"
        "        return token\n"
        "    return token + g()\n"
    )
    r = build_probe("t", "python", vuln, vuln)
    assert isinstance(r, ProbeIneligible)

    # Confirm, by actually executing it, that this function's behavior truly depends on the
    # outer (module-global) `token` -- i.e. this is a real behavioral hazard being avoided, not
    # a hypothetical one.
    ns = {"token": 10}
    exec(vuln, ns)
    assert ns["f"]() == 11


def _node_call(src: str, call_expr: str, workdir: Path) -> str:
    """Writes src + a console.log of call_expr to a temp .js file and returns node's stdout
    (stripped), or raises AssertionError with stderr on a non-zero exit (e.g. ReferenceError)."""
    script = workdir / "probe.js"
    script.write_text(src + f"\nconsole.log(JSON.stringify({call_expr}));\n")
    proc = subprocess.run([NODE, str(script)], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, f"node exited {proc.returncode}, stderr:\n{proc.stderr}"
    return proc.stdout.strip()


@pytest.mark.skipif(not _HAVE_NODE, reason="node runtime not found")
def test_js_behavioral_roundtrip_via_node(tmp_path):
    """Execute a self-contained JS probe via a real `node` subprocess before and after renaming
    and require identical output."""
    vuln = (
        "function f(x) {\n"
        "  var token = x;\n"
        "  var obj = {other: token};\n"
        "  return obj.other + 1;\n"
        "}\n"
    )
    r = build_probe("t", "javascript", vuln, vuln)
    assert isinstance(r, ProbeResult)
    assert r.old_name == "token"
    original = _node_call(vuln, "f(41)", tmp_path)
    probed = _node_call(r.vulnerable_probe, "f(41)", tmp_path)
    assert original == probed == "42"


@pytest.mark.skipif(not _HAVE_NODE, reason="node runtime not found")
def test_js_block_scope_review_reproduction_would_break_behavior(tmp_path):
    """Direct reproduction of Finding 1's JS block-scope counterexample, demonstrating via a
    real `node` run WHY the builder must refuse it (and confirming it does). `token` inside the
    bare `{ }` block is a distinct `let` binding from the `token` read in the return statement.

    CORRECTED 2026-10-13 (follow-up review): the prior version of this fixture renamed only the
    block-local DECLARATION and left the outer `return token` untouched, which does not reproduce
    a crash -- it merely shows the (correct, boring) fallback still works, which the review
    correctly pointed out does not match "the original failure, which renamed both occurrences."
    Before the block-scope fix existed, the builder had no notion of block scope at all, so a
    same-spelled candidate got EVERY textual occurrence renamed uniformly, including the outer
    reference -- reproduced faithfully below by renaming both, which really does raise a
    ReferenceError (the renamed outer reference has nothing in scope to bind to -- the block-local
    `token_renamed` is confined to its block, and the global is still spelled `token`)."""
    vuln = "function f() {\n  { let token = 1; }\n  return token;\n}\n"
    r = build_probe("t", "javascript", vuln, vuln)
    assert isinstance(r, ProbeIneligible)

    original_src = "var token = 10;\n" + vuln
    assert _node_call(original_src, "f()", tmp_path) == "10"
    naively_renamed_both = "var token = 10;\n" + "function f() {\n  { let token_renamed = 1; }\n  return token_renamed;\n}\n"
    script = tmp_path / "broken.js"
    script.write_text(naively_renamed_both + "\nconsole.log(JSON.stringify(f()));\n")
    proc = subprocess.run([NODE, str(script)], capture_output=True, text=True, timeout=30)
    assert proc.returncode != 0
    assert "ReferenceError" in proc.stderr


@pytest.mark.skipif(not _HAVE_NODE, reason="node runtime not found")
def test_js_callee_exclusion_review_reproduction_would_raise_referenceerror(tmp_path):
    """Direct reproduction of Finding 1's JS callee-exclusion counterexample. The builder must
    refuse this candidate entirely (confirmed below); a naive rename that skips only the callee
    occurrence while renaming the declaration -- the exact pre-fix bug -- is shown here via a
    real `node` run to raise a ReferenceError, confirming this is a genuine behavioral hazard."""
    vuln = "function f() {\n  const cb = () => 7;\n  return cb();\n}\n"
    r = build_probe("t", "javascript", vuln, vuln)
    assert isinstance(r, ProbeIneligible)

    assert _node_call(vuln, "f()", tmp_path) == "7"
    naively_renamed = "function f() {\n  const cb_renamed = () => 7;\n  return cb();\n}\n"
    script = tmp_path / "broken_callee.js"
    script.write_text(naively_renamed + "\nconsole.log(JSON.stringify(f()));\n")
    proc = subprocess.run([NODE, str(script)], capture_output=True, text=True, timeout=30)
    assert proc.returncode != 0
    assert "ReferenceError" in proc.stderr


def _compile_and_run_java(class_src: str, class_name: str, workdir: Path) -> str:
    src_file = workdir / f"{class_name}.java"
    src_file.write_text(class_src)
    compile_proc = subprocess.run(
        [JAVAC, "-d", str(workdir), str(src_file)], capture_output=True, text=True, timeout=60
    )
    assert compile_proc.returncode == 0, f"javac failed:\n{compile_proc.stderr}"
    run_proc = subprocess.run(
        [JAVA, "-cp", str(workdir), class_name], capture_output=True, text=True, timeout=30
    )
    assert run_proc.returncode == 0, f"java failed:\n{run_proc.stderr}"
    return run_proc.stdout.strip()


@pytest.mark.skipif(not _HAVE_JAVA, reason="javac/java runtime not found")
def test_java_declaration_name_review_reproduction_now_preserves_callability(tmp_path):
    """Direct reproduction of Finding 1's Java counterexample: a method and a local variable
    share the spelling `token`. Before the fix, the method's own declaration name was renamed
    along with the local, which would break any external caller still invoking it by its
    original name -- a real behavioral break, not just a cosmetic one. Compile and run a class
    that calls the probed method by its ORIGINAL name: this only compiles if the method's own
    name truly survived untouched."""
    method_src = "int token() { int token = 1; return token; }"
    r = build_probe("t", "java", method_src, method_src)
    assert isinstance(r, ProbeResult)
    assert r.old_name == "token"
    assert "int token()" in r.vulnerable_probe  # the method's OWN name must survive untouched

    class_src = (
        "public class Dummy {\n"
        f"  {r.vulnerable_probe}\n"
        "  public static void main(String[] args) {\n"
        "    System.out.println(new Dummy().token());\n"  # calls by the ORIGINAL method name
        "  }\n"
        "}\n"
    )
    assert _compile_and_run_java(class_src, "Dummy", tmp_path) == "1"


# --------------------------------------------------------------------------------------------
# Follow-up behavioral regressions (2026-10-13, second round) -- Dev_Probe_Followup_Review_20261013.md
# found that lexical scope was STILL incompletely modeled (Python comprehensions, Python
# parameter defaults, Java block-local vs. field references) and that the patched-side renamer
# could still rename a global reference lacking any corresponding local declaration. Each is
# reproduced directly here, confirmed fixed, and confirmed with real execution where practical.
# --------------------------------------------------------------------------------------------


def test_python_comprehension_scope_review_reproduction_is_ineligible():
    """A comprehension's own `for` target is scoped to the comprehension itself in Python 3, not
    to the enclosing function. Before the fix, `f`'s independent (module-global) `token` return
    reference got renamed along with the comprehension's unrelated local `token`, raising
    NameError. Confirm ineligibility, and confirm by execution that `f()` really does depend on
    the outer/global `token` -- i.e. this is a genuine behavioral hazard, not a hypothetical one."""
    vuln = "def f():\n    [token for token in (1,2)]\n    return token\n"
    r = build_probe("t", "python", vuln, vuln)
    assert isinstance(r, ProbeIneligible)
    ns = {"token": 10}
    exec(vuln, ns)
    assert ns["f"]() == 10


def test_python_default_argument_scope_review_reproduction_is_ineligible():
    """A parameter default value is evaluated at def-time in the ENCLOSING scope, not the
    function's own body scope. Before the fix, the body-local `token` assignment and the
    default expression's free reference to the outer/global `token` were conflated and renamed
    together, raising NameError while even just defining the function. Confirm ineligibility, and
    confirm by execution that defining the original function depends on the outer `token`."""
    vuln = "def f(x=token):\n    token=1\n    return x+token\n"
    r = build_probe("t", "python", vuln, vuln)
    assert isinstance(r, ProbeIneligible)
    ns = {"token": 10}
    exec(vuln, ns)  # must not raise -- the default legitimately resolves the outer `token`


@pytest.mark.skipif(not _HAVE_JAVA, reason="javac/java runtime not found")
def test_java_block_local_vs_field_review_reproduction_is_ineligible(tmp_path):
    """Every Java local variable declaration is block-scoped (Java has no `var`-like
    function-scoped-regardless-of-nesting local). Before the fix, `_ts_block_scoped_outside_
    function_body` returned False unconditionally for Java, so a block-local `token` and an
    unrelated enclosing FIELD `token` (read via the bare `return token` outside the block) were
    renamed together, breaking compilation. Confirm ineligibility, and confirm by actually
    compiling and running the ORIGINAL method that it really does read the field from outside
    the block (returns the field's value 10, not the block-local's value 1)."""
    vuln = "int f() { { int token=1; } return token; }"
    r = build_probe("t", "java", vuln, vuln)
    assert isinstance(r, ProbeIneligible)

    class_src = (
        "public class Dummy {\n"
        "  int token = 10;\n"
        f"  {vuln}\n"
        "  public static void main(String[] a) { System.out.println(new Dummy().f()); }\n"
        "}\n"
    )
    assert _compile_and_run_java(class_src, "Dummy", tmp_path) == "10"


def test_python_patched_side_global_reference_not_renamed():
    """Direct reproduction of the follow-up review's patched-side counterexample: the vulnerable
    function has a genuine local `token`, but the patched function only READS a module-global
    `token` (no corresponding local declaration at all). Before the fix, the patched-side renamer
    accepted `old_name` merely being present as *some* Name node and renamed the global reference,
    raising NameError. After the fix, the patched side must be left unchanged (not corrupted)
    since `token` is not an independently eligible local of the PATCHED function specifically."""
    vuln = "def f():\n    token = 1\n    return token\n"
    patched = "def f():\n    return token\n"
    r = build_probe("t", "python", vuln, patched)
    assert isinstance(r, ProbeResult)
    assert r.patched_probe_renamed is False
    assert r.patched_probe == patched  # left genuinely untouched, not silently corrupted

    ns = {"token": 7}
    exec("token = 7\n" + r.patched_probe, ns)
    assert ns["f"]() == 7  # the original (unrenamed) patched function still behaves correctly


def test_python_invalid_patched_source_makes_whole_probe_ineligible():
    """Direct reproduction of the follow-up review's remaining documentation-precision point: an
    unparseable patched_function must make the WHOLE probe ineligible, not silently fall through
    as an eligible ProbeResult carrying the original (unparseable) text as the "probe" with
    patched_probe_renamed=False -- those two outcomes were previously indistinguishable."""
    vuln = "def f():\n    token = 1\n    return token\n"
    invalid_patched = "def f(:"
    r = build_probe("t", "python", vuln, invalid_patched)
    assert isinstance(r, ProbeIneligible)
    assert "patched_function" in r.reason


# --------------------------------------------------------------------------------------------
# Round-3 follow-up regressions (2026-10-13) -- Dev_Probe_Round3_Review_20261013.md found the
# lexical-binding problem was not yet fully closed: Python `except ... as name:` bindings and
# JS/TS parameter-default scope were both still unhandled.
# --------------------------------------------------------------------------------------------


def test_python_exception_binding_review_reproduction_is_ineligible():
    """`except ValueError as token:` binds `token` via `ExceptHandler.name` (a plain string
    attribute, not an `ast.Name` node), invisible to text-span replacement. Before the fix, an
    outer `token = 1` and the handler's own `return token` (reading the caught exception, which
    shadows the outer binding) got conflated and renamed together, turning the original's
    `ValueError(7)` result into plain integer `1`. Confirm ineligibility, and confirm by execution
    that the original really does return the exception object, not the outer int."""
    src = (
        "def f():\n"
        "    token = 1\n"
        "    try:\n"
        "        raise ValueError(7)\n"
        "    except ValueError as token:\n"
        "        return token\n"
    )
    r = build_probe("t", "python", src, src)
    assert isinstance(r, ProbeIneligible)
    ns = {}
    exec(src, ns)
    result = ns["f"]()
    assert isinstance(result, ValueError) and result.args == (7,)


@pytest.mark.skipif(not _HAVE_NODE, reason="node runtime not found")
def test_js_default_argument_scope_review_reproduction_is_ineligible(tmp_path):
    """A JS/TS parameter default value expression is evaluated in a scope that sees the
    ENCLOSING scope, not the function body's own `let`/`const`/`var` declarations. Before the
    fix, the default's free reference to an outer/global `token` and the body's own distinct
    `let token` got renamed together, and the renamed probe threw ReferenceError (the default
    still only sees the original, unrenamed global). Confirm ineligibility, and confirm by a real
    `node` run that the original genuinely returns 11 (uses the global default plus the shadowed
    body-local, 10 is never read directly but the default captures it before the body shadows it)."""
    vuln = "function f(x=token) { let token=1; return x+token; }"
    r = build_probe("t", "javascript", vuln, vuln)
    assert isinstance(r, ProbeIneligible)
    original_src = "var token = 10;\n" + vuln
    assert _node_call(original_src, "f()", tmp_path) == "11"


# --------------------------------------------------------------------------------------------
# Bounded binding-form audit regressions (2026-10-13) -- systematic sweep for the "invisible
# binding site" bug class (a declaration whose site is a plain string/other attribute, not an
# `ast.Name`/`identifier` node, so it is invisible to text-span replacement while OTHER same-
# spelled references elsewhere in the function are still textually renamed). Found: Python
# nested def/class names, import aliases, match-case captures; JS/TS nested function/class
# declaration names. Confirmed SAFE (not a bug, just an eligibility gap or already-protected by
# existing checks): Python tuple/list unpacking and the walrus operator; JS/TS destructuring,
# catch-clause parameters, and for-of/for-in loop variables; Java local classes and catch
# parameters (the language's type/value identifier distinction, or outright compile failure,
# rules out the risk).
# --------------------------------------------------------------------------------------------


def test_python_nested_def_name_rebinding_is_ineligible():
    """A nested `def NAME(): ...` statement binds NAME in the enclosing scope via a plain string
    attribute (`FunctionDef.name`), not an `ast.Name` node. Before the fix, a later reference to
    the rebound function got renamed while the def's own name stayed put, turning a function call
    into an attempt to call the (renamed) int. Confirm ineligibility, and confirm by execution
    that the original genuinely calls the nested function (returns 2), not the int."""
    src = (
        "def f():\n"
        "    token = 1\n"
        "    def token():\n"
        "        return 2\n"
        "    return token()\n"
    )
    r = build_probe("t", "python", src, src)
    assert isinstance(r, ProbeIneligible)
    ns = {}
    exec(src, ns)
    assert ns["f"]() == 2


def test_python_import_alias_rebinding_is_ineligible():
    """`import os as token` binds `token` via `ast.alias.asname`, a plain string attribute, not
    an `ast.Name` node. Before the fix, a later reference to the module alias got renamed while
    the import statement's own alias stayed put, raising AttributeError on the renamed int.
    Confirm ineligibility, and confirm by execution that the original genuinely calls through
    the alias (returns a string, not raising)."""
    src = (
        "def f():\n"
        "    token = 1\n"
        "    import os as token\n"
        "    return token.getcwd()\n"
    )
    r = build_probe("t", "python", src, src)
    assert isinstance(r, ProbeIneligible)
    ns = {}
    exec(src, ns)
    assert isinstance(ns["f"](), str)


def test_python_match_case_binding_is_ineligible():
    """A `match`/`case` capture pattern (`case int() as token:`) binds `token` via a plain string
    attribute (`MatchAs.name`), not an `ast.Name` node. Before the fix, the case body's reference
    to the MATCHED value got renamed to refer to the unrelated outer local instead, changing the
    returned value. Confirm ineligibility, and confirm by execution that the original genuinely
    returns the matched value (99), not the outer local (1)."""
    src = (
        "def f(obj):\n"
        "    token = 1\n"
        "    match obj:\n"
        "        case int() as token:\n"
        "            return token\n"
        "    return token\n"
    )
    r = build_probe("t", "python", src, src)
    assert isinstance(r, ProbeIneligible)
    ns = {}
    exec(src, ns)
    assert ns["f"](99) == 99


def test_python_walrus_and_tuple_unpacking_confirmed_safe():
    """Documents, as a test, why the walrus operator and tuple/list unpacking are NOT part of the
    invisible-binding bug class: both bind via genuine `ast.Name` Store-context nodes (unlike
    except/match/import), so they are either safely renamed when chosen, or safely left alone
    (never offered as a candidate, per the existing plain-Name-target-only policy) without any
    risk of an unrelated candidate's rename corrupting them."""
    walrus_src = "def f():\n    token = 1\n    if (other := token + 1):\n        return other\n    return 0\n"
    r = build_probe("t", "python", walrus_src, walrus_src)
    assert isinstance(r, ProbeResult)
    assert r.old_name == "token"
    ns1, ns2 = {}, {}
    exec(walrus_src, ns1)
    exec(r.vulnerable_probe, ns2)
    assert ns1["f"]() == ns2["f"]() == 2

    tuple_src = "def f():\n    a, token = 1, 2\n    return a + token\n"
    r2 = build_probe("t", "python", tuple_src, tuple_src)
    assert isinstance(r2, ProbeIneligible)  # safe omission: tuple-unpack targets are never offered


@pytest.mark.skipif(not _HAVE_NODE, reason="node runtime not found")
def test_js_nested_function_name_rebinding_is_ineligible(tmp_path):
    """A nested `function NAME() {...}` declaration binds NAME in the enclosing scope. Before the
    fix, a reference to the hoisted function (captured before a same-named `var` assignment runs)
    got renamed while the function declaration's own name stayed put, breaking the call. Confirm
    ineligibility, and confirm by a real `node` run that the original genuinely returns 3."""
    vuln = "function f() { var fn = token; var token = 1; function token() { return 2; } return fn() + token; }"
    r = build_probe("t", "javascript", vuln, vuln)
    assert isinstance(r, ProbeIneligible)
    assert _node_call(vuln, "f()", tmp_path) == "3"


@pytest.mark.skipif(not _HAVE_NODE, reason="node runtime not found")
def test_js_catch_clause_and_for_of_shadowing_confirmed_safe(tmp_path):
    """Documents why JS/TS catch-clause parameters and for-of/for-in loop variables are NOT part
    of the invisible-binding bug class, despite shadowing an outer same-named variable: both are
    genuine `identifier` nodes (unlike Python's except-as), so a blanket same-spelling rename
    preserves the shadowing relationship correctly. Confirmed by real `node` runs that both
    produce identical output before and after."""
    catch_src = "function f() { let token=1; try { throw 99; } catch (token) { console.log(token); } return token; }"
    r = build_probe("t", "javascript", catch_src, catch_src)
    assert isinstance(r, ProbeResult)
    assert _node_call(catch_src, "f()", tmp_path) == _node_call(r.vulnerable_probe, "f()", tmp_path)

    forof_src = "function f(arr) { let token=1; for (let token of arr) { } return token; }"
    r2 = build_probe("t", "javascript", forof_src, forof_src)
    assert isinstance(r2, ProbeResult)
    assert (_node_call(forof_src, "f([10,20])", tmp_path)
            == _node_call(r2.vulnerable_probe, "f([10,20])", tmp_path))


# --------------------------------------------------------------------------------------------
# Missing-link regressions (2026-10-13, review Finding 3) -- Binding_Form_Audit_Review_20261013.md
# noted several table rows had no linked test: augmented/annotated assignment, for/with targets,
# global/nonlocal, Java parameter role-change, and nested-block JS `var` (function-scoped
# regardless of nesting, unlike let/const). One test per row below.
# --------------------------------------------------------------------------------------------


def test_python_augassign_and_annassign_targets_are_supported():
    """`x += ...` and `x: T = ...` targets are ordinary Store-context Names, structurally
    identical to a plain assignment -- confirm each is actually offered and renamed correctly,
    not just assumed safe by analogy."""
    aug_src = "def f(x):\n    token = 0\n    token += x\n    return token\n"
    r = build_probe("t", "python", aug_src, aug_src)
    assert isinstance(r, ProbeResult) and r.old_name == "token"
    ns1, ns2 = {}, {}
    exec(aug_src, ns1)
    exec(r.vulnerable_probe, ns2)
    assert ns1["f"](5) == ns2["f"](5) == 5

    ann_src = "def f(x):\n    token: int = 0\n    return token + x\n"
    r2 = build_probe("t", "python", ann_src, ann_src)
    assert isinstance(r2, ProbeResult) and r2.old_name == "token"
    ns3, ns4 = {}, {}
    exec(ann_src, ns3)
    exec(r2.vulnerable_probe, ns4)
    assert ns3["f"](5) == ns4["f"](5) == 5


def test_python_for_and_with_targets_are_supported():
    """`for token in ...:` and `with ... as token:` targets are ordinary Store-context Names --
    confirm each is actually offered and renamed correctly."""
    for_src = "def f(items):\n    total = 0\n    for token in items:\n        total += token\n    return total\n"
    r = build_probe("t", "python", for_src, for_src)
    assert isinstance(r, ProbeResult)
    assert r.old_name in ("token", "total")
    ns1, ns2 = {}, {}
    exec(for_src, ns1)
    exec(r.vulnerable_probe, ns2)
    assert ns1["f"]([1, 2, 3]) == ns2["f"]([1, 2, 3]) == 6

    with_src = (
        "import contextlib\n"
        "def f():\n"
        "    with contextlib.nullcontext(5) as token:\n"
        "        return token\n"
    )
    r2 = build_probe("t", "python", with_src, with_src)
    assert isinstance(r2, ProbeResult) and r2.old_name == "token"
    ns3, ns4 = {}, {}
    exec(with_src, ns3)
    exec(r2.vulnerable_probe, ns4)
    assert ns3["f"]() == ns4["f"]() == 5


def test_python_global_declared_name_is_excluded():
    """A name declared `global` inside the function must never be renamed -- it refers to
    module-level state the probe's isolated re-exec cannot safely rename around."""
    src = "def f():\n    global token\n    token = 1\n    return token\n"
    r = build_probe("t", "python", src, src)
    assert isinstance(r, ProbeIneligible)


def test_java_parameter_role_change_risk_is_excluded():
    """A method parameter must never be renamed -- confirmed by checking the patched side
    specifically still independently rejects a parameter-shaped candidate, matching the
    already-tested Python equivalent (`test_python_parameter_never_renamed`)."""
    src = "int f(int token) {\n    int other = token + 1;\n    return other;\n}\n"
    r = build_probe("t", "java", src, src)
    assert isinstance(r, ProbeResult)
    assert r.old_name != "token"
    assert r.old_name == "other"


@pytest.mark.skipif(not _HAVE_NODE, reason="node runtime not found")
def test_js_nested_var_remains_function_scoped_and_supported(tmp_path):
    """Unlike `let`/`const`, a `var` declared inside a nested block is still function-scoped in
    JS -- it must NOT be excluded by the block-scope check, and renaming it must be behaviorally
    safe. Confirmed via a real `node` run comparing before/after output."""
    src = "function f(x) {\n  if (x) {\n    var token = x + 1;\n  }\n  return token;\n}\n"
    r = build_probe("t", "javascript", src, src)
    assert isinstance(r, ProbeResult)
    assert r.old_name == "token"
    assert _node_call(src, "f(5)", tmp_path) == _node_call(r.vulnerable_probe, "f(5)", tmp_path) == "6"


# --------------------------------------------------------------------------------------------
# Binding_Form_Audit_Review_20261013.md Findings 1-2 regressions -- the "destructuring is safe"
# table claim failed for a SAME-NAME collision (only an unrelated-candidate scenario was tested
# before), and the declared-out-of-scope decorator construct was not actually enforced.
# --------------------------------------------------------------------------------------------


@pytest.mark.skipif(not _HAVE_NODE, reason="node runtime not found")
def test_js_shorthand_destructuring_same_name_collision_is_ineligible(tmp_path):
    """Finding 1: the prior 'destructuring is safe' test only checked an UNRELATED candidate next
    to a destructuring binding -- it never tested the SAME name used both as the outer `var`
    declaration and as a shorthand destructuring target (`var {token}=obj`), which `var`'s
    redeclaration semantics make perfectly valid JS. The shorthand destructuring node
    (`shorthand_property_identifier_pattern`) is a DIFFERENT type than plain `identifier`, so it
    stayed stale while the outer declaration and return got renamed. Confirm ineligibility, and
    confirm by a real `node` run that the original genuinely returns 99 (the destructured value),
    not 1 (the stale initial value)."""
    src = "function f(obj) { var token=1; var {token}=obj; return token; }"
    r = build_probe("t", "javascript", src, src)
    assert isinstance(r, ProbeIneligible)
    assert _node_call(src, "f({token:99})", tmp_path) == "99"


@pytest.mark.skipif(not _HAVE_NODE, reason="node runtime not found")
def test_js_array_and_renamed_key_destructuring_confirmed_still_safe(tmp_path):
    """Companion to the fix above: array destructuring (`var [token]=obj`) and renamed-key object
    destructuring (`var {other: token}=obj`) bind via a plain `identifier` node (the SAME type as
    an ordinary reference), so they were already renamed consistently and remain eligible after
    the shorthand-specific fix -- confirmed by real `node` runs, not just re-asserted."""
    array_src = "function f(obj) { var token=1; var [token] = obj; return token; }"
    r = build_probe("t", "javascript", array_src, array_src)
    assert isinstance(r, ProbeResult)
    assert _node_call(array_src, "f([99])", tmp_path) == _node_call(r.vulnerable_probe, "f([99])", tmp_path) == "99"

    key_src = "function f(obj) { var token2=1; var {other: token2} = obj; return token2; }"
    r2 = build_probe("t", "javascript", key_src, key_src)
    assert isinstance(r2, ProbeResult)
    assert (_node_call(key_src, "f({other:99})", tmp_path)
            == _node_call(r2.vulnerable_probe, "f({other:99})", tmp_path) == "99")


def test_python_decorator_expression_scope_is_excluded():
    """Finding 2: decorator expressions (`FunctionDef.decorator_list`) are evaluated at def-time
    in the ENCLOSING scope, the same free-reference risk as parameter defaults -- but were not
    covered by `_py_names_in_signature` at all (a separate AST field). Before the fix, a body-local
    candidate sharing a name with a decorator's free reference to an outer/global got renamed
    together, raising NameError while DEFINING the function. Confirm ineligibility, and confirm by
    execution that the original genuinely defines and calls cleanly (the decorator reads the
    outer/global value, unrelated to the body local)."""
    src = (
        "decorate = lambda value: lambda fn: fn\n"
        "\n"
        "@decorate(token)\n"
        "def f():\n"
        "    token = 1\n"
        "    return token\n"
    )
    r = build_probe("t", "python", src, src)
    assert isinstance(r, ProbeIneligible)
    ns = {"token": 10}
    exec(src, ns)
    assert ns["f"]() == 1
