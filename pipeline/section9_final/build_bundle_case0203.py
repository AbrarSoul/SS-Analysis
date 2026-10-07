"""
Section 9 ground-truth test bundle: CASE-0203
(jorenbroekema/expr-eval, src/evaluate.js the `else if (type === IVAR)` branch of
evaluate, CVE-2025-13204, CWE-1321 improperly controlled modification of
object prototype attributes).

Core vulnerable mechanism: when an expression names a variable, `evaluate`
resolves it as `values[item.value]` with no own-property check, so names such
as `constructor`, `__proto__`, `toString` or `hasOwnProperty` resolve to the
INHERITED members of Object.prototype (functions and the prototype object
itself) and become values the expression can pass around and call. Measured
with the real parser bundled from the vulnerable commit: the expression
`constructor` evaluates to the Object function and `__proto__.x` walks the
prototype chain. The upstream fix throws for names matching
`/^__proto__|prototype|constructor$/`.

Measured caveats, kept in the manifest notes: upstream's regular expression is
a denylist with a precedence quirk (`^__proto__` or `prototype` ANYWHERE or
`constructor$`), so it rejects a legitimate own variable such as
`myprototypeFlag` and still lets other inherited members (`toString`,
`hasOwnProperty`, `valueOf`) resolve. The safe variant requires the name to be an
OWN property of expr.functions, expr.unaryOps or the supplied values object (the
inherited `constructor` is found by the earlier `in expr.functions` test, not
only by the values lookup).

Sibling sites: the same `values[...]` lookup pattern is used only in this
branch of evaluate (function/operator lookups use expr.functions and
expr.unaryOps first and are unchanged).

Verification: the real expr-eval source tree at the vulnerable commit is
bundled with esbuild (each variant's evaluate.js replaces the original; the
case file is byte-identical to it) and the real parser evaluates the
expressions.

Every variant is the FULL real file. evaluate is the module's default export,
so the renamed variant keeps its name and renames the local `v`.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0203"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

BRANCH = '''        var v = values[item.value];
        if (v !== undefined) {
          nstack.push(v);
        } else {
          throw new Error('undefined variable: ' + item.value);
        }
'''
assert original.count(BRANCH) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, BRANCH, BRANCH.replace("var v =", "var resolved =").replace("if (v !== undefined)", "if (resolved !== undefined)").replace("nstack.push(v);", "nstack.push(resolved);"))
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, BRANCH, '''        if (values[item.value] === undefined) {
          throw new Error('undefined variable: ' + item.value);
        }
        nstack.push(values[item.value]);
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Every name lookup in the branch (functions, unary operators, values) requires
# an OWN property, so nothing inherited from Object.prototype can resolve;
# upstream denylists three names with a regular expression.
IVAR_HEAD = """      if (item.value in expr.functions) {
        nstack.push(expr.functions[item.value]);
      } else if (item.value in expr.unaryOps && expr.parser.isOperatorEnabled(item.value)) {"""
assert original.count(IVAR_HEAD) == 1
v3 = swap(original, IVAR_HEAD, """      if (hasOwn(expr.functions, item.value)) {
        nstack.push(expr.functions[item.value]);
      } else if (hasOwn(expr.unaryOps, item.value) && expr.parser.isOperatorEnabled(item.value)) {""")
v3 = swap(v3, BRANCH, """        var v = hasOwn(values, item.value) ? values[item.value] : undefined;
        if (v !== undefined) {
          nstack.push(v);
        } else {
          throw new Error('undefined variable: ' + item.value);
        }
""")
v3 = swap(v3, "export default function evaluate(tokens, expr, values) {\n", """function hasOwn(obj, name) {
  return Object.prototype.hasOwnProperty.call(obj, name);
}

export default function evaluate(tokens, expr, values) {
""")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign = '''"use strict";

/**
 * Same "look a name up in a values object" step as the expression evaluator,
 * but the lookup is restricted to OWN properties and returns undefined for
 * anything inherited, so it cannot expose Object.prototype members.
 */
function lookup(values, name) {
  return Object.prototype.hasOwnProperty.call(values, name) ? values[name] : undefined;
}

module.exports = lookup;
'''
assert "OWN properties" in benign
(CASE_DIR / "benign_lookalike.js").write_text(benign)
print("Wrote 4 new samples for CASE-0203.")
