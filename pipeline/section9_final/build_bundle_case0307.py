"""
Section 9 ground-truth test bundle: CASE-0307
(totaljs/framework, utils.js exports.set (U.set), CVE-2020-28495,
CWE-1321 prototype pollution).

Core vulnerable mechanism: `U.set(obj, path, value)` assigns a value at a
dotted/bracketed path (`'a.b[0].c'`). To be fast it COMPILES the path into
JavaScript source (`if(typeof(w.a)!=='object'||w.a==null)w.a={};...w.a.b=v`)
and runs it with `new Function('w','a','b', code)`, caching the function.
Nothing stops the path from naming `__proto__`, `constructor` or
`prototype`: `U.set({}, '__proto__.isAdmin', true)` compiles to code that
assigns `w.__proto__.isAdmin = v`, i.e. it writes onto `Object.prototype`, so
EVERY object in the process suddenly has `isAdmin === true` (privilege
escalation, denial of service, and code-execution gadgets). Applications
routinely call `U.set` with a client-supplied key path (settings editors,
query/body-to-object helpers). The upstream fix rejects any generated code
containing `__proto__`, `constructor` or `prototype` by throwing
`Error('Prototype pollution')` before compiling it.

Sibling sites: `U.set` is the only path->code compiler with this shape in the
file (its `exports.get` reader does not assign).

Verification: `parsepath` and `exports.set` are extracted verbatim from each
full file and run in an isolated Node vm context (so that a successful
pollution affects only that context's own `Object.prototype`, not this
process) with stand-ins only for the module globals they reference
(`F.temporary.other` cache object, the two path regexes `REGISARR` and
`REGREPLACEARR`, and `U.get`). `set({}, '__proto__.polluted', 'yes')` is
executed for real, and afterwards `({}).polluted` is evaluated inside the
same context. A benign `set(o, 'a.b', 1)` must produce `{a:{b:1}}` in every
variant.

Every variant is the FULL real file. `exports.set` is the public `U.set`,
so its name/signature are kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0307"
original = (CASE_DIR / "vulnerable_source.js").read_text()
patched = (CASE_DIR / "patched_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


ANCH = "\tvar fn = new Function('w', 'a', 'b', a);\n\tF.temporary.other[cachekey] = fn;\n\tfn(obj, value, path);\n"
assert original.count(ANCH) == 1

# --- Variant 1: renamed vulnerable variant (locals of exports.set) ---
s = original.index("exports.set = function(obj, path, value) {")
e = original.index("\n};\n", s) + 4
F = original[s:e]
f1 = re.sub(r"\bbuilder\b", "guards", F)
f1 = re.sub(r"\bcachekey\b", "cacheId", f1)
f1 = re.sub(r"\bispush\b", "isAppend", f1)
assert f1 != F
(CASE_DIR / "variant_vulnerable_01.js").write_text(original.replace(F, f1))

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, ANCH, "\tvar fn = compileSetter(a);\n\tF.temporary.other[cachekey] = fn;\n\tfn(obj, value, path);\n")
v2 = swap(v2, "exports.set = function(obj, path, value) {", "function compileSetter(code) {\n\treturn new Function('w', 'a', 'b', code);\n}\n\nexports.set = function(obj, path, value) {")
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file, check via a helper) ---
PG = "\tif ((/__proto__|constructor|prototype/).test(a))\n\t\tthrow new Error('Prototype pollution');\n"
assert patched.count(PG) == 1
v3 = swap(patched, PG, "\tassertNoPrototypeAccess(a);\n")
v3 = swap(v3, "exports.set = function(obj, path, value) {", '''const REGPROTOKEYS = /__proto__|constructor|prototype/;

function assertNoPrototypeAccess(code) {
	// the compiled path must never reach an object's prototype chain
	if (REGPROTOKEYS.test(code))
		throw new Error('Prototype pollution');
}

exports.set = function(obj, path, value) {''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

(CASE_DIR / "benign_lookalike.js").write_text('''// Standalone example of the same shape: generate a small formatter function
// with new Function from a FIXED, application-owned list of column names
// (never from request data), so the compiled source is fully trusted.
var COLUMNS = ['id', 'name', 'email'];

var formatRow = new Function('row', 'return ' + COLUMNS.map(function (c) { return 'row.' + c; }).join(" + ',' + "));

module.exports = formatRow;
''')
