"""
Section 9 ground-truth test bundle: CASE-0266
(protobufjs/protobuf.js, src/type.js Type constructor, CVE-2026-41242,
CWE-94 code injection).

Core vulnerable mechanism: `Type`'s constructor stores whatever `name`
string it is given (from a `.proto` schema's `message` declaration, or any
caller building a `Type` programmatically from untrusted input, e.g. a
service that lets users upload/compose a proto schema) directly on the
instance via `Namespace.call(this, name, options)`, with no restriction on
which characters that name may contain. `Type.generateConstructor` later
passes this SAME name, unescaped, as the function-name argument to
`util.codegen(["p"], mtype.name)` -- codegen builds a JS function
definition by literal string concatenation (`"function " + name + "(" +
params + "){...}"`) and compiles it with `new Function(source)()`. A type
name containing characters that are meaningful in a function declaration's
name position (whitespace, parentheses, braces, semicolons) can therefore
break out of the intended `function <Name>(p){...}` skeleton and splice
attacker-controlled statements into the compiled function -- for example a
name of `x(){};(<payload>);function y` closes the generated function early
and appends arbitrary JS that executes the moment the constructor is
generated. The upstream fix sanitizes `name` at the very top of the `Type`
constructor with `name = name.replace(/\\W/g, "")`, so only word characters
(`[A-Za-z0-9_]`) ever reach `this.name`/`this.fullName` (inherited via
`Namespace`), and therefore ever reach `codegen`'s function-name position.

Measured caveat, kept in the manifest notes: the CURRENTLY-INSTALLED
protobufjs's own `util/codegen.js` (a separate file, unrelated to this
patch) has SINCE grown its own independent `safeFunctionName()` sanitizer
that also strips `[^\\w$]` from the function-name argument before building
the source string -- confirmed by generating the real `function
Evil(){...}` constructor from a type deliberately named
`'Evil");}//'` against the installed package: the payload was already
neutralized by that second, independent layer regardless of whether `Type`
itself sanitizes. This bundle's verification therefore measures the actual
code change (`Type`'s own `name`/`fullName` sanitization) directly against
the real `Type`/`Namespace` classes, rather than re-demonstrating the full
codegen-to-`Function()` chain, since that chain is no longer exploitable
through this one entry point against the current dependency version -- the
`Type`-level gap is real and independently worth fixing (a caller or a
different, less-defended code-generation surface may still trust
`type.name` as identifier-safe), but a live double-layered RCE PoC against
today's protobufjs would be a claim this harness cannot back with real
execution.

Sibling sites: `Type` is the only reflection class whose constructor takes
a raw name without sanitizing it this way; `Namespace`, `Enum`, `Field`, and
`Service` (called via `Namespace.call`/similar) are unaffected by this
specific one-line fix and are out of scope for this diff.

Verification: each full file is swapped in for `node_modules/protobufjs/src/type.js`
inside a real npm install of `protobufjs`, so `new Type(name)` runs as real,
unmodified code against the real `Namespace` base class. `new
Type('Evil");}//')` is constructed and `.name`/`.fullName` inspected for
whether the injection-relevant characters (`"`, `)`, `;`, `}`, space, `/`)
survive.

Every variant is the FULL real file. `Type` is `require()`d and
instantiated throughout the rest of protobufjs and by every application
using it (`new protobuf.Type(name)` / `Root#define` / the parser), so its
name and `(name, options)` constructor signature are kept; the renamed
variant renames the constructor's own parameters.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0266"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


CTOR_HEAD = """function Type(name, options) {
    Namespace.call(this, name, options);
"""
assert original.count(CTOR_HEAD) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, CTOR_HEAD, """function Type(typeName, typeOptions) {
    Namespace.call(this, typeName, typeOptions);
""")
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, CTOR_HEAD, """function Type(name, options) {
    var resolvedName = name;
    Namespace.call(this, resolvedName, options);
""")
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same fix outcome as upstream (only word characters survive into
# this.name/this.fullName) but built by filtering characters one at a time
# with Array.prototype.filter/RegExp.prototype.test, instead of upstream's
# single String.prototype.replace(/\\W/g, "") call.
v3 = swap(original, CTOR_HEAD, """function Type(name, options) {
    name = String(name)
        .split("")
        .filter(function(ch) { return /\\w/.test(ch); })
        .join("");
    Namespace.call(this, name, options);
""")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = """// Standalone example of the same shape: normalize a display label by
// stripping leading/trailing whitespace before storing it, purely so the
// UI doesn't show stray padding -- the label is only ever rendered as
// text, never used to build executable source, so untrimmed whitespace is
// a cosmetic issue, not a security one.
function DisplayLabel(text) {
    this.text = String(text).trim();
}

module.exports = DisplayLabel;
"""
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
