"""
Section 9 ground-truth test bundle: CASE-0087
(aheckmann/mpath, CVE-2021-23438, CWE-843 type confusion -> prototype
pollution).

Core vulnerable mechanism: mpath's get/has/unset/set accept a path given
as an ARRAY of segments and guard against `__proto__`/`constructor`/
`prototype` with `ignoreProperties.indexOf(parts[i]) !== -1` (strict
equality). A segment that is not a string, e.g. the array `['__proto__']`,
never strictly equals '__proto__' and so passes the guard, yet is coerced
to the string '__proto__' when used as a property key -- reaching
Object.prototype. The upstream fix throws a TypeError for any segment that
is not a string or number, inside all four functions.

Target function for the renamed/structural variants is exports.get (the
function the locator selected); the SAFE variant hardens ALL FOUR
functions, since leaving any of them unfixed would make the file still
vulnerable. Every variant is the FULL real file.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0087"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.js").read_text().splitlines()) + "\n"

START = "exports.get = function(path, o, special, map) {"
s = original.index(START)
e = original.index("\n};\n", s) + 4
BLOCK = original[s:e]
assert original.count(START) == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("exports.get = function(path, o, special, map) {", "exports.readPath = function(route, root, mode, mapper) {")
for old, new in (("exports.get(", "exports.readPath("), ("parts", "segments"), ("path", "route"), ("paths", "rest"),
                 ("special", "mode"), ("lookup", "customLookup"), ("map", "mapper"), ("part", "segment"),
                 ("obj", "current"), ("_from", "source")):
    if old == "exports.get(":
        b = b.replace(old, new)
    else:
        b = re.sub(r"(?<![.\w])%s\b" % re.escape(old), new, b)
b = re.sub(r"\bo\b(?!\w)", "root", b)
renamed = build(b)
assert "exports.get" not in renamed
assert "ignoreProperties" in renamed  # untouched elsewhere
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed)

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace("  for (var i = 0; i < parts.length; ++i) {\n    part = parts[i];",
                  "  var i = -1;\n  while (++i < parts.length) {\n    part = parts[i];")
(CASE_DIR / "variant_vulnerable_02.js").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# One shared helper validates ALL segments up front (before any use), instead
# of an inline check inside each loop as upstream does; applied to get, has,
# unset and set.
HELPER = """
// Every segment of an array path must be a string or a number: any other type
// (e.g. an array like ['__proto__']) would bypass the ignoreProperties check
// below by strict inequality yet still be coerced to a dangerous property key.
function assertSegmentTypes(parts, fnName) {
  for (var k = 0; k < parts.length; ++k) {
    var t = typeof parts[k];
    if (t !== 'string' && t !== 'number') {
      throw new TypeError('Each segment of path to `' + fnName + '()` must be a string or number, got ' + t);
    }
  }
}
"""
safe = original.replace("var ignoreProperties = ['__proto__', 'constructor', 'prototype'];\n",
                        "var ignoreProperties = ['__proto__', 'constructor', 'prototype'];\n" + HELPER, 1)
CHECK = "  if (!Array.isArray(parts)) {\n    throw new TypeError('Invalid `path`. Must be either string or array');\n  }\n"
assert safe.count(CHECK) == 4
for fn in ("get", "has", "unset", "set"):
    idx = safe.index("exports.%s = function(" % fn)
    at = safe.index(CHECK, idx)
    safe = safe[:at + len(CHECK)] + "\n  assertSegmentTypes(parts, '%s');\n" % fn + safe[at + len(CHECK):]
assert safe.count("assertSegmentTypes(parts,") == 5  # helper declaration + 4 call sites
(CASE_DIR / "variant_safe_01.js").write_text(safe)

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.js").write_text("""// Same ignoreProperties.indexOf(segment) guard shape, but every path handled
// here is a fixed, developer-written array literal of string constants; no
// externally supplied (or non-string) segment can ever reach it.
var ignoreProperties = ['__proto__', 'constructor', 'prototype'];

var SETTINGS_PATHS = {
  port: ['server', 'port'],
  host: ['server', 'host']
};

exports.readSetting = function(name, config) {
  var parts = SETTINGS_PATHS[name];
  if (!parts) return undefined;
  var cur = config;
  for (var i = 0; i < parts.length; ++i) {
    if (ignoreProperties.indexOf(parts[i]) !== -1) return undefined;
    if (cur == null) return undefined;
    cur = cur[parts[i]];
  }
  return cur;
};
""")
print("Wrote 4 new samples for CASE-0087.")
