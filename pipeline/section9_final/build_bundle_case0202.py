"""
Section 9 ground-truth test bundle: CASE-0202
(jonschlinkert/assign-deep, index.js extend, CVE-2018-3720, CWE-471 / prototype
pollution).

Core vulnerable mechanism: `extend(target, obj)` copies every own enumerable key
of `obj` into `target` and recurses into nested objects with
`target[key] = assign(target[key] || {}, val)`. With attacker JSON such as
`JSON.parse('{"__proto__":{"polluted":"yes"}}')` the own key `__proto__` makes
`target['__proto__']` (Object.prototype) the recursion target, so
`Object.prototype.polluted` is set for every object in the process. The
upstream fix skips the key `__proto__`.

Measured caveat, kept in the manifest notes: skipping only `__proto__` leaves
the equivalent route `{"constructor":{"prototype":{...}}}`, which reaches
Object.prototype through `target.constructor.prototype`; the safe variant
skips `__proto__`, `constructor` and `prototype`.

Sibling sites: `assign` calls `extend`; the recursion goes through `assign`
again, so the single check in `extend` covers all levels.

Every variant is the FULL real file. `extend` is a module-private function,
so the renamed variant renames it, its parameters and locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0202"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

CHECK = "    if (hasOwn(obj, key)) {\n"
s = original.index("function extend(target, obj) {\n")
e = original.index("\n}\n", s) + len("\n}\n")
BLOCK = original[s:e]
assert BLOCK.count(CHECK) == 1 and original.count("extend(") == 2


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK
for old, new in (("extend", "mergeInto"), ("target", "dest"), ("obj", "source"), ("key", "prop"), ("val", "value")):
    b = re.sub(r"(?<![.\w$'])%s(?![\w$'])" % old, new, b)
v1 = original[:s] + b + original[e:]
v1 = v1.replace("      extend(target, val);", "      mergeInto(target, val);")
assert "extend(" not in v1 and "hasOwn(source, prop)" in v1
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace("  for (var key in obj) {\n    if (hasOwn(obj, key)) {\n", "  Object.keys(obj).forEach(function(key) {\n    if (true) {\n")
b = b.replace("    }\n  }\n  return target;\n", "    }\n  });\n  return target;\n")
assert b != BLOCK
(CASE_DIR / "variant_vulnerable_02.js").write_text(original[:s] + b + original[e:])

# --- Variant 3: transformed safe variant ---
b = BLOCK.replace(CHECK, "    if (!isUnsafeKey(key) && hasOwn(obj, key)) {\n")
helper = '''
/**
 * Keys that would reach Object.prototype (directly or through constructor.prototype).
 */

function isUnsafeKey(key) {
  return key === '__proto__' || key === 'constructor' || key === 'prototype';
}
'''
(CASE_DIR / "variant_safe_01.js").write_text(original[:s] + b + helper + original[e:])

# --- Variant 4: benign structural look-alike ---
benign = '''"use strict";

/**
 * Same "copy own keys, recursing into nested objects" loop as the deep
 * assign, but the destination and every nested container are created with
 * Object.create(null), so there is no prototype chain to pollute.
 */
function copyInto(target, source) {
  Object.keys(source).forEach(function (key) {
    var value = source[key];
    if (value !== null && typeof value === "object") {
      target[key] = copyInto(Object.create(null), value);
    } else {
      target[key] = value;
    }
  });
  return target;
}

module.exports = function (source) { return copyInto(Object.create(null), source); };
'''
assert "Object.create(null)" in benign
(CASE_DIR / "benign_lookalike.js").write_text(benign)
print("Wrote 4 new samples for CASE-0202.")
