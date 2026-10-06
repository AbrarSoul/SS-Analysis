"""
Section 9 ground-truth test bundle: CASE-0303
(thlorenz/browserify-shim, lib/resolve-shims.js separateExposeGlobals,
CVE-2022-37617, CWE-1321 improperly controlled modification of
object prototype attributes / prototype pollution).

Core vulnerable mechanism: browserify-shim reads a `browserify-shim`
configuration object from a package's `package.json` (or shim file) and
splits its entries with `separateExposeGlobals`: for every key `k` it does
`onlyShims[k] = val` (or `exposeGlobals[k] = exp`). `JSON.parse` produces
`__proto__` as an ordinary OWN key, so a `package.json` -- in any
dependency, i.e. attacker-influenced supply-chain input -- containing
`"browserify-shim": { "__proto__": { "polluted": "yes" } }` makes the
assignment `onlyShims["__proto__"] = val` run the `__proto__` setter and
replace the prototype of the shim table with the attacker's object (a
`"constructor"` key likewise shadows the table's `constructor`). Every
later lookup on the shim table (`shims[x]`, `hasOwnProperty`-less `in`
checks, option reads) then sees attacker-controlled inherited properties,
and the resulting object flows into the build pipeline. The upstream fix
skips the `__proto__` and `constructor` keys in the loop.

Sibling sites: `separateExposeGlobals` is the only place that copies
attacker-keyed entries into fresh objects in this file.

Verification: `inspect`, `mapifyExposeGlobals` and `separateExposeGlobals`
are extracted verbatim from each full file and evaluated in a Node vm
(only `util` provided, since `inspect` uses it). The shims object is built
with `JSON.parse` so `__proto__`/`constructor` are genuine own keys.
`separateExposeGlobals(JSON.parse('{"__proto__":{"polluted":"yes"},
"constructor":{"exports":"x"},"jquery":{"exports":"global:jQuery"},
"lib":{"path":"./lib.js"}}'))` is evaluated; the returned `shims` table is
checked for an inherited attacker property (`shims.polluted`), for a
shadowed own `constructor`, and the benign entries (`jquery` mapped into
`exposeGlobals`, `lib` kept in `shims`) must be intact in every variant.

Every variant is the FULL real file. `separateExposeGlobals` is called by
name from `resolveShims`, so its name/signature are kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0303"
original = (CASE_DIR / "vulnerable_source.js").read_text()
patched = (CASE_DIR / "patched_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


s = original.index("function separateExposeGlobals(shims) {")
e = original.index("\n}\n", s) + 3
F = original[s:e]

# --- Variant 1: renamed vulnerable variant ---
f1 = re.sub(r"\bonlyShims\b", "plainShims", F)
f1 = re.sub(r"\bexposeGlobals\b", "globalExports", f1)
f1 = re.sub(r"\bval\b", "entry", f1)
f1 = re.sub(r"\bexp\b", "expr", f1)
# the returned object key `exposeGlobals` is the public contract with callers: restore it
f1 = swap(f1, "globalExports: mapifyExposeGlobals(globalExports)", "exposeGlobals: mapifyExposeGlobals(globalExports)")
assert f1 != F
(CASE_DIR / "variant_vulnerable_01.js").write_text(original.replace(F, f1))

# --- Variant 2: structurally changed vulnerable variant ---
f2 = '''function separateExposeGlobals(shims) {
  var onlyShims = {}
    , exposeGlobals = {};

  Object.keys(shims).forEach(function (k) {
    copyEntry(k, shims[k], onlyShims, exposeGlobals);
  });

  return { shims: onlyShims, exposeGlobals: mapifyExposeGlobals(exposeGlobals) };
}

function copyEntry(k, val, onlyShims, exposeGlobals) {
  var exp = val && val.exports;

  if (exp && /^global\\:/.test(exp)) {
    exposeGlobals[k] = exp;
  } else {
    onlyShims[k] = val;
  }
}
'''
(CASE_DIR / "variant_vulnerable_02.js").write_text(original.replace(F, f2))

# --- Variant 3: transformed safe variant (real patched file, key test via a denylist Set) ---
PS = patched.index("function separateExposeGlobals(shims) {")
PE = patched.index("\n}\n", PS) + 3
PF = patched[PS:PE]
pf3 = swap(PF, "    if (k === '__proto__' || k === 'constructor') {\n      return;\n    }\n",
           "    if (UNSAFE_KEYS.indexOf(k) !== -1) {\n      return;\n    }\n")
v3 = patched.replace(PF, "var UNSAFE_KEYS = ['__proto__', 'constructor', 'prototype'];\n\n" + pf3)
(CASE_DIR / "variant_safe_01.js").write_text(v3)

(CASE_DIR / "benign_lookalike.js").write_text('''// Standalone example of the same shape: copy the keys of a trusted,
// application-owned defaults table (a literal in this file, never parsed
// from external input) into a fresh object.
var DEFAULTS = { color: 'blue', size: 'm' };

function withDefaults(overrides) {
  var out = {};
  Object.keys(DEFAULTS).forEach(function (k) { out[k] = DEFAULTS[k]; });
  Object.keys(overrides || {}).forEach(function (k) { out[k] = overrides[k]; });
  return out;
}

module.exports = withDefaults;
''')
