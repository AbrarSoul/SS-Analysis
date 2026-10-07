r"""
Section 9 ground-truth test bundle: CASE-0312
(trpc/trpc, packages/server/src/unstable-core-do-not-import/http/formDataToObject.ts,
CVE-2025-68130, CWE-1321 improperly controlled modification of
object prototype attributes).

Core vulnerable mechanism: `formDataToObject` turns multipart/form-data keys
such as `user[name]` or `a.b.c` into a nested object by splitting each key on
`.`, `[` and `]` and walking the parts with the recursive `set`. `set` looks
each intermediate part up with `obj[key]` and only creates a container when it
is falsy, so for the part `__proto__` (or `constructor` followed by
`prototype`) `obj[key]` already exists (Object.prototype) and the walk
continues INTO it: a form field named `__proto__.polluted` executes
`Object.prototype.polluted = value`, polluting every object in the server
process (auth bypass / denial of service, depending on what reads the
polluted property). The upstream fix rejects the three dangerous parts,
uses `Object.hasOwn` instead of a truthiness test, and builds containers and
the result with `Object.create(null)`.

Sibling sites: the leaf assignment `obj[p] = value` in the same function is
the second sink (fixed with its own guard).

Verification: the full TypeScript file is type-stripped with node's own
stripTypeScriptTypes and loaded in a fresh node process per probe (so one
probe's pollution can't leak into the next). A real FormData is built with
the key `__proto__.polluted` (and, separately, `constructor.prototype.polluted`)
and passed to `formDataToObject`; the measurement is whether a brand-new `{}`
then has a `polluted` property. A control FormData with `user[name]`,
`user[tags]` repeated and `a.b.c` checks that ordinary nested parsing still
works in every file.

Every variant is the FULL real file; `formDataToObject` is the exported entry
point and keeps its name.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0312"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
patched = (CASE_DIR / "patched_source.ts").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant (helper, parameters and locals renamed; exported name kept) ---
v1 = original
for old, new in [("isNumberString", "isIndexKey"), ("set", "assignPath"), ("obj", "target"),
                 ("path", "segments"), ("newPath", "rest"), ("nextKey", "following"),
                 ("key", "head"), ("p", "leaf"), ("parts", "segs")]:
    v1 = re.sub(r"(?<![\w.])%s\b" % old, new, v1)
v1 = swap(v1, "[...path]", "[...segments]")
assert "assignPath(" in v1 and "isIndexKey" in v1 and "formDataToObject" in v1
(CASE_DIR / "variant_vulnerable_01.ts").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (container creation extracted into a helper) ---
BLOCK = '''    if (!obj[key]) {
      obj[key] = isNumberString(nextKey) ? [] : {};
    } else if (Array.isArray(obj[key]) && !isNumberString(nextKey)) {
      obj[key] = Object.fromEntries(Object.entries(obj[key]));
    }

    set(obj[key], newPath, value);
'''
v2 = swap(original, BLOCK, "    set(ensureChild(obj, key, nextKey), newPath, value);\n")
v2 = swap(v2, "function set(\n", '''function ensureChild(
  obj: Record<string, any>,
  key: string,
  nextKey: string,
): any {
  if (!obj[key]) {
    obj[key] = isNumberString(nextKey) ? [] : {};
  } else if (Array.isArray(obj[key]) && !isNumberString(nextKey)) {
    obj[key] = Object.fromEntries(Object.entries(obj[key]));
  }
  return obj[key];
}

function set(
''')
(CASE_DIR / "variant_vulnerable_02.ts").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the three-key test becomes a Set lookup) ---
OLD = '''const isUnsafeKey = (key: string) =>
  key === '__proto__' || key === 'constructor' || key === 'prototype';
'''
v3 = swap(patched, OLD, '''const UNSAFE_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const isUnsafeKey = (key: string) => UNSAFE_KEYS.has(key);
''')
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

(CASE_DIR / "benign_lookalike.ts").write_text('''/* Settings form parser: maps known form field names onto a Map, never onto an object. */

const KNOWN_FIELDS = ['name', 'email', 'locale'] as const;

export function readProfileForm(formData: FormData): Map<string, string> {
  const profile = new Map<string, string>();

  for (const [key, value] of formData.entries()) {
    const field = key.split(/[\\.\\[\\]]/).filter(Boolean).join('.');
    if ((KNOWN_FIELDS as readonly string[]).includes(field) && typeof value === 'string') {
      profile.set(field, value);
    }
  }

  return profile;
}
''')
