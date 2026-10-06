"""
Section 9 ground-truth test bundle: CASE-0152
(electron/electron, lib/browser/guest-window-manager.js mergeOptions,
CVE-2018-15685, CWE-1188 insecure default / security options not inherited).

Core vulnerable mechanism: `mergeOptions(child, parent)` copies a parent
window's options into a child window's options only for keys the child does
not already define (`if (key in child) continue`). A child window always has a
`webPreferences` object (mergeBrowserWindowOptions creates `{}` when
missing), so the parent's whole `webPreferences` object is skipped and none of
its settings (webSecurity, preload, custom flags, ...) reach a child that
supplies its own webPreferences, for example through window.open features.
Only the six keys in `inheritedWebPreferences` are re-applied afterwards. The
upstream fix lets `webPreferences` fall through the skip and merges the parent's
object into the child's existing one (`mergeOptions(child[key] || {}, value)`).

Sibling sites: none; mergeOptions is the single merge routine (its recursive
call and the two calls in mergeBrowserWindowOptions all go through it).

Every variant is the FULL real file. mergeOptions is module-private with three
call sites, so the renamed variant renames the function and all of them.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0152"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

s = original.index("const mergeOptions = function (child, parent, visited) {\n")
e = original.index("\n}\n", s) + len("\n}\n")
BLOCK = original[s:e]
assert original.count("mergeOptions") == 4


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


def swap(text, old, new, count=1):
    assert text.count(old) == count and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("mergeOptions", "combineOptions").replace("child", "target").replace("parent", "source") \
         .replace("visited", "seen").replace("value", "entry")
assert "hasProp.call(source, key)" in b and "if (key in target) continue" in b and "combineOptions({}, entry, seen)" in b
v1 = build(b)
for old in ("    mergeOptions(options, parentOptions)\n", "    mergeOptions(options.webPreferences, embedder.getLastWebPreferences())\n"):
    v1 = swap(v1, old, old.replace("mergeOptions", "combineOptions"))
assert v1.count("combineOptions") == 4 and "mergeOptions" not in v1
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
b = '''const mergeOptions = function (child, parent, visited) {
  // Check for circular reference.
  if (visited == null) visited = new Set()
  if (visited.has(parent)) return

  visited.add(parent)
  Object.keys(parent).forEach((key) => {
    if (key in child) return

    const value = parent[key]
    child[key] = typeof value === 'object' ? mergeOptions({}, value, visited) : value
  })
  visited.delete(parent)

  return child
}
'''
(CASE_DIR / "variant_vulnerable_02.js").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Generic deep merge: when both sides hold an object for a key the child
# already has, merge the parent's object INTO the child's (child values still
# win); upstream special-cases the key name 'webPreferences'.
b = swap(BLOCK, "    if (key in child) continue\n", '''    if (key in child) {
      const inner = parent[key]
      if (inner !== null && typeof inner === 'object' && child[key] !== null && typeof child[key] === 'object') {
        mergeOptions(child[key], inner, visited)
      }
      continue
    }
''')
(CASE_DIR / "variant_safe_01.js").write_text(build(b))

# --- Variant 4: benign structural look-alike ---
benign_source = '''"use strict";

const hasProp = {}.hasOwnProperty;

// Cosmetic defaults only (size, title); none of these keys is a security option.
const WINDOW_DEFAULTS = { width: 800, height: 600, title: "Untitled" };

/**
 * Same "copy a key only if the target does not define it" loop as the window
 * option merge, but applied to fixed cosmetic defaults, so skipping an
 * already-set key can never drop an inherited security setting.
 */
function applyWindowDefaults(options) {
  for (const key in WINDOW_DEFAULTS) {
    if (!hasProp.call(WINDOW_DEFAULTS, key)) continue;
    if (key in options) continue;
    options[key] = WINDOW_DEFAULTS[key];
  }
  return options;
}

module.exports = { applyWindowDefaults: applyWindowDefaults };
'''
assert "WINDOW_DEFAULTS" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0152.")
