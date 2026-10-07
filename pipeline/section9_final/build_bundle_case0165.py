"""
Section 9 ground-truth test bundle: CASE-0165
(formio/formio, src/util/util.js Utils.getUrlParams, CVE-2025-67718,
CWE-178 improper handling of case sensitivity / CWE-200 information exposure).

Located target: the `getUrlParams(url) {` method of the Utils object (the
locator's snippet is the object's closing `,`).

Core vulnerable mechanism: `getUrlParams` splits the request path into
alternating key/value segments (`/form/<id>/submission/<id>`) and stores them
as `urlParams[parts[a]]`, keeping the URL's original case. Express routes are
case-insensitive, so `/FORM/<id>/Submission/<id>` reaches the same handlers,
but code that reads `params.form` / `params.submission` (permission and
access checks) then finds nothing under the mixed-case key, so the checks that
depend on those parameters are skipped or applied to the wrong object,
exposing data. The upstream fix stores `parts[a].toLowerCase()`.

Sibling sites: none in this file (getUrlParams is the single URL splitter).

Every variant is the FULL real file. getUrlParams is a method of the exported
Utils object called by name from other modules, so the renamed variant keeps
the name and renames its parameter and locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0165"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

s = original.index("  getUrlParams(url) {\n")
e = original.index("\n  },\n", s) + len("\n  },\n")
BLOCK = original[s:e]
LOOP = '''    for (let a = 0; a < parts.length; a += 2) {
      urlParams[parts[a]] = parts[a + 1];
    }
'''
assert BLOCK.count(LOOP) == 1 and original.count("getUrlParams(url)") == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK
for old, new in (("urlParams", "pairs"), ("parsed", "parsedUrl"), ("parts", "segments"), ("url", "requestUrl"), ("a", "at")):
    # `debug.getUrlParams(...)` and the method name are property/method names, not locals
    b = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, b)
b = b.replace("  getrequestUrlParams(", "  getUrlParams(")
assert "  getUrlParams(requestUrl) {" in b and "debug.getUrlParams(parsedUrl);" in b
assert "pairs[segments[at]] = segments[at + 1];" in b and "nodeUrl.parse(requestUrl)" in b
assert "parsedUrl.pathname.split('/')" in b
(CASE_DIR / "variant_vulnerable_01.js").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(LOOP, '''    _.chunk(parts, 2).forEach(([key, value]) => {
      urlParams[key] = value;
    });
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Keys are lower-cased in one pass with lodash after the pairs are collected;
# upstream lower-cases each key inside the loop.
b = BLOCK.replace("    debug.getUrlParams(urlParams);\n    return urlParams;\n",
                  "    const normalized = _.mapKeys(urlParams, (value, key) => key.toLowerCase());\n    debug.getUrlParams(normalized);\n    return normalized;\n")
assert b != BLOCK
(CASE_DIR / "variant_safe_01.js").write_text(build(b))

# --- Variant 4: benign structural look-alike ---
benign_source = '''"use strict";

const KNOWN_KEYS = ["page", "size"];

/**
 * Same "split the path into key/value pairs" shape as getUrlParams, but only
 * two exact, developer-defined keys are ever read, and the values are coerced
 * to bounded integers, so the case of an unknown segment cannot hide or
 * select any protected object.
 */
function parsePaging(pathname) {
  const parts = pathname.split("/").slice(1);
  const out = { page: 1, size: 20 };
  for (let a = 0; a + 1 < parts.length; a += 2) {
    if (KNOWN_KEYS.indexOf(parts[a]) !== -1) {
      const n = parseInt(parts[a + 1], 10);
      if (n > 0 && n <= 100) {
        out[parts[a]] = n;
      }
    }
  }
  return out;
}

module.exports = { parsePaging: parsePaging };
'''
assert "KNOWN_KEYS" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0165.")
