r"""
Section 9 ground-truth test bundle: CASE-0320
(vercel/ms, index.js parse, CVE-2017-20162, CWE-1333 inefficient regular
expression complexity / ReDoS).

Core vulnerable mechanism: `ms(str)` parses a duration with the regular
expression `^((?:\d+)?\.?\d+) *(milliseconds?|...|y)?$`. The leading
`(?:\d+)?\.?\d+` lets a digit run be split between the optional `\d+` and
the mandatory `\d+` in many ways, so an input of thousands of digits
followed by a character that cannot match makes the engine backtrack
quadratically. The only guard was a length cap of 10,000, which still allows
roughly 0.2 s of blocked event loop per call (measured here for one 9,991-character input, growing quadratically) (denial of service for any service
that passes user input to `ms`). The upstream fix lowers the cap to 100
characters, bounding the work. (The regex itself is unchanged, so the fix is
a mitigation by input size, not a rewrite of the pattern.)

Sibling sites: `fmtShort`/`fmtLong` format numbers and take no
user-controlled strings.

Verification: each full file is loaded with node `require` and called as
`ms('1'.repeat(9990) + 'x')` (a 9,991-character digit run that cannot
match), timing the call; and `ms('2 days')` / `ms('1.5h')` / `ms('100')` are
checked for normal results. Vulnerable variants take ~0.2 s (>50 ms) for
the long input (the patched cap returns undefined immediately, under 5 ms);
normal parsing is identical in all files.

Every variant is the FULL real file; the exported function is the module API.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0320"
original = (CASE_DIR / "vulnerable_source.js").read_text()
patched = (CASE_DIR / "patched_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


PA = original.index("function parse(str) {\n")
PB = original.index("\n}\n", PA) + 3
func = original[PA:PB]

# --- Variant 1: renamed vulnerable variant (parse function, parameter and locals renamed) ---
f1 = func
for old, new in [("parse", "parseDuration"), ("str", "text"), ("match", "found"), ("n", "amount"), ("type", "unit")]:
    f1 = re.sub(r"(?<![\w.'\"])%s(?![\w'\"])" % old, new, f1)
assert "parseFloat(found[1])" in f1 and "case 'years':" in f1 and "return amount * y;" in f1
v1 = original.replace(func, f1)
v1 = swap(v1, "    return parse(val);\n", "    return parseDuration(val);\n")
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (regex and cap hoisted to module constants) ---
RE = "/^((?:\\d+)?\\.?\\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|years?|yrs?|y)?$/i"
assert func.count(RE) == 1
f2 = swap(func, "  if (str.length > 10000) {\n", "  if (str.length > MAX_INPUT_LENGTH) {\n")
f2 = swap(f2, "  var match = " + RE + ".exec(\n    str\n  );\n", "  var match = DURATION_PATTERN.exec(str);\n")
v2 = original.replace(func, "var MAX_INPUT_LENGTH = 10000;\nvar DURATION_PATTERN = " + RE + ";\n\n" + f2)
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the cap becomes a named constant) ---
v3 = swap(patched, "  if (str.length > 100) {\n", "  if (str.length > MAX_INPUT) {\n")
v3 = swap(v3, "function parse(str) {\n", "var MAX_INPUT = 100;\n\nfunction parse(str) {\n")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

(CASE_DIR / "benign_lookalike.js").write_text('''/**
 * Parse a CSS-style hex colour such as "#abc" or "#aabbcc" into [r, g, b].
 * The pattern has no nested or overlapping quantifiers and only accepts 3 or
 * 6 hex digits, so matching is linear and bounded regardless of input.
 */
module.exports = function parseHexColor(str) {
  var match = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(String(str));
  if (!match) {
    return;
  }
  var hex = match[1];
  if (hex.length === 3) {
    hex = hex.replace(/./g, '$&$&');
  }
  return [0, 2, 4].map(function(i) {
    return parseInt(hex.slice(i, i + 2), 16);
  });
};
''')
