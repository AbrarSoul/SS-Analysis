"""
Section 9 ground-truth test bundle: CASE-0082
(absolunet/kafe, CVE-2020-7761, ReDoS in validate.isEmail).

Core vulnerable mechanism: the email regex
`/^\\w+([\\.\\+-]?\\w+)*@\\w+([\\.-]?\\w+)*(\\.\\w{2,3})+$/` nests `\\w+` inside a
repeated group whose separator is OPTIONAL, so a long run of word
characters can be split between the inner and outer quantifiers in
exponentially many ways. A non-matching input such as 'a' * N + '!'
forces the engine to try them all (catastrophic backtracking, CPU
denial of service). The upstream fix swaps in an RFC 5322-style regex
without the ambiguous nested quantifiers.

Every variant is the FULL real file with the isEmail function replaced.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0082"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.js").read_text().splitlines()) + "\n"

START = "\tvalidate.isEmail = function(str) {"
s = original.index(START)
e = original.index("\n\t};\n", s) + len("\n\t};\n")
BLOCK = original[s:e]
assert original.count(START) == 1
assert r"(/^\w+([\.\+-]?\w+)*@" in BLOCK

def build(new_block, text=None):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]

# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("validate.isEmail = function(str) {", "validate.isEmailAddress = function(input) {")
b = re.sub(r"\bstr\b", "input", b)
renamed = build(b)
renamed = re.sub(r"\bisEmail\b", "isEmailAddress", renamed)  # doc comments too
assert "isEmail(" not in renamed and "isEmail =" not in renamed
assert r"\w+([\.\+-]?\w+)*@" in renamed
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed)

# --- Variant 2: structurally changed vulnerable variant ---
STRUCT = """\tvalidate.isEmail = function(str) {
\t\tvar trimmedSpaces = str.replace(/^\\s*|\\s*$/g, '');
\t\tvar trimmed = trimmedSpaces.replace(/^\\t*|\\t*$/g, '');
\t\tvar emailPattern = /^\\w+([\\.\\+-]?\\w+)*@\\w+([\\.-]?\\w+)*(\\.\\w{2,3})+$/;
\t\treturn emailPattern.test(trimmed);
\t};
"""
(CASE_DIR / "variant_vulnerable_02.js").write_text(build(STRUCT))

# --- Variant 3: transformed safe variant ---
# Length cap (RFC 5321 max 254) plus a regex whose every quantified
# element is separated by a mandatory, non-overlapping delimiter, so
# there is exactly one way to match and matching is linear. Different
# from the upstream RFC 5322 regex.
SAFE = """\tvalidate.isEmail = function(str) {
\t\tstr = str.replace(/^\\s*|\\s*$/g, '');
\t\tstr = str.replace(/^\\t*|\\t*$/g, '');
\t\tif (str.length > 254) {
\t\t\treturn false;
\t\t}
\t\treturn (/^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+$/.test(str));
\t};
"""
(CASE_DIR / "variant_safe_01.js").write_text(build(SAFE))

# --- Variant 4: benign structural look-alike ---
BENIGN = """/* Same nested-quantifier shape as the vulnerable email regex, but the
 * input length is capped at 10 characters before matching, so the worst
 * case is bounded and negligible; it is not a denial-of-service vector. */
var codes = {};

codes.isShortCode = function(str) {
\tif (typeof str !== 'string' || str.length > 10) {
\t\treturn false;
\t}
\treturn (/^\\w+([.-]?\\w+)*$/.test(str));
};
"""
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
print("Wrote 4 new samples for CASE-0082.")
