"""
Section 9 ground-truth test bundle: CASE-0030
(mongodb/js-bson, CVE-2018-13863, ReDoS -- unbounded-length input to a
backtracking-prone regex).

Core vulnerable mechanism: Decimal128.fromString() matches the caller-
supplied string against PARSE_STRING_REGEXP/PARSE_INF_REGEXP/
PARSE_NAN_REGEXP with no upper bound on the string's length. Because these
regexes are prone to catastrophic backtracking, an attacker-supplied long
string drives matching time up exponentially -- a denial of service. The
real fix adds a simple length guard (reject strings >= 7000 chars) before
any matching is attempted, bounding worst-case backtracking time.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0030"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = (
    "  // Trim the string\n"
    "  string = string.trim();\n"
    "\n"
    "  // Results\n"
    "  var stringMatch = string.match(PARSE_STRING_REGEXP);\n"
    "  var infMatch = string.match(PARSE_INF_REGEXP);\n"
    "  var nanMatch = string.match(PARSE_NAN_REGEXP);\n"
    "\n"
    "  // Validate the string\n"
    "  if ((!stringMatch && !infMatch && !nanMatch) || string.length === 0) {\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"
DOWNSTREAM_USE = "  if (stringMatch && stringMatch[4] && stringMatch[2] === undefined) {\n"
assert DOWNSTREAM_USE in original

# --- Variant 1: renamed vulnerable variant ---
# Rename stringMatch/infMatch/nanMatch -> parsedStringMatch/
# parsedInfMatch/parsedNanMatch (all 5 occurrences across both blocks).
# Same exact vulnerability: still no length guard before matching.
renamed_source = original.replace(VULNERABLE_BLOCK, VULNERABLE_BLOCK.replace(
    "stringMatch", "parsedStringMatch").replace("infMatch", "parsedInfMatch").replace("nanMatch", "parsedNanMatch")
)
renamed_source = renamed_source.replace(DOWNSTREAM_USE, DOWNSTREAM_USE.replace("stringMatch", "parsedStringMatch"))
assert renamed_source != original
assert "var parsedStringMatch = string.match(PARSE_STRING_REGEXP);" in renamed_source
assert "parsedStringMatch && parsedStringMatch[4]" in renamed_source
assert "var stringMatch" not in renamed_source
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: safe statement reordering / equivalent formatting -- the
# three independent var declarations are combined into one
# comma-separated statement. Same exact vulnerability (still no length
# guard), no renaming.
STRUCTURAL_BLOCK = (
    "  // Trim the string\n"
    "  string = string.trim();\n"
    "\n"
    "  // Results\n"
    "  var stringMatch = string.match(PARSE_STRING_REGEXP),\n"
    "      infMatch = string.match(PARSE_INF_REGEXP),\n"
    "      nanMatch = string.match(PARSE_NAN_REGEXP);\n"
    "\n"
    "  // Validate the string\n"
    "  if ((!stringMatch && !infMatch && !nanMatch) || string.length === 0) {\n"
)
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
assert structural_source != original
assert "var stringMatch = string.match(PARSE_STRING_REGEXP),\n" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same defense-in-depth idea as upstream (reject overly-long input before
# matching) but with a different threshold (5000, not 7000), a strict
# ">" comparison instead of ">=", and a differently-worded error message
# -- not byte-identical to the known fix.
SAFE_BLOCK = (
    "  // Trim the string\n"
    "  string = string.trim();\n"
    "\n"
    "  // Naively prevent against REDOS attacks.\n"
    "  if (string.length > 5000) {\n"
    "    throw new Error('Decimal128 string input is too long to parse safely');\n"
    "  }\n"
    "\n"
    "  // Results\n"
    "  var stringMatch = string.match(PARSE_STRING_REGEXP);\n"
    "  var infMatch = string.match(PARSE_INF_REGEXP);\n"
    "  var nanMatch = string.match(PARSE_NAN_REGEXP);\n"
    "\n"
    "  // Validate the string\n"
    "  if ((!stringMatch && !infMatch && !nanMatch) || string.length === 0) {\n"
)
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
assert safe_source != original
assert "string.length > 5000" in safe_source
assert "too long to parse safely" in safe_source
(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a function that also calls
# a regex .test() on an unbounded-length string with no length guard --
# the same superficial shape as the vulnerable pattern -- but the regex
# (a simple anchored character class) has no nested quantifiers or
# ambiguous alternation, so it cannot catastrophically backtrack
# regardless of input length.
BENIGN_ADDITION = (
    "\n"
    "Decimal128.looksLikeHexString = function(string) {\n"
    "  // /^[0-9a-fA-F]+$/ has no nested quantifiers or ambiguous\n"
    "  // alternation, so unlike PARSE_STRING_REGEXP its matching time is\n"
    "  // linear in the input length regardless of how long the string is --\n"
    "  // no length guard is needed here.\n"
    "  return /^[0-9a-fA-F]+$/.test(string);\n"
    "};\n"
)
anchor = "Decimal128.fromString = function(string) {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "looksLikeHexString" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)

print("Wrote 4 new samples for CASE-0030.")
