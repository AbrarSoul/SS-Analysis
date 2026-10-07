"""
Section 9 ground-truth test bundle: CASE-0024
(KartikTalwar/gmail.js, CVE-2016-1000228, code injection via new Function()
-- functionally equivalent to eval()).

The real patch fixes three near-identical sites. This bundle targets the
first occurrence (line 894) as the representative instance (Section 9.3);
the other two are left untouched in every variant.

Core vulnerable mechanism: `data` (extracted from a parsed Gmail-internal
API response) is concatenated into a code string and executed via
`new Function("\"use strict\"; return " + data)` -- dynamically evaluating
it as arbitrary JavaScript, exactly like eval(). The real fix uses
JSON.parse(data) instead, which only ever produces a data value, never
executes code.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0024"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = (
    "                var get_data = new Function(\"\\\"use strict\\\"; return \" + data);\n"
    "                realData = get_data();\n"
    "\n"
    "                parsedResponse.push(realData);\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"
assert original.count("new Function(") == 3, "expected exactly 3 occurrences total"

# --- Variant 1: renamed vulnerable variant ---
# Rename get_data -> dataFn, realData -> parsedData within this local
# scope. Same exact vulnerability: still new Function() dynamically
# executing code built from response data.
RENAMED_BLOCK = (
    "                var dataFn = new Function(\"\\\"use strict\\\"; return \" + data);\n"
    "                var parsedData = dataFn();\n"
    "\n"
    "                parsedResponse.push(parsedData);\n"
)
renamed_source = original.replace(VULNERABLE_BLOCK, RENAMED_BLOCK)
assert renamed_source != original
assert "var dataFn = new Function(" in renamed_source
assert "parsedResponse.push(parsedData);" in renamed_source
# the other two sibling vulnerable sites (lines 1689, 1939) untouched
assert renamed_source.count("new Function(") == 3
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable -- the code string is
# built separately before being passed to new Function(). Same exact
# vulnerability, no renaming.
STRUCTURAL_BLOCK = (
    "                var codeString = \"\\\"use strict\\\"; return \" + data;\n"
    "                var get_data = new Function(codeString);\n"
    "                realData = get_data();\n"
    "\n"
    "                parsedResponse.push(realData);\n"
)
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
assert structural_source != original
assert "var codeString = " in structural_source
assert structural_source.count("new Function(") == 3
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same fix idea as upstream (JSON.parse instead of dynamic code execution)
# but with a differently-named intermediate variable (parsedJson vs the
# real patch's json) and an extra assignment step -- not byte-identical to
# the known fix.
SAFE_BLOCK = (
    "                var parsedJson = JSON.parse(data);\n"
    "                realData = parsedJson;\n"
    "\n"
    "                parsedResponse.push(realData);\n"
)
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
assert safe_source != original
assert "JSON.parse(data)" in safe_source
# only the two OTHER sibling sites should still use new Function()
assert safe_source.count("new Function(") == 2
(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a function that also calls
# new Function() -- the same superficial API surface as the vulnerable
# line -- but with a hardcoded, compile-time-constant code string, never
# derived from network response data, so it cannot execute
# attacker-controlled code.
BENIGN_ADDITION = (
    "\n"
    "    function makeIdentityFn() {\n"
    "        // The code string here is a fixed, hardcoded literal -- never\n"
    "        // derived from network response data -- so new Function() here\n"
    "        // cannot execute attacker-controlled code, unlike the dynamic\n"
    "        // response-parsing sites above.\n"
    "        return new Function(\"x\", \"return x;\");\n"
    "    }\n"
)
anchor = "var Gmail_ = function(localJQuery) {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, anchor + BENIGN_ADDITION, 1)
assert benign_source != safe_source
assert "makeIdentityFn" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)

print("Wrote 4 new samples for CASE-0024.")
