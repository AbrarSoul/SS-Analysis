"""
Section 9 ground-truth test bundle: CASE-0025
(Mintplex-Labs/anything-llm, CVE-2026-48116, CWE-77/CWE-88 -- argument
injection escalating to command execution).

The real patch fixes two near-identical sites (searchFilesWithRipgrepGlob
and searchWithRipgrep). This bundle targets searchWithRipgrep as the
representative instance (Section 9.3); the other is left untouched.

Core vulnerable mechanism: `pattern` (an LLM agent's user-controlled search
string) is pushed as a positional spawnSync argv entry with no `--`
separator and no rejection of values starting with "-". A pattern like
"--pre=/bin/sh" is parsed by ripgrep as an OPTION rather than a search
string -- ripgrep's --pre flag runs an arbitrary preprocessing command on
every searched file, giving full command execution.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0025"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = (
    "  // Pattern and path come last\n"
    "  args.push(pattern, searchPath);\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"
assert original.count(VULNERABLE_BLOCK) == 1

# --- Variant 1: renamed vulnerable variant ---
# Rename the function searchWithRipgrep -> runRipgrepSearch (definition +
# its one call site). Same exact vulnerability: still args.push(pattern,
# searchPath) with no "--" separator or rejection check.
DEF_LINE = "function searchWithRipgrep({\n"
CALL_SITE = "                  const results = searchWithRipgrep({\n"
assert DEF_LINE in original and CALL_SITE in original
renamed_source = original.replace(DEF_LINE, "function runRipgrepSearch({\n").replace(
    CALL_SITE, "                  const results = runRipgrepSearch({\n"
)
assert renamed_source != original
assert "function runRipgrepSearch(" in renamed_source
assert renamed_source.count("runRipgrepSearch") == 2
assert "searchWithRipgrep" not in renamed_source
assert "args.push(pattern, searchPath);" in renamed_source
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable / equivalent API-call
# formatting -- the trailing args are built into a named array and spread
# instead of passed directly. Same exact vulnerability (still no "--"
# separator, no rejection check), no renaming.
STRUCTURAL_BLOCK = (
    "  // Pattern and path come last\n"
    "  const trailingArgs = [pattern, searchPath];\n"
    "  args.push(...trailingArgs);\n"
)
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
assert structural_source != original
assert "const trailingArgs = [pattern, searchPath];" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (reject dash-prefixed patterns,
# separate positional args with "--") but the validation is factored into
# a reusable helper function instead of the real patch's inline if-check
# -- materially different structure, not byte-identical to the known fix.
SAFE_BLOCK = (
    "  // Pattern and path come last\n"
    "  rejectIfLooksLikeOption(pattern, \"search pattern\");\n"
    "  args.push(\"--\", pattern, searchPath);\n"
)
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
helper_function = (
    "function rejectIfLooksLikeOption(value, label) {\n"
    "  // Security: prevent argument injection where a value like\n"
    "  // \"--pre=/bin/sh\" would be parsed as a ripgrep option (capable of\n"
    "  // running an arbitrary command) instead of a plain search string.\n"
    "  if (typeof value === \"string\" && value.startsWith(\"-\")) {\n"
    "    throw new Error(`${label} must not start with '-'`);\n"
    "  }\n"
    "}\n"
    "\n"
)
anchor = "function searchWithRipgrep({\n"
assert anchor in safe_source
safe_source = safe_source.replace(anchor, helper_function + anchor, 1)
assert safe_source != original
assert "rejectIfLooksLikeOption" in safe_source
assert 'args.push("--", pattern, searchPath);' in safe_source
(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a function that also calls
# spawnSync() with an argv array containing a variable -- the same
# superficial shape as the vulnerable line -- but the value is always an
# internally-resolved path this module already validated, and `wc` (the
# invoked binary) has no dangerous "--pre"-style command-execution option,
# so argument injection here carries no command-execution risk.
BENIGN_ADDITION = (
    "\n"
    "function countLinesInFile(filePath) {\n"
    "  // filePath here is always an internally-resolved, already-validated\n"
    "  // path constructed by this module -- never a raw user-supplied\n"
    "  // search pattern -- and `wc` has no equivalent \"--pre\"-style\n"
    "  // command-execution option, so argument injection here carries no\n"
    "  // command-execution risk, unlike ripgrep's pattern argument above.\n"
    "  const result = spawnSync(\"wc\", [\"-l\", filePath], { encoding: \"utf-8\" });\n"
    "  return result.stdout;\n"
    "}\n"
)
anchor2 = "function rejectIfLooksLikeOption(value, label) {\n"
assert anchor2 in safe_source
benign_source = safe_source.replace(anchor2, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor2, 1)
assert benign_source != safe_source
assert "countLinesInFile" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)

print("Wrote 4 new samples for CASE-0025.")
