"""
Section 9 ground-truth test bundle: CASE-0040
(jasonraimondi/url-to-png, CVE-2024-39918, CWE-22 -- path traversal via
partially-sanitized cache filename).

Core vulnerable mechanism: imageId (used as a cache filename/key for a
rendered screenshot) is built by concatenating a slugified URL with
configToString(params) -- the query-parameter-derived config suffix --
which is NOT slugified. If params (derived from user-supplied query
string values) contains path-traversal sequences or other filesystem-
special characters that configToString() passes through, imageId can
contain "../"-style sequences, letting a crafted request read or write
outside the intended cache directory when imageId is later used to build
a file path. The real fix also slugifies the configToString(params)
portion.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0040"
original = (CASE_DIR / "vulnerable_source.ts").read_text()

VULNERABLE_BLOCK = (
    "    const date = new Date();\n"
    "    const dateString = date.toLocaleDateString().replace(/\\//g, \"-\");\n"
    "    const imageId = dateString + \".\" + slugify(validData.url) + configToString(params);\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

# --- Variant 1: renamed vulnerable variant ---
# Rename imageId -> cacheFileId, dateString -> formattedDate within this
# scope (checking the one downstream use of imageId at c.set("imageId",
# imageId) -- the string literal "imageId" there is the cache/context KEY
# NAME, not this local variable, and must not be renamed). Same exact
# vulnerability: the configToString(params) portion is still unslugified.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    "    const date = new Date();\n"
    "    const formattedDate = date.toLocaleDateString().replace(/\\//g, \"-\");\n"
    "    const cacheFileId = formattedDate + \".\" + slugify(validData.url) + configToString(params);\n",
)
renamed_source = renamed_source.replace(
    "    c.set(\"input\", validData);\n"
    "    c.set(\"imageId\", imageId);\n",
    "    c.set(\"input\", validData);\n"
    "    c.set(\"imageId\", cacheFileId);\n",
)
assert renamed_source != original
assert "const cacheFileId = formattedDate + \".\" + slugify(validData.url) + configToString(params);" in renamed_source
assert "c.set(\"imageId\", cacheFileId);" in renamed_source
(CASE_DIR / "variant_vulnerable_01.ts").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variables for the URL slug
# and config suffix. Same exact vulnerability (configPart still
# unslugified), no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    "    const date = new Date();\n"
    "    const dateString = date.toLocaleDateString().replace(/\\//g, \"-\");\n"
    "    const urlSlug = slugify(validData.url);\n"
    "    const configPart = configToString(params);\n"
    "    const imageId = dateString + \".\" + urlSlug + configPart;\n",
)
assert structural_source != original
assert "const configPart = configToString(params);" in structural_source
assert "const imageId = dateString + \".\" + urlSlug + configPart;" in structural_source
(CASE_DIR / "variant_vulnerable_02.ts").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (no unslugified, potentially
# path-traversal-bearing characters can survive into imageId) but via a
# single slugify() call wrapping the URL and config parts concatenated
# together, instead of the real patch's two separate slugify() calls --
# materially different structure, not byte-identical to the known fix.
safe_source = original.replace(
    VULNERABLE_BLOCK,
    "    const date = new Date();\n"
    "    const dateString = date.toLocaleDateString().replace(/\\//g, \"-\");\n"
    "    const imageId = dateString + \".\" + slugify(validData.url + configToString(params));\n",
)
assert safe_source != original
assert 'slugify(validData.url + configToString(params))' in safe_source
assert '+ configToString(params);' not in safe_source
(CASE_DIR / "variant_safe_01.ts").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a function that also calls
# configToString(params) unslugified -- the same superficial shape as the
# vulnerable pattern -- but the returned string is only ever used as a
# log/analytics label, never as a filesystem path or cache key, so
# unsanitized characters here carry no path-traversal risk.
BENIGN_ADDITION = (
    "\n"
    "function buildAnalyticsLabel(params: URLSearchParams): string {\n"
    "  // The returned label is only ever used as a log/analytics event\n"
    "  // label string, never as a filesystem path or cache key, so\n"
    "  // unslugified characters here carry no path-traversal risk, unlike\n"
    "  // imageId above.\n"
    "  return \"screenshot-request:\" + configToString(params);\n"
    "}\n"
)
anchor = "export function handleExtractQueryParamsMiddleware(encryptionService?: StringEncrypter) {"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "buildAnalyticsLabel" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)

print("Wrote 4 new samples for CASE-0040.")
