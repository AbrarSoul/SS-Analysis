r"""
Section 9 ground-truth test bundle: CASE-0339
(zadam/trilium, src/services/search/services/search.js highlightSearchResults,
CVE-2023-3067, CWE-79 cross-site scripting).

Core vulnerable mechanism: `highlightSearchResults` builds the HTML shown in
the note-search autocomplete from the note path title. It intends to strip
the characters `<`, `{` and `}` (which it later reuses as markers for `<b>`,
`<small>`) with `result.notePathTitle.replace('/[<\{\}]/g', '')`, but the
argument is a STRING literal containing a regex, not a RegExp, so nothing is
removed (it only matches that literal text). The note title therefore goes
straight into `highlightedNotePathTitle`, which the UI inserts as HTML: a note
titled `<img src=x onerror=alert(1)>` executes script for anyone who runs a
search that lists it (stored XSS). The upstream fix uses the regular
expression literal `/[<{}]/g`.

Sibling sites: the identical string-instead-of-regex mistake exists on the
search-token line just above (`token.replace('/[<\{\}]/g', '')`); the
recorded fix only corrects the note-path-title line (kept and flagged).

Verification: the full file is executed with a custom `require` returning
stubs for the trilium modules (`becca` with a note map, `utils.normalize`/
`escapeRegExp`/`escapeHtml`, `normalize-strings` as identity) and the file's
own `formatAttribute`; the function is reached through a harness-added
`module.exports.__highlight`. A search result whose title is
`<img src=x onerror=alert(1)>hello` and token `hello` is highlighted.
Vulnerable variants keep the raw `<img ...>` tag in
`highlightedNotePathTitle`; patched/safe remove the `<` (no tag), and a plain
title produces the same `<b>hello</b>` markup in every file.

Every variant is the FULL real file; `highlightSearchResults` is an internal
function called by name from `searchNotesForAutocomplete`.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0339"
original = (CASE_DIR / "vulnerable_source.js").read_text()
patched = (CASE_DIR / "patched_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


A = original.index("function highlightSearchResults(searchResults, highlightedTokens) {\n")
B = original.index("\nfunction formatAttribute(attr) {")
func = original[A:B]

# --- Variant 1: renamed vulnerable variant (parameters renamed inside the function only) ---
f1 = func
for old, new in [("searchResults", "foundResults"), ("highlightedTokens", "queryTokens")]:
    f1 = re.sub(r"(?<![\w.'\"])%s(?![\w'\"])" % old, new, f1)
assert "queryTokens.sort" in f1 and "foundResults" in f1
v1 = original.replace(func, f1)
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (the marker stripping moved into a helper; still a string pattern) ---
LINE = "        result.highlightedNotePathTitle = result.notePathTitle.replace('/[<\\{\\}]/g', '');\n"
v2 = swap(original, LINE, "        result.highlightedNotePathTitle = stripMarkers(result.notePathTitle);\n")
v2 = swap(v2, "function highlightSearchResults(searchResults, highlightedTokens) {\n",
          "function stripMarkers(text) {\n    return text.replace('/[<\\{\\}]/g', '');\n}\n\nfunction highlightSearchResults(searchResults, highlightedTokens) {\n")
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the regex stripping moved into a helper) ---
PLINE = "        result.highlightedNotePathTitle = result.notePathTitle.replace(/[<{}]/g, '');\n"
v3 = swap(patched, PLINE, "        result.highlightedNotePathTitle = stripMarkers(result.notePathTitle);\n")
v3 = swap(v3, "function highlightSearchResults(searchResults, highlightedTokens) {\n",
          "function stripMarkers(text) {\n    return text.replace(/[<{}]/g, '');\n}\n\nfunction highlightSearchResults(searchResults, highlightedTokens) {\n")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

(CASE_DIR / "benign_lookalike.js").write_text('''"use strict";

// Removes the LITERAL suffix ".md" from an imported file name. Using a string pattern here is intentional:
// the text to remove is a fixed literal, not a character class.
function stripMarkdownExtension(fileName) {
    return fileName.replace('.md', '');
}

module.exports = { stripMarkdownExtension };
''')
