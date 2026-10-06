"""
Section 9 ground-truth test bundle: CASE-0038
(enchant97/note-mark, CVE-2024-41819, CWE-79 -- XSS via sanitize-before-
transform ordering bug).

Core vulnerable mechanism: render() sanitizes the raw MARKDOWN TEXT first
(DOMPurify.sanitize(content)), then converts the already-sanitized text to
HTML (markdown_to_html(content)). Sanitizing plain markdown text does
nothing to the HTML markup that markdown_to_html() subsequently generates
-- if that conversion renders attacker-controlled markdown into dangerous
HTML (e.g. via embedded raw HTML or crafted link/image syntax), the
resulting HTML is returned completely unsanitized. The real fix sanitizes
the HTML OUTPUT instead, after conversion.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0038"
original = (CASE_DIR / "vulnerable_source.ts").read_text()

VULNERABLE_BLOCK = (
    "function render(content: string): string {\n"
    "  content = DOMPurify.sanitize(content)\n"
    "  return markdown_to_html(content)\n"
    "}\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

# --- Variant 1: renamed vulnerable variant ---
# Rename render -> renderMarkdown, parameter content -> markdownSource
# (its one in-file default export continues to reference the function by
# value, not name, so no other call sites need updating). Same exact
# vulnerability: sanitization still happens before the markdown->HTML
# conversion.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    "function renderMarkdown(markdownSource: string): string {\n"
    "  markdownSource = DOMPurify.sanitize(markdownSource)\n"
    "  return markdown_to_html(markdownSource)\n"
    "}\n",
)
renamed_source = renamed_source.replace("export default render", "export default renderMarkdown")
assert renamed_source != original
assert "function renderMarkdown(markdownSource: string): string {" in renamed_source
assert "export default renderMarkdown" in renamed_source
(CASE_DIR / "variant_vulnerable_01.ts").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variables. Same exact
# vulnerability (sanitize-then-transform ordering unchanged), no
# renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    "function render(content: string): string {\n"
    "  const sanitizedInput = DOMPurify.sanitize(content)\n"
    "  const html = markdown_to_html(sanitizedInput)\n"
    "  return html\n"
    "}\n",
)
assert structural_source != original
assert "const sanitizedInput = DOMPurify.sanitize(content)" in structural_source
assert "const html = markdown_to_html(sanitizedInput)" in structural_source
(CASE_DIR / "variant_vulnerable_02.ts").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same fix idea as upstream (sanitize the HTML OUTPUT, not the markdown
# input) but via two named intermediate variables (rawHtml/safeHtml)
# instead of the real patch's direct reassignment-then-return -- not
# byte-identical to the known fix.
safe_source = original.replace(
    VULNERABLE_BLOCK,
    "function render(content: string): string {\n"
    "  const rawHtml = markdown_to_html(content)\n"
    "  const safeHtml = DOMPurify.sanitize(rawHtml)\n"
    "  return safeHtml\n"
    "}\n",
)
assert safe_source != original
assert "const rawHtml = markdown_to_html(content)" in safe_source
assert "const safeHtml = DOMPurify.sanitize(rawHtml)" in safe_source
(CASE_DIR / "variant_safe_01.ts").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a function that also
# sanitizes a string and then applies a further transformation to the
# result -- the same superficial "sanitize, then transform" shape as the
# vulnerable pattern -- but the subsequent transformation (toLowerCase/
# trim) can only remove or case-fold characters, never introduce new HTML
# markup, so sanitizing beforehand is safe here.
BENIGN_ADDITION = (
    "\n"
    "function normalizeSearchQuery(query: string): string {\n"
    "  // toLowerCase()/trim() only ever remove or case-fold characters --\n"
    "  // they cannot introduce new HTML markup the way markdown_to_html()\n"
    "  // can, so sanitizing before this transformation is safe, unlike\n"
    "  // render() above.\n"
    "  const sanitized = DOMPurify.sanitize(query)\n"
    "  return sanitized.toLowerCase().trim()\n"
    "}\n"
)
anchor = "function render(content: string): string {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "normalizeSearchQuery" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)

print("Wrote 4 new samples for CASE-0038.")
