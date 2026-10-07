"""
Section 9 ground-truth test bundle: CASE-0015
(apache/felix-dev, CVE-2025-25247, CWE-79 -- XSS via wrong-context output
encoding).

Core vulnerable mechanism: the "filter" template variable is populated with
Encode.forHtmlContent(filter) -- HTML-context escaping -- but the value is
actually interpolated into a <script> block in the rendered template. HTML
escaping does not neutralize JavaScript-breakout characters (quotes,
backslashes), so a crafted filter value can break out of the JS string
literal context. The real fix switches to Encode.forJavaScript(filter),
the context-correct encoder.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0015"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = (
    "        final String filter = request.getParameter(FILTER_PARAM);\n"
    "        writeJSON(w, reqInfo.service, request.getLocale(), filter);\n"
    "\n"
    "        // prepare variables\n"
    "        final RequestVariableResolver vars = this.getVariableResolver(request);\n"
    "        vars.put( \"bundlePath\", appRoot +  \"/\" + BundlesServlet.NAME + \"/\" );\n"
    "        vars.put( \"drawDetails\", String.valueOf(reqInfo.serviceRequested));\n"
    "        vars.put( \"__data__\", w.toString() );\n"
    "        vars.put( \"filter\", filter == null ? \"\" : Encode.forHtmlContent(filter) );\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

# --- Variant 1: renamed vulnerable variant ---
# Rename the local filter -> filterExpression throughout this method scope
# (3 uses). Same exact vulnerability: still Encode.forHtmlContent() used
# for a value rendered in a <script> context.
RENAMED_BLOCK = (
    "        final String filterExpression = request.getParameter(FILTER_PARAM);\n"
    "        writeJSON(w, reqInfo.service, request.getLocale(), filterExpression);\n"
    "\n"
    "        // prepare variables\n"
    "        final RequestVariableResolver vars = this.getVariableResolver(request);\n"
    "        vars.put( \"bundlePath\", appRoot +  \"/\" + BundlesServlet.NAME + \"/\" );\n"
    "        vars.put( \"drawDetails\", String.valueOf(reqInfo.serviceRequested));\n"
    "        vars.put( \"__data__\", w.toString() );\n"
    "        vars.put( \"filter\", filterExpression == null ? \"\" : Encode.forHtmlContent(filterExpression) );\n"
)
renamed_source = original.replace(VULNERABLE_BLOCK, RENAMED_BLOCK)
assert renamed_source != original
assert "filterExpression == null ? \"\" : Encode.forHtmlContent(filterExpression)" in renamed_source
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable. Same exact
# vulnerability (still the wrong encoder for a JS-context sink), no
# renaming.
STRUCTURAL_BLOCK = (
    "        final String filter = request.getParameter(FILTER_PARAM);\n"
    "        writeJSON(w, reqInfo.service, request.getLocale(), filter);\n"
    "\n"
    "        // prepare variables\n"
    "        final RequestVariableResolver vars = this.getVariableResolver(request);\n"
    "        vars.put( \"bundlePath\", appRoot +  \"/\" + BundlesServlet.NAME + \"/\" );\n"
    "        vars.put( \"drawDetails\", String.valueOf(reqInfo.serviceRequested));\n"
    "        vars.put( \"__data__\", w.toString() );\n"
    "        final String encodedFilter = filter == null ? \"\" : Encode.forHtmlContent(filter);\n"
    "        vars.put( \"filter\", encodedFilter );\n"
)
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
assert structural_source != original
assert "final String encodedFilter = filter == null ? \"\" : Encode.forHtmlContent(filter);" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (context-correct JS encoding) but
# via a separate helper method encodeForScriptContext(), instead of the
# real patch's inline Encode.forJavaScript(filter) ternary -- materially
# different structure, not byte-identical to the known fix.
SAFE_BLOCK = (
    "        final String filter = request.getParameter(FILTER_PARAM);\n"
    "        writeJSON(w, reqInfo.service, request.getLocale(), filter);\n"
    "\n"
    "        // prepare variables\n"
    "        final RequestVariableResolver vars = this.getVariableResolver(request);\n"
    "        vars.put( \"bundlePath\", appRoot +  \"/\" + BundlesServlet.NAME + \"/\" );\n"
    "        vars.put( \"drawDetails\", String.valueOf(reqInfo.serviceRequested));\n"
    "        vars.put( \"__data__\", w.toString() );\n"
    "        vars.put( \"filter\", encodeForScriptContext(filter) );\n"
)
assert SAFE_BLOCK != VULNERABLE_BLOCK
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
helper_method = (
    "\n"
    "    private static String encodeForScriptContext(String value) {\n"
    "        return value == null ? \"\" : Encode.forJavaScript(value);\n"
    "    }\n"
)
# insert the helper method right before the method containing the fix
anchor = "        vars.put( \"filter\", encodeForScriptContext(filter) );\n"
assert anchor in safe_source
# find the enclosing method's opening brace to insert the helper before it;
# simpler and equally valid: append helper right after this method's own
# closing brace, found via the next "    }\n" after the anchor.
idx = safe_source.index(anchor)
close_idx = safe_source.index("\n    }\n", idx)
insertion_point = close_idx + len("\n    }\n")
safe_source = safe_source[:insertion_point] + helper_method + safe_source[insertion_point:]
assert safe_source != original
assert "encodeForScriptContext" in safe_source
assert "Encode.forHtmlContent" not in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a new vars.put(...) call
# using Encode.forHtmlContent(...) -- the same "risky-looking" API as the
# vulnerable line -- but for a value that legitimately is rendered in an
# HTML text context elsewhere in the template, not inside a <script>
# block, so HTML-content encoding is the CORRECT choice here.
BENIGN_ADDITION = (
    '        // "statusMessage" is rendered as plain HTML text content in the\n'
    '        // template body, never inside a <script> block, so\n'
    '        // Encode.forHtmlContent() is the context-correct encoder here --\n'
    '        // unlike the "filter" variable above, which needed JS-context\n'
    '        // encoding instead.\n'
    '        final String statusMessage = request.getParameter( "statusMessage" );\n'
    '        vars.put( "statusMessage", statusMessage == null ? "" : Encode.forHtmlContent(statusMessage) );\n'
)
insertion_marker = "        vars.put( \"filter\", encodeForScriptContext(filter) );\n"
assert insertion_marker in safe_source
benign_source = safe_source.replace(insertion_marker, insertion_marker + BENIGN_ADDITION, 1)
assert benign_source != safe_source
assert "statusMessage" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)

print("Wrote 4 new samples for CASE-0015.")
