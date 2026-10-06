"""
Section 9 ground-truth test bundle: CASE-0070
(OpenRefine/OpenRefine, CVE-2024-47880, CWE-348/CWE-79 reflected XSS via
client-controlled response Content-Type).

Core vulnerable mechanism: `doPost()` lets the CLIENT choose the response
`Content-Type` header via a request parameter
(`params.get("contentType")`), falling back to the exporter's own
content type only if the client didn't supply one. A client exporting
project data can set `contentType=text/html`; if any exported cell value
contains attacker-influenced markup, the browser -- told by the server
that this response IS html -- renders and executes it, a reflected XSS.
The fix removes the client-controlled override entirely (always uses
`exporter.getContentType()`) and adds a `Content-Security-Policy` header
as defense-in-depth against script execution even if the content type
ever legitimately ends up being HTML-like.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0070"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = '''            String contentType = params.get("contentType");
            if (contentType == null) {
                contentType = exporter.getContentType();
            }
            response.setHeader("Content-Type", contentType);'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename contentType -> responseContentType. Same exact
# client-controlled Content-Type override.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''            String responseContentType = params.get("contentType");
            if (responseContentType == null) {
                responseContentType = exporter.getContentType();
            }
            response.setHeader("Content-Type", responseContentType);''',
)
assert "String responseContentType = params.get(\"contentType\");" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: equivalent conditional rewriting (ternary instead of
# if-null-assign). Same exact client-controlled override, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''            String requestedContentType = params.get("contentType");
            String contentType = requestedContentType != null ? requestedContentType : exporter.getContentType();
            response.setHeader("Content-Type", contentType);''',
)
assert structural_source != original
assert "String requestedContentType = params.get(\"contentType\");" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (never let the client dictate the response
# Content-Type) but a materially different technique: keeps ACCEPTING a
# client-supplied contentType parameter, but only honors it if it appears
# on a small allowlist of safe, non-HTML MIME types -- otherwise falls
# back to the exporter's own type -- instead of the real patch's approach
# of removing the client override entirely. Genuinely prevents the
# text/html XSS vector while still allowing a legitimate client override
# for e.g. content negotiation, different design tradeoff from the real
# patch.
SAFE_SOURCE = '''import java.util.Set;
import java.util.Arrays;
import java.util.HashSet;

public class ContentTypeResolver {

    private static final Set<String> SAFE_OVERRIDE_CONTENT_TYPES = new HashSet<>(Arrays.asList(
        "text/csv", "text/tab-separated-values", "application/json", "application/octet-stream"
    ));

    public static String resolveContentType(String requestedContentType, String exporterDefaultType) {
        if (requestedContentType != null && SAFE_OVERRIDE_CONTENT_TYPES.contains(requestedContentType)) {
            return requestedContentType;
        }
        return exporterDefaultType;
    }
}
'''
(CASE_DIR / "variant_safe_01.java").write_text(SAFE_SOURCE)
assert "SAFE_OVERRIDE_CONTENT_TYPES" in SAFE_SOURCE
assert "text/html" not in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (read a "contentType"-style parameter, fall back to
# a default if absent, and set it as a response header) but this sibling
# only ever handles requests to a fixed, admin-only diagnostics endpoint
# where the "contentType" parameter is validated ELSEWHERE, upstream, by
# a servlet filter that already restricts it to "text/plain" before this
# method is ever reached -- so even reading the raw parameter value here
# carries no XSS risk, unlike doPost()'s direct, unvalidated use.
BENIGN_SOURCE = '''public class DiagnosticsCommand {

    // This endpoint's filter chain (AdminOnlyContentTypeFilter, registered
    // in web.xml) rejects any request whose "contentType" parameter is not
    // exactly "text/plain" BEFORE this method ever runs -- so by the time
    // this code executes, the parameter is already guaranteed safe.
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String contentType = request.getParameter("contentType");
        if (contentType == null) {
            contentType = "text/plain";
        }
        response.setHeader("Content-Type", contentType);
        response.setHeader("X-Diagnostics", "ok");
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN_SOURCE)
assert "exporter" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0070.")
