"""
Section 9 ground-truth test bundle: CASE-0302
(theonedev/onedev, server-core/src/main/java/io/onedev/server/web/resource/
ArtifactResource.java newResourceResponse, CVE-2022-39207,
CWE-79/CWE-732 stored cross-site scripting through served build artifacts).

Core vulnerable mechanism: OneDev serves files a build produced (build
"artifacts": test reports, coverage HTML, uploaded files) from the OneDev
origin itself. The vulnerable code sets the response `Content-Type` by SNIFFING
the file (`ContentDetector.detectMediaType(is, artifactPath)`), so an
artifact whose content or extension looks like HTML/SVG is served as
`text/html` (or `image/svg+xml`) inline. Anyone able to run a build (a
contributor, or a pull request from a fork through CI) can publish
`report.html` containing `<script>` and share its URL: when a maintainer
opens it, the script runs in the OneDev origin with the maintainer's
session (stored XSS -> account takeover, token theft, repository changes).
The upstream fix stops trusting the content: it always answers with
`application/octet-stream` and adds `X-Content-Type-Options: nosniff`, so
the browser downloads the artifact instead of rendering it.

Sibling sites: this is the only response builder for artifact downloads.

Verification: the response-construction span
(`ResourceResponse response = new ResourceResponse();` through
`response.disableCaching();`) is extracted verbatim from each full file and
compiled with javac inside a harness with small stand-ins for the Wicket
`ResourceResponse` (recording `setContentType`/headers) and for OneDev's
`ContentDetector` (whose stand-in detects `text/html` from a `<html`/
`<script` signature or `.html` extension, the behaviour the vulnerable code
relies on) and for tika's `MimeTypes.OCTET_STREAM`. A real temp file
`evil.html` containing `<html><script>alert(1)</script></html>` is passed
through the span: the recorded content type and `X-Content-Type-Options`
header are compared.

Every variant is the FULL real file. `newResourceResponse` overrides the
Wicket resource hook by name, so its name/signature are kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0302"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original

T = "\t"
SNIFF = (T * 2 + "try (InputStream is = new BufferedInputStream(new FileInputStream(artifactFile))) {\n" +
         T * 3 + "response.setContentType(ContentDetector.detectMediaType(is, artifactPath).toString());\n" +
         T * 2 + "} catch (Exception e) {\n" +
         T * 3 + "throw new RuntimeException(e);\n" +
         T * 2 + "}\n")


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


assert original.count(SNIFF) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, SNIFF, (T * 2 + "try (InputStream in = new BufferedInputStream(new FileInputStream(artifactFile))) {\n" +
                            T * 3 + "response.setContentType(ContentDetector.detectMediaType(in, artifactPath).toString());\n" +
                            T * 2 + "} catch (Exception ex) {\n" +
                            T * 3 + "throw new RuntimeException(ex);\n" + T * 2 + "}\n"))
v1 = v1.replace("ResourceResponse response = new ResourceResponse();", "ResourceResponse downloadResponse = new ResourceResponse();")
v1 = re.sub(r"\bresponse\b(?=[.,);])", "downloadResponse", v1)
assert not re.search(r"\bresponse\b", v1)
assert "downloadResponse.setContentType" in v1
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, SNIFF, (T * 2 + "java.util.function.Supplier<String> contentTypeOf = () -> {\n" +
                            T * 3 + "try (InputStream is = new BufferedInputStream(new FileInputStream(artifactFile))) {\n" +
                            T * 4 + "return ContentDetector.detectMediaType(is, artifactPath).toString();\n" +
                            T * 3 + "} catch (Exception e) {\n" +
                            T * 4 + "throw new RuntimeException(e);\n" +
                            T * 3 + "}\n" + T * 2 + "};\n" +
                            T * 2 + "response.setContentType(contentTypeOf.get());\n"))
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file, constants for the fixed values) ---
PATCHED_SPAN = (T * 2 + 'response.getHeaders().addHeader("X-Content-Type-Options", "nosniff");\n' +
                T * 2 + "response.setContentType(MimeTypes.OCTET_STREAM);\n")
assert patched.count(PATCHED_SPAN) == 1
v3 = swap(patched, PATCHED_SPAN, (T * 2 + "response.getHeaders().addHeader(NO_SNIFF_HEADER, NO_SNIFF_VALUE);\n" +
                                  T * 2 + "response.setContentType(SAFE_DOWNLOAD_TYPE);\n"))
v3 = swap(v3, "public class ArtifactResource extends AbstractResource {\n",
          ("public class ArtifactResource extends AbstractResource {\n\n" +
           T + "// artifacts are untrusted build output: never let a browser render them inline\n" +
           T + 'private static final String NO_SNIFF_HEADER = "X-Content-Type-Options";\n\n' +
           T + 'private static final String NO_SNIFF_VALUE = "nosniff";\n\n' +
           T + "private static final String SAFE_DOWNLOAD_TYPE = MimeTypes.OCTET_STREAM;\n"))
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package io.onedev.server.web.resource;

/**
 * Standalone example of the same shape: pick a Content-Type from the file
 * extension for a static, application-owned icon set (files shipped in the
 * jar, never user-supplied), which is safe to render inline.
 */
class BundledIconTypes {

    static String contentTypeOf(String iconName) {
        return iconName.endsWith(".svg") ? "image/svg+xml" : "image/png";
    }
}
''')
