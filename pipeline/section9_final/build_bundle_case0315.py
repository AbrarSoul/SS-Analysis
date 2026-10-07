r"""
Section 9 ground-truth test bundle: CASE-0315
(undertow-io/undertow, core/src/main/java/io/undertow/server/protocol/ajp/AjpRequestParser.java
decode, CVE-2024-6162, CWE-488 exposure of data element to wrong session).

Core vulnerable mechanism: `AjpRequestParser` keeps ONE `StringBuilder
decodeBuffer` as an instance field and passes it to `URLUtils.decode(...)` as the
working buffer (which does `setLength(0)` and then appends decoded characters).
A single parser instance serves every AJP connection handled by the
listener, on several IO threads at once, so two requests decoding a URL or
header concurrently write into the same builder: one request can receive the
characters of another request's URL/attribute (information disclosure across
sessions) or a corrupted string. The upstream fix removes the field and
allocates a fresh local `StringBuilder` per call.

Sibling sites: the same shared field is used for every decoded AJP string
(URL, query, attributes) because they all go through `decode`.

Verification (REAL library): the `decode` method plus the `decodeBuffer`
field declaration (when the file has one) are sliced from each full file
into a javac harness compiled against the real undertow-core 2.2.28 jar
(REAL `URLUtils.decode`), jboss-logging and xnio-api. Two threads each
decode a different 800-character percent-encoded string on the SAME parser
instance 20,000 times; any result that is not exactly its own expected
string is a cross-request leak/corruption. Vulnerable variants show
thousands of corrupted results (checked over three runs), patched/safe show
zero; single-threaded decoding is correct in every file.

Every variant is the FULL real file; `decode` keeps its name and signature
because the request parser calls it by name.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0315"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant (shared buffer field and decode's parameters renamed) ---
v1 = original
v1 = re.sub(r"\bdecodeBuffer\b", "scratchBuffer", v1)
v1 = swap(v1, "private String decode(String url, final boolean containsUrlCharacters) throws UnsupportedEncodingException {\n        if (doDecode && containsUrlCharacters) {",
          "private String decode(String rawValue, final boolean hasEscapes) throws UnsupportedEncodingException {\n        if (doDecode && hasEscapes) {")
v1 = swap(v1, "URLUtils.decode(url, this.encoding,", "URLUtils.decode(rawValue, this.encoding,")
v1 = swap(v1, "failedToDecodeURL(url, encoding, e);\n            }\n        }\n        return url;", "failedToDecodeURL(rawValue, encoding, e);\n            }\n        }\n        return rawValue;")
assert v1.count("scratchBuffer") == 4
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (lazy shared-buffer creation moved into a helper) ---
LAZY = '''                if(decodeBuffer == null) {
                    decodeBuffer = new StringBuilder();
                }
                return URLUtils.decode(url, this.encoding, slashDecodingFlag, false, decodeBuffer);
'''
v2 = swap(original, LAZY, "                return URLUtils.decode(url, this.encoding, slashDecodingFlag, false, sharedBuffer());\n")
v2 = swap(v2, "    private String decode(String url, final boolean containsUrlCharacters)",
          "    private StringBuilder sharedBuffer() {\n        if (decodeBuffer == null) {\n            decodeBuffer = new StringBuilder();\n        }\n        return decodeBuffer;\n    }\n\n    private String decode(String url, final boolean containsUrlCharacters)")
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the fresh buffer comes from a small static factory) ---
FRESH = "                final StringBuilder decodeBuffer = new StringBuilder();\n"
v3 = swap(patched, FRESH, "                final StringBuilder decodeBuffer = newDecodeBuffer();\n")
v3 = swap(v3, "    private String decode(String url, final boolean containsUrlCharacters)",
          "    private static StringBuilder newDecodeBuffer() {\n        return new StringBuilder();\n    }\n\n    private String decode(String url, final boolean containsUrlCharacters)")
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package io.undertow.server.protocol.ajp;

/**
 * Standalone example of the same shape: a lazily created shared StringBuilder
 * that is only ever used inside a synchronized method, so two callers can
 * never interleave their writes into it.
 */
class LockedJoiner {

    private StringBuilder buffer;

    synchronized String join(String a, String b) {
        if (buffer == null) {
            buffer = new StringBuilder();
        }
        buffer.setLength(0);
        buffer.append(a).append('/').append(b);
        return buffer.toString();
    }
}
''')
