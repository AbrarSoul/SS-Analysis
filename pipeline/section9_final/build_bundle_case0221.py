"""
Section 9 ground-truth test bundle: CASE-0221
(micronaut-projects/micronaut-core, http-netty/src/main/java/io/micronaut/http/
netty/NettyHttpHeaders.java NettyHttpHeaders(), CVE-2020-7611, CWE-444 /
HTTP header injection and response splitting).

Core vulnerable mechanism: the no-argument constructor creates the underlying
header store with `new DefaultHttpHeaders(false)`. The boolean is Netty's
`validate` flag; `false` turns OFF validation of header names and values, so
`add("X-Note", "a\\r\\nSet-Cookie: session=evil")` is stored as is and written to
the wire as two header lines. Any application that copies request data into a
response header (redirect targets, filenames, echoed values) then lets an
attacker split the response or smuggle headers. The upstream fix uses
`new DefaultHttpHeaders()`, whose default is `validate = true`.

Sibling sites: the two-argument constructor receives an already built
HttpHeaders and does not create one; the no-argument constructor is the only
place in the file that constructs DefaultHttpHeaders.

Verification: the no-argument constructor body is extracted verbatim from each
full file into a small class compiled with javac against the REAL Netty
4.1.45.Final jars (netty-codec-http and dependencies); a header value
containing CRLF and a header name containing CRLF are added, plus a normal
header.

Every variant is the FULL real file. NettyHttpHeaders is instantiated by name
across the module, so the class and its public constructors keep their
signatures; the renamed variant renames the parameters of the two-argument
constructor and introduces a local in the no-argument one.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0221"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


TWO = '''    public NettyHttpHeaders(io.netty.handler.codec.http.HttpHeaders nettyHeaders, ConversionService conversionService) {
        this.nettyHeaders = nettyHeaders;
        this.conversionService = conversionService;
    }
'''
ONE = '''    public NettyHttpHeaders() {
        this.nettyHeaders = new DefaultHttpHeaders(false);
        this.conversionService = ConversionService.SHARED;
    }
'''

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, TWO, '''    public NettyHttpHeaders(io.netty.handler.codec.http.HttpHeaders headers, ConversionService conversions) {
        this.nettyHeaders = headers;
        this.conversionService = conversions;
    }
''')
v1 = swap(v1, ONE, '''    public NettyHttpHeaders() {
        DefaultHttpHeaders created = new DefaultHttpHeaders(false);
        this.nettyHeaders = created;
        this.conversionService = ConversionService.SHARED;
    }
''')
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, ONE, '''    public NettyHttpHeaders() {
        this.nettyHeaders = newLenientNettyHeaders();
        this.conversionService = ConversionService.SHARED;
    }

    private static io.netty.handler.codec.http.HttpHeaders newLenientNettyHeaders() {
        return new DefaultHttpHeaders(false);
    }
''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, ONE, '''    public NettyHttpHeaders() {
        // validate = true: reject CR/LF and other illegal characters in names and values
        this.nettyHeaders = new DefaultHttpHeaders(true);
        this.conversionService = ConversionService.SHARED;
    }
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

BENIGN = '''package io.micronaut.http.netty;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Standalone example of the same shape (a constructor choosing a strictness
 * flag for an internal collection) where the flag only controls whether
 * duplicate keys are tolerated in a locally built settings map.
 */
public class SettingsMap {

    private final Map<String, String> values = new LinkedHashMap<>();
    private final boolean allowDuplicates;

    public SettingsMap() {
        this.allowDuplicates = false;
    }

    public void put(String key, String value) {
        if (!allowDuplicates && values.containsKey(key)) {
            throw new IllegalArgumentException("duplicate key " + key);
        }
        values.put(key, value);
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN)
