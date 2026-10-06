"""
Section 9 ground-truth test bundle: CASE-0309
(traccar/traccar, src/org/traccar/protocol/SpotProtocolDecoder.java
constructor, CVE-2019-5748, CWE-611 XML external entity injection).

Core vulnerable mechanism: the SPOT satellite-tracker protocol decoder parses
each incoming HTTP POST body (an XML document sent by the device or by
anyone who can reach the port) with a `DocumentBuilder` obtained from a
default `DocumentBuilderFactory.newInstance()`. Default JAXP settings resolve
DOCTYPE declarations and external general entities, so a body such as
`<!DOCTYPE m [<!ENTITY e SYSTEM "file:///etc/passwd">]><messageList>&e;
</messageList>` makes the server read a local file (or fetch an internal
URL: SSRF) and place its content into the parsed document (returned in
error messages / stored values). The upstream fix configures the factory
before creating the builder: `disallow-doctype-decl = true`, external
general and parameter entities off, `load-external-dtd` off,
`setXIncludeAware(false)` and `setExpandEntityReferences(false)`.

Sibling sites: the decoder builds its parser in this one constructor.

Verification: the constructor's `try` block of each full file (builder and
XPath setup) is extracted verbatim and compiled with javac against the JDK's
own JAXP implementation (the `super(protocol)` call and the Netty/Traccar
types are not needed), then used to parse a document with an external entity
pointing at a real temp file containing `TOP-SECRET-XXE`; whether the secret
appears in the parsed text, or the parse is rejected, is the measurement. A
benign `<messageList><message>hi</message></messageList>` must parse with
its `message` node found by the decoder's own compiled XPath
(`//messageList/message`) in every variant.

Every variant is the FULL real file. The constructor is the class's only
constructor, so its signature is kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0309"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


LINE = "            documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();\n"
assert original.count(LINE) == 1

# --- Variant 1: renamed vulnerable variant (the private fields are class state; rename the local flow) ---
v1 = swap(original, LINE, ("            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n"
                           "            documentBuilder = factory.newDocumentBuilder();\n"))
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, LINE, "            documentBuilder = createBuilder();\n")
v2 = swap(v2, "    public SpotProtocolDecoder(Protocol protocol) {", '''    private static DocumentBuilder createBuilder() throws ParserConfigurationException {
        return DocumentBuilderFactory.newInstance().newDocumentBuilder();
    }

    public SpotProtocolDecoder(Protocol protocol) {''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file, hardening in a factory method) ---
PBLK = '''            DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
            builderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            builderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            builderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            builderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            builderFactory.setXIncludeAware(false);
            builderFactory.setExpandEntityReferences(false);
            documentBuilder = builderFactory.newDocumentBuilder();
'''
assert patched.count(PBLK) == 1
v3 = swap(patched, PBLK, "            documentBuilder = newHardenedBuilder();\n")
v3 = swap(v3, "    public SpotProtocolDecoder(Protocol protocol) {", '''    /** Device-supplied XML: never resolve DOCTYPE, entities, external DTDs or XInclude. */
    private static DocumentBuilder newHardenedBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory.newDocumentBuilder();
    }

    public SpotProtocolDecoder(Protocol protocol) {''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package org.traccar.protocol;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * Standalone example of the same shape: parse an XML resource that ships
 * inside the application jar (trusted build-time content, never
 * device-supplied), so default parser settings expose nothing.
 */
class BundledConfigParser {

    static DocumentBuilder builder() throws ParserConfigurationException {
        return DocumentBuilderFactory.newInstance().newDocumentBuilder();
    }
}
''')
