"""
Section 9 ground-truth test bundle: CASE-0148
(dom4j/dom4j, src/main/java/org/dom4j/DocumentHelper.java parseText,
CVE-2020-10683, CWE-611 XML external entity (XXE) processing).

Core vulnerable mechanism: `parseText` builds a plain `new SAXReader()` and
parses the caller's text with it. The JAXP defaults resolve external general
entities and load external DTDs, so text such as
`<!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]><d>&x;</d>` puts a
local file's contents into the document (and can trigger outbound requests).
The method's own javadoc even says "Loading external DTD and entities is
disabled (if it is possible)", which the code does not do. The upstream fix
turns off load-external-dtd, external-general-entities and
external-parameter-entities on the reader.

Sibling site: none in this file (parseText is the only place a SAXReader is
built).

Every variant is the FULL real file. parseText is a public static API with no
in-file callers, so the renamed variant renames the method too.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0148"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    public static Document parseText(String text) throws DocumentException {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
READER = "        SAXReader reader = new SAXReader();\n"
assert original.count(HDR) == 1 and BLOCK.count(READER) == 1 and original.count("parseText") == 2


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


def rename(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        for name, new in pairs:
            line = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, line)
        out.append(line)
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = rename(BLOCK, (("parseText", "parseXml"), ("text", "xmlText"), ("reader", "saxReader"), ("encoding", "charset"),
                   ("source", "inputSource"), ("result", "parsed")))
assert "parseXml(String xmlText)" in b and "new StringReader(xmlText)" in b and "saxReader.read(inputSource)" in b
assert "parsed.getXMLEncoding()" in b and "charset" in b and "setFeature" not in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(READER, "        SAXReader reader = newReader();\n")
helper = '''
    private static SAXReader newReader() {
        return new SAXReader();
    }
'''
assert b != BLOCK
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# An entity resolver that answers every external reference (external DTD or
# entity) with an empty document; upstream instead switches three Xerces
# features off.
b = BLOCK.replace(READER, READER + '''        reader.setEntityResolver(new EntityResolver() {
            public InputSource resolveEntity(String publicId, String systemId) {
                return new InputSource(new StringReader(""));
            }
        });
''')
safe_source = build(b).replace("import org.xml.sax.InputSource;\n", "import org.xml.sax.EntityResolver;\nimport org.xml.sax.InputSource;\n")
assert safe_source.count("import org.xml.sax.EntityResolver;") == 1
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.io.StringReader;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.io.SAXReader;
import org.xml.sax.InputSource;

public class BundledConfig {

    /** Fixed, developer-written XML: no external input ever reaches the parser. */
    private static final String DEFAULTS = "<config><timeout>30</timeout></config>";

    /**
     * Same new SAXReader() + read(InputSource) shape as DocumentHelper.parseText,
     * but the text is a constant in the source, so there is no attacker
     * controlled DOCTYPE or entity to resolve.
     */
    public static Document defaults() throws DocumentException {
        SAXReader reader = new SAXReader();
        return reader.read(new InputSource(new StringReader(DEFAULTS)));
    }
}
'''
assert "DEFAULTS" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0148.")
