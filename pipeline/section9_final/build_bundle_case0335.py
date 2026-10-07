r"""
Section 9 ground-truth test bundle: CASE-0335
(xwiki/xwiki-platform, xwiki-platform-xar-model org/xwiki/xar/XarPackage.java
readDescriptor, CVE-2023-27480, CWE-611 XML external entity reference).

Core vulnerable mechanism: `XarPackage.readDescriptor(InputStream)` parses the
`package.xml` descriptor of an uploaded/imported XAR archive with a default
`DocumentBuilderFactory.newInstance()` and no XXE hardening. A crafted
descriptor with a `<!DOCTYPE ... <!ENTITY xxe SYSTEM "file:///etc/passwd">` and an
`&xxe;` reference inside an element makes the parser read local files (or
fetch URLs, SSRF) and place them in the parsed text, e.g. into a package
info field. The upstream fix calls `dbFactory.setFeature(
"http://apache.org/xml/features/disallow-doctype-decl", true)` before
creating the builder.

Sibling sites: other XML readers of the XAR model were not part of the fix.

Verification (REAL JDK JAXP parser): the `readDescriptor` method (plus any
helper a variant adds) is sliced from each full file into a javac harness with
stand-ins for `XarException`, `XarModel` and `readDescriptorPackage`
(which records the package element's text) and the REAL commons-io
`CloseShieldInputStream`. A descriptor whose DOCTYPE defines an external
entity pointing to a temp file containing `TOP-SECRET-XAR`, referenced from
`<infos>`, is parsed: vulnerable variants read the secret into the parsed
text; patched/safe reject the DOCTYPE with an XarException and read nothing.
A plain descriptor (`<package><infos>hello</infos></package>`) is parsed to
`hello` in every file.

Every variant is the FULL real file; `readDescriptor` is public API and
keeps its name and signature.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0335"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


HEAD = '''        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();

        DocumentBuilder dBuilder;
        try {
            dBuilder = dbFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new XarException("Failed to create a new Document builder", e);
        }
'''
assert original.count(HEAD) == 1

# --- Variant 1: renamed vulnerable variant (locals renamed inside readDescriptor) ---
a = original.index("    public void readDescriptor(InputStream stream)")
b = original.index("    private void readDescriptorPackage(Element packageElement)")
seg = original[a:b]
for old, new in [("dbFactory", "factory"), ("dBuilder", "builder"), ("doc", "descriptorDocument"),
                 ("children", "topLevelNodes"), ("node", "current"), ("element", "candidate")]:
    seg = re.sub(r"\b%s\b" % old, new, seg)
assert "descriptorDocument.getDocumentElement().normalize()" in seg and "candidate.getTagName()" in seg
v1 = original[:a] + seg + original[b:]
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (builder creation extracted into a helper; default factory) ---
v2 = swap(original, HEAD, '''        DocumentBuilder dBuilder = newDescriptorBuilder();
''')
v2 = swap(v2, "    private void readDescriptorPackage(Element packageElement)",
          '''    private DocumentBuilder newDescriptorBuilder() throws XarException
    {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();

        try {
            return dbFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new XarException("Failed to create a new Document builder", e);
        }
    }

    private void readDescriptorPackage(Element packageElement)''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the hardened builder comes from a helper) ---
PHEAD = '''        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();

        DocumentBuilder dBuilder;
        try {
            // Prevent XXE attack
            dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dBuilder = dbFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new XarException("Failed to create a new Document builder", e);
        }
'''
v3 = swap(patched, PHEAD, "        DocumentBuilder dBuilder = newHardenedBuilder();\n")
v3 = swap(v3, "    private void readDescriptorPackage(Element packageElement)",
          '''    private DocumentBuilder newHardenedBuilder() throws XarException
    {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();

        try {
            // Prevent XXE attack
            dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            return dbFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new XarException("Failed to create a new Document builder", e);
        }
    }

    private void readDescriptorPackage(Element packageElement)''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package org.xwiki.xar;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * Standalone example of the same shape: parse the application's OWN generated descriptor string with a default
 * parser. The XML never comes from an upload or the network, so there is no attacker-controlled DOCTYPE.
 */
class GeneratedDescriptorReader {

    static String packageName(String generatedXml) throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(generatedXml.getBytes(StandardCharsets.UTF_8)));
        return doc.getDocumentElement().getAttribute("name");
    }
}
''')
