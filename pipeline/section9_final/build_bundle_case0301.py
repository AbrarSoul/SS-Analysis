"""
Section 9 ground-truth test bundle: CASE-0301
(theonedev/onedev, server-core/src/main/java/io/onedev/server/migration/
XmlBuildSpecMigrator.java migrate, CVE-2021-21250, CWE-538/XXE
information exposure through XML external entity processing).

Core vulnerable mechanism: `migrate(String xml)` converts a legacy XML
build spec to YAML. It parses the caller-supplied XML with
`new SAXReader().read(...)` (dom4j) with default settings, so the
underlying JAXP parser resolves DOCTYPE declarations and EXTERNAL ENTITIES.
The XML comes from build spec files in repositories/uploads authored by
untrusted users, so a spec containing
`<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>` with `&e;` used in
a job/property value makes the server read a local file (or fetch an
internal URL: SSRF) and embed its contents in the migrated output the
attacker then views. The upstream fix creates the reader explicitly and
sets `http://apache.org/xml/features/disallow-doctype-decl = true` before
reading, so any DOCTYPE is rejected.

Sibling sites: `migrate` is the only parse site in this class.

Verification: the parse `try` block of each full file's `migrate` is
extracted verbatim and compiled with javac against the REAL `dom4j` 2.1.3
jar and the JDK's real SAX parser, inside a harness method that returns the
parsed document's root text: `<!DOCTYPE r [<!ENTITY e SYSTEM
"file:///.../secret.txt">]><r>&e;</r>` is read, where `secret.txt` is a real
temp file containing `TOP-SECRET-XXE`. Whether the secret reaches the
document (vulnerable) or the parse is rejected (fixed) is the measurement.
A benign document `<r>hello</r>` must parse to `hello` in every variant.

Every variant is the FULL real file. `migrate` is a public static method
called by name from the migration code, so its name/signature are kept.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0301"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


PARSE = '''		Document xmlDoc;
		try {
			xmlDoc = new SAXReader().read(new StringReader(xml));
		} catch (DocumentException e) {
			throw new RuntimeException(e);
		}
'''
assert original.count(PARSE) == 1

# --- Variant 1: renamed vulnerable variant (xmlDoc is local to migrate) ---
import re
s = original.index("	public static String migrate(String xml) {")
body = original[s:]
b1 = re.sub(r"\bxmlDoc\b", "buildSpecDoc", body)
assert b1 != body
(CASE_DIR / "variant_vulnerable_01.java").write_text(original[:s] + b1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, PARSE, '''		Document xmlDoc = parseXml(xml);
''')
v2 = swap(v2, "	public static String migrate(String xml) {", '''	private static Document parseXml(String xml) {
		try {
			return new SAXReader().read(new StringReader(xml));
		} catch (DocumentException e) {
			throw new RuntimeException(e);
		}
	}

	public static String migrate(String xml) {''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file, hardened reader factory) ---
PPARSE = '''		Document xmlDoc;
		try {
			SAXReader reader = new SAXReader();
			// Prevent XXE attack as the xml might be provided by malicious users
			reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
			xmlDoc = reader.read(new StringReader(xml));
		} catch (DocumentException | SAXException e) {
			throw new RuntimeException(e);
		}
'''
assert patched.count(PPARSE) == 1
v3 = swap(patched, PPARSE, '''		Document xmlDoc;
		try {
			xmlDoc = newHardenedReader().read(new StringReader(xml));
		} catch (DocumentException | SAXException e) {
			throw new RuntimeException(e);
		}
''')
v3 = swap(v3, "	public static String migrate(String xml) {", '''	/** The xml may be provided by malicious users: never allow DOCTYPE / external entities. */
	private static SAXReader newHardenedReader() throws SAXException {
		SAXReader reader = new SAXReader();
		reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		return reader;
	}

	public static String migrate(String xml) {''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package io.onedev.server.migration;

import java.io.StringReader;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.io.SAXReader;

/**
 * Standalone example of the same shape: parse an XML document that ships
 * INSIDE the application jar (trusted, build-time content, never user
 * supplied), so default parser settings expose nothing.
 */
class BundledDefaultsParser {

    static Document parse(String bundledXml) throws DocumentException {
        return new SAXReader().read(new StringReader(bundledXml));
    }
}
''')
