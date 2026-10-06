"""
Section 9 ground-truth test bundle: CASE-0193
(jenkinsci/semantic-versioning-plugin, .../parsing/PomParser.java the
MasterToSlaveFileCallable.invoke that parses pom.xml, CVE-2023-24430,
CWE-611 XML external entity processing). This case is the replacement added by
top-up 16 after CASE-0193 (script-security-plugin, a test-only patch) was
excluded.

Core vulnerable mechanism: the plugin parses the workspace's `pom.xml` with
`DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(pom)`, the
JAXP defaults, which resolve external general entities and external DTDs.
A pom.xml that a build (or a pull request) controls can therefore declare
`<!ENTITY x SYSTEM "file:///...">` and reference `&x;` in a value the plugin
reads, pulling a file of the Jenkins agent/controller into the version string
or making it send outbound requests. The upstream fix sets
`XMLConstants.ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA` to the empty
string on the factory.

Sibling sites: the file has one parser factory (this callable); the XPath
queries that read the version run on the already parsed Document.

Every variant is the FULL real file. The located code is an anonymous
callable's `invoke(File pom, VirtualChannel channel)`; its parameters are
not bound by name by anything, so the renamed variant renames them and the
locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0193"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

INVOKE = '''				public Document invoke(File pom, VirtualChannel channel)
						throws IOException, InterruptedException {

					try {
						DocumentBuilder documentBuilder;
						documentBuilder = DocumentBuilderFactory.newInstance()
								.newDocumentBuilder();
						return documentBuilder.parse(pom);

					} catch (SAXException | ParserConfigurationException e) {
						throw new InterruptedException(pom
								.getAbsolutePath()
								+ " is not a valid POM file.");
					}
				}
'''
assert original.count(INVOKE) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, INVOKE, '''				public Document invoke(File pomFile, VirtualChannel remoting)
						throws IOException, InterruptedException {

					try {
						DocumentBuilder builder;
						builder = DocumentBuilderFactory.newInstance()
								.newDocumentBuilder();
						return builder.parse(pomFile);

					} catch (SAXException | ParserConfigurationException failure) {
						throw new InterruptedException(pomFile
								.getAbsolutePath()
								+ " is not a valid POM file.");
					}
				}
''')
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, INVOKE, '''				private DocumentBuilder newBuilder() throws ParserConfigurationException {
					return DocumentBuilderFactory.newInstance().newDocumentBuilder();
				}

				public Document invoke(File pom, VirtualChannel channel)
						throws IOException, InterruptedException {

					try {
						return newBuilder().parse(pom);

					} catch (SAXException | ParserConfigurationException e) {
						throw new InterruptedException(pom
								.getAbsolutePath()
								+ " is not a valid POM file.");
					}
				}
''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
# DOCTYPE declarations are refused outright (no entity can be declared) and
# XInclude is off; upstream restricts external DTD/schema access with the
# JAXP access properties.
v3 = swap(original, INVOKE, '''				public Document invoke(File pom, VirtualChannel channel)
						throws IOException, InterruptedException {

					try {
						DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
						factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
						factory.setXIncludeAware(false);
						factory.setExpandEntityReferences(false);
						return factory.newDocumentBuilder().parse(pom);

					} catch (SAXException | ParserConfigurationException e) {
						throw new InterruptedException(pom
								.getAbsolutePath()
								+ " is not a valid POM file.");
					}
				}
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class DefaultPom {

    private static final String TEMPLATE =
        "<project><modelVersion>4.0.0</modelVersion><version>0.0.1</version></project>";

    /**
     * Same DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(...)
     * chain as the pom parser, but the document is a constant embedded in the
     * source, so no attacker-controlled DOCTYPE or entity can reach the parser.
     */
    public static Document parseTemplate() throws Exception {
        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(TEMPLATE.getBytes(StandardCharsets.UTF_8)));
    }
}
'''
assert "constant embedded in the" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0193.")
