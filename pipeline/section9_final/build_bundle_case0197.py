"""
Section 9 ground-truth test bundle: CASE-0197
(jenkinsci/xcode-plugin, src/main/java/au/com/rayh/XcodeProjectParser.java
parseXcodeScheme and parseXcodeWorkspace, CVE-2021-21656, CWE-611 XXE
(recorded as NVD-CWE-noinfo)).

Located target: `public static ProjectScheme parseXcodeScheme(FilePath schemeFile)`.

Core vulnerable mechanism: the plugin parses `.xcscheme` and
`contents.xcworkspacedata` files from the workspace (attacker-influenced
repository content) with `DocumentBuilderFactory.newInstance()` defaults,
which resolve external entities and DTDs, so a crafted scheme can read local
files or make the build agent send requests. The upstream fix sets the OWASP
hardening features (disallow DOCTYPE, no external general/parameter
entities, no external DTD, no XInclude, no entity expansion) at BOTH sites.

Sibling sites: parseXcodeWorkspace has the identical parser setup and is fixed
together (and in the safe variant); the same file's plist parsing goes
through dd-plist, a different library that is not changed here.

Verification: the whole file is compiled with the real dd-plist 1.23 jar
and stand-ins for hudson.FilePath and the plugin's model classes; the two
parse methods are run on real XML files with the real JDK 26 JAXP parser.

Every variant is the FULL real file. Both methods are public static API, so the
renamed variant keeps the names and renames locals in parseXcodeScheme.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0197"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

SCHEME = '''\t    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
\t    DocumentBuilder documentBuilder = factory.newDocumentBuilder();
\t    Document document = documentBuilder.parse(schemeFile.read());
'''
WORKSPACE = '''\t    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
\t    DocumentBuilder documentBuilder = factory.newDocumentBuilder();
\t    Document document = documentBuilder.parse(workspaceFilePath.read());
'''
assert original.count(SCHEME) == 1 and original.count(WORKSPACE) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant (parseXcodeScheme body) ---
a = original.index("    public static ProjectScheme parseXcodeScheme(FilePath schemeFile) {\n")
b = original.index("    public static List<String> parseXcodeWorkspace", a)
body = original[a:b]
lines = []
for line in body.split("\n"):
    if line.strip().startswith("//"):
        lines.append(line)
        continue
    parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
    for i in range(0, len(parts), 2):
        for old, new in (("factory", "dbf"), ("documentBuilder", "builder"), ("document", "doc")):
            parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, parts[i])
    lines.append("".join(parts))
nb = "\n".join(lines)
assert "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();" in nb and "Document doc = builder.parse(schemeFile.read());" in nb
(CASE_DIR / "variant_vulnerable_01.java").write_text(original[:a] + nb + original[b:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, SCHEME, '''\t    DocumentBuilder documentBuilder = newFactory().newDocumentBuilder();
\t    Document document = documentBuilder.parse(schemeFile.read());
''')
v2 = swap(v2, WORKSPACE, '''\t    DocumentBuilder documentBuilder = newFactory().newDocumentBuilder();
\t    Document document = documentBuilder.parse(workspaceFilePath.read());
''')
v2 = swap(v2, "    public static ProjectScheme parseXcodeScheme(FilePath schemeFile) {\n", '''    private static DocumentBuilderFactory newFactory() {
\treturn DocumentBuilderFactory.newInstance();
    }

    public static ProjectScheme parseXcodeScheme(FilePath schemeFile) {
''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
# One private newHardenedFactory() used by both parse methods: DOCTYPE is
# refused and secure processing is on; upstream sets six features at each site.
v3 = swap(original, SCHEME, '''\t    DocumentBuilderFactory factory = newHardenedFactory();
\t    DocumentBuilder documentBuilder = factory.newDocumentBuilder();
\t    Document document = documentBuilder.parse(schemeFile.read());
''')
v3 = swap(v3, WORKSPACE, '''\t    DocumentBuilderFactory factory = newHardenedFactory();
\t    DocumentBuilder documentBuilder = factory.newDocumentBuilder();
\t    Document document = documentBuilder.parse(workspaceFilePath.read());
''')
v3 = swap(v3, "    public static ProjectScheme parseXcodeScheme(FilePath schemeFile) {\n", '''    private static DocumentBuilderFactory newHardenedFactory() throws ParserConfigurationException {
\tDocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
\tfactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
\tfactory.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
\tfactory.setXIncludeAware(false);
\treturn factory;
    }

    public static ProjectScheme parseXcodeScheme(FilePath schemeFile) {
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class BundledScheme {

    private static final String SCHEME =
        "<Scheme LastUpgradeVersion=\\"0900\\"><BuildAction/></Scheme>";

    /**
     * Same DocumentBuilderFactory.newInstance() / parse(...) chain as the scheme
     * parser, but the XML is a constant embedded in the source, so no
     * attacker-controlled DOCTYPE or entity can reach the parser.
     */
    public static Document parseDefault() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(SCHEME.getBytes(StandardCharsets.UTF_8)));
    }
}
'''
assert "constant embedded in the source" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0197.")
