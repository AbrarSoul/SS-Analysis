"""
Section 9 ground-truth test bundle: CASE-0149
(drogatkin/TJWS2, 1.x/src/rogatkin/web/WarRoller.java deployWar,
CVE-2022-4594, CWE-22 path traversal, "zip slip").

Core vulnerable mechanism: `deployWar` unpacks a .war with
`File outFile = new File(deployDir, en)` where `en` is the zip entry name,
after only converting `\\` to the separator. An entry called `../evil.txt`
(or `a/../../evil.txt`) therefore resolves outside the deployment directory
and is written there. The upstream fix rejects any entry name that contains
`../` or `/..` by throwing an IOException.

Sibling site: none (this is the only place a war entry is extracted).

Every variant is the FULL real file. `deployWar` is called from three places
inside the file and WarRoller implements the Acme WarDeployer interface, so
the renamed variant renames parameters and locals, not the method.

Verification note: the full file needs the TJWS runtime (Acme.Serve, WebAppServlet)
that is not on Maven Central, so the tests extract each variant's deployWar
method into a small harness class with the file's own constants and
helper methods and run it on real zip files.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0149"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    public boolean deployWar(File warFile, File deployTarDir) {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
ENTRY = '''\t\t    String en = ze.getName();
\t\t    if (File.separatorChar == '/')
\t\t\ten = en.replace('\\\\', File.separatorChar);
\t\t    File outFile = new File(deployDir, en);
'''
assert original.count(HDR) == 1 and BLOCK.count(ENTRY) == 1, "entry chunk"


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


def rename(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')', line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = rename(BLOCK, (("warFile", "archive"), ("deployTarDir", "targetRoot"), ("context", "appName"),
                   ("failedMark", "failMarker"), ("zipFile", "zip"), ("deployDir", "appDir"),
                   ("noincremental", "fullRedeploy"), ("lastException", "lastError"), ("entries", "zipEntries"),
                   ("ze", "entry"), ("en", "entryName"), ("outFile", "target"), ("parentFile", "parentDir"),
                   ("os", "sink"), ("is", "source"), ("ioe2", "copyError"), ("ioe", "readError")))
assert "public boolean deployWar(File archive, File targetRoot)" in b
assert "File target = new File(appDir, entryName);" in b and "catch (ZipException entry)" in b
assert "sink = new FileOutputStream(target)" in b and "copyStream(source, sink)" in b
assert "Deploying \" + appName" in b and "if (File.separatorChar == '/')" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(ENTRY, '''\t\t    String en = normalizeEntryName(ze.getName());
\t\t    File outFile = new File(deployDir, en);
''')
helper = '''
    private static String normalizeEntryName(String name) {
\tif (File.separatorChar == '/')
\t    return name.replace('\\\\', File.separatorChar);
\treturn name;
    }
'''
assert b != BLOCK
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# Canonical-path containment: the resolved target must be the deployment
# directory itself or inside it; upstream instead rejects names containing
# "../" or "/..".
b = BLOCK.replace(ENTRY, ENTRY + '''\t\t    String deployRoot = deployDir.getCanonicalPath();
\t\t    String outPath = outFile.getCanonicalPath();
\t\t    if (!outPath.equals(deployRoot) && !outPath.startsWith(deployRoot + File.separator))
\t\t\tthrow new IOException("Entry " + en + " resolves outside the deployment directory");
''')
(CASE_DIR / "variant_safe_01.java").write_text(build(b))

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class FlatUnzipper {

    /**
     * Same ZipFile-entries -> new File(dir, name) loop as a war deployer, but
     * every entry is flattened to its bare file name (new File(name).getName()),
     * so no entry name can carry a path component out of the directory.
     */
    public static void unpackFlat(File archive, File dir) throws IOException {
        try (ZipFile zip = new ZipFile(archive)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry ze = entries.nextElement();
                if (ze.isDirectory()) {
                    continue;
                }
                File outFile = new File(dir, new File(ze.getName()).getName());
                try (InputStream is = zip.getInputStream(ze); FileOutputStream os = new FileOutputStream(outFile)) {
                    byte[] buf = new byte[4096];
                    for (int n; (n = is.read(buf)) > 0; ) {
                        os.write(buf, 0, n);
                    }
                }
            }
        }
    }
}
'''
assert "new File(ze.getName()).getName()" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0149.")
