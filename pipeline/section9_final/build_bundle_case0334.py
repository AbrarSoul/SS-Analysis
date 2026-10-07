r"""
Section 9 ground-truth test bundle: CASE-0334
(xwiki/xwiki-platform, xwiki-platform-skin-skinx
org/xwiki/skinx/internal/AbstractSxExportURLFactoryActionHandler.java
processSx, CVE-2022-23620, CWE-22 path traversal / CWE-116).

Core vulnerable mechanism: when exporting wiki pages to HTML, the skin
extension (SSX/JSX) handler writes each extension's content to a file under the
export directory. The target path is built from the extension document's
SPACE NAMES and PAGE NAME verbatim:
`String.format("%s/%s/%s", getSxPrefix(), StringUtils.join(spaceNames, '/'), name)`
and used with `mkdirs()` and `File.createTempFile`. A page whose space or name
contains `..` (or `/`) makes the target directory point outside the export
directory, so an attacker who can create such an SSX page writes files to
arbitrary locations when an export is run (arbitrary file write). The upstream
fix identifies the extension by `sxDocument.getId()` (a numeric hash) instead
of its reference (`%s/%s` with prefix and id) and adjusts the CSS
relative-URL depth accordingly.

Sibling sites: the same names are also appended to the generated `file://`
URL (fixed the same way); `createURL` only forwards them.

Verification (REAL commons-io/commons-lang3/httpclient jars): the
`createURL`, `processSx`, `getContent` and `encodeURLPart` methods (and any
helper a variant adds) are sliced from each full file into a javac harness with
stand-ins for the XWiki types (`DocumentReference`, `XWikiContext`,
`XWikiDocument`, `FilesystemExportContext`, `LegacySpaceResolver`, ...). The
export directory is a temp directory `<tmp>/export` whose `ssx` sub-directory already exists (as after an earlier SSX export; without it `createTempFile` fails with ENOENT on the `..` path, although the escaped directory is still created); `createURL` is
called with the space list `..`, `..`, `escape` (the stand-in resolver splits
on commas) and page name `pwn`. The measurement is whether the directory
`<tmp>/escape` (outside the export directory) was created and whether any
file exists under it. Vulnerable variants create `<tmp>/escape/pwn` and write
the temp file there; patched/safe write only under `<tmp>/export`.

Every variant is the FULL real file; `createURL` implements the handler
interface and keeps its name and signature.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0334"
original = (CASE_DIR / "vulnerable_source.java").read_text()
patched = (CASE_DIR / "patched_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant (locals/params renamed; the interface method's signature stays) ---
v1 = original
a = v1.index("    public URL createURL(")
b = v1.index("    protected String getContent(")
seg = v1[a:b]
for old, new in [("spaceNames", "spaceList"), ("targetLocation", "sxFile"), ("targetDirectory", "outDir"), ("targetPath", "relTarget")]:
    seg = re.sub(r"\b%s\b" % old, new, seg)
v1 = v1[:a] + seg + v1[b:]
assert v1.count("spaceList") >= 6
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (target path built by a helper) ---
TP = '''        String targetPath = String.format("%s/%s/%s", getSxPrefix(), StringUtils.join(spaceNames, '/'), name);\n'''
v2 = swap(original, TP, "        String targetPath = sxTargetPath(spaceNames, name);\n")
v2 = swap(v2, "    protected String getContent(SxSource sxSource, FilesystemExportContext exportContext)",
          "    private String sxTargetPath(List<String> spaceNames, String name)\n    {\n        return String.format(\"%s/%s/%s\", getSxPrefix(), StringUtils.join(spaceNames, '/'), name);\n    }\n\n    protected String getContent(SxSource sxSource, FilesystemExportContext exportContext)")
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the id-based path built by a helper) ---
PT = '''        String targetPath = String.format("%s/%s", getSxPrefix(), id);\n'''
v3 = swap(patched, PT, "        String targetPath = sxTargetPath(id);\n")
v3 = swap(v3, "    protected String getContent(SxSource sxSource, FilesystemExportContext exportContext)",
          "    private String sxTargetPath(long id)\n    {\n        return String.format(\"%s/%s\", getSxPrefix(), id);\n    }\n\n    protected String getContent(SxSource sxSource, FilesystemExportContext exportContext)")
(CASE_DIR / "variant_safe_01.java").write_text(v3)

(CASE_DIR / "benign_lookalike.java").write_text('''package org.xwiki.skinx.internal;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Standalone example of the same shape: build an output directory from page-name parts, but every part must
 * match a strict allow-list and the resulting canonical path must stay inside the export root.
 */
class SafeExportPaths {

    private static final Pattern SAFE_PART = Pattern.compile("[A-Za-z0-9_-]+");

    static File outputDirectory(File exportRoot, List<String> parts) throws IOException {
        File dir = exportRoot;
        for (String part : parts) {
            if (!SAFE_PART.matcher(part).matches()) {
                throw new IOException("Unsafe path part: " + part);
            }
            dir = new File(dir, part);
        }
        String root = exportRoot.getCanonicalPath() + File.separator;
        if (!(dir.getCanonicalPath() + File.separator).startsWith(root)) {
            throw new IOException("Path escapes the export directory");
        }
        return dir;
    }
}
''')
