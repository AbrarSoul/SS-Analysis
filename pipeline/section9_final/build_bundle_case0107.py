"""
Section 9 ground-truth test bundle: CASE-0107
(apache/netbeans-html4j, UnJarResources, CVE-2020-17534, CWE-362 race
condition -- insecure temporary directory creation).

Core vulnerable mechanism: `UnJarResources.extract()` creates its
extraction directory with
`File.createTempFile(jar.getName(), ".dir"); dir.delete(); dir.mkdirs();`
in the world-writable java.io.tmpdir. Between `delete()` and `mkdirs()`
another local user can create a directory at that path first (the return
value of mkdirs() is ignored), so the jar's resources are unpacked into,
and later read back from, a directory the attacker controls. The upstream
fix creates it atomically with `Files.createTempDirectory(...)`.

Every variant is the FULL real file with extract() replaced. extract() is
package-private static with no in-file callers. Note (not the labeled
weakness, present in BOTH the vulnerable and upstream-patched code): the
loop does `new File(dir, entryName)` with no `..` check (zip-slip).
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0107"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    static URL extract(URL url) throws IOException {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
DIR_STMT = '''        File dir = File.createTempFile(jar.getName(), ".dir");
        dir.delete();
        dir.mkdirs();
'''
LOOP_HEAD = '''        Enumeration<JarEntry> en = jar.entries();
        while (en.hasMoreElements()) {
            JarEntry entry = en.nextElement();
'''
assert original.count(HDR) == 1 and BLOCK.count(DIR_STMT) == 1 and BLOCK.count(LOOP_HEAD) == 1
assert original.count("extract(") == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


def rename_outside_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for old, new in pairs:
                parts[i] = re.sub(r"\b%s\b" % old, new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("extract(", "unpackJarResource(")
b = rename_outside_strings(b, (("url", "resource"), ("jar", "archive"), ("dir", "unpackDir"),
                               ("en", "entries"), ("entry", "item"), ("file", "target")))
assert 'File.createTempFile(archive.getName(), ".dir")' in b and 'if (!"jar".equals(resource.getProtocol()))' in b
assert "unpackDir.delete();" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(LOOP_HEAD, '''        for (JarEntry entry : java.util.Collections.list(jar.entries())) {
''')
assert b != BLOCK and "dir.delete();" in b
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Atomic Files.createTempDirectory using only the jar's BASE name as the
# prefix (a full path is an illegal prefix); no delete/recreate window.
b = BLOCK.replace(DIR_STMT, '''        File dir = Files.createTempDirectory(new File(jar.getName()).getName() + ".dir").toFile();
''')
safe_source = build(b)
assert "createTempFile" not in safe_source and "dir.delete()" not in safe_source and "dir.mkdirs()" not in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

final class SingleResourceCopy {

    private SingleResourceCopy() {}

    /**
     * Same File.createTempFile + Files.copy extraction shape, but the data is
     * written INTO the file createTempFile already created (exclusively, and
     * owner-only on POSIX). There is no delete-then-recreate step, so there
     * is no window in which another user can claim the path first.
     */
    static File copy(InputStream in) throws IOException {
        File target = File.createTempFile("resource", ".bin");
        target.deleteOnExit();
        Files.copy(in, target.toPath(), StandardCopyOption.REPLACE_EXISTING);
        return target;
    }
}
'''
assert ".delete()" not in benign_source.replace("deleteOnExit", "")
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0107.")
