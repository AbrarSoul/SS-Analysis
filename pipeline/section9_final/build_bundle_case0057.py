"""
Section 9 ground-truth test bundle: CASE-0057
(LEMS/jLEMS, CVE unspecified/GHSA, CWE-22 Zip Slip path traversal).

Core vulnerable mechanism: `unpackJar()` builds the extraction path for
each JAR entry via `new File(fout, je.getName())`, using the entry's own
name completely unchecked. A JAR/ZIP entry name is attacker-controlled
whenever the archive itself comes from an untrusted source, and nothing
stops it from containing `../` sequences (e.g. `"../../../etc/cron.d/evil"`)
-- `File`'s constructor happily builds a path that resolves OUTSIDE
`fout`, and the subsequent write follows it there. This is the classic
"Zip Slip" vulnerability. The fix resolves the candidate file's real,
normalized path and verifies it still starts with the (also normalized)
output directory before ever writing to it.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0057"
# Normalize trailing whitespace per line first -- the real file has a
# stray trailing-whitespace-only line right after unpackJar()'s opening
# brace that a hand-typed VULNERABLE_BLOCK literal (auto-stripped by this
# session's own editing tools) can never byte-match otherwise. Cosmetically
# irrelevant for Java syntax validity either way.
original = "\n".join(line.rstrip() for line in (CASE_DIR / "vulnerable_source.java").read_text().splitlines())
if not original.endswith("\n"):
    original += "\n"

VULNERABLE_BLOCK = '''   public static void unpackJar(File fjar, File fout) throws IOException {

      JarFile jf = new JarFile(fjar);
      Enumeration<JarEntry> en = jf.entries();

      while (en.hasMoreElements()) {
         JarEntry je = en.nextElement();
         java.io.File f = new File(fout,  je.getName());
         if (je.isDirectory()) {'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename unpackJar -> extractArchive, fjar/fout -> archiveFile/outputDir,
# je -> entry, f -> target. Same exact unchecked entry-name path join.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''   public static void extractArchive(File archiveFile, File outputDir) throws IOException {

      JarFile jf = new JarFile(archiveFile);
      Enumeration<JarEntry> en = jf.entries();

      while (en.hasMoreElements()) {
         JarEntry entry = en.nextElement();
         java.io.File target = new File(outputDir,  entry.getName());
         if (entry.isDirectory()) {''',
)
renamed_source = renamed_source.replace('f.mkdirs();', 'target.mkdirs();')
renamed_source = renamed_source.replace('f.getPath().indexOf', 'target.getPath().indexOf')
renamed_source = renamed_source.replace('f.getParentFile().mkdirs();\n            java.io.InputStream is = jf.getInputStream(je);\n            java.io.FileOutputStream fos = new FileOutputStream(f);',
                                          'target.getParentFile().mkdirs();\n            java.io.InputStream is = jf.getInputStream(entry);\n            java.io.FileOutputStream fos = new FileOutputStream(target);')
assert "public static void extractArchive(File archiveFile, File outputDir)" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable holding the raw entry name before
# the unchecked File join. Same exact vulnerability, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''   public static void unpackJar(File fjar, File fout) throws IOException {

      JarFile jf = new JarFile(fjar);
      Enumeration<JarEntry> en = jf.entries();

      while (en.hasMoreElements()) {
         JarEntry je = en.nextElement();
         String entryName = je.getName();
         java.io.File f = new File(fout, entryName);
         if (je.isDirectory()) {''',
)
assert structural_source != original
assert "String entryName = je.getName();" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (reject an entry whose resolved path escapes
# the output directory) but a materially different technique:
# getCanonicalPath() string-prefix comparison instead of the real patch's
# toPath().normalize().startsWith() -- genuinely rejects Zip Slip entries,
# different API/implementation shape.
SAFE_SOURCE = '''package org.lemsml.jlems.io.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public final class SafeJarUnpacker {

    public static void unpackJar(File fjar, File fout) throws IOException {
        String outCanonical = fout.getCanonicalPath() + File.separator;
        JarFile jf = new JarFile(fjar);
        Enumeration<JarEntry> en = jf.entries();

        while (en.hasMoreElements()) {
            JarEntry je = en.nextElement();
            File f = new File(fout, je.getName());
            String candidateCanonical = f.getCanonicalPath();
            if (!candidateCanonical.startsWith(outCanonical)) {
                throw new IOException("Entry is outside of the target dir: " + je.getName());
            }
            if (je.isDirectory()) {
                f.mkdirs();
                continue;
            }
            if (f.getPath().indexOf("META-INF") >= 0) {
                continue;
            }
            f.getParentFile().mkdirs();
            java.io.InputStream is = jf.getInputStream(je);
            FileOutputStream fos = new FileOutputStream(f);
            while (is.available() > 0) {
                fos.write(is.read());
            }
            fos.close();
            is.close();
        }
    }
}
'''
(CASE_DIR / "variant_safe_01.java").write_text(SAFE_SOURCE)
assert "getCanonicalPath" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (new File(base, name) built from a loop variable,
# then written to) but this sibling only ever writes files whose names
# come from a FIXED, hard-coded list of expected resource filenames --
# never from an externally-supplied archive entry -- so there is no
# untrusted "../"-bearing name that could ever reach the File
# constructor, unlike unpackJar()'s je.getName().
BENIGN_SOURCE = '''import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public final class DefaultResourceInstaller {

    private static final String[] FIXED_RESOURCE_NAMES = {
        "defaults.xml", "schema.xsd", "README.txt"
    };

    /** Only ever installs files whose names come from the fixed array
     * above, compiled into this class -- never derived from any
     * external archive entry, so there is no traversal-capable input
     * this could ever receive. */
    public static void installDefaults(File outDir) throws IOException {
        for (String name : FIXED_RESOURCE_NAMES) {
            File target = new File(outDir, name);
            InputStream is = DefaultResourceInstaller.class.getResourceAsStream("/" + name);
            FileOutputStream fos = new FileOutputStream(target);
            while (is.available() > 0) {
                fos.write(is.read());
            }
            fos.close();
            is.close();
        }
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN_SOURCE)
assert "je.getName()" not in BENIGN_SOURCE
assert "JarEntry" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0057.")
