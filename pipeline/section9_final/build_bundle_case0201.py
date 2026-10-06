"""
Section 9 ground-truth test bundle: CASE-0201
(joniles/mpxj, src/main/java/net/sf/mpxj/common/InputStreamHelper.java
processZipStream, CVE-2020-35460, CWE-22 "zip slip"). This case is the
replacement added by top-up 17 after CASE-0201 (joblib) was excluded.

Core vulnerable mechanism: `processZipStream` expands an uploaded zip into a
temporary directory with `File file = new File(dir, entry.getName())` and
writes to it, creating parent directories. Nothing checks the entry name, so
an entry such as `../../evil.txt` is written OUTSIDE the temp directory. The
upstream fix compares the entry's canonical path with the canonical directory
path plus a separator and throws IOException.

Sibling sites: none (processZipStream is the only extractor).

Every variant is the FULL real file. processZipStream is private with one
call, so the renamed variant renames its parameters and locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0201"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

s = original.index("   private static void processZipStream(File dir, InputStream inputStream) throws IOException\n")
e = original.index("\n   }\n", s) + len("\n   }\n")
BLOCK = original[s:e]
NEWFILE = "         File file = new File(dir, entry.getName());\n"
assert BLOCK.count(NEWFILE) == 1


def build(b, extra_after=None):
    assert b != BLOCK
    return original[:s] + b + (extra_after or "") + original[e:]


def rename(text, pairs):
    for old, new in pairs:
        text = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, text)
    return text


# --- Variant 1: renamed vulnerable variant ---
b = rename(BLOCK, (("dir", "targetDir"), ("inputStream", "source"), ("zip", "archive"), ("entry", "item"),
                   ("file", "destination"), ("parent", "container"), ("fos", "out"), ("bytes", "buffer"), ("length", "count")))
assert "new File(targetDir, item.getName())" in b and "archive.read(buffer)" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(NEWFILE, "         File file = resolveEntry(dir, entry.getName());\n")
helper = '''
   private static File resolveEntry(File dir, String name)
   {
      return new File(dir, name);
   }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, helper))

# --- Variant 3: transformed safe variant ---
# java.nio Path normalisation: the resolved path must stay under the
# directory (component-wise startsWith); upstream compares canonical path strings.
b = BLOCK.replace(NEWFILE, '''         java.nio.file.Path base = dir.toPath().toAbsolutePath().normalize();
         java.nio.file.Path resolved = base.resolve(entry.getName()).normalize();
         if (!resolved.startsWith(base))
         {
            throw new IOException("Entry is outside of the target dir: " + entry.getName());
         }
         File file = resolved.toFile();
''')
(CASE_DIR / "variant_safe_01.java").write_text(build(b))

# --- Variant 4: benign structural look-alike ---
benign = '''import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class FlatZipExtractor {

   /**
    * Same ZipInputStream loop as processZipStream, but every entry is written
    * to a file named by its bare file name (new File(name).getName()), so no
    * entry can carry a path out of the target directory.
    */
   public static void extractFlat(File dir, InputStream in) throws IOException
   {
      ZipInputStream zip = new ZipInputStream(in);
      ZipEntry entry;
      while ((entry = zip.getNextEntry()) != null)
      {
         if (entry.isDirectory())
         {
            continue;
         }
         try (FileOutputStream out = new FileOutputStream(new File(dir, new File(entry.getName()).getName())))
         {
            byte[] bytes = new byte[1024];
            int length;
            while ((length = zip.read(bytes)) >= 0)
            {
               out.write(bytes, 0, length);
            }
         }
      }
   }
}
'''
assert "bare file name" in benign
(CASE_DIR / "benign_lookalike.java").write_text(benign)
print("Wrote 4 new samples for CASE-0201.")
