"""
Section 9 ground-truth test bundle: CASE-0136
(cowtowncoder/java-merge-sort, StdTempFileProvider.provide,
CVE-2022-24913, CWE-377 insecure temporary file / CWE-668 exposure of
resource to wrong sphere).

Core vulnerable mechanism: `provide()` creates the temporary files that hold
the data being sorted with `File.createTempFile(_prefix, _suffix)`. That API
creates the file with the process's DEFAULT permissions (measured on JDK 26
with umask 022: rw-r--r--, i.e. world-readable) in the shared temp
directory, so any other local user can read the (possibly sensitive)
intermediate sort data. The upstream fix uses `Files.createTempFile(...)`,
which creates the file with owner-only permissions (measured: rw-------).

Every variant is the FULL real file with provide() replaced. provide() is an
@Override of TempFileProvider.provide(), so the renamed variant renames the
fields, constructor parameters and the local instead of the method.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0136"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    public File provide() throws IOException\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
CREATE = "        File f = File.createTempFile(_prefix, _suffix);\n"
assert original.count(HDR) == 1 and BLOCK.count(CREATE) == 1 and original.count("createTempFile") == 1


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


# --- Variant 1: renamed vulnerable variant ---
v = original
for old, new in (("_prefix", "_namePrefix"), ("_suffix", "_nameSuffix")):
    v = re.sub(r"(?<![\w$])%s(?![\w$])" % re.escape(old), new, v)
v = v.replace("public StdTempFileProvider(String prefix, String suffix) {", "public StdTempFileProvider(String filePrefix, String fileSuffix) {")
v = v.replace("_namePrefix = prefix;", "_namePrefix = filePrefix;").replace("_nameSuffix = suffix;", "_nameSuffix = fileSuffix;")
v = v.replace("File f = File.createTempFile(", "File tempFile = File.createTempFile(").replace("        f.deleteOnExit();\n        return f;\n",
                                                                                          "        tempFile.deleteOnExit();\n        return tempFile;\n")
assert "_prefix" not in v and "_suffix" not in v
assert "File.createTempFile(_namePrefix, _nameSuffix)" in v and "return tempFile;" in v
assert "this(DEFAULT_PREFIX, DEFAULT_SUFFIX)" in v
(CASE_DIR / "variant_vulnerable_01.java").write_text(v)

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(CREATE + "        f.deleteOnExit();\n        return f;\n",
                  "        return registerForCleanup(File.createTempFile(_prefix, _suffix));\n")
helper = '''
    private static File registerForCleanup(File f)
    {
        f.deleteOnExit();
        return f;
    }
'''
assert b != BLOCK and "registerForCleanup(File.createTempFile(" in b
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# Owner-only permissions requested EXPLICITLY at creation time on POSIX
# file systems (falls back to Files.createTempFile where POSIX permissions do
# not exist); upstream calls Files.createTempFile(...) with no explicit attribute.
b = BLOCK.replace(CREATE, '''        java.nio.file.Path path;
        if (java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            path = java.nio.file.Files.createTempFile(_prefix, _suffix,
                java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")));
        } else {
            path = java.nio.file.Files.createTempFile(_prefix, _suffix);
        }
        File f = path.toFile();
''')
safe_source = build(b)
assert "File.createTempFile" not in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;

public class PrivateDirTempFiles {

    private final File privateDir;

    public PrivateDirTempFiles() throws IOException {
        // Created atomically with owner-only permissions (rwx------).
        this.privateDir = Files.createTempDirectory(
            "sort-private-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))).toFile();
    }

    /**
     * Same File.createTempFile(...) + deleteOnExit() shape, but the file is
     * created INSIDE a directory only the current user can enter, so even
     * though the file itself gets default permissions no other user can reach
     * or read it.
     */
    public File provide() throws IOException {
        File f = File.createTempFile("j-merge-sort-", ".tmp", privateDir);
        f.deleteOnExit();
        return f;
    }
}
'''
assert "rwx------" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0136.")
