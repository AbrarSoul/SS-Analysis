"""
Section 9 ground-truth test bundle: CASE-0104
(apache/hadoop, RunJar, CVE-2024-23454, CWE-378 insecure temporary
file/directory creation).

Core vulnerable mechanism: `RunJar.run()` allocates its unjar work
directory in the world-writable `java.io.tmpdir` with
`File.createTempFile(...)`, then `workDir.delete()`, then
`ensureDirectory(workDir)` (`mkdirs()`, which also ACCEPTS a directory that
already exists). Between delete and mkdirs another local user can create a
directory at that exact path, so the victim unjars (and then loads classes
from) a directory the attacker owns, and the directory that is created has
default (umask-dependent) permissions. The upstream fix creates it
atomically with `Files.createTempDirectory(tmpDir, prefix, rwx------)`.

Every variant is the FULL real file with the work-directory allocation in
run() replaced. run() has one in-file call site (main), renamed by the
renamed variant; the anonymous Runnable.run() inside it is left alone.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0104"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

SEG_START = "    final File workDir;\n"
SEG_END = "    ensureDirectory(workDir);\n"
a = original.index(SEG_START)
b_ = original.index(SEG_END) + len(SEG_END)
SEG = original[a:b_]
assert original.count(SEG_START) == 1 and original.count(SEG_END) == 1
assert "File.createTempFile" in SEG and "workDir.delete()" in SEG

RUN_HDR = "  public void run(String[] args) throws Throwable {\n"
RUN_CALL = "    new RunJar().run(args);\n"
r0 = original.index(RUN_HDR)
r1 = original.index("\n  }\n", r0) + len("\n  }\n")
RUN = original[r0:r1]
assert original.count(RUN_HDR) == 1 and original.count(RUN_CALL) == 1 and SEG in RUN


def swap(src, old, new):
    assert src.count(old) == 1 and new != old
    return src.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
def rename_outside_comments(text, pairs):
    out = []
    for line in text.split("\n"):
        if not line.lstrip().startswith("//"):
            for old, new in pairs:
                line = re.sub(r"\b%s\b" % old, new, line)
        out.append(line)
    return "\n".join(out)


run_v1 = rename_outside_comments(
    RUN.replace("public void run(String[] args)", "public void execute(String[] args)"),
    (("workDir", "unpackDir"), ("tmpDir", "scratchRoot"), ("mainClassName", "entryClass")))
assert "unpackDir.delete()" in run_v1 and "public void run() {" in run_v1
v1 = swap(original, RUN, run_v1)
v1 = swap(v1, RUN_CALL, "    new RunJar().execute(args);\n")
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
# The same createTempFile -> delete -> mkdirs sequence, moved into a helper.
seg2 = '''    final File workDir;
    try {
      workDir = allocateWorkDir(tmpDir);
    } catch (IOException ioe) {
      // If user has insufficient perms to write to tmpDir, default
      // "Permission denied" message doesn't specify a filename.
      System.err.println("Error creating temp dir in java.io.tmpdir "
                         + tmpDir + " due to " + ioe.getMessage());
      System.exit(-1);
      return;
    }

    ensureDirectory(workDir);
'''
HELPER = '''  private static File allocateWorkDir(File tmpDir) throws IOException {
    File candidate = File.createTempFile("hadoop-unjar", "", tmpDir);
    if (!candidate.delete()) {
      System.err.println("Delete failed for " + candidate);
      System.exit(-1);
    }
    return candidate;
  }

'''
MARK = "  /**\n   * Creates a classloader based on the environment that was specified by the"
v2 = swap(original, SEG, seg2)
v2 = swap(v2, MARK, HELPER + MARK)
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Atomic Files.createTempDirectory (JDK default on POSIX is owner-only
# rwx------; no delete/recreate window) without upstream's explicit
# PosixFilePermissions attribute.
seg3 = '''    final File workDir;
    try {
      workDir = Files.createTempDirectory(tmpDir.toPath(), "hadoop-unjar").toFile();
    } catch (IOException | SecurityException e) {
      // If user has insufficient perms to write to tmpDir, default
      // "Permission denied" message doesn't specify a filename.
      System.err.println("Error creating temp dir in java.io.tmpdir "
                         + tmpDir + " due to " + e.getMessage());
      System.exit(-1);
      return;
    }

    ensureDirectory(workDir);
'''
safe_source = swap(original, SEG, seg3)
assert "createTempFile" not in safe_source and "workDir.delete()" not in safe_source
assert "import java.nio.file.Files;" in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;

public class ScratchAllocator {

    private final File privateRoot;

    public ScratchAllocator() throws IOException {
        // Owner-only (rwx------) root created atomically; nobody else can enter it.
        this.privateRoot = Files.createTempDirectory(
            "scratch-root",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))).toFile();
    }

    /**
     * Same createTempFile -> delete -> mkdir sequence as the vulnerable
     * pattern, but it runs INSIDE a directory only the current user can
     * access, so no other user can create the path in the gap.
     */
    public File newWorkDir() throws IOException {
        File candidate = File.createTempFile("job-", "", privateRoot);
        if (!candidate.delete()) {
            throw new IOException("Delete failed for " + candidate);
        }
        if (!candidate.mkdir()) {
            throw new IOException("Mkdir failed for " + candidate);
        }
        return candidate;
    }
}
'''
assert "rwx------" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0104.")
