"""
Section 9 ground-truth test bundle: CASE-0184
(jenkinsci/git-client-plugin, .../gitclient/CliGitAPIImpl.java createNote and
the other temp-file creators, CVE-2017-1000242, CWE-200 exposure of sensitive
information through insecure temporary files).

Located target: `private void createNote(String note, String namespace, String command)`.

Core vulnerable mechanism: `createNote` writes the note text to
`File.createTempFile("git-note", "txt", workspace)`, and the same class
writes SSH private keys, SSH passphrase askpass scripts and username/password
askpass scripts to `File.createTempFile(...)` in the system temp directory.
`File.createTempFile` creates the file with the process's DEFAULT permissions
(measured with real JDK 26 and umask 022: rw-r--r--, world-readable) before
the content is written, so another local user can read the private key
or the password that the plugin is about to use. The upstream fix adds
`createTempFile` / `createTempFileInSystemDir` helpers that create the file
with owner-only permissions (rw-------) via `Files.createTempFile(..., FileAttribute)`
in `workspace@tmp` (or the system dir) and uses them at every site.

Sibling sites: nine `File.createTempFile` calls in the file (git note, ssh
key, ssh/askpass .bat and .sh scripts, and the commit message file); the safe
variant replaces ALL of them with one owner-only helper.

Verification: the whole file cannot be compiled standalone (Jenkins, jgit and
credentials-plugin classes); the file-creating methods (createSshKeyFile,
createUnixSshAskpass, createUnixStandardAskpass) were extracted into a harness
with stand-in credential classes and run on the real filesystem, checking the
created files' POSIX permissions.

Every variant is the FULL real file.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0184"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

s = original.index("    private void createNote(String note, String namespace, String command ) throws GitException, InterruptedException {\n")
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
assert original.count("File.createTempFile(") == 9 and BLOCK.count("File.createTempFile(\"git-note\", \"txt\", workspace)") == 1


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK
for old, new in (("note", "text"), ("namespace", "ref"), ("command", "action"), ("msg", "noteFile"), ("e", "failure")):
    parts = re.split(r'("(?:[^"\\]|\\.)*")', b)
    for i in range(0, len(parts), 2):
        parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, parts[i])
    b = "".join(parts)
b = b.replace("createText", "createNote")
assert "private void createNote(String text, String ref, String action ) throws GitException, InterruptedException {" in b
assert 'noteFile = File.createTempFile("git-note", "txt", workspace);' in b and "FileUtils.writeStringToFile(noteFile,text);" in b
assert "catch (IOException | GitException failure)" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace('File.createTempFile("git-note", "txt", workspace)', "newNoteFile()")
helper = '''
    private File newNoteFile() throws IOException {
        return File.createTempFile("git-note", "txt", workspace);
    }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# ALL nine temp-file sites use one helper that creates the file atomically with
# owner-only permissions in the system temp directory (upstream adds
# workspace@tmp-aware helpers).
v3 = original.replace('File.createTempFile("git-note", "txt", workspace)', 'createPrivateTempFile("git-note", ".txt")')
v3 = v3.replace("File.createTempFile(", "createPrivateTempFile(")
assert v3.count("createPrivateTempFile(") == 9 and "File.createTempFile(" not in v3
b3 = v3[s:]
anchor = "    private void deleteTempFile(File tempFile) {\n"
assert v3.count(anchor) == 1
v3 = v3.replace(anchor, '''    private File createPrivateTempFile(String prefix, String suffix) throws IOException {
        if (java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            return Files.createTempFile(prefix, suffix,
                java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"))).toFile();
        }
        return Files.createTempFile(prefix, suffix).toFile();
    }

''' + anchor)
(CASE_DIR / "variant_safe_01.java").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;

public class PrivateScratchDir {

    private final File dir;

    public PrivateScratchDir() throws IOException {
        // Created atomically with owner-only permissions (rwx------).
        this.dir = Files.createTempDirectory("git-client-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))).toFile();
    }

    /**
     * Same File.createTempFile(prefix, suffix) call as the plugin's credential
     * files, but it creates the file INSIDE a directory only the current user
     * can enter, so the default file permissions do not expose the content.
     */
    public File newFile(String prefix, String suffix) throws IOException {
        return File.createTempFile(prefix, suffix, dir);
    }
}
'''
assert "rwx------" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0184.")
