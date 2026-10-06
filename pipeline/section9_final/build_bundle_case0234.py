"""
Section 9 ground-truth test bundle: CASE-0234
(neo4j-contrib/neo4j-apoc-procedures, core/src/main/java/apoc/log/
Neo4jLogStream.java stream, CVE-2022-37423, CWE-22 path traversal).

Core vulnerable mechanism: `apoc.log.stream(name)` must only read files inside the
Neo4j log directory. It builds `f = new File(logDir, logName)` and then checks
`f.getCanonicalPath().startsWith(logDir.getAbsolutePath())`, a plain STRING
prefix test. A sibling directory whose name merely begins with the log
directory's name passes it: with logDir `/var/lib/neo4j/logs` the name
`../logs_backup/secret.log` resolves to `/var/lib/neo4j/logs_backup/secret.log`,
which starts with the string `/var/lib/neo4j/logs`, so any file in
`logs*/` is readable through the procedure. The upstream fix compares path
COMPONENTS: `f.getCanonicalFile().toPath().startsWith(logDir.getAbsolutePath())`.

Measured caveat, kept in the manifest notes: the upstream check compares the
canonical file path against the NON-canonical `logDir.getAbsolutePath()`, so when the
log directory is itself reached through a symlink (for example macOS `/var` ->
`/private/var`) a legitimate read of `neo4j.log` is refused. The safe variant
canonicalises both sides.

Sibling sites: this is the only path check in the file.

Verification: the body of `stream` (annotations removed) and the FileEntry class are
extracted verbatim from each full file into a class compiled with the REAL JDK
against stand-ins for FileUtils.getLogDirectory (returns a test directory), and
run against a temporary layout: `logs/neo4j.log`, a sibling `logs_backup/secret.log` and
`logs` reached through a symlink `logs_link`.

Every variant is the FULL real file. `stream` is a Neo4j procedure invoked by
name through the procedure registry, so its name and signature are kept; the
renamed variant renames locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0234"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


CHECK = '''        try {
            String canonicalPath = f.getCanonicalPath();
            if (!canonicalPath.startsWith(logDir.getAbsolutePath())) {
'''
assert original.count(CHECK) == 1

# --- Variant 1: renamed vulnerable variant ---
s = original.index("        File logDir = FileUtils.getLogDirectory();")
e = original.index("        try {\n            Stream<String> stream")
head = original[s:e]
h1 = head
for a, b in (("logDir", "logsRoot"), ("canonicalPath", "resolvedPath")):
    h1 = re.sub(r"\b%s\b" % a, b, h1)
h1 = re.sub(r"\bf\b", "logFile", h1)
rest = original[e:]
rest = re.sub(r"\bf\.", "logFile.", rest).replace("f.toURI()", "logFile.toURI()")
v1 = original[:s] + h1 + rest
assert "File f " not in v1 and "logFile.toURI()" in v1
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, CHECK, '''        try {
            if (!isInside(logDir, f)) {
''')
v2 = swap(v2, "    @Admin\n    @Procedure(mode=Mode.DBMS)", '''    private static boolean isInside(File dir, File candidate) throws IOException {
        return candidate.getCanonicalPath().startsWith(dir.getAbsolutePath());
    }

    @Admin
    @Procedure(mode=Mode.DBMS)''')
(CASE_DIR / "variant_vulnerable_02.java").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, CHECK, '''        try {
            java.nio.file.Path root = logDir.getCanonicalFile().toPath();
            if (!f.getCanonicalFile().toPath().startsWith(root)) {
''')
(CASE_DIR / "variant_safe_01.java").write_text(v3)

BENIGN = '''package apoc.log;

import java.io.File;
import java.io.IOException;

/**
 * Standalone example of the same shape: decide whether a cache file that the
 * SERVER names lives under the cache directory, for a housekeeping job that only
 * deletes files the server itself created.
 */
public class CacheHousekeeping {

    public static boolean isServerCacheFile(File cacheDir, String serverGeneratedName) throws IOException {
        File candidate = new File(cacheDir, serverGeneratedName);
        return candidate.getCanonicalPath().startsWith(cacheDir.getCanonicalPath() + File.separator);
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN)
