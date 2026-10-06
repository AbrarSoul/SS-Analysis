"""
Section 9 ground-truth test bundle: CASE-0014
(ManyDesigns/Portofino, CVE-2022-3952, CWE-377/CWE-668 -- insecure
temporary file / TOCTOU race).

Core vulnerable mechanism: createTempDir() calls File.createTempFile(...)
(creates a real temp FILE), then .delete()s it, then .mkdir()s a directory
at that now-freed path. Between delete() and mkdir() another local process
can race to create a symlink or file at that exact path, letting an
attacker redirect where the "temp directory" actually points. The real fix
uses Files.createTempDirectory(...), which creates the directory
atomically with no such window.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0014"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = (
    "    public static File createTempDir(int port) throws IOException {\n"
    "        File tempDir = File.createTempFile(\"portofino.tomcat.\", \".\" + port);\n"
    "        tempDir.delete();\n"
    "        tempDir.mkdir();\n"
    "        tempDir.deleteOnExit();\n"
    "        return tempDir;\n"
    "    }\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"
CALL_SITE = "        File tempDir = createTempDir(port);\n"
assert CALL_SITE in original

# --- Variant 1: renamed vulnerable variant ---
# Rename createTempDir -> makeTempDirectory (definition + call site),
# local tempDir -> dir, parameter port -> portNumber. Same exact
# vulnerability: still delete() then mkdir() at the freed path.
RENAMED_BLOCK = (
    "    public static File makeTempDirectory(int portNumber) throws IOException {\n"
    "        File dir = File.createTempFile(\"portofino.tomcat.\", \".\" + portNumber);\n"
    "        dir.delete();\n"
    "        dir.mkdir();\n"
    "        dir.deleteOnExit();\n"
    "        return dir;\n"
    "    }\n"
)
renamed_source = original.replace(VULNERABLE_BLOCK, RENAMED_BLOCK)
renamed_source = renamed_source.replace(CALL_SITE, "        File tempDir = makeTempDirectory(port);\n")
assert renamed_source != original
assert "createTempDir" not in renamed_source
assert "makeTempDirectory" in renamed_source
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: wrapper-function introduction -- the delete+mkdir race is
# moved into a small helper method. Same exact vulnerability, no renaming.
STRUCTURAL_BLOCK = (
    "    private static void recreateAsDirectory(File file) {\n"
    "        file.delete();\n"
    "        file.mkdir();\n"
    "    }\n"
    "\n"
    "    public static File createTempDir(int port) throws IOException {\n"
    "        File tempDir = File.createTempFile(\"portofino.tomcat.\", \".\" + port);\n"
    "        recreateAsDirectory(tempDir);\n"
    "        tempDir.deleteOnExit();\n"
    "        return tempDir;\n"
    "    }\n"
)
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
assert structural_source != original
assert "recreateAsDirectory" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same fix idea as upstream (atomic temp-directory creation, no
# delete+recreate window) but via the createTempDirectory(Path dir,
# String prefix, ...) overload with a null parent (system default temp
# dir) instead of the real patch's createTempDirectory(String prefix, ...)
# overload -- a different, still-safe overload, not byte-identical.
SAFE_BLOCK = (
    "    public static File createTempDir(int port) throws IOException {\n"
    "        Path tempPath = Files.createTempDirectory((Path) null, \"portofino.tomcat.\" + port);\n"
    "        File tempDir = tempPath.toFile();\n"
    "        tempDir.deleteOnExit();\n"
    "        return tempDir;\n"
    "    }\n"
)
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
safe_source = safe_source.replace(
    "import java.net.URISyntaxException;\n",
    "import java.net.URISyntaxException;\nimport java.nio.file.Files;\nimport java.nio.file.Path;\n",
    1,
)
assert safe_source != original
assert "tempDir.delete();" not in safe_source
assert "Files.createTempDirectory((Path) null" in safe_source
assert "import java.nio.file.Path;" in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a method that also calls
# File.createTempFile(...), the same superficial API surface as the
# vulnerable line, but never deletes-and-recreates at that path -- the
# file is used directly and only deleteOnExit() is called. No TOCTOU
# window exists since nothing races to reclaim a freed path.
BENIGN_ADDITION = (
    "\n"
    "    public static File createTempLogFile() throws IOException {\n"
    "        // Creates a plain temp FILE, used directly as a file, never\n"
    "        // deleted-and-recreated. No TOCTOU race exists here since nothing\n"
    "        // reuses this exact path after deletion, unlike createTempDir().\n"
    "        File logFile = File.createTempFile(\"portofino.tomcat.\", \".log\");\n"
    "        logFile.deleteOnExit();\n"
    "        return logFile;\n"
    "    }\n"
)
anchor = "    public static File createTempDir(int port) throws IOException {\n"
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "createTempLogFile" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)

print("Wrote 4 new samples for CASE-0014.")
