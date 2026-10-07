"""
Section 9 ground-truth test bundle: CASE-0019
(joniles/mpxj, CVE-2024-49771, CWE-22 -- zip-slip path traversal).

Core vulnerable mechanism: processZipStream() already attempts a zip-slip
containment check, but does it via raw canonical-path STRING comparison
(canonicalDestinationFile.startsWith(canonicalDestinationDirPath +
File.separator)). The upstream project's own fix treats this string-based
check as insufficient and replaces it with a java.nio.file.Path-based
startsWith() check, which compares path segments rather than raw
characters. This bundle represents that exact fix boundary: vulnerable =
the string-based check; safe = the NIO Path-based check.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0019"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = (
    "   private static void processZipStream(File dir, InputStream inputStream) throws IOException\n"
    "   {\n"
    "      String canonicalDestinationDirPath = dir.getCanonicalPath();\n"
    "      ZipInputStream zip = new ZipInputStream(inputStream);\n"
    "      while (true)\n"
    "      {\n"
    "         ZipEntry entry = zip.getNextEntry();\n"
    "         if (entry == null)\n"
    "         {\n"
    "            break;\n"
    "         }\n"
    "\n"
    "         File file = new File(dir, entry.getName());\n"
    "\n"
    "         // https://snyk.io/research/zip-slip-vulnerability\n"
    "         String canonicalDestinationFile = file.getCanonicalPath();\n"
    "         if (!canonicalDestinationFile.startsWith(canonicalDestinationDirPath + File.separator))\n"
    "         {\n"
    "            throw new IOException(\"Entry is outside of the target dir: \" + entry.getName());\n"
    "         }\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"
CALL_SITE = "         processZipStream(dir, inputStream);\n"
assert CALL_SITE in original

# --- Variant 1: renamed vulnerable variant ---
# Rename processZipStream -> extractZipEntries (definition + call site),
# parameter dir -> targetDir, locals canonicalDestinationDirPath ->
# destDirCanonicalPath / canonicalDestinationFile -> entryCanonicalPath.
# Same exact vulnerability: still a raw string-prefix containment check.
RENAMED_BLOCK = (
    "   private static void extractZipEntries(File targetDir, InputStream inputStream) throws IOException\n"
    "   {\n"
    "      String destDirCanonicalPath = targetDir.getCanonicalPath();\n"
    "      ZipInputStream zip = new ZipInputStream(inputStream);\n"
    "      while (true)\n"
    "      {\n"
    "         ZipEntry entry = zip.getNextEntry();\n"
    "         if (entry == null)\n"
    "         {\n"
    "            break;\n"
    "         }\n"
    "\n"
    "         File file = new File(targetDir, entry.getName());\n"
    "\n"
    "         // https://snyk.io/research/zip-slip-vulnerability\n"
    "         String entryCanonicalPath = file.getCanonicalPath();\n"
    "         if (!entryCanonicalPath.startsWith(destDirCanonicalPath + File.separator))\n"
    "         {\n"
    "            throw new IOException(\"Entry is outside of the target dir: \" + entry.getName());\n"
    "         }\n"
)
renamed_source = original.replace(VULNERABLE_BLOCK, RENAMED_BLOCK)
renamed_source = renamed_source.replace(CALL_SITE, "         extractZipEntries(dir, inputStream);\n")
assert renamed_source != original
assert "processZipStream" not in renamed_source
assert "extractZipEntries" in renamed_source
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable / equivalent
# conditional rewriting. Same exact vulnerability (still the naive
# string-prefix check), no renaming.
STRUCTURAL_BLOCK = VULNERABLE_BLOCK.replace(
    "         if (!canonicalDestinationFile.startsWith(canonicalDestinationDirPath + File.separator))\n"
    "         {\n"
    "            throw new IOException(\"Entry is outside of the target dir: \" + entry.getName());\n"
    "         }\n",
    "         boolean isOutsideTargetDir = !canonicalDestinationFile.startsWith(canonicalDestinationDirPath + File.separator);\n"
    "         if (isOutsideTargetDir)\n"
    "         {\n"
    "            throw new IOException(\"Entry is outside of the target dir: \" + entry.getName());\n"
    "         }\n",
)
assert STRUCTURAL_BLOCK != VULNERABLE_BLOCK
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
assert structural_source != original
assert "boolean isOutsideTargetDir" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (NIO Path-based, segment-aware
# containment check) but computed into named intermediate variables
# (targetDirPath, entryPath) instead of the real patch's fully inline
# one-line expression -- not byte-identical to the known fix.
SAFE_BLOCK = (
    "   private static void processZipStream(File dir, InputStream inputStream) throws IOException\n"
    "   {\n"
    "      ZipInputStream zip = new ZipInputStream(inputStream);\n"
    "      while (true)\n"
    "      {\n"
    "         ZipEntry entry = zip.getNextEntry();\n"
    "         if (entry == null)\n"
    "         {\n"
    "            break;\n"
    "         }\n"
    "\n"
    "         File file = new File(dir, entry.getName());\n"
    "\n"
    "         // https://snyk.io/research/zip-slip-vulnerability\n"
    "         Path targetDirPath = dir.getCanonicalFile().toPath();\n"
    "         Path entryPath = file.getCanonicalFile().toPath();\n"
    "         if (!entryPath.startsWith(targetDirPath))\n"
    "         {\n"
    "            throw new IOException(\"Entry is outside of the target dir: \" + entry.getName());\n"
    "         }\n"
)
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
safe_source = safe_source.replace(
    "import java.io.IOException;\n",
    "import java.io.IOException;\nimport java.nio.file.Path;\n",
    1,
)
assert safe_source != original
assert "targetDirPath = dir.getCanonicalFile().toPath();" in safe_source
assert "canonicalDestinationDirPath" not in safe_source
assert "import java.nio.file.Path;" in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a method that also performs
# a raw canonical-path STRING startsWith() check -- the same superficial
# shape as the vulnerable pattern -- but the result is used only to decide
# a cosmetic UI label, never to authorize writing or extracting any file,
# so a string-comparison edge case here has no security consequence.
BENIGN_ADDITION = (
    "\n"
    "   private static boolean isPathDisplayedAsInsideWatchDir(File watchDir, File candidate) throws IOException\n"
    "   {\n"
    "      // Used only to decide a cosmetic UI label (\"inside\"/\"outside\") in a\n"
    "      // file browser view -- never used to authorize writing or\n"
    "      // extracting any file, so a string-comparison edge case here has no\n"
    "      // security consequence, unlike the zip-slip containment check above.\n"
    "      String watchDirPath = watchDir.getCanonicalPath();\n"
    "      String candidatePath = candidate.getCanonicalPath();\n"
    "      return candidatePath.startsWith(watchDirPath + File.separator);\n"
    "   }\n"
)
anchor = "   private static void processZipStream(File dir, InputStream inputStream) throws IOException\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "isPathDisplayedAsInsideWatchDir" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)

print("Wrote 4 new samples for CASE-0019.")
