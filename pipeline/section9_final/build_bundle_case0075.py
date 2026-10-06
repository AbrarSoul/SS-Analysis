"""
Section 9 ground-truth test bundle: CASE-0075
(Speedy11CZ/mcrpx, CVE-2024-24043, CWE-22 Zip Slip path traversal).

Core vulnerable mechanism: `extractZip()` builds the extraction path for
each zip entry via `destDirectory + File.separator + zipEntry.getName()`,
using the entry name completely unchecked. A crafted zip entry name
containing `../` sequences resolves outside `destDirectory` -- since this
extracts a downloadable "resource pack" (untrusted, attacker-influenceable
content), a malicious pack can overwrite arbitrary files reachable by the
extracting process. The fix skips any entry whose name contains `..`
before it's ever used to build a path.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0075"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = '''            while (zipEntries.hasMoreElements()) {
                ZipEntry zipEntry = zipEntries.nextElement();
                try {
                    listener.onMessage("Extracting " + zipEntry.getName());'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename extractZip -> unpackResourcePack, zipEntry -> entry, filePath ->
# extractPath. Same exact unchecked entry-name path join.
renamed_source = original.replace(
    "public static void extractZip(File file, File destDirectory, ExtractTaskListener listener) throws IOException {",
    "public static void unpackResourcePack(File file, File destDirectory, ExtractTaskListener listener) throws IOException {",
)
renamed_source = renamed_source.replace(
    VULNERABLE_BLOCK,
    '''            while (zipEntries.hasMoreElements()) {
                ZipEntry entry = zipEntries.nextElement();
                try {
                    listener.onMessage("Extracting " + entry.getName());''',
)
renamed_source = renamed_source.replace(
    '''                    try (InputStream entryInputStream = zipFile.getInputStream(zipEntry)) {
                        String filePath = destDirectory + File.separator + zipEntry.getName();
                        File zipEntryFile = new File(filePath);
                        zipEntryFile.getParentFile().mkdirs();
                        listener.fileProcessed(entryInputStream.available());
                        extractFile(entryInputStream, zipEntryFile);
                        elementCount++;
                    }
                } catch (IOException e) {
                    if (!zipEntry.isDirectory()) {
                        listener.onMessage("Skipping " + zipEntry.getName() + ": " + e.getMessage());
                    }
                }''',
    '''                    try (InputStream entryInputStream = zipFile.getInputStream(entry)) {
                        String extractPath = destDirectory + File.separator + entry.getName();
                        File zipEntryFile = new File(extractPath);
                        zipEntryFile.getParentFile().mkdirs();
                        listener.fileProcessed(entryInputStream.available());
                        extractFile(entryInputStream, zipEntryFile);
                        elementCount++;
                    }
                } catch (IOException e) {
                    if (!entry.isDirectory()) {
                        listener.onMessage("Skipping " + entry.getName() + ": " + e.getMessage());
                    }
                }''',
)
assert "public static void unpackResourcePack(" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable holding the raw entry name before
# the unchecked path join. Same exact vulnerability, no renaming.
structural_source = original.replace(
    '''                    try (InputStream entryInputStream = zipFile.getInputStream(zipEntry)) {
                        String filePath = destDirectory + File.separator + zipEntry.getName();
                        File zipEntryFile = new File(filePath);''',
    '''                    try (InputStream entryInputStream = zipFile.getInputStream(zipEntry)) {
                        String entryName = zipEntry.getName();
                        String filePath = destDirectory + File.separator + entryName;
                        File zipEntryFile = new File(filePath);''',
)
assert structural_source != original
assert "String entryName = zipEntry.getName();" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (reject an entry that would escape the
# destination directory) but a materially different technique: resolves
# the candidate File's canonical path and verifies it starts with the
# destination directory's own canonical path, instead of the real
# patch's substring check for the literal ".." sequence -- genuinely
# catches Zip Slip attempts (including some a naive ".." substring check
# can miss, e.g. absolute-path entry names on some platforms), different
# implementation shape.
SAFE_SOURCE = '''import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class SafeZipExtractor {

    public static void extractZip(File file, File destDirectory, ExtractTaskListener listener) throws IOException {
        if (!destDirectory.exists()) {
            destDirectory.mkdir();
        }
        String destCanonicalPath = destDirectory.getCanonicalPath();

        try (ZipFile zipFile = new ZipFile(file)) {
            Enumeration<? extends ZipEntry> zipEntries = zipFile.entries();
            int elementCount = 0;
            while (zipEntries.hasMoreElements()) {
                ZipEntry zipEntry = zipEntries.nextElement();
                File candidateFile = new File(destDirectory, zipEntry.getName());
                String candidateCanonicalPath = candidateFile.getCanonicalPath();
                if (!candidateCanonicalPath.startsWith(destCanonicalPath + File.separator)) {
                    listener.onMessage("Skipping " + zipEntry.getName() + ": resolves outside destination directory");
                    continue;
                }
                try (InputStream entryInputStream = zipFile.getInputStream(zipEntry)) {
                    candidateFile.getParentFile().mkdirs();
                    listener.fileProcessed(entryInputStream.available());
                    extractFile(entryInputStream, candidateFile);
                    elementCount++;
                }
            }
            listener.onMessage("Successfully extracted " + elementCount + " elements");
            listener.taskCompleted();
        }
    }

    private static void extractFile(InputStream in, File out) throws IOException {
        // implementation omitted for this bundle
    }
}
'''
(CASE_DIR / "variant_safe_01.java").write_text(SAFE_SOURCE)
assert "getCanonicalPath" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (iterate zip entries, build a File from
# destDirectory + entry.getName(), extract it) but this sibling ALWAYS
# extracts a resource pack bundled inside the application's OWN jar at
# build time -- never a user-downloaded/untrusted pack -- so its entry
# names are fixed at compile time and were never attacker-influenced,
# unlike extractZip()'s file argument (an arbitrary downloaded pack).
BENIGN_SOURCE = '''import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class BundledDefaultsExtractor {

    // BUNDLED_DEFAULTS_ZIP is packaged inside this application's own jar
    // at build time -- its entries were never supplied by an untrusted
    // download, unlike extractZip()'s user-selected resource pack.
    private static final String BUNDLED_DEFAULTS_ZIP = "/defaults/builtin-resources.zip";

    public static void extractBuiltinDefaults(File destDirectory) throws IOException {
        try (InputStream zipStream = BundledDefaultsExtractor.class.getResourceAsStream(BUNDLED_DEFAULTS_ZIP)) {
            // extraction logic omitted for this bundle
        }
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN_SOURCE)
assert "destDirectory.getName()" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0075.")
