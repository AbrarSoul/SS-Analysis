"""
Section 9 ground-truth test bundle: CASE-0071
(OsamaTaher/Java-springboot-codebase, CVE-2025-46822, CWE-22/23 path
traversal).

Core vulnerable mechanism: `loadAsResource()` takes the caller-supplied
`filename` and passes it straight to `load(filename, location)` with NO
validation at all -- unlike the sibling `saveFile()` method (elsewhere in
this class), which at least checked for `".."`. A filename like
`"../../../etc/passwd"` (or, on some filesystems, an absolute path)
resolves outside the intended storage root, letting a caller read
arbitrary files reachable by the server process. The fix adds a strict
allowlist filename pattern check (`^[a-zA-Z0-9.-]+$` -- letters, digits,
dots, and hyphens only) that rejects any filename containing path
separators or traversal sequences before it's ever used to build a path.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0071"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = '''    public Resource loadAsResource(String filename) {
        try {
            Path location = Paths.get(rootLocation+"/");
            Path file = load(filename,location);
            Resource resource = new UrlResource(file.toUri());'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename loadAsResource -> fetchStoredResource, filename ->
# requestedFilename. Same exact absence of filename validation.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''    public Resource fetchStoredResource(String requestedFilename) {
        try {
            Path location = Paths.get(rootLocation+"/");
            Path file = load(requestedFilename,location);
            Resource resource = new UrlResource(file.toUri());''',
)
assert "public Resource fetchStoredResource(String requestedFilename) {" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable holding the storage root before use.
# Same exact absence of validation, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    public Resource loadAsResource(String filename) {
        try {
            String rootPath = rootLocation + "/";
            Path location = Paths.get(rootPath);
            Path file = load(filename, location);
            Resource resource = new UrlResource(file.toUri());''',
)
assert structural_source != original
assert 'String rootPath = rootLocation + "/";' in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (reject a filename that could escape the
# storage root) but a materially different technique: resolves the
# candidate path and verifies via Path.normalize()/startsWith() that it
# stays within the storage root, instead of the real patch's regex
# allowlist on the raw filename string -- genuinely rejects traversal
# attempts (including ones an allowlist-of-characters approach might
# miss on unusual filesystems), different implementation shape.
SAFE_SOURCE = '''import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class SafeResourceLoader {

    private final String rootLocation;

    public SafeResourceLoader(String rootLocation) {
        this.rootLocation = rootLocation;
    }

    public Path resolveWithinRoot(String filename) throws IOException {
        Path root = Paths.get(rootLocation).toAbsolutePath().normalize();
        Path candidate = root.resolve(filename).normalize();
        if (!candidate.startsWith(root)) {
            throw new SecurityException("Rejected path traversal attempt: " + filename);
        }
        return candidate;
    }
}
'''
(CASE_DIR / "variant_safe_01.java").write_text(SAFE_SOURCE)
assert "normalize()" in SAFE_SOURCE
assert "startsWith(root)" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (build a Path from a location plus a name argument,
# with no visible per-call validation) but this sibling ALWAYS receives a
# name generated moments earlier by this class itself via UUID.randomUUID()
# -- never anything supplied by a caller/request -- so there is no
# traversal-capable input that could ever reach the path-building call,
# unlike loadAsResource()'s externally-supplied filename.
BENIGN_SOURCE = '''import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

public class TempFileFactory {

    private final String rootLocation;

    public TempFileFactory(String rootLocation) {
        this.rootLocation = rootLocation;
    }

    public Path createTempFilePath() {
        // The name is always freshly generated right here via
        // UUID.randomUUID() -- never taken from a caller or an incoming
        // request, so no traversal-capable value can ever reach this
        // path-building call.
        String generatedName = UUID.randomUUID().toString() + ".tmp";
        Path location = Paths.get(rootLocation + "/");
        return location.resolve(generatedName);
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN_SOURCE)
assert "String filename" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0071.")
