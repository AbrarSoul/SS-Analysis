import java.io.File;
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
