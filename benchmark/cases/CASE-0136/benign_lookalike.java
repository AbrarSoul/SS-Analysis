import java.io.File;
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
