import java.io.File;
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
