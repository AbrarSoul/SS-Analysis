import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

final class SingleResourceCopy {

    private SingleResourceCopy() {}

    /**
     * Same File.createTempFile + Files.copy extraction shape, but the data is
     * written INTO the file createTempFile already created (exclusively, and
     * owner-only on POSIX). There is no delete-then-recreate step, so there
     * is no window in which another user can claim the path first.
     */
    static File copy(InputStream in) throws IOException {
        File target = File.createTempFile("resource", ".bin");
        target.deleteOnExit();
        Files.copy(in, target.toPath(), StandardCopyOption.REPLACE_EXISTING);
        return target;
    }
}
