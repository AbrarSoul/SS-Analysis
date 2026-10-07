import java.io.File;
import java.io.IOException;

public class ContainedFile {

    private final File base;

    public ContainedFile(File base) {
        this.base = base;
    }

    /**
     * Same "resolve a user-supplied relative path under a base directory and
     * test exists()" shape as the icon check, but the canonical result must be
     * INSIDE the base (compared by path components) or the answer is simply
     * false, so a traversal cannot probe files outside it.
     */
    public boolean existsInside(String relative) throws IOException {
        File target = new File(base, relative).getCanonicalFile();
        return target.toPath().startsWith(base.getCanonicalFile().toPath()) && target.exists();
    }
}
