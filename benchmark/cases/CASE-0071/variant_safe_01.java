import java.io.IOException;
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
