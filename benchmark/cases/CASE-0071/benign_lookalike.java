import java.nio.file.Path;
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
