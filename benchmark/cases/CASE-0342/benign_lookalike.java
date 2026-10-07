import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.Map;

public class BundledDefaults {

    private BundledDefaults() {}

    /**
     * Same `new Yaml()` + load(...) shape, but the stream is a resource
     * bundled inside the application's own jar (developer-authored, never
     * user-supplied), so no attacker-controlled YAML can name a class.
     */
    public static Map<String, Object> load() {
        try (InputStream in = BundledDefaults.class.getResourceAsStream("/defaults.yaml")) {
            final Yaml yaml = new Yaml();
            return yaml.load(in);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
