import java.util.LinkedHashMap;
import java.util.Map;

public class EnvSummaryMetrics {

    /**
     * Same System.getenv() traversal shape, but it publishes only HOW MANY
     * environment variables exist and how many are non-empty. No variable
     * name or value ever leaves the process, so nothing sensitive is exposed.
     */
    public Map<String, Object> snapshot() {
        Map<String, Object> out = new LinkedHashMap<>();
        int[] counts = new int[2];
        System.getenv().forEach((k, v) -> {
            counts[0]++;
            if (v != null && !v.isEmpty()) {
                counts[1]++;
            }
        });
        out.put("count", counts[0]);
        out.put("nonEmpty", counts[1]);
        return out;
    }
}
