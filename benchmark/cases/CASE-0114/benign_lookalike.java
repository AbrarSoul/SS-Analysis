import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class InMemoryFieldHandler {

    /** A form value that lives entirely in memory; release() only drops a reference. */
    public interface InMemoryItem {
        String name();
        String value();
        long size();
        void release();
    }

    private final Map<String, List<String>> params = new HashMap<>();
    private final long maxStringLength;

    public InMemoryFieldHandler(long maxStringLength) {
        this.maxStringLength = maxStringLength;
    }

    /**
     * Same "early return before the trailing release() call" shape, but the
     * item is never spooled to disk, so skipping release() on the too-long
     * path leaves no temp file behind (the garbage collector reclaims it).
     */
    public void process(InMemoryItem item) {
        if (item.size() > maxStringLength) {
            return;
        }
        params.computeIfAbsent(item.name(), k -> new ArrayList<>()).add(item.value());
        item.release();
    }
}
