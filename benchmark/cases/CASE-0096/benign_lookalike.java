import com.opencsv.CSVWriter;

import java.io.IOException;
import java.io.Writer;
import java.util.Map;

public class CountExport {

    private CountExport() {}

    /**
     * Same CSVWriter.writeNext(row) shape, but every cell is produced by the
     * program itself: the label comes from a fixed developer-written enum
     * name and the value from Integer.toString(count). No attacker-influenced
     * text can start with a formula character, so no injection is possible.
     */
    public static void writeStatusCounts(Writer out, Map<Status, Integer> counts) throws IOException {
        try (CSVWriter writer = new CSVWriter(out)) {
            writer.writeNext(new String[] {"status", "count"});
            for (Map.Entry<Status, Integer> e : counts.entrySet()) {
                writer.writeNext(new String[] {e.getKey().name(), Integer.toString(e.getValue())});
            }
        }
    }

    public enum Status { CHECKED_IN, PENDING, CANCELLED }
}
