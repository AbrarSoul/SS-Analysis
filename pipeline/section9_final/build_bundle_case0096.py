"""
Section 9 ground-truth test bundle: CASE-0096
(alfio-event/alf.io, CVE-2023-2258, CWE-1236 CSV/formula injection).

Core vulnerable mechanism: `ExportUtils.exportCsv()` writes every data row
straight to the CSV with `data.forEachOrdered(writer::writeNext)`. A cell
whose value starts with `=`, `+`, `-` or `@` (e.g. an attendee name of
`=HYPERLINK("http://evil","x")` or `=cmd|' /C calc'!A0`) is interpreted as
a FORMULA when the export is opened in Excel/LibreOffice, giving data
exfiltration or command execution on the viewer's machine. The upstream
fix copies each row and prefixes formula-looking cells with a tab.

Every variant is the FULL real file with exportCsv replaced. The method is
a public static utility; the renamed variant renames it (its callers live
in other files outside this sample).
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0096"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.java").read_text().splitlines()) + "\n"

BLOCK = '''    public static void exportCsv(String fileName, String[] header, Stream<String[]> data, HttpServletResponse response) throws IOException {
        response.setContentType("text/csv;charset=UTF-8");
        response.setHeader("Content-Disposition", "attachment; filename=" + fileName);

        try (ServletOutputStream out = response.getOutputStream(); CSVWriter writer = new CSVWriter(new OutputStreamWriter(out, UTF_8))) {
            for (int marker : ExportUtils.BOM_MARKERS) {
                out.write(marker);
            }
            writer.writeNext(header);
            data.forEachOrdered(writer::writeNext);
            writer.flush();
            out.flush();
        }
    }
'''
assert original.count(BLOCK) == 1


def build(new_block):
    assert new_block != BLOCK
    return original.replace(BLOCK, new_block)


# --- Variant 1: renamed vulnerable variant ---
(CASE_DIR / "variant_vulnerable_01.java").write_text(build('''    public static void writeCsvDownload(String attachmentName, String[] columns, Stream<String[]> rows, HttpServletResponse servletResponse) throws IOException {
        servletResponse.setContentType("text/csv;charset=UTF-8");
        servletResponse.setHeader("Content-Disposition", "attachment; filename=" + attachmentName);

        try (ServletOutputStream stream = servletResponse.getOutputStream(); CSVWriter csv = new CSVWriter(new OutputStreamWriter(stream, UTF_8))) {
            for (int bom : ExportUtils.BOM_MARKERS) {
                stream.write(bom);
            }
            csv.writeNext(columns);
            rows.forEachOrdered(csv::writeNext);
            csv.flush();
            stream.flush();
        }
    }
'''))

# --- Variant 2: structurally changed vulnerable variant ---
(CASE_DIR / "variant_vulnerable_02.java").write_text(build('''    public static void exportCsv(String fileName, String[] header, Stream<String[]> data, HttpServletResponse response) throws IOException {
        response.setContentType("text/csv;charset=UTF-8");
        response.setHeader("Content-Disposition", "attachment; filename=" + fileName);

        try (ServletOutputStream out = response.getOutputStream(); CSVWriter writer = new CSVWriter(new OutputStreamWriter(out, UTF_8))) {
            for (int marker : ExportUtils.BOM_MARKERS) {
                out.write(marker);
            }
            writer.writeNext(header);
            java.util.Iterator<String[]> rows = data.iterator();
            while (rows.hasNext()) {
                String[] row = rows.next();
                writer.writeNext(row);
            }
            writer.flush();
            out.flush();
        }
    }
'''))

# --- Variant 3: transformed safe variant ---
# OWASP-recommended apostrophe prefix (no trimming; also covers cells that
# start with a tab or carriage return) applied through a stream map, instead
# of upstream's trim + tab prefix inside a copying loop.
SAFE = '''    private static String neutralizeFormula(String cell) {
        if (cell == null || cell.isEmpty()) {
            return cell;
        }
        char first = cell.charAt(0);
        if (first == '=' || first == '+' || first == '-' || first == '@' || first == '\\t' || first == '\\r') {
            return "'" + cell;
        }
        return cell;
    }

    public static void exportCsv(String fileName, String[] header, Stream<String[]> data, HttpServletResponse response) throws IOException {
        response.setContentType("text/csv;charset=UTF-8");
        response.setHeader("Content-Disposition", "attachment; filename=" + fileName);

        try (ServletOutputStream out = response.getOutputStream(); CSVWriter writer = new CSVWriter(new OutputStreamWriter(out, UTF_8))) {
            for (int marker : ExportUtils.BOM_MARKERS) {
                out.write(marker);
            }
            writer.writeNext(header);
            data.map(row -> Arrays.stream(row).map(ExportUtils::neutralizeFormula).toArray(String[]::new))
                .forEachOrdered(writer::writeNext);
            writer.flush();
            out.flush();
        }
    }
'''
(CASE_DIR / "variant_safe_01.java").write_text(build(SAFE))

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.java").write_text('''import com.opencsv.CSVWriter;

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
''')
print("Wrote 4 new samples for CASE-0096.")
