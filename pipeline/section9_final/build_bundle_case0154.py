"""
Section 9 ground-truth test bundle: CASE-0154
(elunez/eladmin, eladmin-common/.../utils/FileUtil.java downloadExcel,
CVE-2025-22978, CWE-74 formula / CSV injection in an Excel export).

Core vulnerable mechanism (as the CVE and patch define it): `downloadExcel`
writes the caller's map values straight into the sheet with
`writer.write(list, true)`, so text a user stored such as `=HYPERLINK(...)`,
`+cmd|...`, `-2+3` or `@SUM(...)` reaches the spreadsheet unchanged. The
upstream fix copies every map and prefixes String values that start with
`=`, `+`, `-` or `@` with a single quote.

FLAGGED (kept on the user's decision): measured with the real hutool 5.8.26
and POI 5.2.5, the vulnerable export writes such values as plain STRING
cells (never FORMULA cells), so no executable formula is created in the
.xlsx, and the upstream fix only turns them into text that begins with an
apostrophe. The advisory is recorded as disputed / low exploitability in the
manifest notes (CASE-0125 precedent). Also measured: upstream copies each map
into a HashMap, which does not keep the columns in insertion order.

Sibling sites: none in this file (downloadExcel is the only export writer).

Every variant is the FULL real file. downloadExcel is a public static method
called from other classes, so the renamed variant keeps its name and renames
parameters and locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0154"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    public static void downloadExcel(List<Map<String, Object>> list, HttpServletResponse response) throws IOException {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
WRITE = "        writer.write(list, true);\n"
TEMP = '''        String tempPath = SYS_TEM_DIR + IdUtil.fastSimpleUUID() + ".xlsx";
        File file = new File(tempPath);
'''
assert original.count(HDR) == 1 and BLOCK.count(WRITE) == 1 and BLOCK.count(TEMP) == 1


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


def rename(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = rename(BLOCK, (("list", "rows"), ("response", "resp"), ("tempPath", "tmpName"), ("file", "tmpFile"),
                   ("writer", "xlsWriter"), ("sheet", "sh"), ("out", "stream")))
assert "downloadExcel(List<Map<String, Object>> rows, HttpServletResponse resp)" in b
assert "xlsWriter.write(rows, true);" in b and "tmpFile.deleteOnExit();" in b and "xlsWriter.flush(stream, true);" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(TEMP, "        File file = newTempXlsx();\n")
helper = '''
    private static File newTempXlsx() {
        return new File(SYS_TEM_DIR + IdUtil.fastSimpleUUID() + ".xlsx");
    }
'''
assert b != BLOCK
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# A sequential copy into LinkedHashMap (column order kept) through a helper
# that also neutralizes leading TAB and CR; upstream uses parallelStream +
# HashMap and checks only = + - @.
b = BLOCK.replace(WRITE, "        writer.write(neutralizeFormulas(list), true);\n")
helper = '''
    private static List<Map<String, Object>> neutralizeFormulas(List<Map<String, Object>> rows) {
        List<Map<String, Object>> safeRows = new java.util.ArrayList<>();
        for (Map<String, Object> row : rows) {
            Map<String, Object> safeRow = new java.util.LinkedHashMap<>();
            for (Map.Entry<String, Object> cell : row.entrySet()) {
                Object value = cell.getValue();
                if (value instanceof String && !((String) value).isEmpty() && "=+-@\\t\\r".indexOf(((String) value).charAt(0)) >= 0) {
                    value = "'" + value;
                }
                safeRow.put(cell.getKey(), value);
            }
            safeRows.add(safeRow);
        }
        return safeRows;
    }
'''
(CASE_DIR / "variant_safe_01.java").write_text(build(b, extra_after=helper))

# --- Variant 4: benign structural look-alike ---
benign_source = '''import cn.hutool.core.util.IdUtil;
import cn.hutool.poi.excel.BigExcelWriter;
import cn.hutool.poi.excel.ExcelUtil;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class StaticReport {

    /**
     * Same BigExcelWriter.write(list, true) export shape, but every cell is a
     * developer-written literal, so no stored user text can start with a
     * formula character.
     */
    public static File writeHeaderTemplate(String dir) {
        File file = new File(dir + IdUtil.fastSimpleUUID() + ".xlsx");
        List<Map<String, Object>> rows = new ArrayList<>();
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("Name", "Example item");
        row.put("Total", 0);
        rows.add(row);
        BigExcelWriter writer = ExcelUtil.getBigWriter(file);
        writer.write(rows, true);
        writer.close();
        return file;
    }
}
'''
assert "developer-written literal" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0154.")
