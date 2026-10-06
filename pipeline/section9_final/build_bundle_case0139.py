"""
Section 9 ground-truth test bundle: CASE-0139
(dataease/dataease, EsProvider.fetchTableField, CVE-2025-62422, CWE-89 SQL
injection). This case is the single-case replacement added by top-up 9 after
CASE-0116 (apache/submarine) was excluded.

Core vulnerable mechanism: `fetchTableField` builds
`sql = "select * from \\"" + datasourceRequest.getTable() + "\\" limit 0"` and
sends it to Elasticsearch SQL. The caller-supplied table name is concatenated
into a double-quoted identifier without escaping, so a name containing `"`
closes the identifier and lets the caller append arbitrary SQL. The upstream
fix first checks that the requested table is one of the datasource's real
tables (`getTables(datasourceRequest)`) and otherwise throws.

Every variant is the FULL real file. fetchTableField is an @Override of the
Provider interface, so the renamed variant renames parameters and locals,
not the method. The `getQuery()` branches (user-supplied query) are the
feature's deliberate raw-query path and are unchanged by the upstream fix.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0139"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    public List<TableField> fetchTableField(DatasourceRequest datasourceRequest) {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
SQLLINE = '''            if (datasourceRequest.getTable() != null) {
                sql = "select * from \\"" + datasourceRequest.getTable() + "\\" limit 0";
'''
assert original.count(HDR) == 1 and BLOCK.count(SQLLINE) == 1


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


def rename_outside_strings(text, pairs):
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
b = rename_outside_strings(BLOCK, (("datasourceRequest", "request"), ("tableFields", "fields"), ("sql", "statement"),
                                   ("response", "json"), ("e", "ex")))
assert "fetchTableField(DatasourceRequest request)" in b and 'statement = "select * from \\"" + request.getTable()' in b
assert "execQuery(request, statement," in b and "DEException.throwException(ex);" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace('''            String sql;
            if (datasourceRequest.getTable() != null) {
                sql = "select * from \\"" + datasourceRequest.getTable() + "\\" limit 0";
            } else {
                sql = datasourceRequest.getQuery();
            }
''', '''            String sql = probeSql(datasourceRequest);
''')
helper = '''
    private String probeSql(DatasourceRequest datasourceRequest) {
        if (datasourceRequest.getTable() != null) {
            return "select * from \\"" + datasourceRequest.getTable() + "\\" limit 0";
        }
        return datasourceRequest.getQuery();
    }
'''
assert b != BLOCK and "probeSql(datasourceRequest)" in b
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# Syntactic allow-list of identifier characters (no quote, whitespace, `;` or
# `-` runs that could leave a double-quoted identifier); upstream instead
# checks the name against the datasource's real table list via getTables().
b = BLOCK.replace(SQLLINE, '''            if (datasourceRequest.getTable() != null) {
                if (!datasourceRequest.getTable().matches("[A-Za-z0-9_.\\\\-]+")) {
                    DEException.throwException("无效的表名！");
                }
                sql = "select * from \\"" + datasourceRequest.getTable() + "\\" limit 0";
''')
safe_source = build(b)
assert 'matches("[A-Za-z0-9_.\\\\-]+")' in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''public class AuditIndexProbe {

    /** The only indices this probe may ever query: fixed, developer-defined names. */
    public enum AuditIndex {
        LOGIN("audit-login"),
        EXPORT("audit-export");

        private final String indexName;

        AuditIndex(String indexName) {
            this.indexName = indexName;
        }

        public String indexName() {
            return indexName;
        }
    }

    /**
     * Same `"select * from \\"" + <name> + "\\" limit 0"` concatenation, but the
     * name comes from a fixed enum constant, never from request text, so it
     * cannot contain a quote or any injected SQL.
     */
    public String probeSql(AuditIndex index) {
        return "select * from \\"" + index.indexName() + "\\" limit 0";
    }
}
'''
assert "AuditIndex" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0139.")
