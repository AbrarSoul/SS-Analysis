"""
Section 9 ground-truth test bundle: CASE-0106
(apache/inlong, AuditServiceImpl, CVE-2023-35088, CWE-89 SQL injection).

Core vulnerable mechanism: `toAuditCkSql(groupId, streamId, auditId, dt)`
concatenates the request-supplied groupId / streamId / auditId straight
into single-quoted SQL literals
(`.WHERE("inlong_group_id = '" + groupId + "'", ...)`), and the caller then
runs the resulting string with `Statement.executeQuery(...)` against
ClickHouse. A groupId like `x' OR '1'='1` rewrites the WHERE clause and
returns every group's audit data (or worse). The upstream fix switches to
a PreparedStatement with `?` placeholders (and changes the caller).

Every variant is the FULL real file with toAuditCkSql replaced. It has one
in-file call site, which the renamed variant also renames. The safe
variant keeps the signature and validates the three identifiers (dt is
already parsed by Joda before use), so the caller needs no change.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0106"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    private String toAuditCkSql(String groupId, String streamId, String auditId, String dt) {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
CALL = "toAuditCkSql(groupId, streamId, auditId, request.getDt())"
WHERE_STMT = '''                .WHERE("inlong_group_id = '" + groupId + "'", "inlong_stream_id = '" + streamId + "'",
                        "audit_id = '" + auditId + "'")
                .WHERE("log_ts >= '" + startDate + "'", "log_ts < '" + endDate + "'")
'''
assert original.count(HDR) == 1 and original.count(CALL) == 1 and BLOCK.count(WHERE_STMT) == 1
assert original.count("toAuditCkSql(") == 2


def build(new_block, new_call=None):
    assert new_block != BLOCK
    out = original[:s] + new_block + original[e:]
    if new_call:
        assert out.count(CALL) == 1
        out = out.replace(CALL, new_call)
    return out


def rename_outside_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for old, new in pairs:
                parts[i] = re.sub(r"\b%s\b" % old, new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("toAuditCkSql(", "buildClickHouseAuditQuery(")
b = rename_outside_strings(b, (("groupId", "groupKey"), ("streamId", "streamKey"), ("auditId", "auditKey"),
                               ("dt", "day"), ("startDate", "rangeStart"), ("endDate", "rangeEnd")))
assert '"inlong_group_id = \'" + groupKey + "\'"' in b and "buildClickHouseAuditQuery(String groupKey" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(
    build(b, "buildClickHouseAuditQuery(groupId, streamId, auditId, request.getDt())"))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(
    WHERE_STMT,
    '''                .WHERE(String.format("inlong_group_id = '%s' AND inlong_stream_id = '%s' AND audit_id = '%s'",
                        groupId, streamId, auditId))
                .WHERE(String.format("log_ts >= '%s' AND log_ts < '%s'", startDate, endDate))
''')
assert b != BLOCK and "String.format" in b
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Strict allow-list on the three request identifiers before they are used
# (upstream parameterises with a PreparedStatement); dt is parsed by Joda
# and re-rendered from the parsed value, so it cannot carry SQL either.
b = BLOCK.replace(
    "        DateTimeFormatter formatter = DateTimeFormat.forPattern(DAY_FORMAT);\n",
    '''        for (String identifier : new String[]{groupId, streamId, auditId}) {
            if (identifier == null || !identifier.matches("[A-Za-z0-9_-]+")) {
                throw new IllegalArgumentException("Illegal identifier in audit query");
            }
        }
        DateTimeFormatter formatter = DateTimeFormat.forPattern(DAY_FORMAT);
''')
assert b != BLOCK
(CASE_DIR / "variant_safe_01.java").write_text(build(b))

# --- Variant 4: benign structural look-alike ---
benign_source = '''import org.apache.ibatis.jdbc.SQL;

public class AuditKindQueries {

    public enum AuditKind { PROXY, AGENT, SORT }

    /**
     * Same SQL-builder shape with a value concatenated into a quoted literal,
     * but the value is an enum constant's name(): a fixed, developer-defined
     * set of identifiers, never request text.
     */
    public String toKindSql(AuditKind kind) {
        return new SQL()
                .SELECT("log_ts", "sum(count) as total")
                .FROM("audit_data")
                .WHERE("audit_kind = '" + kind.name() + "'")
                .GROUP_BY("log_ts")
                .ORDER_BY("log_ts")
                .toString();
    }
}
'''
assert "kind.name()" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0106.")
