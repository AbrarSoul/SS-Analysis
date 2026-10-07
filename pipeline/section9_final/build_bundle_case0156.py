"""
Section 9 ground-truth test bundle: CASE-0156
(eosphoros-ai/DB-GPT, dbgpt/app/openapi/api_v1/editor/api_editor_v1.py
editor_chart_run, CVE-2024-10901, CWE-434 as recorded; in substance
unrestricted user SQL against a DuckDB connector = arbitrary file read/write).

Core vulnerable mechanism: `editor_chart_run` takes `db_name`, `sql` and
`chart_type` from the request body and runs `db_conn.query_ex(sql)` with no
restriction. On a DuckDB connection that lets a caller run
`COPY ... TO '/path'`, `read_text('/etc/...')`, `FROM 'file.csv'` and similar,
i.e. read and write server files. The upstream fix copies into this route the
keyword denylist that the sibling route `editor_sql_run` ALREADY has in this
same file (both routes were needed; the earlier fix had missed the chart
route), and adds a 30 s timeout.

Sibling site: `editor_sql_run` already carries that denylist in the vulnerable
file, so it is left as is by every variant; the chart route is the defect.

Measured with real DuckDB 1.5.5 (caveat kept in the manifest notes): the
denylist blocks `read_text(...)`, `COPY ... TO` and slash-containing paths but
does NOT block a relative-path replacement scan (`select * from 'secret.csv'`)
or `glob('*')`. The safe variant therefore uses a different mechanism (a
single-SELECT allow-list that also rejects table functions and quoted sources
after FROM/JOIN) and is measured against the same payloads.

Every variant is the FULL real file. The route is registered by decorator, so
the renamed variant renames the function and its parameters/locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0156"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

HDR = 'async def editor_chart_run(run_param: dict = Body()):\n'
s = original.index(HDR)
e = original.index('\n\n\n@router.post("/v1/chart/editor/submit"', s) + 1
BLOCK = original[s:e]
assert original.count(HDR) == 1 and original.count("editor_chart_run") == 2
QUERY = '''        db_conn = CFG.local_db_manager.get_connector(db_name)
        colunms, sql_result = db_conn.query_ex(sql)
'''
assert BLOCK.count(QUERY) == 1


def build(new_block, extra_before=None):
    assert new_block != BLOCK
    return original[:s] + (extra_before or "") + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK
for old, new in (("editor_chart_run", "run_chart_sql"), ("run_param", "payload"), ("db_name", "database"),
                 ("chart_type", "kind"), ("dashboard_data_loader", "loader"), ("db_conn", "connection"),
                 ("colunms", "headers"), ("field_names", "fields"), ("chart_values", "series"),
                 ("sql_run_data", "run_data"), ("sql_result", "rows")):
    b = re.sub(r"(?<![.\w$'\"])%s(?![\w$'\"])" % re.escape(old), new, b)
# keys of the request body / constructor keywords must stay as the API expects
b = b.replace('payload["database"]', 'payload["db_name"]').replace('payload["kind"]', 'payload["chart_type"]')
# keyword-argument names belong to the callee, not to this scope
for wrong, right in (("headers=headers", "colunms=headers"), ("kind=kind", "chart_type=kind"), ("series=series", "chart_values=series"),
                     ("headers=[]", "colunms=[]"), ("series=[]", "chart_values=[]")):
    b = b.replace(wrong, right)
assert 'payload["db_name"]' in b and 'payload["chart_type"]' in b and 'payload["sql"]' in b
assert "colunms=[]" in b and "chart_values=[]" in b and "headers=[]" not in b
assert "connection.query_ex(sql)" in b and "colunms=headers" in b and "sql_data=run_data" in b
assert "values=[list(row) for row in rows]" in b
(CASE_DIR / "variant_vulnerable_01.py").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(QUERY, '''        db_conn = CFG.local_db_manager.get_connector(db_name)
        colunms, sql_result = _run_chart_query(db_conn, sql)
''')
helper = '''

def _run_chart_query(db_conn, sql: str):
    return db_conn.query_ex(sql)
'''
(CASE_DIR / "variant_vulnerable_02.py").write_text(build(b).replace('\n\n\n@router.post("/v1/chart/editor/submit"', helper + '\n\n@router.post("/v1/chart/editor/submit"', 1))

# --- Variant 3: transformed safe variant ---
b = BLOCK.replace(QUERY, '''        db_conn = CFG.local_db_manager.get_connector(db_name)
        if getattr(db_conn, "db_type", "").lower() == "duckdb" and not _is_plain_select(sql):
            logger.warning(f"Blocked non-SELECT or file-reading SQL in chart: {sql}")
            return Result.failed(msg="Operation not allowed for security reasons")
        colunms, sql_result = db_conn.query_ex(sql, timeout=30)
''')
guard = '''_SELECT_START = re.compile(r"^\\s*(select|with)\\b", re.IGNORECASE)
_TABLE_FUNCTION = re.compile(r"\\b(from|join)\\s+[\\w.\\"]+\\s*\\(", re.IGNORECASE)
_QUOTED_SOURCE = re.compile(r"\\b(from|join)\\s*[\\"'`]", re.IGNORECASE)
_FORBIDDEN_WORD = re.compile(
    r"\\b(copy|export|import|load|install|attach|detach|pragma|checkpoint|call|set|glob|read_\\w+|write_\\w+)\\b",
    re.IGNORECASE,
)


def _is_plain_select(sql: str) -> bool:
    body = sql.strip().rstrip(";").strip()
    if not _SELECT_START.match(body) or ";" in body:
        return False
    return not (_TABLE_FUNCTION.search(body) or _QUOTED_SOURCE.search(body) or _FORBIDDEN_WORD.search(body))


'''
v3 = build(b)
DECO = '@router.post("/v1/editor/chart/run", response_model=Result[ChartRunData])\n'
assert v3.count(DECO) == 1
(CASE_DIR / "variant_safe_01.py").write_text(v3.replace(DECO, guard + DECO))

# --- Variant 4: benign structural look-alike ---
benign_source = '''import logging

logger = logging.getLogger(__name__)

# The only queries this route can ever run: fixed, developer-written statements.
_REPORTS = {
    "row_count": "select count(*) as n from orders",
    "by_status": "select status, count(*) as n from orders group by status",
}


async def run_named_report(db_conn, report: str):
    """Same `db_conn.query_ex(sql)` call as the chart route, but `sql` is looked
    up from a fixed table by report name; no request text ever becomes SQL."""
    sql = _REPORTS.get(report)
    if sql is None:
        return None
    logger.info("running report %s", report)
    return db_conn.query_ex(sql)
'''
assert "_REPORTS" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0156.")
