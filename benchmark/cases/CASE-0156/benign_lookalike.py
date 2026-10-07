import logging

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
