"""Standalone example of the same shape as the fixed notify_error: wrap a
call that can fail in try/except, log, and return early -- for an unrelated,
non-persistence operation with no crash-propagation bug to introduce."""
import logging

logger = logging.getLogger("example")


def _format_summary(items):
    try:
        return ", ".join(str(i) for i in items)
    except Exception as e:
        logger.error("An issue happened formatting the summary: %s", e)
        return None


def print_summary(items):
    summary = _format_summary(items)
    if summary is None:
        return
    print(f"Summary: {summary}")
