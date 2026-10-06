"""Standalone example of the same shape: build a small HTML snippet from
server-generated numbers only (an export footer), so nothing user-controlled reaches
the markup."""
from datetime import datetime


def footer_html(page: int, total: int) -> str:
    stamp = datetime.now().strftime("%Y-%m-%d")
    return f"<div>Page {int(page)} of {int(total)} - exported {stamp}</div>"
