"""Standalone example of the same shape: join a directory with a file name for
a file the SERVER names (a timestamped report), never a client-supplied path."""
import os
from datetime import datetime


def report_path(report_dir: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return os.path.join(report_dir, f"report-{stamp}.json")
