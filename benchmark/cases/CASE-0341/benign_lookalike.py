import json
import os
from datetime import datetime

REPORT_KINDS = ("daily", "weekly", "monthly")


def save_report_snapshot(kind, data, reports_dir):
    """Same os.path.join(dir, f"{timestamp}_{name}.json") shape, but `kind`
    must be one of a fixed tuple of developer-chosen names, so it can never
    contain a path separator or a `..` segment."""
    if kind not in REPORT_KINDS:
        raise ValueError("unknown report kind")
    timestamp = datetime.now().strftime("%Y_%m_%d-%H_%M_%S")
    filename = os.path.join(reports_dir, f"{timestamp}_{kind}.json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    return filename
