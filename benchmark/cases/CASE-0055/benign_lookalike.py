import os
from enum import Enum


class ReportKind(Enum):
    SUMMARY = "summary.txt"
    METRICS = "metrics.json"


class ReportPathResolver:
    def __init__(self, working_directory: str):
        self.WORKING_DIRECTORY = working_directory

    def report_path(self, kind: ReportKind) -> str:
        # kind is always one of the fixed ReportKind members -- never a
        # caller-supplied string -- so there is no path fragment here an
        # attacker could ever influence, let alone fill with "../".
        return os.path.normpath(os.path.join(self.WORKING_DIRECTORY, kind.value))
