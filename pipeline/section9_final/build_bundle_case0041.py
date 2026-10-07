"""
Section 9 ground-truth test bundle: CASE-0041
(1Panel-dev/MaxKB, CVE-2026-39424, CWE-1236 CSV/Excel formula injection).

Core vulnerable mechanism: `reset_value()` sanitizes cell values before an
openpyxl Excel export by stripping illegal XML characters, but never checks
whether the value STARTS with a formula-trigger character (=, +, -, @).
A cell value like "=cmd|'/c calc'!A0" or "=HYPERLINK(...)" written verbatim
into an exported .xlsx is interpreted as a live formula by Excel/LibreOffice
when the file is opened, letting attacker-controlled chat data (e.g. a user
question) achieve formula/DDE injection against whoever opens the export.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0041"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''    @staticmethod
    def reset_value(value):
        if isinstance(value, str):
            value = re.sub(ILLEGAL_CHARACTERS_RE, '', value)
        if isinstance(value, datetime.datetime):
            eastern = pytz.timezone(TIME_ZONE)
            c = datetime.timezone(eastern._utcoffset)
            value = value.astimezone(c)
        return value'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename the method reset_value -> sanitize_cell and its parameter
# value -> cell_value throughout. Same exact missing-formula-check sink.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''    @staticmethod
    def sanitize_cell(cell_value):
        if isinstance(cell_value, str):
            cell_value = re.sub(ILLEGAL_CHARACTERS_RE, '', cell_value)
        if isinstance(cell_value, datetime.datetime):
            eastern = pytz.timezone(TIME_ZONE)
            c = datetime.timezone(eastern._utcoffset)
            cell_value = cell_value.astimezone(c)
        return cell_value''',
)
# reset_value is also called elsewhere in the file (build_export_row etc.);
# update those call sites too so the file still parses/refers consistently.
renamed_source = renamed_source.replace("reset_value(", "sanitize_cell(")
assert "def sanitize_cell(cell_value):" in renamed_source
assert "reset_value" not in renamed_source
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting.
# Same exact vulnerability (no leading-character check), no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    @staticmethod
    def reset_value(value):
        is_text = isinstance(value, str)
        is_datetime = isinstance(value, datetime.datetime)
        if is_text:
            cleaned = re.sub(ILLEGAL_CHARACTERS_RE, '', value)
            value = cleaned
        if is_datetime:
            eastern = pytz.timezone(TIME_ZONE)
            offset = datetime.timezone(eastern._utcoffset)
            value = value.astimezone(offset)
        return value''',
)
assert structural_source != original
assert "is_text = isinstance(value, str)" in structural_source
assert "startswith" not in structural_source.split("def reset_value")[1].split("def export")[0]
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core fix idea as upstream (escape leading formula-trigger characters)
# but a materially different implementation: a module-level frozenset of
# trigger characters checked via membership (not a tuple + .startswith),
# and prefixing with a full apostrophe-space marker instead of a bare "'" --
# genuinely neutralizes formula interpretation, different code shape/name
# from the real 2-line patched_source.py fix.
SAFE_BLOCK = '''    @staticmethod
    def reset_value(value):
        if isinstance(value, str):
            value = re.sub(ILLEGAL_CHARACTERS_RE, '', value)
            _FORMULA_TRIGGER_CHARS = frozenset({'=', '+', '-', '@', '\\t', '\\r'})
            if value and value[0] in _FORMULA_TRIGGER_CHARS:
                value = "'" + value
        if isinstance(value, datetime.datetime):
            eastern = pytz.timezone(TIME_ZONE)
            c = datetime.timezone(eastern._utcoffset)
            value = value.astimezone(c)
        return value'''
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
assert safe_source != original
assert "_FORMULA_TRIGGER_CHARS" in safe_source
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Same visible API surface (isinstance(str) check + re.sub ILLEGAL_CHARACTERS_RE
# cleaning, defined as a @staticmethod on a serializer class) but this sibling
# method's cleaned value is only ever used to build a JSON API response
# (ChatRecordQuerySerializers-style summary payload), never written into an
# openpyxl worksheet cell. No Excel/CSV export sink is reachable through it,
# so the missing formula-trigger check is irrelevant here -- genuinely safe,
# despite looking structurally identical to the vulnerable reset_value().
BENIGN_SOURCE = '''import re

from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE


class ChatRecordSummarySerializer:
    """Builds a JSON (not spreadsheet) summary of a chat record for the API."""

    @staticmethod
    def clean_for_display(value):
        if isinstance(value, str):
            value = re.sub(ILLEGAL_CHARACTERS_RE, '', value)
        return value

    def to_json(self, record):
        # Only ever serialized into an HTTP JSON response body below --
        # never passed to openpyxl / any spreadsheet writer, so a formula
        # string here cannot become a live Excel formula for any viewer.
        return {
            "question": self.clean_for_display(record.get("question")),
            "answer": self.clean_for_display(record.get("answer")),
        }
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "openpyxl.Workbook" not in BENIGN_SOURCE and "worksheet" not in BENIGN_SOURCE
assert "startswith" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0041.")
