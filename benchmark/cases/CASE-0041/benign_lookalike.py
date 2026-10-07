import re

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
