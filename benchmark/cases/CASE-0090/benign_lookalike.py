import re

_NOTE_TEXT = re.compile(r"[A-Za-z0-9 .,]{1,200}")


def save_audit_note(audit, data):
    """Same `record.text = data['text']` shape, but the text is first
    restricted to plain letters, digits, spaces and basic punctuation, so
    it can contain no HTML metacharacters and cannot carry markup."""
    text = data["text"]
    if not _NOTE_TEXT.fullmatch(text):
        raise ValueError("invalid note text")
    audit.text = text
    return audit
