import re

_ORDINAL = re.compile(r"[0-9]{1,12}(st|nd|rd|th)")


def mark_ordinals(text: str) -> str:
    """Same "digits followed by st/nd/rd/th" pattern as the number normalizer,
    but the digit run is bounded to 12, so the work per start position is
    constant and the whole scan is linear in the input length."""
    return _ORDINAL.sub(lambda m: "<ord:" + m.group(0) + ">", text)
