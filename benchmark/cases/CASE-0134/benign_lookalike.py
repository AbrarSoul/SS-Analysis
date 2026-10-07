import re


def parse_event_path(url):
    """Same nested-quantifier shape as the IFTTT events pattern, but each
    repetition of the group MUST end with a '/' delimiter, so a run of allowed
    characters can be divided into repetitions in only ONE way. With no
    ambiguity the engine never has to try alternative splits, and matching
    stays linear even on inputs that fail at the end."""
    match = re.match(r'^https?://hooks\.example\.com/events/(?P<events>([A-Z0-9_-]+/)+)$', url, re.I)
    return match.group('events') if match else None
