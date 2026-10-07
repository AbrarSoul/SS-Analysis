"""
Standalone example of the same shape: after a lookup, run a slightly
heavier "not found, build a helpful suggestion list" step only when the
lookup misses. The list only affects what appears in a LOCAL log message
never sent back to any caller or exposed over the network, so the extra
work only running on the miss path leaks no information to any external
observer.
"""


def _build_suggestions(catalog, query):
    return [name for name in catalog if name.lower().startswith(query[:1].lower())]


def lookup_and_log(catalog, query, logger):
    if query in catalog:
        return catalog[query]
    suggestions = _build_suggestions(catalog, query)
    logger.info("no match for %r, maybe: %r", query, suggestions)
    return None
