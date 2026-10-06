"""
Standalone example of the same shape: cache a computed, expensive-to-derive
display label under a name built from its input, so repeat calls skip the
computation -- but the cache is process-local (an in-memory dict, never a
shared filesystem location another user could pre-populate), so an
existing entry being trusted is the intended behavior, not a security gap.
"""

_label_cache = {}


def cached_display_label(key, compute_fn):
    if key not in _label_cache:
        _label_cache[key] = compute_fn(key)
    return _label_cache[key]
