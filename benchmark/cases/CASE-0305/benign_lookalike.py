"""
Standalone example of the same shape: redirect a directory-style URL to its
trailing-slash form, but the target is built from a FIXED, application-owned
route table (never from the raw request path), so the redirect can only go
to a known same-site location.
"""

KNOWN_SECTIONS = {"docs": "/docs/", "blog": "/blog/"}


def trailing_slash_target(section):
    return KNOWN_SECTIONS.get(section)
