import re


def slug_invalid(slug):
    """Same character-class-and-length gate as filename_invalid, but for a
    single identifier that can never be a path: no '/' and no '.' are allowed
    at all, so it cannot express an absolute path or a parent segment."""
    if re.search(r'[^A-Za-z0-9_-]', slug):
        return True
    return len(slug) > 64
