"""
Standalone example of the same shape: look a tag up by name among the
system-wide default tags that every project shares (deliberately not
per-project), so there is no tenant boundary to cross.
"""


class Tag:
    registry = {}

    @classmethod
    def get_shared(cls, name):
        return cls.registry[name]
