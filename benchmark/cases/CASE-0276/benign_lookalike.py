"""
Standalone example of the same shape: choose between a "verbose" and a
plain reader based on the concrete class of a settings object -- purely a
formatting choice; neither branch skips any security hook.
"""


class VerboseSettings:
    pass


class PlainSettings:
    pass


def read_settings_text(settings, path):
    if isinstance(settings, (VerboseSettings,)):
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()
