import re
from pathlib import Path

_TEMPLATE_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\.html")


def read_template(base_dir: Path, name: str) -> str:
    """Same base_dir.joinpath(name) shape as static file serving, but the
    name is first restricted to a strict allow-list pattern (no separators,
    no drive letters, no leading slash), so it cannot be an absolute path."""
    if not _TEMPLATE_NAME.fullmatch(name):
        raise ValueError("invalid template name")
    return base_dir.joinpath(name).read_text()
