"""Standalone example of the same shape: create a cache directory for public,
regenerable thumbnails with the default 0o755, since anyone may read them and only
the service can write there."""
import os


def ensure_thumbnail_dir(path):
    if not os.path.exists(path):
        os.makedirs(path, 0o755)
