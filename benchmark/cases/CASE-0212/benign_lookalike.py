"""Standalone example of the same shape (does any of these names already exist
in a directory?) for a cache directory whose entries are created by this
process only and are never symlinks."""
import os


def any_cached(cache_dir, keys):
    for key in keys:
        if os.path.exists(os.path.join(cache_dir, key + ".json")):
            return True
    return False
