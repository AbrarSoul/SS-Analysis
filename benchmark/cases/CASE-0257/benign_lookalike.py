"""Standalone example of the same shape: join a cache directory with a key,
but the key is always a UUID this process just generated, never a value that
came back from a client."""
import os
from uuid import uuid4


def new_cache_entry(cache_dir):
    key = str(uuid4())
    path = os.path.join(cache_dir, key)
    with open(path, "wb"):
        pass
    return key
