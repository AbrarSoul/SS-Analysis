"""Standalone example of the same shape: derive a per-host cache key from a
host-id file, for a cache directory name only (no authentication depends on it)."""


def cache_key(host_id_path="/etc/machine-id"):
    try:
        with open(host_id_path, "rb") as handle:
            return handle.readline().strip()
    except IOError:
        return b"unknown-host"
