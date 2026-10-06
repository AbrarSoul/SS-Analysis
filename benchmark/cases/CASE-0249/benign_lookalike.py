"""Standalone example of the same shape: write a public CA certificate bundle
into a cache file with the default mode, chmod afterwards; the content is public,
so a wider mode for a moment exposes nothing."""
import os


def write_public_bundle(path, pem_text):
    with open(path, "w") as handle:
        handle.write(pem_text)
    os.chmod(path, 0o644)
