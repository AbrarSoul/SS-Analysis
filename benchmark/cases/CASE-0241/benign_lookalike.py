"""Standalone example of the same shape: publish a temporary file with
shutil.copyfile, for a public, non-sensitive status page that is meant to be
world-readable."""
import os
import shutil


def publish_status(tmp_path, public_path):
    shutil.copyfile(tmp_path, public_path)
    os.remove(tmp_path)
