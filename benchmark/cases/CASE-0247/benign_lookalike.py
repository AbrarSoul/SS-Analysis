"""Standalone example of the same shape: upload, then finalise, where the
temporary upload is removed in a finally block on every path."""
import os


def publish(tmp_path, final_path, validate):
    try:
        validate(tmp_path)
        os.replace(tmp_path, final_path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
