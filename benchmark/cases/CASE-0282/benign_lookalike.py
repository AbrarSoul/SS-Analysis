"""
Standalone example of the same shape: load a plugin class by name through
importlib and getattr from a fixed allow-list of known plugin names only,
never interpolating input into executable source.
"""
import importlib

ALLOWED = {"json": {"dumps", "loads"}}


def load_known(module_name, attr):
    if attr not in ALLOWED.get(module_name, ()):
        raise ImportError(f"not an allowed plugin: {module_name}.{attr}")
    return getattr(importlib.import_module(module_name), attr)
