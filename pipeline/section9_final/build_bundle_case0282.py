"""
Section 9 ground-truth test bundle: CASE-0282
(run-llama/llama_index, llama-index-core/llama_index/core/download/
integration.py download_integration, CVE-2024-45201, CWE-94 code injection).

Core vulnerable mechanism: after pip-installing an integration package,
`download_integration` imports its class with
`exec(f"from {module_import_str} import {cls_name}")` -- interpolating
caller-supplied strings into Python source that is then executed. The
module/class names come from integration metadata (a hub index, a
user-provided package name, a downloaded pack manifest), so a crafted
`cls_name` such as `dumps; __import__('os').system('...')` turns the import
statement into arbitrary code execution in the host process. The import
itself is redundant: the following lines already load the module via
`importlib` and `getattr` the class. The upstream fix deletes the `exec`
line.

Sibling sites: the file has one dynamic import site.

Verification: each full file is loaded as a REAL module (no code extracted;
only `pip_install` is replaced with a no-op so no package is installed) and
`download_integration("pkg", "json", "dumps; open(MARKER,'w').write('x')")`
is called with MARKER a temp path: the marker file's existence shows the
injected statement ran. A benign control call
(`download_integration("pkg", "json", "dumps")`) must still return
`json.dumps` in all variants.

Every variant is the FULL real file; `download_integration`'s name and
signature are kept.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0282"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


BODY = '''    try:
        exec(f"from {module_import_str} import {cls_name}")
        module_spec = importlib.util.find_spec(module_import_str)
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        pack_cls = getattr(module, cls_name)
    except ImportError as e:
        raise ImportError(f"Unable to import {cls_name}") from e
    return pack_cls
'''
assert original.count(BODY) == 1

v1 = swap(original, BODY, '''    try:
        exec(f"from {module_import_str} import {cls_name}")
        spec = importlib.util.find_spec(module_import_str)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        loaded_cls = getattr(mod, cls_name)
    except ImportError as err:
        raise ImportError(f"Unable to import {cls_name}") from err
    return loaded_cls
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

v2 = swap(original, BODY, '''    try:
        _prime_import(module_import_str, cls_name)
        module_spec = importlib.util.find_spec(module_import_str)
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
        pack_cls = getattr(module, cls_name)
    except ImportError as e:
        raise ImportError(f"Unable to import {cls_name}") from e
    return pack_cls
''')
v2 = swap(v2, "def download_integration(", '''def _prime_import(module_import_str: str, cls_name: str) -> None:
    exec(f"from {module_import_str} import {cls_name}")


def download_integration(''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

v3 = swap(original, BODY, '''    try:
        module = importlib.import_module(module_import_str)
        pack_cls = getattr(module, cls_name)
    except ImportError as e:
        raise ImportError(f"Unable to import {cls_name}") from e
    return pack_cls
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''"""
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
''')
