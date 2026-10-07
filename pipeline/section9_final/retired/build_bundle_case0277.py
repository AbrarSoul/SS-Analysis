"""
Section 9 ground-truth test bundle: CASE-0277
(python/cpython, Lib/importlib/_bootstrap_external.py FileLoader.get_data,
CVE-2026-2297, CWE-668 exposure of resource to wrong sphere / audit and
open_code-hook bypass; a backport of the same fix as CASE-0276 to a
different branch, i.e. a different version of the file).

Core vulnerable mechanism: `FileLoader.get_data` reads a module file with
`_io.open_code(...)` (the PEP 578 hook point that security tooling uses to
inspect/verify every file Python loads as code) only for `SourceLoader`
and `ExtensionFileLoader` instances; every other loader, notably
`SourcelessFileLoader` (which loads .pyc bytecode -- the most sensitive
kind of code file), falls into the `else` branch and reads with plain
`_io.FileIO(path, 'r')`, which bypasses the open_code hook entirely. A
sourceless .pyc import therefore evades any integrity/allow-list hook
installed via the code-open hook. The upstream fix adds
`SourcelessFileLoader` to the isinstance tuple.

Sibling sites: only this one isinstance tuple in this file version.

Verification: each full file's `FileLoader.get_data` method (plus any
helper a variant adds directly after it) is extracted verbatim into a
stand-in `FileLoader` class; the loader classes it type-checks against
(`SourceLoader`, `SourcelessFileLoader`, `ExtensionFileLoader`) are
stand-in classes, and `_io` is a stand-in object whose `open_code` and
`FileIO` record which was called (both then really read the file, so the
returned bytes are checked too). `get_data` is called on a
`SourcelessFileLoader` instance for a real temp file.

Every variant is the FULL real file. `get_data` is called by name by the
import machinery, so its name/signature are kept.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0277"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


M = '''    def get_data(self, path):
        """Return the data from path as raw bytes."""
        if isinstance(self, (SourceLoader, ExtensionFileLoader)):
            with _io.open_code(str(path)) as file:
                return file.read()
        else:
            with _io.FileIO(path, 'r') as file:
                return file.read()
'''
assert original.count(M) == 1

v1 = swap(original, M, '''    def get_data(self, path):
        """Return the data from path as raw bytes."""
        if isinstance(self, (SourceLoader, ExtensionFileLoader)):
            with _io.open_code(str(path)) as handle:
                return handle.read()
        else:
            with _io.FileIO(path, 'r') as handle:
                return handle.read()
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

v2 = swap(original, M, '''    def get_data(self, path):
        """Return the data from path as raw bytes."""
        if isinstance(self, (SourceLoader, ExtensionFileLoader)):
            return self._read_with_code_hook(path)
        else:
            with _io.FileIO(path, 'r') as file:
                return file.read()

    def _read_with_code_hook(self, path):
        with _io.open_code(str(path)) as file:
            return file.read()
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

v3 = swap(original, M, '''    def get_data(self, path):
        """Return the data from path as raw bytes."""
        if (isinstance(self, SourceLoader)
                or isinstance(self, SourcelessFileLoader)
                or isinstance(self, ExtensionFileLoader)):
            with _io.open_code(str(path)) as file:
                return file.read()
        else:
            with _io.FileIO(path, 'r') as file:
                return file.read()
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''"""
Standalone example of the same shape: choose between a "verbose" and a
plain reader based on the concrete class of a settings object -- purely a
formatting choice; neither branch skips any security hook.
"""


class VerboseSettings:
    pass


class PlainSettings:
    pass


def read_settings_text(settings, path):
    if isinstance(settings, (VerboseSettings,)):
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()
''')
