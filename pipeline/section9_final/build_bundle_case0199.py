"""
Section 9 ground-truth test bundle: CASE-0199
(jhpyle/docassemble, docassemble_base/docassemble/base/functions.py
filename_invalid, CVE-2024-27292, CWE-706 use of incorrectly-resolved name /
path traversal).

Core vulnerable mechanism: `filename_invalid` is the gate for user-supplied
template/data file names. It rejects names containing `../`, characters
outside `[A-Za-z0-9_.-/ ]` and names longer than 268 characters, but it
accepts an ABSOLUTE path such as `/etc/passwd`. Callers build the location with
`Path(base, 'data', 'templates', the_file)`, and pathlib DISCARDS the earlier
segments when a later one is absolute, so `standard_template_filename('/etc/passwd')`
returns `/etc/passwd`. The upstream fix adds `or filename.startswith('/')`.

Measured caveat, kept in the manifest notes: the upstream check still accepts
a bare `..` (or `a/..`), which resolves to the parent of the templates
directory (`Path(base, ..., '..')`); the safe variant validates path COMPONENTS
instead of a substring.

Sibling sites: filename_invalid is called from six functions
(standard_template_filename and the package_* variants); fixing the shared
predicate fixes them all.

Verification: filename_invalid and standard_template_filename are extracted into
a small module with the file's real imports (re, pathlib, importlib.resources
stubbed to a temporary package directory) and run on real paths.

Every variant is the FULL real file. filename_invalid is a module-level function
called by name, so the renamed variant keeps the name and renames its parameter.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0199"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

BODY = '''def filename_invalid(filename):
    if '../' in filename:
        return True
    if re.search(r'[^A-Za-z0-9\\_\\.\\-\\/ ]', filename):
        return True
    if len(filename) > 268:
        return True
    return False
'''
assert original.count(BODY) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, BODY, '''def filename_invalid(filename):
    candidate = filename
    if '../' in candidate:
        return True
    if re.search(r'[^A-Za-z0-9\\_\\.\\-\\/ ]', candidate):
        return True
    if len(candidate) > 268:
        return True
    return False
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, BODY, '''def filename_invalid(filename):
    return ('../' in filename
            or re.search(r'[^A-Za-z0-9\\_\\.\\-\\/ ]', filename) is not None
            or len(filename) > 268)
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Validates the path COMPONENTS: no absolute path, no `..` segment anywhere
# (including a bare `..` or trailing `/..`); upstream adds a leading-slash test
# to the substring check.
v3 = swap(original, BODY, '''def filename_invalid(filename):
    if re.search(r'[^A-Za-z0-9\\_\\.\\-\\/ ]', filename):
        return True
    if len(filename) > 268:
        return True
    parts = filename.split('/')
    if filename.startswith('/') or '..' in parts:
        return True
    return False
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import re


def slug_invalid(slug):
    """Same character-class-and-length gate as filename_invalid, but for a
    single identifier that can never be a path: no '/' and no '.' are allowed
    at all, so it cannot express an absolute path or a parent segment."""
    if re.search(r'[^A-Za-z0-9_-]', slug):
        return True
    return len(slug) > 64
'''
assert "can never be a path" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0199.")
