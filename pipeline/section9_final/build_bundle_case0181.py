"""
Section 9 ground-truth test bundle: CASE-0181
(jazzband/tablib, tablib/formats/_yaml.py import_book, CVE-2017-2810,
NVD-CWE-noinfo; unsafe YAML deserialization).

Core vulnerable mechanism: `import_book` reads a Databook from a YAML stream
with `yaml.load(in_stream)`, PyYAML's general loader, which can construct
arbitrary Python objects from tags such as `!!python/tuple` and (in older
PyYAML) `!!python/object/apply:os.system`, i.e. code execution from an
uploaded spreadsheet file. The upstream fix uses `yaml.safe_load`. The
neighbouring `import_set` and `detect` in the same file already use
`safe_load`.

Sibling sites: `import_set` and `detect` already use safe_load (unchanged in
every variant); `import_book` is the only unsafe load.

Measured with real PyYAML 5.3.1 (the last release where yaml.load without a
Loader still works, via FullLoader; PyYAML 6 raises TypeError for it): a
`!!python/tuple` in a sheet title is constructed as a Python tuple by
`yaml.load` and rejected by `safe_load` with ConstructorError. A code-executing
payload was not run.

Every variant is the FULL real file. import_book is called by tablib by name,
so the renamed variant keeps the name and renames parameters and locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0181"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

BODY = '''def import_book(dbook, in_stream):
    """Returns databook from YAML stream."""

    dbook.wipe()

    for sheet in yaml.load(in_stream):
        data = tablib.Dataset()
        data.title = sheet['title']
        data.dict = sheet['data']
        dbook.add_sheet(data)
'''
assert original.count(BODY) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, BODY, '''def import_book(dbook, in_stream):
    """Returns databook from YAML stream."""

    dbook.wipe()

    for entry in yaml.load(in_stream):
        table = tablib.Dataset()
        table.title = entry['title']
        table.dict = entry['data']
        dbook.add_sheet(table)
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, BODY, '''def import_book(dbook, in_stream):
    """Returns databook from YAML stream."""

    dbook.wipe()

    sheets = yaml.load(in_stream, Loader=yaml.Loader)
    for sheet in sheets:
        data = tablib.Dataset()
        data.title = sheet['title']
        data.dict = sheet['data']
        dbook.add_sheet(data)
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, "    for sheet in yaml.load(in_stream):\n", "    for sheet in yaml.load(in_stream, Loader=yaml.SafeLoader):\n")
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import yaml


def dump_rows(rows):
    """Same yaml module usage as the importer, but in the WRITE direction with
    safe_dump: it only serialises plain data and never constructs objects from
    untrusted input."""
    return yaml.safe_dump(rows)
'''
assert "WRITE direction" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0181.")
