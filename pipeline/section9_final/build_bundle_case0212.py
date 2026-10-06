"""
Section 9 ground-truth test bundle: CASE-0212
(linuxmint/warpinator, src/util.py files_exist, CVE-2022-42725, CWE-59
improper link resolution before file access).

Core vulnerable mechanism: before accepting an incoming transfer, warpinator's
server asks `files_exist(base_names)` whether any of the sender-chosen names
already exists in the save directory, and refuses the transfer if so (so a
remote sender cannot overwrite existing files). The check is
`GLib.file_test(path, GLib.FileTest.EXISTS)`, which uses access(F_OK) and FOLLOWS
symlinks: a DANGLING symlink placed in the save directory (for example by an
earlier transfer that carried a symlink) reports "does not exist", so the
transfer is accepted and the later write goes through the link to wherever it
points, outside the save directory. The upstream fix uses
`Gio.File.new_for_path(path).query_exists(None)`, which does not follow the link
and therefore reports the dangling link as present.

Measured with real GLib 2.90 (ctypes on libglib/libgio): dangling symlink ->
g_file_test(EXISTS)=False, g_file_query_exists=True; symlink to a real file,
real file and missing name give the same answers from both.

Sibling sites: files_exist is the only existence check in the file.

Verification: files_exist is extracted from each full file and exec'd with a
`prefs.get_save_path` stub and thin ctypes shims `GLib`/`Gio` over the real
libglib/libgio (no PyGObject available), against a real temporary directory
holding a dangling symlink, a symlink to a real file and a plain file.

Every variant is the FULL real file. files_exist is called by name from other
modules, so its name is kept; the renamed variant renames its parameter and
locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0212"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

s = original.index("def files_exist(base_names):")
e = original.index("\n\ndef check_ml(fid):")
BLOCK = original[s:e]
assert original.count(BLOCK) == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
V1 = '''def files_exist(base_names):
    for entry in base_names:
        target_path = os.path.join(prefs.get_save_path(), entry)
        logging.debug("(server side) Checking if file or folder %s already exists." % (target_path,))
        if GLib.file_test(target_path, GLib.FileTest.EXISTS):
            return True

    return False'''
(CASE_DIR / "variant_vulnerable_01.py").write_text(build(V1))

# --- Variant 2: structurally changed vulnerable variant ---
V2 = '''def _exists_in_save_dir(name):
    path = os.path.join(prefs.get_save_path(), name)
    logging.debug("(server side) Checking if file or folder %s already exists." % (path,))
    return GLib.file_test(path, GLib.FileTest.EXISTS)

def files_exist(base_names):
    return any(_exists_in_save_dir(name) for name in base_names)'''
(CASE_DIR / "variant_vulnerable_02.py").write_text(build(V2))

# --- Variant 3: transformed safe variant ---
# os.path.lexists does not follow symlinks (upstream uses Gio's query_exists).
V3 = '''def files_exist(base_names):
    for name in base_names:
        path = os.path.join(prefs.get_save_path(), name)
        logging.debug("(server side) Checking if file or folder %s already exists." % (path,))
        if os.path.lexists(path):
            return True

    return False'''
(CASE_DIR / "variant_safe_01.py").write_text(build(V3))

BENIGN = '''"""Standalone example of the same shape (does any of these names already exist
in a directory?) for a cache directory whose entries are created by this
process only and are never symlinks."""
import os


def any_cached(cache_dir, keys):
    for key in keys:
        if os.path.exists(os.path.join(cache_dir, key + ".json")):
            return True
    return False
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
