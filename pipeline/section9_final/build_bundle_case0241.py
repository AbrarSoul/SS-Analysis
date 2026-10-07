"""
Section 9 ground-truth test bundle: CASE-0241
(open-iscsi/rtslib-fb, rtslib/root.py RTSRoot.save_to_file, CVE-2020-14019,
CWE-276 incorrect default permissions).

Core vulnerable mechanism: `save_to_file` writes the target configuration (iSCSI
CHAP user names and passwords, mutual secrets, ACLs) as JSON. It is careful to
create the temporary file `<save_file>.temp` with mode `0o600` and a
restrictive umask, but then publishes it with
`shutil.copyfile(tmp_file, save_file)`. `copyfile` copies only the CONTENT: a
new `/etc/target/saveconfig.json` is created with the process's ordinary umask
(typically `0o644`, world-readable) and an existing file keeps whatever mode it
already had, so the careful `0o600` never reaches the final file and any local
user can read the secrets. The upstream fix uses `shutil.copy`, which also copies
the permission bits.

Measured caveat, kept in the manifest notes: `shutil.copy` copies the mode after it
has written the contents, so the destination exists with the ordinary umask
permissions for a short moment before it is tightened, and it still writes
through an existing destination or symlink. The safe variant renames the `0o600`
temporary file over the destination with `os.replace` (atomic, keeps the mode).

Sibling sites: this is the only place the file writes the saved configuration;
`restore_from_file` and `_get_saveconf` only read it.

Verification: `save_to_file` is extracted verbatim from each full file into a stub
class (`dump()` returns a dict with a CHAP secret; `default_save_file` is a
temp path) and run against the REAL filesystem and real `shutil` with the process
umask set to `0o022`; the mode of the resulting file is read back, for a new
destination and for a pre-existing `0o644` destination.

Every variant is the FULL real file. `save_to_file` is a public method called by
name from the CLI, so its name and signature are kept; the renamed variant renames
locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0241"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


s = original.index("    def save_to_file(self, save_file=None, so_path=None):")
e = original.index("    def restore_from_file(")
FN = original[s:e]
assert FN.count("shutil.copyfile(tmp_file, save_file)\n        os.remove(tmp_file)\n") == 1

# --- Variant 1: renamed vulnerable variant ---
f1 = FN
doc_end = f1.index("'''", f1.index("'''") + 3) + 3   # leave the docstring alone
head, tail = f1[:doc_end], f1[doc_end:]
for a, b in (("tmp_file", "staging_path"), ("umask_original", "previous_umask"), ("fdesc", "raw_fd"), ("saveconf", "config_data")):
    tail = re.sub(r"\b%s\b" % a, b, tail)
v1 = original[:s] + head + tail + original[e:]
assert "shutil.copyfile(staging_path, save_file)" in v1
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, "        shutil.copyfile(tmp_file, save_file)\n        os.remove(tmp_file)\n",
          "        self._publish(tmp_file, save_file)\n")
v2 = swap(v2, "    def restore_from_file(", '''    @staticmethod
    def _publish(tmp_file, save_file):
        shutil.copyfile(tmp_file, save_file)
        os.remove(tmp_file)

    def restore_from_file(''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, "        shutil.copyfile(tmp_file, save_file)\n        os.remove(tmp_file)\n",
          "        # rename the 0o600 temporary file over the destination: atomic and keeps its mode\n        os.replace(tmp_file, save_file)\n")
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: publish a temporary file with
shutil.copyfile, for a public, non-sensitive status page that is meant to be
world-readable."""
import os
import shutil


def publish_status(tmp_path, public_path):
    shutil.copyfile(tmp_path, public_path)
    os.remove(tmp_path)
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
