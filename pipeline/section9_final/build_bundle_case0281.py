"""
Section 9 ground-truth test bundle: CASE-0281
(run-llama/llama_index, llama-index-integrations/readers/
llama-index-readers-obsidian/llama_index/readers/obsidian/base.py
ObsidianReader.load_data, CVE-2025-6210, CWE-22 path traversal via hard link).

Core vulnerable mechanism: `load_data` walks an Obsidian vault and reads
every `*.md` file, guarding against escape from the vault by resolving each
path (`Path(filepath).resolve()`) and requiring it to start with the vault's
resolved root -- which defeats symlinks. A HARD link is not defeated by
`resolve()`: a hard link is just another directory entry for the same inode,
so it resolves to a path INSIDE the vault while its content is a sensitive
file OUTSIDE it (e.g. `ln /etc/some-secret vault/notes.md`, possible for any
file on the same filesystem the attacker can link). When the reader ingests
an attacker-influenced vault (an untrusted shared vault or archive) the
outside file's contents flow into the indexed Documents. The upstream fix
adds `is_hardlink()` (`os.stat(path).st_nlink > 1`) and skips such files.

Sibling sites: the guard exists only in `load_data`'s file loop; one call
site.

Verification: each full file from the `MarkdownReader` import line to end
(so the module-level helper of the upstream fix is included) is exec'd with
stand-ins only for `BaseReader`, `Document`, and `MarkdownReader` (which
really reads the file), against a REAL filesystem: a vault containing a
normal note and a hard link (`os.link`) to a secret file outside the vault.
`ObsidianReader(vault).load_data()` is run for real and the returned
documents are checked for the secret and for the normal note.

Every variant is the FULL real file. `ObsidianReader.load_data` is the
public API, so its name and signature are kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0281"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


s = original.index("    def load_data(self, *args")
e = original.index("    def load_langchain_documents")
BODY = original[s:e]

# --- Variant 1: renamed vulnerable variant ---
b1 = re.sub(r"\bdocs\b", "documents", BODY)
b1 = re.sub(r"\bbacklinks_map\b", "links_to", b1)
b1 = re.sub(r"\binput_dir_abs\b", "vault_root", b1)
assert b1 != BODY
v1 = original.replace(BODY, b1)
# load_langchain_documents also uses `docs`; keep it consistent.
v1 = swap(v1, "        docs = self.load_data(**load_kwargs)\n        return [d.to_langchain_format() for d in docs]",
          "        documents = self.load_data(**load_kwargs)\n        return [d.to_langchain_format() for d in documents]")
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
CHECK = '''                        if not str(file_path_obj).startswith(str(input_dir_abs)):
                            print(
                                f"Warning: Skipping file outside input directory: {filepath}"
                            )
                            continue
'''
assert original.count(CHECK) == 1
v2 = swap(original, CHECK, '''                        if not self._inside_vault(file_path_obj, input_dir_abs):
                            print(
                                f"Warning: Skipping file outside input directory: {filepath}"
                            )
                            continue
''')
v2 = swap(v2, "    def load_langchain_documents", '''    @staticmethod
    def _inside_vault(file_path_obj: Path, vault_root: Path) -> bool:
        return str(file_path_obj).startswith(str(vault_root))

    def load_langchain_documents''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same fix outcome as upstream (skip files with more than one hard link)
# but as a staticmethod using Path.stat() and evaluated after the vault
# containment check instead of a module-level os.stat() helper before it.
v3 = swap(original, CHECK, CHECK + '''                        if self._has_extra_hardlinks(file_path_obj):
                            print(
                                f"Warning: Skipping file because it is a hardlink (potential malicious exploit): {filepath}"
                            )
                            continue
''')
v3 = swap(v3, "    def load_langchain_documents", '''    @staticmethod
    def _has_extra_hardlinks(file_path_obj: Path) -> bool:
        return file_path_obj.stat().st_nlink > 1

    def load_langchain_documents''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''"""
Standalone example of the same shape: skip note files whose name starts
with an underscore (a personal convention for drafts) while walking a
folder -- a content-selection filter, not a containment boundary.
"""
import os


def list_published_notes(folder):
    notes = []
    for dirpath, _dirnames, filenames in os.walk(folder, followlinks=False):
        for name in filenames:
            if name.endswith(".md") and not name.startswith("_"):
                notes.append(os.path.join(dirpath, name))
    return notes
''')
