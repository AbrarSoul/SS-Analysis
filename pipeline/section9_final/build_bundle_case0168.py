"""
Section 9 ground-truth test bundle: CASE-0168
(gaizhenbiao/chuanhuchatgpt, modules/utils.py get_history_names, CVE-2024-6037,
CWE-22 path traversal; the advisory also lists CWE-770). This case is the
single-case replacement added by top-up 14 after CASE-0167 (frappe/lms) was
excluded.

Core vulnerable mechanism: `get_history_names(user_name)` builds
`os.path.join(HISTORY_DIR, user_name)` and lists the `.json` files in it, first
creating the directory when it does not exist (`get_file_names_by_type` runs
`os.makedirs(dir, exist_ok=True)`). A `user_name` such as `../secrets` or an
absolute path escapes HISTORY_DIR, so the endpoint lists the file names of an
arbitrary directory (and can create directories). The upstream fix adds
`assert os.path.realpath(user_history_dir).startswith(os.path.realpath(HISTORY_DIR))`.

Measured caveat, kept in the manifest notes: upstream's check is an `assert`
(removed when Python runs with -O) and a plain `startswith` on paths without a
separator, so a sibling directory whose name merely starts with the base name
(`history2` next to `history`) passes it. The safe variant uses an explicit
`os.path.commonpath` check that raises ValueError.

Sibling sites: `save_file`, `new_auto_history_filename` and
`get_history_filepath` also join `user_name` into HISTORY_DIR paths, but they
receive the authenticated session's user name rather than a free request
parameter, and no traversal through them was demonstrated, so they are left
unchanged in every variant.

Every variant is the FULL real file. get_history_names is called by name from
the same module and others, so the renamed variant keeps the name and renames
its parameter and locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0168"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

BODY = '''def get_history_names(user_name=""):
    logging.debug(f"从用户 {user_name} 中获取历史记录文件名列表")
    if user_name == "" and hide_history_when_not_logged_in:
        return []
    else:
        history_files = get_file_names_by_last_modified_time(
            os.path.join(HISTORY_DIR, user_name)
        )
        history_files = [f[: f.rfind(".")] for f in history_files]
        return history_files
'''
assert original.count(BODY) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, BODY, '''def get_history_names(user_name=""):
    logging.debug(f"从用户 {user_name} 中获取历史记录文件名列表")
    if user_name == "" and hide_history_when_not_logged_in:
        return []
    else:
        found = get_file_names_by_last_modified_time(
            os.path.join(HISTORY_DIR, user_name)
        )
        stems = [entry[: entry.rfind(".")] for entry in found]
        return stems
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, BODY, '''def get_history_names(user_name=""):
    logging.debug(f"从用户 {user_name} 中获取历史记录文件名列表")
    if user_name == "" and hide_history_when_not_logged_in:
        return []
    history_dir = os.path.join(HISTORY_DIR, user_name)
    return [name[: name.rfind(".")] for name in get_file_names_by_last_modified_time(history_dir)]
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Explicit containment check with os.path.commonpath that raises ValueError
# (works under python -O and is not fooled by a sibling directory with a shared
# name prefix); upstream uses an assert with startswith.
v3 = swap(original, BODY, '''def get_history_names(user_name=""):
    logging.debug(f"从用户 {user_name} 中获取历史记录文件名列表")
    if user_name == "" and hide_history_when_not_logged_in:
        return []
    else:
        base_dir = os.path.realpath(HISTORY_DIR)
        user_history_dir = os.path.realpath(os.path.join(HISTORY_DIR, user_name))
        if os.path.commonpath([base_dir, user_history_dir]) != base_dir:
            raise ValueError("invalid user name")
        history_files = get_file_names_by_last_modified_time(user_history_dir)
        history_files = [f[: f.rfind(".")] for f in history_files]
        return history_files
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import os

HISTORY_DIR = "history"


def list_chat_names(chat_id):
    """Same os.path.join(HISTORY_DIR, <name>) listing shape, but the name is
    only accepted when it is a bare file-name component made of safe
    characters, so it can never contain a separator or '..'."""
    if not chat_id.replace("_", "").replace("-", "").isalnum():
        raise ValueError("invalid chat id")
    folder = os.path.join(HISTORY_DIR, chat_id)
    return sorted(f for f in os.listdir(folder) if f.endswith(".json"))
'''
assert "isalnum()" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0168.")
