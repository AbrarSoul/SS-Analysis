"""
Section 9 ground-truth test bundle: CASE-0231
(modelscope/agentscope, src/agentscope/studio/_app.py _delete_workflow,
CVE-2024-8537, CWE-29 path traversal).

Core vulnerable mechanism: the Studio's workflow endpoints keep each user's
workflows as JSON files in `<cache>/<user>/` and build the path from a client
supplied name. `/delete-workflow` does
`filepath = os.path.join(user_dir, filename)` with `filename` straight from the
request JSON: `../secret.json` walks out of the user folder, and an absolute
path makes `os.path.join` discard `user_dir` altogether, so any file the
server can write can be deleted. The upstream fix requires the name to end in
`.json` and reduces it with `os.path.basename` before joining.

Sibling sites (same file, same unsanitised join): `/load-workflow`
(`os.path.join(user_dir, filename)` then `json.load`, an arbitrary JSON file
read) and `/save-workflow` (`f"{filename}.json"` joined the same way, so a name
with `../` writes a `.json` file outside the user folder). The upstream patch
changes only `/delete-workflow`; the safe variant fixes all three with one shared
helper and the vulnerable variants leave all three unchanged.

Verification: the three route functions are extracted verbatim from each full
file and registered on a REAL Flask 3 app (real `request`, `session`, `jsonify`)
with a temporary cache directory holding `local_user/` plus a `secret.json`
beside it. Requests through Flask's test client try `../secret.json`, an absolute
path to it, and a save named `../planted`.

Every variant is the FULL real file. The route functions are registered under
their names by Flask (the endpoint name), so their names are kept; the renamed
variant renames locals of `_delete_workflow` only.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0231"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


DELETE = '''    data = request.json
    filename = data.get("filename")
    if not filename:
        return jsonify({"error": "Filename is required"})

    filepath = os.path.join(user_dir, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"})

    try:
        os.remove(filepath)
'''
assert original.count(DELETE) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, DELETE, '''    payload = request.json
    filename = payload.get("filename")
    if not filename:
        return jsonify({"error": "Filename is required"})

    target = os.path.join(user_dir, filename)
    if not os.path.exists(target):
        return jsonify({"error": "File not found"})

    try:
        os.remove(target)
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, DELETE, '''    data = request.json
    filename = data.get("filename")
    if not filename:
        return jsonify({"error": "Filename is required"})

    filepath = _workflow_file(user_dir, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"})

    try:
        os.remove(filepath)
''')
v2 = swap(v2, '@_app.route("/save-workflow", methods=["POST"])', '''def _workflow_file(user_dir: str, filename: str) -> str:
    return os.path.join(user_dir, filename)


@_app.route("/save-workflow", methods=["POST"])''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, '@_app.route("/save-workflow", methods=["POST"])', '''def _safe_workflow_name(filename: Any, need_json: bool = True) -> Optional[str]:
    """Return a bare file name for the user's workflow folder, or None."""
    if not isinstance(filename, str):
        return None
    name = os.path.basename(filename.replace("\\\\", "/"))
    if name in ("", ".", "..") or (need_json and not name.endswith(".json")):
        return None
    return name


@_app.route("/save-workflow", methods=["POST"])''')
v3 = swap(v3, '''    filepath = os.path.join(user_dir, f"{filename}.json")
''', '''    safe_name = _safe_workflow_name(f"{filename}.json")
    if safe_name is None:
        return jsonify({"message": "Invalid filename"})
    filepath = os.path.join(user_dir, safe_name)
''')
v3 = swap(v3, DELETE, '''    data = request.json
    filename = data.get("filename")
    if not filename:
        return jsonify({"error": "Filename is required"})

    safe_name = _safe_workflow_name(filename)
    if safe_name is None:
        return jsonify({"error": "Only JSON files can be deleted"})

    filepath = os.path.join(user_dir, safe_name)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"})

    try:
        os.remove(filepath)
''')
LOAD = '''    filepath = os.path.join(user_dir, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"}), 404
'''
v3 = swap(v3, LOAD, '''    safe_name = _safe_workflow_name(filename)
    if safe_name is None:
        return jsonify({"error": "Only JSON files can be loaded"}), 400

    filepath = os.path.join(user_dir, safe_name)
    if not os.path.exists(filepath):
        return jsonify({"error": "File not found"}), 404
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: join a directory with a file name for
a file the SERVER names (a timestamped report), never a client-supplied path."""
import os
from datetime import datetime


def report_path(report_dir: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return os.path.join(report_dir, f"report-{stamp}.json")
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
