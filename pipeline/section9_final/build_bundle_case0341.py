"""
Section 9 ground-truth test bundle: CASE-0341
(AUTOMATIC1111/stable-diffusion-webui, CVE-2024-31462, CWE-22 path
traversal). Replacement for the retired duplicate CASE-0277 (top-up 40).

Core vulnerable mechanism: `save_config_state(name)` takes the user-typed
config name from the extensions tab and puts it, unsanitised, into a file
path -- `os.path.join(config_states_dir, f"{timestamp}_{name}.json")` --
that is then opened for writing. A name containing path separators or
`..` segments steers the write outside `config_states_dir`. (On Windows
the `..` is resolved lexically, so `..\\..\\x` escapes directly; on POSIX
the first component is always `<timestamp>_...`, so the escape needs a
directory with that prefix to exist.) The upstream fix reduces the name
with `os.path.basename(name or "Config")`.

Every variant is the FULL real file with save_config_state replaced (the
renamed variant also renames its two other references).
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0341"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.py").read_text().splitlines()) + "\n"

START = "def save_config_state(name):\n"
s = original.index(START)
e = original.index("\n\n\n", s) + 1
BLOCK = original[s:e]
assert original.count(START) == 1 and 'f"{timestamp}_{name}.json"' in BLOCK
assert original.count("save_config_state") == 3


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("def save_config_state(name):", "def store_state_snapshot(label):")
for old, new in (("current_config_state", "snapshot"), ("timestamp", "stamp"), ("filename", "target_file"),
                 ("new_value", "selected"), ("new_choices", "options")):
    b = re.sub(r"\b%s\b" % old, new, b)
b = b.replace("if not name:\n        name = \"Config\"", "if not label:\n        label = \"Config\"")
b = b.replace('snapshot["name"] = name', 'snapshot["name"] = label').replace("{stamp}_{name}.json", "{stamp}_{label}.json")
assert not re.search(r"\bname\b", b.replace('["name"]', "")), b
renamed = build(b)
renamed = re.sub(r"\bsave_config_state\b", "store_state_snapshot", renamed)
assert "save_config_state" not in renamed and renamed.count("store_state_snapshot") == 3
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed)

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace('    if not name:\n        name = "Config"\n', '    label = name if name else "Config"\n')
b = b.replace('current_config_state["name"] = name', 'current_config_state["name"] = label')
b = b.replace('    filename = os.path.join(config_states_dir, f"{timestamp}_{name}.json")\n',
              '    file_stem = f"{timestamp}_{label}.json"\n    filename = os.path.join(config_states_dir, file_stem)\n')
assert "{name}" not in b and "file_stem" in b
(CASE_DIR / "variant_vulnerable_02.py").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Allow-list sanitiser (only letters, digits, space, dot, underscore, hyphen;
# leading dots stripped) PLUS an explicit containment check on the final
# real path, instead of upstream's os.path.basename().
b = BLOCK.replace('    if not name:\n        name = "Config"\n',
                  "    name = re.sub(r\"[^A-Za-z0-9._ -]\", \"_\", name or \"Config\").lstrip(\".\") or \"Config\"\n")
b = b.replace('    print(f"Saving backup of webui/extension state to {filename}.")\n',
              '    if os.path.commonpath([os.path.realpath(filename), os.path.realpath(config_states_dir)]) != os.path.realpath(config_states_dir):\n'
              '        raise ValueError("config state name escapes the config states directory")\n'
              '    print(f"Saving backup of webui/extension state to {filename}.")\n')
assert "re.sub" in b and "commonpath" in b
safe = build(b).replace("import json\nimport os\n", "import json\nimport os\nimport re\n", 1)
assert "import re\n" in safe
(CASE_DIR / "variant_safe_01.py").write_text(safe)

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.py").write_text('''import json
import os
from datetime import datetime

REPORT_KINDS = ("daily", "weekly", "monthly")


def save_report_snapshot(kind, data, reports_dir):
    """Same os.path.join(dir, f"{timestamp}_{name}.json") shape, but `kind`
    must be one of a fixed tuple of developer-chosen names, so it can never
    contain a path separator or a `..` segment."""
    if kind not in REPORT_KINDS:
        raise ValueError("unknown report kind")
    timestamp = datetime.now().strftime("%Y_%m_%d-%H_%M_%S")
    filename = os.path.join(reports_dir, f"{timestamp}_{kind}.json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    return filename
''')
print("Wrote 4 new samples for CASE-0341.")
