"""
Section 9 ground-truth test bundle: CASE-0122
(aryan6673/project-ai, AIAssistantApp.__init__ in backup/kvs.py,
CVE-2025-48491, CWE-798 use of hard-coded credentials).

Core vulnerable mechanism: `__init__` assigns a real Google Generative AI
API key as a string literal (`self.api_key = "AIza..."`) and passes it to
`genai.configure(api_key=self.api_key)`. Anyone with read access to the
repository (it is public) obtains the credential and can spend the owner's
quota or abuse the API in their name. The upstream fix replaces the literal
with the placeholder "add api here".

The literal itself is read programmatically from the real file in this
script; it is never written into the script, the manifest, or any note.
Every variant is the FULL real file with the credential handling changed.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0122"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

KEY_LINE_RE = re.compile(r'^        self\.api_key = ("AIza[0-9A-Za-z_\-]+")$', re.M)
m = KEY_LINE_RE.search(original)
assert m and len(KEY_LINE_RE.findall(original)) == 1
KEY_LITERAL = m.group(1)
KEY_LINE = m.group(0)
CLASS_LINE = "class AIAssistantApp(ctk.CTk):\n"
INSTANCE_LINE = "    app = AIAssistantApp()\n"
IMPORT_LINE = "import threading\n"
assert original.count(CLASS_LINE) == 1 and original.count(INSTANCE_LINE) == 1 and original.count(IMPORT_LINE) == 1
assert original.count("self.api_key") == 2 and original.count("AIAssistantApp") == 2


def swap(src, old, new, count=1):
    assert src.count(old) == count and new != old
    return src.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
# Class and attribute renamed; the `api_key=` KEYWORD of genai.configure is
# a library parameter and stays.
v1 = swap(original, "AIAssistantApp", "StudyAssistantWindow", 2)
v1 = swap(v1, "self.api_key", "self.service_token", 2)
assert "genai.configure(api_key=self.service_token)" in v1 and KEY_LITERAL in v1
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
# The same literal moved to a module-level constant.
v2 = swap(original, KEY_LINE, "        self.api_key = _API_KEY")
v2 = swap(v2, CLASS_LINE, "_API_KEY = " + KEY_LITERAL + "\n\n\n" + CLASS_LINE)
assert v2.count(KEY_LITERAL) == 1
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# The key is read from the environment at run time (upstream replaces the
# literal with a placeholder string).
v3 = swap(original, KEY_LINE, '        self.api_key = os.environ.get("GEMINI_API_KEY", "")')
v3 = swap(v3, IMPORT_LINE, IMPORT_LINE + "import os\n")
assert KEY_LITERAL not in v3 and "AIza" not in v3
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''class MockGenerativeClient:
    """Client for the local mock server used by the test suite."""

    def __init__(self):
        # Same "literal assigned to api_key" shape, but this is the documented
        # dummy token of the local mock server (127.0.0.1 only); it is valid
        # nowhere else and grants nothing, so nothing sensitive is committed.
        self.api_key = "test-token-not-a-real-key"
        self.base_url = "http://127.0.0.1:8080"

    def headers(self):
        return {"Authorization": "Bearer " + self.api_key}
'''
assert "AIza" not in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0122.")
