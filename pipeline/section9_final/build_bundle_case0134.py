"""
Section 9 ground-truth test bundle: CASE-0134
(caronc/apprise, apprise/plugins/NotifyIFTTT.py
NotifyIFTTT.parse_native_url, CVE-2021-39229, CWE-400 uncontrolled resource
consumption -- ReDoS).

Core vulnerable mechanism: `parse_native_url` matches the URL with
`r'/?(?P<events>([A-Z0-9_-]+/?)+)?'`. The group `([A-Z0-9_-]+/?)+` is a
nested quantifier over an AMBIGUOUS body: `[A-Z0-9_-]+` may stop anywhere
because the following `/?` is optional, so a run of n allowed characters can
be split into iterations in 2^(n-1) ways. On a URL that fails at the end
(e.g. a trailing `!`) the regex engine tries them all: exponential time, so
one crafted URL can hang the process (denial of service). The upstream fix
rewrites it as `((?P<events>(/[A-Z0-9_-]+)+))?`, which is linear but also
changes what the `events` group contains (it now starts with '/').

Every variant is the FULL real file with parse_native_url replaced. It is a
@staticmethod called by the plugin loader (no in-file callers), so the
renamed variant renames the declaration only.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0134"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

HDR = "    @staticmethod\n    def parse_native_url(url):\n"
s = original.index(HDR)
e = original.index("        return None\n", s) + len("        return None\n")
BLOCK = original[s:e]
EVENTS = "            r'/?(?P<events>([A-Z0-9_-]+/?)+)?'\n"
assert original.count(HDR) == 1 and original.count("parse_native_url") == 1 and BLOCK.count(EVENTS) == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("def parse_native_url(url):", "def parse_ifttt_webhook_url(raw_url):")
b = b.replace("r'/?(?P<params>\\?.+)?$', url, re.I)", "r'/?(?P<params>\\?.+)?$', raw_url, re.I)")
b = b.replace("result = re.match(", "found = re.match(").replace("if result:", "if found:")
b = b.replace("result.group(", "found.group(")
assert "raw_url, re.I)" in b and "found.group('webhook_id')" in b and "result" not in b
assert "([A-Z0-9_-]+/?)+" in b
(CASE_DIR / "variant_vulnerable_01.py").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
# The pattern is compiled once from named parts; the same nested quantifier.
b = BLOCK.replace('''        result = re.match(
            r'^https?://maker\\.ifttt\\.com/use/'
            r'(?P<webhook_id>[A-Z0-9_-]+)'
            r'/?(?P<events>([A-Z0-9_-]+/?)+)?'
            r'/?(?P<params>\\?.+)?$', url, re.I)
''', '''        events_part = r'/?(?P<events>([A-Z0-9_-]+/?)+)?'
        pattern = re.compile(
            r'^https?://maker\\.ifttt\\.com/use/'
            r'(?P<webhook_id>[A-Z0-9_-]+)'
            + events_part +
            r'/?(?P<params>\\?.+)?$', re.I)
        result = pattern.match(url)
''')
assert b != BLOCK and "([A-Z0-9_-]+/?)+" in b
(CASE_DIR / "variant_vulnerable_02.py").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Linear rewrite that accepts EXACTLY the same strings and captures the same
# `events` text as the original: one or more slash-separated chunks, an
# optional trailing slash, no ambiguity about where a chunk ends.
b = BLOCK.replace(EVENTS, "            r'/?(?P<events>[A-Z0-9_-]+(?:/[A-Z0-9_-]+)*/?)?'\n")
safe_source = build(b)
assert "([A-Z0-9_-]+/?)+" not in safe_source
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import re


def parse_event_path(url):
    """Same nested-quantifier shape as the IFTTT events pattern, but each
    repetition of the group MUST end with a '/' delimiter, so a run of allowed
    characters can be divided into repetitions in only ONE way. With no
    ambiguity the engine never has to try alternative splits, and matching
    stays linear even on inputs that fail at the end."""
    match = re.match(r'^https?://hooks\\.example\\.com/events/(?P<events>([A-Z0-9_-]+/)+)$', url, re.I)
    return match.group('events') if match else None
'''
assert "([A-Z0-9_-]+/)+" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0134.")
