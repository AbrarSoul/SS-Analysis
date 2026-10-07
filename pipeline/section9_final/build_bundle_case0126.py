"""
Section 9 ground-truth test bundle: CASE-0126
(badkeys/badkeys, badkeys/dkim.py parsedkim, CVE-2026-21439, CWE-150
improper neutralization of escape, meta, or control sequences).

Core vulnerable mechanism: for a DKIM record whose `k=` (key type) is
neither `rsa` nor `ed25519`, `parsedkim()` warns with
`_warnmsg(f"Unknown DKIM key type {dkim['k']}")`, copying attacker-controlled
DNS TXT text verbatim into a message printed to the operator's terminal. A
value carrying ANSI/VT escape sequences or control characters can rewrite
the screen, spoof output, change the window title or trigger terminal
features. The upstream fix removes the value from the message.

Every variant is the FULL real file with parsedkim replaced. parsedkim has
no in-file callers (it is called from other modules), so the renamed variant
renames the declaration only.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0126"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

HDR = "def parsedkim(line):\n"
s = original.index(HDR)
BLOCK = original[s:]
assert original.count(HDR) == 1 and original.count("parsedkim(") == 1
WARN = "    _warnmsg(f\"Unknown DKIM key type {dkim['k']}\")\n"
QUOTE_LOOP = '''    if '"' in line:
        add = 0
        dk = ""
        for x in line.split('"'):
            add ^= 1
            if add == 0:
                dk += x
    else:
        dk = line
'''
assert BLOCK.count(WARN) == 1 and BLOCK.count(QUOTE_LOOP) == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block


def rename_outside_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        parts = re.split(r"""('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")""", line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
# The f-string's embedded expression is renamed by hand (string-protecting
# regexes cannot see inside f-strings).
b = BLOCK.replace(WARN, "    _warnmsg(f\"Unknown DKIM key type {FIELDS_PLACEHOLDER['k']}\")\n")
b = b.replace("def parsedkim(line):", "def parse_dkim_record(record):")
b = rename_outside_strings(b, (("line", "record"), ("dk", "joined"), ("add", "toggle"), ("x", "part"), ("dkim", "fields"),
                               ("s", "pair"), ("key", "name"), ("value", "val"), ("rawed", "raw"), ("der", "spki")))
b = b.replace("FIELDS_PLACEHOLDER", "fields")
assert "def parse_dkim_record(record):" in b and "fields[name] = val" in b
assert "_warnmsg(f\"Unknown DKIM key type {fields['k']}\")" in b
compile(build(b), "v1", "exec")
(CASE_DIR / "variant_vulnerable_01.py").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(QUOTE_LOOP, '''    if '"' in line:
        dk = "".join(line.split('"')[1::2])
    else:
        dk = line
''')
assert b != BLOCK and WARN in b
(CASE_DIR / "variant_vulnerable_02.py").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Keeps the value in the message (useful to the operator) but neutralised
# with ascii() -- escapes control/escape/non-ASCII characters -- and capped in
# length (upstream removes the value entirely).
b = BLOCK.replace(WARN, "    _warnmsg(\"Unknown DKIM key type \" + ascii(dkim[\"k\"][:64]))\n")
safe_source = build(b)
assert "{dkim['k']}" not in safe_source
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''from .utils import _warnmsg


def check_key_type(kind):
    """Same "warn about an unknown attacker-supplied key type" shape, but the
    only thing put into the message is the LENGTH of the value (an int), never
    its text, so no escape or control sequence can reach the terminal."""
    if kind in ("rsa", "ed25519"):
        return True
    _warnmsg(f"Unknown DKIM key type (length {len(kind)})")
    return False
'''
assert "len(kind)" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0126.")
