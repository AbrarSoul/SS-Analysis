"""
Section 9 ground-truth test bundle: CASE-0097
(ansible/ansible-modules-core, apt_key, CVE-2016-8614, CWE-320/CWE-358
improper verification of the GPG key identity).

Core vulnerable mechanism: `parse_key_id()` returns
`(short_key_id, fingerprint, key_id)` (8 chars, 16 chars, full length) but
`main()` unpacks the result in the WRONG order
(`key_id, fingerprint, short_key_id = parse_key_id(key_id)`). As a result
the variable used with `apt-key adv --recv-key` and the key-presence
comparison holds the short/16-char id instead of the full one, so a key
whose 8-character short id merely COLLIDES with the requested one (short
ids are trivially collidable) is imported and accepted as the intended
key. The upstream fix corrects the unpacking order.

Every variant is the FULL real file with main() (and its __main__ guard)
replaced.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0097"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.py").read_text().splitlines()) + "\n"

START = "def main():\n    module = AnsibleModule("
s = original.index(START)
BLOCK = original[s:]
UNPACK = "            key_id, fingerprint, short_key_id = parse_key_id(key_id)\n"
assert original.count(START) == 1 and BLOCK.count(UNPACK) == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("def main():", "def run_module():").replace("    main()\n", "    run_module()\n")
for old, new in (("key_id", "requested_key"), ("fingerprint", "listing_form"), ("short_key_id", "delete_form"),
                 ("short_format", "use_short_listing"), ("keys2", "keys_after"), ("keys", "installed")):
    b = re.sub(r"\b%s\b" % old, new, b)
# put back the human-readable strings/comments that the word-boundary rename also touched
b = b.replace("msg='Invalid requested_key'", "msg='Invalid key_id'")
b = b.replace("write installed out to", "write keys out to")
b = b.replace('msg="error removing requested_key"', 'msg="error removing key_id"')
b = b.replace('"short" id: requested_key[-8:]', '"short" id: key_id[-8:]')
assert "requested_key, listing_form, delete_form = parse_key_id(requested_key)" in b
assert "run_module()" in b and "def main" not in b
(CASE_DIR / "variant_vulnerable_01.py").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(UNPACK,
                  "            parsed = parse_key_id(key_id)\n"
                  "            key_id, fingerprint, short_key_id = parsed\n")
(CASE_DIR / "variant_vulnerable_02.py").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Correct unpacking order PLUS an explicit refusal to import from a keyserver
# with anything shorter than a full-length id (defence in depth; upstream
# only fixes the ordering).
b = BLOCK.replace(UNPACK,
                  "            short_key_id, fingerprint, key_id = parse_key_id(key_id)\n"
                  "            if keyserver and len(key_id) < 16:\n"
                  "                module.fail_json(msg='key_id must be at least 16 characters to import from a keyserver', id=key_id)\n")
assert b != BLOCK
(CASE_DIR / "variant_safe_01.py").write_text(build(b))

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.py").write_text('''def parse_dimensions(text):
    """Returns (length, width, height) from a string like '2x3x4'."""
    length, width, height = (int(part) for part in text.split("x"))
    return length, width, height


def box_volume(text):
    """Unpacks the tuple in a different order than it is returned, but the
    result is a product, which does not depend on the order, so the
    'wrong' order is harmless here."""
    height, width, length = parse_dimensions(text)
    return length * width * height
''')
print("Wrote 4 new samples for CASE-0097.")
