"""
Section 9 ground-truth test bundle: CASE-0174
(huggingface/transformers, src/transformers/models/clvp/number_normalizer.py
EnglishNormalizer.normalize_numbers, CVE-2025-6051, CWE-1333 inefficient
regular expression complexity).

Core vulnerable mechanism: `normalize_numbers` runs six regexes over
untrusted text, including `([0-9]+\\.[0-9]+)` and `[0-9]+(st|nd|rd|th)`. On a
long run of digits with no `.` or ordinal suffix, each regex tries every start
position of the run and, from each one, scans and backtracks over the rest of
the run: quadratic time. Measured on Python 3.14 with `'1' * n + '!'`:
n=10,000 / 20,000 / 40,000 takes 320 ms / 1.27 s / 5.07 s for the ordinal
pattern and 89 ms / 270 ms / 1.0 s for the decimal pattern. The upstream fix
makes the digit runs possessive (`[0-9]++`), which needs Python 3.11 or the
`regex` package.

Measured caveat, kept in the manifest notes: possessive quantifiers remove the
backtracking but the engine still re-scans from every start position, so the
patched patterns are still quadratic (846 ms at n=40,000, about 6 times faster than
the original but the same growth). The safe variant adds a `(?<![0-9])`
lookbehind so scanning only starts at the beginning of a digit run, which is
linear (measured).

Sibling sites: the other patterns in this method (comma removal, pounds and
dollars) are linear on the same input (measured 0 ms) and are left unchanged.

Every variant is the FULL real file. normalize_numbers is a public method
called from `__call__`, so the renamed variant keeps the name and renames its
parameter.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0174"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

BODY = '''        text = re.sub(re.compile(r"([0-9][0-9\\,]+[0-9])"), self._remove_commas, text)
        text = re.sub(re.compile(r"£([0-9\\,]*[0-9]+)"), r"\\1 pounds", text)
        text = re.sub(re.compile(r"\\$([0-9\\.\\,]*[0-9]+)"), self._expand_dollars, text)
        text = re.sub(re.compile(r"([0-9]+\\.[0-9]+)"), self._expand_decimal_point, text)
        text = re.sub(re.compile(r"[0-9]+(st|nd|rd|th)"), self._expand_ordinal, text)
        text = re.sub(re.compile(r"[0-9]+"), self._expand_number, text)
        return text
'''
assert original.count(BODY) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, "    def normalize_numbers(self, text: str) -> str:\n", "    def normalize_numbers(self, raw: str) -> str:\n")
v1 = swap(v1, BODY, BODY.replace("text = re.sub(", "raw = re.sub(").replace(", text)", ", raw)").replace("return text", "return raw"))
assert v1.count("raw = re.sub(") == 6 and "return raw" in v1
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, BODY, '''        steps = [
            (r"([0-9][0-9\\,]+[0-9])", self._remove_commas),
            (r"£([0-9\\,]*[0-9]+)", r"\\1 pounds"),
            (r"\\$([0-9\\.\\,]*[0-9]+)", self._expand_dollars),
            (r"([0-9]+\\.[0-9]+)", self._expand_decimal_point),
            (r"[0-9]+(st|nd|rd|th)", self._expand_ordinal),
            (r"[0-9]+", self._expand_number),
        ]
        for pattern, replacement in steps:
            text = re.sub(re.compile(pattern), replacement, text)
        return text
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# A negative lookbehind keeps each scan from starting in the middle of a digit
# run (linear time on any input); upstream makes the digit runs possessive,
# which is still quadratic because every start position is retried.
v3 = swap(original, BODY, BODY
          .replace('re.compile(r"([0-9]+\\.[0-9]+)")', 're.compile(r"(?<![0-9])([0-9]+\\.[0-9]+)")')
          .replace('re.compile(r"[0-9]+(st|nd|rd|th)")', 're.compile(r"(?<![0-9])[0-9]+(st|nd|rd|th)")'))
assert v3.count("(?<![0-9])") == 2
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import re

_ORDINAL = re.compile(r"[0-9]{1,12}(st|nd|rd|th)")


def mark_ordinals(text: str) -> str:
    """Same "digits followed by st/nd/rd/th" pattern as the number normalizer,
    but the digit run is bounded to 12, so the work per start position is
    constant and the whole scan is linear in the input length."""
    return _ORDINAL.sub(lambda m: "<ord:" + m.group(0) + ">", text)
'''
assert "{1,12}" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0174.")
