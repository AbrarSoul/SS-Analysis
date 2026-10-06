r"""
Section 9 ground-truth test bundle: CASE-0324
(wagtail/wagtail, wagtail/core/forms.py PasswordViewRestrictionForm.clean_password,
CVE-2020-11037, CWE-208 observable timing discrepancy / CWE-362).

Core vulnerable mechanism: the form that unlocks a password-protected page
compares the submitted password with the stored restriction password using
`data != self.restriction.password`. The ordinary string comparison stops at
the first differing character, so the response time depends on how long a
prefix of the guess is correct; an attacker who can time many requests can
recover the shared password one character at a time. The upstream fix uses
Django's `constant_time_compare`.

Sibling sites: none in this file; the restriction password is otherwise only
read here.

Verification (REAL Django): each full file is exec'd with real
`django.forms` and `django.utils.crypto`, with `ugettext` aliased to
`gettext` (removed from modern Django). `clean_password` is called on a form
instance whose stored password is 20,000,000 characters of `a`, with (i) a
guess that differs at the FIRST character and (ii) a guess that differs at
the LAST character (median of 7 timed calls each). The timing ratio (last/
first) is the measurement: vulnerable variants are >20x slower for the
late-mismatch guess (early-exit comparison), patched/safe are within 3x
(full-length comparison). The correct password is accepted and a wrong one
raises ValidationError in every file.

Every variant is the FULL real file; `clean_password` is called by Django
form validation by name.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0324"
original = (CASE_DIR / "vulnerable_source.py").read_text()
patched = (CASE_DIR / "patched_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


CMP = "        if data != self.restriction.password:\n"

# --- Variant 1: renamed vulnerable variant (local renamed) ---
v1 = original.replace("        data = self.cleaned_data['password']\n" + CMP, "        submitted = self.cleaned_data['password']\n        if submitted != self.restriction.password:\n")
assert v1 != original
v1 = swap(v1, "        return data", "        return submitted")
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (comparison moved into a helper method) ---
v2 = swap(original, CMP, "        if not self._matches(data):\n")
v2 = swap(v2, "    def clean_password(self):\n", "    def _matches(self, candidate):\n        return candidate == self.restriction.password\n\n    def clean_password(self):\n")
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the constant-time comparison sits in a helper method) ---
PCMP = "        if not constant_time_compare(data, self.restriction.password):\n"
v3 = swap(patched, PCMP, "        if not self._matches(data):\n")
v3 = swap(v3, "    def clean_password(self):\n", "    def _matches(self, candidate):\n        return constant_time_compare(candidate, self.restriction.password)\n\n    def clean_password(self):\n")
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''class PasswordChangeForm(object):
    """Sign-up style form: checks that the two password boxes the user just typed match."""

    def __init__(self, password1, password2):
        self.cleaned_data = {'password1': password1, 'password2': password2}

    def clean_password2(self):
        first = self.cleaned_data['password1']
        second = self.cleaned_data['password2']
        # Both values come from the same request; neither is a stored secret,
        # so an ordinary comparison leaks nothing.
        if first != second:
            raise ValueError("The two password fields didn't match.")
        return second
''')
