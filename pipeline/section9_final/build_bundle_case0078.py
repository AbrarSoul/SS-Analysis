"""
Section 9 ground-truth test bundle: CASE-0078
(Tethik/flask-session-captcha, CVE-2022-24880, CWE-253/CWE-394/CWE-754
incorrect check of return value enabling a captcha bypass).

NOTE on this case's data: the originally auto-selected commit for this
CVE turned out to be a test-only follow-up commit ("add some extra tests
to ensure False is returned"), not the real code fix. Traced via the
GitHub advisory (GHSA-7r87-cj48-wj45) and the source PR (#27) to the real
fix commit (ab36ee2...), "Fix validate returned value" -- this case's
`benchmark/cases/CASE-0078/*` files and metadata were corrected to that
real commit pair before this bundle was built (see
Research_Log/Implementation_Log.md Section 12.16).

Core vulnerable mechanism: `validate()` ends with
`return value and value == session_value`. Python's `and` short-circuits
on a falsy left operand and returns THAT falsy value itself, not `False`
-- so `validate(value="")` returns `""`, and `validate(value=None)`
returns `None`, neither of which IS `False`. The library's own advisory
warns that implementers commonly write `if captcha.validate() == False:`
to gate access -- and `"" == False` and `None == False` are both `False`
in Python, so a caller using that (very natural) pattern never detects
the failed/missing-value case as a failure, silently treating a blank or
absent captcha response as if validation had never run one way or the
other and falling through to the "success" branch. The fix changes the
short-circuit to an explicit `value is not None and ...`, so the
function always returns a real boolean.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0078"
original = "\n".join(line.rstrip() for line in (CASE_DIR / "vulnerable_source.py").read_text().splitlines()) + "\n"

VULNERABLE_BLOCK = '''    def validate(self, form_key="captcha", value=None):
        """
        Validate a captcha answer (taken from request.form) against the answer saved in the session.
        Returns always true if CAPTCHA_ENABLE is set to False. Otherwise return true only if it is the correct answer.
        """
        if not self.enabled:
            return True

        session_value = session.get('captcha_answer')
        if not session_value:
            return False

        if not value and form_key in request.form:
            value = request.form[form_key].strip()

        # invalidate the answer to stop new tries on the same challenge.
        session['captcha_answer'] = None
        return value and value == session_value'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename validate -> check_answer, value -> submitted_value, session_value
# -> expected_value. Same exact truthy-short-circuit return, which can
# yield a non-boolean falsy value instead of False.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''    def check_answer(self, form_key="captcha", submitted_value=None):
        """
        Validate a captcha answer (taken from request.form) against the answer saved in the session.
        Returns always true if CAPTCHA_ENABLE is set to False. Otherwise return true only if it is the correct answer.
        """
        if not self.enabled:
            return True

        expected_value = session.get('captcha_answer')
        if not expected_value:
            return False

        if not submitted_value and form_key in request.form:
            submitted_value = request.form[form_key].strip()

        # invalidate the answer to stop new tries on the same challenge.
        session['captcha_answer'] = None
        return submitted_value and submitted_value == expected_value''',
)
assert 'def check_answer(self, form_key="captcha", submitted_value=None):' in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting
# (explicit if/else instead of the `and`-chain return). Same exact
# truthy-short-circuit bug (an empty-string/None value still causes the
# function to return that non-boolean falsy value on the early-return
# path, and the final line still uses `and` rather than an explicit
# boolean check), no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    def validate(self, form_key="captcha", value=None):
        """
        Validate a captcha answer (taken from request.form) against the answer saved in the session.
        Returns always true if CAPTCHA_ENABLE is set to False. Otherwise return true only if it is the correct answer.
        """
        if not self.enabled:
            return True

        session_value = session.get('captcha_answer')
        if not session_value:
            return False

        if not value and form_key in request.form:
            value = request.form[form_key].strip()

        # invalidate the answer to stop new tries on the same challenge.
        session['captcha_answer'] = None
        is_match = value and value == session_value
        return is_match''',
)
assert structural_source != original
assert "is_match = value and value == session_value" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (always return a real boolean) but a
# materially different technique: wraps the final expression in
# `bool(...)` -- coercing ANY truthy/falsy result to an actual True/False
# -- instead of the real patch's `value is not None` guard. Genuinely
# fixes the same class of bug (any falsy-but-not-False return becomes
# real False), different mechanism (a defensive outer coercion rather
# than restructuring the condition itself).
SAFE_SOURCE = '''class FlaskSessionCaptcha:
    def validate(self, form_key="captcha", value=None):
        """
        Validate a captcha answer (taken from request.form) against the answer saved in the session.
        Returns always true if CAPTCHA_ENABLE is set to False. Otherwise return true only if it is the correct answer.
        """
        if not self.enabled:
            return True

        session_value = session.get('captcha_answer')
        if not session_value:
            return False

        if not value and form_key in request.form:
            value = request.form[form_key].strip()

        # invalidate the answer to stop new tries on the same challenge.
        session['captcha_answer'] = None
        return bool(value and value == session_value)
'''
(CASE_DIR / "variant_safe_01.py").write_text(SAFE_SOURCE)
assert "bool(value and value == session_value)" in SAFE_SOURCE

# --- Verify the bool()-wrapped version genuinely returns real booleans
# for both the empty-string and None cases, matching the real fix's
# observable behavior ---
class _FakeSession(dict):
    def get(self, k, default=None):
        return dict.get(self, k, default)

def _validate_like_safe(value, session_value):
    if not session_value:
        return False
    return bool(value and value == session_value)

assert _validate_like_safe("", "realanswer") is False
assert _validate_like_safe(None, "realanswer") is False
assert _validate_like_safe("wrong", "realanswer") is False
assert _validate_like_safe("realanswer", "realanswer") is True
# Confirm this is a STRICT boolean, not just a falsy non-bool (the actual
# bug being fixed: `"" == False` is True in Python, `False is False` is
# also True, so checking identity with `is` is the meaningful test here).
assert _validate_like_safe("", "realanswer") is False and type(_validate_like_safe("", "realanswer")) is bool

# --- Variant 4: benign structural look-alike ---
# Same visible shape (`return x and x == y`) but this sibling only
# ever backs an internal debug-logging decision (whether to print a
# verbose comparison message), never a security-relevant access-control
# gate -- so even if it returns a non-boolean falsy value in some case,
# no caller anywhere treats its result as an authorization decision via
# a strict `== False` check, unlike validate()'s use as a captcha gate.
BENIGN_SOURCE = '''def should_log_verbose_comparison(current_value, expected_value):
    """Purely a logging-verbosity decision -- callers only ever use this
    in an `if should_log_verbose_comparison(...):` truthiness check
    (never `== False`), and nothing security-relevant depends on it, so
    returning a non-boolean falsy value here has no access-control
    consequence, unlike a validator used as an access-control gate."""
    return current_value and current_value == expected_value
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "captcha" not in BENIGN_SOURCE.lower()

print("Wrote 4 new samples for CASE-0078.")
