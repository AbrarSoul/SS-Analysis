"""
Section 9 ground-truth test bundle: CASE-0170
(getsentry/sentry, src/sentry/api/endpoints/auth_index.py
AuthIndexEndpoint._validate_superuser, CVE-2024-32474, CWE-117 / CWE-312
sensitive data written to logs).

Core vulnerable mechanism: `_validate_superuser` logs
`extra={"validator": validator, ...}` where `validator` is the
AuthVerifyValidator (a DRF Serializer) built from `request.data`. Measured
with real Django REST framework: `repr(serializer)` (what structured-log
formatters use for extra values) is `V(data={'password': 'hunter2'}): ...`,
i.e. the submitted PASSWORD ends up in the log. The upstream fix removes the
`"validator"` entry from that log call.

Sibling site: `_verify_user_via_inputs` logs
`extra={"validated_data": validator.validated_data, ...}` in the
`u2f_authentication.interface_not_enrolled` branch; validated_data contains the
password when one is submitted together with a u2f challenge, so it leaks the
same secret and upstream did not change it. The safe variant fixes BOTH log
calls; the vulnerable variants leave both.

Every variant is the FULL real file. `_validate_superuser` is an internal
method called by name from `put`, so the renamed variant renames its
parameters and locals, not the method.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0170"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

LOG1 = '''        logger.info(
            "auth-index.validate_superuser",
            extra={
                "validator": validator,
                "user": request.user.id,
                "raise_exception": not DISABLE_SSO_CHECK_FOR_LOCAL_DEV,
                "verify_authenticator": verify_authenticator,
            },
        )
'''
LOG2 = '''                    extra={"validated_data": validator.validated_data, "user": request.user.id},
'''
assert original.count(LOG1) == 1 and original.count(LOG2) == 1
s = original.index("    def _validate_superuser(\n")
e = original.index("\n    def post(self, request: Request)", s)
BLOCK = original[s:e]


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
head, rest = BLOCK.split('        """\n        For a superuser', 1)
doc_end = rest.index('        """\n') + len('        """\n')
docstring = '        """\n        For a superuser' + rest[:doc_end]
code = rest[doc_end:]
parts = re.split(r'("(?:[^"\\]|\\.)*")', code)
for i in range(0, len(parts), 2):
    for old, new in (("validator", "checker"), ("request", "req"), ("verify_authenticator", "need_u2f"),
                     ("authenticated", "verified")):
        parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, parts[i])
head = head.replace("self, validator: AuthVerifyValidator, request: Request, verify_authenticator: bool",
                    "self, checker: AuthVerifyValidator, req: Request, need_u2f: bool")
b = head + docstring + "".join(parts)
assert '"validator": checker,' in b and "req.user.id" in b and "self._verify_user_via_inputs(checker, req)" in b
assert "def _validate_superuser(\n        self, checker: AuthVerifyValidator, req: Request, need_u2f: bool" in b
assert "checker.is_valid(raise_exception=" in b and '"verify_authenticator": need_u2f,' in b
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:s] + b + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, LOG1, "        self._log_superuser_check(validator, request, verify_authenticator)\n")
v2 = swap(v2, "    def _validate_superuser(\n", '''    @staticmethod
    def _log_superuser_check(validator, request, verify_authenticator) -> None:
        logger.info(
            "auth-index.validate_superuser",
            extra={
                "validator": validator,
                "user": request.user.id,
                "raise_exception": not DISABLE_SSO_CHECK_FOR_LOCAL_DEV,
                "verify_authenticator": verify_authenticator,
            },
        )

    def _validate_superuser(
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Log only the NAMES of the submitted fields, never their values, at both
# sites (upstream just drops the validator entry from the first call).
v3 = swap(original, LOG1, LOG1.replace('                "validator": validator,\n',
                                       '                "submitted_fields": sorted(validator.initial_data),\n'))
v3 = swap(v3, LOG2, '''                    extra={"validated_fields": sorted(validator.validated_data), "user": request.user.id},
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import logging

logger = logging.getLogger(__name__)


def log_verification_attempt(user_id, method):
    """Same logger.info(..., extra={...}) shape as the superuser validation
    log, but the extra values are only the numeric user id and the fixed name
    of the verification method, never any submitted credential or the
    serializer that holds it."""
    logger.info("auth-index.verify_attempt", extra={"user": user_id, "method": method})
'''
assert "never any submitted credential" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0170.")
