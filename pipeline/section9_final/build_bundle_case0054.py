"""
Section 9 ground-truth test bundle: CASE-0054
(JanssenProject/jans, CVE-2025-54876, CWE-522 insufficiently protected
credentials).

Core vulnerable mechanism: `print_to_log()` writes every HTTP-request
argument it receives straight into the CLI's debug log via
`" ".join(args)`, with no filtering at all. When the logged request is a
credential-setting call (a "send:" request whose JSON body carries fields
like `userPassword`/`clientSecret`), the raw plaintext credential value
ends up written to the on-disk debug log file. The fix parses the "send:"
request body and replaces any `userPassword`/`clientSecret` value with a
fixed `*****` placeholder before logging.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0054"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''            def print_to_log(*args):
                self.cli_logger.debug(" ".join(args))'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename print_to_log -> log_http_line, args -> parts. Same exact
# unfiltered logging of every argument, including credential values.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''            def log_http_line(*parts):
                self.cli_logger.debug(" ".join(parts))''',
)
renamed_source = renamed_source.replace(
    "http.client.print = print_to_log", "http.client.print = log_http_line"
)
assert "def log_http_line(*parts):" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable holding the joined line before
# logging. Same exact unfiltered credential logging, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''            def print_to_log(*args):
                joined_line = " ".join(args)
                self.cli_logger.debug(joined_line)''',
)
assert structural_source != original
assert "joined_line = \" \".join(args)" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (never write userPassword/clientSecret in
# plaintext to the log) but a materially different technique: a regex
# substitution applied to the WHOLE joined line, replacing any
# `"userPassword": "..."` / `"clientSecret": "..."` style substring
# wherever it appears, instead of the real patch's JSON-parse-then-
# reserialize approach -- genuinely redacts both fields, different
# implementation shape, more permissive about the surrounding format.
SAFE_SOURCE = '''import re

_CREDENTIAL_FIELD_RE = re.compile(
    r'("(?:userPassword|clientSecret)"\\s*:\\s*")([^"]*)(")'
)


def redact_credentials(line: str) -> str:
    return _CREDENTIAL_FIELD_RE.sub(r"\\1*****\\3", line)


class JCA_CLI:
    def _install_log_filter(self):
        def print_to_log(*args):
            joined = " ".join(args)
            self.cli_logger.debug(redact_credentials(joined))
        http.client.print = print_to_log
'''
(CASE_DIR / "variant_safe_01.py").write_text(SAFE_SOURCE)
assert "redact_credentials" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (a *args-collecting inner function that joins and
# logs its arguments) but this sibling is only ever wired up to log
# health-check ping results (fixed, non-sensitive strings like "ok"/
# response time) -- never receives request bodies or any credential-
# bearing data at all, so joining and logging everything unfiltered here
# carries no exposure risk, unlike print_to_log()'s HTTP-request hook.
BENIGN_SOURCE = '''class HealthMonitor:
    def __init__(self, logger):
        self.logger = logger

    def install_ping_logger(self):
        # Only ever receives fixed status strings from the health-check
        # loop below -- never wired to HTTP request/response bodies, so
        # there is no credential-bearing data this could ever log.
        def log_ping_result(*args):
            self.logger.debug(" ".join(args))
        return log_ping_result

    def run_health_check(self, ping_fn, log_ping_result):
        ok = ping_fn()
        log_ping_result("health-check:", "ok" if ok else "failed")
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "userPassword" not in BENIGN_SOURCE
assert "clientSecret" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0054.")
