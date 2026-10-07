"""
Section 9 ground-truth test bundle: CASE-0056
(Kozea/Radicale, CVE-2017-8342, CWE-362 timing-oracle race condition).

Core vulnerable mechanism: `is_authenticated()` returns as soon as it
finds a matching username line, immediately returning whatever
`self.verify()` yields (True or False) with NO subsequent delay -- so the
total time the function takes leaks information: a request for a
non-existent username returns almost instantly, while a request for a
real username (even with a wrong password) takes as long as the hash
verification itself. An attacker probing many usernames can time
responses to enumerate which usernames exist, and probe passwords with no
rate-limiting delay at all. The fix only returns True on an actually-
verified match, and unconditionally adds a randomized ~1-2 second delay
before any `False` result, normalizing response timing and slowing
brute-force attempts.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0056"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''    def is_authenticated(self, user, password):
        # The content of the file is not cached because reading is generally a
        # very cheap operation, and it's useful to get live updates of the
        # htpasswd file.
        with open(self.filename) as fd:
            for line in fd:
                line = line.strip()
                if line:
                    login, hash_value = line.split(":")
                    if login == user:
                        return self.verify(hash_value, password)
        return False'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename is_authenticated -> check_credentials, login/hash_value ->
# username/stored_hash. Same exact immediate-return-with-no-delay timing
# leak.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''    def check_credentials(self, user, password):
        # The content of the file is not cached because reading is generally a
        # very cheap operation, and it's useful to get live updates of the
        # htpasswd file.
        with open(self.filename) as fd:
            for line in fd:
                line = line.strip()
                if line:
                    username, stored_hash = line.split(":")
                    if username == user:
                        return self.verify(stored_hash, password)
        return False''',
)
assert "def check_credentials(self, user, password):" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting.
# Same exact timing-leak vulnerability, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    def is_authenticated(self, user, password):
        # The content of the file is not cached because reading is generally a
        # very cheap operation, and it's useful to get live updates of the
        # htpasswd file.
        with open(self.filename) as fd:
            for line in fd:
                stripped_line = line.strip()
                if not stripped_line:
                    continue
                login, hash_value = stripped_line.split(":")
                is_match = (login == user)
                if is_match:
                    return self.verify(hash_value, password)
        return False''',
)
assert structural_source != original
assert "is_match = (login == user)" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (normalize response timing, never
# short-circuit based on whether a match exists) but a materially
# different technique: always iterates every line (no early return inside
# the loop under any circumstance) and busy-checks a target minimum
# wall-clock duration via time.perf_counter() instead of the real patch's
# fixed `time.sleep(1 + random.random())` -- genuinely removes the timing
# signal, different implementation shape.
SAFE_SOURCE = '''import time


class HtpasswdAuth:
    MIN_RESPONSE_SECONDS = 1.0

    def __init__(self, filename, verify):
        self.filename = filename
        self.verify = verify

    def is_authenticated(self, user, password):
        started_at = time.perf_counter()
        authenticated = False
        with open(self.filename) as fd:
            for line in fd:
                line = line.strip()
                if not line:
                    continue
                login, hash_value = line.split(":")
                if login == user and self.verify(hash_value, password):
                    authenticated = True
        elapsed = time.perf_counter() - started_at
        remaining = self.MIN_RESPONSE_SECONDS - elapsed
        if remaining > 0:
            time.sleep(remaining)
        return authenticated
'''
(CASE_DIR / "variant_safe_01.py").write_text(SAFE_SOURCE)
assert "MIN_RESPONSE_SECONDS" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (open a file, scan lines, split on ":", return
# immediately on the first match) but this sibling looks up a purely
# COSMETIC display-name preference from a non-secret mapping file --
# there is no credential verification anywhere in it, so its response
# timing reveals nothing an attacker could use for account enumeration or
# brute-forcing, unlike is_authenticated()'s password check.
BENIGN_SOURCE = '''class DisplayNameLookup:
    def __init__(self, filename):
        self.filename = filename

    def get_display_name(self, username):
        """Looks up a user's chosen display name from a public,
        non-secret preferences file -- no credential of any kind is
        involved, so timing behavior here carries no security-relevant
        signal."""
        with open(self.filename) as fd:
            for line in fd:
                line = line.strip()
                if line:
                    login, display_name = line.split(":")
                    if login == username:
                        return display_name
        return username
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "password" not in BENIGN_SOURCE
assert "verify" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0056.")
