"""
Section 9 ground-truth test bundle: CASE-0169
(gaizhenbiao/chuanhuchatgpt, modules/utils.py auth_from_conf, CVE-2024-5124,
CWE-203 observable discrepancy / timing side channel in credential checking).

Core vulnerable mechanism: `auth_from_conf` checks the login against
config.json with `passwords[usernames.index(username)] == password`: an
ordinary string comparison that stops at the first differing character, and
that is skipped entirely for an unknown user, so response time reveals both
whether a username exists and how much of a guessed password is right.
The upstream fix builds a dict, uses `hmac.compare_digest` and narrows the
exceptions.

Measured caveats, kept in the manifest notes (real interpreter, config.json
on a real temp directory): (1) upstream calls `hmac.compare_digest` on two
str values, which raises TypeError for non-ASCII characters and is swallowed by
the new generic `except Exception`, so a CORRECT non-ASCII password is
rejected after the patch; (2) the comparison is still skipped for an unknown
username, so username existence remains observable. The safe variant encodes
to UTF-8 bytes before compare_digest and compares against a dummy value for an
unknown user.

Sibling sites: none in this file (auth_from_conf is the only credential check).

Every variant is the FULL real file. auth_from_conf is passed to the web UI as
its authentication callback by name, so the renamed variant keeps the name and
renames its locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0169"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

BODY = '''def auth_from_conf(username, password):
    try:
        with open("config.json", encoding="utf-8") as f:
            conf = json.load(f)
        usernames, passwords = [i[0] for i in conf["users"]], [
            i[1] for i in conf["users"]
        ]
        if username in usernames:
            if passwords[usernames.index(username)] == password:
                return True
        return False
    except:
        return False
'''
assert original.count(BODY) == 1 and "import hmac" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, BODY, '''def auth_from_conf(username, password):
    try:
        with open("config.json", encoding="utf-8") as f:
            settings = json.load(f)
        names, secrets = [entry[0] for entry in settings["users"]], [
            entry[1] for entry in settings["users"]
        ]
        if username in names:
            if secrets[names.index(username)] == password:
                return True
        return False
    except:
        return False
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, BODY, '''def auth_from_conf(username, password):
    try:
        with open("config.json", encoding="utf-8") as f:
            conf = json.load(f)
        for entry in conf["users"]:
            if entry[0] == username:
                return entry[1] == password
        return False
    except:
        return False
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, BODY, '''def auth_from_conf(username, password):
    import hmac

    try:
        with open("config.json", "r", encoding="utf-8") as f:
            conf = json.load(f)
        users = {entry[0]: entry[1] for entry in conf["users"]}
        # Always run one constant-time comparison, against a dummy value for an
        # unknown user, on UTF-8 bytes so non-ASCII passwords work.
        stored = users.get(username)
        known = stored is not None
        expected = (stored if known else "\\x00" * 16).encode("utf-8")
        supplied = str(password).encode("utf-8")
        matched = hmac.compare_digest(expected, supplied)
        return bool(known and matched)
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        return False
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''def is_admin_role(role_name):
    """Same `==` string comparison shape as the credential check, but on a
    non-secret label (a role name that is shown in the UI), so the comparison
    time reveals nothing an attacker could not already read."""
    return role_name == "admin"
'''
assert "non-secret label" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0169.")
