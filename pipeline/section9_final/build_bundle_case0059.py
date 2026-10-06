"""
Section 9 ground-truth test bundle: CASE-0059
(LibrIT/passhport, CVE-2021-3027, CWE-74 LDAP injection).

Core vulnerable mechanism: `useruid()` builds an LDAP search filter by
concatenating the user-controlled `login` value directly into the filter
string: `"(" + config.LDAPFIELD + "=" + login + ")"`. LDAP filter syntax
treats characters like `*`, `(`, `)`, `\\`, and NUL as structurally
significant -- an attacker-supplied `login` containing them can alter the
filter's meaning (e.g. injecting `*)(uid=*))(|(uid=*` -style payloads to
widen the match, bypass intended filtering, or enumerate directory
entries). The fix wraps `login` in `escape_rdn()` before concatenation,
neutralizing LDAP-significant characters.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0059"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''    # Look for the user entry.
    if not c.search(config.LDAPBASE,
                    "(" + config.LDAPFIELD + "=" + login + ")") :'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename useruid -> lookup_user_dn, login -> username throughout the
# function. Same exact unescaped LDAP filter concatenation.
renamed_source = original.replace(
    "def useruid(s, login):", "def lookup_user_dn(s, username):"
)
renamed_source = renamed_source.replace(VULNERABLE_BLOCK, '''    # Look for the user entry.
    if not c.search(config.LDAPBASE,
                    "(" + config.LDAPFIELD + "=" + username + ")") :''')
assert "def lookup_user_dn(s, username):" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable holding the built filter string
# before use. Same exact unescaped concatenation, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    # Look for the user entry.
    ldap_filter = "(" + config.LDAPFIELD + "=" + login + ")"
    if not c.search(config.LDAPBASE, ldap_filter) :''',
)
assert structural_source != original
assert 'ldap_filter = "(" + config.LDAPFIELD + "=" + login + ")"' in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (neutralize LDAP-significant characters in
# the user-controlled value before it reaches the filter) but a
# materially different technique: a small hand-written character-escape
# function covering the specific LDAP filter metacharacters, instead of
# the real patch's escape_rdn() library call -- genuinely neutralizes
# filter injection, different implementation shape.
SAFE_SOURCE = '''_LDAP_FILTER_ESCAPES = {
    "\\\\": "\\\\5c",
    "*": "\\\\2a",
    "(": "\\\\28",
    ")": "\\\\29",
}


def escape_ldap_filter_value(value):
    return "".join(_LDAP_FILTER_ESCAPES.get(ch, ch) for ch in value)


def useruid(s, login):
    """Connect to a LDAP and check the uid matching the given field data"""
    uid = False
    c = Connection(s, config.LDAPACC,
                   password=config.LDAPPASS, auto_bind=True)

    if c.result["description"] != "success":
        app.logger.error("Error connecting to the LDAP with the service account")
        return False

    safe_login = escape_ldap_filter_value(login)
    if not c.search(config.LDAPBASE,
                    "(" + config.LDAPFIELD + "=" + safe_login + ")") :
        app.logger.error("Error: Connection to the LDAP with service account failed")
    else:
        if len(c.entries) >= 1 :
            if len(c.entries) > 1 :
                app.logger.error("Error: multiple entries with this login. Trying first entry...")
            uid = c.entries[0].entry_dn
        else:
            app.logger.error("Error: Login not found")
        c.unbind()

    return uid
'''
(CASE_DIR / "variant_safe_01.py").write_text(SAFE_SOURCE)
assert "escape_ldap_filter_value" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (concatenate a value into an LDAP filter string and
# call c.search()) but this sibling looks up the SERVICE ACCOUNT's own
# fixed, config-defined identity -- never a value derived from an
# incoming login request -- so there is no attacker-controlled input
# reaching the filter, unlike useruid()'s login parameter.
BENIGN_SOURCE = '''def service_account_entry(s):
    """Looks up the service account's OWN directory entry, using only
    config.LDAPACC -- a fixed, server-side configuration value, never
    anything derived from an incoming user request."""
    c = Connection(s, config.LDAPACC, password=config.LDAPPASS, auto_bind=True)
    if c.result["description"] != "success":
        return None
    if not c.search(config.LDAPBASE, "(" + config.LDAPFIELD + "=" + config.LDAPACC + ")"):
        return None
    return c.entries[0].entry_dn if c.entries else None
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "login" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0059.")
