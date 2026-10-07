"""
Section 9 ground-truth test bundle: CASE-0167
(frappe/press, press/api/saas.py account_request, CVE-2024-49751, CWE-79
stored cross-site scripting).

Core vulnerable mechanism: `account_request` is a guest-callable API
(`allow_guest=True`) that stores the caller's `first_name` and `last_name`
in an Account Request after passing them through `frappe.utils.sanitize_html`.
That sanitiser is designed for rich text: it allows a large tag set (svg,
mathml, style, link, ...), keeps `data-*` attributes, and RETURNS ITS INPUT
UNCHANGED when the string parses as JSON. Measured with the real
frappe v15.40.0 `html_utils.py` and real bleach: the JSON-string payload
`"<img src=x onerror=alert(1)>"` comes back byte-for-byte, and
`<link rel=stylesheet href=//evil/x.css>` and `<style>` survive. The names
are later rendered in emails and dashboards, so the markup executes. The
upstream fix switches to `clean_html`, which allows only a handful of basic
tags and no attributes and strips the rest.

Sibling sites: `first_name` and `last_name` are the two free-text fields
passed to the sanitiser (both are fixed together); `country` is validated
against the country list, `email` by validate_email_address.

Every variant is the FULL real file. account_request is a whitelisted API
called by name and keyword from the frontend, so the renamed variant keeps
the function name and the parameter names and renames locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0167"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

IMP = "\tfrom frappe.utils import sanitize_html\n"
NAMES = '''\t\t\t\t"first_name": sanitize_html(first_name),
\t\t\t\t"last_name": sanitize_html(last_name),
'''
s = original.index("def account_request(\n")
e = original.index("\n\ndef create_or_rename_saas_site", s)
BLOCK = original[s:e]
assert original.count(IMP) == 1 and original.count(NAMES) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
head, body = BLOCK.split(IMP)
parts = re.split(r'("(?:[^"\\]|\\.)*")', body)
for i in range(0, len(parts), 2):
    for old, new in (("account_request", "signup"), ("all_countries", "countries"), ("team", "existing_team"),
                     ("site_name", "site_label")):
        parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, parts[i])
b = head + IMP + "".join(parts)
assert "signup = frappe.get_doc(" in b and "site_label = signup.get_site_name()" in b
assert 'find(countries, lambda x: x.lower() == country.lower())' in b and "existing_team = frappe.db.get_value(" in b
assert '{"team": existing_team, "status": "Unpaid"' in b
assert "create_or_rename_saas_site(app, signup)" in b and '"first_name": sanitize_html(first_name)' in b
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:s] + b + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, NAMES, '''\t\t\t\t"first_name": _clean_name(first_name, sanitize_html),
\t\t\t\t"last_name": _clean_name(last_name, sanitize_html),
''')
v2 = swap(v2, "\n\ndef create_or_rename_saas_site", '''

def _clean_name(value, sanitizer):
\treturn sanitizer(value) if value else value


def create_or_rename_saas_site''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Names are plain text: every markup character is HTML-escaped with the
# standard library; upstream strips disallowed markup with frappe's clean_html.
v3 = swap(original, IMP, "\timport html\n")
v3 = swap(v3, NAMES, '''\t\t\t\t"first_name": html.escape(first_name),
\t\t\t\t"last_name": html.escape(last_name),
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''def display_name(first_name, last_name):
\t"""Same first_name/last_name handling as the signup API, but the combined
\tname is only ever used as plain text in a log line (never rendered as HTML),
\tso markup in it has nothing to execute in."""
\treturn f"{first_name or ''} {last_name or ''}".strip()


def log_signup(logger, first_name, last_name):
\tlogger.info("signup requested by %s", display_name(first_name, last_name))
'''
assert "never rendered as HTML" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0167.")
