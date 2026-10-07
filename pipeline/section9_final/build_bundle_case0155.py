"""
Section 9 ground-truth test bundle: CASE-0155
(emmett-framework/core, emmett_core/http/wrappers/__init__.py
IngressWrapper.cookies, CVE-2026-25577, CWE-248 uncaught exception /
CWE-307 improper restriction of repeated failures -> denial of service).

Core vulnerable mechanism: `cookies` splits the request's Cookie header on
";" and calls `SimpleCookie.load(fragment)` on each piece with no error
handling. `SimpleCookie.load` raises `http.cookies.CookieError` for some
malformed fragments (measured by fuzzing 300,000 random fragments on Python
3.12 and 3.14: the fragment `,==` raises "Illegal key ','"), so a request with
`Cookie: ,==` (or `a=1; ,==`) makes every access to `request.cookies` raise
and the request fail with a server error. The upstream fix wraps the load in
`try/except Exception: continue`, dropping the bad fragment.

Sibling sites: none in this file; `cookies` is the only place a Cookie header
is parsed.

Every variant is the FULL real file. `cookies` is a public cached property used
by application code, so the renamed variant renames only its locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0155"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

BODY = '''    def cookies(self) -> SimpleCookie:
        cookies: SimpleCookie = SimpleCookie()
        for cookie in self.headers.get("cookie", "").split(";"):
            cookies.load(cookie)
        return cookies
'''
assert original.count(BODY) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, BODY, '''    def cookies(self) -> SimpleCookie:
        jar: SimpleCookie = SimpleCookie()
        for fragment in self.headers.get("cookie", "").split(";"):
            jar.load(fragment)
        return jar
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, BODY, '''    def cookies(self) -> SimpleCookie:
        raw = self.headers.get("cookie", "")
        fragments = [part for part in raw.split(";")]
        cookies: SimpleCookie = SimpleCookie()
        for cookie in fragments:
            cookies.load(cookie)
        return cookies
''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Catches only the parser's own CookieError (dropping that fragment) instead
# of every Exception like upstream.
v3 = swap(original, BODY, '''    def cookies(self) -> SimpleCookie:
        cookies: SimpleCookie = SimpleCookie()
        for cookie in self.headers.get("cookie", "").split(";"):
            try:
                cookies.load(cookie)
            except CookieError:
                continue
        return cookies
''')
v3 = swap(v3, "from http.cookies import SimpleCookie\n", "from http.cookies import CookieError, SimpleCookie\n")
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''from http.cookies import SimpleCookie


def default_preference_cookies() -> SimpleCookie:
    """Same SimpleCookie.load(fragment) loop as a Cookie-header parser, but the
    fragments are a developer-written constant, so no request data can reach
    load() and it can never see a malformed fragment."""
    jar: SimpleCookie = SimpleCookie()
    for fragment in "theme=dark; lang=en".split(";"):
        jar.load(fragment)
    return jar
'''
assert '"theme=dark; lang=en"' in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)
print("Wrote 4 new samples for CASE-0155.")
