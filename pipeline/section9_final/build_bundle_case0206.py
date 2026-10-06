"""
Section 9 ground-truth test bundle: CASE-0206
(kennethreitz/requests, requests/sessions.py SessionRedirectMixin.resolve_redirects,
CVE-2015-2296, CWE not classified upstream (NVD-CWE-Other): cookie of a redirect
response is attributed to the redirect TARGET host).

Core vulnerable mechanism: while following a redirect, `resolve_redirects`
builds `prepared_request` (a copy of the previous request whose URL was ALREADY
changed to the Location target) and then calls
`extract_cookies_to_jar(prepared_request._cookies, prepared_request, resp.raw)`.
The cookie jar attributes a host-only Set-Cookie to the host of the request it
is given, so a cookie set by the redirecting host (a.example) is stored and
sent as if it belonged to the redirect target (b.example). The upstream fix
passes `req`, the previous request that actually produced `resp`.

Sibling sites: the second `extract_cookies_to_jar(self.cookies, prepared_request,
resp.raw)` after `self.send(...)` is NOT a sibling: `req = prepared_request` has
run by then, so prepared_request is the request that produced the new response.

Verification: the real SessionRedirectMixin source is extracted from each full
file and run against the installed requests (2.34) cookie jar/PreparedRequest
with a stand-in send() (the file itself cannot be imported on this Python
because of `from collections import Mapping`). The Cookie header of the
redirected request is measured.

Every variant is the FULL real file. resolve_redirects keeps its name and
parameters (public API / called positionally); locals are renamed instead.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0206"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original

CALL = "            extract_cookies_to_jar(prepared_request._cookies, prepared_request, resp.raw)\n"
assert original.count(CALL) == 1

start = original.index("    def resolve_redirects(")
end = original.index("    def rebuild_auth(")
METHOD = original[start:end]


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
# Locals of resolve_redirects only (prepared_request, hist, new_hist,
# parsed_rurl); the vulnerable call still hands the redirected request over.
m1 = METHOD
for a, b in (("prepared_request", "follow_up"), ("new_hist", "trail_copy"),
             ("hist", "trail"), ("parsed_rurl", "origin_parts")):
    assert a in m1
    m1 = m1.replace(a, b)
assert "extract_cookies_to_jar(follow_up._cookies, follow_up, resp.raw)" in m1
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:start] + m1 + original[end:])

# --- Variant 2: structurally changed vulnerable variant ---
# The cookie bookkeeping moves into a helper method; it still receives (and
# uses) the redirected request as the URL source.
v2 = swap(original, CALL, '''            self._carry_redirect_cookies(prepared_request, resp)
''')
v2 = swap(v2, "    def rebuild_auth(", '''    def _carry_redirect_cookies(self, prepared_request, resp):
        jar = prepared_request._cookies
        extract_cookies_to_jar(jar, prepared_request, resp.raw)

    def rebuild_auth(''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Remember the request that produced resp at the top of the loop and attribute
# the cookies to it (upstream passes `req` directly).
v3 = swap(original, "        while resp.is_redirect:\n            prepared_request = req.copy()\n",
          "        while resp.is_redirect:\n            request_of_resp = req\n            prepared_request = req.copy()\n")
v3 = swap(v3, CALL, "            extract_cookies_to_jar(prepared_request._cookies, request_of_resp, resp.raw)\n")
(CASE_DIR / "variant_safe_01.py").write_text(v3)

# --- Variant 4: benign look-alike ---
benign = '''"""Response-cookie bookkeeping for a hand-rolled redirect follower."""
from requests.cookies import RequestsCookieJar, extract_cookies_to_jar


def remember_cookies(jar, request, response):
    """Store the cookies of `response` in `jar`, attributed to the request that
    produced it (not to the redirect target)."""
    if jar is None:
        jar = RequestsCookieJar()
    extract_cookies_to_jar(jar, request, response.raw)
    return jar


def follow(session, response, request):
    """Follow one redirect: cookies of `response` belong to `request`."""
    remember_cookies(session.cookies, request, response)
    return response.headers.get("location")
'''
(CASE_DIR / "benign_lookalike.py").write_text(benign)
