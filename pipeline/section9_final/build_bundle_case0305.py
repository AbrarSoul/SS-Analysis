"""
Section 9 ground-truth test bundle: CASE-0305
(tornadoweb/tornado, tornado/web.py StaticFileHandler.validate_absolute_path,
CVE-2023-28370, CWE-601 open redirect).

Core vulnerable mechanism: when `StaticFileHandler` is configured with a
`default_filename` and a request names a DIRECTORY without a trailing slash,
`validate_absolute_path` redirects to the same path plus `/`
(`self.redirect(self.request.path + "/", permanent=True)`) so relative links
in the index file resolve. `self.request.path` is the raw request path. If a
route pattern trims a prefix (the handler is mounted under a regex that
consumes leading path text -- "only reachable under certain
configurations", as upstream notes), an attacker can request
`//evil.example/sub`: the router extracts `sub` as the static path but the
redirect target is built from the untrimmed request path, giving
`Location: //evil.example/sub/`. A URL starting with two slashes is a
protocol-relative URL, so the browser treats `evil.example` as the HOST:
the site redirects visitors to an attacker's domain (open redirect: phishing,
OAuth-token leakage). The upstream fix rejects such paths with `403` before
redirecting.

Sibling sites: the redirect for directories is issued at one place in this
method.

Verification: the vulnerable file is byte-identical to the real
`tornado==6.3.1` release's `tornado/web.py` and the patched file to
`tornado==6.3.2`. Each full file is copied over `tornado/web.py` inside a
REAL venv with tornado installed and a real Tornado HTTP server is started
in-process with `StaticFileHandler(path=<tmp>, default_filename=
"index.html")` mounted on the routes `r"/static/(.*)"` (a normal mount) and
`r"/.*/(.*)"` (a prefix-trimming mount) over a real directory `<tmp>/sub`. A real HTTP request `GET //evil.example/sub` (raw request line,
no client-side normalisation) is sent with a socket and the response status
line and `Location` header are read: `301` with `Location: //evil.example/
sub/` is the open redirect; `403` is the fix. A control request for
`/static/sub/index.html` (a normal file URL through the ordinary mount) must
be served (`200`) by every variant.

Every variant is the FULL real file. `validate_absolute_path` is a hook the
base class calls by name, so its name/signature are kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0305"
original = (CASE_DIR / "vulnerable_source.py").read_text()
patched = (CASE_DIR / "patched_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


REDIR = '''            if not self.request.path.endswith("/"):
                self.redirect(self.request.path + "/", permanent=True)
                return None
'''
assert original.count(REDIR) == 1

# --- Variant 1: renamed vulnerable variant (method-local rename) ---
ms = original.index("    def validate_absolute_path(self, root: str, absolute_path: str) -> Optional[str]:")
me = original.index("\n    def ", ms + 10)
body = original[ms:me]
b1 = re.sub(r"\babsolute_path\b", "abs_path", body)
assert b1 != body
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:ms] + b1 + original[me:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, REDIR, '''            if not self.request.path.endswith("/"):
                return self._redirect_to_directory()
''')
v2 = swap(v2, "    def validate_absolute_path(self, root: str, absolute_path: str) -> Optional[str]:", '''    def _redirect_to_directory(self) -> None:
        self.redirect(self.request.path + "/", permanent=True)
        return None

    def validate_absolute_path(self, root: str, absolute_path: str) -> Optional[str]:''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file, guard extracted) ---
PGUARD = '''                if self.request.path.startswith("//"):
                    # A redirect with two initial slashes is a "protocol-relative" URL.
                    # This means the next path segment is treated as a hostname instead
                    # of a part of the path, making this effectively an open redirect.
                    # Reject paths starting with two slashes to prevent this.
                    # This is only reachable under certain configurations.
                    raise HTTPError(
                        403, "cannot redirect path with two initial slashes"
                    )
'''
assert patched.count(PGUARD) == 1
v3 = swap(patched, PGUARD, '''                self._reject_protocol_relative_redirect()
''')
v3 = swap(v3, "    def validate_absolute_path(self, root: str, absolute_path: str) -> Optional[str]:", '''    def _reject_protocol_relative_redirect(self) -> None:
        # "//host/..." as a Location is protocol-relative: the browser treats
        # the next segment as a HOST (open redirect), so never emit it.
        if self.request.path.startswith("//"):
            raise HTTPError(403, "cannot redirect path with two initial slashes")

    def validate_absolute_path(self, root: str, absolute_path: str) -> Optional[str]:''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''"""
Standalone example of the same shape: redirect a directory-style URL to its
trailing-slash form, but the target is built from a FIXED, application-owned
route table (never from the raw request path), so the redirect can only go
to a known same-site location.
"""

KNOWN_SECTIONS = {"docs": "/docs/", "blog": "/blog/"}


def trailing_slash_target(section):
    return KNOWN_SECTIONS.get(section)
''')
