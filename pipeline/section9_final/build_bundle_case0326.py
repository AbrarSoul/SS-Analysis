r"""
Section 9 ground-truth test bundle: CASE-0326
(web2py/web2py, gluon/globals.py Request.__init__, CVE-2016-3952,
CWE-255 credentials management / CWE-798 hard-coded credentials; sensitive
server settings exposed to applications).

Core vulnerable mechanism: every web2py `Request` copies the whole
process-wide `global_settings` object into `request.env`
(`self.env.update(global_settings)`) and also keeps a reference in
`request.global_settings`. `global_settings` holds server-side values (paths, version, the command-line
options the server was started with, ...). The harness models a secret in it
with a stub `hmac_key`. Any application code, template, or debugging view that dumps
`request.env` or `request.global_settings` (a very common pattern:
`{{=BEAUTIFY(request.env)}}` in the default layout) therefore discloses server
secrets to whoever can see the page. The upstream fix removes both lines so
the request no longer carries the global settings.

Sibling sites: `request.env.web2py_path` (set on the line above) is the one
setting the request keeps.

Verification: `Request.__init__` (from `def __init__` to the end of the
constructor) is sliced from each full file and exec'd inside a `Request`
class over a stub `Storage`/`List`, with real `datetime`, a stub `Cookie`,
and stub `global_settings`/`settings` objects containing
`applications_parent` and a secret `hmac_key`. After
`Request({'REQUEST_METHOD': 'GET'})` the measurement is whether
`request.env` holds `hmac_key`/`web2py_path` and whether
`request.global_settings` exists. Vulnerable variants expose the secret in
`env` and keep `global_settings`; patched/safe expose neither, and still set
`env.web2py_path` and copy the caller's environ in every file.

Every variant is the FULL real file; `Request.__init__` keeps its name and
signature.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0326"
original = (CASE_DIR / "vulnerable_source.py").read_text()
patched = (CASE_DIR / "patched_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


HEAD = "    def __init__(self, env):\n        Storage.__init__(self)\n        self.env = Storage(env)\n"
UPD = "        self.env.update(global_settings)\n"

# --- Variant 1: renamed vulnerable variant (constructor parameter renamed) ---
v1 = swap(original, HEAD, "    def __init__(self, wsgi_environ):\n        Storage.__init__(self)\n        self.env = Storage(wsgi_environ)\n")
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (settings merge moved into a helper method) ---
v2 = swap(original, UPD, "        self._merge_settings()\n")
v2 = swap(v2, "        self.global_settings = settings.global_settings\n        self._uuid = None\n",
          "        self.global_settings = settings.global_settings\n        self._uuid = None\n\n    def _merge_settings(self):\n        self.env.update(global_settings)\n")
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the env construction moved into a static helper) ---
PH = "        self.env = Storage(env)\n        self.env.web2py_path = global_settings.applications_parent\n"
v3 = swap(patched, PH, "        self.env = self._build_env(env)\n")
v3 = swap(v3, "        self._uuid = None\n\n    def parse_get_vars(self):",
          "        self._uuid = None\n\n    @staticmethod\n    def _build_env(env):\n        built = Storage(env)\n        built.web2py_path = global_settings.applications_parent\n        return built\n\n    def parse_get_vars(self):")
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''PUBLIC_SETTINGS = ('web2py_version', 'applications_parent')


class RequestEnvironment(object):
    """Builds a request environment that carries only an explicit, non-secret subset of the server settings."""

    def __init__(self, environ, server_settings):
        self.env = dict(environ)
        for key in PUBLIC_SETTINGS:
            if key in server_settings:
                self.env[key] = server_settings[key]
''')
