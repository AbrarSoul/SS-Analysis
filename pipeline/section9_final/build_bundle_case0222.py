"""
Section 9 ground-truth test bundle: CASE-0222
(mindsdb/mindsdb, mindsdb/integrations/handlers/dremio_handler/dremio_handler.py
DremioHandler.connect, CVE-2023-38699, CWE-311 as labelled upstream; the code
weakness is disabled TLS certificate verification, CWE-295).

Core vulnerable mechanism: `connect` logs in to the Dremio server with
`requests.post(self.base_url + '/apiv2/login', headers=headers, data=data,
verify=False)`. `verify=False` turns off certificate validation, so anyone who
can intercept the connection (a machine in the network path, a spoofed DNS
answer) can present any certificate, receive the JSON body containing the
Dremio user name and password in clear text, and return a forged token that the
handler then trusts for every later query. The upstream fix removes
`verify=False`, restoring requests' default of verifying the certificate.

Measured caveat, kept in the manifest notes: `base_url` is built as
`http://host:port` in `__init__`, so the handler as recorded talks plain HTTP
unless the caller replaces base_url; the verify flag only matters once an
`https://` URL is used, which is why the harness sets `base_url` to an https URL.
The JSON login body is also built by string concatenation, which is a separate
injection weakness that neither version changes.

Sibling sites: the other requests calls in the file (`native_query`'s POST and
three GETs) do not pass `verify`, so they already verify certificates; the login
call is the only `verify=False`.

Verification: each full file is imported as a module with the `mindsdb`,
`mindsdb_sql`, `sqlalchemy_dremio` and `pandas` imports stubbed, and the real
`requests` (2.34) is used. A local HTTPS server with a freshly generated
self-signed certificate answers POST /apiv2/login with a token; `connect()`
is called with base_url pointing at it.

Every variant is the FULL real file. `connect` is called by name from the
handler base class machinery, so its name and signature are kept; the renamed
variant renames locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0222"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


s = original.index("    def connect(self) -> dict:")
e = original.index("    def disconnect(self):")
BLOCK = original[s:e]
assert original.count(BLOCK) == 1

# --- Variant 1: renamed vulnerable variant ---
V1 = '''    def connect(self) -> dict:
        """
        Set up the connection required by the handler.
        Returns:
            HandlerStatusResponse
        """

        request_headers = {
            'Content-Type': 'application/json',
        }

        credentials_json = '{' + f'"userName": "{self.connection_data["username"]}","password": "{self.connection_data["password"]}"' + '}'

        login_response = requests.post(self.base_url + '/apiv2/login', headers=request_headers, data=credentials_json, verify=False)

        return {
            'Authorization': '_dremio' + login_response.json()['token'],
            'Content-Type': 'application/json',
        }

'''
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:s] + V1 + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
V2 = BLOCK.replace(
    "        response = requests.post(self.base_url + '/apiv2/login', headers=headers, data=data, verify=False)\n",
    "        response = self._post_login(headers, data)\n",
)
assert V2 != BLOCK
V2 += '''    def _post_login(self, headers, data):
        # certificate verification is switched off for this call
        session = requests.Session()
        session.verify = False
        return session.post(self.base_url + '/apiv2/login', headers=headers, data=data)

'''
(CASE_DIR / "variant_vulnerable_02.py").write_text(original[:s] + V2 + original[e:])

# --- Variant 3: transformed safe variant ---
V3 = BLOCK.replace(
    "        response = requests.post(self.base_url + '/apiv2/login', headers=headers, data=data, verify=False)\n",
    "        response = requests.post(self.base_url + '/apiv2/login', headers=headers, data=data, verify=True, timeout=30)\n",
)
assert V3 != BLOCK
(CASE_DIR / "variant_safe_01.py").write_text(original[:s] + V3 + original[e:])

BENIGN = '''"""Standalone example of the same shape: an HTTPS GET with the default
certificate verification, used to read a public, unauthenticated status page."""
import requests


def read_status(base_url):
    response = requests.get(base_url + "/status.json", timeout=10)
    return response.json()
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
