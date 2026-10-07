r"""
Section 9 ground-truth test bundle: CASE-0317
(urllib3/urllib3, urllib3/contrib/pyopenssl.py PyOpenSSLContext.verify_mode,
CVE-2016-9015, CWE-295 improper certificate validation).

Core vulnerable mechanism: `PyOpenSSLContext` emulates the standard-library
`ssl.SSLContext` on top of pyOpenSSL. Its `verify_mode` setter passes the
STDLIB constant straight to `OpenSSL.SSL.Context.set_verify` without
translating it. The two constant families differ: `ssl.CERT_REQUIRED` is 2,
but in OpenSSL 2 is `VERIFY_FAIL_IF_NO_PEER_CERT` on its own (no
`VERIFY_PEER`). Per the fix commit, with OpenSSL 1.1.0 (as used through
pyOpenSSL) a client whose verify mode lacks `VERIFY_PEER` silently does NOT
validate the server certificate, so `cert_reqs='CERT_REQUIRED'` accepts any
certificate (man-in-the-middle); the advisory itself calls this an
uncommon configuration. The getter likewise returns the raw OpenSSL mode instead of the stdlib
constant. The fix introduces `_stdlib_to_openssl_verify` /
`_openssl_to_stdlib_verify` and translates in both directions.

Sibling sites: `ssl_wrap_socket` already translated with `_openssl_verify`
and is renamed to the new mapping in the fix.

Verification (REAL pyOpenSSL): the verify-mode mapping dictionaries and the
`PyOpenSSLContext` class are sliced from each full file and exec'd against
the real pyOpenSSL, ssl, six and socket (the wrapper socket class is a
stand-in). The context sets `verify_mode = ssl.CERT_REQUIRED` and the raw pyOpenSSL
mode and the getter are read; a handshake against a local stdlib-ssl server
with a self-signed certificate is also attempted. Vulnerable variants set
raw mode 2 (VERIFY_PEER bit clear); patched/safe set 3 (VERIFY_PEER +
FAIL_IF_NO_PEER_CERT); the getter returns ssl.CERT_REQUIRED (2) in all files.
Caveat: the installed OpenSSL is 3.0.x, where a client with mode 2 still
verifies, so the handshake is rejected in every file; the wrong flag itself
(not a completed MITM handshake) is the measured difference.

Every variant is the FULL real file; the class and property names are the
urllib3 API and are kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0317"
original = (CASE_DIR / "vulnerable_source.py").read_text()
patched = (CASE_DIR / "patched_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant (module mapping and setter parameter renamed) ---
v1 = original.replace("_openssl_verify", "_verify_translation")
assert v1.count("_verify_translation") == 2
v1 = swap(v1, "    def verify_mode(self, value):\n        self._ctx.set_verify(value, _verify_callback)\n",
          "    def verify_mode(self, requested):\n        self._ctx.set_verify(requested, _verify_callback)\n")
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (setter delegates to a helper method) ---
v2 = swap(original, "    def verify_mode(self, value):\n        self._ctx.set_verify(value, _verify_callback)\n",
          "    def verify_mode(self, value):\n        self._apply_verify_mode(value)\n\n    def _apply_verify_mode(self, mode):\n        self._ctx.set_verify(mode, _verify_callback)\n")
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the reverse map is an explicit literal) ---
REV = '''_openssl_to_stdlib_verify = dict(
    (v, k) for k, v in _stdlib_to_openssl_verify.items()
)
'''
v3 = swap(patched, REV, '''_openssl_to_stdlib_verify = {
    OpenSSL.SSL.VERIFY_NONE: ssl.CERT_NONE,
    OpenSSL.SSL.VERIFY_PEER: ssl.CERT_OPTIONAL,
    OpenSSL.SSL.VERIFY_PEER + OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT:
        ssl.CERT_REQUIRED,
}
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''"""Log-level adapter: translates the standard-library logging levels to a vendor SDK's own numbering."""
import logging

_stdlib_to_vendor = {
    logging.DEBUG: 5,
    logging.INFO: 4,
    logging.WARNING: 3,
    logging.ERROR: 2,
}
_vendor_to_stdlib = dict((v, k) for k, v in _stdlib_to_vendor.items())


class VendorLogger(object):
    def __init__(self):
        self._level = 3

    @property
    def level(self):
        return _vendor_to_stdlib[self._level]

    @level.setter
    def level(self, value):
        self._level = _stdlib_to_vendor[value]
''')
