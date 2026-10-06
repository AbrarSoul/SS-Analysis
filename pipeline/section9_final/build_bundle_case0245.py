"""
Section 9 ground-truth test bundle: CASE-0245
(opendns/OpenResolve, resolverapi/endpoints.py LookupRecordType.valid_args,
CVE-2015-10010, CWE-79 reflected content).

Core vulnerable mechanism: the API's error responses copy the caller's input
straight into the message: `abort(400, message="%s type is not supported" % rdtype)`,
`"%s is not a valid domain name" % domain`, `"%s is not a valid ip address" % ip`
and `'No nameserver found for %s' % ip`. Anything in the URL path, for example
`<img src=x onerror=alert(1)>`, comes back verbatim in the JSON body. A front end
that inserts `message` into the page with `innerHTML` (or any client that renders
the body as HTML) executes it. The upstream fix replaces the four messages with
fixed text that does not include the input.

Measured caveat, kept in the manifest notes: the API answers with
`Content-Type: application/json` and no `X-Content-Type-Options: nosniff`, so a
current browser that opens the URL shows the JSON as text; the reflection is
exploitable through a client that treats `message` as HTML or through legacy
content sniffing, not by direct navigation. The messages also stay reflected in
`"No nameservers for %s" % domain` (404 in LookupRecordType.get), which the upstream
patch does not touch (the domain has passed `is_valid_hostname` by then; the real
validator is not part of this file).

Sibling sites: four reflection sites are in the upstream diff (two in
`LookupRecordType.valid_args`, one in `ReverseLookup.get`, one in
`ReverseLookup.valid_args`); the auto-located target is the first method only. The
safe variant covers all four and also the untouched NXDOMAIN message of
`LookupRecordType.get`.

Verification: each full file is imported as a module with `resolverapi.*` stubbed and
registered on a REAL Flask app through REAL flask-restful (`Api`, `abort`), and the
routes are called with the test client using `<img src=x onerror=alert(1)>` as the
record type, the domain and the IP.

Every variant is the FULL real file. The resource classes are registered by name, so
their names and `get`/`valid_args` signatures are kept; the renamed variant renames
the parameters of `LookupRecordType.valid_args`.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0245"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


VA1 = '''    def valid_args(self, rdtype, domain):
        if not is_valid_rdtype(rdtype):
            abort(400, message="%s type is not supported" % rdtype)
        if not is_valid_hostname(domain):
            abort(400, message="%s is not a valid domain name" % domain)
'''
NX = "                return {'message': 'No nameserver found for %s' % ip}, 404\n"
VA2 = '''    def valid_args(self, ip):
        if not is_valid_ip(ip):
            abort(400, message="%s is not a valid ip address" % ip)
'''
NOSRV = '''                return {'message': "No nameservers for %s" % domain}, 404
'''
for b in (VA1, NX, VA2, NOSRV):
    assert original.count(b) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, VA1, '''    def valid_args(self, record_type, hostname):
        if not is_valid_rdtype(record_type):
            abort(400, message="%s type is not supported" % record_type)
        if not is_valid_hostname(hostname):
            abort(400, message="%s is not a valid domain name" % hostname)
''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, VA1, '''    def valid_args(self, rdtype, domain):
        if not is_valid_rdtype(rdtype):
            bad_request("%s type is not supported" % rdtype)
        if not is_valid_hostname(domain):
            bad_request("%s is not a valid domain name" % domain)
''')
v2 = swap(v2, "class LookupRecordType(Resource):", '''def bad_request(message):
    abort(400, message=message)


class LookupRecordType(Resource):''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, "import time\n", "import time\nfrom html import escape\n")
v3 = swap(v3, VA1, '''    def valid_args(self, rdtype, domain):
        if not is_valid_rdtype(rdtype):
            abort(400, message="%s type is not supported" % escape(rdtype))
        if not is_valid_hostname(domain):
            abort(400, message="%s is not a valid domain name" % escape(domain))
''')
v3 = swap(v3, NX, "                return {'message': 'No nameserver found for %s' % escape(ip)}, 404\n")
v3 = swap(v3, VA2, '''    def valid_args(self, ip):
        if not is_valid_ip(ip):
            abort(400, message="%s is not a valid ip address" % escape(ip))
''')
v3 = swap(v3, NOSRV, '''                return {'message': "No nameservers for %s" % escape(domain)}, 404
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape: an error message built from a fixed
list of server-side error codes, never from the request."""
ERRORS = {"bad_type": "record type not supported", "bad_domain": "domain name invalid"}


def error_message(code):
    return {"message": ERRORS.get(code, "unexpected error")}
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
