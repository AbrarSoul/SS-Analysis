"""
Section 9 ground-truth test bundle: CASE-0275
(pyload/pyload, src/pyload/webui/app/blueprints/cnl_blueprint.py
local_check.wrapper, CVE-2025-7346, CWE-281 improper access control via a
spoofable Host-header bypass).

Core vulnerable mechanism: `local_check` is meant to restrict the CNL
("Click'N'Load") endpoints -- including `/flash/add` and
`/flash/addcrypted`, which write files to disk based on request data --
to localhost only. It correctly checks `REMOTE_ADDR` (the real TCP peer
address, which a remote client cannot forge at the application layer),
but ALSO accepts the request if the client-supplied `Host:` header
(`flask.request.environ["HTTP_HOST"]`) equals `"127.0.0.1:9666"` or
`"[::1]:9666"`. Unlike `REMOTE_ADDR`, the `Host` header is ordinary
request data any HTTP client controls completely -- a remote,
unauthenticated attacker anywhere on the internet can send `Host:
127.0.0.1:9666` and be treated as a trusted local client, fully bypassing
the "local only" restriction and reaching the CNL endpoints' file-write
primitives. The upstream fix simply removes the `HTTP_HOST` branch,
authorizing solely on `REMOTE_ADDR`.

Sibling sites: `local_check` is the only access-control decorator in the
file (and is applied to every route in this blueprint); there is one call
site to fix.

Verification: each full file's `local_check` decorator is extracted
verbatim and applied to a trivial real view function registered on a
real `flask.Flask` app, then exercised through a real
`flask.Flask.test_client()` request. Flask's test client lets
`REMOTE_ADDR` be forced via `environ_overrides` independently of the
`Host` header, which is set via the normal `headers=` argument --
letting the harness send a request that is NOT from localhost
(`REMOTE_ADDR` forced to a public IP) but DOES carry the spoofed `Host:
127.0.0.1:9666` header, exactly reproducing what a remote attacker
controls.

Every variant is the FULL real file. `local_check` decorates every route
in the blueprint by name (`@local_check`), so its name and
decorator-factory shape are kept; the renamed variant renames its own
locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0275"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


DECORATOR = '''def local_check(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        remote_addr = flask.request.environ.get("REMOTE_ADDR", "0")
        http_host = flask.request.environ.get("HTTP_HOST", "0")

        if remote_addr in ("127.0.0.1", "::ffff:127.0.0.1", "::1", "localhost") or http_host in (
            "127.0.0.1:9666",
            "[::1]:9666",
        ):
            return func(*args, **kwargs)
        else:
            return "Forbidden", 403

    return wrapper'''
assert original.count(DECORATOR) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, DECORATOR, '''def local_check(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        peer_addr = flask.request.environ.get("REMOTE_ADDR", "0")
        host_header = flask.request.environ.get("HTTP_HOST", "0")

        if peer_addr in ("127.0.0.1", "::ffff:127.0.0.1", "::1", "localhost") or host_header in (
            "127.0.0.1:9666",
            "[::1]:9666",
        ):
            return func(*args, **kwargs)
        else:
            return "Forbidden", 403

    return wrapper''')
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, DECORATOR, '''def _is_trusted_request(environ):
    remote_addr = environ.get("REMOTE_ADDR", "0")
    http_host = environ.get("HTTP_HOST", "0")
    return remote_addr in ("127.0.0.1", "::ffff:127.0.0.1", "::1", "localhost") or http_host in (
        "127.0.0.1:9666",
        "[::1]:9666",
    )


def local_check(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if _is_trusted_request(flask.request.environ):
            return func(*args, **kwargs)
        else:
            return "Forbidden", 403

    return wrapper''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same fix outcome as upstream (authorize solely on REMOTE_ADDR, the
# Host header is never consulted) but expressed as an early-return guard
# clause over a frozenset membership test, instead of upstream's single
# positive if/else condition.
v3 = swap(original, DECORATOR, '''_LOCAL_ADDRESSES = frozenset({"127.0.0.1", "::ffff:127.0.0.1", "::1", "localhost"})


def local_check(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        remote_addr = flask.request.environ.get("REMOTE_ADDR", "0")

        if remote_addr not in _LOCAL_ADDRESSES:
            return "Forbidden", 403

        return func(*args, **kwargs)

    return wrapper''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""
Standalone example of the same shape: skip a decorative "you're viewing
from home" banner unless the request looks like it came from the user's
OWN saved home-network IP range, falling back on the client-supplied
X-Client-Network header as a convenience hint when REMOTE_ADDR is a
known shared NAT gateway -- purely cosmetic personalization, not an
access-control decision, so trusting the client-supplied header here
has no security consequence.
"""


def is_probably_home_network(environ, known_home_ranges):
    remote_addr = environ.get("REMOTE_ADDR", "")
    hint = environ.get("HTTP_X_CLIENT_NETWORK", "")
    return remote_addr in known_home_ranges or hint == "home"
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
