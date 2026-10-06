"""
Section 9 ground-truth test bundle: CASE-0095
(alexta69/metube, CVE-2026-7581, CWE-346/CWE-942 permissive CORS).

Core vulnerable mechanism: the response hook `on_prepare()` reflects
whatever `Origin` request header the client sent into
`Access-Control-Allow-Origin` (and the Socket.IO server is created with
`cors_allowed_origins='*'`). Any website can therefore make credentialed
cross-origin requests to the local service and read the responses. The
upstream fix introduces a CORS_ALLOWED_ORIGINS allow-list (empty by
default) and only echoes an origin that is in it.

Every variant is the FULL real file with on_prepare replaced (the renamed
variant also renames its registration line). The SAFE variant also fixes
the Socket.IO wildcard, since leaving it would keep the file vulnerable.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0095"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.py").read_text().splitlines()) + "\n"

BLOCK = '''async def on_prepare(request, response):
    if 'Origin' in request.headers:
        response.headers['Access-Control-Allow-Origin'] = request.headers['Origin']
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'

app.on_response_prepare.append(on_prepare)
'''
SIO = "sio = socketio.AsyncServer(cors_allowed_origins='*')\n"
assert original.count(BLOCK) == 1 and original.count(SIO) == 1


def build(new_block, text=None):
    assert new_block != BLOCK
    return (text or original).replace(BLOCK, new_block)


# --- Variant 1: renamed vulnerable variant ---
(CASE_DIR / "variant_vulnerable_01.py").write_text(build('''async def apply_cors_headers(req, resp):
    if 'Origin' in req.headers:
        resp.headers['Access-Control-Allow-Origin'] = req.headers['Origin']
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'

app.on_response_prepare.append(apply_cors_headers)
'''))

# --- Variant 2: structurally changed vulnerable variant ---
(CASE_DIR / "variant_vulnerable_02.py").write_text(build('''async def on_prepare(request, response):
    origin = request.headers.get('Origin')
    if origin is not None:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'

app.on_response_prepare.append(on_prepare)
'''))

# --- Variant 3: transformed safe variant ---
# A frozenset allow-list read straight from the environment (no new Config
# key), used for BOTH the Socket.IO server and the response hook, plus a
# `Vary: Origin` header; differs from upstream's list derived from
# config.CORS_ALLOWED_ORIGINS.
SAFE_HOOK = '''async def on_prepare(request, response):
    origin = request.headers.get('Origin')
    if origin and origin in ALLOWED_CORS_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        response.headers['Vary'] = 'Origin'

app.on_response_prepare.append(on_prepare)
'''
safe = build(SAFE_HOOK).replace(
    SIO,
    "ALLOWED_CORS_ORIGINS = frozenset(o.strip() for o in os.environ.get('CORS_ALLOWED_ORIGINS', '').split(',') if o.strip())\n"
    "sio = socketio.AsyncServer(cors_allowed_origins=list(ALLOWED_CORS_ORIGINS))\n")
assert "cors_allowed_origins='*'" not in safe and "ALLOWED_CORS_ORIGINS" in safe
(CASE_DIR / "variant_safe_01.py").write_text(safe)

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.py").write_text('''import logging

logger = logging.getLogger(__name__)


async def log_request_origin(request, response):
    """Same 'Origin' in request.headers shape, but the value is only written
    to a log line. No Access-Control-* response header is ever set from it,
    so it grants no cross-origin access."""
    if 'Origin' in request.headers:
        logger.info('request origin: %s', request.headers['Origin'])
''')
print("Wrote 4 new samples for CASE-0095.")
