"""
Section 9 ground-truth test bundle: CASE-0263
(polonel/trudesk, src/middleware/index.js allowCrossDomain, CVE-2022-1803,
CWE-1021 improper restriction of rendered UI layers / clickjacking).

Core vulnerable mechanism: `allowCrossDomain` is registered as global Express
middleware and runs on every response, setting the app's permissive CORS
headers -- but it never sets any header that restricts framing. With no
`X-Frame-Options` or `Content-Security-Policy: frame-ancestors` header, a
browser will happily render the app inside an `<iframe>` on an attacker's
page; combined with the wide-open `Access-Control-Allow-Origin: *` set two
lines above (data can also be read cross-origin) the app is directly
clickjackable -- an attacker overlays invisible/transparent UI (e.g. the
trudesk agent's "delete ticket" or "change password" controls) on top of
bait content and tricks a logged-in agent into clicking it, executing the
action inside their own authenticated session. The upstream fix adds
`res.setHeader('Content-Security-Policy', "frame-ancestors 'none';")` to the
same function, telling the browser to refuse to render the page in any
frame regardless of origin.

Sibling sites: `allowCrossDomain` is the only place in the file (and, being
global middleware registered once, the only place in the app) that sets
response headers on every request; there is one call site to fix.

Verification: each full file's `allowCrossDomain` is extracted (via
`Function.prototype` reconstruction from its exact text, since the whole
file also requires unrelated app-bootstrap dependencies like `async`) and
invoked as real JS against a minimal fake `res` that records
`setHeader(name, value)` calls in a Map, exactly mirroring
`http.ServerResponse.setHeader`'s call contract; the recorded headers are
checked for `content-security-policy` containing `frame-ancestors` (or
`x-frame-options`, treated as an equally-valid framing restriction) being
present and restrictive.

Every variant is the FULL real file. `allowCrossDomain` is wired into the
Express app as `app.use(allowCrossDomain)` elsewhere, so its name and
`(req, res, next)` signature are kept where the variant still needs Express
to call it directly; the renamed variant renames its parameters.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0263"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


FUNC = """function allowCrossDomain (req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS')
  res.setHeader(
    'Access-Control-Allow-Headers',
    'DNT,X-Mx-ReqToken,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,accesstoken,X-RToken,X-Token'
  )

  if (req.method === 'OPTIONS') {
    res.sendStatus(200)
  } else {
    next()
  }
}"""
assert original.count(FUNC) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, FUNC, """function allowCrossDomain (request, response, cb) {
  response.setHeader('Access-Control-Allow-Origin', '*')
  response.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS')
  response.setHeader(
    'Access-Control-Allow-Headers',
    'DNT,X-Mx-ReqToken,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,accesstoken,X-RToken,X-Token'
  )

  if (request.method === 'OPTIONS') {
    response.sendStatus(200)
  } else {
    cb()
  }
}""")
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, FUNC, """function setCorsHeaders (res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS')
  res.setHeader(
    'Access-Control-Allow-Headers',
    'DNT,X-Mx-ReqToken,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,accesstoken,X-RToken,X-Token'
  )
}

function allowCrossDomain (req, res, next) {
  setCorsHeaders(res)

  if (req.method === 'OPTIONS') {
    res.sendStatus(200)
  } else {
    next()
  }
}""")
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Same fix outcome as upstream (a frame-restricting header on every
# response) but built from a headers map and applied in a loop, instead of
# upstream's single extra literal setHeader call.
v3 = swap(original, FUNC, """const RESPONSE_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
  'Access-Control-Allow-Headers':
    'DNT,X-Mx-ReqToken,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,accesstoken,X-RToken,X-Token',
  // Refuse to be rendered inside a frame on any origin, so a malicious page
  // cannot overlay bait content on top of the authenticated UI (clickjacking).
  'Content-Security-Policy': "frame-ancestors 'none';",
}

function allowCrossDomain (req, res, next) {
  for (const [name, value] of Object.entries(RESPONSE_HEADERS)) {
    res.setHeader(name, value)
  }

  if (req.method === 'OPTIONS') {
    res.sendStatus(200)
  } else {
    next()
  }
}""")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = """// Standalone example of the same shape: set a batch of response headers,
// but the "missing" one here is a caching hint (ETag support), a
// performance nicety with no security consequence either way.
function applyCacheableHeaders (req, res, next) {
  res.setHeader('Cache-Control', 'public, max-age=3600')
  res.setHeader('Vary', 'Accept-Encoding')
  next()
}

module.exports = { applyCacheableHeaders }
"""
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
