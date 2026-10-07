"""
Section 9 ground-truth test bundle: CASE-0123
(avwo/whistle, biz/webui/lib/index.js checkAllowOrigin, CVE-2024-55500,
CWE-352 cross-site request forgery / cross-origin trust).

Core vulnerable mechanism: `checkAllowOrigin()` returns true immediately
for any request whose path is in ALLOW_CROSS_URLS (and for allowAllOrigin /
same-origin), regardless of the request's Origin. `cgiHandler()` then does
`if (!req._isWebUIHost && req.headers.origin)` and REFLECTS that Origin as
`access-control-allow-origin` together with
`access-control-allow-credentials: true`. A page on any origin can therefore
make a credentialed cross-origin read of those endpoints (e.g.
/cgi-bin/status, /cgi-bin/server-info). The upstream fix splits the logic
(checkInternalPath for the 403 gate, a stricter checkAllowOrigin only for
deciding whether to send CORS headers).

Every variant is the FULL real file with checkAllowOrigin replaced (the
locator's confidence was auto_low_confidence; the located function is the
right one). checkAllowOrigin is a top-level function with one in-file call
site (cgiHandler), which the renamed variant also renames.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0123"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

HDR = "function checkAllowOrigin(req) {\n"
s = original.index(HDR)
e = original.index("\n}\n", s) + len("\n}\n")
BLOCK = original[s:e]
CALL = "!checkAllowOrigin(req)"
FIRST = '''  if (config.allowAllOrigin ||
    req.headers['sec-fetch-site'] === 'same-origin' ||
    ALLOW_CROSS_URLS.indexOf(req.path) !== -1) {
    return true;
  }
'''
LOOP = '''  if (list) {
    for (var i = 0, len = list.length; i < len; i++) {
      var h = list[i];
      if (typeof h === 'string' ? host === h : h.test(host)) {
        return true;
      }
    }
  }
'''
assert original.count(HDR) == 1 and original.count(CALL) == 1 and original.count("checkAllowOrigin(") == 2
assert BLOCK.count(FIRST) == 1 and BLOCK.count(LOOP) == 1


def build(new_block, new_call=None):
    assert new_block != BLOCK
    out = original[:s] + new_block + original[e:]
    if new_call:
        assert out.count(CALL) == 1
        out = out.replace(CALL, new_call)
    return out


def rename_outside_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r"""('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")""", line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("function checkAllowOrigin(", "function isOriginPermitted(")
b = rename_outside_strings(b, (("req", "request"), ("host", "originHost"), ("list", "allowedList"), ("index", "sepPos"),
                               ("i", "idx"), ("len", "count"), ("h", "entry")))
assert "request.headers.origin" in b and "request._isWebUIHost = true;" in b and "typeof entry === 'string'" in b
assert "ALLOW_CROSS_URLS.indexOf(request.path)" in b and "config.isWebUIHost(originHost)" in b
(CASE_DIR / "variant_vulnerable_01.js").write_text(build(b, "!isOriginPermitted(req)"))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(LOOP, '''  if (list && list.some(function(h) {
    return typeof h === 'string' ? host === h : h.test(host);
  })) {
    return true;
  }
''')
assert b != BLOCK and "list.some(" in b
(CASE_DIR / "variant_vulnerable_02.js").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# The cross-origin-readable paths are allowed only for requests that carry NO
# Origin (non-browser / navigation); a request WITH an Origin must pass the
# normal allow-list checks, so cgiHandler can never reflect an arbitrary
# Origin with credentials for them (upstream instead separates the 403 gate
# from the CORS-header decision).
b = BLOCK.replace(FIRST, '''  if (config.allowAllOrigin ||
    req.headers['sec-fetch-site'] === 'same-origin') {
    return true;
  }
  if (ALLOW_CROSS_URLS.indexOf(req.path) !== -1 && !req.headers.origin) {
    return true;
  }
''')
safe_source = build(b)
assert "ALLOW_CROSS_URLS.indexOf(req.path) !== -1 && !req.headers.origin" in b
(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''"use strict";

/**
 * Same "reflect the request's Origin with credentials" shape as a CORS
 * handler, but only for origins that are OWN keys of an explicit allow-list
 * object (exact string match), never for arbitrary or inherited names, so a
 * foreign page never receives a credentialed cross-origin grant.
 */
function applyCors(req, res, allowedOrigins) {
  var origin = req.headers.origin;
  if (typeof origin === "string" && Object.prototype.hasOwnProperty.call(allowedOrigins, origin)) {
    res.setHeader("access-control-allow-origin", origin);
    res.setHeader("access-control-allow-credentials", true);
    return true;
  }
  return false;
}

module.exports = { applyCors: applyCors };
'''
assert "hasOwnProperty.call(allowedOrigins" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0123.")
