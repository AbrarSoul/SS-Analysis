"""
Section 9 ground-truth test bundle: CASE-0079
(TooTallNate/node-http-proxy-agent, CVE-2019-10196, CWE-665 improper
initialization).

Core vulnerable mechanism: the proxy `auth` value is passed straight to
the deprecated `new Buffer(auth)` constructor. When `auth` is not a
string (e.g. a number supplied through a parsed proxy URL/options
object), `new Buffer(<number>)` allocates a buffer of that size rather
than encoding text; on affected Node versions the memory is not
guaranteed to be initialised, so the resulting Proxy-Authorization
header can leak process memory. The upstream fix uses
`Buffer.from(proxy.auth)`, which never allocates by size and throws for
a non-string/non-buffer argument.

The target block is sliced out of the real file programmatically (from
the callback assignment to its closing `};`), and every variant is the
FULL real file with that block replaced.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0079"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.js").read_text().splitlines()) + "\n"

START = "HttpProxyAgent.prototype.callback = function connect (req, opts, fn) {"
END = "  fn(null, socket);\n};"
s = original.index(START)
e = original.index(END) + len(END)
BLOCK = original[s:e]

AUTH_ORIG = """  var auth = proxy.auth;
  if (auth) {
    req.setHeader('Proxy-Authorization', 'Basic ' + new Buffer(auth).toString('base64'));
  }
"""
assert AUTH_ORIG in BLOCK
assert original.count(START) == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
AUTH_RENAMED = """  var credentials = proxy.auth;
  if (credentials) {
    req.setHeader('Proxy-Authorization', 'Basic ' + new Buffer(credentials).toString('base64'));
  }
"""
b = BLOCK.replace(AUTH_ORIG, AUTH_RENAMED)
b = b.replace("function connect (", "function createProxiedSocket (")
for old, new in (("req", "clientRequest"), ("opts", "requestOpts"), ("fn", "done")):
    b = re.sub(r"\b%s\b" % old, new, b)
assert "new Buffer(credentials)" in b
# proxy.auth is a property name and must survive the renaming
assert "proxy.auth" in b
assert not re.search(r"\b(req|opts|fn)\b", b)
(CASE_DIR / "variant_vulnerable_01.js").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
AUTH_STRUCT = """  var rawAuth = proxy.auth;
  var encodedAuth = rawAuth ? new Buffer(rawAuth).toString('base64') : null;
  if (encodedAuth !== null) {
    req.setHeader('Proxy-Authorization', 'Basic ' + encodedAuth);
  }
"""
(CASE_DIR / "variant_vulnerable_02.js").write_text(build(BLOCK.replace(AUTH_ORIG, AUTH_STRUCT)))

# --- Variant 3: transformed safe variant ---
# Explicit type validation (reject anything that is not a string) followed
# by Buffer.from(<string>, 'utf8'). Different mechanism from the upstream
# fix, which relies on Buffer.from() throwing for a number.
AUTH_SAFE = """  var auth = proxy.auth;
  if (auth) {
    if (typeof auth !== 'string') {
      throw new TypeError('proxy `auth` must be a string of the form "user:password"');
    }
    req.setHeader('Proxy-Authorization', 'Basic ' + Buffer.from(auth, 'utf8').toString('base64'));
  }
"""
(CASE_DIR / "variant_safe_01.js").write_text(build(BLOCK.replace(AUTH_ORIG, AUTH_SAFE)))

# --- Variant 4: benign structural look-alike ---
# `new Buffer(...)` applied to a fixed string literal: same construct, but
# no externally influenced argument, so no size-allocation/uninitialised
# memory exposure is possible.
BENIGN = """var debug = require('debug')('http-proxy-agent');

function describeAgent () {
  // fixed, developer-supplied banner text: the Buffer argument is a
  // constant string literal, never caller- or network-controlled
  var banner = new Buffer('http-proxy-agent').toString('base64');
  debug('agent banner: %s', banner);
  return banner;
}

module.exports = describeAgent;
"""
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)

print("Wrote 4 new samples for CASE-0079.")
