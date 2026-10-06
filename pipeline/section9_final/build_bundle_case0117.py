"""
Section 9 ground-truth test bundle: CASE-0117
(apache/thrift, web_server.js Node.js WebSocket upgrade handler,
CVE-2026-43870, CWE-113 / CWE-22 / CWE-346 / CWE-400).

Located target: the anonymous `.on("upgrade", function (request, socket,
head) {...})` callback of createWebServer (the locator's extraction starts
with a stray `)` from the preceding chained call -- a known, reviewed,
harmless artifact for anonymous callbacks).

Core vulnerable mechanism (inside the handler): (1) NO Origin/CORS check on
WebSocket upgrades although the HTTP paths enforce options.cors (CWE-346);
(2) the client-supplied Origin, Host and request URL are echoed VERBATIM
into the "101 Switching Protocols" response (CWE-113 CRLF/header injection
if a value ever carries CR/LF); (3) `new Buffer(n)` for reassembled frames
(CWE-400/uninitialised memory on old Node). The upstream commit also fixes,
elsewhere in the same file, the static-file `filename.indexOf(baseDir) != 0`
prefix check (CWE-22) and other `new Buffer(...)` sites.

Every variant is the FULL real file with the upgrade handler replaced. The
SAFE variant additionally applies the file's OTHER fixes (path-traversal
check, Buffer.alloc everywhere) so that no tagged weakness remains anywhere
in a file labeled safe; the two vulnerable variants leave them untouched.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0117"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

HDR = '    .on("upgrade", function (request, socket, head) {\n'
s = original.index(HDR)
e = original.index("\n    });\n", s) + len("\n    });\n")
BLOCK = original[s:e]
assert original.count(HDR) == 1 and BLOCK.count("new Buffer(") == 1
LOOKUP = '''      //Lookup service
      var svc;
      try {
        svc = services[Object.keys(services)[0]];
      } catch (e) {
        socket.write("HTTP/1.1 403 No Apache Thrift Service available\\r\\n\\r\\n");
        return;
      }
'''
RESPONSE = '''      socket.write(
        "HTTP/1.1 101 Switching Protocols\\r\\n" +
          "Upgrade: websocket\\r\\n" +
          "Connection: Upgrade\\r\\n" +
          "Sec-WebSocket-Accept: " +
          hash.digest("base64") +
          "\\r\\n" +
          "Sec-WebSocket-Origin: " +
          request.headers.origin +
          "\\r\\n" +
          "Sec-WebSocket-Location: ws://" +
          request.headers.host +
          request.url +
          "\\r\\n" +
          "\\r\\n",
      );
'''
assert BLOCK.count(LOOKUP) == 1 and BLOCK.count(RESPONSE) == 1
PATH_CHECK = '''    if (filename.indexOf(baseDir) != 0) {
'''
assert original.count(PATH_CHECK) == 1 and original.count("new Buffer(") == 5


def build(new_block, full=None):
    assert new_block != BLOCK
    src = full if full is not None else original
    return src[:src.index(HDR)] + new_block + src[src.index("\n    });\n", src.index(HDR)) + len("\n    });\n"):]


def rename_outside_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                # identifier use only: not a property access (.name), not part of a longer identifier
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = rename_outside_strings(BLOCK, (("request", "req"), ("socket", "sock"), ("head", "firstChunk"), ("svc", "service"),
                                   ("hash", "acceptHash"), ("data", "pending"), ("frame", "chunk"),
                                   ("result", "decoded"), ("newData", "merged"), ("e", "err")))
assert "req.headers.origin" in b and "decoded.data" in b and 'sock.on("data"' in b and "wsFrame.decode(chunk)" in b
assert "new Buffer(pending.length + decoded.data.length)" in b and "acceptHash.digest" in b
(CASE_DIR / "variant_vulnerable_01.js").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
# The handshake response built as an array joined with CRLF: byte-identical
# output, same verbatim echo of Origin / Host / URL.
b = BLOCK.replace(RESPONSE, '''      var responseLines = [
        "HTTP/1.1 101 Switching Protocols",
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Accept: " + hash.digest("base64"),
        "Sec-WebSocket-Origin: " + request.headers.origin,
        "Sec-WebSocket-Location: ws://" + request.headers.host + request.url,
        "",
        "",
      ];
      socket.write(responseLines.join("\\r\\n"));
''')
assert b != BLOCK
(CASE_DIR / "variant_vulnerable_02.js").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# (1) origin allow-list via own-property lookup (upstream indexes options.cors
#     directly, which also treats inherited names like "constructor" as allowed);
# (2) REJECT non-printable-ASCII Origin/Host/URL instead of stripping CR/LF;
# (3) Buffer.alloc. Plus the file's other fixes below.
b = BLOCK.replace(LOOKUP, '''      //Verify the Origin of WebSocket upgrades against options.cors (own keys only)
      if (request.headers.origin && options.cors) {
        var allowedOrigins = Object.keys(options.cors);
        if (
          allowedOrigins.indexOf("*") === -1 &&
          allowedOrigins.indexOf(request.headers.origin) === -1
        ) {
          socket.write("HTTP/1.1 403 Origin not allowed\\r\\n\\r\\n");
          socket.destroy();
          return;
        }
      }
      //Values echoed into the handshake must be plain printable ASCII (no CR/LF)
      var echoed = [request.headers.origin, request.headers.host, request.url];
      for (var i = 0; i < echoed.length; i++) {
        if (echoed[i] !== undefined && !/^[\\x20-\\x7E]*$/.test(echoed[i])) {
          socket.write("HTTP/1.1 400 Bad Request\\r\\n\\r\\n");
          socket.destroy();
          return;
        }
      }
''' + LOOKUP).replace("new Buffer(", "Buffer.alloc(")
assert "Buffer.alloc(pending" not in b and "Buffer.alloc(data.length + result.data.length)" in b
safe = build(b)
# the file's other fixes (outside the located handler), same effect as upstream's hunks:
safe = safe.replace(PATH_CHECK, '''    var baseWithSep = baseDir.endsWith(path.sep) ? baseDir : baseDir + path.sep;
    if (filename !== baseDir && filename.indexOf(baseWithSep) !== 0) {
''')
safe = safe.replace("new Buffer(", "Buffer.alloc(")
assert "new Buffer(" not in safe and "filename.indexOf(baseDir) != 0" not in safe
(CASE_DIR / "variant_safe_01.js").write_text(safe)

# --- Variant 4: benign structural look-alike ---
benign_source = '''"use strict";

// The only origins that may open a WebSocket, exact keys of a plain lookup table.
var ALLOWED_ORIGINS = { "https://app.example.com": true, "https://admin.example.com": true };

/**
 * Same "echo the client's Origin into the 101 handshake response" shape as a
 * WebSocket upgrade handler, but the value written is one of the fixed,
 * developer-defined keys above (looked up by own-property test), never
 * arbitrary request text, so it cannot carry CR/LF and cannot be forged.
 */
function acceptUpgrade(request, socket) {
  var origin = request.headers.origin;
  if (!Object.prototype.hasOwnProperty.call(ALLOWED_ORIGINS, origin)) {
    socket.write("HTTP/1.1 403 Origin not allowed\\r\\n\\r\\n");
    socket.destroy();
    return false;
  }
  socket.write(
    "HTTP/1.1 101 Switching Protocols\\r\\n" +
      "Upgrade: websocket\\r\\n" +
      "Connection: Upgrade\\r\\n" +
      "Sec-WebSocket-Origin: " +
      origin +
      "\\r\\n\\r\\n",
  );
  return true;
}

module.exports = { acceptUpgrade: acceptUpgrade };
'''
assert "hasOwnProperty.call(ALLOWED_ORIGINS" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0117.")
