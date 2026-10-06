"""
Section 9 ground-truth test bundle: CASE-0289
(socketio/engine.io-client, lib/socket.js Socket constructor,
CVE-2016-10536, CWE-295/CWE-300 improper certificate validation).

Core vulnerable mechanism: the `Socket` constructor copies TLS options
from the caller, defaulting an unspecified `rejectUnauthorized` to `null`:
`this.rejectUnauthorized = opts.rejectUnauthorized === undefined ? null :
opts.rejectUnauthorized`. `null` is falsy and is passed down to the Node.js
transports (`ws`, `https.request`), where a falsy `rejectUnauthorized`
disables certificate verification. A client that just writes
`io('https://api.example.com')` -- never touching the option -- therefore
connects over TLS without validating the server certificate, so anyone able
to intercept the connection (rogue Wi-Fi, DNS/ARP spoofing, hostile proxy)
can present any certificate and read/modify the session (man-in-the-middle).
The upstream fix changes the default from `null` to `true`.

Sibling sites: the option is defined once in this constructor and forwarded
to transports from `this.rejectUnauthorized`; one site to fix.

Verification: the vulnerable file is byte-identical to the real
`engine.io-client@1.7.0` npm release's `lib/socket.js`. Each full file is
copied over that file inside a REAL npm install of `engine.io-client@1.7.0`
(with its real `ws`/`xmlhttprequest` dependencies), a real `Socket` is
constructed for a secure `wss` endpoint on a closed local port with
`transports: ['websocket']` and no `rejectUnauthorized` option, and both
`socket.rejectUnauthorized` and the value the real WebSocket transport
received (`socket.transport.rejectUnauthorized`) are read (the socket is
closed immediately; no network exchange is needed). A control with an
explicit `rejectUnauthorized: false` must stay `false` in every variant
(the caller's explicit choice is preserved).

Every variant is the FULL real file. The constructor is the library's
exported API, so its name/signature are kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0289"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


LINE = "  this.rejectUnauthorized = opts.rejectUnauthorized === undefined ? null : opts.rejectUnauthorized;\n"
assert original.count(LINE) == 1

# --- Variant 1: renamed vulnerable variant (constructor's `opts`) ---
s = original.index("function Socket (uri, opts) {")
e = original.index("\n}\n", s) + 3
ctor = original[s:e]
c1 = re.sub(r"\bopts\b", "options", ctor)
assert c1 != ctor
(CASE_DIR / "variant_vulnerable_01.js").write_text(original.replace(ctor, c1))

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, LINE, "  this.rejectUnauthorized = resolveRejectUnauthorized(opts);\n")
v2 = swap(v2, "function Socket (uri, opts) {", '''function resolveRejectUnauthorized (opts) {
  return opts.rejectUnauthorized === undefined ? null : opts.rejectUnauthorized;
}

function Socket (uri, opts) {''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, LINE, "  this.rejectUnauthorized = typeof opts.rejectUnauthorized === 'boolean' ? opts.rejectUnauthorized : true;\n")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

(CASE_DIR / "benign_lookalike.js").write_text('''// Standalone example of the same shape: default an unspecified reconnection
// delay option to null (meaning "use the library default"), a tuning knob
// with no security consequence.
function readOptions(opts) {
  opts = opts || {};
  return {
    reconnectionDelay: opts.reconnectionDelay === undefined ? null : opts.reconnectionDelay
  };
}

module.exports = readOptions;
''')
