"""
Section 9 ground-truth test bundle: CASE-0213
(mafintosh/dns-packet, index.js name.encodingLength, CVE-2021-23386,
CWE-476 as labelled upstream; the measured effect is an over-sized packet
buffer that carries uninitialised memory).

Core vulnerable mechanism: `name.encode` strips a leading and a trailing `.`
from the name (`str.replace(/^\\.|\\.$/gm, '')`) before writing the labels, but
`name.encodingLength` counts the name UNSTRIPPED (`Buffer.byteLength(n) + 2`).
Every caller sizes its buffer with encodingLength, and `name.encode` /
`exports.encode` allocate with `Buffer.allocUnsafe`, so a name such as
`example.com.` or `.` gets a buffer 1-2 bytes larger than what is written and
those trailing bytes are uninitialised process memory that goes out in the
DNS packet. The upstream fix makes encodingLength apply the same strip and
special-cases `'.'`.

Measured caveat, kept in the manifest notes: the upstream-patched
encodingLength still over-counts `''` and `'..'` (strip yields the empty
string, so it returns 2 while encode writes only the 1-byte terminator); the
safe variant treats "empty after stripping" as length 1.

Sibling sites: `name.encodingLength` is called by every record type's
encodingLength (SOA, SRV, NS, questions, answers, ...), so fixing the one
function fixes them all; there are no separate copies of the strip logic.

Verification: dns-packet 1.3.4's real types.js/rcodes.js/opcodes.js and the
real `ip` and `safe-buffer` packages sit next to each full variant file; a
Node script compares name.encodingLength(n) with name.encode(n).length /
name.encode.bytes and with the length of a full exports.encode() packet.

Every variant is the FULL real file. name.encodingLength is a property of the
exported `name` object used by other modules, so it keeps its name; the
renamed variant renames parameters and locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0213"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


ENC = '''name.encodingLength = function (n) {
  return Buffer.byteLength(n) + 2
}
'''

# --- Variant 1: renamed vulnerable variant ---
s = original.index("name.encode = function (str, buf, offset) {")
e = original.index("name.encode.bytes = 0")
enc = original[s:e]
enc = enc.replace("var n = str.replace", "var stripped = str.replace").replace("if (n.length) {", "if (stripped.length) {").replace("var list = n.split('.')", "var labels = stripped.split('.')").replace("list.length", "labels.length").replace("list[i]", "labels[i]")
assert "list" not in enc and "var n " not in enc
v1 = original[:s] + enc + original[e:]
v1 = swap(v1, ENC, '''name.encodingLength = function (hostname) {
  return Buffer.byteLength(hostname) + 2
}
''')
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, ENC, '''var labelBytes = function (n) {
  return Buffer.byteLength(n)
}

var TERMINATOR_AND_LENGTH_BYTES = 2

name.encodingLength = function (n) {
  return labelBytes(n) + TERMINATOR_AND_LENGTH_BYTES
}
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, ENC, '''name.encodingLength = function (n) {
  // same normalisation name.encode applies
  var trimmed = n.replace(/^\\.|\\.$/gm, '')
  if (!trimmed.length) return 1
  return Buffer.byteLength(trimmed) + 2
}
''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = '''// Standalone example of the same shape: a length calculation that mirrors an
// encoder's normalisation (here for a CSV row) and is used to size a buffer
// that is fully zero-filled before writing.
function encodedLength (fields) {
  return fields.map(function (f) { return Buffer.byteLength(String(f).trim()) }).reduce(function (a, b) { return a + b + 1 }, 0)
}

function encodeRow (fields) {
  var buf = Buffer.alloc(encodedLength(fields))
  var off = 0
  fields.forEach(function (f) {
    off += buf.write(String(f).trim() + ',', off)
  })
  return buf
}

module.exports = { encodedLength: encodedLength, encodeRow: encodeRow }
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
