"""
Section 9 ground-truth test bundle: CASE-0176
(indutny/elliptic, lib/elliptic/ec/signature.js Signature.prototype._importDER,
CVE-2020-13822, CWE-190 integer overflow; in effect DER signature malleability).

Core vulnerable mechanism: `_importDER` accepts ANY BER-style encoding of an
ECDSA signature: long-form lengths for values that fit in short form
(`0x81 0x45`), lengths of up to 15 octets (the `<<= 8` accumulation overflows
32-bit ints), and integers with redundant leading zero bytes. The same (r, s)
therefore has many byte encodings that all verify, so a third party can
re-encode a valid signature into a different valid one (signature
malleability, dangerous for anything that identifies data by signature bytes,
e.g. transactions). The upstream fix rejects indefinite/over-long lengths,
unsigned-overflow (`>>> 0`), non-minimal lengths (`val <= 0x7f`) and leading
zeros, checking `false` after every getLength.

Sibling sites: `getLength` is the shared length reader used for the outer
sequence and both integers, so it is fixed once (upstream) or the whole parse is
validated once (the safe variant); `toDER` is the canonical encoder and is
unchanged.

Every variant is the FULL real file (identical to elliptic 6.5.2's file, which
is what the tests run). `Signature.prototype._importDER` is called by the
constructor by name, so the renamed variant renames the module-private
getLength helper, its locals and its three call sites.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0176"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

GL = original[original.index("function getLength(buf, p) {"):original.index("function rmPadding")]
TAIL = '''  this.r = new BN(r);
  this.s = new BN(s);
  this.recoveryParam = null;

  return true;
};
'''
assert original.count(TAIL) == 1 and original.count("getLength(") == 4


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
g = GL
for old, new in (("getLength", "readDerLength"), ("buf", "bytes"), ("p", "cursor"), ("initial", "first"),
                 ("octetLen", "octets"), ("val", "value"), ("i", "k"), ("off", "at")):
    g = re.sub(r"(?<![.\w$'])%s(?![\w$'])" % old, new, g)
assert "function readDerLength(bytes, cursor) {" in g and "cursor.place = at;" in g and "var first = bytes[cursor.place++];" in g
v1 = swap(original, GL, g)
v1 = v1.replace("getLength(data, p)", "readDerLength(data, p)")
assert "getLength" not in v1 and v1.count("readDerLength(") == 4
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
g2 = GL.replace('''  var val = 0;
  for (var i = 0, off = p.place; i < octetLen; i++, off++) {
    val <<= 8;
    val |= buf[off];
  }
  p.place = off;
  return val;
''', '''  var val = 0;
  var i = 0;
  var off = p.place;
  while (i < octetLen) {
    val = (val << 8) | buf[off];
    i++;
    off++;
  }
  p.place = off;
  return val;
''')
assert g2 != GL
(CASE_DIR / "variant_vulnerable_02.js").write_text(swap(original, GL, g2))

# --- Variant 3: transformed safe variant ---
# Parse leniently as before, then require the parsed (r, s) to re-encode with
# the canonical toDER to EXACTLY the input bytes; any non-canonical encoding
# (long-form length, leading zero, overflowing length) fails that comparison.
# Upstream instead adds many individual checks inside getLength/_importDER.
v3 = swap(original, TAIL, '''  this.r = new BN(r);
  this.s = new BN(s);
  this.recoveryParam = null;

  var canonical = this.toDER();
  if (canonical.length !== data.length) {
    return false;
  }
  for (var k = 0; k < canonical.length; k++) {
    if (canonical[k] !== data[k]) {
      return false;
    }
  }

  return true;
};
''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''"use strict";

/**
 * Same "read a length prefix" shape as getLength, but it accepts only the
 * MINIMAL encoding: a long-form length must use the fewest octets and must be
 * larger than the short form can express, and at most 4 octets are read with
 * unsigned arithmetic, so one value has exactly one valid encoding.
 */
function readMinimalLength(bytes, pos) {
  var first = bytes[pos.place++];
  if (!(first & 0x80)) {
    return first;
  }
  var octets = first & 0x7f;
  if (octets === 0 || octets > 4) {
    return -1;
  }
  var value = 0;
  for (var i = 0; i < octets; i++) {
    value = ((value << 8) | bytes[pos.place++]) >>> 0;
  }
  if (value <= 0x7f || (octets > 1 && bytes[pos.place - octets] === 0)) {
    return -1;
  }
  return value;
}

module.exports = readMinimalLength;
'''
assert "MINIMAL encoding" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0176.")
