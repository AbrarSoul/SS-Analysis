"""
Section 9 ground-truth test bundle: CASE-0205
(juliangruber/keypair, index.js (bundled node-forge) the PRNG seed source
`defaultSeedFile` and the `var crypto = null;` declaration, CVE-2021-41117,
CWE-335 use of a weak PRNG seed).

Located target: `function defaultSeedFile(needed) {`.

Core vulnerable mechanism: the bundled forge PRNG picks its seed source with
`if (crypto) { ...crypto.randomBytes... } else { ...defaultSeedFile... }`,
but the module declares `var crypto = null;` and never assigns it, so the
Node.js strong source is NEVER used. In Node the seed therefore comes from
`defaultSeedFile`, whose non-browser fallback is a Park-Miller generator
seeded by `Math.floor(Math.random() * 0xFFFF)` (a 16-bit seed) and mixed with more
Math.random, i.e. a predictable RSA key. Measured by running the file with a
seeded Math.random and a frozen clock: two `keypair({bits: 512})` runs return the
IDENTICAL private key. The upstream fix assigns
`crypto = require('crypto')` (in try/catch) and fixes a `putByte` type bug.

Sibling sites: the seed-file selection (`if(crypto)` block) and the
`ctx.seedFile*` wiring depend on the same variable; the safe variant fixes the
variable and also removes the weak fallback (fail closed).

Every variant is the FULL real file (a 4,400-line bundled library).
`defaultSeedFile` is referenced twice in the same function (`seedFile` and
`seedFileSync` wiring), so the renamed variant renames it and both uses.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0205"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

CRYPTO = "var crypto = null;\n"
WEAK = '''    // be sad and add some weak random data
    if(b.length() < needed) {
      /* Draws from Park-Miller "minimal standard" 31 bit PRNG,
      implemented with David G. Carta's optimization: with 32 bit math
      and without division (Public Domain). */
      var hi, lo, next;
      var seed = Math.floor(Math.random() * 0xFFFF);
      while(b.length() < needed) {
        lo = 16807 * (seed & 0xFFFF);
        hi = 16807 * (seed >> 16);
        lo += (hi & 0x7FFF) << 16;
        lo += hi >> 15;
        lo = (lo & 0x7FFFFFFF) + (lo >> 31);
        seed = lo & 0xFFFFFFFF;

        // consume lower 3 bytes of seed
        for(var i = 0; i < 3; ++i) {
          // throw in more pseudo random
          next = seed >>> (i << 3);
          next ^= Math.floor(Math.random() * 0xFF);
          b.putByte(String.fromCharCode(next & 0xFF));
        }
      }
    }
'''
assert original.count(CRYPTO) == 1 and original.count(WEAK) == 1 and original.count("defaultSeedFile") == 3


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = original.replace("defaultSeedFile", "immediateSeedFile")
v1 = swap(v1, "      var hi, lo, next;\n      var seed = Math.floor(Math.random() * 0xFFFF);\n", "      var hi, lo, next;\n      var state = Math.floor(Math.random() * 0xFFFF);\n")
w = v1[v1.index("      while(b.length() < needed) {\n        lo = 16807"):v1.index("    return b.getBytes();\n  }\n  // initialize seed file APIs")]
w2 = w.replace("seed & 0xFFFF", "state & 0xFFFF").replace("seed >> 16", "state >> 16").replace("seed = lo & 0xFFFFFFFF;", "state = lo & 0xFFFFFFFF;").replace("seed >>> (i << 3)", "state >>> (i << 3)")
v1 = v1.replace(w, w2)
assert "immediateSeedFile" in v1 and "defaultSeedFile" not in v1 and "seed >>>" not in v1.split("immediateSeedFile")[1][:2600]
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, WEAK, '''    // be sad and add some weak random data
    if(b.length() < needed) {
      addWeakBytes(b, needed);
    }
''')
v2 = swap(v2, "  function defaultSeedFile(needed) {\n", '''  function addWeakBytes(b, needed) {
    var hi, lo, next;
    var seed = Math.floor(Math.random() * 0xFFFF);
    while(b.length() < needed) {
      lo = 16807 * (seed & 0xFFFF);
      hi = 16807 * (seed >> 16);
      lo += (hi & 0x7FFF) << 16;
      lo += hi >> 15;
      lo = (lo & 0x7FFFFFFF) + (lo >> 31);
      seed = lo & 0xFFFFFFFF;
      for(var i = 0; i < 3; ++i) {
        next = seed >>> (i << 3);
        next ^= Math.floor(Math.random() * 0xFF);
        b.putByte(String.fromCharCode(next & 0xFF));
      }
    }
  }

  function defaultSeedFile(needed) {
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Node's crypto module is loaded (so the strong seed source is selected) AND
# the weak Math.random fallback is removed: with no strong source the seed
# function throws; upstream keeps the weak fallback for environments without crypto.
v3 = swap(original, CRYPTO, "var crypto;\ntry {\n  crypto = require('crypto');\n} catch (_) {}\n")
v3 = swap(v3, WEAK, '''    // no secure source of randomness is available: refuse instead of using Math.random
    if(b.length() < needed) {
      throw new Error('No secure source of randomness available');
    }
''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign = '''"use strict";

/**
 * Same Math.random() based byte generator shape as the weak seed fallback,
 * but it is used only for retry JITTER (a delay in milliseconds), a value with
 * no security meaning, so predictability costs nothing.
 */
function jitterMs(baseMs) {
  return baseMs + Math.floor(Math.random() * baseMs);
}

module.exports = jitterMs;
'''
assert "retry JITTER" in benign
(CASE_DIR / "benign_lookalike.js").write_text(benign)
print("Wrote 4 new samples for CASE-0205.")
