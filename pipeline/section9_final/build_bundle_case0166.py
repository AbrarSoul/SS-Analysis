"""
Section 9 ground-truth test bundle: CASE-0166
(foxinmy/weixin4j, weixin4j-base/.../util/CharArrayBuffer.java
ensureCapacity, CVE-2026-24819, CWE-1325 improperly controlled sequential
memory allocation / integer overflow in a size computation).

Core vulnerable mechanism: `ensureCapacity(required)` computes the new size as
`expand(this.len + required)` in int arithmetic. When `len + required`
overflows past Integer.MAX_VALUE the sum turns negative, `expand` then takes
`Math.max(buffer.length << 1, newlen)` = just the doubled current length, and
the method returns as if the requested capacity had been provided: measured,
with 50 chars in a 100-char buffer `ensureCapacity(Integer.MAX_VALUE - 10)`
leaves the capacity at 200 instead of throwing or providing the space. The
upstream patch computes the sum as a long and throws when it exceeds
MAXIMUM_CAPACITY.

Measured caveat, kept in the manifest notes: the upstream-patched file
references `MAXIMUM_CAPACITY`, a constant that no file in this case defines,
so `patched_source.java` does not compile (javac: cannot find symbol).

Sibling sites: the append(...) overloads use `newlen = len + n` and skip
`expand` when it overflows, which fails safely in System.arraycopy with an
exception rather than silently under-allocating, so they are left unchanged in
every variant.

Every variant is the FULL real file. ensureCapacity is the class's public
API, so the renamed variant keeps the name and renames the parameter and local.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0166"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

s = original.index("    public void ensureCapacity(final int required) {\n")
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
assert original.count("public void ensureCapacity(") == 1 and "MAXIMUM_CAPACITY" not in original


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = '''    public void ensureCapacity(final int minimum) {
        if (minimum <= 0) {
            return;
        }
        final int free = this.buffer.length - this.len;
        if (minimum > free) {
            expand(this.len + minimum);
        }
    }
'''
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = '''    public void ensureCapacity(final int required) {
        if (required > 0 && required > this.buffer.length - this.len) {
            expand(this.len + required);
        }
    }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Math.addExact detects the int overflow and the method refuses with an
# IllegalStateException; upstream computes a long and compares it with an
# undefined MAXIMUM_CAPACITY.
b = '''    public void ensureCapacity(final int required) {
        if (required <= 0) {
            return;
        }
        final int available = this.buffer.length - this.len;
        if (required > available) {
            final int needed;
            try {
                needed = Math.addExact(this.len, required);
            } catch (final ArithmeticException ex) {
                throw new IllegalStateException("Required capacity exceeds the maximum: " + this.len + " + " + required, ex);
            }
            expand(needed);
        }
    }
'''
(CASE_DIR / "variant_safe_01.java").write_text(build(b))

# --- Variant 4: benign structural look-alike ---
benign_source = '''public final class GrowthPlanner {

    private static final int MAX_ARRAY_SIZE = Integer.MAX_VALUE - 8;

    /**
     * Same "current length + requested amount" computation as ensureCapacity,
     * but done in long arithmetic and checked against the maximum array size
     * before narrowing back to int, so it can never overflow.
     */
    public static int newCapacity(final int currentLength, final int requested) {
        final long wanted = (long) currentLength + requested;
        if (wanted < 0 || wanted > MAX_ARRAY_SIZE) {
            throw new IllegalArgumentException("capacity out of range: " + wanted);
        }
        return (int) wanted;
    }
}
'''
assert "MAX_ARRAY_SIZE" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0166.")
