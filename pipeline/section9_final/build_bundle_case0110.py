"""
Section 9 ground-truth test bundle: CASE-0110
(apache/poi, UnhandledDataStructure, CVE-2012-0213, CWE-399 resource
management error -- allocation before validation).

Core vulnerable mechanism: the constructor does `_buf = new byte[length]`
BEFORE checking that `offset`/`length` are sane. `length` comes from
attacker-controlled structure fields in a crafted Word document, so a huge
value (e.g. 0x7FFFFFF0) forces a giant allocation (OutOfMemoryError /
memory exhaustion) and a negative value throws NegativeArraySizeException,
both before the bounds check that would have rejected the request. The
upstream fix moves the checks first (adds the negative check) and copies
with Arrays.copyOfRange.

Every variant is the FULL real file with the constructor replaced. The
constructor's name is the class name, so the renamed variant renames its
parameters and the private-by-convention field _buf (and its accessor's
use of it) instead.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0110"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "  public UnhandledDataStructure(byte[] buf, int offset, int length)\n"
s = original.index(HDR)
e = original.index("\n  }\n", s) + len("\n  }\n")
BLOCK = original[s:e]
assert original.count(HDR) == 1 and BLOCK.count("_buf = new byte[length];") == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
def rename_outside_comments_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for pat, new in pairs:
                parts[i] = re.sub(pat, new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


PAIRS = ((r"\b_buf\b", "_data"), (r"\bbuf\b", "source"), (r"\boffset\b", "from"), (r"(?<!\.)\blength\b", "count"))
v1 = rename_outside_comments_strings(original, PAIRS)
assert "_data = new byte[count];" in v1 and "if (from + count > source.length)" in v1
assert "System.arraycopy(source, from, _data, 0, count);" in v1 and "return _data;" in v1
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
b = '''  public UnhandledDataStructure(byte[] buf, int offset, int length)
  {
    byte[] copy = new byte[length];
    if (offset + length > buf.length)
    {
      throw new IndexOutOfBoundsException("buffer length is " + buf.length +
                                          "but code is trying to read " + length + " from offset " + offset);
    }
    System.arraycopy(buf, offset, copy, 0, length);
    _buf = copy;
  }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# All validation (including negatives, overflow-safe subtraction) happens
# BEFORE any allocation; upstream instead checks with `offset + length` and
# switches to Arrays.copyOfRange.
b = '''  public UnhandledDataStructure(byte[] buf, int offset, int length)
  {
    if (offset < 0 || length < 0 || length > buf.length - offset)
    {
      throw new IndexOutOfBoundsException("buffer length is " + buf.length +
                                          " but code is trying to read " + length + " from offset " + offset);
    }
    _buf = new byte[length];
    System.arraycopy(buf, offset, _buf, 0, length);
  }
'''
safe_source = build(b)
assert safe_source.index("throw new IndexOutOfBounds") < safe_source.index("new byte[length]")
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''public final class FixedChunk
{
  private static final int CHUNK_SIZE = 4096;

  byte[] _buf;

  /**
   * Same `new byte[length]` allocation followed by System.arraycopy, but the
   * length is NOT taken from the caller: it is derived from the real source
   * array and capped at CHUNK_SIZE, so the allocation is bounded no matter
   * what offset is passed.
   */
  public FixedChunk(byte[] source, int offset)
  {
    if (offset < 0 || offset > source.length)
    {
      throw new IndexOutOfBoundsException("offset " + offset + " outside 0.." + source.length);
    }
    int length = Math.min(CHUNK_SIZE, source.length - offset);
    _buf = new byte[length];
    System.arraycopy(source, offset, _buf, 0, length);
  }
}
'''
assert "Math.min(CHUNK_SIZE" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0110.")
