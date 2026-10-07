"""
Section 9 ground-truth test bundle: CASE-0109
(apache/pdfbox, PDFXrefStreamParser.ObjectNumbers, CVE-2021-27906,
CWE-789 uncontrolled memory allocation / resource exhaustion from a
crafted xref-stream /Index array).

Core vulnerable mechanism: the nested `ObjectNumbers` iterator's `next()`
has NO exhaustion guard. Once the last range is consumed it does
`currentNumber = start[++currentRange]` past the end of the arrays (an
unchecked ArrayIndexOutOfBoundsException instead of the
NoSuchElementException the Iterator contract requires), and for crafted
/Index arrays it can hand out object numbers outside every declared range.
The upstream fix adds
`if (currentNumber >= maxValue) throw new NoSuchElementException();`.

Every variant is the FULL real file. `next()` is the Iterator<Long>
implementation of the nested class (its caller uses the interface), so it
is NOT renamed; the renamed variant renames the iterator's fields instead.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0109"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "        public Long next()\n        {\n"
s = original.index(HDR)
e = original.index("\n        }\n", s) + len("\n        }\n")
BLOCK = original[s:e]
assert original.count(HDR) == 1 and "NoSuchElementException" not in original
CLS_HDR = "    private static class ObjectNumbers implements Iterator<Long>\n"
c0 = original.index(CLS_HDR)
CLS = original[c0:]
PRE = original[:c0]


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
FIELDS = (("currentRange", "rangeIndex"), ("currentEnd", "rangeEnd"), ("currentNumber", "cursor"),
          ("maxValue", "upperBound"), ("start", "rangeStarts"), ("end", "rangeEnds"))
for name in ("currentRange", "currentEnd", "currentNumber", "maxValue"):
    assert not re.search(r"\b%s\b" % name, PRE), name  # fields are private to the nested class
# `start` in PRE is an unrelated parameter of parseValue(); the outer class only calls hasNext()/next()
assert set(re.findall(r"objectNumbers\.(\w+)", PRE)) == {"hasNext", "next"}
cls_v1 = CLS
for old, new in FIELDS:
    cls_v1 = re.sub(r"\b%s\b" % old, new, cls_v1)
assert "return cursor++;" in cls_v1 and "cursor = rangeStarts[++rangeIndex];" in cls_v1
assert "public Long next()" in cls_v1 and "Xref stream must have integer" in cls_v1
(CASE_DIR / "variant_vulnerable_01.java").write_text(PRE + cls_v1)

# --- Variant 2: structurally changed vulnerable variant ---
b = '''        public Long next()
        {
            long value;
            if (currentNumber < currentEnd)
            {
                value = currentNumber;
            }
            else
            {
                currentNumber = start[++currentRange];
                currentEnd = end[currentRange];
                value = currentNumber;
            }
            currentNumber = value + 1;
            return value;
        }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Guards with the Iterator-contract idiom (delegating to hasNext(), which is
# `currentNumber < maxValue`) instead of upstream's inline comparison.
b = BLOCK.replace(
    HDR,
    HDR + '''            if (!hasNext())
            {
                throw new java.util.NoSuchElementException();
            }
''')
assert b != BLOCK
safe_source = build(b)
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.util.Iterator;
import java.util.NoSuchElementException;

public class SequentialIds implements Iterator<Long>
{
    private final long end;
    private long current;

    public SequentialIds(long start, long count)
    {
        this.current = start;
        this.end = start + Math.max(0, count);
    }

    @Override
    public boolean hasNext()
    {
        return current < end;
    }

    /**
     * Same Iterator<Long> shape as the range-walking iterator, but over ONE
     * range and with the contract check: calling next() after exhaustion
     * throws NoSuchElementException instead of indexing past any array.
     */
    @Override
    public Long next()
    {
        if (current >= end)
        {
            throw new NoSuchElementException();
        }
        return current++;
    }
}
'''
assert "NoSuchElementException();" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0109.")
