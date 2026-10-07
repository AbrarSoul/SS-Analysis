"""
Section 9 ground-truth test bundle: CASE-0160
(facebook/fbthrift, thrift/lib/java/thrift/src/main/java/com/facebook/thrift/protocol/TProtocolUtil.java
skip, CVE-2019-3559, CWE-755 / CWE-834 improper handling of exceptional
conditions / excessive iteration).

Core vulnerable mechanism: `skip(prot, type, maxDepth)` switches on the wire
type, and its `default:` branch just does `break`, consuming NOTHING for an
unknown type. When the unknown type is the element type of a list, set or map
whose declared size is large, the loop `for (i = 0; i < size; i++) skip(...)`
runs `size` times without reading a single byte, so a tiny message with a
huge declared size and a bogus element type keeps a server thread busy
(denial of service) and, for small sizes, silently mis-parses the stream. The
upstream fix makes the default branch throw a TProtocolException
(INVALID_DATA).

Sibling sites: none in this file; the two-argument skip delegates to the
three-argument one, so a single check covers every call.

Every variant is the FULL real file. skip is a public static API called by
generated code, so the renamed variant keeps the name and renames parameters
and locals.

Verification: fbthrift's Java library is not on Maven Central, so the tests
compile the full file against minimal stand-ins for TProtocol, TType, TList
and friends (same names and signatures as used by the file).
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0160"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

s = original.index("  public static void skip(TProtocol prot, byte type, int maxDepth)\n")
e = original.index("\n  }\n", s) + len("\n  }\n")
BLOCK = original[s:e]
DEFAULT = '''    default:
      break;
    }
'''
assert BLOCK.count(DEFAULT) == 1 and original.count("TProtocolException") == 0


def build(new_block, extra_after=None, text=None):
    text = text or original
    assert new_block != BLOCK
    return text[:s] + new_block + (extra_after or "") + text[e:]


def rename(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = rename(BLOCK, (("prot", "protocol"), ("maxDepth", "depthLeft"), ("type", "wireType"), ("field", "fieldHeader"),
                   ("map", "mapHeader"), ("set", "setHeader"), ("list", "listHeader"), ("i", "n")))
assert "skip(TProtocol protocol, byte wireType, int depthLeft)" in b and "switch (wireType) {" in b
assert "TField fieldHeader = protocol.readFieldBegin();" in b and "(mapHeader.size < 0) ? protocol.peekMap() : (n < mapHeader.size)" in b
assert "skip(protocol, listHeader.elemType, depthLeft - 1);" in b and "if (fieldHeader.type == TType.STOP)" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace('''    case TType.BOOL:
      {
        prot.readBool();
        break;
      }
    case TType.BYTE:
      {
        prot.readByte();
        break;
      }
    case TType.I16:
      {
        prot.readI16();
        break;
      }
    case TType.I32:
      {
        prot.readI32();
        break;
      }
    case TType.I64:
      {
        prot.readI64();
        break;
      }
    case TType.DOUBLE:
      {
        prot.readDouble();
        break;
      }
    case TType.FLOAT:
      {
        prot.readFloat();
        break;
      }
    case TType.STRING:
      {
        prot.readBinary();
        break;
      }
''', '''    case TType.BOOL:
    case TType.BYTE:
    case TType.I16:
    case TType.I32:
    case TType.I64:
    case TType.DOUBLE:
    case TType.FLOAT:
    case TType.STRING:
      {
        skipScalar(prot, type);
        break;
      }
''')
helper = '''
  private static void skipScalar(TProtocol prot, byte type) throws TException {
    switch (type) {
    case TType.BOOL: prot.readBool(); break;
    case TType.BYTE: prot.readByte(); break;
    case TType.I16: prot.readI16(); break;
    case TType.I32: prot.readI32(); break;
    case TType.I64: prot.readI64(); break;
    case TType.DOUBLE: prot.readDouble(); break;
    case TType.FLOAT: prot.readFloat(); break;
    default: prot.readBinary(); break;
    }
  }
'''
assert b != BLOCK
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# The type is validated against the set of skippable wire types BEFORE the
# switch (a helper), so an unknown type is refused wherever it appears;
# upstream makes the switch's default branch throw.
b = BLOCK.replace('''      throw new TException("Maximum skip depth exceeded");
    }
''', '''      throw new TException("Maximum skip depth exceeded");
    }
    if (!isSkippableType(type)) {
      throw new TProtocolException(
          TProtocolException.INVALID_DATA, "Invalid type encountered during skipping: " + type);
    }
''')
helper = '''
  private static boolean isSkippableType(byte type) {
    switch (type) {
    case TType.BOOL:
    case TType.BYTE:
    case TType.I16:
    case TType.I32:
    case TType.I64:
    case TType.DOUBLE:
    case TType.FLOAT:
    case TType.STRING:
    case TType.STRUCT:
    case TType.MAP:
    case TType.SET:
    case TType.LIST:
      return true;
    default:
      return false;
    }
  }
'''
(CASE_DIR / "variant_safe_01.java").write_text(build(b, extra_after=helper))

# --- Variant 4: benign structural look-alike ---
benign_source = '''package com.facebook.thrift.protocol;

import com.facebook.thrift.TException;

public class BoundedListSkipper {

  private static final int MAX_ELEMENTS = 1 << 20;

  /**
   * Same declared-size element loop as the protocol skipper, but the declared
   * size is bounded and every iteration actually consumes an element (an
   * unknown element type is rejected up front), so the loop cannot run
   * without reading.
   */
  public static void skipInts(TProtocol prot, TList list) throws TException {
    if (list.elemType != TType.I32 || list.size < 0 || list.size > MAX_ELEMENTS) {
      throw new TException("Unsupported list header");
    }
    for (int i = 0; i < list.size; i++) {
      prot.readI32();
    }
  }
}
'''
assert "MAX_ELEMENTS" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0160.")
