"""
Section 9 ground-truth test bundle: CASE-0172
(hjson/hjson-java, src/main/org/hjson/HjsonParser.java readMlString,
CVE-2023-39685, CWE-94 as recorded; in substance an unchecked
StringBuilder index on an empty multiline string). This case is the
single-case replacement added by top-up 15 after CASE-0172 (gulpjs/glob-parent)
was excluded.

Located target: the single-quote branch `else if (current=='\\'') {` of
`readMlString`.

Core vulnerable mechanism: when the closing `'''` of a multiline string is
reached, the parser does `if (sb.charAt(sb.length()-1)=='\\n') sb.deleteCharAt(...)`
with no check that `sb` is non-empty. An EMPTY multiline string (`''''''`)
therefore calls charAt(-1) and throws StringIndexOutOfBoundsException (an
unchecked exception, not the parser's ParseException), which an application
that parses untrusted Hjson does not expect. The upstream fix adds
`sb.length() > 0 &&` to the condition.

Sibling sites: none in this file (the only other trailing-character access is
guarded by the loop structure).

Every variant is the FULL real file. readMlString is a private method with a
single call, so the renamed variant renames the method, its call, and its
locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0172"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

s = original.index("  private String readMlString() throws IOException {\n")
e = original.index("\n  }\n", s) + len("\n  }\n")
BLOCK = original[s:e]
TRIM = "          if (sb.charAt(sb.length()-1)=='\\n') sb.deleteCharAt(sb.length()-1);\n"
assert BLOCK.count(TRIM) == 1 and original.count("readMlString") >= 2


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
        parts = re.split(r"""("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')""", line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = rename(BLOCK, (("readMlString", "readTripleQuoted"), ("sb", "buf"), ("triple", "quotes"), ("indent", "baseIndent")))
assert "if (buf.charAt(buf.length()-1)=='\\n') buf.deleteCharAt(buf.length()-1);" in b
assert "StringBuilder buf=new StringBuilder();" in b and "int quotes=0;" in b
v1 = build(b)
assert v1.count("readMlString") >= 1
v1 = v1.replace("readMlString()", "readTripleQuoted()")
assert "readMlString" not in v1
(CASE_DIR / "variant_vulnerable_01.java").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(TRIM, "          dropTrailingNewline(sb);\n")
helper = '''
  private static void dropTrailingNewline(StringBuilder sb) {
    if (sb.charAt(sb.length()-1)=='\\n') sb.deleteCharAt(sb.length()-1);
  }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b, extra_after=helper))

# --- Variant 3: transformed safe variant ---
# endsWith-based check (an empty builder simply does not end with a newline);
# upstream prefixes the condition with sb.length() > 0.
b = BLOCK.replace(TRIM, "          if (sb.toString().endsWith(\"\\n\")) sb.setLength(sb.length()-1);\n")
(CASE_DIR / "variant_safe_01.java").write_text(build(b))

# --- Variant 4: benign structural look-alike ---
benign_source = '''public class TrailingNewline {

    /**
     * Same "drop one trailing newline" step as the multiline string reader, but
     * it returns early for an empty builder, so the charAt(length - 1) lookup
     * can never see index -1.
     */
    public static String withoutTrailingNewline(StringBuilder sb) {
        if (sb.length() == 0) {
            return "";
        }
        if (sb.charAt(sb.length() - 1) == '\\n') {
            sb.deleteCharAt(sb.length() - 1);
        }
        return sb.toString();
    }
}
'''
assert "sb.length() == 0" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0172.")
