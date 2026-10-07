"""
Section 9 ground-truth test bundle: CASE-0114
(apache/struts, JakartaMultiPartRequest, CVE-2023-41835, CWE-459 incomplete
cleanup of temporary files).

Core vulnerable mechanism: `processNormalFormField()` releases the
uploaded item's temp file with a trailing `item.delete()`, but the
oversized-parameter branch (`size > maxStringLength`) does an early
`return;` BEFORE that call, and an exception from `item.getString(charset)`
also skips it. Each such request leaves a temp file on disk (the
DiskFileItem was already spooled), so an attacker can send many
oversized form fields and fill the disk (DoS). The upstream fix wraps the
body in try/finally so `item.delete()` always runs (the isEmpty()/toArray
edits in the same commit are cosmetic).

Every variant is the FULL real file with processNormalFormField replaced.
It is `protected` with one in-file call site (in parse()), which the
renamed variant also renames.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0114"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    protected void processNormalFormField(FileItem item, String charset) throws UnsupportedEncodingException {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
CALL = "processNormalFormField(item, request.getCharacterEncoding());"
assert original.count(HDR) == 1 and original.count(CALL) == 1 and original.count("processNormalFormField(") == 2
assert BLOCK.count("        item.delete();\n") == 1 and BLOCK.count("return;") == 1


def build(new_block, new_call=None):
    assert new_block != BLOCK
    out = original[:s] + new_block + original[e:]
    if new_call:
        assert out.count(CALL) == 1
        out = out.replace(CALL, new_call)
    return out


def rename_outside_comments_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        st = line.lstrip()
        if st.startswith("//") or st.startswith("*") or st.startswith("/*"):
            out.append(line)
            continue
        parts = re.split(r'("(?:[^"\\]|\\.)*")', line)
        for i in range(0, len(parts), 2):
            for old, new in pairs:
                parts[i] = re.sub(r"\b%s\b" % old, new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("processNormalFormField(", "handleRegularField(")
b = rename_outside_comments_strings(b, (("item", "part"), ("charset", "encoding"), ("values", "collected"),
                                        ("size", "byteCount"), ("errorKey", "messageKey"),
                                        ("localizedMessage", "tooLongMessage")))
assert "part.delete();" in b and "handleRegularField(FileItem part, String encoding)" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(
    build(b, "handleRegularField(item, request.getCharacterEncoding());"))

# --- Variant 2: structurally changed vulnerable variant ---
# Extract-method of the too-long error recording; the early `return;` (and
# therefore the skipped item.delete()) is unchanged.
OLD_BRANCH = '''        } else if (size > maxStringLength) {
          String errorKey = "struts.messages.upload.error.parameter.too.long";
          LocalizedMessage localizedMessage = new LocalizedMessage(this.getClass(), errorKey, null,
                  new Object[] { item.getFieldName(), maxStringLength, size });

          if (!errors.contains(localizedMessage)) {
              errors.add(localizedMessage);
          }
          return;

'''
assert BLOCK.count(OLD_BRANCH) == 1
b = BLOCK.replace(OLD_BRANCH, '''        } else if (size > maxStringLength) {
            recordParameterTooLong(item, size);
            return;

''')
b += '''
    private void recordParameterTooLong(FileItem item, long size) {
        String errorKey = "struts.messages.upload.error.parameter.too.long";
        LocalizedMessage localizedMessage = new LocalizedMessage(this.getClass(), errorKey, null,
                new Object[] { item.getFieldName(), maxStringLength, size });

        if (!errors.contains(localizedMessage)) {
            errors.add(localizedMessage);
        }
    }
'''
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# The original body moves into a worker WITHOUT the trailing delete; the
# protected entry point calls it inside try/finally (upstream instead wraps
# the body in place).
worker = BLOCK.replace(
    "    protected void processNormalFormField(FileItem item, String charset) throws UnsupportedEncodingException {\n",
    "    private void storeNormalFormField(FileItem item, String charset) throws UnsupportedEncodingException {\n"
).replace("        item.delete();\n", "")
entry = '''    protected void processNormalFormField(FileItem item, String charset) throws UnsupportedEncodingException {
        try {
            storeNormalFormField(item, charset);
        } finally {
            item.delete();
        }
    }

'''
b = entry + worker
safe_source = build(b)
assert "item.delete();" in entry and worker.count("item.delete()") == 0
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class InMemoryFieldHandler {

    /** A form value that lives entirely in memory; release() only drops a reference. */
    public interface InMemoryItem {
        String name();
        String value();
        long size();
        void release();
    }

    private final Map<String, List<String>> params = new HashMap<>();
    private final long maxStringLength;

    public InMemoryFieldHandler(long maxStringLength) {
        this.maxStringLength = maxStringLength;
    }

    /**
     * Same "early return before the trailing release() call" shape, but the
     * item is never spooled to disk, so skipping release() on the too-long
     * path leaves no temp file behind (the garbage collector reclaims it).
     */
    public void process(InMemoryItem item) {
        if (item.size() > maxStringLength) {
            return;
        }
        params.computeIfAbsent(item.name(), k -> new ArrayList<>()).add(item.value());
        item.release();
    }
}
'''
assert "spooled to disk" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0114.")
