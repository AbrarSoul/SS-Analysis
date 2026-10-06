"""
Section 9 ground-truth test bundle: CASE-0120
(apache/tomcat, Parameters.addParameter, CVE-2023-28709, CWE-193 off-by-one
error in a limit check).

Core vulnerable mechanism: `addParameter()` does `parameterCount++` BEFORE
comparing with the configured `limit`, so the counter also counts the
parameter that is being REJECTED (it ends at limit+1) and reports a value
that does not equal the number of stored parameters. Code that budgets
further parameters (uploaded multipart parts) from `getParameterCount()`
after a request with exactly the maximum number of query-string parameters
therefore works from a wrong figure, letting the part limit be bypassed
(denial of service). The upstream fix checks `parameterCount >= limit`
first and only then increments.

Every variant is the FULL real file with addParameter replaced. It is
public (also called from other files) with one in-file call site
(processParameters), which the renamed variant also renames.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0120"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    public void addParameter(String key, String value) throws IllegalStateException {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
CALL = "                    addParameter(name, value);\n"
CHECK = '''        parameterCount++;
        if (limit > -1 && parameterCount > limit) {
'''
assert original.count(HDR) == 1 and original.count(CALL) == 1 and BLOCK.count(CHECK) == 1
assert original.count("addParameter(") == 2


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
b = BLOCK.replace("addParameter(", "registerParameter(")
b = rename_outside_comments_strings(b, (("key", "paramName"), ("value", "paramValue"), ("values", "collected")))
assert "paramHashValues.get(paramName)" in b and "collected.add(paramValue);" in b
assert "parameterCount++;" in b and "parameterCount > limit" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b, "                    registerParameter(name, value);\n"))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(CHECK, '''        int newCount = ++parameterCount;
        if (limit > -1 && newCount > limit) {
''')
assert b != BLOCK
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Check against the current count first, and count a parameter only once it
# has actually been stored (so the counter always equals the number of
# accepted parameters).
b = BLOCK.replace(CHECK, "        if (limit > -1 && parameterCount >= limit) {\n")
b = b.replace("        values.add(value);\n", "        values.add(value);\n        parameterCount++;\n")
assert "parameterCount++;" in b and b.index("parameterCount >= limit") < b.index("parameterCount++;")
safe_source = build(b)
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''public class AttemptCounter {

    private final int maxAttempts;
    private int attempts = 0;

    public AttemptCounter(int maxAttempts) {
        this.maxAttempts = maxAttempts;
    }

    /**
     * Same "increment, then compare with the limit" order, but this counter
     * is DEFINED as the number of ATTEMPTS (accepted or rejected), and that
     * is exactly what attemptsSoFar() reports and what the audit log wants,
     * so counting the rejected attempt is the intended behaviour, not a
     * miscount.
     */
    public void recordAttempt() {
        attempts++;
        if (maxAttempts > -1 && attempts > maxAttempts) {
            throw new IllegalStateException("Too many attempts: " + maxAttempts);
        }
    }

    public int attemptsSoFar() {
        return attempts;
    }
}
'''
assert "DEFINED as the number of ATTEMPTS" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0120.")
