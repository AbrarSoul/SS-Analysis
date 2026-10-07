"""
Section 9 ground-truth test bundle: CASE-0102
(apache/camel, camel-undertow, CVE-2025-30177, CWE-164 internal special
element injection -- inbound Camel* header injection).

Core vulnerable mechanism: `UndertowHeaderFilterStrategy.initialize()`
only configures the OUT filter (`setOutFilterStartsWith(CAMEL_FILTER_STARTS_WITH)`),
so headers whose name starts with "Camel" / "org.apache.camel" are NOT
stripped from INBOUND HTTP requests. A remote client can therefore send
e.g. `CamelExecCommandExecutable: ...` and have it interpreted as an
internal Camel header by later components in the route. The upstream fix
adds `setInFilterStartsWith(CAMEL_FILTER_STARTS_WITH)`.

Every variant is the FULL real file with initialize() replaced. initialize()
has one in-file call site (the constructor), which the renamed variant also
renames.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0102"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    protected void initialize() {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
CALL = "        initialize();\n"
OUT_LINE = "        setOutFilterStartsWith(CAMEL_FILTER_STARTS_WITH);\n"
assert original.count(HDR) == 1 and original.count(CALL) == 1 and BLOCK.count(OUT_LINE) == 1
assert "setInFilter" not in original


def build(new_block, new_call=None):
    assert new_block != BLOCK
    out = original[:s] + new_block + original[e:]
    if new_call:
        assert out.count(CALL) == 1
        out = out.replace(CALL, new_call)
    return out


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("protected void initialize()", "protected void configureFilters()")
assert "configureFilters" in b and "setInFilter" not in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b, "        configureFilters();\n"))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(OUT_LINE, "        final String[] camelPrefixes = CAMEL_FILTER_STARTS_WITH;\n        setOutFilterStartsWith(camelPrefixes);\n")
assert b != BLOCK and "setInFilter" not in b
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Inbound filtering via an explicit case-insensitive regex on the in-filter
# (upstream uses the startsWith list; CAMEL_FILTER_PATTERN is deprecated).
b = BLOCK.replace(OUT_LINE, OUT_LINE + '        setInFilterPattern("(?i)(camel|org\\\\.apache\\\\.camel\\\\.).*");\n')
safe_source = build(b)
assert "setInFilterPattern(" in safe_source and "CAMEL_FILTER_PATTERN" not in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import org.apache.camel.Exchange;
import org.apache.camel.support.DefaultHeaderFilterStrategy;
import org.apache.camel.support.http.HttpUtil;

public class ProducerOnlyHeaderFilterStrategy extends DefaultHeaderFilterStrategy {

    public ProducerOnlyHeaderFilterStrategy() {
        initialize();
    }

    protected void initialize() {
        HttpUtil.addCommonFilters(getOutFilter());

        setLowerCase(true);

        // same outbound-only configuration as a consumer-side strategy ...
        setOutFilterStartsWith(CAMEL_FILTER_STARTS_WITH);
    }

    /**
     * ... but this strategy belongs to a producer-only endpoint: no external
     * (inbound) header is ever allowed into the Camel message, so a client
     * cannot inject Camel* headers.
     */
    @Override
    public boolean applyFilterToExternalHeaders(String headerName, Object headerValue, Exchange exchange) {
        return true;
    }
}
'''
assert "applyFilterToExternalHeaders" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0102.")
