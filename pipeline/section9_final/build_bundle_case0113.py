"""
Section 9 ground-truth test bundle: CASE-0113
(apache/solr, CoreContainerProvider, CVE-2023-50290, CWE-200 exposure of
sensitive information to an unauthorized actor).

Core vulnerable mechanism: `setupJvmMetrics()` registers a metrics gauge
("system.env") whose MetricsMap publishes EVERY process environment
variable (`System.getenv().forEach(...)`), filtered only by
`hiddenSysProps`, a list of hidden SYSTEM-PROPERTY names. Secrets that live
in the environment (cloud credentials, tokens, passwords) therefore appear
in the metrics API output readable by anyone who can reach it. The
upstream fix deletes the env gauge registration.

The diff-driven locator originally resolved this deletion-only patch to a
truncated fragment; the case is hand-retargeted to the enclosing method
setupJvmMetrics (see benchmark/hand_curations.json). Every variant is the
FULL real file with setupJvmMetrics (or its env region) replaced.
setupJvmMetrics has one in-file call site, which the renamed variant also
renames.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0113"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "  private void setupJvmMetrics(CoreContainer coresInit, MetricsConfig config) {\n"
s = original.index(HDR)
e = original.index("\n  }\n", s) + len("\n  }\n")
BLOCK = original[s:e]
CALL = "setupJvmMetrics(coresInit, coresInit.getNodeConfig().getMetricsConfig());"
ENV_START = "      MetricsMap sysenv =\n"
ENV_REG = '''      metricManager.registerGauge(
          null, registryName, sysenv, metricTag, ResolutionStrategy.IGNORE, "env", "system");
'''
es = BLOCK.index(ENV_START)
ee = BLOCK.index(ENV_REG) + len(ENV_REG)
ENV_REGION = BLOCK[es:ee]
assert original.count(HDR) == 1 and original.count(CALL) == 1 and original.count("setupJvmMetrics(") == 2
assert BLOCK.count(ENV_START) == 1 and BLOCK.count(ENV_REG) == 1 and "System.getenv()" in ENV_REGION
assert BLOCK[ee:].startswith("    } catch (Exception e) {")


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
b = BLOCK.replace("private void setupJvmMetrics(", "private void registerJvmGauges(")
b = rename_outside_comments_strings(b, (("coresInit", "container"), ("config", "metricsCfg"),
                                        ("hiddenSysProps", "hiddenNames"), ("sysenv", "envGauge"),
                                        ("sysprops", "propsGauge")))
assert "envGauge" in b and "System.getenv()" in b and "metricsCfg.getCacheConfig()" in b
assert '"env", "system"' in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(
    build(b, "registerJvmGauges(coresInit, coresInit.getNodeConfig().getMetricsConfig());"))

# --- Variant 2: structurally changed vulnerable variant ---
# Snapshot the environment once at registration instead of reading it live.
env_v2 = '''      final java.util.Map<String, String> envSnapshot = System.getenv();
      MetricsMap sysenv =
          new MetricsMap(
              map ->
                  envSnapshot.forEach(
                      (k, v) -> {
                        if (!hiddenSysProps.contains(k)) {
                          map.putNoEx(String.valueOf(k), v);
                        }
                      }));
''' + ENV_REG
b = BLOCK[:es] + env_v2 + BLOCK[ee:]
assert "System.getenv()" in b and b != BLOCK
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Keep the gauge but publish only an allow-list of non-secret variable names
# (upstream deletes the gauge outright).
env_v3 = '''      final Set<String> publishedEnv = new java.util.HashSet<>(java.util.Arrays.asList("HOSTNAME", "LANG", "TZ"));
      MetricsMap sysenv =
          new MetricsMap(
              map ->
                  System.getenv()
                      .forEach(
                          (k, v) -> {
                            if (publishedEnv.contains(k) && !hiddenSysProps.contains(k)) {
                              map.putNoEx(String.valueOf(k), v);
                            }
                          }));
''' + ENV_REG
b = BLOCK[:es] + env_v3 + BLOCK[ee:]
safe_source = build(b)
assert "publishedEnv.contains(k)" in safe_source and "import java.util.Set;" in original
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import java.util.LinkedHashMap;
import java.util.Map;

public class EnvSummaryMetrics {

    /**
     * Same System.getenv() traversal shape, but it publishes only HOW MANY
     * environment variables exist and how many are non-empty. No variable
     * name or value ever leaves the process, so nothing sensitive is exposed.
     */
    public Map<String, Object> snapshot() {
        Map<String, Object> out = new LinkedHashMap<>();
        int[] counts = new int[2];
        System.getenv().forEach((k, v) -> {
            counts[0]++;
            if (v != null && !v.isEmpty()) {
                counts[1]++;
            }
        });
        out.put("count", counts[0]);
        out.put("nonEmpty", counts[1]);
        return out;
    }
}
'''
assert "out.put(k" not in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0113.")
