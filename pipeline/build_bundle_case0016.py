"""
Section 9 ground-truth test bundle: CASE-0016
(apache/kylin, CVE-2020-1937, CWE-89 -- SQL injection).

The real patch fixes three near-identical SQL-building methods
(getCuboidHitFrequency, getCuboidRollingUpStats, and a third hit-frequency
method). This bundle targets getCuboidHitFrequency() as the representative
instance (Section 9.3); the other two are left untouched in every variant.

Core vulnerable mechanism: cubeName (a caller-supplied parameter) is
concatenated directly into a raw SQL string inside a quoted literal
(" = '" + cubeName + "'"), then executed via querySystemCube(sql) with no
parameter binding -- classic SQL injection. The real fix switches to a
parameterized query (PrepareSqlRequest/StateParam binding, "= ?").
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0016"
original = (CASE_DIR / "vulnerable_source.java").read_text()

VULNERABLE_BLOCK = (
    "    public Map<Long, Long> getCuboidHitFrequency(String cubeName, boolean isCuboidSource) {\n"
    "        String cuboidColumn = isCuboidSource ? QueryCubePropertyEnum.CUBOID_SOURCE.toString()\n"
    "                : QueryCubePropertyEnum.CUBOID_TARGET.toString();\n"
    "        String hitMeasure = QueryCubePropertyEnum.WEIGHT_PER_HIT.toString();\n"
    "        String table = getMetricsManager().getSystemTableFromSubject(getConfig().getKylinMetricsSubjectQueryCube());\n"
    "        String sql = \"select \" + cuboidColumn + \", sum(\" + hitMeasure + \")\" //\n"
    "                + \" from \" + table//\n"
    "                + \" where \" + QueryCubePropertyEnum.CUBE.toString() + \" = '\" + cubeName + \"'\" //\n"
    "                + \" group by \" + cuboidColumn;\n"
    "        List<List<String>> orgHitFrequency = queryService.querySystemCube(sql).getResults();\n"
    "        return formatQueryCount(orgHitFrequency);\n"
    "    }\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"
assert original.count(VULNERABLE_BLOCK) == 1

# --- Variant 1: renamed vulnerable variant ---
# Rename the method getCuboidHitFrequency -> computeCuboidHitFrequency (no
# other in-file call sites exist), parameter cubeName -> targetCubeName,
# local sql -> query. Same exact vulnerability: still raw string
# concatenation into the SQL literal.
RENAMED_BLOCK = (
    "    public Map<Long, Long> computeCuboidHitFrequency(String targetCubeName, boolean isCuboidSource) {\n"
    "        String cuboidColumn = isCuboidSource ? QueryCubePropertyEnum.CUBOID_SOURCE.toString()\n"
    "                : QueryCubePropertyEnum.CUBOID_TARGET.toString();\n"
    "        String hitMeasure = QueryCubePropertyEnum.WEIGHT_PER_HIT.toString();\n"
    "        String table = getMetricsManager().getSystemTableFromSubject(getConfig().getKylinMetricsSubjectQueryCube());\n"
    "        String query = \"select \" + cuboidColumn + \", sum(\" + hitMeasure + \")\" //\n"
    "                + \" from \" + table//\n"
    "                + \" where \" + QueryCubePropertyEnum.CUBE.toString() + \" = '\" + targetCubeName + \"'\" //\n"
    "                + \" group by \" + cuboidColumn;\n"
    "        List<List<String>> orgHitFrequency = queryService.querySystemCube(query).getResults();\n"
    "        return formatQueryCount(orgHitFrequency);\n"
    "    }\n"
)
renamed_source = original.replace(VULNERABLE_BLOCK, RENAMED_BLOCK)
assert renamed_source != original
assert "computeCuboidHitFrequency" in renamed_source
assert "targetCubeName" in renamed_source
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: equivalent API-call formatting -- String.format() instead
# of + concatenation. Still no escaping/parameter binding, so cubeName is
# still embedded raw inside the quoted literal -- same exact vulnerability,
# no renaming.
STRUCTURAL_BLOCK = (
    "    public Map<Long, Long> getCuboidHitFrequency(String cubeName, boolean isCuboidSource) {\n"
    "        String cuboidColumn = isCuboidSource ? QueryCubePropertyEnum.CUBOID_SOURCE.toString()\n"
    "                : QueryCubePropertyEnum.CUBOID_TARGET.toString();\n"
    "        String hitMeasure = QueryCubePropertyEnum.WEIGHT_PER_HIT.toString();\n"
    "        String table = getMetricsManager().getSystemTableFromSubject(getConfig().getKylinMetricsSubjectQueryCube());\n"
    "        String sql = String.format(\"select %s, sum(%s) from %s where %s = '%s' group by %s\",\n"
    "                cuboidColumn, hitMeasure, table, QueryCubePropertyEnum.CUBE.toString(), cubeName, cuboidColumn);\n"
    "        List<List<String>> orgHitFrequency = queryService.querySystemCube(sql).getResults();\n"
    "        return formatQueryCount(orgHitFrequency);\n"
    "    }\n"
)
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
assert structural_source != original
assert "String.format(" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (cubeName bound as a query
# parameter, never concatenated into the SQL string) but constructed
# inline in this one method, instead of the real patch's shared
# getPrepareQueryResult() helper used by all three sibling methods --
# materially different structure, not byte-identical to the known fix.
SAFE_BLOCK = (
    "    public Map<Long, Long> getCuboidHitFrequency(String cubeName, boolean isCuboidSource) {\n"
    "        String cuboidColumn = isCuboidSource ? QueryCubePropertyEnum.CUBOID_SOURCE.toString()\n"
    "                : QueryCubePropertyEnum.CUBOID_TARGET.toString();\n"
    "        String hitMeasure = QueryCubePropertyEnum.WEIGHT_PER_HIT.toString();\n"
    "        String table = getMetricsManager().getSystemTableFromSubject(getConfig().getKylinMetricsSubjectQueryCube());\n"
    "        String sql = \"select \" + cuboidColumn + \", sum(\" + hitMeasure + \")\" //\n"
    "                + \" from \" + table//\n"
    "                + \" where \" + QueryCubePropertyEnum.CUBE.toString() + \" = ?\" //\n"
    "                + \" group by \" + cuboidColumn;\n"
    "        PrepareSqlRequest sqlRequest = new PrepareSqlRequest();\n"
    "        sqlRequest.setProject(MetricsManager.SYSTEM_PROJECT);\n"
    "        PrepareSqlRequest.StateParam param = new PrepareSqlRequest.StateParam();\n"
    "        param.setClassName(\"java.lang.String\");\n"
    "        param.setValue(cubeName);\n"
    "        sqlRequest.setParams(new PrepareSqlRequest.StateParam[] { param });\n"
    "        sqlRequest.setSql(sql);\n"
    "        List<List<String>> orgHitFrequency = queryService.doQueryWithCache(sqlRequest, false).getResults();\n"
    "        return formatQueryCount(orgHitFrequency);\n"
    "    }\n"
)
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
safe_source = safe_source.replace(
    "import org.apache.kylin.metrics.property.QueryCubePropertyEnum;\n",
    "import org.apache.kylin.metrics.MetricsManager;\n"
    "import org.apache.kylin.metrics.property.QueryCubePropertyEnum;\n",
    1,
)
safe_source = safe_source.replace(
    "import org.apache.kylin.rest.request.MetricsRequest;\n",
    "import org.apache.kylin.rest.request.MetricsRequest;\n"
    "import org.apache.kylin.rest.request.PrepareSqlRequest;\n",
    1,
)
assert safe_source != original
assert SAFE_BLOCK in safe_source
# the other two sibling vulnerable methods are intentionally left
# untouched (out of scope for this bundle), so the raw-concatenation
# pattern still legitimately appears twice elsewhere in the file
assert safe_source.count("= '\" + cubeName") == 2
assert "PrepareSqlRequest" in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a method that also builds a
# SQL string via + concatenation with a quoted literal -- the same
# superficial shape as the vulnerable line -- but the concatenated value
# is a hardcoded compile-time constant, never caller input, so no
# injection is possible regardless of what any caller passes.
BENIGN_ADDITION = (
    "\n"
    "    private String buildSystemHealthCheckQuery(String table) {\n"
    "        // \"SYSTEM_HEALTH_CHECK_MARKER\" is a compile-time constant, never\n"
    "        // derived from caller input, so string-concatenating it into SQL\n"
    "        // carries no injection risk, unlike cubeName in\n"
    "        // getCuboidHitFrequency().\n"
    "        return \"select 1 from \" + table + \" where \" + QueryCubePropertyEnum.CUBE.toString()\n"
    "                + \" = '\" + \"SYSTEM_HEALTH_CHECK_MARKER\" + \"'\";\n"
    "    }\n"
)
anchor = "    public Map<Long, Long> getCuboidHitFrequency(String cubeName, boolean isCuboidSource) {\n"
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "buildSystemHealthCheckQuery" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)

print("Wrote 4 new samples for CASE-0016.")
