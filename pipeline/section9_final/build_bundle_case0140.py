"""
Section 9 ground-truth test bundle: CASE-0140
(dataease/dataease, MysqlConfiguration.getJdbc, CVE-2022-39312,
CWE-20 / CWE-502 JDBC URL parameter injection -> unsafe deserialization).

Core vulnerable mechanism: `getJdbc()` appends the user-supplied
`extraParams` string to the JDBC URL unvalidated
(`.replace("EXTRA_PARAMS", getExtraParams().trim())`). MySQL Connector/J
honours dangerous properties such as `autoDeserialize`,
`queryInterceptors` and `statementInterceptors`, so an attacker who can set
the datasource's extra parameters can make the server deserialize
attacker-controlled data from a malicious MySQL server (remote code
execution). The upstream fix adds a case-sensitive SUBSTRING denylist of
four names.

FLAGGED: upstream's denylist is bypassable, verified with the real
Connector/J 8.4.0 URL parser (no DB connection): `auto%44eserialize=true` and
similar percent-encodings are not blocked by `contains("autoDeserialize")`
but are decoded by Connector/J into an active `autoDeserialize=true`. The
case is kept on the user's decision (the fix still closes the documented
vector); the SAFE variant uses an allow-list instead, and the bypass is
recorded in the manifest notes.

Every variant is the FULL real file with getJdbc replaced. getJdbc is a
public method called from other classes (no in-file callers), so the renamed
variant renames the declaration only.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0140"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    public String getJdbc() {\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
ELSE_RET = '''        }else {
            return "jdbc:mysql://HOSTNAME:PORT/DATABASE?EXTRA_PARAMS"
'''
assert original.count(HDR) == 1 and BLOCK.count(ELSE_RET) == 1 and original.count("getJdbc") == 1


def build(new_block, extra_after=None):
    assert new_block != BLOCK
    return original[:s] + new_block + (extra_after or "") + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK.replace("public String getJdbc()", "public String buildJdbcUrl()")
assert "buildJdbcUrl" in b and '.replace("EXTRA_PARAMS", getExtraParams().trim())' in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = '''    public String getJdbc() {
        String base = "jdbc:mysql://" + getHost().trim() + ":" + getPort().toString().trim() + "/" + getDataBase().trim();
        if (StringUtils.isEmpty(extraParams.trim())) {
            return base;
        }
        return base + "?" + getExtraParams().trim();
    }
'''
assert b != BLOCK
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Strict allow-list: the whole extraParams string may only contain a small
# character set (so no '%' encoding, ';', spaces, quotes ...), and every
# property NAME must be one of a fixed list of benign options; upstream
# rejects four names by case-sensitive substring.
b = BLOCK.replace(ELSE_RET, '''        }else {
            assertSafeExtraParams(getExtraParams().trim());
            return "jdbc:mysql://HOSTNAME:PORT/DATABASE?EXTRA_PARAMS"
''')
helper = '''
    private static void assertSafeExtraParams(String params) {
        java.util.Set<String> allowed = new java.util.HashSet<>(java.util.Arrays.asList(
                "characterEncoding", "connectTimeout", "socketTimeout", "useSSL", "allowPublicKeyRetrieval",
                "zeroDateTimeBehavior", "serverTimezone", "useUnicode", "autoReconnect", "tinyInt1isBit"));
        if (!params.matches("[A-Za-z0-9_.\\\\-=&/:]*")) {
            throw new RuntimeException("Illegal characters in extra parameters");
        }
        for (String pair : params.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String name = eq < 0 ? pair : pair.substring(0, eq);
            if (!allowed.contains(name)) {
                throw new RuntimeException("Illegal parameter: " + name);
            }
        }
    }
'''
safe_source = build(b, extra_after=helper)
assert "assertSafeExtraParams(" in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''public class FixedMysqlUrl {

    /** Developer-fixed connection options; nothing user-supplied can extend them. */
    private static final String FIXED_PARAMS = "characterEncoding=UTF-8&useSSL=false&connectTimeout=5000";

    private static void requireSimple(String value, String what) {
        if (!value.matches("[A-Za-z0-9_.\\\\-]+")) {
            throw new IllegalArgumentException("Illegal " + what);
        }
    }

    /**
     * Same replace-a-template JDBC URL construction as a datasource
     * configuration, but the EXTRA_PARAMS slot is filled with a constant, and
     * host and database name are restricted to plain identifier characters, so
     * no caller can add a driver property such as autoDeserialize.
     */
    public String jdbc(String host, int port, String database) {
        requireSimple(host.trim(), "host");
        requireSimple(database.trim(), "database");
        return "jdbc:mysql://HOSTNAME:PORT/DATABASE?EXTRA_PARAMS"
                .replace("HOSTNAME", host.trim())
                .replace("PORT", String.valueOf(port))
                .replace("DATABASE", database.trim())
                .replace("EXTRA_PARAMS", FIXED_PARAMS);
    }
}
'''
assert "FIXED_PARAMS" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0140.")
