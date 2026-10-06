"""
Section 9 ground-truth test bundle: CASE-0100
(apache/axis-axis1-java, CVE-2023-40743, CWE-20/CWE-75 JNDI injection).

Core vulnerable mechanism: `ServiceFactory.getService(Map environment)`
takes `environment.get("jndiName")` from the caller and passes it straight
to `new InitialContext().lookup(name)` (and `bind(name, service)`). A
caller-controlled name such as `ldap://evil/x`, `rmi://evil/x` or
`dns://evil/x` makes the JVM resolve an attacker-chosen naming service,
which can return a remote object/reference (RCE via deserialization or
factory loading). The upstream fix adds a case-insensitive DENY-LIST of
scheme substrings (LDAP/RMI/JMS/JMX/JRMP/JAVA/DNS) that returns null.

Every variant is the FULL real file with getService replaced. getService
is `public static` with no in-file call sites (callers are in other files).
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0100"
original = (CASE_DIR / "vulnerable_source.java").read_text()
assert "\r" not in original

HDR = "    public static Service getService(Map environment)\n"
s = original.index(HDR)
e = original.index("\n    }\n", s) + len("\n    }\n")
BLOCK = original[s:e]
NAME_STMT = '''            String name = (String)environment.get("jndiName");
            if (name == null) {
                name = "axisServiceName";
            }
'''
assert original.count(HDR) == 1 and BLOCK.count(NAME_STMT) == 1
assert original.count("getService(") == 1 and "context.lookup(name)" in BLOCK


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
def rename_outside_comments(text, pairs):
    out = []
    for line in text.split("\n"):
        if not line.lstrip().startswith("//"):
            for old, new in pairs:
                line = re.sub(r"\b%s\b" % old, new, line)
        out.append(line)
    return "\n".join(out)


b = BLOCK.replace("getService(", "obtainService(")
b = rename_outside_comments(b, (("environment", "env"), ("name", "registryName"), ("service", "axisService"), ("context", "jndiContext")))
assert "jndiContext.lookup(registryName)" in b and 'env.get("jndiName")' in b and "obtainService(Map env)" in b
(CASE_DIR / "variant_vulnerable_01.java").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(
    NAME_STMT,
    '''            final String requested = (String)environment.get("jndiName");
            final String name = (requested != null) ? requested : "axisServiceName";
''')
assert b != BLOCK and "context.lookup(name)" in b
(CASE_DIR / "variant_vulnerable_02.java").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# ALLOW-LIST of plain composite-name characters (no ':' so no URL/scheme
# forms at all) instead of upstream's substring deny-list; null-safe.
b = BLOCK.replace(
    NAME_STMT,
    NAME_STMT + '''
            if (!name.matches("[A-Za-z0-9_./-]+")) {
                return null;
            }
''')
safe_source = build(b)
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.util.Map;

public class ConfigLocator {

    private static final String CONFIG_NAME = "axisServiceName";

    /**
     * Same InitialContext.lookup(name) call and Map-driven signature, but the
     * looked-up name is a fixed developer-written constant; the caller's map
     * is only read for a display label that never reaches the naming service.
     */
    public static Object findConfig(Map environment) {
        String label = (String) environment.get("displayLabel");
        System.out.println("Locating configuration for " + label);
        try {
            InitialContext context = new InitialContext();
            return context.lookup(CONFIG_NAME);
        } catch (NamingException e) {
            return null;
        }
    }
}
'''
assert "environment.get(\"jndiName\")" not in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)
print("Wrote 4 new samples for CASE-0100.")
