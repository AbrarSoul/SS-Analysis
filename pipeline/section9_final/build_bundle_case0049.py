"""
Section 9 ground-truth test bundle: CASE-0049
(FasterXML/jackson-databind, CVE-2018-5968, CWE-184/CWE-502 incomplete
denylist enabling unsafe polymorphic deserialization).

Core vulnerable mechanism: `SubTypeValidator`'s static initializer builds
`DEFAULT_NO_DESER_CLASS_NAMES`, a denylist of class names jackson-databind
refuses to instantiate during polymorphic deserialization (to block known
"gadget chain" classes usable for remote code execution via crafted JSON).
This revision's denylist is missing two specific known-dangerous classes
(`org.hibernate.jmx.StatisticsService`, a JMX MBean-registration gadget;
`org.apache.ibatis.datasource.jndi.JndiDataSourceFactory`, a JNDI-lookup
gadget) -- an attacker able to control the polymorphic type of a
deserialized value can still target these classes. The fix simply adds
both names to the denylist.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0049"
original = (CASE_DIR / "vulnerable_source.java").read_text()

ANCHOR = '''        s.add("oracle.jdbc.connector.OracleManagedConnectionFactory");
        s.add("oracle.jdbc.rowset.OracleJDBCRowSet");

        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);'''
assert ANCHOR in original

# --- Variant 1: renamed vulnerable variant ---
# Rename the local Set variable s -> denylist throughout the static block.
# Same exact missing entries (hibernate/ibatis gadgets absent).
renamed_source = original.replace("Set<String> s = new HashSet<String>();",
                                   "Set<String> denylist = new HashSet<String>();")
# Only rename occurrences of "s." (the local var's own method calls) and
# "(s)" inside THIS static block/class, not unrelated "s" substrings
# elsewhere in the file -- scope the renaming to just the block's own
# s.add(...) calls and the final assignment, matching the anchor text.
block_start = renamed_source.find("Set<String> denylist = new HashSet<String>();")
block_end = renamed_source.find("DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);") + len(
    "DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);"
)
block_text = renamed_source[block_start:block_end]
renamed_block = block_text.replace("s.add(", "denylist.add(").replace(
    "Collections.unmodifiableSet(s)", "Collections.unmodifiableSet(denylist)"
)
renamed_source = renamed_source[:block_start] + renamed_block + renamed_source[block_end:]
assert "denylist.add(" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of an intermediate boolean variable guarding
# the final assignment. Same exact missing entries, no renaming.
structural_source = original.replace(
    "static {\n        Set<String> s = new HashSet<String>();",
    "static {\n        Set<String> s = new HashSet<String>();\n        boolean initialized = false;",
)
structural_source = structural_source.replace(
    "DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);",
    "initialized = true;\n        DEFAULT_NO_DESER_CLASS_NAMES = initialized ? Collections.unmodifiableSet(s) : null;",
)
assert structural_source != original
assert "boolean initialized = false;" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (add the two missing gadget class names to
# the denylist) but a materially different technique: a separate
# `addAll(Arrays.asList(...))` bulk call after the main block, instead of
# the real patch's two individual s.add() lines interleaved at a specific
# point with a specific comment -- genuinely includes both required
# entries, different code shape.
safe_source = original.replace(
    "DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);",
    '''s.addAll(java.util.Arrays.asList(
            "org.hibernate.jmx.StatisticsService",
            "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory"
        ));

        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);''',
)
assert safe_source != original
assert "org.hibernate.jmx.StatisticsService" in safe_source
assert "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory" in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Same visible shape (a static block building a Set<String> of class
# names via s.add(...) calls, exposed as an unmodifiable set) but this
# sibling is a completely unrelated ALLOWLIST of known-safe primitive
# wrapper type names used by a totally different, non-deserialization
# code path (a debug pretty-printer's "is this a simple scalar type"
# check) -- missing an entry here has no security consequence at all,
# unlike DEFAULT_NO_DESER_CLASS_NAMES.
BENIGN_SOURCE = '''import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class SimpleScalarTypes
{
    public final static Set<String> KNOWN_SIMPLE_TYPE_NAMES;
    static {
        Set<String> s = new HashSet<String>();
        s.add("java.lang.String");
        s.add("java.lang.Integer");
        s.add("java.lang.Long");
        s.add("java.lang.Boolean");
        s.add("java.lang.Double");
        KNOWN_SIMPLE_TYPE_NAMES = Collections.unmodifiableSet(s);
    }

    public static boolean isSimpleScalar(String className)
    {
        return KNOWN_SIMPLE_TYPE_NAMES.contains(className);
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN_SOURCE)
assert "DEFAULT_NO_DESER" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0049.")
