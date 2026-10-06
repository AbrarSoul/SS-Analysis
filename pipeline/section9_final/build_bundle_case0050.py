"""
Section 9 ground-truth test bundle: CASE-0050
(FasterXML/jackson-databind, CVE-2019-14893, CWE-200/CWE-502 incomplete
denylist enabling unsafe polymorphic deserialization).

Same class of vulnerability as CASE-0049 (a later revision of the same
`SubTypeValidator` denylist), this time missing a single class:
`org.apache.xalan.lib.sql.JNDIConnectionPool`, a JNDI-lookup gadget usable
during polymorphic deserialization for JNDI injection / info exposure.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0050"
original = (CASE_DIR / "vulnerable_source.java").read_text()

ANCHOR = '''        s.add("org.apache.commons.configuration.JNDIConfiguration");
        s.add("org.apache.commons.configuration2.JNDIConfiguration");

        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);'''
assert ANCHOR in original

# --- Variant 1: renamed vulnerable variant ---
# Rename the local Set variable s -> blockedTypes, scoped to just this
# static block's own s.add(...)/assignment calls (not unrelated "s"
# substrings elsewhere in this large file). Same exact missing entry.
block_start = original.find("Set<String> s = new HashSet<String>();")
block_end = original.find(
    "DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);"
) + len("DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);")
block_text = original[block_start:block_end]
renamed_block = block_text.replace(
    "Set<String> s = new HashSet<String>();", "Set<String> blockedTypes = new HashSet<String>();"
).replace("s.add(", "blockedTypes.add(").replace(
    "Collections.unmodifiableSet(s)", "Collections.unmodifiableSet(blockedTypes)"
)
renamed_source = original[:block_start] + renamed_block + original[block_end:]
assert "blockedTypes.add(" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: equivalent conditional rewriting -- wraps the final
# assignment in a redundant-but-equivalent if/else instead of a direct
# statement. Same exact missing entry, no renaming.
structural_source = original.replace(
    "DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);",
    '''if (s.isEmpty()) {
            DEFAULT_NO_DESER_CLASS_NAMES = Collections.emptySet();
        } else {
            DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);
        }''',
)
assert structural_source != original
assert "if (s.isEmpty())" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (deny org.apache.xalan.lib.sql.JNDIConnectionPool)
# but via a separate, explicitly-named constant array iterated with a
# for-loop, instead of the real patch's single inline s.add() line with a
# specific comment -- materially different code shape, genuinely includes
# the required entry.
safe_source = original.replace(
    ANCHOR,
    '''        s.add("org.apache.commons.configuration.JNDIConfiguration");
        s.add("org.apache.commons.configuration2.JNDIConfiguration");

        String[] xalanGadgets = { "org.apache.xalan.lib.sql.JNDIConnectionPool" };
        for (String gadget : xalanGadgets) {
            s.add(gadget);
        }

        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);''',
)
assert safe_source != original
assert "org.apache.xalan.lib.sql.JNDIConnectionPool" in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Same visible shape (static block, Set<String>, s.add() calls, exposed
# as an unmodifiable set) but this sibling lists known-SAFE, explicitly
# whitelisted Jackson module package prefixes used only to decide whether
# to log a one-time startup notice -- not consulted anywhere in the
# deserialization security path, so a missing or extra entry here has no
# security consequence, unlike DEFAULT_NO_DESER_CLASS_NAMES.
BENIGN_SOURCE = '''import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class KnownModulePrefixes
{
    public final static Set<String> RECOGNIZED_MODULE_PACKAGE_PREFIXES;
    static {
        Set<String> s = new HashSet<String>();
        s.add("com.fasterxml.jackson.datatype");
        s.add("com.fasterxml.jackson.module");
        RECOGNIZED_MODULE_PACKAGE_PREFIXES = Collections.unmodifiableSet(s);
    }

    public static boolean isRecognizedModule(String packageName)
    {
        for (String prefix : RECOGNIZED_MODULE_PACKAGE_PREFIXES) {
            if (packageName.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN_SOURCE)
assert "DEFAULT_NO_DESER" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0050.")
