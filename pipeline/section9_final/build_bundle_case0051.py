"""
Section 9 ground-truth test bundle: CASE-0051
(FasterXML/jackson-databind, CVE-2020-9547, CWE-502 incomplete denylist
enabling unsafe polymorphic deserialization).

Same class of vulnerability as CASE-0049/CASE-0050 (a later revision of
the same `SubTypeValidator` denylist), this time missing three classes:
`org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig`,
`com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig`, and
`br.com.anteros.dbcp.AnterosDBCPConfig` -- three more known JNDI/config
gadget classes usable during polymorphic deserialization.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0051"
original = (CASE_DIR / "vulnerable_source.java").read_text()

ANCHOR = '''        // [databind#2620]: xbean-reflect
        s.add("org.apache.xbean.propertyeditor.JndiConverter");

        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);'''
assert ANCHOR in original

# --- Variant 1: renamed vulnerable variant ---
# Rename the local Set variable s -> forbiddenClasses, scoped to just this
# static block's own s.add(...)/assignment calls. Same exact 3 missing
# entries.
block_start = original.find("Set<String> s = new HashSet<String>();")
block_end = original.find(
    "DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);"
) + len("DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);")
block_text = original[block_start:block_end]
renamed_block = block_text.replace(
    "Set<String> s = new HashSet<String>();", "Set<String> forbiddenClasses = new HashSet<String>();"
).replace("s.add(", "forbiddenClasses.add(").replace(
    "Collections.unmodifiableSet(s)", "Collections.unmodifiableSet(forbiddenClasses)"
)
renamed_source = original[:block_start] + renamed_block + original[block_end:]
assert "forbiddenClasses.add(" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: wrapper-function introduction -- a small private static
# helper method that the static block calls, instead of building the set
# inline. Same exact missing entries, no renaming of the local variable.
structural_source = original.replace(
    "static {\n        Set<String> s = new HashSet<String>();",
    "static {\n        Set<String> s = buildInitialDenySet();",
)
structural_source = structural_source.replace(
    "DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);",
    '''DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);
    }

    private static Set<String> buildInitialDenySet() {
        return new HashSet<String>();''',
)
assert structural_source != original
assert "buildInitialDenySet" in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (deny the three gadget classes) but via a
# single Collections.addAll(s, ...) varargs call instead of the real
# patch's three individual s.add() lines with their own comments --
# materially different code shape, genuinely includes all three required
# entries.
safe_source = original.replace(
    ANCHOR,
    '''        // [databind#2620]: xbean-reflect
        s.add("org.apache.xbean.propertyeditor.JndiConverter");

        Collections.addAll(s,
            "org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig",
            "com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig",
            "br.com.anteros.dbcp.AnterosDBCPConfig"
        );

        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);''',
)
assert safe_source != original
assert "org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig" in safe_source
assert "com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig" in safe_source
assert "br.com.anteros.dbcp.AnterosDBCPConfig" in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Same visible shape (static block, Set<String>, s.add() calls, exposed
# as an unmodifiable set) but this sibling lists known SAFE built-in
# Jackson annotation class names used only to decide whether to emit a
# deprecation warning at startup -- never consulted during actual
# deserialization type validation, so a missing entry here carries no
# security consequence, unlike DEFAULT_NO_DESER_CLASS_NAMES.
BENIGN_SOURCE = '''import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class DeprecatedAnnotationNames
{
    public final static Set<String> KNOWN_DEPRECATED_ANNOTATIONS;
    static {
        Set<String> s = new HashSet<String>();
        s.add("com.fasterxml.jackson.databind.annotation.JsonSerialize.Inclusion");
        s.add("com.fasterxml.jackson.databind.annotation.JsonTypeInfo.As.PROPERTY_LEGACY");
        KNOWN_DEPRECATED_ANNOTATIONS = Collections.unmodifiableSet(s);
    }

    public static boolean isDeprecated(String annotationClassName)
    {
        return KNOWN_DEPRECATED_ANNOTATIONS.contains(annotationClassName);
    }
}
'''
(CASE_DIR / "benign_lookalike.java").write_text(BENIGN_SOURCE)
assert "DEFAULT_NO_DESER" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0051.")
