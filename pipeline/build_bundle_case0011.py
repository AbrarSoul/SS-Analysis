"""
Section 9 ground-truth test bundle: CASE-0011
(FasterXML/jackson-databind, CVE-2020-24616, CWE-502 -- deserialization of
untrusted data).

Core vulnerable mechanism: SubTypeValidator maintains a hardcoded denylist
(DEFAULT_NO_DESER_CLASS_NAMES, built by repeated s.add(...) calls in a
static initializer) of known-dangerous "gadget" classes that
validateSubType() rejects during polymorphic deserialization. A class NOT
on this list, and not otherwise caught by the Spring/c3p0 heuristics, is
silently allowed through (see validateSubType(), unchanged by this patch).
The vulnerable state is simply that "br.com.anteros.dbcp.
AnterosDBCPDataSource" (a known RCE gadget) is missing from the list --
this is a data-completeness vulnerability, not a single dangerous call.

All transformations are scoped to the static initializer block (lines
31-204) to avoid touching the ~90 unrelated denylist entries elsewhere in
the file.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0011"
original_lines = (CASE_DIR / "vulnerable_source.java").read_text().splitlines(keepends=True)

assert original_lines[30] == "    static {\n"
assert original_lines[31] == "        Set<String> s = new HashSet<String>();\n"
assert original_lines[203] == "    }\n"
assert original_lines[139] == "        // [databind#2634]: ibatis-sqlmap, anteros-core\n"
assert original_lines[140] == '        s.add("com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig");\n'
assert original_lines[141] == '        s.add("br.com.anteros.dbcp.AnterosDBCPConfig");\n'
assert original_lines[202] == "        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);\n"

original = "".join(original_lines)
ANTEROS_DATASOURCE = "br.com.anteros.dbcp.AnterosDBCPDataSource"
assert ANTEROS_DATASOURCE not in original, "sanity check: should be genuinely missing in the vulnerable source"

# --- Variant 1: renamed vulnerable variant ---
# Rename the local variable s -> denylist throughout the static block
# only (skipping the one comment on the "version(s))" line that is not the
# variable). Same exact vulnerability: AnterosDBCPDataSource still missing.
STATIC_BLOCK_START, STATIC_BLOCK_END = 30, 204  # 0-indexed slice bounds


def rename_s_in_block(lines):
    out = []
    for line in lines:
        if line.strip().startswith("//"):
            out.append(line)
        else:
            out.append(re.sub(r"\bs\b", "denylist", line))
    return out


renamed_block = rename_s_in_block(original_lines[STATIC_BLOCK_START:STATIC_BLOCK_END])
renamed_source = "".join(original_lines[:STATIC_BLOCK_START] + renamed_block + original_lines[STATIC_BLOCK_END:])
assert renamed_source != original
assert "Set<String> denylist = new HashSet<String>();" in renamed_source
assert "denylist.add(\"br.com.anteros.dbcp.AnterosDBCPConfig\");" in renamed_source
assert "DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(denylist);" in renamed_source
assert ANTEROS_DATASOURCE not in renamed_source
(CASE_DIR / "variant_vulnerable_01.java").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: wrapper-function introduction -- the anteros-related entries
# are populated via a small private static helper method invoked from the
# static block, instead of inline s.add() calls. Same exact vulnerability
# (still missing AnterosDBCPDataSource), no renaming.
old_anteros_lines = (
    '        // [databind#2634]: ibatis-sqlmap, anteros-core\n'
    '        s.add("com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig");\n'
    '        s.add("br.com.anteros.dbcp.AnterosDBCPConfig");\n'
)
assert old_anteros_lines in original
new_anteros_lines = (
    '        // [databind#2634]: ibatis-sqlmap, anteros-core\n'
    '        addIbatisAndAnterosEntries(s);\n'
)
structural_source = original.replace(old_anteros_lines, new_anteros_lines)
assert structural_source != original
helper_method = (
    '\n'
    '    private static void addIbatisAndAnterosEntries(Set<String> s) {\n'
    '        s.add("com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig");\n'
    '        s.add("br.com.anteros.dbcp.AnterosDBCPConfig");\n'
    '    }\n'
)
# insert the helper method right after the static block's closing brace
static_block_close = "        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);\n    }\n"
assert static_block_close in structural_source
structural_source = structural_source.replace(static_block_close, static_block_close + helper_method, 1)
assert "addIbatisAndAnterosEntries" in structural_source
assert ANTEROS_DATASOURCE not in structural_source
(CASE_DIR / "variant_vulnerable_02.java").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Adds the real fix's missing denylist entry (AnterosDBCPDataSource), but
# appended at the end of the static block via s.addAll(Arrays.asList(...))
# instead of a single s.add(...) call placed next to the anteros-core
# comment like the real patch -- same security property, materially
# different location/mechanism, not byte-identical to the known fix.
safe_source = original.replace(
    "        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);\n    }\n",
    '        // additional gadget classes closing known deserialization gaps\n'
    '        s.addAll(Arrays.asList("br.com.anteros.dbcp.AnterosDBCPDataSource"));\n'
    '\n'
    '        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(s);\n    }\n',
    1,
)
assert safe_source != original
assert ANTEROS_DATASOURCE in safe_source
# needs java.util.Arrays imported
safe_source = safe_source.replace("import java.util.HashSet;\n", "import java.util.Arrays;\nimport java.util.HashSet;\n", 1)
assert "import java.util.Arrays;" in safe_source
(CASE_DIR / "variant_safe_01.java").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a second, unrelated
# Set<String> built the same textual way (repeated .add() calls in a
# static-like block) but used only for non-security diagnostic/logging
# purposes -- omitting an entry from THIS set has no security consequence,
# unlike DEFAULT_NO_DESER_CLASS_NAMES. Tests whether a rule over-fires on
# any Set<String> built via .add() calls missing a specific string,
# regardless of whether that set is actually used as a security denylist.
BENIGN_ADDITION = (
    '\n'
    '    /**\n'
    '     * Class names to mention in verbose debug logging only -- NOT used for\n'
    '     * any security decision, unlike DEFAULT_NO_DESER_CLASS_NAMES above.\n'
    '     */\n'
    '    protected final static Set<String> VERBOSE_LOG_CLASS_NAMES;\n'
    '    static {\n'
    '        Set<String> names = new HashSet<String>();\n'
    '        names.add("com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig");\n'
    '        names.add("br.com.anteros.dbcp.AnterosDBCPConfig");\n'
    '        VERBOSE_LOG_CLASS_NAMES = Collections.unmodifiableSet(names);\n'
    '    }\n'
)
anchor = "    protected Set<String> _cfgIllegalClassNames = DEFAULT_NO_DESER_CLASS_NAMES;\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "VERBOSE_LOG_CLASS_NAMES" in benign_source
(CASE_DIR / "benign_lookalike.java").write_text(benign_source)

print("Wrote 4 new samples for CASE-0011.")
