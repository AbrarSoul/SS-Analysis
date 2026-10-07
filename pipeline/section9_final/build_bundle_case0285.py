"""
Section 9 ground-truth test bundle: CASE-0285
(sequelize/sequelize, lib/sql-string.js SqlString.escape, CVE-2016-10554,
CWE-89 SQL injection).

Core vulnerable mechanism: `SqlString.escape(val, stringifyObjects,
timeZone, dialect)` quotes string values for interpolation into SQL. It has
two escaping strategies: for `postgres` it doubles single quotes
(`'` -> `''`, correct for standard SQL); for every OTHER dialect it uses
MySQL-style backslash escaping (`'` -> `\'`). SQLite follows standard SQL
string rules -- a backslash is an ordinary character inside a string
literal and does NOT escape the following quote -- so under the `sqlite`
dialect a value like `' OR 1=1 --` becomes `'\' OR 1=1 --'`, in which the
`\'` still terminates the string literal and the rest (`OR 1=1`, then a
`--` comment swallowing the closing quote) is parsed as SQL: classic
injection. The upstream fix routes `sqlite` through the same
quote-doubling branch as `postgres`.

Sibling sites: `escape` is the one function choosing an escaping strategy
by dialect; `escapeId` (identifier quoting) is a separate function and out
of scope.

Verification: each full file is loaded as a REAL Node module (`require`;
it only uses `Buffer` and its own exports) and its `escape` output for the
payload `' OR 1=1 --` under the `sqlite` dialect is interpolated into a
query executed on a REAL in-memory SQLite database via Node's built-in
`node:sqlite`: `SELECT name FROM t WHERE name = <escaped>` over a table with
two rows; the number of rows returned shows whether the injection succeeded.
A benign value (`alice`) must return exactly one row in every variant.

Every variant is the FULL real file. `SqlString.escape` is the library's
exported API, so its name/signature are kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0285"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


s = original.index("SqlString.escape = function(val, stringifyObjects, timeZone, dialect) {")
e = original.index("\n};\n", s) + 4
FUNC = original[s:e]

# --- Variant 1: renamed vulnerable variant ---
f1 = FUNC.replace("function(val, stringifyObjects, timeZone, dialect)", "function(value, stringifyObjects, timeZone, dialect)")
f1 = re.sub(r"\bval\b", "value", f1)
f1 = swap(f1, "function(s) {\n      switch(s) {", "function(ch) {\n      switch(ch) {")
f1 = f1.replace('default: return "\\\\"+s;', 'default: return "\\\\"+ch;')
assert '"+s;' not in f1
(CASE_DIR / "variant_vulnerable_01.js").write_text(original.replace(FUNC, f1))

# --- Variant 2: structurally changed vulnerable variant ---
old_tail = FUNC[FUNC.index('  if (dialect == "postgres") {'):]
new_tail = '''  return "'" + SqlString.escapeString(val, dialect) + "'";
};

SqlString.escapeString = function(val, dialect) {
  if (dialect == "postgres") {
    // http://www.postgresql.org/docs/8.2/static/sql-syntax-lexical.html#SQL-SYNTAX-STRINGS
    return val.replace(/'/g, "''");
  }
  return val.replace(/[\\0\\n\\r\\b\\t\\\\\\'\\"\\x1a]/g, function(s) {
    switch(s) {
      case "\\0": return "\\\\0";
      case "\\n": return "\\\\n";
      case "\\r": return "\\\\r";
      case "\\b": return "\\\\b";
      case "\\t": return "\\\\t";
      case "\\x1a": return "\\\\Z";
      default: return "\\\\"+s;
    }
  });
};
'''
f2 = FUNC.replace(old_tail, new_tail)
(CASE_DIR / "variant_vulnerable_02.js").write_text(original.replace(FUNC, f2))

# --- Variant 3: transformed safe variant ---
f3 = swap(FUNC, '  if (dialect == "postgres") {\n    // http://www.postgresql.org/docs/8.2/static/sql-syntax-lexical.html#SQL-SYNTAX-STRINGS\n',
          '  if (SINGLE_QUOTE_DIALECTS.indexOf(dialect) !== -1) {\n    // standard-SQL string literals: only the single quote is special, doubled\n')
f3 = "var SINGLE_QUOTE_DIALECTS = [\"postgres\", \"sqlite\"];\n\n" + f3
(CASE_DIR / "variant_safe_01.js").write_text(original.replace(FUNC, f3))

(CASE_DIR / "benign_lookalike.js").write_text('''// Standalone example of the same shape: choose a display quoting style per
// output format for a label shown in a CLI table (not SQL, never executed).
function quoteLabel(label, format) {
  if (format === "markdown") {
    return "`" + label.replace(/`/g, "'") + "`";
  }
  return '"' + label.replace(/"/g, '\\\\"') + '"';
}

module.exports = { quoteLabel };
''')
