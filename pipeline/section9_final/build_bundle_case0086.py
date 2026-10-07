"""
Section 9 ground-truth test bundle: CASE-0086
(agenticmail/agenticmail, CVE-2026-47255, storage-API SQL access control).

Core vulnerable mechanism: `verifySqlAccess()` ownership-checks only the
tables returned by `extractTableRefs()`, which finds tables solely via a
`FROM|INTO|UPDATE|TABLE|JOIN <identifier>` regex. A comma-join such as
`SELECT * FROM agt_mine, agt_victim` yields only `agt_mine`: the second
table is never ownership-checked, so an authenticated caller can read
another agent's storage table. The upstream fix adds a second scan for
every storage-table-shaped token anywhere in the query (agt_*, shared_*,
agenticmail_storage_meta), plus a separate HAVING-clause sanitizer.

Every variant is the FULL real file with extractTableRefs replaced (the
renamed variant also renames its call site in verifySqlAccess).
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0086"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.ts").read_text().splitlines()) + "\n"

START = "function extractTableRefs(sql: string): string[] {"
s = original.index(START)
e = original.index("\n}\n", s) + 3
BLOCK = original[s:e]
assert original.count(START) == 1
assert original.count("extractTableRefs(") == 2  # declaration + one call site


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK
for old, new in (("extractTableRefs", "collectReferencedTables"), ("sql", "statement"), ("refs", "found"),
                 ("refPattern", "tablePattern"), ("match", "hit")):
    b = re.sub(r"\b%s\b" % old, new, b)
renamed = build(b)
renamed = re.sub(r"\bextractTableRefs\b", "collectReferencedTables", renamed)
assert "extractTableRefs" not in renamed and renamed.count("collectReferencedTables(") == 2
(CASE_DIR / "variant_vulnerable_01.ts").write_text(renamed)

# --- Variant 2: structurally changed vulnerable variant ---
(CASE_DIR / "variant_vulnerable_02.ts").write_text(build("""function extractTableRefs(sql: string): string[] {
  const refPattern = /\\b(?:FROM|INTO|UPDATE|TABLE|JOIN)\\s+["`[]?([A-Za-z_][A-Za-z0-9_]{0,63})["`\\]]?/gi;
  const names = Array.from(sql.matchAll(refPattern), (m) => m[1]);
  return [...new Set(names)];
}
"""))

# --- Variant 3: transformed safe variant ---
# Comma-join aware parsing of each FROM clause (every comma-separated item
# contributes its table), on top of the original keyword scan. Different
# mechanism from upstream's "any storage-shaped token anywhere" backstop.
(CASE_DIR / "variant_safe_01.ts").write_text(build("""function extractTableRefs(sql: string): string[] {
  const refs = new Set<string>();
  const refPattern = /\\b(?:FROM|INTO|UPDATE|TABLE|JOIN)\\s+["`[]?([A-Za-z_][A-Za-z0-9_]{0,63})["`\\]]?/gi;
  for (const match of sql.matchAll(refPattern)) refs.add(match[1]);
  // A FROM clause may list several tables separated by commas; every item
  // is a table reference that needs an ownership check.
  const fromClausePattern = /\\bFROM\\s+([^;]*?)(?=\\bWHERE\\b|\\bGROUP\\b|\\bORDER\\b|\\bHAVING\\b|\\bLIMIT\\b|\\bUNION\\b|\\bJOIN\\b|\\)|;|$)/gis;
  for (const clause of sql.matchAll(fromClausePattern)) {
    for (const item of clause[1].split(',')) {
      const ident = item.trim().match(/^["`[]?([A-Za-z_][A-Za-z0-9_]{0,63})/);
      if (ident) refs.add(ident[1]);
    }
  }
  return [...refs];
}
"""))

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.ts").write_text("""/**
 * Same FROM/JOIN keyword scan as a table-reference extractor, but used only
 * to label a query in a metrics counter. Missing a comma-joined table here
 * only makes a dashboard label less complete; no authorization decision
 * depends on the result.
 */
export function tablesForMetricsLabel(sql: string): string {
  const refPattern = /\\b(?:FROM|INTO|UPDATE|TABLE|JOIN)\\s+["`[]?([A-Za-z_][A-Za-z0-9_]{0,63})["`\\]]?/gi;
  const names = new Set<string>();
  for (const match of sql.matchAll(refPattern)) names.add(match[1]);
  return [...names].sort().join('+') || 'unknown';
}
""")
print("Wrote 4 new samples for CASE-0086.")
