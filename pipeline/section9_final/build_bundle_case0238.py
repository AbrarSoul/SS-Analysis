"""
Section 9 ground-truth test bundle: CASE-0238
(nocodb/nocodb, packages/nocodb/src/lib/dataMapper/lib/sql/BaseModelSql.ts
extractCsvData, CVE-2022-22121, CWE-1236 CSV injection).

Core vulnerable mechanism: `extractCsvData` turns table rows into a CSV
download with `Papaparse.unparse({ fields, data: csvRows })` and no escaping
options. A cell whose text starts with `=`, `+`, `-`, `@`, a tab or a carriage
return is written as is, so a spreadsheet program that opens the export
evaluates it as a formula (`=cmd|' /C calc'!A0`, `=HYPERLINK(...)`); an
attacker who can write to any table exports a payload into the CSV of anyone
who downloads it. The upstream fix passes `{ escapeFormulae: true }` as
Papaparse's second argument.

Measured caveat, kept in the manifest notes: `escapeFormulae` only exists from
papaparse 5.3.0; the real 5.1.1 and 5.2.0 packages silently ignore the option (the
cell comes out as `=1+1`), so the upstream fix depends on the papaparse version
installed by the dependency manifest, which is not part of this file. The safe
variant escapes the cells itself before calling unparse, so it does not depend on
the library version.

Sibling sites: `Papaparse.unparse` is called once in the file (extractCsvData).

Verification: the `Papaparse.unparse(...)` statement and the return of
`extractCsvData` are extracted verbatim from each full file, types stripped with
node:module.stripTypeScriptTypes and run against the REAL papaparse 5.3.2 with
`this.columns` stand-ins and rows containing formula-looking strings, a number
and a plain string; the CSV text is inspected.

Every variant is the FULL real file. `extractCsvData` is a public method called by
name from the controllers, so its name and signature are kept; the renamed variant
renames the local `data` and keeps the returned property name `data`.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0238"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


UNP = '''    const data = Papaparse.unparse({
      fields:
        fields &&
        fields.filter(
          f =>
            this.columns.some(c => c._cn === f) ||
            this.virtualColumns.some(c => c._cn === f)
        ),
      data: csvRows
    });
    return { data, offset, elapsed };
'''
assert original.count(UNP) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, UNP, '''    const csvText = Papaparse.unparse({
      fields:
        fields &&
        fields.filter(
          f =>
            this.columns.some(c => c._cn === f) ||
            this.virtualColumns.some(c => c._cn === f)
        ),
      data: csvRows
    });
    return { data: csvText, offset, elapsed };
''')
(CASE_DIR / "variant_vulnerable_01.ts").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, UNP, '''    const data = this.csvFromRows(fields, csvRows);
    return { data, offset, elapsed };
''')
v2 = swap(v2, "  public serializeCellValue({", '''  private csvFromRows(fields: any, csvRows: any[]): string {
    const wanted =
      fields &&
      fields.filter(
        f =>
          this.columns.some(c => c._cn === f) ||
          this.virtualColumns.some(c => c._cn === f)
      );
    return Papaparse.unparse({ fields: wanted, data: csvRows });
  }

  public serializeCellValue({''')
(CASE_DIR / "variant_vulnerable_02.ts").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, UNP, '''    const neutralised = csvRows.map(row =>
      Object.fromEntries(
        Object.entries(row).map(([key, value]) => [key, BaseModelSql.neutraliseFormula(value)])
      )
    );
    const data = Papaparse.unparse({
      fields:
        fields &&
        fields.filter(
          f =>
            this.columns.some(c => c._cn === f) ||
            this.virtualColumns.some(c => c._cn === f)
        ),
      data: neutralised
    });
    return { data, offset, elapsed };
''')
v3 = swap(v3, "  public serializeCellValue({", '''  // A spreadsheet treats a cell starting with = + - @ tab or CR as a formula: prefix such text with a quote.
  private static neutraliseFormula(value: any): any {
    return typeof value === 'string' && /^[=+\\-@\\t\\r]/.test(value)
      ? `'${value}`
      : value;
  }

  public serializeCellValue({''')
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

BENIGN = '''// Standalone example of the same shape: a CSV export whose columns are
// server-generated numbers only, so no cell can start with a formula character.
import Papaparse from 'papaparse';

export function exportCounters(counters: Record<string, number>): string {
    const rows = Object.entries(counters).map(([name, count]) => ({ name: name.replace(/[^a-z0-9_]/gi, '_'), count }));
    return Papaparse.unparse({ fields: ['name', 'count'], data: rows });
}
'''
(CASE_DIR / "benign_lookalike.ts").write_text(BENIGN)
