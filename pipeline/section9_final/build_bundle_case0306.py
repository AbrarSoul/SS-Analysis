"""
Section 9 ground-truth test bundle: CASE-0306
(totaljs/cms, themes/admin/public/ui.js COMPONENT('grid') self.redraw,
CVE-2019-10260, CWE-22/CWE-79 stored cross-site scripting in the admin grid).

Core vulnerable mechanism: the CMS admin UI's data grid component builds each
table cell from the row data and inserts the resulting HTML string into the
DOM (`tbody.prepend(builder.join(''))`). For plain columns (no custom
`template`/`render`), the cell text is `val` -- the raw field value from the
row -- concatenated into markup with no HTML escaping. Administrators view
lists of records (pages, users, form submissions, widgets) whose fields can
be written by less-privileged or anonymous users (contact forms, page
titles, usernames, log entries): a value such as
`<img src=x onerror=alert(document.cookie)>` becomes live markup in the
admin's browser (stored XSS in the highest-privileged context of the CMS).
The upstream fix wraps the plain-value branch in `Thelpers.encode(...)`.

Sibling sites: columns that define their own `template` or `render`
function deliberately return trusted markup and are not touched by the fix;
the plain-value branch of this one expression is the site.

Verification: each full file's `self.redraw` function is extracted verbatim
and run in a Node vm with stand-ins for the jComponent context it closes
over (`options` with one row/one plain column, `tbody`/`container` recorders,
`self.template` returning the cell value) and for `Thelpers.encode` (a
standard HTML-escaper; the real helper lives elsewhere in the framework,
outside this file). The HTML the grid would insert is captured and parsed by
a REAL jsdom document: the row `{name: '<img src=x onerror=alert(1)>'}` must
not yield an `<img>` element, and a benign row `{name: 'Alice'}` must render
the text `Alice`.

Every variant is the FULL real file. `redraw` is called by name by the
component's data-binding code, so its name is kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0306"
original = (CASE_DIR / "vulnerable_source.js").read_text()
patched = (CASE_DIR / "patched_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


VAL = "\t\t\t\tvar val = items[i][column.name];\n"
LINE = ("\t\t\t\tm.value = column.template ? column.template(items[i], column) : column.render ? "
        "column.render(val, column, items[i]) : val == null ? '' : (column.format ? val.format(column.format) : val);\n")
assert original.count(VAL) == 1 and original.count(LINE) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, VAL, "\t\t\t\tvar cell = items[i][column.name];\n")
v1 = swap(v1, LINE, ("\t\t\t\tm.value = column.template ? column.template(items[i], column) : column.render ? "
                     "column.render(cell, column, items[i]) : cell == null ? '' : (column.format ? cell.format(column.format) : cell);\n"))
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, LINE, ("\t\t\t\tvar plain = val == null ? '' : (column.format ? val.format(column.format) : val);\n"
                           "\t\t\t\tm.value = column.template ? column.template(items[i], column) : column.render ? "
                           "column.render(val, column, items[i]) : plain;\n"))
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file, encode in a local) ---
PLINE = ("\t\t\t\tm.value = column.template ? column.template(items[i], column) : column.render ? "
         "column.render(val, column, items[i]) : val == null ? '' : Thelpers.encode((column.format ? val.format(column.format) : val));\n")
assert patched.count(PLINE) == 1
v3 = swap(patched, PLINE, ("\t\t\t\tvar plain = val == null ? '' : Thelpers.encode(column.format ? val.format(column.format) : val);\n"
                           "\t\t\t\tm.value = column.template ? column.template(items[i], column) : column.render ? "
                           "column.render(val, column, items[i]) : plain;\n"))
(CASE_DIR / "variant_safe_01.js").write_text(v3)

(CASE_DIR / "benign_lookalike.js").write_text('''// Standalone example of the same shape: build a grid cell from a value the
// application itself computed (a row number), never from user-controlled
// text, so unescaped interpolation has nothing hostile to carry.
function rowNumberCell(index) {
	return '<td class="num">' + (index + 1) + '</td>';
}

module.exports = rowNumberCell;
''')
