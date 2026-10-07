"""
Section 9 ground-truth test bundle: CASE-0198
(jgraph/mxgraph, javascript/examples/grapheditor/www/js/Dialogs.js the Apply
button handler of ColorDialog, CVE-2019-13127, CWE-20 / CWE-79).

Core vulnerable mechanism: the ColorDialog's Apply handler reads free text from
the colour input (`var color = input.value;`), remembers it in the recent-colour
list (`ColorDialog.addRecentColor(color, 12)`) and, after prefixing a `#`,
passes it to `applyFunction(color)` WITHOUT checking that it is a colour.
Whatever the user typed (or a crafted shared diagram/preset supplies) ends up
in a cell style string and later in HTML/CSS, e.g. `red;background:url(//x)` or
`"><img src=x onerror=alert(1)>`. The upstream fix validates the text with a hex
regex before doing anything.

Measured caveat, kept in the manifest notes: upstream's regex
`/(^#?[0-9A-F]{6}$)|(^#[0-9A-F]{3}$)/i` no longer accepts the literal value
`none`, which the original handler explicitly supported (the dialog even
sets `input.value = 'none'`), so after the patch "no colour" can no longer be
applied. The safe variant validates the same way but keeps `none`.

Sibling sites: none checked in this 2,600-line file beyond the ColorDialog
handler (other colour inputs use the same dialog).

Verification: the Apply handler's function body is extracted and executed in
node with stand-ins for `mxUtils.button`, `ColorDialog.addRecentColor`,
`applyFunction`, `editorUi.hideDialog` and the input element; the rest of the
file needs the browser and the mxGraph runtime.

Every variant is the FULL real file. The handler is an anonymous function
passed to mxUtils.button, so the renamed variant renames its locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0198"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

HANDLER = '''\tvar applyBtn = mxUtils.button(mxResources.get('apply'), function()
\t{
\t\tvar color = input.value;
\t\tColorDialog.addRecentColor(color, 12);
\t\t
\t\tif (color != 'none' && color.charAt(0) != '#')
\t\t{
\t\t\tcolor = '#' + color;
\t\t}

\t\tapplyFunction(color);
\t\teditorUi.hideDialog();
\t});
'''
assert original.count(HANDLER) == 1


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, HANDLER, HANDLER.replace("var color = input.value;", "var entered = input.value;")
          .replace("addRecentColor(color, 12)", "addRecentColor(entered, 12)")
          .replace("if (color != 'none' && color.charAt(0) != '#')", "if (entered != 'none' && entered.charAt(0) != '#')")
          .replace("\t\t\tcolor = '#' + color;", "\t\t\tentered = '#' + entered;")
          .replace("applyFunction(color);", "applyFunction(entered);"))
assert "color" not in v1[v1.index("var entered"):v1.index("var entered") + 380].replace("addRecentColor", "").replace("Color", "")
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, HANDLER, '''\tvar applyBtn = mxUtils.button(mxResources.get('apply'), function()
\t{
\t\tvar color = input.value;
\t\tColorDialog.addRecentColor(color, 12);
\t\t
\t\tcolor = (color == 'none' || color.charAt(0) == '#') ? color : '#' + color;

\t\tapplyFunction(color);
\t\teditorUi.hideDialog();
\t});
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# The text is normalised by a small function that returns null unless it is
# `none` or a 3/6-digit hex colour (with or without `#`); nothing is stored or
# applied for invalid input. Upstream's regex rejects `none` as well.
v3 = swap(original, HANDLER, '''\tvar applyBtn = mxUtils.button(mxResources.get('apply'), function()
\t{
\t\tvar color = ColorDialog.normalizeColor(input.value);
\t\t
\t\tif (color != null)
\t\t{
\t\t\tColorDialog.addRecentColor(color, 12);
\t\t\tapplyFunction(color);
\t\t}

\t\teditorUi.hideDialog();
\t});
''')
v3 = swap(v3, "ColorDialog.addRecentColor = function(color, max)\n", '''ColorDialog.normalizeColor = function(text)
{
\tvar value = (text == null) ? '' : String(text).trim();

\tif (value == 'none')
\t{
\t\treturn value;
\t}

\tvar match = /^#?([0-9a-f]{6}|[0-9a-f]{3})$/i.exec(value);

\treturn (match != null) ? '#' + match[1] : null;
};

ColorDialog.addRecentColor = function(color, max)
''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''"use strict";

var PALETTE = ['#000000', '#ffffff', '#ff0000', '#00ff00', '#0000ff'];

/**
 * Same "apply a colour then close the dialog" shape as the dialog handler,
 * but the colour comes from a FIXED palette by index, never from typed text,
 * so there is nothing to validate or inject.
 */
function applyPaletteColor(index, applyFunction, hideDialog) {
  var color = PALETTE[index];
  if (color != null) {
    applyFunction(color);
  }
  hideDialog();
}

module.exports = { applyPaletteColor: applyPaletteColor };
'''
assert "FIXED palette" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0198.")
