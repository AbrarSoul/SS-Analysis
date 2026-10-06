"""
Section 9 ground-truth test bundle: CASE-0253
(parallax/jsPDF, src/modules/javascript.js jsPDFAPI.addJS, CVE-2026-24040,
CWE-362 concurrent execution using a shared resource without synchronisation:
state shared between documents).

Core vulnerable mechanism: the `javascript` plugin declares
`var jsNamesObj, jsJsObj, text;` once at plugin scope. `addJS(javascript)`
stores its argument in the shared `text` and subscribes two callbacks that later
read `text`, `jsNamesObj` and `jsJsObj` when the document is serialised
(`postPutResources`, `putCatalog`). Because the variables belong to the plugin, not to
the document, every jsPDF instance in the process writes into and reads from the same
three variables: creating a second document and calling `addJS` on it overwrites the
first document's script before the first document is output, so the first PDF embeds
the SECOND document's JavaScript (and object ids from the wrong document). In a
server that builds PDFs for several users this puts one user's embedded script into
another user's PDF. The upstream fix moves the three variables inside `addJS`, so each
call has its own state.

Sibling sites: the plugin has no other function using the shared variables.

Verification: the real `jspdf` 2.5.1 package (`jspdf.node.js`) is loaded; the
plugin body of each full variant (from `(function(jsPDFAPI) {` to `})(jsPDF.API);`, the
ES import line removed) is evaluated against the REAL `jsPDF.API`, which replaces `addJS`;
two real documents are created, `addJS('FIRST-DOC-JS')` and
`addJS('SECOND-DOC-JS')` are called, and both documents are output. The PDF text is
searched for each script.

Every variant is the FULL real file. `addJS` is public jsPDF API called by name, so its
name and parameter are kept; the renamed variant renames the shared variables.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0253"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


import re

# --- Variant 1: renamed vulnerable variant ---
s = original.index("  var jsNamesObj, jsJsObj, text;")
e = original.index("})(jsPDF.API);")
seg = original[s:e]
for a, b in (("jsNamesObj", "namesObjId"), ("jsJsObj", "jsObjId"), ("text", "scriptText")):
    seg = re.sub(r"\b%s\b" % a, b, seg)
assert "var namesObjId, jsObjId, scriptText;" in seg and "scriptText = javascript;" in seg
seg = seg.replace('"/JS (" + scriptText + ")"', '"/JS (" + scriptText + ")"')
(CASE_DIR / "variant_vulnerable_01.js").write_text(original[:s] + seg + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, "  jsPDFAPI.addJS = function(javascript) {\n    text = javascript;\n", '''  jsPDFAPI.addJS = function(javascript) {
    remember(javascript);
''')
v2 = swap(v2, "  /**\n   * @name addJS", '''  function remember(javascript) {
    text = javascript;
  }
  /**
   * @name addJS''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, "  var jsNamesObj, jsJsObj, text;\n", "")
v3 = swap(v3, "    text = javascript;\n    this.internal.events.subscribe(\"postPutResources\", function() {\n", '''    // per-call state: nothing is shared between documents or between addJS calls
    var state = { namesObj: undefined, jsObj: undefined, text: javascript };
    this.internal.events.subscribe("postPutResources", function() {
''')
v3 = v3.replace("      jsNamesObj = this.internal.newObject();", "      state.namesObj = this.internal.newObject();")
v3 = v3.replace('(jsNamesObj + 1)', '(state.namesObj + 1)')
v3 = v3.replace("      jsJsObj = this.internal.newObject();", "      state.jsObj = this.internal.newObject();")
v3 = v3.replace('"/JS (" + text + ")"', '"/JS (" + state.text + ")"')
v3 = v3.replace("if (jsNamesObj !== undefined && jsJsObj !== undefined) {", "if (state.namesObj !== undefined && state.jsObj !== undefined) {")
v3 = v3.replace('"/Names <</JavaScript " + jsNamesObj + " 0 R>>"', '"/Names <</JavaScript " + state.namesObj + " 0 R>>"')
for leftover in ("jsNamesObj", "jsJsObj", " text "):
    assert leftover not in v3.split("jsPDFAPI.addJS")[1], leftover
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = '''// Standalone example of the same shape: a plugin-level constant that is only
// READ by every document (a default page label) and never written per document.
(function(API) {
  var DEFAULT_LABEL = "Page";
  API.pageLabel = function(n) {
    return DEFAULT_LABEL + " " + n;
  };
})(typeof jsPDF !== "undefined" ? jsPDF.API : {});
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
