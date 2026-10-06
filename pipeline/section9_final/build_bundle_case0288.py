"""
Section 9 ground-truth test bundle: CASE-0288
(simplerisk/code, simplerisk/js/common.js checkAndSetValidation,
CVE-2021-4269, CWE-707/CWE-79 cross-site scripting).

Core vulnerable mechanism: `checkAndSetValidation` validates a form's
required fields client-side and, for each empty one, builds an error message
by substituting the field's `title` attribute into a language string
(`field_required_lang.replace("_XXX_", issue_el.attr("title"))`) and passes
it to `showAlertFromMessage`, which hands it to toastr -- a notification
library that renders the message string AS HTML. A `title` containing
markup (e.g. a field whose title is server-rendered from user-controlled
data such as a custom field label or a risk/asset name, or an element an
attacker managed to inject) therefore becomes live HTML in the victim's
browser: `<img src=x onerror=...>` runs script. The upstream fix HTML-
escapes the title first (`$("<div/>").text(title).html()`).

Sibling sites: this is the only place in the function (and the only
`_XXX_` substitution shown in the changed hunk) where an attribute value
is inserted into a toastr message.

Verification: each full file's `checkAndSetValidation` (plus any helper
function defined directly after it) is extracted verbatim and run in a REAL
jsdom document with REAL jQuery (the page's `$`); `field_required_lang` and
`showAlertFromMessage` (a recorder) are stand-ins. A required, empty input
with `title='<img src=x onerror=alert(1)>'` is validated; the recorded
message is then parsed as HTML by jsdom (`div.innerHTML = message`) and the
number of `<img>` elements produced is counted (toastr renders messages as
HTML, so an element appearing means injected markup executes). A benign
title (`Name`) must appear as plain text in every variant.

Every variant is the FULL real file. `checkAndSetValidation` is called by
name from form-submit handlers throughout the app, so its name/signature are
kept.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0288"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


MSG = '''            var message = field_required_lang.replace("_XXX_", issue_el.attr("title"))
            showAlertFromMessage(message, false)
'''
assert original.count(MSG) == 1

# --- Variant 1: renamed vulnerable variant ---
s = original.index("function checkAndSetValidation(container)")
e = original.index("\n}\n", s) + 3
F = original[s:e]
import re
f1 = re.sub(r"\bissue_els\b", "invalid_fields", F)
f1 = re.sub(r"\bissue_el\b", "field", f1)
f1 = re.sub(r"\bmessage\b", "alert_text", f1)
f1 = f1.replace("var error_messages = [];", "var field_errors = [];")
assert f1 != F
(CASE_DIR / "variant_vulnerable_01.js").write_text(original.replace(F, f1))

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, MSG, '''            showAlertFromMessage(buildRequiredMessage(issue_el), false)
''')
v2 = v2.replace(F.replace(MSG, '''            showAlertFromMessage(buildRequiredMessage(issue_el), false)
'''), F.replace(MSG, '''            showAlertFromMessage(buildRequiredMessage(issue_el), false)
''') + '''
function buildRequiredMessage(issue_el)
{
    return field_required_lang.replace("_XXX_", issue_el.attr("title"))
}
''') if False else v2
f2s = v2.index("function checkAndSetValidation(container)")
f2e = v2.index("\n}\n", f2s) + 3
v2 = v2[:f2e] + '''
function buildRequiredMessage(issue_el)
{
    return field_required_lang.replace("_XXX_", issue_el.attr("title"))
}
''' + v2[f2e:]
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, MSG, '''            var message = field_required_lang.replace("_XXX_", escapeHtmlText(issue_el.attr("title")))
            showAlertFromMessage(message, false)
''')
f3s = v3.index("function checkAndSetValidation(container)")
f3e = v3.index("\n}\n", f3s) + 3
v3 = v3[:f3e] + '''
function escapeHtmlText(value)
{
    return String(value === undefined || value === null ? "" : value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}
''' + v3[f3e:]
(CASE_DIR / "variant_safe_01.js").write_text(v3)

(CASE_DIR / "benign_lookalike.js").write_text('''// Standalone example of the same shape: substitute a label into a message
// that is written with .text() (never parsed as HTML), so markup in the
// label stays inert text.
function showFieldHint(container, label)
{
    var message = "Please fill in _XXX_".replace("_XXX_", label);
    $(container).find(".hint").text(message);
}
''')
