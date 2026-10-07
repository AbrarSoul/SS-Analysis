"""
Section 9 ground-truth test bundle: CASE-0028
(kanaka/noVNC, CVE-2013-7436, CWE-310 -- cryptographic issue / missing
Secure cookie flag).

Core vulnerable mechanism: createCookie() sets document.cookie with no
"Secure" attribute, even when the page is served over HTTPS. Without
Secure, the browser will also send the cookie over a subsequent plain-HTTP
request to the same host (e.g. a mixed-content redirect or protocol
downgrade), exposing it to network eavesdroppers.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0028"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = (
    "WebUtil.createCookie = function(name,value,days) {\n"
    "    var date, expires;\n"
    "    if (days) {\n"
    "        date = new Date();\n"
    "        date.setTime(date.getTime()+(days*24*60*60*1000));\n"
    "        expires = \"; expires=\"+date.toGMTString();\n"
    "    }\n"
    "    else {\n"
    "        expires = \"\";\n"
    "    }\n"
    "    document.cookie = name+\"=\"+value+expires+\"; path=/\";\n"
    "};\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

# --- Variant 1: renamed vulnerable variant ---
# Rename the function createCookie -> setPersistentCookie (definition +
# its one in-file call site), and locals date/expires -> expiryDate/
# expiresClause. Same exact vulnerability: still no Secure attribute.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    "WebUtil.setPersistentCookie = function(name,value,days) {\n"
    "    var expiryDate, expiresClause;\n"
    "    if (days) {\n"
    "        expiryDate = new Date();\n"
    "        expiryDate.setTime(expiryDate.getTime()+(days*24*60*60*1000));\n"
    "        expiresClause = \"; expires=\"+expiryDate.toGMTString();\n"
    "    }\n"
    "    else {\n"
    "        expiresClause = \"\";\n"
    "    }\n"
    "    document.cookie = name+\"=\"+value+expiresClause+\"; path=/\";\n"
    "};\n",
)
renamed_source = renamed_source.replace(
    'WebUtil.createCookie(name,"",-1);', 'WebUtil.setPersistentCookie(name,"",-1);'
)
assert renamed_source != original
assert "WebUtil.setPersistentCookie = function" in renamed_source
assert "WebUtil.createCookie" not in renamed_source
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: equivalent conditional rewriting -- the if/else is
# collapsed into a ternary. Same exact vulnerability (still no Secure
# attribute), no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    "WebUtil.createCookie = function(name,value,days) {\n"
    "    var date = days ? new Date() : null;\n"
    "    var expires = days ? (function() {\n"
    "        date.setTime(date.getTime()+(days*24*60*60*1000));\n"
    "        return \"; expires=\"+date.toGMTString();\n"
    "    })() : \"\";\n"
    "    document.cookie = name+\"=\"+value+expires+\"; path=/\";\n"
    "};\n",
)
assert structural_source != original
assert "var date = days ? new Date() : null;" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (Secure attribute added when
# served over HTTPS) but built via a ternary expression appended directly
# into the cookie string, instead of the real patch's separate secure
# variable computed with an if/else block -- materially different
# structure, not byte-identical to the known fix.
safe_source = original.replace(
    VULNERABLE_BLOCK,
    "WebUtil.createCookie = function(name,value,days) {\n"
    "    var date, expires;\n"
    "    if (days) {\n"
    "        date = new Date();\n"
    "        date.setTime(date.getTime()+(days*24*60*60*1000));\n"
    "        expires = \"; expires=\"+date.toGMTString();\n"
    "    }\n"
    "    else {\n"
    "        expires = \"\";\n"
    "    }\n"
    "    document.cookie = name+\"=\"+value+expires+\"; path=/\"+\n"
    "        (document.location.protocol === \"https:\" ? \"; secure\" : \"\");\n"
    "};\n",
)
assert safe_source != original
assert '(document.location.protocol === "https:" ? "; secure" : "")' in safe_source
assert 'document.cookie = name+"="+value+expires+"; path=/";' not in safe_source
(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a function that also
# writes to document.cookie with no Secure attribute -- the same
# superficial API surface as the vulnerable line -- but the cookie holds
# only a non-sensitive UI preference (theme name), so exposure over a
# downgraded HTTP connection carries no meaningful security consequence.
BENIGN_ADDITION = (
    "\n"
    "WebUtil.setThemePreference = function(themeName) {\n"
    "    // Stores only a UI theme name (e.g. \"dark\"/\"light\"), never a\n"
    "    // session token or credential, so omitting Secure here carries no\n"
    "    // meaningful confidentiality risk, unlike the session cookie above.\n"
    "    document.cookie = \"theme=\"+themeName+\"; path=/\";\n"
    "};\n"
)
anchor = "WebUtil.createCookie = function(name,value,days) {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "setThemePreference" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)

print("Wrote 4 new samples for CASE-0028.")
