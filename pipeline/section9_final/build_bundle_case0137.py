"""
Section 9 ground-truth test bundle: CASE-0137
(cryptpad/cryptpad, www/bounce/main.js, CVE-2025-49590, CWE-692 incomplete
denylist to cross-site scripting).

Located target: the module's whole AMD factory
`define(['/api/config'], function (ApiConfig) {...})` (locator confidence
auto_low_confidence; reviewed, it is the right and only unit).

Core vulnerable mechanism: the bounce page navigates to a URL taken from the
location hash. It shortcuts `if (target.host === host.host) { return void
go(); }` (and the docs.cryptpad.org shortcut) BEFORE the denylist of
dangerous schemes (`javascript:`, `vbscript:`, `data:`, `blob:`), which only
runs later inside the async translations callback. A URL such as
`javascript://<own-host>/%0Aalert(document.domain)` has `host` equal to the
instance's own host (non-special schemes still parse an authority), so it
takes the shortcut and `window.location.href = 'javascript://...'` runs
script in the bounce (sandbox) origin. The upstream fix moves both
shortcuts to AFTER the scheme denylist.

Every variant is the FULL real file. There are no in-file callers; the
factory is the module.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0137"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

LOCAL = '''    // Local URLs don't require any warning and can navigate directly without user input.
    if (target.host === host.host) { return void go(); }
'''
DOCS = '''    if (target.host === 'docs.cryptpad.org' && target.host.endsWith(host.host)) {
        return void go();
    }
'''
assert original.count(LOCAL) == 1 and original.count(DOCS) == 1
assert "['javascript:', 'vbscript:', 'data:', 'blob:']" in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


def rename_outside_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r"""('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")""", line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
v1 = rename_outside_strings(original, (("reject", "abort"), ("host", "ownOrigin"), ("target", "destination"),
                                       ("go", "navigate"), ("bounceTo", "hashUrl"), ("err", "error"),
                                       ("Messages", "Msgs"), ("question", "leaveQuestion"), ("answer", "agreed")))
assert "destination.host === ownOrigin.host" in v1 and "var navigate = function" in v1
assert "['javascript:', 'vbscript:', 'data:', 'blob:'].includes(destination.protocol)" in v1
assert "window.location.href = destination.href;" in v1 and "function (Msgs)" in v1
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, LOCAL + "\n", "")
v2 = swap(v2, DOCS, '''    var trusted = target.host === host.host ||
        (target.host === 'docs.cryptpad.org' && target.host.endsWith(host.host));
    if (trusted) { return void go(); }
''')
assert v2.count("go()") == original.count("go()") - 1
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# A positive allow-list of schemes (http/https) is enforced BEFORE any
# navigation, including the local-URL shortcut. (Upstream keeps the
# javascript:/vbscript:/data:/blob: denylist and just moves the shortcuts
# after it; this variant is stricter and also refuses e.g. file: and ftp:.)
v3 = swap(original, LOCAL, '''    // Only web URLs may be navigated to at all; refuse every other scheme before any shortcut.
    if (!['http:', 'https:'].includes(target.protocol)) {
        window.alert('The bounce application only navigates to http(s) URLs');
        return void reject();
    }

''' + LOCAL)
assert v3.index("only navigates to http(s) URLs") < v3.index("target.host === host.host")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''"use strict";

/**
 * Same "if the target host equals our own host, navigate directly" shortcut,
 * but it is only taken for http(s) URLs whose scheme has been validated FIRST,
 * so a javascript:, data: or blob: URL that merely carries our host name in
 * its authority can never reach the shortcut.
 */
function canNavigateDirectly(target, ownHost) {
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    return false;
  }
  return target.host === ownHost.host;
}

module.exports = { canNavigateDirectly: canNavigateDirectly };
'''
assert "target.protocol !== \"http:\"" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0137.")
