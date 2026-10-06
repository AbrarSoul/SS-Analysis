r"""
Section 9 ground-truth test bundle: CASE-0239
(npm/hosted-git-info, index.js fromUrl, CVE-2021-23362, CWE-1333 regular
expression denial of service).

Core vulnerable mechanism: `fromUrl` splits a git URL with
`new RegExp('^([^:]+):(?:(?:[^@:]+(?:[^@]+)?@)?([^/]*))[/](.+?)(?:[.]git)?($|#)')`.
The optional group `[^@:]+(?:[^@]+)?@` contains two adjacent, overlapping
unbounded quantifiers over almost the same character class; when the input has
a long run of such characters and no `@` the engine tries every way to split the
run between them before giving up, so matching time grows quadratically with the
length of an attacker-supplied URL string (an npm dependency spec, for example).
A 100,000-character `github:aaaa...` string keeps the process busy for seconds
and blocks the event loop. The upstream fix uses the linear regexp
`/^([^:]+):(?:[^@]+@)?(?:([^/]*)\/)?([^#]+)/` and strips a trailing `.git` from
the project afterwards.

Sibling sites: `fromUrl` builds this regexp once per call; `isGitHubShorthand` and
`parseGitUrl`'s `authmatch` regexp (`/[^@]+@[^:/]+/`) are single-quantifier and did
not change.

Verification: the vulnerable source is byte-identical to `index.js` of the real
hosted-git-info 2.8.8 package and the patched source to 2.8.9. Each full variant
replaces `index.js` in a copy of the real 2.8.8 package (whose `git-host.js` and
`git-host-info.js` are used unchanged) and `fromUrl('github:' + 'a'.repeat(N))`
is timed for N = 25,000 and 100,000, with a normal `github:user/repo.git` URL as a
control.

Every variant is the FULL real file. `fromUrl` is exported and called by name; only the
regexp and the lines that use its groups change. The renamed variant renames a local
of `fromUrl`.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0239"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


RE_LINE = "  var shortcutMatch = url.match(new RegExp('^([^:]+):(?:(?:[^@:]+(?:[^@]+)?@)?([^/]*))[/](.+?)(?:[.]git)?($|#)'))\n"
assert original.count(RE_LINE) == 1

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, RE_LINE, "  var shortcutParts = url.match(new RegExp('^([^:]+):(?:(?:[^@:]+(?:[^@]+)?@)?([^/]*))[/](.+?)(?:[.]git)?($|#)'))\n")
v1 = v1.replace("shortcutMatch", "shortcutParts")
assert "shortcutMatch" not in v1
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, RE_LINE, "  var shortcutMatch = url.match(SHORTCUT_URL)\n")
v2 = swap(v2, "function fromUrl (giturl, opts) {", '''var SHORTCUT_URL = new RegExp('^([^:]+):(?:(?:[^@:]+(?:[^@]+)?@)?([^/]*))[/](.+?)(?:[.]git)?($|#)')

function fromUrl (giturl, opts) {''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Linear regexp compiled once at module level (upstream builds it inline in fromUrl), with the
# same group layout, and the trailing .git stripped from the project afterwards.
v3 = swap(original, RE_LINE, "  var shortcutMatch = url.match(SHORTCUT_URL)\n")
v3 = swap(v3, "function fromUrl (giturl, opts) {", '''var SHORTCUT_URL = /^([^:]+):(?:[^@]+@)?(?:([^/]*)\\/)?([^#]+)/

function fromUrl (giturl, opts) {''')
v3 = swap(v3, "        project = decodeURIComponent(shortcutMatch[3])\n", "        project = decodeURIComponent(shortcutMatch[3].replace(/\\.git$/, ''))\n")
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = '''// Standalone example of the same shape: a linear regexp (one quantifier per
// character class, no overlap) that splits `scheme:owner/repo` for a display label.
var LABEL_RE = /^([a-z]+):([^/]+)\\/([^#]+)/

module.exports = function label (spec) {
  var m = spec.match(LABEL_RE)
  return m ? m[1] + ' ' + m[2] + '/' + m[3] : null
}
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
