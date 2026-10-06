"""
Section 9 ground-truth test bundle: CASE-0214
(markdown-it/markdown-it, lib/index.js validateLink, CVE-2015-3295,
CWE-284 as labelled upstream; effect: script-capable `data:` URLs rendered as
links).

Core vulnerable mechanism: markdown-it renders `[x](url)` / `![x](url)` only
when `md.validateLink(url)` is true. The default validator rejects the schemes
`vbscript`, `javascript` and `file` but not `data`, so
`[click](data:text/html;base64,PHNjcmlwdD4uLi48L3NjcmlwdD4=)` becomes a real
`<a href="data:text/html;...">` that runs script in the browser when followed.
The upstream fix adds `data` to the blocked schemes and re-allows only the
four image types gif, png, jpeg and webp.

Sibling sites: validateLink is the single validator; `md.validateLink` is set
once in the MarkdownIt constructor and used by the link, image and autolink
rules, so there is nothing else to change.

Verification: the vulnerable source is byte-identical to lib/index.js of the
real markdown-it 4.0.3 package. Each full variant replaces lib/index.js in a
copy of that package and the real renderer (`md.render`) is run on links and
images with `data:` URLs.

Every variant is the FULL real file. `this.validateLink = validateLink` is the
public API (users override md.validateLink), so the property name stays; the
renamed variant renames the internal function, its parameter and locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0214"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


BLOCK = '''var BAD_PROTOCOLS    = [ 'vbscript', 'javascript', 'file' ];

function validateLink(url) {
  // url should be normalized at this point, and existing entities are decoded
  //
  var str = url.trim().toLowerCase();

  if (str.indexOf(':') >= 0 && BAD_PROTOCOLS.indexOf(str.split(':')[0]) >= 0) {
    return false;
  }
  return true;
}
'''

# --- Variant 1: renamed vulnerable variant ---
v1 = swap(original, BLOCK, '''var BLOCKED_SCHEMES = [ 'vbscript', 'javascript', 'file' ];

function isLinkAllowed(href) {
  // url should be normalized at this point, and existing entities are decoded
  //
  var lowered = href.trim().toLowerCase();

  if (lowered.indexOf(':') >= 0 && BLOCKED_SCHEMES.indexOf(lowered.split(':')[0]) >= 0) {
    return false;
  }
  return true;
}
''')
v1 = swap(v1, "this.validateLink = validateLink;", "this.validateLink = isLinkAllowed;")
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, BLOCK, '''var BAD_PROTOCOLS    = [ 'vbscript', 'javascript', 'file' ];

function schemeOf(str) {
  var idx = str.indexOf(':');
  return idx >= 0 ? str.slice(0, idx) : null;
}

function validateLink(url) {
  // url should be normalized at this point, and existing entities are decoded
  //
  var scheme = schemeOf(url.trim().toLowerCase());

  return scheme === null || BAD_PROTOCOLS.indexOf(scheme) < 0;
}
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Upstream re-allows image data URLs by comparing the text before ';'; this
# variant matches a strict `data:image/<type>;base64,` prefix with a regexp.
v3 = swap(original, BLOCK, '''var BAD_PROTOCOLS    = [ 'vbscript', 'javascript', 'file', 'data' ];
var SAFE_DATA_IMAGE  = /^data:image\\/(?:gif|png|jpeg|webp)[;,]/;

function validateLink(url) {
  // url should be normalized at this point, and existing entities are decoded
  //
  var str = url.trim().toLowerCase();

  if (str.indexOf(':') >= 0 && BAD_PROTOCOLS.indexOf(str.split(':')[0]) >= 0) {
    return SAFE_DATA_IMAGE.test(str);
  }
  return true;
}
''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = '''// Standalone example of the same shape: a scheme denylist for a link checker
// that only decides which links get a "leaves the site" icon; nothing is
// rendered as active content because of the result.
var EXTERNAL_SCHEMES = [ 'http', 'https', 'ftp' ];

function isExternalLink(url) {
  var str = url.trim().toLowerCase();

  return str.indexOf(':') >= 0 && EXTERNAL_SCHEMES.indexOf(str.split(':')[0]) >= 0;
}

module.exports = isExternalLink;
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
