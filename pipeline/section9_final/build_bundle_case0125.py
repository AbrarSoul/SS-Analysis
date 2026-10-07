"""
Section 9 ground-truth test bundle: CASE-0125
(axios/axios, lib/helpers/isURLSameOrigin.js, CVE-2024-57965, CWE-346
origin validation error) -- a DISPUTED advisory.

Advisory text: "In axios before 1.7.8, lib/helpers/isURLSameOrigin.js does
not use a URL object when determining an origin, and has a potentially
unwanted setAttribute('href',href) call. NOTE: some parties feel that the
code change only addresses a warning message from a SAST tool and does not
fix a vulnerability." The flagged pattern: the same-origin decision is made
by writing an untrusted URL into a DOM <a> element (`setAttribute('href',
...)`) and reading its parsed parts, instead of a URL object. The located
"function" is the module's whole `export default` conditional expression
(a default-export IIFE), not a named function.

Empirically (jsdom, 14 string URLs incl. protocol-relative, embedded
credentials, javascript:, backslash forms, default ports) the old and new
logic give IDENTICAL answers; they differ only for non-string input, where
the old code trusts the object's fields. No exploit was reproduced; the
label rests on the advisory's stated pattern (see manifest notes).

Every variant is the FULL real file. The nonStandardBrowserEnv branch is
never touched.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0125"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

STD_START = "  (function standardBrowserEnv() {\n"
STD_END = "  })() :\n"
a = original.index(STD_START)
b_ = original.index(STD_END) + len(STD_END)
STD = original[a:b_]
assert original.count(STD_START) == 1 and original.count(STD_END) == 1
assert STD.count("setAttribute('href', href)") == 2


def swap(text, old, new, count=1):
    assert text.count(old) == count, (old, text.count(old))
    assert new != old
    return text.replace(old, new)


def with_std(new_std):
    assert new_std != STD
    return original[:a] + new_std + original[b_:]


# --- Variant 1: renamed vulnerable variant ---
v = STD
v = swap(v, "(function standardBrowserEnv() {", "(function pageOriginProbe() {")
v = swap(v, "const msie = ", "const isLegacyIE = ")
v = swap(v, "if (msie) {", "if (isLegacyIE) {")
v = v.replace("urlParsingNode", "anchor")                      # identifier only (comment lines unaffected in meaning)
v = swap(v, "let originURL;", "let pageOrigin;")
v = swap(v, "originURL = resolveURL(window.location.href);", "pageOrigin = parseWithAnchor(window.location.href);")
v = swap(v, "function resolveURL(url) {", "function parseWithAnchor(rawUrl) {")
v = swap(v, "let href = url;", "let resolved = rawUrl;")
v = swap(v, "anchor.setAttribute('href', href);", "anchor.setAttribute('href', resolved);", 2)
v = swap(v, "href = anchor.href;", "resolved = anchor.href;")
v = swap(v, "return function isURLSameOrigin(requestURL) {", "return function isURLSameOrigin(target) {")
v = swap(v, "const parsed = (utils.isString(requestURL)) ? resolveURL(requestURL) : requestURL;",
         "const candidate = (utils.isString(target)) ? parseWithAnchor(target) : target;")
v = swap(v, "return (parsed.protocol === originURL.protocol &&\n          parsed.host === originURL.host);",
         "return (candidate.protocol === pageOrigin.protocol &&\n          candidate.host === pageOrigin.host);")
assert "resolveURL" not in v and "originURL" not in v and "setAttribute('href', resolved)" in v
(CASE_DIR / "variant_vulnerable_01.js").write_text(with_std(v))

# --- Variant 2: structurally changed vulnerable variant ---
# A fresh anchor per call instead of one shared node; the same DOM-anchor sink.
v = STD
v = swap(v, "    const urlParsingNode = document.createElement('a');\n", "")
v = swap(v, "    function resolveURL(url) {\n      let href = url;\n",
         "    function resolveURL(url) {\n      const urlParsingNode = document.createElement('a');\n      let href = url;\n")
assert v.count("setAttribute('href', href)") == 2
(CASE_DIR / "variant_vulnerable_02.js").write_text(with_std(v))

# --- Variant 3: transformed safe variant ---
# WHATWG URL object instead of a DOM anchor; fails closed on non-string input
# and on unparsable URLs (upstream: arrow-function form with new URL(url, base)
# and an explicit port check).
new_std = '''  (function standardBrowserEnv() {
    const originURL = new URL(window.location.href);

    /**
    * Determine if a URL shares the same origin as the current location
    *
    * @param {String} requestURL The URL to test
    * @returns {boolean} True if URL shares the same origin, otherwise false
    */
    return function isURLSameOrigin(requestURL) {
      if (!utils.isString(requestURL)) {
        return false;
      }
      let parsed;
      try {
        parsed = new URL(requestURL, window.location.href);
      } catch (err) {
        return false;
      }
      return (parsed.protocol === originURL.protocol &&
          parsed.host === originURL.host &&
          parsed.port === originURL.port);
    };
  })() :
'''
safe_source = with_std(new_std)
assert "setAttribute" not in safe_source and "createElement" not in safe_source
(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''const NAV_LINKS = { docs: "/docs", help: "/help", status: "/status" };

/**
 * Same "setAttribute('href', value)" DOM-anchor sink, but the value is one of
 * a fixed set of developer-written site-relative paths looked up by own-key,
 * never request or user text, so nothing untrusted reaches the sink.
 */
export function setNavLink(anchor, key) {
  const target = Object.prototype.hasOwnProperty.call(NAV_LINKS, key) ? NAV_LINKS[key] : "/";
  anchor.setAttribute("href", target);
  return anchor;
}
'''
assert "hasOwnProperty.call(NAV_LINKS" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0125.")
