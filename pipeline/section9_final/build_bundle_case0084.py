"""
Section 9 ground-truth test bundle: CASE-0084
(advplyr/audiobookshelf, CVE-2025-25205, CWE-202/CWE-287/CWE-400).

NOTE on this case's data: the pipeline originally captured the commit that
INTRODUCED the bug ("No auth for author images", bf84072). Per the GitHub
advisory the real fix is ec65376 ("Security fix for GHSA-pg8v-5jcv-wrvw");
this case was hand-curated to that real vulnerable/fixed pair via
pipeline/apply_hand_curations.py (see Implementation_Log.md Section 12.16).

Core vulnerable mechanism: `authNotNeeded()` skips authentication for GET
requests whose `req.originalUrl` matches UNANCHORED regexes such as
`/\\/api\\/items\\/[^/]+\\/cover/`. originalUrl includes the query string, so
an attacker can request ANY protected endpoint with a query parameter like
`?r=/api/items/1/cover` and the substring match makes the server treat the
request as public: information disclosure, and a server crash when
handlers dereference the missing `req.user`. The upstream fix anchors the
patterns (^...$) and tests `req.path` instead of `req.originalUrl`.

Every variant is the FULL real file with the constructor + authNotNeeded
block replaced.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0084"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.js").read_text().splitlines()) + "\n"

START = "  constructor() {\n    // Map of openId sessions"
END = "  ifAuthNeeded(middleware) {"
s = original.index(START)
e = original.index(END)
BLOCK = original[s:e]
assert original.count(START) == 1 and original.count(END) == 1
assert "this.ignorePatterns.some((pattern) => pattern.test(req.originalUrl))" in BLOCK


def build(new_block, text=None):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK
b = b.replace("ignorePatterns", "publicRoutePatterns").replace("authNotNeeded", "isPublicRequest")
b = re.sub(r"\breq\b", "request", b)
b = re.sub(r"\bpattern\b", "routeRegex", b)
renamed = build(b)
renamed = re.sub(r"\bauthNotNeeded\b", "isPublicRequest", renamed)  # ifAuthNeeded call site
assert "authNotNeeded" not in renamed and "ignorePatterns" not in renamed
assert renamed.count("isPublicRequest") == 2
assert "routeRegex.test(request.originalUrl)" in renamed
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed)

# --- Variant 2: structurally changed vulnerable variant ---
STRUCT = """  constructor() {
    // Map of openId sessions indexed by oauth2 state-variable
    this.openIdAuthSession = new Map()
    const coverPattern = /\\/api\\/items\\/[^/]+\\/cover/
    const authorImagePattern = /\\/api\\/authors\\/[^/]+\\/image/
    this.ignorePatterns = [coverPattern, authorImagePattern]
  }

  /**
   * Checks if the request should not be authenticated.
   * @param {Request} req
   * @returns {boolean}
   * @private
   */
  authNotNeeded(req) {
    if (req.method !== 'GET') return false
    const url = req.originalUrl
    for (const pattern of this.ignorePatterns) {
      if (pattern.test(url)) return true
    }
    return false
  }

"""
(CASE_DIR / "variant_vulnerable_02.js").write_text(build(STRUCT))

# --- Variant 3: transformed safe variant ---
# Parse the request URL and match ANCHORED patterns against the normalised
# pathname only (query string and fragment are discarded, dot-segments are
# resolved). Different mechanism from the upstream fix (which tests
# req.path with base-path-aware anchored RegExps).
SAFE = """  constructor() {
    // Map of openId sessions indexed by oauth2 state-variable
    this.openIdAuthSession = new Map()
    this.ignorePatterns = [/^\\/api\\/items\\/[^/]+\\/cover$/, /^\\/api\\/authors\\/[^/]+\\/image$/]
  }

  /**
   * Checks if the request should not be authenticated.
   * @param {Request} req
   * @returns {boolean}
   * @private
   */
  authNotNeeded(req) {
    if (req.method !== 'GET') return false
    let pathname
    try {
      pathname = new URL(req.originalUrl, 'http://localhost').pathname
    } catch (error) {
      return false
    }
    return this.ignorePatterns.some((pattern) => pattern.test(pathname))
  }

"""
(CASE_DIR / "variant_safe_01.js").write_text(build(SAFE))

# --- Variant 4: benign structural look-alike ---
BENIGN = """class RequestLogFilter {
  constructor() {
    // Cover image requests are very frequent and only add noise to the log
    this.quietPatterns = [/\\/api\\/items\\/[^/]+\\/cover/, /\\/api\\/authors\\/[^/]+\\/image/]
  }

  /**
   * Decides whether a request line should be omitted from the access log.
   * Same unanchored-regex-on-originalUrl shape as an auth allow-list, but a
   * false match only suppresses a log line; no access-control decision
   * depends on it.
   * @param {Request} req
   * @returns {boolean}
   */
  shouldSkipLogging(req) {
    return req.method === 'GET' && this.quietPatterns.some((pattern) => pattern.test(req.originalUrl))
  }
}

module.exports = RequestLogFilter
"""
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
print("Wrote 4 new samples for CASE-0084.")
