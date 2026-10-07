"""
Section 9 ground-truth test bundle: CASE-0068
(OWASP/NodeGoat, CVE-2021-4247, CWE-404 improper resource shutdown via an
unhandled exception on a failed request).

Core vulnerable mechanism: the `needle.get()` callback accesses
`newResponse.body` UNCONDITIONALLY, regardless of whether `error` was
set. When the outbound HTTP request fails outright (connection refused,
DNS failure, timeout, TLS error -- all realistic for a URL built from
user-controlled `req.query.url`), `needle` invokes the callback with
`newResponse` as `undefined`, and `newResponse.body` throws a
`TypeError: Cannot read properties of undefined`. In an Express route
handler with no surrounding try/catch, an uncaught exception in an async
callback like this can crash the Node process (or leave the socket
half-handled), a real denial-of-service surface reachable just by
supplying a URL that fails to connect. The fix uses `body`, the third
argument `needle` also passes to the callback, and only writes it when
truthy -- avoiding the unconditional property access on a value that may
not exist.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0068"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = '''            return needle.get(url, (error, newResponse) => {
                if (!error && newResponse.statusCode === 200) {
                    res.writeHead(200, {
                        "Content-Type": "text/html"
                    });
                }
                res.write("<h1>The following is the stock information you requested.</h1>\\n\\n");
                res.write("\\n\\n");
                res.write(newResponse.body);
                return res.end();
            });'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename url -> targetUrl, newResponse -> httpResponse. Same exact
# unconditional .body access on a value that may be undefined on error.
renamed_source = original.replace(
    "const url = req.query.url + req.query.symbol;",
    "const targetUrl = req.query.url + req.query.symbol;",
)
renamed_source = renamed_source.replace(
    VULNERABLE_BLOCK,
    '''            return needle.get(targetUrl, (error, httpResponse) => {
                if (!error && httpResponse.statusCode === 200) {
                    res.writeHead(200, {
                        "Content-Type": "text/html"
                    });
                }
                res.write("<h1>The following is the stock information you requested.</h1>\\n\\n");
                res.write("\\n\\n");
                res.write(httpResponse.body);
                return res.end();
            });''',
)
assert "needle.get(targetUrl," in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable holding the response body reference
# before writing. Same exact crash-on-undefined vulnerability, no
# renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''            return needle.get(url, (error, newResponse) => {
                const succeeded = !error && newResponse.statusCode === 200;
                if (succeeded) {
                    res.writeHead(200, {
                        "Content-Type": "text/html"
                    });
                }
                res.write("<h1>The following is the stock information you requested.</h1>\\n\\n");
                res.write("\\n\\n");
                const responseBody = newResponse.body;
                res.write(responseBody);
                return res.end();
            });''',
)
assert structural_source != original
assert "const succeeded = !error && newResponse.statusCode === 200;" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (never dereference a possibly-missing
# response) but a materially different technique: a single defensive
# guard clause at the top of the callback (`if (error || !newResponse)
# return handleFetchFailure(...)`) that returns early on ANY failure
# condition, instead of the real patch's approach of using the separate
# `body` callback parameter and conditionally writing it -- genuinely
# avoids the crash, different control-flow shape.
SAFE_SOURCE = '''function ResearchHandler(db) {
    return function (req, res) {
        const needle = require("needle");

        if (req.query.symbol) {
            const url = req.query.url + req.query.symbol;
            return needle.get(url, (error, newResponse) => {
                if (error || !newResponse) {
                    res.writeHead(502, { "Content-Type": "text/plain" });
                    res.write("Unable to fetch stock information at this time.");
                    return res.end();
                }
                if (newResponse.statusCode === 200) {
                    res.writeHead(200, {
                        "Content-Type": "text/html"
                    });
                }
                res.write("<h1>The following is the stock information you requested.</h1>\\n\\n");
                res.write("\\n\\n");
                res.write(newResponse.body);
                return res.end();
            });
        }
    };
}

module.exports = ResearchHandler;
'''
(CASE_DIR / "variant_safe_01.js").write_text(SAFE_SOURCE)
assert "if (error || !newResponse)" in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# Same visible shape (a callback that unconditionally accesses
# `.body` on its second argument) but this sibling is only ever invoked
# by this module's OWN unit-test harness with a synthetic, always-
# present, synchronously-constructed response object -- never a real
# network callback whose argument can legitimately be undefined on
# failure -- so the unconditional access can never actually throw, unlike
# the needle.get() callback's newResponse.
BENIGN_SOURCE = '''function renderMockedResponse(res, mockResponse) {
  // mockResponse is always a plain object constructed synchronously by
  // this module's own test harness (e.g. { body: "...", statusCode: 200 }),
  // never a real HTTP-library network callback argument -- there is no
  // failure path here that could ever make it undefined.
  res.write(mockResponse.body);
  return res.end();
}

module.exports = { renderMockedResponse };
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN_SOURCE)
assert "needle" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0068.")
