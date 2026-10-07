"""
Section 9 ground-truth test bundle: CASE-0127
(balderdashy/sails, lib/router/req.js buildRequest, CVE-2023-38504,
CWE-248 uncaught exception).

Located target (hand-retargeted, see benchmark/hand_curations.json): the
enclosing function `module.exports = function buildRequest (_req)`. The
diff-driven locator had produced a truncated 5-line `_.each(...)` fragment
that did not even contain the defect.

Core vulnerable mechanism: header values that are not strings are coerced
with `headerVal = ''+headerVal+''` inside a `_.mapValues` callback with NO
error handling. A value that cannot be converted to a primitive -- an
object without toString/valueOf (`Object.create(null)`), or a Symbol --
makes that expression throw a TypeError. The exception propagates out of
buildRequest as an uncaught error, so a crafted (virtual/socket) request
can crash the request handler or process (denial of service). The upstream
fix rewrites the loop and wraps the coercion in try/catch, deleting the
offending header.

Every variant is the FULL real file. buildRequest is the module's only
export; nothing in the file calls it by name, so the renamed variant only
renames the function expression's own name.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0127"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

FN_HDR = "module.exports = function buildRequest (_req) {\n"
f0 = original.index(FN_HDR)
FN = original[f0:]
assert original.count(FN_HDR) == 1

HDR = "    if (_req.headers && typeof _req.headers === 'object') {\n"
h0 = original.index(HDR)
h1 = original.index("\n    }\n", h0) + len("\n    }\n")
BLOCK = original[h0:h1]
assert original.count(HDR) == 1 and "''+headerVal+''" in BLOCK and "try" not in BLOCK


def build(new_block):
    assert new_block != BLOCK
    return original[:h0] + new_block + original[h1:]


def rename_outside_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        st = line.lstrip()
        if st.startswith("//") or st.startswith("*") or st.startswith("/*"):
            out.append(line)
            continue
        parts = re.split(r"""('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")""", line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
fn1 = rename_outside_strings(FN, (("buildRequest", "makeVirtualRequest"), ("_req", "rawReq"), ("headerVal", "hv"),
                                  ("headerKey", "hk"), ("parsedUrl", "urlParts"), ("unusedErr", "ignoredErr")))
assert "module.exports = function makeVirtualRequest (rawReq) {" in fn1 and "hv = ''+hv+'';" in fn1
assert "rawReq.headers" in fn1 and "urlParts.pathname" in fn1
(CASE_DIR / "variant_vulnerable_01.js").write_text(original[:f0] + fn1)

# --- Variant 2: structurally changed vulnerable variant ---
b = '''    if (_req.headers && typeof _req.headers === 'object') {
      for (const headerKey of Object.keys(_req.headers)) {
        if (_.isUndefined(_req.headers[headerKey])) {
          delete _req.headers[headerKey];
          continue;
        }
        if (typeof _req.headers[headerKey] !== 'string') {
          _req.headers[headerKey] = ''+_req.headers[headerKey]+'';
        }
      }
    }
'''
(CASE_DIR / "variant_vulnerable_02.js").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Only primitives (string / number / boolean / bigint) are kept -- numbers etc.
# are converted with String(), which cannot throw for a primitive; everything
# else (undefined, null, objects, functions, symbols) is dropped. Upstream
# instead keeps the coercion and catches the exception per header.
b = '''    if (_req.headers && typeof _req.headers === 'object') {
      var cleanedHeaders = {};
      _.each(_req.headers, function (headerVal, headerKey) {
        var kind = typeof headerVal;
        if (kind === 'string') {
          cleanedHeaders[headerKey] = headerVal;
        } else if (kind === 'number' || kind === 'boolean' || kind === 'bigint') {
          cleanedHeaders[headerKey] = String(headerVal);
        }
        // undefined, null, objects, functions and symbols are not valid header values: drop them
      });
      _req.headers = cleanedHeaders;
    }
'''
safe_source = build(b)
assert "''+headerVal+''" not in safe_source
(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
benign_source = '''"use strict";

function isPrimitiveHeaderValue(value) {
  var kind = typeof value;
  return kind === "string" || kind === "number" || kind === "boolean";
}

/**
 * Same "if it is not a string, coerce with ''+value+''" idiom as a header
 * normaliser, but only values that are ALREADY string/number/boolean ever
 * reach the coercion (everything else is filtered out first), and
 * concatenating a primitive with '' can never throw.
 */
function normalizeHeaders(headers) {
  var result = {};
  Object.keys(headers).forEach(function (name) {
    var value = headers[name];
    if (!isPrimitiveHeaderValue(value)) {
      return;
    }
    if (typeof value !== "string") {
      value = "" + value + "";
    }
    result[name] = value;
  });
  return result;
}

module.exports = { normalizeHeaders: normalizeHeaders };
'''
assert "isPrimitiveHeaderValue(value)" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0127.")
