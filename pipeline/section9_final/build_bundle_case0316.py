r"""
Section 9 ground-truth test bundle: CASE-0316
(unshiftio/url-parse, index.js Url constructor, CVE-2018-3774,
CWE-601 open redirect / CWE-918 SSRF / CWE-425; hand-curated real fix 53b1794
'[security] Sanitize paths, hosts before parsing', v1.4.3).

Core vulnerable mechanism: the `Url` constructor splits an address with a
fixed sequence of rules (hash, query, path on '/', auth on '@', ...). It only
treats forward slash as the path separator, but browsers and most HTTP
clients treat a backslash as a slash in special schemes. In
`http://google.com:80\@yahoo.com/` url-parse therefore reads the userinfo
`google.com:80\` and the host `yahoo.com`, while a browser/request library
connects to `google.com` (path `/@yahoo.com/`): the parsed hostname disagrees
with the real destination, defeating host allow-lists (open redirect, SSRF,
credential-leak host confusion). The fix adds a `sanitize` rule that
replaces the backslash with `/` before the pathname rule and teaches the
constructor loop to run function rules.

Sibling sites: the `//\what-is-up.com` protocol-relative form goes through
the same rule list; `set('host', ...)` is a separate setter and unchanged.

Note (recorded caveat): the upstream fix uses `address.replace('\\', '/')`
with a string pattern, which replaces only the FIRST backslash (not
exercised by the probes below; a two-backslash address still yields the
browser-consistent host google.com here).

Verification (REAL dependencies): each full file is loaded with node (with
the real `requires-port` and `querystringify` npm packages) and the
constructor is called with `http://google.com:80\@yahoo.com/#x`,
`//\what-is-up.com` and a plain `http://good.com/path?q=1` control.
Vulnerable variants report hostname yahoo.com with username google.com and
hostname `\what-is-up.com`; patched/safe report hostname google.com and path
`/what-is-up.com`; the control parses identically in all files.

Every variant is the FULL real file; the exported constructor name is kept
because it is the module's API (`module.exports = Url`).
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0316"
original = (CASE_DIR / "vulnerable_source.js").read_text()
patched = (CASE_DIR / "patched_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


START = "function Url(address, location, parser) {\n"
END = "/**\n * This is convenience method for changing properties"
assert original.count(START) == 1
a = original.index(START)
b = original.index(END, a)
func = original[a:b]

# --- Variant 1: renamed vulnerable variant (locals renamed inside the Url constructor) ---
def rename_code(text, pairs):
    out = []
    for line in text.split("\n"):
        if not line.lstrip().startswith("//"):
            for old, new in pairs:
                line = re.sub(r"(?<![\w.])%s\b" % old, new, line)
        out.append(line)
    return "\n".join(out)


f1 = rename_code(func, [("relative", "isRelative"), ("extracted", "prefix"), ("parse", "matcher"),
                        ("instructions", "steps"), ("instruction", "step"), ("index", "pos"), ("key", "prop")])
assert "matcher.exec" in f1 and "pos.index" in f1 and "pos[1]" in f1
v1 = original.replace(func, f1)
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (rule application moved into a helper function) ---
CHAIN = '''    parse = instruction[0];
    key = instruction[1];

    if (parse !== parse) {
      url[key] = address;
    } else if ('string' === typeof parse) {
      if (~(index = address.indexOf(parse))) {
        if ('number' === typeof instruction[2]) {
          url[key] = address.slice(0, index);
          address = address.slice(index + instruction[2]);
        } else {
          url[key] = address.slice(index);
          address = address.slice(0, index);
        }
      }
    } else if ((index = parse.exec(address))) {
      url[key] = index[1];
      address = address.slice(0, index.index);
    }
'''
HELPER = '''function applyRule(url, instruction, address) {
  var parse = instruction[0]
    , key = instruction[1]
    , index;

  if (parse !== parse) {
    url[key] = address;
  } else if ('string' === typeof parse) {
    if (~(index = address.indexOf(parse))) {
      if ('number' === typeof instruction[2]) {
        url[key] = address.slice(0, index);
        address = address.slice(index + instruction[2]);
      } else {
        url[key] = address.slice(index);
        address = address.slice(0, index);
      }
    }
  } else if ((index = parse.exec(address))) {
    url[key] = index[1];
    address = address.slice(0, index.index);
  }

  return address;
}

'''
f2 = swap(func, CHAIN, "    address = applyRule(url, instruction, address);\n    key = instruction[1];\n")
v2 = original.replace(func, HELPER + f2)
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the sanitize rule becomes a named module-level function) ---
INLINE = '''  function sanitize(address) {          // Sanitize what is left of the address
    return address.replace('\\\\', '/');
  },
'''
v3 = swap(patched, INLINE, "  sanitizeAddress,                      // Sanitize what is left of the address\n")
v3 = swap(v3, "var rules = [\n", '''function sanitizeAddress(address) {
  return address.replace('\\\\', '/');
}

var rules = [
''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

(CASE_DIR / "benign_lookalike.js").write_text(''''use strict';

/**
 * Display helper: turns a Windows-style file path from a build log into a
 * forward-slash path for a report. It never parses hosts or URLs and its
 * output is only printed.
 */
function toPosixDisplayPath(filePath) {
  return String(filePath).replace(/\\\\/g, '/');
}

function splitDisplayPath(filePath) {
  var normalized = toPosixDisplayPath(filePath)
    , index = normalized.lastIndexOf('/');

  return index === -1
    ? { dir: '', base: normalized }
    : { dir: normalized.slice(0, index), base: normalized.slice(index + 1) };
}

module.exports = { toPosixDisplayPath: toPosixDisplayPath, splitDisplayPath: splitDisplayPath };
''')
