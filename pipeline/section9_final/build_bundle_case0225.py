"""
Section 9 ground-truth test bundle: CASE-0225
(mintplex-labs/anything-llm, server/utils/helpers/updateENV.js dumpENV,
CVE-2024-3104, CWE-78 as labelled upstream; the mechanism is injection into
the generated .env file).

Core vulnerable mechanism: `dumpENV` rewrites the server's `.env` from
`process.env` by joining lines of the form `KEY='value'`, with the values put
in unescaped. The values are set through the settings API (`updateENV` copies
API-supplied strings into process.env), so a value that contains a newline
followed by `OTHER=...` turns one setting into two `.env` entries, and a value
containing `'` closes the quote early. On the next start the file is loaded
(dotenv / the container entrypoint), so an authenticated administrator or
manager can inject arbitrary environment variables (for example
`NODE_OPTIONS`, `STORAGE_DIR`, `JWT_SECRET`) that persist across restarts. The
upstream fix adds `sanitizeValue`, which truncates each value at the first
newline/whitespace-control/quote/backtick/`#` character.

Measured caveat, kept in the manifest notes: truncation silently changes the
setting (a password containing `'` or `#` is cut short and later fails to
match), instead of rejecting it. The safe variant leaves out any entry whose
value contains one of those characters and logs the key name.

Sibling sites: `dumpENV` is the only writer of the `.env` file in the module.
`updateENV` (line ~500) writes to process.env only.

Verification: `dumpENV` is extracted verbatim from each full file and run with
a captured `fs.writeFileSync`, a `KEY_MAPPING` stand-in and process.env values
set to an injection payload; the captured file text is parsed with the REAL
`dotenv` package (16.x) to show which variables the next start would load.

Every variant is the FULL real file. `dumpENV` is exported and called by name
from the server, so its name and signature are kept; the renamed variant
renames its locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0225"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


s = original.index("async function dumpENV() {")
e = original.index("\n}\n", s) + 3
FN = original[s:e]
assert original.count(FN) == 1

LINES = '''  var envResult = `# Auto-dump ENV from system call on ${new Date().toTimeString()}\\n`;
  envResult += Object.entries(frozenEnvs)
    .map(([key, value]) => {
      return `${key}='${value}'`;
    })
    .join("\\n");
'''
assert FN.count(LINES) == 1

# --- Variant 1: renamed vulnerable variant ---
f1 = FN
for a, b in (("frozenEnvs", "captured"), ("protectedKeys", "keysToPersist"), ("envResult", "envText"),
             ("envPath", "destination"), ("envValue", "currentValue")):
    assert a in f1
    f1 = f1.replace(a, b)
(CASE_DIR / "variant_vulnerable_01.js").write_text(original[:s] + f1 + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
f2 = swap(FN, LINES, '''  const formatLine = (key, value) => `${key}='${value}'`;
  var envResult = `# Auto-dump ENV from system call on ${new Date().toTimeString()}\\n`;
  envResult += Object.entries(frozenEnvs)
    .map(([key, value]) => formatLine(key, value))
    .join("\\n");
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(original[:s] + f2 + original[e:])

# --- Variant 3: transformed safe variant ---
f3 = swap(FN, LINES, '''  // A value that could break out of the quotes or start a new line is not written.
  const UNSAFE_ENV_VALUE = /[\\n\\r\\t\\v\\f\\u0085\\u00a0\\u1680\\u180e\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000"'`#]/;
  var envResult = `# Auto-dump ENV from system call on ${new Date().toTimeString()}\\n`;
  envResult += Object.entries(frozenEnvs)
    .filter(([key, value]) => {
      if (!UNSAFE_ENV_VALUE.test(value)) return true;
      console.log(`dumpENV: not persisting ${key}, its value contains characters that are unsafe in a .env file`);
      return false;
    })
    .map(([key, value]) => `${key}='${value}'`)
    .join("\\n");
''')
(CASE_DIR / "variant_safe_01.js").write_text(original[:s] + f3 + original[e:])

BENIGN = '''// Standalone example of the same shape: writing settings to a file, but as
// JSON.stringify output, so a value can never start a new entry.
const fs = require("fs");
const path = require("path");

function dumpSettings(settings, dir) {
  const out = {};
  for (const [key, value] of Object.entries(settings)) {
    if (value) out[key] = String(value);
  }
  fs.writeFileSync(path.join(dir, "settings.json"), JSON.stringify(out, null, 2), "utf8");
  return true;
}

module.exports = { dumpSettings };
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
