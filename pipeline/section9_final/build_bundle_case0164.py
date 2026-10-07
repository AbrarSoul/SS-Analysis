"""
Section 9 ground-truth test bundle: CASE-0164
(flitto/express-param, lib/fetchParams.js requiredParameter, CVE-2017-20160,
CWE-235 improper handling of extra parameters / HTTP parameter pollution).

Located target: `requiredParameter(req, required_expressions)`.

Core vulnerable mechanism: `getValue` returns `req.query[key]` as is, and with
Express's query parser a repeated parameter (`?id=1&id=2`, or `id[]=1`) is an
ARRAY. `requiredParameter` (and `getOptionalParams`) store that array as the
parameter value; for the default `string` type it reaches application code
as an array where a string was promised (a filter such as `role=user&role=admin`
can then satisfy or bypass string comparisons and validation, or change how a
database driver expands the value), and for `number` it is coerced by
`isNaN`/`parseFloat` through Array.prototype.toString. The upstream fix
reduces an array to its LAST element in `getValue` and adds integer type
handling.

Sibling site: `getOptionalParams` reads values through the same `getValue`,
so it has the same defect; the safe variant covers both loops, the vulnerable
variants leave both.

Every variant is the FULL real file. fetchParameter is the module export;
requiredParameter is module-private with one in-file caller, so the renamed
variant renames its locals and keeps the function name.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0164"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

s = original.index("function requiredParameter(req, required_expressions) {\n")
e = original.index("\n}\n", s) + len("\n}\n")
BLOCK = original[s:e]
REQ_GET = "    val = getFunc(req, key);\n    if (keyInfo.type === 'number') {\n      if (isNaN(val)) {"
OPT_GET = "    val = getFunc(req, key);\n\n    if (keyInfo.type === 'number') {\n      if (val !== undefined && val !== '')"
assert BLOCK.count(REQ_GET) == 1 and original.count(OPT_GET) == 1


def build(new_block, text=None):
    text = text or original
    return text[:s] + new_block + text[e:]


def rename(text, pairs):
    out = []
    for line in text.split("\n"):
        parts = re.split(r"""('(?:[^'\\]|\\.)*')""", line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = rename(BLOCK, (("options", "result"), ("getFunc", "reader"), ("err", "failure"), ("key", "name"), ("val", "raw"),
                   ("keyInfo", "info"), ("i", "idx"), ("li", "count")))
# keys of the returned object belong to the caller
b = b.replace("failure: failure,", "err: failure,").replace("params: result", "params: result")
assert "err: failure," in b and "params: result" in b and "failure: failure" not in b
assert "info = getRequiredKeyInfo(required_expressions[idx]);" in b and "name = info.keyName;" in b
assert "raw = reader(req, name);" in b and "if (isNaN(raw)) {" in b
(CASE_DIR / "variant_vulnerable_01.js").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace('''    val = getFunc(req, key);
    if (keyInfo.type === 'number') {
      if (isNaN(val)) {
        err = new Error('The parameter value is not a number : ' + key);
        err.code = 400;
        break;
      }
      options[key] = parseFloat(val);
    } else {
      options[key] = val;
    }
''', '''    val = getFunc(req, key);
    var isNumber = keyInfo.type === 'number';
    if (isNumber && isNaN(val)) {
      err = new Error('The parameter value is not a number : ' + key);
      err.code = 400;
      break;
    }
    options[key] = isNumber ? parseFloat(val) : val;
''')
assert b != BLOCK
(CASE_DIR / "variant_vulnerable_02.js").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# A parameter that arrives more than once (an array) is REJECTED with a 400 in
# both loops; upstream instead collapses the array to its last element inside
# getValue.
b = BLOCK.replace("    val = getFunc(req, key);\n    if (keyInfo.type === 'number') {\n      if (isNaN(val)) {",
                  '''    val = getFunc(req, key);
    if (Array.isArray(val)) {
      err = new Error('The parameter was given more than once : ' + key);
      err.code = 400;
      break;
    }
    if (keyInfo.type === 'number') {
      if (isNaN(val)) {''')
v3 = build(b)
v3 = v3.replace(OPT_GET, '''    val = getFunc(req, key);

    if (Array.isArray(val)) {
      err = new Error('The parameter was given more than once : ' + key);
      err.code = 400;
      break;
    }

    if (keyInfo.type === 'number') {
      if (val !== undefined && val !== '')''')
assert v3.count("The parameter was given more than once") == 2
(CASE_DIR / "variant_safe_01.js").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''"use strict";

/**
 * Same "read a query parameter" shape as getValue, but it is deliberately
 * multi-valued: a repeated parameter is expected (a multi-select filter), the
 * result is ALWAYS an array of strings, and each element is checked against
 * an allow-list, so there is no scalar-versus-array confusion.
 */
function getAllowedList(req, keyName, allowed) {
  var raw = req.query && req.query[keyName];
  var list = raw === undefined ? [] : [].concat(raw);
  return list.filter(function (item) {
    return typeof item === "string" && allowed.indexOf(item) !== -1;
  });
}

exports.getAllowedList = getAllowedList;
'''
assert "ALWAYS an array" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0164.")
