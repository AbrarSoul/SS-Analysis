"""
Section 9 ground-truth test bundle: CASE-0065
(NodeBB/NodeBB, CVE-2021-43786, CWE-287 improper authentication via
JS built-in property lookup).

Core vulnerable mechanism: `verifyToken()` converts the configured API
token list into a plain object keyed by token string
(`tokens.reduce((memo, cur) => { memo[cur.token] = cur.uid; ... })`), then
looks up the caller-supplied `token` as a property of that object:
`tokens[token]`. A plain JS object's property lookup falls through to
`Object.prototype` for any key it doesn't own -- so a caller sending the
literal string `"constructor"` as their token gets back the real
`Object` constructor function for `uid`, NOT `undefined`. The code then
checks `uid !== undefined` (true, since a function is not undefined) and
`parseInt(uid, 10) > 0` (false, since a function stringifies to
non-numeric text) -- falling into the ELSE branch, which calls
`done(null, { master: true })`, granting MASTER-level API access to a
request that supplied no real token at all. The fix uses
`Array.prototype.find()` directly on the array instead of ever turning it
into a plain object, so there is no property-lookup path into
`Object.prototype` at all.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0065"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = '''Auth.verifyToken = async function (token, done) {
	let { tokens = [] } = await meta.settings.get('core.api');
	tokens = tokens.reduce((memo, cur) => {
		memo[cur.token] = cur.uid;
		return memo;
	}, {});

	const uid = tokens[token];'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename verifyToken -> checkApiToken, tokens -> apiTokens, uid ->
# matchedUid. Same exact array-to-object-then-property-lookup pattern.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''Auth.checkApiToken = async function (token, done) {
	let { tokens: apiTokens = [] } = await meta.settings.get('core.api');
	apiTokens = apiTokens.reduce((memo, cur) => {
		memo[cur.token] = cur.uid;
		return memo;
	}, {});

	const matchedUid = apiTokens[token];''',
)
renamed_source = renamed_source.replace(
    "if (uid !== undefined) {\n\t\tif (parseInt(uid, 10) > 0) {\n\t\t\tdone(null, {\n\t\t\t\tuid: uid,",
    "if (matchedUid !== undefined) {\n\t\tif (parseInt(matchedUid, 10) > 0) {\n\t\t\tdone(null, {\n\t\t\t\tuid: matchedUid,",
)
assert "Auth.checkApiToken = async function (token, done) {" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable + equivalent conditional rewriting
# (for-of loop instead of reduce, same end result: a plain-object lookup
# map with a property-lookup vulnerable to Object.prototype fallthrough).
# Same exact vulnerability, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''Auth.verifyToken = async function (token, done) {
	let { tokens = [] } = await meta.settings.get('core.api');
	const tokenMap = {};
	for (const cur of tokens) {
		tokenMap[cur.token] = cur.uid;
	}
	tokens = tokenMap;

	const uid = tokens[token];''',
)
assert structural_source != original
assert "const tokenMap = {};" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (never let the caller-supplied token string
# resolve through Object.prototype) but a materially different technique:
# a real ES6 Map instead of the real patch's Array.prototype.find() --
# Map keys are stored independently of the prototype chain, so
# map.get("constructor") returns undefined unless a token literally named
# "constructor" was explicitly set() on it, never the built-in
# Object.prototype.constructor -- genuinely safe, different data
# structure from the real patch.
SAFE_SOURCE = '''Auth.verifyToken = async function (token, done) {
	const { tokens = [] } = await meta.settings.get('core.api');
	const tokenMap = new Map();
	tokens.forEach(cur => tokenMap.set(cur.token, cur.uid));

	const uid = tokenMap.get(token);

	if (uid !== undefined) {
		if (parseInt(uid, 10) > 0) {
			done(null, {
				uid: uid,
			});
		} else {
			done(null, {
				master: true,
			});
		}
	} else {
		done(false);
	}
}
'''
(CASE_DIR / "variant_safe_01.js").write_text(SAFE_SOURCE)
assert "new Map()" in SAFE_SOURCE

# --- Verify the Map-based lookup genuinely does not fall through to
# Object.prototype for the same "constructor" bypass string ---
import subprocess

node_check = """
const tokenMap = new Map();
tokenMap.set('realtoken', 42);
const result = tokenMap.get('constructor');
if (result !== undefined) {
  console.error('FAIL: constructor lookup returned', result);
  process.exit(1);
}
console.log('OK: constructor lookup correctly returns undefined');
"""
proc = subprocess.run(["node", "-e", node_check], capture_output=True, text=True)
assert proc.returncode == 0, f"Map-based safe variant failed live verification: {proc.stdout} {proc.stderr}"

# --- Variant 4: benign structural look-alike ---
# Same visible shape (reduce an array into a plain object, then look up a
# property by a variable key) but the lookup key here always comes from a
# FIXED, hard-coded set of internal config names -- never anything a
# caller supplies over the API -- so a request can never trigger a
# "constructor"/"__proto__"-style built-in-property fallthrough, unlike
# verifyToken()'s caller-supplied `token`.
BENIGN_SOURCE = '''const KNOWN_SETTING_NAMES = ['core.api', 'core.theme', 'core.locale'];

async function loadKnownSettings(meta) {
  const settingsList = await Promise.all(
    KNOWN_SETTING_NAMES.map(name => meta.settings.get(name))
  );
  const byName = KNOWN_SETTING_NAMES.reduce((memo, name, i) => {
    memo[name] = settingsList[i];
    return memo;
  }, {});

  // Only ever looked up by the fixed names above -- never by a value
  // that came from an incoming request, so there is no way for
  // "constructor"/"__proto__" to be looked up here with attacker intent.
  return byName['core.api'];
}

module.exports = { loadKnownSettings };
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN_SOURCE)
assert "token" not in BENIGN_SOURCE.lower()

print("Wrote 4 new samples for CASE-0065.")
