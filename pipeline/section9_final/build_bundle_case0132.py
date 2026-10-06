"""
Section 9 ground-truth test bundle: CASE-0132
(bluewave-labs/Checkmate, server/controllers/settingsController.js
getAppSettings, CVE-2025-48024, CWE-497 exposure of sensitive system
information).

Core vulnerable mechanism: `getAppSettings` returns the stored application
settings to the API caller after masking ONLY `pagespeedApiKey`
(`sanitizedSettings.pagespeedApiKey = "********"`). Every other secret in the
settings document -- notably `systemEmailPassword`, the SMTP password -- is
returned in clear text. The upstream fix deletes both secrets from the
response and returns `pagespeedKeySet` / `emailPasswordSet` booleans instead.

Sibling site (NOT fixed upstream, verified: updateAppSettings is byte-identical
in the upstream-patched file): `updateAppSettings` returns the reloaded
settings with only `jwtSecret` deleted, so it leaks the same two secrets. Per
the sibling-site rule the SAFE variant fixes both functions; the two
vulnerable variants leave both untouched.

Every variant is the FULL real file. `getAppSettings` is a class field (an
arrow function); `this.stringService.getAppSettings` is a different property
and is never renamed.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0132"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

HDR = "\tgetAppSettings = async (req, res, next) => {\n"
s = original.index(HDR)
e = original.index("\n\t};\n", s) + len("\n\t};\n")
BLOCK = original[s:e]
assert original.count(HDR) == 1 and original.count("getAppSettings") == 2
MASK = '''		const sanitizedSettings = { ...dbSettings };
		if (typeof sanitizedSettings.pagespeedApiKey !== "undefined") {
			sanitizedSettings.pagespeedApiKey = "********";
		}
'''
UPD = '''			const updatedSettings = { ...(await this.settingsService.reloadSettings()) };
			delete updatedSettings.jwtSecret;
'''
assert BLOCK.count(MASK) == 1 and original.count(UPD) == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


def rename_outside_strings(text, pairs):
    out = []
    for line in text.split("\n"):
        if line.lstrip().startswith("//"):
            out.append(line)
            continue
        parts = re.split(r"""('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")""", line)
        for i in range(0, len(parts), 2):
            for name, new in pairs:
                parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])(?!\s*:)" % re.escape(name), new, parts[i])
        out.append("".join(parts))
    return "\n".join(out)


# --- Variant 1: renamed vulnerable variant ---
b = rename_outside_strings(BLOCK, (("getAppSettings", "loadSettings"), ("req", "request"), ("res", "response"),
                                   ("dbSettings", "stored"), ("sanitizedSettings", "visible")))
b = b.replace("...dbSettings", "...stored")   # spread dots defeat the `not preceded by .` identifier rule
assert "dbSettings" not in b and "{ ...stored }" in b
assert "\tloadSettings = async (request, response, next) => {" in b
assert "msg: this.stringService.getAppSettings," in b and "return response.success({" in b
assert 'visible.pagespeedApiKey = "********";' in b
(CASE_DIR / "variant_vulnerable_01.js").write_text(build(b))

# --- Variant 2: structurally changed vulnerable variant ---
b = BLOCK.replace(MASK, '''		const sanitizedSettings = Object.assign(
			{},
			dbSettings,
			typeof dbSettings.pagespeedApiKey !== "undefined" ? { pagespeedApiKey: "********" } : {}
		);
''')
assert b != BLOCK
(CASE_DIR / "variant_vulnerable_02.js").write_text(build(b))

# --- Variant 3: transformed safe variant ---
# Generic masking of every secret-looking key (by name), applied to BOTH
# getAppSettings and the sibling updateAppSettings; upstream instead deletes
# the two known keys in getAppSettings only.
HELPER = '''const SECRET_KEY_PATTERN = /password|apikey|secret|token/i;

const maskSecrets = (settings) => {
	const masked = {};
	for (const [key, value] of Object.entries(settings || {})) {
		masked[key] = SECRET_KEY_PATTERN.test(key) && typeof value !== "undefined" ? "********" : value;
	}
	return masked;
};

'''
CLASS = "class SettingsController {\n"
assert original.count(CLASS) == 1
b = BLOCK.replace(MASK, "\t\tconst sanitizedSettings = maskSecrets(dbSettings);\n")
safe = build(b)
safe = safe.replace(CLASS, HELPER + CLASS)
safe = safe.replace(UPD, '''			const updatedSettings = maskSecrets(await this.settingsService.reloadSettings());
			delete updatedSettings.jwtSecret;
''')
assert safe.count("maskSecrets(") == 2 and safe.count("const maskSecrets = ") == 1 and "{ ...dbSettings }" not in safe and "{ ...(await" not in safe
(CASE_DIR / "variant_safe_01.js").write_text(safe)

# --- Variant 4: benign structural look-alike ---
benign_source = '''const PUBLIC_FIELDS = ["appName", "logoUrl", "supportEmail"];

/**
 * Same "res.success({ msg, data }) with the stored settings" shape, but the
 * response is built by picking an explicit allow-list of PUBLIC branding
 * fields, so no secret (password, API key, token) can ever be in it -- new
 * secret fields added to the settings document later are excluded by
 * default.
 */
export const getPublicBranding = (settingsService, stringService) => async (req, res) => {
	const stored = await settingsService.getDBSettings();
	const data = {};
	for (const field of PUBLIC_FIELDS) {
		if (typeof stored[field] !== "undefined") {
			data[field] = stored[field];
		}
	}
	return res.success({ msg: stringService.getPublicBranding, data });
};
'''
assert "PUBLIC_FIELDS" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)
print("Wrote 4 new samples for CASE-0132.")
