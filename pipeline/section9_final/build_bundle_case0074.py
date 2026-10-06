"""
Section 9 ground-truth test bundle: CASE-0074
(SignalK/signalk-server, CVE-2026-25228, CWE-22 path traversal).

Core vulnerable mechanism: `pathForApplicationData()` joins the
application-data directory with a version-derived filename via
`path.join(...)` and returns the result with NO verification that it
actually stays within the intended configuration directory. Combined
with `validateAppId()`'s incomplete separator check elsewhere in this
file (missing a backslash check, letting Windows-style traversal through)
a crafted `appid`/`version` can make the joined path resolve outside the
server's config directory entirely, exposing arbitrary files reachable by
the server process. The fix normalizes the joined path, resolves both it
and the configured config directory to absolute form, and rejects the
result if it doesn't start with the config directory's own resolved path.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0074"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = '''  function pathForApplicationData(req, appid, version, isUser) {
    return path.join(
      dirForApplicationData(req, appid, isUser),
      `${version}.json`
    )
  }'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename pathForApplicationData -> resolveAppDataPath, appid ->
# applicationId, version -> dataVersion. Same exact unverified path join.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''  function resolveAppDataPath(req, applicationId, dataVersion, isUser) {
    return path.join(
      dirForApplicationData(req, applicationId, isUser),
      `${dataVersion}.json`
    )
  }''',
)
assert "function resolveAppDataPath(req, applicationId, dataVersion, isUser) {" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable holding the filename before the
# join. Same exact unverified path join, no renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''  function pathForApplicationData(req, appid, version, isUser) {
    const dataDir = dirForApplicationData(req, appid, isUser)
    const fileName = `${version}.json`
    return path.join(dataDir, fileName)
  }''',
)
assert structural_source != original
assert "const dataDir = dirForApplicationData(req, appid, isUser)" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (verify the joined path can't escape the
# config directory) but a materially different technique: uses
# path.relative() between the config dir and the candidate path, and
# rejects it if the relative path starts with ".." or is itself absolute
# (both indicate escape) -- instead of the real patch's resolve()+
# startsWith() string-prefix check. Genuinely equivalent containment
# check, different API/algorithm.
SAFE_SOURCE = '''const path = require('path')

function pathForApplicationData(req, appid, version, isUser, dirForApplicationData, configPath) {
  const candidatePath = path.normalize(
    path.join(dirForApplicationData(req, appid, isUser), `${version}.json`)
  )
  const relative = path.relative(configPath, candidatePath)
  const escapesConfigDir = relative.startsWith('..') || path.isAbsolute(relative)
  if (escapesConfigDir) {
    throw new Error('Invalid path: outside configuration directory')
  }
  return candidatePath
}

module.exports = { pathForApplicationData }
'''
(CASE_DIR / "variant_safe_01.js").write_text(SAFE_SOURCE)
assert "path.relative" in SAFE_SOURCE

# --- Verify the relative()-based containment check genuinely rejects a
# traversal attempt and genuinely accepts a legitimate in-bounds path ---
import subprocess

node_check = """
const path = require('path')
const { pathForApplicationData } = require('./variant_safe_01.js')

const configPath = '/etc/signalk'
const dirForApplicationData = () => '/etc/signalk/applicationData/user1'

// Legitimate case: should NOT throw
try {
  pathForApplicationData({}, 'myapp', '1.0.0', true, dirForApplicationData, configPath)
  console.log('OK: legitimate path accepted')
} catch (e) {
  console.error('FAIL: legitimate path was rejected:', e.message)
  process.exit(1)
}

// Traversal case: dirForApplicationData itself resolves outside configPath
const maliciousDirFn = () => '/etc/signalk/applicationData/../../../etc'
try {
  pathForApplicationData({}, 'x', 'passwd', true, maliciousDirFn, configPath)
  console.error('FAIL: traversal path was NOT rejected')
  process.exit(1)
} catch (e) {
  console.log('OK: traversal path correctly rejected:', e.message)
}
"""
proc = subprocess.run(["node", "-e", node_check], capture_output=True, text=True, cwd=str(CASE_DIR))
assert proc.returncode == 0, f"safe variant failed live verification: {proc.stdout} {proc.stderr}"

# --- Variant 4: benign structural look-alike ---
# Same visible shape (path.join(directory, variableName)) but this
# sibling always builds the filename from a FIXED, hard-coded constant
# ("manifest.json"), never from a request-derived appid/version pair --
# so there is no traversal-capable input that could ever influence the
# resulting path, unlike pathForApplicationData()'s version-derived
# filename.
BENIGN_SOURCE = '''const path = require('path')

function pathForServerManifest(baseDir) {
  // The filename here is always the fixed literal "manifest.json" --
  // never derived from a request parameter -- so there is no traversal-
  // capable input this join could ever receive.
  return path.join(baseDir, 'manifest.json')
}

module.exports = { pathForServerManifest }
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN_SOURCE)
assert "appid" not in BENIGN_SOURCE
assert "version" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0074.")
