"""
Section 9 ground-truth test bundle: CASE-0210
(kindspells/astro-shield, @kindspells/astro-shield/src/core.mjs
updateDynamicPageSriHashes, CVE-2024-30250, CWE-345 insufficient
verification of data authenticity).

Core vulnerable mechanism: `updateDynamicPageSriHashes` post-processes an
already-rendered (dynamic/SSR) HTML page to attach `integrity` attributes,
using `globalHashes` as the trusted allow-list of real SRI hashes (normally
populated ahead of time by `updateStaticPageSriHashes` scanning the actual
build output). When it meets a `<script src="...">`/`<link href="...">` tag
that ALREADY carries an `integrity="..."` attribute and that `src` is NOT yet
in `globalHashes`, the vulnerable code does not treat "unknown resource" as
suspicious -- it does `globalHashes[t2].set(src, sriHash)`, i.e. it takes
whatever hash value is sitting in the untrusted, already-rendered HTML and
adopts it as the henceforth-trusted expected hash for that URL. Since the
dynamic page content is exactly the thing an attacker with any influence
over what gets rendered (templated user content, a compromised upstream
include, a CMS field) can shape, an attacker can add
`<script src="https://evil.example/x.js" integrity="sha256-<hash of x.js>">`
for a resource they control, and the tool will silently accept and
"vouch for" it -- defeating the purpose of SRI, which is supposed to
originate from hashes computed at build time from real, known-good content,
not read back out of the page being protected. The upstream fix stops
short-circuit-trusting an unknown `src`+`integrity` pair: if `src` is not
already in `globalHashes`, the element is logged and REMOVED from the output
rather than adopted.

Sibling sites: `updateStaticPageSriHashes` has a structurally similar
integrity-attribute block, but by design (per its own docstring: "it assumes
... that in case it already contains integrity attributes then they are
correct") it processes the site's OWN static build output, not
attacker-influenced dynamic content, so unconditionally trusting an embedded
hash there is the intended threat model and it is correctly left unchanged
by the real upstream patch too -- not a sibling of this vulnerability.

Verification: the real file (each full variant) is imported as a Node ES
module, with `./fs.mjs` and `./headers.mjs` (unrelated sibling files this
case does not include, and not reached by `updateDynamicPageSriHashes`)
replaced by empty stub modules alongside it. `updateDynamicPageSriHashes` is
called directly with real `node:crypto`-backed `generateSRIHash` in scope,
`globalHashes = {scripts: new Map(), styles: new Map()}` (nothing
pre-registered, as for a first-seen resource), and HTML containing
`<script src="https://evil.example/x.js" integrity="sha256-attacker-hash">`.
The resulting `globalHashes.scripts` map and the returned HTML are inspected.

Every variant is the FULL real file. `updateDynamicPageSriHashes` is
exported and imported by name from `main.js` elsewhere in the real package,
so its name and signature are never changed; the renamed variant renames
only its internal locals.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0210"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

dyn_start = original.index("export const updateDynamicPageSriHashes")
s = original.index("\t\t\t\tif (integrityMatch) {\n\t\t\t\t\tsriHash =", dyn_start)
e = original.index('\n\n\t\t\t\tif (src) {', s) + 1
BLOCK = original[s:e]
assert original.count(BLOCK) == 1


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
# sriHash is declared (`let sriHash = undefined`) outside this block and used
# after it, so it keeps its name; only the block-local `globalHash` (declared
# with `const` right here) is renamed.
V1 = '''\t\t\t\tif (integrityMatch) {
\t\t\t\t\tsriHash =
\t\t\t\t\t\tintegrityMatch.groups?.integrity1 ??
\t\t\t\t\t\tintegrityMatch.groups?.integrity2
\t\t\t\t\tif (sriHash) {
\t\t\t\t\t\tif (src) {
\t\t\t\t\t\t\tconst knownHash = globalHashes[t2].get(src)
\t\t\t\t\t\t\tif (knownHash) {
\t\t\t\t\t\t\t\tif (knownHash !== sriHash) {
\t\t\t\t\t\t\t\t\tthrow new Error(
\t\t\t\t\t\t\t\t\t\t`SRI hash mismatch for "${src}", expected "${knownHash}" but got "${sriHash}"`,
\t\t\t\t\t\t\t\t\t)
\t\t\t\t\t\t\t\t}
\t\t\t\t\t\t\t} else {
\t\t\t\t\t\t\t\tglobalHashes[t2].set(src, sriHash)
\t\t\t\t\t\t\t}
\t\t\t\t\t\t}
\t\t\t\t\t\tpageHashes[t2].add(sriHash)
\t\t\t\t\t} else {
\t\t\t\t\t\tlogger.warn('Found empty integrity attribute, skipping...')
\t\t\t\t\t}
\t\t\t\t\tcontinue
\t\t\t\t}
'''
assert V1 != BLOCK
v1 = build(V1)
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
# The trust-and-register step is extracted into a helper, still adopted
# unconditionally for a src not yet in globalHashes.
V2 = '''\t\t\t\tif (integrityMatch) {
\t\t\t\t\tsriHash =
\t\t\t\t\t\tintegrityMatch.groups?.integrity1 ??
\t\t\t\t\t\tintegrityMatch.groups?.integrity2
\t\t\t\t\tif (sriHash) {
\t\t\t\t\t\tif (src) {
\t\t\t\t\t\t\trememberResourceHash(globalHashes, t2, src, sriHash)
\t\t\t\t\t\t}
\t\t\t\t\t\tpageHashes[t2].add(sriHash)
\t\t\t\t\t} else {
\t\t\t\t\t\tlogger.warn('Found empty integrity attribute, skipping...')
\t\t\t\t\t}
\t\t\t\t\tcontinue
\t\t\t\t}
'''
assert V2 != BLOCK
v2 = build(V2)
assert v2.count("export const updateDynamicPageSriHashes") == 1
helper = '''const rememberResourceHash = (globalHashes, t2, src, sriHash) => {
\tconst globalHash = globalHashes[t2].get(src)
\tif (globalHash) {
\t\tif (globalHash !== sriHash) {
\t\t\tthrow new Error(
\t\t\t\t`SRI hash mismatch for "${src}", expected "${globalHash}" but got "${sriHash}"`,
\t\t\t)
\t\t}
\t} else {
\t\tglobalHashes[t2].set(src, sriHash)
\t}
}

'''
v2 = v2.replace(
    "export const updateDynamicPageSriHashes",
    helper + "export const updateDynamicPageSriHashes",
    1,
)
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

# --- Variant 3: transformed safe variant ---
# Splits the "already-known" and "not yet known" cases into two explicit
# branches (upstream restructures the same logic inline); a src not already
# present in globalHashes is treated as unverifiable and the element is
# dropped, instead of being adopted as newly-trusted.
V3 = '''\t\t\t\tif (integrityMatch) {
\t\t\t\t\tconst claimedHash =
\t\t\t\t\t\tintegrityMatch.groups?.integrity1 ??
\t\t\t\t\t\tintegrityMatch.groups?.integrity2
\t\t\t\t\tif (!claimedHash) {
\t\t\t\t\t\tlogger.warn(
\t\t\t\t\t\t\t`Found empty integrity attribute, removing inline ${t.toLowerCase()} block.`,
\t\t\t\t\t\t)
\t\t\t\t\t\tupdatedContent = updatedContent.replace(match[0], '')
\t\t\t\t\t\tcontinue
\t\t\t\t\t}
\t\t\t\t\tif (src) {
\t\t\t\t\t\tconst isKnownResource = globalHashes[t2].has(src)
\t\t\t\t\t\tif (!isKnownResource) {
\t\t\t\t\t\t\tlogger.warn(
\t\t\t\t\t\t\t\t`Detected reference to not explicitly allowed external resource "${src}". Removing it.`,
\t\t\t\t\t\t\t)
\t\t\t\t\t\t\tupdatedContent = updatedContent.replace(match[0], '')
\t\t\t\t\t\t\tcontinue
\t\t\t\t\t\t}
\t\t\t\t\t\tconst globalHash = globalHashes[t2].get(src)
\t\t\t\t\t\tif (globalHash !== claimedHash) {
\t\t\t\t\t\t\tlogger.warn(
\t\t\t\t\t\t\t\t`Detected integrity hash mismatch for resource "${src}". Removing it.`,
\t\t\t\t\t\t\t)
\t\t\t\t\t\t\tupdatedContent = updatedContent.replace(match[0], '')
\t\t\t\t\t\t\tcontinue
\t\t\t\t\t\t}
\t\t\t\t\t\tsriHash = claimedHash
\t\t\t\t\t\tpageHashes[t2].add(sriHash)
\t\t\t\t\t\tcontinue
\t\t\t\t\t}
\t\t\t\t\tsriHash = claimedHash
\t\t\t\t\tpageHashes[t2].add(sriHash)
\t\t\t\t\tcontinue
\t\t\t\t}
'''
assert V3 != BLOCK
v3 = build(V3)
(CASE_DIR / "variant_safe_01.js").write_text(v3)

# --- Variant 4: benign look-alike ---
BENIGN = '''// Standalone example of the same shape as the fixed SRI-trust check (verify
// a claimed value against an independently-established allow-list; treat an
// unknown key as unverifiable rather than adopting the claim) but over a
// purely local, non-adversarial lookup table with no untrusted input.

/**
 * @param {Map<string, string>} knownUnits
 * @param {string} itemName
 * @param {string} claimedUnit
 * @returns {{ok: boolean, reason?: string}}
 */
export const checkDisplayUnit = (knownUnits, itemName, claimedUnit) => {
\tif (!knownUnits.has(itemName)) {
\t\treturn { ok: false, reason: `no configured unit for "${itemName}"` }
\t}
\tconst expected = knownUnits.get(itemName)
\tif (expected !== claimedUnit) {
\t\treturn { ok: false, reason: `unit mismatch for "${itemName}"` }
\t}
\treturn { ok: true }
}
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
