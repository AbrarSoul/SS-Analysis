"""
Section 9 ground-truth test bundle: CASE-0173
(honojs/hono, src/adapter/cloudflare-workers/utils.ts getContentFromKVAsset,
CVE-2026-24473, CWE-200 / CWE-284 / CWE-668 exposure of resources).

Located target: `const key = ASSET_MANIFEST[path] || path`.

Core vulnerable mechanism: the helper maps the requested `path` through the
asset manifest to the deployed (hashed) KV key, but FALLS BACK to the raw
request `path` when the manifest has no entry, and then reads that key from
the KV namespace. Anything stored in the same KV namespace but not listed in
the manifest can therefore be fetched just by naming its key in the URL.
Measured with a fake KV: `secret.txt` (in KV, not in the manifest) is
returned. The upstream fix drops the fallback (`const key = ASSET_MANIFEST[path]`).

Measured caveat, kept in the manifest notes: upstream still indexes the
manifest object with the raw path, so `constructor` and `__proto__` (inherited
properties) return a truthy non-string and become the KV key; the safe
variant uses an own-property check.

Sibling sites: none in this file.

Every variant is the FULL real file. getContentFromKVAsset is the exported
API, so the renamed variant keeps the name and renames parameters and locals.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0173"
original = (CASE_DIR / "vulnerable_source.ts").read_text()
assert "\r" not in original

KEY = '''  const key = ASSET_MANIFEST[path] || path
  if (!key) {
    return null
  }
'''
assert original.count(KEY) == 1
s = original.index("export const getContentFromKVAsset = async (")


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


# --- Variant 1: renamed vulnerable variant ---
head, code = original[:s], original[s:]
lines = []
for line in code.split("\n"):
    if line.lstrip().startswith("//"):
        lines.append(line)
        continue
    parts = re.split(r"""('(?:[^'\\]|\\.)*')""", line)
    for i in range(0, len(parts), 2):
        for old, new in (("ASSET_MANIFEST", "manifestMap"), ("ASSET_NAMESPACE", "kvNamespace"), ("options", "opts"),
                         ("path", "assetPath"), ("key", "storageKey"), ("content", "body")):
            parts[i] = re.sub(r"(?<![.\w$])%s(?![\w$])" % old, new, parts[i])
    lines.append("".join(parts))
v1 = head + "\n".join(lines)
assert "let manifestMap: Record<string, string>" in v1 and "const storageKey = manifestMap[assetPath] || assetPath" in v1
assert "await kvNamespace.get(storageKey, { type: 'stream' })" in v1 and "typeof opts.manifest === 'string'" in v1
assert "  path: string" not in v1 and "assetPath: string," in v1
assert "options?: KVAssetOptions" not in v1 and "opts?: KVAssetOptions" in v1
assert "manifest?: object | string" in v1 and "namespace?: unknown" in v1
(CASE_DIR / "variant_vulnerable_01.ts").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant ---
v2 = swap(original, KEY, '''  const key = resolveKey(ASSET_MANIFEST, path)
  if (!key) {
    return null
  }
''')
v2 = swap(v2, "export const getContentFromKVAsset = async (", '''const resolveKey = (manifest: Record<string, string>, path: string): string => manifest[path] || path

export const getContentFromKVAsset = async (''')
(CASE_DIR / "variant_vulnerable_02.ts").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, KEY, '''  const key = Object.prototype.hasOwnProperty.call(ASSET_MANIFEST, path)
    ? ASSET_MANIFEST[path]
    : undefined
  if (!key) {
    return null
  }
''')
(CASE_DIR / "variant_safe_01.ts").write_text(v3)

# --- Variant 4: benign structural look-alike ---
benign_source = '''const DEFAULT_PAGE = 'index.html'

/**
 * Same `manifest[name] || <fallback>` shape as the KV asset lookup, but the
 * fallback is a developer-written constant, never the caller's input, so an
 * unknown name can only ever resolve to the public default page.
 */
export const resolvePublicKey = (manifest: Record<string, string>, name: string): string => {
  return manifest[name] || DEFAULT_PAGE
}
'''
assert "DEFAULT_PAGE" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)
print("Wrote 4 new samples for CASE-0173.")
