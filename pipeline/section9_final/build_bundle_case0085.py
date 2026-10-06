"""
Section 9 ground-truth test bundle: CASE-0085
(aedart/ion, CVE-2023-30857, CWE-1321 prototype pollution).

Core vulnerable mechanism: `resolveMetadataRecord()` creates the record
that user-supplied meta keys/paths are later written into (via
`set(metadata, entry.key, entry.value)`) with a plain `{}` literal. That
object inherits from Object.prototype, so a crafted key/path such as
`__proto__.polluted` walks INTO Object.prototype and pollutes every object
in the process. The upstream fix creates the record with
`Object.create(null)` so it has no prototype to reach.

NOTE: the auto-locator originally extracted only the one-line `?? {}`
expression as this case's "function" (it mistook the empty object literal
for a method block); fixed in auto_locate_target._looks_method_like (an
operator after the last ")" means an object literal, not a method). The
target here is the enclosing resolveMetadataRecord function.

Every variant is the FULL real file with resolveMetadataRecord replaced
(the renamed variant also renames its call site in save()).
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0085"
original = "\n".join(l.rstrip() for l in (CASE_DIR / "vulnerable_source.ts").read_text().splitlines()) + "\n"

START = "function resolveMetadataRecord(owner: object, context: Context, useMetaFromContext: boolean): MetadataRecord\n{"
s = original.index(START)
e = original.index("\n}\n", s) + 3
BLOCK = original[s:e]
assert original.count(START) == 1
assert "registry.get(owner) ?? {};" in BLOCK


def build(new_block):
    assert new_block != BLOCK
    return original[:s] + new_block + original[e:]


# --- Variant 1: renamed vulnerable variant ---
b = BLOCK
for old, new in (("resolveMetadataRecord", "obtainWritableRecord"), ("owner", "target"),
                 ("context", "decoratorContext"), ("useMetaFromContext", "preferContextMeta"),
                 ("metadata", "record")):
    b = re.sub(r"\b%s\b" % old, new, b)
# `context.metadata` is a property of the decorator context and must keep its name
b = b.replace("decoratorContext.record", "decoratorContext.metadata")
renamed = build(b)
renamed = re.sub(r"\bresolveMetadataRecord\b", "obtainWritableRecord", renamed)  # call site + doc
assert "resolveMetadataRecord" not in renamed
assert renamed.count("obtainWritableRecord") >= 2
assert "registry.get(target) ?? {};" in renamed and "decoratorContext.metadata as MetadataRecord" in renamed
(CASE_DIR / "variant_vulnerable_01.ts").write_text(renamed)

# --- Variant 2: structurally changed vulnerable variant ---
(CASE_DIR / "variant_vulnerable_02.ts").write_text(build(BLOCK.replace(
    "    let metadata: MetadataRecord = registry.get(owner) ?? {};",
    "    const existing: MetadataRecord | undefined = registry.get(owner);\n"
    "    let metadata: MetadataRecord;\n"
    "    if (existing !== undefined) {\n"
    "        metadata = existing;\n"
    "    } else {\n"
    "        metadata = {};\n"
    "    }")))

# --- Variant 3: transformed safe variant ---
# Strips the prototype from whatever record is used (new OR fetched from the
# registry) via Object.setPrototypeOf(x, null), rather than only creating new
# records with Object.create(null) as upstream does.
(CASE_DIR / "variant_safe_01.ts").write_text(build(BLOCK.replace(
    "    let metadata: MetadataRecord = registry.get(owner) ?? {};",
    "    let metadata: MetadataRecord = Object.setPrototypeOf(registry.get(owner) ?? {}, null);")))

# --- Variant 4: benign structural look-alike ---
(CASE_DIR / "benign_lookalike.ts").write_text("""type RenderOptions = Record<string, string | number | boolean>;

/**
 * Same `x ?? {}` default-object shape as the metadata record, but this bag
 * only ever receives fixed, developer-chosen option names below; no
 * externally supplied key or path is ever written into it, so there is no
 * prototype-pollution vector.
 */
export function resolveRenderOptions(overrides?: RenderOptions): RenderOptions {
    const options: RenderOptions = overrides ?? {};
    options.indent = options.indent ?? 4;
    options.sortKeys = options.sortKeys ?? true;
    return options;
}
""")
print("Wrote 4 new samples for CASE-0085.")
