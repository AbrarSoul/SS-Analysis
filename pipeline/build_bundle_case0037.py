"""
Section 9 ground-truth test bundle: CASE-0037
(edmundhung/conform, CVE-2024-32866, CWE-1321 -- prototype pollution).

The real patch fixes three call sites (getPaths' segment filter, setValue's
Object.hasOwn guard, getValue's Object.hasOwn guard). This bundle targets
getPaths() as the representative, root-cause instance (Section 9.3):
blocking dangerous segment names at parse time prevents them from ever
reaching setValue/getValue's traversal logic, which are left untouched in
every variant below.

Core vulnerable mechanism: getPaths() splits a form field name like
"__proto__.polluted" into path segments with no filter on dangerous
segment names ("__proto__", "constructor", "prototype"). Those segments
are later used by setValue()/getValue() to walk and write nested object
properties (pointer[key] = newValue), so a crafted field name can write
through the prototype chain, polluting Object.prototype for the whole
application.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0037"
original = (CASE_DIR / "vulnerable_source.ts").read_text()

VULNERABLE_BLOCK = (
    "export function getPaths(name: string | undefined): Array<string | number> {\n"
    "\tif (!name) {\n"
    "\t\treturn [];\n"
    "\t}\n"
    "\n"
    "\treturn name\n"
    "\t\t.split(/\\.|(\\[\\d*\\])/)\n"
    "\t\t.reduce<Array<string | number>>((result, segment) => {\n"
    "\t\t\tif (typeof segment !== 'undefined' && segment !== '') {\n"
    "\t\t\t\tif (segment.startsWith('[') && segment.endsWith(']')) {\n"
    "\t\t\t\t\tconst index = segment.slice(1, -1);\n"
    "\n"
    "\t\t\t\t\tresult.push(Number(index));\n"
    "\t\t\t\t} else {\n"
    "\t\t\t\t\tresult.push(segment);\n"
    "\t\t\t\t}\n"
    "\t\t\t}\n"
    "\t\t\treturn result;\n"
    "\t\t}, []);\n"
    "}\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"
assert len(re.findall(r"\bgetPaths\b", original)) == 7

# --- Variant 1: renamed vulnerable variant ---
# Rename the exported function getPaths -> parseFieldPaths throughout the
# file (definition, doc comment, and all 5 call sites), and locals
# name/segment/result/index -> fieldName/token/paths/arrayIndex within
# the function body. Same exact vulnerability: still no filter for
# "__proto__"/"constructor"/"prototype" segments.
RENAMED_BLOCK = (
    "export function parseFieldPaths(fieldName: string | undefined): Array<string | number> {\n"
    "\tif (!fieldName) {\n"
    "\t\treturn [];\n"
    "\t}\n"
    "\n"
    "\treturn fieldName\n"
    "\t\t.split(/\\.|(\\[\\d*\\])/)\n"
    "\t\t.reduce<Array<string | number>>((paths, token) => {\n"
    "\t\t\tif (typeof token !== 'undefined' && token !== '') {\n"
    "\t\t\t\tif (token.startsWith('[') && token.endsWith(']')) {\n"
    "\t\t\t\t\tconst arrayIndex = token.slice(1, -1);\n"
    "\n"
    "\t\t\t\t\tpaths.push(Number(arrayIndex));\n"
    "\t\t\t\t} else {\n"
    "\t\t\t\t\tpaths.push(token);\n"
    "\t\t\t\t}\n"
    "\t\t\t}\n"
    "\t\t\treturn paths;\n"
    "\t\t}, []);\n"
    "}\n"
)
renamed_source = original.replace(VULNERABLE_BLOCK, RENAMED_BLOCK)
renamed_source = re.sub(r"\bgetPaths\b", "parseFieldPaths", renamed_source)
assert renamed_source != original
assert "getPaths" not in renamed_source
assert len(re.findall(r"\bparseFieldPaths\b", renamed_source)) == 7
(CASE_DIR / "variant_vulnerable_01.ts").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: equivalent conditional rewriting -- the bracket-index
# branch is rewritten with an early continue-style guard via a ternary
# assignment instead of if/else. Same exact vulnerability (still no
# dangerous-segment filter), no renaming.
STRUCTURAL_BLOCK = (
    "export function getPaths(name: string | undefined): Array<string | number> {\n"
    "\tif (!name) {\n"
    "\t\treturn [];\n"
    "\t}\n"
    "\n"
    "\treturn name\n"
    "\t\t.split(/\\.|(\\[\\d*\\])/)\n"
    "\t\t.reduce<Array<string | number>>((result, segment) => {\n"
    "\t\t\tif (typeof segment !== 'undefined' && segment !== '') {\n"
    "\t\t\t\tconst isArrayIndex = segment.startsWith('[') && segment.endsWith(']');\n"
    "\t\t\t\tconst parsedSegment: string | number = isArrayIndex\n"
    "\t\t\t\t\t? Number(segment.slice(1, -1))\n"
    "\t\t\t\t\t: segment;\n"
    "\t\t\t\tresult.push(parsedSegment);\n"
    "\t\t\t}\n"
    "\t\t\treturn result;\n"
    "\t\t}, []);\n"
    "}\n"
)
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
assert structural_source != original
assert "const isArrayIndex = segment.startsWith('[')" in structural_source
(CASE_DIR / "variant_vulnerable_02.ts").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same security property as the real fix (dangerous prototype-chain
# segment names are never pushed into the resulting path array) but
# implemented via a Set-based membership check against a named constant,
# instead of the real patch's inline chained !== comparisons -- materially
# different structure, not byte-identical to the known fix.
SAFE_BLOCK = (
    "const DANGEROUS_PATH_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);\n"
    "\n"
    "export function getPaths(name: string | undefined): Array<string | number> {\n"
    "\tif (!name) {\n"
    "\t\treturn [];\n"
    "\t}\n"
    "\n"
    "\treturn name\n"
    "\t\t.split(/\\.|(\\[\\d*\\])/)\n"
    "\t\t.reduce<Array<string | number>>((result, segment) => {\n"
    "\t\t\tif (\n"
    "\t\t\t\ttypeof segment !== 'undefined' &&\n"
    "\t\t\t\tsegment !== '' &&\n"
    "\t\t\t\t!DANGEROUS_PATH_SEGMENTS.has(segment)\n"
    "\t\t\t) {\n"
    "\t\t\t\tif (segment.startsWith('[') && segment.endsWith(']')) {\n"
    "\t\t\t\t\tconst index = segment.slice(1, -1);\n"
    "\n"
    "\t\t\t\t\tresult.push(Number(index));\n"
    "\t\t\t\t} else {\n"
    "\t\t\t\t\tresult.push(segment);\n"
    "\t\t\t\t}\n"
    "\t\t\t}\n"
    "\t\t\treturn result;\n"
    "\t\t}, []);\n"
    "}\n"
)
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
assert safe_source != original
assert "DANGEROUS_PATH_SEGMENTS" in safe_source
assert "!DANGEROUS_PATH_SEGMENTS.has(segment)" in safe_source
(CASE_DIR / "variant_safe_01.ts").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a function that also
# splits a string into segments and pushes them into a result array with
# no dangerous-segment filter -- the same superficial shape as the
# vulnerable pattern -- but the segments are only ever used to build a
# display breadcrumb string, never to traverse or assign into a live
# object, so prototype pollution is not reachable through it.
BENIGN_ADDITION = (
    "\n"
    "export function getBreadcrumbSegments(path: string | undefined): Array<string> {\n"
    "\t// The returned segments are only ever joined into a display\n"
    "\t// breadcrumb string -- never used to index into or assign onto a\n"
    "\t// live object -- so a segment named \"__proto__\" here cannot reach\n"
    "\t// the prototype chain, unlike getPaths()'s output above.\n"
    "\tif (!path) {\n"
    "\t\treturn [];\n"
    "\t}\n"
    "\treturn path.split('/').filter((segment) => segment !== '');\n"
    "}\n"
)
anchor = "export function getPaths(name: string | undefined): Array<string | number> {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "getBreadcrumbSegments" in benign_source
(CASE_DIR / "benign_lookalike.ts").write_text(benign_source)

print("Wrote 4 new samples for CASE-0037.")
