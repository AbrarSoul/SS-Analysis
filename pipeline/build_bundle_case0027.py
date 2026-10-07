"""
Section 9 ground-truth test bundle: CASE-0027
(ether/etherpad-lite, CVE-2015-3297, CWE-22 -- path traversal via
validate-then-transform ordering bug).

Core vulnerable mechanism: the containment check
(filename.indexOf(ROOT_DIR) == 0) runs on the normalized path BEFORE a
backslash-to-forward-slash replace. On POSIX, path.normalize() does not
treat "\\" as a separator, so a crafted filename with backslash-encoded
traversal sequences (e.g. "..\\..\\..\\etc\\passwd") passes the
containment check as inert literal characters -- then the later
`.replace(/\\/g, '/')` turns those same characters into REAL path
separators, producing a string that, when used for actual file access,
escapes ROOT_DIR. Validating before a transformation that can reintroduce
meaningful path syntax is the anti-pattern the real fix removes.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0027"
original_lines = (CASE_DIR / "vulnerable_source.js").read_text().splitlines(keepends=True)
original = "".join(original_lines)

# minify()'s full body spans lines 140-242 (0-indexed 139-242); `filename`
# is also used as an unrelated local variable in OTHER functions in this
# file, so any rename must be scoped to just this range to avoid breaking
# those functions' own bindings.
MINIFY_START, MINIFY_END = 139, 242
minify_body = "".join(original_lines[MINIFY_START:MINIFY_END])
assert original_lines[MINIFY_START] == "function minify(req, res, next)\n"
assert minify_body.count("filename") == 23

VULNERABLE_BLOCK = (
    "  var filename = req.params['filename'];\n"
    "\n"
    "  // No relative paths, especially if they may go up the file hierarchy.\n"
    "  filename = path.normalize(path.join(ROOT_DIR, filename));\n"
    "  if (filename.indexOf(ROOT_DIR) == 0) {\n"
    "    filename = filename.slice(ROOT_DIR.length);\n"
    "    filename = filename.replace(/\\\\/g, '/'); // Windows (safe generally?)\n"
    "  } else {\n"
    "    res.writeHead(404, {});\n"
    "    res.end();\n"
    "    return; \n"
    "  }\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"
assert original.count(VULNERABLE_BLOCK) == 1, "must be unique (declaration line anchors it to the first occurrence only)"

# --- Variant 1: renamed vulnerable variant ---
# Rename filename -> requestedFile consistently across the WHOLE minify()
# function body (all 18 occurrences, via word-boundary regex), not just
# the vulnerable lines -- filename is a local variable used throughout
# this function, so a partial rename would leave dangling references.
# Other functions in this file have their own, unrelated local `filename`
# variables and are left untouched. Same exact vulnerability: backslash
# normalization still happens AFTER the containment check.
# req.params['filename'] is Express's route-parameter NAME (a string
# literal key, not the local variable) and must not be renamed -- protect
# it with a sentinel before the word-boundary rename, then restore it.
SENTINEL = "__EXPRESS_ROUTE_PARAM_NAME_SENTINEL__"
protected_body = minify_body.replace("req.params['filename']", f"req.params['{SENTINEL}']")
assert protected_body.count("filename") == 22
renamed_minify_body = re.sub(r"\bfilename\b", "requestedFile", protected_body)
renamed_minify_body = renamed_minify_body.replace(SENTINEL, "filename")
assert renamed_minify_body.count("requestedFile") == 22
assert "req.params['filename']" in renamed_minify_body
renamed_source = "".join(original_lines[:MINIFY_START]) + renamed_minify_body + "".join(original_lines[MINIFY_END:])
assert renamed_source != original
assert "var requestedFile = req.params['filename'];" in renamed_source
assert "requestedFile.replace(/\\\\/g, '/')" in renamed_source
# unrelated filename usage elsewhere in the file, and the Express route
# parameter name string literal, must be untouched
assert renamed_source.count("filename") == original.count("filename") - 22
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: wrapper-function introduction -- the backslash replace is
# moved into a small helper, still called at the same point (after the
# containment check). Same exact vulnerability, no renaming.
STRUCTURAL_BLOCK = VULNERABLE_BLOCK.replace(
    "    filename = filename.replace(/\\\\/g, '/'); // Windows (safe generally?)\n",
    "    filename = normalizeSeparators(filename); // still happens AFTER the check\n",
)
assert STRUCTURAL_BLOCK != VULNERABLE_BLOCK
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
helper = "function normalizeSeparators(str) {\n  return str.replace(/\\\\/g, '/');\n}\n\n"
structural_source = structural_source.replace(
    "function minify(req, res, next)\n", helper + "function minify(req, res, next)\n", 1
)
assert structural_source != original
assert "function normalizeSeparators(str)" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same underlying fix (no meaningful transformation happens AFTER the
# trust decision) but via reordering -- normalize backslashes to forward
# slashes BEFORE the containment check, then check containment against
# the fully-canonical form -- instead of the real patch's simpler
# approach of just deleting the post-check replace. Materially different
# fix mechanism, not byte-identical to the known patch.
SAFE_BLOCK = (
    "  var filename = req.params['filename'];\n"
    "\n"
    "  // No relative paths, especially if they may go up the file hierarchy.\n"
    "  filename = path.normalize(path.join(ROOT_DIR, filename));\n"
    "  filename = filename.replace(/\\\\/g, '/'); // normalize BEFORE checking containment\n"
    "  var normalizedRootDir = ROOT_DIR.replace(/\\\\/g, '/');\n"
    "  if (filename.indexOf(normalizedRootDir) == 0) {\n"
    "    filename = filename.slice(normalizedRootDir.length);\n"
    "  } else {\n"
    "    res.writeHead(404, {});\n"
    "    res.end();\n"
    "    return; \n"
    "  }\n"
)
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
assert safe_source != original
assert "filename = filename.replace(/\\\\/g, '/'); // normalize BEFORE checking containment" in safe_source
# a second, separate instance of the same pattern exists later in the file
# (the plugin-path branch) and is NOT part of the real patch's fix scope
# (the official diff only touches this one occurrence) -- left untouched,
# same as CASE-0016's sibling-method handling.
assert safe_source.count("filename = filename.replace(/\\\\/g, '/'); // Windows (safe generally?)") == 1
(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a function that also does
# a `.replace(/\\/g, '/')` transformation -- the same superficial API
# surface as the vulnerable line -- but on a value only ever used for a
# human-readable log line, never passed back into any filesystem or
# access-control decision, so a check-then-transform ordering issue is
# not even possible here.
BENIGN_ADDITION = (
    "\n"
    "function formatPathForDisplay(resolvedAbsolutePath) {\n"
    "  // resolvedAbsolutePath here is only ever used for a human-readable\n"
    "  // log line -- never passed to fs.* or used for any access-control\n"
    "  // decision afterward -- so transforming separators after the fact\n"
    "  // carries none of the check-then-transform risk in minify() above.\n"
    "  return resolvedAbsolutePath.replace(/\\\\/g, '/');\n"
    "}\n"
)
anchor = "function minify(req, res, next)\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "formatPathForDisplay" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)

print("Wrote 4 new samples for CASE-0027.")
