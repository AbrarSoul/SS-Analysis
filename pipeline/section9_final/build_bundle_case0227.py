"""
Section 9 ground-truth test bundle: CASE-0227
(mintplex-labs/anything-llm, collector/utils/files/index.js normalizePath,
CVE-2024-5211, CWE-29 path traversal `\\..\\filename`).

Core vulnerable mechanism: `normalizePath` sanitises a caller-supplied file
name before it is joined with the collector's hot directory. It runs
`path.normalize(filepath.trim())`, removes leading `../` (or `..\\`) groups with
`/^(\\.\\.(\\/|\\\\|$))+/`, and then `.trim()`s the result. Whitespace between two
traversal groups defeats that: for `"../ ../etc/passwd"` normalize leaves the
string unchanged (the second segment is ` ..`, a normal name), the regexp strips
only the first `../`, and the final `.trim()` turns the remaining
` ../etc/passwd` into `../etc/passwd`, a fresh leading traversal. Joined with the
hot directory the result lands outside it, where the collector's write and
delete helpers act on files. The upstream fix rewrites all whitespace to `-`
before normalising.

Measured caveat, kept in the manifest notes: the upstream fix also renames
every legitimate name that contains a space (`my file.pdf` -> `my-file.pdf`). The
safe variant leaves ordinary names alone and instead rejects any result that
still contains a `..` path segment after trimming each segment.

Sibling sites: normalizePath is defined once here; other modules import it
(the server has its own copy, out of this file).

Verification: each full variant is loaded as a real Node module (its only
sibling import, ./mime, is replaced by a stub file) and normalizePath is run on a
list of inputs; the result is joined with a hot directory and tested with the
file's own isWithin.

Every variant is the FULL real file. normalizePath is exported and imported by name
elsewhere, so its name and signature are kept; the renamed variant renames the
parameter and local.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0227"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


FN = '''function normalizePath(filepath = "") {
  const result = path
    .normalize(filepath.trim())
    .replace(/^(\\.\\.(\\/|\\\\|$))+/, "")
    .trim();
  if (["..", ".", "/"].includes(result)) throw new Error("Invalid path.");
  return result;
}
'''
assert original.count(FN) == 1

v1 = swap(original, FN, '''function normalizePath(userPath = "") {
  const cleaned = path
    .normalize(userPath.trim())
    .replace(/^(\\.\\.(\\/|\\\\|$))+/, "")
    .trim();
  if (["..", ".", "/"].includes(cleaned)) throw new Error("Invalid path.");
  return cleaned;
}
''')
(CASE_DIR / "variant_vulnerable_01.js").write_text(v1)

v2 = swap(original, FN, '''function normalizePath(filepath = "") {
  let result = path.normalize(filepath.trim());
  result = result.replace(/^(\\.\\.(\\/|\\\\|$))+/, "");
  result = result.trim();
  if (["..", ".", "/"].includes(result)) throw new Error("Invalid path.");
  return result;
}
''')
(CASE_DIR / "variant_vulnerable_02.js").write_text(v2)

v3 = swap(original, FN, '''function normalizePath(filepath = "") {
  const result = path
    .normalize(filepath.trim())
    .replace(/^(\\.\\.(\\/|\\\\|$))+/, "")
    .trim();
  if (["..", ".", "/"].includes(result)) throw new Error("Invalid path.");
  // whitespace around a segment must not hide a traversal segment
  const segments = result.split(/[\\\\/]+/).map((segment) => segment.trim());
  if (segments.includes("..")) throw new Error("Invalid path.");
  return result;
}
''')
(CASE_DIR / "variant_safe_01.js").write_text(v3)

BENIGN = '''// Standalone example of the same shape: tidy a display title by trimming
// and collapsing runs of whitespace; the value is only shown in a heading and
// never used as a path.
function tidyTitle(title = "") {
  const result = title.trim().replace(/\\s+/g, " ").trim();
  if (["", "-"].includes(result)) throw new Error("Invalid title.");
  return result;
}

module.exports = { tidyTitle };
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN)
