"""
Section 9 ground-truth test bundle: CASE-0283
(sebhildebrandt/systeminformation, lib/util.js sanitizeShellString,
CVE-2020-26300, CWE-77/CWE-78 command injection).

Core vulnerable mechanism: systeminformation builds shell command lines by
string concatenation (`exec('cmd ' + userValue)`), first passing caller
values through `sanitizeShellString`, a DENYLIST that deletes a fixed set of
shell metacharacters (`> < * ? [ ] | backtick $ ; & ( ) # and backslash). The
list omits the newline and tab characters: `sh -c` treats a newline as a
command separator exactly like `;`, so a value such as
`eth0\ntouch /tmp/pwned` passes through unchanged and runs the second line
as an attacker-chosen command (and `"` lets a value break out of any
double-quoted context). The upstream fix adds `\t`, `\n` and `"` to the
deletion list.

Measured caveat, kept in the manifest notes: the fix is still a denylist;
characters such as single quote, `{`, `}`, `!`, `%`, `~` and `\r` are still
passed through, so it hardens this specific bypass rather than removing the
class. This bundle's safe variant instead uses an allow-list (delete
everything except letters, digits, space and a few harmless punctuation
characters), which is strictly stronger for the tested property.

Sibling sites: `sanitizeShellString` is the single sanitizer; there is one
function to change.

Verification: each full file's `sanitizeShellString` function is extracted
verbatim, evaluated in Node, and used the way the library uses it: the
sanitized payload `a\ntouch MARKER` is concatenated into a REAL shell
command via `child_process.execSync('echo ' + sanitized)`; whether MARKER
was created (the second line executed) is measured. A benign value
(`eth0`) must pass through unchanged in all variants.

Every variant is the FULL real file. `sanitizeShellString` is exported and
called by name throughout the library, so its name/signature are kept.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0283"
original = (CASE_DIR / "vulnerable_source.js").read_text()
assert "\r" not in original

s = original.index("function sanitizeShellString(str) {")
e = original.index("\n}\n", s) + 3
FUNC = original[s:e]
assert original.count(FUNC) == 1

# --- Variant 1: renamed vulnerable variant ---
f1 = FUNC.replace("function sanitizeShellString(str) {", "function sanitizeShellString(input) {").replace("let result = str;", "let cleaned = input;")
f1 = re.sub(r"\bresult\b", "cleaned", f1)
assert "result" not in f1
(CASE_DIR / "variant_vulnerable_01.js").write_text(original.replace(FUNC, f1))

# --- Variant 2: structurally changed vulnerable variant ---
f2 = '''const SHELL_METACHARS = [/>/g, /</g, /\\*/g, /\\?/g, /\\[/g, /\\]/g, /\\|/g, /\\`/g, /$/g, /;/g, /&/g, /\\)/g, /\\(/g, /\\$/g, /#/g, /\\\\/g];

function sanitizeShellString(str) {
  return SHELL_METACHARS.reduce((acc, re) => acc.replace(re, ""), str);
}
'''
(CASE_DIR / "variant_vulnerable_02.js").write_text(original.replace(FUNC, f2))

# --- Variant 3: transformed safe variant (allow-list) ---
f3 = '''function sanitizeShellString(str) {
  // allow-list: keep only characters that are never shell-significant
  return String(str).replace(/[^A-Za-z0-9_ .,:\\/@=+-]/g, "");
}
'''
(CASE_DIR / "variant_safe_01.js").write_text(original.replace(FUNC, f3))

(CASE_DIR / "benign_lookalike.js").write_text('''// Standalone example of the same shape: strip characters from a display
// label before rendering it in a terminal table header -- purely cosmetic
// cleanup of text that is never passed to a shell.
function cleanLabel(label) {
  let result = label;
  result = result.replace(/\\t/g, " ");
  result = result.replace(/\\n/g, " ");
  return result.trim();
}

module.exports = { cleanLabel };
''')
