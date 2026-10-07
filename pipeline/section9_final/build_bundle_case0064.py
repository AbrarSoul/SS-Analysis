"""
Section 9 ground-truth test bundle: CASE-0064
(NaturalIntelligence/fast-xml-parser, CVE-2026-25896, CWE-185 incorrect
regular expression via unescaped user input).

Core vulnerable mechanism: `addExternalEntities()` builds a regex directly
from each caller-supplied entity key: `new RegExp("&"+ent+";","g")`. `ent`
is used completely unescaped -- if it contains regex-metacharacter
characters (`.`, `*`, `+`, `-`, `:`, etc.), those are interpreted as regex
syntax rather than literal text, so the resulting pattern can match
something entirely different from the literal entity name the caller
configured (e.g. an entity key containing `.` matches ANY character at
that position, not a literal dot) -- letting a value that was only meant
to be compared as a literal string instead behave as an arbitrary,
attacker-influenced regex. The fix escapes the specific regex-special
characters `. - + * :` before building the pattern.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0064"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = '''function addExternalEntities(externalEntities){
  const entKeys = Object.keys(externalEntities);
  for (let i = 0; i < entKeys.length; i++) {
    const ent = entKeys[i];
    this.lastEntities[ent] = {
       regex: new RegExp("&"+ent+";","g"),
       val : externalEntities[ent]
    }
  }
}'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename addExternalEntities -> registerCustomEntities, ent -> entityName,
# entKeys -> keys. Same exact unescaped regex construction.
renamed_source = original.replace(
    VULNERABLE_BLOCK,
    '''function registerCustomEntities(externalEntities){
  const keys = Object.keys(externalEntities);
  for (let i = 0; i < keys.length; i++) {
    const entityName = keys[i];
    this.lastEntities[entityName] = {
       regex: new RegExp("&"+entityName+";","g"),
       val : externalEntities[entityName]
    }
  }
}''',
)
assert "function registerCustomEntities(externalEntities){" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable holding the built pattern string
# before compiling it. Same exact unescaped regex construction, no
# renaming.
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''function addExternalEntities(externalEntities){
  const entKeys = Object.keys(externalEntities);
  for (let i = 0; i < entKeys.length; i++) {
    const ent = entKeys[i];
    const patternSource = "&" + ent + ";";
    this.lastEntities[ent] = {
       regex: new RegExp(patternSource,"g"),
       val : externalEntities[ent]
    }
  }
}''',
)
assert structural_source != original
assert 'const patternSource = "&" + ent + ";";' in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (escape regex-significant characters in the
# caller-supplied key before building the pattern) but a materially
# different technique: a GENERIC escape covering the full standard set of
# JS regex special characters (`.*+?^${}()|[]\\`), via the commonly-used
# `replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&")` idiom, instead of the real
# patch's narrower 5-character class -- strictly broader and still
# genuinely safe, different implementation shape.
SAFE_SOURCE = '''function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&");
}

function addExternalEntities(externalEntities){
  const entKeys = Object.keys(externalEntities);
  for (let i = 0; i < entKeys.length; i++) {
    const ent = entKeys[i];
    const safeEnt = escapeRegExp(ent);
    this.lastEntities[ent] = {
       regex: new RegExp("&"+safeEnt+";","g"),
       val : externalEntities[ent]
    }
  }
}
'''
(CASE_DIR / "variant_safe_01.js").write_text(SAFE_SOURCE)
assert "escapeRegExp" in SAFE_SOURCE

# --- Verify the safe escaping function actually neutralizes a
# metacharacter-bearing key (e.g. confirm "a.b" only matches the literal
# three-character string, not "aXb") ---
import re

def js_style_escape(value):
    return re.sub(r"[.*+?^${}()|\[\]\\]", lambda m: "\\" + m.group(0), value)

pattern = re.compile("&" + js_style_escape("a.b") + ";")
assert pattern.search("&aXb;") is None, "escaped pattern should NOT match a wildcard substitution"
assert pattern.search("&a.b;") is not None, "escaped pattern should still match the literal entity"

# --- Variant 4: benign structural look-alike ---
# Same visible shape (build new RegExp(...) from a key taken out of an
# object via Object.keys()) but this sibling only ever iterates over a
# FIXED, hard-coded internal config object with compile-time-constant key
# names -- never a caller-supplied `externalEntities` argument -- so
# there is no way an attacker-influenced key containing regex
# metacharacters could ever reach the RegExp constructor, unlike
# addExternalEntities()'s externalEntities parameter.
BENIGN_SOURCE = '''const BUILT_IN_PLACEHOLDERS = { amp: "&", lt: "<", gt: ">" };

function compileBuiltInPlaceholderRegexes() {
  // BUILT_IN_PLACEHOLDERS is a fixed object literal defined above, in
  // this module's own source -- never derived from caller input, so its
  // keys can never contain attacker-influenced regex metacharacters.
  const compiled = {};
  const keys = Object.keys(BUILT_IN_PLACEHOLDERS);
  for (let i = 0; i < keys.length; i++) {
    const name = keys[i];
    compiled[name] = new RegExp("&" + name + ";", "g");
  }
  return compiled;
}

module.exports = { compileBuiltInPlaceholderRegexes };
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN_SOURCE)
assert "externalEntities" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0064.")
