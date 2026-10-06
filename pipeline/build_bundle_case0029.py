"""
Section 9 ground-truth test bundle: CASE-0029
(micromatch/braces, CVE-2018-1109, CWE-185/CWE-400 -- ReDoS via
catastrophic-backtracking regular expression).

Core vulnerable mechanism: the 'multiplier' lexer rule's regex
/^\\{(,+(?:(\\{,+\\})*),*|,*(?:(\\{,+\\})*),+)\\}/ has nested quantifiers over
overlapping content inside an alternation (a repeated group containing an
inner repeated group, matched against the same comma characters both
alternatives can also match). A crafted brace-expression input (long runs
of commas/nested braces) triggers exponential-time catastrophic
backtracking -- a denial of service. Only m[0] (the full match) is used
downstream, so the capture-group structure is free to change.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0029"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = (
    "    .set('multiplier', function() {\n"
    "      var isInside = this.isInside('brace');\n"
    "      var pos = this.position();\n"
    "      var m = this.match(/^\\{(,+(?:(\\{,+\\})*),*|,*(?:(\\{,+\\})*),+)\\}/);\n"
    "      if (!m) return;\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

# --- Variant 1: renamed vulnerable variant ---
# Rename isInside -> insideBrace, pos -> startPos, m -> match within this
# callback (checking downstream uses in the same function are updated
# too). Same exact vulnerability: still the catastrophic-backtracking
# regex.
FULL_CALLBACK_OLD = (
    "    .set('multiplier', function() {\n"
    "      var isInside = this.isInside('brace');\n"
    "      var pos = this.position();\n"
    "      var m = this.match(/^\\{(,+(?:(\\{,+\\})*),*|,*(?:(\\{,+\\})*),+)\\}/);\n"
    "      if (!m) return;\n"
    "\n"
    "      this.multiplier = true;\n"
    "      var prev = this.prev();\n"
    "      var val = m[0];\n"
    "\n"
    "      if (isInside && prev.type === 'brace') {\n"
    "        prev.text = prev.text || '';\n"
    "        prev.text += val;\n"
    "      }\n"
    "\n"
    "      var node = pos(new Node({\n"
    "        type: 'text',\n"
    "        multiplier: 1,\n"
    "        match: m,\n"
    "        val: val\n"
    "      }));\n"
    "\n"
    "      return concatNodes.call(this, pos, node, prev, options);\n"
    "    })\n"
)
assert FULL_CALLBACK_OLD in original

renamed_callback = (
    "    .set('multiplier', function() {\n"
    "      var insideBrace = this.isInside('brace');\n"
    "      var startPos = this.position();\n"
    "      var match = this.match(/^\\{(,+(?:(\\{,+\\})*),*|,*(?:(\\{,+\\})*),+)\\}/);\n"
    "      if (!match) return;\n"
    "\n"
    "      this.multiplier = true;\n"
    "      var prev = this.prev();\n"
    "      var val = match[0];\n"
    "\n"
    "      if (insideBrace && prev.type === 'brace') {\n"
    "        prev.text = prev.text || '';\n"
    "        prev.text += val;\n"
    "      }\n"
    "\n"
    "      var node = startPos(new Node({\n"
    "        type: 'text',\n"
    "        multiplier: 1,\n"
    "        match: match,\n"
    "        val: val\n"
    "      }));\n"
    "\n"
    "      return concatNodes.call(this, startPos, node, prev, options);\n"
    "    })\n"
)
renamed_source = original.replace(FULL_CALLBACK_OLD, renamed_callback)
assert renamed_source != original
assert "var insideBrace = this.isInside('brace');" in renamed_source
assert "var startPos = this.position();" in renamed_source
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: introduction of intermediate variable -- the regex literal
# is assigned to a named variable before being passed to this.match().
# Same exact vulnerability (identical catastrophic-backtracking regex),
# no renaming.
STRUCTURAL_BLOCK = (
    "    .set('multiplier', function() {\n"
    "      var isInside = this.isInside('brace');\n"
    "      var pos = this.position();\n"
    "      var multiplierRegex = /^\\{(,+(?:(\\{,+\\})*),*|,*(?:(\\{,+\\})*),+)\\}/;\n"
    "      var m = this.match(multiplierRegex);\n"
    "      if (!m) return;\n"
)
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
assert structural_source != original
assert "var multiplierRegex = " in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same class of fix as upstream (eliminates the nested-quantifier
# ambiguity that causes catastrophic backtracking) but via a plain
# character class (/^\{[,{}]+\}/) instead of the real patch's grouped
# alternation (/^\{((?:,|\{,+\})+)\}/) -- a materially different, still
# linear-time regex, not byte-identical to the known fix.
SAFE_BLOCK = (
    "    .set('multiplier', function() {\n"
    "      var isInside = this.isInside('brace');\n"
    "      var pos = this.position();\n"
    "      var m = this.match(/^\\{[,{}]+\\}/);\n"
    "      if (!m) return;\n"
)
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
assert safe_source != original
assert "this.match(/^\\{[,{}]+\\}/)" in safe_source
assert "(,+(?:(\\{,+\\})*)" not in safe_source.split("'multiplier'")[1].split("'brace.open'")[0]
(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a new lexer rule with a
# similarly complex-looking regex (alternation + repetition), but with no
# overlap between the alternatives and no nested quantifier over
# overlapping content, so it cannot catastrophically backtrack.
BENIGN_ADDITION = (
    "\n"
    "    .set('safe_pattern', function() {\n"
    "      // This regex has alternation and repetition but no nested\n"
    "      // quantifier over overlapping content, so it cannot\n"
    "      // catastrophically backtrack, unlike the multiplier regex above.\n"
    "      var pos = this.position();\n"
    "      var m = this.match(/^\\((?:a|b)+\\)/);\n"
    "      if (!m) return;\n"
    "      return pos(new Node({ type: 'text', val: m[0] }));\n"
    "    })\n"
)
anchor = "    .set('multiplier', function() {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION.strip("\n") + "\n\n" + anchor, 1)
assert benign_source != safe_source
assert "safe_pattern" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)

print("Wrote 4 new samples for CASE-0029.")
