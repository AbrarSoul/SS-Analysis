"""
Section 9 ground-truth test bundle: CASE-0063
(MrRio/jsPDF, CVE-2021-23353, ReDoS via catastrophic regex backtracking).

Core vulnerable mechanism: `extractImageFromDataUrl()` parses a data: URL
prefix with `/^data:(\\w*\\/\\w*);*(charset=[\\w=-]*)*;*$/`. The inner
group `(charset=[\\w=-]*)` is itself wrapped in an outer `*` quantifier --
a nested-quantifier construction where a crafted input (many repeated
"charset=" substrings with no closing match) forces the regex engine to
try an exponential number of ways to partition the input between the
inner and outer repetition before it can conclude there's no match.
Since `dataUrl` can come from untrusted, attacker-supplied image data,
this is a real denial-of-service vector: a single crafted string can pin
a CPU core for a very long time. The fix adds a negative lookahead
`(?!charset=)` inside the inner group, which removes the ambiguous
overlapping matches that caused the exponential blowup.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0063"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_BLOCK = r'''  var extractImageFromDataUrl = (jsPDFAPI.__addimage__.extractImageFromDataUrl = function(
    dataUrl
  ) {
    dataUrl = dataUrl || "";
    var dataUrlParts = dataUrl.split("base64,");
    var result = null;

    if (dataUrlParts.length === 2) {
      var extractedInfo = /^data:(\w*\/\w*);*(charset=[\w=-]*)*;*$/.exec(
        dataUrlParts[0]
      );
      if (Array.isArray(extractedInfo)) {
        result = {
          mimeType: extractedInfo[1],
          charset: extractedInfo[2],
          data: dataUrlParts[1]
        };
      }
    }
    return result;
  }'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename extractImageFromDataUrl -> parseDataUrlInfo, dataUrlParts ->
# urlSegments. Same exact catastrophic-backtracking regex.
renamed_block = r'''  var parseDataUrlInfo = (jsPDFAPI.__addimage__.parseDataUrlInfo = function(
    dataUrl
  ) {
    dataUrl = dataUrl || "";
    var urlSegments = dataUrl.split("base64,");
    var result = null;

    if (urlSegments.length === 2) {
      var extractedInfo = /^data:(\w*\/\w*);*(charset=[\w=-]*)*;*$/.exec(
        urlSegments[0]
      );
      if (Array.isArray(extractedInfo)) {
        result = {
          mimeType: extractedInfo[1],
          charset: extractedInfo[2],
          data: urlSegments[1]
        };
      }
    }
    return result;
  }'''
renamed_source = original.replace(VULNERABLE_BLOCK, renamed_block)
assert "parseDataUrlInfo" in renamed_source
assert renamed_source != original
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable holding the regex object itself.
# Same exact catastrophic-backtracking pattern, no renaming.
structural_block = r'''  var extractImageFromDataUrl = (jsPDFAPI.__addimage__.extractImageFromDataUrl = function(
    dataUrl
  ) {
    dataUrl = dataUrl || "";
    var dataUrlParts = dataUrl.split("base64,");
    var result = null;
    var dataUrlPattern = /^data:(\w*\/\w*);*(charset=[\w=-]*)*;*$/;

    if (dataUrlParts.length === 2) {
      var extractedInfo = dataUrlPattern.exec(dataUrlParts[0]);
      if (Array.isArray(extractedInfo)) {
        result = {
          mimeType: extractedInfo[1],
          charset: extractedInfo[2],
          data: dataUrlParts[1]
        };
      }
    }
    return result;
  }'''
structural_source = original.replace(VULNERABLE_BLOCK, structural_block)
assert structural_source != original
assert "dataUrlPattern" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core idea as upstream (a linear-time parse of the data: URL prefix)
# but a materially different technique: rewrites the inner repeated group
# as a NON-CAPTURING, non-repeated `(?:charset=([\w=-]*))?` -- removing
# the nested quantifier entirely (only the outer character class repeats,
# never a group containing its own repetition) rather than the real
# patch's negative-lookahead approach -- genuinely linear-time, different
# regex structure.
safe_block = r'''  var extractImageFromDataUrl = (jsPDFAPI.__addimage__.extractImageFromDataUrl = function(
    dataUrl
  ) {
    dataUrl = dataUrl || "";
    var dataUrlParts = dataUrl.split("base64,");
    var result = null;

    if (dataUrlParts.length === 2) {
      var extractedInfo = /^data:(\w*\/\w*);*(?:charset=([\w=-]*))?;*$/.exec(
        dataUrlParts[0]
      );
      if (Array.isArray(extractedInfo)) {
        result = {
          mimeType: extractedInfo[1],
          charset: extractedInfo[2],
          data: dataUrlParts[1]
        };
      }
    }
    return result;
  }'''
safe_source = original.replace(VULNERABLE_BLOCK, safe_block)
assert safe_source != original
assert "(?:charset=" in safe_source

# --- Verify the safe regex is actually linear-time on a pathological
# input that would catastrophically backtrack the original pattern ---
import re
import time

vulnerable_pattern = re.compile(r"^data:(\w*/\w*);*(charset=[\w=-]*)*;*$")
safe_pattern = re.compile(r"^data:(\w*/\w*);*(?:charset=([\w=-]*))?;*$")
pathological = "data:a/a;" + "charset=" * 25 + "!"

start = time.time()
safe_pattern.match(pathological)
safe_elapsed = time.time() - start
assert safe_elapsed < 0.1, f"safe variant regex took {safe_elapsed}s on pathological input, expected near-instant"

(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Same visible shape (a regex with a nested-quantifier group applied via
# .exec()) but this sibling only ever runs against a small set of
# HARD-CODED, compile-time-constant MIME strings used in an internal
# self-test, never attacker-supplied data -- so even though the pattern
# is structurally just as ReDoS-prone, there is no untrusted, unbounded-
# length input that could ever reach it, unlike
# extractImageFromDataUrl()'s dataUrl parameter.
BENIGN_SOURCE = r'''export function selfTestMimeParser() {
  // Only ever exercised against these two fixed literal strings at
  // module load time -- never receives external/attacker-supplied
  // input, so the nested-quantifier regex below has no exploitable
  // pathological-input surface despite its structural resemblance to
  // extractImageFromDataUrl()'s vulnerable pattern.
  var samples = ["data:image/png;charset=utf-8;", "data:image/jpeg;"];
  return samples.map(function (sample) {
    return /^data:(\w*\/\w*);*(charset=[\w=-]*)*;*$/.exec(sample);
  });
}
'''
(CASE_DIR / "benign_lookalike.js").write_text(BENIGN_SOURCE)
assert "dataUrl" not in BENIGN_SOURCE

print("Wrote 4 new samples for CASE-0063.")
