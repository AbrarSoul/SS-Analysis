"""
Section 9 ground-truth test bundle: CASE-0003
(CyrilleB79/NVDA-Dev-Test-Toolbox, CVE-2026-28211, CWE-943).

Core vulnerable mechanism: getSpeakIoMessage() calls `eval(txtSeq)` on text
extracted from a log line (regex match + substitutions), executing it as
arbitrary Python code. A crafted log file can therefore run arbitrary code
when replayed. File uses TAB indentation throughout -- preserved exactly.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0003"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = (
    "\tdef getSpeakIoMessage(self, mode):\n"
    "\t\tmatch = matchDict(RE_MSG_SPEAKING.match(self.content))\n"
    "\t\tif match:\n"
    "\t\t\ttry:\n"
    "\t\t\t\ttxtSeq = match['seq']\n"
    "\t\t\texcept Exception:\n"
    "\t\t\t\tlog.error(\"Sequence cannot be spoken: {seq}\".format(seq=match['seq']))\n"
    "\t\t\t\treturn self.content\n"
    "\t\t\ttxtSeq = RE_CANCELLABLE_SPEECH.sub('', txtSeq)\n"
    "\t\t\ttxtSeq = RE_CALLBACK_COMMAND.sub('', txtSeq)\n"
    "\t\t\tseq = eval(txtSeq)\n"
    "\t\t\t# Ignore CallbackCommand and ConfigProfileTriggerCommand to avoid producing errors or unexpected\n"
    "\t\t\t# side effects.\n"
    "\t\t\tif not preSpeechRefactor:\n"
    "\t\t\t\tseq = [c for c in seq if not isinstance(c, (CallbackCommand, ConfigProfileTriggerCommand))]\n"
    "\t\t\tif LogContainer.translateLog:\n"
    "\t\t\t\tseq2 = []\n"
    "\t\t\t\tfor s in seq:\n"
    "\t\t\t\t\tif isinstance(s, str):\n"
    "\t\t\t\t\t\tseq2.append(self._translate(s))\n"
    "\t\t\t\t\telse:\n"
    "\t\t\t\t\t\tseq2.append(s)\n"
    "\t\t\t\tseq = seq2\n"
    "\t\t\treturn seq\n"
)
assert VULNERABLE_BLOCK in original, "vulnerable block not found verbatim"

# --- Variant 1: renamed vulnerable variant ---
RENAMED_BLOCK = (
    "\tdef getSpeakIoMessage(self, mode):\n"
    "\t\tmatch = matchDict(RE_MSG_SPEAKING.match(self.content))\n"
    "\t\tif match:\n"
    "\t\t\ttry:\n"
    "\t\t\t\tlogSeqText = match['seq']\n"
    "\t\t\texcept Exception:\n"
    "\t\t\t\tlog.error(\"Sequence cannot be spoken: {seq}\".format(seq=match['seq']))\n"
    "\t\t\t\treturn self.content\n"
    "\t\t\tlogSeqText = RE_CANCELLABLE_SPEECH.sub('', logSeqText)\n"
    "\t\t\tlogSeqText = RE_CALLBACK_COMMAND.sub('', logSeqText)\n"
    "\t\t\tspeechSeq = eval(logSeqText)\n"
    "\t\t\t# Ignore CallbackCommand and ConfigProfileTriggerCommand to avoid producing errors or unexpected\n"
    "\t\t\t# side effects.\n"
    "\t\t\tif not preSpeechRefactor:\n"
    "\t\t\t\tspeechSeq = [c for c in speechSeq if not isinstance(c, (CallbackCommand, ConfigProfileTriggerCommand))]\n"
    "\t\t\tif LogContainer.translateLog:\n"
    "\t\t\t\tspeechSeq2 = []\n"
    "\t\t\t\tfor s in speechSeq:\n"
    "\t\t\t\t\tif isinstance(s, str):\n"
    "\t\t\t\t\t\tspeechSeq2.append(self._translate(s))\n"
    "\t\t\t\t\telse:\n"
    "\t\t\t\t\t\tspeechSeq2.append(s)\n"
    "\t\t\t\tspeechSeq = speechSeq2\n"
    "\t\t\treturn speechSeq\n"
)
renamed_source = original.replace(VULNERABLE_BLOCK, RENAMED_BLOCK)
assert renamed_source != original
assert "eval(logSeqText)" in renamed_source
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: wrapper-function introduction. eval() is moved into a small
# helper, same exact vulnerability, no renaming.
STRUCTURAL_BLOCK = VULNERABLE_BLOCK.replace(
    "\t\t\tseq = eval(txtSeq)\n",
    "\t\t\tseq = self._evalSpeechSequenceText(txtSeq)\n",
)
structural_source = original.replace(VULNERABLE_BLOCK, STRUCTURAL_BLOCK)
# insert the helper method right before getSpeakIoMessage's def line
structural_source = structural_source.replace(
    "\tdef getSpeakIoMessage(self, mode):\n",
    "\tdef _evalSpeechSequenceText(self, txtSeq):\n"
    "\t\treturn eval(txtSeq)\n"
    "\n"
    "\tdef getSpeakIoMessage(self, mode):\n",
    1,
)
assert structural_source != original
assert "_evalSpeechSequenceText" in structural_source
assert "return eval(txtSeq)" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Replaces eval() with a hand-rolled AST-restricted parser (string literals
# only) -- materially different and much smaller than the real upstream fix
# (generateSpeechSequence + astNodeToStr + astNodeToLitteral, ~100 lines
# supporting full command-call reconstruction). Genuinely safe: no
# eval()/exec() anywhere, and non-literal/non-string nodes raise instead of
# being evaluated.
SAFE_BLOCK = (
    "\tdef getSpeakIoMessage(self, mode):\n"
    "\t\tmatch = matchDict(RE_MSG_SPEAKING.match(self.content))\n"
    "\t\tif match:\n"
    "\t\t\ttry:\n"
    "\t\t\t\ttxtSeq = match['seq']\n"
    "\t\t\texcept Exception:\n"
    "\t\t\t\tlog.error(\"Sequence cannot be spoken: {seq}\".format(seq=match['seq']))\n"
    "\t\t\t\treturn self.content\n"
    "\t\t\ttxtSeq = RE_CANCELLABLE_SPEECH.sub('', txtSeq)\n"
    "\t\t\ttxtSeq = RE_CALLBACK_COMMAND.sub('', txtSeq)\n"
    "\t\t\tseq = self._safeParseSequence(txtSeq)\n"
    "\t\t\tif LogContainer.translateLog:\n"
    "\t\t\t\tseq2 = []\n"
    "\t\t\t\tfor s in seq:\n"
    "\t\t\t\t\tif isinstance(s, str):\n"
    "\t\t\t\t\t\tseq2.append(self._translate(s))\n"
    "\t\t\t\t\telse:\n"
    "\t\t\t\t\t\tseq2.append(s)\n"
    "\t\t\t\tseq = seq2\n"
    "\t\t\treturn seq\n"
    "\n"
    "\tdef _safeParseSequence(self, txtSeq):\n"
    "\t\t\"\"\"Parses a logged speech sequence without executing arbitrary code.\n"
    "\n"
    "\t\tOnly string-literal elements of a list literal are supported; any\n"
    "\t\tother AST node is rejected rather than evaluated, unlike the\n"
    "\t\tvulnerable eval()-based implementation this replaces.\n"
    "\t\t\"\"\"\n"
    "\t\tparsedTree = ast.parse(txtSeq, mode=\"eval\")\n"
    "\t\tif not isinstance(parsedTree.body, ast.List):\n"
    "\t\t\traise ValueError(\"Speech sequence must be a list literal\")\n"
    "\t\tresult = []\n"
    "\t\tfor element in parsedTree.body.elts:\n"
    "\t\t\tif isinstance(element, ast.Constant) and isinstance(element.value, str):\n"
    "\t\t\t\tresult.append(element.value)\n"
    "\t\t\telse:\n"
    "\t\t\t\traise ValueError(\"Unsupported speech sequence element\")\n"
    "\t\treturn result\n"
)
safe_source = original.replace(VULNERABLE_BLOCK, SAFE_BLOCK)
safe_source = safe_source.replace("import re\nimport os\n", "import re\nimport os\nimport ast\n")
assert safe_source != original
assert "import ast" in safe_source
assert "eval(" not in safe_source.split("class LogMessage")[1].split("class ")[0]
(CASE_DIR / "variant_safe_01.py").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a separate method that also
# calls eval(), superficially matching the vulnerable API surface, but only
# on a hardcoded literal never derived from log content -- genuinely safe.
BENIGN_ADDITION = (
    "\tdef _selfTestParser(self):\n"
    "\t\t\"\"\"Internal sanity check using a fixed, hardcoded sequence text.\n"
    "\n"
    "\t\tNever receives log-derived content -- this string is a compile-time\n"
    "\t\tconstant, so eval() here cannot execute attacker-controlled code,\n"
    "\t\tunlike the vulnerable pattern this class replaces.\n"
    "\t\t\"\"\"\n"
    "\t\tfixedSeq = \"['debug self-test']\"\n"
    "\t\treturn eval(fixedSeq)  # pylint: disable=eval-used\n"
    "\n"
)
benign_source = safe_source.replace(
    "\tdef _safeParseSequence(self, txtSeq):",
    BENIGN_ADDITION + "\tdef _safeParseSequence(self, txtSeq):",
    1,
)
assert benign_source != safe_source
assert "eval(fixedSeq)" in benign_source
(CASE_DIR / "benign_lookalike.py").write_text(benign_source)

print("Wrote 4 new samples for CASE-0003.")
