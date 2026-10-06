"""
Section 9 ground-truth test bundle: CASE-0026
(NodeBB/NodeBB, CVE-2022-46164, CWE-665 -- improper initialization /
prototype pollution exposure).

Core vulnerable mechanism: Namespaces is a plain object literal ({}),
which inherits from Object.prototype. It is later indexed with a
dynamic, client-controlled key (Namespaces[namespace] at lines 155-156,
where `namespace` comes from an incoming socket.io event). An attacker
sending a namespace value like "constructor" or "__proto__" reaches
inherited Object.prototype members instead of a real registered
namespace handler, which the vulnerable version's `if (Namespaces
[namespace])`-style checks do not guard against. The real fix uses
Object.create(null), which has no prototype chain at all.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0026"
original = (CASE_DIR / "vulnerable_source.js").read_text()

VULNERABLE_LINE = "const Namespaces = {};\n"
assert VULNERABLE_LINE in original
assert original.count(VULNERABLE_LINE) == 1
assert len(re.findall(r"\bNamespaces\b", original)) == 5

# --- Variant 1: renamed vulnerable variant ---
# Rename Namespaces -> EventNamespaces throughout the file (all 5
# occurrences, via word-boundary regex so it can't collide with the
# unrelated lowercase `namespace` variable). Same exact vulnerability:
# still a plain {} object indexed with a dynamic, client-controlled key.
renamed_source = re.sub(r"\bNamespaces\b", "EventNamespaces", original)
assert renamed_source != original
assert renamed_source.count("EventNamespaces") == 5
assert "const EventNamespaces = {};" in renamed_source
(CASE_DIR / "variant_vulnerable_01.js").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: wrapper-function introduction -- the plain object literal
# is now produced by a small factory function. Same exact vulnerability
# (still a {} with Object.prototype in its chain), no renaming.
structural_source = original.replace(
    VULNERABLE_LINE,
    "function createNamespaceRegistry() {\n"
    "\treturn {};\n"
    "}\n"
    "const Namespaces = createNamespaceRegistry();\n",
)
assert structural_source != original
assert "function createNamespaceRegistry()" in structural_source
(CASE_DIR / "variant_vulnerable_02.js").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same fix idea as upstream (a prototype-less object, immune to this
# class of pollution/inherited-property confusion) but produced via a
# small factory function, instead of the real patch's direct one-line
# Object.create(null) assignment -- materially different structure, not
# byte-identical to the known fix.
safe_source = original.replace(
    VULNERABLE_LINE,
    "function createSafeRegistry() {\n"
    "\treturn Object.create(null);\n"
    "}\n"
    "const Namespaces = createSafeRegistry();\n",
)
assert safe_source != original
assert "Object.create(null)" in safe_source
assert "const Namespaces = {};" not in safe_source
(CASE_DIR / "variant_safe_01.js").write_text(safe_source)

# --- Variant 4: benign structural look-alike ---
# Built on the safe implementation above. Adds a plain {} object literal
# used as a config map -- the same superficial "risky" shape as the
# vulnerable pattern -- but it is only ever accessed via hardcoded,
# compile-time-constant property names, never indexed by an
# attacker-controlled string, so its Object.prototype chain is never
# reachable via untrusted input.
BENIGN_ADDITION = (
    "const InternalConfigDefaults = {};\n"
    "InternalConfigDefaults.maxRetries = 3;\n"
    "InternalConfigDefaults.timeoutMs = 5000;\n"
    "// Only ever accessed via these two hardcoded, compile-time-constant\n"
    "// property names -- never indexed by an attacker-controlled string\n"
    "// like Namespaces[namespace] is -- so the {} prototype chain is never\n"
    "// reachable via untrusted input here.\n"
    "\n"
)
anchor = "function createSafeRegistry() {\n"
assert anchor in safe_source
benign_source = safe_source.replace(anchor, BENIGN_ADDITION + anchor, 1)
assert benign_source != safe_source
assert "InternalConfigDefaults" in benign_source
(CASE_DIR / "benign_lookalike.js").write_text(benign_source)

print("Wrote 4 new samples for CASE-0026.")
