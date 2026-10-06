r"""
Section 9 ground-truth test bundle: CASE-0310
(trailofbits/fickling, fickling/fickle.py, CVE-2026-22609,
CWE-184 incomplete list of disallowed inputs / CWE-502 deserialization).

Core vulnerable mechanism: fickling decides whether a pickle imports
something dangerous by comparing the imported MODULE NAME, exactly, against a
denylist (os, posix, subprocess, sys, socket, ctypes, ...). `Pickled.unsafe_imports`
does `node.module in (...)`, so `from os.path import ...` (a submodule of a
denylisted package, and a module that itself exposes `os`) is not reported as
an unsafe import. Independently, `StackGlobal.run` (the protocol-4 STACK_GLOBAL
opcode) validates the module string with `module.isidentifier()`, which is
False for any dotted module name, so such a pickle makes the analysis raise
ValueError instead of being classified. The upstream fix compares the
top-level package (`node.module.split(".")[0]`) and validates each dotted
component.

Sibling site: the two edited lines are the same defect (treating a dotted
module path as a single identifier); `non_standard_imports` uses is_std_module
and is unaffected.

Verification (REAL package): fickling 0.1.6 is installed in a venv; the case
file `fickling/fickle.py` is copied over the installed one (the vulnerable
source equals 0.1.6 plus four extra denylist entries, so it imports cleanly).
A fresh interpreter then loads three real pickles with `Pickled.load` (a
protocol-2 GLOBAL `os.path os`, a protocol-4 STACK_GLOBAL `os.path os`, and
control pickles `os system` / `collections OrderedDict`) and records
(a) the names returned by `unsafe_imports()` and (b) whether analysing the
STACK_GLOBAL pickle raises. Vulnerable: os.path not reported, STACK_GLOBAL
raises ValueError. Patched/safe: os.path reported, no exception.

Every variant is the FULL real file. `unsafe_imports` and `StackGlobal.run`
keep their names because fickling calls them by name.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0310"
original = (CASE_DIR / "vulnerable_source.py").read_text()
patched = (CASE_DIR / "patched_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


FUNC = re.compile(r"(    def unsafe_imports\(self\).*?\n)(?=    def non_standard_imports)", re.S)
m = FUNC.search(original)
assert m
func = m.group(1)

# --- Variant 1: renamed vulnerable variant (loop variable renamed inside unsafe_imports) ---
f1 = func.replace("for node in", "for import_node in").replace("node.module", "import_node.module")
f1 = f1.replace("in node.names", "in import_node.names").replace("yield node", "yield import_node")
assert "node)" not in f1.replace("import_node", "") and " node" not in f1.replace("import_node", "")
v1 = original.replace(func, f1)
assert v1 != original and v1.count("import_node") == 5
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (denylist hoisted into a local) ---
TUP = re.search(r"            if node\.module in \(\n(.*?)            \):\n", func, re.S)
assert TUP
entries = TUP.group(1)
f2 = func.replace(TUP.group(0), "            if node.module in dangerous_modules:\n")
f2 = swap(f2, "        for node in self.properties.imports:\n",
          "        dangerous_modules = (\n" + entries.replace("                ", "            ") +
          "        )\n        for node in self.properties.imports:\n")
v2 = original.replace(func, f2)
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; top-level package in a local, components in a local) ---
v3 = swap(patched, '            if node.module and node.module.split(".")[0] in (\n',
          '            top_level = node.module.split(".")[0] if node.module else None\n'
          '            if top_level in (\n')
v3 = swap(v3, '        if not all(m.isidentifier() for m in module.split(".")) or not attr.isidentifier():\n',
          '        module_parts = module.split(".")\n'
          '        if not attr.isidentifier() or not all(part.isidentifier() for part in module_parts):\n')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''"""Plugin loader example: routes a dotted module name to a plugin namespace."""
from __future__ import annotations

FIRST_PARTY_NAMESPACES = ("acme_reports", "acme_export", "acme_import")


def plugin_namespace(module_name: str) -> str | None:
    """Return the first-party namespace a dotted plugin module belongs to.

    The name comes from the application's own plugin manifest (never from
    untrusted input) and is only used to choose a settings section, so an
    exact-match comparison against the namespaces is what is wanted here: a
    sub-package such as `acme_reports.pdf` maps to `acme_reports`, and anything
    else returns None and is loaded with default settings.
    """
    if not module_name:
        return None
    for namespace in FIRST_PARTY_NAMESPACES:
        if module_name == namespace or module_name.startswith(namespace + "."):
            return namespace
    return None


def all_components_valid(module_name: str) -> bool:
    return all(part.isidentifier() for part in module_name.split("."))
''')
