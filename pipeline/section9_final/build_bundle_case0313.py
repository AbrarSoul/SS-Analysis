r"""
Section 9 ground-truth test bundle: CASE-0313
(tryton/trytond, trytond/model/modelstorage.py ModelStorage.__init__,
CVE-2012-0215, CWE-264 permissions, privileges and access controls).

Core vulnerable mechanism: every `ModelStorage` registers its data-access
methods in the class's RPC table (`self._rpc`): create, write, delete, copy,
import_data (callable by any authenticated client) and read/search/
search_read/export_data/search_count. This is done for ALL storage models,
including plain internal models that are not meant to be user-facing
(models that do not inherit `ModelView`). A remote client can therefore call
`create`/`write`/`delete` on internal tables through the RPC layer and bypass
the checks that only the user-facing view models enforce. The upstream fix
wraps the registration in `if isinstance(self, ModelView)`.

Sibling sites: `ModelView.__init__` registers its own view-related RPC
methods and is unaffected.

Verification: `ModelStorage.__init__` (up to `default_create_uid`) is sliced
out of each full file and exec'd into a class deriving from a stub `Model`
(whose init creates `_rpc = {}`); a stub `ModelView` supplies the isinstance
check. Two real subclasses are instantiated: a plain internal model
`Plain(ModelStorage)` and a view model `View(ModelStorage, ModelView)`, and the
resulting `_rpc` keys are read. Vulnerable variants expose `write` on Plain;
patched/safe do not, while the view model exposes all ten methods in every
file.

Every variant is the FULL real file; `__init__` keeps its name.
"""
import re
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0313"
original = (CASE_DIR / "vulnerable_source.py").read_text()
patched = (CASE_DIR / "patched_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old, old
    return text.replace(old, new)


RPC = '''        self._rpc.update({
            'create': True,
            'read': False,
            'write': True,
            'delete': True,
            'copy': True,
            'search': False,
            'search_count': False,
            'search_read': False,
            'export_data': False,
            'import_data': True,
        })
'''
assert original.count(RPC) == 1
BODY = RPC[len("        self._rpc.update("):-len(")\n")]

# --- Variant 1: renamed vulnerable variant (dict passed through a newly named local) ---
v1 = swap(original, RPC, "        exposed_methods = " + BODY.replace("\n        ", "\n        ") + "\n        self._rpc.update(exposed_methods)\n")
(CASE_DIR / "variant_vulnerable_01.py").write_text(v1)

# --- Variant 2: structurally changed vulnerable variant (RPC table moved to a class attribute) ---
v2 = swap(original, RPC, "        self._rpc.update(self._default_rpc)\n")
v2 = swap(v2, "    def __init__(self):\n        super(ModelStorage, self).__init__()\n",
          "    _default_rpc = " + BODY.replace("\n        ", "\n    ") + "\n\n    def __init__(self):\n        super(ModelStorage, self).__init__()\n")
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant (real patched file; the isinstance test becomes an MRO membership test) ---
v3 = swap(patched, "        if isinstance(self, ModelView):\n", "        if ModelView in type(self).__mro__:\n")
(CASE_DIR / "variant_safe_01.py").write_text(v3)

(CASE_DIR / "benign_lookalike.py").write_text('''"""Report registry: a class that publishes only read-only entry points in its own RPC-style table."""


class ReportHandler(object):
    """Internal report model; nothing that changes state is ever published."""

    def __init__(self):
        self._rpc = {}
        self._rpc.update({
            'render': False,
            'list_templates': False,
            'export_pdf': False,
        })
        self._constraints = []

    def render(self, template, values):
        return template.format(**values)

    def list_templates(self):
        return ['invoice', 'statement']
''')
