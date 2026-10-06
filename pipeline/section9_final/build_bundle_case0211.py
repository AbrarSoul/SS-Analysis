"""
Section 9 ground-truth test bundle: CASE-0211
(langchain-ai/langchain, libs/experimental/langchain_experimental/pal_chain/base.py
PALChain.validate_code, CVE-2024-27444, CWE-749 exposed dangerous method).

Core vulnerable mechanism: `validate_code` is the gate that decides whether
LLM-generated code may be exec'd by PALChain. With `allow_command_exec=False` it
only rejects calls to a short list of NAMES (`system`, `exec`, `eval`, ...) and
imports. It never looks at attribute access, so the classic sandbox escape
`().__class__.__base__.__subclasses__()` (then `__builtins__`/`__globals__`
lookups) passes validation and is run by the REPL. The upstream fix adds
`COMMAND_EXECUTION_ATTRIBUTES` and rejects any `ast.Attribute` whose `attr` is in it.

Measured caveat, kept in the manifest notes: the upstream fix is a denylist
over attribute NODES only. `getattr(().__class__, '__ba' + 'se__')` and
`getattr(b, '__subclasses__')()` contain no forbidden ast.Attribute and no call
to a listed name, so the same escape is ACCEPTED by the upstream-patched
validator. The safe variant additionally rejects calls to `getattr` and string
constants equal to a forbidden attribute name.

Sibling sites: validate_code is the only validator (called once from _call).

Verification: each full file is imported with the langchain modules stubbed
(only PALValidation/PALChain.validate_code run; real ast) and fed three programs.

Every variant is the FULL real file. validate_code is a classmethod called by
name, so its name/signature are kept; locals are renamed instead.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent.parent / "benchmark" / "cases" / "CASE-0211"
original = (CASE_DIR / "vulnerable_source.py").read_text()
assert "\r" not in original


def swap(text, old, new):
    assert text.count(old) == 1 and new != old
    return text.replace(old, new)


s = original.index("    def validate_code(")
e = original.index("    @classmethod\n    def from_math_prompt")
METHOD = original[s:e]

# --- Variant 1: renamed vulnerable variant ---
m1 = METHOD
for a, b in (("code_tree", "parsed_tree"), ("found_solution_expr", "solution_seen"),
             ("has_imports", "import_seen"), ("top_level_nodes", "root_nodes"),
             ("target_node", "assign_target")):
    assert a in m1
    m1 = m1.replace(a, b)
(CASE_DIR / "variant_vulnerable_01.py").write_text(original[:s] + m1 + original[e:])

# --- Variant 2: structurally changed vulnerable variant ---
CALL_CHECK = '''                    if (
                        hasattr(node.func, "id")
                        and node.func.id in COMMAND_EXECUTION_FUNCTIONS
                    ):
                        raise ValueError(
                            f"Found illegal command execution function "
                            f"{node.func.id} in code {code}"
                        )

                    if (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr in COMMAND_EXECUTION_FUNCTIONS
                    ):
                        raise ValueError(
                            f"Found illegal command execution function "
                            f"{node.func.attr} in code {code}"
                        )
'''
v2 = swap(original, CALL_CHECK, '''                    called = cls._called_name(node)
                    if called in COMMAND_EXECUTION_FUNCTIONS:
                        raise ValueError(
                            f"Found illegal command execution function "
                            f"{called} in code {code}"
                        )
''')
v2 = swap(v2, "    @classmethod\n    def from_math_prompt", '''    @staticmethod
    def _called_name(node: ast.Call) -> Optional[str]:
        if hasattr(node.func, "id"):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    @classmethod
    def from_math_prompt''')
(CASE_DIR / "variant_vulnerable_02.py").write_text(v2)

# --- Variant 3: transformed safe variant ---
v3 = swap(original, 'COMMAND_EXECUTION_FUNCTIONS = ["system", "exec", "execfile", "eval", "__import__"]\n',
          'COMMAND_EXECUTION_FUNCTIONS = ["system", "exec", "execfile", "eval", "__import__"]\n'
          'FORBIDDEN_DYNAMIC_ACCESS = ["getattr", "setattr", "delattr", "vars", "globals", "locals"]\n'
          'COMMAND_EXECUTION_ATTRIBUTES = frozenset(\n'
          '    ["__import__", "__subclasses__", "__builtins__", "__globals__",\n'
          '     "__getattribute__", "__bases__", "__mro__", "__base__"]\n'
          ')\n')
v3 = swap(v3, '''            for node in ast.walk(code_tree):
                if (not code_validations.allow_command_exec) and isinstance(
                    node, ast.Call
                ):
''', '''            for node in ast.walk(code_tree):
                if not code_validations.allow_command_exec:
                    dangerous = None
                    if isinstance(node, ast.Attribute) and node.attr in COMMAND_EXECUTION_ATTRIBUTES:
                        dangerous = node.attr
                    elif (
                        isinstance(node, ast.Constant)
                        and isinstance(node.value, str)
                        and node.value in COMMAND_EXECUTION_ATTRIBUTES
                    ):
                        dangerous = node.value
                    elif (
                        isinstance(node, ast.Call)
                        and getattr(node.func, "id", None) in FORBIDDEN_DYNAMIC_ACCESS
                    ):
                        dangerous = node.func.id
                    if dangerous is not None:
                        raise ValueError(
                            f"Found illegal command execution function "
                            f"{dangerous} in code {code}"
                        )
                if (not code_validations.allow_command_exec) and isinstance(
                    node, ast.Call
                ):
''')
(CASE_DIR / "variant_safe_01.py").write_text(v3)

BENIGN = '''"""Standalone example of the same shape (walk an ast and reject a denylist of
names) applied to a linter for a templating DSL: nothing is executed."""
import ast

DISCOURAGED_NAMES = ["print", "input"]


def find_discouraged(source: str):
    hits = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) in DISCOURAGED_NAMES:
            hits.append(node.func.id)
        if isinstance(node, ast.Attribute) and node.attr in DISCOURAGED_NAMES:
            hits.append(node.attr)
    return hits
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN)
