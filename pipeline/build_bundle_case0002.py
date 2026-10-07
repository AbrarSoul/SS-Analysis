"""
Section 9 ground-truth test bundle: CASE-0002
(ComposioHQ/composio, CVE-2024-8953, CWE-627/CWE-913).

Core vulnerable mechanism: `eval(request.operation)` evaluates a raw,
user-controlled string as arbitrary Python code (a calculator tool that
should only ever compute simple arithmetic). Single-line, unambiguous sink.
"""
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "cases" / "CASE-0002"
original = (CASE_DIR / "vulnerable_source.py").read_text()

VULNERABLE_BLOCK = '''    def execute(self, request: CalculatorRequest, metadata: Dict) -> CalculatorResponse:
        return CalculatorResponse(
            result=str(eval(request.operation))  # pylint: disable=eval-used
        )'''
assert VULNERABLE_BLOCK in original

# --- Variant 1: renamed vulnerable variant ---
# Rename the tainted field operation -> expression (class field + Field(...)
# declaration + all read sites) and the method-local parameter
# request -> req. Same exact eval() sink over the same tainted source.
RENAMED_REQUEST_MODEL = '''class CalculatorRequest(BaseModel):
    expression: str = Field(
        ...,
        description="A mathematical expression, a couple examples are `200*7` or `5000/2*10`",
        json_schema_extra={"file_readable": True},
    )'''
renamed_source = original.replace(
    '''class CalculatorRequest(BaseModel):
    operation: str = Field(
        ...,
        description="A mathematical expression, a couple examples are `200*7` or `5000/2*10`",
        json_schema_extra={"file_readable": True},
    )''',
    RENAMED_REQUEST_MODEL,
)
renamed_source = renamed_source.replace(
    VULNERABLE_BLOCK,
    '''    def execute(self, req: CalculatorRequest, metadata: Dict) -> CalculatorResponse:
        return CalculatorResponse(
            result=str(eval(req.expression))  # pylint: disable=eval-used
        )''',
)
assert "eval(req.expression)" in renamed_source
assert "operation" not in renamed_source
(CASE_DIR / "variant_vulnerable_01.py").write_text(renamed_source)

# --- Variant 2: structurally changed vulnerable variant ---
# Section 9.1: intermediate variable introduction. Same exact vulnerability,
# no renaming (isolates structural-generalization from identifier test).
structural_source = original.replace(
    VULNERABLE_BLOCK,
    '''    def execute(self, request: CalculatorRequest, metadata: Dict) -> CalculatorResponse:
        expression_text = request.operation
        computed_value = eval(expression_text)  # pylint: disable=eval-used
        return CalculatorResponse(result=str(computed_value))''',
)
assert structural_source != original
assert "eval(expression_text)" in structural_source
(CASE_DIR / "variant_vulnerable_02.py").write_text(structural_source)

# --- Variant 3: transformed safe variant ---
# Same core fix idea as upstream (AST-restricted evaluation instead of raw
# eval()) but a materially different, much shorter implementation than the
# real 109-line patched_source.py: fewer operators, different helper names,
# a module-level dispatch dict instead of per-node-type methods, no custom
# exception messages. Genuinely safe: no eval()/exec() anywhere.
SAFE_SOURCE = '''import ast
import operator
from typing import Dict, Union

from pydantic import BaseModel, Field

from composio.tools.base.local import LocalAction


class CalculatorRequest(BaseModel):
    operation: str = Field(
        ...,
        description="A mathematical expression, a couple examples are `200*7` or `5000/2*10`",
        json_schema_extra={"file_readable": True},
    )


class CalculatorResponse(BaseModel):
    result: str = Field(..., description="Result of the calculation")


_ALLOWED_BINARY_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}


class Calculator(LocalAction[CalculatorRequest, CalculatorResponse]):
    """
    Useful to perform any mathematical calculations, like sum, minus, multiplication, division, etc.
    """

    _tags = ["calculator"]

    def execute(self, request: CalculatorRequest, metadata: Dict) -> CalculatorResponse:
        parsed = ast.parse(request.operation, mode="eval")
        return CalculatorResponse(result=str(self._resolve(parsed.body)))

    def _resolve(self, node: ast.AST) -> Union[int, float]:
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp):
            op_func = _ALLOWED_BINARY_OPS.get(type(node.op))
            if op_func is None:
                raise ValueError("Unsupported operator in expression")
            return op_func(self._resolve(node.left), self._resolve(node.right))
        raise ValueError("Unsupported expression")
'''
(CASE_DIR / "variant_safe_01.py").write_text(SAFE_SOURCE)
assert "eval(" not in SAFE_SOURCE and "exec(" not in SAFE_SOURCE

# --- Variant 4: benign structural look-alike ---
# The request-handling path (execute()) is genuinely safe -- same
# AST-restricted approach as variant_safe_01 -- but a SEPARATE method also
# calls eval(), superficially matching the vulnerable API surface. It is
# safe because its argument is a hardcoded literal, never user input, so no
# injection is reachable through it.
BENIGN_SOURCE = SAFE_SOURCE + '''
    def self_test(self) -> str:
        """Internal sanity check using a fixed, hardcoded expression.

        Never receives user input -- the string below is a compile-time
        constant, so eval() here cannot execute attacker-controlled code,
        unlike the vulnerable pattern this class replaces.
        """
        fixed_expression = "2+2"
        return str(eval(fixed_expression))  # pylint: disable=eval-used
'''
(CASE_DIR / "benign_lookalike.py").write_text(BENIGN_SOURCE)
assert "eval(fixed_expression)" in BENIGN_SOURCE
assert "request.operation" not in BENIGN_SOURCE.split("def self_test")[1]

print("Wrote 4 new samples for CASE-0002.")
