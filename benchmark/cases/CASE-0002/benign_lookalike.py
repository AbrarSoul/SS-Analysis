import ast
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

    def self_test(self) -> str:
        """Internal sanity check using a fixed, hardcoded expression.

        Never receives user input -- the string below is a compile-time
        constant, so eval() here cannot execute attacker-controlled code,
        unlike the vulnerable pattern this class replaces.
        """
        fixed_expression = "2+2"
        return str(eval(fixed_expression))  # pylint: disable=eval-used
