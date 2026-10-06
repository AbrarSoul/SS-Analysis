"""Standalone example of the same shape (walk an ast and reject a denylist of
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
