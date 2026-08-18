from __future__ import annotations

"""Safe condition evaluator for MiniSOAR playbooks."""

import ast
import logging
from typing import Any

logger = logging.getLogger(__name__)


class SafeExpressionEvaluator:
    """Evaluates boolean conditions safely using Python's AST parser."""

    ALLOWED_NODE_TYPES = (
        ast.Expression,
        ast.BoolOp,
        ast.UnaryOp,
        ast.BinOp,
        ast.Compare,
        ast.Name,
        ast.Constant,
        ast.List,
        ast.Tuple,
        ast.Set,
        ast.Dict,
        ast.Attribute,
        ast.Subscript,
        ast.Index,
        ast.Slice,
        ast.Load,
        # Operators
        ast.And,
        ast.Or,
        ast.Not,
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.Is,
        ast.IsNot,
        ast.In,
        ast.NotIn,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.Mod,
        ast.USub,
        ast.UAdd,
    )

    @classmethod
    def validate_ast(cls, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if not isinstance(child, cls.ALLOWED_NODE_TYPES):
                logger.warning("Disallowed AST node type in playbook condition: %s", type(child).__name__)
                return False
        return True

    @classmethod
    def evaluate(cls, expression: str, context: dict[str, Any]) -> bool:
        if not expression or not expression.strip():
            return True

        cleaned_expr = expression.strip()
        try:
            tree = ast.parse(cleaned_expr, mode="eval")
            if not cls.validate_ast(tree):
                logger.error("Condition failed AST security validation: %s", cleaned_expr)
                return False

            compiled_code = compile(tree, filename="<playbook_condition>", mode="eval")
            safe_globals = {"__builtins__": {}}
            result = eval(compiled_code, safe_globals, context)  # nosec B307 (validated by AST)
            return bool(result)
        except Exception as e:
            logger.error("Error evaluating playbook condition '%s': %s", cleaned_expr, e)
            return False


def evaluate_conditions(conditions: list[str], context: dict[str, Any]) -> bool:
    """Evaluates a list of conditions with AND logic."""
    if not conditions:
        return True

    for cond in conditions:
        if not SafeExpressionEvaluator.evaluate(cond, context):
            return False
    return True
