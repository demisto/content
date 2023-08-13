import demistomock as demisto
from CommonServerPython import *
from typing import Callable
from functools import reduce
import json
import ast
import re

CONTEXT = demisto.context()

boolean_keywords = {
    'true': True,
    'false': False,
    'null': None,
}


operator_functions: dict[type, Callable] = {
    # comparison operators:
    ast.Eq: lambda x, y: x == y,
    ast.NotEq: lambda x, y: x != y,
    ast.Lt: lambda x, y: x < y,
    ast.LtE: lambda x, y: x <= y,
    ast.Gt: lambda x, y: x > y,
    ast.GtE: lambda x, y: x >= y,
    ast.In: lambda x, y: x in y,
    ast.NotIn: lambda x, y: x not in y,

    # boolean operators:
    ast.And: lambda x, y: x and y,
    ast.Or: lambda x, y: x or y,

    # unary operators:
    ast.Not: lambda x: not x,
    ast.USub: lambda x: -x,
}


def get_value(node):

    match type(node):
        
        # objects:
        case ast.Constant:
            return node.value
        case ast.List:
            return [get_value(item) for item in node.elts]
        case ast.Dict:
            return {get_value(key): get_value(value)
                    for key, value in zip(node.keys, node.values)}
        case ast.Name:
            return boolean_keywords[node.id]

        #  boolean operators:
        case ast.Compare:
            left = get_value(node.left)
            return all(
                operator_functions[type(op)](left, left := get_value(right))  # noqa: F841
                for op, right in zip(node.ops, node.comparators)
            )
        case ast.BoolOp:
            return reduce(
                operator_functions[type(node.op)],
                map(get_value, node.values)
            )
        case ast.UnaryOp:
            return operator_functions[type(node.op)](get_value(node.operand))

        case _:
            raise SyntaxError(
                f'Unsupported expression type found: {node.__class__.__name__}')


def parse_boolean_expression(expression: str) -> bool:
    try:
        parsed = ast.parse(expression, mode='eval')
        return bool(get_value(parsed.body))
    except Exception:
        raise SyntaxError(f'Cannot parse expression: {expression}')


def get_from_context(keys: re.Match) -> str:
    context_keys = (
        (
            int(idx[1])
            if (idx := re.fullmatch('\[([0-9]+)\]', key))
            else key
        )
        for key in keys[1].split('.')
    )
    value = dict_safe_get(CONTEXT, context_keys)
    return json.dumps(value)


def load_conditions(args: dict) -> list:  # TEST
    conditions = args['conditions']
    conditions = conditions.replace('#VALUE', json.dumps(args['value']))  # how does value appear?
    conditions = re.compile('#{([\s\S]+?)}').sub(get_from_context, conditions)
    return json.loads(conditions)


def main():

    try:
        *conditions, default = load_conditions(demisto.args())

        result = next(
            (
                condition['return']
                for condition in conditions
                if parse_boolean_expression(condition['condition'])
            ),
            default
        )

        return_results(result)

    except Exception as e:
        return_error(f'Error in If-Elif Transformer: {e}')


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
