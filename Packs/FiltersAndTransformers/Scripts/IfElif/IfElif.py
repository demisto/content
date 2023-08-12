import demistomock as demisto
from CommonServerPython import *
from functools import reduce
import json
import ast
import re


boolean_keywords = {
    'true': True,
    'false': False,
    'null': None,
}


operator_functions = {
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
                operator_functions[type(op)](left, left := get_value(right))
                for op, right in zip(node.ops, node.comparators))
        case ast.BoolOp:
            return reduce(
                operator_functions[type(node.op)],  # check
                map(get_value, node.values))
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


def get_from_context(keys: str):
    pass


def load_conditions(args: dict) -> list:  # TEST
    conditions = args['conditions']
    conditions = conditions.replace('$VALUE', repr(args['value']))
    for match in set(re.findall(r'\${[\s\S]+?}', conditions)):
        conditions.replace(match, get_from_context(match[2:-1]) or match)
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
            default['else']
        )

        return_results(result)

    except Exception:
        return_error('Error in If-Elif Transformer. Make sure you entered the values correctly.')


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
