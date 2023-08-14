import demistomock as demisto
from CommonServerPython import *
from collections.abc import Callable
from functools import reduce, partial
import json
import ast
import re

CONTEXT = demisto.context()
ARGS = demisto.args()
FLAGS = argToList(ARGS.get('flags'))


regex_flags = (
    re.DOTALL * ('regex_dot_all' in FLAGS)
    | re.MULTILINE * ('regex_multiline' in FLAGS)
    | re.IGNORECASE * ('case_insensitive' in FLAGS)
)

equal_func = (  # noqa: E731
    lambda x, y: repr(x).lower() == repr(y).lower()
    if 'case_insensitive' in FLAGS
    else lambda x, y: x == y
)

boolean_keywords = {
    'true': True,
    'false': False,
    'null': None,
}


operator_functions: dict[type, Callable] = {
    # comparison operators:
    ast.Eq: equal_func,
    ast.NotEq: lambda x, y: not equal_func(x, y),
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

functions = {
    'regex_match': partial(
        re.fullmatch if 'regex_full_match' in FLAGS else re.search,
        flags=regex_flags
    )
}


def get_value(node):
    match type(node):
        case ast.Constant:
            return node.value
        case ast.List:
            return [get_value(item) for item in node.elts]
        case ast.Dict:
            return {
                get_value(key): get_value(value)
                for key, value in zip(node.keys, node.values)
            }
        case ast.Name:
            return boolean_keywords[node.id]
        case ast.Call:
            return functions[node.func.id](*map(get_value, node.args))
        case ast.Compare:
            left = get_value(node.left)
            return all(
                operator_functions[type(op)](
                    left, left := get_value(right)  # noqa: F841
                )
                for op, right in zip(node.ops, node.comparators)
            )
        case ast.BoolOp:
            return reduce(
                operator_functions[type(node.op)], map(get_value, node.values)
            )
        case ast.UnaryOp:
            return operator_functions[type(node.op)](get_value(node.operand))
        case _:
            raise SyntaxError(
                f'Unsupported expression type found: {node.__class__.__name__}'
            )


def parse_boolean_expression(expression: str) -> bool:
    try:
        parsed = ast.parse(expression, mode='eval')
        return bool(get_value(parsed.body))
    except Exception:
        raise SyntaxError(f'Cannot parse expression: {expression}')


def get_from_context(keys: re.Match) -> str:
    context_obj = demisto.dt(CONTEXT, keys[1])
    return json.dumps(context_obj)


def load_conditions() -> list:
    '''
    Replace #{...}'s with the string representation of the corresponding value in CONTEXT
    and '#VALUE' with the args['value'] and load the resulting json.
    '''
    conditions = ARGS['conditions']
    conditions = conditions.replace('#VALUE', json.dumps(ARGS['value']))
    conditions = re.compile('#{([\s\S]+?)}').sub(get_from_context, conditions)
    return json.loads(conditions)


def main():
    try:
        *conditions, default = load_conditions()

        result = next(
            (
                condition['return']
                for condition in conditions
                if parse_boolean_expression(condition['condition'])
            ),
            default['else'],
        )

        return_results(result)

    except Exception as e:
        return_error(f'Error in If-Elif Transformer: {e}')


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
