import demistomock as demisto
from CommonServerPython import *
from collections.abc import Callable
from functools import reduce, partial
import ast
import re


class IfElif:
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

    def __init__(self, value, conditions, variables='', flags=None):
        self.load_variables(variables, value)
        self.handle_flags(argToList(flags))
        self.conditions = self.evaluate(conditions)

    def handle_flags(self, flags: list):
        self.regex_flags = (
            re.DOTALL * ('regex_dot_all' in flags)
            | re.MULTILINE * ('regex_multiline' in flags)
            | re.IGNORECASE * ('case_insensitive' in flags)
        )
        if 'case_insensitive' in flags:
            def eq(x, y):
                return str(x).lower() == str(y).lower()
            self.operator_functions |= {
                ast.Eq: eq,
                ast.NotEq: lambda x, y: not eq(x, y),
            }
        self.functions = {
            'regex_match': partial(
                re.fullmatch if 'regex_full_match' in flags else re.search,
                flags=self.regex_flags
            )
        }

    def load_variables(self, variables: str, value: Any):
        self.variables: dict = {}
        for assign in variables.splitlines():
            left, right = assign.strip().split('=', 1)
            try:
                right = ast.literal_eval(right)
            except Exception:  # is a string
                right = right.strip()
            self.variables[left.strip()] = right
        self.variables |= {
            'true': True,
            'false': False,
            'null': None,
            'VALUE': value,
        }

    def get_value(self, node):
        match type(node):
            case ast.Constant:
                return node.value
            case ast.List:
                return [self.get_value(item) for item in node.elts]
            case ast.Dict:
                return {
                    self.get_value(key): self.get_value(value)
                    for key, value in zip(node.keys, node.values)
                }
            case ast.Name:
                return self.variables[node.id]
            case ast.Call:
                return self.functions[node.func.id](*map(self.get_value, node.args))
            case ast.Compare:
                left = self.get_value(node.left)
                return all(
                    self.operator_functions[type(op)](
                        left, left := self.get_value(right)  # noqa: F841
                    )
                    for op, right in zip(node.ops, node.comparators)
                )
            case ast.BoolOp:
                return reduce(
                    self.operator_functions[type(node.op)], map(self.get_value, node.values)
                )
            case ast.UnaryOp:
                return self.operator_functions[type(node.op)](self.get_value(node.operand))
            case _:
                raise SyntaxError(
                    f'Unsupported expression type found: {node.__class__.__name__}'
                )

    def evaluate(self, expression: str):
        # sourcery skip: raise-from-previous-error
        try:
            parsed = ast.parse(expression, mode='eval')
        except Exception:
            raise SyntaxError(f'Cannot parse expression: {expression!r}')
        return self.get_value(parsed.body)

    def parse_conditions(self):
        *conditions, default = self.conditions
        result = next(
            (
                condition['return']
                for condition in conditions
                if self.evaluate(condition['condition'])
            ),
            default['else']
        )
        return result


def main():
    try:
        if_elif = IfElif(**demisto.args())
        return_results(if_elif.parse_conditions())
    except Exception as e:
        return_error(f'Error in If-Elif Transformer: {e}')


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
