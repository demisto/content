import demistomock as demisto
from CommonServerPython import *
from collections.abc import Callable
from functools import reduce, partial
import ast


class ConditionParser:
    variables: dict[str, Any] = {
        'true': True,
        'false': False,
        'null': None
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
        # binary operators:
        ast.Add: lambda x, y: x + y,
    }

    def __init__(self, context, conditions, flags=None):
        self.conditions: list
        self.load_conditions(conditions)
        self.default = (
            self.conditions.pop()['default']
            if 'default' in self.conditions[-1]
            else ''
        )
        self.validate_conditions()
        self.functions: dict[str, Callable] = {
            'from_context': partial(demisto.dt, context)
        }
        self.modify_functions_with_flags(argToList(flags))

    def modify_functions_with_flags(self, flags: list):
        self.regex_flags = (
            re.DOTALL * ('regex_dot_all' in flags)
            | re.MULTILINE * ('regex_multiline' in flags)
            | re.IGNORECASE * ('case_insensitive' in flags)
        )
        self.functions['regex_match'] = partial(
            re.fullmatch if 'regex_full_match' in flags else re.search,
            flags=self.regex_flags
        )
        if 'case_insensitive' in flags:
            def eq(x, y):
                return repr(x).lower() == repr(y).lower()
            self.operator_functions |= {
                ast.Eq: eq,
                ast.NotEq: lambda x, y: not eq(x, y),
            }

    def load_conditions(self, conditions):
        conditions = re.sub(
            '#{([\s\S]+?)}',
            r" from_context('\1')",
            conditions
        )
        try:
            self.conditions = self.evaluate(conditions)
        except SyntaxError as e:
            raise SyntaxError(
                f'Cannot load JSON. Invalid syntax at line: {e.args[1][1]}; position: {e.args[1][2]}'
            ) from e

    def validate_conditions(self):
        for i, d in enumerate(self.conditions, 1):
            if 'condition' not in d:
                raise ValueError(f'Condition {i} has no key "condition".')
            elif 'return' not in d:
                raise ValueError(f'Condition {i} has no key "return".')
            elif not isinstance(d, dict):
                raise ValueError(f'Condition {i} is not a dictionary.')

    def get_value(self, node):
        match type(node):
            case ast.Name:
                return self.variables[node.id]
            case ast.Constant:
                return node.value
            case ast.List:
                return [self.get_value(item) for item in node.elts]
            case ast.Dict:
                return {
                    self.get_value(key): self.get_value(value)
                    for key, value in zip(node.keys, node.values)
                }
            case ast.Call:
                return self.functions[node.func.id](
                    *map(self.get_value, node.args)
                )
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
                    self.operator_functions[type(node.op)],
                    map(self.get_value, node.values)
                )
            case ast.UnaryOp:
                return self.operator_functions[type(node.op)](
                    self.get_value(node.operand)
                )
            case ast.BinOp:
                return self.operator_functions[type(node.op)](
                    self.get_value(node.left),
                    self.get_value(node.right)
                )
            case _:
                raise KeyError(node.__class__.__name__)

    def evaluate(self, expression: str):
        try:
            parsed = ast.parse(expression.strip(), mode='eval')
            return self.get_value(parsed.body)
        except KeyError as e:
            raise NameError(f'Unknown variable/operator: {e.args[0]!r}') from e

    def parse_conditions(self):

        try:
            return next(
                (
                    condition['return']
                    for condition in self.conditions
                    if self.evaluate(condition['condition'])
                ),
                self.default
            )
        except SyntaxError as e:
            raise SyntaxError(f'Invalid expression: {e.args[1][3]!r}') from e


def main():
    try:
        args: dict = demisto.args()
        if_elif = ConditionParser(args.pop('value'), **args)
        return_results(if_elif.parse_conditions())
    except Exception as e:
        return_error(f'Error in If-Elif Transformer: {e}')


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
