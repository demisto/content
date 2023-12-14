import demistomock as demisto
from CommonServerPython import *
from collections.abc import Callable
from functools import reduce, partial
import ast


def return_none_on_error(func: Callable) -> Callable:
    '''Makes a function return None if an error is raised.'''
    def new_func(*args):
        try:
            return func(*args)
        except Exception:
            return None
    return new_func


class ConditionParser:
    known_constants: dict[str, Any] = {
        'true': True,
        'false': False,
        'null': None
    }

    comparison_operators: dict[type, Callable] = {
        ast.Eq: lambda x, y: x == y,
        ast.NotEq: lambda x, y: x != y,
        ast.Lt: return_none_on_error(lambda x, y: x < y),
        ast.LtE: return_none_on_error(lambda x, y: x <= y),
        ast.Gt: return_none_on_error(lambda x, y: x > y),
        ast.GtE: return_none_on_error(lambda x, y: x >= y),
        ast.In: return_none_on_error(lambda x, y: x in y),
        ast.NotIn: return_none_on_error(lambda x, y: x not in y),
    }

    boolean_operators: dict[type, Callable] = {
        ast.And: lambda x, y: x and y,
        ast.Or: lambda x, y: x or y,
    }

    unary_operators: dict[type, Callable] = {
        ast.Not: lambda x: not x,
        ast.USub: lambda x: -x,
    }

    binary_operators: dict[type, Callable] = {
        ast.Add: return_none_on_error(lambda x, y: x + y),
    }

    def __init__(self, context, conditions, flags=None, **_):
        self.conditions: list
        self.functions: dict[str, Callable] = {
            'from_context': partial(demisto.dt, context)
        }
        self.modify_functions_with_flags(argToList(flags))
        self.load_conditions(conditions)
        self.default = (
            self.conditions.pop()['default']
            if 'default' in self.conditions[-1]
            else ''
        )
        self.validate_conditions()

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
            def to_case_insensitive(func):
                return lambda x, y: func(repr(x).lower(), repr(y).lower())
            self.comparison_operators |= {
                ast.Eq: to_case_insensitive(self.comparison_operators[ast.Eq]),
                ast.NotEq: to_case_insensitive(self.comparison_operators[ast.NotEq]),
            }
        if 'list_compare' in flags:
            def to_deep_search(func):
                return lambda x, y: (
                    func(x, y) or (
                        any(func(x, i) for i in y)
                        if isinstance(y, list)
                        else False
                    )
                )
            self.comparison_operators = {
                k: to_deep_search(v)
                for k, v
                in self.comparison_operators.items()
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
                return self.known_constants[node.id]
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
                    self.comparison_operators[type(op)](
                        left, left := self.get_value(right)  # noqa: F841
                    )
                    for op, right in zip(node.ops, node.comparators)
                )
            case ast.BoolOp:
                return reduce(
                    self.boolean_operators[type(node.op)],
                    map(self.get_value, node.values)
                )
            case ast.BinOp:
                return self.binary_operators[type(node.op)](
                    self.get_value(node.left),
                    self.get_value(node.right)
                )
            case ast.UnaryOp:
                return self.unary_operators[type(node.op)](
                    self.get_value(node.operand)
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
