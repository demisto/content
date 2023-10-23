import pytest
from IfElif import ConditionParser
import ast
import json


class MockConditionParser(ConditionParser):
    def __init__(self, *args, **kwargs) -> None:
        self.functions = {}


def test_modify_functions_with_flags():

    if_elif1 = MockConditionParser()
    if_elif1.modify_functions_with_flags(['regex_multiline', 'regex_dot_all'])
    assert int(if_elif1.regex_flags) == 24

    if_elif2 = MockConditionParser()
    assert if_elif2.comparison_operators[ast.Eq]('a', 'A') is False
    assert if_elif2.comparison_operators[ast.NotEq]('a', 'A') is True
    if_elif2.modify_functions_with_flags(['case_insensitive'])
    assert if_elif2.comparison_operators[ast.Eq]('a', 'A') is True
    assert if_elif2.comparison_operators[ast.NotEq]('a', 'A') is False

    if_elif3 = MockConditionParser()
    if_elif3.modify_functions_with_flags([])
    assert if_elif3.functions['regex_match']('\s', 'a a')
    if_elif3.modify_functions_with_flags(['regex_full_match'])
    assert not if_elif3.functions['regex_match']('\s', 'a a')
    assert if_elif3.functions['regex_match']('\s', ' ')


@pytest.mark.parametrize(
    'expression, expected_result',
    [
        ('1 < 2', True),
        ('1 > 2', False),
        ('1 <= 2 <= 2', True),
        ('2 >= 2 >= 1', True),
        ('1 == 2', False),
        ('1 == 1', True),
        ('1 != 1', False),
        ('1 != 2', True),
        ('1 and 1 and 0', False),
        ('1 or 0', True),
        ('1 or 0 or 0 or null or []', True),
        ('not 1', False),
        ('not false', True),
        ('1 not in [1,2,3,4,5]', False),
        ('1 in [1,2,3,4,5]', True),
        ('"a" + "b" == "ab"', True),
        ('(true and not false and (0 or 2) in {2:3})'
         ' and (1 not in [[[1]]] or false)'
         ' and (1 < 2 < 3 > 2 > 1) in [true, null]', True),
        ('1 < "hi"', False),
        ('"a" < [1,2,3]', False),
        ('3 + [1,2]', False)
    ]
)
def test_parse_conditions(expression, expected_result):
    """
    Given:
        - A boolean expression as a string.

    When:
        - Running If-Elif

    Then:
        - Parse the expression and return it's boolean value.
    """

    if_elif = ConditionParser(
        context=None,
        conditions=json.dumps([
            {
                'condition': expression,
                'return': True
            },
            {
                'default': False
            }
        ]),
    )

    result = if_elif.parse_conditions()

    assert result is expected_result


@pytest.mark.parametrize(
    'expression',
    [
        'unknown_word or 1',
        '__import__("os").system("RM -RF /")',
        '1 if 0 else 2',
        'sys.exit()'
    ]
)
def test_evaluate_error(expression):
    """
    Given:
        - A boolean expression with invalid or unsupported syntax.

    When:
        - Running If-Elif

    Then:
        - Raise an error.
    """
    with pytest.raises(Exception):
        MockConditionParser().evaluate(expression)
