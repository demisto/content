import pytest
from IfElif import IfElif
import ast


class MockIfElif(IfElif):
    def __init__(self, *args, **kwargs) -> None:
        pass


def test_handle_flags():

    if_elif1 = MockIfElif()
    if_elif1.handle_flags(['case_insensitive', 'regex_multiline', 'regex_dot_all'])
    assert int(if_elif1.regex_flags) == 26

    if_elif2 = MockIfElif()
    assert if_elif2.operator_functions[ast.Eq]('a', 'A') is False
    assert if_elif2.operator_functions[ast.NotEq]('a', 'A') is True
    if_elif2.handle_flags(['case_insensitive'])
    assert if_elif2.operator_functions[ast.Eq]('a', 'A') is True
    assert if_elif2.operator_functions[ast.NotEq]('a', 'A') is False

    if_elif3 = MockIfElif()
    if_elif3.handle_flags([])
    assert if_elif3.functions['regex_match']('\s', 'a a')
    if_elif3.handle_flags(['regex_full_match'])
    assert not if_elif3.functions['regex_match']('\s', 'a a')
    assert not if_elif3.functions['regex_match']('\s', ' ')


def test_load_variables():

    if_elif = MockIfElif()
    if_elif.load_variables(
        variables='int_var=42 \n str_var = hello  \nlist_var  =  [1, 2, 3]',
        value='some_value'
    )

    assert if_elif.variables['int_var'] == 42
    assert if_elif.variables['str_var'] == 'hello'
    assert if_elif.variables['list_var'] == [1, 2, 3]
    assert if_elif.variables['true'] is True
    assert if_elif.variables['false'] is False
    assert if_elif.variables['null'] is None
    assert if_elif.variables['VALUE'] == 'some_value'


@pytest.mark.parametrize(
    'value, expression, variables, expected_result',
    [
        ('a', 'VALUE == "a" and [1,2,3]', '', True),
        (None, '1 in list_var and 2 < 3 < int_var', 'int_var=42 \nlist_var  =  [1, 2, 3]', True),
        (None, 'regex_match(regex, str_var)', ' str_var = hello\nregex = ^\w{4}$\n', True),
        (None, 'false and {1: 2, 3: [4,5,6,7]}', '', False),
        (None, 'regex_match("\s", "s")', '', False),
    ]
)
def test_parse_conditions(value, expression, variables, expected_result):
    """
    Given:
        - A boolean expression as a string.

    When:
        - Running If-Elif

    Then:
        - Parse the expression and return it's boolean value.
    """

    if_elif = IfElif(
        value=value,
        conditions=str({
            {
                'condition': expression,
                'return': True
            },
            {
                'else': False
            }
        }),
        variables=variables,
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
        MockIfElif().evaluate(expression)
