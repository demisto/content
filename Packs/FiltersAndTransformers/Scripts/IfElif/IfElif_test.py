import pytest
from unittest.mock import patch


def test_load_variables():
    import IfElif

    IfElif.ARGS = {
        'variables': 'int_var=42 \n str_var = hello  \nlist_var  =  [1, 2, 3]',
        'value': 'some_value'
    }

    variables = IfElif.load_variables()

    assert variables['int_var'] == 42
    assert variables['str_var'] == 'hello'
    assert variables['list_var'] == [1, 2, 3]
    assert variables['true'] is True
    assert variables['false'] is False
    assert variables['null'] is None
    assert variables['VALUE'] == 'some_value'


@pytest.mark.parametrize(
    'expression, expected_result',
    [
        ('true and [1,2,3]', True),
        ('1 and 2 < 3 < 4 or 5 or [] or 4', True),
        ('1 or 2 or 0', True),
        ('false and {1: 2, 3: [4,5,6,7]}', False),
        ('regex_match("\s", " ")', True),
        ('regex_match("\s", "s")', False),
    ]
)
def test_evaluate(expression, expected_result):
    """
    Given:
        - A boolean expression as a string.

    When:
        - Running If-Elif

    Then:
        - Parse the expression and return it's boolean value.
    """
    from IfElif import evaluate

    result = evaluate(expression)

    assert bool(result) is expected_result


@pytest.mark.parametrize(
    'expression',
    [
        'word or 1',
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
    from IfElif import evaluate

    with pytest.raises(SyntaxError):
        evaluate(expression)


# @patch('demisto.args', return_value={'value': 'some_value'})
@pytest.mark.parametrize(
    'expression, expected_result',
    [
        ('true and [1,2,3]', True),
        ('1 and 2 < 3 < 4 or 5 or [] or 4', True),
        ('1 or 2 or 0', True),
        ('false and {1: 2, 3: [4,5,6,7]}', False),
        ('regex_match("\s", " ")', True),
        ('regex_match("\s", "s")', False),
    ]
)
def test_evaluate_flags(expression, expected_result):
    """
    Given:
        - A boolean expression as a string.

    When:
        - Running If-Elif with flags

    Then:
        - Parse the expression and return it's boolean value.
    """
    from IfElif import evaluate

    result = evaluate(expression)

    assert bool(result) is expected_result
