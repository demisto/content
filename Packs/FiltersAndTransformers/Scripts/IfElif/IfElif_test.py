import pytest


@pytest.mark.parametrize(
    'expression, expected_result',
    [
        ('true and [1,2,3]', True),
        ('1 and 2 < 3 < 4 or 5 or [] or 4', True),
        ('1 or 2 or 0', True),
        ('false and {1: 2, 3: [4,5,6,7]}', False),
    ]
)
def test_parse_boolean_expression(expression, expected_result):
    """
    Given:
        - A boolean expression as a string.

    When:
        - Running If-Elif

    Then:
        - Parse the expression and return it's boolean value.
    """
    from IfElif import parse_boolean_expression

    result = parse_boolean_expression(expression)

    assert result is expected_result


@pytest.mark.parametrize(
    'expression',
    [
        'sdjkasds or 1',
        '__import__("os").system("RM -RF /")',
        '1 if 0 else 2',
        'sys.exit()'
    ]
)
def test_parse_boolean_expression_error(expression):
    """
    Given:
        - A boolean expression with invalid or unsupported syntax.

    When:
        - Running If-Elif

    Then:
        - Raise an error.
    """
    from IfElif import parse_boolean_expression

    with pytest.raises(SyntaxError):
        parse_boolean_expression(expression)


def test_load_conditions(mocker):
    """
    Given:
        - A string containing context references in the format #{<path>} and/or "#VALUE".

    When:
        - Running If-Elif

    Then:
        - Replace #{...}'s with the string representation of the corresponding value in the context
          and "#VALUE" with the demisto.args()['value'].
    """
    import IfElif

    args = {'conditions': '{"key1": #{a.b.[0].c}, "key2": #{a.b.[1].c}, "key3": #VALUE}', 'value': 'value3'}
    IfElif.CONTEXT = {'a': {'b': [{'c': 'value1'}, {'c': 'value2'}]}}

    result = IfElif.load_conditions(args)

    assert result == {'key1': 'value1', 'key2': 'value2', 'key3': 'value3'}
