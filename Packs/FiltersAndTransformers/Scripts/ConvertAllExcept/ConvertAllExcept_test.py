import pytest


@pytest.mark.parametrize(
    "args, expected_result",
    [
        ({'value': "Value_to_convert", 'convertTo': 'hello', 'except': "Value_to_convert"}, "Value_to_convert"),
    ],
)
def test_ConvertAllExcept(args, expected_result):
    """
    Given:
        - A dict of args.
    When:
        - Running ConvertAllExcept script.
    Then:
        - Validating the value of the script.
    """
    from ConvertAllExcept import main
    result = main(args)
    assert result == expected_result
