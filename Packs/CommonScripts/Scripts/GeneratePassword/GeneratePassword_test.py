import pytest
from GeneratePassword import generate_password, SYMBOLS
from CommonServerPython import DemistoException


def does_password_meet_requirement(
    password: str,
    min_lowercase: int,
    max_lowercase: int,
    min_uppercase: int,
    max_uppercase: int,
    min_digits: int,
    max_digits: int,
    min_symbols: int,
    max_symbols: int,
) -> bool:
    lowercase_count = sum(1 for char in password if char.islower())
    uppercase_count = sum(1 for char in password if char.isupper())
    digit_count = sum(1 for char in password if char.isdigit())
    symbol_count = sum(1 for char in password if char in SYMBOLS)

    return all([
        min_lowercase <= lowercase_count <= max_lowercase,
        min_uppercase <= uppercase_count <= max_uppercase,
        min_digits <= digit_count <= max_digits,
        min_symbols <= symbol_count <= max_symbols
    ])


@pytest.mark.parametrize(
    'min_lowercase, max_lowercase, min_uppercase, max_uppercase, min_digits, max_digits, min_symbols, max_symbols',
    [
        (1, 2, 1, 2, 1, 2, 1, 2),  # Test case with all ranges set to 1-2
        (2, 5, 3, 5, 4, 6, 1, 3),  # Test case with various ranges
        (2, 5, 3, 5, 4, 10, 0, 0),  # Test case with no symbols
    ]
)
def test_generate_password(
    min_lowercase: int,
    max_lowercase: int,
    min_uppercase: int,
    max_uppercase: int,
    min_digits: int,
    max_digits: int,
    min_symbols: int,
    max_symbols: int,
):
    args = {
        'debug': 'true',
        'min_lcase': min_lowercase,
        'max_lcase': max_lowercase,
        'min_ucase': min_uppercase,
        'max_ucase': max_uppercase,
        'min_digits': min_digits,
        'max_digits': max_digits,
        'min_symbols': min_symbols,
        'max_symbols': max_symbols,
    }
    result = generate_password(args)
    pwd = result.outputs
    assert isinstance(pwd, str)
    assert does_password_meet_requirement(
        pwd,
        min_lowercase,
        max_lowercase,
        min_uppercase,
        max_uppercase,
        min_digits,
        max_digits,
        min_symbols,
        max_symbols,
    )


@pytest.mark.parametrize(
    'min_lowercase, max_lowercase, min_uppercase, max_uppercase, min_digits, max_digits, min_symbols, max_symbols, exception',
    [
        (0, 5, 0, 5, 0, 5, 0, 5,
         "error: At least one of the following arguments should be above 0"),  # Test case with all ranges set to 0-5
        (-3, 5, 0, 5, 0, 5, 0, 5, "All numeral arguments must be positive.")
    ]
)
def test_generate_password_zero_inputs(
    min_lowercase: int,
    max_lowercase: int,
    min_uppercase: int,
    max_uppercase: int,
    min_digits: int,
    max_digits: int,
    min_symbols: int,
    max_symbols: int,
    exception: str,
):
    args = {
        'debug': 'true',
        'min_lcase': min_lowercase,
        'max_lcase': max_lowercase,
        'min_ucase': min_uppercase,
        'max_ucase': max_uppercase,
        'min_digits': min_digits,
        'max_digits': max_digits,
        'min_symbols': min_symbols,
        'max_symbols': max_symbols,
    }
    with pytest.raises(DemistoException, match=exception):
        generate_password(args)
