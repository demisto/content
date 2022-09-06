import pytest


@pytest.mark.parametrize('str1, str2, expected_results', [
    ('aaa', 'aaa', 0),
    ('aba', 'baba', 1),
    ('kitten', 'sitting', 3)
])
def test_levenshtein(str1, str2, expected_results):
    """
        Given
        - Two strings.
        When
        - Calling levenshtein function.
        Then
        - Return the Levenshtein distance (int).
    """
    from GetStringsDistance import levenshtein

    assert levenshtein(str1, str2) == expected_results
