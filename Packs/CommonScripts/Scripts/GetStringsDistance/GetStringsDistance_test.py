import demistomock as demisto
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


def test_main(mocker):
    """
        Given
        - The commands args.
        When
        - Calling the main function.
        Then
        - Verify the result is as expected.
    """
    from GetStringsDistance import main

    mocker.patch('GetStringsDistance.levenshtein', return_value=1)
    mocker.patch.object(demisto, 'args', return_value={"inputString": "aba", "compareString": "baba"})
    results_mock = mocker.patch.object(demisto, 'results')
    expected_result = {"LevenshteinDistance": 1, "StringA": "aba", "StringB": "baba", "TooClose": True}

    main()

    assert results_mock.call_args[0][0][0]['Contents']['Distances'][0] == expected_result
