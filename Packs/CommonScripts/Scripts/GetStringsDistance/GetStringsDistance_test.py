import demistomock as demisto
import pytest


@pytest.mark.parametrize("str1, str2, expected_results", [("aaa", "aaa", 0), ("aba", "baba", 1), ("kitten", "sitting", 3)])
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


@pytest.mark.parametrize(
    "args, expected_result",
    [
        pytest.param(
            {"inputString": "123", "compareString": "abc"},
            {"LevenshteinDistance": 3, "StringA": "123", "StringB": "abc", "TooClose": False},
            id="Two different strings",
        ),
        pytest.param(
            {"inputString": "aba", "compareString": "baba"},
            {"LevenshteinDistance": 1, "StringA": "aba", "StringB": "baba", "TooClose": True},
            id="Two similar strings",
        ),
        pytest.param(
            {"inputString": "johndoe", "compareString": "johndoe"},
            {"LevenshteinDistance": 0, "StringA": "johndoe", "StringB": "johndoe", "TooClose": True},
            id="Two identical strings",
        ),
    ],
)
def test_main(mocker, args: dict, expected_result: dict):
    """
    Given
    - The commands args.
    When
    - Calling the main function.
    Then
    - Verify the result is as expected.
    """
    from GetStringsDistance import main

    mocker.patch.object(demisto, "args", return_value=args)
    results_mock = mocker.patch.object(demisto, "results")

    main()

    assert results_mock.call_args[0][0][0]["Contents"]["Distances"][0] == expected_result
