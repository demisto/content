import DarkmonLevenshtein
import demistomock as demisto  # noqa: F401


def test_levenshtein_identical():
    """
    Given:
        - Two identical strings

    When:
        - levenshtein() is called

    Then:
        - Distance is 0
    """
    assert DarkmonLevenshtein.levenshtein("acme", "acme") == 0


def test_levenshtein_single_substitution():
    """
    Given:
        - Two strings differing by one character

    When:
        - levenshtein() is called

    Then:
        - Distance is 1
    """
    assert DarkmonLevenshtein.levenshtein("acme", "acne") == 1


def test_main_returns_closest_brand(mocker):
    """
    Given:
        - A domain and a list of brand names

    When:
        - main() is called

    Then:
        - return_results is called with the closest brand and its distance
    """
    mocker.patch.object(demisto, "args", return_value={"domain": "acmee.com", "brands": "acme,google"})
    mock_return = mocker.patch.object(DarkmonLevenshtein, "return_results")

    DarkmonLevenshtein.main()

    mock_return.assert_called_once()
    result = mock_return.call_args[0][0]
    assert result["Contents"]["brand"] == "acme"
    assert result["Contents"]["distance"] == 1
