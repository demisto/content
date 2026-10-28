import DarkmonFilterCVEs
import demistomock as demisto  # noqa: F401


def test_main_no_items(mocker):
    """
    Given:
        - No items passed to the script

    When:
        - main() is called with an empty items list

    Then:
        - return_results is called with an empty FilteredCVEs list
    """
    mocker.patch.object(demisto, "args", return_value={"items": [], "min_cvss": "9.0"})
    mocker.patch.object(demisto, "executeCommand", return_value=None)
    mock_return = mocker.patch.object(DarkmonFilterCVEs, "return_results")

    DarkmonFilterCVEs.main()

    mock_return.assert_called_once_with({"FilteredCVEs": []})


def test_main_filters_below_min_cvss(mocker):
    """
    Given:
        - Two CVE items, one above and one below the min_cvss threshold

    When:
        - main() is called with min_cvss=9.0

    Then:
        - Only the CVE with score >= 9.0 is returned in FilteredCVEs
    """
    items = [
        {"id": "CVE-2024-0001", "cvssScore": 9.5, "tags": []},
        {"id": "CVE-2024-0002", "cvssScore": 5.0, "tags": []},
    ]
    mocker.patch.object(demisto, "args", return_value={"items": items, "min_cvss": "9.0"})
    mocker.patch.object(demisto, "executeCommand", return_value=None)
    mock_return = mocker.patch.object(DarkmonFilterCVEs, "return_results")

    DarkmonFilterCVEs.main()

    mock_return.assert_called_once_with({"FilteredCVEs": [items[0]]})
