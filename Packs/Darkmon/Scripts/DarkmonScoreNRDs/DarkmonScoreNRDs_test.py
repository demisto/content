import DarkmonScoreNRDs
import demistomock as demisto  # noqa: F401


def test_main_no_items(mocker):
    """
    Given:
        - No NRD items passed to the script

    When:
        - main() is called with an empty items list

    Then:
        - return_results is called with an empty Typosquats list
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={"items": [], "brands_list": "test-brands", "max_distance": "2"},
    )
    mocker.patch.object(
        demisto, "executeCommand", return_value=[{"Contents": "", "Type": 1}]
    )
    mock_return = mocker.patch.object(DarkmonScoreNRDs, "return_results")

    DarkmonScoreNRDs.main()

    mock_return.assert_called_once()
    result = mock_return.call_args[0][0]
    assert result.get("Typosquats") == [] or result.get("Typosquats") is not None
