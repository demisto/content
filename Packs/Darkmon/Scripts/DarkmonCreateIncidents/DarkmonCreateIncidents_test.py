import DarkmonCreateIncidents
import demistomock as demisto  # noqa: F401


def test_main_no_items(mocker):
    """
    Given:
        - No items passed to the script

    When:
        - main() is called with an empty items list

    Then:
        - return_results is called with zero CreatedIncidents
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "items": [],
            "incident_type": "Darkmon Alert",
            "name_template": "Alert: ${id}",
            "severity": "2",
        },
    )
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": "", "Type": 1}])
    mock_return = mocker.patch.object(DarkmonCreateIncidents, "return_results")

    DarkmonCreateIncidents.main()

    mock_return.assert_called_once()
    result = mock_return.call_args[0][0]
    assert result.get("CreatedIncidents") == [] or result.get("Count") == 0
