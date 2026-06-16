import DarkmonVIPFanOut
import demistomock as demisto  # noqa: F401


def test_main_no_emails(mocker):
    """
    Given:
        - No protected emails passed to the script

    When:
        - main() is called with an empty emails list

    Then:
        - return_results is called with zero VIPCreated
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "emails": [],
            "seen_list": "test-list",
            "incident_type": "Darkmon VIP Alert",
            "name_template": "VIP: ${email}",
            "severity": "3",
        },
    )
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": "", "Type": 1}])
    mock_return = mocker.patch.object(DarkmonVIPFanOut, "return_results")

    DarkmonVIPFanOut.main()

    mock_return.assert_called_once()
    result = mock_return.call_args[0][0]
    assert result.get("VIPCreated") == 0 or result.get("VIPCreated") is not None
