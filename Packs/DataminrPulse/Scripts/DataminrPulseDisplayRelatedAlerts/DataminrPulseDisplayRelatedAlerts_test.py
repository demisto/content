import demistomock as demisto
from DataminrPulseDisplayRelatedAlerts import main
from unittest.mock import patch


@patch("DataminrPulseDisplayRelatedAlerts.return_results")
def test_display_related_alerts_success(mock_return, mocker):
    """
    Test the display_related_alerts function when related alerts are present.

    Given:
        - alerts data
    When:
        - Calling `display_related_alerts` function
    Then:
        - Returns CommandResults object.
    """
    mocker.patch.object(
        demisto,
        "get",
        return_value=[
            {
                "alertType": {"name": "Test Alert Type"},
                "alertId": "12345",
                "caption": "Test Alert",
                "expandAlertURL": " http://dummy.com",
                "watchlistsMatchedByType": [{"name": "Test Watchlist"}],
                "eventTime": 1620149700,
                "eventLocation": {"name": "Test Location"},
                "post": {"link": " http://dummy.com"},
                "source": {"verified": True},
                "publisherCategory": {"name": "Test Publisher Category"},
            }
        ],
    )
    expected_output = "### \n# Related Alerts Information: \n|Alert Type|Alert ID|Caption|Alert URL|Watchlist Name|Alert Time|Alert Location|Post Link|Is source verified|Publisher Category|\n|---|---|---|---|---|---|---|---|---|---|\n| Test Alert Type | 12345 | Test Alert | [ http://dummy.com]( http://dummy.com) | Test Watchlist | 19 Jan 1970, 06:02 PM UTC | Test Location | [ http://dummy.com]( http://dummy.com) | true | Test Publisher Category |\n"  # noqa:E501
    main()
    assert expected_output in mock_return.call_args.args[0].readable_output


@patch("DataminrPulseDisplayRelatedAlerts.return_results")
def test_display_related_alerts_with_no_alerts(mock_return, mocker):
    """
    Test the display_related_alerts function when no related alerts are present.

    Given:
        - no alerts are present
    When:
        - Calling `display_related_alerts` function
    Then:
        - Returns CommandResults object.
    """
    mocker.patch.object(demisto, "context", return_value={})
    expected_output = "\n#### No related alerts available for this alert."
    main()
    assert expected_output in mock_return.call_args.args[0].readable_output
