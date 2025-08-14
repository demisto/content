import json


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)


def test_get_asset_details_command_success(mocker):
    """
    GIVEN:
        A mocked client and valid arguments with an asset ID.
    WHEN:
        The get_asset_details_command function is called.
    THEN:
        The response is parsed, formatted, and returned correctly.
    """
    from CortexPlatformCore import Client, get_asset_details_command

    mock_client = Client(base_url="", headers={})
    mock_get_asset_details = mocker.patch.object(
        mock_client, "_http_request", return_value={"reply": {"id": "1234", "name": "Test Asset"}}
    )

    args = {"asset_id": "1234"}

    result = get_asset_details_command(mock_client, args)

    assert result.outputs == {"id": "1234", "name": "Test Asset"}
    assert "Test Asset" in result.readable_output
    assert mock_get_asset_details.call_count == 1


def test_replace_args_alert_with_issue():
    """
    GIVEN:
        Arguments dictionary with various key types - single issue key, multiple issue keys, and mixed keys.
    WHEN:
        The replace_args_alert_with_issue function is called.
    THEN:
        All 'issue' keys are replaced with 'alert' and values are preserved, while other keys remain unchanged.
    """
    from CortexPlatformCore import replace_args_alert_with_issue

    # Test single issue key
    args = {"issue_id": "12345"}
    result = replace_args_alert_with_issue(args)

    assert result == {"alert_id": "12345"}
    assert "issue_id" not in result
    assert "alert_id" in result

    # Test multiple issue keys
    args = {"issue_id": "12345", "issue_status": "open", "issue_priority": "high"}
    result = replace_args_alert_with_issue(args)

    expected = {"alert_id": "12345", "alert_status": "open", "alert_priority": "high"}
    assert result == expected
    assert "issue_id" not in result
    assert "issue_status" not in result
    assert "issue_priority" not in result

    # Test mixed keys
    args = {"issue_id": "12345", "user_name": "john", "issue_type": "bug", "timestamp": "2023-01-01"}
    result = replace_args_alert_with_issue(args)

    expected = {"alert_id": "12345", "user_name": "john", "alert_type": "bug", "timestamp": "2023-01-01"}
    assert result == expected
    assert "issue_id" not in result
    assert "issue_type" not in result
    assert result["user_name"] == "john"
    assert result["timestamp"] == "2023-01-01"
