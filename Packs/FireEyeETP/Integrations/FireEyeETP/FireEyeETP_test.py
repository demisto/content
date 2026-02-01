import json
from unittest.mock import MagicMock, mock_open, patch

import demistomock as demisto
import FireEyeETP
import pytest
from CommonServerPython import CommandResults, EntryType, tableToMarkdown
from FireEyeETP import Client


def test_malware_readable_data():
    """
    Given:
        A dict with only "name" key
    When:
        calling malware_readable_data method on it
    Then:
        Ensure execution does not raise exception on it
    """
    from FireEyeETP import malware_readable_data

    try:
        malware_readable_data({"name": "some-name"})
    except KeyError:
        raise AssertionError("malware_readable_data method should not fail on dict with name key only")


def test_get_alert_command(mocker, requests_mock):
    """
    Given:
        - ID of alert to get
        - The alert object contain unicode

    When:
        - Running get-alert command

    Then:
        - Ensure command runs successfully
        - Ensure results are returned
    """
    import FireEyeETP

    base_url = "https://server_url/api/v1"
    mocker.patch("FireEyeETP.BASE_PATH_V1", base_url)
    mocker.patch("FireEyeETP.API_KEY", "fake-api-key")
    mocker.patch.object(demisto, "args", return_value={"alert_id": "KgBdei7RQS4u4m8Jl7mG"})
    mocker.patch.object(demisto, "results")
    requests_mock.get(
        base_url + "/alerts/KgBdei7RQS4u4m8Jl7mG?",
        json={
            "meta": {"total": 1},
            "data": [
                {
                    "alert": {"explanation": {"malware_detected": {"malware": {}}}},
                    "email": {"headers": {"to": "\u200b"}, "timestamp": {}},
                }
            ],
        },
    )
    FireEyeETP.get_alert_command()
    results = demisto.results.call_args[0][0]
    assert results


def test_fetch_incident_by_status_messages(mocker):
    """
    Given:
        - A status message similar to the alert's status
    When:
        - Running fetch-incidents command (v2 implementation)
    Then:
        - Ensure one incident was fetched as expected
        - Ensure the correct v2 request functions were called
    """
    from FireEyeETP import Client

    mock_client = MagicMock(spec=Client)
    response_1 = {
        "meta": {"search_after": "token123", "size": 1},
        "data": [{"id": "alert1", "email_status": "delivered (retroactive)"}],
    }
    response_2 = {"id": "alert1", "alert": {"occurred": "2023-02-09T19:34:17Z", "severity": "minr"}}

    mocker.patch.object(FireEyeETP, "MESSAGE_STATUS", ["delivered (retroactive)"])
    mocker.patch("FireEyeETP.demisto.getLastRun", return_value={})
    mock_client.get_alerts_request_v2.return_value = response_1
    mock_client.get_alert_request_v2.return_value = response_2
    mocker.patch("FireEyeETP.demisto.setLastRun")

    incidents, last_run = FireEyeETP.fetch_incidents(mock_client)

    assert incidents[0].get("name") == "alert1"
    assert incidents[0].get("rawJSON") == json.dumps(response_2)
    assert last_run.get("pagination_token") == "token123"


def test_fetch_incident_by_status_messages_mismatch_status(mocker):
    """
    Given:
        - A status message differs from the alert's status
    When:
        - Running fetch-incidents command (v2 implementation)
    Then:
        - Ensure no incidents were fetched as expected due to filtering
    """
    from FireEyeETP import Client

    mock_client = MagicMock(spec=Client)
    response_1 = {
        "meta": {"search_after": "token123", "size": 1},
        "data": [{"id": "alert1", "email_status": "deleted"}],
    }

    mocker.patch.object(FireEyeETP, "MESSAGE_STATUS", ["delivered (retroactive)"])
    mocker.patch("FireEyeETP.demisto.getLastRun", return_value={})
    mock_client.get_alerts_request_v2.return_value = response_1
    mocker.patch("FireEyeETP.demisto.setLastRun")

    incidents, _ = FireEyeETP.fetch_incidents(mock_client)

    assert incidents == []


def test_fetch_incident_by_status_messages_with_two_status(mocker):
    """
    Given:
        - A list of status messages matching the alerts' statuses
    When:
        - Running fetch-incidents command (v2 implementation)
    Then:
        - Ensure 2 incidents were fetched as expected
    """
    from FireEyeETP import Client

    mock_client = MagicMock(spec=Client)

    response_1 = {
        "meta": {"search_after": "token456", "size": 2},
        "data": [{"id": "alert1", "email_status": "delivered (retroactive)"}, {"id": "alert2", "email_status": "deleted"}],
    }
    response_alert1 = {"id": "alert1", "alert": {"occurred": "2023-02-09T19:34:17Z", "severity": "minr"}}
    response_alert2 = {"id": "alert2", "alert": {"occurred": "2023-02-09T19:34:18Z", "severity": "majr"}}

    mocker.patch.object(FireEyeETP, "MESSAGE_STATUS", ["delivered (retroactive)", "deleted"])
    mocker.patch("FireEyeETP.demisto.getLastRun", return_value={})
    mock_client.get_alerts_request_v2.return_value = response_1
    mock_client.get_alert_request_v2.side_effect = [response_alert1, response_alert2]
    mocker.patch("FireEyeETP.demisto.setLastRun")

    incidents, _ = FireEyeETP.fetch_incidents(mock_client)

    assert len(incidents) == 2
    assert incidents[0].get("name") == "alert1"
    assert incidents[1].get("name") == "alert2"


@pytest.fixture
def FireEyeETP_client():
    return Client(base_url="https://fireeyeetp", verify=False, headers={}, proxy=False)


@patch("FireEyeETP.fileResult")
def test_download_alert_artifacts_command(mock_file_result):
    """
    Given:
        - ID of alert to get
    When:
        - Running download-alert-artifact command
    Then:
        - Ensure 1 zip file fetched as expected
    """
    from FireEyeETP import Client, download_alert_artifacts_command

    args = {"alert_id": "12345"}
    mock_client = MagicMock(spec=Client)
    mock_response = MagicMock()
    mock_response.content = b"fake_zip_content"
    mock_client.get_artifacts.return_value = mock_response
    mock_file_result.return_value = {"File": "12345.zip", "Type": EntryType.FILE, "Contents": "fake_zip_content"}
    results = download_alert_artifacts_command(mock_client, args)
    mock_client.get_artifacts.assert_called_once_with("12345")
    mock_file_result.assert_called_once_with("12345.zip", data=b"fake_zip_content", file_type=EntryType.FILE)
    assert isinstance(results[0], CommandResults)
    assert results[0].readable_output == "Download alert artifact completed successfully"
    assert results[1] == {"File": "12345.zip", "Type": EntryType.FILE, "Contents": "fake_zip_content"}


def test_list_yara_rulesets_command():
    """
    Given:
        - Policy UUID to get
    When:
        - Running list-yara-rulesets command
    Then:
        - Ensure command runs successfully
        - Ensure results are returned
    """
    from FireEyeETP import Client, list_yara_rulesets_command

    args = {"policy_uuid": "abc-123-uuid"}
    mock_client = MagicMock(spec=Client)
    mock_response = {
        "data": {
            "rulesets": [
                {"name": "Test Ruleset", "description": "Test Description", "uuid": "uuid-123", "yara_file_name": "test.yara"}
            ]
        }
    }
    mock_client.get_yara_rulesets.return_value = mock_response
    result = list_yara_rulesets_command(mock_client, args)
    mock_client.get_yara_rulesets.assert_called_once_with("abc-123-uuid")
    assert isinstance(result, CommandResults)
    assert result.outputs == [
        {"name": "Test Ruleset", "description": "Test Description", "uuid": "uuid-123", "yara_file_name": "test.yara"}
    ]
    assert result.outputs_prefix == "FireEyeETP.Policy.abc-123-uuid"
    assert result.readable_output == (
        "### Rulesets\n|name|description|uuid|yara_file_name|\n|---|---|---|---|\n| Test Ruleset"
        " | Test Description | uuid-123 | test.yara |\n"
    )


@patch("FireEyeETP.fileResult")
def test_download_yara_file_command(mock_file_result):
    """
    Given:
        - Policy UUID to get
        - Ruleset UUID to get
    When:
        - Running download-yara-file command
    Then:
        - Ensure command runs successfully
        - Ensure 1 yara file fetched as expected
    """
    from FireEyeETP import Client, download_yara_file_command

    args = {"policy_uuid": "policy-12345", "ruleset_uuid": "ruleset-67890"}
    mock_client = MagicMock(spec=Client)
    mock_response = MagicMock()
    mock_response.content = b"fake_yara_file_content"
    mock_file_result.return_value = {"File": "original.yara", "Type": EntryType.FILE, "Contents": "fake_yara_file_content"}
    mock_client.get_yara_file.return_value = mock_response
    results = download_yara_file_command(mock_client, args)
    mock_file_result.assert_called_once_with("original.yara", data=b"fake_yara_file_content", file_type=EntryType.FILE)
    assert isinstance(results[0], CommandResults)
    assert results[0].readable_output == "Download yara file completed successfully."
    assert results[1] == {"File": "original.yara", "Type": EntryType.FILE, "Contents": "fake_yara_file_content"}


@patch("FireEyeETP.demisto.getFilePath")
@patch("FireEyeETP.open", new_callable=mock_open, read_data=b"fake_yara_file_content")
def test_upload_yara_file_command_success(mock_open_file, mock_getFilePath):
    """
    Given:
        - Policy UUID to get
        - Ruleset UUID to get
        - EntryID of context file to put
    When:
        - Running upload-yara-file command
    Then:
        - Ensure command runs successfully
        - Ensure 1 yara file uploaded as expected
    """
    from FireEyeETP import Client, upload_yara_file_command

    args = {"entryID": "1", "policy_uuid": "policy-12345", "ruleset_uuid": "ruleset-67890"}
    mock_getFilePath.return_value = {"path": "/path/to/file"}
    mock_response = MagicMock()
    mock_response.status_code = 202
    mock_client = MagicMock(spec=Client)
    mock_client.upload_yara_file.return_value = mock_response
    results = upload_yara_file_command(mock_client, args)
    mock_getFilePath.assert_called_once_with("1")
    mock_open_file.assert_called_once_with("/path/to/file", "rb")
    assert isinstance(results, CommandResults)
    assert results.readable_output == "Upload of Yara file succesfully."


@patch("FireEyeETP.demisto.getFilePath")
@patch("FireEyeETP.open", new_callable=mock_open, read_data=b"fake_yara_file_content")
def test_upload_yara_file_command_failure(mock_open_file, mock_getFilePath):
    """
    Given:
        - Policy UUID to get
        - Ruleset UUID to get
        - EntryID of context file to put
    When:
        - Running upload-yara-file command
    Then:
        - Ensure no yara file uploaded as expected
    """
    from FireEyeETP import Client, upload_yara_file_command

    args = {"entryID": "1", "policy_uuid": "policy-12345", "ruleset_uuid": "ruleset-67890"}
    mock_getFilePath.return_value = {"path": "/path/to/file"}
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_client = MagicMock(spec=Client)
    mock_client.upload_yara_file.return_value = mock_response
    results = upload_yara_file_command(mock_client, args)
    mock_getFilePath.assert_called_once_with("1")
    mock_open_file.assert_called_once_with("/path/to/file", "rb")
    assert isinstance(results, CommandResults)
    assert results.readable_output == "Upload of Yara file failed."


def test_get_events_data_command_delivered():
    """
    Given:
        - Message ID to get
    When:
        - Running get-events-data command
    Then:
        - Ensure command runs successfully
        - Ensure results are returned
    """
    from FireEyeETP import Client, get_events_data_command

    args = {"message_id": "12345"}
    mock_response = {
        "data": {"12345": [{"action_on_msg": "MTA_RCPT_DELIVERED_OUTBOUND", "display_msg": "Delivered <internetMessageId12345>"}]}
    }
    mock_client = MagicMock(spec=Client)
    mock_client.get_events_data.return_value = mock_response
    result = get_events_data_command(mock_client, args)
    assert isinstance(result, CommandResults)
    expected_output = {
        "Logs": mock_response["data"]["12345"],
        "Delivered_msg": "Delivered <internetMessageId12345>",
        "Delivered_status": "Delivered",
        "InternetMessageId": "internetMessageId12345",
    }
    assert result.outputs == expected_output
    assert result.outputs_prefix == "FireEyeETP.Events"
    expected_md = tableToMarkdown(
        "Events", expected_output, headers=["Logs", "Delivered_msg", "Delivered_status"], is_auto_json_transform=True
    )
    assert result.readable_output == expected_md


def test_get_events_data_command_failed():
    """
    Given:
        - Message ID to get
    When:
        - Running get-events-data command
    Then:
        - Ensure results are not returned
    """
    from FireEyeETP import Client, get_events_data_command

    args = {"message_id": "12345"}
    mock_response = {
        "data": {
            "12345": [
                {
                    "action_on_msg": "MTA_RCPT_DELIVERY_PERM_FAILURE_OUTBOUND",
                    "display_msg": "Failed to deliver <internetMessageId67890>",
                }
            ]
        }
    }
    mock_client = MagicMock(spec=Client)
    mock_client.get_events_data.return_value = mock_response
    result = get_events_data_command(mock_client, args)
    assert isinstance(result, CommandResults)
    expected_output = {
        "Logs": mock_response["data"]["12345"],
        "Delivered_msg": "Failed to deliver <internetMessageId67890>",
        "Delivered_status": "Failed",
    }
    assert result.outputs == expected_output
    assert result.outputs_prefix == "FireEyeETP.Events"
    expected_md = tableToMarkdown(
        "Events", expected_output, headers=["Logs", "Delivered_msg", "Delivered_status"], is_auto_json_transform=True
    )
    assert result.readable_output == expected_md


class MockResponse:
    def __init__(self, data):
        self.data = data

    def json(self):
        return self.data


def test_quarantine_release_command(mocker):
    """
    Given:
        - Message ID to get
    When:
        - Running quarantine-release command
    Then:
        - Ensure command runs successfully
        - Ensure results are returned
        - Ensure message send succesfully to quarantine
    """
    from FireEyeETP import Client, quarantine_release_command

    response_data = {"data": {"type": "some_type", "operation": "some_operation", "successful_message_ids": "1,2,3"}}

    mock_response = MockResponse(response_data)
    args = {"message_id": "12345"}
    mock_client = MagicMock(spec=Client)
    mock_client.quarantine_release.return_value = mock_response
    result = quarantine_release_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.readable_output == (
        "### Quarantine\n|type|operation|successful_message_ids|\n|---|---|---|\n| some_type | some_operation | 1,2,3 |\n"
    )
    mock_client.quarantine_release.assert_called_once_with("12345")


@pytest.mark.parametrize(
    "client_id, client_secret, api_key, scopes, expected_result, expected_exception",
    [
        # Case 1: SUCCESS - Full OAuth2 configuration
        ("id", "secret", "", "scope", "oauth2", None),
        # Case 2: SUCCESS - API Key configuration
        ("", "", "key", "", "api_key", None),
        # Case 3: FAILURE - Ambiguous Over-Configuration (OAuth2 + API Key)
        ("id", "secret", "key", "scope", None, r"Both OAuth2 \(Client ID/Secret\) and API Key were provided\..*"),
        # Case 4: FAILURE - Incomplete OAuth2 (Missing Scopes)
        ("id", "secret", "", "", None, r".*'OAuth Scopes' parameter is missing\..*"),
        # Case 5 (FIXED): FAILURE - Incomplete OAuth2 (Missing Secret)
        # We expect the error message for MISSING SECRET.
        ("id", "", "", "scope", None, r"Client ID provided but Client Secret is missing\..*"),
        # Case 6 (FIXED): FAILURE - Incomplete OAuth2 (Missing ID)
        # We expect the error message for MISSING ID.
        ("", "secret", "", "scope", None, r"Client Secret provided but Client ID is missing\..*"),
        # Case 7: FAILURE - No credentials provided
        ("", "", "", "", None, r"No authentication credentials provided\."),
    ],
)
def test_validate_authentication_params_parametrized(
    client_id, client_secret, api_key, scopes, expected_result, expected_exception, mocker
):
    """
    Given:
        - A set of authentication parameters (client ID, client secret, API key, scopes).
    When:
        - Calling the validate_authentication_params function.
    Then:
        - Ensure the function returns the expected authentication method ('oauth2' or 'api_key'),
          OR
        - Ensure the function raises the expected ValueError for invalid or over-configured parameters.
    """
    mocker.patch("FireEyeETP.CLIENT_ID", client_id)
    mocker.patch("FireEyeETP.CLIENT_SECRET", client_secret)
    mocker.patch("FireEyeETP.API_KEY", api_key)
    mocker.patch("FireEyeETP.SCOPES", scopes)

    from FireEyeETP import validate_authentication_params

    if expected_exception:
        with pytest.raises(ValueError, match=expected_exception):
            validate_authentication_params()
    else:
        assert validate_authentication_params() == expected_result


def test_convert_to_demisto_severity():
    from FireEyeETP import convert_to_demisto_severity
    from CommonServerPython import IncidentSeverity

    assert convert_to_demisto_severity("crit") == IncidentSeverity.CRITICAL
    assert convert_to_demisto_severity("majr") == IncidentSeverity.HIGH
    assert convert_to_demisto_severity("minr") == IncidentSeverity.LOW
    assert convert_to_demisto_severity("unkn") == IncidentSeverity.UNKNOWN


def test_get_search_alert_summary_v2():
    from FireEyeETP import get_search_alert_summary_v2

    alert = {
        "id": "1",
        "sha256": "s",
        "md5": "m",
        "domain": "d",
        "original": "o",
        "report_id": "r",
        "alert_date": "date",
        "malware": [{"name": "mn", "stype": "ms"}, {"name": "mn2", "stype": "ms2"}],
        "email_status": "es",
    }
    res = get_search_alert_summary_v2(alert)
    assert res["Alert ID"] == "1"
    assert res["Malware name"] == ["mn", "mn2"]
    assert res["Malware stype"] == ["ms", "ms2"]


def test_get_single_alert_summary_v2():
    from FireEyeETP import get_single_alert_summary_v2

    alert = {
        "id": "1",
        "domain": "d",
        "msg": "m",
        "traffic_type": "t",
        "verdict": "v",
        "report_id": "r",
        "alert_date": "ad",
        "product": "p",
        "alert": {"occurred": "o", "name": "n", "attack-time": "at", "severity": "s"},
    }
    res = get_single_alert_summary_v2(alert)
    assert res["Alert ID"] == "1"
    assert res["Severity"] == "s"


def test_get_alert_list_with_alert_id(mocker):
    """
    Given:
        - An alert_id argument is provided
    When:
        - Running get_alert_list function
    Then:
        - Ensure get_single_alert_entry is called
        - Ensure the correct CommandResults is returned
    """
    from FireEyeETP import get_alert_list, Client

    mock_client = MagicMock(spec=Client)

    alert_data = {
        "id": "alert123",
        "domain": "example.com",
        "msg": "test message",
        "traffic_type": "email",
        "verdict": "malicious",
        "report_id": "report1",
        "alert_date": "2023-01-01",
        "product": "ETP",
        "alert": {
            "occurred": "2023-01-01T10:00:00Z",
            "name": "Test Alert",
            "attack-time": "2023-01-01T09:00:00Z",
            "severity": "majr",
        },
    }

    mocker.patch("FireEyeETP.demisto.args", return_value={"alert_id": "alert123"})
    mock_client.get_alert_request_v2.return_value = alert_data

    result = get_alert_list(mock_client)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "FireEyeETP.Alerts"
    assert result.outputs_key_field == "id"
    assert result.outputs == alert_data


def test_get_alert_list_without_alert_id(mocker):
    """
    Given:
        - No alert_id argument is provided (search parameters instead)
    When:
        - Running get_alert_list function
    Then:
        - Ensure get_alerts_entry is called
        - Ensure the correct CommandResults is returned with multiple alerts
    """
    from FireEyeETP import Client, get_alert_list

    mock_client = MagicMock(spec=Client)

    search_response = {
        "data": [
            {
                "id": "alert1",
                "sha256": "sha1",
                "md5": "md5_1",
                "domain": "example1.com",
                "original": "orig1",
                "report_id": "r1",
                "alert_date": "2023-01-01",
                "malware": [{"name": "malware1", "stype": "type1"}],
                "email_status": "delivered",
            },
            {
                "id": "alert2",
                "sha256": "sha2",
                "md5": "md5_2",
                "domain": "example2.com",
                "original": "orig2",
                "report_id": "r2",
                "alert_date": "2023-01-02",
                "malware": [{"name": "malware2", "stype": "type2"}],
                "email_status": "quarantined",
            },
        ]
    }

    mocker.patch("FireEyeETP.demisto.args", return_value={"limit": "10", "domain": "example.com"})
    mock_client.get_alerts_request_v2.return_value = search_response

    result = get_alert_list(mock_client)

    assert isinstance(result, CommandResults)
    assert result.outputs_prefix == "FireEyeETP.Alerts"
    assert result.outputs_key_field == "id"
    assert len(result.outputs) == 2
    assert result.outputs[0]["id"] == "alert1"
    assert result.outputs[1]["id"] == "alert2"
