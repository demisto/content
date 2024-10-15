from FireEyeETP import Client
import json
from unittest.mock import MagicMock, mock_open, patch

import pytest
from CommonServerPython import CommandResults, EntryType, tableToMarkdown
import demistomock as demisto
import FireEyeETP


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
        malware_readable_data({'name': 'some-name'})
    except KeyError:
        raise AssertionError('malware_readable_data method should not fail on dict with name key only')


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
    base_url = 'https://server_url/api/v1'
    mocker.patch('FireEyeETP.BASE_PATH', base_url)
    mocker.patch.object(demisto, 'args', return_value={'alert_id': 'KgBdei7RQS4u4m8Jl7mG'})
    mocker.patch.object(demisto, 'results')
    requests_mock.get(
        base_url + '/alerts/KgBdei7RQS4u4m8Jl7mG?',
        json={
            'meta': {
                'total': 1
            },
            'data': [
                {
                    'alert': {
                        'explanation': {
                            'malware_detected': {
                                'malware': {}
                            }
                        }
                    },
                    'email': {
                        'headers': {
                            'to': '\u200b'
                        },
                        'timestamp': {}
                    }
                }
            ]
        }
    )
    FireEyeETP.get_alert_command()
    results = demisto.results.call_args[0][0]
    assert results


def test_fetch_incident_by_status_messages(mocker):
    """
    Given:
        - A status message similar to the alert's status
    When:
        - Running fetch-incidents command
    Then:
        - Ensure one incident was fetched as expected
    """
    alerts = {'meta': {'fromLastModifiedOn': {'end': ''}},
              'data': [
        {'attributes': {'email': {'status': 'delivered (retroactive)', 'headers': {'subject': ''}},
                        'alert': {'timestamp': '2023-02-09T19:34:17'}}}]}
    expected_incidents = {'email': {'status': 'delivered (retroactive)', 'headers': {'subject': ''}},
                          'alert': {'timestamp': '2023-02-09T19:34:17'}}
    last_run = {'last_modified': '2023-02-08T19:34:17', 'last_created': '2023-02-08T19:34:17'}
    mocker.patch.object(FireEyeETP, 'MESSAGE_STATUS', ['delivered (retroactive)'])
    mocker.patch('FireEyeETP.demisto.getLastRun', return_value=last_run)
    mocker.patch('FireEyeETP.get_alerts_request', return_value=alerts)
    res = mocker.patch('FireEyeETP.demisto.incidents')
    FireEyeETP.fetch_incidents()
    assert res.call_args.args[0][0].get('rawJSON') == json.dumps(expected_incidents)


def test_fetch_incident_by_status_messages_mismatch_status(mocker):
    """
    Given:
        - A status message differs from to the alert's status
    When:
        - Running fetch-incidents command
    Then:
        - Ensure no incidents were fetched as expected
    """
    alerts = {'meta': {'fromLastModifiedOn': {'end': ''}},
              'data': [
        {'attributes': {'email': {'status': 'deleted', 'headers': {'subject': ''}},
                        'alert': {'timestamp': '2023-02-09T19:34:17'}}}]}
    last_run = {'last_modified': '2023-02-08T19:34:17', 'last_created': '2023-02-08T19:34:17'}
    mocker.patch.object(FireEyeETP, 'MESSAGE_STATUS', ['delivered (retroactive)'])
    mocker.patch('FireEyeETP.demisto.getLastRun', return_value=last_run)
    mocker.patch('FireEyeETP.get_alerts_request', return_value=alerts)
    res = mocker.patch('FireEyeETP.demisto.incidents')
    FireEyeETP.fetch_incidents()
    assert len(res.call_args.args[0]) == 0


def test_fetch_incident_by_status_messages_with_two_status(mocker):
    """
    Given:
        - A list of status message similar to the alert's status
    When:
        - Running fetch-incidents command
    Then:
        - Ensure 2 incidents were fetched as expected
    """
    alerts = {'meta': {'fromLastModifiedOn': {'end': ''}},
              'data': [
        {'attributes': {'email': {'status': 'delivered (retroactive)', 'headers': {'subject': ''}},
                        'alert': {'timestamp': '2023-02-09T19:34:17'}}},
        {'attributes': {'email': {'status': 'deleted', 'headers': {'subject': ''}},
                        'alert': {'timestamp': '2023-02-09T19:34:17'}}}
    ]}
    expected_incidents = [
        {"email": {"status": "delivered (retroactive)", "headers": {"subject": ""}},
         "alert": {"timestamp": '2023-02-09T19:34:17'}},
        {"email": {"status": "deleted", "headers": {"subject": ""}}, "alert": {"timestamp": '2023-02-09T19:34:17'}}]
    last_run = {'last_modified': '2023-02-08T19:34:17', 'last_created': '2023-02-08T19:34:17'}
    mocker.patch.object(FireEyeETP, 'MESSAGE_STATUS', ['delivered (retroactive)', 'deleted'])
    mocker.patch('FireEyeETP.demisto.getLastRun', return_value=last_run)
    mocker.patch('FireEyeETP.get_alerts_request', return_value=alerts)
    res = mocker.patch('FireEyeETP.demisto.incidents')
    FireEyeETP.fetch_incidents()
    for incident, expected_incident in zip(res.call_args.args[0], expected_incidents):
        assert incident.get('rawJSON') == json.dumps(expected_incident)


@pytest.fixture
def FireEyeETP_client():
    return Client(base_url='https://fireeyeetp',
                  verify=False,
                  headers={},
                  proxy=False)


@patch('FireEyeETP.fileResult')
def test_download_alert_artifacts_command(mock_file_result):
    """
    Given:
        - ID of alert to get
    When:
        - Running download-alert-artifact command
    Then:
        - Ensure 1 zip file fetched as expected
    """
    from FireEyeETP import download_alert_artifacts_command, Client
    args = {'alert_id': '12345'}
    mock_client = MagicMock(spec=Client)
    mock_response = MagicMock()
    mock_response.content = b'fake_zip_content'
    mock_client.get_artifacts.return_value = mock_response
    mock_file_result.return_value = {'File': '12345.zip', 'Type': EntryType.FILE, 'Contents': 'fake_zip_content'}
    results = download_alert_artifacts_command(mock_client, args)
    mock_client.get_artifacts.assert_called_once_with('12345')
    mock_file_result.assert_called_once_with('12345.zip', data=b'fake_zip_content', file_type=EntryType.FILE)
    assert isinstance(results[0], CommandResults)
    assert results[0].readable_output == 'Download alert artifact completed successfully'
    assert results[1] == {'File': '12345.zip', 'Type': EntryType.FILE, 'Contents': 'fake_zip_content'}


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
    from FireEyeETP import list_yara_rulesets_command, Client
    args = {'policy_uuid': 'abc-123-uuid'}
    mock_client = MagicMock(spec=Client)
    mock_response = {
        'data': {
            'rulesets': [
                {
                    'name': 'Test Ruleset',
                    'description': 'Test Description',
                    'uuid': 'uuid-123',
                    'yara_file_name': 'test.yara'
                }
            ]
        }
    }
    mock_client.get_yara_rulesets.return_value = mock_response
    result = list_yara_rulesets_command(mock_client, args)
    mock_client.get_yara_rulesets.assert_called_once_with('abc-123-uuid')
    assert isinstance(result, CommandResults)
    assert result.outputs == [{'name': 'Test Ruleset',
                               'description': 'Test Description',
                               'uuid': 'uuid-123',
                               'yara_file_name': 'test.yara'}]
    assert result.outputs_prefix == 'FireEyeETP.Policy.abc-123-uuid'
    assert result.readable_output == ('### Rulesets\n|name|description|uuid|yara_file_name|\n|---|---|---|---|\n| Test Ruleset'
                                      ' | Test Description | uuid-123 | test.yara |\n')


@patch('FireEyeETP.fileResult')
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
    from FireEyeETP import download_yara_file_command, Client
    args = {'policy_uuid': 'policy-12345', 'ruleset_uuid': 'ruleset-67890'}
    mock_client = MagicMock(spec=Client)
    mock_response = MagicMock()
    mock_response.content = b'fake_yara_file_content'
    mock_file_result.return_value = {'File': 'original.yara', 'Type': EntryType.FILE, 'Contents': 'fake_yara_file_content'}
    mock_client.get_yara_file.return_value = mock_response
    results = download_yara_file_command(mock_client, args)
    mock_file_result.assert_called_once_with('original.yara', data=b'fake_yara_file_content', file_type=EntryType.FILE)
    assert isinstance(results[0], CommandResults)
    assert results[0].readable_output == 'Download yara file completed successfully.'
    assert results[1] == {'File': 'original.yara', 'Type': EntryType.FILE, 'Contents': 'fake_yara_file_content'}


@patch('FireEyeETP.demisto.getFilePath')
@patch('FireEyeETP.open', new_callable=mock_open, read_data=b'fake_yara_file_content')
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
    from FireEyeETP import upload_yara_file_command, Client
    args = {'entryID': '1', 'policy_uuid': 'policy-12345', 'ruleset_uuid': 'ruleset-67890'}
    mock_getFilePath.return_value = {'path': '/path/to/file'}
    mock_response = MagicMock()
    mock_response.status_code = 202
    mock_client = MagicMock(spec=Client)
    mock_client.upload_yara_file.return_value = mock_response
    results = upload_yara_file_command(mock_client, args)
    mock_getFilePath.assert_called_once_with('1')
    mock_open_file.assert_called_once_with('/path/to/file', 'rb')
    assert isinstance(results, CommandResults)
    assert results.readable_output == 'Upload of Yara file succesfully.'


@patch('FireEyeETP.demisto.getFilePath')
@patch('FireEyeETP.open', new_callable=mock_open, read_data=b'fake_yara_file_content')
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
    from FireEyeETP import upload_yara_file_command, Client
    args = {'entryID': '1', 'policy_uuid': 'policy-12345', 'ruleset_uuid': 'ruleset-67890'}
    mock_getFilePath.return_value = {'path': '/path/to/file'}
    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_client = MagicMock(spec=Client)
    mock_client.upload_yara_file.return_value = mock_response
    results = upload_yara_file_command(mock_client, args)
    mock_getFilePath.assert_called_once_with('1')
    mock_open_file.assert_called_once_with('/path/to/file', 'rb')
    assert isinstance(results, CommandResults)
    assert results.readable_output == 'Upload of Yara file failed.'


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
    from FireEyeETP import get_events_data_command, Client
    args = {'message_id': '12345'}
    mock_response = {
        'data': {
            '12345': [
                {
                    'action_on_msg': 'MTA_RCPT_DELIVERED_OUTBOUND',
                    'display_msg': 'Delivered <internetMessageId12345>'
                }
            ]
        }
    }
    mock_client = MagicMock(spec=Client)
    mock_client.get_events_data.return_value = mock_response
    result = get_events_data_command(mock_client, args)
    assert isinstance(result, CommandResults)
    expected_output = {
        'Logs': mock_response['data']['12345'],
        'Delivered_msg': 'Delivered <internetMessageId12345>',
        'Delivered_status': 'Delivered',
        'InternetMessageId': 'internetMessageId12345'
    }
    assert result.outputs == expected_output
    assert result.outputs_prefix == 'FireEyeETP.Events'
    expected_md = tableToMarkdown(
        "Events", expected_output,
        headers=["Logs", "Delivered_msg", "Delivered_status"],
        is_auto_json_transform=True
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
    from FireEyeETP import get_events_data_command, Client
    args = {'message_id': '12345'}
    mock_response = {
        'data': {
            '12345': [
                {
                    'action_on_msg': 'MTA_RCPT_DELIVERY_PERM_FAILURE_OUTBOUND',
                    'display_msg': 'Failed to deliver <internetMessageId67890>'
                }
            ]
        }
    }
    mock_client = MagicMock(spec=Client)
    mock_client.get_events_data.return_value = mock_response
    result = get_events_data_command(mock_client, args)
    assert isinstance(result, CommandResults)
    expected_output = {
        'Logs': mock_response['data']['12345'],
        'Delivered_msg': 'Failed to deliver <internetMessageId67890>',
        'Delivered_status': 'Failed'
    }
    assert result.outputs == expected_output
    assert result.outputs_prefix == 'FireEyeETP.Events'
    expected_md = tableToMarkdown(
        "Events", expected_output,
        headers=["Logs", "Delivered_msg", "Delivered_status"],
        is_auto_json_transform=True
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
    from FireEyeETP import quarantine_release_command, Client

    response_data = {
        'data': {
            "type": "some_type",
            "operation": "some_operation",
            "successful_message_ids": "1,2,3"
        }
    }

    mock_response = MockResponse(response_data)
    args = {'message_id': '12345'}
    mock_client = MagicMock(spec=Client)
    mock_client.quarantine_release.return_value = mock_response
    result = quarantine_release_command(mock_client, args)
    assert isinstance(result, CommandResults)
    assert result.readable_output == ('### Quarantine\n|type|operation|successful_message_ids|\n|---|---|---|\n| some_type '
                                      '| some_operation | 1,2,3 |\n')
    mock_client.quarantine_release.assert_called_once_with('12345')
