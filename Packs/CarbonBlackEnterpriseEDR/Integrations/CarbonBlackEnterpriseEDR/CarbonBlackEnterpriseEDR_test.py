import pytest
import CarbonBlackEnterpriseEDR as cbe
import demistomock as demisto
from freezegun import freeze_time
from CommonServerPython import CommandResults

PROCESS_CASES = [
    (
        {'process_hash': '63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6',
         'process_name': None, 'event_id': None, 'query': None, 'limit': 20, 'start_time': '1 day'},  # args
        {'criteria': {'process_hash': ['63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6']}, 'rows': 20,
         'start': 0, 'time_range': {'end': '2020-11-04T13:34:14.758295Z', 'start': '2020-11-03T13:34:14.758295Z'}}
        # expected
    ),
    (
        {"process_name": "svchost.exe,vmtoolsd.exe", 'event_id': None, 'query': None, 'limit': 20,
         'start_time': '1 day',
         'process_hash': '63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6'},  # args
        {'criteria': {'process_hash': ['63d423ea882264dbb157a965c200306212fc5e1c6ddb8cbbb0f1d3b51ecd82e6'],
                      "process_name": ["svchost.exe", "vmtoolsd.exe"]}, 'rows': 20, 'start': 0,
         'time_range': {'end': '2020-11-04T13:34:14.758295Z', 'start': '2020-11-03T13:34:14.758295Z'}}  # expected
    )
]


@freeze_time("2020-11-04T13:34:14.758295Z")
@pytest.mark.parametrize('demisto_args,expected_results', PROCESS_CASES)
def test_create_process_search_body(mocker, demisto_args, expected_results):
    """
    Given:
        - search task's argument

    When:
        - creating a search process task

    Then:
        - validating the body sent to request is matching the search

    """

    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    client = cbe.Client(
        base_url='https://server_url.com',
        use_ssl=False,
        use_proxy=False,
        token=None,
        cb_org_key="123")
    m = mocker.patch.object(client, '_http_request', return_value={})

    client.create_search_process_request(**demisto_args)
    assert m.call_args[1].get('json_data') == expected_results


PROCESS_BAD_CASES = [
    (
        {'process_hash': None, 'process_name': None, 'event_id': None, 'query': None, 'limit': 20},
        # args for missing parameters
        "To perform an process search, please provide at least one of the following: "
        "'process_hash', 'process_name', 'event_id' or 'query'"  # expected
    ),

]


@pytest.mark.parametrize('demisto_args,expected_error_msg', PROCESS_BAD_CASES)
def test_create_process_search_failing(mocker, requests_mock, demisto_args, expected_error_msg):
    """
    Given:
      - search task's argument

    When:
     - creating a search event by process task

    Then:
       - validating the body sent to request is matching the search
    """

    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    client = cbe.Client(
        base_url='https://server_url.com',
        use_ssl=False,
        use_proxy=False,
        token=None,
        cb_org_key="123")
    mocker.patch.object(client, '_http_request', return_value={})

    with pytest.raises(Exception) as e:
        client.create_search_process_request(**demisto_args)
    assert str(e.value) == expected_error_msg


EVENT_CASES = [
    (
        {"process_guid": "1234", 'event_type': 'modload', 'query': None, 'limit': 20, 'start_time': '1 day'},  # args
        {'criteria': {'event_type': ['modload']}, 'rows': 20, 'start': 0,
         'time_range': {'end': '2020-11-04T13:34:14.758295Z', 'start': '2020-11-03T13:34:14.758295Z'}}  # expected
    ),
    (
        {"process_guid": "1234", 'event_type': 'modload', 'query': None, 'limit': 20, 'start': 20,
         'start_time': '1 day'},  # args
        {'criteria': {'event_type': ['modload']}, 'rows': 20, 'start': 20,
         'time_range': {'end': '2020-11-04T13:34:14.758295Z', 'start': '2020-11-03T13:34:14.758295Z'}}  # expected
    )
]


@freeze_time("2020-11-04T13:34:14.758295Z")
@pytest.mark.parametrize('demisto_args,expected_results', EVENT_CASES)
def test_create_event_by_process_search_body(mocker, demisto_args, expected_results):
    """
    Given:
        - search task's argument

    When:
        - creating a search event by process task

    Then:
        - validating the body sent to request is matching the search

    """

    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    client = cbe.Client(
        base_url='https://server_url.com',
        use_ssl=False,
        use_proxy=False,
        token=None,
        cb_org_key="123")
    m = mocker.patch.object(client, '_http_request', return_value={})

    client.create_search_event_by_process_request(**demisto_args)
    assert m.call_args[1].get('json_data') == expected_results


EVENT_BAD_CASES = [
    (
        {"process_guid": "1234", 'event_type': 'invalid', 'query': None, 'limit': 20, 'start_time': '1 day'},
        # args for invalid parameters
        "Only the following event types can be searched: "
        "'filemod', 'netconn', 'regmod', 'modload', 'crossproc', 'childproc'"  # expected
    ),
    (
        {"process_guid": "1234", 'event_type': None, 'query': None, 'limit': 20, 'start_time': '1 day'},
        # args for missing parameters
        "To perform an event search, please provide either event_type or query."  # expected
    )
]


@pytest.mark.parametrize('demisto_args,expected_error_msg', EVENT_BAD_CASES)
def test_event_by_process_failing(mocker, requests_mock, demisto_args, expected_error_msg):
    """
    Given:
      - search task's argument

    When:
     - creating a search event by process task

    Then:
       - validating the body sent to request is matching the search
    """

    mocker.patch.object(demisto, 'args', return_value=demisto_args)
    client = cbe.Client(
        base_url='https://server_url.com',
        use_ssl=False,
        use_proxy=False,
        token=None,
        cb_org_key="123")
    mocker.patch.object(client, '_http_request', return_value={})

    with pytest.raises(Exception) as e:
        client.create_search_event_by_process_request(**demisto_args)
    assert str(e.value) == expected_error_msg


@pytest.fixture(autouse=True)
def mock_demisto(mocker):
    mocker.patch('CarbonBlackEnterpriseEDR.demisto', autospec=True)


MOCK_UPDATE_THREAT_TAGS_RESPONSE = {
    'tags': ['tag1', 'tag2']
}


def demisto_commands(command_func):
    @pytest.fixture
    def wrapped(mocker):
        from CarbonBlackEnterpriseEDR import demisto
        mocker.patch.object(demisto, 'Command', autospec=True)
        mocker.patch.object(demisto, 'args', return_value={})
        mocker.patch.object(demisto, 'executeCommand', return_value=[{'Contents': MOCK_UPDATE_THREAT_TAGS_RESPONSE}])
        mocker.patch.object(demisto.Command, 'results', return_value=CommandResults())

        mocker.patch('CarbonBlackEnterpriseEDR.demisto', autospec=True)

        demisto.Command.func = command_func

        return demisto.Command

    return wrapped


@demisto_commands
def test_add_threat_tags_command(mocker, demisto_command):
    mocker.patch.object(demisto_command.client, 'update_threat_tags', return_value=MOCK_UPDATE_THREAT_TAGS_RESPONSE)

    demisto_command.set_args({'threat_id': '123456', 'tags': 'tag1,tag2'})

    result = demisto_command.execute()

    assert result.outputs == {'ThreatID': '123456', 'Tags': ['tag1', 'tag2']}
    assert result.outputs_prefix == 'CarbonBlackEEDR.Threat'
    assert result.outputs_key_field == 'tags'

    assert "Successfully updated threat: \"123456\"" in result.readable_output
    assert result.raw_response == MOCK_UPDATE_THREAT_TAGS_RESPONSE


MOCK_CREATE_THREAT_NOTES_RESPONSE = {
    'notes': 'These are threat notes'
}


@demisto_commands
def test_add_threat_notes_command(mocker, demisto_command):
    mocker.patch.object(demisto_command.client, 'create_threat_notes', return_value=MOCK_CREATE_THREAT_NOTES_RESPONSE)

    demisto_command.set_args({'threat_id': '123456', 'notes': 'These are threat notes'})

    result = demisto_command.execute()

    assert result.outputs == {'ThreatID': '123456', 'Notes': 'These are threat notes'}
    assert result.outputs_prefix == 'CarbonBlackEEDR.Threat'
    assert result.outputs_key_field == 'ThreatID'

    assert "Successfully added notes to threat: \"123456\"" in result.readable_output
    assert result.raw_response == MOCK_CREATE_THREAT_NOTES_RESPONSE


MOCK_UPDATE_ALERT_NOTES_RESPONSE = {
    'notes': 'These are alert notes'
}


@demisto_commands
def test_add_alert_notes_command(mocker, demisto_command):
    mocker.patch.object(demisto_command.client, 'update_alert_notes', return_value=MOCK_UPDATE_ALERT_NOTES_RESPONSE)

    demisto_command.set_args({'alert_id': '987654', 'notes': 'These are alert notes'})

    result = demisto_command.execute()

    assert result.outputs == {'AlertID': '987654', 'Notes': 'These are alert notes'}
    assert result.outputs_prefix == 'CarbonBlackEEDR.Threat'
    assert result.outputs_key_field == 'AlertID'

    assert "Successfully added notes to alert: \"987654\"" in result.readable_output
    assert result.raw_response == MOCK_UPDATE_ALERT_NOTES_RESPONSE


MOCK_GET_THREAT_TAGS_RESPONSE = {
    'list': [
        {'tag': 'malware'},
        {'tag': 'suspicious'}
    ]
}


@demisto_commands
def test_get_threat_tags_command(mocker, demisto_command):
    mocker.patch.object(demisto_command.client, 'get_threat_tags', return_value=MOCK_GET_THREAT_TAGS_RESPONSE)

    demisto_command.set_args({'threat_id': '123456'})

    result = demisto_command.execute()

    assert result.outputs == {'ThreatID': '123456', 'Tags': [{'tag': 'malware'}, {'tag': 'suspicious'}]}
    assert result.outputs_prefix == 'CarbonBlackEEDR.Threat'
    assert result.outputs_key_field == 'ThreatID'

    assert "Successfully sent for threat: \"123456\"" in result.readable_output
    assert result.raw_response == MOCK_GET_THREAT_TAGS_RESPONSE


def test_get_threat_tags(mocker):
    client = cbe.Client(
        base_url='https://server_url.com',
        use_ssl=False,
        use_proxy=False,
        token=None,
        cb_org_key="123")

    # Mock the _http_request method to return the mock response
    mocker.patch.object(client, '_http_request', return_value=MOCK_GET_THREAT_TAGS_RESPONSE)
    threat_id = '123456'
    result = client.get_threat_tags(threat_id)

    # Assert that _http_request was called with the correct parameters
    client._http_request.assert_called_with('GET', f'api/alerts/v7/orgs/{client.cb_org_key}/threats/{threat_id}/tags')

    # Assert the result
    assert result == MOCK_GET_THREAT_TAGS_RESPONSE
