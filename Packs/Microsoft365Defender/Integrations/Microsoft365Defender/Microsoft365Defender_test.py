"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
from datetime import datetime, timedelta, UTC
from unittest.mock import patch

import pytest

import demistomock as demisto
from CommonServerPython import EntryType
from Microsoft365Defender import Client, fetch_incidents, _query_set_limit, main, fetch_modified_incident_ids, \
    get_modified_remote_data_command, get_modified_incidents_close_or_repopen_entries

MOCK_MAX_ENTRIES = 2
COMMENT_TAG_FROM_MS = "CommentFromMicrosoft365Defender"


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_convert_incident():
    from Microsoft365Defender import convert_incident_to_readable
    empty_incident = util_load_json("./test_data/empty_incident.json")
    assert convert_incident_to_readable(None) == empty_incident
    raw_incident = util_load_json("./test_data/raw_incident.json")
    converted_incident = util_load_json("./test_data/converted_incident.json")
    assert convert_incident_to_readable(raw_incident) == converted_incident


def mock_client(mocker, function: str = None, http_response=None):
    mocker.patch.object(demisto, 'getIntegrationContext',
                        return_value={'current_refresh_token': 'refresh_token', 'access_token': 'access_token'})
    client = Client(
        app_id='app_id',
        verify=False,
        proxy=False,
        base_url='https://api.security.microsoft.com'
    )
    if http_response:
        mocker.patch.object(client, function, return_value=http_response)
    return client


def check_api_response(results, results_mock):
    assert results.outputs_prefix == results_mock['outputs_prefix']
    assert results.outputs_key_field == results_mock['outputs_key_field']
    assert results.readable_output == results_mock['readable_output']
    assert results.outputs == results_mock['outputs']


def test_microsoft_365_defender_incidents_list_command(mocker):
    from Microsoft365Defender import microsoft_365_defender_incidents_list_command
    client = mock_client(mocker, 'incidents_list', util_load_json('./test_data/incidents_list_response.json'))
    results = microsoft_365_defender_incidents_list_command(client, {'limit': 10})
    check_api_response(results, util_load_json('./test_data/incidents_list_results.json'))


def test_microsoft_365_defender_incident_update_command(mocker):
    from Microsoft365Defender import microsoft_365_defender_incident_update_command
    client = mock_client(mocker, 'update_incident', util_load_json('./test_data/incident_update_response.json'))
    args = {'id': '263', 'tags': 'test1,test2', 'status': 'Active', 'classification': 'Unknown',
            'determination': 'NotAvailable', 'assigned_to': ""}
    results = microsoft_365_defender_incident_update_command(client, args)
    check_api_response(results, util_load_json('./test_data/incident_update_results.json'))


def test_microsoft_365_defender_incident_get_command(mocker):
    from Microsoft365Defender import microsoft_365_defender_incident_get_command
    client = mock_client(mocker, 'get_incident', util_load_json('./test_data/incident_get_response.json'))
    args = {'id': '263'}
    results = microsoft_365_defender_incident_get_command(client, args)
    check_api_response(results, util_load_json('./test_data/incident_get_results.json'))


def test_microsoft_365_defender_advanced_hunting_command(mocker):
    from Microsoft365Defender import microsoft_365_defender_advanced_hunting_command
    client = mock_client(mocker, 'advanced_hunting', util_load_json('./test_data/advanced_hunting_response.json'))
    args = {'query': 'AlertInfo'}
    results = microsoft_365_defender_advanced_hunting_command(client, args)
    check_api_response(results, util_load_json('./test_data/advanced_hunting_results.json'))


def fetch_check(mocker, client, last_run, first_fetch_time, fetch_limit, mock_results):
    mocker.patch.object(demisto, 'getLastRun', return_value=last_run)
    mirroring_fields = {"mirror_direction": "Incoming", "mirror_instance": "1234"}
    results = fetch_incidents(client, mirroring_fields, first_fetch_time, fetch_limit)
    assert len(results) == len(mock_results)
    for incident, mock_incident in zip(results, mock_results):
        assert incident['name'] == mock_incident['name']
        assert incident['occurred'] == mock_incident['occurred']
        assert json.loads(incident['rawJSON']) == json.loads(mock_incident['rawJSON'])


def test_fetch_incidents(mocker):
    """
    This test check for 4 fetch cycles.
        First - get all the incidents and fill the queue 127, returns 50
        Second - get 50 incidents from the queue
        Third - tries to fill the queue with new incidents but there are no new ones so returns all the remaining
                incidents in the queue
        Forth - tries to fill the queue with new incidents but there are no new ones so returns empty list
    """
    response_dict = util_load_json('./test_data/fetch_response.json')
    client = Client(
        app_id='app_id',
        verify=False,
        proxy=False,
        base_url='https://api.security.microsoft.com'
    )
    mocker.patch.object(demisto, 'getIntegrationContext',
                        return_value={'current_refresh_token': 'refresh_token', 'access_token': 'access_token'})
    response_list = response_dict['response_list']
    mocker.patch.object(client, 'incidents_list', side_effect=response_list)

    first_fetch_time = "3000 days"
    fetch_limit = 50
    results = util_load_json('./test_data/fetch_results.json')

    for current_flow in ['first', 'second', 'third', 'forth']:
        fetch_check(mocker, client, response_dict[f'{current_flow}_last_run'], first_fetch_time, fetch_limit,
                    results[f'{current_flow}_result'])


@pytest.mark.parametrize('query, limit, result', [("a | b | limit 5", 10, "a | b | limit 10 "),
                                                  ("a | b ", 10, "a | b | limit 10 "),
                                                  ("a | b | limit 1 | take 1", 10, "a | b | limit 10 | limit 10 "),
                                                  ("a | where Subject == \"a || b\" | limit  ", 10,
                                                   "a | where Subject == \"a || b\" | limit 10 ")
                                                  ])
def test_query_set_limit(query: str, limit: int, result: str):
    assert _query_set_limit(query, limit) == result


def test_params(mocker):
    """
    Given:
      - Configuration parameters
    When:
      - The required parameter app_id is missed.
    Then:
      - Ensure the exception message as expected.
    """

    mocker.patch.object(demisto, 'params', return_value={'_tenant_id': '_tenant_id', 'credentials': {'password': '1234'}})
    mocker.patch.object(demisto, 'error')
    return_error_mock = mocker.patch('Microsoft365Defender.return_error')

    main()

    assert 'Application ID must be provided.' in return_error_mock.call_args[0][0]


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """

    from Microsoft365Defender import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import Microsoft365Defender

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)

    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True',
        'base_url': 'test_base_url'
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(Microsoft365Defender, 'return_results', return_value=params)
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in Microsoft365Defender.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.security]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


class MockMicrosoft365DefenderClient(Client):
    def __init__(self, mocker, response_data: dict,
                 app_id='app_id',
                 verify=False,
                 proxy=False):
        super().__init__(app_id, verify, proxy)
        self.response_data = response_data

    def incidents_list(self, *args, **kwargs) -> dict:
        skip = kwargs.get("skip", 0)
        batch = self.response_data["value"][skip:skip + MOCK_MAX_ENTRIES]
        return {
            "@odata.context": self.response_data["@odata.context"],
            "value": batch
        }


# Test case
@patch("Microsoft365Defender.MAX_ENTRIES", MOCK_MAX_ENTRIES)
def test_fetch_modified_incident_ids(mocker):
    mock_responses = [util_load_json("./test_data/incidents_list_response.json"),
                      util_load_json("./test_data/incidents_empty_list_response.json")]
    for mock_response in mock_responses:
        client = MockMicrosoft365DefenderClient(mocker, mock_response)
        result = fetch_modified_incident_ids(client, last_update_time="2021-03-01T00:00:00Z")
        expected_incidents = [str(incident["incidentId"]) for incident in mock_response["value"]]
        assert result == expected_incidents


def test_get_modified_remote_data_command(mocker):
    import Microsoft365Defender
    mock_args = {"lastUpdate": "2023-01-01T12:00:00Z"}
    mocker.patch.object(Microsoft365Defender, 'fetch_modified_incident_ids', return_value=["123", "456"])
    response = get_modified_remote_data_command(mock_client(mocker), mock_args)
    assert response.modified_incident_ids == ["123", "456"]


def test_get_modified_remote_data_command_invalid_last_update(mocker):
    import Microsoft365Defender
    mock_args = {"lastUpdate": "invalid_date_string"}
    mocker.patch.object(Microsoft365Defender, 'fetch_modified_incident_ids', return_value=[])

    with pytest.raises(AssertionError, match="could not parse invalid_date_string"):
        get_modified_remote_data_command(mock_client(mocker), mock_args)


@pytest.fixture
def resolved_incidents():
    """Fixture for resolved incidents."""
    return [
        {'incidentId': '1234', 'status': 'Resolved', 'classification': 'TruePositive'},
        {'incidentId': '5678', 'status': 'Resolved', 'classification': 'Unknown'},
        {'incidentId': '9012', 'status': 'Resolved', 'classification': 'FalsePositive'},
        {'incidentId': '3456', 'status': 'Resolved', 'classification': 'InformationalExpectedActivity'}
    ]


@pytest.fixture
def unresolved_incidents():
    """Fixture for unresolved incidents."""
    return [
        {'incidentId': '1234', 'status': 'Active'},
        {'incidentId': '5678', 'status': 'InProgress'}
    ]


def test_get_modified_incidents_close_entries(mocker, resolved_incidents):
    """
    Test when close_incident is True and incidents are Resolved.
    """
    result = get_modified_incidents_close_or_repopen_entries(resolved_incidents, close_incident=True)

    assert len(result) == 4
    assert result[0]['Type'] == EntryType.NOTE
    assert result[0]['Contents'] == {
        'dbotIncidentClose': True,
        'closeReason': 'Resolved',
    }
    assert result[1]['Contents'] == {
        'dbotIncidentClose': True,
        'closeReason': 'Other',
    }
    assert result[2]['Contents'] == {
        'dbotIncidentClose': True,
        'closeReason': 'False Positive',
    }
    assert result[3]['Contents'] == {
        'dbotIncidentClose': True,
        'closeReason': 'Resolved',
    }


def test_get_modified_incidents_reopen_entries(mocker, unresolved_incidents):
    """
    Test when close_incident is True and incidents are not Resolved.
    """
    result = get_modified_incidents_close_or_repopen_entries(unresolved_incidents, close_incident=True)
    assert len(result) == 2
    assert result[0] == {'dbotIncidentReopen': True}
    assert result[1] == {'dbotIncidentReopen': True}


def test_get_modified_incidents_close_incident_false(mocker, resolved_incidents):
    """
    Test when close_incident is False.
    """
    result = get_modified_incidents_close_or_repopen_entries(resolved_incidents, close_incident=False)
    assert result == []


def test_get_modified_incidents_empty_list(mocker):
    """
    Test when modified_incidents is an empty list.
    """
    result = get_modified_incidents_close_or_repopen_entries([], close_incident=True)
    assert result == []


def test_get_entries_for_comments_new_incident():
    from Microsoft365Defender import get_entries_for_comments

    comments = [
        {"comment": "Test comment 1", "createdBy": "User1@gmail.com", "createdTime": "2024-01-01T10:00:00.8404534Z"},
        {"comment": "Test comment 2", "createdBy": "User2@gmail.com", "createdTime": "2024-01-02T12:00:00.8404534Z"}
    ]
    last_update = datetime.utcnow() - timedelta(days=1)
    result = get_entries_for_comments(comments, last_update, COMMENT_TAG_FROM_MS, True)

    assert len(result) == 2
    assert result[0]["Contents"].startswith("Created By: User1@gmail.com")
    assert result[0]["Tags"] == [COMMENT_TAG_FROM_MS]
    assert result[0]["Note"] is True


def test_get_entries_for_comments_filter_by_last_update():
    from Microsoft365Defender import get_entries_for_comments

    comments = [
        {"comment": "Old comment", "createdBy": "User1@gmail.com", "createdTime": "2024-01-01T10:00:00.8404534Z"},
        {"comment": "New comment", "createdBy": "User2@gmail.com", "createdTime": "2024-01-03T12:00:00.8404534Z"}
    ]
    last_update = datetime(2024, 1, 2, 0, 0, 0, tzinfo=UTC)
    result = get_entries_for_comments(comments, last_update, COMMENT_TAG_FROM_MS, False)

    assert len(result) == 1
    assert result[0]["Contents"].startswith("Created By: User2@gmail.com")
    assert result[0]["Tags"] == [COMMENT_TAG_FROM_MS]


def test_get_entries_for_comments_ignores_mirrored_comments():
    from Microsoft365Defender import get_entries_for_comments, MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR

    comments = [
        {"comment": f"Ignored comment {MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR}",
         "createdBy": "User1@gmail.com", "createdTime": "2024-01-03T12:00:00.8404534Z"}
    ]

    last_update = last_update = datetime(2024, 1, 2, 0, 0, 0, tzinfo=UTC)
    result = get_entries_for_comments(comments, last_update, COMMENT_TAG_FROM_MS, False)

    assert len(result) == 0


def test_get_entries_for_comments_empty_comments():
    from Microsoft365Defender import get_entries_for_comments

    comments = []
    last_update = datetime.utcnow() - timedelta(days=1)
    result = get_entries_for_comments(comments, last_update, COMMENT_TAG_FROM_MS, False)

    assert len(result) == 0
