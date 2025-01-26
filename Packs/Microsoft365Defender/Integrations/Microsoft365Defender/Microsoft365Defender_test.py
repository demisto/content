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
from CommonServerPython import EntryType, DemistoException, GetMappingFieldsResponse, SchemeTypeMapping, IncidentStatus
from Microsoft365Defender import Client, fetch_incidents, _query_set_limit, main, fetch_modified_incident_ids, \
    get_modified_remote_data_command, get_modified_incidents_close_or_repopen_entries, get_determination_value, \
    fetch_modified_incident, get_remote_data_command, \
    get_mapping_fields_command, handle_incident_close_out_or_reactivation, mirror_out_entries, update_remote_system_command

MOCK_MAX_ENTRIES = 2
COMMENT_TAG_FROM_MS = "CommentFromMicrosoft365Defender"
MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR = "Mirrored from Cortex XSOAR"
OUTGOING_MIRRORED_FIELDS = {
    'status': 'Specifies the current status of the incident.',
    'assignedTo': 'Owner of the incident.',
    'classification': 'Specification of the incident.',
    'determination': 'Specifies the determination of the incident.',
    'tags': 'List of Incident tags.',
    'comment': 'Comment to be added to the incident.'
}


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


def mock_get_modified_incidents_close_or_reopen_entries(mirrored_objects, close_incident):
    return [{"Type": 1, "Contents": "Mock close/reopen entry"}]


def mock_get_entries_for_comments(comments, last_update, comment_tag):
    return [{"Type": 1, "Contents": "Mock comment entry"}]


@pytest.fixture
def mock_dependencies(mocker):
    mocker.patch(
        "Microsoft365Defender.get_modified_incidents_close_or_repopen_entries",
        side_effect=mock_get_modified_incidents_close_or_reopen_entries,
    )
    mocker.patch(
        "Microsoft365Defender.get_entries_for_comments",
        side_effect=mock_get_entries_for_comments,
    )


def test_get_incident_entries(mock_dependencies):
    """
    Test that the function calls both helper functions and combines their outputs into a single list.
    """
    mirrored_object = {"id": "12345", "comments": [{"text": "Test comment", "timestamp": "2025-01-25T10:00:00Z"}]}
    last_update = datetime.strptime("2025-01-20T10:00:00Z", "%Y-%m-%dT%H:%M:%SZ")
    close_incident = True

    from Microsoft365Defender import get_incident_entries

    entries = get_incident_entries(mirrored_object, last_update, MIRRORED_OUT_XSOAR_ENTRY_TO_MICROSOFT_COMMENT_INDICATOR,
                                   close_incident)

    assert len(entries) == 2  # Should combine outputs from both mocked functions
    assert {"Type": 1, "Contents": "Mock close/reopen entry"} in entries
    assert {"Type": 1, "Contents": "Mock comment entry"} in entries


def test_get_determination_value():
    # Test: Valid classification, no determination provided
    assert get_determination_value('TruePositive', None) == 'Other'
    assert get_determination_value('Unknown', None) == 'NotAvailable'

    # Test: Valid classification and determination
    assert get_determination_value('TruePositive', 'Malware') == 'Malware'
    assert get_determination_value('InformationalExpectedActivity', 'ConfirmedActivity') == 'ConfirmedActivity'

    # Test: Invalid classification
    with pytest.raises(DemistoException, match="Please provide a valid classification"):
        get_determination_value('InvalidClassification', 'Malware')

    # Test: Valid classification but invalid determination
    with pytest.raises(DemistoException, match="Invalid determination. Please provide one of the following:"):
        get_determination_value('TruePositive', 'InvalidDetermination')

    # Test: Valid classification with "Other" determination
    assert get_determination_value('TruePositive', 'Other') == 'Other'
    assert get_determination_value('InformationalExpectedActivity', 'Other') == 'Other'

    # Test: Edge case with valid classification and determination not matching any key
    with pytest.raises(DemistoException, match="Invalid determination. Please provide one of the following:"):
        get_determination_value('FalsePositive', 'Phishing')


def test_get_meta_data_for_incident():
    """
    Tests the `_get_meta_data_for_incident` function using the provided raw_incident.json data.
    """
    from Microsoft365Defender import _get_meta_data_for_incident

    raw_incident = util_load_json("./test_data/raw_incident.json")
    metadata = _get_meta_data_for_incident(raw_incident)

    assert metadata["Categories"] == ["SuspiciousActivity"]
    assert metadata["Impacted entities"] == []
    assert metadata["Active alerts"] == "0 / 0"
    assert metadata["Service sources"] == ["MicrosoftDefenderForEndpoint"]
    assert metadata["Detection sources"] == ["AutomatedInvestigation"]
    assert metadata["First activity"] == "2021-03-22 12:34:31+00:00"
    assert metadata["Last activity"] == "2021-03-22 12:59:07+00:00"

    assert len(metadata["Devices"]) > 0
    assert metadata["Devices"][0]["device name"] == "deviceDnsName"
    assert metadata["Devices"][0]["risk level"] == "Informational"
    assert metadata["Devices"][0]["tags"] == "new test,test add tag,testing123"

    assert metadata["Mailboxes"] == []

    assert metadata["comments"] == []


def test_get_meta_data_empty_incident():
    """
    Tests the function with an empty incident.
    """
    from Microsoft365Defender import _get_meta_data_for_incident

    raw_incident = {}
    metadata = _get_meta_data_for_incident(raw_incident)

    assert metadata["Categories"] == []
    assert metadata["Impacted entities"] == []
    assert metadata["Active alerts"] == "0 / 0"
    assert metadata["Service sources"] == []
    assert metadata["Detection sources"] == []
    assert metadata["First activity"] == ""
    assert metadata["Last activity"] == ""
    assert metadata["Devices"] == []
    assert metadata["Mailboxes"] == []
    assert metadata["comments"] == []


def test_fetch_modified_incident(mocker):
    client = mock_client(mocker, 'get_incident', util_load_json('./test_data/incident_get_response.json'))
    mock_meta_data = mocker.patch('your_module_name._get_meta_data_for_incident', return_value={
        'Categories': ['SuspiciousActivity'],
        'Impacted entities': [],
        'Active alerts': '0 / 1',
        'Service sources': ['MicrosoftDefenderForEndpoint'],
        'Detection sources': ['AutomatedInvestigation'],
        'First activity': '2021-03-22T12:34:31.8123759Z',
        'Last activity': '2021-03-22T12:34:31.8123759Z',
        'Devices': [{'device name': 'deviceDnsName', 'risk level': 'Informational', 'tags': 'new test,test add tag,testing123'}],
        'Mailboxes': [],
        'comments': [],
    })
    # Valid incident ID
    incident_id = 263
    incident = fetch_modified_incident(client, incident_id)

    assert "incidentId" in incident
    assert incident["incidentId"] == 263
    assert "@odata.context" not in incident  # Should be removed
    # Assert metadata was added
    assert "Categories" in incident
    assert incident["Categories"] == ['SuspiciousActivity']
    assert "Devices" in incident
    assert incident["Devices"][0] == {'device name': 'deviceDnsName', 'risk level': 'Informational',
                                      'tags': 'new test,test add tag,testing123'}
    assert mock_meta_data.called  # Ensure _get_meta_data_for_incident was called


def test_get_remote_data_command_success(mocker):
    """
    Test a successful run of the get_remote_data_command function.
    """

    mocker.patch("demisto.params", return_value={
        "comment_tag_from_microsoft365defender": "CommentFromMicrosoft365Defender",
        "close_incident": True
    })

    mocker.patch(
        "Microsoft365Defender.fetch_modified_incident",
        return_value={
            "incidentId": 12345,
            "status": "Active",
            "comments": [{"comment": "Test comment", "timestamp": "2025-01-01T12:01:00Z"}],
            "alerts": [{"alertId": "alert1"}],
        }
    )

    mocker.patch(
        "Microsoft365Defender.get_incident_entries",
        return_value=[
            {"Type": 1, "Contents": "Test entry"}
        ]
    )

    args = {
        "remote_incident_id": "12345",
        "last_update": "2025-01-01T12:00:00Z"
    }

    response = get_remote_data_command(MockMicrosoft365DefenderClient(mocker), args)

    assert response.mirrored_object["incidentId"] == 12345
    assert len(response.entries) == 1
    assert response.entries[0]["Contents"] == "Test entry"


def test_get_mapping_fields_command():
    """
    Test the `get_mapping_fields_command` function to verify the mapping fields are returned correctly.
    """
    response = get_mapping_fields_command()

    assert isinstance(response, GetMappingFieldsResponse)

    scheme_types = response.scheme_types
    assert len(scheme_types) == 1  # Only one incident type is defined
    incident_mapping = scheme_types[0]

    assert isinstance(incident_mapping, SchemeTypeMapping)
    assert incident_mapping.type_name == 'Microsoft 365 Defender Incident'
    assert len(incident_mapping.fields) == len(OUTGOING_MIRRORED_FIELDS)

    for field_name, field_description in OUTGOING_MIRRORED_FIELDS.items():
        assert field_name in incident_mapping.fields
        assert incident_mapping.fields[field_name] == field_description


def test_handle_incident_close_out_or_reactivation_close(mocker):
    """
    Test that the incident is properly closed when 'close_out' is enabled and the status is DONE.
    """
    mocker.patch("demisto.params", return_value={"close_out": True})
    delta = {
        "closeReason": "FalsePositive",
        "closeNotes": "This was a false positive alert",
        "closingUserId": "user123"
    }
    incident_status = IncidentStatus.DONE

    handle_incident_close_out_or_reactivation(delta, incident_status)

    assert delta["status"] == "Resolved"
    assert delta["classification"] == "FalsePositive"
    assert delta["determination"] == "Other"


def test_handle_incident_close_out_or_reactivation_close_other(mocker):
    """
    Test that the incident is properly closed with 'Other' or 'Duplicate' reasons.
    """
    mocker.patch("demisto.params", return_value={"close_out": True})
    delta = {
        "closeReason": "Other",
        "closeNotes": "General closure",
        "closingUserId": "user123"
    }
    incident_status = IncidentStatus.DONE

    handle_incident_close_out_or_reactivation(delta, incident_status)

    assert delta["status"] == "Resolved"
    assert delta["classification"] == "Unknown"
    assert delta["determination"] == "NotAvailable"


def test_handle_incident_close_out_or_reactivation_reopen(mocker):
    """
    Test that the incident is reopened when 'closeReason', 'closeNotes', or 'closingUserId' are empty.
    """
    mocker.patch("demisto.params", return_value={"close_out": True})
    delta = {
        "closeReason": "",
        "closeNotes": "",
        "closingUserId": ""
    }
    incident_status = IncidentStatus.ACTIVE

    handle_incident_close_out_or_reactivation(delta, incident_status)

    assert delta["status"] == "Active"


def test_handle_incident_close_out_or_reactivation_close_out_disabled(mocker):
    """
    Test that the function exits early when 'close_out' is disabled.
    """
    mocker.patch("demisto.params", return_value={"close_out": False})
    delta = {
        "closeReason": "FalsePositive",
        "closeNotes": "This was a false positive alert",
        "closingUserId": "user123"
    }
    incident_status = IncidentStatus.DONE

    handle_incident_close_out_or_reactivation(delta, incident_status)

    # Delta should remain unchanged
    assert "status" not in delta
    assert "classification" not in delta
    assert "determination" not in delta


def test_handle_incident_close_out_or_reactivation_no_delta_changes(mocker):
    """
    Test that the function exits early when no relevant keys in the delta are present.
    """
    mocker.patch("demisto.params", return_value={"close_out": True})
    delta = {}
    incident_status = IncidentStatus.DONE

    handle_incident_close_out_or_reactivation(delta, incident_status)

    assert "status" not in delta
    assert "classification" not in delta
    assert "determination" not in delta


def test_mirror_out_entries_with_comment_tag(mocker):
    """
    Test `mirror_out_entries` where entries contain the comment tag and are mirrored out.
    """
    client = mock_client(mocker, 'update_incident', util_load_json('./test_data/incident_update_response.json'))
    mocker.patch("demisto.debug")

    comment_tag = "CommentFromXSOAR"
    entries = [
        {"id": 1, "type": "note", "tags": [comment_tag], "user": "user1", "contents": "Test content", "format": "text"},
        {"id": 2, "type": "note", "tags": [comment_tag], "user": "user2", "contents": "Another test content", "format": "html"},
    ]
    remote_incident_id = 12345

    mirror_out_entries(client, entries, comment_tag, remote_incident_id)

    # Assert that update_incident was called twice with appropriate payloads
    assert client.update_incident.call_count == 2
    client.update_incident.assert_any_call(
        incident_id=remote_incident_id,
        timeout=50,
        comment="(user1): Test content\n\n [XSOAR_COMMENT_TO_MICROSOFT]"
    )
    client.update_incident.assert_any_call(
        incident_id=remote_incident_id,
        timeout=50,
        comment="(user2): <br/><br/>[code]Another test content <br/><br/>[/code] [XSOAR_COMMENT_TO_MICROSOFT]"
    )


def test_mirror_out_entries_without_comment_tag(mocker):
    """
    Test `mirror_out_entries` where entries do not contain the comment tag.
    """

    client = mock_client(mocker, 'update_incident', util_load_json('./test_data/incident_update_response.json'))
    mocker.patch("demisto.debug")

    comment_tag = "CommentFromXSOAR"
    entries = [
        {"id": 1, "type": "note", "tags": [], "user": "user1", "contents": "Test content"},
        {"id": 2, "type": "note", "tags": ["UnrelatedTag"], "user": "user2", "contents": "Another test content"},
    ]
    remote_incident_id = 12345

    mirror_out_entries(client, entries, comment_tag, remote_incident_id)

    # Assert that update_incident was not called
    client.update_incident.assert_not_called()


def test_mirror_out_entries_with_missing_fields(mocker):
    """
    Test `mirror_out_entries` where entries have missing fields.
    """
    client = mock_client(mocker, 'update_incident', util_load_json('./test_data/incident_update_response.json'))
    mocker.patch("demisto.debug")

    comment_tag = "CommentFromXSOAR"
    entries = [
        {"id": 1, "tags": [comment_tag]},  # Missing contents
        {"id": 2, "type": "note", "tags": [comment_tag]},  # Missing user and contents
    ]
    remote_incident_id = 12345

    mirror_out_entries(client, entries, comment_tag, remote_incident_id)

    # Assert that update_incident was called with default values
    assert client.update_incident.call_count == 2
    client.update_incident.assert_any_call(
        incident_id=remote_incident_id,
        timeout=50,
        comment="(dbot): \n\n [XSOAR_COMMENT_TO_MICROSOFT]"
    )
    client.update_incident.assert_any_call(
        incident_id=remote_incident_id,
        timeout=50,
        comment="(dbot): \n\n [XSOAR_COMMENT_TO_MICROSOFT]"
    )


def test_mirror_out_entries_empty_entries(mocker):
    """
    Test `mirror_out_entries` with no entries provided.
    """
    client = mock_client(mocker, 'update_incident', util_load_json('./test_data/incident_update_response.json'))
    mocker.patch("demisto.debug")

    comment_tag = "CommentFromXSOAR"
    entries = []
    remote_incident_id = 12345

    mirror_out_entries(client, entries, comment_tag, remote_incident_id)

    # Assert that update_incident was not called
    client.update_incident.assert_not_called()


def test_update_remote_system_with_incident_changes(mocker):
    """
    Test `update_remote_system_command` where the incident has changes and is updated.
    """
    client = mock_client(mocker, 'update_incident', {"status": "success"})
    mocker.patch("demisto.debug")
    mocker.patch("demisto.params", return_value={"comment_tag": "CommentToMicrosoft"})

    args = {
        "remote_incident_id": "12345",
        "data": {"name": "incident"},
        "delta": {"status": "Resolved", "assignedTo": "user1", "tags": "test_tag", "comment": "Test comment"},
        "incident_changed": True,
        "inc_status": "DONE",
        "entries": []
    }

    result = update_remote_system_command(client, args)

    # Assertions
    assert result == "12345"
    client.update_incident.assert_called_once_with(
        incident_id="12345",
        status="Resolved",
        assigned_to="user1",
        classification=None,
        determination=None,
        tags=["test_tag"],
        timeout=50,
        comment="Test comment"
    )


def test_update_remote_system_without_incident_changes(mocker):
    """
    Test `update_remote_system_command` where the incident has no changes and is not updated.
    """
    client = mock_client(mocker, 'update_incident', {"status": "success"})
    mocker.patch("demisto.debug")

    args = {
        "remote_incident_id": "12345",
        "data": {"name": "incident"},
        "delta": None,
        "incident_changed": False,
        "inc_status": "DONE",
        "entries": []
    }

    result = update_remote_system_command(client, args)

    assert result == "12345"
    client.update_incident.assert_not_called()


def test_update_remote_system_with_entries(mocker):
    """
    Test `update_remote_system_command` where new entries are mirrored out.
    """
    client = mock_client(mocker, 'update_incident', {"status": "success"})
    mocker.patch("demisto.debug")
    mocker.patch("demisto.params", return_value={"comment_tag": "CommentToMicrosoft"})
    mocker.patch("Microsoft365Defender.mirror_out_entries", return_value=None)

    args = {
        "remote_incident_id": "12345",
        "data": {"name": "incident"},
        "delta": None,
        "incident_changed": False,
        "inc_status": "ACTIVE",
        "entries": [{"id": 1, "tags": ["CommentToMicrosoft"], "contents": "Test entry"}]
    }

    result = update_remote_system_command(client, args)

    # Assertions
    assert result == "12345"
    client.update_incident.assert_not_called()
    from Microsoft365Defender import mirror_out_entries
    mirror_out_entries.assert_called_once_with(
        client,
        [{"id": 1, "tags": ["CommentToMicrosoft"], "contents": "Test entry"}],
        "CommentToMicrosoft",
        "12345"
    )


def test_update_remote_system_error_handling(mocker):
    """
    Test `update_remote_system_command` error handling when an exception occurs.
    """
    client = mock_client(mocker, 'update_incident', {"status": "success"})
    mocker.patch("demisto.debug")
    mocker.patch("demisto.error")
    mocker.patch("Microsoft365Defender.mirror_out_entries", side_effect=Exception("Test error"))

    args = {
        "remote_incident_id": "12345",
        "data": {"name": "incident"},
        "delta": {"status": "Resolved", "assignedTo": "user1", "tags": "test_tag", "comment": "Test comment"},
        "incident_changed": True,
        "inc_status": "DONE",
        "entries": [{"id": 1, "tags": ["CommentToMicrosoft"], "contents": "Test entry"}]
    }

    result = update_remote_system_command(client, args)

    # Assertions
    assert result == "12345"
    client.update_incident.assert_called_once_with(
        incident_id="12345",
        status="Resolved",
        assigned_to="user1",
        classification=None,
        determination=None,
        tags=["test_tag"],
        timeout=50,
        comment="Test comment"
    )
    from Microsoft365Defender import mirror_out_entries
    mirror_out_entries.assert_called_once()
    demisto.error.assert_called_once_with(
        "Microsoft Defender 365 - Error in outgoing mirror for incident 12345 \nError message: Test error"
    )