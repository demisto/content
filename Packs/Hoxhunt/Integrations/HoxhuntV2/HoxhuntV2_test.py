from datetime import datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from HoxhuntV2 import *
from requests import Response

import demistomock as demisto
from CommonServerPython import *

del globals()["test_module_command"]

FROZEN_DATE = '2024-09-01T00:00:00Z'
FROZEN_DATE_AFTER = '2024-10-01T00:00:00Z'


def form_incidents(incidents: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
    return [create_incident_from_log(item, now) for item in incidents]


@pytest.fixture
def mock_client():
    client = MagicMock(spec=Client)
    return client


@pytest.fixture
def mock_demisto(mocker):
    incidents_mock = mocker.patch.object(demisto, 'incidents')
    set_last_run_mock = mocker.patch.object(demisto, 'setLastRun')
    params_mock = mocker.patch.object(demisto, 'params')
    args_mock = mocker.patch.object(demisto, 'args')
    return {
        'incidents': incidents_mock,
        'setLastRun': set_last_run_mock,
        'params': params_mock,
        'args': args_mock,
    }


def setup_mock_params(mock_demisto,
                      first_fetch=FROZEN_DATE,
                      max_fetch='',
                      query_filter='',
                      incident_id='',
                      last_update=FROZEN_DATE,
                      delta={},
                      incidentChanged=False,
                      status=1,
                      data={},
                      remoteId="1234"):

    mock_demisto['args'].return_value = {
        'incident_id': incident_id,
        'lastUpdate': last_update,
        'delta': delta,
        'incidentChanged': incidentChanged,
        'status': status,
        'data': data,
        'remoteId': remoteId,
        'id': incident_id,
    }
    mock_demisto['params'].return_value = {
        'first_fetch': first_fetch,
        'max_fetch': max_fetch,
        'queryfilter': query_filter,
    }


@pytest.fixture
def incident_1():
    return {
        '_id': '1',
        'createdAt': FROZEN_DATE_AFTER,
        'updatedAt': FROZEN_DATE_AFTER,
        'humanReadableId': 'incident-1',
        'classification': 'malicious',
        'policyName': 'BEC',
        'threatCount': 5,
        'globalThreatCount': 10,
        'firstThreat': {
            '_id': 'threat-1',
            'createdAt': FROZEN_DATE,
            'classification': 'malicious'
        }
    }


@pytest.fixture
def incident_2():
    return {
        '_id': '2',
        'createdAt': FROZEN_DATE_AFTER,
        'updatedAt': FROZEN_DATE_AFTER,
        'humanReadableId': 'incident-2',
        'classification': 'malicious',
        'policyName': 'BEC',
        'threatCount': 5,
        'globalThreatCount': 10,
        'firstThreat': {
            '_id': 'threat-2',
            'createdAt': FROZEN_DATE,
            'classification': 'malicious'
        }
    }


@pytest.fixture
def mock_incidents(incident_1, incident_2):
    return [incident_1, incident_2]

#  GqlResult


def test_gql_result_no_errors():
    """
    Given
        GqlResult initialized without errors
    When
        Creating a new GqlResult instance
    Then
        Check that data is an empty dictionary and errors is an empty list
    """
    gql_result = GqlResult()
    assert gql_result.data == {}
    assert gql_result.errors == []
    assert not gql_result.has_errors()


def test_gql_result_with_errors():
    """
    Given
        GqlResult initialized with errors
    When
        Creating a new GqlResult instance
    Then
        Check that errors are stored and has_errors returns True
    """
    error = "Sample error"
    gql_result = GqlResult(errors=[error])
    assert gql_result.has_errors()
    assert gql_result.errors == [error]


# http_error_handler

def test_http_error_handler_rate_limit():
    """
    Given
        A Response object with a status code of 429 (rate limit)
    When
        Calling http_error_handler with the response
    Then
        Expect an exception with message 'API rate limit'
    """
    res = MagicMock(spec=Response)
    res.status_code = 429

    with pytest.raises(Exception, match="API rate limit"):
        http_error_handler(res)


def test_http_error_handler_json_error():
    """
    Given
        A Response object with a status code and a JSON error message
    When
        Calling http_error_handler with the response
    Then
        Expect a DemistoException with the parsed JSON message
    """
    res = MagicMock(spec=Response)
    res.status_code = 400
    res.reason = "Bad Request"
    res.json.return_value = {"error": "Invalid request"}

    with pytest.raises(DemistoException) as excinfo:
        http_error_handler(res)

    assert "Error in API call [400] - Bad Request" in str(excinfo.value)
    assert '{"error": "Invalid request"}' in str(excinfo.value)

# client.query


@pytest.mark.parametrize(
    "mock_response, expected_data, expected_errors",
    [
        (
            {'data': {'key': 'value'}},
            {'key': 'value'},
            []
        ),
        (
            {
                'errors': [
                    {
                        'message': 'An error occurred',
                        'locations': [{'line': 1, 'column': 2}],
                        'path': ['query', 'field'],
                        'extensions': {'code': 'INTERNAL_ERROR'}
                    }
                ]
            },
            {},
            [
                'An error occurred'
            ]
        ),
        (
            {
                'data': {'key': 'value'},
                'errors': [
                    {
                        'message': 'Partial error occurred',
                        'locations': [{'line': 2, 'column': 3}],
                        'path': ['query', 'otherField'],
                        'extensions': {'code': 'PARTIAL_ERROR'}
                    }
                ]
            },
            {'key': 'value'},
            [
                'Partial error occurred'
            ]
        ),
    ]
)
def test_query(mock_response, expected_data, expected_errors, mocker):
    client = Client(base_url='https://api.example.com', headers={'Authorization': 'Bearer token'})

    with mocker.patch.object(client, '_http_request', return_value=mock_response):
        gql_result = client.query('query { field }')

        assert gql_result.data == expected_data
        assert len(gql_result.errors) == len(expected_errors)

        for actual_error, expected_error in zip(gql_result.errors, expected_errors):
            assert actual_error == expected_error


# fetch_incidents_command


@pytest.mark.parametrize(
    "first_fetch, max_fetch, only_open_incidents, only_escalated_incidents, last_run, "
    "expected_next_run, expected_query_part, raises_exception",
    [
        (FROZEN_DATE, '50', None, None, {},
         {'start_time': FROZEN_DATE_AFTER},
         "createdAt_gt", False),
        (FROZEN_DATE, '50', False, True, {},
         {'start_time': FROZEN_DATE_AFTER},
         'escalation__escalatedAt_exists: true', False),
        (FROZEN_DATE, '50', True, True, {},
         {'start_time': FROZEN_DATE_AFTER},
         'escalation__escalatedAt_exists: true, state_eq: OPEN', False),
        (FROZEN_DATE, '50', True, False, {},
         {'start_time': FROZEN_DATE_AFTER},
         'state_eq: OPEN', False),
        (FROZEN_DATE, '50', False, False, {},
         {'start_time': FROZEN_DATE_AFTER},
         'createdAt_gt', False),
        ('invalid-time-format', '50', None, None, {}, None, "", True)
    ]
)
def test_fetch_incidents(
    mock_client,
    mock_incidents,
    first_fetch,
    max_fetch,
    only_open_incidents,
    only_escalated_incidents,
    last_run,
    expected_next_run,
    expected_query_part,
    raises_exception
):
    mock_client.query = MagicMock(return_value=GqlResult({'incidents': mock_incidents if not raises_exception else []}))
    now = datetime.now().timestamp()

    if raises_exception:
        with pytest.raises(ValueError, match="Invalid first_fetch format"):
            fetch_incidents(mock_client, first_fetch, max_fetch, only_open_incidents, only_escalated_incidents, now, last_run)
    else:
        incidents, next_run = fetch_incidents(mock_client, first_fetch, max_fetch,
                                              only_open_incidents, only_escalated_incidents, now, last_run)

        if expected_next_run:
            expected_incidents = form_incidents(mock_incidents, now)
        else:
            expected_incidents = []

        assert incidents == expected_incidents
        assert next_run == expected_next_run

        if expected_query_part:
            query_call = mock_client.query.call_args[0][0]
            assert expected_query_part in query_call, f"Expected query to contain: {expected_query_part}"


# get_remote_data_command


def test_get_remote_data_command_resolved(mock_client, mock_demisto):
    """
    Given
        An incident with state 'RESOLVED' that has been updated since the last update time
    When
        Calling get_remote_data_command
    Then
        The incident data is returned with an entry to close the incident in Demisto
    """
    incident_id = 'incident-1'
    last_update = FROZEN_DATE
    setup_mock_params(mock_demisto, incident_id, last_update)

    incident_data = {
        '_id': incident_id,
        'state': 'RESOLVED',
        'updatedAt': FROZEN_DATE,
    }
    mock_client.get_incident_by_id.return_value = incident_data

    response = get_remote_data_command(mock_client, mock_demisto['args'](), mock_demisto['params']())

    assert response.mirrored_object['id'] == incident_id
    assert response.mirrored_object['state'] == 'RESOLVED'

    expected_entry = {
        'Type': EntryType.NOTE,
        'Contents': {
            'closeReason': 'Incident was resolved in Hoxhunt platform',
            'dbotIncidentClose': True
        },
        'ContentsFormat': EntryFormat.JSON,
    }
    assert response.entries == [expected_entry]


def test_get_remote_data_command_open(mock_client, mock_demisto):
    """
    Given
        An incident with state 'OPEN' that has been updated since the last update time
    When
        Calling get_remote_data_command
    Then
        The incident data is returned with an entry to reopen the incident in Demisto
    """
    incident_id = 'incident-2'
    last_update = FROZEN_DATE
    setup_mock_params(mock_demisto, incident_id, last_update)

    incident_data = {
        '_id': incident_id,
        'state': 'OPEN',
        'updatedAt': FROZEN_DATE,
    }
    mock_client.get_incident_by_id.return_value = incident_data

    response = get_remote_data_command(mock_client, mock_demisto['args'](), mock_demisto['params']())

    assert response.mirrored_object['id'] == incident_id
    assert response.mirrored_object['state'] == 'OPEN'

    expected_entry = {
        'Type': EntryType.NOTE,
        'Contents': {'dbotIncidentReopen': True},
        'ContentsFormat': EntryFormat.JSON,
    }
    assert response.entries == [expected_entry]


def test_get_remote_data_command_no_update(mock_client, mock_demisto):
    """
    Given
        An incident that has not been updated since the last update time
    When
        Calling get_remote_data_command
    Then
        No incident data or entries are returned
    """
    incident_id = 'incident-3'
    last_update = FROZEN_DATE
    setup_mock_params(mock_demisto, incident_id, last_update)

    mock_client.get_incident_by_id.return_value = {}

    response = get_remote_data_command(mock_client, mock_demisto['args'](), mock_demisto['params']())

    assert response.mirrored_object == {}
    assert response.entries == []


def test_get_remote_data_command_missing_id(mock_client, mock_demisto):
    """
    Given
        Incident data returned without an '_id' field
    When
        Calling get_remote_data_command
    Then
        The 'id' field is not set in the mirrored object
    """
    incident_id = 'incident-4'
    last_update = FROZEN_DATE
    setup_mock_params(mock_demisto, incident_id, last_update)

    incident_data = {
        'state': 'OPEN',
        'updatedAt': FROZEN_DATE,
    }
    mock_client.get_incident_by_id.return_value = incident_data

    response = get_remote_data_command(mock_client, mock_demisto['args'](), mock_demisto['params']())

    assert 'id' not in response.mirrored_object
    assert response.mirrored_object['state'] == 'OPEN'

    expected_entry = {
        'Type': EntryType.NOTE,
        'Contents': {'dbotIncidentReopen': True},
        'ContentsFormat': EntryFormat.JSON,
    }
    assert response.entries == [expected_entry]


# get_mapping_fields_command


def test_get_mapping_fields_command(mock_client, mocker):
    """
    Given
        The Hoxhunt integration is properly set up
    When
        Calling get_mapping_fields_command
    Then
        A GetMappingFieldsResponse is returned containing the correct mapping fields for each incident type
    """
    mocker.patch('HoxhuntV2.CAMPAIGN_INCIDENT_TYPE_NAME', CAMPAIGN_INCIDENT_TYPE_NAME)
    mocker.patch('HoxhuntV2.USER_ACTED_TYPE_NAME', USER_ACTED_TYPE_NAME)
    mocker.patch('HoxhuntV2.BEC_TYPE_NAME', BEC_TYPE_NAME)
    mocker.patch('HoxhuntV2.INCIDENT_MAPPING_FIELDS', INCIDENT_MAPPING_FIELDS)

    response = get_mapping_fields_command(mock_client, args={}, params={})

    assert isinstance(response, GetMappingFieldsResponse)

    schemes = response.scheme_types_mappings

    assert len(schemes) == 3

    type_names = [scheme.type_name for scheme in schemes]
    expected_type_names = [
        CAMPAIGN_INCIDENT_TYPE_NAME,
        USER_ACTED_TYPE_NAME,
        BEC_TYPE_NAME
    ]
    assert set(type_names) == set(expected_type_names)

    for scheme in schemes:
        fields = scheme.fields
        assert len(fields) == len(INCIDENT_MAPPING_FIELDS)

        for field_name, field in fields.items():
            assert field_name in INCIDENT_MAPPING_FIELDS
            mapping_field = INCIDENT_MAPPING_FIELDS[field_name]
            expected_description = mapping_field['description']
            assert field == expected_description


# update_remote_system_command


def test_update_remote_system_command_incident_opened(mock_client, mock_demisto, mocker):
    """
    Given
        An incident that was changed in XSOAR with delta changes, and the status is 'open'
    When
        Running update_remote_system_command
    Then
        The client's update_incident_state is called with 'OPEN', and update_changed_incident_fields is called
    """
    setup_mock_params(
        mock_demisto,
        delta={'field1': 'value1'},
        incidentChanged=True,
        status=1,
        data={'some': 'data'},
        remoteId='1234'
    )

    update_changed_fields_mock = mocker.patch.object(mock_client, 'update_changed_incident_fields')

    incident_id = update_remote_system_command(mock_client, mock_demisto['args'](), mock_demisto['params']())

    mock_client.update_incident_state.assert_called_with('1234', 'OPEN')
    update_changed_fields_mock.assert_called_with('1234', {'field1': 'value1'})
    assert incident_id == '1234'


# get_modified_remote_data_command

def test_get_modified_remote_data_command_success(mock_client, mock_demisto):
    """
    Given
        A valid last_update timestamp, and the client returns modified incidents without errors
    When
        Running get_modified_remote_data_command
    Then
        The function returns a GetModifiedRemoteDataResponse with the modified incident IDs
    """

    setup_mock_params(mock_demisto, last_update=FROZEN_DATE)

    mock_result = MagicMock()
    mock_result.has_errors.return_value = False
    mock_result.data = {
        'incidents': [
            {'_id': 'inc1'},
            {'_id': 'inc2'},
            {'_id': 'inc3'},
        ]
    }
    mock_client.get_modified_incidents.return_value = mock_result

    response = get_modified_remote_data_command(mock_client, mock_demisto['args'](), mock_demisto['params']())

    assert isinstance(response, GetModifiedRemoteDataResponse)
    assert response.modified_incident_ids == ['inc1', 'inc2', 'inc3']


def test_get_modified_remote_data_command_client_error(mock_client, mock_demisto):
    """
    Given
        A valid last_update timestamp, but the client returns errors
    When
        Running get_modified_remote_data_command
    Then
        The function raises an Exception with the client's error messages
    """

    setup_mock_params(mock_demisto, last_update=FROZEN_DATE)

    mock_result = MagicMock()
    mock_result.has_errors.return_value = True
    mock_result.errors = 'Some error occurred'
    mock_client.get_modified_incidents.return_value = mock_result

    with pytest.raises(Exception, match='Some error occurred'):
        get_modified_remote_data_command(mock_client, mock_demisto['args'](), mock_demisto['params']())


def test_get_modified_remote_data_command_no_incidents(mock_client, mock_demisto):
    """
    Given
        A valid last_update timestamp, and the client returns no modified incidents
    When
        Running get_modified_remote_data_command
    Then
        The function returns an empty list of modified incident IDs
    """

    setup_mock_params(mock_demisto, last_update=FROZEN_DATE)

    mock_result = MagicMock()
    mock_result.has_errors.return_value = False
    mock_result.data = {'incidents': []}
    mock_client.get_modified_incidents.return_value = mock_result

    response = get_modified_remote_data_command(mock_client, mock_demisto['args'](), mock_demisto['params']())

    assert isinstance(response, GetModifiedRemoteDataResponse)
    assert response.modified_incident_ids == []

# gql commands


@pytest.mark.parametrize(
    "command_function, args, query_return_value, expected_output",
    [
        (
            hoxhunt_get_current_user_command,
            {},
            {'data': {'currentUser': {'emails': ['user@example.com']}}},
            ['user@example.com'],
        ),
        (
            hoxhunt_get_current_user_command,
            {},
            {'errors': ['Some error occurred']},
            None,
        ),
        (
            hoxhunt_get_incident_threats_command,
            {"incident_id": "123"},
            {'data': {'incidents': [{'threats': [{'id': 't1', 'name': 'Threat 1'}]}]}},
            [{'id': 't1', 'name': 'Threat 1'}],
        ),
        (
            hoxhunt_get_incident_threats_command,
            {},
            {'errors': ['Some error occurred']},
            None,
        ),
        (
            hoxhunt_add_incident_note_command,
            {'incident_id': 'inc123', 'note': 'Test note'},
            {'data': {'addIncidentNote': {'notes': [{'text': 'Previous note',
                                                     '_id': 'note122'}, {'text': 'Test note', '_id': 'note123'}]}}},
            {'incident_id': 'inc123', 'note_id': 'note123', 'note': 'Test note'},
        ),
        (
            hoxhunt_add_incident_note_command,
            {'incident_id': 'inc123', 'note': 'Test note'},
            {'errors': ['Some error occurred']},
            None,
        ),
        (
            hoxhunt_remove_incident_threats_command,
            {'incident_id': 'inc123'},
            {'data': {'removeIncidentThreats': 5}},
            {'incident_id': 'inc123', 'removed threats number': 5},
        ),
        (
            hoxhunt_remove_incident_threats_command,
            {'incident_id': 'inc123'},
            {'errors': ['Some error occurred']},
            None,
        ),
        (
            hoxhunt_send_incident_soc_feedback_command,
            {'incident_id': 'inc123', 'custom_message': 'Test message', 'threat_feedback_reported_at_limit': '2023-10-01'},
            {'data': {}},
            {'_id': 'inc123', 'custom_message': 'Test message', 'limit date': '2023-10-01'},
        ),
        (
            hoxhunt_send_incident_soc_feedback_command,
            {'incident_id': 'inc123', 'custom_message': 'Test message', 'threat_feedback_reported_at_limit': '2023-10-01'},
            {'errors': ['Some error occurred']},
            None,
        ),
        (
            hoxhunt_set_incident_sensitive_command,
            {'incident_id': 'inc123', 'is_sensitive': 'true'},
            {'_id': 'inc123', 'hasSensitiveInformation': True},
            {'incident_id': 'inc123', 'is_sensitive': 'True'},
        ),
        (
            hoxhunt_set_incident_sensitive_command,
            {'incident_id': 'inc123', 'is_sensitive': 'false'},
            {'_id': 'inc123', 'hasSensitiveInformation': False},
            {'incident_id': 'inc123', 'is_sensitive': 'False'},
        ),
        (
            hoxhunt_set_incident_soc_classification_command,
            {'incident_id': 'inc123', 'classification': 'Malware'},
            {'data': {'setIncidentSocClassification': {'_id': 'inc123', 'classification': 'Malware'}}},
            {'_id': 'inc123', 'classification': 'Malware'},
        ),
        (
            hoxhunt_set_incident_soc_classification_command,
            {'incident_id': 'inc123', 'classification': 'Malware'},
            {'errors': ['Some error occurred']},
            None,
        ),
        (
            hoxhunt_update_incident_state_command,
            {'incident_id': 'inc123', 'state': 'closed'},
            {'data': {'updateIncidentState': {'_id': 'inc123', 'state': 'closed'}}},
            {'_id': 'inc123', 'state': 'closed'},
        ),
        (
            hoxhunt_update_incident_state_command,
            {'incident_id': 'inc123', 'state': 'closed'},
            {'errors': ['Some error occurred']},
            None,
        ),
    ]
)
def test_commands(
    mock_client,
    command_function,
    args,
    query_return_value,
    expected_output,
    mocker,
):
    command_function_to_client_method = {
        hoxhunt_get_current_user_command: 'get_current_user',
        hoxhunt_add_incident_note_command: 'add_incident_note',
        hoxhunt_remove_incident_threats_command: 'remove_incident_threats',
        hoxhunt_send_incident_soc_feedback_command: 'send_incident_soc_feedback',
        hoxhunt_set_incident_sensitive_command: 'set_incident_sensitive',
        hoxhunt_set_incident_soc_classification_command: 'set_incident_soc_classification',
        hoxhunt_update_incident_state_command: 'update_incident_state',
    }

    # Set up mocks
    if command_function == hoxhunt_set_incident_sensitive_command:
        # For functions where client method returns a dict
        mocker.patch.object(
            mock_client,
            command_function_to_client_method[command_function],
            return_value=query_return_value
        )
    else:
        mock_result = GqlResult(
            data=query_return_value.get('data', {}),
            errors=query_return_value.get('errors', [])
        )
        mocker.patch.object(
            mock_result,
            "has_errors",
            return_value=bool(query_return_value.get('errors', []))
        )

        mocker.patch.object(mock_client, "query", return_value=mock_result)

        if command_function in command_function_to_client_method:
            client_method_name = command_function_to_client_method[command_function]
            mocker.patch.object(
                mock_client,
                client_method_name,
                return_value=mock_result
            )
        else:
            pass

    mocker.patch('HoxhuntV2.create_output', side_effect=lambda results, *_: results)

    if query_return_value.get('errors'):
        with pytest.raises(Exception):
            command_function(mock_client, args, params={})
    else:
        output = command_function(mock_client, args, params={})
        assert output == expected_output


def test_format_date_to_iso_string():
    """
    Given
        A datetime object
    When
        Calling format_date_to_iso_string
    Then
        Returns correctly formatted ISO string with milliseconds and Z suffix
    """
    # Test with a specific datetime
    test_date = datetime(2024, 1, 15, 14, 30, 45, 123456)
    result = format_date_to_iso_string(test_date)
    assert result == "2024-01-15T14:30:45.123Z"


def test_format_date_to_iso_string_with_none():
    """
    Given
        None as input
    When
        Calling format_date_to_iso_string
    Then
        Raises AttributeError since None has no strftime method
    """
    with pytest.raises(AttributeError):
        format_date_to_iso_string(None)
