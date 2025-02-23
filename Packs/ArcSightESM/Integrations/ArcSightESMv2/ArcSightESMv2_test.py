from pathlib import Path
import json
import requests
from ArcSightESMv2 import parse_json_response
import demistomock as demisto
import pytest
import requests_mock

PARAMS = {
    'server': 'https://server.local',
    'credentials': {},
    'proxy': True}

ARGS = {'ids': 'lastDateRange',
        'lastDateRange': '2 hours'}


def test_decode_ip(mocker):
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'auth_token': 'token'})
    mocker.patch.object(demisto, 'setIntegrationContext')

    mocker.patch.object(demisto, 'params', return_value=PARAMS)

    import ArcSightESMv2

    mocker.patch.object(demisto, 'args', return_value=ARGS)
    res = ArcSightESMv2.decode_ip('52.213.8.10')
    assert res == '52.213.8.10'

    res = ArcSightESMv2.decode_ip(3232235845)
    assert res == '192.168.1.69'


test_data = [
    (
        True,
        'as-get-entries',
        'https://server/www/manager-service/rest/ActiveListService/getEntries?alt=json'
    ),
    (
        False,
        'as-get-entries',
        'https://server/www/manager-service/services/ActiveListService/'
    ),
    (
        True,
        'as-clear-entries',
        'https://server/www/manager-service/rest/ActiveListService/clearEntries?alt=json'
    ),
    (
        False,
        'as-clear-entries',
        'https://server/www/manager-service/services/ActiveListService/'
    )
]


@pytest.mark.parametrize('use_rest, cmd_name, expected_rest_endpoint', test_data)
def test_use_rest(mocker, use_rest, cmd_name, expected_rest_endpoint):
    '''Check that the correct endpoint is queried depending on the value of the 'use_rest' integration parameter.

    This applies for the entries-related commands `as-get-entries` and `as-clear-entries`.

    Args:
        mocker (fixture): Mocking fixture
        use_rest (bool): Whether the 'use_rest' integration parameter should be mocked as True or False
        cmd_name (str): The entries-related command to run
        expected_rest_endpoint (str): The endpoint that should be queried based on the parametrized configuration

    Scenario: Execute the entries-related ArcSightESMv2 commands

    Given
    - The 'use_rest' integration parameter value
    - The ArcSightESMv2 entries-related command to execute

    When
    - case A: 'use_rest' is True and the 'as-get-entries' command is executed
    - case B: 'use_rest' is False and the 'as-get-entries' command is executed
    - case C: 'use_rest' is True and the 'as-clear-entries' command is executed
    - case D: 'use_rest' is False and the 'as-clear-entries' command is executed

    Then
    - case A: Ensure the REST endpoint for 'as-get-entries' is used
    - case B: Ensure the SOAP endpoint for 'as-get-entries' is used
    - case C: Ensure the REST endpoint for 'as-clear-entries' is used
    - case D: Ensure the SOAP endpoint for 'as-clear-entries' is used
    '''
    params = {
        'server': 'https://server',
        'credentials': {},
        'use_rest': use_rest,
        'proxy': True
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value=cmd_name)
    mocker.patch.object(demisto, 'args', return_value={'resourceId': 'blah'})
    with requests_mock.Mocker() as m:
        fake_response = {'log.loginResponse': {'log.return': 'fake'}}
        m.post('https://server/www/core-service/rest/LoginService/login', json=fake_response)

        import ArcSightESMv2

        m.post('https://server/www/manager-service/rest/ActiveListService/clearEntries?alt=json', json={})
        m.post('https://server/www/manager-service/rest/ActiveListService/getEntries?alt=json', json={})
        fake_xml = '<?xml version="1.0"?><Envelope><Body><getEntriesResponse><return>' \
                   '<entryList><entry>1.1.1.1</entry></entryList><columns>Blah</columns>' \
                   '</return></getEntriesResponse></Body></Envelope>'
        m.post('https://server/www/manager-service/services/ActiveListService/', text=fake_xml)
        ArcSightESMv2.main()
        last_request = m.last_request
        assert last_request.url == expected_rest_endpoint


def test_decode_arcsight_output_event_ids():
    """Unit test - When output to the incident context integers, demisto can round them if they are bigger than 2^32
    Given
    - a long eventId, baseEventIds
    When
    - running decode_arcsight_output
    Then
    - run the command on the input
    Validate that the eventId, baseEventIds values were casted to string
    """
    import ArcSightESMv2
    raw = {'eventId': 2305843016676439806, 'baseEventIds': 2305843016676439600}
    expected = {'eventId': '2305843016676439806', 'baseEventIds': '2305843016676439600'}
    d = ArcSightESMv2.decode_arcsight_output(raw)
    assert isinstance(d.get('eventId'), str)
    assert isinstance(d.get('baseEventIds'), str)
    assert d == expected


def test_decoding_incidents():
    """
    Given
    - an incident created while fetch.
    When
    - running fetch_incidents.
    Then
    - create incidents without bytes objects.

    """
    import ArcSightESMv2
    import demistomock as demisto
    incident = {'name': 'Test XSOAR', 'occurred': '2023-03-22T12:44:51.000Z',
                'labels': [{'type': b'Event ID', 'value': b'1234'},
                           {'type': b'Start Time', 'value': b'1234'}, {'type': b'Name', 'value': b'Test XSOAR'},
                           {'type': b'Message', 'value': None}, {'type': b'End Time', 'value': b'1234'},
                           ],
                'rawJSON': '{"Event ID": "1234", "Start Time": "1234", "Name": "Test XSOAR",'
                           ' "Message": null, "End Time": "1234"}'}
    d = ArcSightESMv2.decode_arcsight_output(incident)
    try:
        demisto.incidents(d)
    except Exception as e:
        pytest.fail(str(e))


def test_filtered():
    import ArcSightESMv2
    entries = [
        {'userAccount': 'abba', 'internalAddress': '127.0.0.2', 'externalLocation': 'Russia',
         'externalAddress': '1.2.3.4'},
        {'userAccount': 'abba', 'internalAddress': '127.0.0.1', 'externalLocation': 'USA',
         'externalAddress': '1.2.3.4'},
        {'userAccount': 'abba', 'internalAddress': '127.0.0.1', 'externalLocation': 'ISS',
         'externalAddress': '1.2.3.4'}
    ]
    entry_filter = 'userAccount:abba,internalAddress:127.0.0.1'
    expected_output = [
        {'userAccount': 'abba', 'internalAddress': '127.0.0.1', 'externalLocation': 'USA',
         'externalAddress': '1.2.3.4'},
        {'userAccount': 'abba', 'internalAddress': '127.0.0.1', 'externalLocation': 'ISS',
         'externalAddress': '1.2.3.4'}
    ]
    filtered_entries = ArcSightESMv2.filter_entries(entries, entry_filter)
    assert filtered_entries == expected_output


def test_get_case(mocker, requests_mock):
    """
    Given:
        - Case with nested event field of type int with large value in it (larger than 10000000000000000)

    When:
        - Running get-case command

    Then:
        - Ensure the the value of the test_big_int_number field is a string
    """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'auth_token': 'token'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'command', return_value='as-get-case')
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    requests_mock.get(
        PARAMS['server'] + '/www/manager-service/rest/CaseService/getResourceById',
        json={
            'cas.getResourceByIdResponse': {
                'cas.return': {
                    'createdTimestamp': 1629097454417,
                    'events': [
                        {
                            'test_object': {
                                'test_big_int_number': 10000000000000001,
                            }
                        }
                    ]
                }
            }
        },
    )
    import ArcSightESMv2
    ArcSightESMv2.AUTH_TOKEN = 'token'

    ArcSightESMv2.main()

    results = demisto.results.call_args[0][0]
    events = results['Contents']['events']
    assert events[0]['test_object']['test_big_int_number'] == '10000000000000001'


def test_add_entries_using_detect_api(mocker, requests_mock):
    """
    Given
    - an active list in ArcSight with resource id=100, and fields Name, IP
    - entries [{"Name": "foo", "IP": "8.8.8.8"},{"Name": "roo", "IP": "1.1.1.1"}]

    When
    - adding entries to the active list

    Then
    - ensure token is passed in the Authorization header with Bearer prefix
    - entries passed in the body in the format like:

    {
        "fields": ["Name", "IP"],
        "entries": [
            {
                "fields": ["foo", "8.8.8.8"]
            },
            {
                "fields": ["roo", "1.1.1.1"]
            }
        ]
    }
    """
    # Given
    # - an active list in ArcSight with resource id=100, and fields Name, IP
    # - entries [{"Name": "foo", "IP": "8.8.8.8"},{"Name": "roo", "IP": "1.1.1.1"}]
    base_url = 'https://testurl.com'
    params = {
        'server': base_url,
        'credentials': {},
        'productVersion': '7.4 and above',
        'proxy': True
    }
    entries = [{"Name": "foo", "IP": "8.8.8.8"}, {"Name": "roo", "IP": "1.1.1.1"}]
    resource_id = '100'

    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='as-add-entries')
    mocker.patch.object(demisto, 'args', return_value={'resourceId': resource_id, 'entries': entries})

    post_mock = requests_mock.post(f'{base_url}/detect-api/rest/activelists/{resource_id}/entries')

    import ArcSightESMv2

    token = 'TEST_TOKEN'
    mocker.patch.object(ArcSightESMv2, 'login', return_value=token)

    # When
    # - adding entries to the active list
    ArcSightESMv2.main()

    # Then
    # - ensure token is passed in the Authorization header with Bearer prefix
    # - entries passed in the body in the format like:

    res = post_mock.last_request.json()
    expected_request_body = {
        "fields": ["Name", "IP"],
        "entries": [
            {
                "fields": ["foo", "8.8.8.8"]
            },
            {
                "fields": ["roo", "1.1.1.1"]
            }
        ]
    }

    assert expected_request_body == res


def test_get_all_cases(mocker, requests_mock):
    """
    Given:
        - Cases

    When:
        - Running get-all-cases command

    Then:
        - Ensure the list of cases is returned as expected
    """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'auth_token': 'token'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'command', return_value='as-get-all-cases')
    mocker.patch.object(demisto, 'params', return_value=PARAMS)

    requests_mock.get(
        PARAMS['server'] + '/www/manager-service/rest/CaseService/findAllIds',
        json={
            'cas.findAllIdsResponse': {
                'cas.return': [
                    "1234DfGkBABCenF0601F2Ww==",
                    "456mUEWcBABD6cSFwTn5Fog==",
                    "789pEo2gBABCBcJbK9kU04Q==",
                ]
            }
        },
    )
    import ArcSightESMv2
    ArcSightESMv2.main()
    results = demisto.results.call_args[0][0]
    cases = results['Contents']
    assert len(cases) == 3
    assert cases[0] == '1234DfGkBABCenF0601F2Ww=='


def test_get_query_viewer_results_command(mocker, requests_mock):
    """
    Given:
        - a resource id

    When:
        - Running as-get-matrix-data command

    Then:
        - Ensure the parsed list is returned as expected
    """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'auth_token': 'token'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'command', return_value='as-get-query-viewer-results')
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    mocker.patch.object(demisto, 'args', return_value={'onlyColumns': "false", "resource_id": "id"})

    requests_mock.get(
        PARAMS['server'] + '/www/manager-service/rest/QueryViewerService/getMatrixData',
        json={
            "qvs.getMatrixDataResponse": {
                "qvs.return": {
                    "columnHeaders": [
                        "ID",
                        "Event-Event ID",
                    ],
                    "rows": [
                        {
                            "@xsi.type": "listWrapper",
                            "value": [
                                {
                                    "@xsi.type": "xs:string",
                                    "$": "test_one"
                                },
                                {
                                    "@xsi.type": "xs:string",
                                    "$": "event_one"
                                }
                            ]
                        },
                        {
                            "@xsi.type": "listWrapper",
                            "value": [
                                {
                                    "@xsi.type": "xs:string",
                                    "$": "test_two"
                                },
                                {
                                    "@xsi.type": "xs:string",
                                    "$": "event_two"
                                }
                            ]
                        }
                    ]
                }
            }
        },
    )
    import ArcSightESMv2
    ArcSightESMv2.main()
    results = demisto.results.call_args[0][0]
    output = results['Contents']
    assert len(output) == 2
    assert output[0].get("ID") == "test_one"
    assert output[1].get("Event-Event ID") == "event_two"


def test_update_case_command(mocker):
    """
    Given:
        - Case to be updated

    When:
        - Running update-case command

    Then:
        - Ensure the the value of the updated field is a updated with the new value
    """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'auth_token': 'token'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    mocker.patch.object(demisto, 'args', return_value={"caseId": "test id", "stage": "QUEUED",
                                                       "severity": "INSIGNIFICANT"})

    import ArcSightESMv2

    class ReqMock:
        ok = True

        @staticmethod
        def json():
            return {
                'cas.updateResponse': {
                    'cas.return': {
                        'createdTimestamp': 1629097454417,
                        'events': [{
                            'event one': {
                                'case_id': "test id"
                            }
                        }]}}
            }
    mocker.patch.object(ArcSightESMv2, "get_case", return_value={
        "Name": "test case",
        "EventIDs": [],
        "CaseID": "test id",
        "createdTimestamp": 1629097454417
    }
    )
    mocker.patch.object(ArcSightESMv2, "send_request", return_value=ReqMock())

    import ArcSightESMv2
    ArcSightESMv2.update_case_command()
    results = demisto.results.call_args[0][0]
    case = results['Contents']
    assert case.get('consequenceSeverity') == 'INSIGNIFICANT'
    assert case.get('stage') == 'QUEUED'


def test_delete_case_command(mocker):
    """
    Given:
        - Case to be deleted

    When:
        - Running delete-case command

    Then:
        - Ensure that the case is deleted
    """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'auth_token': 'token'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'command', return_value='as-case-delete')
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    mocker.patch.object(demisto, 'args', return_value={"caseId": "test"})

    import ArcSightESMv2

    class ReqMock:
        ok = True

    mocker.patch.object(ArcSightESMv2, "send_request", return_value=ReqMock())

    import ArcSightESMv2
    ArcSightESMv2.main()
    results = demisto.results.call_args[0][0]
    assert results['Contents'] == 'Case test  was deleted successfully'


def test_get_case_event_ids_command(mocker, requests_mock):
    """
    Given:
        - A case Id

    When:
        - Running as-get-case-event-ids command

    Then:
        - Returns a list of events of the same given case
    """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'auth_token': 'token'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'command', return_value='as-get-case-event-ids')
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    requests_mock.get(
        PARAMS['server'] + '/www/manager-service/rest/CaseService/getCaseEventIDs',
        json={
            'cas.getCaseEventIDsResponse': {
                'cas.return': [
                    12396713,
                    45695741,
                    78996719
                ]
            }
        },
    )
    import ArcSightESMv2
    ArcSightESMv2.main()
    results = demisto.results.call_args[0][0]
    events_ids = results['Contents']['cas.getCaseEventIDsResponse']['cas.return']
    assert len(events_ids) == 3
    assert events_ids[0] == 12396713


def test_get_all_query_viewers_command(mocker, requests_mock):
    """
    Given:
        - a resource id

    When:
        - Running as-get-all-query-viewers command

    Then:
        - Ensure the parsed list is returned as expected
    """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'auth_token': 'token'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'command', return_value='as-get-all-query-viewers')
    mocker.patch.object(demisto, 'params', return_value=PARAMS)

    requests_mock.post(
        PARAMS['server'] + '/www/manager-service/rest/QueryViewerService/findAllIds',
        json={
            "qvs.findAllIdsResponse": {
                "qvs.return":
                    [
                        "123457WYBABCw9lZRkCjVIQ==",
                        "54321rlkBABCJREkQ7PrIRg==",
                        "56789py4BABCN9NYml6MSoA==",
                    ]

            }
        },
    )
    import ArcSightESMv2
    ArcSightESMv2.main()
    results = demisto.results.call_args[0][0]
    output = results['Contents']
    assert len(output) == 3
    assert output[2] == "56789py4BABCN9NYml6MSoA=="


def test_invalid_json_response(mocker, requests_mock):
    """
    Given:
        - The servers responds with a response that is not a valid json

    When:
        - Running as-get-security-events command

    Then:
        - Ensure the response data is fixed and parsed.
    """
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'auth_token': 'token'})
    mocker.patch.object(demisto, 'results')
    mocker.patch.object(demisto, 'command', return_value='as-get-security-events')
    mocker.patch.object(demisto, 'params', return_value=PARAMS)
    mocker.patch.object(demisto, 'args', return_value={"ids": "X"})
    mock_data_path = Path.cwd() / 'test_data' / 'QueryViewerService_getMatrixData_invalid_api_response.txt'

    debug_logs_mock = mocker.patch.object(demisto, 'debug')

    import ArcSightESMv2
    from requests.models import Response
    mock_response = Response()
    mock_response._content = mock_data_path.read_bytes()
    mock_response.status_code = 200
    mocker.patch.object(ArcSightESMv2, 'send_request', return_value=mock_response)
    debug_logs_mock = mocker.patch.object(ArcSightESMv2.demisto, 'debug')

    ArcSightESMv2.main()
    assert debug_logs_mock.call_args_list[0].startswith('Failed to parse response to JSON.\n')
    assert debug_logs_mock.call_args_list[1].startswith('Response successfully parsed after fixing invalid escape sequences')

    results = demisto.results.call_args[0][0]
    assert results['Contents']  # assert that the response was parsed successfully


def test_valid_json_response():
    valid_response = requests.Response()
    valid_response.status_code = 200
    valid_response._content = b'{"key": "value"}'
    assert parse_json_response(valid_response) == {"key": "value"}


def test_invalid_json_with_escape_sequence():
    invalid_response = requests.Response()
    invalid_response.status_code = 200
    invalid_response._content = b'{"key": "value with \\ backslash"}'
    assert parse_json_response(invalid_response) == {"key": "value with \\ backslash"}


def test_invalid_json_with_multiple_escape_sequences():
    complex_invalid_response = requests.Response()
    complex_invalid_response.status_code = 200
    complex_invalid_response._content = b'{"key": "value with \\ backslash and \\" quote"}'
    assert parse_json_response(complex_invalid_response) == {"key": 'value with \\ backslash and " quote'}


def test_invalid_json_requiring_fixing_json_string():
    broken_json_response = requests.Response()
    broken_json_response.status_code = 200
    broken_json_response._content = b'{"$": "value with "quotes" inside"}'
    assert parse_json_response(broken_json_response) == {"$": 'value with "quotes" inside'}


def test_invalid_json_requiring_fixing_json_string_with_multi_json_object():
    broken_json_response = requests.Response()
    broken_json_response.status_code = 200
    broken_json_response._content = (
        b'{"test":[{"test1": "test_val", "$": "value with "quotes" inside"},{"$": "value with "quotes" inside"}]}'
    )
    assert parse_json_response(broken_json_response) == {
        "test": [
            {"test1": "test_val", '$': 'value with "quotes" inside'},
            {'$': 'value with "quotes" inside'}
        ]
    }


def test_unfixable_json_response():
    unfixable_response = requests.Response()
    unfixable_response.status_code = 200
    unfixable_response._content = b'{"key": "value"'  # Missing closing brace
    with pytest.raises(json.JSONDecodeError):
        parse_json_response(unfixable_response)
