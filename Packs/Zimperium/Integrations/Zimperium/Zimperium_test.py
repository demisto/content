import pytest
from Zimperium import Client, events_search, users_search, user_get_by_id, devices_search, device_get_by_id, \
    devices_get_last_updated, app_classification_get, file_reputation, fetch_incidents, report_get
from test_data.response_constants import RESPONSE_SEARCH_EVENTS, RESPONSE_SEARCH_USERS, RESPONSE_USER_GET_BY_ID, \
    RESPONSE_SEARCH_DEVICES, RESPONSE_DEVICE_GET_BY_ID, RESPONSE_APP_CLASSIFICATION_GET, \
    RESPONSE_MULTIPLE_APP_CLASSIFICATION_GET, RESPONSE_GET_LAST_UPDATED_DEVICES, RESPONSE_REPORT_GET_ITUNES_ID, \
    RESPONSE_MULTIPLE_EVENTS_FETCH
from test_data.result_constants import EXPECTED_SEARCH_EVENTS, EXPECTED_SEARCH_USERS, EXPECTED_USER_GET_BY_ID, \
    EXPECTED_SEARCH_DEVICES, EXPECTED_DEVICE_GET_BY_ID, EXPECTED_GET_LAST_UPDATED_DEVICES, \
    EXPECTED_APP_CLASSIFICATION_GET, EXPECTED_MULTIPLE_APP_CLASSIFICATION_GET, EXPECTED_REPORT_GET_ITUNESID


@pytest.mark.parametrize('command, args, http_response, context', [
    (events_search, {'query': 'eventId==*', 'size': '10', 'page': '0', 'verbose': 'true'}, RESPONSE_SEARCH_EVENTS,
     EXPECTED_SEARCH_EVENTS),
    (users_search, {'query': 'objectId==*', 'size': '10', 'page': '0'}, RESPONSE_SEARCH_USERS, EXPECTED_SEARCH_USERS),
    (user_get_by_id, {'object_id': '1B9182C7-8C12-4499-ADF0-A338DEFDFC33'}, RESPONSE_USER_GET_BY_ID,
     EXPECTED_USER_GET_BY_ID),
    (devices_search, {'query': 'deviceId==*', 'size': '10', 'page': '0'}, RESPONSE_SEARCH_DEVICES,
     EXPECTED_SEARCH_DEVICES),
    (device_get_by_id, {'zdid': "87a587de-283f-48c9-9ff2-047c8b025b6d"}, RESPONSE_DEVICE_GET_BY_ID,
     EXPECTED_DEVICE_GET_BY_ID),
    (devices_get_last_updated, {'from_last_update': "5 days"}, RESPONSE_GET_LAST_UPDATED_DEVICES,
     EXPECTED_GET_LAST_UPDATED_DEVICES),
    (app_classification_get, {'app_hash': "aad9b2fd4606467f06931d72048ee1dff137cbc9b601860a88ad6a2c092"},
     RESPONSE_APP_CLASSIFICATION_GET, EXPECTED_APP_CLASSIFICATION_GET),
    (app_classification_get, {'app_name': "Duo"},
     RESPONSE_MULTIPLE_APP_CLASSIFICATION_GET, EXPECTED_MULTIPLE_APP_CLASSIFICATION_GET),
    (report_get, {'itunes_id': '331177714'}, RESPONSE_REPORT_GET_ITUNES_ID, EXPECTED_REPORT_GET_ITUNESID),
])
def test_zimperium_commands(command, args, http_response, context, mocker):
    """Unit test
    Given
    - demisto args
    - raw response of the http request
    When
    - mock the http request result
    Then
    - convert the result to human readable table
    - create the context
    - validate the expected_result and the created context
    """
    client = Client(base_url="https://domain.zimperium.com/", api_key="api_key", verify=False)
    mocker.patch.object(Client, '_http_request', return_value=http_response)
    command_results = command(client, args)
    assert command_results.outputs == context


def test_file_reputation(mocker):
    """Unit test
    Given
    - file reputation command
    - command args
    - command raw response
    When
    - mock the Client's http_request.
    Then
    - run the file reputation command using the Client
    Validate The contents of the outputs and indicator of the results
    """
    client = Client(base_url="https://domain.zimperium.com/", api_key="api_key", verify=False)
    mocker.patch.object(Client, '_http_request', return_value=RESPONSE_APP_CLASSIFICATION_GET)
    command_results_list = file_reputation(client,
                                           args={'file': "aad9b2fd4606467f06931d72048ee1dff137cbc9b601860a88ad6a2c092"})

    assert command_results_list[0].indicator.dbot_score.score == 1


def test_file_reputation_404(mocker):
    """Unit test
    Given
    - file reputation command
    - command args
    - command raw response
    When
    - Sending HTTP request and getting 404 status code (not found)
    Then
    - run the file reputation command using the Client
    - Ensure we set the file reputation as unknown
    """
    client = Client(base_url="https://domain.zimperium.com/", api_key="api_key", verify=False)

    def error_404_mock(message, error):
        raise Exception('Error in API call [404]')

    mocker.patch('Zimperium.Client.app_classification_get_request', side_effect=error_404_mock)

    command_results_list = file_reputation(client,
                                           args={'file': "aad9b2fd4606467f06931d72048ee1dff137cbc9b601860a88ad6a2c092"})
    assert command_results_list[0].indicator.dbot_score.score == 0


def test_fetch_incidents(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's http_request.
    Then
    - run the fetch incidents command using the Client
    Validate The length of the results and the incident name.
    """
    client = Client(base_url="https://domain.zimperium.com/", api_key="api_key", verify=False)
    mocker.patch.object(Client, '_http_request', return_value=RESPONSE_MULTIPLE_EVENTS_FETCH)
    _, incidents = fetch_incidents(client, last_run={}, fetch_query='', first_fetch_time='3 days', max_fetch='50')
    assert len(incidents) == 14
    assert incidents[0].get('name') == "Detected network scan after connecting to Free Wi-Fi. No active attacks were" \
                                       " detected and this network will continue to be monitored. It is safe to" \
                                       " continue to use this network."


def test_fetch_incidents_last_event_ids(mocker):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the last_event_ids and time.
    - mock the Client's http_request.
    Then
    - run the fetch incidents command using the Client
    Validate that no incidents will be returned.
    """
    client = Client(base_url="https://domain.zimperium.com/", api_key="api_key", verify=False)
    mocker.patch.object(Client, '_http_request', return_value=RESPONSE_MULTIPLE_EVENTS_FETCH)
    last_run = {
        'time': "whatever",
        'last_event_ids': [
            '421931cc-13bf-422a-890b-9958011e4926',
            '239be3f7-ead8-4157-b24c-35590811ca19',
            '102065eb-7ffa-4a70-b35f-bc8ca655f9ee',
            '431638cf-21fc-4fba-86b2-0e2a4850705b',
            'bef068eb-5482-469c-990a-5ea363e029a0',
            'c37d7379-589e-4976-8cf2-6f2876ba7e6a',
            '4f1a77cf-fb76-4753-b09b-422fa8a9e102',
            '4a688920-372d-45b6-934d-284d5ecacb29',
            '22b960e7-554a-413a-bcbf-2da75bbb2731',
            '5f9609a6-974c-4c0d-b007-7934ddf76cff',
            '461d1b55-53f2-4b89-b337-c24367b525ef',
            '55a43106-9c1c-47e2-9f9f-ce212304f4c0',
            '7dc89a3d-6fd0-4090-ac4c-f19e33402576',
            'e696ad05-32d5-43e8-95c3-5060b0ee468e',
        ]
    }
    _, incidents = fetch_incidents(client, last_run=last_run, fetch_query='', first_fetch_time='3 days', max_fetch='50')
    assert len(incidents) == 0
