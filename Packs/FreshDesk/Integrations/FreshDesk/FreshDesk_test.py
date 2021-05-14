import demistomock as demisto
import pytest
from test_data.response_constants import RESPONSE_SECOND_PAGE_INCIDENTS, RESPONSE_FIRST_PAGE_INCIDENTS

MOCK_PARAMS = {
    'credentials': {
        'identifier': 'TEST',
        'password': 'TEST'
    },
    'url': 'https://MOCK_URL',
    'maxFetch': '14',
}


def test_fetch_incidents_no_pagination(mocker, requests_mock):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the fetch incidents command using the Client
    Validate the length of the results.
    Validate the incident name
    Validate that the severity is low (1)
    """

    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    from FreshDesk import fetch_incidents

    mocker.patch.object(demisto, 'getLastRun', return_value={'time': '2021-05-01-04:58:18'})
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'incidents')
    requests_mock.get('https://MOCK_URL/api/v2/tickets',
                      json=RESPONSE_FIRST_PAGE_INCIDENTS)
    requests_mock.get('https://MOCK_URL/api/v2/tickets?page=2',
                      json=[])
    fetch_incidents()
    assert len(demisto.incidents.call_args_list[0][0][0]) == 10
    assert demisto.setLastRun.call_args_list[0][0][0] == {'last_created_incident_timestamp': 1620815411000}


def test_fetch_incidents_with_pagination(mocker, requests_mock):
    """Unit test
    Given
    - fetch incidents command
    - command args
    - command raw response
    When
    - mock the Client's send_request.
    Then
    - run the fetch incidents command using the Client
    Validate the length of the results.
    Validate the incident name
    Validate that the severity is low (1)
    """

    mocker.patch.object(demisto, 'params', return_value=MOCK_PARAMS)
    from FreshDesk import fetch_incidents

    mocker.patch.object(demisto, 'getLastRun', return_value={'time': '2021-05-01-04:58:18'})
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'incidents')
    requests_mock.get('https://MOCK_URL/api/v2/tickets',
                      json=RESPONSE_FIRST_PAGE_INCIDENTS)
    requests_mock.get('https://MOCK_URL/api/v2/tickets?page=2',
                      json=RESPONSE_SECOND_PAGE_INCIDENTS)
    requests_mock.get('https://MOCK_URL/api/v2/tickets?page=3',
                      json=[])
    fetch_incidents()
    assert len(demisto.incidents.call_args_list[0][0][0]) == 14
    assert demisto.setLastRun.call_args_list[0][0][0] == {'last_created_incident_timestamp': 1620815415000}
