import demistomock as demisto
import io
import json


MOCK_PARAMS = {
    'credentials': {
        'identifier': 'TEST',
        'password': 'TEST'
    },
    'url': 'https://MOCK_URL',
    'maxFetch': '14',
}


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


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
    raw_response = util_load_json('test_data/first_page_incindents_respone.json')
    mocker.patch.object(demisto, 'getLastRun', return_value={'time': '2021-05-01-04:58:18',
                                                             'last_created_incident_timestamp': 1619834298000})
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'incidents')
    requests_mock.get('https://MOCK_URL/api/v2/tickets',
                      json=raw_response)
    requests_mock.get('https://MOCK_URL/api/v2/tickets?page=2',
                      json=[])
    fetch_incidents()
    assert len(demisto.incidents.call_args_list[0][0][0]) == 10
    # 1620826211000 was taken according to the AWS machine timestamp
    assert demisto.setLastRun.call_args_list[0][0][0] == {'last_created_incident_timestamp': 1620826211000}


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
    raw_response_first = util_load_json('test_data/first_page_incindents_respone.json')
    raw_response_second = util_load_json('test_data/second_page_incidents_response.json')

    mocker.patch.object(demisto, 'getLastRun', return_value={'time': '2021-05-01-04:58:18',
                                                             'last_created_incident_timestamp': 1619834298000})
    mocker.patch.object(demisto, 'setLastRun')
    mocker.patch.object(demisto, 'incidents')
    requests_mock.get('https://MOCK_URL/api/v2/tickets',
                      json=raw_response_first)
    requests_mock.get('https://MOCK_URL/api/v2/tickets?page=2',
                      json=raw_response_second)
    requests_mock.get('https://MOCK_URL/api/v2/tickets?page=3',
                      json=[])
    fetch_incidents()
    assert len(demisto.incidents.call_args_list[0][0][0]) == 14
    # 1620826215000 was taken according to the AWS machine timestamp
    assert demisto.setLastRun.call_args_list[0][0][0] == {'last_created_incident_timestamp': 1620826215000}
