from datetime import datetime
import json


def load_json_file(filename):
    """
    Loads the json content and return the json object
    :param filename:
    :return:
    """
    with open("test_data/{0}".format(filename), 'r') as f:
        return json.load(f)


def test_module():
    """
    Test the basic test command for Cyble Events
    :return:
    """
    pass


def test_fetch_incidents(requests_mock):
    """
    Tests the fetch incident command

    Configures requests_mock instance to generate the appropriate fetch_incidents
    API response when the correct fetch_incidents API request is performed. Checks
    the output of the command function with the expected output.

    Uses
    :param requests_mock:
    :return:
    """

    from CybleEvents import Client, fetch_incidents

    mock_response_1 = load_json_file("dummy_fetch_incidents.json")
    mock_response_2 = load_json_file("dummy_fetch_incidents_types.json")

    requests_mock.post('https://test.com/api/v2/events/all', json=mock_response_1)
    requests_mock.get('https://test.com/api/v2/events/types', json=mock_response_2)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'token': 'some_random_token',
        'max_fetch': 1,
    }

    response = fetch_incidents(client=client, method='POST', token=args['token'], maxResults=args['max_fetch'])

    # assert the response object

    # check if the response object is a list
    assert isinstance(response, list)
    # each entry is a dict
    assert isinstance(response[0], dict)

    assert response[0]['name'] == 'Cyble Intel Alert on some_alias_2'
    assert response[0]['severity'] == 3
    assert response[0]['rawJSON'] == '{"name": "Cyble Intel Alert on some_alias_2", "cybleeventtype": "service_type_2", "severity": 3, "occurred": "2022-03-07T00:01:24.242000Z", "cybleeventid": "some_alert_id_1", "cybleeventname": "Incident of some_alias_2 type", "cybleeventbucket": "some_keywords_1", "cybleeventkeyword": "some_tag_1", "cybleeventalias": "some_alias_2"}'


def test_cyble_vision_fetch_iocs(requests_mock):
    """
    Tests the cyble_vision_fetch_iocs command

    Configures requests_mock instance to generate the appropriate cyble_vision_fetch_iocs
    API response when the correct cyble_vision_fetch_iocs API request is performed. Checks
    the output of the command function with the expected output.


    :param requests_mock:
    :return:
    """

    from CybleEvents import Client, cyble_fetch_iocs

    mock_response_1 = load_json_file("dummy_fetch_iocs.json")
    requests_mock.post('https://test.com/api/iocs', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )


    args = {
        'token': 'some_random_token',
        'max_fetch': 1,
        'start_date': datetime.today().strftime('%Y-%m-%d'),
        'end_date': datetime.today().strftime('%Y-%m-%d'),
        'from': '0',
        'limit': '10'
    }

    response = cyble_fetch_iocs(client=client, method='POST', args=args)

    assert isinstance(response, dict)

    assert response['count'] == 100
    assert isinstance(response['results'], list)

    assert isinstance(response['results'][0], dict)

    assert response['results'][0]['event_title'] == 'some_event_title'
    assert response['results'][0]['created_at'] == '2022-02-22T23:55:33.154000'
    assert response['results'][0]['modified'] == '2022-02-22T23:55:33.154000'
    assert response['results'][0]['type'] == 'some_type'
    assert response['results'][0]['indicator'] == 'some_indicator'


def test_cyble_vision_fetch_events(requests_mock):
    """
    Tests the cyble_vision_fetch_events command

    Configures requests_mock instance to generate the appropriate cyble_vision_fetch_events
    API response when the correct cyble_vision_fetch_events API request is performed. Checks
    the output of the command function with the expected output.

    :param requests_mock:
    :return:
    """

    from CybleEvents import Client, cyble_fetch_events

    mock_response_1 = load_json_file("dummy_fetch_incidents.json")
    mock_response_2 = load_json_file("dummy_fetch_incidents_types.json")

    requests_mock.post('https://test.com/api/v2/events/all', json=mock_response_1)
    requests_mock.get('https://test.com/api/v2/events/types', json=mock_response_2)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'token': 'some_random_token',
        'max_fetch': 1,
        'start_date': datetime.today().strftime('%Y-%m-%d'),
        'end_date': datetime.today().strftime('%Y-%m-%d'),
        'from': '0',
        'limit': '10',
        'order_by': 'Ascending'
    }

    response = cyble_fetch_events(client=client, method='POST', args=args)

    assert isinstance(response, list)
    assert isinstance(response[0], dict)

    assert response[0]['name'] == 'Cyble Intel Alert on some_alias_2'
    assert response[0]['cybleeventtype'] == 'service_type_2'
    assert response[0]['severity'] == 3
    assert response[0]['occurred'] == '2022-03-07T00:01:24.242000Z'
    assert response[0]['cybleeventid'] == 'some_alert_id_1'
    assert response[0]['cybleeventname'] == 'Incident of some_alias_2 type'
    assert response[0]['cybleeventbucket'] == 'some_keywords_1'
    assert response[0]['cybleeventkeyword'] == 'some_tag_1'
    assert response[0]['cybleeventalias'] == 'some_alias_2'


def test_cyble_vision_fetch_detail(requests_mock):
    """
    Tests the cyble_vision_fetch_detail command

    Configures requests_mock instance to generate the appropriate cyble_vision_fetch_detail
    API response when the correct cyble_vision_fetch_detail API request is performed. Checks
    the output of the command function with the expected output.

    :param requests_mock:
    :return:
    """

    from CybleEvents import Client, fetch_alert_details

    mock_response_1 = load_json_file("dummy_fetch_detail.json")

    requests_mock.post('https://test.com/api/v2/events/some_event_type/some_event_id', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'token': 'some_random_token',
        'event_type': 'some_event_type',
        'event_id': 'some_event_id'
    }

    response = fetch_alert_details(client=client, args=args)

    assert isinstance(response, list)
    assert isinstance(response[0], dict)

    for i, el in enumerate(response):
        assert el['id'] == i+1
        assert el['eventtitle'] == 'some_event_title_{0}'.format(i+1)
        assert el['createdat'] == '2020-06-15T07:34:20.062000'
        assert el['modified'] == 'Mar 01 2022'
        assert el['type'] == 'some_type_{0}'.format(i + 1)
        assert el['indicator'] == 'some_indicator_{0}'.format(i + 1)
        assert el['references'] == ''
        assert el['lastseenon'] == '2022-03-02'


