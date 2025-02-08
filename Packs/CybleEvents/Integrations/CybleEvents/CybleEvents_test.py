from datetime import datetime, timedelta
import demistomock as demisto
import json
import pytest


def load_json_file(filename):
    """
    Loads the json content and return the json object
    :param filename:
    :return:
    """
    with open(f"test_data/{filename}") as f:
        return json.load(f)


def test_module(requests_mock):
    """
    Test the basic test command for Cyble Events
    :return:
    """
    from CybleEvents import Client, get_test_response

    mock_response_1 = load_json_file("dummy_fetch_incidents_types.json")
    requests_mock.post('https://test.com/api/v2/events/types', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    response = get_test_response(client=client, method='POST', token="some_random_token")

    assert isinstance(response, str)
    assert response == 'ok'


def test_module_failure(mocker, requests_mock):
    """
    Test the basic test-module command in case of a failure.
    """
    from CybleEvents import Client, get_test_response

    requests_mock.post('https://test.com/api/v2/events/types', json={})
    mocker.patch.object(demisto, 'error')

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    response = get_test_response(client=client, method='POST', token="some_random_token")

    assert isinstance(response, str)
    assert response == 'fail'


def test_get_event_types(requests_mock):
    """
    Test the module get_event_types
    :param requests_mock:
    :return:
    """
    from CybleEvents import Client, get_event_types

    mock_response_1 = load_json_file("dummy_fetch_incidents_types.json")
    requests_mock.post('https://test.com/api/v2/events/types', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )
    response = get_event_types(client=client, method='POST', token='some_random_token')

    assert isinstance(response, dict)
    assert len(response) == 3


def test_format_incidents(requests_mock):
    """
    Test the format_incident module
    :param requests_mock:
    :return:
    """
    from CybleEvents import Client, format_incidents, get_event_types

    mock_response_1 = load_json_file("dummy_fetch_incidents.json")
    mock_response_2 = load_json_file("dummy_fetch_incidents_types.json")

    requests_mock.post('https://test.com/api/v2/events/all', json=mock_response_1)
    requests_mock.get('https://test.com/api/v2/events/types', json=mock_response_2)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    eTypes = get_event_types(client, 'GET', mock_response_2)
    response = format_incidents(mock_response_1.get('data', {}).get('results'), eTypes)

    assert isinstance(response, list)
    assert isinstance(response[0], dict)
    assert response[0]['eventtype'] == 'service_type_2'
    assert response[0]['eventid'] == 'some_alert_id_1'
    assert response[0]['cybleeventsbucket'] == 'some_keywords_1'
    assert response[0]['cybleeventskeyword'] == 'some_tag_1'
    assert response[0]['cybleeventsalias'] == 'some_alias_2'


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
    assert response[0]['severity'] == 2
    assert response[0]['rawJSON'] == '{"name": "Cyble Intel Alert on some_alias_2", ' \
                                     '"eventtype": "service_type_2", "severity": 2, ' \
                                     '"occurred": "2022-03-07T00:01:24.242000Z", ' \
                                     '"eventid": "some_alert_id_1", "cybleeventsname": ' \
                                     '"Incident of some_alias_2 type", "cybleeventsbucket": ' \
                                     '"some_keywords_1", "cybleeventskeyword": "some_tag_1", ' \
                                     '"cybleeventsalias": "some_alias_2"}'


@pytest.mark.parametrize("offset", [0, 6, 7, 9, 11, 15, 21])
def test_cyble_vision_fetch_iocs(requests_mock, offset):
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
        'from': offset,
        'limit': '10'
    }

    response = cyble_fetch_iocs(client=client, method='POST', args=args).outputs

    assert isinstance(response, dict)

    assert response['count'] == 100
    assert isinstance(response['results'], list)

    assert isinstance(response['results'][0], dict)

    assert response['results'][0]['event_title'] == 'some_event_title'
    assert response['results'][0]['created_at'] == '2022-02-22T23:55:33.154000'
    assert response['results'][0]['modified'] == '2022-02-22T23:55:33.154000'
    assert response['results'][0]['type'] == 'some_type'
    assert response['results'][0]['indicator'] == 'some_indicator'


def test_cyble_vision_fetch_alerts(requests_mock):
    """
    Tests the cyble_vision_fetch_alerts command

    Configures requests_mock instance to generate the appropriate cyble_vision_fetch_alerts
    API response when the correct cyble_vision_fetch_alerts API request is performed. Checks
    the output of the command function with the expected output.

    :param requests_mock:
    :return:
    """

    from CybleEvents import Client, cyble_fetch_alerts

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

    response = cyble_fetch_alerts(client=client, method='POST', args=args).outputs

    assert isinstance(response, list)
    assert isinstance(response[0], dict)

    assert response[0]['name'] == 'Cyble Intel Alert on some_alias_2'
    assert response[0]['eventtype'] == 'service_type_2'
    assert response[0]['severity'] == 2
    assert response[0]['occurred'] == '2022-03-07T00:01:24.242000Z'
    assert response[0]['eventid'] == 'some_alert_id_1'
    assert response[0]['cybleeventsname'] == 'Incident of some_alias_2 type'
    assert response[0]['cybleeventsbucket'] == 'some_keywords_1'
    assert response[0]['cybleeventskeyword'] == 'some_tag_1'
    assert response[0]['cybleeventsalias'] == 'some_alias_2'


@pytest.mark.parametrize(
    "eID,eType", [
        ('type1', 'id1'), ('type2', 'id2'), ('some_event_type', 'some_event_id'), ('new_event_type', 'new_event_id')
    ]
)
def test_cyble_vision_fetch_detail(requests_mock, eID, eType):
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

    requests_mock.post(f'https://test.com/api/v2/events/{eType}/{eID}', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'token': 'some_random_token',
        'event_type': eType,
        'event_id': eID
    }

    response = fetch_alert_details(client=client, args=args).outputs

    assert isinstance(response, dict)
    assert isinstance(response['events'], list)

    for i, el in enumerate(response['events']):
        assert el['id'] == i + 1
        assert el['eventtitle'] == f'some_event_title_{i + 1}'
        assert el['createdat'] == '2020-06-15T07:34:20.062000'
        assert el['modified'] == 'Mar 01 2022'
        assert el['type'] == f'some_type_{i + 1}'
        assert el['indicator'] == f'some_indicator_{i + 1}'
        assert el['references'] == ''
        assert el['lastseenon'] == '2022-03-02'


@pytest.mark.parametrize(
    "offset,limit", [
        ('0', '-2'), ('0', '1289')
    ]
)
def test_limit_cyble_vision_fetch_detail(requests_mock, capfd, offset, limit):
    """
    Tests the cyble_vision_fetch_detail command for failure

    Configures requests_mock instance to generate the appropriate cyble_vision_fetch_detail
    API response when the correct cyble_vision_fetch_detail API request is performed. Checks
    the output of the command function with the expected output.

    :param requests_mock:
    :return:
    """
    from CybleEvents import Client, fetch_alert_details

    mock_response_1 = load_json_file("dummy_fetch_detail.json")

    requests_mock.post('https://test.com/api/v2/events/eType/eID', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'token': 'some_random_token',
        'event_type': 'eType',
        'event_id': 'eID',
        'from': offset,
        'limit': limit
    }

    with capfd.disabled(), pytest.raises(ValueError,
                                         match=f"Limit should a positive number up to 1000, limit: {limit}"):
        fetch_alert_details(client=client, args=args)


def test_offset_cyble_vision_fetch_detail(requests_mock, capfd):
    """
    Tests the cyble_vision_fetch_detail command for failure

    Configures requests_mock instance to generate the appropriate cyble_vision_fetch_detail
    API response when the correct cyble_vision_fetch_detail API request is performed. Checks
    the output of the command function with the expected output.

    :param requests_mock:
    :return:
    """
    from CybleEvents import Client, fetch_alert_details

    mock_response_1 = load_json_file("dummy_fetch_detail.json")

    requests_mock.post('https://test.com/api/v2/events/eType/eID', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'token': 'some_random_token',
        'event_type': 'eType',
        'event_id': 'eID',
        'from': '-1',
        'limit': 1
    }

    with capfd.disabled(), pytest.raises(ValueError,
                                         match="Parameter having negative value, from: -1'"):
        fetch_alert_details(client=client, args=args)


def test_etype_cyble_vision_fetch_detail(requests_mock, capfd):
    """
    Tests the cyble_vision_fetch_detail command for failure

    Configures requests_mock instance to generate the appropriate cyble_vision_fetch_detail
    API response when the correct cyble_vision_fetch_detail API request is performed. Checks
    the output of the command function with the expected output.

    :param requests_mock:
    :return:
    """
    from CybleEvents import Client, fetch_alert_details

    mock_response_1 = load_json_file("dummy_fetch_detail.json")
    requests_mock.post('https://test.com/api/v2/events/eType/eID', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'token': 'some_random_token',
        'event_id': 'eID'
    }

    with capfd.disabled(), pytest.raises(ValueError,
                                         match="Event Type not specified"):
        fetch_alert_details(client=client, args=args)


def test_eid_cyble_vision_fetch_detail(requests_mock, capfd):
    """
    Tests the cyble_vision_fetch_detail command for failure

    Configures requests_mock instance to generate the appropriate cyble_vision_fetch_detail
    API response when the correct cyble_vision_fetch_detail API request is performed. Checks
    the output of the command function with the expected output.

    :param requests_mock:
    :return:
    """
    from CybleEvents import Client, fetch_alert_details

    mock_response_1 = load_json_file("dummy_fetch_detail.json")
    requests_mock.post('https://test.com/api/v2/events/eType/eID', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'token': 'some_random_token',
        'event_type': 'eType'
    }

    with capfd.disabled(), pytest.raises(ValueError,
                                         match="Event ID not specified"):
        fetch_alert_details(client=client, args=args)


def test_validate_input(capfd):
    from CybleEvents import validate_input

    args = {
        'start_date': datetime.today().strftime('%Y-%m-%d'),
        'end_date': datetime.today().strftime('%Y-%m-%d'),
        'from': '-1',
        'limit': '1',
    }
    with capfd.disabled(), pytest.raises(ValueError, match=f"Parameter having negative value, from: {args.get('from')}"):
        validate_input(args=args)


def test_limit_validate_input(capfd):
    from CybleEvents import validate_input

    args = {
        'start_date': datetime.today().strftime('%Y/%m/%d'),
        'end_date': datetime.today().strftime('%Y/%m/%d'),
        'from': '0',
        'limit': '-1',
    }
    with capfd.disabled():
        with pytest.raises(ValueError, match=f"Limit should a positive number upto 50, limit: {args.get('limit', '50')}"):
            validate_input(args=args)


def test_sdate_validate_input(capfd):
    from CybleEvents import validate_input

    args = {
        'start_date': (datetime.today() + timedelta(days=4)).strftime('%Y/%m/%d'),
        'end_date': datetime.today().strftime('%Y/%m/%d'),
        'from': '0',
        'limit': '1'
    }
    with capfd.disabled(), pytest.raises(
        ValueError,
        match=f"Start date must be a date before or equal to {datetime.today().strftime('%Y/%m/%d')}",
    ):
        validate_input(args=args)


def test_edate_validate_input(capfd):
    from CybleEvents import validate_input

    args = {
        'start_date': datetime.today().strftime('%Y/%m/%d'),
        'end_date': (datetime.today() + timedelta(days=4)).strftime('%Y/%m/%d'),
        'from': '0',
        'limit': '1'
    }
    with capfd.disabled(), pytest.raises(
        ValueError,
        match=f"End date must be a date before or equal to {datetime.today().strftime('%Y/%m/%d')}",
    ):
        validate_input(args=args)


def test_date_validate_input(capfd):
    from CybleEvents import validate_input

    args = {
        'start_date': datetime.today().strftime('%Y/%m/%d'),
        'end_date': (datetime.today() - timedelta(days=4)).strftime('%Y/%m/%d'),
        'from': '0',
        'limit': '1'
    }

    with capfd.disabled(), pytest.raises(
        ValueError,
        match=f"Start date {args.get('start_date')} cannot be after end date {args.get('end_date')}",
    ):
        validate_input(args=args)


def test_datecheck_validate_input(capfd):
    from CybleEvents import validate_input

    args = {
        'start_date': datetime.today().strftime('%Y-%m-%d'),
        'end_date': (datetime.today() - timedelta(days=4)).strftime('%Y-%m-%d'),
        'from': '0',
        'limit': '1'
    }

    with capfd.disabled(), pytest.raises(
        ValueError,
        match=f"Start date {args.get('start_date')} cannot be after end date {args.get('end_date')}",
    ):
        validate_input(args=args, is_iocs=True)
