from datetime import datetime, timedelta
import json
import pytest


def load_json_file(filename):
    """
    Loads the json content and return the json object
    :param filename:
    :return:
    """
    content = None
    with open("test_data/{0}".format(filename), 'r') as f:
        content = json.load(f)
    return content


def test_module(requests_mock):
    """
    Test the basic test command for Cyble Threat Intel
    :return:
    """
    from CybleThreatIntel import Client, get_test_response
    mock_response = load_json_file("cyble_threat_intel.json")
    requests_mock.post('https://test.com/taxii/stix-data/v21/get', json=mock_response)

    args = {
        'token': 'some_random_token',
        "page": 1,
        "limit": 1,
        "start_date": "2022-02-22",
        "end_date": "2022-02-22",
        "start_time": "00:00:00",
        "end_time": "00:00:00",
    }

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    response = get_test_response(client=client, method='POST', params=args)

    assert isinstance(response, str)
    assert response == 'ok'


def test_response_failure(requests_mock):
    """
    Test the basic test-module command in case of a failure.
    """
    from CybleThreatIntel import Client, get_test_response
    mock_response = load_json_file("cyble_threat_intel.json")
    requests_mock.post('https://test.com/taxii/stix-data/v21/get', json=mock_response)

    args = {
        "page": 1,
        "limit": 1,
        "start_date": "2022-02-22",
        "end_date": "2022-02-22",
        "start_time": "00:00:00",
        "end_time": "00:00:00",
    }

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    response = get_test_response(client=client, method='POST', params=args)

    assert isinstance(response, str)
    assert response == 'Access token missing.'


def test_module_failure(requests_mock):
    """
    Test the basic test-module command in case of a failure.
    """
    from CybleThreatIntel import Client, get_test_response
    requests_mock.post('https://test.com/taxii/stix-data/v21/get', json={})

    args = {
        'token': 'some_random_token',
        "page": 1,
        "limit": 1,
        "start_date": "2022-02-22",
        "end_date": "2022-02-22",
        "start_time": "00:00:00",
        "end_time": "00:00:00",
    }

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    response = get_test_response(client=client, method='POST', params=args)

    assert isinstance(response, str)
    assert response == 'Failed to fetch feed!!'


@pytest.mark.parametrize(
    "page,limit", [
        (1, 1), (3, 5), (5, 15), (7, 7), (9, 20)
    ]
)
def test_cyble_vision_fetch_taxii(requests_mock, page, limit):
    """
    Tests the cyble_vision_fetch_taxii command

    Configures requests_mock instance to generate the appropriate cyble_vision_fetch_taxii
    API response when the correct cyble_vision_fetch_taxii API request is performed. Checks
    the output of the command function with the expected output.

    Uses
    :param requests_mock:
    :return:
    """

    from CybleThreatIntel import Client, cyble_fetch_taxii

    mock_response = load_json_file("cyble_threat_intel.json")
    requests_mock.post('https://test.com/taxii/stix-data/v21/get', json=mock_response)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'token': 'some_random_token',
        "page": page,
        "limit": limit,
        "start_date": "2022-02-22",
        "end_date": "2022-02-22",
        "start_time": "00:00:00",
        "end_time": "00:00:00",
    }

    response = cyble_fetch_taxii(client=client, method='POST', args=args).outputs
    # assert the response object

    # check if the response object is a dict
    assert isinstance(response, dict)

    # each result entry is a list
    assert isinstance(response['result'], list)

    # check if the result entry is a dict
    assert isinstance(response['result'][0], dict)

    # assert the entries for indicator key
    assert isinstance(response['result'][0]['indicator'], dict)
    assert response['result'][0]['indicator']['type'] == 'some_type'
    assert response['result'][0]['indicator']['spec_version'] == 'some_spec_version'
    assert response['result'][0]['indicator']['id'] == 'some_id'
    assert response['result'][0]['indicator']['created'] == '2022-02-04T22:54:38Z'
    assert response['result'][0]['indicator']['modified'] == '2022-02-04T22:54:38Z'
    assert response['result'][0]['indicator']['description'] == ''
    assert response['result'][0]['indicator']['indicator_types'] == 'some_indicator_type'
    assert response['result'][0]['indicator']['pattern'] == 'some_pattern'
    assert response['result'][0]['indicator']['pattern_type'] == 'some_pattern_type'


def test_failure_cyble_vision_fetch_taxii(requests_mock):
    """
    Tests the cyble_vision_fetch_taxii command failure case

    Configures requests_mock instance to generate the appropriate cyble_vision_fetch_taxii
    API response when the correct cyble_vision_fetch_taxii API request is performed. Checks
    the output of the command function with the expected output.

    Uses
    :param requests_mock:
    :return:
    """

    from CybleThreatIntel import Client, cyble_fetch_taxii

    requests_mock.post('https://test.com/taxii/stix-data/v21/get', json={})

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'token': 'some_random_token',
        "page": 1,
        "limit": 1,
        "start_date": "2022-02-22",
        "end_date": "2022-02-22",
        "start_time": "00:00:00",
        "end_time": "00:00:00",
    }

    response = cyble_fetch_taxii(client=client, method='POST', args=args).outputs
    # assert the response object

    # check if the response object is a dict
    assert isinstance(response, dict)

    # each result entry is a list
    assert response == {}


def test_failure_fetch_taxii(requests_mock):
    """
    Tests the cyble_fetch_taxii command failure case

    Configures requests_mock instance to generate the appropriate cyble_vision_fetch_taxii
    API response when the correct cyble_vision_fetch_taxii API request is performed. Checks
    the output of the command function with the expected output.

    Uses
    :param requests_mock:
    :return:
    """

    from CybleThreatIntel import Client, cyble_fetch_taxii

    mock_response = load_json_file("cyble_threat_intel.json")
    requests_mock.post('https://test.com/taxii/stix-data/v21/get', json=mock_response)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        "page": 1,
        "limit": 1,
        "start_date": "2022-02-22",
        "end_date": "2022-02-22"
    }

    response = cyble_fetch_taxii(client=client, method='POST', args=args).outputs
    # assert the response object

    # check if the response object is a dict
    assert isinstance(response, dict)

    # each result entry is a list
    assert response['error'] == 'Invalid Token!!'


def test_fail_fetch_taxii(requests_mock):
    """
    Tests the cyble_fetch_taxii command failure case

    Configures requests_mock instance to generate the appropriate cyble_vision_fetch_taxii
    API response when the correct cyble_vision_fetch_taxii API request is performed. Checks
    the output of the command function with the expected output.

    Uses
    :param requests_mock:
    :return:
    """

    from CybleThreatIntel import Client, cyble_fetch_taxii

    requests_mock.post('https://test.com/taxii/stix-data/v21/get', json={})

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    response = cyble_fetch_taxii(client=client, method='POST', args={}).outputs
    # assert the response object

    # check if the response object is a dict
    assert isinstance(response, dict)

    # each result entry is a list
    assert response['error'] == 'Invalid Token!!'


def test_failure_cyble_fetch_taxii(requests_mock):
    """
    Tests the cyble_vision_fetch_taxii command failure case

    Configures requests_mock instance to generate the appropriate cyble_vision_fetch_taxii
    API response when the correct cyble_vision_fetch_taxii API request is performed. Checks
    the output of the command function with the expected output.

    Uses
    :param requests_mock:
    :return:
    """

    from CybleThreatIntel import Client, cyble_fetch_taxii

    requests_mock.post('https://test.com/taxii/stix-data/v21/get', json={})

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    response = cyble_fetch_taxii(client=client, method='POST', args={}).outputs
    # assert the response object

    # check if the response object is a dict
    assert isinstance(response, dict)

    # each result entry is a list
    assert response['error'] == 'Invalid Token!!'


def test_page_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        'start_date': datetime.today().strftime('%Y-%m-%d'),
        'end_date': datetime.today().strftime('%Y-%m-%d'),
        'page': '-1',
        'limit': '1',
    }
    with capfd.disabled():
        with pytest.raises(ValueError, match=f"Parameter should be positive number, page: {args.get('page')}"):
            validate_input(args=args)


def test_limit_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        'start_date': datetime.today().strftime('%Y-%m-%d'),
        'end_date': datetime.today().strftime('%Y-%m-%d'),
        'page': '1',
        'limit': '40',
    }
    with capfd.disabled():
        with pytest.raises(ValueError, match=f"Limit should be positive number upto 20, limit: {args.get('limit', 0)}"):
            validate_input(args=args)


def test_sdate_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        'start_date': (datetime.today() + timedelta(days=4)).strftime('%Y-%m-%d'),
        'end_date': datetime.today().strftime('%Y-%m-%d'),
        'page': '1',
        'limit': '1'
    }
    with capfd.disabled():
        with pytest.raises(ValueError,
                           match=f"Start date must be a date before or equal to {datetime.today().strftime('%Y-%m-%d')}"):
            validate_input(args=args)


def test_edate_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        'start_date': datetime.today().strftime('%Y-%m-%d'),
        'end_date': (datetime.today() + timedelta(days=4)).strftime('%Y-%m-%d'),
        'page': '1',
        'limit': '1'
    }
    with capfd.disabled():
        with pytest.raises(ValueError,
                           match=f"End date must be a date before or equal to {datetime.today().strftime('%Y-%m-%d')}"):
            validate_input(args=args)


def test_date_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        'start_date': datetime.today().strftime('%Y-%m-%d'),
        'end_date': (datetime.today() - timedelta(days=4)).strftime('%Y-%m-%d'),
        'page': '1',
        'limit': '1'
    }

    with capfd.disabled():
        with pytest.raises(ValueError,
                           match=f"Start date {args.get('start_date')} cannot be after end date {args.get('end_date')}"):
            validate_input(args=args)


def test_idate_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        'start_date': '2001-18-12',
        'end_date': datetime.today().strftime('%Y-%m-%d')
    }

    with capfd.disabled():
        with pytest.raises(ValueError, match="Invalid date format received"):
            validate_input(args=args)


def test_time_validate_input(capfd):
    from CybleThreatIntel import validate_input

    args = {
        'start_date': datetime.today().strftime('%Y-%m-%d'),
        'end_date': datetime.today().strftime('%Y-%m-%d'),
        'page': '1',
        'limit': '1',
        'start_time': '12:34:23',
        'end_time': '16:83:45'
    }

    with capfd.disabled():
        with pytest.raises(ValueError, match="Invalid time format received"):
            validate_input(args=args)
