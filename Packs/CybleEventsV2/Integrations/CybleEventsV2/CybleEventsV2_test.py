"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
from datetime import datetime, timedelta
import pytz

import pytest

import demistomock as demisto

UTC = pytz.UTC


def util_load_json(path):
    with open("test_data/" + path, encoding='utf-8') as f:
        return json.loads(f.read())


# # # TODO: ADD HERE unit tests for every command

def test_module(requests_mock):
    """
    Test the basic test command for Cyble Events
    Returns:

    """
    from CybleEventsV2 import Client, test_response

    mock_response_1 = util_load_json("dummy_fetch_subscribed_services.json")
    requests_mock.get('https://test.com/apollo/api/v1/y/services', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    response = test_response(client, 'GET', 'https://test.com', "some_random_token")

    assert isinstance(response, str)
    assert response == 'ok'


def test_module_failure(mocker, requests_mock):
    """
    Test the basic test-module command in case of a failure.
    """
    from CybleEventsV2 import Client, test_response

    requests_mock.get('https://test.com/apollo/api/v1/y/services', json={})
    mocker.patch.object(demisto, 'error')

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    with pytest.raises(Exception) as excinfo:
        test_response(client, 'GET', 'https://test.com', "some_random_token")

    assert str(excinfo.value) == 'failed to connect'


def test_get_subscribed_services(requests_mock):
    """
    Test the module get_event_types
    :param requests_mock:
    :return:
    """
    from CybleEventsV2 import Client, fetch_subscribed_services_alert

    mock_response_1 = util_load_json("dummy_fetch_subscribed_services.json")
    requests_mock.get('https://test.com/apollo/api/v1/y/services', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )
    response = fetch_subscribed_services_alert(client, 'GET', 'https://test.com', "some_random_token").outputs
    assert isinstance(response, list)
    assert response[0]['name'] == 'name_1'


@pytest.mark.parametrize("offset", [0, 6, 7, 9, 11, 15, 21])
def test_get_iocs(requests_mock, offset):
    """
    Test the module get_event_types
    :param requests_mock:
    :return:
    """
    from CybleEventsV2 import Client, cyble_fetch_iocs

    mock_response_1 = util_load_json("dummy_fetch_iocs.json")
    requests_mock.get('https://test.com/engine/api/v2/y/iocs', json=mock_response_1)

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
        'limit': 1
    }

    url = "https://test.com/engine/api/v2/y/iocs"

    response = cyble_fetch_iocs(client, 'GET', "some_random_token", args, url).outputs

    assert isinstance(response, list)
    assert isinstance(response[0], dict)
    assert response[0]['ioc'] == 'Indicator'
    assert response[0]['ioc_type'] == 'Some IOC Type'
    assert response[0]['first_seen'] == '1722227702'
    assert response[0]['last_seen'] == '1722472568'
    assert response[0]['risk_score'] == '70'


def test_get_alert_group(requests_mock):
    """
    Test the module get_event_types
    :param requests_mock:
    :return:
    """
    from CybleEventsV2 import Client, cyble_alert_group

    mock_response_1 = util_load_json("dummy_fetch_incident_group.json")
    requests_mock.post('https://test.com/apollo/api/v1/y/alerts/groups', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    url = "https://test.com/apollo/api/v1/y/alerts/groups"

    input_params = {
        "order_by": [
            {
                "created_at": "desc"
            }
        ],
        "skip": 0,
        "take": 1,
        "include": {
            "tags": True
        }
    }

    response = cyble_alert_group(client, 'POST', "some_random_token", url, input_params).outputs

    assert isinstance(response, list)
    assert len(response) == 1


def test_get_alert(requests_mock):
    """
    Test the module get_event_types
    :param requests_mock:
    :return:
    """
    from CybleEventsV2 import Client, cyble_events

    mock_response_1 = util_load_json("dummy_fetch_incidents.json")
    requests_mock.post('https://test.com/apollo/api/v1/y/alerts', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'from': 0,
        'limit': 1,
        'start_date': '2023-04-18T00:00:00+00:00',
        'end_date': '2023-04-19T00:00:00+00:00'
    }

    url = "https://test.com/apollo/api/v1/y/alerts"

    collections = ["random_collections", "Darkweb Marketplaces", "Data Breaches", "Compromised Endpoints", "Compromised Cards"]
    incident_severity = ["Low", "Medium", "High"]

    response, next = cyble_events(client, 'POST', "some_random_token", url, args, {},
                                  False, collections, incident_severity, False)

    assert isinstance(response, list)
    assert len(response) == 1


@pytest.mark.parametrize(
    "offset,limit", [
        ('0', '1789'), ('0', '-2')
    ]
)
def test_limit_cyble_vision_fetch_detail(requests_mock, capfd, offset, limit):
    from CybleEventsV2 import Client, cyble_events

    mock_response_1 = util_load_json("dummy_fetch_incidents.json")

    requests_mock.post('https://test.com/apollo/api/v1/y/alerts', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'from': offset,
        'limit': limit,
        'start_date': datetime.now().astimezone().replace(microsecond=0).isoformat(),
        'end_date': datetime.now().astimezone().replace(microsecond=0).isoformat()
    }

    url = "https://test.com/apollo/api/v1/y/alerts"

    collections = ["random_collections", "Darkweb Marketplaces", "Data Breaches", "Compromised Endpoints", "Compromised Cards"]
    incident_severity = ["Low", "Medium", "High"]

    with capfd.disabled(), pytest.raises(ValueError,
                                         match="The limit argument should contain a positive number,"
                                               f" up to 1000, limit: {limit}"):
        cyble_events(client, 'POST', "some_random_token", url, args, {},
                     False, collections, incident_severity, True)


def test_limit_validate_input(capfd):
    from CybleEventsV2 import validate_input

    args = {
        'start_date': datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S%z"),
        'end_date': datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S%z"),
        'from': '0',
        'limit': '-1',
    }
    with capfd.disabled(), pytest.raises(ValueError,
                                         match="The limit argument should contain a positive number,"
                                               f" up to 1000, limit: {args.get('limit', '50')}"):
        validate_input(args=args)


def test_limit_validate_ioc_input(capfd):
    from CybleEventsV2 import validate_input

    args = {
        'start_date': datetime.today().strftime('%Y-%m-%d'),
        'end_date': datetime.today().strftime('%Y-%m-%d'),
        'from': '0',
        'limit': '-1',
    }
    with capfd.disabled(), pytest.raises(ValueError,
                                         match="The limit argument should contain a positive number,"
                                               f" up to 100, limit: {args.get('limit', '50')}"):
        validate_input(args=args, is_iocs=True)


def test_datecheck_validate_input(capfd):
    from CybleEventsV2 import validate_input

    args = {
        'start_date': datetime.today().strftime('%Y-%m-%d'),
        'end_date': (datetime.today() - timedelta(days=4)).strftime('%Y-%m-%d'),
        'from': '0',
        'limit': '1'
    }

    with capfd.disabled(), pytest.raises(ValueError,
                                         match=f"Start date {args.get('start_date')} cannot "
                                         f"be after end date {args.get('end_date')}"):
        validate_input(args=args, is_iocs=True)


def test_edate_validate_input(capfd):
    from CybleEventsV2 import validate_input

    args = {
        'start_date': datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S%z"),
        'end_date': (datetime.now(tz=UTC) + timedelta(days=4)).strftime("%Y-%m-%dT%H:%M:%S%z"),
        'from': '0',
        'limit': '1'
    }

    with capfd.disabled():
        with pytest.raises(ValueError) as excinfo:
            validate_input(args=args)
        assert "End date must be a date before or equal to" in str(excinfo)


def test_date_validate_input(capfd):
    from CybleEventsV2 import validate_input

    args = {
        'start_date': datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S%z"),
        'end_date': (datetime.now(tz=UTC) - timedelta(days=4)).strftime("%Y-%m-%dT%H:%M:%S%z"),
        'from': '0',
        'limit': '1'
    }

    with capfd.disabled():
        with pytest.raises(ValueError) as excinfo:
            validate_input(args=args)
        assert "cannot be after end date" in str(excinfo)


def test_offset_cyble_vision_fetch_detail(requests_mock, capfd):
    """
    Tests the cyble_vision_fetch_detail command for failure

    Configures requests_mock instance to generate the appropriate cyble_vision_fetch_detail
    API response when the correct cyble_vision_fetch_detail API request is performed. Checks
    the output of the command function with the expected output.

    :param requests_mock:
    :return:
    """

    from CybleEventsV2 import Client, cyble_events

    mock_response_1 = util_load_json("dummy_fetch_incidents.json")
    requests_mock.post('https://test.com/apollo/api/v1/y/alerts', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'from': '-1',
        'limit': 1,
        'start_date': datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S%z"),
        'end_date': datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S%z")
    }

    url = "https://test.com/apollo/api/v1/y/alerts"

    with capfd.disabled(), pytest.raises(ValueError,
                                         match=f"The parameter from has a negative value, from: {args.get('from')}'"):
        cyble_events(client, 'POST', "some_random_token", url, args, {},
                     True, [], [], True)


def test_get_alert_fetch(requests_mock):
    """
    Test the module fetch details
    :param requests_mock:
    :return:
    """
    from CybleEventsV2 import Client, cyble_events

    mock_response_1 = util_load_json("dummy_fetch_incidents.json")
    requests_mock.post('https://test.com/apollo/api/v1/y/alerts', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'from': 1,
        'limit': 1,
        'start_date': datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S%z"),
        'end_date': datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S%z")
    }

    url = "https://test.com/apollo/api/v1/y/alerts"

    response, next = cyble_events(client, 'POST', "some_random_token", url, args, {},
                                  False, [], [], False)

    assert isinstance(response, list)
    assert len(response) == 1


def test_get_alert_fetch2(requests_mock):
    """
    Test the module fetch details
    :param requests_mock:
    :return:
    """
    from CybleEventsV2 import Client, cyble_events

    mock_response_1 = util_load_json("dummy_fetch_incidents.json")
    requests_mock.post('https://test.com/apollo/api/v1/y/alerts', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'from': 1,
        'limit': 1,
        'start_date': datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S%z"),
        'end_date': datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S%z")
    }

    url = "https://test.com/apollo/api/v1/y/alerts"

    response, next = cyble_events(client, 'POST', "some_random_token", url, args, {},
                                  False, [], [], True)

    assert isinstance(response, list)
    assert len(response) == 1


def test_get_alert_output(requests_mock):
    """
    Test the module get_event_types
    :param requests_mock:
    :return:
    """
    from CybleEventsV2 import Client, cyble_events

    mock_response_1 = util_load_json("dummy_fetch_incidents.json")
    requests_mock.post('https://test.com/apollo/api/v1/y/alerts', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'from': 0,
        'limit': 1,
        'start_date': '2023-04-18T00:00:00+00:00',
        'end_date': '2023-04-19T00:00:00+00:00'
    }

    url = "https://test.com/apollo/api/v1/y/alerts"

    response, next = cyble_events(client, 'POST', "some_random_token", url, args, {},
                                  False, [], [], False)

    assert isinstance(response, list)
    assert response[0]['alert_group_id'] == '00000000-0000-0000-0000-000000000000'
    assert response[0]['event_id'] == '00000000-0000-0000-0000-000000000000'
    assert response[0]['keyword'] == 'keyword'


def test_data_alert_invalidate_date(capfd):
    from CybleEventsV2 import validate_input

    args = {
        'start_date': datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M"),
        'end_date': (datetime.now(tz=UTC) - timedelta(days=4)).strftime("%Y-%m-%dT%H:%M"),
        'from': '0',
        'limit': '1'
    }

    with capfd.disabled():
        with pytest.raises(ValueError) as excinfo:
            validate_input(args=args)
        assert "does not match format" in str(excinfo)


def test_data_alert_iocs_date(capfd):
    from CybleEventsV2 import validate_input

    args = {
        'start_date': datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M"),
        'end_date': (datetime.now(tz=UTC) - timedelta(days=4)).strftime("%Y-%m-%dT%H:%M"),
        'from': '0',
        'limit': '1'
    }

    with capfd.disabled():
        with pytest.raises(ValueError) as excinfo:
            validate_input(args=args, is_iocs=True)
        assert "unconverted data remains" in str(excinfo)


def test_get_subscribed_services_for_other_alert(requests_mock):
    """
    Test the module get_event_types
    :param requests_mock:
    :return:
    """
    from CybleEventsV2 import Client, fetch_subscribed_services_alert

    mock_response_1 = util_load_json("dummy_fetch_subscribed_services.json")
    requests_mock.get('https://test.com/apollo/api/v1/y/services', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )
    response = fetch_subscribed_services_alert(client, 'GET', 'https://test.com', "some_random_token").outputs
    assert isinstance(response, list)
    assert response[0]['name'] == 'name_1'


def test_update_incident(requests_mock):
    """
    Test the module update-remote-system
    :param requests_mock:
    :return:
    """
    from CybleEventsV2 import Client, cyble_events

    mock_response_1 = util_load_json("dummy_update_incident.json")
    requests_mock.put('https://test.com/apollo/api/v1/y/alerts', json=mock_response_1)

    client = Client(
        base_url='https://test.com',
        verify=False
    )

    args = {
        'from': 0,
        'limit': 1,
        'start_date': '2023-09-18T00:00:00+00:00',
        'end_date': '2023-09-19T00:00:00+00:00'
    }

    url = "https://test.com/apollo/api/v1/y/alerts"

    response, next = cyble_events(client, 'PUT', "some_random_token", url, args, {},
                                  False, [], [], False)

    assert isinstance(response, list)
    assert len(response) == 1
