import json
import io
from datetime import datetime


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_add_time_key_to_events():
    """
       Given:
           - list of events
       When:
           - Calling add_time_key_to_events
       Then:
           - Ensure the _time key is added to the events
       """
    from DigitalGuardianARCEventCollector import add_time_to_events

    events = util_load_json('test_data/events.json')
    add_time_to_events(events)

    assert events[0]['_time'] == "2023-05-23T06:56:39Z"
    assert events[1]['_time'] == "2023-05-23T11:53:11Z"


def test_get_raw_events_command(mocker):
    """
    Given:
        - Digital Guardian ARC client and number of days to get events
    When:
        - Calling get_raw_events command, this command is called by get_events and fetch_incidents to get the raw
          events before they are parsed
    Then:
        - Ensure the events are returned as expected
    """
    from DigitalGuardianARCEventCollector import Client, get_raw_events

    raw_events = util_load_json(f'test_data/events_mock_request.json')
    mocker.patch.object(Client, 'get_token', return_value='token')
    mocker.patch.object(Client, 'get_events', return_value=raw_events)
    days = 7
    client = Client(verify=False, proxy=False, auth_url="example.com", gateway_url="test.com", client_id="11",
                    client_secret="22", export_profile="33")
    events = get_raw_events(client, days)

    mock_events = util_load_json('test_data/events.json')

    assert events == mock_events


def test_get_events_command(mocker):
    """
    Given:
        - Digital Guardian ARC client and limit of events to get
    When:
        - Calling get_events command, which will run after the get_raw_events and will return results according to the
          limit that was provided
    Then:
        - Ensure the events are returned as expected
    """
    from DigitalGuardianARCEventCollector import Client, get_events

    raw_events = util_load_json(f'test_data/events_mock_request.json')
    mocker.patch.object(Client, 'get_token', return_value='aaa')
    mocker.patch.object(Client, 'get_events', return_value=raw_events)

    args = {"limit": 1, "days": 7}
    client = Client(verify=False, proxy=False, auth_url="example.com", gateway_url="test.com", client_id="11",
                    client_secret="22", export_profile="33")
    events, _ = get_events(client, args)

    mock_events = util_load_json('test_data/events_mock_1_response.json')

    assert events == mock_events


def test_fetch_events_command(mocker):
    """
        Given:
            - DigitalGuardianARC client and max_fetch, last_run and first_fetch_time
        When:
            - Calling fetch_events_command
        Then:
            - Ensure the events are returned as expected and the next_run is as expected
    """
    from DigitalGuardianARCEventCollector import Client, fetch_events
    events = util_load_json('test_data/events.json')
    mocker.patch("DigitalGuardianARCEventCollector.get_raw_events", return_value=events)

    client = Client(verify=False, proxy=False, auth_url="example.com", gateway_url="test.com", client_id="11",
                    client_secret="22", export_profile="33")
    next_run, events = fetch_events(client, limit=2, last_run={}, first_fetch_time={})

    mock_events = util_load_json('test_data/events.json')
    today = datetime.now()
    response_date = datetime.strptime('2023-05-23 11:53:11', '%Y-%m-%d %H:%M:%S')
    days = (today - response_date).days + 1
    assert events == mock_events
    assert next_run == {'start_time': '2023-05-23 11:53:11', 'days': days, 'last_id': 'c742c377-b429-428a-b0c9-515cbbf143be'}