import json
import io


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

    raw_events = util_load_json('test_data/events_mock_request.json')
    mocker.patch.object(Client, 'get_token', return_value='token')
    mocker.patch.object(Client, 'get_events', return_value=raw_events)
    client = Client(verify=False, proxy=False, auth_url="example.com", gateway_url="test.com", base_url="exmpt.com",
                    client_id="11", client_secret="22", export_profile="33")
    events = get_raw_events(client, None)

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
    from DigitalGuardianARCEventCollector import Client, get_events_command

    raw_events = util_load_json('test_data/events_mock_request.json')
    mocker.patch.object(Client, 'get_token', return_value='aaa')
    mocker.patch.object(Client, 'get_events', return_value=raw_events)

    args = {"limit": 1}
    client = Client(verify=False, proxy=False, auth_url="example.com", gateway_url="test.com", base_url="exmpt.com",
                    client_id="11", client_secret="22", export_profile="33")
    events, _ = get_events_command(client, args)

    expected_events = util_load_json('test_data/events_mock_1_response.json')

    assert events == expected_events


def test_create_events_for_push():
    """
        Given:
            - Digital Guardian events list from API response, last_time, list of id's and limit
        When:
            - Calling create_events_for_push command, which will run after the get_raw_events in fetch events function
              and will return results according to the limit that was provided
        Then:
            - Ensure the events, id_list and last_time are returned as expected
    """
    from DigitalGuardianARCEventCollector import create_events_for_push

    events = util_load_json('test_data/events_for_create_and_push.json')
    events_result = util_load_json('test_data/results_for_create_and_push.json')

    last_time = None
    id_list = []
    limit = 3
    event_list, l_time, ids = create_events_for_push(events, last_time, id_list, limit)

    assert ids == ['c742c377-b429-428a-b0c9-515cbbf143ae']
    assert l_time == '2023-04-23 11:53:11'
    assert event_list == events_result


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

    client = Client(verify=False, proxy=False, auth_url="example.com", gateway_url="test.com", base_url="exmpt.com",
                    client_id="11", client_secret="22", export_profile="33")
    next_run, events = fetch_events(client, limit=2, last_run={})

    mock_events = util_load_json('test_data/events.json')
    assert events == mock_events
    assert next_run == {'start_time': '2023-05-23 11:53:11',
                        'id_list': ['1dc3c1fa-5474-4fc0-a7c3-74ff42d28e5e', 'c742c377-b429-428a-b0c9-515cbbf143be']}
