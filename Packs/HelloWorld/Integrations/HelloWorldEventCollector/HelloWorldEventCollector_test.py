from HelloWorldEventCollector import Client, fetch_events, get_events


def test_fetch_detection_events_command():
    """
    Given:
    - fetch events command (fetches detections)

    When:
    - Running fetch-events command

    Then:
    - Ensure number of events fetched, and next run fields
    """
    first_fetch_str = '2022-12-21T03:42:05Z'
    base_url = 'https://server_url/'
    client = Client(
        base_url=base_url,
        verify=True,
        proxy=False,
    )
    last_run = {'prev_id': 1}
    next_run, events = fetch_events(
        client=client,
        last_run=last_run,
        first_fetch_time=first_fetch_str,
        alert_status="Status",
        max_events_per_fetch=1,
    )

    assert len(events) == 1
    assert next_run.get('prev_id') == 2
    assert events[0].get('id') == 2


def test_test_module_command():
    """
    Given:
    - test module command (fetches detections)

    When:
    - Pressing test button

    Then:
    - Test module passed
    """
    from HelloWorldEventCollector import test_module
    first_fetch_str = '2022-12-21T03:42:05Z'
    base_url = 'https://server_url/'
    client = Client(
        base_url=base_url,
        verify=True,
        proxy=False,
    )
    res = test_module(
        client=client,
        params={},
        first_fetch_time=first_fetch_str,
    )

    assert res == 'ok'


def test_get_events_command():
    """
    Given:
    - get_events command (fetches detections)

    When:
    - running get events command

    Then:
    - events and human readable as expected
    """
    base_url = 'https://server_url/'
    client = Client(
        base_url=base_url,
        verify=True,
        proxy=False,
    )
    events, hr = get_events(
        client=client,
        alert_status="Some Status",
        args={},
    )

    assert events[0].get('id') == 1
    assert 'Test Event' in hr.readable_output
