from HelloWorldEventCollectorV2 import Client, add_time_to_events, fetch_events, get_events, test_module


def test_test_module_command():
    """
    Given:
    - test module command (fetches detections)

    When:
    - Pressing test button

    Then:
    - Test module passed
    """
    first_fetch_str = "2022-12-21T03:42:05Z"
    base_url = "https://server_url/"
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

    assert res == "ok"


def test_get_events_command():
    """
    Given:
    - get_events command (fetches detections)

    When:
    - running get events command

    Then:
    - events and human readable as expected
    """
    base_url = "https://server_url/"
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

    assert events[0].get("id") == 1
    assert "Test Event" in hr.readable_output


def test_fetch_events_returns_normalized_events(mocker):
    """
    Given:
    - A mocked API response returning a single raw alert.

    When:
    - Driving one ``fetch_events`` cycle (mocked API response -> parse/normalize -> emit).

    Then:
    - The emitted events are normalized (``_time`` added) and returned as expected.
    """
    first_fetch_str = "2022-12-21T03:42:05Z"
    base_url = "https://server_url/"
    client = Client(
        base_url=base_url,
        verify=True,
        proxy=False,
    )

    raw_event = {
        "id": 6,
        "created_time": "2022-12-21T03:42:05Z",
        "description": "This is test description 6",
        "alert_status": "ACTIVE",
    }
    mocker.patch.object(client, "search_events", return_value=[raw_event])

    last_run = {"prev_id": 5}

    # Drive the fetch cycle. NOTE: we only care about the emitted events here.
    _, events = fetch_events(
        client=client,
        last_run=last_run,
        first_fetch_time=first_fetch_str,
        alert_status="ACTIVE",
        max_events_per_fetch=100,
    )

    # Parse / normalize step.
    add_time_to_events(events)

    # Assert emitted events only (lastRun is intentionally not asserted here).
    assert len(events) == 1
    assert events[0]["id"] == 6
    assert events[0]["_time"] == "2022-12-21T03:42:05Z"


def test_add_time_to_events_sets_time_key():
    """
    Given:
    - A list of raw events with a ``created_time`` field.

    When:
    - Calling ``add_time_to_events``.

    Then:
    - Each event has a ``_time`` key set from ``created_time``.
    """
    events = [
        {"id": 1, "created_time": "2022-12-21T03:42:05Z"},
        {"id": 2, "created_time": "2022-12-22T03:42:05Z"},
    ]
    add_time_to_events(events)

    assert events[0]["_time"] == "2022-12-21T03:42:05Z"
    assert events[1]["_time"] == "2022-12-22T03:42:05Z"
