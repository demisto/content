from HelloWorldEventCollectorV2 import Client, add_time_to_events, fetch_events, get_events


def test_fetch_detection_events_command():
    """
    Given:
    - fetch events command (fetches detections)

    When:
    - Running fetch-events command

    Then:
    - Ensure number of events fetched, and next run fields
    """
    first_fetch_str = "2022-12-21T03:42:05Z"
    base_url = "https://server_url/"
    client = Client(
        base_url=base_url,
        verify=True,
        proxy=False,
    )
    last_run = {"prev_id": 1}
    next_run, events = fetch_events(
        client=client,
        last_run=last_run,
        first_fetch_time=first_fetch_str,
        alert_status="Status",
        max_events_per_fetch=1,
    )

    assert len(events) == 1
    assert next_run.get("prev_id") == 2
    assert events[0].get("id") == 2


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


def test_fetch_events_full_cycle(mocker):
    """
    Given:
    - A mocked API response returning a single raw alert.

    When:
    - Driving one complete ``fetch_events`` cycle end to end
      (mocked API response -> parse/normalize -> dedup -> emit).

    Then:
    - The emitted events are normalized (``_time`` added) and returned as expected.
      fetch does not re-pull the same id (dedup guarantee).
    """
    first_fetch_str = "2022-12-21T03:42:05Z"
    base_url = "https://server_url/"
    client = Client(
        base_url=base_url,
        verify=True,
        proxy=False,
    )

    # --- Mocked API response (raw event, exactly one page) ---
    raw_event = {
        "id": 6,
        "created_time": "2022-12-21T03:42:05Z",
        "description": "This is test description 6",
        "alert_status": "ACTIVE",
    }
    mocker.patch.object(client, "search_events", return_value=[raw_event])

    last_run = {"prev_id": 5}

    # --- Drive one complete fetch cycle ---
    _, events = fetch_events(
        client=client,
        last_run=last_run,
        first_fetch_time=first_fetch_str,
        alert_status="ACTIVE",
        max_events_per_fetch=100,
    )

    # --- Parse / normalize step ---
    add_time_to_events(events)

    # --- Assert emitted events ---
    assert len(events) == 1
    assert events[0]["id"] == 6
    assert events[0]["_time"] == "2022-12-21T03:42:05Z"

