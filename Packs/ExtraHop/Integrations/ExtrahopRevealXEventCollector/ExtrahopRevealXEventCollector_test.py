import pytest

from ExtrahopRevealXEventCollector import Client
from CommonServerPython import *

MOCK_BASEURL = "https://example.com"
MOCK_CLIENT_ID = "ID"
MOCK_CLIENT_SECRET = "SECRET"
OK_CODES = (200, 201, 204)


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def client():
    return Client(
        base_url=MOCK_BASEURL,
        verify=False,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        use_proxy=False,
        ok_codes=OK_CODES
    )


def test_update_time_values_detections():
    """
    Given: A mock raw response containing detections logs.
    When: Updating time fields
    Then: Ensure the events are added the new time fields
    """
    from ExtrahopRevealXEventCollector import update_time_values_detections
    raw_detections = util_load_json("test_data/detections-dummy.json")
    update_time_values_detections(raw_detections)

    for detection in raw_detections:
        assert "_TIME" in detection
        assert "_ENTRY_STATUS" in detection



def test_fetch_events_update_last_run(client, mocker):
    """
    Given: A mock raw response containing detections logs.
    When: fetching events.
    Then: Make sure that the last run object was updated as expected
    """
    from ExtrahopRevealXEventCollector import fetch_events
    raw_detections = util_load_json("test_data/detections-dummy.json")
    mocker.patch("ExtrahopRevealXEventCollector.Client.detections_list", return_value=raw_detections)

    output, new_last_run = fetch_events(client, last_run={}, max_events=len(raw_detections))

    assert len(output) == 5
    assert new_last_run.get("offset") == 0
    assert new_last_run.get("detection_start_time") == raw_detections[-1]["mod_time"] + 1


def test_fetch_events_already_fetched(client, mocker):
    """
    Given: A mock raw response containing detections events.
    When: Fetching events that was already fetched
    Then: Ensure the function does not return any events
    """
    from ExtrahopRevealXEventCollector import fetch_events
    raw_detections = util_load_json("test_data/detections-dummy.json")
    mocker.patch("ExtrahopRevealXEventCollector.Client.detections_list", return_value=raw_detections)

    mock_already_fetched = [d["id"] for d in raw_detections]
    last_run_mock = {"already_fetched": mock_already_fetched}

    output, new_last_run = fetch_events(client, last_run=last_run_mock, max_events=len(raw_detections))

    assert len(output) == 0
    assert new_last_run.get("already_fetched") == mock_already_fetched


def test_fetch_events_reaching_limit(client, mocker):
    """
    Given: A mock raw response containing detections events.
    When: Fetching events with a fetch limit higher than the number of available logs.
    Then: Ensure the function returns exactly the requested number of events and updates the last run timestamp correctly.
    """
    from ExtrahopRevealXEventCollector import fetch_events
    raw_detections = util_load_json("test_data/detections-dummy.json")[:-2]
    mocker.patch("ExtrahopRevealXEventCollector.Client.detections_list", return_value=raw_detections)

    output, new_last_run = fetch_events(client, last_run={}, max_events=len(raw_detections) + 2)

    assert len(output) == len(raw_detections)
    assert new_last_run.get("detection_start_time") == raw_detections[-1]["mod_time"] + 1


def test_fetch_events_more_than_exist(client, mocker):
    """
    Given: A mock raw response containing detections events.
    When: Fetching events with a fetch limit smaller than the number of available logs.
    Then: Ensure the function returns exactly the requested number of events and updates the last run timestamp correctly.
    """
    from ExtrahopRevealXEventCollector import fetch_events
    raw_detections = util_load_json("test_data/detections-dummy.json")
    mocker.patch("ExtrahopRevealXEventCollector.Client.detections_list", return_value=raw_detections)

    output, new_last_run = fetch_events(client, last_run={}, max_events=len(raw_detections) - 2)

    assert len(output) == len(raw_detections) - 2
    assert new_last_run.get("detection_start_time") == raw_detections[-3]["mod_time"] + 1


def test_fetch_events_same_mod_time(client, mocker):
    """
    Given: A mock raw response containing detections events.
    When: Fetching events with a fetch limit less than the number of available logs and they all have the same mod_time
    Then: Ensure the function returns exactly the requested number of events and updates the last run timestamp correctly.
    """
    from ExtrahopRevealXEventCollector import fetch_events
    raw_detections = util_load_json("test_data/detections-dummy.json")
    mod_time_all = 1000
    for d in raw_detections:
        d["mod_time"] = mod_time_all

    mocker.patch("ExtrahopRevealXEventCollector.Client.detections_list", return_value=raw_detections)

    output, new_last_run = fetch_events(client, last_run={}, max_events=len(raw_detections) - 2)

    assert len(output) == len(raw_detections) - 2
    assert new_last_run.get("detection_start_time") == mod_time_all
