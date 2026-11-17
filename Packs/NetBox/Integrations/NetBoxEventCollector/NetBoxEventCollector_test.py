import json

import pytest
from NetBoxEventCollector import (
    LOG_TYPES,
    NETBOX_VERSION_4_1_AND_ABOVE,
    NETBOX_VERSION_BELOW_4_1,
)

BASE_URL = "https://www.example.com/api"
# Endpoint of each log type per NetBox version (object-changes moved from extras to core in v4.1)
LOG_TYPE_URLS = {
    NETBOX_VERSION_4_1_AND_ABOVE: {
        "journal-entries": f"{BASE_URL}/extras/journal-entries",
        "object-changes": f"{BASE_URL}/core/object-changes",
    },
    NETBOX_VERSION_BELOW_4_1: {
        "journal-entries": f"{BASE_URL}/extras/journal-entries",
        "object-changes": f"{BASE_URL}/extras/object-changes",
    },
}
URLS = LOG_TYPE_URLS[NETBOX_VERSION_4_1_AND_ABOVE]

# Fields returned by the NetBox API (v4.6.3 serializers) that the modeling rules and the _time logic rely on
EXPECTED_JOURNAL_ENTRY_FIELDS = {"id", "created", "assigned_object", "assigned_object_type", "kind", "comments", "display"}
EXPECTED_OBJECT_CHANGE_FIELDS = {
    "id",
    "time",
    "user",
    "user_name",
    "request_id",
    "action",
    "display",
    "changed_object",
    "changed_object_id",
    "changed_object_type",
    "prechange_data",
    "postchange_data",
}


# helper function to load json file
def util_load_json(path):
    with open(path, encoding="utf-8") as f:
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
    from NetBoxEventCollector import add_time_key_to_events

    events = util_load_json("test_data/netbox-get-events.json")
    events = add_time_key_to_events(events)

    assert events[0]["_time"] == "2022-12-04T14:33:52.067484Z"
    assert events[4]["_time"] == "2022-12-07T08:19:57.810348Z"


def test_get_events_command(requests_mock):
    """
    Given:
        - NetBox client (default version - v4.1 and above) and limit of events to fetch
    When:
        - Calling get_events_command
    Then:
        - Ensure the events are returned as expected and the pagination is working as expected
    """
    from NetBoxEventCollector import Client, get_events_command

    for log_type in LOG_TYPES:
        requests_mock.get(
            f"{URLS[log_type]}?limit=4&ordering=&id__gte=0",
            json=util_load_json(f"test_data/get_events_{log_type}-01.json"),
        )
        requests_mock.get(
            f"{URLS[log_type]}/?id__gte=0&limit=2&offset=2&ordering=",
            json=util_load_json(f"test_data/get_events_{log_type}-02.json"),
        )

    client = Client(base_url=BASE_URL, verify=False)
    events, _ = get_events_command(client, limit=4)

    mock_events = util_load_json("test_data/netbox-get-events.json")

    assert events == mock_events


def test_get_events_command_no_events(requests_mock):
    """
    Given:
        - NetBox client and no events in both log types
    When:
        - Calling get_events_command
    Then:
        - Ensure the human readable mentions both log types
    """
    from NetBoxEventCollector import Client, get_events_command

    for url in URLS.values():
        requests_mock.get(url, json={"count": 0, "next": None, "previous": None, "results": []})

    client = Client(base_url=BASE_URL, verify=False)
    events, results = get_events_command(client, limit=4)

    assert events == []
    assert "No events found for journal-entries." in results.readable_output
    assert "No events found for object-changes." in results.readable_output


def test_fetch_events_command(requests_mock):
    """
    Given:
        - NetBox client (default version - v4.1 and above) and max_fetch, last_run and first_fetch_time
    When:
        - Calling fetch_events_command
    Then:
        - Ensure object-changes is fetched from /api/core, journal-entries from /api/extras,
          and the events and next_run are as expected
    """
    from NetBoxEventCollector import Client, fetch_events_command

    # mock the first fetch id
    requests_mock.get(
        f"{URLS['journal-entries']}?ordering=id&limit=1&created_after=2022-01-01T00:00:00Z",
        json={"results": [{"id": 5}]},
    )
    requests_mock.get(
        f"{URLS['object-changes']}?ordering=id&limit=1&time_after=2022-01-01T00:00:00Z",
        json={"results": [{"id": 9}]},
    )

    # mock the events
    requests_mock.get(
        f"{URLS['journal-entries']}?limit=2&ordering=id&id__gte=5",
        json=util_load_json("test_data/fetch_events_journal-entries.json"),
    )
    requests_mock.get(
        f"{URLS['object-changes']}?limit=2&ordering=id&id__gte=9",
        json=util_load_json("test_data/fetch_events_object-changes.json"),
    )

    client = Client(base_url=BASE_URL, verify=False)
    next_run, events = fetch_events_command(client, max_fetch=2, last_run={}, first_fetch_time="2022-01-01T00:00:00Z")

    mock_events = util_load_json("test_data/netbox-fetch-events.json")

    assert events == mock_events
    assert next_run == {"journal-entries": 7, "object-changes": 11}


@pytest.mark.parametrize("netbox_version", [NETBOX_VERSION_4_1_AND_ABOVE, NETBOX_VERSION_BELOW_4_1])
def test_fetch_events_command_uses_endpoints_of_selected_version(requests_mock, netbox_version):
    """
    Given:
        - NetBox client configured with a specific NetBox version
    When:
        - Calling fetch_events_command
    Then:
        - Ensure each log type is requested from the endpoint of the selected version only
    """
    from NetBoxEventCollector import Client, fetch_events_command

    urls = LOG_TYPE_URLS[netbox_version]
    other_version = NETBOX_VERSION_BELOW_4_1 if netbox_version == NETBOX_VERSION_4_1_AND_ABOVE else NETBOX_VERSION_4_1_AND_ABOVE
    wrong_object_changes_mock = requests_mock.get(LOG_TYPE_URLS[other_version]["object-changes"], status_code=404)

    requests_mock.get(
        f"{urls['journal-entries']}?ordering=id&limit=1&created_after=2022-01-01T00:00:00Z",
        json={"results": [{"id": 5}]},
    )
    requests_mock.get(
        f"{urls['object-changes']}?ordering=id&limit=1&time_after=2022-01-01T00:00:00Z",
        json={"results": [{"id": 9}]},
    )
    requests_mock.get(
        f"{urls['journal-entries']}?limit=2&ordering=id&id__gte=5",
        json=util_load_json("test_data/fetch_events_journal-entries.json"),
    )
    requests_mock.get(
        f"{urls['object-changes']}?limit=2&ordering=id&id__gte=9",
        json=util_load_json("test_data/fetch_events_object-changes.json"),
    )

    client = Client(base_url=BASE_URL, netbox_version=netbox_version, verify=False)
    next_run, events = fetch_events_command(client, max_fetch=2, last_run={}, first_fetch_time="2022-01-01T00:00:00Z")

    assert events == util_load_json("test_data/netbox-fetch-events.json")
    assert next_run == {"journal-entries": 7, "object-changes": 11}
    assert wrong_object_changes_mock.call_count == 0


def test_fetch_events_command_continues_from_last_run(requests_mock):
    """
    Given:
        - A last_run with ids for both log types
    When:
        - Calling fetch_events_command
    Then:
        - Ensure the first fetch id is not requested again and the fetch continues from the last_run ids
    """
    from NetBoxEventCollector import Client, fetch_events_command

    first_fetch_mock = requests_mock.get(f"{URLS['object-changes']}?ordering=id&limit=1", json={"results": [{"id": 1}]})
    requests_mock.get(
        f"{URLS['journal-entries']}?limit=2&ordering=id&id__gte=5",
        json=util_load_json("test_data/fetch_events_journal-entries.json"),
    )
    requests_mock.get(
        f"{URLS['object-changes']}?limit=2&ordering=id&id__gte=9",
        json=util_load_json("test_data/fetch_events_object-changes.json"),
    )

    client = Client(base_url=BASE_URL, verify=False)
    next_run, _ = fetch_events_command(
        client, max_fetch=2, last_run={"journal-entries": 5, "object-changes": 9}, first_fetch_time="2022-01-01T00:00:00Z"
    )

    assert next_run == {"journal-entries": 7, "object-changes": 11}
    assert first_fetch_mock.call_count == 0


def test_client_invalid_netbox_version():
    """
    Given:
        - An unsupported NetBox version value
    When:
        - Creating the Client
    Then:
        - Ensure a clear error is raised
    """
    from CommonServerPython import DemistoException
    from NetBoxEventCollector import Client

    with pytest.raises(DemistoException, match="Invalid NetBox version"):
        Client(base_url=BASE_URL, netbox_version="v3", verify=False)


def test_test_module_success(requests_mock):
    """
    Given:
        - Both log type endpoints are reachable
    When:
        - Calling test_module_command
    Then:
        - Ensure 'ok' is returned and both log types are checked
    """
    from NetBoxEventCollector import Client, test_module_command

    mocks = [requests_mock.get(url, json={"results": []}) for url in URLS.values()]

    client = Client(base_url=BASE_URL, verify=False)
    assert test_module_command(client) == "ok"
    assert all(mock.call_count == 1 for mock in mocks)


def test_test_module_object_changes_not_found(requests_mock):
    """
    Given:
        - The selected NetBox version does not match the server, so object-changes returns 404
          (e.g. 'Below v4.1' is selected but the server is NetBox v4.1 and above)
    When:
        - Calling test_module_command
    Then:
        - Ensure a message pointing to the 'NetBox Version' parameter is returned instead of 'ok'
    """
    from NetBoxEventCollector import Client, test_module_command

    urls = LOG_TYPE_URLS[NETBOX_VERSION_BELOW_4_1]
    requests_mock.get(urls["journal-entries"], json={"results": []})
    requests_mock.get(urls["object-changes"], status_code=404, text="<!DOCTYPE html>Not Found")

    client = Client(base_url=BASE_URL, netbox_version=NETBOX_VERSION_BELOW_4_1, verify=False)
    result = test_module_command(client)

    assert "object-changes" in result
    assert "NetBox Version" in result


def test_test_module_forbidden(requests_mock):
    """
    Given:
        - The API key is not authorized
    When:
        - Calling test_module_command
    Then:
        - Ensure an authorization error message is returned
    """
    from NetBoxEventCollector import Client, test_module_command

    requests_mock.get(URLS["journal-entries"], status_code=403, json={"detail": "Forbidden"})

    client = Client(base_url=BASE_URL, verify=False)
    assert test_module_command(client) == "Authorization Error: make sure API Key is correctly set"


def test_test_module_unexpected_error_is_raised(requests_mock):
    """
    Given:
        - The server returns an unexpected error (500)
    When:
        - Calling test_module_command
    Then:
        - Ensure the error is raised
    """
    from CommonServerPython import DemistoException
    from NetBoxEventCollector import Client, test_module_command

    requests_mock.get(URLS["journal-entries"], status_code=500, text="Server Error")

    client = Client(base_url=BASE_URL, verify=False)
    with pytest.raises(DemistoException, match="500"):
        test_module_command(client)


@pytest.mark.parametrize(
    "file_name, expected_fields",
    [
        ("test_data/get_events_journal-entries-01.json", EXPECTED_JOURNAL_ENTRY_FIELDS),
        ("test_data/get_events_object-changes-01.json", EXPECTED_OBJECT_CHANGE_FIELDS),
    ],
)
def test_response_structure(file_name, expected_fields):
    """
    Given:
        - Mocked NetBox API responses
    When:
        - Loading the responses
    Then:
        - Ensure the pagination keys and the fields used by the modeling rules and the _time logic exist.
          The fields were verified against the NetBox v4.6.3 serializers (the v4.1+ changes are additive only).
    """
    response = util_load_json(file_name)

    assert {"count", "next", "previous", "results"} <= response.keys()
    for event in response["results"]:
        assert expected_fields <= event.keys()


def test_truncate_error_message():
    """
    Given:
        - A very long error message (e.g. a full HTML page returned by NetBox)
    When:
        - Calling truncate_error_message
    Then:
        - Ensure the message is truncated to MAX_ERROR_MESSAGE_LENGTH and short messages are left untouched
    """
    from NetBoxEventCollector import MAX_ERROR_MESSAGE_LENGTH, truncate_error_message

    long_message = "Error in API call [404] - Not Found <!DOCTYPE html>" + "x" * 10000
    truncated = truncate_error_message(long_message)

    assert len(truncated) == MAX_ERROR_MESSAGE_LENGTH + len("... (truncated)")
    assert truncated.startswith("Error in API call [404] - Not Found")
    assert truncated.endswith("... (truncated)")
    assert truncate_error_message("short error") == "short error"
