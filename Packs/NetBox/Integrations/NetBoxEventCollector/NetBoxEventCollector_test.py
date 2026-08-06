import json

import demistomock as demisto
import pytest
from CommonServerPython import *  # noqa: F403
from NetBoxEventCollector import LOG_TYPES

# The client is built on the API root; the namespace is resolved per log type (NetBox 4.1 moved
# object-changes from /api/extras/ to /api/core/, journal-entries stayed in /api/extras/).
BASE_URL = "https://www.example.com/api"

# Where each log type is served from on a modern (>= 4.1) NetBox.
PATHS = {
    "journal-entries": "extras/journal-entries",
    "object-changes": "core/object-changes",
}

# NetBox answers an unknown API path with an HTML 404 page, not a JSON error body.
NETBOX_404_HTML = (
    '<!DOCTYPE html><html lang="en" data-netbox-version="4.6.5"><head>'
    "<title>Page Not Found | NetBox</title></head>"
    "<body>The requested page does not exist.</body></html>"
)

_ONE_PAGE = {"count": 1, "next": None, "previous": None, "results": [{"id": 1, "time": "2026-08-03T14:52:02Z"}]}


# helper function to load json file
def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def mock_netbox_4x(requests_mock):
    """Routes like a NetBox >= 4.1 server: core/object-changes serves, extras/object-changes 404s."""
    for path in PATHS.values():
        requests_mock.get(f"{BASE_URL}/{path}", json=_ONE_PAGE)
        requests_mock.get(f"{BASE_URL}/{path}/", json=_ONE_PAGE)
    requests_mock.get(f"{BASE_URL}/extras/object-changes", status_code=404, text=NETBOX_404_HTML)
    requests_mock.get(f"{BASE_URL}/extras/object-changes/", status_code=404, text=NETBOX_404_HTML)


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
        - NetBox client and limit of events to fetch
    When:
        - Calling get_events_command
    Then:
        - Ensure the events are returned as expected and the pagination is working as expected
    """
    from NetBoxEventCollector import Client, get_events_command

    for log_type in LOG_TYPES:
        path = PATHS[log_type]
        requests_mock.get(
            f"{BASE_URL}/{path}?limit=4&ordering=&id__gte=0", json=util_load_json(f"test_data/get_events_{log_type}-01.json")
        )
        requests_mock.get(
            f"{BASE_URL}/{path}/?id__gte=0&limit=2&offset=2&ordering=",
            json=util_load_json(f"test_data/get_events_{log_type}-02.json"),
        )
    # The 404 probe that resolves object-changes to the core namespace.
    requests_mock.get(f"{BASE_URL}/core/object-changes?limit=1", json=_ONE_PAGE)

    client = Client(base_url=BASE_URL, verify=False)
    events, _ = get_events_command(client, limit=4)

    mock_events = util_load_json("test_data/netbox-get-events.json")

    assert events == mock_events


def test_fetch_events_command(requests_mock):
    """
    Given:
        - NetBox client and max_fetch, last_run and first_fetch_time
    When:
        - Calling fetch_events_command
    Then:
        - Ensure the events are returned as expected and the next_run is as expected
    """
    from NetBoxEventCollector import Client, fetch_events_command

    # The 404 probe that resolves object-changes to the core namespace, before get_first_fetch_id
    # adds its own ordering param.
    requests_mock.get(f"{BASE_URL}/core/object-changes?limit=1&time_after=2022-01-01T00:00:00Z", json=_ONE_PAGE)

    # mock the first fetch id
    requests_mock.get(
        f"{BASE_URL}/extras/journal-entries?ordering=id&limit=1&created_after=2022-01-01T00:00:00Z",
        json={"results": [{"id": 5}]},
    )
    requests_mock.get(
        f"{BASE_URL}/core/object-changes?ordering=id&limit=1&time_after=2022-01-01T00:00:00Z", json={"results": [{"id": 9}]}
    )

    # mock the events
    requests_mock.get(
        f"{BASE_URL}/extras/journal-entries?limit=2&ordering=id&id__gte=5",
        json=util_load_json("test_data/fetch_events_journal-entries.json"),
    )
    requests_mock.get(
        f"{BASE_URL}/core/object-changes?limit=2&ordering=id&id__gte=9",
        json=util_load_json("test_data/fetch_events_object-changes.json"),
    )

    client = Client(base_url=BASE_URL, verify=False)
    next_run, events = fetch_events_command(client, max_fetch=2, last_run={}, first_fetch_time="2022-01-01T00:00:00Z")

    mock_events = util_load_json("test_data/netbox-fetch-events.json")

    assert events == mock_events
    # The last_run keys are the log type names, unchanged by the namespace fix - an existing
    # cursor stored by an older pack version must still be readable after the upgrade.
    assert next_run == {"journal-entries": 7, "object-changes": 11}


def test_fetch_events_command_on_netbox_4x(requests_mock):
    """
    XSUP-74288 regression.

    Given:
        - A NetBox >= 4.1 server, where object-changes moved to /api/core/ and
          /api/extras/object-changes/ answers 404 with an HTML page
    When:
        - Calling fetch_events_command
    Then:
        - Both log types are fetched from their correct namespaces and no exception is raised
    """
    from NetBoxEventCollector import Client, fetch_events_command

    mock_netbox_4x(requests_mock)

    client = Client(base_url=BASE_URL, verify=False)
    next_run, events = fetch_events_command(client, max_fetch=10, last_run={}, first_fetch_time="2026-08-01T00:00:00Z")

    assert len(events) == 2
    assert next_run == {"journal-entries": 2, "object-changes": 2}
    assert client.resolve_path("object-changes") == "core/object-changes"
    assert client.resolve_path("journal-entries") == "extras/journal-entries"


def test_test_module_command_probes_every_log_type(requests_mock):
    """
    XSUP-74288 regression.

    Given:
        - A NetBox >= 4.1 server where only one of the two log-type endpoints would have resolved
          under the old hardcoded namespace
    When:
        - Calling test_module_command
    Then:
        - Every log type is probed and 'ok' is returned only once they all answer
    """
    from NetBoxEventCollector import Client, test_module_command

    mock_netbox_4x(requests_mock)

    client = Client(base_url=BASE_URL, verify=False)

    assert test_module_command(client) == "ok"
    requested = [r.path for r in requests_mock.request_history]
    assert any("core/object-changes" in path for path in requested)
    assert any("extras/journal-entries" in path for path in requested)


def test_resolve_path_falls_back_to_legacy_namespace(requests_mock):
    """
    Given:
        - A NetBox < 4.1 server, where object-changes is served from /api/extras/ and
          /api/core/object-changes/ does not exist
    When:
        - Resolving the object-changes path
    Then:
        - The client falls back to the legacy extras namespace
    """
    from NetBoxEventCollector import Client

    requests_mock.get(f"{BASE_URL}/core/object-changes", status_code=404, text=NETBOX_404_HTML)
    requests_mock.get(f"{BASE_URL}/extras/object-changes", json=_ONE_PAGE)

    client = Client(base_url=BASE_URL, verify=False)

    assert client.resolve_path("object-changes") == "extras/object-changes"


def test_resolve_path_caches_the_probe(requests_mock):
    """
    Given:
        - A client that already resolved a log type
    When:
        - Resolving the same log type again
    Then:
        - No second probe request is sent
    """
    from NetBoxEventCollector import Client

    mock_netbox_4x(requests_mock)

    client = Client(base_url=BASE_URL, verify=False)
    client.resolve_path("object-changes")
    calls_after_first = len(requests_mock.request_history)
    client.resolve_path("object-changes")

    assert len(requests_mock.request_history) == calls_after_first


@pytest.mark.parametrize("status_code", [401, 403, 500], ids=["unauthorized", "forbidden", "server_error"])
def test_resolve_path_reraises_non_404_errors(requests_mock, status_code):
    """
    Given:
        - The modern endpoint answers with an error that is not a 404
    When:
        - Resolving the path
    Then:
        - The error is raised rather than silently falling back to the legacy namespace
    """
    from NetBoxEventCollector import Client

    requests_mock.get(f"{BASE_URL}/core/object-changes", status_code=status_code, json={"detail": "nope"})

    client = Client(base_url=BASE_URL, verify=False)

    with pytest.raises(DemistoException):
        client.resolve_path("object-changes")


def test_fetch_events_command_isolates_a_failing_log_type(requests_mock, mocker):
    """
    XSUP-74288 regression.

    Given:
        - One log type fails while the other returns events
    When:
        - Calling fetch_events_command
    Then:
        - The healthy log type's events are still returned and its cursor advances, while the
          failing one keeps its cursor so nothing is skipped on the next run
    """
    from NetBoxEventCollector import Client, fetch_events_command

    mocker.patch.object(demisto, "error")
    requests_mock.get(f"{BASE_URL}/core/object-changes", status_code=500, json={"detail": "boom"})
    requests_mock.get(f"{BASE_URL}/extras/journal-entries", json=_ONE_PAGE)

    client = Client(base_url=BASE_URL, verify=False)
    next_run, events = fetch_events_command(
        client,
        max_fetch=10,
        last_run={"journal-entries": 1, "object-changes": 42},
        first_fetch_time="2026-08-01T00:00:00Z",
    )

    assert len(events) == 1
    assert next_run["journal-entries"] == 2
    assert next_run["object-changes"] == 42


def test_fetch_events_command_raises_when_every_log_type_fails(requests_mock, mocker):
    """
    Given:
        - Every log type fails
    When:
        - Calling fetch_events_command
    Then:
        - An exception is raised, so the failure is visible rather than reported as an empty fetch
    """
    from NetBoxEventCollector import Client, fetch_events_command

    mocker.patch.object(demisto, "error")
    requests_mock.get(f"{BASE_URL}/core/object-changes", status_code=500, json={"detail": "boom"})
    requests_mock.get(f"{BASE_URL}/extras/journal-entries", status_code=500, json={"detail": "boom"})

    client = Client(base_url=BASE_URL, verify=False)

    with pytest.raises(DemistoException, match="Failed to fetch events for all log types"):
        fetch_events_command(
            client,
            max_fetch=10,
            last_run={"journal-entries": 1, "object-changes": 42},
            first_fetch_time="2026-08-01T00:00:00Z",
        )
