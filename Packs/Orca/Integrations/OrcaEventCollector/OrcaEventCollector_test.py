import demistomock as demisto
import pytest
from freezegun import freeze_time

from OrcaEventCollector import (
    Client,
    DEFAULT_PAGE_SIZE,
    TEST_MODULE_LIMIT,
    get_alerts,
    add_time_key_to_alerts,
    add_entry_status_to_alerts,
    dedup_alerts,
    get_boundary_ids,
    normalize_last_updated,
    orca_test_module,
    main,
)
from CommonServerPython import DemistoException


# --- MOCK DATA ---

# 'now' used by freeze_time across the main tests; the run-start upper bound (end_time) equals this.
FROZEN_NOW = "2023-01-04T00:00:00"
END_TIME = "2023-01-04T00:00:00Z"


def _make_alerts(count: int) -> list:
    """Build a list of ``count`` minimal alert dicts with unique AlertId/LastUpdated values."""
    return [
        {
            "id": f"alert-{i}",
            "data": {
                "AlertId": {"value": f"alert-{i}"},
                "CreatedAt": {"value": f"2023-01-01T00:00:{i:02d}Z"},
                "LastUpdated": {"value": f"2023-01-01T00:00:{i:02d}Z"},
            },
        }
        for i in range(count)
    ]


# --- CLIENT CLASS TESTS ---


@pytest.mark.parametrize(
    "start_index",
    [0, 100, 250],
)
def test_client_get_alerts_request_payload(mocker, start_index):
    """
    Given:
        - A last_fetch (lower bound), end_time (upper bound) and a start_at_index (SQL OFFSET).
    When:
        - Calling get_alerts_request.
    Then:
        - Ensure the _http_request method is called with the correct POST payload:
          a two-sided LastUpdated window (gte/lt, no value_type), offset-based start_at_index,
          order_by LastUpdated, and LastUpdated present in the select list.
    """
    mock_http_request = mocker.patch.object(Client, "_http_request")

    client = Client(server_url="https://test.com/api", headers={})
    last_fetch = "2023-01-01T00:00:00Z"
    end_time = "2023-01-04T00:00:00Z"
    page_size = 150

    client.get_alerts_request(page_size, start_index, last_fetch, end_time)

    expected_payload = {
        "query": {
            "models": ["Alert"],
            "type": "object_set",
            "with": {
                "type": "operation",
                "operator": "and",
                "values": [
                    {"key": "LastUpdated", "values": [last_fetch], "type": "datetime", "operator": "gte"},
                    {"key": "LastUpdated", "values": [end_time], "type": "datetime", "operator": "lt"},
                ],
            },
        },
        "limit": page_size,
        "start_at_index": start_index,
        "order_by[]": ["LastUpdated"],
        "select": [
            "AlertId",
            "AlertType",
            "OrcaScore",
            "RiskLevel",
            "RuleSource",
            "ScoreVector",
            "Category",
            "Inventory.Name",
            "CloudAccount.Name",
            "CloudAccount.CloudProvider",
            "Source",
            "Status",
            "CreatedAt",
            "LastUpdated",
            "LastSeen",
            "Labels",
        ],
    }

    mock_http_request.assert_called_once_with(method="POST", url_suffix="/serving-layer/query", json_data=expected_payload)


# --- HELPER FUNCTION TESTS ---


@freeze_time("2023-01-04T00:00:00")
def test_add_time_key_to_alerts_uses_last_updated(mocker):
    """
    Given:
        - Alerts with LastUpdated and/or CreatedAt values.
    When:
        - Calling add_time_key_to_alerts.
    Then:
        - _time is taken from LastUpdated when present.
        - Falls back to CreatedAt when LastUpdated is missing.
        - Falls back to 'now' when both are missing/unparseable.
    """
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")
    alerts = [
        # LastUpdated present -> used for _time.
        {"data": {"CreatedAt": {"value": "2023-01-01T12:00:00Z"}, "LastUpdated": {"value": "2023-01-02T09:00:00Z"}}},
        # LastUpdated with timezone offset -> normalized to Z.
        {"data": {"LastUpdated": {"value": "2023-01-02T13:00:00+00:00"}}},
        # LastUpdated missing -> fall back to CreatedAt.
        {"data": {"CreatedAt": {"value": "2023-01-01T05:00:00Z"}}},
        # Both missing -> fall back to now.
        {"data": {}},
        {},  # Empty alert -> now.
    ]

    expected = [
        {
            "data": {"CreatedAt": {"value": "2023-01-01T12:00:00Z"}, "LastUpdated": {"value": "2023-01-02T09:00:00Z"}},
            "_time": "2023-01-02T09:00:00Z",
        },
        {"data": {"LastUpdated": {"value": "2023-01-02T13:00:00+00:00"}}, "_time": "2023-01-02T13:00:00Z"},
        {"data": {"CreatedAt": {"value": "2023-01-01T05:00:00Z"}}, "_time": "2023-01-01T05:00:00Z"},
        {"data": {}, "_time": "2023-01-04T00:00:00Z"},
        {"_time": "2023-01-04T00:00:00Z"},
    ]

    assert add_time_key_to_alerts(alerts) == expected
    assert add_time_key_to_alerts([]) == []


def test_add_entry_status_to_alerts(mocker):
    """
    Given:
        - Alerts with various CreatedAt/LastUpdated relationships.
    When:
        - Calling add_entry_status_to_alerts.
    Then:
        - _ENTRY_STATUS is 'new' when LastUpdated == CreatedAt.
        - _ENTRY_STATUS is 'updated' when LastUpdated > CreatedAt.
        - _ENTRY_STATUS defaults to 'new' when a timestamp is missing.
    """
    mocker.patch.object(demisto, "debug")
    alerts = [
        # Equal -> new.
        {
            "data": {
                "AlertId": {"value": "a"},
                "CreatedAt": {"value": "2023-01-01T12:00:00Z"},
                "LastUpdated": {"value": "2023-01-01T12:00:00Z"},
            }
        },
        # LastUpdated later -> updated.
        {
            "data": {
                "AlertId": {"value": "b"},
                "CreatedAt": {"value": "2023-01-01T12:00:00Z"},
                "LastUpdated": {"value": "2023-01-02T12:00:00Z"},
            }
        },
        # Missing LastUpdated -> new (safe default).
        {"data": {"AlertId": {"value": "c"}, "CreatedAt": {"value": "2023-01-01T12:00:00Z"}}},
        # Missing both -> new.
        {"data": {"AlertId": {"value": "d"}}},
    ]

    result = add_entry_status_to_alerts(alerts)

    assert [a["_ENTRY_STATUS"] for a in result] == ["new", "updated", "new", "new"]
    assert add_entry_status_to_alerts([]) == []


def test_dedup_alerts_removes_boundary_duplicates(mocker):
    """
    Given:
        - Alerts where some share the previous run's boundary second and were already seen.
        - The alerts' LastUpdated uses the API's '+00:00' offset form while the boundary
          cursor uses the normalized '...Z' form (the two must still compare equal).
    When:
        - Calling dedup_alerts with the seen IDs and boundary time.
    Then:
        - Only alerts whose (LastUpdated == boundary AND AlertId in seen) are removed,
          regardless of the timestamp string format.
    """
    mocker.patch.object(demisto, "debug")
    # Cursor is normalized ('...Z'); API payloads use '+00:00'. These are the same instant.
    boundary = "2023-01-01T00:00:05Z"
    boundary_api = "2023-01-01T00:00:05+00:00"
    alerts = [
        {"data": {"AlertId": {"value": "seen-1"}, "LastUpdated": {"value": boundary_api}}},  # dup -> removed
        {"data": {"AlertId": {"value": "seen-2"}, "LastUpdated": {"value": boundary_api}}},  # dup -> removed
        {"data": {"AlertId": {"value": "new-1"}, "LastUpdated": {"value": boundary_api}}},  # same second, not seen -> kept
        {"data": {"AlertId": {"value": "new-2"}, "LastUpdated": {"value": "2023-01-01T00:00:06+00:00"}}},  # later -> kept
    ]

    result = dedup_alerts(alerts, ["seen-1", "seen-2"], boundary)

    kept_ids = [a["data"]["AlertId"]["value"] for a in result]
    assert kept_ids == ["new-1", "new-2"]


def test_dedup_alerts_noop_when_no_seen_ids():
    """
    Given:
        - No previously-seen boundary IDs (e.g., first run).
    When:
        - Calling dedup_alerts.
    Then:
        - The alerts list is returned unchanged.
    """
    alerts = _make_alerts(3)
    assert dedup_alerts(alerts, [], "2023-01-01T00:00:00Z") == alerts
    assert dedup_alerts([], ["x"], "2023-01-01T00:00:00Z") == []


def test_get_boundary_ids():
    """
    Given:
        - Alerts ordered by LastUpdated with several sharing the newest second.
        - Alert LastUpdated uses the API '+00:00' form while the boundary uses '...Z'.
    When:
        - Calling get_boundary_ids with the newest LastUpdated value.
    Then:
        - Only AlertIds sharing that boundary second are returned, despite the format difference.
    """
    boundary = "2023-01-01T00:00:09Z"
    boundary_api = "2023-01-01T00:00:09+00:00"
    alerts = [
        {"data": {"AlertId": {"value": "old"}, "LastUpdated": {"value": "2023-01-01T00:00:08+00:00"}}},
        {"data": {"AlertId": {"value": "b1"}, "LastUpdated": {"value": boundary_api}}},
        {"data": {"AlertId": {"value": "b2"}, "LastUpdated": {"value": boundary_api}}},
    ]

    assert get_boundary_ids(alerts, boundary) == ["b1", "b2"]


def test_normalize_last_updated():
    """
    Given:
        - LastUpdated values in different valid forms (API '+00:00', normalized '...Z', None, junk).
    When:
        - Calling normalize_last_updated.
    Then:
        - Equivalent instants normalize to the same canonical '...Z' string; unparseable -> None.
    """
    assert normalize_last_updated("2026-08-05T22:26:13+00:00") == "2026-08-05T22:26:13Z"
    assert normalize_last_updated("2026-08-05T22:26:13Z") == "2026-08-05T22:26:13Z"
    # Same instant, two formats -> equal after normalization (the core of the fix).
    assert normalize_last_updated("2026-08-05T22:26:13+00:00") == normalize_last_updated("2026-08-05T22:26:13Z")
    assert normalize_last_updated(None) is None
    assert normalize_last_updated("") is None


def test_dedup_alerts_regression_boundary_format_mismatch(mocker):
    """
    Regression for the stuck-cursor bug: the boundary duplicate arrives from the API with a
    '+00:00' offset while the persisted seen boundary cursor is '...Z'. Before normalization
    these strings did not compare equal, so the duplicate was never dropped and the cursor
    re-fetched the same boundary events every cycle forever.

    Given:
        - A single boundary-second alert whose AlertId is in seen_ids, in '+00:00' form.
        - The boundary cursor in normalized '...Z' form.
    When:
        - Calling dedup_alerts.
    Then:
        - The duplicate is removed (result is empty), proving the format mismatch is handled.
    """
    mocker.patch.object(demisto, "debug")
    alerts = [{"data": {"AlertId": {"value": "orca-7679203"}, "LastUpdated": {"value": "2026-08-05T22:26:13+00:00"}}}]

    result = dedup_alerts(alerts, ["orca-7679203"], "2026-08-05T22:26:13Z")

    assert result == []


# --- COMMAND FUNCTION TESTS ---


def test_get_alerts_single_page(mocker):
    """
    Given:
        - An API that returns a single short page (fewer rows than the page size).
    When:
        - Calling get_alerts.
    Then:
        - All alerts from the single page are returned.
        - Only one API request is made (no extra page requested after a short page).
    """
    client = Client(server_url="https://test.com/api", headers={})
    page = _make_alerts(3)
    mock_request = mocker.patch.object(client, "get_alerts_request", return_value={"status": "success", "data": page})
    mocker.patch.object(demisto, "debug")

    alerts = get_alerts(client, max_fetch=1000, last_fetch="2023-01-01T00:00:00Z", end_time=END_TIME, page_size=DEFAULT_PAGE_SIZE)

    assert alerts == page
    mock_request.assert_called_once()
    # First (and only) page is requested at offset 0 (start_index is the 2nd positional arg).
    assert mock_request.call_args.args[1] == 0
    # The end_time upper bound is passed through.
    assert mock_request.call_args.args[3] == END_TIME


def test_get_alerts_paginates_multiple_pages(mocker):
    """
    Given:
        - An API with more results than a single page (offset-based pagination, no token).
    When:
        - Calling get_alerts with a small page_size.
    Then:
        - The offset (start_at_index) advances by the number of rows returned each page.
        - Pagination stops on the first short page.
        - All alerts across pages are returned in order.
    """
    client = Client(server_url="https://test.com/api", headers={})
    full_page_1 = _make_alerts(2)
    full_page_2 = _make_alerts(2)
    short_page_3 = _make_alerts(1)
    responses = [
        {"status": "success", "data": full_page_1},
        {"status": "success", "data": full_page_2},
        {"status": "success", "data": short_page_3},
    ]
    mock_request = mocker.patch.object(client, "get_alerts_request", side_effect=responses)
    mocker.patch.object(demisto, "debug")

    alerts = get_alerts(client, max_fetch=1000, last_fetch="2023-01-01T00:00:00Z", end_time=END_TIME, page_size=2)

    assert len(alerts) == 5
    assert alerts == full_page_1 + full_page_2 + short_page_3
    # Three pages requested at offsets 0, 2, 4 (advance by rows returned).
    assert mock_request.call_count == 3
    assert [call.args[1] for call in mock_request.call_args_list] == [0, 2, 4]


def test_get_alerts_stops_on_empty_page(mocker):
    """
    Given:
        - A full page followed by an empty page (exact multiple of page_size).
    When:
        - Calling get_alerts.
    Then:
        - The empty page ends pagination and only the first page's alerts are returned.
    """
    client = Client(server_url="https://test.com/api", headers={})
    full_page = _make_alerts(2)
    responses = [
        {"status": "success", "data": full_page},
        {"status": "success", "data": []},
    ]
    mock_request = mocker.patch.object(client, "get_alerts_request", side_effect=responses)
    mocker.patch.object(demisto, "debug")

    alerts = get_alerts(client, max_fetch=1000, last_fetch="2023-01-01T00:00:00Z", end_time=END_TIME, page_size=2)

    assert alerts == full_page
    assert mock_request.call_count == 2


def test_get_alerts_respects_max_fetch(mocker):
    """
    Given:
        - An API that would return more results than max_fetch.
    When:
        - Calling get_alerts with a max_fetch smaller than the available data.
    Then:
        - No more than max_fetch alerts are returned.
        - The last page request is capped to the remaining number of events.
    """
    client = Client(server_url="https://test.com/api", headers={})
    responses = [
        {"status": "success", "data": _make_alerts(2)},
        {"status": "success", "data": _make_alerts(1)},
    ]
    mock_request = mocker.patch.object(client, "get_alerts_request", side_effect=responses)
    mocker.patch.object(demisto, "debug")

    alerts = get_alerts(client, max_fetch=3, last_fetch="2023-01-01T00:00:00Z", end_time=END_TIME, page_size=2)

    assert len(alerts) == 3
    # Second call requests only the remaining 1 event (max_fetch - already collected).
    assert mock_request.call_args_list[1].args[0] == 1


def test_get_alerts_empty_first_page(mocker):
    """
    Given:
        - An API that returns no results at all.
    When:
        - Calling get_alerts.
    Then:
        - An empty list is returned and only one request is made.
    """
    client = Client(server_url="https://test.com/api", headers={})
    mock_request = mocker.patch.object(client, "get_alerts_request", return_value={"status": "success", "data": []})
    mocker.patch.object(demisto, "debug")

    alerts = get_alerts(client, max_fetch=1000, last_fetch="2023-01-01T00:00:00Z", end_time=END_TIME)

    assert alerts == []
    mock_request.assert_called_once()


def test_orca_test_module(mocker):
    """
    Given:
        - A mock client.
    When:
        - Calling test-module.
    Then:
        - Return 'ok' on success and request only TEST_MODULE_LIMIT events at offset 0
          with the two-sided window (last_fetch, end_time).
        - Raise the correct exception on failure (404).
        - Raise a generic exception on other failures.
    """
    client = Client(server_url="https://test.com/api", headers={})

    # Test success
    mock_request = mocker.patch.object(client, "get_alerts_request", return_value={"status": "success", "data": []})
    assert orca_test_module(client, "2023-01-01T00:00:00Z", END_TIME) == "ok"
    mock_request.assert_called_once_with(TEST_MODULE_LIMIT, 0, "2023-01-01T00:00:00Z", END_TIME)

    # Test 404 failure
    mocker.patch.object(client, "get_alerts_request", side_effect=DemistoException("Error in API call [404] - Not Found"))
    with pytest.raises(Exception) as e:
        orca_test_module(client, "2023-01-01T00:00:00Z", END_TIME)
    assert "Error in API call [404] - Not Found" in str(e.value)
    assert "URL is invalid" in str(e.value)

    # Test other failure
    mocker.patch.object(client, "get_alerts_request", side_effect=DemistoException("Some other error"))
    with pytest.raises(Exception) as e:
        orca_test_module(client, "2023-01-01T00:00:00Z", END_TIME)
    assert "Some other error" in str(e.value)


# --- MAIN FUNCTION TESTS ---

# Base parameters for all main function tests
BASE_PARAMS = {
    "credentials": {"password": "api_token"},
    "insecure": True,
    "proxy": False,
    "server_url": "server_url",
    "first_fetch": "3 days",
    "max_fetch": "1000",
}


def _alert(alert_id: str, last_updated: str, created: str | None = None) -> dict:
    """Build an alert with LastUpdated (and optional CreatedAt) for main() tests."""
    data = {"AlertId": {"value": alert_id}, "LastUpdated": {"value": last_updated}}
    data["CreatedAt"] = {"value": created if created is not None else last_updated}
    return {"data": data}


@freeze_time(FROZEN_NOW)  # Set a consistent 'now' for '3 days' and end_time
@pytest.mark.parametrize(
    "test_name, last_run_in, alerts, expected_last_fetch_arg, expected_set_last_run, expected_events_sent_count",
    [
        (
            "1. First Run (fetches events)",
            {},  # No last run
            [
                _alert("a", "2023-01-01T12:00:00Z"),
                _alert("b", "2023-01-01T13:00:00Z"),
            ],
            "2023-01-01T00:00:00Z",  # '3 days' before freeze_time
            {"lastRun": "2023-01-01T13:00:00Z", "lastRunIds": ["b"]},  # newest LastUpdated + boundary ids
            2,
        ),
        (
            "2. First Run (no events)",
            {},  # No last run
            [],  # No alerts
            "2023-01-01T00:00:00Z",
            {"lastRun": "2023-01-01T00:00:00Z", "lastRunIds": []},  # Keeps first_fetch time, no ids
            0,
        ),
        (
            "3. Second Run (fetches new events)",
            {"lastRun": "2023-01-01T09:00:00Z", "lastRunIds": ["z"]},
            [_alert("c", "2023-01-02T10:00:00Z")],
            "2023-01-01T09:00:00Z",  # Uses lastRun time
            {"lastRun": "2023-01-02T10:00:00Z", "lastRunIds": ["c"]},
            1,
        ),
        (
            "4. Second Run (no new events)",
            {"lastRun": "2023-01-01T09:00:00Z", "lastRunIds": ["z"]},
            [],  # No alerts
            "2023-01-01T09:00:00Z",
            {"lastRun": "2023-01-01T09:00:00Z", "lastRunIds": ["z"]},  # unchanged, ids preserved
            0,
        ),
    ],
)
def test_main_fetch_events_scenarios(
    mocker,
    test_name,
    last_run_in,
    alerts,
    expected_last_fetch_arg,
    expected_set_last_run,
    expected_events_sent_count,
):
    """
    Given:
        - Various 'fetch-events' scenarios (first run, second run, no events).
    When:
        - Calling main() with the 'fetch-events' command.
    Then:
        - Ensure get_alerts is called with (client, max_fetch, last_fetch, end_time).
        - Ensure send_events_to_xsiam is called with the correct number of events.
        - Ensure setLastRun persists both lastRun (newest LastUpdated) and lastRunIds.
    """
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "params", return_value=BASE_PARAMS)
    mocker.patch.object(demisto, "getLastRun", return_value=last_run_in)
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_send_events = mocker.patch("OrcaEventCollector.send_events_to_xsiam")

    # Mock get_alerts to return the scenario's alerts (returns a plain list).
    mock_get_alerts = mocker.patch("OrcaEventCollector.get_alerts", return_value=alerts)

    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")

    main()

    # 1. Verify get_alerts call (client, max_fetch, last_fetch, end_time).
    mock_get_alerts.assert_called_once_with(
        mocker.ANY,  # the client instance
        1000,  # max_fetch from BASE_PARAMS
        expected_last_fetch_arg,
        END_TIME,
    )

    # 2. Verify send_events call
    if expected_events_sent_count > 0:
        mock_send_events.assert_called_once()
        sent_alerts = mock_send_events.call_args[0][0]
        assert len(sent_alerts) == expected_events_sent_count
        # Check that _time and _ENTRY_STATUS were added.
        assert sent_alerts[0].get("_time") is not None
        assert sent_alerts[0].get("_ENTRY_STATUS") == "new"
    else:
        mock_send_events.assert_not_called()

    # 3. Verify last_run was set with both keys.
    mock_set_last_run.assert_called_once_with(expected_set_last_run)


@freeze_time(FROZEN_NOW)
def test_main_fetch_events_dedup(mocker):
    """
    Given:
        - A subsequent run whose fetched alerts include one already emitted at the previous
          run's boundary second (present in lastRunIds).
    When:
        - Calling main() with 'fetch-events'.
    Then:
        - The boundary duplicate is dropped before sending.
        - Only the genuinely-new alert is sent to XSIAM.
    """
    boundary = "2023-01-02T10:00:00Z"
    last_run_in = {"lastRun": boundary, "lastRunIds": ["dup"]}
    fetched = [
        _alert("dup", boundary),  # already seen at boundary -> removed
        _alert("fresh", "2023-01-02T10:00:01Z"),  # new -> kept
    ]

    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "params", return_value=BASE_PARAMS)
    mocker.patch.object(demisto, "getLastRun", return_value=last_run_in)
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_send_events = mocker.patch("OrcaEventCollector.send_events_to_xsiam")
    mocker.patch("OrcaEventCollector.get_alerts", return_value=fetched)
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")

    main()

    sent_alerts = mock_send_events.call_args[0][0]
    assert [a["data"]["AlertId"]["value"] for a in sent_alerts] == ["fresh"]
    mock_set_last_run.assert_called_once_with({"lastRun": "2023-01-02T10:00:01Z", "lastRunIds": ["fresh"]})


@freeze_time(FROZEN_NOW)
def test_main_fetch_events_stuck_cursor_regression(mocker):
    """
    Regression for the live tenant stuck-cursor loop: the previous run persisted the boundary
    AlertIds (normalized '...Z'), and the API keeps returning ONLY those same boundary events,
    but with a '+00:00' offset. Before the normalization fix the format mismatch meant dedup
    never matched, so the same events were re-sent every cycle and the cursor never moved.

    Given:
        - lastRun holds the boundary '...Z' cursor and its two boundary AlertIds.
        - get_alerts returns exactly those two events again, in '+00:00' form, nothing newer.
    When:
        - Calling main() with 'fetch-events'.
    Then:
        - Both are recognized as duplicates and dropped -> nothing is sent to XSIAM.
        - The cursor is held (not re-advanced onto the same second) with the ids preserved.
    """
    boundary_z = "2026-08-05T22:26:13Z"
    boundary_api = "2026-08-05T22:26:13+00:00"
    last_run_in = {"lastRun": boundary_z, "lastRunIds": ["orca-7679203", "orca-7704352"]}
    fetched = [
        _alert("orca-7679203", boundary_api),
        _alert("orca-7704352", boundary_api),
    ]

    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "params", return_value=BASE_PARAMS)
    mocker.patch.object(demisto, "getLastRun", return_value=last_run_in)
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_send_events = mocker.patch("OrcaEventCollector.send_events_to_xsiam")
    mocker.patch("OrcaEventCollector.get_alerts", return_value=fetched)
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")

    main()

    # Nothing is re-sent: both boundary events were recognized as duplicates.
    mock_send_events.assert_not_called()
    # Cursor is held on the boundary second with its ids preserved (no forward loop onto itself).
    mock_set_last_run.assert_called_once_with({"lastRun": boundary_z, "lastRunIds": ["orca-7679203", "orca-7704352"]})


@freeze_time(FROZEN_NOW)
def test_main_get_events_command(mocker):
    """
    Given:
        - command="orca-security-get-events"
    When:
        - Calling main.
    Then:
        - Fetches events (with end_time upper bound).
        - Does *not* send events to XSIAM (should_push_events is false).
        - Does *not* dedup (stateless debug command).
        - Returns results via return_results.
        - Does *not* call setLastRun.
    """
    alerts = [_alert("c", "2023-01-02T10:00:00Z")]

    mocker.patch.object(demisto, "command", return_value="orca-security-get-events")
    mocker.patch.object(demisto, "params", return_value=BASE_PARAMS)
    mocker.patch.object(demisto, "args", return_value={"should_push_events": "false"})
    mocker.patch.object(demisto, "getLastRun", return_value={})  # First run
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_send_events = mocker.patch("OrcaEventCollector.send_events_to_xsiam")
    mock_return_results = mocker.patch("OrcaEventCollector.return_results")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")

    mocker.patch("OrcaEventCollector.get_alerts", return_value=alerts)

    main()

    # 1. Verify results were returned
    mock_return_results.assert_called_once()
    assert mock_return_results.call_args[0][0].raw_response == alerts

    # 2. Verify events were *not* sent
    mock_send_events.assert_not_called()

    # 3. Verify last_run was NOT touched by the manual get-events command.
    mock_set_last_run.assert_not_called()
