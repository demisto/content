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
    add_one_second,
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


def test_get_alerts_start_offset_resumes_mid_second(mocker):
    """
    Given:
        - A non-zero start_offset (an in-second resume point carried from a wedged boundary second).
    When:
        - Calling get_alerts with that start_offset and a small page_size.
    Then:
        - The FIRST API request uses start_at_index == start_offset (not 0).
        - Subsequent pages advance the offset by the number of rows returned.
    """
    client = Client(server_url="https://test.com/api", headers={})
    full_page_1 = _make_alerts(2)
    short_page_2 = _make_alerts(1)
    responses = [
        {"status": "success", "data": full_page_1},
        {"status": "success", "data": short_page_2},
    ]
    mock_request = mocker.patch.object(client, "get_alerts_request", side_effect=responses)
    mocker.patch.object(demisto, "debug")

    alerts = get_alerts(
        client,
        max_fetch=1000,
        last_fetch="2023-01-01T00:00:00Z",
        end_time=END_TIME,
        start_offset=100,
        page_size=2,
    )

    assert alerts == full_page_1 + short_page_2
    # Pagination resumes at the persisted offset (100) then advances by rows returned (100 -> 102).
    assert [call.args[1] for call in mock_request.call_args_list] == [100, 102]


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
            # newest LastUpdated + boundary ids; offset resets to 0 (page not full / second crossed)
            {"lastRun": "2023-01-01T13:00:00Z", "lastRunIds": ["b"], "lastRunOffset": 0},
            2,
        ),
        (
            "2. First Run (no events)",
            {},  # No last run
            [],  # No alerts
            "2023-01-01T00:00:00Z",
            # Keeps first_fetch time, no ids, offset 0
            {"lastRun": "2023-01-01T00:00:00Z", "lastRunIds": [], "lastRunOffset": 0},
            0,
        ),
        (
            "3. Second Run (fetches new events)",
            {"lastRun": "2023-01-01T09:00:00Z", "lastRunIds": ["z"]},
            [_alert("c", "2023-01-02T10:00:00Z")],
            "2023-01-01T09:00:00Z",  # Uses lastRun time
            {"lastRun": "2023-01-02T10:00:00Z", "lastRunIds": ["c"], "lastRunOffset": 0},
            1,
        ),
        (
            "4. Second Run (no new events)",
            {"lastRun": "2023-01-01T09:00:00Z", "lastRunIds": ["z"]},
            [],  # No alerts
            "2023-01-01T09:00:00Z",
            # unchanged, ids preserved, offset 0
            {"lastRun": "2023-01-01T09:00:00Z", "lastRunIds": ["z"], "lastRunOffset": 0},
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
        start_offset=0,  # no in-second backlog carried into these scenarios
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
    mock_set_last_run.assert_called_once_with({"lastRun": "2023-01-02T10:00:01Z", "lastRunIds": ["fresh"], "lastRunOffset": 0})


@freeze_time(FROZEN_NOW)
def test_main_fetch_events_stuck_cursor_regression(mocker):
    """Stuck-cursor regression: the API returns only the boundary events again in '+00:00' form.

    They must dedup against the persisted '...Z' ids (nothing sent), and the cursor must be held.
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
    mock_set_last_run.assert_called_once_with(
        {"lastRun": boundary_z, "lastRunIds": ["orca-7679203", "orca-7704352"], "lastRunOffset": 0}
    )


@freeze_time(FROZEN_NOW)
def test_main_fetch_events_boundary_second_exceeds_max_fetch(mocker):
    """Oversized-boundary-second wedge: a full page (== max_fetch) all on the same second.

    The cursor timestamp must be held and lastRunOffset must advance by the page size so the next
    run resumes mid-second.
    """
    boundary = "2026-08-06T00:57:51Z"
    params = {**BASE_PARAMS, "max_fetch": "2"}
    last_run_in = {"lastRun": boundary, "lastRunIds": ["x0", "x1"]}
    # A full page (== max_fetch) entirely within the boundary second -> second not fully drained.
    fetched = [_alert("x2", boundary), _alert("x3", boundary)]

    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "getLastRun", return_value=last_run_in)
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mocker.patch("OrcaEventCollector.send_events_to_xsiam")
    mock_get_alerts = mocker.patch("OrcaEventCollector.get_alerts", return_value=fetched)
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")

    main()

    # This run starts at offset 0 (no prior backlog).
    mock_get_alerts.assert_called_once_with(mocker.ANY, 2, boundary, END_TIME, start_offset=0)
    # Cursor held on the same second; offset advanced by the page size so the next run resumes there.
    persisted = mock_set_last_run.call_args[0][0]
    assert persisted["lastRun"] == boundary
    assert persisted["lastRunOffset"] == 2


@freeze_time(FROZEN_NOW)
def test_main_fetch_events_offset_resumes_then_resets_on_second_cross(mocker):
    """
    Follow-on to the wedge guard: the previous run left an in-second backlog (lastRunOffset=2).
    This run resumes at that offset and this time the page is short / crosses into a NEWER second,
    so the cursor advances normally and the offset resets to 0.

    Given:
        - lastRunOffset=2 carried from the previous run; max_fetch=2.
        - get_alerts returns a partial page (1 alert) at a NEWER second (second fully consumed).
    When:
        - Calling main() with 'fetch-events'.
    Then:
        - get_alerts is called with start_offset=2 (resume mid-second).
        - The cursor advances to the newer second and lastRunOffset resets to 0.
    """
    old_second = "2026-08-06T00:57:51Z"
    new_second = "2026-08-06T00:57:52Z"
    params = {**BASE_PARAMS, "max_fetch": "2"}
    last_run_in = {"lastRun": old_second, "lastRunIds": ["x0", "x1"], "lastRunOffset": 2}
    # Partial page (< max_fetch) at a newer second -> boundary second fully drained, cross over.
    fetched = [_alert("y0", new_second)]

    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "getLastRun", return_value=last_run_in)
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mocker.patch("OrcaEventCollector.send_events_to_xsiam")
    mock_get_alerts = mocker.patch("OrcaEventCollector.get_alerts", return_value=fetched)
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")

    main()

    # Resumes mid-second at the persisted offset.
    mock_get_alerts.assert_called_once_with(mocker.ANY, 2, old_second, END_TIME, start_offset=2)
    # Cursor crosses to the newer second and the offset resets.
    persisted = mock_set_last_run.call_args[0][0]
    assert persisted["lastRun"] == new_second
    assert persisted["lastRunOffset"] == 0


@freeze_time(FROZEN_NOW)
def test_main_fetch_events_wedge_guard_survives_full_page_emptied_by_dedup(mocker):
    """
    Regression: on an oversized boundary second, get_alerts re-returns the same full page (all at the
    boundary second) whose ids are all already in lastRunIds, so dedup empties the page. If the wedge
    guard keys off the POST-dedup list it sees 0 events, never fires, and the cursor stays pinned. The
    guard MUST key off the RAW page size instead so the offset still advances.

    Given:
        - max_fetch=2; lastRunOffset=0; lastRunIds holds BOTH ids at the boundary second.
        - get_alerts returns a FULL page (2 alerts) all at the boundary second - identical ids.
    When:
        - Calling main() with 'fetch-events' (dedup removes BOTH -> empty push list).
    Then:
        - Nothing is sent (both were duplicates).
        - The cursor is HELD on the boundary second AND lastRunOffset advances by the RAW page size (2),
          so the next run resumes past this slice instead of wedging.
    """
    boundary = "2026-08-06T01:37:59Z"
    params = {**BASE_PARAMS, "max_fetch": "2"}
    last_run_in = {"lastRun": boundary, "lastRunIds": ["e0", "e1"], "lastRunOffset": 0}
    # Full page (== max_fetch), all at the boundary second, ids already seen -> dedup empties it.
    fetched = [_alert("e0", boundary), _alert("e1", boundary)]

    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "getLastRun", return_value=last_run_in)
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_send_events = mocker.patch("OrcaEventCollector.send_events_to_xsiam")
    mocker.patch("OrcaEventCollector.get_alerts", return_value=fetched)
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")

    main()

    # Dedup removed both -> nothing pushed.
    mock_send_events.assert_not_called()
    # Critical: despite the emptied page, the guard fired off the RAW page size and advanced the offset.
    persisted = mock_set_last_run.call_args[0][0]
    assert persisted["lastRun"] == boundary
    assert persisted["lastRunOffset"] == 2


def test_add_one_second():
    """
    Given:
        - A DATE_FORMAT cursor timestamp (and an unparseable value).
    When:
        - Calling add_one_second.
    Then:
        - The timestamp is advanced by exactly one second (incl. minute/hour rollover).
        - An unparseable value is returned unchanged (safe fallback).
    """
    assert add_one_second("2026-08-06T01:37:59Z") == "2026-08-06T01:38:00Z"
    assert add_one_second("2026-08-06T01:59:59Z") == "2026-08-06T02:00:00Z"
    assert add_one_second("not-a-date") == "not-a-date"


@freeze_time(FROZEN_NOW)
def test_main_fetch_events_drained_second_terminator_no_infinite_loop(mocker):
    """
    Regression for the infinite duplicate loop on an exact-multiple boundary second: after the offset
    walk fully drains a second whose size is an exact multiple of max_fetch, the resume run asks for
    start_offset=N and the API returns NOTHING (second exhausted, no newer events yet). If we merely
    reset the offset to 0 on the SAME cursor, the inclusive lower bound re-reads that drained second
    forever, re-sending it as duplicates every cycle. The terminator must instead STEP the cursor one
    second forward and reset the offset, so the drained second is never re-read.

    Given:
        - lastRunOffset=200 (>0, mid-drain of an exact-multiple second); max_fetch=100.
        - get_alerts returns an EMPTY page (offset is past the end; no newer events yet).
    When:
        - Calling main() with 'fetch-events'.
    Then:
        - Nothing is sent.
        - The cursor STEPS to boundary + 1 second, lastRunOffset resets to 0, and lastRunIds clears -
          so the next window starts strictly after the drained second (no re-read, loop terminated).
    """
    boundary = "2026-08-06T01:37:59Z"
    params = {**BASE_PARAMS, "max_fetch": "100"}
    last_run_in = {"lastRun": boundary, "lastRunIds": ["p198", "p199"], "lastRunOffset": 200}

    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "getLastRun", return_value=last_run_in)
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_send_events = mocker.patch("OrcaEventCollector.send_events_to_xsiam")
    # Empty page: resuming at offset 200 returns nothing (second fully drained, nothing newer yet).
    mock_get_alerts = mocker.patch("OrcaEventCollector.get_alerts", return_value=[])
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")

    main()

    # We resumed at the persisted offset.
    mock_get_alerts.assert_called_once_with(mocker.ANY, 100, boundary, END_TIME, start_offset=200)
    # Nothing to send.
    mock_send_events.assert_not_called()
    # Loop terminated: cursor stepped one second forward, offset cleared, ids cleared.
    persisted = mock_set_last_run.call_args[0][0]
    assert persisted["lastRun"] == "2026-08-06T01:38:00Z"
    assert persisted["lastRunOffset"] == 0
    assert persisted["lastRunIds"] == []


@freeze_time(FROZEN_NOW)
def test_main_fetch_events_empty_page_at_offset_zero_holds_cursor(mocker):
    """
    Guard against over-stepping: an empty page when lastRunOffset==0 is the ordinary "no new events"
    case (NOT a drained oversized second). The cursor must be HELD, not stepped forward - stepping
    here would skip the inclusive boundary and risk missing events that arrive exactly at last_fetch.

    Given:
        - lastRunOffset=0; get_alerts returns an empty page.
    When:
        - Calling main() with 'fetch-events'.
    Then:
        - The cursor is unchanged and the offset stays 0 (terminator does NOT fire).
    """
    boundary = "2026-08-06T01:37:59Z"
    params = {**BASE_PARAMS, "max_fetch": "100"}
    last_run_in = {"lastRun": boundary, "lastRunIds": ["a"], "lastRunOffset": 0}

    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "getLastRun", return_value=last_run_in)
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_send_events = mocker.patch("OrcaEventCollector.send_events_to_xsiam")
    mocker.patch("OrcaEventCollector.get_alerts", return_value=[])
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "info")

    main()

    mock_send_events.assert_not_called()
    persisted = mock_set_last_run.call_args[0][0]
    # Cursor HELD (not stepped) because offset was 0 - ordinary "no new events" case.
    assert persisted["lastRun"] == boundary
    assert persisted["lastRunOffset"] == 0


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
