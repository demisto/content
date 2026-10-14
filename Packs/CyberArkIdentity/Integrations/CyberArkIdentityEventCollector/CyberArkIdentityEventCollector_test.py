import json
import re
from datetime import datetime, timedelta, UTC

import demistomock as demisto
import pytest
import requests_mock

URL = "https://example.my.idaptive.app/"
DEMISTO_PARAMS = {
    "url": URL,
    "credentials": {
        "identifier": "admin@example.com.11",
        "password": "123456",
    },
    # Before the test_data/events.json events, so the first fetch includes them.
    "from": "2022-05-15T00:00:00",
    "app_id": "test_app",
    "limit": 100,
}
BASE_MS = 1652621700000
FIRST_FETCH = "2022-05-15T13:00:00"
WHEN_OCCURRED_MS = re.compile(r"/Date\((-?\d+)")


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def ms_to_cursor(milliseconds: int) -> str:
    return (datetime(1970, 1, 1) + timedelta(milliseconds=milliseconds)).strftime("%Y-%m-%dT%H:%M:%S.%f")


def cursor_to_ms(cursor: str) -> int:
    return (datetime.strptime(cursor, "%Y-%m-%dT%H:%M:%S.%f") - datetime(1970, 1, 1)) // timedelta(milliseconds=1)


def _build_row(index: int, when_occurred_ms: int | None, when_occurred: str | None = None) -> dict:
    """Build one RedRock 'Results' entry. Pass when_occurred to set a raw WhenOccurred value."""
    if when_occurred is None and when_occurred_ms is not None:
        when_occurred = f"/Date({when_occurred_ms})/"
    return {
        "Entities": [{"Type": "User", "Key": f"key-{index}", "IsForeignKey": True}],
        "Row": {"_TableName": "events", "ID": f"event-{index}", "Level": "Info", "WhenOccurred": when_occurred},
    }


class FakeRedRock:
    """In-memory RedRock: filters by the query's cursor, sorts by (WhenOccurred, ID), pages.

    precision="second" compares the cursor truncated to whole seconds, like a server that ignores milliseconds.
    Rows with no parseable WhenOccurred always match and sort first.
    """

    def __init__(self, rows: list, precision: str = "millisecond", full_count: int | None | str = "actual"):
        self.rows = rows
        self.precision = precision
        self.full_count = full_count
        self.requested_pages: list = []
        self.page_sizes: list = []
        self.after_page = None  # optional callback(page_number), run after each page is served

    @staticmethod
    def _ms(row: dict) -> int | None:
        match = WHEN_OCCURRED_MS.search(str(row["Row"].get("WhenOccurred") or ""))
        return int(match.group(1)) if match else None

    def __call__(self, request, context):
        body = json.loads(request.text)
        match = re.search(r"WhenOccurred >= '([^']+)'", body["Script"])
        assert match, f"query is not using an inclusive cursor: {body['Script']}"
        cursor_ms = cursor_to_ms(match.group(1))
        if self.precision == "second":
            cursor_ms -= cursor_ms % 1000
        matching = sorted(
            (row for row in self.rows if self._ms(row) is None or self._ms(row) >= cursor_ms),
            key=lambda row: (self._ms(row) or -1, row["Row"]["ID"]),
        )
        page_number, page_size = body["args"]["PageNumber"], body["args"]["PageSize"]
        self.requested_pages.append(page_number)
        self.page_sizes.append(page_size)
        page_rows = matching[(page_number - 1) * page_size : page_number * page_size]
        if self.after_page:
            self.after_page(page_number)
        full_count = len(matching) if self.full_count == "actual" else self.full_count
        context.status_code = 200
        return {"success": True, "Result": {"Count": len(page_rows), "FullCount": full_count, "Results": page_rows}}


def _run(mocker, redrock, last_run: dict | None = None, command: str = "fetch-events", args: dict | None = None, **params):
    """Run one command against a fake RedRock.

    Returns (events sent to XSIAM, last run saved or None, command result contents or None, return_error message or None).
    """
    demisto_params = dict(DEMISTO_PARAMS) | {"from": FIRST_FETCH} | params
    mocker.patch.object(demisto, "params", return_value=demisto_params)
    mocker.patch.object(demisto, "args", return_value=args or {})
    mocker.patch.object(demisto, "command", return_value=command)
    mocker.patch.object(demisto, "getLastRun", return_value=last_run or {})
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mock_results = mocker.patch.object(demisto, "results")
    mock_return_error = mocker.patch("CyberArkIdentityEventCollector.return_error")
    sent = mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json=redrock)

        from CyberArkIdentityEventCollector import main

        main(command, demisto_params | (args or {}))

    events = sent.call_args[0][0] if sent.called else []
    new_last_run = mock_set_last_run.call_args[0][0] if mock_set_last_run.called else None
    contents = mock_results.call_args[0][0] if mock_results.called else None
    error = mock_return_error.call_args[0][0] if mock_return_error.called else None
    return events, new_last_run, contents, error


def _ids(events: list) -> list:
    return [event["ID"] for event in events]


def test_fetch_events_few_events(mocker):
    """
    Given
        - 3 events in CyberArk.
    When
        - cyberarkidentity-get-events runs with should_push_events=True.
    Then
        - All 3 events are returned and the last run keeps only the newest event's ID.
    """
    events, last_run, contents, error = _run(
        mocker,
        util_load_json("test_data/events.json"),
        command="cyberarkidentity-get-events",
        args={"should_push_events": "true"},
        **{"from": "2022-05-15T00:00:00"},
    )
    assert error is None
    assert len(contents["Contents"]) == len(events) == 3
    assert last_run == {"from": "2022-05-15T13:35:26.645000", "ids": ["123456abcdef.123456.abcdeh"]}


def test_fetch_events_no_events(mocker):
    """
    Given
        - No events in CyberArk.
    When
        - cyberarkidentity-get-events runs with should_push_events=True.
    Then
        - Nothing is returned and the last run is not updated.
    """
    events, last_run, contents, error = _run(
        mocker, {"Result": {}}, command="cyberarkidentity-get-events", args={"should_push_events": "true"}
    )
    assert error is None
    assert not contents["Contents"]
    assert not events
    assert last_run is None


def test_fetch_events_limit_set_to_one(mocker):
    """
    Given
        - 3 events in CyberArk.
    When
        - cyberarkidentity-get-events runs with limit=1 and should_push_events=True.
    Then
        - Only the oldest event is returned and the last run points at it.
    """
    events, last_run, contents, error = _run(
        mocker,
        util_load_json("test_data/events.json"),
        command="cyberarkidentity-get-events",
        args={"should_push_events": "true", "limit": "1"},
        **{"from": "2022-05-15T00:00:00"},
    )
    assert error is None
    assert len(contents["Contents"]) == len(events) == 1
    assert last_run == {"from": "2022-05-15T13:35:03.570000", "ids": ["123456abcdef.123456.abcdef"]}


def test_fetch_events_paginates_full_backlog(mocker):
    """
    Given
        - 2500 matching events (3 pages).
    When
        - fetch-events runs.
    Then
        - All events are collected and the cursor is the newest event.
    """
    redrock = FakeRedRock([_build_row(i, BASE_MS + i) for i in range(2500)])
    events, last_run, _, error = _run(mocker, redrock)
    assert error is None
    assert redrock.requested_pages == [1, 2, 3]
    assert len(events) == 2500
    assert last_run == {"from": ms_to_cursor(BASE_MS + 2499), "ids": ["event-2499"]}


def test_fetch_events_stops_at_limit(mocker):
    """
    Given
        - 6,500 matching events and the default limit of 5000.
    When
        - fetch-events runs twice.
    Then
        - Run 1 sends 5000 events (5 pages); run 2 collects the rest, with no duplicates or gaps.
    """
    from CyberArkIdentityEventCollector import DEFAULT_LIMIT

    redrock = FakeRedRock([_build_row(i, BASE_MS + i) for i in range(6500)])
    first_events, first_last_run, _, _ = _run(mocker, redrock, limit=None)
    assert redrock.requested_pages == [1, 2, 3, 4, 5]
    assert len(first_events) == DEFAULT_LIMIT
    assert first_last_run["ids"] == [f"event-{DEFAULT_LIMIT - 1}"]

    second_events, second_last_run, _, _ = _run(mocker, redrock, last_run=first_last_run, limit=None)
    all_ids = _ids(first_events + second_events)
    assert len(all_ids) == len(set(all_ids)) == 6500
    assert second_last_run["ids"] == ["event-6499"]


@pytest.mark.parametrize(
    "limit, expected_page_size, expected_pages",
    [(50, 50, [1]), (1000, 1000, [1]), (2500, 1000, [1, 2, 3])],
)
def test_fetch_events_page_size_follows_limit(mocker, limit, expected_page_size, expected_pages):
    """
    Given
        - 5000 matching events and a limit below, at, or above one page.
    When
        - fetch-events runs.
    Then
        - The request asks for min(limit, 1000) rows per page and exactly `limit` events are sent.
    """
    redrock = FakeRedRock([_build_row(i, BASE_MS + i) for i in range(5000)])
    events, _, _, error = _run(mocker, redrock, limit=limit)
    assert error is None
    assert redrock.page_sizes == [expected_page_size] * len(expected_pages)
    assert redrock.requested_pages == expected_pages
    assert len(events) == limit


def test_fetch_events_millisecond_tie_across_limit_is_not_lost(mocker):
    """
    Given
        - 5 events share one millisecond across the limit boundary.
    When
        - fetch-events runs twice.
    Then
        - Each event is sent exactly once.
    """
    limit = 2500
    tie_ms = BASE_MS + limit
    rows = [_build_row(i, BASE_MS + i) for i in range(limit - 2)]
    rows += [_build_row(i, tie_ms) for i in range(limit - 2, limit + 3)]  # 2 inside the limit, 3 after
    rows += [_build_row(i, tie_ms + 1 + i) for i in range(limit + 3, limit + 10)]
    redrock = FakeRedRock(rows)

    first_events, first_last_run, _, _ = _run(mocker, redrock, limit=limit)
    assert len(first_events) == limit
    tie_ids_in_first_run = sorted(event["ID"] for event in first_events if event["WhenOccurred"] == f"/Date({tie_ms})/")
    assert sorted(first_last_run["ids"]) == tie_ids_in_first_run

    second_events, _, _, _ = _run(mocker, redrock, last_run=first_last_run, limit=limit)
    all_ids = _ids(first_events + second_events)
    assert len(all_ids) == len(set(all_ids)) == len(rows)


@pytest.mark.parametrize("limit", [0, -5])
def test_invalid_limit_returns_error(mocker, limit):
    """
    Given
        - A limit of 0 or below.
    When
        - fetch-events runs.
    Then
        - The run fails with a clear error and no query is made.
    """
    redrock = FakeRedRock([_build_row(0, BASE_MS)])
    events, last_run, _, error = _run(mocker, redrock, limit=limit)
    assert "limit must be a positive number" in error
    assert events == []
    assert last_run is None
    assert redrock.requested_pages == []


def test_second_precision_server_does_not_cause_duplicates(mocker):
    """
    Given
        - A server that compares the cursor at whole-second precision, and a previous run that ended mid-second.
    When
        - fetch-events runs.
    Then
        - Events earlier in the cursor's second are returned by the server but dropped client-side.
    """
    rows = [_build_row(i, BASE_MS + i * 100) for i in range(30)]  # 10 events per second
    redrock = FakeRedRock(rows, precision="second")
    # The previous run sent event-0 .. event-14 and ended at event-14 (mid-second).
    previous_last_run = {"from": ms_to_cursor(BASE_MS + 1400), "ids": ["event-14"]}

    events, last_run, _, error = _run(mocker, redrock, last_run=previous_last_run)
    assert error is None
    assert _ids(events) == [f"event-{i}" for i in range(15, 30)]
    assert last_run["ids"] == ["event-29"]


def test_last_run_ids_merged_when_cursor_does_not_move(mocker):
    """
    Given
        - All returned events are at the previous cursor millisecond, some already sent.
    When
        - fetch-events runs.
    Then
        - Only new events are sent and the saved IDs include old and new.
    """
    cursor = ms_to_cursor(BASE_MS)
    redrock = FakeRedRock([_build_row(i, BASE_MS) for i in range(4)])

    events, last_run, _, _ = _run(mocker, redrock, last_run={"from": cursor, "ids": ["event-0", "event-1"]})
    assert _ids(events) == ["event-2", "event-3"]
    assert last_run["from"] == cursor
    assert sorted(last_run["ids"]) == ["event-0", "event-1", "event-2", "event-3"]


def test_fetch_events_already_fetched_ids_are_skipped(mocker):
    """
    Given
        - 3 events, 2 already fetched in the previous run.
    When
        - fetch-events runs.
    Then
        - Only the new event is sent.
    """
    redrock = FakeRedRock([_build_row(i, BASE_MS + i) for i in range(3)])
    events, _, _, _ = _run(mocker, redrock, last_run={"from": ms_to_cursor(BASE_MS), "ids": ["event-0", "event-1"]})
    assert _ids(events) == ["event-2"]


def test_row_repeated_across_page_boundary_is_sent_once(mocker):
    """
    Given
        - An event with an old timestamp appears after page 1 is read, shifting page 2 by one row.
    When
        - fetch-events runs.
    Then
        - The row pushed from page 1 onto page 2 is not sent twice.
    """
    from CyberArkIdentityEventCollector import PAGE_SIZE

    redrock = FakeRedRock([_build_row(i, BASE_MS + i * 2) for i in range(1500)])

    def insert_late_event(page_number):
        if page_number == 1:
            redrock.rows.append(_build_row(99999, BASE_MS + 501))

    redrock.after_page = insert_late_event
    events, _, _, error = _run(mocker, redrock)
    assert error is None
    assert redrock.requested_pages == [1, 2]
    assert f"event-{PAGE_SIZE - 1}" in _ids(events)
    assert len(_ids(events)) == len(set(_ids(events)))


def test_unparseable_when_occurred_does_not_crash(mocker):
    """
    Given
        - One event with no WhenOccurred, one with a time-zone offset, and normal events.
    When
        - fetch-events runs.
    Then
        - All events are sent, the cursor comes from the parseable ones, and the unparseable event's ID
          is kept so it isn't sent again.
    """
    rows = [_build_row(i, BASE_MS + i) for i in range(3)]
    rows.append(_build_row(3, None))
    rows.append(_build_row(4, None, when_occurred=f"/Date({BASE_MS + 10}+0300)/"))
    redrock = FakeRedRock(rows)

    events, last_run, _, error = _run(mocker, redrock)
    assert error is None
    assert sorted(_ids(events)) == ["event-0", "event-1", "event-2", "event-3", "event-4"]
    assert last_run["from"] == ms_to_cursor(BASE_MS + 10)
    assert sorted(last_run["ids"]) == ["event-3", "event-4"]


def test_all_rows_unparseable_keeps_cursor_and_dedups(mocker):
    """
    Given
        - Every returned event has no parseable WhenOccurred.
    When
        - fetch-events runs twice.
    Then
        - Run 1 sends them and keeps the previous cursor with their IDs; run 2 sends nothing.
    """
    cursor = ms_to_cursor(BASE_MS)
    redrock = FakeRedRock([_build_row(i, None) for i in range(3)])

    first_events, first_last_run, _, error = _run(mocker, redrock, last_run={"from": cursor, "ids": []})
    assert error is None
    assert len(first_events) == 3
    assert first_last_run == {"from": cursor, "ids": ["event-0", "event-1", "event-2"]}

    second_events, _, _, _ = _run(mocker, redrock, last_run=first_last_run)
    assert second_events == []


def test_null_full_count(mocker):
    """
    Given
        - RedRock returns FullCount: null.
    When
        - fetch-events runs.
    Then
        - The run doesn't crash and all events are sent.
    """
    redrock = FakeRedRock([_build_row(i, BASE_MS + i) for i in range(3)], full_count=None)
    events, _, _, error = _run(mocker, redrock)
    assert error is None
    assert len(events) == 3


def test_get_events_push_with_limit_cut_at_a_tie(mocker):
    """
    Given
        - 4 events share one millisecond, and cyberarkidentity-get-events runs with limit=2 and push enabled.
    When
        - fetch-events runs afterwards.
    Then
        - The command sends 2 events and saves the cursor; fetch-events sends the other 2 with no duplicates.
    """
    rows = [_build_row(i, BASE_MS) for i in range(4)] + [_build_row(4, BASE_MS + 1)]
    redrock = FakeRedRock(rows)

    command_events, command_last_run, _, error = _run(
        mocker, redrock, command="cyberarkidentity-get-events", args={"should_push_events": "true", "limit": "2"}
    )
    assert error is None
    assert _ids(command_events) == ["event-0", "event-1"]
    assert command_last_run == {"from": ms_to_cursor(BASE_MS), "ids": ["event-0", "event-1"]}

    fetch_events, _, _, _ = _run(mocker, redrock, last_run=command_last_run)
    assert sorted(_ids(command_events + fetch_events)) == ["event-0", "event-1", "event-2", "event-3", "event-4"]


def test_get_events_without_push_does_not_save_last_run(mocker):
    """
    Given
        - cyberarkidentity-get-events with should_push_events=false.
    When
        - The command runs.
    Then
        - Events are returned, nothing is sent and the last run isn't saved.
    """
    redrock = FakeRedRock([_build_row(i, BASE_MS + i) for i in range(3)])
    events, last_run, contents, _ = _run(
        mocker, redrock, command="cyberarkidentity-get-events", args={"should_push_events": "false"}
    )
    assert len(contents["Contents"]) == 3
    assert events == []
    assert last_run is None


def test_test_module_reads_one_page(mocker):
    """
    Given
        - 2500 matching events.
    When
        - test-module runs.
    Then
        - Only page 1 is requested and the result is 'ok'.
    """
    redrock = FakeRedRock([_build_row(i, BASE_MS + i) for i in range(2500)])
    _, last_run, contents, error = _run(mocker, redrock, command="test-module")
    assert error is None
    assert contents == "ok"
    assert redrock.requested_pages == [1]
    assert last_run is None


REDROCK_FAILURE_RESPONSE = {
    "success": False,
    "Result": None,
    "Message": "Query has failed: query timed out",
    "MessageID": "_I18N_RedrockQuery",
    "Exception": "Idaptive.Cloud.Query.RedrockQueryException: Query has failed",
    "ErrorID": "test-error-id",
    "ErrorCode": None,
}


@pytest.mark.parametrize("failing_page", [1, 2])
def test_fetch_events_redrock_failure_is_raised(mocker, failing_page):
    """
    Given
        - RedRock fails (success=false, Result=null) on page 1 or page 2.
    When
        - fetch-events runs.
    Then
        - The error includes Message and ErrorID; nothing is sent and the last run is unchanged.
    """
    from CyberArkIdentityEventCollector import PAGE_SIZE

    first_page = [_build_row(i, BASE_MS + i) for i in range(PAGE_SIZE)]

    def redrock(request, context):
        context.status_code = 200
        if json.loads(request.text)["args"]["PageNumber"] == failing_page:
            return REDROCK_FAILURE_RESPONSE
        return {"success": True, "Result": {"Count": PAGE_SIZE, "FullCount": PAGE_SIZE * 2, "Results": first_page}}

    events, last_run, _, error = _run(mocker, redrock)
    assert f"page {failing_page}" in error
    assert "Query has failed: query timed out" in error
    assert "test-error-id" in error
    assert events == []
    assert last_run is None


@pytest.mark.parametrize(
    "token_response, expected_error",
    [
        ({"status_code": 401, "json": {"error": "invalid_client"}}, "CyberArk authentication failed"),
        ({"status_code": 200, "json": {"token_type": "Bearer"}}, "no access_token in the response"),
    ],
)
def test_authentication_failure_is_clear(mocker, token_response, expected_error):
    """
    Given
        - The token endpoint returns 401, or 200 without an access_token.
    When
        - fetch-events runs.
    Then
        - The run fails with a clear authentication error and no RedRock query is made.
    """
    mocker.patch.object(demisto, "params", return_value=dict(DEMISTO_PARAMS))
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mock_return_error = mocker.patch("CyberArkIdentityEventCollector.return_error")
    mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", **token_response)
        redrock = m.post(f"{URL}RedRock/Query", json={"success": True, "Result": {}})

        from CyberArkIdentityEventCollector import main

        main("fetch-events", dict(DEMISTO_PARAMS))

    assert expected_error in mock_return_error.call_args[0][0]
    assert not redrock.called


def test_invalid_saved_cursor_fails_loudly(mocker):
    """
    Given
        - A saved last run whose 'from' isn't in the cursor format.
    When
        - fetch-events runs.
    Then
        - The run fails with an error that says how to recover, instead of refetching from the first fetch time.
    """
    redrock = FakeRedRock([_build_row(0, BASE_MS)])
    events, _, _, error = _run(mocker, redrock, last_run={"from": "3 days", "ids": []})
    assert "Invalid saved last run cursor" in error
    assert "Reset the last run" in error
    assert events == []
    assert redrock.requested_pages == []


def test_first_fetch_uses_relative_from(mocker):
    """
    Given
        - No saved last run and a relative first fetch time.
    When
        - The cursor is computed.
    Then
        - The first fetch time is parsed with dateparser (not the strict cursor format).
    """
    from CyberArkIdentityEventCollector import DATETIME_FORMAT, get_from_time

    from_time = get_from_time({"from": "3 days"}, last_run={})
    parsed = datetime.strptime(from_time, DATETIME_FORMAT)
    now = datetime.now(UTC).replace(tzinfo=None)
    assert timedelta(days=2, hours=23) < now - parsed < timedelta(days=3, hours=1)


def test_request_params_include_order_by_and_caching():
    """
    Given
        - A cursor.
    When
        - Building the RedRock request.
    Then
        - The query uses >=, sorts by WhenOccurred then ID, and requests live data.
    """
    from CyberArkIdentityEventCollector import PAGE_SIZE, get_request_params

    params = get_request_params("2022-05-15T13:00:00.000000", URL)
    body = json.loads(params["data"])
    assert "where WhenOccurred >= '2022-05-15T13:00:00.000000'" in body["Script"]
    assert "ORDER BY WhenOccurred ASC, ID ASC" in body["Script"]
    assert body["args"] == {"PageNumber": 1, "PageSize": PAGE_SIZE, "Caching": -1}
    assert params["url"] == f"{URL}RedRock/Query"
