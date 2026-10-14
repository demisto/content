import json
from datetime import datetime

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
    "from": "3 days",
    "app_id": "test_app",
    "limit": 100,
}


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def mock_set_last_run(last_run):
    return last_run


# @freeze_time('2022-05-12T00:00:00Z')
def test_fetch_events_few_events(mocker):
    """
    Given
        - 3 events was created in CyberArk side in the last 3 days.
    When
        - fetch-events is running (with limit set to 100).
    Then
        - Verify that all 3 events were created in XSIAM.
        - Verify last_run was set as expected.
    """

    params = mocker.patch.object(demisto, "params", return_value=DEMISTO_PARAMS)
    args = mocker.patch.object(demisto, "args", return_value={"should_push_events": True})
    mock_last_run = mocker.patch.object(demisto, "setLastRun", side_effect=mock_set_last_run)
    results = mocker.patch.object(demisto, "results")
    mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json=util_load_json("test_data/events.json"))

        from CyberArkIdentityEventCollector import main

        main("cyberarkidentity-get-events", params.return_value | args.return_value)

    events = results.call_args[0][0]["Contents"]
    last_run = mock_last_run.call_args[0][0]
    assert len(events) == 3
    assert last_run.get("from") == "2022-05-15T13:35:26.645000"
    # Only the event at the cursor's millisecond is kept for dedup.
    assert last_run.get("ids") == ["123456abcdef.123456.abcdeh"]


def test_fetch_events_no_events(mocker):
    """
    Given
        - 3 events was created in CyberArk side in the last 3 days.
    When
        - fetch-events is running (with limit set to 100).
    Then
        - Make sure no events was created in XSIAM.
        - Make sure last_run was set as expected.
    """

    params = mocker.patch.object(demisto, "params", return_value=DEMISTO_PARAMS)
    args = mocker.patch.object(demisto, "args", return_value={"should_push_events": True})
    mock_last_run = mocker.patch.object(demisto, "setLastRun", side_effect=mock_set_last_run)
    results = mocker.patch.object(demisto, "results")
    mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json={"Result": {}})

        from CyberArkIdentityEventCollector import main

        main("cyberarkidentity-get-events", params.return_value | args.return_value)

    events = results.call_args[0][0]["Contents"]
    last_run = mock_last_run.call_args
    assert not last_run
    assert not events


class FakeRedRock:
    """In-memory RedRock: filters by the query's WhenOccurred cursor, sorts by (WhenOccurred, ID), pages."""

    def __init__(self, rows: list):
        self.rows = rows
        self.requested_pages: list = []

    @staticmethod
    def _when_occurred_ms(row: dict) -> int:
        return int(row["Row"]["WhenOccurred"].removesuffix(")/").removeprefix("/Date("))

    def __call__(self, request, context):
        import re
        from datetime import timedelta

        body = json.loads(request.text)
        match = re.search(r"WhenOccurred >= '([^']+)'", body["Script"])
        assert match, f"query is not using an inclusive cursor: {body['Script']}"
        cursor_ms = (datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S.%f") - datetime(1970, 1, 1)) // timedelta(
            milliseconds=1
        )
        matching = sorted(
            (row for row in self.rows if self._when_occurred_ms(row) >= cursor_ms),
            key=lambda row: (self._when_occurred_ms(row), row["Row"]["ID"]),
        )
        page_number, page_size = body["args"]["PageNumber"], body["args"]["PageSize"]
        self.requested_pages.append(page_number)
        page_rows = matching[(page_number - 1) * page_size : page_number * page_size]
        context.status_code = 200
        return {"success": True, "Result": {"Count": len(page_rows), "FullCount": len(matching), "Results": page_rows}}


def _run_fetch(mocker, fake_redrock: FakeRedRock, last_run: dict, cursor: str = "2022-05-15T13:00:00.000000") -> tuple:
    """Run one fetch-events cycle. Returns (events sent to XSIAM, last run set, or None if not set)."""
    params = mocker.patch.object(demisto, "params", return_value=dict(DEMISTO_PARAMS))
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mocker.patch.object(demisto, "getLastRun", return_value=last_run)
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    sent = mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json=fake_redrock)

        from CyberArkIdentityEventCollector import main

        # In production the last run's 'from' overrides the 'from' param (see __main__).
        main("fetch-events", params.return_value | {"from": last_run.get("from", cursor)})

    events = sent.call_args[0][0] if sent.called else []
    new_last_run = mock_set_last_run.call_args[0][0] if mock_set_last_run.called else None
    return events, new_last_run


def _build_row(index: int, when_occurred_ms: int) -> dict:
    """Build a single RedRock 'Results' entry with a unique ID and WhenOccurred."""
    return {
        "Entities": [{"Type": "User", "Key": f"key-{index}", "IsForeignKey": True}],
        "Row": {
            "_TableName": "events",
            "ID": f"event-{index}",
            "Level": "Info",
            "WhenOccurred": f"/Date({when_occurred_ms})/",
            "WhenLogged": f"/Date({when_occurred_ms})/",
        },
    }


def test_fetch_events_paginates_full_backlog(mocker):
    """
    Given
        - 2500 events match the fetch window in CyberArk (more than a single RedRock page of 1000).
    When
        - fetch-events is running.
    Then
        - Verify the integration pages through ALL results (3 pages) and collects every event,
          so no events are dropped when the backlog exceeds one page.
        - Verify the last_run cursor is set to the max WhenOccurred of the whole backlog.
    """
    from CyberArkIdentityEventCollector import PAGE_SIZE

    total_events = 2500
    base_ms = 1652621700000
    all_rows = [_build_row(i, base_ms + i) for i in range(total_events)]

    def redrock_callback(request, context):
        body = json.loads(request.text)
        page_number = body["args"]["PageNumber"]
        start = (page_number - 1) * PAGE_SIZE
        page_rows = all_rows[start : start + PAGE_SIZE]
        context.status_code = 200
        return {"success": True, "Result": {"Count": len(page_rows), "FullCount": total_events, "Results": page_rows}}

    demisto_params = dict(DEMISTO_PARAMS)
    demisto_params["limit"] = 1000
    params = mocker.patch.object(demisto, "params", return_value=demisto_params)
    args = mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "command", return_value="fetch-events")
    mock_last_run = mocker.patch.object(demisto, "setLastRun", side_effect=mock_set_last_run)
    mocker.patch.object(demisto, "getLastRun", return_value={})
    sent = mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json=redrock_callback)

        from CyberArkIdentityEventCollector import main

        main("fetch-events", params.return_value | args.return_value)

    events = sent.call_args[0][0]
    # All 2500 events must be collected across the 3 pages (1000 + 1000 + 500) - none dropped.
    assert len(events) == total_events
    last_run = mock_last_run.call_args[0][0]
    # Cursor must advance to the newest event in the whole backlog, not just the first page.
    assert last_run.get("from") == datetime.utcfromtimestamp((base_ms + total_events - 1) / 1000).strftime("%Y-%m-%dT%H:%M:%S.%f")
    # Only the event at the cursor's millisecond is kept for dedup.
    assert last_run.get("ids") == [f"event-{total_events - 1}"]


def test_fetch_events_stops_at_per_fetch_cap(mocker):
    """
    Given
        - 12,500 events match the fetch window (more than the 10-page per-fetch cap).
    When
        - fetch-events runs twice.
    Then
        - Verify the first run stops after MAX_PAGES_PER_FETCH pages and sends exactly 10,000 events.
        - Verify the cursor moves to the last collected event, and the second run collects the
          remaining 2,500 events with no duplicates and none missing.
    """
    from CyberArkIdentityEventCollector import MAX_PAGES_PER_FETCH, PAGE_SIZE

    total_events = 12500
    base_ms = 1652621700000
    fake_redrock = FakeRedRock([_build_row(i, base_ms + i) for i in range(total_events)])

    first_events, first_last_run = _run_fetch(mocker, fake_redrock, last_run={})
    assert fake_redrock.requested_pages == list(range(1, MAX_PAGES_PER_FETCH + 1))
    assert len(first_events) == MAX_PAGES_PER_FETCH * PAGE_SIZE
    assert first_last_run["ids"] == [f"event-{MAX_PAGES_PER_FETCH * PAGE_SIZE - 1}"]

    second_events, second_last_run = _run_fetch(mocker, fake_redrock, last_run=first_last_run)
    all_ids = [event["ID"] for event in first_events + second_events]
    assert len(all_ids) == len(set(all_ids)) == total_events
    assert second_last_run["ids"] == [f"event-{total_events - 1}"]


def test_fetch_events_millisecond_tie_across_cap_is_not_lost(mocker):
    """
    Given
        - The 10,000th and 10,001st events (the last event of the per-fetch cap and the first event
          after it) share the same WhenOccurred millisecond, together with a few more events.
    When
        - fetch-events runs twice.
    Then
        - Verify the events at the shared millisecond are split across the two runs without being
          lost or sent twice, because the cursor is inclusive (>=) and the boundary IDs are deduped.
    """
    from CyberArkIdentityEventCollector import MAX_PAGES_PER_FETCH, PAGE_SIZE

    cap = MAX_PAGES_PER_FETCH * PAGE_SIZE
    base_ms = 1652621700000
    tie_ms = base_ms + cap
    rows = [_build_row(i, base_ms + i) for i in range(cap - 2)]
    # 5 events share one millisecond: 2 fall inside the first run's cap, 3 fall after it.
    rows += [_build_row(i, tie_ms) for i in range(cap - 2, cap + 3)]
    rows += [_build_row(i, tie_ms + 1 + i) for i in range(cap + 3, cap + 10)]
    fake_redrock = FakeRedRock(rows)

    first_events, first_last_run = _run_fetch(mocker, fake_redrock, last_run={})
    assert len(first_events) == cap
    tie_ids_in_first_run = sorted(event["ID"] for event in first_events if event["WhenOccurred"] == f"/Date({tie_ms})/")
    assert sorted(first_last_run["ids"]) == tie_ids_in_first_run

    second_events, _ = _run_fetch(mocker, fake_redrock, last_run=first_last_run)
    all_ids = [event["ID"] for event in first_events + second_events]
    assert len(all_ids) == len(set(all_ids)) == len(rows)


def test_last_run_ids_merged_when_cursor_does_not_move(mocker):
    """
    Given
        - The previous run ended at a millisecond that still has more events, and this run returns
          only events at that same millisecond (some already sent).
    When
        - fetch-events runs.
    Then
        - Verify only the new events are sent, and the new last run keeps both the previous and the
          new IDs at that millisecond, so the next run doesn't send the earlier ones again.
    """
    tie_ms = 1652621700000
    fake_redrock = FakeRedRock([_build_row(i, tie_ms) for i in range(4)])
    cursor = datetime.utcfromtimestamp(tie_ms / 1000).strftime("%Y-%m-%dT%H:%M:%S.%f")

    events, new_last_run = _run_fetch(mocker, fake_redrock, last_run={"from": cursor, "ids": ["event-0", "event-1"]})
    assert [event["ID"] for event in events] == ["event-2", "event-3"]
    assert new_last_run["from"] == cursor
    assert sorted(new_last_run["ids"]) == ["event-0", "event-1", "event-2", "event-3"]


def test_fetch_events_already_fetched_ids_are_skipped(mocker):
    """
    Given
        - A single page of 3 events, two of which were already fetched in the previous run.
    When
        - fetch-events is running.
    Then
        - Verify only the one new event is sent to XSIAM (dedup by ID works with pagination).
    """
    total_events = 3
    base_ms = 1652621700000
    all_rows = [_build_row(i, base_ms + i) for i in range(total_events)]

    def redrock_callback(request, context):
        context.status_code = 200
        return {"success": True, "Result": {"Count": len(all_rows), "FullCount": total_events, "Results": all_rows}}

    params = mocker.patch.object(demisto, "params", return_value=dict(DEMISTO_PARAMS))
    args = mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "setLastRun", side_effect=mock_set_last_run)
    mocker.patch.object(demisto, "getLastRun", return_value={"ids": ["event-0", "event-1"]})
    sent = mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json=redrock_callback)

        from CyberArkIdentityEventCollector import main

        main("fetch-events", params.return_value | args.return_value)

    events = sent.call_args[0][0]
    assert len(events) == 1
    assert events[0]["ID"] == "event-2"


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
        - RedRock returns a failure response (success=false, Result=null) on page 1, or on page 2
          after a full first page.
    When
        - fetch-events is running.
    Then
        - Verify the run fails with an error that includes CyberArk's message and ErrorID.
        - Verify no events are sent and the last run is not updated, so the next run retries
          the same window and no events are lost.
    """
    from CyberArkIdentityEventCollector import PAGE_SIZE

    base_ms = 1652621700000
    first_page = [_build_row(i, base_ms + i) for i in range(PAGE_SIZE)]

    def redrock_callback(request, context):
        context.status_code = 200
        page_number = json.loads(request.text)["args"]["PageNumber"]
        if page_number == failing_page:
            return REDROCK_FAILURE_RESPONSE
        return {"success": True, "Result": {"Count": PAGE_SIZE, "FullCount": PAGE_SIZE * 2, "Results": first_page}}

    params = mocker.patch.object(demisto, "params", return_value=dict(DEMISTO_PARAMS))
    args = mocker.patch.object(demisto, "args", return_value={})
    mock_set_last_run = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "getLastRun", return_value={})
    sent = mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")
    mock_return_error = mocker.patch("CyberArkIdentityEventCollector.return_error")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json=redrock_callback)

        from CyberArkIdentityEventCollector import main

        main("fetch-events", params.return_value | args.return_value)

    error_message = mock_return_error.call_args[0][0]
    assert f"page {failing_page}" in error_message
    assert "Query has failed: query timed out" in error_message
    assert "test-error-id" in error_message
    sent.assert_not_called()
    mock_set_last_run.assert_not_called()


def test_request_params_include_order_by_and_caching():
    """
    Given
        - Fetch parameters.
    When
        - Building the RedRock request params.
    Then
        - Verify the query is ordered ascending by WhenOccurred and requests live (non-cached) data,
          which is required for safe pagination and a monotonic last-run cursor.
    """
    from CyberArkIdentityEventCollector import PAGE_SIZE, get_request_params

    params = get_request_params(url=URL, **{"from": "3 days"}, limit=50)
    body = json.loads(params["data"])
    assert "where WhenOccurred >= '" in body["Script"]
    assert "ORDER BY WhenOccurred ASC, ID ASC" in body["Script"]
    assert body["args"]["Caching"] == -1
    assert body["args"]["PageSize"] == PAGE_SIZE
    assert body["args"]["PageNumber"] == 1


def test_fetch_events_limit_set_to_one(mocker):
    """
    Given
        - 3 events was created in CyberArk side in the last 3 days.
    When
        - fetch-events is running (with limit set to 1).
    Then
        - Verify that only 1 event were created in XSIAM.
        - Verify last_run was set as expected.
    """

    demisto_params = DEMISTO_PARAMS
    demisto_params["limit"] = 1
    params = mocker.patch.object(demisto, "params", return_value=demisto_params)
    args = mocker.patch.object(demisto, "args", return_value={"should_push_events": True})
    mock_last_run = mocker.patch.object(demisto, "setLastRun", side_effect=mock_set_last_run)
    results = mocker.patch.object(demisto, "results")
    mocker.patch("CyberArkIdentityEventCollector.send_events_to_xsiam")

    with requests_mock.Mocker() as m:
        m.post(f"{URL}oauth2/platformtoken", json={"access_token": "123456abc"})
        m.post(f"{URL}RedRock/Query", json=util_load_json("test_data/events.json"))

        from CyberArkIdentityEventCollector import main

        main("cyberarkidentity-get-events", params.return_value | args.return_value)

    events = results.call_args[0][0]["Contents"]
    last_run = mock_last_run.call_args[0][0]
    assert last_run.get("from") == "2022-05-15T13:35:03.570000"
    assert len(last_run.get("ids")) == len(events) == 1
