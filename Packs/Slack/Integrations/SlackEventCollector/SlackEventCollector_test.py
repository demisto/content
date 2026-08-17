import json
from copy import deepcopy

import demistomock as demisto
import pytest
from CommonServerPython import DemistoException
from requests import Session
from SlackEventCollector import Client

""" Helpers """


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


MOCK_ENTRY = util_load_json("test_data/mock_event.json")


class MockResponse:
    def __init__(self, data: list):
        self.ok = True
        self.status_code = 200
        self.data = {"entries": [self.create_mock_entry(**e) for e in data]}

    def create_mock_entry(self, **kwargs) -> dict:
        return deepcopy(MOCK_ENTRY) | kwargs

    def json(self):
        return self.data

    def raise_for_status(self):
        pass


def make_page(events: list, next_cursor: str | None = None) -> dict:
    """Builds a raw Slack /logs API page (dict) from a list of {id, date_create} events."""
    page = MockResponse(events).data
    if next_cursor:
        page["response_metadata"] = {"next_cursor": next_cursor}
    return page


""" Test methods """


def test_update_last_run_keeps_boundary_ids_at_window_end_when_draining():
    """
    Given:
        - A drained window still below 'now' (reached_limit=False, caught_up=False) whose sent
          events include one recorded EXACTLY at window_end (Slack's `latest` is inclusive).
    When:
        - Updating last_run for that window.
    Then:
        - last_fetched_time advances to window_end AND last_fetched_ids keeps the id(s) at
          window_end, so the next run (which re-queries from window_end, inclusive) dedups the
          boundary event instead of re-ingesting it. (Regression: previously ids were cleared,
          causing duplicate ingestion for events at window_end.)
    """
    from SlackEventCollector import update_last_run

    last_run: dict = {"last_fetched_time": 0, "last_fetched_ids": []}
    sent_events = [
        {"id": "a", "date_create": 50},
        {"id": "b", "date_create": 100},  # exactly at window_end
    ]
    update_last_run(last_run, sent_events, window_end=100, reached_limit=False, caught_up=False)

    assert last_run["last_fetched_time"] == 100
    assert last_run["last_fetched_ids"] == ["b"]  # boundary id retained, NOT cleared


def test_update_last_run_drained_window_no_event_at_boundary_has_empty_ids():
    """
    Given:
        - A drained window still below 'now' whose sent events are all strictly before window_end.
    When:
        - Updating last_run.
    Then:
        - last_fetched_time advances to window_end and last_fetched_ids is empty (nothing sits on
          the inclusive boundary, so there is nothing to dedup next run).
    """
    from SlackEventCollector import update_last_run

    last_run: dict = {"last_fetched_time": 0, "last_fetched_ids": []}
    sent_events = [{"id": "a", "date_create": 50}, {"id": "b", "date_create": 90}]
    update_last_run(last_run, sent_events, window_end=100, reached_limit=False, caught_up=False)

    assert last_run["last_fetched_time"] == 100
    assert last_run["last_fetched_ids"] == []


def test_compute_window_start_first_fetch_defaults_to_config_lookback():
    """
    Given:
        - The FIRST fetch: empty last_run and NO 'oldest' configured.
    When:
        - Computing the window start.
    Then:
        - It falls back to Config.DEFAULT_FIRST_FETCH ("10 minutes ago") - roughly 600 seconds
          of lookback from the current time - NOT exactly 'now', so events around startup are
          not missed. (The default is parsed relative to the real clock, so a small tolerance
          is allowed.)
    """
    import time as _time

    from SlackEventCollector import Config, compute_window_start

    now = 1_000_000  # arbitrary; the default lookback is parsed relative to the real clock
    before = int(_time.time())
    window_start = compute_window_start(params={}, last_run={}, now=now)
    after = int(_time.time())

    assert Config.DEFAULT_FIRST_FETCH == "10 minutes ago"
    # window_start should be ~10 minutes before "now"; allow a couple seconds of clock drift.
    assert before - 600 - 2 <= window_start <= after - 600 + 2


def test_compute_window_start_explicit_oldest_wins_over_default():
    """
    Given:
        - The FIRST fetch (empty last_run) but an explicit 'oldest' IS configured.
    When:
        - Computing the window start.
    Then:
        - The explicit 'oldest' takes precedence over the default first-fetch lookback.
    """
    from SlackEventCollector import compute_window_start

    now = 1_000_000
    window_start = compute_window_start(params={"oldest": "500"}, last_run={}, now=now)

    assert window_start == 500


def test_compute_window_start_resumes_from_last_fetched_time():
    """
    Given:
        - A subsequent fetch where last_run holds a 'last_fetched_time'.
    When:
        - Computing the window start.
    Then:
        - It resumes from the stored 'last_fetched_time', ignoring both 'oldest' and the default.
    """
    from SlackEventCollector import compute_window_start

    now = 1_000_000
    window_start = compute_window_start(params={"oldest": "500"}, last_run={"last_fetched_time": 750}, now=now)

    assert window_start == 750


def test_test_module(mocker):
    """
    Given:
        - test-module call
    When:
        - A response with an OK status_code is retrieved from the API call.
    Then:
        - Make sure 'ok' is returned and only a single, lightweight credentials-check
          API call is made (NOT a full fetch loop).
    """
    from SlackEventCollector import test_module_command

    request = mocker.patch.object(Session, "request", return_value=MockResponse([]))
    assert test_module_command(Client(base_url=""), {}) == "ok"
    assert request.call_count == 1


def test_get_events_runs_fetch_cycle_oldest_first(mocker):
    """
    Given:
        - slack-get-events call (manual command).
        - Three results retrieved from the API (newest-first).
    When:
        - Running the command, which reuses the same fetch cycle as the collector.
    Then:
        - All events are returned as part of the CommandResult, sorted oldest-first.
    """
    from SlackEventCollector import get_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=make_page(
            [
                {"id": "3", "date_create": 300},
                {"id": "2", "date_create": 200},
                {"id": "1", "date_create": 100},
            ]
        ),
    )
    events, results = get_events_command(Client(base_url=""), args={"limit": 10, "oldest": "100"})

    assert [e["id"] for e in events] == ["1", "2", "3"]  # oldest-first
    assert len(results.raw_response.get("entries", [])) == 3


def test_get_events_has_no_side_effects_on_collector_state(mocker):
    """
    Given:
        - slack-get-events call while a lastRun already exists on the instance.
    When:
        - Running the manual command (which internally runs a collection cycle).
    Then:
        - The command persists nothing (demisto.setLastRun is never called) and runs from a fresh
          state, so it has no side effects on the collector's persisted state; the object returned
          by getLastRun stays exactly as it was.
    """
    from SlackEventCollector import get_events_command

    persisted_last_run = {"last_fetched_time": 50, "last_fetched_ids": ["old"]}
    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    get_last_run = mocker.patch.object(demisto, "getLastRun", return_value=persisted_last_run)
    set_last_run = mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=make_page(
            [
                {"id": "3", "date_create": 300},
                {"id": "2", "date_create": 200},
            ]
        ),
    )
    get_events_command(Client(base_url=""), args={"limit": 10, "oldest": "100"})

    # the manual command must never persist progress
    set_last_run.assert_not_called()
    # the persisted state stays exactly as it was
    assert get_last_run.return_value == {"last_fetched_time": 50, "last_fetched_ids": ["old"]}


""" fetch-events (forward-window algorithm) """


def test_first_fetch_sends_oldest_first_within_timeframe(mocker):
    """
    Given:
        - The FIRST fetch (empty last_run), first-fetch 'oldest' = 100, and 'now' = 1000.
        - The API returns events newest-first within the window.
    When:
        - Running the fetch and the number of events is below the limit and the window reaches 'now'.
    Then:
        - Even on the first fetch, the returned events are sorted OLDEST-first (ascending by date_create),
          i.e. the oldest events in the queried timeframe are sent to XSIAM first.
        - last_run advances 'last_fetched_time' to the newest event time (caught up, no resume state).
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=make_page(
            [
                {"id": "3", "date_create": 300},
                {"id": "2", "date_create": 200},
                {"id": "1", "date_create": 100},
            ]
        ),
    )
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 10, "oldest": "100"},
        last_run={},
    )

    assert [e["id"] for e in events] == ["1", "2", "3"]  # oldest-first
    assert last_run.get("last_fetched_time") == 300
    assert last_run.get("last_fetched_ids") == ["3"]


def test_first_fetch_over_limit_sends_oldest_then_resumes(mocker):
    """
    Given:
        - The FIRST fetch (empty last_run) with more events in the window than the limit.
        - limit = 2, oldest = 100, now = 1000.
    When:
        - Sorting ascending and sending only the oldest 'limit' events.
    Then:
        - On the first fetch the OLDEST 2 events (not the newest) are sent to XSIAM.
        - last_fetched_time / last_fetched_ids point at the last SENT event (time=200, id="2"),
          so the next run resumes mid-window and continues forward.
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=make_page(
            [
                {"id": "4", "date_create": 400},
                {"id": "3", "date_create": 300},
                {"id": "2", "date_create": 200},
                {"id": "1", "date_create": 100},
            ]
        ),
    )
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 2, "oldest": "100"},
        last_run={},
    )

    assert [e["id"] for e in events] == ["1", "2"]  # oldest two, NOT ["3", "4"]
    assert last_run.get("last_fetched_time") == 200
    assert last_run.get("last_fetched_ids") == ["2"]


def test_fetch_events_caps_each_window_to_max_fetch_window(mocker):
    """
    Given:
        - last_fetched_time = 100, DEFAULT_MAX_FETCH_WINDOW patched to 50 seconds, now = 200.
        - The first window is therefore [100, 150] (capped by max_window, NOT jumping to now).
        - The first window returns two events; later windows are empty.
    When:
        - Running a fetch (which walks forward window-by-window until 'now').
    Then:
        - The FIRST API call uses the capped upper boundary (150), proving no single request
          ever spans more than max_window seconds (timeout / OOM protection).
        - The two events are returned oldest-first.
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=200)
    mocker.patch("SlackEventCollector.Config.DEFAULT_MAX_FETCH_WINDOW", 50)
    window_with_events = make_page(
        [
            {"id": "b", "date_create": 140},
            {"id": "a", "date_create": 120},
        ]
    )
    empty = make_page([])
    http = mocker.patch.object(Client, "_http_request", side_effect=[window_with_events, empty])
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 10},
        last_run={"last_fetched_time": 100, "last_fetched_ids": []},
    )

    # The FIRST request's upper bound is the cap (150), not now (200): each window is bounded.
    first_call_params = http.call_args_list[0].kwargs["params"]
    assert first_call_params["oldest"] == 100
    assert first_call_params["latest"] == 150

    assert [e["id"] for e in events] == ["a", "b"]


def test_fetch_events_dedups_boundary_ids(mocker):
    """
    Given:
        - last_fetched_time = 200 and last_fetched_ids = ["2"] (already sent on a previous run).
        - Slack 'oldest' is inclusive, so the API returns id="2"/date=200 again.
    When:
        - Fetching the next window.
    Then:
        - The already-sent boundary event ("2") is filtered out.
        - Only the genuinely new events are returned, oldest-first.
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=make_page(
            [
                {"id": "4", "date_create": 400},
                {"id": "3", "date_create": 300},
                {"id": "2", "date_create": 200},  # already fetched boundary event
            ]
        ),
    )
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 10},
        last_run={"last_fetched_time": 200, "last_fetched_ids": ["2"]},
    )

    assert [e["id"] for e in events] == ["3", "4"]  # "2" deduped
    assert last_run.get("last_fetched_time") == 400
    assert last_run.get("last_fetched_ids") == ["4"]


def test_fetch_events_paginates_within_window(mocker):
    """
    Given:
        - A single window whose events span two cursor-paginated API pages.
        - limit is high enough to send all of them.
    When:
        - Fetching all events in the window.
    Then:
        - Both pages are requested (cursor pagination).
        - All events are aggregated and returned oldest-first.
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    page1 = make_page(
        [
            {"id": "6", "date_create": 600},
            {"id": "5", "date_create": 500},
            {"id": "4", "date_create": 400},
        ],
        next_cursor="page2",
    )
    page2 = make_page(
        [
            {"id": "3", "date_create": 300},
            {"id": "2", "date_create": 200},
            {"id": "1", "date_create": 100},
        ]
    )
    http = mocker.patch.object(Client, "_http_request", side_effect=[page1, page2])
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 100, "oldest": "100"},
        last_run={},
    )

    assert http.call_count == 2
    assert [e["id"] for e in events] == ["1", "2", "3", "4", "5", "6"]
    assert last_run.get("last_fetched_time") == 600


def test_fetch_events_groups_boundary_ids_at_same_timestamp(mocker):
    """
    Given:
        - The limit falls exactly between two events that share the same date_create.
        - limit = 3; events at time 200 have ids "2a" and "2b".
    When:
        - Sending the oldest 'limit' events (id=1@100, id=2a@200, id=2b@200).
    Then:
        - last_fetched_time = 200 and last_fetched_ids contains BOTH ids at time 200,
          so neither is re-sent next run.
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=make_page(
            [
                {"id": "3", "date_create": 300},
                {"id": "2b", "date_create": 200},
                {"id": "2a", "date_create": 200},
                {"id": "1", "date_create": 100},
            ]
        ),
    )
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 3, "oldest": "100"},
        last_run={},
    )

    assert [e["id"] for e in events] == ["1", "2a", "2b"]
    assert last_run.get("last_fetched_time") == 200
    assert sorted(last_run.get("last_fetched_ids")) == ["2a", "2b"]


def test_fetch_events_stops_on_first_empty_window(mocker):
    """
    Given:
        - A backlog capped well below 'now' (still backfilling).
        - last_fetched_time = 100, DEFAULT_MAX_FETCH_WINDOW = 50, now = 1000.
        - MAX_WINDOWS_PER_RUN patched high enough that the per-run cap is NOT the limiting factor.
    When:
        - The very first window ([100, 150]) returns no events.
    Then:
        - The run stops walking as soon as a window returns zero events (only ONE API call),
          instead of crawling forward across further empty windows. The mark still advances to
          that first window's end (150) so the next scheduled run resumes from there, and no
          events are returned.
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    mocker.patch("SlackEventCollector.Config.DEFAULT_MAX_FETCH_WINDOW", 50)
    mocker.patch("SlackEventCollector.Config.MAX_WINDOWS_PER_RUN", 1000)
    http = mocker.patch.object(Client, "_http_request", return_value=make_page([]))
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 10},
        last_run={"last_fetched_time": 100, "last_fetched_ids": ["x"]},
    )

    assert events == []
    assert http.call_count == 1  # stopped immediately on the empty response
    assert last_run.get("last_fetched_time") == 150  # advanced to the first window's end


def test_fetch_events_empty_window_when_caught_up_keeps_state(mocker):
    """
    Given:
        - An empty window whose upper bound reaches 'now' (caught up, steady state).
        - last_fetched_time = 990, large max window, now = 1000 -> window [990, 1000].
    When:
        - The API returns no events.
    Then:
        - The boundary state is preserved (last_fetched_time not pushed to 'now' with no events)
          so that no events recorded exactly at the boundary could be skipped.
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    mocker.patch.object(Client, "_http_request", return_value=make_page([]))
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 10},
        last_run={"last_fetched_time": 990, "last_fetched_ids": ["x"]},
    )

    assert events == []
    assert last_run.get("last_fetched_time") == 990
    assert last_run.get("last_fetched_ids") == ["x"]


def test_fetch_events_merges_boundary_ids_when_high_water_mark_unchanged(mocker):
    """
    Given:
        - Previous run boundary: last_fetched_time = 200, last_fetched_ids = ["2a"] (caught up).
        - This run (also caught up) returns a NEW event "2b" ALSO at time 200,
          plus the already-seen "2a" (inclusive 'oldest' boundary).
    When:
        - Fetching, deduping "2a", and sending "2b".
    Then:
        - The high-water mark stays at 200 and last_fetched_ids == {"2a", "2b"} (merged with the
          previous ids, not replaced), so a subsequent run will dedup BOTH and never re-send them.
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=200)
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=make_page(
            [
                {"id": "2b", "date_create": 200},  # new, same timestamp as previous boundary
                {"id": "2a", "date_create": 200},  # already fetched
            ]
        ),
    )
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 10},
        last_run={"last_fetched_time": 200, "last_fetched_ids": ["2a"]},
    )

    assert [e["id"] for e in events] == ["2b"]  # only the new one is sent
    assert last_run.get("last_fetched_time") == 200
    assert sorted(last_run.get("last_fetched_ids")) == ["2a", "2b"]  # merged, not replaced


def test_fetch_events_walks_multiple_windows_in_one_run_until_now(mocker):
    """
    Given:
        - last_fetched_time = 0, DEFAULT_MAX_FETCH_WINDOW = 100, now = 300.
        - Draining the backlog requires 3 windows: [0,100], [100,200], [200,300].
        - Each window returns one event; the limit is high so we never stop early.
    When:
        - Running a single fetch.
    Then:
        - All three windows are queried in ONE run (3 API calls) so a sparse backlog is
          drained quickly instead of one window per fetch interval.
        - All three events are returned oldest-first. The final window is caught up to 'now',
          so the mark is set to the newest sent event (250) and its id is kept for boundary
          dedup (we never advance the mark past 'now' without having seen an event there).
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=300)
    mocker.patch("SlackEventCollector.Config.DEFAULT_MAX_FETCH_WINDOW", 100)
    win1 = make_page([{"id": "a", "date_create": 50}])
    win2 = make_page([{"id": "b", "date_create": 150}])
    win3 = make_page([{"id": "c", "date_create": 250}])
    http = mocker.patch.object(Client, "_http_request", side_effect=[win1, win2, win3])
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 100},
        last_run={"last_fetched_time": 0, "last_fetched_ids": []},
    )

    assert http.call_count == 3  # one call per window, all in a single run
    assert [e["id"] for e in events] == ["a", "b", "c"]
    assert last_run.get("last_fetched_time") == 250  # newest sent event at the caught-up boundary
    assert last_run.get("last_fetched_ids") == ["c"]


def test_fetch_events_stops_walking_windows_when_limit_reached(mocker):
    """
    Given:
        - last_fetched_time = 0, DEFAULT_MAX_FETCH_WINDOW = 100, now = 300, limit = 2.
        - Window [0,100] returns two events (a@40, b@60), already filling the limit.
    When:
        - Running a single fetch.
    Then:
        - Only the first window is queried (1 API call) - the walk stops at the limit and does
          NOT keep walking to 'now'.
        - The oldest 2 events are returned and the resume point is the last sent event (b@60).
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=300)
    mocker.patch("SlackEventCollector.Config.DEFAULT_MAX_FETCH_WINDOW", 100)
    win1 = make_page(
        [
            {"id": "b", "date_create": 60},
            {"id": "a", "date_create": 40},
        ]
    )
    http = mocker.patch.object(Client, "_http_request", side_effect=[win1])
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 2},
        last_run={"last_fetched_time": 0, "last_fetched_ids": []},
    )

    assert http.call_count == 1  # stopped after the first window
    assert [e["id"] for e in events] == ["a", "b"]
    assert last_run.get("last_fetched_time") == 60
    assert last_run.get("last_fetched_ids") == ["b"]


def test_fetch_events_keeps_earlier_pages_when_a_later_page_fails(mocker):
    """
    Given:
        - Page 1 succeeds with events; page 2 raises an exception.
    When:
        - Paginating within the window.
    Then:
        - The page-1 events are still returned (oldest-first) instead of the whole run aborting,
          and the mark advances so the next run resumes from the high-water mark.
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    # Later-page failures are logged at error level; mock it so the captured-output guard passes.
    mocker.patch.object(demisto, "error")
    page1 = make_page(
        [
            {"id": "2", "date_create": 200},
            {"id": "1", "date_create": 100},
        ],
        next_cursor="page2",
    )
    http = mocker.patch.object(
        Client,
        "_http_request",
        side_effect=[page1, DemistoException("boom on page 2")],
    )
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 100, "oldest": "100"},
        last_run={},
    )

    assert http.call_count == 2  # tried the second page and it failed
    assert [e["id"] for e in events] == ["1", "2"]  # page-1 events retained
    assert last_run.get("last_fetched_time") == 200


def test_fetch_events_first_page_failure_propagates(mocker):
    """
    Given:
        - The very first API call raises an exception (no events collected yet).
    When:
        - Running a fetch.
    Then:
        - The exception propagates out of fetch_events_command so the caller does NOT advance
          last_run (data-loss protection - the same window is retried next run).
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    mocker.patch.object(Client, "_http_request", side_effect=DemistoException("boom on page 1"))

    with pytest.raises(DemistoException):
        fetch_events_command(
            Client(base_url=""),
            params={"limit": 100, "oldest": "100"},
            last_run={},
        )


def test_fetch_events_handles_none_last_run(mocker):
    """
    Given:
        - The fetch-events path is invoked with last_run=None (as some platforms return from
          demisto.getLastRun() on the very first run).
    When:
        - Running a fetch.
    Then:
        - It does NOT crash (None is treated as an empty last run) and returns events normally.
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=make_page([{"id": "1", "date_create": 500}]),
    )
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 10, "oldest": "100"},
        last_run=None,
    )

    assert [e["id"] for e in events] == ["1"]
    assert last_run.get("last_fetched_time") == 500


def test_fetch_events_caps_number_of_windows_per_run(mocker):
    """
    Given:
        - A huge sparse backlog: last_fetched_time = 0, DEFAULT_MAX_FETCH_WINDOW = 10, now = 10000.
        - Draining fully would require 1000 windows; EACH window returns one new event (so the
          walk is never stopped early by an empty response) and the limit is high enough that a
          full batch is never reached either.
        - MAX_WINDOWS_PER_RUN caps how many windows a single run may walk.
    When:
        - Running a fetch.
    Then:
        - The run walks at most MAX_WINDOWS_PER_RUN windows (bounding run duration / API calls),
          advances the mark by that many windows, and resumes the rest on the next run - the very
          timeout / OOM protection the windowing is meant to provide.
    """
    from SlackEventCollector import Config, fetch_events_command

    MAX_WINDOWS_PER_RUN = Config.MAX_WINDOWS_PER_RUN
    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=10000)
    mocker.patch("SlackEventCollector.Config.DEFAULT_MAX_FETCH_WINDOW", 10)
    # Window n (1-indexed) covers [10*(n-1), 10*n]; return one event mid-window so it is neither
    # deduped nor empty, forcing the per-run window cap (not stop-on-empty) to be the limiter.
    pages = [make_page([{"id": str(n), "date_create": 10 * n - 5}]) for n in range(1, MAX_WINDOWS_PER_RUN + 1)]
    http = mocker.patch.object(Client, "_http_request", side_effect=pages)
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 10000},  # high enough that 'have_enough' never triggers
        last_run={"last_fetched_time": 0, "last_fetched_ids": []},
    )

    assert len(events) == MAX_WINDOWS_PER_RUN  # one event collected per walked window
    assert http.call_count == MAX_WINDOWS_PER_RUN  # never walks more than the cap in one run
    # Advanced exactly MAX_WINDOWS_PER_RUN windows of 10 seconds each, then stops (still < now).
    assert last_run.get("last_fetched_time") == MAX_WINDOWS_PER_RUN * 10


""" Unit tests for pure helpers """


def test_filter_already_fetched_returns_unchanged_when_no_boundary_ids():
    """
    Given:
        - last_run has a last_fetched_time but an EMPTY last_fetched_ids.
    When:
        - Filtering already-fetched events.
    Then:
        - The list is returned unchanged (with no boundary ids there is nothing to dedup).
    """
    from SlackEventCollector import filter_already_fetched

    events = [{"id": "1", "date_create": 100}, {"id": "2", "date_create": 200}]
    result = filter_already_fetched(events, last_run={"last_fetched_time": 100, "last_fetched_ids": []})

    assert result == events


def test_filter_already_fetched_returns_unchanged_when_boundary_matches_nothing():
    """
    Given:
        - last_run boundary ids that do not match any event at the boundary_time.
    When:
        - Filtering already-fetched events.
    Then:
        - Nothing is dropped (no event both sits at boundary_time AND has a boundary id).
    """
    from SlackEventCollector import filter_already_fetched

    events = [{"id": "1", "date_create": 100}, {"id": "2", "date_create": 200}]
    result = filter_already_fetched(events, last_run={"last_fetched_time": 999, "last_fetched_ids": ["nope"]})

    assert result == events


def test_filter_already_fetched_drops_only_boundary_matches():
    """
    Given:
        - An event sitting exactly at boundary_time with a matching boundary id.
    When:
        - Filtering already-fetched events.
    Then:
        - Only that boundary event is dropped; all others are kept.
    """
    from SlackEventCollector import filter_already_fetched

    events = [
        {"id": "old", "date_create": 100},  # already-sent boundary event
        {"id": "new", "date_create": 100},  # same second, not yet sent
        {"id": "later", "date_create": 200},
    ]
    result = filter_already_fetched(events, last_run={"last_fetched_time": 100, "last_fetched_ids": ["old"]})

    assert [e["id"] for e in result] == ["new", "later"]


def test_sort_events_oldest_first_handles_missing_date_create_and_id():
    """
    Given:
        - Events some of which are missing 'date_create' and/or 'id'.
    When:
        - Sorting oldest-first.
    Then:
        - It does not raise; missing date_create sorts as 0 (oldest) and missing id as "",
          giving a deterministic ascending order by (date_create, id).
    """
    from SlackEventCollector import sort_events_oldest_first

    events = [
        {"id": "b", "date_create": 200},
        {"date_create": 200},  # missing id -> "" sorts before "b" at the same time
        {"id": "a", "date_create": 100},
        {"id": "z"},  # missing date_create -> 0 (oldest)
    ]
    result = sort_events_oldest_first(events)

    # date_create: z=0, a=100, then the two at 200 ordered by id ("" before "b")
    assert result == [
        {"id": "z"},
        {"id": "a", "date_create": 100},
        {"date_create": 200},
        {"id": "b", "date_create": 200},
    ]


def test_update_last_run_last_fetched_time_never_regresses_across_windows():
    """
    Given:
        - A multi-window walk where an earlier window advanced the mark, and a later
          update carries an OLDER newest-sent timestamp (limit truncation landing inside an
          earlier window).
    When:
        - update_last_run is applied window after window.
    Then:
        - last_fetched_time never regresses below the previously stored value - the exact
          XSUP-74148 duplicate-ingestion guard. (The drained-below-now branch only advances when
          window_end is strictly greater than the stored mark.)
    """
    from SlackEventCollector import update_last_run

    last_run: dict = {"last_fetched_time": 0, "last_fetched_ids": []}

    # Window 1 drained below 'now' -> mark advances to window_end=100.
    update_last_run(last_run, [{"id": "a", "date_create": 50}], window_end=100, reached_limit=False, caught_up=False)
    assert last_run["last_fetched_time"] == 100

    # A stale/earlier drained window (window_end=80) must NOT pull the mark backwards.
    update_last_run(last_run, [{"id": "b", "date_create": 70}], window_end=80, reached_limit=False, caught_up=False)
    assert last_run["last_fetched_time"] == 100  # unchanged, no regression


def test_fetch_events_adds_time_field_to_every_event(mocker):
    """
    Given:
        - A fetch that returns several events.
    When:
        - Running fetch_events_command.
    Then:
        - Every returned event carries a '_time' field derived from its 'date_create'.
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=make_page(
            [
                {"id": "3", "date_create": 300},
                {"id": "2", "date_create": 200},
                {"id": "1", "date_create": 100},
            ]
        ),
    )
    events, _ = fetch_events_command(
        Client(base_url=""),
        params={"limit": 10, "oldest": "100"},
        last_run={},
    )

    assert events, "expected events to be returned"
    assert all("_time" in e for e in events)


def test_fetch_events_rate_limited_later_page_retains_events_and_logs_error(mocker):
    """
    Given:
        - Page 1 succeeds; page 2 fails with a DemistoException carrying a 429 (rate limit) after
          retries are exhausted.
    When:
        - Paginating within the window.
    Then:
        - The events already collected from page 1 are retained (not lost), and the partial-
          collection failure is logged at ERROR level so operators can see it.
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    error_log = mocker.patch.object(demisto, "error")
    page1 = make_page([{"id": "1", "date_create": 100}], next_cursor="page2")
    mocker.patch.object(
        Client,
        "_http_request",
        side_effect=[page1, DemistoException("Error in API call [429] - Too Many Requests")],
    )
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 100, "oldest": "100"},
        last_run={},
    )

    assert [e["id"] for e in events] == ["1"]  # page-1 events retained despite the 429
    assert last_run.get("last_fetched_time") == 100
    assert error_log.called  # partial-collection failure surfaced at error level


def test_fetch_events_limit_zero_defaults_to_1000(mocker):
    """
    Given:
        - limit = 0 is passed.
    When:
        - Running a fetch.
    Then:
        - CURRENT behavior: `arg_to_number(...) or 1000` treats 0 as falsy and defaults to 1000,
          so all available events (well under 1000) are returned.
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=make_page([{"id": "2", "date_create": 200}, {"id": "1", "date_create": 100}]),
    )
    events, _ = fetch_events_command(
        Client(base_url=""),
        params={"limit": 0, "oldest": "100"},
        last_run={},
    )

    assert [e["id"] for e in events] == ["1", "2"]  # 0 -> default 1000, everything returned


def test_fetch_events_negative_limit_current_behavior(mocker):
    """
    Given:
        - A negative limit (-1) is passed.
    When:
        - Running a fetch.
    Then:
        - CURRENT behavior: a negative limit is truthy, so it is used as-is in the final slice
          `collected[:limit]`, which for -1 drops the last (newest) event.
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    mocker.patch.object(
        Client,
        "_http_request",
        return_value=make_page(
            [
                {"id": "3", "date_create": 300},
                {"id": "2", "date_create": 200},
                {"id": "1", "date_create": 100},
            ]
        ),
    )
    events, _ = fetch_events_command(
        Client(base_url=""),
        params={"limit": -1, "oldest": "100"},
        last_run={},
    )

    # oldest-first sorted [1, 2, 3], sliced [:-1] -> [1, 2]
    assert [e["id"] for e in events] == ["1", "2"]


def test_get_events_uses_oldest_arg_as_window_start(mocker):
    """
    Given:
        - An explicit 'oldest' argument passed to the manual slack-get-events command.
    When:
        - Running the command.
    Then:
        - The first API call's `oldest` equals the 'oldest' argument (100), so the command is
          driven purely by its arguments.
    """
    from SlackEventCollector import get_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    mocker.patch.object(demisto, "getLastRun", return_value={"last_fetched_time": 500, "last_fetched_ids": []})
    http = mocker.patch.object(Client, "_http_request", return_value=make_page([{"id": "9", "date_create": 600}]))

    get_events_command(Client(base_url=""), args={"limit": 10, "oldest": "100"})

    first_call_params = http.call_args_list[0].kwargs["params"]
    assert first_call_params["oldest"] == 100  # driven by the 'oldest' argument


def test_get_events_uses_latest_arg_as_upper_bound(mocker):
    """
    Given:
        - slack-get-events called with 'oldest' and 'latest' arguments and a DEFAULT_MAX_FETCH_WINDOW
          large enough for one window to span the whole [oldest, latest] range.
    When:
        - Running the command.
    Then:
        - The API call's `latest` equals the 'latest' argument (300), and the events within
          [oldest, latest] are returned oldest-first.
    """
    from SlackEventCollector import get_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=100000)
    mocker.patch.object(demisto, "getLastRun", return_value={})
    http = mocker.patch.object(
        Client,
        "_http_request",
        return_value=make_page(
            [
                {"id": "3", "date_create": 300},
                {"id": "2", "date_create": 200},
                {"id": "1", "date_create": 100},
            ]
        ),
    )

    events, _ = get_events_command(Client(base_url=""), args={"limit": 10, "oldest": "100", "latest": "300"})

    first_call_params = http.call_args_list[0].kwargs["params"]
    assert first_call_params["oldest"] == 100
    assert first_call_params["latest"] == 300  # bounded by the 'latest' argument
    assert [e["id"] for e in events] == ["1", "2", "3"]  # oldest-first


def test_get_events_walks_multiple_windows_until_latest(mocker):
    """
    Given:
        - slack-get-events with oldest=100, latest=400, DEFAULT_MAX_FETCH_WINDOW=100 and a high limit.
        - The range [100, 400] spans three forward windows, each returning one event.
    When:
        - Running the command.
    Then:
        - It walks the windows forward (the same mechanism as fetch-events), querying all three
          windows in a single run and returning every event oldest-first.
    """
    from SlackEventCollector import get_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=100000)
    mocker.patch("SlackEventCollector.Config.DEFAULT_MAX_FETCH_WINDOW", 100)
    mocker.patch.object(demisto, "getLastRun", return_value={})
    win1 = make_page([{"id": "a", "date_create": 150}])
    win2 = make_page([{"id": "b", "date_create": 250}])
    win3 = make_page([{"id": "c", "date_create": 350}])
    http = mocker.patch.object(Client, "_http_request", side_effect=[win1, win2, win3])

    events, _ = get_events_command(Client(base_url=""), args={"limit": 100, "oldest": "100", "latest": "400"})

    assert http.call_count == 3  # walked all three windows in one run
    # the final window's upper bound is the 'latest' argument
    assert http.call_args_list[-1].kwargs["params"]["latest"] == 400
    assert [e["id"] for e in events] == ["a", "b", "c"]  # oldest-first


def test_get_events_stops_walking_windows_when_limit_reached(mocker):
    """
    Given:
        - slack-get-events with a 'latest' upper bound spanning several windows and a small limit.
        - The first window returns enough events to fill the limit.
    When:
        - Running the command.
    Then:
        - The walk stops as soon as the limit is filled (a single API call), returning the oldest
          'limit' events - the same limit-driven loop as fetch-events.
    """
    from SlackEventCollector import get_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=100000)
    mocker.patch("SlackEventCollector.Config.DEFAULT_MAX_FETCH_WINDOW", 100)
    mocker.patch.object(demisto, "getLastRun", return_value={})
    win1 = make_page(
        [
            {"id": "b", "date_create": 60},
            {"id": "a", "date_create": 40},
        ]
    )
    http = mocker.patch.object(Client, "_http_request", side_effect=[win1])

    events, _ = get_events_command(Client(base_url=""), args={"limit": 2, "oldest": "0", "latest": "300"})

    assert http.call_count == 1  # stopped once the limit was filled
    assert [e["id"] for e in events] == ["a", "b"]  # oldest-first, limited


def test_fetch_events_later_window_first_page_failure_propagates(mocker):
    """
    Given:
        - Window 1 returns events; window 2's FIRST page raises a DemistoException.
    When:
        - Walking multiple windows in one run.
    Then:
        - CURRENT behavior: get_all_logs_in_window re-raises when the first page of a window fails
          (its per-window buffer is empty), so the exception propagates out of the run. (Documents
          that earlier windows' events are NOT independently flushed on a later-window first-page
          failure.)
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=300)
    mocker.patch("SlackEventCollector.Config.DEFAULT_MAX_FETCH_WINDOW", 100)
    win1 = make_page([{"id": "a", "date_create": 50}])
    mocker.patch.object(
        Client,
        "_http_request",
        side_effect=[win1, DemistoException("boom on window 2 page 1")],
    )

    with pytest.raises(DemistoException):
        fetch_events_command(
            Client(base_url=""),
            params={"limit": 100},
            last_run={"last_fetched_time": 0, "last_fetched_ids": []},
        )
