import json
from copy import deepcopy

import demistomock as demisto
import pytest
from CommonServerPython import DemistoException
from requests import Session
from SlackEventCollector import Client, prepare_query_params

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


@pytest.mark.parametrize(
    "params, expected_params",
    [
        ({"limit": "1"}, {"limit": 1}),
        ({"oldest": "1643806800"}, {"limit": 1000, "oldest": 1643806800}),
        ({"latest": "02/02/2022 15:00:00"}, {"limit": 1000, "latest": 1643814000}),
        ({"action": "user_login"}, {"limit": 1000, "action": "user_login"}),
    ],
)
def test_slack_events_params_good(params, expected_params):
    """
    Given:
        - Various dictionary values.
    When:
        - preparing the parameters.
    Then:
        - Make sure they are parsed correctly.
    """
    assert expected_params.items() <= prepare_query_params(params).items()


@pytest.mark.parametrize("params", [{"limit": "hello"}, {"oldest": "hello"}, {"latest": "hello"}])
def test_slack_events_params_bad(params):
    """
    Given:
        - Various dictionary values.
    When:
        - Parsing them as a SlackEventsParams object.
    Then:
        - Make sure a ValueError exception is raised.
    """
    with pytest.raises(ValueError):
        prepare_query_params(params)


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


def test_get_events_does_not_mutate_last_run(mocker):
    """
    Given:
        - slack-get-events call while a lastRun already exists on the instance.
    When:
        - Running the manual command (which internally runs a fetch cycle).
    Then:
        - The persisted lastRun is NOT modified (no demisto.setLastRun call, and the
          object returned by getLastRun is untouched), so previewing has no side effects.
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
    get_events_command(Client(base_url=""), args={"limit": 10})

    # the manual command must never persist progress
    set_last_run.assert_not_called()
    # and the object we read must be left exactly as it was
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
    mocker.patch("SlackEventCollector.DEFAULT_MAX_FETCH_WINDOW", 50)
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


def test_fetch_events_empty_backlog_walks_forward_across_windows(mocker):
    """
    Given:
        - An empty backlog capped well below 'now' (still backfilling).
        - last_fetched_time = 100, DEFAULT_MAX_FETCH_WINDOW = 50, now = 1000.
        - MAX_WINDOWS_PER_RUN patched high enough that the per-run cap is NOT the limiting factor,
          so the run can walk all the way toward 'now'.
    When:
        - Every window returns no events.
    Then:
        - The multi-window walk keeps advancing forward across empty windows within the SAME
          run, so we never get stuck slowly crawling one window per fetch interval when there
          is simply no data. It advances to the last window boundary before 'now' (950); the
          final caught-up empty window ([950, 1000]) intentionally does not advance the mark so
          no event recorded at the boundary second can ever be skipped.
    """
    from SlackEventCollector import fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=1000)
    mocker.patch("SlackEventCollector.DEFAULT_MAX_FETCH_WINDOW", 50)
    mocker.patch("SlackEventCollector.MAX_WINDOWS_PER_RUN", 1000)
    mocker.patch.object(Client, "_http_request", return_value=make_page([]))
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 10},
        last_run={"last_fetched_time": 100, "last_fetched_ids": ["x"]},
    )

    assert events == []
    assert last_run.get("last_fetched_time") == 950  # walked forward across all empty windows


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
    mocker.patch("SlackEventCollector.DEFAULT_MAX_FETCH_WINDOW", 100)
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
    mocker.patch("SlackEventCollector.DEFAULT_MAX_FETCH_WINDOW", 100)
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
        - Draining fully would require 1000 windows; every window is empty.
        - MAX_WINDOWS_PER_RUN caps how many windows a single run may walk.
    When:
        - Running a fetch.
    Then:
        - The run walks at most MAX_WINDOWS_PER_RUN windows (bounding run duration / API calls),
          advances the mark by that many windows, and resumes the rest on the next run - the very
          timeout / OOM protection the windowing is meant to provide.
    """
    from SlackEventCollector import MAX_WINDOWS_PER_RUN, fetch_events_command

    mocker.patch("SlackEventCollector.get_now_timestamp", return_value=10000)
    mocker.patch("SlackEventCollector.DEFAULT_MAX_FETCH_WINDOW", 10)
    http = mocker.patch.object(Client, "_http_request", return_value=make_page([]))
    events, last_run = fetch_events_command(
        Client(base_url=""),
        params={"limit": 10},
        last_run={"last_fetched_time": 0, "last_fetched_ids": []},
    )

    assert events == []
    assert http.call_count == MAX_WINDOWS_PER_RUN  # never walks more than the cap in one run
    # Advanced exactly MAX_WINDOWS_PER_RUN windows of 10 seconds each, then stops (still < now).
    assert last_run.get("last_fetched_time") == MAX_WINDOWS_PER_RUN * 10
