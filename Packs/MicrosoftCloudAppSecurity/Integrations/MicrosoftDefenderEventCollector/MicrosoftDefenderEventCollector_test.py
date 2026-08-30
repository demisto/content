"""Unit tests for the Microsoft Defender for Cloud Apps Event Collector."""

import demistomock as demisto
import pytest
from freezegun import freeze_time

from CommonServerPython import DemistoException
from MicrosoftDefenderEventCollector import (
    ACTIVITIES_LIMIT,
    ACTIVITIES_PAGE_SIZE,
    ADMIN_ACTIVITIES_FILTER,
    ALERTS_FILTER,
    ALERTS_LIMIT,
    ALERTS_PAGE_SIZE,
    ALL_EVENT_FILTERS,
    AUTH_ERROR_MSG,
    LOGIN_ACTIVITIES_FILTER,
    DefenderClient,
    DefenderGetEvents,
    EventFilter,
    IntegrationOptions,
    main,
    module_test,
    select_event_filters,
)


def _event_filter(event_type_name: str) -> EventFilter:
    """Build a minimal stub EventFilter for a given event type.

    The endpoint category (alerts vs activities) is derived from the type name so run() can
    resolve the correct per-cycle cap (options.alerts_limit vs options.activities_limit).
    """
    api_type = "alerts" if event_type_name == "alerts" else "activities"
    page_size = ALERTS_PAGE_SIZE if api_type == "alerts" else ACTIVITIES_PAGE_SIZE
    return EventFilter(
        ui_name=event_type_name,
        name=event_type_name,
        attributes={"type": api_type, "filters": {}},
        page_size=page_size,
    )


def _options(alerts_limit: int = 10_000, activities_limit: int = 10_000) -> IntegrationOptions:
    """Build IntegrationOptions with explicit per-type caps for deterministic tests."""
    return IntegrationOptions.parse_obj({"alerts_limit": alerts_limit, "activities_limit": activities_limit})


def _make_get_events(options: IntegrationOptions, pages_by_type: dict) -> DefenderGetEvents:
    """Build a DefenderGetEvents whose _iter_events yields predefined pages per event type.

    Args:
        options: The IntegrationOptions to use. run() reads the per-type per-cycle caps from
            options.alerts_limit / options.activities_limit.
        pages_by_type: Mapping of event_type_name -> list of pages (each page is a list of events).

    Returns:
        A DefenderGetEvents instance with a stubbed _iter_events and no HTTP dependencies.
    """
    get_events = DefenderGetEvents.__new__(DefenderGetEvents)
    get_events.options = options
    # run() iterates filter_name_to_event_filter.items() and reads the per-type cap from options.
    get_events.filter_name_to_event_filter = {event_type: _event_filter(event_type) for event_type in pages_by_type}

    def fake_iter_events(event_type_name, _event_filter):
        yield from pages_by_type[event_type_name]

    get_events._iter_events = fake_iter_events  # type: ignore[method-assign]
    return get_events


def _events(event_type: str, count: int, start: int = 0) -> list:
    """Create a list of events tagged with the given event type."""
    return [{"timestamp": start + i, "event_type_name": event_type} for i in range(count)]


class TestIntegrationOptionsLimit:
    def test_per_type_defaults_applied_when_missing(self):
        """With no user input, each type uses its per-type default cap (alerts low, activities high)."""
        options = IntegrationOptions.parse_obj({})
        assert options.alerts_limit == ALERTS_LIMIT
        assert options.activities_limit == ACTIVITIES_LIMIT

    def test_user_can_override_per_type_limits(self):
        """A user may raise either per-type cap independently."""
        options = IntegrationOptions.parse_obj({"alerts_limit": 2000, "activities_limit": 100000})
        assert options.alerts_limit == 2000
        assert options.activities_limit == 100000

    def test_large_limit_is_accepted(self):
        """There is no upper cap: a large activities limit is accepted for high-volume tenants."""
        options = IntegrationOptions.parse_obj({"activities_limit": 500000})
        assert options.activities_limit == 500000

    @pytest.mark.parametrize("empty_value", [None, ""])
    def test_main_empty_per_cycle_config_falls_back_to_defaults(self, mocker, empty_value):
        """An instance upgraded from an older version passes the new per-cycle keys with
        empty/None values (unset config fields). main() must strip them so pydantic applies the
        per-type Field defaults instead of failing int validation."""
        demisto_params = {
            "url": "https://example.test",
            "credentials": {"password": "secret", "identifier": "id"},
            "verify": False,
            "tenant_id": "tenant",
            "client_id": "client",
            "scope": "scope",
            "endpoint_type": "Worldwide",
            "after": "3 days",
            "alerts_limit": empty_value,
            "activities_limit": empty_value,
        }
        # Stub the network-facing pieces; keep the real DefenderGetEvents.__init__ so the code
        # path that consumes options (and filter_name_to_event_filter) runs as in production.
        mocker.patch.object(DefenderClient, "__init__", return_value=None)
        mocker.patch.object(DefenderGetEvents, "run", return_value=[])
        mocker.patch("MicrosoftDefenderEventCollector.send_events_to_xsiam")
        mocker.patch.object(demisto, "setLastRun")
        get_events_init = mocker.spy(DefenderGetEvents, "__init__")

        # Must not raise the pydantic validation error seen on the tenant.
        main("fetch-events", demisto_params)

        options = get_events_init.call_args.kwargs["options"]
        assert options.alerts_limit == ALERTS_LIMIT
        assert options.activities_limit == ACTIVITIES_LIMIT


class TestRunPaginationRegression:
    def test_backlog_drains_beyond_single_page(self):
        """Regression for XSUP-72224: run() must paginate past the first page up to the per-type cap.

        Before the fix the limit was capped at 100, so only the first page was kept per type.
        With a higher cap the collector should accumulate events across multiple pages.
        """
        options = _options(activities_limit=1000)
        # Three pages of 100 admin events => a 300-event backlog in one cycle.
        pages = {"activities_admin": [_events("activities_admin", 100, start=s) for s in (0, 100, 200)]}
        get_events = _make_get_events(options, pages)

        result = get_events.run()

        assert len(result) == 300  # all three pages drained, not just the first 100

    def test_limit_is_enforced_per_event_type(self):
        """Each event type is capped by its own per-type limit; total may reach sum of caps."""
        options = _options(alerts_limit=150, activities_limit=150)
        pages = {
            "alerts": [_events("alerts", 100, start=s) for s in (0, 100)],
            "activities_admin": [_events("activities_admin", 100, start=s) for s in (0, 100)],
        }
        get_events = _make_get_events(options, pages)

        result = get_events.run()

        # Each type is capped at 150 -> 2 types * 150 = 300 total.
        assert len(result) == 300
        assert len([e for e in result if e["event_type_name"] == "alerts"]) == 150
        assert len([e for e in result if e["event_type_name"] == "activities_admin"]) == 150

    def test_alerts_and_activities_use_distinct_caps(self):
        """The per-type caps are independent: alerts_limit bounds alerts, activities_limit bounds activities."""
        options = _options(alerts_limit=50, activities_limit=500)
        pages = {
            "alerts": [_events("alerts", 100, start=s) for s in (0, 100)],  # 200 available, capped to 50
            "activities_login": [_events("activities_login", 100, start=s) for s in range(0, 700, 100)],  # 700 -> 500
        }
        get_events = _make_get_events(options, pages)

        result = get_events.run()

        assert len([e for e in result if e["event_type_name"] == "alerts"]) == 50
        assert len([e for e in result if e["event_type_name"] == "activities_login"]) == 500

    def test_fewer_events_than_limit_returns_all(self):
        """When the source has fewer events than the cap, all are returned (partial page stops)."""
        options = _options(alerts_limit=1000)
        pages = {"alerts": [_events("alerts", 30)]}
        get_events = _make_get_events(options, pages)

        result = get_events.run()

        assert len(result) == 30

    def test_one_type_crashing_does_not_stop_other_types(self, mocker):
        """XSUP-72224 crash-isolation: a failure fetching one type must not abort the others.

        activities_login raises mid-fetch; activities_admin and alerts must still be
        collected. The failing type contributes nothing (its watermark won't advance),
        while the healthy types are returned in full.
        """
        # The failure path logs via demisto.error; mock it so nothing leaks to stdout
        # (the test harness fails on unexpected stdout) and to assert the error is logged.
        error_mock = mocker.patch.object(demisto, "error")
        options = _options()
        get_events = DefenderGetEvents.__new__(DefenderGetEvents)
        get_events.options = options
        get_events.filter_name_to_event_filter = {
            "activities_login": _event_filter("activities_login"),
            "activities_admin": _event_filter("activities_admin"),
            "alerts": _event_filter("alerts"),
        }

        def failing_iter(event_type_name, _event_filter):
            if event_type_name == "activities_login":
                raise RuntimeError("simulated API failure (e.g., 429/timeout)")
            yield _events(event_type_name, 20)

        get_events._iter_events = failing_iter  # type: ignore[method-assign]

        result = get_events.run()

        by_type = {t: len([e for e in result if e["event_type_name"] == t]) for t in ("activities_admin", "alerts")}
        assert by_type["activities_admin"] == 20  # healthy type not blocked by the crash
        assert by_type["alerts"] == 20  # healthy type not blocked by the crash
        # The crashing type contributes zero events (watermark stays put, retried next cycle).
        assert not [e for e in result if e["event_type_name"] == "activities_login"]
        # The failure was logged (and not raised) so the cycle completed for the healthy types.
        assert error_mock.called

    def test_low_volume_types_are_not_discarded_when_below_limit(self):
        """Regression for XSUP-72224 second bug: low-volume types must NOT be dropped.

        Reproduces production: one high-volume type (activities_login) hits the
        per-type limit while two low-volume types (activities_admin, alerts) stay
        below it. The previous run() only kept a type's events when it reached the
        limit, so the sub-limit types were silently discarded every cycle - starving
        those datasets. All three types must be present in the result.
        """
        options = _options(alerts_limit=1000, activities_limit=1000)
        pages = {
            # 12 pages of 100 => 1200 login events, exceeds the 1000 cap -> sliced to 1000.
            "activities_login": [_events("activities_login", 100, start=s) for s in range(0, 1200, 100)],
            # Low-volume types well below the cap - must still be kept in full.
            "activities_admin": [_events("activities_admin", 10)],
            "alerts": [_events("alerts", 5)],
        }
        get_events = _make_get_events(options, pages)

        result = get_events.run()

        by_type = {t: len([e for e in result if e["event_type_name"] == t]) for t in pages}
        assert by_type["activities_login"] == 1000  # high-volume type capped at the limit
        assert by_type["activities_admin"] == 10  # low-volume type NOT discarded
        assert by_type["alerts"] == 5  # low-volume type NOT discarded
        assert len(result) == 1015


# Frozen instant used for the watermark tests. 1_700_000_000_000 ms == 2023-11-14T22:13:20Z,
# so datetime.now(timezone.utc).timestamp() * 1000 == NOW_MS while frozen.
NOW_MS = 1_700_000_000_000
FROZEN_TIME = "2023-11-14T22:13:20Z"


@freeze_time(FROZEN_TIME)
class TestGetLastRunWatermark:
    """Regression for XSUP-72224: a fetched type that returns 0 events must still get a
    watermark, otherwise it re-scans the same first-fetch lookback window forever."""

    def _patch_env(self, mocker, stored_last_run: dict):
        mocker.patch.object(demisto, "getLastRun", return_value=dict(stored_last_run))
        mocker.patch.object(demisto, "debug")

    def test_empty_type_with_no_watermark_is_seeded_forward(self, mocker):
        """login/admin return 0 events and have no prior watermark -> seeded to 'now'."""
        self._patch_env(mocker, stored_last_run={})
        events = [{"timestamp": 111, "event_type_name": "alerts"}]

        last_run = DefenderGetEvents.get_last_run(events, fetched_types=["alerts", "activities_login", "activities_admin"])

        assert last_run["alerts"] == 112  # type with events advances to max+1
        assert last_run["activities_login"] == NOW_MS  # 0-event type seeded forward
        assert last_run["activities_admin"] == NOW_MS  # 0-event type seeded forward

    def test_empty_type_with_existing_watermark_is_preserved(self, mocker):
        """A 0-event type that already has a watermark must keep it (no data skipped)."""
        self._patch_env(mocker, stored_last_run={"activities_login": 555})
        events = [{"timestamp": 111, "event_type_name": "alerts"}]

        last_run = DefenderGetEvents.get_last_run(events, fetched_types=["alerts", "activities_login"])

        assert last_run["activities_login"] == 555  # preserved, NOT overwritten with now
        assert last_run["alerts"] == 112

    def test_type_with_events_advances_past_newest(self, mocker):
        """A type with events advances to the newest timestamp + 1 (ms), ignoring order."""
        self._patch_env(mocker, stored_last_run={})
        events = [
            {"timestamp": 300, "event_type_name": "activities_login"},
            {"timestamp": 500, "event_type_name": "activities_login"},
            {"timestamp": 400, "event_type_name": "activities_login"},
        ]

        last_run = DefenderGetEvents.get_last_run(events, fetched_types=["activities_login"])

        assert last_run["activities_login"] == 501  # max(300,500,400) + 1

    def test_unfetched_types_are_not_seeded(self, mocker):
        """Only fetched types are seeded; a type not fetched this cycle is untouched."""
        self._patch_env(mocker, stored_last_run={})
        events = [{"timestamp": 111, "event_type_name": "alerts"}]

        last_run = DefenderGetEvents.get_last_run(events, fetched_types=["alerts"])

        assert "activities_login" not in last_run
        assert "activities_admin" not in last_run


class _FakeResponse:
    """Minimal stand-in for requests.Response exposing only .json()."""

    def __init__(self, payload: dict):
        self._payload = payload

    def json(self):
        return self._payload


def _make_defender_get_events_with_client(pages: list[dict], mocker) -> DefenderGetEvents:
    """Build a DefenderGetEvents whose client returns the given API payloads in order.

    Each element of `pages` is a raw API response dict (e.g. {"data": [...], "hasNext": bool}).
    The client's network/auth side effects are stubbed so _iter_events can be exercised
    end-to-end without HTTP.
    """
    get_events = DefenderGetEvents.__new__(DefenderGetEvents)
    get_events.base_url = "https://example.test/api/v1/"

    client = DefenderClient.__new__(DefenderClient)
    client.after = 1000
    client.request = mocker.Mock()
    client.request.json = {}
    # authenticate() and set_request_filter() must be no-ops / simple for the test.
    client.authenticate = mocker.Mock()  # type: ignore[method-assign]
    responses = [_FakeResponse(p) for p in pages]
    client.call = mocker.Mock(side_effect=responses)  # type: ignore[method-assign]
    client.set_request_filter = mocker.Mock()  # type: ignore[method-assign]
    get_events.client = client
    return get_events


class TestIterEventsPagination:
    """Coverage for DefenderGetEvents._iter_events: pagination, event tagging, the per-type
    start window taken from the last run, and the per-type API page size sent to the API."""

    def test_single_page_no_next_yields_once_and_tags_type(self, mocker):
        """A response with hasNext=False yields exactly one page and tags each event's type."""
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(demisto, "debug")
        payload = {"data": [{"timestamp": 1}, {"timestamp": 2}], "hasNext": False}
        get_events = _make_defender_get_events_with_client([payload], mocker)

        pages = list(get_events._iter_events("alerts", ALERTS_FILTER))

        assert len(pages) == 1
        assert len(pages[0]) == 2
        assert all(e["event_type_name"] == "alerts" for e in pages[0])
        # A single call means the client was hit once and pagination did not continue.
        assert get_events.client.call.call_count == 1
        get_events.client.set_request_filter.assert_not_called()

    def test_paginates_until_has_next_false(self, mocker):
        """_iter_events follows hasNext, advancing the filter by the last event each page."""
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(demisto, "debug")
        pages_payload = [
            {"data": [{"timestamp": 10}, {"timestamp": 20}], "hasNext": True},
            {"data": [{"timestamp": 30}, {"timestamp": 40}], "hasNext": True},
            {"data": [{"timestamp": 50}], "hasNext": False},
        ]
        get_events = _make_defender_get_events_with_client(pages_payload, mocker)

        # Capture each page length as it is yielded: _iter_events pops the last event off the
        # previously-yielded page to advance pagination (as run() consumes each page before the
        # next), so lengths must be read during iteration, not from an eagerly-collected list.
        page_lengths = [len(page) for page in get_events._iter_events("activities_login", LOGIN_ACTIVITIES_FILTER)]

        # All three pages are yielded and the client was called three times.
        assert page_lengths == [2, 2, 1]
        assert get_events.client.call.call_count == 3
        # set_request_filter is called once per continuation (2 times for 3 pages).
        assert get_events.client.set_request_filter.call_count == 2

    def test_last_run_window_overrides_client_after(self, mocker):
        """When a per-type watermark exists in the last run, it is used as the start filter."""
        mocker.patch.object(demisto, "getLastRun", return_value={"alerts": 8888})
        mocker.patch.object(demisto, "debug")
        payload = {"data": [{"timestamp": 9999}], "hasNext": False}
        get_events = _make_defender_get_events_with_client([payload], mocker)

        list(get_events._iter_events("alerts", ALERTS_FILTER))

        # The request filters must carry the per-type watermark (8888), not client.after (1000).
        sent_filters = get_events.client.request.json["filters"]
        assert sent_filters["date"] == {"gte": 8888}

    def test_alerts_page_size_sent_to_api(self, mocker):
        """The alerts endpoint requests its per-type page size (100) as the API `limit`."""
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(demisto, "debug")
        payload = {"data": [{"timestamp": 1}], "hasNext": False}
        get_events = _make_defender_get_events_with_client([payload], mocker)

        list(get_events._iter_events("alerts", ALERTS_FILTER))

        assert get_events.client.request.json["limit"] == ALERTS_PAGE_SIZE

    def test_activities_page_size_sent_to_api(self, mocker):
        """The activities endpoint requests its larger per-type page size (5000) as the API `limit`.

        This is the core throughput fix (XSUP-72224): without it each page returned only ~100.
        """
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(demisto, "debug")
        payload = {"data": [{"timestamp": 1}], "hasNext": False}
        get_events = _make_defender_get_events_with_client([payload], mocker)

        list(get_events._iter_events("activities_login", LOGIN_ACTIVITIES_FILTER))

        assert get_events.client.request.json["limit"] == ACTIVITIES_PAGE_SIZE


class TestSetRequestFilter:
    """Coverage for DefenderClient.set_request_filter: the +1ms forward advance."""

    def test_advances_gte_by_one_millisecond(self, mocker):
        client = DefenderClient.__new__(DefenderClient)
        client.request = mocker.Mock()
        client.request.json = {"filters": {"date": {"gte": 100}}}

        client.set_request_filter(1_700_000_000_000)

        updated = client.request.json["filters"]
        assert updated["date"] == {"gte": 1_700_000_000_001}  # last timestamp + 1 ms

    def test_preserves_other_filter_keys(self, mocker):
        client = DefenderClient.__new__(DefenderClient)
        client.request = mocker.Mock()
        client.request.json = {"filters": {"date": {"gte": 1}, "activity.type": {"eq": True}}}

        client.set_request_filter(500)

        updated = client.request.json["filters"]
        assert updated["activity.type"] == {"eq": True}  # unrelated filters untouched
        assert updated["date"] == {"gte": 501}


class TestModuleTest:
    """Coverage for module_test: success returns 'ok'; auth errors map to a readable message."""

    def test_returns_ok_on_success(self, mocker):
        get_events = mocker.Mock()
        get_events.client.request.params = {}
        get_events.run.return_value = []

        assert module_test(get_events) == "ok"
        # module_test probes with a minimal per-type cap of 1 for both categories.
        assert get_events.options.alerts_limit == 1
        assert get_events.options.activities_limit == 1

    def test_auth_error_returns_readable_message(self, mocker):
        get_events = mocker.Mock()
        get_events.client.request.params = {}
        get_events.run.side_effect = DemistoException("403 Forbidden")

        assert module_test(get_events) == AUTH_ERROR_MSG

    def test_non_auth_error_is_raised(self, mocker):
        get_events = mocker.Mock()
        get_events.client.request.params = {}
        get_events.run.side_effect = DemistoException("500 Internal Server Error")

        with pytest.raises(DemistoException):
            module_test(get_events)


class TestSelectEventFilters:
    """Coverage for select_event_filters: the event_types_to_fetch scoping used by get-events."""

    def test_empty_request_returns_all_filters(self):
        """No requested types (the default) means fetch every configured event type."""
        assert select_event_filters([]) == ALL_EVENT_FILTERS

    def test_single_type_scopes_to_that_filter(self):
        """Requesting only 'Login activities' selects just the login filter (backfill scoping)."""
        assert select_event_filters(["Login activities"]) == [LOGIN_ACTIVITIES_FILTER]

    def test_multiple_types_are_all_selected(self):
        """Multiple requested types map to their respective filters."""
        selected = select_event_filters(["Alerts", "Admin activities"])
        assert selected == [ALERTS_FILTER, ADMIN_ACTIVITIES_FILTER]

    def test_unknown_type_is_ignored(self):
        """An unrecognized display name is silently dropped (no crash, no bad filter)."""
        assert select_event_filters(["Does not exist"]) == []
