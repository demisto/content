"""Unit tests for the Microsoft Defender for Cloud Apps Event Collector."""

import json

import demistomock as demisto
import pytest
from freezegun import freeze_time

from CommonServerPython import DemistoException
from MicrosoftDefenderEventCollector import (
    ALL_EVENT_FILTERS,
    AUTH_ERROR_MSG,
    DEFAULT_LIMIT,
    UI_NAME_TO_EVENT_FILTERS,
    WATERMARK_SAFETY_BUFFER_MS,
    DefenderClient,
    DefenderGetEvents,
    DefenderHTTPRequest,
    IntegrationOptions,
    load_json,
    main,
    module_test,
)


def _make_get_events(options: IntegrationOptions, pages_by_type: dict) -> DefenderGetEvents:
    """Build a DefenderGetEvents whose _iter_events yields predefined pages per event type.

    Args:
        options: The IntegrationOptions to use (holds the limit).
        pages_by_type: Mapping of event_type_name -> list of pages (each page is a list of events).

    Returns:
        A DefenderGetEvents instance with a stubbed _iter_events and no HTTP dependencies.
    """
    get_events = DefenderGetEvents.__new__(DefenderGetEvents)
    get_events.options = options
    # run() iterates filter_name_to_attributes.items(); the value is unused by our stub.
    get_events.filter_name_to_attributes = {event_type: {} for event_type in pages_by_type}

    def fake_iter_events(event_type_name, _endpoint_details):
        yield from pages_by_type[event_type_name]

    get_events._iter_events = fake_iter_events  # type: ignore[method-assign]
    return get_events


def _events(event_type: str, count: int, start: int = 0) -> list:
    """Create a list of events tagged with the given event type."""
    return [{"timestamp": start + i, "event_type_name": event_type} for i in range(count)]


class TestIntegrationOptionsLimit:
    def test_default_limit_is_applied_when_missing(self):
        """When no limit is supplied, the model defaults to DEFAULT_LIMIT (bounded, never None)."""
        options = IntegrationOptions.parse_obj({})
        assert options.limit == DEFAULT_LIMIT

    def test_limit_above_page_size_is_accepted(self):
        """A limit greater than the old 100 ceiling is now valid (regression for the lag bug)."""
        options = IntegrationOptions.parse_obj({"limit": 1000})
        assert options.limit == 1000

    def test_large_limit_is_accepted(self):
        """There is no upper cap: a large limit is accepted so admins can size to their volume."""
        options = IntegrationOptions.parse_obj({"limit": 50000})
        assert options.limit == 50000


class TestRunPaginationRegression:
    def test_backlog_drains_beyond_single_page(self):
        """Regression for XSUP-72224: run() must paginate past the first ~100 page up to `limit`.

        Before the fix the limit was capped at 100, so only the first page was kept per type.
        With limit=1000 the collector should accumulate events across multiple pages.
        """
        options = IntegrationOptions.parse_obj({"limit": 1000})
        # Three pages of 100 admin events => a 300-event backlog in one cycle.
        pages = {"activities_admin": [_events("activities_admin", 100, start=s) for s in (0, 100, 200)]}
        get_events = _make_get_events(options, pages)

        result = get_events.run()

        assert len(result) == 300  # all three pages drained, not just the first 100

    def test_limit_is_enforced_per_event_type(self):
        """`limit` caps each event type independently; total may reach limit * number_of_types."""
        options = IntegrationOptions.parse_obj({"limit": 150})
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

    def test_fewer_events_than_limit_returns_all(self):
        """When the source has fewer events than the limit, all are returned."""
        options = IntegrationOptions.parse_obj({"limit": 1000})
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
        options = IntegrationOptions.parse_obj({"limit": 1000})
        get_events = DefenderGetEvents.__new__(DefenderGetEvents)
        get_events.options = options
        get_events.filter_name_to_attributes = {
            "activities_login": {},
            "activities_admin": {},
            "alerts": {},
        }

        def failing_iter(event_type_name, _endpoint_details):
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
        options = IntegrationOptions.parse_obj({"limit": 1000})
        pages = {
            # 12 pages of 100 => 1200 login events, exceeds the 1000 limit -> sliced to 1000.
            "activities_login": [_events("activities_login", 100, start=s) for s in range(0, 1200, 100)],
            # Low-volume types well below the limit - must still be kept in full.
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
        """login/admin return 0 events and have no prior watermark -> seeded to (now - safety buffer).

        The small step-back (WATERMARK_SAFETY_BUFFER_MS) covers the vendor ingestion lag so recent,
        not-yet-available events are not skipped, while the watermark still advances (no loop).
        """
        self._patch_env(mocker, stored_last_run={})
        events = [{"timestamp": 111, "event_type_name": "alerts"}]

        last_run = DefenderGetEvents.get_last_run(events, fetched_types=["alerts", "activities_login", "activities_admin"])

        seeded = NOW_MS - WATERMARK_SAFETY_BUFFER_MS
        assert last_run["alerts"] == 112  # type with events advances to max+1
        assert last_run["activities_login"] == seeded  # 0-event type seeded to now - buffer
        assert last_run["activities_admin"] == seeded  # 0-event type seeded to now - buffer
        # The seed is in the past relative to now, guaranteeing no recent events are skipped.
        assert last_run["activities_login"] < NOW_MS

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
    client.request.params = {}
    # authenticate() and set_request_filter() must be no-ops / simple for the test.
    client.authenticate = mocker.Mock()  # type: ignore[method-assign]
    responses = [_FakeResponse(p) for p in pages]
    client.call = mocker.Mock(side_effect=responses)  # type: ignore[method-assign]
    client.set_request_filter = mocker.Mock()  # type: ignore[method-assign]
    get_events.client = client
    return get_events


class TestIterEventsPagination:
    """Coverage for DefenderGetEvents._iter_events: pagination, event tagging, and the
    per-type start window taken from the last run."""

    def test_single_page_no_next_yields_once_and_tags_type(self, mocker):
        """A response with hasNext=False yields exactly one page and tags each event's type."""
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(demisto, "debug")
        payload = {"data": [{"timestamp": 1}, {"timestamp": 2}], "hasNext": False}
        get_events = _make_defender_get_events_with_client([payload], mocker)

        pages = list(get_events._iter_events("alerts", {"type": "alerts", "filters": {}}))

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

        # Measure each page's length as it is yielded. _iter_events pops the last event off the
        # previously-yielded page to advance pagination; run() consumes (extends) each page before
        # the generator resumes and pops, so lengths must be read during iteration - not from an
        # eagerly-collected list, which would observe the post-pop mutation.
        page_lengths = [len(page) for page in get_events._iter_events("activities_login", {"type": "activities", "filters": {}})]

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

        list(get_events._iter_events("alerts", {"type": "alerts", "filters": {}}))

        # The request filters must carry the per-type watermark (8888), not client.after (1000).
        sent_filters = json.loads(get_events.client.request.params["filters"])
        assert sent_filters["date"] == {"gte": 8888}


class TestSetRequestFilter:
    """Coverage for DefenderClient.set_request_filter: the +1ms forward advance."""

    def test_advances_gte_by_one_millisecond(self, mocker):
        client = DefenderClient.__new__(DefenderClient)
        client.request = mocker.Mock()
        client.request.params = {"filters": json.dumps({"date": {"gte": 100}})}

        client.set_request_filter(1_700_000_000_000)

        updated = json.loads(client.request.params["filters"])
        assert updated["date"] == {"gte": 1_700_000_000_001}  # last timestamp + 1 ms

    def test_preserves_other_filter_keys(self, mocker):
        client = DefenderClient.__new__(DefenderClient)
        client.request = mocker.Mock()
        client.request.params = {"filters": json.dumps({"date": {"gte": 1}, "activity.type": {"eq": True}})}

        client.set_request_filter(500)

        updated = json.loads(client.request.params["filters"])
        assert updated["activity.type"] == {"eq": True}  # unrelated filters untouched
        assert updated["date"] == {"gte": 501}


class TestModuleTest:
    """Coverage for module_test: success returns 'ok'; auth errors map to a readable message."""

    def test_returns_ok_on_success(self, mocker):
        get_events = mocker.Mock()
        get_events.client.request.params = {}
        get_events.run.return_value = []

        assert module_test(get_events) == "ok"
        # module_test probes with a minimal limit of 1.
        assert get_events.options.limit == 1

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


class TestLoadJson:
    """Coverage for the load_json validator helper."""

    def test_passthrough_dict(self):
        assert load_json({"a": 1}) == {"a": 1}

    def test_parses_json_string(self):
        assert load_json('{"a": 1}') == {"a": 1}

    def test_invalid_json_string_raises(self):
        with pytest.raises(ValueError, match="not valid Json"):
            load_json("{not-json")

    def test_json_string_not_a_dict_raises(self):
        with pytest.raises(ValueError, match="not from dict type"):
            load_json("[1, 2, 3]")

    def test_non_dict_non_str_raises(self):
        with pytest.raises(ValueError, match="not dict or a valid json"):
            load_json(123)


class TestDefenderHTTPRequest:
    """Coverage for DefenderHTTPRequest: URL normalization and GET defaults."""

    def test_url_is_normalized_with_api_suffix(self):
        request = DefenderHTTPRequest.parse_obj({"url": "https://tenant.portal.cloudappsecurity.com"})
        # The validator appends the API path to the base URL.
        assert str(request.url).rstrip("/").endswith("/api/v1")

    def test_default_method_is_get_and_sort_ascending(self):
        request = DefenderHTTPRequest.parse_obj({"url": "https://tenant.portal.cloudappsecurity.com"})
        assert request.method == "GET"
        assert request.params["sortDirection"] == "asc"


class TestClientCall:
    """Coverage for IntegrationEventsClient.call: success returns the response, errors wrap."""

    def test_call_returns_response_on_success(self, mocker):
        mocker.patch.object(demisto, "debug")
        client = DefenderClient.__new__(DefenderClient)
        response = mocker.Mock()
        response.raise_for_status = mocker.Mock()
        session = mocker.Mock()
        session.request = mocker.Mock(return_value=response)
        client.session = session
        request = DefenderHTTPRequest.parse_obj({"url": "https://tenant.portal.cloudappsecurity.com"})

        assert client.call(request) is response
        response.raise_for_status.assert_called_once()

    def test_call_wraps_errors_in_demisto_exception(self, mocker):
        mocker.patch.object(demisto, "debug")
        client = DefenderClient.__new__(DefenderClient)
        session = mocker.Mock()
        session.request = mocker.Mock(side_effect=ValueError("boom"))
        client.session = session
        request = DefenderHTTPRequest.parse_obj({"url": "https://tenant.portal.cloudappsecurity.com"})

        with pytest.raises(DemistoException, match="something went wrong with the http call"):
            client.call(request)


class TestIterEventsClientAfterFallback:
    """Coverage for _iter_events when no per-type watermark exists: it falls back to client.after."""

    def test_uses_client_after_when_no_last_run(self, mocker):
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(demisto, "debug")
        payload = {"data": [{"timestamp": 1}], "hasNext": False}
        get_events = _make_defender_get_events_with_client([payload], mocker)  # client.after == 1000

        list(get_events._iter_events("alerts", {"type": "alerts", "filters": {}}))

        sent_filters = json.loads(get_events.client.request.params["filters"])
        # No watermark in last run -> the initial client.after (1000) is used as the start window.
        assert sent_filters["date"] == {"gte": 1000}
        get_events.client.authenticate.assert_called_once()

    def test_no_date_filter_when_after_is_zero(self, mocker):
        """If neither a watermark nor client.after is set, no date filter is added."""
        mocker.patch.object(demisto, "getLastRun", return_value={})
        mocker.patch.object(demisto, "debug")
        payload = {"data": [], "hasNext": False}
        get_events = _make_defender_get_events_with_client([payload], mocker)
        get_events.client.after = 0  # falsy -> no date filter

        list(get_events._iter_events("alerts", {"type": "alerts", "filters": {}}))

        sent_filters = json.loads(get_events.client.request.params["filters"])
        assert "date" not in sent_filters


class TestEventFilterSelection:
    """Coverage for the UI-name -> EventFilter mapping used by main() to scope fetches."""

    def test_ui_name_mapping_covers_all_filters(self):
        assert set(UI_NAME_TO_EVENT_FILTERS) == {"Alerts", "Admin activities", "Login activities"}
        assert len(ALL_EVENT_FILTERS) == 3

    def test_selecting_subset_of_event_types(self):
        selected = [
            event_filter
            for ui_name, event_filter in UI_NAME_TO_EVENT_FILTERS.items()
            if ui_name in ["Alerts", "Login activities"]
        ]
        names = {event_filter.name for event_filter in selected}
        assert names == {"alerts", "activities_login"}


def _base_params(**overrides) -> dict:
    """Build a minimal, valid demisto_params dict for main()."""
    params = {
        "credentials": {"identifier": "client-id", "password": "secret"},
        "url": "https://tenant.portal.cloudappsecurity.com",
        "tenant_id": "tenant",
        "client_id": "client-id",
        "scope": "scope/.default",
        "endpoint_type": "Worldwide",
        "verify": True,
        "proxy": False,
    }
    params.update(overrides)
    return params


class TestMainCommandDispatch:
    """Coverage for main(): command routing, event-type scoping, after parsing, and error handling."""

    def _patch_common(self, mocker):
        mocker.patch.object(demisto, "debug")
        mocker.patch.object(demisto, "error")
        # Avoid real auth / HTTP by stubbing the authenticator and client construction side effects.
        mocker.patch("MicrosoftDefenderEventCollector.DefenderAuthenticator.set_authorization")

    def test_test_module_command_returns_ok(self, mocker):
        self._patch_common(mocker)
        return_results = mocker.patch("MicrosoftDefenderEventCollector.return_results")
        mocker.patch.object(DefenderGetEvents, "run", return_value=[])

        main("test-module", _base_params())

        return_results.assert_called_once_with("ok")

    def test_fetch_events_sets_last_run_and_pushes(self, mocker):
        self._patch_common(mocker)
        events = [{"timestamp": 10, "event_type_name": "alerts"}]
        mocker.patch.object(DefenderGetEvents, "run", return_value=events)
        send = mocker.patch("MicrosoftDefenderEventCollector.send_events_to_xsiam")
        set_last_run = mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(demisto, "getLastRun", return_value={})

        main("fetch-events", _base_params())

        send.assert_called_once()
        set_last_run.assert_called_once()
        # The alerts watermark advances to max timestamp + 1.
        assert set_last_run.call_args[0][0]["alerts"] == 11

    def test_get_events_command_returns_results_without_push_by_default(self, mocker):
        self._patch_common(mocker)
        events = [{"timestamp": 10, "event_type_name": "alerts", "_id": "a1"}]
        mocker.patch.object(DefenderGetEvents, "run", return_value=events)
        return_results = mocker.patch("MicrosoftDefenderEventCollector.return_results")
        send = mocker.patch("MicrosoftDefenderEventCollector.send_events_to_xsiam")

        main("microsoft-defender-cloud-apps-get-events", _base_params())

        return_results.assert_called_once()
        # should_push_events defaults to false -> no push for the manual command.
        send.assert_not_called()

    def test_get_events_command_pushes_when_requested(self, mocker):
        self._patch_common(mocker)
        events = [{"timestamp": 10, "event_type_name": "alerts", "_id": "a1"}]
        mocker.patch.object(DefenderGetEvents, "run", return_value=events)
        mocker.patch("MicrosoftDefenderEventCollector.return_results")
        send = mocker.patch("MicrosoftDefenderEventCollector.send_events_to_xsiam")

        main("microsoft-defender-cloud-apps-get-events", _base_params(should_push_events="true"))

        send.assert_called_once()

    def test_event_types_to_fetch_scopes_the_fetch(self, mocker):
        """When event_types_to_fetch is provided, only those filters are passed to DefenderGetEvents."""
        self._patch_common(mocker)
        mocker.patch.object(DefenderGetEvents, "run", return_value=[])
        mocker.patch("MicrosoftDefenderEventCollector.send_events_to_xsiam")
        mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(demisto, "getLastRun", return_value={})
        init_spy = mocker.spy(DefenderGetEvents, "__init__")

        main("fetch-events", _base_params(event_types_to_fetch=["Alerts"]))

        # The event_filters kwarg passed to DefenderGetEvents must contain only the Alerts filter.
        passed_filters = init_spy.call_args.kwargs["event_filters"]
        assert [event_filter.name for event_filter in passed_filters] == ["alerts"]

    def test_after_string_is_parsed_to_epoch_ms(self, mocker):
        """A human 'after' string is parsed into an int epoch-ms and passed to the client."""
        self._patch_common(mocker)
        mocker.patch.object(DefenderGetEvents, "run", return_value=[])
        mocker.patch("MicrosoftDefenderEventCollector.send_events_to_xsiam")
        mocker.patch.object(demisto, "setLastRun")
        mocker.patch.object(demisto, "getLastRun", return_value={})
        client_init = mocker.spy(DefenderClient, "__init__")

        main("fetch-events", _base_params(after="1 day"))

        after_value = client_init.call_args.kwargs["after"]
        assert isinstance(after_value, int)
        assert after_value > 0

    def test_exception_is_caught_and_returns_error(self, mocker):
        self._patch_common(mocker)
        mocker.patch.object(DefenderGetEvents, "run", side_effect=RuntimeError("kaboom"))
        return_error = mocker.patch("MicrosoftDefenderEventCollector.return_error")
        mocker.patch.object(demisto, "getLastRun", return_value={})

        main("fetch-events", _base_params())

        return_error.assert_called_once()
        assert "Failed to execute fetch-events" in return_error.call_args[0][0]
