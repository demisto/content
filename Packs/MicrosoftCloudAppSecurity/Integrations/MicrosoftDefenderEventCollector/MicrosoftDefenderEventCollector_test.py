"""Unit tests for the Microsoft Defender for Cloud Apps Event Collector."""

import demistomock as demisto
import pytest
from pydantic import ValidationError

from MicrosoftDefenderEventCollector import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    DefenderGetEvents,
    IntegrationOptions,
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

    def test_limit_above_max_is_rejected(self):
        """Values above MAX_LIMIT are rejected by validation."""
        with pytest.raises(ValidationError):
            IntegrationOptions.parse_obj({"limit": MAX_LIMIT + 1})


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


class TestGetLastRunWatermark:
    """Regression for XSUP-72224: a fetched type that returns 0 events must still get a
    watermark, otherwise it re-scans the same first-fetch lookback window forever."""

    NOW_MS = 1_700_000_000_000

    def _patch_env(self, mocker, stored_last_run: dict):
        mocker.patch.object(demisto, "getLastRun", return_value=dict(stored_last_run))
        mocker.patch.object(demisto, "debug")
        # Freeze "now" so the seeded watermark is deterministic.
        import MicrosoftDefenderEventCollector as md

        fake_dt = mocker.Mock()
        fake_dt.now.return_value.timestamp.return_value = self.NOW_MS / 1000
        mocker.patch.object(md, "datetime", fake_dt)

    def test_empty_type_with_no_watermark_is_seeded_forward(self, mocker):
        """login/admin return 0 events and have no prior watermark -> seeded to 'now'."""
        self._patch_env(mocker, stored_last_run={})
        events = [{"timestamp": 111, "event_type_name": "alerts"}]

        last_run = DefenderGetEvents.get_last_run(events, fetched_types=["alerts", "activities_login", "activities_admin"])

        assert last_run["alerts"] == 112  # type with events advances to max+1
        assert last_run["activities_login"] == self.NOW_MS  # 0-event type seeded forward
        assert last_run["activities_admin"] == self.NOW_MS  # 0-event type seeded forward

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
