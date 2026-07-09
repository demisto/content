"""Unit tests for the Microsoft Defender for Cloud Apps Event Collector."""

import pytest

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
        with pytest.raises(Exception):
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
